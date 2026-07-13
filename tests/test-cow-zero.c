/*
 * Anonymous zero-page COW regressions
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define PAGE_SIZE 4096
#define WORKERS 8
#define ROUNDS 100

static pthread_barrier_t start_barrier;
static pthread_barrier_t done_barrier;
static pthread_barrier_t release_barrier;
static _Atomic(uintptr_t) current_page;
static _Atomic int cow_go;

static void test_fast_mmap_journal(void)
{
    TEST("EL1 mmap journal synchronizes host state");
    int ok = 1;
    for (int i = 0; i < 5000; i++) {
        void *tmp = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (tmp == MAP_FAILED || (uintptr_t) tmp < 0x200000000ULL ||
            (uintptr_t) tmp >= 0x201000000ULL || munmap(tmp, PAGE_SIZE) != 0) {
            ok = 0;
            break;
        }
    }

    uint8_t *page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED || (uintptr_t) page < 0x200000000ULL ||
        (uintptr_t) page >= 0x201000000ULL) {
        FAIL("mapping did not use fast arena");
        return;
    }
    page[0] = 0x5A;

    int fd = open("/proc/self/maps", O_RDONLY);
    char maps[16384];
    ssize_t n = fd >= 0 ? read(fd, maps, sizeof(maps) - 1) : -1;
    if (fd >= 0)
        close(fd);
    if (n < 0) {
        munmap(page, PAGE_SIZE);
        FAIL("read /proc/self/maps");
        return;
    }
    maps[n] = '\0';
    char needle[32];
    snprintf(needle, sizeof(needle), "%llx-",
             (unsigned long long) (uintptr_t) page);
    ok = ok && strstr(maps, needle) != NULL;

    pid_t child = fork();
    if (child == 0)
        _exit(page[0] == 0x5A ? 0 : 1);
    int status = 0;
    ok = ok && child > 0 && waitpid(child, &status, 0) == child &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0;
    ok = ok && mprotect(page, PAGE_SIZE, PROT_READ) == 0 && page[0] == 0x5A;
    ok = ok && munmap(page, PAGE_SIZE) == 0;
    if (ok)
        PASS();
    else
        FAIL("journal visibility in maps/fork/mprotect");
}

static void *cow_writer(void *arg)
{
    uintptr_t slot = (uintptr_t) arg;
    int go;
    while ((go = atomic_load_explicit(&cow_go, memory_order_acquire)) == 0)
        sched_yield();
    if (go < 0)
        return NULL;
    for (int round = 0; round < ROUNDS; round++) {
        pthread_barrier_wait(&start_barrier);
        volatile uint8_t *page = (volatile uint8_t *) atomic_load_explicit(
            &current_page, memory_order_acquire);
        if (page)
            page[slot * 8] = (uint8_t) (0x80 + slot);
        pthread_barrier_wait(&done_barrier);
        pthread_barrier_wait(&release_barrier);
    }
    return NULL;
}

static void test_concurrent_first_write(void)
{
    TEST("concurrent COW-zero first write");

    pthread_barrier_init(&start_barrier, NULL, WORKERS + 1);
    pthread_barrier_init(&done_barrier, NULL, WORKERS + 1);
    pthread_barrier_init(&release_barrier, NULL, WORKERS + 1);
    atomic_store(&cow_go, 0);
    pthread_t threads[WORKERS];
    int nthreads = 0;
    for (uintptr_t i = 0; i < WORKERS; i++) {
        if (pthread_create(&threads[i], NULL, cow_writer, (void *) i) != 0) {
            atomic_store_explicit(&cow_go, -1, memory_order_release);
            for (int j = 0; j < nthreads; j++)
                pthread_join(threads[j], NULL);
            pthread_barrier_destroy(&start_barrier);
            pthread_barrier_destroy(&done_barrier);
            pthread_barrier_destroy(&release_barrier);
            FAIL("pthread_create");
            return;
        }
        nthreads++;
    }
    atomic_store_explicit(&cow_go, 1, memory_order_release);

    int ok = 1;
    for (int round = 0; round < ROUNDS; round++) {
        uint8_t *page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED) {
            ok = 0;
            page = NULL;
        }
        atomic_store_explicit(&current_page, (uintptr_t) page,
                              memory_order_release);
        pthread_barrier_wait(&start_barrier);
        pthread_barrier_wait(&done_barrier);

        for (uintptr_t i = 0; page && i < WORKERS; i++)
            if (page[i * 8] != (uint8_t) (0x80 + i))
                ok = 0;
        if (page && page[PAGE_SIZE - 1] != 0)
            ok = 0;
        if (page)
            munmap(page, PAGE_SIZE);
        pthread_barrier_wait(&release_barrier);
    }

    for (int i = 0; i < WORKERS; i++)
        pthread_join(threads[i], NULL);
    pthread_barrier_destroy(&start_barrier);
    pthread_barrier_destroy(&done_barrier);
    pthread_barrier_destroy(&release_barrier);
    if (ok)
        PASS();
    else
        FAIL("COW page contents");
}

static void test_host_write_materialization(void)
{
    TEST("host-to-guest write materializes COW range");
    int fds[2];
    uint8_t source[PAGE_SIZE];
    memset(source, 0xA5, sizeof(source));
    if (pipe(fds) != 0) {
        FAIL("pipe setup");
        return;
    }
    size_t written = 0;
    while (written < sizeof(source)) {
        ssize_t n = write(fds[1], source + written, sizeof(source) - written);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        written += (size_t) n;
    }
    if (written != sizeof(source)) {
        close(fds[0]);
        close(fds[1]);
        FAIL("pipe write");
        return;
    }

    uint8_t *page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    size_t received = 0;
    while (received < PAGE_SIZE) {
        ssize_t n = read(fds[0], page + received, PAGE_SIZE - received);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        received += (size_t) n;
    }
    close(fds[0]);
    close(fds[1]);
    int ok = received == PAGE_SIZE && memcmp(page, source, PAGE_SIZE) == 0;
    munmap(page, PAGE_SIZE);
    if (ok)
        PASS();
    else
        FAIL("read into untouched mapping");
}

static void test_short_read_materializes_only_result(void)
{
    TEST("short read materializes only returned bytes");
    const size_t len = 64UL * 1024 * 1024;
    int fds[2];
    if (pipe(fds) != 0) {
        FAIL("pipe");
        return;
    }
    int ok = write(fds[1], "abc", 3) == 3;
    close(fds[1]);

    unsigned char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        close(fds[0]);
        FAIL("mmap");
        return;
    }
    unsigned char cold_last = 1;
    int cold_last_rc = mincore(p + len - PAGE_SIZE, PAGE_SIZE, &cold_last);
    ok = ok && cold_last_rc == 0 && !(cold_last & 1);
    ssize_t short_n = read(fds[0], p, len);
    ok = ok && short_n == 3 && !memcmp(p, "abc", 3);
    unsigned char first = 0, last = 1;
    int first_rc = mincore(p, PAGE_SIZE, &first);
    int last_rc = mincore(p + len - PAGE_SIZE, PAGE_SIZE, &last);
    ok = ok && first_rc == 0 && (first & 1) && last_rc == 0 && !(last & 1);

    unsigned char *eof = mmap(NULL, len, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char eof_vec = 1;
    ssize_t eof_n = eof != MAP_FAILED ? read(fds[0], eof, len) : -1;
    int eof_rc = eof != MAP_FAILED ? mincore(eof, PAGE_SIZE, &eof_vec) : -1;
    ok = ok && eof != MAP_FAILED && eof_n == 0 && eof_rc == 0 && !(eof_vec & 1);

    if (eof != MAP_FAILED)
        munmap(eof, len);
    munmap(p, len);
    close(fds[0]);
    if (ok)
        PASS();
    else {
        printf(
            "  (cold-last=%d/%u short=%zd first=%d/%u last=%d/%u "
            "eof=%zd/%d/%u)\n",
            cold_last_rc, cold_last, short_n, first_rc, first, last_rc, last,
            eof_n, eof_rc, eof_vec);
        FAIL("read eagerly materialized untouched tail");
    }
}

static void test_host_read_after_el1_cow(void)
{
    TEST("host read observes EL1-materialized page");
    int fds[2];
    uint8_t out[2] = {0xFF, 0xFF};
    uint8_t *page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED || pipe(fds) != 0) {
        FAIL("setup");
        return;
    }

    /* The first write() makes the host walk the COW_ZERO read mapping. That
     * translation must not remain cached after EL1 replaces the PTE. */
    int ok = write(fds[1], page, 1) == 1;
    page[0] = 0x5A;
    ok = ok && write(fds[1], page, 1) == 1;
    ok = ok && read(fds[0], out, sizeof(out)) == (ssize_t) sizeof(out);
    close(fds[0]);
    close(fds[1]);
    munmap(page, PAGE_SIZE);
    if (ok && out[0] == 0 && out[1] == 0x5A)
        PASS();
    else
        FAIL("stale host GVA cache");
}

static void test_map_fixed_over_valid_zero(void)
{
    TEST("MAP_FIXED replaces a valid zero alias");
    uint8_t *page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        FAIL("initial mmap");
        return;
    }

    int ok = page[0] == 0; /* validate the lazy zero template */
    uint8_t *replacement = mmap(page, PAGE_SIZE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (replacement == page) {
        replacement[0] = 0x6B;
        ok = ok && replacement[0] == 0x6B && replacement[PAGE_SIZE - 1] == 0;
        munmap(replacement, PAGE_SIZE);
    } else {
        ok = 0;
        if (replacement != MAP_FAILED)
            munmap(replacement, PAGE_SIZE);
        else
            munmap(page, PAGE_SIZE);
    }

    if (ok)
        PASS();
    else
        FAIL("MAP_FIXED lazy-zero replacement");
}

/* A host-side buffer resolve that lands inside a fault-around zeroing window
 * must wait for the materializer's publish. The window descriptor is valid
 * but EL1-only, so a resolver that only waits on invalid MATERIALIZING words
 * fails the whole syscall with EFAULT instead. The reader aims write(2) at a
 * fixed distance ahead of the writer's progress cursor: between windows that
 * validates a template and caps the next claim run, which in turn keeps the
 * reader's target inside every window the writer forms. */
#define FA_RACE_LEN (8UL * 1024 * 1024)
#define FA_RACE_ROUNDS 16
#define FA_RACE_LEAD (2UL * PAGE_SIZE)

static _Atomic uintptr_t fa_race_region;
static _Atomic size_t fa_race_progress;
static _Atomic int fa_race_stop;
static _Atomic int fa_race_ready;
static _Atomic long fa_race_efault;
static _Atomic long fa_race_reads;

static void *fa_race_reader(void *arg)
{
    int *fds = arg;
    char drain = 0;
    /* Warm up the syscall path before signalling readiness so the writer's
     * first rounds actually overlap the reader loop. */
    if (write(fds[1], &drain, 1) == 1)
        while (read(fds[0], &drain, 1) < 0 && errno == EINTR)
            ;
    atomic_store_explicit(&fa_race_ready, 1, memory_order_release);
    while (!atomic_load_explicit(&fa_race_stop, memory_order_acquire)) {
        uint8_t *region = (uint8_t *) atomic_load_explicit(
            &fa_race_region, memory_order_acquire);
        size_t off =
            atomic_load_explicit(&fa_race_progress, memory_order_acquire) +
            FA_RACE_LEAD;
        if (!region || off + PAGE_SIZE > FA_RACE_LEN)
            continue;
        ssize_t n = write(fds[1], region + off, 1);
        if (n == 1) {
            atomic_fetch_add(&fa_race_reads, 1);
            while (read(fds[0], &drain, 1) < 0 && errno == EINTR)
                ;
        } else if (n < 0 && errno == EFAULT) {
            atomic_fetch_add(&fa_race_efault, 1);
        }
    }
    return NULL;
}

static void test_host_read_in_fault_around_window(void)
{
    TEST("host read waits out fault-around window");
    int fds[2];
    if (pipe(fds) != 0) {
        FAIL("pipe setup");
        return;
    }
    pthread_t reader;
    if (pthread_create(&reader, NULL, fa_race_reader, fds) != 0) {
        close(fds[0]);
        close(fds[1]);
        FAIL("pthread_create");
        return;
    }
    while (!atomic_load_explicit(&fa_race_ready, memory_order_acquire))
        ;

    int ok = 1;
    for (int round = 0; ok && round < FA_RACE_ROUNDS; round++) {
        uint8_t *p = mmap(NULL, FA_RACE_LEN, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            ok = 0;
            break;
        }
        atomic_store_explicit(&fa_race_progress, 0, memory_order_release);
        atomic_store_explicit(&fa_race_region, (uintptr_t) p,
                              memory_order_release);
        for (size_t off = 0; off < FA_RACE_LEN; off += PAGE_SIZE) {
            p[off] = 1;
            atomic_store_explicit(&fa_race_progress, off, memory_order_release);
        }
        /* Keep the region mapped: unmapping would race the reader's resolve
         * and turn a legitimate EFAULT into a false positive. */
        atomic_store_explicit(&fa_race_region, 0, memory_order_release);
    }
    atomic_store_explicit(&fa_race_stop, 1, memory_order_release);
    pthread_join(reader, NULL);
    close(fds[0]);
    close(fds[1]);
    long efaults = atomic_load(&fa_race_efault);
    long reads = atomic_load(&fa_race_reads);
    if (ok && efaults == 0 && reads > 0)
        PASS();
    else
        FAIL("EFAULT inside fault-around window");
    if (efaults)
        printf("  (%ld EFAULT, %ld clean reads)\n", efaults, reads);
}

/* The EL1 fault-around window is valid but privileged-only while its owner
 * zeroes the claimed pages. A sibling guest load therefore takes a read
 * permission fault and must wait for the MATERIALIZING owner, not receive a
 * guest-visible SIGSEGV. Returning from the handler retries the load, allowing
 * the test to count any erroneous delivery without terminating. */
static _Atomic uintptr_t fa_guest_region;
static _Atomic size_t fa_guest_progress;
static _Atomic int fa_guest_stop;
static _Atomic int fa_guest_ready;
static _Atomic long fa_guest_reads;
static volatile sig_atomic_t fa_guest_segv;
static _Thread_local sigjmp_buf fa_guest_jmp;
static _Thread_local volatile sig_atomic_t fa_guest_jmp_armed;

static void fa_guest_segv_handler(int sig)
{
    (void) sig;
    fa_guest_segv++;
    if (fa_guest_jmp_armed)
        siglongjmp(fa_guest_jmp, 1);
    _exit(128 + sig);
}

static void *fa_guest_reader(void *arg)
{
    (void) arg;
    atomic_store_explicit(&fa_guest_ready, 1, memory_order_release);
    while (!atomic_load_explicit(&fa_guest_stop, memory_order_acquire)) {
        uint8_t *region = (uint8_t *) atomic_load_explicit(
            &fa_guest_region, memory_order_acquire);
        size_t off =
            atomic_load_explicit(&fa_guest_progress, memory_order_acquire) +
            FA_RACE_LEAD;
        if (!region || off + PAGE_SIZE > FA_RACE_LEN)
            continue;
        if (sigsetjmp(fa_guest_jmp, 1) == 0) {
            fa_guest_jmp_armed = 1;
            (void) *(volatile uint8_t *) (region + off);
            fa_guest_jmp_armed = 0;
            atomic_fetch_add_explicit(&fa_guest_reads, 1, memory_order_relaxed);
        } else {
            fa_guest_jmp_armed = 0;
        }
    }
    return NULL;
}

static void test_guest_read_in_fault_around_window(void)
{
    TEST("guest read waits out fault-around window");
    struct sigaction sa = {0}, old_sa;
    sa.sa_handler = fa_guest_segv_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, &old_sa) != 0) {
        FAIL("sigaction");
        return;
    }

    atomic_store(&fa_guest_region, 0);
    atomic_store(&fa_guest_progress, 0);
    atomic_store(&fa_guest_stop, 0);
    atomic_store(&fa_guest_ready, 0);
    atomic_store(&fa_guest_reads, 0);
    fa_guest_segv = 0;

    pthread_t reader;
    if (pthread_create(&reader, NULL, fa_guest_reader, NULL) != 0) {
        sigaction(SIGSEGV, &old_sa, NULL);
        FAIL("pthread_create");
        return;
    }
    while (!atomic_load_explicit(&fa_guest_ready, memory_order_acquire))
        ;

    int ok = 1;
    uint8_t *regions[FA_RACE_ROUNDS] = {0};
    for (int round = 0; ok && round < FA_RACE_ROUNDS; round++) {
        uint8_t *p = mmap(NULL, FA_RACE_LEN, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            ok = 0;
            break;
        }
        regions[round] = p;
        atomic_store_explicit(&fa_guest_progress, 0, memory_order_release);
        atomic_store_explicit(&fa_guest_region, (uintptr_t) p,
                              memory_order_release);
        for (size_t off = 0; off < FA_RACE_LEN; off += PAGE_SIZE) {
            p[off] = 1;
            atomic_store_explicit(&fa_guest_progress, off,
                                  memory_order_release);
        }
        /* See the host-reader race above: keep mappings alive until the reader
         * stops so clearing the published pointer cannot race an in-flight
         * load with munmap. */
        atomic_store_explicit(&fa_guest_region, 0, memory_order_release);
    }
    atomic_store_explicit(&fa_guest_stop, 1, memory_order_release);
    pthread_join(reader, NULL);
    sigaction(SIGSEGV, &old_sa, NULL);
    for (int round = 0; round < FA_RACE_ROUNDS; round++)
        if (regions[round])
            munmap(regions[round], FA_RACE_LEN);

    long reads = atomic_load(&fa_guest_reads);
    if (ok && fa_guest_segv == 0 && reads > 0)
        PASS();
    else
        FAIL("SIGSEGV inside fault-around window");
    if (fa_guest_segv)
        printf("  (%d SIGSEGV, %ld clean reads)\n", (int) fa_guest_segv,
               reads);
}

/* Fault-around must never lose a guest write or leak stale bytes: sequential
 * writes ramp the per-vCPU window to its cap, strided and backward writes
 * must reset it, and every untouched byte of a materialized page must read
 * as zero. */
static void test_fault_around_content(void)
{
    TEST("fault-around zero-fill and write order");
    size_t len = 2UL * 1024 * 1024;
    int ok = 1;
    for (int round = 0; ok && round < 10; round++) {
        unsigned char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            ok = 0;
            break;
        }
        for (size_t off = 0; off < len; off += PAGE_SIZE)
            p[off] = (unsigned char) (off >> 12);
        for (size_t off = 0; ok && off < len; off += PAGE_SIZE)
            ok = p[off] == (unsigned char) (off >> 12) && p[off + 1] == 0 &&
                 p[off + PAGE_SIZE - 1] == 0;
        munmap(p, len);

        p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                 -1, 0);
        if (p == MAP_FAILED) {
            ok = 0;
            break;
        }
        for (size_t off = 0; off < len; off += 3UL * PAGE_SIZE)
            p[off] = 0xA5;
        for (size_t off = 0; ok && off < len; off += PAGE_SIZE) {
            unsigned char want = ((off >> 12) % 3 == 0) ? 0xA5 : 0;
            ok = p[off] == want && p[off + PAGE_SIZE - 1] == 0;
        }
        for (size_t off = len; off > 0; off -= PAGE_SIZE)
            p[off - 1] = 0x5A;
        for (size_t off = 0; ok && off < len; off += PAGE_SIZE)
            ok = p[off + PAGE_SIZE - 1] == 0x5A;
        munmap(p, len);

        /* Sequential reads batch-validate zero aliases; writing afterwards
         * must still COW every page without losing data. */
        p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                 -1, 0);
        if (p == MAP_FAILED) {
            ok = 0;
            break;
        }
        for (size_t off = 0; ok && off < len; off += PAGE_SIZE)
            ok = p[off] == 0 && p[off + PAGE_SIZE - 1] == 0;
        for (size_t off = 0; off < len; off += PAGE_SIZE)
            p[off + 7] = (unsigned char) ((off >> 12) | 1);
        for (size_t off = 0; ok && off < len; off += PAGE_SIZE)
            ok = p[off + 7] == (unsigned char) ((off >> 12) | 1) && p[off] == 0;
        munmap(p, len);
    }
    if (ok)
        PASS();
    else
        FAIL("fault-around corrupted page contents");
}

/* Cross-thread signal delivery cancels the target vCPU. If that cancellation
 * lands while EL1 owns a fault-around MATERIALIZING run, the shim must finish
 * the transaction and restore the saved EL0 frame before the host snapshots
 * registers or writes the signal frame. A direct delivery from the middle of
 * EL1 either corrupts X0-X2, loses the interrupted write, or can recursively
 * wait on the target's own claim while growing the signal stack. */
#define SIGNAL_COW_LEN (8UL * 1024 * 1024)
#define SIGNAL_COW_SIGNALS 1000

static _Atomic int signal_cow_ready;
static _Atomic int signal_cow_stop;
static _Atomic int signal_cow_seen;
static _Atomic int signal_cow_bad;

static void signal_cow_handler(int sig, siginfo_t *info, void *ucontext)
{
    if (sig != SIGUSR1 || !info || info->si_signo != SIGUSR1 || !ucontext)
        atomic_store_explicit(&signal_cow_bad, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&signal_cow_seen, 1, memory_order_release);
}

static void *signal_cow_writer(void *arg)
{
    (void) arg;
    atomic_store_explicit(&signal_cow_ready, 1, memory_order_release);
    unsigned char value = 1;
    while (!atomic_load_explicit(&signal_cow_stop, memory_order_acquire)) {
        unsigned char *p = mmap(NULL, SIGNAL_COW_LEN,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            atomic_store(&signal_cow_bad, 1);
            break;
        }
        for (size_t off = 0; off < SIGNAL_COW_LEN; off += PAGE_SIZE) {
            p[off] = value;
            if (p[off] != value || p[off + 1] != 0)
                atomic_store_explicit(&signal_cow_bad, 1,
                                      memory_order_relaxed);
        }
        if (munmap(p, SIGNAL_COW_LEN) != 0) {
            atomic_store(&signal_cow_bad, 1);
            break;
        }
        value = value == 255 ? 1 : (unsigned char) (value + 1);
    }
    return NULL;
}

static void test_signal_preempts_fault_around(void)
{
    TEST("signal preempts COW fault-around");
    struct sigaction sa = {0}, old_sa;
    sa.sa_sigaction = signal_cow_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, &old_sa) != 0) {
        FAIL("sigaction");
        return;
    }

    atomic_store(&signal_cow_ready, 0);
    atomic_store(&signal_cow_stop, 0);
    atomic_store(&signal_cow_seen, 0);
    atomic_store(&signal_cow_bad, 0);
    pthread_t writer;
    if (pthread_create(&writer, NULL, signal_cow_writer, NULL) != 0) {
        sigaction(SIGUSR1, &old_sa, NULL);
        FAIL("pthread_create");
        return;
    }
    while (!atomic_load_explicit(&signal_cow_ready, memory_order_acquire))
        ;

    int sent = 0;
    for (int i = 0; i < SIGNAL_COW_SIGNALS; i++) {
        int before = atomic_load_explicit(&signal_cow_seen,
                                          memory_order_acquire);
        if (pthread_kill(writer, SIGUSR1) != 0) {
            atomic_store(&signal_cow_bad, 1);
            break;
        }
        sent++;
        /* Avoid standard-signal coalescing: each iteration waits until its
         * delivery completed, continually re-aiming cancellation at the COW
         * stream rather than merely filling one pending bit. */
        while (atomic_load_explicit(&signal_cow_seen, memory_order_acquire) ==
               before)
            sched_yield();
    }
    atomic_store_explicit(&signal_cow_stop, 1, memory_order_release);
    pthread_join(writer, NULL);
    sigaction(SIGUSR1, &old_sa, NULL);

    if (!atomic_load(&signal_cow_bad) && atomic_load(&signal_cow_seen) == sent &&
        sent == SIGNAL_COW_SIGNALS)
        PASS();
    else
        FAIL("signal/COW register or data corruption");
}

int main(void)
{
    printf("test-cow-zero: EL1 and host materialization\n");
    test_fast_mmap_journal();
    test_concurrent_first_write();
    test_host_write_materialization();
    test_short_read_materializes_only_result();
    test_host_read_after_el1_cow();
    test_map_fixed_over_valid_zero();
    test_host_read_in_fault_around_window();
    test_guest_read_in_fault_around_window();
    test_fault_around_content();
    test_signal_preempts_fault_around();
    printf("\ntest-cow-zero: %d passed, %d failed - %s\n", passes, fails,
           fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
