/*
 * Fork vs. COW-zero materialization windows
 *
 * A fork snapshot can catch a sibling vCPU (or a host materializer) mid
 * COW-zero materialization: the snapshot then carries a PTE with the
 * MATERIALIZING bit set but no owner in the child to finish the publish.
 * Untreated, the child's first touch of such a page spins forever at EL1
 * (invalid claimed template) or dies with SIGSEGV (valid EL1-only
 * fault-around zeroing-window descriptor).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define PAGE_SIZE 4096
#define REGION_LEN (8UL * 1024 * 1024)
#define ROUNDS 20
#define CHILD_TIMEOUT_MS 5000

static _Atomic uintptr_t cur_region;
static _Atomic int stop_flag;
static _Atomic int streamer_failed;

/* Stream sequential first writes through fresh anonymous mappings so the
 * EL1 fault-around path keeps a materialization window open most of the
 * time. cur_region is cleared before munmap so a fork child never scans an
 * unmapped snapshot region.
 */
static void *first_write_streamer(void *arg)
{
    (void) arg;
    while (!atomic_load_explicit(&stop_flag, memory_order_acquire)) {
        uint8_t *p = mmap(NULL, REGION_LEN, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            atomic_store_explicit(&streamer_failed, 1, memory_order_release);
            break;
        }
        atomic_store_explicit(&cur_region, (uintptr_t) p, memory_order_release);
        for (size_t off = 0; off < REGION_LEN; off += PAGE_SIZE) {
            p[off] = 1;
            if (atomic_load_explicit(&stop_flag, memory_order_relaxed))
                break;
        }
        atomic_store_explicit(&cur_region, 0, memory_order_release);
        munmap(p, REGION_LEN);
    }
    return NULL;
}

/* Touch every page of the streamer's region: reads take the template
 * validate path, writes the materialize path. Either spins or faults on an
 * inherited MATERIALIZING descriptor.
 */
static int child_scan(void)
{
    uint8_t *p =
        (uint8_t *) atomic_load_explicit(&cur_region, memory_order_acquire);
    if (!p)
        return 0;
    volatile uint8_t sink = 0;
    for (size_t off = 0; off < REGION_LEN; off += PAGE_SIZE)
        sink += p[off];
    (void) sink;
    for (size_t off = 0; off < REGION_LEN; off += PAGE_SIZE)
        p[off + 1] = 2;
    return 0;
}

static void test_fork_during_materialization(void)
{
    TEST("fork snapshot vs. COW materializing window");
    pthread_t streamer;
    if (pthread_create(&streamer, NULL, first_write_streamer, NULL) != 0) {
        FAIL("pthread_create");
        return;
    }
    while (!atomic_load_explicit(&cur_region, memory_order_acquire) &&
           !atomic_load_explicit(&streamer_failed, memory_order_acquire))
        sched_yield();

    if (atomic_load_explicit(&streamer_failed, memory_order_acquire)) {
        atomic_store_explicit(&stop_flag, 1, memory_order_release);
        pthread_join(streamer, NULL);
        FAIL("streamer mmap");
        return;
    }

    int ok = 1;
    for (int round = 0; ok && round < ROUNDS; round++) {
        pid_t pid = fork();
        if (pid < 0) {
            ok = 0;
            break;
        }
        if (pid == 0)
            _exit(child_scan());

        int status = 0;
        int waited_ms = 0;
        pid_t r;
        while ((r = waitpid(pid, &status, WNOHANG)) == 0 &&
               waited_ms < CHILD_TIMEOUT_MS) {
            struct timespec ts = {0, 1000L * 1000};
            nanosleep(&ts, NULL);
            waited_ms++;
        }
        if (r == 0) {
            printf("  round %d: child hung, killing\n", round);
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            ok = 0;
        } else if (r != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            printf("  round %d: child status 0x%x\n", round, status);
            ok = 0;
        }
    }

    atomic_store_explicit(&stop_flag, 1, memory_order_release);
    pthread_join(streamer, NULL);
    if (ok)
        PASS();
    else
        FAIL("fork child hung or crashed on inherited MATERIALIZING page");
}

int main(void)
{
    printf("test-fork-cow-mat: fork vs. COW materialization windows\n");
    test_fork_during_materialization();
    printf("\ntest-fork-cow-mat: %d passed, %d failed - %s\n", passes, fails,
           fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
