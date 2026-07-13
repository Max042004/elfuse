/*
 * Cross-subsystem lazy-zero regressions
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "test-harness.h"

int passes = 0, fails = 0;

#define PAGE_SIZE 4096
#define COMMIT_LEN (16UL * PAGE_SIZE)

static long futex_call(uint32_t *uaddr,
                       int op,
                       uint32_t val,
                       const struct timespec *timeout)
{
    return syscall(SYS_futex, uaddr, op, val, timeout, NULL, 0);
}

/* Populate the host's one-entry GVA cache with a private identity translation,
 * recycle the same EL1 fast-arena VA, then make read(2) the first writer of the
 * new lazy mapping. Journal synchronization must invalidate the old cache or
 * the byte is written behind the new shared-zero template and disappears. */
static void test_fast_recycle_host_tlb(void)
{
    TEST("fast mmap recycle invalidates host GVA cache");
    int fds[2];
    const uint8_t input[2] = {'A', 'Z'};
    uint8_t *p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED || pipe(fds) != 0) {
        FAIL("setup");
        return;
    }

    /* Seed both bytes before populating gva_tlb. A write(2) between the two
     * read(2) calls would resolve its guest-stack source and evict the
     * single-entry cache, accidentally hiding the stale-generation bug. */
    int ok = write(fds[1], input, sizeof(input)) == (ssize_t) sizeof(input) &&
             read(fds[0], p, 1) == 1 && p[0] == input[0];
    uintptr_t old_addr = (uintptr_t) p;
    ok = ok && munmap(p, PAGE_SIZE) == 0;
    uint8_t *q = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ok = ok && q != MAP_FAILED && (uintptr_t) q == old_addr;
    ok = ok && read(fds[0], q, 1) == 1;
    ok = ok && q[0] == input[1];

    if (q != MAP_FAILED)
        munmap(q, PAGE_SIZE);
    close(fds[0]);
    close(fds[1]);
    if (ok)
        PASS();
    else
        FAIL("host write disappeared behind recycled lazy PTE");
}

struct futex_ctx {
    uint32_t *word;
    _Atomic int stay_alive;
};

static void *futex_waker(void *arg)
{
    struct futex_ctx *ctx = arg;
    usleep(200000);
    atomic_store_explicit((_Atomic uint32_t *) ctx->word, 1,
                          memory_order_release);
    futex_call(ctx->word, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, NULL);
    /* Keep the worker alive: thread exit is itself an interrupt source and can
     * mask a lost wake by making the waiter return EINTR. */
    while (atomic_load_explicit(&ctx->stay_alive, memory_order_acquire))
        sched_yield();
    return NULL;
}

/* Waiting on an untouched lazy page must use the same stable host address as
 * the later wake. Sleeping on the shared zero-page alias loses the wake when
 * the waker's store materializes the futex into its private identity page. */
static void test_untouched_lazy_futex(void)
{
    TEST("untouched lazy futex preserves wakeup");
    uint32_t *word = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (word == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    struct futex_ctx ctx = {.word = word};
    atomic_store(&ctx.stay_alive, 1);
    pthread_t thread;
    if (pthread_create(&thread, NULL, futex_waker, &ctx) != 0) {
        munmap(word, PAGE_SIZE);
        FAIL("pthread_create");
        return;
    }

    struct timespec timeout = {2, 0};
    struct timespec started, finished;
    clock_gettime(CLOCK_MONOTONIC, &started);
    errno = 0;
    long rc = futex_call(word, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, &timeout);
    int saved_errno = errno;
    clock_gettime(CLOCK_MONOTONIC, &finished);
    atomic_store_explicit(&ctx.stay_alive, 0, memory_order_release);
    pthread_join(thread, NULL);
    int64_t elapsed_ms =
        (int64_t) (finished.tv_sec - started.tv_sec) * 1000 +
        (finished.tv_nsec - started.tv_nsec) / 1000000;
    /* The os_sync adapter may report the post-wake value change as EAGAIN;
     * both 0 and EAGAIN tell a correct futex caller to re-check its condition.
     * The regression is a lost key/wake, observed as consuming the timeout. */
    int woke = rc == 0 || (rc == -1 && saved_errno == EAGAIN);
    int ok = woke && elapsed_ms < 1000 &&
             atomic_load_explicit((_Atomic uint32_t *) word,
                                  memory_order_acquire) == 1;
    munmap(word, PAGE_SIZE);
    if (ok)
        PASS();
    else {
        errno = saved_errno;
        FAIL("futex wake was lost");
    }
}

/* A decommitted lazy mapping must not leave its materialized identity bytes
 * available to a later PROT_NONE reserve + mprotect commit at the same VA. */
static void test_lazy_unmap_commit_zero_fill(void)
{
    TEST("lazy munmap preserves reserve/commit zero fill");
    uint8_t *p = mmap(NULL, COMMIT_LEN, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("initial mmap");
        return;
    }
    memset(p, 'A', COMMIT_LEN);
    uintptr_t addr = (uintptr_t) p;
    int ok = munmap(p, COMMIT_LEN) == 0;
    p = mmap((void *) addr, COMMIT_LEN, PROT_NONE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    ok = ok && p != MAP_FAILED && (uintptr_t) p == addr;
    ok = ok && mprotect(p, COMMIT_LEN, PROT_READ | PROT_WRITE) == 0;
    for (size_t i = 0; ok && i < COMMIT_LEN; i++)
        ok = p[i] == 0;
    if (p != MAP_FAILED)
        munmap(p, COMMIT_LEN);
    if (ok)
        PASS();
    else
        FAIL("decommitted backing retained old bytes");
}

int main(void)
{
    printf("test-lazy-zero-critical: cross-subsystem lazy-zero invariants\n");
    test_fast_recycle_host_tlb();
    test_lazy_unmap_commit_zero_fill();
    test_untouched_lazy_futex();
    SUMMARY("test-lazy-zero-critical");
    return fails ? 1 : 0;
}
