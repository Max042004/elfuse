/*
 * exit_group teardown reachability for internal condvar parks (issue #158)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * exit_group must terminate the process even when a thread is parked on one
 * of the runtime's internal condvars, which neither the wakeup pipe nor the
 * hv_vcpus_exit kick can reach:
 *
 *   wait: the main thread blocks in wait4 on a SEIZEd tracee that never
 *         stops (parked on ptrace_cond in thread_ptrace_wait) while a worker
 *         calls exit_group. Without the teardown broadcast this deadlocks:
 *         the tracee exits without signalling ptrace_cond (only VM-clone
 *         exits do), so the main thread sleeps forever and guest_destroy is
 *         never reached. The driver timeout turns that hang into a failure.
 *
 *   stop: a tracee is held in ptrace-stop (parked on resume_cond in
 *         thread_ptrace_stop) when the tracer calls exit_group without
 *         PTRACE_CONT. Only the tracer's CONT signals resume_cond, so the
 *         tracee must be woken by the teardown broadcast to exit inside the
 *         join window instead of sleeping past the memory unmap.
 *
 *   fork: exit_group races a fork loop, so siblings are parked on the fork
 *         barrier (fork_cond in thread_fork_barrier_check) when the flag is
 *         set. Their resume normally depends on the forking thread's
 *         progress; the teardown broadcast frees them directly.
 *
 * The tracee/spinner continuously first-writes fresh anonymous pages. Thus the
 * ptrace interrupt and exit_group cancellation also race the EL1 lazy-zero
 * materializer; a canceled owner must rendezvous and publish its claim before
 * entering ptrace-stop or teardown.
 *
 * All scenarios must exit with code 42, carried by exit_group from whichever
 * thread raced the park. PTRACE_SEIZE on a same-thread-group thread fails
 * with EPERM on real Linux (it works on elfuse, where ptrace is scoped to
 * the emulated process); the ptrace scenarios treat SEIZE failure as "park
 * cannot be constructed" and fall through to a plain exit_group(42) so the
 * expected exit code holds under differential testing.
 *
 * Syscalls: clone(220), ptrace(117), wait4(260), nanosleep(101),
 * sched_yield(124), munmap(215), mmap(222), exit(93), exit_group(94)
 */

#include <string.h>

#include "raw-syscall.h"

#define CLONE_THREAD_FLAGS \
    (0x00010000 | 0x00000100 | 0x00000200 | 0x00000800 | 0x00200000)

#define PTRACE_SEIZE 0x4206
#define PTRACE_INTERRUPT 0x4207

#define EXIT_CODE 42

static char killer_stack[16384] __attribute__((aligned(16)));
static char tracee_stack[16384] __attribute__((aligned(16)));
static char spinner_stack[16384] __attribute__((aligned(16)));

static volatile int killer_armed = 0;

#define COW_STREAM_LEN (8UL * 1024 * 1024)
#define PAGE_SIZE 4096
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20

static void msleep(long ms)
{
    struct {
        long tv_sec, tv_nsec;
    } ts = {ms / 1000, (ms % 1000) * 1000000L};
    raw_syscall4(101, (long) &ts, 0, 0, 0); /* nanosleep */
}

/* Terminates the process group from a worker thread after a delay, so the
 * park under test is in place when the exit-group flag is set.
 */
static int killer_fn(void)
{
    killer_armed = 1;
    msleep(200);
    raw_syscall1(94, EXIT_CODE); /* exit_group */
    return 0;
}

/* Stream first writes through fresh lazy-zero mappings. The thread alternates
 * between EL0 and long EL1 fault-around transactions, making ptrace/exit-group
 * cancellation exercise the MATERIALIZING-owner rendezvous. Never exits on
 * its own.
 */
static int spin_fn(void)
{
    unsigned char value = 1;
    for (;;) {
        long addr = raw_syscall6(222, 0, COW_STREAM_LEN,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (addr < 0) {
            raw_syscall0(124); /* sched_yield */
            continue;
        }
        volatile unsigned char *p = (volatile unsigned char *) addr;
        for (unsigned long off = 0; off < COW_STREAM_LEN; off += PAGE_SIZE)
            p[off] = value;
        raw_syscall2(215, addr, COW_STREAM_LEN); /* munmap */
        value = value == 255 ? 1 : (unsigned char) (value + 1);
    }
    return 0;
}

static long spawn_thread(char *stack_top, int (*fn)(void))
{
    long ret = raw_syscall5(220, CLONE_THREAD_FLAGS, (long) stack_top, 0, 0, 0);
    if (ret == 0) {
        fn();
        raw_syscall1(93, 0); /* exit (not reached; fn never returns) */
    }
    return ret;
}

/* wait: park the main thread on ptrace_cond, then exit_group from a worker */
static int scenario_wait(void)
{
    if (spawn_thread(killer_stack + sizeof(killer_stack), killer_fn) < 0)
        return 1;
    while (!killer_armed)
        raw_syscall0(124);

    long tracee = spawn_thread(tracee_stack + sizeof(tracee_stack), spin_fn);
    if (tracee < 0)
        return 1;

    /* SEIZE without INTERRUPT: the tracee keeps spinning and never enters
     * ptrace-stop, so the wait4 below has nothing to report and parks on the
     * tracee's ptrace_cond. EPERM (real Linux) leaves the tracee untraced;
     * wait4 then returns ECHILD immediately and the killer still fires.
     */
    raw_syscall4(117, PTRACE_SEIZE, tracee, 0, 0);

    int status = 0;
    raw_syscall4(260, tracee, (long) &status, 0, 0); /* wait4: parks here */

    /* Only reachable when the park was refused or torn down; wait for the
     * killer's exit_group to take effect.
     */
    for (;;)
        msleep(50);
    return 0;
}

/* stop: hold a tracee in ptrace-stop (parked on resume_cond), then
 * exit_group from the tracer without ever calling PTRACE_CONT.
 */
static int scenario_stop(void)
{
    long tracee = spawn_thread(tracee_stack + sizeof(tracee_stack), spin_fn);
    if (tracee < 0)
        return 1;

    if (raw_syscall4(117, PTRACE_SEIZE, tracee, 0, 0) == 0) {
        raw_syscall4(117, PTRACE_INTERRUPT, tracee, 0, 0);
        /* Blocks until the tracee reaches ptrace-stop, i.e. is parked on
         * resume_cond with nobody left to CONT it after this thread exits.
         */
        int status = 0;
        raw_syscall4(260, tracee, (long) &status, 0, 0);
    }

    raw_syscall1(94, EXIT_CODE); /* exit_group with the tracee still stopped */
    return 0;
}

/* fork: race exit_group against fork barriers quiescing a spinning sibling */
static int scenario_fork(void)
{
    if (spawn_thread(killer_stack + sizeof(killer_stack), killer_fn) < 0)
        return 1;
    if (spawn_thread(spinner_stack + sizeof(spinner_stack), spin_fn) < 0)
        return 1;
    while (!killer_armed)
        raw_syscall0(124);

    /* Fork continuously so a barrier is likely in flight when the killer
     * fires; each child exits immediately and is reaped to keep the process
     * table bounded. The loop only ends when exit_group tears it down.
     */
    for (;;) {
        /* clone with flags=SIGCHLD: plain fork */
        long child = raw_syscall5(220, 17, 0, 0, 0, 0);
        if (child == 0)
            raw_syscall1(94, 0); /* child: exit_group */
        if (child < 0) {
            msleep(1);
            continue;
        }
        int status = 0;
        raw_syscall4(260, (long) (int) child, (long) &status, 0, 0);
    }
    return 0;
}

int main(int argc, char **argv)
{
    int rc;

    if (argc < 2) {
        static const char usage[] =
            "usage: test-exit-group-teardown wait|stop|fork\n";
        raw_syscall3(64, 2, (long) usage, sizeof(usage) - 1); /* write */
        return 2;
    }

    if (!strcmp(argv[1], "wait"))
        rc = scenario_wait();
    else if (!strcmp(argv[1], "stop"))
        rc = scenario_stop();
    else if (!strcmp(argv[1], "fork"))
        rc = scenario_fork();
    else
        rc = 2;

    /* Scenarios normally never return: exit_group(42) ends the process. A
     * return means setup failed; make that a visible wrong exit code.
     */
    raw_syscall1(94, rc);
    return rc;
}
