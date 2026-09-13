/*
 * test-ptrace-interrupt.c -- what PTRACE_INTERRUPT shows when it lands in the
 * EL1 shim.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * PTRACE_INTERRUPT kicks the tracee out of hv_vcpu_run. The kick can land while
 * the tracee is inside an EL1 fast path rather than in EL0 code, and there the
 * live registers are the shim's scratch: the guest's own values are in the
 * saved SVC frame and ELR_EL1 holds the EL0 return the shim still means to ERET
 * through. A stop taken from that state reports scratch through
 * PTRACE_GETREGSET and discards what PTRACE_SETREGSET writes, because the shim
 * restores its frame over it on the way out.
 *
 * The tracee here does nothing but calls the shim answers inline: getpid off
 * the identity cache and a 256-byte urandom read off the entropy ring. Neither
 * reaches the host and neither can block, so the thread is only ever in EL0 or
 * inside the shim, which is what gives the kick somewhere useful to land.
 *
 * Two things are checked at every stop. The reported PC has to be an EL0
 * address, not a shim one: the shim lives just under the interpreter base, at
 * 60 GiB on a 36-bit IPA and 1020 GiB on a 40-bit one, and this guest's own
 * text is under 4 GiB. And the tracee keeps a known value in x21, a
 * callee-saved register its loop never writes, so a snapshot of shim scratch
 * shows something else there.
 *
 * This is an elfuse-internal test. PTRACE_SEIZE of a thread in the caller's own
 * thread group fails with EPERM on Linux, so the reference kernel cannot
 * adjudicate the shape, and what is under test is elfuse's own register
 * snapshot rather than a kernel behavior. The penultimate stop also changes
 * x21, which the final snapshot verifies survived PTRACE_CONT. The tracee
 * signals itself throughout, so a share of the kicks are consumed on the
 * rt_sigreturn tail, which returns on host-rebuilt state.
 *
 * The run closes on a BRK stop. That tail reloads X8 from the shim's saved
 * frame, so the stop has to report the guest's X8 and the X8 the tracer writes
 * there has to be the one the tracee resumes with.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "raw-syscall.h"

#define PTRACE_CONT 7
#define PTRACE_GETREGSET 0x4204
#define PTRACE_SETREGSET 0x4205
#define PTRACE_SEIZE 0x4206
#define PTRACE_INTERRUPT 0x4207
#define NT_PRSTATUS 1

#define CLONE_THREAD_FLAGS 0x00050f00 /* VM|FS|FILES|SIGHAND|THREAD */

/* The tracee's loop never writes x21, so anything else there came from outside
 * the guest's own code.
 */
#define CANARY 0x5ec0ffee5ec0ffeeULL
#define SIGUSR1 10
#define UPDATED_CANARY 0x1234567812345678ULL

/* What the tracee holds in x8 at its BRK, and what the tracer writes over it.
 * The written value is the drop-frame marker's own number, which is the one a
 * reload keyed on the marker takes for it and replaces.
 */
#define BRK_X8 0xc3
#define BRK_X8_WRITTEN 2

/* Between the highest address this guest maps and the lowest the shim uses, so
 * a PC at or above it can only be shim state.
 *
 * Both bounds matter and the earlier value satisfied only one. 64 GiB sits
 * above the shim rather than below it on the common configuration: a 36-bit IPA
 * host gives a 64 GiB guest whose interpreter base is 60 GiB, with the infra
 * reserve and the shim just beneath that, so no shim PC ever reached the
 * comparison and this assertion could not fail there. It separated the two only
 * on a 40-bit guest, whose interpreter base is 1020 GiB.
 *
 * 16 GiB clears this guest's own mappings, whose text is at 4 MiB and whose
 * mmap allocations start at the 8 GiB RW base, and stays far under the shim on
 * either configuration. A guest that mapped 8 GiB of address space would need
 * this raised, which no test here does.
 */
#define EL0_PC_CEILING 0x400000000ULL

/* Enough interrupts that the kick lands inside the shim repeatedly. A
 * regression does not need all of them: one stop reporting scratch fails.
 */
#define ROUNDS 600

typedef struct {
    uint64_t regs[31];
    uint64_t sp, pc, pstate;
} user_pt_regs_t;

typedef struct {
    void *base;
    unsigned long len;
} iovec_t;

static char tracee_stack[64 * 1024] __attribute__((aligned(16)));
static volatile int tracee_ready;
static volatile int tracee_stop;

typedef struct {
    void (*handler)(int);
    unsigned long flags;
    void *restorer;
    unsigned long mask;
} k_sigaction_t;

static volatile int tracee_nosig;
static volatile int tracee_sigs;
static volatile int tracee_quiet;

static volatile int tracee_brk_done;
volatile uint64_t brk_seen_x8;

/* Take a BRK with a known x8 and record the x8 the instruction after it runs
 * with. x21 is left alone: it is the canary the rounds above depend on.
 */
void brk_stub(void);
__asm__(
    ".text\n.globl brk_stub\n.type brk_stub, %function\n"
    "brk_stub:\n"
    "    mov x8, #0xc3\n"
    "    brk #0\n"
    "    adrp x9, brk_seen_x8\n"
    "    add x9, x9, :lo12:brk_seen_x8\n"
    "    str x8, [x9]\n"
    "    ret\n"
    ".size brk_stub, .-brk_stub\n");

/* A stop can land inside this handler, and the canary check upstairs cannot
 * tell which frame it caught. Pin X21 to the value the loop holds so either
 * frame answers the same.
 */
static void tracee_sig_handler(int sig)
{
    register uint64_t canary asm("x21") = CANARY;
    (void) sig;
    tracee_sigs++;
    __asm__ volatile("" : : "r"(canary));
}

/* Mostly calls the shim answers without ever reaching the host: getpid off the
 * identity cache, and a 256-byte urandom read off the entropy ring, which is
 * the longest EL1 run the shim has that cannot block. Nothing here parks, so
 * the thread is always either in EL0 or inside the shim and a kick has
 * somewhere useful to land.
 *
 * The self-signal is the exception, and it is deliberate: rt_sigreturn returns
 * on state the host rebuilt rather than on the shim's saved frame, so it is the
 * one syscall tail that cannot carry the stop request back through the shim. A
 * kick consumed there and not taken is a stop the tracer never sees.
 *
 * That coverage is statistical, not guaranteed: nothing here can observe which
 * tail consumed a given kick, only that the run as a whole raised signals. It
 * holds because the signal cycle dominates the loop, and it was measured to
 * hold, failing at round 0 or 1 every time the inline stop was removed. Thin
 * the signal traffic here and the detector weakens with it.
 */
static int tracee_fn(void)
{
    register uint64_t canary asm("x21") = CANARY;
    unsigned char buf[256];
    int fd = (int) raw_syscall4(56, -100 /* AT_FDCWD */, (long) "/dev/urandom",
                                0 /* O_RDONLY */, 0);

    k_sigaction_t act = {tracee_sig_handler, 0, 0, 0};
    raw_syscall4(134, SIGUSR1, (long) &act, 0, 8); /* rt_sigaction */
    long pid = raw_getpid();
    long tid = raw_gettid();

    tracee_ready = 1;
    while (!tracee_stop) {
        /* Reached only outside a handler: the signal this loop raises is
         * delivered on the tgkill return below, so a handler that started has
         * already returned by the time control is back here. Publishing the
         * acknowledgement here, and never raising another signal once nosig is
         * set, is what lets the tracer know no sigframe is in flight.
         */
        if (tracee_nosig)
            tracee_quiet = 1;

        raw_getpid();
        if (fd >= 0)
            raw_syscall3(63, fd, (long) buf, sizeof(buf)); /* read */
        if (!tracee_nosig)
            raw_tgkill((int) pid, (int) tid, SIGUSR1);
        raw_getpid();
    }

    /* Keep the register live to the end of the loop, or the compiler is free to
     * stop keeping the value there and the check above becomes a tautology.
     */
    __asm__ volatile("" : : "r"(canary));

    brk_stub();
    tracee_brk_done = 1;
    return 0;
}

static long spawn(char *stack_top, int (*fn)(void))
{
    long ret = raw_syscall5(220, CLONE_THREAD_FLAGS, (long) stack_top, 0, 0, 0);
    if (ret == 0) {
        fn();
        raw_syscall1(93, 0); /* exit */
    }
    return ret;
}

static long getregs(long tid, user_pt_regs_t *regs)
{
    iovec_t iov = {regs, sizeof(*regs)};
    return raw_syscall4(117, PTRACE_GETREGSET, tid, NT_PRSTATUS, (long) &iov);
}

static long setregs(long tid, const user_pt_regs_t *regs)
{
    iovec_t iov = {(void *) regs, sizeof(*regs)};
    return raw_syscall4(117, PTRACE_SETREGSET, tid, NT_PRSTATUS, (long) &iov);
}

/* Yield while a wait is likely to be short, then sleep. A pure yield spin is a
 * convoy on the thread table lock the tracee needs to make progress, and a pure
 * sleep costs a millisecond on waits that almost always resolve at once.
 */
static void poll_backoff(int spin)
{
    struct {
        long sec, nsec;
    } ms = {0, 1000000};

    if (spin < 500)
        raw_syscall0(124); /* sched_yield */
    else
        raw_syscall2(101, (long) &ms, 0); /* nanosleep */
}

int main(void)
{
    long stops = 0, el1_pc = 0, bad_canary = 0;

    long tracee = spawn(tracee_stack + sizeof(tracee_stack), tracee_fn);
    if (tracee < 0) {
        printf("FAIL: clone failed (%ld)\n", tracee);
        return 1;
    }
    while (!tracee_ready)
        raw_syscall0(124); /* sched_yield */

    if (raw_syscall4(117, PTRACE_SEIZE, tracee, 0, 0) != 0) {
        printf("FAIL: PTRACE_SEIZE refused\n");
        return 1;
    }

    for (int r = 0; r < ROUNDS; r++) {
        /* Quiesce the self-signal before the SETREGSET rounds and wait for the
         * tracee to acknowledge from outside any handler.
         *
         * Counting rounds is not enough. A stop can catch the tracee inside a
         * handler, SETREGSET then writes x21 into the handler's live set, and
         * the rt_sigreturn that follows restores the sigframe's older x21 over
         * it. The final round would read the pre-write canary and fail a test
         * that is not testing signals at all. The acknowledgement is published
         * at a point no sigframe can be in flight, so the write lands on the
         * loop's own registers.
         */
        if (r == ROUNDS - 4) {
            tracee_nosig = 1;
            for (int spin = 0; spin < 1000 && !tracee_quiet; spin++)
                poll_backoff(spin);
            if (!tracee_quiet) {
                printf("FAIL: tracee never quiesced at round %d\n", r);
                return 1;
            }
        }

        if (raw_syscall4(117, PTRACE_INTERRUPT, tracee, 0, 0) != 0)
            continue;

        /* WNOHANG with a bounded poll rather than a blocking wait4: a stop that
         * never arrives is the regression this file is about, and it should be
         * reported rather than hung on.
         *
         * poll_backoff explains the shape. The budget stays under the 10 s
         * TEST_TIMEOUT in tests/lib/test-runner.sh, so a genuinely lost stop is
         * reported here rather than by the harness watchdog.
         */
        int status = 0;
        long w = -1;
        for (int spin = 0; spin < 1500; spin++) {
            w = raw_syscall4(260, tracee, (long) &status, 1 /* WNOHANG */, 0);
            if (w > 0)
                break;
            poll_backoff(spin);
        }
        if (w <= 0) {
            printf("FAIL: no ptrace-stop within the poll at round %d\n", r);
            return 1;
        }

        user_pt_regs_t regs;
        memset(&regs, 0, sizeof(regs));
        if (getregs(tracee, &regs) != 0) {
            printf("FAIL: GETREGSET refused at round %d\n", r);
            return 1;
        }

        stops++;
        if (regs.pc >= EL0_PC_CEILING)
            el1_pc++;
        uint64_t expected_canary = (r == ROUNDS - 1) ? UPDATED_CANARY : CANARY;
        if (regs.regs[21] != expected_canary)
            bad_canary++;

        if (r == ROUNDS - 2) {
            regs.regs[21] = UPDATED_CANARY;
            if (setregs(tracee, &regs) != 0) {
                printf("FAIL: SETREGSET refused at round %d\n", r);
                return 1;
            }
        }

        raw_syscall4(117, PTRACE_CONT, tracee, 0, 0);
    }

    tracee_stop = 1;

    /* The tracee leaves its loop and takes the BRK. */
    int brk_status = 0;
    long bw = -1;
    for (int spin = 0; spin < 1500; spin++) {
        bw = raw_syscall4(260, tracee, (long) &brk_status, 1 /* WNOHANG */, 0);
        if (bw > 0)
            break;
        poll_backoff(spin);
    }
    if (bw <= 0) {
        printf("FAIL: no ptrace-stop at the BRK\n");
        return 1;
    }

    user_pt_regs_t brk_regs;
    memset(&brk_regs, 0, sizeof(brk_regs));
    if (getregs(tracee, &brk_regs) != 0) {
        printf("FAIL: GETREGSET refused at the BRK stop\n");
        return 1;
    }
    if (brk_regs.regs[8] != BRK_X8) {
        printf("FAIL: the BRK stop reports x8 = 0x%llx, want 0x%x\n",
               (unsigned long long) brk_regs.regs[8], BRK_X8);
        return 1;
    }

    brk_regs.regs[8] = BRK_X8_WRITTEN;
    brk_regs.pc += 4; /* past the BRK */
    if (setregs(tracee, &brk_regs) != 0) {
        printf("FAIL: SETREGSET refused at the BRK stop\n");
        return 1;
    }
    raw_syscall4(117, PTRACE_CONT, tracee, 0, 0);

    for (int spin = 0; spin < 1500 && !tracee_brk_done; spin++)
        poll_backoff(spin);
    if (!tracee_brk_done) {
        printf("FAIL: the tracee never resumed past the BRK\n");
        return 1;
    }
    if (brk_seen_x8 != BRK_X8_WRITTEN) {
        printf(
            "FAIL: resumed past the BRK with x8 = 0x%llx, want the 0x%x "
            "the tracer wrote\n",
            (unsigned long long) brk_seen_x8, BRK_X8_WRITTEN);
        return 1;
    }

    if (stops == 0) {
        printf("FAIL: no ptrace-stop was ever taken\n");
        return 1;
    }
    if (el1_pc) {
        printf("FAIL: %ld of %ld stops reported a PC above EL0 (shim state)\n",
               el1_pc, stops);
        return 1;
    }
    if (bad_canary) {
        printf("FAIL: %ld of %ld stops reported x21 as scratch\n", bad_canary,
               stops);
        return 1;
    }
    if (tracee_sigs == 0) {
        printf("FAIL: the tracee never took its own signal\n");
        return 1;
    }
    printf("OK: ptrace-stop reports EL0 state (%ld stops, %d signals)\n", stops,
           tracee_sigs);
    return 0;
}
