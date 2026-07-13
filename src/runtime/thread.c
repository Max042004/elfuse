/*
 * Per-thread state for Linux threading support
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Thread table with _Thread_local fast path for current thread access.
 * Protected by a mutex since thread creation/destruction is infrequent relative
 * to per-syscall access (which uses the lock-free TLS pointer).
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>

#include "utils.h"

#include "runtime/thread.h"
#include "debug/log.h"
#include "core/guest.h"   /* guest_t (shim_data_base/ipa_base), BLOCK_2MIB */
#include "hvutil.h"       /* vcpu_get_gpr, vcpu_get_sysreg */
#include "syscall/proc.h" /* proc_exit_group_requested */

/* From syscall/signal.h, included here directly to avoid pulling in the full
 * signal header (macOS defines sa_handler as a macro that conflicts with the
 * linux_sigaction_t field name).
 */
#define LINUX_SS_DISABLE 2

static void thread_ptrace_init(thread_entry_t *t);
static int thread_add_deferred_unmap_locked(thread_entry_t *t,
                                            uint64_t start,
                                            uint64_t end);
static int thread_can_add_deferred_unmap_locked(thread_entry_t *t,
                                                uint64_t start,
                                                uint64_t end);

/* Top of the EL1 exception stack region (one 4KiB slot per thread). The shim
 * data block sits at high IPA, computed at guest_init time and stored in
 * g->shim_data_base; the top of the EL1 stacks is the next 2MiB boundary above
 * that. Caller must hold a guest_t reference.
 */
static inline uint64_t sp_el1_top(const guest_t *g)
{
    return g->ipa_base + g->shim_data_base + BLOCK_2MIB;
}

/* Thread table. */

static thread_entry_t thread_table[MAX_THREADS];
static pthread_mutex_t thread_lock =
    PTHREAD_MUTEX_INITIALIZER; /* Lock order: 5 */
static _Atomic int active_thread_count = 0;

/* Fork barrier state. Protected by thread_lock. Declared here (rather than
 * beside thread_quiesce_siblings) because thread_deactivate, earlier in the
 * file, hands its count back when a counted sibling exits before the barrier.
 */
static bool fork_quiesce_active = false; /* True while a fork is in progress */
static int fork_quiesced_count = 0;      /* Siblings blocked on barrier */
static int fork_target_count = 0;        /* Number of siblings to quiesce */
static pthread_cond_t fork_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t fork_all_quiesced_cond = PTHREAD_COND_INITIALIZER;

/* Iterate every slot. */
#define THREAD_FOR_EACH(t) \
    for (thread_entry_t *t = thread_table; t < thread_table + MAX_THREADS; t++)

/* Iterate active slots. Caller must hold thread_lock; the lock already orders
 * these reads against the release-stores of active, so a relaxed atomic load
 * suffices. It is used (rather than a plain read) only to keep every access to
 * active uniformly atomic -- no mixed atomic-write / plain-read on one object.
 */
#define THREAD_FOR_EACH_ACTIVE(t) \
    THREAD_FOR_EACH (t)           \
        if (__atomic_load_n(&t->active, __ATOMIC_RELAXED))

/* Iterate active slots without holding thread_lock. Uses an acquire load on the
 * active flag so the lock-free observers in thread_tid_alive() and
 * thread_signal_deliverable() see a consistent transition.
 */
#define THREAD_FOR_EACH_ACTIVE_RELAXED(t) \
    THREAD_FOR_EACH (t)                   \
        if (__atomic_load_n(&t->active, __ATOMIC_ACQUIRE))

/* Bitmask tracking allocated SP_EL1 slots. Bit N set = slot N in use.
 * MAX_THREADS=64 fits exactly in a uint64_t. Slot 0 is the main thread (top of
 * shim data region); each subsequent slot is 4KiB below.
 */
static uint64_t sp_el1_allocated = 0;

/* Per-thread pointer to the current thread's entry. Set once when a host
 * pthread starts running a guest vCPU. Syscall handlers read this without
 * locking since it is thread-local and never changes after init.
 */
_Thread_local thread_entry_t *current_thread = NULL;

/* Public API */

void thread_init(void)
{
    pthread_mutex_lock(&thread_lock);
    memset(thread_table, 0, sizeof(thread_table));
    sp_el1_allocated = 0;
    atomic_store(&active_thread_count, 0);
    current_thread = NULL;
    pthread_mutex_unlock(&thread_lock);
}

void thread_register_main(hv_vcpu_t vcpu,
                          hv_vcpu_exit_t *vexit,
                          int64_t tid,
                          uint64_t sp_el1)
{
    pthread_mutex_lock(&thread_lock);

    thread_entry_t *t = &thread_table[0];
    t->guest_tid = tid;
    t->vcpu = vcpu;
    t->vexit = vexit;
    t->host_thread = pthread_self();
    t->host_thread_needs_join = false; /* Never join the process main thread */
    t->clear_child_tid = 0;
    t->sp_el1 = sp_el1;
    t->sp_el1_slot = 0; /* Main thread always owns slot 0 */
    t->altstack_flags = LINUX_SS_DISABLE;
    t->on_altstack = false;
    thread_ptrace_init(t);
    /* Release-store so a lock-free scanner that acquire-loads active == 1 sees
     * this slot's initialized fields (see thread_pending_union,
     * thread_tid_alive).
     */
    __atomic_store_n(&t->active, 1, __ATOMIC_RELEASE);

    /* Slot 0 is consumed by main thread */
    sp_el1_allocated = BIT64(0);
    atomic_store(&active_thread_count, 1);

    pthread_mutex_unlock(&thread_lock);

    /* Set TLS pointer for the main thread */
    current_thread = t;
}

thread_entry_t *thread_alloc(int64_t tid,
                             uint64_t stack_start,
                             uint64_t stack_end)
{
    thread_entry_t *result = NULL;

    pthread_mutex_lock(&thread_lock);
rescan:
    THREAD_FOR_EACH (t) {
        if (__atomic_load_n(&t->active, __ATOMIC_RELAXED))
            continue;
        /* Skip slots where a tracer is still inside pthread_cond_wait on
         * ptrace_cond. Memset+reinit while a waiter holds a reference is UB.
         */
        if (t->ptrace_conds_inited && t->ptrace_waiters > 0)
            continue;
        /* Reap the previous occupant's pthread before reusing the slot. Workers
         * that exit on their own are joinable but never joined
         * (thread_join_workers snapshots active entries only), so dropping the
         * handle in the memset below would leak its pthread bookkeeping for the
         * process lifetime. active == 0 means the pthread is already past
         * thread_deactivate, so the join blocks at most for its final wind-down
         * -- but that wind-down can take thread_lock (the last-worker wakeup
         * calls thread_interrupt_all), so the join must run with the lock
         * dropped. Claim the handle first so no one else joins it, then rescan:
         * the table may have changed while unlocked.
         */
        if (t->host_thread_needs_join) {
            pthread_t stale = t->host_thread;
            t->host_thread_needs_join = false;
            pthread_mutex_unlock(&thread_lock);
            pthread_join(stale, NULL);
            pthread_mutex_lock(&thread_lock);
            goto rescan;
        }
        if (t->ptrace_conds_inited) {
            pthread_cond_destroy(&t->ptrace_cond);
            pthread_cond_destroy(&t->resume_cond);
        }
        /* Bump generation across the memset so a caller still holding this
         * slot's pointer from before reuse (e.g. a clone parent racing its own
         * worker's startup-failure path) can detect the recycle via
         * thread_set_host_thread's generation check instead of writing into
         * what is now a different logical thread.
         */
        uint64_t next_generation = t->generation + 1;
        memset(t, 0, sizeof(*t));
        t->generation = next_generation;
        t->sp_el1_slot = -1; /* No SP_EL1 yet; thread_alloc_sp_el1 fills this */
        t->guest_tid = tid;
        if (stack_start < stack_end) {
            t->stack_map_start = stack_start;
            t->stack_map_end = stack_end;
        }
        t->altstack_flags = LINUX_SS_DISABLE;
        thread_ptrace_init(t);
        /* Release-store last so a lock-free scanner that observes active == 1
         * also sees the zeroed tpending / guest_tid set above.
         */
        __atomic_store_n(&t->active, 1, __ATOMIC_RELEASE);
        atomic_fetch_add(&active_thread_count, 1);
        result = t;
        break;
    }
    pthread_mutex_unlock(&thread_lock);

    return result;
}

/* Free an SP_EL1 slot for reuse. Must be called with thread_lock held. Reads
 * the slot index recorded at allocation time and clears the bit.
 */
static void thread_free_sp_el1_locked(thread_entry_t *t)
{
    int slot = t->sp_el1_slot;
    if (RANGE_CHECK(slot, 0, MAX_THREADS))
        sp_el1_allocated &= ~BIT64(slot);
    t->sp_el1 = 0;
    t->sp_el1_slot = -1;
}

static void thread_ptrace_cleanup_locked(thread_entry_t *t)
{
    if (!t->ptrace_conds_inited ||
        __atomic_load_n(&t->active, __ATOMIC_RELAXED) || t->ptrace_waiters != 0)
        return;

    pthread_cond_destroy(&t->ptrace_cond);
    pthread_cond_destroy(&t->resume_cond);
    t->ptrace_conds_inited = false;
    t->ptrace_cleanup_pending = false;
}

bool thread_set_host_thread(thread_entry_t *t,
                            pthread_t thr,
                            bool joinable,
                            uint64_t generation)
{
    pthread_mutex_lock(&thread_lock);
    bool recorded = (t->generation == generation);
    if (recorded) {
        t->host_thread = thr;
        t->host_thread_needs_join = joinable;
    }
    pthread_mutex_unlock(&thread_lock);

    return recorded;
}

bool thread_claim_worker_join(thread_entry_t *t, pthread_t thr)
{
    pthread_mutex_lock(&thread_lock);
    bool claimed =
        t->host_thread_needs_join && pthread_equal(t->host_thread, thr);
    if (claimed)
        t->host_thread_needs_join = false;
    pthread_mutex_unlock(&thread_lock);

    return claimed;
}

void thread_fork_release_counted_locked(thread_entry_t *t)
{
    /* Caller holds thread_lock. If a fork snapshot counted this slot but it is
     * exiting or failing bring-up before it could reach
     * thread_fork_barrier_check, hand its count back so thread_quiesce_siblings
     * is not stalled the full timeout waiting for a thread that will never
     * arrive. Guarded by fork_counted so a slot created after the barrier armed
     * (never counted) does not over-decrement. No-op when no barrier is armed.
     */
    if (fork_quiesce_active && t->fork_counted) {
        t->fork_counted = false;
        fork_target_count--;
        if (fork_quiesced_count >= fork_target_count)
            pthread_cond_signal(&fork_all_quiesced_cond);
    }
}

void thread_deactivate(thread_entry_t *t)
{
    if (!t)
        return;

    pthread_mutex_lock(&thread_lock);

    /* If this is a VM-clone child, mark it as exited and wake the tracer/parent
     * so wait4 can collect the exit status. Must happen BEFORE destroying the
     * condvars, since broadcasting a destroyed condvar is undefined behavior.
     * Guard against double-deactivation: if already inactive, skip.
     */
    if (!__atomic_load_n(&t->active, __ATOMIC_RELAXED)) {
        pthread_mutex_unlock(&thread_lock);
        return;
    }

    if (t->is_vm_clone) {
        t->vm_exited = true;
        pthread_cond_broadcast(&t->ptrace_cond);
    }

    /* Free SP_EL1 slot so it can be reused by future threads */
    thread_free_sp_el1_locked(t);

    /* Release store: everything this thread did -- including its last guest
     * memory access -- must happen-before thread_join_workers' acquire load
     * observing 0, or the joiner could green-light guest_destroy's unmap
     * while stores are still in flight. The joiner polls lock-free, so the
     * mutex held here provides no edge to it.
     */
    __atomic_store_n(&t->active, 0, __ATOMIC_RELEASE);
    atomic_fetch_sub(&active_thread_count, 1);

    thread_fork_release_counted_locked(t);

    /* Destroy condvars once no waiters still reference them. A tracer woken by
     * the broadcast above may still be re-acquiring thread_lock.
     */
    t->ptrace_cleanup_pending = true;
    thread_ptrace_cleanup_locked(t);

    pthread_mutex_unlock(&thread_lock);

    /* The slot is now inactive, so thread_pending_union() excludes it.
     * Recompute the global pending hint so any thread-directed signal left
     * unconsumed in this thread's private set stops pinning the
     * identity-syscall fast path off for the surviving threads. Done outside
     * thread_lock to honor sig_lock (4) before thread_lock (5).
     */
    signal_refresh_pending_hint();
}

thread_entry_t *thread_find(int64_t tid)
{
    thread_entry_t *result = NULL;

    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH_ACTIVE (t) {
        if (t->guest_tid == tid) {
            result = t;
            break;
        }
    }
    pthread_mutex_unlock(&thread_lock);

    return result;
}

thread_entry_t *thread_find_locked(int64_t tid)
{
    THREAD_FOR_EACH_ACTIVE (t) {
        if (t->guest_tid == tid)
            return t;
    }
    return NULL;
}

uint64_t thread_pending_union(void)
{
    /* Lock-free active scan; sig_lock (held by the caller) already serializes
     * every tpending write, so reads here are stable. A slot mid-(de)activation
     * only ever contributes extra bits, which the caller treats as a harmless
     * false positive in the pending hint.
     */
    uint64_t u = 0;
    THREAD_FOR_EACH_ACTIVE_RELAXED (t)
        u |= t->tpending.pending;
    return u;
}

int thread_tid_alive(int64_t tid)
{
    /* Lock-free scan: active transitions 1->0 exactly once (in
     * thread_deactivate under thread_lock), and guest_tid is set at allocation
     * and never changes until the slot is reused (after active=0). A stale read
     * of active=1 for a thread being deactivated is benign; the caller retries
     * on the next poll iteration (100ms later).
     */
    THREAD_FOR_EACH_ACTIVE_RELAXED (t)
        if (t->guest_tid == tid)
            return 1;
    return 0;
}

int thread_active_count(void)
{
    return atomic_load(&active_thread_count);
}

int thread_is_single_active(void)
{
    return atomic_load(&active_thread_count) == 1;
}

int thread_count_active_vm_clones(void)
{
    int count = 0;

    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH_ACTIVE (t)
        if (t->is_vm_clone && !t->vm_exited)
            count++;
    pthread_mutex_unlock(&thread_lock);

    return count;
}

uint64_t thread_alloc_sp_el1(const guest_t *g, thread_entry_t *t)
{
    uint64_t sp = 0;

    pthread_mutex_lock(&thread_lock);

    /* Find the first free slot (lowest clear bit in the bitmask). */
    uint64_t free_mask = ~sp_el1_allocated & bit_mask64_low(MAX_THREADS);
    if (free_mask == 0) {
        log_error("thread: SP_EL1 slots exhausted");
    } else {
        int slot = bit_ctz64(free_mask);
        /* Main thread's SP_EL1 sits at the top of the shim data block. Each
         * subsequent thread is 4KiB below.
         */
        uint64_t top = sp_el1_top(g);
        sp = top - (uint64_t) slot * 4096;
        sp_el1_allocated |= BIT64(slot);
        t->sp_el1 = sp;
        t->sp_el1_slot = slot;
    }

    pthread_mutex_unlock(&thread_lock);

    return sp;
}

void thread_for_each(void (*fn)(thread_entry_t *t, void *ctx), void *ctx)
{
    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH_ACTIVE (t)
        fn(t, ctx);
    pthread_mutex_unlock(&thread_lock);
}

bool thread_join_workers(void)
{
    /* Snapshot worker threads under the lock. The code needs the host_thread
     * handle and a way to check the active flag without re-locking. Storing the
     * table entry pointer lets the loop use __atomic_load on active. Claim each
     * joinable handle here (clear host_thread_needs_join) so a concurrent slot
     * reuse in thread_alloc cannot join the same pthread twice. Unclaimed
     * entries -- vm-clone children (created detached) and the main thread's
     * slot when a worker drives teardown -- are still polled below so teardown
     * waits for them to leave the guest, but their handle is never joined or
     * detached. Entries a previous pass already detached (join_abandoned) are
     * skipped outright: joining or detaching the same pthread twice is
     * undefined, and main()'s join is followed by guest_destroy's internal one.
     */
    struct {
        pthread_t thr;
        thread_entry_t *t;
        uint64_t generation;
        bool claimed;
        bool recycled;
    } workers[MAX_THREADS];
    int nworkers = 0;
    bool abandoned_active = false;

    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH (t) {
        if (t == current_thread)
            continue;
        if (t->join_abandoned) {
            if (__atomic_load_n(&t->active, __ATOMIC_ACQUIRE))
                abandoned_active = true;
            continue;
        }
        /* Never wait for the main thread (slot 0): its entry only deactivates
         * inside guest_destroy, which runs on the main thread AFTER its own
         * thread_join_workers. A worker waiting here (exit_group called from
         * a worker) would burn the full cap on it, and the resulting mutual
         * wait (worker polling main while main polls the worker) ends in
         * pthread_detach on both sides, leaving the loser to touch guest
         * memory after guest_destroy unmaps it.
         */
        if (t == &thread_table[0])
            continue;
        /* Inactive slots are included when they still hold an unjoined handle:
         * a worker that exited on its own shortly before teardown and whose
         * slot was never reused. Its pthread has terminated (or is in final
         * wind-down), so the join below is immediate.
         */
        if (!__atomic_load_n(&t->active, __ATOMIC_RELAXED) &&
            !t->host_thread_needs_join)
            continue;
        workers[nworkers].thr = t->host_thread;
        workers[nworkers].t = t;
        workers[nworkers].generation = t->generation;
        workers[nworkers].claimed = t->host_thread_needs_join;
        workers[nworkers].recycled = false;
        t->host_thread_needs_join = false;
        nworkers++;
    }
    pthread_mutex_unlock(&thread_lock);

    /* Poll under one shared 500ms deadline OUTSIDE the lock, then join or
     * detach each worker. Workers that responded to hv_vcpus_exit typically
     * finish within microseconds; the cap only matters for workers parked in
     * host blocking calls, and it must exceed the worst-case teardown-flag
     * re-check latency of every such state or a worker that WOULD wind down
     * cleanly gets abandoned on timing alone: the interruptible io wait
     * re-checks every 200ms (io.c wait helper) and the futex paths every 100ms
     * (FUTEX_OS_SYNC_POLL_CAP_NS quanta), so 500ms covers the slowest bound
     * with margin. One shared deadline keeps worst-case shutdown at the cap
     * even with many stuck workers, rather than multiplying a per-worker cap
     * by nworkers. A worker still alive past the cap is detached and, if this
     * pass claimed its handle, marked join_abandoned so a later pass does not
     * touch it again. The vCPU is NOT destroyed here because HVF vCPUs are
     * thread-affine, so cross-thread hv_vcpu_destroy while the owning thread
     * may still be inside hv_vcpu_run is unsafe.
     */
    for (int i = 0; i < 100; i++) {
        bool any_active = false;
        for (int w = 0; w < nworkers; w++) {
            if (workers[w].recycled)
                continue;
            if (!__atomic_load_n(&workers[w].t->active, __ATOMIC_ACQUIRE))
                continue;
            /* The slot may have been reused for a new logical thread while we
             * polled: thread_alloc only recycles a slot once its previous
             * occupant is inactive, so a generation bump here proves our
             * snapshotted worker already deactivated even though the slot now
             * reads active == 1 again for the replacement thread. Stop
             * tracking this worker's active bit for the rest of the loop
             * rather than following the wrong thread.
             */
            if (workers[w].t->generation != workers[w].generation) {
                workers[w].recycled = true;
                continue;
            }
            any_active = true;
        }
        if (!any_active)
            break;
        usleep(5000);
    }

    bool all_stopped = !abandoned_active;
    for (int w = 0; w < nworkers; w++) {
        bool stopped =
            workers[w].recycled ||
            !__atomic_load_n(&workers[w].t->active, __ATOMIC_ACQUIRE);
        if (!stopped)
            all_stopped = false;
        if (!workers[w].claimed)
            continue;
        /* recycled short-circuits before the active re-check: once recycled,
         * that bit belongs to the replacement thread and must not influence the
         * join-vs-detach decision for our (already-terminated) handle.
         */
        if (stopped) {
            pthread_join(workers[w].thr, NULL);
        } else {
            pthread_detach(workers[w].thr);
            pthread_mutex_lock(&thread_lock);
            workers[w].t->join_abandoned = true;
            pthread_mutex_unlock(&thread_lock);
        }
    }
    return all_stopped;
}

void thread_destroy_all_vcpus(void)
{
    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH_ACTIVE (t) {
        if (!t->vcpu)
            continue;
        hv_vcpu_destroy(t->vcpu);
        t->vcpu = 0;
        thread_free_sp_el1_locked(t);
        __atomic_store_n(&t->active, 0, __ATOMIC_RELEASE);
        /* Do NOT destroy condvars. Same race as thread_deactivate: a waiter
         * woken by an earlier broadcast may still reference the condvar.
         * Process is exiting, so the leak is harmless.
         */
    }
    atomic_store(&active_thread_count, 0);
    pthread_mutex_unlock(&thread_lock);
}

void thread_interrupt_all(void)
{
    /* Collect active vCPUs under the lock, then call hv_vcpus_exit outside the
     * lock to avoid holding it during a framework call.
     */
    hv_vcpu_t vcpus[MAX_THREADS];
    int count = 0;

    pthread_mutex_lock(&thread_lock);
    THREAD_FOR_EACH_ACTIVE (t)
        if (t->vcpu) /* skip slots whose vCPU was already torn down */
            vcpus[count++] = t->vcpu;
    pthread_mutex_unlock(&thread_lock);

    /* Force all active vCPUs out of hv_vcpu_run(). Each vCPU will see
     * HV_EXIT_REASON_CANCELED and check for pending signals.
     */
    if (count > 0)
        hv_vcpus_exit(vcpus, (uint32_t) count);
}

int thread_signal_deliverable(uint64_t sigbit)
{
    /* Lock-free scan: each thread's blocked field is written under sig_lock
     * (lock order 4), but the code reads it without locking here. A stale read
     * is benign: worst case is a harmless spurious interrupt after reading
     * blocked=0 concurrently with a transition to blocked=1, or a delayed
     * delivery corrected by the next signal_pending() check.
     */
    THREAD_FOR_EACH_ACTIVE_RELAXED (t) {
        uint64_t mask = __atomic_load_n(&t->blocked, __ATOMIC_ACQUIRE);
        if (sigbit & ~mask)
            return 1;
    }
    return 0;
}

/* Fork quiesce. */

static pthread_cond_t deferred_stack_unmap_cond = PTHREAD_COND_INITIALIZER;

void thread_quiesce_siblings(void)
{
    hv_vcpu_t vcpus[MAX_THREADS];
    int count = 0;
    int targets = 0;

    pthread_mutex_lock(&thread_lock);

    /* Count every active sibling. Startup siblings may not have published a
     * vCPU yet, but once they do they check the barrier before guest entry.
     * fork_counted marks the slots that owe the barrier a response, so a
     * sibling that exits before arriving can hand its count back (see
     * thread_deactivate) instead of stalling the forker the full timeout.
     */
    THREAD_FOR_EACH_ACTIVE (t) {
        if (t == current_thread)
            continue;
        t->fork_counted = true;
        targets++;
        if (t->vcpu)
            vcpus[count++] = t->vcpu;
    }

    if (targets == 0) {
        pthread_mutex_unlock(&thread_lock);
        return;
    }

    /* Arm the barrier */
    fork_quiesce_active = true;
    fork_quiesced_count = 0;
    fork_target_count = targets;

    pthread_mutex_unlock(&thread_lock);

    /* Force siblings out of hv_vcpu_run */
    if (count > 0)
        hv_vcpus_exit(vcpus, (uint32_t) count);

    /* Wait until all siblings have blocked on the barrier. Use a bounded wait:
     * siblings in long-running host syscalls (poll, read, accept) may not reach
     * the barrier check promptly since hv_vcpus_exit only affects threads
     * inside hv_vcpu_run. After the timeout, proceed with the snapshot; the
     * sibling is blocked in a host syscall and not mutating guest memory.
     */
    pthread_mutex_lock(&thread_lock);
    if (fork_quiesced_count < fork_target_count) {
        struct timespec deadline;
        timespec_deadline_in_ms(&deadline, 100);
        while (fork_quiesced_count < fork_target_count) {
            int rc = pthread_cond_timedwait(&fork_all_quiesced_cond,
                                            &thread_lock, &deadline);
            if (rc == ETIMEDOUT)
                break; /* Proceed with snapshot anyway */
        }
    }
    pthread_mutex_unlock(&thread_lock);
}

void thread_resume_siblings(void)
{
    pthread_mutex_lock(&thread_lock);
    fork_quiesce_active = false;
    fork_quiesced_count = 0;
    fork_target_count = 0;
    /* Clear any fork_counted still set on siblings that never reached the
     * barrier (blocked in a host syscall and released by the timeout) so the
     * next barrier generation starts from a clean slate.
     */
    THREAD_FOR_EACH (t)
        t->fork_counted = false;
    pthread_cond_broadcast(&fork_cond);
    pthread_mutex_unlock(&thread_lock);
}

int thread_fork_barrier_check(void)
{
    pthread_mutex_lock(&thread_lock);
    if (!fork_quiesce_active) {
        pthread_mutex_unlock(&thread_lock);
        return 0;
    }

    /* Only a thread that thread_quiesce_siblings counted contributes to the
     * quiesced tally, and only once. A thread created after the barrier armed
     * (fork_counted == false) still blocks below so it cannot run guest code
     * during the snapshot, but must not inflate fork_quiesced_count past
     * fork_target_count and let the forker proceed before a real sibling has
     * stopped.
     */
    if (current_thread && current_thread->fork_counted) {
        current_thread->fork_counted = false;
        if (++fork_quiesced_count >= fork_target_count)
            pthread_cond_signal(&fork_all_quiesced_cond);
    }

    /* Block until fork is complete. Bail out on exit_group: the resume
     * broadcast comes from the forking thread, whose progress the teardown
     * path does not control, so waiting for it would leave this park outside
     * the bounded-wake guarantee. thread_wake_exit_waiters broadcasts
     * fork_cond after the flag is set; the caller's run loop re-checks
     * proc_exit_group_requested and exits.
     */
    while (fork_quiesce_active && !proc_exit_group_requested())
        pthread_cond_wait(&fork_cond, &thread_lock);

    pthread_mutex_unlock(&thread_lock);
    return 1;
}

void thread_wake_exit_waiters(void)
{
    pthread_mutex_lock(&thread_lock);

    /* Fork barrier: siblings parked in thread_fork_barrier_check. Their wait
     * loop re-checks proc_exit_group_requested on wake.
     */
    pthread_cond_broadcast(&fork_cond);

    /* Ptrace parks: tracers blocked in thread_ptrace_wait (ptrace_cond) and
     * tracees blocked in thread_ptrace_stop (resume_cond). Scan every slot
     * with live condvars, not just active ones: a tracer may still be parked
     * on a slot whose thread was deactivated. ptrace_conds_inited only
     * transitions under thread_lock with ptrace_waiters == 0, so broadcasting
     * here never touches a destroyed condvar.
     */
    THREAD_FOR_EACH (t) {
        if (!t->ptrace_conds_inited)
            continue;
        pthread_cond_broadcast(&t->ptrace_cond);
        pthread_cond_broadcast(&t->resume_cond);
    }

    pthread_mutex_unlock(&thread_lock);
}

/* Ptrace helpers. */

pthread_mutex_t *thread_get_lock(void)
{
    return &thread_lock;
}

int thread_collect_and_defer_stack_ranges(
    uint64_t start,
    uint64_t end,
    thread_deferred_stack_unmap_txn_t *txns,
    int max_ranges)
{
    int nranges = 0;

    if (start >= end || !txns || max_ranges <= 0)
        return 0;

    pthread_mutex_lock(&thread_lock);
retry:
    nranges = 0;

    /* Pass 1: enumerate every thread whose live stack overlaps [start, end) and
     * verify each one can record a new deferred-unmap entry. If the
     * caller-provided buffer is too small or any thread is at its
     * deferred-unmap cap, refuse the whole operation so pass 2 never has to
     * handle a partial commit.
     */
    THREAD_FOR_EACH_ACTIVE (t) {
        uint64_t rs = t->stack_map_start;
        uint64_t re = t->stack_map_end;

        if (rs >= re || re <= start || rs >= end)
            continue;
        if (t->deferred_stack_unmap_busy > 0) {
            pthread_cond_wait(&deferred_stack_unmap_cond, &thread_lock);
            goto retry;
        }
        if (nranges >= max_ranges) {
            pthread_mutex_unlock(&thread_lock);
            return -1;
        }
        uint64_t ds = (rs > start) ? rs : start;
        uint64_t de = (re < end) ? re : end;
        if (thread_can_add_deferred_unmap_locked(t, ds, de) < 0) {
            pthread_mutex_unlock(&thread_lock);
            return -1;
        }

        txns[nranges].thread = t;
        txns[nranges].guest_tid = t->guest_tid;
        txns[nranges].start = ds;
        txns[nranges].end = de;
        txns[nranges].deferred_count = t->deferred_stack_unmap_count;
        for (int j = 0; j < t->deferred_stack_unmap_count; j++) {
            txns[nranges].deferred_starts[j] =
                t->deferred_stack_unmap_starts[j];
            txns[nranges].deferred_ends[j] = t->deferred_stack_unmap_ends[j];
        }
        nranges++;
    }
    /* Pass 2: commit. Both passes iterate the table in the same order under the
     * same lock, so the active set seen here matches pass 1.
     */
    for (int i = 0; i < nranges; i++) {
        (void) thread_add_deferred_unmap_locked(txns[i].thread, txns[i].start,
                                                txns[i].end);
        txns[i].thread->deferred_stack_unmap_busy++;
    }
    pthread_mutex_unlock(&thread_lock);

    return nranges;
}

void thread_finish_deferred_stack_ranges(
    const thread_deferred_stack_unmap_txn_t *txns,
    int nranges)
{
    bool wake = false;

    if (!txns || nranges <= 0)
        return;

    pthread_mutex_lock(&thread_lock);
    for (int i = 0; i < nranges; i++) {
        thread_entry_t *t = txns[i].thread;

        if (!t || !__atomic_load_n(&t->active, __ATOMIC_RELAXED) ||
            t->guest_tid != txns[i].guest_tid ||
            t->deferred_stack_unmap_busy <= 0)
            continue;
        t->deferred_stack_unmap_busy--;
        wake = true;
    }
    if (wake)
        pthread_cond_broadcast(&deferred_stack_unmap_cond);
    pthread_mutex_unlock(&thread_lock);
}

void thread_rollback_deferred_stack_ranges(
    const thread_deferred_stack_unmap_txn_t *txns,
    int nranges)
{
    bool wake = false;

    if (!txns || nranges <= 0)
        return;

    pthread_mutex_lock(&thread_lock);
    for (int i = 0; i < nranges; i++) {
        thread_entry_t *t = txns[i].thread;

        if (!t || !__atomic_load_n(&t->active, __ATOMIC_RELAXED) ||
            t->guest_tid != txns[i].guest_tid)
            continue;
        t->deferred_stack_unmap_count = txns[i].deferred_count;
        for (int j = 0; j < txns[i].deferred_count; j++) {
            t->deferred_stack_unmap_starts[j] = txns[i].deferred_starts[j];
            t->deferred_stack_unmap_ends[j] = txns[i].deferred_ends[j];
        }
        if (t->deferred_stack_unmap_busy > 0) {
            t->deferred_stack_unmap_busy--;
            wake = true;
        }
    }
    if (wake)
        pthread_cond_broadcast(&deferred_stack_unmap_cond);
    pthread_mutex_unlock(&thread_lock);
}

int thread_prepare_deferred_stack_unmaps_for_cleanup(thread_entry_t *t,
                                                     uint64_t *starts,
                                                     uint64_t *ends,
                                                     int max_ranges)
{
    int nranges = 0;

    if (!t || !starts || !ends || max_ranges <= 0)
        return 0;

    pthread_mutex_lock(&thread_lock);
    while (t->deferred_stack_unmap_busy > 0)
        pthread_cond_wait(&deferred_stack_unmap_cond, &thread_lock);
    t->stack_map_start = 0;
    t->stack_map_end = 0;
    nranges = t->deferred_stack_unmap_count;
    if (nranges > max_ranges)
        nranges = max_ranges;
    for (int i = 0; i < nranges; i++) {
        starts[i] = t->deferred_stack_unmap_starts[i];
        ends[i] = t->deferred_stack_unmap_ends[i];
    }
    pthread_mutex_unlock(&thread_lock);

    return nranges;
}

int thread_peek_deferred_stack_unmaps(thread_entry_t *t,
                                      uint64_t *starts,
                                      uint64_t *ends,
                                      int max_ranges)
{
    int nranges = 0;

    if (!t || !starts || !ends || max_ranges <= 0)
        return 0;

    pthread_mutex_lock(&thread_lock);
    nranges = t->deferred_stack_unmap_count;
    if (nranges > max_ranges)
        nranges = max_ranges;
    for (int i = 0; i < nranges; i++) {
        starts[i] = t->deferred_stack_unmap_starts[i];
        ends[i] = t->deferred_stack_unmap_ends[i];
    }
    pthread_mutex_unlock(&thread_lock);

    return nranges;
}

int thread_drop_deferred_stack_unmap(thread_entry_t *t,
                                     uint64_t start,
                                     uint64_t end)
{
    int removed = 0;

    if (!t || start >= end)
        return 0;

    pthread_mutex_lock(&thread_lock);
    int n = t->deferred_stack_unmap_count;
    for (int i = 0; i < n; i++) {
        if (t->deferred_stack_unmap_starts[i] != start ||
            t->deferred_stack_unmap_ends[i] != end)
            continue;
        n--;
        t->deferred_stack_unmap_starts[i] = t->deferred_stack_unmap_starts[n];
        t->deferred_stack_unmap_ends[i] = t->deferred_stack_unmap_ends[n];
        t->deferred_stack_unmap_count = n;
        removed = 1;
        break;
    }
    pthread_mutex_unlock(&thread_lock);

    return removed;
}

void thread_clear_stack_map(thread_entry_t *t)
{
    if (!t)
        return;

    pthread_mutex_lock(&thread_lock);
    t->stack_map_start = 0;
    t->stack_map_end = 0;
    pthread_mutex_unlock(&thread_lock);
}

static int thread_add_deferred_unmap_locked(thread_entry_t *t,
                                            uint64_t start,
                                            uint64_t end)
{
    if (!t || start >= end)
        return 0;

    /* Absorb every existing slot that overlaps or is adjacent to [start, end),
     * expanding the candidate as needed. Compact the array in place by pulling
     * the live tail into each absorbed slot.
     */
    int n = t->deferred_stack_unmap_count;
    int i = 0;
    while (i < n) {
        uint64_t rs = t->deferred_stack_unmap_starts[i];
        uint64_t re = t->deferred_stack_unmap_ends[i];

        if (end < rs || start > re) {
            i++;
            continue;
        }
        if (rs < start)
            start = rs;
        if (re > end)
            end = re;
        n--;
        t->deferred_stack_unmap_starts[i] = t->deferred_stack_unmap_starts[n];
        t->deferred_stack_unmap_ends[i] = t->deferred_stack_unmap_ends[n];
    }

    if (n >= MAX_DEFERRED_STACK_UNMAPS) {
        t->deferred_stack_unmap_count = n;
        return -1;
    }

    t->deferred_stack_unmap_starts[n] = start;
    t->deferred_stack_unmap_ends[n] = end;
    t->deferred_stack_unmap_count = n + 1;
    return 0;
}

static int thread_can_add_deferred_unmap_locked(thread_entry_t *t,
                                                uint64_t start,
                                                uint64_t end)
{
    if (!t || start >= end)
        return 0;

    for (int i = 0; i < t->deferred_stack_unmap_count; i++) {
        uint64_t rs = t->deferred_stack_unmap_starts[i];
        uint64_t re = t->deferred_stack_unmap_ends[i];

        if (end < rs || start > re)
            continue;
        return 0;
    }

    return (t->deferred_stack_unmap_count < MAX_DEFERRED_STACK_UNMAPS) ? 0 : -1;
}

static void thread_ptrace_init(thread_entry_t *t)
{
    t->ptraced = false;
    t->tracer_tid = 0;
    t->ptrace_stopped = false;
    t->ptrace_stop_sig = 0;
    t->ptrace_cont_sig = 0;
    t->ptrace_regs_dirty = false;
    t->is_vm_clone = false;
    t->parent_tid = 0;
    t->exit_signal = 0;
    t->vm_exited = false;
    t->vm_exit_status = 0;
    memset(&t->ptrace_regs, 0, sizeof(t->ptrace_regs));
    pthread_cond_init(&t->ptrace_cond, NULL);
    pthread_cond_init(&t->resume_cond, NULL);
    t->ptrace_conds_inited = true;
    t->ptrace_waiters = 0;
    t->ptrace_cleanup_pending = false;
}

int thread_ptrace_stop(thread_entry_t *t, int sig)
{
    pthread_mutex_lock(&thread_lock);

    /* Snapshot vCPU registers into ptrace_regs so the tracer can read them
     * without cross-thread HVF access.
     */
    vcpu_snapshot_gprs(t->vcpu, t->ptrace_regs.regs);
    t->ptrace_regs.sp = vcpu_get_sysreg(t->vcpu, HV_SYS_REG_SP_EL0);
    t->ptrace_regs.pc = vcpu_get_sysreg(t->vcpu, HV_SYS_REG_ELR_EL1);
    t->ptrace_regs.pstate = vcpu_get_sysreg(t->vcpu, HV_SYS_REG_SPSR_EL1);

    /* Enter ptrace-stop state */
    t->ptrace_stopped = true;
    t->ptrace_stop_sig = sig;
    t->ptrace_cont_sig = 0;
    t->ptrace_regs_dirty = false;

    /* Wake the tracer (blocked in thread_ptrace_wait) */
    pthread_cond_broadcast(&t->ptrace_cond);

    /* Block until tracer calls PTRACE_CONT. Bail out on exit_group: only the
     * tracer signals resume_cond, and a tracer that exits (or calls
     * exit_group itself) will never CONT this stop. thread_wake_exit_waiters
     * broadcasts resume_cond; returning 0 sends the caller back to its run
     * loop, which re-checks proc_exit_group_requested.
     */
    while (t->ptrace_stopped && !proc_exit_group_requested())
        pthread_cond_wait(&t->resume_cond, &thread_lock);

    /* Apply register changes if tracer wrote via SETREGSET */
    if (t->ptrace_regs_dirty) {
        vcpu_restore_gprs(t->vcpu, t->ptrace_regs.regs);
        vcpu_set_sysreg(t->vcpu, HV_SYS_REG_SP_EL0, t->ptrace_regs.sp);
        vcpu_set_sysreg(t->vcpu, HV_SYS_REG_ELR_EL1, t->ptrace_regs.pc);
        vcpu_set_sysreg(t->vcpu, HV_SYS_REG_SPSR_EL1, t->ptrace_regs.pstate);
        t->ptrace_regs_dirty = false;
    }

    int cont_sig = t->ptrace_cont_sig;
    pthread_mutex_unlock(&thread_lock);

    return cont_sig;
}

void thread_ptrace_cont(thread_entry_t *t, int sig)
{
    pthread_mutex_lock(&thread_lock);
    t->ptrace_cont_sig = sig;
    t->ptrace_stopped = false;
    pthread_cond_signal(&t->resume_cond);
    pthread_mutex_unlock(&thread_lock);
}

/* True when t is a waitable child of the given tracer, optionally narrowed by
 * pid (>0 = exact TID, <=0 = any). Caller holds thread_lock.
 */
static bool thread_matches_tracer_child(const thread_entry_t *t,
                                        int64_t tracer_tid,
                                        int pid)
{
    if (!__atomic_load_n(&t->active, __ATOMIC_RELAXED))
        return false;
    bool is_child = (t->ptraced && t->tracer_tid == tracer_tid) ||
                    (t->is_vm_clone && t->parent_tid == tracer_tid);
    if (!is_child)
        return false;
    if (pid > 0 && t->guest_tid != pid)
        return false;
    return true;
}

int64_t thread_ptrace_wait(int64_t tracer_tid,
                           int pid,
                           int *out_status,
                           int options)
{
    int wnohang = (options & 1); /* WNOHANG = 1 on Linux */

    pthread_mutex_lock(&thread_lock);

    for (;;) {
        /* exit_group teardown: the stop/exit notifications that would signal
         * ptrace_cond stop arriving once workers are being torn down. Return 0
         * ("no matching children") so the caller falls through and its
         * blocking paths re-check proc_exit_group_requested.
         */
        if (proc_exit_group_requested()) {
            pthread_mutex_unlock(&thread_lock);
            return 0;
        }

        bool found_any = false; /* Any waitable children at all? */

        THREAD_FOR_EACH (t) {
            if (!thread_matches_tracer_child(t, tracer_tid, pid))
                continue;

            found_any = true;

            /* Ptrace-stopped: report stop signal in wait status. */
            if (t->ptrace_stopped) {
                int64_t tid = t->guest_tid;
                if (out_status)
                    *out_status = (t->ptrace_stop_sig << 8) | 0x7F;
                pthread_mutex_unlock(&thread_lock);
                return tid;
            }

            /* VM-clone child exited: reap and deactivate. */
            if (t->vm_exited) {
                int64_t tid = t->guest_tid;
                if (out_status)
                    *out_status = t->vm_exit_status;
                /* Destroy condvars after the last waiter returns from
                 * pthread_cond_wait().
                 */
                thread_free_sp_el1_locked(t);
                __atomic_store_n(&t->active, 0, __ATOMIC_RELEASE);
                atomic_fetch_sub(&active_thread_count, 1);
                t->ptrace_cleanup_pending = true;
                thread_ptrace_cleanup_locked(t);
                pthread_mutex_unlock(&thread_lock);
                /* Slot is now inactive; drop any unconsumed thread-directed
                 * pending bits from the global hint (same rationale as
                 * thread_deactivate). Outside thread_lock to honor sig_lock (4)
                 * before thread_lock (5).
                 */
                signal_refresh_pending_hint();
                return tid;
            }
        }

        if (!found_any) {
            pthread_mutex_unlock(&thread_lock);
            return 0; /* No matching children; let caller fall through */
        }

        if (wnohang) {
            pthread_mutex_unlock(&thread_lock);
            return 0;
        }

        /* Block on the first matching child's ptrace_cond. In practice VM-clone
         * has one tracee, so this scans little.
         */
        THREAD_FOR_EACH (t) {
            if (!thread_matches_tracer_child(t, tracer_tid, pid))
                continue;

            t->ptrace_waiters++;
            pthread_cond_wait(&t->ptrace_cond, &thread_lock);
            t->ptrace_waiters--;
            if (t->ptrace_cleanup_pending)
                thread_ptrace_cleanup_locked(t);
            break; /* Re-scan after wakeup */
        }
    }
}
