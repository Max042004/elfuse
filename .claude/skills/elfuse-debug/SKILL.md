---
name: elfuse-debug
description: Localizing a guest that misbehaves under elfuse - building a repro loop that goes red, reading the crash report, and the trace, TLBI, and GDB switches. Use when a guest faults, hangs, returns a wrong errno, dies only sometimes, or starts too slowly, and you do not yet know whether the fault is host-side or guest-side.
---

# Localizing an elfuse failure

Every other skill in this repo tells you which rule you broke. This one tells
you how to find out. The question that orders all of it is the same one every
time: did the host hand the guest something wrong, or did the guest execute
something the guest ABI does not support?

Answer that before editing anything. The most expensive mistake here is
patching a syscall whose real fault is a stale TLB entry or a return path that
rebuilt EL0 state incorrectly, because the syscall is where the damage becomes
visible and not where it was caused.

The order is fixed: read the crash report, build a loop that goes red, then
theorize. Reading source to build a theory before the loop exists is the
failure this skill prevents, and it is the expensive one here, because a guest
that runs 99% of the time makes any theory look confirmed.

## Read the crash report first

A fatal error prints a structured report from `crash_report()`
(`src/debug/crashreport.c`) with the register dump and the memory layout. Its
classification is the first bisection, and it is free:

| Type | What it means for you |
|------|-----------------------|
| `CRASH_BAD_EXCEPTION` | The guest took an exception at EL1 (HVC #2). Guest-side: permissions, a bad mapping, or a vector rule. Start at `elfuse-guest-abi`. |
| `CRASH_UNEXPECTED_HVC` / `CRASH_UNEXPECTED_EC` | The shim and the host dispatcher disagree about the protocol. Usually a half-landed HVC change. |
| `CRASH_HV_CHECK` | Hypervisor.framework refused a call. Host-side: a mapping or permission elfuse asked for is not one HVF allows. |
| `CRASH_ELR_ZERO` | Register state after exec is not what the host wrote. A return-to-EL0 path problem, not a loader problem. |
| `CRASH_UNEXPECTED_EXIT` | `hv_vcpu_run()` returned an exit reason the loop does not handle. Host-side: HVF or the run loop, not the guest. |
| `CRASH_TIMEOUT` | One `hv_vcpu_run()` iteration exceeded the `--timeout` watchdog. |

`CRASH_TIMEOUT` is the one that gets misread. The watchdog bounds a single run
iteration, not total runtime, so a CPU-bound guest can trip it legitimately and
`--timeout 0` is the right answer there. A guest that is actually stuck (futex,
wait, poll) trips it too, and raising the timeout only makes it take longer to
say so.

## Build a loop that goes red

One command that fails on this bug and passes once it is fixed. Everything
after this is mechanical: bisection, hypothesis testing, and instrumentation
all just consume the loop. Spend the effort here rather than after here.

In rough order of how tight the result is:

1. One guest binary under the built host, run directly:
   `build/elfuse -v build/test-<name>`. Fastest signal in the tree, and the
   verbose flag is a diagnostic rather than part of the loop (see the
   `needs_extra_regs` trap below).
2. One suite entry: `tests/driver.sh -f <pattern> -v`. `-t` bounds it and
   `TEST_TIMEOUT` sets the default. Use this when the failure needs the
   fixture set the manifest builds.
3. A new `tests/test-<feature>.c` reproducing the guest behavior in a few
   lines. Worth writing early, because it is the regression test afterward.
4. The QEMU reference lane: `make test-matrix-qemu-aarch64`. It runs the full
   matrix under a real kernel, not a selected guest binary and not an elfuse
   comparison. Use it to check whether a portable suite failure also occurs
   on Linux. A TIMEOUT there is emulation speed.
5. The whole lane, `make test-matrix-elfuse-aarch64`, when nothing smaller
   reproduces yet. Loosest, and the one to narrow away from.

Then tighten it. Cut the guest binary down until every remaining line is
load-bearing, assert on the exact symptom rather than on "did not crash", and
pin whatever varies. A minimal repro shrinks the hypothesis space, and it is
what the regression test is built from.

Done when one named command, already run once with its output shown, drives
the real code path, asserts the reported symptom, gives the same verdict every
run, and finishes in seconds unattended.

### When it only fails sometimes

The goal is a higher reproduction rate, not a clean repro. A 50% failure is
debuggable and a 1% failure is not, so raise the rate before theorizing: loop
the trigger a few hundred times, run the lane under load, and lean on the
switches that widen the window. `ELFUSE_DISABLE_TLBI_RANGE=1` is the sharpest
one, because it answers a question rather than just shaking the timing.
Anything involving two vCPUs is also worth a `make check-tsan` run: vCPUs are
host threads, so a race in elfuse's own state can be reported there without the
guest-visible failure having to reproduce at all.

For a hang, the harness has already sampled it: `tests/lib/hang-sample.sh`
runs from both `tests/driver.sh` and `tests/lib/test-runner.sh`, samples the
live process shortly before `timeout` kills it, and keeps the output only when
the watchdog actually fired. Read that sample before reaching for anything
else; `TEST_SAMPLE_TIMEOUTS=0` is how it gets turned off, not how it gets used.

## By symptom

Faults at or near the first guest instruction.
Bring-up, not your syscall. `ELFUSE_STARTUP_TRACE=steps` gives per-step
wall-time for VM bring-up so you can see which step is the last one to
complete. The usual causes are all in `elfuse-guest-abi`: the initial stack,
enabling the MMU from the wrong side, or sysreg bits that HVF does not
default the way the architecture does.

Dies at a specific syscall.
`-v` / `--verbose` turns on syscall-level and loader diagnostics. If the
syscall is new, suspect its `dispatch.tbl` entry before its implementation: a
fourth argument that behaves as 0 or NULL on every call is the signature of a
missing `needs_extra_regs`. See `elfuse-syscall`.

Works under `-v`, fails without it.
That is the same bug, and the verbose flag is what hides it. The dispatcher
fetches X3-X5 when the entry asks for them or when verbose is on, so a missing
`needs_extra_regs` reads real arguments under `-v` and deterministic zeros
without it. Any behavioral difference between a verbose and a quiet run is
this until proven otherwise; do not debug it as a timing problem.

Wrong result, no crash.
Start with the direct repro above. For a portable suite failure,
`make test-matrix-qemu-aarch64` runs that full suite under a real kernel; it
is a reference lane, not a single-binary differential command. Reasoning
from memory about what Linux would do is what it replaces.

Works almost always, fails under load or after an mmap/mprotect.
Suspect a stale TLB before suspecting the syscall. `ELFUSE_DISABLE_TLBI_RANGE=1`
forces the broadcast fallback (`src/core/guest.c`); if the failure disappears,
the selective or range request the host computed was too small, and the fix is
in the accumulator, not in the caller. The same shape of bug appears when two
vCPUs are involved, which is why the accumulator slot is per-vCPU.

A handler runs with the wrong PC, SP, or LR.
The host rebuilt EL0 state and the shim restored a stale frame over it, or the
reverse. See "Paths that rebuild EL0 state" in `elfuse-guest-abi`. Nothing in
the syscall implementation can cause or fix this.

Dynamic guest starts too slowly.
`ELFUSE_STARTUP_TRACE=syscalls` records a per-syscall histogram (count, total,
max latency) through the linker's syscall storm and freezes at the first
successful `execve`, so the dump is the startup picture rather than steady
state. `=all` enables it alongside the step tracer. `ELFUSE_SHIM_STATS` dumps
the shim's counter table at exit, attributing every fast-path bail, which is
how you tell a syscall that is slow from one that is not being served inline
at all.

Terminal or pty behavior.
`ELFUSE_PTY_LOG=<file>` mirrors the pty layer's diagnostics to a file.

## Rank the theories, then probe one variable

Write down three to five candidates before testing any of them, each stated so
the loop can refute it: "if the accumulator asked for too few pages, then
`ELFUSE_DISABLE_TLBI_RANGE=1` turns the failure green". A candidate with no
prediction attached is a vibe; sharpen it or drop it. Single-candidate
debugging anchors on the first plausible story, which in this tree is almost
always the syscall that surfaced the damage.

Show the ranked list before spending a run on it. The person reporting the bug
often re-ranks it in one line, and the check costs nothing.

Each probe then tests one prediction and changes one variable. Prefer the
switches already in the tree, since each is a probe someone else already
debugged: the startup tracer, the syscall histogram, `ELFUSE_SHIM_STATS`, the
TLBI fallback, `ELFUSE_PTY_LOG`. Reach for the GDB stub when the question is
about register or memory state at a point, since one breakpoint answers what
ten prints only suggest.

A temporary print carries a unique tag, so removing every one of them at the
end is a single grep. Untagged prints survive and land in review; the tree
takes an unrequested log line as a defect. Before calling the bug fixed:
the loop from the first section runs green, the regression test is in
`tests/` and fails without the fix, every tagged probe is gone, and the
theory that turned out right is in the commit body, where the next person
looking at this code finds it.

## Stepping the guest

```
build/elfuse --gdb 1234 --gdb-stop-on-entry ./binary
aarch64-linux-gnu-gdb -ex "target remote :1234" ./binary
```

All-stop, hardware breakpoints and watchpoints, full register and memory
access. Two properties are not negotiable and will confuse you if you forget
them: registers come from a snapshot, because HVF requires register access on
the owning thread, and `--gdb` is rejected for x86_64 guests because the stub
would serve the translated aarch64 view rather than the state the guest thinks
it has.

## Before calling it an elfuse bug

Reproduce it under `qemu-aarch64`. A divergence from that lane is an elfuse
bug worth reporting with the crash report attached; identical behavior in both
means the guest is doing something the guest itself got wrong.

## Authoritative sources

This skill is a working summary. These are tracked and survive a fresh clone,
so prefer them when the two disagree:

- `docs/usage.md` - the full option list and the exact semantics of
  `--timeout`, `--fakeroot`, and `ELFUSE_FAKEROOT_EXEC`.
- `docs/internals.md`, section "GDB Stub" - the snapshot protocol and the
  `src/debug/` split.
- The header comments in `src/core/startup-trace.h` and
  `src/debug/syscall-hist.h` - each states its env var's accepted values and
  what it costs when disabled.
- `src/debug/crashreport.h` for the crash-type enum and the report layout.
  The report is unconditional.
