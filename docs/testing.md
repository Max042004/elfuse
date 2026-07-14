# Building And Testing

This document describes the development toolchain, the main `make` targets, and
how the repository validation flow is structured.

## Build Requirements

Host build requirements:

- Apple Silicon macOS host
- macOS 13 or newer
- Xcode Command Line Tools
- `clang`
- `codesign`
- GNU `make`
- GNU `objcopy` or `llvm-objcopy`
- GNU coreutils
- `bash` 3.2+ (the version Apple ships as `/bin/bash`) is sufficient for
  the test harness; no Homebrew `bash` is required. See
  `tests/lib/bash-compat.sh` for the cross-version shims (a portable
  microsecond clock and the parallel-array lookup pattern that replaces
  associative arrays). When editing a shell script under `tests/` or
  `scripts/`, the conventions in that file's header are the source of
  truth: no `EPOCHREALTIME`, no `declare -A`, no `mapfile`, no
  `${var^^}` / `${var,,}` case-conversion, and guard any potentially
  empty array expansion with `${arr[@]+"${arr[@]}"}` so `set -u` does
  not trip on it.
- Hypervisor entitlement: `com.apple.security.hypervisor`

Guest test builds additionally require:

- An AArch64 Linux cross-compiler for C test programs
- An AArch64 bare-metal toolchain for the assembly smoke test

The toolchain defaults are defined in `mk/toolchain.mk`. 
These variables are intended to be overridden when needed:

- `CROSS_COMPILE`
- `BAREMETAL_CROSS`
- `SIGN_IDENTITY`

### Installing the toolchains with Homebrew

The following block installs everything needed to run both `make check` and
the full `make test-matrix` (including the `qemu-aarch64` reference run). Run it
once on an Apple Silicon macOS host:

```sh
# GNU coreutils (gtimeout) — required by the test harness timeout wrapper
brew install coreutils

# GNU objcopy
brew install binutils

# Bare-metal aarch64-none-elf toolchain used by `make check`
brew install --cask gcc-aarch64-embedded

# AArch64 Linux cross-compiler for guest test binaries (make test-matrix)
brew tap messense/macos-cross-toolchains
brew trust --formula messense/macos-cross-toolchains/aarch64-unknown-linux-gnu
brew install aarch64-unknown-linux-gnu

# QEMU — boots the Alpine minirootfs for the qemu-aarch64 reference run
brew install qemu
```

Depending on your setup, you might need to add the following to your PATH
```
export PATH="/opt/homebrew/opt/aarch64-elf-gcc/bin:$PATH"
```

## Main Targets

The most useful development targets are:

```sh
make elfuse
make check
make test-rosetta-all
make test-gdbstub
make test-matrix
make lint
make clean
```

What they do:

- `make elfuse`: build and sign `build/elfuse`
- `make check`: fast elfuse-internal gate. Runs, in order:
  - `scripts/check-syscall-coverage.py` so any new `dispatch.tbl`
    entry without a direct or aliased test reference fails the build
  - the unit suite from `tests/manifest.txt` -- deliberately narrow: only
    tests that assert elfuse-internal implementation details with no real
    Linux counterpart (the EL1 shim fast-path suite, `test-mremap-infra`,
    `test-oom-proc`), plus whatever `mk/tests.mk`'s `SANITIZER_SECTIONS`
    needs for the `check-{asan,ubsan,tsan}` lanes. Everything that is
    meaningful to cross-check against a real Linux kernel lives exclusively
    in `tests/test-matrix.sh`'s `run_unit_tests` instead (see Test Matrix
    below) -- `make check` alone is *not* a substitute for it
  - the TLBI RVAE1IS encoder unit test
  - the proctitle argv-tail and low-stack regressions
  - the BusyBox applet smoke suite (auto-resolved from
    `externals/test-fixtures/aarch64-musl/staticbin/bin/busybox` or
    downloaded into `build/busybox` on first run)
  - the sysroot procfs exec, FUSE-on-Alpine, and `timeout=0` regressions
  - the Rosetta CLI gating regressions
  - the hot-syscall guardrail (`tests/test-bench-guardrail.sh`)
    asserting `getpid`, libc `clock_gettime`, and 1-byte
    `/dev/urandom` reads stay under their ns/op ceilings
- `make test-rosetta-all`: Rosetta-specific x86_64 acceptance scripts
  (`test-rosetta-cli`, `test-rosetta-failure-modes`,
  `test-rosetta-statics`, `test-rosetta-alpine`,
  `test-rosetta-audit`, `test-rosetta-jit`, `test-rosetta-glibc`)
- `make test-busybox`: just the BusyBox suite, useful when iterating on a
  single applet failure without rerunning the unit suite
- `make test-fuse-alpine`: validate guest `/dev/fuse` + `mount("fuse")`
  against the Alpine musl sysroot fixture
- `make test-gdbstub`: debugger integration checks against the built-in GDB stub
- `make test-matrix`: cross-check `elfuse` (aarch64), QEMU (aarch64),
  and `elfuse` (x86_64-via-Rosetta) on overlapping corpora
- `make bench`: two-tier performance benchmark suite (see Performance
  Benchmarks below); `make bench-ci` is the strict CI variant
- `make lint`: static analysis through `clang-tidy`

## Quick Iteration

For normal code changes touching syscall or runtime logic:

```sh
make elfuse
make check
make test-matrix-elfuse-aarch64
```

`make check` alone only covers elfuse-internal plumbing and the sanitizer
subset now; `test-matrix-elfuse-aarch64` is what actually exercises the full
unit-test surface against `build/elfuse` (no qemu boot needed, so it is about
as fast to iterate with as `make check` was before the split). For changes
that touch procfs, path handling, `/dev`, FUSE, networking, dynamic linking,
or guest process semantics, also cross-check against the qemu reference
kernel:

```sh
make test-matrix-qemu-aarch64
```

or run all matrix modes back-to-back with `make test-matrix`.

`make check` already runs the BusyBox applet suite as a second stage, so a
green `make check` covers BusyBox validation. Use `make test-busybox` to
iterate on a single applet failure without rerunning the unit suite.

## Performance Benchmarks

`make bench` runs `tests/bench-suite.sh`, the two-tier suite, and
writes `build/bench-results.json`:

- Tier 1 -- lmbench (issue #195): `lat_syscall`
  (null/read/write/stat/open) for syscall entry and forwarding cost,
  `lat_proc` (fork, fork+execve) for process creation and the whole
  ELF-load path, and `lat_fs` (0k create/delete) for filesystem
  metadata cost. Alpine ships no lmbench package, so
  `tests/fetch-fixtures.sh` cross-compiles the three benchmarks (plus
  `lat_proc`'s `hello-s` exec target) from a sha256-pinned, unmodified
  intel/lmbench source snapshot into
  `externals/test-fixtures/aarch64-musl/lmbench/`; the pinned commit
  is recorded in a `VERSION` stamp there and in each result's
  `meta.tier1`. Every metric is lmbench's own self-timed microsecond
  result; a benchmark that fails or hangs in a runtime appears as an
  `ERR` status row instead of aborting the run
- Tier 2 -- application workloads over the fixed corpus in
  `tests/bench-corpus/` using the Alpine fixture tools:
  `python3 -c pass`, `git status`, `rg`, `zstd`, and `make`

Each metric runs warmup + timed iterations and reports the median plus
raw samples. `scripts/bench-compare.py` diffs the results against
`tests/bench-baseline.json` and exits non-zero when a metric regresses
more than the threshold (default +20%, `BENCH_REGRESSION_THRESHOLD`);
`BENCH_REPORT_ONLY=1` downgrades that to a log-only signal, which is how
the CI `Benchmark` leg currently runs.

Tier-2 metrics are workload-only in every environment, so the columns
are directly comparable: the qemu, orbstack, and native columns time
each sample inside the guest/machine via `bench-timeit`, and the elfuse
column subtracts the median of the dedicated `startup_ms` metric from
every sample. `startup_ms` itself reports each environment's
per-command entry toll from the macOS caller's side (elfuse: VM +
sysroot setup + static ELF load; OrbStack: the `orb run` session; qemu:
one ssh round-trip).

`BENCH_ENV=qemu-aarch64 make bench` produces the `qemu-aarch64` reference
column: the same workloads inside the fixture Alpine VM (HVF, `-cpu
host`), i.e. a real Linux kernel on the same silicon -- there is no
separate `bench-qemu` target; `BENCH_ENV` picks this column exactly
like it picks any other, and (since it isn't the default) writes
`build/bench-results-qemu-aarch64.json` instead of
`build/bench-results.json` so it doesn't clobber an elfuse-aarch64
capture. Its guest root is the initramfs (tmpfs), so fs-heavy metrics
do not measure a disk filesystem (recorded in `meta.note`), and
boot-time calibration reboots the VM when the scheduler lands its
vCPUs on efficiency cores (`BENCH_QEMU_NULL_CEILING` tunes the probe
for non-M-series hosts). `BENCH_ENV=orbstack` runs the workloads in a
machine-local work area of the default OrbStack machine (Tier-2 tools
must be installed inside it); `BENCH_ENV=native` also works for an
aarch64 Linux host, though qemu-aarch64's real-kernel-on-same-silicon
column already serves as the native-Linux reference on the
Apple-Silicon hosts this project mainly targets. The baseline-refresh
procedure lives in the header of `tests/bench-suite.sh`.

Do not edit `tests/bench-corpus/` -- the corpus is part of the benchmark
definition, and any change to it invalidates the baseline.

### Manual / Ad-hoc Runs

Prefer the Makefile targets (`bench` / `bench-ci`, with `BENCH_ENV` to
pick the column -- there is no separate `-qemu` target) for a full run:
they build the prerequisites and wire up `ELFUSE`/`BENCH_BIN_DIR`. The
commands below drive the same pieces directly, useful for iterating on
one case or comparing an existing results file without rerunning
everything.

**Full suite with custom env/output:**

```sh
BENCH_ENV=elfuse-aarch64 BENCH_ITERATIONS=20 BENCH_WARMUP=3 \
    bash tests/bench-suite.sh -o build/bench-results.json
```

`BENCH_ENV` selects the column (`elfuse-aarch64` default,
`qemu-aarch64`, `orbstack`, `native`); the CI variant just adds
`BENCH_STRICT=1` (fetch fixtures on demand, fail hard instead of
skipping Tier 2 when they're missing).

**One Tier-1 benchmark without the suite harness:**

```sh
tests/fetch-fixtures.sh                # builds the lmbench fixtures once
env ENOUGH=100000 ./build/elfuse \
    externals/test-fixtures/aarch64-musl/lmbench/lat_syscall -N 5 null
```

`ENOUGH` pins lmbench's timing-interval length in microseconds (the
suite sets it via `BENCH_LMBENCH_ENOUGH`); without it lmbench's
interval auto-calibration adds ~30-40 s per invocation under elfuse.
`lat_syscall stat|open` take a file argument, `lat_fs` a scratch
directory, and `lat_proc exec` expects its hello binary at
`/tmp/hello-s` (copy it from the lmbench fixture directory first).
This is the fastest loop for checking one metric's number after a
change: no corpus, no fixture rootfs, no JSON output.

**One Tier-2 workload's wall-clock cost:**

```sh
./build/elfuse --sysroot externals/test-fixtures/rootfs \
    ./build/bench-timeit /bin/busybox true
```

`bench-timeit` times fork+exec+wait of the given command and prints one
integer of microseconds; running it as the guest program under `elfuse
--sysroot` spot-checks a single guest binary's spawn cost the same way
`bench-suite.sh` times the qemu/orbstack/native columns in-guest (its
elfuse-aarch64 column instead times from the host side and subtracts
the separate `startup_ms` metric, so this ad-hoc number is not directly
comparable to that column without the same subtraction). Reproducing an
actual Tier-2 metric exactly (e.g. `git status` against the corpus)
needs the same guest-side prep `bench-suite.sh` does -- a case-sensitive
sparseimage copy of the sysroot with the corpus staged and
`PATH`/`HOME`/`LC_ALL` pinned (see `run_tier2_suite`, `prepare_corpus`,
and `tier2_cmd` in `tests/bench-suite.sh`) -- a bare CLI call cannot
resolve a host working directory inside the guest.

**Compare an existing results file against baseline without rerunning:**

```sh
python3 scripts/bench-compare.py --results build/bench-results.json \
    --baseline tests/bench-baseline.json --threshold 0.20
```

Add `--report-only` (or `BENCH_REPORT_ONLY=1`) to print regressions
without a non-zero exit. Any file matching the schema in
`tests/bench-suite.sh`'s header works, including one captured with
`BENCH_ENV=qemu-aarch64`/`orbstack`/`native`.

**Promote a captured results file into the baseline:**

```sh
python3 scripts/bench-promote.py --results build/bench-results.json \
    --baseline tests/bench-baseline.json
```

Merges each metric's median into `environments.<env>` (the env comes
from the results file's `meta.env`) and records `date`/`host`/
`iterations` into `captured.<env>`. Cases present in the baseline but
absent from `--results` (an ERR/SKIP row, or a deliberately filtered
partial run) are left untouched by default; add `--prune` to drop them
instead -- use that after a case was renamed or removed so the stale
key doesn't linger. `--dry-run` prints the added/updated/pruned diff
without writing. This is the mechanical half of the baseline-refresh
procedure in `tests/bench-suite.sh`'s header; it doesn't decide whether
a refresh is warranted (capture back-to-back and confirm they agree
within a few percent first) or commit the result.

**Environment variables** (all optional; defaults shown):

| Variable | Default | Meaning |
| --- | --- | --- |
| `BENCH_ENV` | `elfuse-aarch64` | column: `elfuse-aarch64` \| `qemu-aarch64` \| `orbstack` \| `native` |
| `BENCH_ITERATIONS` | `10` | timed Tier-2 samples per metric |
| `BENCH_WARMUP` | `2` | discarded leading Tier-2 samples per metric |
| `BENCH_LMBENCH_REPS` | `11` | lmbench `-N` repetitions per Tier-1 benchmark |
| `BENCH_LMBENCH_RETRIES` | `1` | extra attempts for a failed/hung Tier-1 benchmark before its `ERR` row |
| `BENCH_LMBENCH_TIMEOUT` | `60` | per-lmbench-invocation timeout in seconds |
| `BENCH_LMBENCH_ENOUGH` | `100000` | lmbench `ENOUGH` (us per timing interval); empty restores lmbench auto-calibration |
| `LMBENCH_DIR` | fixtures `aarch64-musl/lmbench` | directory holding the lmbench fixture binaries |
| `BENCH_STRICT` | `0` | `1` = missing fixtures are fatal and fetched on demand (what `bench-ci` sets) |
| `ELFUSE` | `build/elfuse` | elfuse binary driving the elfuse-aarch64 column |
| `BENCH_BIN_DIR` | `build/` | directory holding `bench-timeit` |
| `TEST_TIMEOUT` | `120` | per-invocation timeout in seconds |
| `BENCH_QEMU_NULL_CEILING` | `180` | ns/op; the qemu boot-calibration probe reboots the VM above this (efficiency-core placement) |
| `BENCH_QEMU_BOOT_RETRIES` | `2` | qemu boot-calibration retry attempts before proceeding with a warning |
| `BENCH_REGRESSION_THRESHOLD` | `0.20` | fractional regression that fails `bench-compare.py` |
| `BENCH_REPORT_ONLY` | unset | `1` = `bench-compare.py` reports regressions but exits 0 |

## Test Matrix

The matrix driver lives in `tests/test-matrix.sh`. It currently covers three
execution modes:

- `elfuse-aarch64`: every binary is executed via `build/elfuse` on macOS
- `qemu-aarch64`: the same binaries run natively inside an Alpine
  `aarch64-linux-musl` minirootfs booted by `qemu-system-aarch64`
- `elfuse-x86_64`: Rosetta-for-Linux acceptance scripts against the staged
  Alpine x86_64 fixture tree

The goal is not to compare performance. The goal is to compare guest-observable
behavior against a ground-truth Linux AArch64 environment so that any divergence
in syscall translation, procfs emulation, or process semantics is caught early.

`run_unit_tests` in `tests/test-matrix.sh` is the full aarch64 unit-test
surface -- every binary that is meaningful to run against a real kernel, which
is almost everything. It deliberately excludes only the handful of tests that
assert elfuse-internal implementation details with no meaningful counterpart
on a real kernel (the EL1 shim fast-path suite, `test-mremap-infra`,
`test-oom-proc` -- these live solely in `tests/manifest.txt` / `make check`,
see that file's header for the full split rationale). There is no separate
"core" vs "extended" test set inside the matrix; a test that has a real,
understood divergence from the qemu reference kernel is listed in
`QEMU_SKIP` with a comment explaining why instead -- see that variable in
`tests/test-matrix.sh` for the current list and rationale. `run_unit_tests`
runs in both `elfuse-aarch64` and `qemu-aarch64` modes, so most tests are
exercised twice per matrix run: once against `build/elfuse`, once against the
real kernel.

The x86_64 mode is narrower: it aggregates the Rosetta-specific acceptance
scripts and their per-binary summaries into the same matrix runner, including
the Rosetta thread/signal audit smoke, the LuaJIT guest-JIT probe, and the
glibc dynamic-binary acceptance helper.

Run a single mode with `bash tests/test-matrix.sh elfuse-aarch64`,
`bash tests/test-matrix.sh qemu-aarch64`, or
`bash tests/test-matrix.sh elfuse-x86_64`; `all` runs all three back-to-back.

Fixture handling is self-contained:

- On first use, `tests/fetch-fixtures.sh` downloads the required Alpine
  packages and the `linux-virt` kernel into `externals/test-fixtures/` and
  assembles an initramfs. Subsequent runs are zero-config.
- The same fixture tree is reused across the matrix modes.
- When Rosetta mode is requested and the translator is installed,
  `tests/test-matrix.sh` auto-fetches the x86_64 fixture tree
  (`INCLUDE_X86_64=1`) on demand.
- QEMU mode requires `qemu-system-aarch64` on `PATH` (Homebrew `qemu` provides it).
- musl is the only Alpine libc; the glibc-dynamic suite is skipped unless
  `GUEST_GLIBC_*` environment variables point at an external sysroot.

## Rosetta Limitations

`elfuse-x86_64` is expected to inherit two Rosetta-internal limitations that are
not treated as elfuse regressions:

- `SA_RESETHAND` is not reset reliably because Rosetta shadows guest signal
  handler state internally.
- `clone(..., CLONE_SETTLS, tls=0, ...)` can hang.

The x86_64 matrix branch is therefore a Rosetta acceptance gate, not a claim
that translated guests fully match native Linux thread and signal semantics.

## x86_64 Acceptance Inventory and Per-Host Baselines

The `elfuse-x86_64` matrix mode aggregates seven sub-suites. Each one
emits a deterministic per-binary pass list; the matrix runner sums
those into a single `Results:` line and compares against a per-host
baseline. The exact labels each sub-suite emits, and the contract
they verify, are:

- `tests/test-rosetta-cli.sh` (4): `rosetta-disabled-flag`,
  `rosetta-disabled-env`, `rosetta-gdb`, `rosetta-default` --
  command-line gating of the translator path (opt-out flag, env
  override, `--gdb` rejection, install-hint surface).

- `tests/test-rosetta-failure-modes.sh` (3): `no-rosetta-flag`,
  `no-rosetta-env`, `gdb-x86_64` -- command-line rejection paths.
  Self-contained against a synthesized minimal x86_64 ELF; no
  external fixture tree required. The dynamic-linker bring-up and
  mid-process execve scenarios that used to live here are now
  exclusively in the glibc and statics suites against the vendored
  rootfs (see `glibc-hello` / `glibc-hello-via-ldso` and
  `env-execve`).

- `tests/test-rosetta-statics.sh` (20): `echo`, `true`, `false`,
  `printenv`, `expr-zero`, `expr-mul`, `basename`, `dirname`,
  `stat-self`, `factor`, `seq`, `sha256sum`, `md5sum`, `uname-m`, `arch`,
  `busybox-arch-subcommand`, `date-utc`, `id-u`, `nproc`,
  `env-execve` -- statically-linked Alpine busybox applets,
  exercising VZ ioctl gate, `/proc/self/exe` redirect, high-VA mmap,
  and the kbuf alias.

- `tests/test-rosetta-alpine.sh` (33): `cat-fruits-first-line`,
  `wc-l-fruits`, `wc-l-lines`, `wc-c-lines`, `ls-data`, `stat-data`,
  `find-by-name`, `du-sk-data`, `sha256-fruits`,
  `sha256-lines-matches-host`, `sha512-lines`, `md5-fruits`,
  `cksum-fruits`, `sort-first`, `sort-reverse-first`, `pipe-sort-wc`,
  `pipe-tr-uppercase`, `pipe-cat-grep`, `pipe-sed-subst`,
  `pipe-awk-field`, `head-n3`, `tail-n3`, `pipe-sort-uniq`,
  `pipe-cut-field`, `pipe-rev`, `tac-reverse-first-line`, `seq-1-5`,
  `seq-step`, `factor-prime`, `factor-composite`, `diff-identical`,
  `diff-differs`, `pipe-base64-decode` -- broader file I/O, text
  processing, and host-shell pipelines stitched through Rosetta on
  every stage.

- `tests/test-rosetta-audit.sh` (2): `audit-known-limitations`,
  `tls0-known-hang` -- bookkeeping probe that asserts the documented
  Rosetta shadowing failures (above) remain the only divergences;
  fails loudly if a new threading/signal-state edge case starts
  diverging.

- `tests/test-rosetta-jit.sh` (2): `luajit-trace`,
  `luajit-coroutine` -- guest-side JIT under translation
  (LuaJIT trace emission + coroutine allocation), covering the
  small-mprotect RW->RX and per-thread icache observation path that
  rosetta's own JIT does not exercise.

- `tests/test-rosetta-glibc.sh` (7): `glibc-hello`,
  `glibc-hello-via-ldso`, `glibc-hello-list`, `glibc-dlopen`,
  `glibc-tls`, `glibc-gdtls`, `glibc-pthread-tls` --
  dynamically-linked glibc x86_64 binary acceptance through
  `--sysroot` against the staged minimal glibc rootfs under
  `externals/test-fixtures/x86_64-glibc/rootfs/`. The first three
  cover load-time `PT_INTERP` resolution and `ld.so --list`
  introspection. `glibc-dlopen` runs `dlopen("libm.so.6")` plus a
  `dlsym(sqrt)` round-trip to exercise the runtime fresh-`.so`-mmap
  codepath, which is distinct from the load-time path the first
  three probes touch. `glibc-tls` reads and writes two
  initial-exec `__thread` variables (one integer, one pointer) so a
  broken FS-register to `TPIDR_EL0` translation surfaces as a
  value mismatch rather than as a silent skip. `glibc-gdtls`
  `dlopen`s a companion `libgdtls.so` whose `__thread` variable
  must use the general-dynamic model (calls `__tls_get_addr`);
  this is the only probe that exercises that lowering path, which
  the initial-exec probe cannot reach. `glibc-pthread-tls`
  `pthread_create`s a worker thread that reads and writes its own
  `__thread` slot; the probe asserts the worker saw its own
  default value (not the main thread's overwritten marker) and that
  the main thread's slot survives the worker's write, so a broken
  per-thread `TPIDR_EL0` setup on additional threads surfaces as
  isolation failure rather than as a silent crash.

Total: 71 expected passes, 0 expected failures.

### Per-Host Baseline Capture

The matrix runner keys its `elfuse-x86_64` baseline by detected host
SoC class. Two classes matter because `sys_mmap_fixed_high_va` takes
different paths under different IPA widths:

- `apple-m1-m2`: 36-bit native IPA, exercises the overflow-segment
  path. Captured on this codebase against Apple M1 hardware
  (MacBookAir10,1). The seven sub-suites land at 71/0/0.

- `apple-m3-plus`: 40-bit native IPA, exercises the bisected-slab
  path (and the M5 slab-bisection variant). Currently held equal to
  `apple-m1-m2` pending operator capture on real M3+ hardware. When
  that capture lands, only the
  `"elfuse-x86_64:apple-m3-plus|<min_pass>|<max_fail>"` row in the
  `EXPECTED_BASELINES` array in `tests/test-matrix.sh` moves; the
  M1/M2 row stays intact.

- `apple-unknown`: fallback for SoC brand strings the detector does
  not recognise. Inherits the M1/M2 numbers and triggers a one-line
  warning so a new SoC does not silently graft onto an existing row.

Class detection reads `sysctl -n machdep.cpu.brand_string` and matches
against `Apple M1`/`Apple M2` (M1/M2) and `Apple M3`/`Apple M4`/`Apple
M5` (M3+). To exercise the M3+ row from an M1/M2 host (and vice
versa) without changing the detector, set
`MATRIX_HOST_CLASS_OVERRIDE=apple-m3-plus` (or `apple-m1-m2`,
`apple-unknown`) before invoking `tests/test-matrix.sh`.

When the seven sub-suites grow or trim a test, the per-sub-suite
counts in the comment block above `EXPECTED_BASELINES` and the
inventory list above must move in the same commit so the per-host
baseline stays in sync with reality. Each `EXPECTED_BASELINES` entry
is a pipe-separated `mode-key|min_pass|max_fail` triple parsed by
`expected_baseline_get()` in `tests/test-matrix.sh`.

## Test Inventory

The repository contains several layers of validation:

- unit-style guest tests compiled from `tests/*.c`
- shell integration suites such as BusyBox, coreutils, and dynamic-loader tests
- debugger integration tests for the GDB stub
- native macOS HVF checks such as multi-vCPU and RWX validation

The quick suite is driven by `tests/driver.sh`, which supports:

- `-f PATTERN` to filter tests
- `-l` to list them
- `-T` for TAP output

Example:

```sh
bash tests/driver.sh -f test-proc
```

## Validation Strategy By Change Type

Suggested minimum validation:

| Change area | Recommended validation |
|-------------|------------------------|
| CLI, logging, docs-only build rules | `make elfuse` |
| General syscall or runtime logic | `make elfuse && make check && make test-matrix-elfuse-aarch64` |
| `/proc`, `/dev`, path, or BusyBox-sensitive behavior | `make elfuse && make check && make test-matrix-elfuse-aarch64` |
| Rosetta hosting, x86_64 dispatch, VZ ioctls, AOT cache | `make elfuse && make test-rosetta-all` |
| Broad behavioral changes | `make elfuse && make check && make test-matrix` |
| Debugger or ptrace flow | `make elfuse && make test-gdbstub` |
