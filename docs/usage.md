# Using elfuse

This document covers the command-line interface, common launch patterns,
dynamic linking through `--sysroot`, and debugger attachment.

## Command-Line Synopsis

```sh
build/elfuse [options] <elf-path> [args...]
```

Supported user-facing options:

| Option | Meaning |
|--------|---------|
| `-h`, `--help` | Print built-in usage help |
| `-V`, `--version` | Print the build version and exit |
| `-v`, `--verbose` | Enable syscall-level and loader diagnostics |
| `-t`, `--timeout N` | Per-iteration vCPU watchdog, in seconds (default `10`, `0` disables) |
| `--sysroot PATH` | Resolve guest absolute paths under `PATH` first |
| `--gdb PORT` | Listen for a GDB RSP client on `PORT` |
| `--gdb-stop-on-entry` | Stop before the first guest instruction |
| `--` | End `elfuse` option parsing; remaining tokens are guest argv |

`--timeout` is a run-loop watchdog. It does not cap total process runtime. It
only bounds a single `hv_vcpu_run()` iteration before the host regains control,
which is what allows host-side timers and signals to be observed promptly.
Setting `--timeout 0` disables this watchdog for long-running CPU-bound guests.

## Common Launch Patterns

Run a statically linked guest binary:

```sh
build/elfuse ./build/test-hello
```

Run with verbose tracing:

```sh
build/elfuse --verbose ./guest-program arg1 arg2
```

Pass guest arguments that begin with `-`:

```sh
build/elfuse -- ./guest-program --guest-flag
```

## Dynamic Linking And Sysroots

Dynamic Linux guests need a sysroot that contains the expected interpreter and
shared libraries. `elfuse` reads `PT_INTERP`, loads the requested interpreter
from the supplied sysroot, and redirects guest absolute-path opens to that tree
before falling back to the host filesystem.

Example:

```sh
build/elfuse --sysroot /path/to/sysroot ./hello-dynamic
```

This model supports both musl and glibc guest environments as long as the
expected interpreter path (for example `/lib/ld-musl-aarch64.so.1` or
`/lib/ld-linux-aarch64.so.1`) exists inside the sysroot.

Practical notes:

- The sysroot is consulted only for guest absolute paths; relative paths still
  resolve from the guest working directory.
- The sysroot setting is preserved across guest `fork` and `execve`, so spawned
  children see the same view of the filesystem.

## Debugging With GDB Or LLDB

`elfuse` includes a built-in GDB Remote Serial Protocol stub.

Start the guest and wait at entry:

```sh
build/elfuse --gdb 1234 --gdb-stop-on-entry ./guest-program
```

Attach with GNU GDB:

```sh
aarch64-linux-gnu-gdb -ex "target remote :1234" ./guest-program
```

Or attach with LLDB:

```sh
lldb --batch -o "gdb-remote 1234" ./guest-program
```

The stub supports all-stop debugging, up to 16 hardware breakpoints, up to 16
watchpoints, single-step (implemented as a temporary breakpoint), full register
and memory access, and per-thread inspection. Implementation details, including
the snapshot protocol used to keep Hypervisor.framework register access on the
owning thread, are documented in [internals.md](internals.md).

## Running OCI Images (`elfuse oci run`)

Phase 3 adds a direct-execution path for pulled OCI images:

```sh
elfuse oci run [OPTIONS] IMAGE [ARG...]
```

The subcommand reads the image's runtime block (Entrypoint, Cmd, Env,
WorkingDir, User) and folds in any CLI overrides, then unpacks the image
into the local APFS sysroot volume, clones a per-run rootfs via APFS
`clonefile(2)`, resolves argv[0] against PATH inside the rootfs, and
hands off to the same VM bring-up the legacy positional-ELF `elfuse`
entry uses.

The image must already be pulled. `oci run` does not auto-pull on miss.
The usual workflow is:

```sh
elfuse oci pull alpine:3
elfuse oci run  alpine:3 /bin/sh -c 'echo hello from inside'
```

### Options

| Option | Meaning |
|--------|---------|
| `--store DIR` | Override the local store root |
| `--volume DIR` | Override the APFS sysroot volume mount point |
| `--entrypoint PROG` | Replace the image Entrypoint with `PROG` |
| `-e KEY=VAL`, `--env KEY=VAL` | Set or replace one env var (repeatable) |
| `-e KEY`, `--env KEY` | Import `KEY` from the host environ (repeatable) |
| `-w DIR`, `--workdir DIR` | Override image WorkingDir |
| `-u UID[:GID]`, `--user UID[:GID]` | Override image User (numeric only) |
| `--keep` | Keep the per-run cloned rootfs after exit |
| `--name NAME` | Reserved: deterministic clone-dir suffix (ignored today) |

### Argv override matrix

| Image Entrypoint | Image Cmd | CLI ARGV | `--entrypoint` | Result argv |
|--|--|--|--|--|
| set | set | none | none | Entrypoint ++ Cmd |
| set | set | provided | none | Entrypoint ++ CLI ARGV (Cmd dropped) |
| set | none | provided | none | Entrypoint ++ CLI ARGV |
| none | set | none | none | Cmd |
| none | set | provided | none | CLI ARGV (Cmd dropped) |
| set | set | optional | provided | [`--entrypoint`] ++ CLI ARGV |
| none | none | provided | none | CLI ARGV |
| none | none | none | none | `EINVAL` "image has no entrypoint or cmd; pass one on the CLI" |

### Env merge policy

The merged guest env is built in this order:

1. Image `Env` (verbatim, in spec order)
2. Each CLI `-e KEY=VAL` set-or-replaces by key
3. Each CLI `-e KEY` (no `=`) imports the host's value when present, otherwise drops silently
4. `TERM` auto-imported from the host iff the merged env has no `TERM`
5. `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` injected iff the merged env has no `PATH`
6. `container=elfuse` injected unconditionally so systemd-style sandbox detection works

CLI `-e DYLD_*=...` overrides are hard-rejected with `EINVAL`: `DYLD_*` is a
macOS-only loader contract with no meaning inside an aarch64-linux guest.
Image-provided `DYLD_*` entries pass through (the guest ignores them).

### User and WorkingDir

`User` accepts numeric `UID` or `UID:GID` only. Symbolic users (`User
nginx`) are rejected with a deterministic Phase 4 pointer message;
static `/etc/passwd` parsing waits for Phase 4 along with the rest of
the NSS resolution work. `--user UID` alone defaults GID to the same
value.

`WorkingDir` must be absolute and free of `..` segments. If neither the
image nor the CLI sets it, the guest starts in `/`. The directory is
materialized under the cloned rootfs (`mkdir -p`, mode 0755, best-
effort chown to the resolved uid:gid when `--user` or image User
selects credentials).

### Scope guardrails

- Symbolic `User` -> Phase 4 (NSS / static `/etc/passwd` resolution)
- `/etc/resolv.conf`, `/etc/hosts`, `/dev/*`, `/proc/*` synthesis -> Phase 4
- Auto-pull on `run` miss -> never; `elfuse oci pull` must run first
- Network policy, `docker run -p`-style port mapping -> later phases
- Live `docker exec`-style attach -> never

## Guest Compatibility Model

`elfuse` is designed for Linux user-space workloads, not for booting a Linux
kernel or presenting a complete Linux host environment. Compatibility comes
from targeted ABI translation and emulation at the syscall boundary.

That has a few direct implications:

- `/proc` and `/dev` are compatibility surfaces, not passthrough mounts.
- macOS and Linux file, socket, and signal semantics are normalized in the host
  syscall layer.
- Behavior is strongest for normal command-line tools, language runtimes, test
  binaries, and debugger-driven workflows.
