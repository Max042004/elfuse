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

`User` accepts seven shapes: the empty string (no override), a numeric
`UID`, `UID:GID`, a symbolic `name`, `name:group`, `uid:group`, or
`name:gid`. Symbolic forms read `/etc/passwd` and `/etc/group` from
the cloned rootfs. A token made entirely of ASCII digits is always
parsed numerically, even when a same-named account ships in the image
(this matches runc semantics, so an image that happens to carry a
`1234` account does not capture `--user 1234`). When the symbolic
form names an account the unpacked layers do not actually carry,
lookup fails closed; `elfuse` never silently falls back to root.
`--user UID` alone defaults GID to the same value.

`WorkingDir` must be absolute and free of `..` segments. If neither the
image nor the CLI sets it, the guest starts in `/`. The directory is
materialized under the cloned rootfs (`mkdir -p`, mode 0755, best-
effort chown to the resolved uid:gid when `--user` or image User
selects credentials).

### Scope guardrails

- Auto-pull on `run` miss -> never; `elfuse oci pull` must run first
- Network policy, `docker run -p`-style port mapping -> later phases
- Live `docker exec`-style attach -> never

### Runtime host-truth surface

`elfuse oci run` runs the guest against a freshly cloned per-run
rootfs and a small set of synthesized host-truth files. The rootfs
is produced by APFS `clonefile(2)` against the unpacked image
layers, so the first guest write to any path triggers copy-on-write
in APFS without touching the original image. The clone is removed at
guest exit unless `--keep` is set; nothing is ever pushed back to
the on-disk image, and concurrent `oci run` invocations against the
same image are isolated.

Three `/etc` files are overwritten in the clone before the guest
starts. Any pre-existing symlink (the common case is
`/etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf`) is
unlinked first so it does not dangle inside the guest:

| File | Source |
|--|--|
| `/etc/resolv.conf` | `nameserver` lines harvested from `scutil --dns`; falls back to `8.8.8.8` and `1.1.1.1` on any scutil failure |
| `/etc/hosts` | fixed 5-line block: `localhost`, the ip6-loopback aliases, ip6 link-local multicast, and `127.0.0.1 host.elfuse.internal` |
| `/etc/hostname` | literal string `elfuse` |

The following pseudo-filesystem paths are synthesized by the host-side
openat interceptor and do not need to exist inside the rootfs:

| Path | Behavior |
|--|--|
| `/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom`, `/dev/tty` | redirected to the host device of the same name |
| `/dev/full` | reads zero-fill, writes of any non-zero length return `ENOSPC` |
| `/dev/console` | mirrored from the controlling tty when present (macOS reserves the real `/dev/console` for the kernel) |
| other `/dev/*` | `ENOENT` |
| `/proc/cpuinfo`, `/proc/meminfo`, `/proc/version` | derived from host sysctl |
| `/proc/self/{maps,exe,status,stat,comm,statm,cgroup}` | synthesized; `cgroup` reports the canonical `0::/` (elfuse runs outside any cgroup hierarchy) |
| `/proc/sys/kernel/{ostype,osrelease,hostname}` | tracks the cached `uname` fields (`Linux`, `6.17.0-20-generic`, `elfuse`) |

### Libc-adjacent compatibility

`elfuse` does not patch libc-adjacent payload (NSS modules, time-zone
data, locale data, character-set converters, dynamic-linker cache)
inside the guest. Each item below names the contract `elfuse` honors
and the failure mode an image hits when it does not ship the
matching files.

- **`/etc/nsswitch.conf`** is read by the guest's libc, not by
  `elfuse`. Only the `files` and `dns` backends actually function:
  `files` resolves through `/etc/{passwd,group,hosts}` in the cloned
  rootfs, and `dns` resolves through host `getaddrinfo` via the
  synthesized `/etc/resolv.conf`. Backends such as `systemd`, `sss`,
  or `ldap` need their NSS shared object plus a matching daemon,
  neither of which `elfuse` provides.
- **NSS shared objects** (`libnss_systemd.so`, `libnss_sss.so`,
  `libnss_ldap.so`, ...) are `dlopen`'d by guest libc against its own
  loader. `elfuse` never injects NSS modules: they are aarch64-linux
  ELF objects against guest libc, so the macOS host has no way to
  load them, and the guest can only `dlopen` the modules its image
  already carries.
- **tzdata** (`/usr/share/zoneinfo`, `/etc/localtime`, `/etc/timezone`)
  ships with the image. `elfuse` does not transcode macOS
  `/var/db/timezone/zoneinfo` into the tzdata format; if the image is
  missing the needed zone, glibc / musl fall back to UTC. The `TZ`
  environment variable is honored as-is and is not rewritten by the
  Env merge policy.
- **`/usr/lib/locale/locale-archive`** is not regenerated. glibc
  images without a built archive (or the matching `<lang>.UTF-8/`
  directory) fall back to the `C` locale; locale-aware sort / printf
  / strcoll outputs ASCII order. musl images do not use the archive
  and are unaffected.
- **`/usr/lib/<triple>/gconv/`** modules and the `gconv-modules`
  index ship with the image. Missing modules surface as `EILSEQ` from
  `iconv` / glibc's character-set conversion; this most often shows
  up when an image ships a stripped glibc layer.
- **`ld.so.cache`** is not rebuilt. The guest dynamic linker reads
  whatever cache the image carries; missing entries fall through to
  the linker's library-path search, which is the normal slow path.

Common workloads and the symptom-to-workaround mapping:

| Symptom | Trigger | Workaround |
|--|--|--|
| `getaddrinfo` returns `EAI_AGAIN` or an empty result | `/etc/nsswitch.conf` lists a backend (`systemd`, `sss`, ...) that needs a daemon | use a distro whose `nsswitch.conf` is `files dns` (alpine ships this by default; debian needs the file edited) |
| `date`, `strftime` show UTC instead of the expected zone | the image does not contain `/usr/share/zoneinfo/<Zone>` | install tzdata in the image (`apk add tzdata` / `apt install tzdata`), or pass `-e TZ=UTC` to acknowledge UTC |
| `sort`, `printf`, `strcoll` collate in ASCII order | the image is missing `/usr/lib/locale/locale-archive` or the matching `<lang>.UTF-8/` directory | accept the C-locale fallback, run `locale-gen` during the image build, or use a musl-based image (alpine), which does not depend on the archive |

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
