# elfuse — aarch64-linux ELF executor on macOS Apple Silicon
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# Usage:
#   make <target> [SIGN_IDENTITY="Your Signing Identity"]
#
# Example: make elfuse
#          make test-hello
#          make V=1 elfuse    (verbose — show full commands)

.DEFAULT_GOAL := help
.DELETE_ON_ERROR:

include mk/toolchain.mk
include mk/config.mk

# Source files.
SRCS := \
    main.c \
    core/guest.c \
    core/elf.c \
    core/stack.c \
    core/vdso.c \
    core/bootstrap.c \
    core/launch.c \
    core/sysroot.c \
    runtime/thread.c \
    runtime/futex.c \
    runtime/forkipc.c \
    runtime/fork-state.c \
    runtime/procemu.c \
    runtime/proctitle.c \
    syscall/syscall.c \
    syscall/fdtable.c \
    syscall/translate.c \
    syscall/mem.c \
    syscall/path.c \
    syscall/sidecar.c \
    syscall/fs.c \
    syscall/fs-stat.c \
    syscall/fs-xattr.c \
    syscall/io.c \
    syscall/poll.c \
    syscall/fd.c \
    syscall/inotify.c \
    syscall/time.c \
    syscall/sys.c \
    syscall/proc.c \
    syscall/proc-identity.c \
    syscall/proc-pidfd.c \
    syscall/proc-state.c \
    syscall/exec.c \
    syscall/signal.c \
    syscall/net.c \
    syscall/net-msg.c \
    syscall/net-abi.c \
    syscall/net-absock.c \
    syscall/net-sockopt.c \
    syscall/netlink.c \
    syscall/sysvipc.c \
    debug/crashreport.c \
    debug/gdbstub.c \
    debug/gdbstub-reg.c \
    debug/gdbstub-rsp.c \
    debug/log.c \
    oci/ref.c \
    oci/cli.c \
    oci/digest.c \
    oci/blob-store.c \
    oci/media-type.c \
    oci/manifest.c \
    oci/fetch.c \
    oci/store.c \
    oci/pull.c \
    oci/inspect.c \
    oci/tar.c \
    oci/decompress.c \
    oci/layer-meta.c \
    oci/layer-apply.c \
    oci/volume.c \
    oci/clone-rootfs.c \
    oci/unpack.c

SRCS := $(addprefix src/,$(SRCS))
OBJS := $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# Vendored cJSON: third-party MIT JSON parser pinned at v1.7.18. Only OCI
# translation units include it. Compiles cleanly with the project warning
# posture, so no per-file CFLAGS override is required.
CJSON_DIR := externals/cjson
CJSON_OBJ := $(BUILD_DIR)/externals/cjson/cJSON.o
OBJS += $(CJSON_OBJ)

$(CJSON_OBJ): $(CJSON_DIR)/cJSON.c $(CJSON_DIR)/cJSON.h | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	@echo "  CC      $<"
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

# Vendored zstd v1.5.6 (decode-only). Phase 2 OCI layer unpack consumes
# zstd-compressed layer media types. Compression, dictBuilder, deprecated,
# and legacy v01-v06 paths are NOT vendored; do not call ZSTD_compress*.
# Only src/oci/decompress.c includes externals/zstd/lib/zstd.h.
ZSTD_DIR := externals/zstd
ZSTD_SRCS := $(wildcard $(ZSTD_DIR)/lib/common/*.c) \
             $(wildcard $(ZSTD_DIR)/lib/decompress/*.c)
ZSTD_OBJS := $(patsubst $(ZSTD_DIR)/%.c,$(BUILD_DIR)/externals/zstd/%.o,$(ZSTD_SRCS))
OBJS += $(ZSTD_OBJS)

ZSTD_CFLAGS := -DZSTD_DISABLE_ASM=1 -DZSTD_LEGACY_SUPPORT=0 \
               -DZSTD_MULTITHREAD=0 -DZSTDLIB_VISIBILITY= \
               -Wno-pedantic -Wno-shadow -Wno-strict-prototypes \
               -Wno-missing-prototypes -Wno-unused-parameter \
               -Wno-cast-align -Wno-implicit-fallthrough \
               -I$(ZSTD_DIR)/lib -I$(ZSTD_DIR)/lib/common

$(BUILD_DIR)/externals/zstd/%.o: $(ZSTD_DIR)/%.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	@echo "  CC      $<"
	$(Q)$(CC) $(CFLAGS) $(ZSTD_CFLAGS) -c -o $@ $<

DISPATCH_MANIFEST := src/syscall/dispatch.tbl
DISPATCH_GENERATOR := scripts/gen-syscall-dispatch.py
DISPATCH_HEADER := $(BUILD_DIR)/dispatch.h
# -lz: gzip-compressed OCI layers route through zlib (system library).
# -lcurl: HTTPS fetch for the Phase 1 oci pull path.
HVF_LDFLAGS := -framework Hypervisor -arch arm64 -lcurl -lz

# Generated headers under build/ that must exist before compiling sources that
# include them.
GENERATED_HEADERS := $(BUILD_DIR)/shim_blob.h $(BUILD_DIR)/version.h $(DISPATCH_HEADER)

include mk/common.mk
include mk/shim.mk

define link-and-sign
	@echo "  LD      $1"
	$(Q)tmp="$1.$$$$.tmp"; \
	$(CC) $(CFLAGS) -o "$$tmp" $2 $(HVF_LDFLAGS); \
	echo "  SIGN    $1"; \
	codesign --entitlements $(ENTITLEMENTS) -f -s "$(SIGN_IDENTITY)" "$$tmp"; \
	mv "$$tmp" "$1"
endef

# ── Main executable ──────────────────────────────────────────────
.PHONY: all elfuse
.PHONY: gen-syscall-dispatch check-syscall-dispatch

all: elfuse

## Regenerate build/dispatch.h from src/syscall/dispatch.tbl
gen-syscall-dispatch:
	@python3 $(DISPATCH_GENERATOR)

## Verify build/dispatch.h matches the generator output
check-syscall-dispatch: $(DISPATCH_HEADER)
	@python3 $(DISPATCH_GENERATOR) --check

$(DISPATCH_HEADER): $(DISPATCH_MANIFEST) $(DISPATCH_GENERATOR) src/syscall/abi.h | $(BUILD_DIR)
	@echo "  GEN     $@"
	$(Q)tmp="$@.$$$$.tmp"; \
	python3 $(DISPATCH_GENERATOR) --output "$$tmp"; \
	cmp -s "$$tmp" "$@" 2>/dev/null || mv "$$tmp" "$@"; \
	rm -f "$$tmp"

$(BUILD_DIR)/syscall/syscall.o: $(DISPATCH_HEADER)

## Build the elfuse executable
elfuse: $(ELFUSE_BIN)

$(ELFUSE_BIN): $(OBJS) | $(BUILD_DIR)
	$(call link-and-sign,$@,$(OBJS))

# ── Native test binaries (macOS, Hypervisor.framework) ───────────

## Build the multi-vCPU HVF validation test (native macOS binary)
$(BUILD_DIR)/test-multi-vcpu: $(BUILD_DIR)/test-multi-vcpu.o | $(BUILD_DIR)
	$(call link-and-sign,$@,$<)

## Build the RWX W^X validation test (native macOS binary)
$(BUILD_DIR)/test-rwx: $(BUILD_DIR)/test-rwx.o | $(BUILD_DIR)
	$(call link-and-sign,$@,$<)

## Build the OCI reference parser unit test (native macOS binary).
## Pure C, no HVF, no codesign required.
$(BUILD_DIR)/test-oci-ref: $(BUILD_DIR)/test-oci-ref.o $(BUILD_DIR)/oci/ref.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI digest unit test (native macOS binary). Pure C, no HVF.
$(BUILD_DIR)/test-oci-digest: $(BUILD_DIR)/test-oci-digest.o $(BUILD_DIR)/oci/digest.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI blob store unit test (native macOS binary). Pure C, no HVF.
$(BUILD_DIR)/test-oci-blob-store: $(BUILD_DIR)/test-oci-blob-store.o $(BUILD_DIR)/oci/blob-store.o $(BUILD_DIR)/oci/digest.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI manifest / index / config parser unit test (native, no HVF).
$(BUILD_DIR)/test-oci-manifest: $(BUILD_DIR)/test-oci-manifest.o $(BUILD_DIR)/oci/manifest.o $(BUILD_DIR)/oci/media-type.o $(BUILD_DIR)/oci/digest.o $(CJSON_OBJ) | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the shared OCI mock HTTPS server helper. tests/lib/oci-mock.{c,h}
## terminates TLS via libssl from brew openssl@3; both the fetch and pull
## suites link against the same compiled object to avoid duplicating ~400 LOC
## of scaffolding in their own translation units.
$(BUILD_DIR)/lib/oci-mock.o: CFLAGS += $(OPENSSL_CFLAGS)

## Build the OCI fetch (libcurl) unit test (native macOS, no HVF). Pulls in
## blob-store + digest + manifest models + cJSON; links against system libcurl
## and the platform pthread runtime for the in-process mock HTTP server. The
## test mock terminates TLS using libssl from brew openssl@3 so the ca_file
## negative cases exercise a real certificate verification path.
$(BUILD_DIR)/test-oci-fetch.o: CFLAGS += $(OPENSSL_CFLAGS)
$(BUILD_DIR)/test-oci-fetch: $(BUILD_DIR)/test-oci-fetch.o $(BUILD_DIR)/lib/oci-mock.o $(BUILD_DIR)/oci/fetch.o $(BUILD_DIR)/oci/blob-store.o $(BUILD_DIR)/oci/digest.o $(BUILD_DIR)/oci/manifest.o $(BUILD_DIR)/oci/media-type.o $(BUILD_DIR)/oci/ref.o $(CJSON_OBJ) | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lcurl -lpthread $(OPENSSL_LDFLAGS)

## Build the OCI local store unit test (native macOS, no HVF). Pure C; links
## against the store wrapper plus its blob-store and digest dependencies.
$(BUILD_DIR)/test-oci-store: $(BUILD_DIR)/test-oci-store.o $(BUILD_DIR)/oci/store.o $(BUILD_DIR)/oci/blob-store.o $(BUILD_DIR)/oci/digest.o $(BUILD_DIR)/oci/ref.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI pull pipeline unit test (native macOS, no HVF). Shares the
## TLS-terminating mock server with test-oci-fetch via tests/lib/oci-mock.
$(BUILD_DIR)/test-oci-pull.o: CFLAGS += $(OPENSSL_CFLAGS)
$(BUILD_DIR)/test-oci-pull: $(BUILD_DIR)/test-oci-pull.o $(BUILD_DIR)/lib/oci-mock.o $(BUILD_DIR)/oci/pull.o $(BUILD_DIR)/oci/store.o $(BUILD_DIR)/oci/fetch.o $(BUILD_DIR)/oci/blob-store.o $(BUILD_DIR)/oci/digest.o $(BUILD_DIR)/oci/manifest.o $(BUILD_DIR)/oci/media-type.o $(BUILD_DIR)/oci/ref.o $(CJSON_OBJ) | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lcurl -lpthread $(OPENSSL_LDFLAGS)

## Build the OCI inspect renderer unit test (native macOS, no HVF). Pure
## offline: no fetcher, no mock server, no libcurl. Pre-populates the store
## via oci_blob_store_put_bytes + oci_store_put_ref.
$(BUILD_DIR)/test-oci-inspect: $(BUILD_DIR)/test-oci-inspect.o $(BUILD_DIR)/oci/inspect.o $(BUILD_DIR)/oci/store.o $(BUILD_DIR)/oci/blob-store.o $(BUILD_DIR)/oci/digest.o $(BUILD_DIR)/oci/manifest.o $(BUILD_DIR)/oci/media-type.o $(BUILD_DIR)/oci/ref.o $(CJSON_OBJ) | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI tar reader unit test (native macOS, no HVF). Pure C; the
## test constructs ustar / GNU long-name streams in memory and drives them
## through the reader via a callback that exercises short-read chunking.
$(BUILD_DIR)/test-oci-tar: $(BUILD_DIR)/test-oci-tar.o $(BUILD_DIR)/oci/tar.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI runspec unit test (native macOS, no HVF). Pure-data
## merge of image-config runtime block + CLI overrides; the test feeds
## oci_image_runtime_t literals directly through oci_runspec_build with
## no filesystem or libcurl dependency.
$(BUILD_DIR)/test-oci-runspec: $(BUILD_DIR)/test-oci-runspec.o $(BUILD_DIR)/oci/runspec.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI path-resolve unit test (native macOS, no HVF). Touches
## the host filesystem to build a small fake sysroot tree and drives
## oci_path_resolve through realpath / stat / symlink-follow scenarios.
## Pure C; no libcurl, no zstd, no HVF.
$(BUILD_DIR)/test-oci-path-resolve: $(BUILD_DIR)/test-oci-path-resolve.o $(BUILD_DIR)/oci/path-resolve.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## decompress.c is the only translation unit in elfuse that includes
## externals/zstd/lib/zstd.h. Attach the zstd include path as a target-
## specific CFLAG so the rest of the codebase never sees zstd headers.
$(BUILD_DIR)/oci/decompress.o: CFLAGS += -I$(ZSTD_DIR)/lib

## Build the OCI sidecar metadata unit test (native macOS, no HVF). Pure
## C; links against cJSON for the JSON round-trip plus the layer-meta
## translation unit.
$(BUILD_DIR)/test-oci-meta: $(BUILD_DIR)/test-oci-meta.o $(BUILD_DIR)/oci/layer-meta.o $(CJSON_OBJ) | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI layer applier unit test (native macOS, no HVF). Builds
## tar payloads in memory, drives them through oci_layer_apply into a
## tmp tree, and verifies filesystem state via lstat/readlink.
$(BUILD_DIR)/test-oci-layer-apply: $(BUILD_DIR)/test-oci-layer-apply.o $(BUILD_DIR)/oci/layer-apply.o $(BUILD_DIR)/oci/layer-meta.o $(BUILD_DIR)/oci/tar.o $(CJSON_OBJ) | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI volume bootstrap unit test (native macOS, no HVF).
## Default-volume test is gated behind OCI_VOLUME_TEST=1 because it
## costs ~150 ms of hdiutil orchestration on first run. Links
## src/core/sysroot.o for the hdiutil wrappers PR #33 introduced.
$(BUILD_DIR)/test-oci-volume: $(BUILD_DIR)/test-oci-volume.o $(BUILD_DIR)/oci/volume.o $(BUILD_DIR)/core/sysroot.o $(BUILD_DIR)/debug/log.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI clone-rootfs unit test (native macOS, no HVF). The
## test skips itself if clonefile returns ENOTSUP (non-APFS scratch).
$(BUILD_DIR)/test-oci-clone: $(BUILD_DIR)/test-oci-clone.o $(BUILD_DIR)/oci/clone-rootfs.o | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^

## Build the OCI unpack orchestrator integration smoke (native macOS,
## no HVF). Pulls in the full Phase 2 OCI stack so the dependency
## edges between modules are exercised at link time.
$(BUILD_DIR)/test-oci-unpack: $(BUILD_DIR)/test-oci-unpack.o $(BUILD_DIR)/oci/unpack.o $(BUILD_DIR)/oci/volume.o $(BUILD_DIR)/oci/clone-rootfs.o $(BUILD_DIR)/oci/layer-apply.o $(BUILD_DIR)/oci/layer-meta.o $(BUILD_DIR)/oci/decompress.o $(BUILD_DIR)/oci/tar.o $(BUILD_DIR)/oci/store.o $(BUILD_DIR)/oci/blob-store.o $(BUILD_DIR)/oci/digest.o $(BUILD_DIR)/oci/manifest.o $(BUILD_DIR)/oci/media-type.o $(BUILD_DIR)/oci/ref.o $(BUILD_DIR)/core/sysroot.o $(BUILD_DIR)/debug/log.o $(CJSON_OBJ) $(ZSTD_OBJS) | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lz

## Build the OCI decompression dispatch unit test (native macOS, no HVF).
## Links zstd objects + system zlib so gzip and zstd payloads both round-
## trip through oci_stream_t. The gzip fixture is generated at test time
## via zlib; the zstd fixture is an embedded byte array because the
## vendored libzstd is decode-only.
$(BUILD_DIR)/test-oci-decompress.o: CFLAGS += -I$(ZSTD_DIR)/lib
$(BUILD_DIR)/test-oci-decompress: $(BUILD_DIR)/test-oci-decompress.o $(BUILD_DIR)/oci/decompress.o $(ZSTD_OBJS) | $(BUILD_DIR)
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) -o $@ $^ -lz

# ── Guest test binaries (cross-compiled, aarch64-linux) ──────────
# Only used when GUEST_TEST_BINARIES is not set.

ifndef GUEST_TEST_BINARIES
$(BUILD_DIR)/test-hello: tests/hello.S tests/simple.ld | $(BUILD_DIR)
	@echo "  AS      tests/hello.S"
	$(Q)$(BAREMETAL_CROSS)as -o $(BUILD_DIR)/test-hello.o tests/hello.S
	@echo "  LD      $@"
	$(Q)$(BAREMETAL_CROSS)ld -T tests/simple.ld -o $@ $(BUILD_DIR)/test-hello.o

# Pattern rule: cross-compile tests/*.c to static aarch64-linux binaries
# -D_GNU_SOURCE exposes pipe2/dup3/O_DIRECT/etc. on glibc (musl exposes them by default)
$(BUILD_DIR)/%: tests/%.c | $(BUILD_DIR)
	@echo "  CROSS   $<"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $<

# test-pthread needs -lpthread
$(BUILD_DIR)/test-pthread: tests/test-pthread.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-sched-policy spawns a pthread to verify per-thread TID lookup
$(BUILD_DIR)/test-sched-policy: tests/test-sched-policy.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-signalfd-hardening needs -lpthread for the worker-thread tid
# regression case in test_rt_sigqueueinfo_rejects_thread_tid.
$(BUILD_DIR)/test-signalfd-hardening: tests/test-signalfd-hardening.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-futex-waitv needs -lpthread for the host wake-thread used to unblock
# the main thread's futex_waitv.
$(BUILD_DIR)/test-futex-waitv: tests/test-futex-waitv.c | $(BUILD_DIR)
	@echo "  CROSS   $< (with -lpthread)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -o $@ $< -lpthread

# test-fork-lowbase must be a non-PIE ET_EXEC linked below ELF_DEFAULT_BASE so
# nested forks exercise elf_load_min preservation across fork IPC.
$(BUILD_DIR)/test-fork-lowbase: tests/test-fork-lowbase.c | $(BUILD_DIR)
	@echo "  CROSS   $< (low-base ET_EXEC)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -no-pie \
		-Wl,-Ttext-segment=0x200000 -o $@ $<

# test-lowbase-mem variants must be non-PIE ET_EXEC binaries linked below
# ELF_DEFAULT_BASE so mprotect/munmap exercise the old low-address reject
# window at two offsets.
$(BUILD_DIR)/test-lowbase-mem-200000: tests/test-lowbase-mem.c | $(BUILD_DIR)
	@echo "  CROSS   $< (low-base ET_EXEC @0x200000)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -no-pie \
		-Wl,-Ttext-segment=0x200000 -o $@ $<

$(BUILD_DIR)/test-lowbase-mem-300000: tests/test-lowbase-mem.c | $(BUILD_DIR)
	@echo "  CROSS   $< (low-base ET_EXEC @0x300000)"
	$(Q)$(CROSS_COMPILE)gcc -D_GNU_SOURCE -static -O2 -no-pie \
		-Wl,-Ttext-segment=0x300000 -o $@ $<

endif

include mk/tests.mk
include mk/analysis.mk
include mk/help.mk
