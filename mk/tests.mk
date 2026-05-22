# Test targets

.PHONY: test-hello test-all check check-syscall-coverage test-gdbstub test-coreutils test-busybox \
        test-static-bins \
        test-dynamic test-dynamic-coreutils test-glibc-dynamic \
        test-glibc-coreutils test-perf \
        test-matrix test-matrix-elfuse-aarch64 test-matrix-qemu-aarch64 \
        test-full test-multi-vcpu test-rwx \
        test-oci-ref test-oci-digest test-oci-blob-store test-oci-manifest \
        test-oci-fetch test-oci-fetch-online test-oci-store test-oci-pull \
        test-oci-inspect test-oci-dedup-metrics test-oci-rebuild-cache \
        test-oci-status \
        test-oci-policy \
        test-oci-tar test-oci-decompress test-oci-meta \
        test-oci-origin \
        test-oci-layer-apply test-oci-volume test-oci-clone \
        test-oci-unpack test-oci-runspec test-oci-user test-oci-path-resolve \
        test-oci-runtime-files \
        test-oci-run test-oci-compat oci-fixture-builder \
        test-sysroot-rename \
        test-case-collision test-case-collision-fallback test-sysroot-create-paths \
        test-proctitle-low-stack \
        test-sysroot-procfs-exec test-timeout-disable \
        test-sysroot-nofollow test-sysroot-chdir perf

## Build and run the assembly hello world test
test-hello: $(ELFUSE_BIN) $(TEST_HELLO_DEP)
	@printf "$(BLUE)▸ Running$(RESET) test-hello\n"
	$(ELFUSE_BIN) $(TEST_DIR)/test-hello

## Verify dispatch.tbl coverage of the kernel-supported syscall set
check-syscall-coverage:
	@python3 scripts/check-syscall-coverage.py

## Run the unit test suite plus busybox applet validation
check: $(ELFUSE_BIN) $(TEST_DEPS) check-syscall-coverage
	@bash tests/driver.sh -e $(ELFUSE_BIN) -d $(TEST_DIR) -v
	@printf "\n$(BLUE)━━━ proctitle low-stack regression ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-proctitle-low-stack
	@printf "\n$(BLUE)━━━ busybox applet validation ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-busybox
	@printf "\n$(BLUE)━━━ sysroot procfs exec validation ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-sysroot-procfs-exec
	@printf "\n$(BLUE)━━━ timeout=0 validation ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-timeout-disable
	@printf "\n$(BLUE)━━━ OCI reference parser unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-ref
	@printf "\n$(BLUE)━━━ OCI digest unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-digest
	@printf "\n$(BLUE)━━━ OCI blob store unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-blob-store
	@printf "\n$(BLUE)━━━ OCI manifest parser unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-manifest
	@printf "\n$(BLUE)━━━ OCI fetch unit tests (offline mock HTTP) ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-fetch
	@printf "\n$(BLUE)━━━ OCI store unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-store
	@printf "\n$(BLUE)━━━ OCI pull pipeline unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-pull
	@printf "\n$(BLUE)━━━ OCI inspect renderer unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-inspect
	@printf "\n$(BLUE)━━━ OCI cross-image dedup metrics unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-dedup-metrics
	@printf "\n$(BLUE)━━━ OCI rebuild-cache unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-rebuild-cache
	@printf "\n$(BLUE)━━━ OCI store-wide status unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-status
	@printf "\n$(BLUE)━━━ OCI policy.json loader unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-policy
	@printf "\n$(BLUE)━━━ OCI tar reader unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-tar
	@printf "\n$(BLUE)━━━ OCI decompression dispatch unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-decompress
	@printf "\n$(BLUE)━━━ OCI sidecar metadata unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-meta
	@printf "\n$(BLUE)━━━ OCI origin sidecar unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-origin
	@printf "\n$(BLUE)━━━ OCI layer applier unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-layer-apply
	@printf "\n$(BLUE)━━━ OCI volume bootstrap unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-volume
	@printf "\n$(BLUE)━━━ OCI clone-rootfs unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-clone
	@printf "\n$(BLUE)━━━ OCI unpack orchestrator smoke ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-unpack
	@printf "\n$(BLUE)━━━ OCI runspec resolver unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-runspec
	@printf "\n$(BLUE)━━━ OCI User-field resolver unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-user
	@printf "\n$(BLUE)━━━ OCI path-resolve unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-path-resolve
	@printf "\n$(BLUE)━━━ OCI runtime-files injection unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-runtime-files
	@printf "\n$(BLUE)━━━ OCI run orchestrator unit tests ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-run
	@printf "\n$(BLUE)━━━ OCI compat shell smoke ━━━$(RESET)\n"
	@$(MAKE) --no-print-directory test-oci-compat

## Run the OCI image reference parser unit tests (native, no HVF)
test-oci-ref: $(BUILD_DIR)/test-oci-ref
	@$(BUILD_DIR)/test-oci-ref

## Run the OCI digest unit tests (native, no HVF)
test-oci-digest: $(BUILD_DIR)/test-oci-digest
	@$(BUILD_DIR)/test-oci-digest

## Run the OCI blob store unit tests (native, no HVF)
test-oci-blob-store: $(BUILD_DIR)/test-oci-blob-store
	@$(BUILD_DIR)/test-oci-blob-store

## Run the OCI manifest / index / config parser unit tests (native, no HVF)
test-oci-manifest: $(BUILD_DIR)/test-oci-manifest
	@$(BUILD_DIR)/test-oci-manifest

## Run the OCI fetch unit tests against an in-process mock HTTP server
## (native, no HVF, no network).
test-oci-fetch: $(BUILD_DIR)/test-oci-fetch
	@$(BUILD_DIR)/test-oci-fetch

## Pull alpine:3.20 from Docker Hub anonymously, verify manifest parse and
## blob digests against a real registry. Opt-in; requires network. Not run by
## `make check`.
test-oci-fetch-online: $(BUILD_DIR)/test-oci-fetch
	@OCI_FETCH_ONLINE=1 $(BUILD_DIR)/test-oci-fetch

## Run the OCI local store unit tests (native, no HVF)
test-oci-store: $(BUILD_DIR)/test-oci-store
	@$(BUILD_DIR)/test-oci-store

## Run the OCI pull pipeline unit tests (native, no HVF, no network)
test-oci-pull: $(BUILD_DIR)/test-oci-pull
	@$(BUILD_DIR)/test-oci-pull

## Run the OCI inspect renderer unit tests (native, no HVF, no network)
test-oci-inspect: $(BUILD_DIR)/test-oci-inspect
	@$(BUILD_DIR)/test-oci-inspect

## Run the OCI cross-image dedup metrics unit tests (native, no HVF, no network).
## Phase 1 Plan 3 C3.4: validates oci_dedup_metrics_compute against pin-only
## and pin + unpacked-tree scratch stores.
test-oci-dedup-metrics: $(BUILD_DIR)/test-oci-dedup-metrics
	@$(BUILD_DIR)/test-oci-dedup-metrics

## Run the OCI rebuild-cache unit tests (native, no HVF, no network).
## Phase 1 Plan 3 C3.5: validates oci_rebuild_cache against scratch
## stores hand-populated via oci_origin_write into a fixture
## <volume>/images/sha256-<hex>/ tree.
test-oci-rebuild-cache: $(BUILD_DIR)/test-oci-rebuild-cache
	@$(BUILD_DIR)/test-oci-rebuild-cache

## Run the OCI store-wide status unit tests (native, no HVF, no network).
## Phase 1 Plan 4 C4.1: validates oci_status_compute against scratch stores
## hand-populated via stage_image + oci_origin_write fixture helpers.
test-oci-status: $(BUILD_DIR)/test-oci-status
	@$(BUILD_DIR)/test-oci-status

## Run the OCI policy.json schema and loader unit tests (native, no HVF,
## no network). Phase 1 Plan 6 C6.1: validates oci_policy_load against
## scratch HOME / XDG / override trees, the load-order chain, and the
## per-host effective view returned by oci_policy_lookup.
test-oci-policy: $(BUILD_DIR)/test-oci-policy
	@$(BUILD_DIR)/test-oci-policy

## Run the OCI tar reader unit tests (native, no HVF, no network)
test-oci-tar: $(BUILD_DIR)/test-oci-tar
	@$(BUILD_DIR)/test-oci-tar

## Run the OCI decompression dispatch unit tests (native, no HVF, no network)
test-oci-decompress: $(BUILD_DIR)/test-oci-decompress
	@$(BUILD_DIR)/test-oci-decompress

## Run the OCI sidecar metadata unit tests (native, no HVF, no network)
test-oci-meta: $(BUILD_DIR)/test-oci-meta
	@$(BUILD_DIR)/test-oci-meta

## Run the OCI origin sidecar unit tests (native, no HVF, no network).
## Covers oci_origin_write + cJSON parse-back round-trips. Phase 3 sees
## the file in unpacked image directories; Plan 1's root-set walker
## consumes it to attribute layer blobs back to live sysroots.
test-oci-origin: $(BUILD_DIR)/test-oci-origin
	@$(BUILD_DIR)/test-oci-origin

## Run the OCI layer applier unit tests (native, no HVF, no network)
test-oci-layer-apply: $(BUILD_DIR)/test-oci-layer-apply
	@$(BUILD_DIR)/test-oci-layer-apply

## Run the OCI volume bootstrap unit tests (native, no HVF). The
## default-sparsebundle case is gated behind OCI_VOLUME_TEST=1 because
## hdiutil orchestration is slow.
test-oci-volume: $(BUILD_DIR)/test-oci-volume
	@$(BUILD_DIR)/test-oci-volume

## Run the OCI clone-rootfs unit tests (native, no HVF). Skips itself
## if the test scratch directory does not support clonefile.
test-oci-clone: $(BUILD_DIR)/test-oci-clone
	@$(BUILD_DIR)/test-oci-clone

## Run the OCI unpack orchestrator smoke (native, no HVF). The full
## end-to-end fixture is gated behind OCI_VOLUME_TEST=1.
test-oci-unpack: $(BUILD_DIR)/test-oci-unpack
	@$(BUILD_DIR)/test-oci-unpack

## Run the OCI runspec resolver unit tests (native, no HVF, no network).
## Feeds hand-built oci_image_runtime_t literals plus synthetic CLI flags
## through oci_runspec_build and asserts argv / envp / uid / cwd outputs
## against the Phase 3 override matrix and Env policy. Phase 4 symbolic
## User cases write scratch /tmp rootfses for /etc/passwd lookup.
test-oci-runspec: $(BUILD_DIR)/test-oci-runspec
	@$(BUILD_DIR)/test-oci-runspec

## Run the OCI User-field resolver unit tests (native, no HVF, no network).
## Phase 4 F4.7: validates oci_user_lookup against scratch rootfses
## carrying synthetic /etc/passwd / /etc/group; covers the seven OCI
## image-spec User shapes plus the policy edges (digit-name collision,
## missing passwd, name-not-found, invalid characters).
test-oci-user: $(BUILD_DIR)/test-oci-user
	@$(BUILD_DIR)/test-oci-user

## Run the OCI guest PATH resolver unit tests (native, no HVF, no network).
## Builds a fake sysroot tree under /tmp and drives oci_path_resolve
## against it: PATH search, symlink-follow, escape-symlink skip,
## EACCES on noexec, ENOENT diagnostics with searched-dirs list.
test-oci-path-resolve: $(BUILD_DIR)/test-oci-path-resolve
	@$(BUILD_DIR)/test-oci-path-resolve

## Run the OCI runtime-files injection unit tests (native, no HVF, no network).
## Phase 4 F4.2 / F4.3: validates oci_runtime_files_inject against scratch
## run directories, covering fresh-/etc creation, symlink overwrite,
## regular-file overwrite, and the synthesised /etc/{resolv.conf,
## hosts, hostname} content.
test-oci-runtime-files: $(BUILD_DIR)/test-oci-runtime-files
	@$(BUILD_DIR)/test-oci-runtime-files

## Run the OCI run orchestrator unit tests (native, no HVF, no network).
## Covers oci_cli_run argument parsing plus oci_run early-failure
## paths against a case-insensitive volume; the launch backend is
## stubbed via oci_run_set_launch_for_testing so the test never spins
## up a real HVF VM. End-to-end launch coverage lives in the Phase 3
## commit 6 compat shell suite.
test-oci-run: $(BUILD_DIR)/test-oci-run
	@$(BUILD_DIR)/test-oci-run

## Build the OCI fixture builder tool. Standalone executable used by
## tests/test-oci-compat.sh and available for hand-rolled fixtures.
oci-fixture-builder: $(BUILD_DIR)/oci-fixture-builder

## Run the OCI run compatibility shell smoke (native, no HVF). Default
## mode covers CLI surface + fixture-builder integration; OCI_COMPAT_TEST=1
## gates the heavy end-to-end harness (hdiutil sparsebundle + actual
## elfuse oci run launches); OCI_FETCH_ONLINE=1 gates the docker.io
## pull + run sibling. Requires test-hello (assembly aarch64 ELF) +
## elfuse + oci-fixture-builder pre-built.
test-oci-compat: $(ELFUSE_BIN) $(BUILD_DIR)/oci-fixture-builder $(TEST_HELLO_DEP)
	@bash tests/test-oci-compat.sh

test-sysroot-rename: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-rename
	@tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"; rm -f /tmp/elfuse-sysroot-rename-dst.txt' EXIT; \
	mkdir -p "$$tmpdir/tmp"; \
	printf 'inside-sysroot\n' > "$$tmpdir/tmp/elfuse-sysroot-rename-src.txt"; \
	rm -f /tmp/elfuse-sysroot-rename-dst.txt; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" $(BUILD_DIR)/test-sysroot-rename; \
	if [ -f "$$tmpdir/tmp/elfuse-sysroot-rename-src.txt" ]; then \
		printf "$(RED)FAIL$(RESET) rename did not remove source from sysroot\n"; \
		exit 1; \
	fi; \
	if [ -e /tmp/elfuse-sysroot-rename-dst.txt ]; then \
		printf "$(RED)FAIL$(RESET) rename escaped sysroot to host /tmp\n"; \
		exit 1; \
	fi

test-sysroot-nofollow: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-nofollow
	@tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	mkdir -p "$$tmpdir/tmp"; \
	ln -sf /outside-target "$$tmpdir/tmp/elfuse-sysroot-nofollow-link"; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" $(BUILD_DIR)/test-sysroot-nofollow

test-sysroot-chdir: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-chdir
	@tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	mkdir -p "$$tmpdir/bin" "$$tmpdir/lib" "$$tmpdir/lib/elfuse-sysroot-shadow"; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" $(BUILD_DIR)/test-sysroot-chdir

test-case-collision: $(ELFUSE_BIN) $(BUILD_DIR)/test-case-collision
	@tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	$(ELFUSE_BIN) --create-sysroot "$$tmpdir/case-sysroot" $(BUILD_DIR)/test-case-collision

test-case-collision-fallback: $(ELFUSE_BIN) $(BUILD_DIR)/test-case-collision
	@tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" $(BUILD_DIR)/test-case-collision

test-sysroot-create-paths: $(ELFUSE_BIN) $(BUILD_DIR)/test-sysroot-create-paths
	@tmpdir=$$(mktemp -d); \
	guest_tmp="/tmp/elfuse-sysroot-create-paths/file.txt"; \
	mounted_tmp="$$tmpdir/case-sysroot/tmp/elfuse-sysroot-create-paths/file.txt"; \
	host_out_dir="$$tmpdir/host-out"; \
	host_out="$$host_out_dir/result.txt"; \
	trap 'rm -rf "$$tmpdir"; rm -rf /tmp/elfuse-sysroot-create-paths' EXIT; \
	rm -rf /tmp/elfuse-sysroot-create-paths; \
	mkdir -p "$$host_out_dir"; \
	$(ELFUSE_BIN) --create-sysroot "$$tmpdir/case-sysroot" $(BUILD_DIR)/test-sysroot-create-paths "$$guest_tmp" "$$mounted_tmp" "$$host_out" "$$tmpdir/case-sysroot"; \
	if [ -e "$$guest_tmp" ]; then \
		printf "$(RED)FAIL$(RESET) guest /tmp escaped to host /tmp\n"; \
		exit 1; \
	fi; \
	if [ ! -f "$$host_out" ]; then \
		printf "$(RED)FAIL$(RESET) host fallback path was not created\n"; \
		exit 1; \
	fi; \
	if ! grep -q "host-fallback" "$$host_out"; then \
		printf "$(RED)FAIL$(RESET) host fallback file contents mismatch\n"; \
		exit 1; \
	fi

test-sysroot-procfs-exec: $(ELFUSE_BIN) $(BUILD_DIR)/test-procfs-exec
	@tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	mkdir -p "$$tmpdir/bin"; \
	cp $(BUILD_DIR)/test-procfs-exec "$$tmpdir/bin/test-procfs-exec"; \
	$(ELFUSE_BIN) --sysroot "$$tmpdir" "$$tmpdir/bin/test-procfs-exec"

test-timeout-disable: $(ELFUSE_BIN) $(TEST_HELLO_DEP)
	@$(ELFUSE_BIN) --timeout 0 $(TEST_DIR)/test-hello > /dev/null

## Run GDB stub integration tests (LLDB <-> elfuse gdbstub)
test-gdbstub: $(ELFUSE_BIN) $(TEST_DIR)/test-hello
	@bash tests/test-gdbstub.sh -e $(ELFUSE_BIN) -v

## Alias for check (backward compat)
test-all: check

# ── Coreutils integration test ───────────────────────────────────

FIXTURES_DIR ?= $(CURDIR)/externals/test-fixtures

ifeq ($(origin GUEST_COREUTILS), undefined)
  ifneq ($(wildcard $(FIXTURES_DIR)/aarch64-musl/dyn-bin),)
    GUEST_COREUTILS := $(FIXTURES_DIR)/aarch64-musl/dyn-bin
  endif
endif

ifeq ($(origin GUEST_BUSYBOX), undefined)
  ifneq ($(wildcard $(FIXTURES_DIR)/aarch64-musl/staticbin/bin/busybox),)
    GUEST_BUSYBOX := $(FIXTURES_DIR)/aarch64-musl/staticbin/bin/busybox
  endif
endif

ifeq ($(origin GUEST_STATIC_BINS), undefined)
  ifneq ($(wildcard $(FIXTURES_DIR)/aarch64-musl/dyn-bin),)
    GUEST_STATIC_BINS := $(FIXTURES_DIR)/aarch64-musl/dyn-bin
  endif
endif

ifeq ($(origin GUEST_SYSROOT), undefined)
  ifneq ($(wildcard $(FIXTURES_DIR)/rootfs),)
    GUEST_SYSROOT := $(FIXTURES_DIR)/rootfs
  endif
endif

ifeq ($(origin GUEST_DYNAMIC_COREUTILS), undefined)
  ifneq ($(wildcard $(FIXTURES_DIR)/aarch64-musl/dyn-bin),)
    GUEST_DYNAMIC_COREUTILS := $(FIXTURES_DIR)/aarch64-musl/dyn-bin
  endif
endif

# Path to static aarch64-linux coreutils bin directory.
# Auto-detected from GUEST_COREUTILS; override with COREUTILS_BIN=...
ifdef GUEST_COREUTILS
  ifneq ($(wildcard $(GUEST_COREUTILS)/bin),)
    COREUTILS_BIN ?= $(GUEST_COREUTILS)/bin
  else
    COREUTILS_BIN ?= $(GUEST_COREUTILS)
  endif
endif

## Run GNU coreutils 9.9 integration tests (104 tools)
test-coreutils: $(ELFUSE_BIN)
	@if [ ! -d "$(COREUTILS_BIN)" ]; then \
		printf "$(RED)✗ Coreutils not found.$(RESET) Set COREUTILS_BIN=/path/to/bin.\n"; \
		exit 1; \
	fi
	@if [ "$(COREUTILS_BIN)" = "$(FIXTURES_DIR)/aarch64-musl/dyn-bin" ]; then \
		COREUTILS_PROFILE=smoke bash tests/test-coreutils.sh $(ELFUSE_BIN) $(COREUTILS_BIN) $(SYSROOT_DIR); \
	elif [ -n "$(SYSROOT_DIR)" ] && [ -d "$(SYSROOT_DIR)" ]; then \
		bash tests/test-coreutils.sh $(ELFUSE_BIN) $(COREUTILS_BIN) $(SYSROOT_DIR); \
	else \
		bash tests/test-coreutils.sh $(ELFUSE_BIN) $(COREUTILS_BIN); \
	fi

# ── Busybox integration test ─────────────────────────────────────

ifneq ($(wildcard $(BUILD_DIR)/busybox),)
  BUSYBOX_BIN ?= $(BUILD_DIR)/busybox
else ifdef GUEST_BUSYBOX
  ifneq ($(wildcard $(GUEST_BUSYBOX)/bin/busybox),)
    BUSYBOX_BIN ?= $(GUEST_BUSYBOX)/bin/busybox
  else
    BUSYBOX_BIN ?= $(GUEST_BUSYBOX)
  endif
else
  BUSYBOX_BIN ?= $(BUILD_DIR)/busybox
endif

BUSYBOX_SUITE ?= sid
BUSYBOX_PACKAGE_PAGE ?= https://packages.debian.org/$(BUSYBOX_SUITE)/busybox-static
BUSYBOX_DOWNLOAD_PAGE ?= https://packages.debian.org/$(BUSYBOX_SUITE)/arm64/busybox-static/download

ifeq ($(BUSYBOX_BIN),$(BUILD_DIR)/busybox)
  BUSYBOX_DEPS := $(BUILD_DIR)/busybox
else
  BUSYBOX_DEPS :=
endif

$(BUILD_DIR)/busybox: | $(BUILD_DIR)
	@printf "$(BLUE)▸ Downloading$(RESET) busybox-static (arm64) from $(BUSYBOX_PACKAGE_PAGE)\n"
	@tmpdir="$(BUILD_DIR)/busybox-static.tmp"; \
	rm -rf "$$tmpdir"; \
	mkdir -p "$$tmpdir"; \
	package_page="$$tmpdir/package.html"; \
	download_page="$$tmpdir/download.html"; \
	deb="$$tmpdir/busybox-static.deb"; \
	curl -fsSL "$(BUSYBOX_PACKAGE_PAGE)" -o "$$package_page"; \
	download_url=$$(sed -n 's/.*href="\([^"]*\/arm64\/busybox-static\/download\)".*/\1/p' "$$package_page" | head -n 1); \
	if [ -z "$$download_url" ]; then \
		download_url="$(BUSYBOX_DOWNLOAD_PAGE)"; \
	fi; \
	case "$$download_url" in \
		http*) ;; \
		*) download_url="https://packages.debian.org$$download_url" ;; \
	esac; \
	curl -fsSL "$$download_url" -o "$$download_page"; \
	deb_url=$$(sed -n 's/.*href="\([^"]*busybox-static_[^"]*_arm64\.deb\)".*/\1/p' "$$download_page" | head -n 1); \
	if [ -z "$$deb_url" ]; then \
		printf "$(RED)✗ Could not find busybox-static .deb link on %s$(RESET)\n" "$$download_url"; \
		exit 1; \
	fi; \
	case "$$deb_url" in \
		http*) ;; \
		//*) deb_url="https:$$deb_url" ;; \
		*) deb_url="https://packages.debian.org$$deb_url" ;; \
	esac; \
	curl -fL "$$deb_url" -o "$$deb"; \
	( cd "$$tmpdir" && ar x busybox-static.deb ); \
	data_archive=$$(find "$$tmpdir" -maxdepth 1 -name 'data.tar.*' -print | head -n 1); \
	if [ -z "$$data_archive" ]; then \
		printf "$(RED)✗ Debian package did not contain data.tar.*$(RESET)\n"; \
		exit 1; \
	fi; \
	mkdir -p "$$tmpdir/root"; \
	tar -xf "$$data_archive" -C "$$tmpdir/root"; \
	if [ ! -x "$$tmpdir/root/usr/bin/busybox" ]; then \
		printf "$(RED)✗ Debian package did not contain /usr/bin/busybox$(RESET)\n"; \
		exit 1; \
	fi; \
	cp "$$tmpdir/root/usr/bin/busybox" "$@"; \
	chmod 0755 "$@"; \
	rm -rf "$$tmpdir"

## Run busybox applet smoke tests
test-busybox: $(ELFUSE_BIN) $(BUSYBOX_DEPS)
	@if [ ! -x "$(BUSYBOX_BIN)" ]; then \
		printf "$(RED)✗ Busybox not found.$(RESET) Set BUSYBOX_BIN=/path/to/busybox.\n"; \
		exit 1; \
	fi
	@bash tests/test-busybox.sh $(ELFUSE_BIN) $(BUSYBOX_BIN)

## Run the low-stack argv rewrite regression on busybox startup
test-proctitle-low-stack: $(ELFUSE_BIN) $(BUSYBOX_DEPS)
	@if [ ! -x "$(BUSYBOX_BIN)" ]; then \
		printf "$(RED)✗ Busybox not found.$(RESET) Set BUSYBOX_BIN=/path/to/busybox.\n"; \
		exit 1; \
	fi
	@bash tests/test-proctitle-low-stack.sh $(ELFUSE_BIN) $(BUSYBOX_BIN)

# ── Static binary integration tests ──────────────────────────────

ifdef GUEST_STATIC_BINS
  ifneq ($(wildcard $(GUEST_STATIC_BINS)/bin),)
    STATIC_BINS_DIR ?= $(GUEST_STATIC_BINS)/bin
  else
    STATIC_BINS_DIR ?= $(GUEST_STATIC_BINS)
  endif
endif

## Run static binary smoke tests (bash, lua, gawk, jq, sqlite, etc.)
test-static-bins: $(ELFUSE_BIN)
	@if [ ! -d "$(STATIC_BINS_DIR)" ]; then \
		printf "$(RED)✗ Static bins not found.$(RESET) Set STATIC_BINS_DIR=/path/to/bin.\n"; \
		exit 1; \
	fi
	@if [ -n "$(SYSROOT_DIR)" ] && [ -d "$(SYSROOT_DIR)" ]; then \
		bash tests/test-static-bins.sh $(ELFUSE_BIN) $(STATIC_BINS_DIR) $(SYSROOT_DIR); \
	else \
		bash tests/test-static-bins.sh $(ELFUSE_BIN) $(STATIC_BINS_DIR); \
	fi

# ── Dynamic linking tests ────────────────────────────────────────

# Musl sysroot with dynamic linker + libc.so.
SYSROOT_DIR ?= $(GUEST_SYSROOT)
ifdef GUEST_DYNAMIC_COREUTILS
  ifneq ($(wildcard $(GUEST_DYNAMIC_COREUTILS)/bin),)
    DYNAMIC_COREUTILS_BIN ?= $(GUEST_DYNAMIC_COREUTILS)/bin
  else
    DYNAMIC_COREUTILS_BIN ?= $(GUEST_DYNAMIC_COREUTILS)
  endif
endif

## Run dynamic linking smoke test (hello-dynamic via --sysroot)
test-dynamic: $(ELFUSE_BIN)
	@if [ -z "$(SYSROOT_DIR)" ] || [ ! -d "$(SYSROOT_DIR)" ]; then \
		printf "$(RED)✗ Sysroot not found.$(RESET) Set SYSROOT_DIR=/path/to/sysroot.\n"; \
		exit 1; \
	fi
	@printf "$(BLUE)▸ Running$(RESET) dynamic hello-dynamic (--sysroot)\n"
	$(ELFUSE_BIN) --sysroot $(SYSROOT_DIR) $(GUEST_DYNAMIC_TESTS)/bin/hello-dynamic

## Run dynamically-linked coreutils tests (--sysroot)
test-dynamic-coreutils: $(ELFUSE_BIN)
	@if [ -z "$(SYSROOT_DIR)" ] || [ ! -d "$(SYSROOT_DIR)" ]; then \
		printf "$(RED)✗ Sysroot not found.$(RESET) Set SYSROOT_DIR=/path/to/sysroot.\n"; \
		exit 1; \
	fi
	@if [ ! -d "$(DYNAMIC_COREUTILS_BIN)" ]; then \
		printf "$(RED)✗ Dynamic coreutils not found.$(RESET) Set DYNAMIC_COREUTILS_BIN=/path/to/bin.\n"; \
		exit 1; \
	fi
	@if [ "$(DYNAMIC_COREUTILS_BIN)" = "$(FIXTURES_DIR)/aarch64-musl/dyn-bin" ]; then \
		COREUTILS_PROFILE=smoke bash tests/test-dynamic-coreutils.sh $(ELFUSE_BIN) $(SYSROOT_DIR) $(DYNAMIC_COREUTILS_BIN); \
	else \
		bash tests/test-dynamic-coreutils.sh $(ELFUSE_BIN) $(SYSROOT_DIR) $(DYNAMIC_COREUTILS_BIN); \
	fi

# ── glibc dynamic linking tests ───────────────────────────────────

# glibc sysroot with dynamic linker + libc.so.
GLIBC_SYSROOT_DIR ?= $(GUEST_GLIBC_SYSROOT)
ifdef GUEST_GLIBC_DYNAMIC_COREUTILS
  ifneq ($(wildcard $(GUEST_GLIBC_DYNAMIC_COREUTILS)/bin),)
    GLIBC_DYNAMIC_COREUTILS_BIN ?= $(GUEST_GLIBC_DYNAMIC_COREUTILS)/bin
  else
    GLIBC_DYNAMIC_COREUTILS_BIN ?= $(GUEST_GLIBC_DYNAMIC_COREUTILS)
  endif
endif

## Run glibc dynamic linking smoke test (hello-dynamic via --sysroot)
test-glibc-dynamic: $(ELFUSE_BIN)
	@if [ -z "$(GLIBC_SYSROOT_DIR)" ] || [ ! -d "$(GLIBC_SYSROOT_DIR)" ]; then \
		printf "$(RED)✗ glibc sysroot not found.$(RESET) Set GLIBC_SYSROOT_DIR=/path/to/sysroot.\n"; \
		exit 1; \
	fi
	@printf "$(BLUE)▸ Running$(RESET) glibc hello-dynamic (--sysroot)\n"
	$(ELFUSE_BIN) --sysroot $(GLIBC_SYSROOT_DIR) $(GUEST_GLIBC_DYNAMIC_TESTS)/bin/hello-dynamic

## Run glibc dynamically-linked coreutils tests (--sysroot)
test-glibc-coreutils: $(ELFUSE_BIN)
	@if [ -z "$(GLIBC_SYSROOT_DIR)" ] || [ ! -d "$(GLIBC_SYSROOT_DIR)" ]; then \
		printf "$(RED)✗ glibc sysroot not found.$(RESET) Set GLIBC_SYSROOT_DIR=/path/to/sysroot.\n"; \
		exit 1; \
	fi
	@if [ ! -d "$(GLIBC_DYNAMIC_COREUTILS_BIN)" ]; then \
		printf "$(RED)✗ glibc dynamic coreutils not found.$(RESET) Set GLIBC_DYNAMIC_COREUTILS_BIN=/path/to/bin.\n"; \
		exit 1; \
	fi
	@SUITE_LABEL="glibc dynamic GNU coreutils test suite (--sysroot)" \
	    SUITE_SUMMARY="glibc results" \
	    bash tests/test-dynamic-coreutils.sh $(ELFUSE_BIN) $(GLIBC_SYSROOT_DIR) $(GLIBC_DYNAMIC_COREUTILS_BIN)

# ── Performance benchmark ─────────────────────────────────────────

ifneq ($(wildcard $(BUILD_DIR)/busybox),)
  PERF_BIN ?= $(BUILD_DIR)/perf-bin
  PERF_DEPS := $(addprefix $(PERF_BIN)/,grep wc cat sort)
else
  PERF_BIN ?= $(COREUTILS_BIN)
  PERF_DEPS :=
endif

$(BUILD_DIR)/perf-bin:
	@mkdir -p $@

$(BUILD_DIR)/perf-bin/%: $(BUILD_DIR)/busybox | $(BUILD_DIR)/perf-bin
	@ln -sf ../busybox $@

## Run performance benchmarks (native vs elfuse, 10 iterations each)
test-perf: $(ELFUSE_BIN) $(PERF_DEPS)
	@if [ ! -d "$(PERF_BIN)" ]; then \
		printf "$(RED)✗ Perf tools not found.$(RESET) Set COREUTILS_BIN=/path/to/bin or provide $(BUILD_DIR)/busybox.\n"; \
		exit 1; \
	fi
	@bash tests/test-perf.sh $(ELFUSE_BIN) $(PERF_BIN)

## Alias for test-perf
perf: test-perf

# ── Test matrix (elfuse + qemu, aarch64) ────────────────────────────────

## Run full test matrix (all modes: elfuse + qemu, aarch64)
test-matrix: $(ELFUSE_BIN) $(TEST_DEPS)
	@bash tests/test-matrix.sh all

## Run test matrix: elfuse aarch64 mode
test-matrix-elfuse-aarch64: $(ELFUSE_BIN) $(TEST_DEPS)
	@bash tests/test-matrix.sh elfuse-aarch64

## Run test matrix: qemu aarch64 mode
test-matrix-qemu-aarch64: $(ELFUSE_BIN) $(TEST_DEPS)
	@bash tests/test-matrix.sh qemu-aarch64

# ── Full test suite ──────────────────────────────────────────────────

## Run the complete test suite (aarch64: unit + busybox + gdbstub + coreutils + static + dynamic)
test-full: $(ELFUSE_BIN)
	@printf "\n$(CYAN)╔══════════════════════════════════════════════════════╗$(RESET)\n"
	@printf "$(CYAN)║              elfuse full test suite                      ║$(RESET)\n"
	@printf "$(CYAN)╚══════════════════════════════════════════════════════╝$(RESET)\n"
	@fail=0; \
	printf "\n$(BLUE)━━━ [1/6] aarch64 unit tests + busybox ━━━$(RESET)\n"; \
	$(MAKE) --no-print-directory check || fail=$$((fail + 1)); \
	printf "\n$(BLUE)━━━ [2/6] GDB stub integration (LLDB) ━━━$(RESET)\n"; \
	$(MAKE) --no-print-directory test-gdbstub || fail=$$((fail + 1)); \
	printf "\n$(BLUE)━━━ [3/6] aarch64 coreutils (static) ━━━$(RESET)\n"; \
	if [ -n "$(COREUTILS_BIN)" ] && [ -d "$(COREUTILS_BIN)" ] && \
	   [ "$(COREUTILS_BIN)" != "$(FIXTURES_DIR)/aarch64-musl/dyn-bin" ]; then \
		$(MAKE) --no-print-directory test-coreutils || fail=$$((fail + 1)); \
	else \
		printf "$(YELLOW)SKIP$(RESET) static coreutils suite (set COREUTILS_BIN to a dedicated full coreutils bundle)\n"; \
	fi; \
	printf "\n$(BLUE)━━━ [4/6] aarch64 static bins (bash, jq, sqlite, lua, ...) ━━━$(RESET)\n"; \
	$(MAKE) --no-print-directory test-static-bins || fail=$$((fail + 1)); \
	printf "\n$(BLUE)━━━ [5/6] aarch64 dynamic coreutils (musl) ━━━$(RESET)\n"; \
	$(MAKE) --no-print-directory test-dynamic-coreutils || fail=$$((fail + 1)); \
	printf "\n$(BLUE)━━━ [6/6] aarch64 dynamic coreutils (glibc) ━━━$(RESET)\n"; \
	if [ -n "$(GLIBC_SYSROOT_DIR)" ] && [ -d "$(GLIBC_SYSROOT_DIR)" ] && \
	   [ -n "$(GLIBC_DYNAMIC_COREUTILS_BIN)" ] && [ -d "$(GLIBC_DYNAMIC_COREUTILS_BIN)" ]; then \
		$(MAKE) --no-print-directory test-glibc-coreutils || fail=$$((fail + 1)); \
	else \
		printf "$(YELLOW)SKIP$(RESET) glibc dynamic coreutils (set GLIBC_SYSROOT_DIR and GLIBC_DYNAMIC_COREUTILS_BIN)\n"; \
	fi; \
	printf "\n$(CYAN)╔══════════════════════════════════════════════════════╗$(RESET)\n"; \
	if [ "$$fail" -eq 0 ]; then \
		printf "$(CYAN)║  $(GREEN)✓ All required suites passed$(CYAN)                      ║$(RESET)\n"; \
	else \
		printf "$(CYAN)║  $(RED)✗ $$fail suite(s) had failures$(CYAN)                        ║$(RESET)\n"; \
	fi; \
	printf "$(CYAN)╚══════════════════════════════════════════════════════╝$(RESET)\n"; \
	[ "$$fail" -eq 0 ]

# ── Multi-vCPU validation test ─────────────────────────────────────
# Build rules in top-level Makefile; these are just run targets.

## Run multi-vCPU validation tests (5 tests)
test-multi-vcpu: $(BUILD_DIR)/test-multi-vcpu
	$(BUILD_DIR)/test-multi-vcpu

# ── RWX page table entry test ───────────────────────────────────

## Run RWX page table entry test (does HVF allow W+X?)
test-rwx: $(BUILD_DIR)/test-rwx
	$(BUILD_DIR)/test-rwx
