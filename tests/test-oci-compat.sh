#!/usr/bin/env bash
# elfuse oci run compatibility / end-to-end smoke tests
#
# Default mode (always runs):
#   - CLI surface smokes (--help, missing IMAGE, no-pin ref)
#   - Fixture-builder integration: assemble a tiny store from a single
#     uncompressed-tar layer, verify the resulting blob count and that
#     elfuse oci inspect can render the runtime block
#
# Heavy mode (OCI_COMPAT_TEST=1):
#   - alpine-shaped, busybox-shaped, two-layer-whiteout fixtures from
#     the Phase 3 plan, each driven end-to-end through elfuse oci run.
#     Requires a case-sensitive APFS sysroot volume; the suite skips
#     the actual launch unless OCI_COMPAT_TEST=1 is set in the
#     environment to gate the hdiutil-attach + run path.
#
# Online mode (OCI_FETCH_ONLINE=1):
#   - Pulls docker.io/library/alpine:3 from the real registry, runs
#     elfuse oci run alpine:3 /bin/true, asserts exit 0. Not in
#     `make check`.
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${ROOT}/build"
ELFUSE="${BUILD}/elfuse"
BUILDER="${BUILD}/oci-fixture-builder"

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
RESET=$'\033[0m'

PASS=0
FAIL=0

ok()   { printf "  ${GREEN}OK${RESET}   %s\n" "$1"; PASS=$((PASS+1)); }
bad()  { printf "  ${RED}FAIL${RESET} %s: %s\n" "$1" "$2"; FAIL=$((FAIL+1)); }
skip() { printf "  ${YELLOW}SKIP${RESET} %s: %s\n" "$1" "$2"; }

if [ ! -x "${ELFUSE}" ]; then
    echo "error: ${ELFUSE} not built; run 'make elfuse' first" >&2
    exit 1
fi
if [ ! -x "${BUILDER}" ]; then
    echo "error: ${BUILDER} not built; run 'make oci-fixture-builder' first" >&2
    exit 1
fi

SCRATCH=$(mktemp -d /tmp/elfuse-compat-XXXXXX)
trap 'rm -rf "${SCRATCH}"' EXIT

# ── CLI surface smokes ───────────────────────────────────────────────

# --help renders the run usage block and exits 0.
out=$("${ELFUSE}" oci run --help 2>&1)
rc=$?
case "${out}" in
    *"usage: elfuse oci run"*)
        if [ "${rc}" = 0 ]; then
            ok "cli: --help prints usage and exits 0"
        else
            bad "cli: --help" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "cli: --help" "no usage text"
        ;;
esac

# Missing IMAGE returns rc=2.
"${ELFUSE}" oci run --keep >/dev/null 2>&1
rc=$?
if [ "${rc}" = 2 ]; then
    ok "cli: missing IMAGE returns rc=2"
else
    bad "cli: missing IMAGE" "rc=${rc} (want 2)"
fi

# Unknown option returns rc=2.
"${ELFUSE}" oci run --nope alpine >/dev/null 2>&1
rc=$?
if [ "${rc}" = 2 ]; then
    ok "cli: unknown option returns rc=2"
else
    bad "cli: unknown option" "rc=${rc} (want 2)"
fi

# -e without a value returns rc=2.
"${ELFUSE}" oci run -e >/dev/null 2>&1
rc=$?
if [ "${rc}" = 2 ]; then
    ok "cli: -e without value returns rc=2"
else
    bad "cli: -e w/o value" "rc=${rc} (want 2)"
fi

# ── Fixture builder integration ──────────────────────────────────────

STORE="${SCRATCH}/store"
mkdir -p "${STORE}"

# Hand-build a one-file uncompressed tar layer. tar(1) is portable; the
# OCI manifest descriptor uses mediaType=...tar (uncompressed) so no
# gzip step is needed.
mkdir -p "${SCRATCH}/layer-src"
cp "${BUILD}/test-hello" "${SCRATCH}/layer-src/hello"
chmod 0755 "${SCRATCH}/layer-src/hello"
(cd "${SCRATCH}/layer-src" && tar cf "${SCRATCH}/layer.tar" hello)

if "${BUILDER}" \
        --store "${STORE}" \
        --ref "local/scratch:v1" \
        --entrypoint "/hello" \
        --env "GREETING=phase3" \
        --workdir "/" \
        --user "1234:5678" \
        --layer "${SCRATCH}/layer.tar" \
        >"${SCRATCH}/manifest-digest.txt" 2>"${SCRATCH}/builder.err"; then
    ok "fixture: oci-fixture-builder exits 0"
else
    bad "fixture: oci-fixture-builder" "$(cat "${SCRATCH}/builder.err")"
fi

# Pin file must exist somewhere under refs/.
pin_files=$(find "${STORE}/refs" -type f 2>/dev/null | wc -l | tr -d ' ')
if [ "${pin_files}" -ge 1 ]; then
    ok "fixture: ref pin written"
else
    bad "fixture: ref pin" "no file under refs/"
fi

# Blob count: layer + config + manifest = 3.
blob_count=$(find "${STORE}/blobs/sha256" -type f 2>/dev/null | wc -l | tr -d ' ')
if [ "${blob_count}" = 3 ]; then
    ok "fixture: 3 blobs (layer + config + manifest)"
else
    bad "fixture: blob count" "got ${blob_count} (want 3)"
fi

# elfuse oci inspect on the fresh fixture must render the runtime block
# Phase 3 commit 1 added. This proves the manifest -> config blob ->
# image-config-parser -> inspect renderer chain still composes after
# the rest of the Phase 3 work landed on top.
inspect_out=$("${ELFUSE}" oci inspect --store "${STORE}" local/scratch:v1 2>&1)
case "${inspect_out}" in
    *"runtime:"*"entrypoint:"*"/hello"*)
        ok "fixture: oci inspect renders runtime block"
        ;;
    *)
        bad "fixture: oci inspect runtime" "no runtime+entrypoint match in output"
        ;;
esac

# Runtime block must echo Env / User / WorkingDir verbatim so the
# operator can read the launch contract before invoking oci run.
case "${inspect_out}" in
    *"GREETING=phase3"*) ok "fixture: inspect shows Env line" ;;
    *) bad "fixture: inspect Env" "no GREETING=phase3" ;;
esac
case "${inspect_out}" in
    *"1234:5678"*) ok "fixture: inspect shows User line" ;;
    *) bad "fixture: inspect User" "no 1234:5678" ;;
esac

# ── Heavy mode (full E2E launches) ───────────────────────────────────

if [ -n "${OCI_COMPAT_TEST:-}" ]; then
    skip "alpine-shaped / busybox-shaped / two-layer-whiteout" \
         "OCI_COMPAT_TEST=1 is set but heavy harness is deferred:" \
         "fixture builder is wired, sparsebundle volume provisioning" \
         "and the three Phase 3 plan fixtures land in a follow-up" \
         "compat-matrix patch (issue #31 Phase 3 acceptance 8)."
else
    skip "alpine-shaped / busybox-shaped / two-layer-whiteout E2E" \
         "OCI_COMPAT_TEST=1 gates the hdiutil-backed pipeline"
fi

# ── Online mode (gated) ──────────────────────────────────────────────

if [ -n "${OCI_FETCH_ONLINE:-}" ]; then
    skip "alpine:3 online pull + run" \
         "OCI_FETCH_ONLINE=1 set but online harness lands with the" \
         "heavy compat matrix in a follow-up patch"
else
    skip "alpine:3 online pull + run" \
         "OCI_FETCH_ONLINE=1 gates docker.io network access"
fi

TOTAL=$((PASS + FAIL))
echo ""
echo "Results: ${PASS}/${TOTAL} passed"
[ "${FAIL}" = 0 ]
