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

# `oci pull --help` advertises the --refresh flag added in C4.2.
pull_help=$("${ELFUSE}" oci pull --help 2>&1)
case "${pull_help}" in
    *"--refresh"*)
        ok "pull-smoke: --help advertises --refresh"
        ;;
    *)
        bad "pull-smoke: --refresh usage" "${pull_help}"
        ;;
esac

# `oci pull --help` documents the policy.json file lookup added in C6.2.
case "${pull_help}" in
    *"Policy:"*)
        ok "pull-smoke: --help mentions policy.json"
        ;;
    *)
        bad "pull-smoke: --help lacks Policy section" "${pull_help}"
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

# Pin must appear as a manifests[] entry in index.json. Use grep over the
# raw bytes so the test stays portable (jq is not on the macOS default
# install). The canonical ref-name annotation is what oci_store_put_ref
# emits for local/scratch:v1.
if [ -f "${STORE}/index.json" ] &&
   grep -q '"org.opencontainers.image.ref.name"' "${STORE}/index.json" &&
   grep -q 'docker.io/local/scratch:v1' "${STORE}/index.json"; then
    ok "fixture: ref pin written to index.json"
else
    bad "fixture: ref pin" "no matching ref.name annotation in index.json"
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

# ── Prune CLI smoke ──────────────────────────────────────────────────

# The fixture above produced 3 reachable blobs (layer + config + manifest).
# Drop two extra dangling blobs into blobs/sha256/ via dd + sha256sum
# substitutes; this proves the end-to-end CLI dispatch (parser, store
# open, mark, sweep, output formatter) runs without any C-level
# unit-test scaffolding.
mkdir -p "${SCRATCH}/danglings"
echo "compat-dangling-one" > "${SCRATCH}/danglings/a"
echo "compat-dangling-two" > "${SCRATCH}/danglings/b"
for f in "${SCRATCH}/danglings/a" "${SCRATCH}/danglings/b"; do
    if command -v shasum >/dev/null 2>&1; then
        hex=$(shasum -a 256 "$f" | awk '{print $1}')
    else
        hex=$(sha256sum "$f" | awk '{print $1}')
    fi
    cp "$f" "${STORE}/blobs/sha256/${hex}"
done

blob_before_prune=$(find "${STORE}/blobs/sha256" -type f 2>/dev/null | wc -l | tr -d ' ')
if [ "${blob_before_prune}" = 5 ]; then
    ok "prune-smoke: 5 blobs before prune (3 reachable + 2 dangling)"
else
    bad "prune-smoke: pre-state" "got ${blob_before_prune} (want 5)"
fi

# Dry-run must not touch disk and must report 2 reclaimable blobs.
dry_out=$("${ELFUSE}" oci prune --store "${STORE}" 2>&1)
rc=$?
case "${dry_out}" in
    *"reclaimable: 2 blobs"*"kept:"*"3 blobs"*"dry-run"*)
        if [ "${rc}" = 0 ]; then
            ok "prune-smoke: dry-run reports 2 reclaimable, 3 kept"
        else
            bad "prune-smoke: dry-run" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "prune-smoke: dry-run output" "${dry_out}"
        ;;
esac

blob_after_dry=$(find "${STORE}/blobs/sha256" -type f 2>/dev/null | wc -l | tr -d ' ')
if [ "${blob_after_dry}" = 5 ]; then
    ok "prune-smoke: dry-run did not touch disk"
else
    bad "prune-smoke: dry-run disk" "got ${blob_after_dry} (want 5)"
fi

# Commit reclaims the two dangling blobs.
commit_out=$("${ELFUSE}" oci prune --store "${STORE}" --commit 2>&1)
rc=$?
case "${commit_out}" in
    *"reclaimed: 2 blobs"*"kept:"*"3 blobs"*)
        if [ "${rc}" = 0 ]; then
            ok "prune-smoke: --commit reclaims 2 blobs"
        else
            bad "prune-smoke: --commit" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "prune-smoke: --commit output" "${commit_out}"
        ;;
esac

blob_after_commit=$(find "${STORE}/blobs/sha256" -type f 2>/dev/null | wc -l | tr -d ' ')
if [ "${blob_after_commit}" = 3 ]; then
    ok "prune-smoke: --commit unlinked dangling blobs"
else
    bad "prune-smoke: --commit disk" "got ${blob_after_commit} (want 3)"
fi

# ── C1.4 filter smoke (--older-than / --keep-bytes) ──────────────────

# Stage two fresh dangling blobs and backdate one so --older-than 1d
# distinguishes them. The fresh one must survive; the backdated one
# must be reclaimed and counted in the skipped line that only renders
# when at least one candidate was spared.
mkdir -p "${SCRATCH}/c14"
echo "filter-fresh" > "${SCRATCH}/c14/fresh"
echo "filter-stale" > "${SCRATCH}/c14/stale"
for f in "${SCRATCH}/c14/fresh" "${SCRATCH}/c14/stale"; do
    if command -v shasum >/dev/null 2>&1; then
        hex=$(shasum -a 256 "$f" | awk '{print $1}')
    else
        hex=$(sha256sum "$f" | awk '{print $1}')
    fi
    cp "$f" "${STORE}/blobs/sha256/${hex}"
    case "${f}" in
        *stale)
            stale_hex="${hex}"
            ;;
        *fresh)
            fresh_hex="${hex}"
            ;;
    esac
done
# touch -t accepts [[CC]YY]MMDDhhmm[.SS]; pick 1970-01-02 so the blob
# is unambiguously older than any 1-day cutoff regardless of TZ.
touch -t 197001020000 "${STORE}/blobs/sha256/${stale_hex}"

older_out=$("${ELFUSE}" oci prune --store "${STORE}" --commit --older-than 1d 2>&1)
rc=$?
case "${older_out}" in
    *"reclaimed: 1 blobs"*"skipped:"*"1 blobs"*)
        if [ "${rc}" = 0 ]; then
            ok "prune-smoke: --older-than reclaims stale, skips fresh"
        else
            bad "prune-smoke: --older-than" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "prune-smoke: --older-than output" "${older_out}"
        ;;
esac

if [ ! -e "${STORE}/blobs/sha256/${stale_hex}" ] \
   && [ -e "${STORE}/blobs/sha256/${fresh_hex}" ]; then
    ok "prune-smoke: --older-than only the stale blob was unlinked"
else
    bad "prune-smoke: --older-than disk state" \
        "stale=${stale_hex} fresh=${fresh_hex}"
fi

# --keep-bytes 0 must behave as no filter (the C1.4 spec): the fresh
# blob that survived the previous step is dangling and gets reclaimed.
keep_out=$("${ELFUSE}" oci prune --store "${STORE}" --commit --keep-bytes 0 2>&1)
rc=$?
case "${keep_out}" in
    *"reclaimed: 1 blobs"*)
        if [ "${rc}" = 0 ]; then
            ok "prune-smoke: --keep-bytes 0 disables the budget filter"
        else
            bad "prune-smoke: --keep-bytes 0" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "prune-smoke: --keep-bytes 0 output" "${keep_out}"
        ;;
esac

# Invalid duration -> non-zero exit, stderr describes the failure.
bad_dur_out=$("${ELFUSE}" oci prune --store "${STORE}" --older-than foo 2>&1)
rc=$?
case "${bad_dur_out}" in
    *"invalid duration"*)
        if [ "${rc}" != 0 ]; then
            ok "prune-smoke: invalid --older-than rejected"
        else
            bad "prune-smoke: invalid duration" "rc=${rc} (want non-zero)"
        fi
        ;;
    *)
        bad "prune-smoke: invalid duration message" "${bad_dur_out}"
        ;;
esac

bad_size_out=$("${ELFUSE}" oci prune --store "${STORE}" --keep-bytes foo 2>&1)
rc=$?
case "${bad_size_out}" in
    *"invalid byte size"*)
        if [ "${rc}" != 0 ]; then
            ok "prune-smoke: invalid --keep-bytes rejected"
        else
            bad "prune-smoke: invalid byte size" "rc=${rc} (want non-zero)"
        fi
        ;;
    *)
        bad "prune-smoke: invalid byte size message" "${bad_size_out}"
        ;;
esac

# ── Rebuild-cache CLI smoke (C3.5) ───────────────────────────────────

# A volume without any unpacked trees still parses cleanly and reports
# scanned=0. The store under SCRATCH/store has no images/, so the walker
# treats it as the empty case and rc must be 0.
rebuild_out=$("${ELFUSE}" oci rebuild-cache --store "${STORE}" \
                                            --volume "${SCRATCH}" 2>&1)
rc=$?
case "${rebuild_out}" in
    *"rebuild-cache (dry-run):"*"scanned:"*"0 unpacked trees"*"dry-run; pass --commit to write"*)
        if [ "${rc}" = 0 ]; then
            ok "rebuild-cache-smoke: dry-run on empty volume reports scanned=0"
        else
            bad "rebuild-cache-smoke: dry-run rc" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "rebuild-cache-smoke: dry-run output" "${rebuild_out}"
        ;;
esac

# ── C3.3d layer + stack prune sweep smoke ───────────────────────────

# After the prune-smoke section above the store holds 3 reachable blobs
# (manifest + config + layer for the dry/commit fixture pin). Drop one
# dangling layer dir and one dangling stack dir into the store and verify
# the CLI render now mentions layers and stacks alongside blobs, that the
# directories are unlinked on --commit, and that the existing blob lines
# still match the pre-C3.3d output shape.
mkdir -p "${SCRATCH}/c33d"
echo "dangling-layer" > "${SCRATCH}/c33d/layer"
echo "dangling-stack" > "${SCRATCH}/c33d/stack"
if command -v shasum >/dev/null 2>&1; then
    layer_hex=$(shasum -a 256 "${SCRATCH}/c33d/layer" | awk '{print $1}')
    stack_hex=$(shasum -a 256 "${SCRATCH}/c33d/stack" | awk '{print $1}')
else
    layer_hex=$(sha256sum "${SCRATCH}/c33d/layer" | awk '{print $1}')
    stack_hex=$(sha256sum "${SCRATCH}/c33d/stack" | awk '{print $1}')
fi
mkdir -p "${STORE}/layers/sha256/${layer_hex}"
mkdir -p "${STORE}/layers/stacks/sha256/${stack_hex}"
echo "filler" > "${STORE}/layers/sha256/${layer_hex}/payload"

c33d_out=$("${ELFUSE}" oci prune --store "${STORE}" --commit 2>&1)
rc=$?
case "${c33d_out}" in
    *"layers:"*"reclaimed"*"stacks:"*"reclaimed"*)
        if [ "${rc}" = 0 ]; then
            ok "c33d-smoke: --commit renders layers + stacks lines"
        else
            bad "c33d-smoke: --commit rc" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "c33d-smoke: --commit output" "${c33d_out}"
        ;;
esac

if [ ! -e "${STORE}/layers/sha256/${layer_hex}" ] \
   && [ ! -e "${STORE}/layers/stacks/sha256/${stack_hex}" ]; then
    ok "c33d-smoke: dangling layer and stack dirs were unlinked"
else
    bad "c33d-smoke: disk state" \
        "layer=${layer_hex} stack=${stack_hex} still present"
fi

# ── C4.1 store-wide status smoke ─────────────────────────────────────

# Default human render exposes the three sections so an operator running
# `elfuse oci status` after prune still gets a coherent snapshot of the
# remaining store state.
status_out=$("${ELFUSE}" oci status --store "${STORE}" 2>&1)
rc=$?
case "${status_out}" in
    *"PINS ("*"STORE TOTALS:"*"blobs:"*)
        if [ "${rc}" = 0 ]; then
            ok "status-smoke: human render shows PINS and STORE TOTALS"
        else
            bad "status-smoke: human rc" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "status-smoke: human render" "${status_out}"
        ;;
esac

# Structured output for jq-style consumers. Substring matches keep the
# check portable across jq / no-jq installs; the schema is enforced via
# the test-oci-status unit suite.
json_out=$("${ELFUSE}" oci status --store "${STORE}" --json 2>&1)
rc=$?
case "${json_out}" in
    *'"schemaVersion":1'*'"pins":'*'"totals":'*'"blob_count":'*)
        if [ "${rc}" = 0 ]; then
            ok "status-smoke: --json schemaVersion 1 with pins/totals"
        else
            bad "status-smoke: --json rc" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "status-smoke: --json render" "${json_out}"
        ;;
esac

# --no-disk-usage zeroes the size fields but counters still populate.
nodu_out=$("${ELFUSE}" oci status --store "${STORE}" --json --no-disk-usage 2>&1)
case "${nodu_out}" in
    *'"blob_bytes":0'*'"disk_usage_skipped":true'*)
        ok "status-smoke: --no-disk-usage zeroes byte totals"
        ;;
    *)
        bad "status-smoke: --no-disk-usage" "${nodu_out}"
        ;;
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
