#!/usr/bin/env bash
# bench-mmap.sh -- Compare mmap / munmap lifecycle cost under elfuse and Linux.
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
#
# The same static aarch64 benchmark binary runs locally through elfuse and in
# an OrbStack Linux machine. Each sample reports mmap, optional mprotect
# commit, touch, and munmap time per cycle; this harness collects repeated
# samples and prints medians.
#
# Environment overrides:
#   ELFUSE                 elfuse binary (default: build/elfuse)
#   BENCH_MMAP_BIN         static aarch64 benchmark binary
#   BENCH_MMAP_RUNS        samples per platform and mode (default: 10)
#   BENCH_MMAP_ITERATIONS  mmap cycles in each sample (default: 5000)
#   BENCH_MMAP_WARMUP      unmeasured warmup cycles per sample (default: 100)
#   BENCH_MMAP_SIZES       space-separated mapping sizes in bytes
#                          (default: "4096 16384 262144 2097152")
#   BENCH_MMAP_VARIANTS    space-separated anonymous mapping variants
#                          (default: "private"; choices: private, noreserve,
#                          protnone)
#   ORBCTL                 OrbStack CLI (default: orbctl)
#   ORBSTACK_MACHINE       optional OrbStack machine name

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ELFUSE="${ELFUSE:-${ROOT_DIR}/build/elfuse}"
BENCH_MMAP_BIN="${BENCH_MMAP_BIN:-${ROOT_DIR}/build/bench-mmap}"
BENCH_MMAP_RUNS="${BENCH_MMAP_RUNS:-10}"
BENCH_MMAP_ITERATIONS="${BENCH_MMAP_ITERATIONS:-5000}"
BENCH_MMAP_WARMUP="${BENCH_MMAP_WARMUP:-100}"
BENCH_MMAP_SIZES="${BENCH_MMAP_SIZES:-4096 16384 262144 2097152}"
BENCH_MMAP_VARIANTS="${BENCH_MMAP_VARIANTS:-private}"
ORBCTL="${ORBCTL:-orbctl}"
ORBSTACK_MACHINE="${ORBSTACK_MACHINE:-}"

usage()
{
    printf 'usage: %s\n' "$0" >&2
    printf 'run through make: make bench-mmap ORBSTACK_MACHINE=<machine>\n' >&2
    exit 2
}

require_positive_integer()
{
    case "$2" in
        ''|*[!0-9]*)
            printf '%s must be a positive integer, got %s\n' "$1" "$2" >&2
            exit 2
            ;;
    esac
    if [ "$2" -eq 0 ]; then
        printf '%s must be greater than zero\n' "$1" >&2
        exit 2
    fi
}

absolute_path()
{
    case "$1" in
        /*) printf '%s\n' "$1" ;;
        *)
            local dir base
            dir="$(cd "$(dirname "$1")" && pwd)"
            base="$(basename "$1")"
            printf '%s/%s\n' "$dir" "$base"
            ;;
    esac
}

field_value()
{
    local field="$1" line="$2" token
    for token in $line; do
        case "$token" in
            "${field}"=*)
                printf '%s\n' "${token#*=}"
                return 0
                ;;
        esac
    done
    return 1
}

run_elfuse()
{
    "$ELFUSE" "$BENCH_MMAP_BIN" "$3" "$1" "$4" "$2" "$5"
}

run_orbstack()
{
    local mode="$1" size="$2" iterations="$3" warmup="$4" variant="$5"
    local command=("$ORBCTL" run)
    if [ -n "$ORBSTACK_MACHINE" ]; then
        command+=(-m "$ORBSTACK_MACHINE")
    fi
    command+=(-p "$BENCH_MMAP_BIN" "$iterations" "$mode" "$warmup" \
              "$size" "$variant")
    "${command[@]}"
}

summarize()
{
    local platform="$1" variant="$2" size="$3" mode="$4"
    awk -F '\t' -v platform="$platform" -v variant="$variant" \
        -v size="$size" -v mode="$mode" '
        function sort(values, count, i, j, swap) {
            for (i = 2; i <= count; i++) {
                for (j = i; j > 1 && values[j] < values[j - 1]; j--) {
                    swap = values[j]; values[j] = values[j - 1]; values[j - 1] = swap;
                }
            }
        }
        function metric(label, values, count, median) {
            sort(values, count)
            if (count % 2)
                median = values[(count + 1) / 2]
            else
                median = (values[count / 2] + values[count / 2 + 1]) / 2
            printf "  %s median=%8.1f [min=%8.1f max=%8.1f]", label, median, values[1], values[count]
        }
        $1 == platform && $2 == variant && $3 == size && $4 == mode {
            count++
            mmap[count] = $6
            commit[count] = $7
            touch[count] = $8
            munmap[count] = $9
            total[count] = $10
        }
        END {
            if (count == 0)
                exit 1
            printf "%-8s %-10s %7s %-4s", platform, variant, size, mode
            metric("mmap", mmap, count)
            metric("commit", commit, count)
            metric("touch", touch, count)
            metric("munmap", munmap, count)
            metric("total", total, count)
            printf "\n"
        }
    ' "$RESULTS"
}

ratio()
{
    local variant="$1" size="$2" mode="$3"
    awk -F '\t' -v variant="$variant" -v size="$size" -v mode="$mode" '
        function sort(values, count, i, j, swap) {
            for (i = 2; i <= count; i++) {
                for (j = i; j > 1 && values[j] < values[j - 1]; j--) {
                    swap = values[j]; values[j] = values[j - 1]; values[j - 1] = swap;
                }
            }
        }
        function median(values, count) {
            sort(values, count)
            return count % 2 ? values[(count + 1) / 2] : (values[count / 2] + values[count / 2 + 1]) / 2
        }
        $2 == variant && $3 == size && $4 == mode && $1 == "elfuse" { elfuse[++elfuse_count] = $10 }
        $2 == variant && $3 == size && $4 == mode && $1 == "orbstack" { orbstack[++orbstack_count] = $10 }
        END {
            if (!elfuse_count || !orbstack_count)
                exit 1
            printf "  %-10s %7s %-4s elfuse/orbstack total median ratio: %.2fx\n", variant, size, mode, median(elfuse, elfuse_count) / median(orbstack, orbstack_count)
        }
    ' "$RESULTS"
}

require_positive_integer BENCH_MMAP_RUNS "$BENCH_MMAP_RUNS"
require_positive_integer BENCH_MMAP_ITERATIONS "$BENCH_MMAP_ITERATIONS"
case "$BENCH_MMAP_WARMUP" in
    ''|*[!0-9]*)
        printf 'BENCH_MMAP_WARMUP must be a non-negative integer, got %s\n' \
            "$BENCH_MMAP_WARMUP" >&2
        exit 2
        ;;
esac
for size in $BENCH_MMAP_SIZES; do
    require_positive_integer BENCH_MMAP_SIZES "$size"
    if [ $((size % 4096)) -ne 0 ]; then
        printf 'BENCH_MMAP_SIZES entries must be multiples of 4096, got %s\n' \
            "$size" >&2
        exit 2
    fi
done
for variant in $BENCH_MMAP_VARIANTS; do
    case "$variant" in
        private|noreserve|protnone) ;;
        *)
            printf 'unknown BENCH_MMAP_VARIANTS entry: %s\n' "$variant" >&2
            exit 2
            ;;
    esac
done

ELFUSE="$(absolute_path "$ELFUSE")"
BENCH_MMAP_BIN="$(absolute_path "$BENCH_MMAP_BIN")"
if [ ! -x "$ELFUSE" ]; then
    printf 'elfuse binary not found: %s\n' "$ELFUSE" >&2
    usage
fi
if [ ! -x "$BENCH_MMAP_BIN" ]; then
    printf 'benchmark binary not found: %s\n' "$BENCH_MMAP_BIN" >&2
    usage
fi
if ! command -v "$ORBCTL" > /dev/null 2>&1; then
    printf 'OrbStack CLI not found: %s\n' "$ORBCTL" >&2
    exit 1
fi

RESULTS="$(mktemp "${TMPDIR:-/tmp}/elfuse-bench-mmap.XXXXXX")"
trap 'rm -f "$RESULTS"' EXIT

printf 'mmap/munmap benchmark\n'
printf '  elfuse:      %s\n' "$ELFUSE"
printf '  benchmark:   %s\n' "$BENCH_MMAP_BIN"
printf '  orb machine: %s\n' "${ORBSTACK_MACHINE:-default}"
printf '  samples:     %s, cycles/sample: %s, warmup: %s\n' \
    "$BENCH_MMAP_RUNS" "$BENCH_MMAP_ITERATIONS" "$BENCH_MMAP_WARMUP"
printf '  sizes:       %s\n' "$BENCH_MMAP_SIZES"
printf '  variants:    %s\n\n' "$BENCH_MMAP_VARIANTS"

for platform in elfuse orbstack; do
    for variant in $BENCH_MMAP_VARIANTS; do
        for size in $BENCH_MMAP_SIZES; do
            for mode in none one all; do
                printf '%s %s %s %s:\n' "$platform" "$variant" "$size" "$mode"
                for ((run = 1; run <= BENCH_MMAP_RUNS; run++)); do
                    if [ "$platform" = elfuse ]; then
                        output="$(run_elfuse "$mode" "$size" "$BENCH_MMAP_ITERATIONS" "$BENCH_MMAP_WARMUP" "$variant")"
                    else
                        output="$(run_orbstack "$mode" "$size" "$BENCH_MMAP_ITERATIONS" "$BENCH_MMAP_WARMUP" "$variant")"
                    fi

                    mmap_ns="$(field_value mmap_ns "$output")" || {
                        printf 'unexpected benchmark output: %s\n' "$output" >&2
                        exit 1
                    }
                    commit_ns="$(field_value commit_ns "$output")"
                    touch_ns="$(field_value touch_ns "$output")"
                    munmap_ns="$(field_value munmap_ns "$output")"
                    total_ns="$(field_value total_ns "$output")"
                    printf '%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n' \
                        "$platform" "$variant" "$size" "$mode" "$run" \
                        "$mmap_ns" "$commit_ns" "$touch_ns" "$munmap_ns" \
                        "$total_ns" >> "$RESULTS"
                    printf '  run %2d: total=%8.1f ns/cycle\n' "$run" "$total_ns"
                done
                printf '\n'
            done
        done
    done
done

printf 'Median per-cycle timings in ns, with sample min/max:\n'
for platform in elfuse orbstack; do
    for variant in $BENCH_MMAP_VARIANTS; do
        for size in $BENCH_MMAP_SIZES; do
            for mode in none one all; do
                summarize "$platform" "$variant" "$size" "$mode"
            done
        done
    done
done

printf '\nTotal median ratios:\n'
for variant in $BENCH_MMAP_VARIANTS; do
    for size in $BENCH_MMAP_SIZES; do
        for mode in none one all; do
            ratio "$variant" "$size" "$mode"
        done
    done
done
