#!/usr/bin/env python3
"""Compare bench-suite results against the checked-in baseline.

Reads build/bench-results.json (tests/bench-suite.sh output) and
tests/bench-baseline.json, prints a per-metric ratio table for the
matching environment column, and exits non-zero when any metric
regresses beyond the threshold (default +20%). When the baseline also
carries a native-Linux column, a cross-environment ratio table relative
to native is printed for context.

Usage:
    scripts/bench-compare.py [--results PATH] [--baseline PATH]
                             [--threshold FRACTION] [--report-only]

Environment:
    BENCH_REGRESSION_THRESHOLD  overrides --threshold (e.g. 0.20)
    BENCH_REPORT_ONLY=1         report regressions but exit 0
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_RESULTS = ROOT / "build" / "bench-results.json"
DEFAULT_BASELINE = ROOT / "tests" / "bench-baseline.json"

SECTIONS = ("lmbench", "applications")


def flatten(tree: dict) -> dict[str, float]:
    """Flatten a results/baseline document into {dotted-path: median}.

    Result files store {"median": x, "samples": [...]} leaves; baseline
    columns store plain numbers. Both shapes are accepted so a captured
    results file can be pasted into the baseline as-is if desired.
    """
    flat: dict[str, float] = {}

    def walk(prefix: str, node) -> None:
        if isinstance(node, dict):
            if "median" in node:
                flat[prefix] = float(node["median"])
                return
            for key, value in node.items():
                walk(f"{prefix}.{key}" if prefix else key, value)
        elif isinstance(node, (int, float)):
            flat[prefix] = float(node)

    for section in SECTIONS:
        walk(section, tree.get(section, {}))
    return flat


def load_json(path: pathlib.Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"bench-compare: missing {path}", file=sys.stderr)
        raise SystemExit(2)
    except json.JSONDecodeError as exc:
        print(f"bench-compare: invalid JSON in {path}: {exc}",
              file=sys.stderr)
        raise SystemExit(2)


def print_table(rows: list[tuple[str, str, str, str, str]]) -> None:
    widths = [max(len(row[col]) for row in rows) for col in range(5)]
    for row in rows:
        print("  {0:<{w0}}  {1:>{w1}}  {2:>{w2}}  {3:>{w3}}  {4}".format(
            *row, w0=widths[0], w1=widths[1], w2=widths[2], w3=widths[3]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=pathlib.Path,
                        default=DEFAULT_RESULTS)
    parser.add_argument("--baseline", type=pathlib.Path,
                        default=DEFAULT_BASELINE)
    parser.add_argument(
        "--threshold", type=float,
        default=float(os.environ.get("BENCH_REGRESSION_THRESHOLD", "0.20")),
        help="regression threshold as a fraction (default 0.20 = +20%%)")
    parser.add_argument("--report-only", action="store_true",
                        default=os.environ.get("BENCH_REPORT_ONLY") == "1",
                        help="print the report but always exit 0")
    args = parser.parse_args()

    results = load_json(args.results)
    baseline = load_json(args.baseline)

    env = results.get("meta", {}).get("env", "elfuse-aarch64")
    column = (baseline.get("environments") or {}).get(env)
    if not column:
        print(f"bench-compare: baseline has no '{env}' column; "
              "nothing to compare (capture one per the procedure in "
              "tests/bench-suite.sh)")
        return 0

    current = flatten(results)
    base = flatten(column)

    regressions: list[str] = []
    improvements: list[str] = []
    rows = [("metric", "baseline", "current", "ratio", "")]
    for metric in sorted(base):
        if metric not in current:
            rows.append((metric, f"{base[metric]:g}", "-", "-",
                         "MISSING (not measured in this run)"))
            continue
        ratio = (current[metric] / base[metric]) if base[metric] else 0.0
        verdict = ""
        if ratio > 1.0 + args.threshold:
            verdict = f"REGRESSION (> +{args.threshold:.0%})"
            regressions.append(metric)
        elif ratio < 1.0 - args.threshold:
            verdict = "improved"
            improvements.append(metric)
        rows.append((metric, f"{base[metric]:g}", f"{current[metric]:g}",
                     f"{ratio:.2f}x", verdict))
    for metric in sorted(set(current) - set(base)):
        rows.append((metric, "-", f"{current[metric]:g}", "-",
                     "NEW (no baseline)"))

    captured = (baseline.get("captured") or {}).get(env, {})
    print(f"bench-compare: environment '{env}', threshold "
          f"+{args.threshold:.0%}")
    if captured:
        print(f"  baseline captured: {captured.get('date', '?')} on "
              f"{captured.get('host', '?')}")
    print_table(rows)

    # Context: how the current run compares to the Linux reference
    # columns (bare-metal native and the same-silicon qemu VM),
    # mirroring the issue #195 comparison-target table. Informational
    # only -- cross-environment ratios never gate.
    for ref in ("native", "qemu-aarch64"):
        if ref == env:
            continue
        ref_column = (baseline.get("environments") or {}).get(ref)
        if not ref_column:
            continue
        rbase = flatten(ref_column)
        shared = sorted(set(rbase) & set(current))
        if not shared:
            continue
        print(f"\n  ratio vs {ref} baseline column (informational):")
        rrows = [("metric", ref, env, "ratio", "")]
        for metric in shared:
            ratio = current[metric] / rbase[metric] if rbase[metric] \
                else 0.0
            rrows.append((metric, f"{rbase[metric]:g}",
                          f"{current[metric]:g}", f"{ratio:.2f}x", ""))
        print_table(rrows)

    if improvements:
        print(f"\nimproved beyond threshold: {', '.join(improvements)}")
        print("  (consider refreshing tests/bench-baseline.json so the "
              "gain is locked in)")

    if regressions:
        sys.stdout.flush()
        print(f"\nbench-compare: FAIL -- {len(regressions)} metric(s) "
              f"regressed: {', '.join(regressions)}", file=sys.stderr)
        if args.report_only:
            print("bench-compare: report-only mode, exiting 0",
                  file=sys.stderr)
            return 0
        return 1

    print("\nbench-compare: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
