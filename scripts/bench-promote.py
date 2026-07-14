#!/usr/bin/env python3
"""Promote a captured bench-suite results file into the baseline.

Reads build/bench-results.json (tests/bench-suite.sh output) and merges
its per-metric medians into tests/bench-baseline.json under the
"environments.<env>" and "captured.<env>" entries for the run's
BENCH_ENV column (taken from the results file's meta.env), then writes
the baseline back in place.

This is the mechanical half of the baseline refresh procedure in the
header of tests/bench-suite.sh: it does not decide whether an update is
warranted (capture back-to-back runs and confirm they agree within a
few percent first) or commit the result. Run it once per column after
each `make bench-ci` / `BENCH_ENV=... make bench-ci`:

    make bench-ci                         && scripts/bench-promote.py
    BENCH_ENV=qemu-aarch64 make bench-ci  && scripts/bench-promote.py \\
        --results build/bench-results-qemu-aarch64.json
    BENCH_ENV=orbstack make bench-ci      && scripts/bench-promote.py \\
        --results build/bench-results-orbstack.json

Cases/metrics present in the baseline but absent from the results file
(e.g. an ERR/SKIP row, or a filtered partial run) are left untouched by
default; pass --prune to drop them instead, which is what a full
recapture after removing or renaming cases should use.

Usage:
    scripts/bench-promote.py [--results PATH] [--baseline PATH]
                             [--prune] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_RESULTS = ROOT / "build" / "bench-results.json"
DEFAULT_BASELINE = ROOT / "tests" / "bench-baseline.json"

SECTIONS = ("lmbench", "applications")


def to_baseline_tree(node: dict) -> dict:
    """Recursively collapse a results section tree to plain medians
    ({name: median} leaves, nested dicts preserved), dropping SKIP/ERR
    rows (they carry no number to promote)."""
    out: dict = {}
    for name, leaf in node.items():
        if not isinstance(leaf, dict):
            continue
        if "median" in leaf:
            out[name] = leaf["median"]
        elif "status" in leaf:
            continue  # {"status": "SKIP"|"ERR"} -- nothing to promote.
        else:
            sub = to_baseline_tree(leaf)
            if sub:
                out[name] = sub
    return out


def merge_tree(dest: dict, src: dict, prefix: str,
               added: list, updated: list) -> None:
    for name, value in src.items():
        tag = f"{prefix}{name}"
        if isinstance(value, dict):
            merge_tree(dest.setdefault(name, {}), value, f"{tag}.",
                       added, updated)
        else:
            if name in dest:
                if dest[name] != value:
                    updated.append(tag)
            else:
                added.append(tag)
            dest[name] = value


def prune_tree(dest: dict, src: dict, prefix: str, pruned: list) -> None:
    for name in list(dest):
        tag = f"{prefix}{name}"
        if name not in src:
            pruned.append(tag)
            del dest[name]
        elif isinstance(dest[name], dict) and isinstance(src[name], dict):
            prune_tree(dest[name], src[name], f"{tag}.", pruned)


def format_host(host: dict) -> str:
    return (f"{host.get('os', '?')} {host.get('os_version', '?')} "
            f"{host.get('machine', '?')} ({host.get('cpu', '?')})")


def load_json(path: pathlib.Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"bench-promote: missing {path}", file=sys.stderr)
        raise SystemExit(2)
    except json.JSONDecodeError as exc:
        print(f"bench-promote: invalid JSON in {path}: {exc}", file=sys.stderr)
        raise SystemExit(2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=pathlib.Path,
                        default=DEFAULT_RESULTS)
    parser.add_argument("--baseline", type=pathlib.Path,
                        default=DEFAULT_BASELINE)
    parser.add_argument("--prune", action="store_true",
                        help="drop baseline cases/metrics absent from "
                             "--results instead of leaving them untouched")
    parser.add_argument("--dry-run", action="store_true",
                        help="print what would change; don't write "
                             "--baseline")
    args = parser.parse_args()

    results = load_json(args.results)
    baseline = load_json(args.baseline)

    env = results.get("meta", {}).get("env")
    if not env:
        print("bench-promote: results file has no meta.env", file=sys.stderr)
        return 2

    baseline.setdefault("environments", {}).setdefault(env, {})
    column = baseline["environments"][env]

    added, updated, pruned = [], [], []
    for section in SECTIONS:
        new_leaves = to_baseline_tree(results.get(section, {}))
        dest = column.setdefault(section, {})
        prefix = f"{section}."
        merge_tree(dest, new_leaves, prefix, added, updated)
        if args.prune:
            prune_tree(dest, new_leaves, prefix, pruned)

    meta = results.get("meta", {})
    captured_entry = {
        "date": meta.get("date"),
        "host": format_host(meta.get("host", {})),
        "iterations": meta.get("iterations"),
    }
    if meta.get("note"):
        captured_entry["note"] = meta["note"]
    baseline.setdefault("captured", {})[env] = captured_entry

    print(f"bench-promote: environment '{env}' from {args.results}")
    print(f"  {len(added)} added, {len(updated)} updated, "
          f"{len(pruned)} pruned")
    for tag in added:
        print(f"    + {tag}")
    for tag in updated:
        print(f"    ~ {tag}")
    for tag in pruned:
        print(f"    - {tag}")

    if args.dry_run:
        print("bench-promote: --dry-run, not writing", file=sys.stderr)
        return 0

    args.baseline.write_text(
        json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
    print(f"bench-promote: wrote {args.baseline}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
