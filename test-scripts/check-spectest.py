#!/usr/bin/env python3
"""CI gate for the *positive* WebAssembly spec-test suite (the decode/decompile harness).

Reads the harness output produced by `test-scripts/spectest/run_spectest.ps1`
(`summary.json`, or `summary.md`) plus the recorded baseline `spectest-expected.json` and exits
non-zero with a readable diff when a metric regresses.

Failures:

  * the expectation file is missing (or a requested ``--subset`` is not recorded in it),
  * a metric recorded for the subset is absent from the run's summary (the harness stopped emitting
    it - that is itself a regression),
  * a metric differs from the recorded value.

Timing fields are ignored on purpose: the expectation file never records wall-clock numbers, so a
slower or faster machine cannot fail the gate.

Usage
-----
    # verify (what CI does)
    python3 test-scripts/check-spectest.py \
        --summary "$RUNNER_TEMP/spectest-core/summary.json" --subset core

    # regenerate the baseline from a fresh run (never hand-edit spectest-expected.json)
    python3 test-scripts/check-spectest.py \
        --summary "$RUNNER_TEMP/spectest-core/summary.json" --subset core --update

Stdlib only. ``--summary`` may point at ``summary.json``, the run directory containing it, or at
``summary.md`` (the human-readable table is parsed back to the same numbers).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Expected-key -> key in summary.json's ``summary.totals`` (or a derived value, see DERIVED below).
# ``undefined_bytes`` is the raw harness total (import-stub bytes + real decode gaps);
# ``real_undefined_bytes`` is ``decode_gap_bytes`` (the import-stub bytes removed by the harness) -
# this is the one that must stay 0 for a clean suite.
TOTAL_KEYS = {
    "modules_selected": "modules_selected",
    "imported": "modules_imported",
    "not_imported": "modules_not_imported",
    "functions": "functions",
    "instructions": "instructions",
    "undefined_bytes": "undefined_bytes",
    "external_stub_bytes": "external_stub_bytes",
    "real_undefined_bytes": "decode_gap_bytes",
    "decompiled": "decompiled",
    "decompile_failed": "decompile_failed",
}

# Derived from summary.json's shape, not a single totals field.
DERIVED = ("files",)

# The minimum set every recorded subset must carry (the acceptance criteria for the CI gate).
REQUIRED_METRICS = (
    "files",
    "imported",
    "not_imported",
    "instructions",
    "undefined_bytes",
    "real_undefined_bytes",
    "decompiled",
    "decompile_failed",
)

ERRORS = 1
SETUP = 2


# --------------------------------------------------------------------------- load the run

def _metrics_from_totals(totals: dict, per_wast: dict | None) -> dict[str, int]:
    m: dict[str, int] = {}
    if per_wast is not None:
        m["files"] = len(per_wast)
    for key, src in TOTAL_KEYS.items():
        if src in totals:
            m[key] = int(totals[src])
    return m


def load_json_metrics(path: Path) -> dict[str, int]:
    data = json.loads(path.read_text(encoding="utf-8"))
    summary = data.get("summary", data)
    totals = summary.get("totals")
    if not isinstance(totals, dict):
        raise ValueError(f"{path}: no summary.totals object (not a spec-harness summary.json?)")
    return _metrics_from_totals(totals, summary.get("per_wast"))


def load_markdown_metrics(path: Path) -> dict[str, int]:
    """Parse the ``| metric | value |`` table written by parse_spec_results.py."""
    totals: dict[str, int] = {}
    per_wast_rows = 0
    in_per_wast = False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("## "):
            in_per_wast = line.lower().startswith("## per-wast")
            continue
        if line.startswith("|") and line.endswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if not in_per_wast and len(cells) == 2:
                k, v = cells
                if v.isdigit():
                    totals[k] = int(v)
            elif in_per_wast and len(cells) == 8 and cells[0] not in ("wast", "") and "---" not in cells[0]:
                per_wast_rows += 1
    m = _metrics_from_totals(totals, {"dummy": 1} if per_wast_rows else None)
    if per_wast_rows:
        m["files"] = per_wast_rows
    return m


def load_run_metrics(summary_arg: str) -> tuple[dict[str, int], Path]:
    p = Path(summary_arg).resolve()
    if p.is_dir():
        p = p / "summary.json"
    if not p.exists():
        raise FileNotFoundError(p)
    if p.suffix.lower() == ".md":
        return load_markdown_metrics(p), p
    return load_json_metrics(p), p


# --------------------------------------------------------------------------- expectation file

def default_expected() -> Path:
    return Path(__file__).resolve().parent / "spectest-expected.json"


def load_expected(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def update_expected(path: Path, subset: str, metrics: dict[str, int]) -> None:
    try:
        data = load_expected(path)
    except FileNotFoundError:
        data = {}
    data["comment"] = (
        "Positive WebAssembly spec-suite baseline. The 'core' subset is enforced by "
        ".github/workflows/spectest.yml; 'simd' is a recorded reference (a clean SIMD run). "
        "Metrics come from real harness runs - never hand-edit. Generators: "
        "'core' = run_spectest.ps1 -Subset core -MaxPerWast 10; "
        "'simd' = run_spectest.ps1 -Subset simd -MaxPerWast 10. Regenerate one subset with: "
        "python3 test-scripts/check-spectest.py --summary <summary.json> --subset <core|simd> --update"
    )
    data.setdefault("subsets", {})
    data["subsets"][subset] = {k: metrics[k] for k in sorted(metrics)}
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- compare

def compare(expected: dict[str, int], run: dict[str, int], subset: str) -> list[str]:
    errors: list[str] = []
    missing_required = [k for k in REQUIRED_METRICS if k not in expected]
    if missing_required:
        errors.append(
            "EXPECTATION INCOMPLETE: subset '%s' has no recorded value for: %s"
            % (subset, ", ".join(missing_required)))
    for key in sorted(expected):
        want = expected[key]
        if key not in run:
            errors.append(
                "METRIC MISSING: '%s' is recorded in spectest-expected.json (subset '%s' = %s) but "
                "the run's summary does not emit it - the harness changed or was truncated"
                % (key, subset, want))
            continue
        got = run[key]
        if got != want:
            errors.append("DIFF %s: expected %s, got %s (delta %+d)" % (key, want, got, got - want))
    return errors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--summary", required=True,
                    help="summary.json (or the run directory, or summary.md) from run_spectest.ps1")
    ap.add_argument("--expected", default=str(default_expected()),
                    help="recorded baseline JSON (default: test-scripts/spectest-expected.json)")
    ap.add_argument("--subset", default="core",
                    help="subset key inside the expectation file (default: core)")
    ap.add_argument("--update", action="store_true",
                    help="rewrite the expectation file from this run instead of checking it")
    args = ap.parse_args(argv)

    expected_path = Path(args.expected).resolve()

    try:
        run, run_path = load_run_metrics(args.summary)
    except FileNotFoundError as exc:
        print(f"error: harness summary not found: {exc}", file=sys.stderr)
        return SETUP
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: cannot read {args.summary}: {exc}", file=sys.stderr)
        return SETUP

    if args.update:
        update_expected(expected_path, args.subset, run)
        print(f"updated {expected_path}: subset '{args.subset}' <- {run_path}")
        print("  " + ", ".join(f"{k}={run[k]}" for k in sorted(run)))
        return 0

    if not expected_path.exists():
        print(f"error: expectation file not found: {expected_path}", file=sys.stderr)
        print("Generate it from a real run with --update.", file=sys.stderr)
        return SETUP
    try:
        data = load_expected(expected_path)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: cannot read {expected_path}: {exc}", file=sys.stderr)
        return SETUP

    subsets = data.get("subsets", {})
    if args.subset not in subsets:
        print(f"error: subset '{args.subset}' is not recorded in {expected_path} "
              f"(have: {', '.join(sorted(subsets)) or 'none'})", file=sys.stderr)
        return SETUP
    expected = {k: int(v) for k, v in subsets[args.subset].items()}

    print(f"subset: {args.subset}  ({run_path})")
    print("  %-22s %10s %10s" % ("metric", "expected", "run"))
    for key in sorted(set(expected) | set(run)):
        want = expected.get(key)
        got = run.get(key)
        if want is None:
            mark = ""                              # extra run metric: not compared
        elif got is None:
            mark = "  <-- absent from run"
        elif want != got:
            mark = "  <-- differs"
        else:
            mark = ""
        print("  %-22s %10s %10s%s" % (key, want if want is not None else "-",
                                       got if got is not None else "-", mark))

    errors = compare(expected, run, args.subset)
    if errors:
        print()
        for e in errors:
            print(f"FAIL: {e}")
        print(f"\n{len(errors)} problem(s) - the positive spec-suite baseline does not match the run.")
        print("If the change is intended, regenerate with:")
        print(f"  python3 test-scripts/check-spectest.py --summary {args.summary} "
              f"--subset {args.subset} --update")
        return ERRORS

    print(f"\nOK: subset '{args.subset}' matches {expected_path.name}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
