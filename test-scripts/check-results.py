#!/usr/bin/env python3
"""CI gate for the WebAssembly probe suite.

Reads a Ghidra headless `probe-run.log` (produced by `test-scripts/run_probes.ps1`) plus the recorded
baseline `expected-results.json` and exits non-zero with a readable diff when

  * a probe is missing from the log,
  * a probe's metrics (`funcs`/`instrs`/`undefined_bytes`/`decompiled`/`decompile_failed`) differ,
  * an expected import failure unexpectedly succeeds (or a probe that must import now fails),
  * the log contains a probe that has no recorded baseline (a probe nobody tests is not a test),
  * the decompiler baseline of the committed fixture (`test-scripts/fixtures/wasm_fixture.wasm`,
    checked through `DumpDecomp.java`'s `SUMMARY` line) changed.

Usage
-----
    # verify (what CI does)
    python test-scripts/check-results.py --log probe-run.log \
        --fixture-log fixture-run.log --require-fixture

    # regenerate the baseline from a fresh run (never hand-edit expected-results.json)
    python test-scripts/check-results.py --update --log probe-run.log \
        --fixture-log fixture-run.log --real-module-log real-run.log

Stdlib only. The log format is the raw analyzeHeadless stdout with prefixes such as
`INFO  WasmFeatureReport.java> ... (GhidraScript)`; the regexes below match the payload anywhere in
the line so Windows and Linux runs parse identically.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------- log parsing

# PROBE <program name> funcs=N instrs=N undefined_bytes=N decompiled=N decompile_failed=N
PROBE_RE = re.compile(
    r"\bPROBE\s+(?P<name>\S+)\s+"
    r"funcs=(?P<funcs>\d+)\s+"
    r"instrs=(?P<instrs>\d+)\s+"
    r"undefined_bytes=(?P<undefined_bytes>\d+)\s+"
    r"decompiled=(?P<decompiled>\d+)\s+"
    r"decompile_failed=(?P<decompile_failed>\d+)"
)

# Import-failure markers emitted by the headless analyzer / loader.
IMPORT_FAIL_RES = (
    re.compile(r"Import failed for file:\s*(?P<ref>\S+)"),
    re.compile(r"No load spec found for import file:\s*(?P<ref>\S+)"),
)

# SUMMARY functions=N decompiled=N failed=N instructions=N [undefined_bytes=N]  (DumpDecomp.java)
SUMMARY_RE = re.compile(
    r"\bSUMMARY\s+functions=(?P<functions>\d+)\s+"
    r"decompiled=(?P<decompiled>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+"
    r"instructions=(?P<instructions>\d+)"
    r"(?:\s+undefined_bytes=(?P<undefined_bytes>\d+))?"
)

METRIC_KEYS = ("funcs", "instrs", "undefined_bytes", "decompiled", "decompile_failed")


def basename_of(ref: str) -> str:
    """`file:///tmp/probes/21_component_model.wasm?MD5=..` -> `21_component_model.wasm`."""
    ref = ref.split("?", 1)[0].split("#", 1)[0].replace("\\", "/")
    return ref.rsplit("/", 1)[-1]


def read_log(path: Path) -> str:
    """Read a harness log.

    The capture is pinned to UTF-8 by the PowerShell scripts, but older captures (or a run under
    Windows PowerShell 5.1, whose Tee-Object/Out-File wrote UTF-16) must still parse: detect a
    BOM or NUL bytes and fall back to UTF-16, otherwise read UTF-8 (BOM tolerated).
    """
    raw = path.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff") or b"\x00" in raw[:64]:
        for enc in ("utf-16", "utf-16-le"):
            try:
                return raw.decode(enc)
            except UnicodeError:
                continue
    return raw.decode("utf-8-sig", errors="replace")


def parse_probe_log(text: str):
    """Return (results, import_failures, duplicates)."""
    results: dict[str, dict] = {}
    duplicates: list[str] = []
    for line in text.splitlines():
        m = PROBE_RE.search(line)
        if not m:
            continue
        name = m.group("name")
        if name in results:
            duplicates.append(name)
        results[name] = {k: int(m.group(k)) for k in METRIC_KEYS}

    import_failures: set[str] = set()
    for line in text.splitlines():
        for rx in IMPORT_FAIL_RES:
            m = rx.search(line)
            if m:
                import_failures.add(basename_of(m.group("ref")))
    # A module that both failed to import and produced metrics is contradictory; keep it as a probe
    # result (metrics win) and drop the stale failure so the diff stays honest.
    import_failures -= set(results)
    return results, import_failures, duplicates


def parse_summary(text: str):
    """Return (summary dict or None, has_decompile_failures)."""
    summary = None
    for line in text.splitlines():
        m = SUMMARY_RE.search(line)
        if m:
            summary = {k: int(v) for k, v in m.groupdict().items() if v is not None}
    return summary, ("DECOMPILE FAIL" in text)


# ---------------------------------------------------------------- checks

def summary_pairs(s: str) -> dict[str, int]:
    """`"functions=437 decompiled=437 ..."` -> {"functions": 437, ...}."""
    pairs = {}
    for token in s.split():
        if "=" in token:
            k, v = token.split("=", 1)
            if v.isdigit():
                pairs[k] = int(v)
    return pairs


def check_probes(expected: dict, results: dict, failures: set[str], duplicates: list[str],
                 allow_extra: bool) -> list[str]:
    errors: list[str] = []
    for name in sorted(set(results) | set(failures)):
        if name not in expected:
            if allow_extra:
                print(f"note  {name}: no recorded baseline (allowed by --allow-extra)")
            else:
                errors.append(
                    f"UNEXPECTED {name}: probe present in the log but absent from "
                    f"expected-results.json - regenerate it with --update")
    if duplicates:
        errors.append("DUPLICATE PROBE lines for: " + ", ".join(sorted(set(duplicates))))

    for name, exp in sorted(expected.items()):
        exp_ok = exp.get("import_ok", True)
        got = results.get(name)
        if exp_ok:
            if got is None:
                if name in failures:
                    errors.append(
                        f"IMPORT REGRESSION {name}: expected it to import, but it failed to import")
                else:
                    errors.append(
                        f"MISSING {name}: expected import + metrics, found nothing in the log")
                continue
            diff = []
            for k in METRIC_KEYS:
                want = exp.get(k)
                if want is None:          # unrecorded metric: nothing to compare
                    continue
                if got[k] != want:
                    diff.append(f"{k} expected {want}, got {got[k]}")
            if diff:
                errors.append(f"DIFF {name}: " + "; ".join(diff))
        else:
            if got is not None:
                errors.append(
                    f"IMPORT UNEXPECTEDLY SUCCEEDED {name}: expected an import failure, but it "
                    f"imported (funcs={got['funcs']} instrs={got['instrs']})")
            elif name not in failures:
                errors.append(
                    f"MISSING {name}: expected an import failure, but the log shows neither a "
                    f"failure nor metrics")
    return errors


def check_fixture(expected: dict, log_path: Path, required: bool) -> list[str]:
    fixture = expected.get("fixture")
    if fixture is None:
        return []
    if not log_path.exists():
        if required:
            return [f"MISSING FIXTURE LOG {log_path}: expected a DumpDecomp run of the fixture"]
        print(f"note  fixture check skipped (no {log_path})")
        return []
    text = read_log(log_path)
    summary, decomp_failed = parse_summary(text)
    if summary is None:
        return [f"MISSING SUMMARY in {log_path}: DumpDecomp.java did not print one "
                f"(did the fixture import?)"]
    errors = []
    if decomp_failed:
        errors.append(f"FIXTURE DECOMPILE FAILURE: {log_path} contains a 'DECOMPILE FAIL' line")
    want = summary_pairs(fixture["summary"])
    got = {k: v for k, v in summary.items() if k in want}
    if set(want) - set(summary):
        errors.append(f"FIXTURE SUMMARY {log_path}: missing fields {sorted(set(want) - set(summary))}")
    elif want != got:
        want_line = str(fixture["summary"])
        got_line = "SUMMARY " + " ".join("%s=%s" % (k, v) for k, v in summary.items())
        errors.append(f"FIXTURE SUMMARY {log_path}: expected '{want_line}', got '{got_line}'")
    exp_u = fixture.get("undefined_bytes")
    if exp_u is not None and summary.get("undefined_bytes") != exp_u:
        errors.append(f"FIXTURE SUMMARY {log_path}: undefined_bytes expected {exp_u}, "
                      f"got {summary.get('undefined_bytes')}")
    return errors


def check_real_module(expected: dict, log_path: Path) -> list[str]:
    real = expected.get("real_module")
    if real is None or log_path is None:
        return []
    if not real.get("summary"):
        print(f"note  real-module check skipped (no recorded summary)")
        return []
    if not log_path.exists():
        print(f"note  real-module check skipped (no {log_path})")
        return []
    text = read_log(log_path)
    summary, _ = parse_summary(text)
    if summary is None:
        return [f"REAL MODULE {log_path}: expected a SUMMARY line, found none"]
    want = summary_pairs(real["summary"])
    bad = {k: (v, summary.get(k)) for k, v in want.items() if summary.get(k) != v}
    if bad:
        return [f"REAL MODULE {log_path}: " +
                "; ".join(f"{k} expected {w}, got {g}" for k, (w, g) in sorted(bad.items()))]
    exp_u = real.get("undefined_bytes")
    if exp_u is not None and summary.get("undefined_bytes") != exp_u:
        return [f"REAL MODULE {log_path}: undefined_bytes expected {exp_u}, "
                f"got {summary.get('undefined_bytes')}"]
    return []


# ---------------------------------------------------------------- update

def update_json(expected_path: Path, results: dict, failures: set[str],
                fixture_log: Path | None, real_log: Path | None) -> dict:
    try:
        data = json.loads(expected_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        data = {}
    data.setdefault("real_module", {})
    data["comment"] = ("Probe baseline enforced by .github/workflows/probes.yml. Regenerate - never "
                       "hand-edit - with: python test-scripts/check-results.py --update "
                       "--log <probe-run.log> --fixture-log <fixture-run.log>")
    probes = {}
    for name in sorted(set(results) | set(failures)):
        if name in results:
            probes[name] = dict(results[name], import_ok=True)
        else:
            probes[name] = {k: None for k in METRIC_KEYS}
            probes[name]["import_ok"] = False
    data["probes"] = probes
    data["probe_count"] = len(probes)

    if fixture_log is not None and fixture_log.exists():
        summary, _ = parse_summary(read_log(fixture_log))
        if summary is None:
            raise SystemExit(f"--update: no SUMMARY line in {fixture_log}")
        data["fixture"] = {
            "wasm": "test-scripts/fixtures/wasm_fixture.wasm",
            "summary": " ".join(f"{k}={summary[k]}" for k in
                                ("functions", "decompiled", "failed", "instructions")),
        }
        if "undefined_bytes" in summary:
            data["fixture"]["undefined_bytes"] = summary["undefined_bytes"]

    if real_log is not None and real_log.exists():
        summary, _ = parse_summary(read_log(real_log))
        if summary is None:
            raise SystemExit(f"--update: no SUMMARY line in {real_log}")
        real = data.setdefault("real_module", {})
        real["wasm"] = "rasterbator_rs_bg.wasm"
        real["summary"] = " ".join(f"{k}={summary[k]}" for k in
                                   ("functions", "decompiled", "failed", "instructions"))
        if "undefined_bytes" in summary:
            real["undefined_bytes"] = summary["undefined_bytes"]
        real["note"] = ("external payload, not committed to the repo; verified only when a "
                        "DumpDecomp log is supplied via --real-module-log")
    return data


# ---------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", default="probe-run.log",
                    help="probe-run.log from run_probes.ps1 (default: ./probe-run.log)")
    ap.add_argument("--expected", default=str(here / "expected-results.json"),
                    help="recorded baseline JSON")
    ap.add_argument("--fixture-log", default=None,
                    help="DumpDecomp log of the committed fixture "
                         "(default: fixture-run.log beside --log)")
    ap.add_argument("--real-module-log", default=None,
                    help="optional DumpDecomp log of a real module (e.g. real-run.log)")
    ap.add_argument("--require-fixture", action="store_true",
                    help="fail if the fixture log is absent")
    ap.add_argument("--no-fixture", action="store_true", help="skip the fixture check entirely")
    ap.add_argument("--allow-extra", action="store_true",
                    help="only warn about probes missing from expected-results.json")
    ap.add_argument("--update", action="store_true",
                    help="rewrite expected-results.json from the logs instead of checking")
    args = ap.parse_args(argv)

    log_path = Path(args.log).resolve()
    expected_path = Path(args.expected).resolve()
    fixture_log = None
    if not args.no_fixture:
        fixture_log = Path(args.fixture_log).resolve() if args.fixture_log \
            else log_path.parent / "fixture-run.log"
    real_log = Path(args.real_module_log).resolve() if args.real_module_log else None

    if not log_path.exists():
        print(f"error: probe log not found: {log_path}", file=sys.stderr)
        return 2
    results, failures, duplicates = parse_probe_log(read_log(log_path))

    if args.update:
        data = update_json(expected_path, results, failures, fixture_log, real_log)
        expected_path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n",
                                 encoding="utf-8")
        print(f"updated {expected_path}: {len(results)} probe(s) with metrics, "
              f"{len(failures)} expected import failure(s)")
        return 0

    if not expected_path.exists():
        print(f"error: baseline not found: {expected_path}", file=sys.stderr)
        return 2
    expected = json.loads(expected_path.read_text(encoding="utf-8"))

    errors = check_probes(expected.get("probes", {}), results, failures, duplicates,
                          args.allow_extra)
    errors += check_fixture(expected, fixture_log, args.require_fixture) if fixture_log else []
    errors += check_real_module(expected, real_log)

    n_exp = len(expected.get("probes", {}))
    print(f"probes: {len(results)} imported, {len(failures)} import failure(s); "
          f"baseline has {n_exp}")
    if errors:
        for e in errors:
            print(f"FAIL: {e}")
        print(f"\n{len(errors)} problem(s) - the probe baseline does not match the run.")
        print("If the change is intended, regenerate with:")
        print("  python test-scripts/check-results.py --update --log <probe-run.log> "
              "--fixture-log <fixture-run.log>")
        return 1
    print("OK: every probe matches the recorded baseline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
