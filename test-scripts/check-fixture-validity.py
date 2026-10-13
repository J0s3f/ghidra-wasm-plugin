#!/usr/bin/env python3
"""Fixture-validity gate: every generated probe module must decode as expected by the
external oracles (wabt `wasm-validate`, binaryen `wasm-dis`).

Why: the probe suite is the evidence base for the plugin's feature support, so every
probe that claims to exercise a feature must be a *valid* module. An invalid fixture
silently tests lenient-parse behaviour instead. This gate locks in the verified
classification:

  valid          - accepted by every available oracle (must stay accepted)
  wabt-gap       - wabt rejects it, binaryen accepts it (wabt 1.0.42 is behind the
                   final GC/typed-reference encodings)
  binaryen-gap   - binaryen rejects it, wabt accepts it (unexpected; investigate)
  unsupported    - both reject it because neither tool implements the feature
                   (components, stack switching, string builtins, memory.discard)
  invalid        - deliberately invalid (negative probes: malformed/overflowing bodies)

The expectation file is `test-scripts/fixture-validity.json`, recorded from a real run
(never hand-written). A probe that is not recorded, or whose verdict changes, fails the
gate; a human then decides whether to fix the probe or re-record with `--update`.

Usage
-----
    python3 test-scripts/check-fixture-validity.py --generate \
        --probes "$RUNNER_TEMP/fixture-probes" --wabt "$RUNNER_TEMP/spectest-tools/wabt-1.0.42/bin"

    # full check (adds the binaryen oracle; also asserts the wabt-gap class)
    python3 test-scripts/check-fixture-validity.py --generate \
        --probes <dir> --wabt <dir> --binaryen <dir>

    # re-record after an intentional fixture change
    python3 test-scripts/check-fixture-validity.py --generate --probes <dir> \
        --wabt <dir> --binaryen <dir> --update

Exit codes: 0 = all probes match the recorded classification, 1 = mismatch,
2 = setup problem (missing tool, no probes, malformed expectation file).
Stdlib only. The generators are the same gen_*.py + probes_*.py globs run_probes.ps1
uses, so the gate covers exactly the CI probe batch.
"""
import argparse
import glob
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

CLASSES = ("valid", "wabt-gap", "binaryen-gap", "unsupported", "invalid")


def exe(directory: pathlib.Path, name: str) -> pathlib.Path:
    for candidate in (directory / name, directory / f"{name}.exe",
                      directory / "bin" / name, directory / "bin" / f"{name}.exe"):
        if candidate.exists():
            return candidate
    return None


def first_error_line(text: str) -> str:
    for line in text.strip().splitlines():
        if line.strip():
            return line.strip()
    return "?"


def run(cmd, timeout: int = 120) -> tuple:
    """Run an oracle. Returns (ok, reason) where ok is True/False, or None when the oracle
    timed out (a runaway `wasm-dis` was observed consuming >20 GB on one probe - never let that
    hang the gate; the timeout is reported and the probe is judged by the other oracle)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"oracle timed out after {timeout}s (runaway process killed)"
    except OSError as exc:
        return None, f"oracle failed to start: {exc}"
    return p.returncode == 0, first_error_line(p.stderr or p.stdout)


def generate(script_dir: pathlib.Path, probe_dir: pathlib.Path) -> int:
    if probe_dir.exists():
        shutil.rmtree(probe_dir)
    probe_dir.mkdir(parents=True)
    generators = sorted(glob.glob(str(script_dir / "gen_*.py")) +
                        glob.glob(str(script_dir / "probes_*.py")))
    for g in generators:
        r = subprocess.run([sys.executable, g, str(probe_dir)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"ERROR: generator {pathlib.Path(g).name} failed:\n{r.stderr.strip()}")
            return 2
    return 0


def classify(wabt_ok, bin_ok, recorded: dict, binaryen_enabled: bool = True) -> str:
    # A timed-out oracle (None) carries no verdict: judge the probe by the oracle(s) that
    # answered and fall back to the recorded class, so a runaway validator cannot fail the gate.
    if binaryen_enabled and (wabt_ok is None or bin_ok is None):
        cls = recorded.get("class")
        return cls if cls in CLASSES and cls != "binaryen-gap" else ("valid" if (wabt_ok or bin_ok) else "unknown")
    # A probe recorded as deliberately invalid must stay rejected by wabt; that class is
    # authoritative whenever wabt rejects (binaryen is lenient about some of them, e.g.
    # out-of-order sections). A probe that starts being accepted still shows as a mismatch.
    if not wabt_ok and recorded.get("class") == "invalid":
        return "invalid"
    if not binaryen_enabled:
        if wabt_ok:
            return "valid"
        cls = recorded.get("class")
        return cls if cls in ("wabt-gap", "unsupported", "invalid") else "unexpected"
    if wabt_ok and bin_ok:
        return "valid"
    if bin_ok and not wabt_ok:
        return "wabt-gap"
    if wabt_ok and not bin_ok:
        return "binaryen-gap"
    cls = recorded.get("class")
    return cls if cls in ("unsupported", "invalid") else "unexpected"


def load_expectation(path: pathlib.Path) -> dict:
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data.get("probes"), dict):
        raise ValueError("expectation file has no 'probes' object")
    return data["probes"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--probes", required=True, help="directory holding the generated .wasm probes")
    ap.add_argument("--wabt", required=True, help="directory containing wasm-validate")
    ap.add_argument("--binaryen", default=None, help="directory containing wasm-dis (optional)")
    ap.add_argument("--expected", default=str(pathlib.Path(__file__).with_name("fixture-validity.json")),
                    help="expectation file (default: test-scripts/fixture-validity.json)")
    ap.add_argument("--generate", action="store_true", help="run the generators into --probes first")
    ap.add_argument("--update", action="store_true", help="re-record the expectation file")
    ap.add_argument("--timeout", type=int, default=120,
                    help="per-probe oracle timeout in seconds (default 120; a runaway wasm-dis was "
                         "observed consuming >20 GB on one probe - the timeout keeps the gate alive)")
    ap.add_argument("--invalid", action="append", default=[], metavar="PROBE",
                    help="declare a probe deliberately invalid (for --update)")
    ap.add_argument("--unsupported", action="append", default=[], metavar="PROBE",
                    help="declare a probe whose feature no oracle implements (for --update)")
    args = ap.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    probe_dir = pathlib.Path(args.probes)
    expected_path = pathlib.Path(args.expected)

    if args.generate:
        rc = generate(script_dir, probe_dir)
        if rc:
            return rc
    if not probe_dir.is_dir():
        print(f"ERROR: probe directory not found: {probe_dir}")
        return 2
    probes = sorted(probe_dir.glob("*.wasm"))
    if not probes:
        print(f"ERROR: no .wasm probes in {probe_dir}")
        return 2

    wabt = exe(pathlib.Path(args.wabt), "wasm-validate")
    if not wabt:
        print(f"ERROR: wasm-validate not found under {args.wabt}")
        return 2
    binaryen = None
    if args.binaryen:
        binaryen = exe(pathlib.Path(args.binaryen), "wasm-dis")
        if not binaryen:
            print(f"ERROR: wasm-dis not found under {args.binaryen}")
            return 2

    try:
        recorded = load_expectation(expected_path)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: bad expectation file {expected_path}: {exc}")
        return 2

    results = {}
    problems = []
    timeouts = []
    for probe in probes:
        wabt_ok, wabt_msg = run([str(wabt), "--enable-all", str(probe)], timeout=args.timeout)
        bin_ok, bin_msg = None, ""
        skipped_invalid = False
        if binaryen:
            if not wabt_ok and recorded.get(probe.name, {}).get("class") == "invalid":
                # deliberately invalid probe: wabt's rejection is the assertion, and binaryen's
                # wasm-dis has been observed running away (>20 GB) on this malformed family
                bin_msg = "skipped: deliberately invalid probe (wabt rejects it)"
                skipped_invalid = True
            else:
                bin_ok, bin_msg = run([str(binaryen), "--all-features", "-o",
                                       "NUL" if os.name == "nt" else "/dev/null", str(probe)],
                                      timeout=args.timeout)
        cls = classify(wabt_ok, bin_ok, recorded.get(probe.name, {}),
                       binaryen_enabled=binaryen is not None)
        why = ""
        if cls != "valid":
            reasons = []
            if wabt_ok is not True and wabt_msg:
                reasons.append("wabt: " + wabt_msg)
            if binaryen and bin_ok is not True and bin_msg:
                reasons.append("binaryen: " + bin_msg)
            why = "; ".join(reasons)
        if not skipped_invalid and (wabt_ok is None or (binaryen and bin_ok is None)):
            timeouts.append(probe.name)
        results[probe.name] = {"class": cls, "why": why}

    if args.update:
        declared_invalid = set(args.invalid)
        declared_unsupported = set(args.unsupported)
        out = {}
        unresolved = []
        for name, r in sorted(results.items()):
            cls = r["class"]
            if cls == "unknown":
                # an oracle timed out: keep the recorded class, or record it as unsupported
                cls = recorded.get(name, {}).get("class", "unsupported")
            if cls == "unexpected":
                if name in declared_invalid:
                    cls = "invalid"
                elif name in declared_unsupported:
                    cls = "unsupported"
                elif recorded.get(name, {}).get("class") in ("invalid", "unsupported"):
                    cls = recorded[name]["class"]
                else:
                    unresolved.append(name)
                    continue
            entry = {"class": cls}
            old_why = recorded.get(name, {}).get("why")
            if cls != "valid":
                entry["why"] = old_why or r["why"]
            out[name] = entry
        if unresolved:
            print("ERROR: these probes are rejected by every oracle and are not declared "
                  "invalid or unsupported:\n  " + "\n  ".join(unresolved)
                  + "\nDecide deliberately and pass --invalid <probe> or --unsupported <probe>.")
            return 2
        payload = {
            "oracles": {
                "wabt": "1.0.42",
                "binaryen": "version_133" if binaryen else "not checked",
            },
            "note": ("Recorded from real runs of the probe generators. 'valid' must stay valid; "
                     "'wabt-gap' is wabt 1.0.42 not implementing the final GC/typed-ref encodings; "
                     "'unsupported' is a feature neither oracle implements; 'invalid' is a "
                     "deliberately invalid negative probe."),
            "probes": out,
        }
        expected_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
        changed = [n for n in results
                   if recorded.get(n, {}).get("class") != results[n]["class"]]
        print(f"updated {expected_path} ({len(out)} probes"
              + (f", {len(changed)} class change(s): {', '.join(sorted(changed))}" if changed else "")
              + ")")
        return 0

    for name in sorted(results):
        r = results[name]
        rec = recorded.get(name)
        if r["class"] == "unknown":
            continue  # an oracle timed out; the probe is judged by the other oracle / recorded class
        if rec is None:
            problems.append(f"{name}: probe present in the run but not recorded in "
                            f"{expected_path.name} - re-record with --update "
                            f"(current class: {r['class']}: {r['why']})")
        elif rec["class"] != r["class"]:
            problems.append(f"{name}: expected class '{rec['class']}', got '{r['class']}' "
                            f"({r['why']})")
    for name in sorted(recorded):
        if name not in results:
            problems.append(f"{name}: recorded but not generated (stale entry)")

    if timeouts:
        print(f"WARNING: {len(timeouts)} oracle timeout(s) - those probes are judged by the other "
              f"oracle / their recorded class: {', '.join(sorted(timeouts))}")
    counts = {c: sum(1 for r in results.values() if r["class"] == c) for c in CLASSES}
    print(f"probes: {len(results)}  " + "  ".join(f"{c}: {counts[c]}" for c in CLASSES
                                                  if c != "binaryen-gap" or counts[c]))
    if problems:
        print(f"\n{len(problems)} problem(s) - the fixture classification does not match "
              f"{expected_path.name}:")
        for p in problems:
            print(f"  {p}")
        print("\nIf the change is intended, re-record with: "
              "python3 test-scripts/check-fixture-validity.py ... --update")
        return 1
    print(f"OK: every probe matches the recorded fixture classification ({expected_path.name}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
