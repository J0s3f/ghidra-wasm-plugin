#!/usr/bin/env python3
"""Cross-engine decode oracle: does our plugin's decode match two independent engines?

Goal (REUSE_OPPORTUNITIES.md section 1 / work order step 4): make "our decode matches a second
engine on real modules" a *checked* property. For a pinned set of valid, offline-available
corpus modules this script:

  1. reads the plugin's per-function decode facts (DecodeOracleReport.java output, collected by
     decode-oracle.ps1 into <artifacts>/<module>/plugin.log),
  2. runs WABT `wasm-objdump -d` (instruction listing) and `-x` (section counts) and Binaryen
     `wasm-dis` (timeout-guarded) on the same modules as reference decoders,
  3. compares normalized decode facts across the engines:
       - bodies          : defined-function count        plugin == wabt == binaryen
       - imports         : imported-function count       plugin == wabt == binaryen
       - real_instrs     : total real wasm instructions   plugin == wabt
       - per_body_instrs : per-function real instr count  plugin == wabt (aligned by body ordinal)
       - opcode_histogram: normalized mnemonic histogram  plugin == wabt
     Binaryen is used only for function counts and validity: it is not byte-faithful
     (IRBuilder restructures the body and invents $scratch locals), so instruction counts are
     compared against WABT only (REUSE_OPPORTUNITIES.md section 4).
  4. checks the agreed facts against the recorded baseline
     (test-scripts/decode-oracle-baseline.json) and exits non-zero on any divergence.

Normalization (documented; the mnemonics differ between WABT and our SLEIGH listing text):
  * an instruction's normalized mnemonic is the first whitespace-delimited token of the
    disassembly line, lower-cased; all operands/immediates are stripped;
  * the plugin's pre-analyzer marker pseudo-instructions (mnemonics beginning with '.', i.e.
    .locals/.local/.case/.default - MODERN_WASM_GAPS 2.4) are excluded from real-instruction
    counts and histograms;
  * WABT's locals-declaration lines (mnemonic `local[N]`) and empty-mnemonic continuation lines
    (a multi-byte instruction whose bytes overflow onto a second `| ` line) are excluded.

The baseline is recorded from a real run (never hand-written), like fixture-validity.json. A fact
is recorded only when every oracle that produces it agrees; --update re-records. Any known,
intentional divergence (e.g. a mnemonic our SLEIGH spells differently from WABT) is an explicit,
justified entry in the module's allow_list, never a silent edit.

Usage:
    python3 test-scripts/check-decode-oracle.py --artifacts <dir> \
        --wabt <dir-with-wasm-objdump> --binaryen <dir-with-wasm-dis>
    python3 test-scripts/check-decode-oracle.py --artifacts <dir> --wabt <dir> --binaryen <dir> --update

Exit codes: 0 = every module's decode matches the baseline and the engines agree,
            1 = a divergence (cross-engine disagreement or drift from the baseline),
            2 = setup problem (missing tool / artifact / malformed baseline).
Stdlib only.
"""
import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Which oracles produce which fact (the baseline records the agreed value + this mapping).
FACT_ORACLES = {
    "bodies": ("plugin", "wabt", "binaryen"),
    "imports": ("plugin", "wabt", "binaryen"),
    "real_instrs": ("plugin", "wabt"),
    "per_body_instrs": ("plugin", "wabt"),
    "opcode_histogram": ("plugin", "wabt"),
}
FACT_DESC = {
    "bodies": "defined-function count",
    "imports": "imported-function count",
    "real_instrs": "total real wasm instructions (markers / locals-decl excluded)",
    "per_body_instrs": "per-function real instruction count, aligned by body ordinal",
    "opcode_histogram": "normalized mnemonic histogram (operands stripped, lower-cased)",
}


# ---------------------------------------------------------------- artifact parsing --
def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def parse_plugin_log(path: pathlib.Path) -> dict:
    """Parse DecodeOracleReport.java ORACLE-* lines out of the headless log."""
    facts = {"bodies": None, "imports": None, "real_instrs": None,
             "per_body_instrs": [], "opcode_histogram": {}}
    total_re = re.compile(r"ORACLE-TOTAL\s+bodies=(\d+)\s+imports=(\d+)\s+real=(\d+)\s+funcs=(\d+)")
    func_re = re.compile(r"ORACLE-FUNC\s+(\d+)\s+(.*)\s+real=(\d+)")
    histo_re = re.compile(r"ORACLE-HISTO\s+(\S+)\s+(\d+)")
    saw_total = False
    for raw in strip_ansi(path.read_text(encoding="utf-8", errors="replace")).splitlines():
        m = total_re.search(raw)
        if m:
            facts["bodies"] = int(m.group(1))
            facts["imports"] = int(m.group(2))
            facts["real_instrs"] = int(m.group(3))
            saw_total = True
            continue
        m = func_re.search(raw)
        if m:
            facts["per_body_instrs"].append(int(m.group(3)))
            continue
        m = histo_re.search(raw)
        if m:
            facts["opcode_histogram"][m.group(1)] = int(m.group(2))
    if not saw_total:
        raise ValueError(f"no ORACLE-TOTAL line in {path} (DecodeOracleReport.java did not run?)")
    return facts


# WABT renders a function header as `<addr> func[N]:` for an unnamed function (a stripped module
# has no .name section) and `<addr> func[N] <name>:` for a named/exported one - the <name> is
# optional. The body ordinal is the order of appearance in the Code Disassembly.
WABT_HEADER_RE = re.compile(r"^([0-9a-fA-F]+) func\[(\d+)\](?: <(.*)>)?:\s*$")
WABT_INSTR_RE = re.compile(r"^\s+([0-9a-fA-F]+):\s+([0-9a-fA-F ]+?)\s*\|\s*(.*)$")
# WABT renders a function's locals declaration as one line per contiguous same-type group:
# a single local is `local[2] type=v128`, a run is `local[1..3] type=i32`. None of these are
# instructions; the real local ops are local.get/.set/.tee (mnemonic starts with `local.`).
WABT_LOCALS_RE = re.compile(r"^local\[")


def parse_wabt_d(text: str) -> dict:
    """Parse `wasm-objdump -d` Code Disassembly into per-body instruction counts + histogram."""
    bodies = []          # list of {"func_index", "name", "instrs", "histo"}
    cur = None
    for line in text.splitlines():
        hm = WABT_HEADER_RE.match(line)
        if hm:
            cur = {"func_index": int(hm.group(2)), "name": hm.group(3), "instrs": 0, "histo": {}}
            bodies.append(cur)
            continue
        im = WABT_INSTR_RE.match(line)
        if im and cur is not None:
            rest = im.group(3).strip()
            if rest == "":
                continue                      # continuation line (bytes overflow, no mnemonic)
            mnemonic = rest.split()[0].lower()
            if WABT_LOCALS_RE.match(mnemonic):
                continue                      # locals declaration `local[N] type=...`
            cur["instrs"] += 1
            cur["histo"][mnemonic] = cur["histo"].get(mnemonic, 0) + 1
    histo = {}
    for b in bodies:
        for k, v in b["histo"].items():
            histo[k] = histo.get(k, 0) + v
    return {
        "bodies": len(bodies),
        "per_body_instrs": [b["instrs"] for b in bodies],
        "real_instrs": sum(b["instrs"] for b in bodies),
        "opcode_histogram": histo,
    }


def parse_wabt_x(text: str) -> dict:
    """Parse `wasm-objdump -x` for the import (func) count and Function/Code section counts."""
    imports = 0
    in_import = False
    section_re = re.compile(r"^([A-Z][A-Za-z]+)\[(\d+)\]:")
    for line in text.splitlines():
        sm = section_re.match(line)
        if sm:
            in_import = (sm.group(1) == "Import")
            continue
        if in_import and re.match(r"^\s*-\s*func\[", line):
            imports += 1

    def sec_count(name):
        m = re.search(r"^%s\[(\d+)\]:" % name, text, re.M)
        return int(m.group(1)) if m else None

    return {"imports": imports, "function_section": sec_count("Function"),
            "code_section": sec_count("Code")}


BIN_FUNC_RE = re.compile(r"^\s*\(func\s")
BIN_IMPORT_FUNC_RE = re.compile(r"^\s*\(import\s.*\(func\s")


def parse_binaryen(text: str) -> dict:
    bodies = sum(1 for l in text.splitlines() if BIN_FUNC_RE.match(l))
    imports = sum(1 for l in text.splitlines() if BIN_IMPORT_FUNC_RE.match(l))
    return {"bodies": bodies, "imports": imports}


# ---------------------------------------------------------------- oracle runners ---
def exe(directory: pathlib.Path, name: str) -> pathlib.Path:
    for cand in (directory / name, directory / f"{name}.exe",
                 directory / "bin" / name, directory / "bin" / f"{name}.exe"):
        if cand.exists():
            return cand
    return None


def run(cmd, timeout: int):
    """Run an oracle. Returns (returncode, stdout) or (None, reason) on timeout/start failure."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s (killed)"
    except OSError as exc:
        return None, f"failed to start: {exc}"
    return p.returncode, (p.stdout or "") + (p.stderr or "")


# ---------------------------------------------------------------- comparison -------
def apply_allow_list(histo: dict, allow_list: list) -> dict:
    """Rename wabt mnemonics to their plugin equivalents per the allow-list, so the two
    histograms can be compared. Each entry: {"wabt": X, "plugin": Y, "reason": ...}."""
    out = dict(histo)
    for e in allow_list:
        src, dst = e.get("wabt"), e.get("plugin")
        if src in out and src != dst:
            out[dst] = out.pop(src) + out.get(dst, 0)
    return out


def histo_diff(a: dict, b: dict) -> list:
    keys = sorted(set(a) | set(b))
    return [f"{k}: plugin={a.get(k, 0)} wabt={b.get(k, 0)}" for k in keys if a.get(k, 0) != b.get(k, 0)]


def compare_module(name: str, eng: dict, baseline: dict, update: bool) -> list:
    """Compare one module's per-engine facts against the baseline. Returns a list of problem
    strings (empty == pass). When update is True, returns problems only for cross-engine
    disagreement (the caller records the agreed facts)."""
    problems = []
    mod = baseline.get("modules", {}).get(name, {})
    skip = set(mod.get("skip") or [])
    allow = mod.get("allow_list") or []

    # Cross-engine agreement + baseline match, per fact.
    for fact, oracles in FACT_ORACLES.items():
        vals = {}
        for o in oracles:
            if o in skip:
                continue
            if o not in eng:
                problems.append(f"{name}.{fact}: oracle '{o}' produced no value (skipped? not run?)")
                continue
            vals[o] = eng[o][fact]
        if len(vals) < 1:
            continue
        # normalize wabt histogram through the allow-list before comparing to plugin
        if fact == "opcode_histogram" and "wabt" in vals and "plugin" in vals:
            vals["wabt"] = apply_allow_list(vals["wabt"], allow)
        distinct = []
        for o, v in vals.items():
            if v not in distinct:
                distinct.append(v)
        if len(distinct) > 1:
            # cross-engine disagreement
            detail = "; ".join(f"{o}={fmt(vals[o])}" for o in vals)
            problems.append(f"{name}.{fact}: engines disagree -> {detail}")
            continue
        agreed = distinct[0]
        if update:
            continue  # recording mode: disagreement already reported above
        expected = mod.get(fact)
        if expected is None:
            problems.append(f"{name}.{fact}: not recorded in baseline (re-record with --update)")
        elif not fact_eq(agreed, expected):
            problems.append(f"{name}.{fact}: baseline drift -> expected {fmt(expected)}, "
                            f"engines agree on {fmt(agreed)}")
    return problems


def fact_eq(a, b) -> bool:
    if isinstance(a, dict) and isinstance(b, dict):
        return a == b
    if isinstance(a, list) and isinstance(b, list):
        return a == b
    return a == b


def fmt(v) -> str:
    if isinstance(v, dict):
        return "{" + ", ".join(f"{k}:{v[k]}" for k in sorted(v)) + "}"
    if isinstance(v, list):
        return "[" + ", ".join(str(x) for x in v) + "]"
    return str(v)


# ---------------------------------------------------------------- main -------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--artifacts", required=True, help="directory written by decode-oracle.ps1 "
                    "(modules.json + <module>/plugin.log)")
    ap.add_argument("--wabt", required=True, help="directory containing wasm-objdump")
    ap.add_argument("--binaryen", required=True, help="directory containing wasm-dis")
    ap.add_argument("--baseline", default=str(pathlib.Path(__file__).with_name("decode-oracle-baseline.json")))
    ap.add_argument("--update", action="store_true", help="re-record the baseline from this run "
                    "(fails if the engines disagree)")
    ap.add_argument("--timeout", type=int, default=300,
                    help="per-oracle timeout in seconds (default 300; wasm-dis is only run on "
                         "valid, committed modules so it is safe, but the guard stays)")
    args = ap.parse_args()

    art = pathlib.Path(args.artifacts)
    modules_json = art / "modules.json"
    if not modules_json.is_file():
        print(f"ERROR: {modules_json} not found (run decode-oracle.ps1 first)")
        return 2
    modules = json.loads(modules_json.read_text(encoding="utf-8")).get("modules", [])
    if not modules:
        print("ERROR: no modules listed in modules.json")
        return 2

    wabt_objdump = exe(pathlib.Path(args.wabt), "wasm-objdump")
    if not wabt_objdump:
        print(f"ERROR: wasm-objdump not found under {args.wabt}")
        return 2
    wasm_dis = exe(pathlib.Path(args.binaryen), "wasm-dis")
    if not wasm_dis:
        print(f"ERROR: wasm-dis not found under {args.binaryen}")
        return 2

    baseline_path = pathlib.Path(args.baseline)
    baseline = {"modules": {}}
    if baseline_path.exists():
        try:
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        except (ValueError, json.JSONDecodeError) as exc:
            print(f"ERROR: bad baseline {baseline_path}: {exc}")
            return 2

    all_problems = []
    recorded = {}
    for mod in modules:
        name = mod["name"]
        wasm = pathlib.Path(mod["file"])
        mdir = art / name
        plugin_log = mdir / "plugin.log"
        if not plugin_log.is_file():
            print(f"ERROR: missing plugin log {plugin_log}")
            return 2
        print(f"== {name} ({wasm.name}) ==")

        # --- plugin facts (from the headless log) ---
        try:
            plugin = parse_plugin_log(plugin_log)
        except ValueError as exc:
            print(f"ERROR: {exc}")
            return 2

        # --- wabt wasm-objdump -d (instruction listing) ---
        rc, d_text = run([str(wabt_objdump), "-d", str(wasm)], args.timeout)
        if rc is None:
            all_problems.append(f"{name}: wabt wasm-objdump -d {d_text}")
            wabt = None
        else:
            (mdir / "wabt-d.txt").write_text(d_text, encoding="utf-8")
            wabt = parse_wabt_d(d_text)

        # --- wabt wasm-objdump -x (section counts / imports) ---
        rc2, x_text = run([str(wabt_objdump), "-x", str(wasm)], args.timeout)
        if rc2 is None:
            all_problems.append(f"{name}: wabt wasm-objdump -x {x_text}")
            wabt_x = {"imports": None}
        else:
            (mdir / "wabt-x.txt").write_text(x_text, encoding="utf-8")
            wabt_x = parse_wabt_x(x_text)
        if wabt is not None:
            wabt["imports"] = wabt_x["imports"]
            # cross-check wabt -d bodies against the -x Function section count
            fs = wabt_x.get("function_section")
            if fs is not None and fs != wabt["bodies"]:
                all_problems.append(f"{name}: wabt internal mismatch: -d bodies={wabt['bodies']} "
                                    f"but -x Function[{fs}]")

        # --- binaryen wasm-dis (function counts + validity) ---
        rc3, bin_text = run([str(wasm_dis), "--all-features", str(wasm)], args.timeout)
        if rc3 is None:
            all_problems.append(f"{name}: binaryen wasm-dis {bin_text}")
            binaryen = None
        elif rc3 != 0:
            all_problems.append(f"{name}: binaryen wasm-dis rejected the module "
                                f"(exit {rc3}): {first_line(bin_text)}")
            binaryen = None
        else:
            (mdir / "binaryen.wat").write_text(bin_text, encoding="utf-8")
            binaryen = parse_binaryen(bin_text)

        eng = {"plugin": plugin}
        if wabt is not None:
            eng["wabt"] = wabt
        if binaryen is not None:
            eng["binaryen"] = binaryen

        # summary line
        b = eng.get("plugin", {}).get("bodies")
        wb = eng.get("wabt", {}).get("bodies")
        bb = eng.get("binaryen", {}).get("bodies")
        print(f"   bodies plugin={b} wabt={wb} binaryen={bb}   "
              f"real_instrs plugin={eng.get('plugin',{}).get('real_instrs')} "
              f"wabt={eng.get('wabt',{}).get('real_instrs')}")

        problems = compare_module(name, eng, baseline, args.update)
        all_problems.extend(problems)

        if args.update:
            # record the agreed facts (only meaningful if the engines agreed)
            rec = {"file": mod.get("file_name", wasm.name), "sha256": mod.get("sha256", ""),
                   "skip": baseline.get("modules", {}).get(name, {}).get("skip", []),
                   "allow_list": baseline.get("modules", {}).get(name, {}).get("allow_list", [])}
            for fact in FACT_ORACLES:
                if fact in eng.get("plugin", {}):
                    rec[fact] = eng["plugin"][fact]
            recorded[name] = rec

    if args.update:
        if all_problems:
            print(f"\nERROR: {len(all_problems)} cross-engine problem(s); refusing to record a "
                  f"baseline from a disagreeing run:")
            for p in all_problems:
                print(f"  {p}")
            return 1
        out = {
            "version": 1,
            "oracles": {"wabt": "1.0.42 (wasm-objdump)", "binaryen": "version_133 (wasm-dis)",
                        "plugin": "ghidra-wasm extension (this build)"},
            "normalization": ("instruction mnemonic = first whitespace-delimited token of the "
                              "disassembly line, lower-cased, operands stripped; plugin marker "
                              "pseudo-instructions (mnemonics beginning with '.') and WABT "
                              "locals-declaration lines (local[N]) and empty continuation lines "
                              "are excluded from real-instruction counts and histograms."),
            "comparisons": {f: {"oracles": list(o), "fact": FACT_DESC[f]} for f, o in FACT_ORACLES.items()},
            "modules": dict(sorted(recorded.items())),
        }
        # Write bytes (not text) so the file is always LF, matching the repo's
        # core.autocrlf=input convention and avoiding CRLF/LF churn on Windows.
        baseline_path.write_bytes((json.dumps(out, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        print(f"\nupdated {baseline_path} ({len(recorded)} module(s))")
        return 0

    if all_problems:
        print(f"\n{len(all_problems)} divergence(s) - the decode oracle does not match the baseline:")
        for p in all_problems:
            print(f"  {p}")
        print("\nIf the change is intended, re-record with: "
              "python3 test-scripts/check-decode-oracle.py --artifacts <dir> --wabt <dir> "
              "--binaryen <dir> --update")
        return 1
    print(f"\nOK: every module's decode matches the baseline and the engines agree "
          f"({baseline_path.name}).")
    return 0


def first_line(text: str) -> str:
    for line in text.strip().splitlines():
        if line.strip():
            return line.strip()
    return "?"


if __name__ == "__main__":
    sys.exit(main())
