#!/usr/bin/env python3
"""Parse a spec-test harness headless log into per-module metrics + a ranked failure list.

Reads the ``SPECMODULE``/``SPECFUNC`` lines emitted by ``SpecModuleReport.java`` and the raw
analyzeHeadless log (for import/analysis exceptions and crashes), and writes ``summary.json`` and
``summary.md`` next to the log.

Usage:
    python parse_spec_results.py --log <headless.log> --modules <modules.json> --out <workdir>
"""
import argparse
import json
import os
import re
import sys

SPECMODULE = re.compile(r"SPECMODULE name=(\S+) (.*)")
SPECFUNC = re.compile(r"SPECFUNC name=(\S+) (.*)")
KV = re.compile(r"(\w+)=(\S*)")

# Substrings in the headless log that indicate a program did not import or analysis blew up.
CRASH_PATTERNS = [
    ("import_failed", re.compile(r"Import failed", re.I)),
    ("validation", re.compile(r"ValidationException", re.I)),
    ("illegal_argument", re.compile(r"IllegalArgumentException", re.I)),
    ("illegal_state", re.compile(r"IllegalStateException", re.I)),
    ("npe", re.compile(r"NullPointerException", re.I)),
    ("out_of_bounds", re.compile(r"IndexOutOfBoundsException|ArrayIndexOutOfBounds", re.I)),
    ("stack_overflow", re.compile(r"StackOverflowError", re.I)),
    ("oom", re.compile(r"OutOfMemoryError", re.I)),
    ("wasm_error", re.compile(r"wasm\.[A-Za-z]*Exception|WasmException|MalformedException", re.I)),
    ("analyzer_exception", re.compile(r"Exception during analysis|AnalysisException", re.I)),
    ("decode_error", re.compile(r"Failed to disassemble|BadInstruction|unknown opcode|invalid opcode", re.I)),
    ("class_cast", re.compile(r"cannot be cast to class ghidra")),
    ("stackvar_fail", re.compile(r"Failed to process instruction at ram:")),
    ("load_error", re.compile(r"Error loading|LoaderException|Unable to import", re.I)),
]

# analyzeHeadless prints the program name in INFO/WARN/ERROR lines; used to attribute a log line to
# a module. Falls back to global (name=None) if no module is found.
LINE_TS = re.compile(r"^\S+\s+\S+\s+(INFO|WARN|ERROR|DEBUG)\s+", re.I)
PROG_IN_LINE = re.compile(r"\((?:GhidraScript|HeadlessAnalyzer)\)", re.I)


def parse_kv(text):
    out = {}
    for k, v in KV.findall(text):
        out[k] = v
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--modules", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    with open(args.modules, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    by_wasm = {m["wasm"]: m for m in manifest}
    by_id = {m["id"]: m for m in manifest}

    modules = {}
    funcs = []
    syntax_errors = []
    import_failures = []
    current = None

    import_line = re.compile(r"IMPORTING: file:///\S*?/([^/?]+\.wasm)")
    fail_line = re.compile(r"FAILED to import|Import failed|Error loading|LoaderException|Unable to import", re.I)
    stackvar = re.compile(r"Failed to process instruction at ram:(\S+?):\s*([^:]+?):\s*(.*)")
    stackvar_fails = []

    with open(args.log, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()

    for line in lines:
        line = line.rstrip("\n").rstrip("\r")
        m = import_line.search(line)
        if m:
            current = m.group(1)
        m = SPECMODULE.search(line)
        if m:
            name = m.group(1)
            rec = parse_kv(m.group(2))
            rec = {k: (int(v) if re.fullmatch(r"-?\d+", v) else v) for k, v in rec.items()}
            rec["name"] = name
            rec["crashes"] = []
            modules[name] = rec
            continue
        m = SPECFUNC.search(line)
        if m:
            name = m.group(1)
            rec = parse_kv(m.group(2))
            rec["module"] = name
            funcs.append(rec)
            continue
        # attribution of raw log noise to a module
        low = line
        target = None
        for wasm in by_wasm:
            if wasm in line:
                target = wasm
                break
        if target is None and current is not None:
            target = current
        ms = stackvar.search(line)
        if ms:
            stackvar_fails.append({"addr": ms.group(1), "op": ms.group(2).strip(),
                                   "err": ms.group(3).strip()[:160], "module": target})
        for pname, pat in CRASH_PATTERNS:
            if pat.search(low):
                entry = {"kind": pname, "line": line.strip()[:400]}
                if target and target in modules:
                    modules[target]["crashes"].append(entry)
                else:
                    syntax_errors.append({"kind": pname, "line": line.strip()[:400], "module": target})
                break
        if fail_line.search(line):
            import_failures.append({"module": target, "line": line.strip()[:400]})

    # every manifest module should have a SPECMODULE line; those without = import failed
    not_imported = []
    imported_ids = set()
    for name in modules:
        imported_ids.add(name)

    summary_mods = []
    for m in manifest:
        wasm = m["wasm"]
        key = m["id"]
        rec = modules.get(wasm)
        if rec is None:
            not_imported.append(m)
        summary_mods.append({
            "id": key,
            "wast": m["wast"],
            "wast_line": m["wast_line"],
            "module_name": m["module_name"],
            "wasm": wasm,
            "imported": rec is not None,
            **(rec or {}),
        })

    total_funcs = sum(m.get("funcs", 0) or 0 for m in summary_mods)
    total_instrs = sum(m.get("instrs", 0) or 0 for m in summary_mods)
    total_undef = sum(m.get("undefined_bytes", 0) or 0 for m in summary_mods)
    total_decok = sum(m.get("decompiled", 0) or 0 for m in summary_mods)
    total_decfail = sum(m.get("decompile_failed", 0) or 0 for m in summary_mods)

    # rank modules by severity
    def sev(m):
        return (
            0 if not m["imported"] else 1,
            -(m.get("undefined_bytes", 0) or 0),
            -(m.get("decompile_failed", 0) or 0),
            len(m.get("crashes", []) or []),
        )

    worst_undef = sorted([m for m in summary_mods if (m.get("undefined_bytes", 0) or 0) > 0],
                         key=lambda m: -(m["undefined_bytes"]))
    worst_decfail = sorted([m for m in summary_mods if (m.get("decompile_failed", 0) or 0) > 0],
                           key=lambda m: -(m["decompile_failed"]))

    per_wast = {}
    for m in summary_mods:
        w = per_wast.setdefault(m["wast"], {"modules": 0, "imported": 0, "funcs": 0, "instrs": 0,
                                            "undefined_bytes": 0, "decode_gap_bytes": 0,
                                            "decompile_failed": 0, "decode_gap_funcs": 0})
        w["modules"] += 1
        w["imported"] += 1 if m["imported"] else 0
        w["funcs"] += m.get("funcs", 0) or 0
        w["instrs"] += m.get("instrs", 0) or 0
        w["undefined_bytes"] += m.get("undefined_bytes", 0) or 0
        w["decompile_failed"] += m.get("decompile_failed", 0) or 0

    def tally(seq):
        c = {}
        for k in seq:
            c[k] = c.get(k, 0) + 1
        return dict(sorted(c.items(), key=lambda kv: -kv[1]))

    funcs_undef = [f for f in funcs if int(f.get("undef", 0) or 0) > 0]
    funcs_decfail = [f for f in funcs if f.get("decompile") == "FAIL"]

    # An "external stub" is a function the loader placed in its external/import block (0x7f000000):
    # it has no body, so its undefined bytes are a modelling artifact, not a decode gap.
    def is_external(f):
        return str(f.get("entry", "")).startswith("ram:7f")

    ext_funcs = [f for f in funcs_undef if is_external(f)]
    gap_funcs = [f for f in funcs_undef if not is_external(f)]
    ext_bytes = sum(int(f.get("undef", 0) or 0) for f in ext_funcs)
    gap_bytes = sum(int(f.get("undef", 0) or 0) for f in gap_funcs)
    for f in gap_funcs:
        w = f["module"].rsplit(".", 1)[0]
        if w in per_wast:
            per_wast[w]["decode_gap_bytes"] += int(f.get("undef", 0) or 0)
            per_wast[w]["decode_gap_funcs"] += 1
    crash_kinds = tally([c["kind"] for m in summary_mods for c in (m.get("crashes") or [])] +
                        [p["kind"] for p in syntax_errors])
    stackvar_by_op = tally([s["op"] for s in stackvar_fails])

    summary = {
        "totals": {
            "modules_selected": len(manifest),
            "modules_imported": len(manifest) - len(not_imported),
            "modules_not_imported": len(not_imported),
            "functions": total_funcs,
            "instructions": total_instrs,
            "undefined_bytes": total_undef,
            "decompiled": total_decok,
            "decompile_failed": total_decfail,
            "funcs_with_undef": len(funcs_undef),
            "external_stub_funcs": len(ext_funcs),
            "external_stub_bytes": ext_bytes,
            "decode_gap_funcs": len(gap_funcs),
            "decode_gap_bytes": gap_bytes,
            "funcs_with_decompile_failure": len(funcs_decfail),
            "log_failure_lines": len(syntax_errors),
            "stackvar_failures": len(stackvar_fails),
        },
        "crash_kinds": crash_kinds,
        "stackvar_by_op": stackvar_by_op,
        "external_stub_funcs": ext_funcs[:50],
        "decode_gap_funcs": gap_funcs[:100],
        "import_failures": import_failures[:50],
        "not_imported": [{"id": m["id"], "wast": m["wast"], "wasm": m["wasm"]} for m in not_imported],
        "log_patterns": syntax_errors[:200],
        "per_wast": per_wast,
        "worst_undefined": worst_undef[:25],
        "worst_decompile_failed": worst_decfail[:25],
        "funcs_with_undef": funcs_undef[:100],
        "funcs_with_decompile_failure": funcs_decfail[:100],
        "stackvar_failures": stackvar_fails[:200],
    }

    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump({"summary": summary, "modules": summary_mods, "funcs": funcs}, fh, indent=1)

    md = []
    t = summary["totals"]
    md.append("# Spec-test harness summary\n")
    md.append("| metric | value |")
    md.append("| --- | --- |")
    for k, v in t.items():
        md.append("| %s | %s |" % (k, v))
    md.append("\n## Per-wast\n")
    md.append("| wast | modules | imported | funcs | instrs | undefined_bytes | decode_gap_bytes | decompile_failed |")
    md.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for w in sorted(per_wast, key=lambda k: (-per_wast[k]["decode_gap_bytes"], -per_wast[k]["decompile_failed"])):
        d = per_wast[w]
        md.append("| %s | %d | %d | %d | %d | %d | %d | %d |" % (
            w, d["modules"], d["imported"], d["funcs"], d["instrs"], d["undefined_bytes"],
            d["decode_gap_bytes"], d["decompile_failed"]))
    md.append("\n## Modules not imported (%d)\n" % len(not_imported))
    for m in not_imported[:60]:
        md.append("- %s (%s)" % (m["wasm"], m["wast"]))
    md.append("\n## Worst undefined_bytes\n")
    for m in worst_undef[:25]:
        md.append("- %s undef=%d funcs=%d instrs=%d" % (m["id"], m["undefined_bytes"], m.get("funcs", 0), m.get("instrs", 0)))
    md.append("\n## Worst decompile_failed\n")
    for m in worst_decfail[:25]:
        md.append("- %s failed=%d funcs=%d" % (m["id"], m["decompile_failed"], m.get("funcs", 0)))
    md.append("\n## Crash / warning classes\n")
    for k, v in crash_kinds.items():
        md.append("- %s: %d" % (k, v))
    md.append("\n## WasmStackVariableAnalyzer failures by opcode\n")
    for k, v in list(stackvar_by_op.items())[:30]:
        md.append("- %s: %d" % (k, v))
    md.append("\n## Functions with undefined bytes (decode gaps only, first 100)\n")
    for f in gap_funcs[:100]:
        md.append("- %s %s @ %s size=%s undef=%s at=%s decompile=%s" % (
            f["module"], f.get("fn"), f.get("entry"), f.get("size"), f.get("undef"),
            f.get("undef_at"), f.get("decompile")))
    md.append("\n## External/import stubs with undefined bytes (%d funcs, %d bytes)\n" %
              (len(ext_funcs), ext_bytes))
    seen_stub_mod = sorted({f["module"] for f in ext_funcs})
    md.append("- modules: " + (", ".join(seen_stub_mod[:40]) or "(none)"))
    md.append("\n## Decompile failures (first 100)\n")
    for f in funcs_decfail[:100]:
        md.append("- %s %s @ %s err=%s" % (f["module"], f.get("fn"), f.get("entry"), f.get("err")))

    with open(os.path.join(args.out, "summary.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(md) + "\n")

    print("modules: %d selected, %d imported, %d not imported" % (
        len(manifest), len(manifest) - len(not_imported), len(not_imported)))
    print("functions: %d, instructions: %d, undefined_bytes: %d, decompiled: %d, decompile_failed: %d" % (
        total_funcs, total_instrs, total_undef, total_decok, total_decfail))
    print("log failure patterns: %d" % len(syntax_errors))
    print("wrote %s and %s" % (os.path.join(args.out, "summary.json"), os.path.join(args.out, "summary.md")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
