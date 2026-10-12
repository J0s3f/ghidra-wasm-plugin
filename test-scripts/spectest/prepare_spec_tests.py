#!/usr/bin/env python3
"""Turn WebAssembly spec ``.wast`` files into importable ``.wasm`` modules.

For every selected ``.wast`` file this runs wabt's ``wast2json`` (which emits one ``.json`` plus one
``.wasm`` per module, both valid and invalid), then copies only the **valid** modules (the ones
referenced by a ``"module"`` command) into a flat import directory named ``<wast>.<n>.wasm`` so the
Ghidra side sees one program per valid spec module.

Outputs, under ``--out``:

    json/<wast>.json           raw wast2json output (kept for the emulation driver / debugging)
    import/<wast>.<n>.wasm     valid modules, the actual Ghidra import set
    modules.json               manifest: id, wast file, wast line, module name, wasm file
    parse_failures.json        wast files wabt could not parse

Usage:
    python prepare_spec_tests.py --spec <testsuite-dir> --wast2json <wast2json[.exe]>
                                 --out <workdir> [--subset smoke|core|memory|numeric|all]
                                 [--files a.wast,b.wast]
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

# Small hand-picked suites. "core" is the intended default: broad MVP + bulk-memory + table coverage
# whose module count keeps one headless run under a few minutes.
SUBSETS = {
    "smoke": [
        "i32", "i64", "f32", "f64", "nop", "block", "loop", "if", "br", "return",
    ],
    "numeric": [
        "i32", "i64", "f32", "f64", "f32_cmp", "f64_cmp", "f32_bitwise", "f64_bitwise",
        "conversions", "const", "int_literals", "float_literals", "float_memory", "endianness",
        "int_exprs", "float_exprs", "float_misc",
    ],
    "control": [
        "block", "loop", "if", "br", "br_if", "br_table", "return", "call", "call_indirect",
        "unreachable", "unreached-valid", "nop", "select", "labels", "switch", "fac", "forward",
        "stack", "func", "local_get", "local_set", "local_tee", "type", "traps",
    ],
    "memory": [
        "memory", "memory_size", "memory_grow", "memory_fill", "memory_copy", "address", "align",
        "load", "store", "memory_redundancy", "memory_trap", "data", "bulk", "memory_init",
    ],
    "table": [
        "table", "table_get", "table_set", "table_size", "table_grow", "table_fill", "table_copy",
        "table_init", "elem", "ref_null", "ref_is_null", "ref_func", "global", "exports",
        "imports", "start", "names", "comments",
    ],
}
SUBSETS["core"] = SUBSETS["control"] + SUBSETS["memory"] + SUBSETS["numeric"] + SUBSETS["table"]


def run_wast2json(wast2json, wast_path, json_path):
    """Return (ok, stderr). --no-check lets wabt emit invalid modules too (we filter later)."""
    proc = subprocess.run(
        [wast2json, "--no-check", "-o", json_path, wast_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    return proc.returncode == 0, (proc.stdout or "").strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", required=True, help="directory containing the .wast files")
    ap.add_argument("--wast2json", required=True, help="path to wast2json(.exe)")
    ap.add_argument("--out", required=True, help="work directory to create")
    ap.add_argument("--subset", default="core", choices=sorted(SUBSETS))
    ap.add_argument("--files", default="", help="comma-separated .wast basenames (overrides --subset)")
    ap.add_argument("--max-per-wast", type=int, default=0,
                    help="cap valid modules taken from each .wast (0 = unlimited); keeps one headless "
                         "run bounded while still covering each file's opcodes")
    args = ap.parse_args()

    spec = os.path.abspath(args.spec)
    out = os.path.abspath(args.out)
    json_dir = os.path.join(out, "json")
    import_dir = os.path.join(out, "import")
    for d in (json_dir, import_dir):
        if os.path.isdir(d):
            shutil.rmtree(d)
        os.makedirs(d)

    if args.files:
        names = [n.strip() for n in args.files.split(",") if n.strip()]
    else:
        names = SUBSETS[args.subset]
    # de-duplicate, preserve order
    seen = set()
    names = [n for n in names if not (n in seen or seen.add(n))]

    manifest = []
    parse_failures = []
    missing = []
    for name in names:
        wast = os.path.join(spec, name + ".wast")
        if not os.path.isfile(wast):
            missing.append(name)
            continue
        json_path = os.path.join(json_dir, name + ".json")
        ok, log = run_wast2json(args.wast2json, wast, json_path)
        if not ok:
            parse_failures.append({"name": name, "log": log})
            continue
        with open(json_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        taken = 0
        for cmd in data["commands"]:
            if cmd.get("type") != "module":
                continue
            wasm = cmd.get("filename")
            if not wasm:
                continue          # an inline module with no emitted file (should not happen)
            if args.max_per_wast and taken >= args.max_per_wast:
                continue
            src = os.path.join(json_dir, wasm)
            if not os.path.isfile(src):
                continue
            dst = os.path.join(import_dir, wasm)
            shutil.copyfile(src, dst)
            taken += 1
            manifest.append({
                "id": os.path.splitext(wasm)[0],
                "wast": name,
                "wast_line": cmd.get("line"),
                "module_name": cmd.get("name", ""),
                "wasm": wasm,
            })

    with open(os.path.join(out, "modules.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1)
    with open(os.path.join(out, "parse_failures.json"), "w", encoding="utf-8") as fh:
        json.dump(parse_failures, fh, indent=1)

    per_wast = {}
    for m in manifest:
        per_wast[m["wast"]] = per_wast.get(m["wast"], 0) + 1
    print("selected wast files : %d" % len(names))
    print("valid modules       : %d" % len(manifest))
    print("wast2json failures  : %d" % len(parse_failures))
    if missing:
        print("missing .wast files : %s" % ", ".join(missing))
    print("modules per wast    : " + ", ".join("%s=%d" % (k, per_wast[k]) for k in sorted(per_wast)))
    for pf in parse_failures:
        print("  PARSE-FAIL %s: %s" % (pf["name"], pf["log"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
