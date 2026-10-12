#!/usr/bin/env python3
"""Turn the WebAssembly spec ``.wast`` *negative* commands into importable ``.wasm`` modules.

Sibling of ``prepare_spec_tests.py`` (which handles the *valid* ``"module"`` commands). This script
collects the modules referenced by ``assert_invalid`` / ``assert_malformed`` / ``assert_unlinkable``
- modules a correct WebAssembly implementation must **reject** - and copies them into a flat import
directory whose file names carry the expectation:

    <wast>.<n>.invalid.wasm
    <wast>.<n>.malformed.wasm
    <wast>.<n>.unlinkable.wasm

The Ghidra side (``run_spectest_negative.ps1``) imports that directory and classifies each outcome as
rejected / accepted (silent acceptance) / crash / hang.

Outputs, under ``--out``:

    json/<wast>.json             raw wast2json output (kept for debugging)
    import/<wast>.<n>.<kind>.wasm  the negative modules, the actual Ghidra import set
    modules.json                 manifest: id, wasm, wast, wast line, kind, module_type, expected text
    prepare_summary.json         counts (selected / skipped text modules / per-kind / per-wast)

Usage:
    python prepare_spec_negative.py --spec <testsuite-dir> --wast2json <wast2json[.exe]>
                                    --out <workdir> [--subset all|core|...] [--files a.wast,b.wast]
                                    [--kinds invalid,malformed,unlinkable]
                                    [--max-per-wast-per-kind N] [--include-text]

Notes:
  * ``module_type: "text"`` commands (a ``assert_malformed`` on the *text* format) are emitted by
    wabt as ``.wat`` files. They are not WebAssembly binaries at all, so a binary loader rejects them
    trivially; they are skipped by default to keep the run bounded. ``--include-text`` copies them
    too (still named ``.wasm`` so the import directory stays uniform).
  * ``assert_unlinkable`` modules are *valid* modules that fail to link/instantiate; the plugin does
    not link, so "accepted" is the expected (if uninteresting) outcome for them. They are kept in a
    separate ``unlinkable`` class so the table can be read correctly.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from prepare_spec_tests import SUBSETS  # noqa: E402  (reuse the existing subset definitions)

NEGATIVE_TYPES = {
    "assert_invalid": "invalid",
    "assert_malformed": "malformed",
    "assert_unlinkable": "unlinkable",
}


def run_wast2json(wast2json, wast_path, json_path):
    """Return (ok, output). --no-check lets wabt emit invalid modules too (we want exactly those)."""
    proc = subprocess.run(
        [wast2json, "--no-check", "-o", json_path, wast_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    return proc.returncode == 0, (proc.stdout or "").strip()


def select_names(args, spec):
    if args.files:
        names = [n.strip() for n in args.files.split(",") if n.strip()]
        # accept both "binary" and "binary.wast"
        names = [os.path.splitext(n)[0] for n in names]
    elif args.subset == "all":
        names = sorted(os.path.splitext(f)[0] for f in os.listdir(spec) if f.endswith(".wast"))
    elif args.subset == "simd":
        names = sorted(os.path.splitext(f)[0] for f in os.listdir(spec)
                       if f.startswith("simd_") and f.endswith(".wast"))
    else:
        names = SUBSETS[args.subset]
    seen = set()
    return [n for n in names if not (n in seen or seen.add(n))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", required=True, help="directory containing the .wast files")
    ap.add_argument("--wast2json", required=True, help="path to wast2json(.exe)")
    ap.add_argument("--out", required=True, help="work directory to create")
    ap.add_argument("--subset", default="all", choices=sorted(SUBSETS))
    ap.add_argument("--files", default="", help="comma-separated .wast basenames (overrides --subset)")
    ap.add_argument("--kinds", default="invalid,malformed,unlinkable",
                    help="which negative classes to take")
    ap.add_argument("--max-per-wast-per-kind", type=int, default=0,
                    help="cap modules per (.wast, kind) (0 = unlimited); bounds the run while "
                         "keeping each file represented")
    ap.add_argument("--max-per-wast", type=int, default=0,
                    help="synonym for --max-per-wast-per-kind")
    ap.add_argument("--include-text", action="store_true",
                    help="also take assert_malformed commands on the text format (emitted as .wat)")
    args = ap.parse_args()

    kinds = {k.strip() for k in args.kinds.split(",") if k.strip()}
    bad = kinds - set(NEGATIVE_TYPES.values())
    if bad:
        ap.error("unknown --kinds: %s" % ", ".join(sorted(bad)))
    cap = args.max_per_wast_per_kind or args.max_per_wast

    spec = os.path.abspath(args.spec)
    out = os.path.abspath(args.out)
    json_dir = os.path.join(out, "json")
    import_dir = os.path.join(out, "import")
    for d in (json_dir, import_dir):
        if os.path.isdir(d):
            shutil.rmtree(d)
        os.makedirs(d)

    names = select_names(args, spec)
    manifest = []
    parse_failures = []
    missing = []
    skipped_text = 0
    per_kind = {}
    per_wast = {}

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

        taken = {}
        for cmd in data["commands"]:
            kind = NEGATIVE_TYPES.get(cmd.get("type"))
            if kind is None or kind not in kinds:
                continue
            src_name = cmd.get("filename")
            if not src_name:
                continue                      # inline module with no emitted file
            module_type = cmd.get("module_type", "binary")
            if module_type == "text" and not args.include_text:
                skipped_text += 1
                continue
            if cap and taken.get(kind, 0) >= cap:
                continue
            src = os.path.join(json_dir, src_name)
            if not os.path.isfile(src):
                continue

            stem = os.path.splitext(os.path.basename(src_name))[0]
            dst_name = "%s.%s.wasm" % (stem, kind)
            shutil.copyfile(src, os.path.join(import_dir, dst_name))
            taken[kind] = taken.get(kind, 0) + 1
            manifest.append({
                "id": "%s.%s" % (stem, kind),
                "wasm": dst_name,
                "wast": name,
                "wast_line": cmd.get("line"),
                "kind": kind,
                "module_type": module_type,
                "text": (cmd.get("text") or "")[:200],
            })
            per_kind[kind] = per_kind.get(kind, 0) + 1
            per_wast[name] = per_wast.get(name, 0) + 1

    with open(os.path.join(out, "modules.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1)

    summary = {
        "selected_wast_files": len(names),
        "negative_modules": len(manifest),
        "skipped_text_modules": skipped_text,
        "wast2json_failures": len(parse_failures),
        "missing_wast_files": missing,
        "per_kind": per_kind,
        "per_wast": per_wast,
    }
    with open(os.path.join(out, "prepare_summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)

    print("selected wast files : %d" % len(names))
    print("negative modules    : %d  (%s)" % (
        len(manifest), ", ".join("%s=%d" % (k, per_kind[k]) for k in sorted(per_kind))))
    print("skipped text modules: %d%s" % (
        skipped_text, "" if args.include_text else "  (assert_malformed on the text format; --include-text)"))
    print("wast2json failures  : %d" % len(parse_failures))
    if missing:
        print("missing .wast files : %s" % ", ".join(missing))
    for pf in parse_failures:
        print("  PARSE-FAIL %s: %s" % (pf["name"], pf["log"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
