#!/usr/bin/env python3
"""Build a filtered import directory + manifest from a previous ``negative.json``.

Used by the harness for a second ("evidence") pass: take only the modules that were *accepted*
(optionally only the ones whose outcome is interesting, e.g. ``accepted-empty``/``accepted-partial``)
from a completed run and re-import them with analysis enabled, so the SPECNEG lines get real
instrs / undefined_bytes and a nonsense program becomes measurable.

Usage:
    python select_negative_subset.py --results <negative.json> --modules <modules.json>
                                     --srcdir <previous import dir> --out <new workdir>
                                     [--reasons accepted-empty,accepted-partial]
                                     [--kinds malformed] [--limit N]
"""
import argparse
import json
import os
import shutil
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--modules", required=True)
    ap.add_argument("--srcdir", required=True, help="directory holding the .wasm files to copy")
    ap.add_argument("--out", required=True)
    ap.add_argument("--reasons", default="accepted-empty,accepted-partial,accepted-shape",
                    help="comma-separated reasons to keep ('' = every accepted module)")
    ap.add_argument("--kinds", default="", help="comma-separated kinds to keep ('' = all)")
    ap.add_argument("--exclude", default="", help="comma-separated .wasm names to drop (e.g. the "
                                                  "modules already known to wedge the analysers)")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    with open(args.results, "r", encoding="utf-8") as fh:
        results = json.load(fh)["modules"]
    with open(args.modules, "r", encoding="utf-8") as fh:
        manifest = {m["wasm"]: m for m in json.load(fh)}

    reasons = {r for r in args.reasons.split(",") if r}
    kinds = {k for k in args.kinds.split(",") if k}
    exclude = {e for e in args.exclude.split(",") if e}
    keep = []
    for m in results:
        if m["outcome"] != "accepted":
            continue
        if reasons and m["reason"] not in reasons:
            continue
        if kinds and m["kind"] not in kinds:
            continue
        if m["wasm"] in exclude or m["id"] in exclude:
            continue
        keep.append(m)
    if args.limit:
        keep = keep[:args.limit]

    out = os.path.abspath(args.out)
    import_dir = os.path.join(out, "import")
    if os.path.isdir(import_dir):
        shutil.rmtree(import_dir)
    os.makedirs(import_dir)
    out_manifest = []
    missing = []
    for m in keep:
        src = os.path.join(args.srcdir, m["wasm"])
        if not os.path.isfile(src):
            missing.append(m["wasm"])
            continue
        shutil.copyfile(src, os.path.join(import_dir, m["wasm"]))
        out_manifest.append(manifest.get(m["wasm"], {"wasm": m["wasm"], "id": m["id"],
                                                      "wast": m["wast"], "wast_line": m["wast_line"],
                                                      "kind": m["kind"], "text": ""}))
    with open(os.path.join(out, "modules.json"), "w", encoding="utf-8") as fh:
        json.dump(out_manifest, fh, indent=1)
    print("selected %d accepted module(s) into %s" % (len(out_manifest), import_dir))
    if missing:
        print("missing sources: %d" % len(missing))
    return 0


if __name__ == "__main__":
    sys.exit(main())
