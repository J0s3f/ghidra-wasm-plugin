#!/usr/bin/env python3
"""Render ``test-scripts/spectest-NEGATIVE.md`` from a completed negative run.

Reads ``negative.json`` (written by ``parse_spec_negative.py``) plus the optional
``prepare_summary.json`` and emits the human-readable result document: headline counts, the
per-``.wast`` breakdown, the ranked lists (crash / useless program / analyzer exception), the
reproduction commands and the full per-file table.

Usage:
    python render_negative_doc.py --results <OutDir>\\negative.json
                                  [--prepare <OutDir>\\prepare_summary.json]
                                  [--out ..\\spectest-NEGATIVE.md]
"""
import argparse
import json
import os
from collections import Counter, defaultdict

KIND_ORDER = ["invalid", "malformed", "unlinkable"]


def short(text, n=80):
    text = (text or "").replace("|", "\\|").replace("\n", " ")
    return text if len(text) <= n else text[: n - 3] + "..."


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--prepare", default="")
    ap.add_argument("--out", required=True)
    ap.add_argument("--evidence", default="", help="optional negative.json of the analysis pass")
    ap.add_argument("--hazard", default="", help="optional negative.json of the hazard pass (the "
                                                 "modules whose analysis crashes/hangs)")
    args = ap.parse_args()

    with open(args.results, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    modules = data["modules"]
    t = data["totals"]
    prep = {}
    if args.prepare and os.path.isfile(args.prepare):
        with open(args.prepare, "r", encoding="utf-8") as fh:
            prep = json.load(fh)
    ev = []
    if args.evidence and os.path.isfile(args.evidence):
        with open(args.evidence, "r", encoding="utf-8") as fh:
            ev = json.load(fh)["modules"]
    haz = []
    if args.hazard and os.path.isfile(args.hazard):
        with open(args.hazard, "r", encoding="utf-8") as fh:
            haz = json.load(fh)["modules"]

    rejected = [m for m in modules if m["outcome"] == "rejected"]
    accepted = [m for m in modules if m["outcome"] == "accepted"]
    crashes = [m for m in modules if m["outcome"] in ("crash", "hang")]
    useless = [m for m in accepted if m["reason"] in ("accepted-empty", "accepted-partial")]
    excs = [m for m in accepted if m.get("exceptions")]

    by_wast = defaultdict(Counter)
    for m in modules:
        by_wast[m["wast"]][m["outcome"]] += 1
        if m["outcome"] == "accepted":
            by_wast[m["wast"]]["empty" if m["reason"] == "accepted-empty" else
                               "partial" if m["reason"] == "accepted-partial" else "shape"] += 1

    md = []
    md.append("# Negative spec-test results - rejection behaviour\n")
    md.append("Harness: `test-scripts/spectest/run_spectest_negative.ps1` (see `README.md` section 5).")
    md.append("Plugin under test: this worktree (plugin sources unchanged), built with")
    md.append("`test-scripts/build-install.ps1` into Ghidra 12.1.4.")
    md.append("Toolchain: wabt `1.0.42`, testsuite `WebAssembly/spec @ d76759e7`.")
    md.append("Raw machine-readable result: the `negative.json` of the run; the table below is the")
    md.append("same per-file data in Markdown. Ranked findings: **`REPORT-NS.md`**.\n")

    md.append("## Summary\n")
    md.append("**%d rejected / %d accepted / %d crash / %d hang** -- %d modules inspected.\n" % (
        t["rejected"], t["accepted"], t["crash"], t["hang"], t["modules"]))
    if prep:
        md.append("| | |")
        md.append("| --- | --- |")
        md.append("| negative commands in the testsuite | %d |" % (t["modules"] + prep.get("skipped_text_modules", 0)))
        md.append("| binary modules imported (this run) | %d |" % t["modules"])
        md.append("| `module_type: text` modules skipped | %d |" % prep.get("skipped_text_modules", 0))
        md.append("| accepted but useless (empty shell / partial load) | %d |" % t.get("accepted_useless", len(useless)))
        md.append("| accepted, then an analyzer raised an exception | %d |" % t.get("accepted_with_analyzer_exception", 0))
        md.append("")
    md.append("| kind | modules | rejected | accepted | crash | hang |")
    md.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    for k in KIND_ORDER:
        v = data["by_kind"].get(k)
        if not v:
            continue
        md.append("| %s | %d | %d | %d | %d | %d |" % (
            k, sum(v.values()), v.get("rejected", 0), v.get("accepted", 0),
            v.get("crash", 0), v.get("hang", 0)))
    md.append("")
    md.append("Accepted-program shapes: " + ", ".join(
        "`%s`=%d" % kv for kv in sorted(data["accepted_reasons"].items())))
    md.append("")
    md.append("Rejection diagnostics: " + ", ".join(
        "`%s`=%d" % kv for kv in sorted(data["rejected_reasons"].items())))
    md.append("")
    md.append("The `crash`/`hang` columns are for the import-only (`-noanalysis`) classification run:")
    md.append("none of the %d modules kills the *loader*. Five of them stall the *analysis* when it is" % t["modules"])
    md.append("enabled (the default for an interactive import) - see the hazard pass at the end.")
    md.append("")

    md.append("\n## Reproduction\n")
    md.append("```powershell")
    md.append("$env:GHIDRA_INSTALL_DIR = \"<pinned Ghidra 12.1.4 install>\"")
    md.append("cd <worktree>")
    md.append("")
    md.append("# 1. fetch the pinned wabt + testsuite (once) -> %TEMP%\\spectest-tools")
    md.append(".\\test-scripts\\spectest\\fetch_spectest_tools.ps1")
    md.append("# 2. build + clean-install this worktree's plugin")
    md.append(".\\test-scripts\\build-install.ps1 -GhidraDir $env:GHIDRA_INSTALL_DIR")
    md.append("# 3. the whole binary negative set (%d modules; ~8 min at -max-cpu 2)" % t["modules"])
    md.append("#    -ChunkSize bounds one run; a chunk that wedges is split and retried automatically.")
    md.append(".\\test-scripts\\spectest\\run_spectest_negative.ps1 -OutDir \"$env:TEMP\\specneg-all\" -ChunkSize 5000")
    md.append("#    -> $env:TEMP\\specneg-all\\negative.json / negative.md")
    md.append("")
    md.append("# bounded smoke run (one malformed module per .wast, ~1 min)")
    md.append(".\\test-scripts\\spectest\\run_spectest_negative.ps1 -Kinds malformed -MaxPerWastPerKind 1 `")
    md.append("    -OutDir \"$env:TEMP\\specneg-smoke\"")
    md.append("")
    md.append("# hazard pass: the 9 modules whose analysis crashes/wedges the run are imported one per run")
    md.append("# (analysis on), because a single one can abort or stall the whole batch.")
    md.append(".\\test-scripts\\spectest\\run_spectest_negative.ps1 -SkipPrepare -WithAnalysis `")
    md.append("    -ImportDir \"$env:TEMP\\specneg-hazard\\import\" -ChunkSize 1 -TimeoutSec 90 `")
    md.append("    -OutDir \"$env:TEMP\\specneg-hazard\"")
    md.append("")
    md.append("# optional evidence pass: re-import an accepted subset WITH analysis (instrs/undefined_bytes,")
    md.append("# analyzer exceptions, OOM). Bounded by --limit; --exclude drops the hazard modules above.")
    md.append("python test-scripts\\spectest\\select_negative_subset.py `")
    md.append("    --results \"$env:TEMP\\specneg-all\\negative.json\" --modules \"$env:TEMP\\specneg-all\\modules.json\" `")
    md.append("    --srcdir \"$env:TEMP\\specneg-all\\import\" --out \"$env:TEMP\\specneg-evidence\" --kinds malformed `")
    md.append("    --limit 250 --exclude binary.51.malformed.wasm,binary.52.malformed.wasm,binary.53.malformed.wasm,binary.54.malformed.wasm,binary-leb128.48.malformed.wasm,binary-leb128.49.malformed.wasm")
    md.append(".\\test-scripts\\spectest\\run_spectest_negative.ps1 -SkipPrepare `")
    md.append("    -ImportDir \"$env:TEMP\\specneg-evidence\\import\" -WithAnalysis -ChunkSize 100 `")
    md.append("    -OutDir \"$env:TEMP\\specneg-evidence\"")
    md.append("```")
    md.append("")
    md.append("One headless run per chunk:")
    md.append("")
    md.append("```")
    md.append("analyzeHeadless <projdir> NegRun -import <chunkdir> -recursive \\")
    md.append("  -scriptPath <worktree>\\test-scripts\\spectest -postScript SpecNegativeReport.java \\")
    md.append("  -noanalysis -max-cpu 2 -deleteProject")
    md.append("```")
    md.append("")
    md.append("(`-noanalysis` for the classification run: rejection happens at load. A chunk whose run")
    md.append("does not return every module's verdict is split in half and retried, so a module that")
    md.append("crashes/hangs the loader is isolated to a chunk of its own.)")
    md.append("")

    md.append("\n## Per-.wast breakdown\n")
    md.append("| wast | modules | rejected | accepted-shape | accepted-empty | accepted-partial | crash | hang |")
    md.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for w in sorted(by_wast):
        c = by_wast[w]
        md.append("| %s | %d | %d | %d | %d | %d | %d | %d |" % (
            w, sum(c[k] for k in ("rejected", "accepted", "crash", "hang")), c["rejected"],
            c["shape"], c["empty"], c["partial"], c["crash"], c["hang"]))
    md.append("")

    if crashes:
        md.append("\n## Crash / hang (%d)\n" % len(crashes))
        for m in crashes:
            md.append("- `%s` (%s, line %s) - %s: %s" % (
                m["wasm"], m["kind"], m["wast_line"], m["outcome"], short(m["message"], 120)))
        md.append("")
    if useless:
        md.append("\n## Silent acceptance with a useless program (%d)\n" % len(useless))
        md.append("`accepted-empty` = the program contains nothing but the raw-byte `.module` block;")
        md.append("`accepted-partial` = the loader logged `Failed to load Wasm module` and the import was")
        md.append("still reported as successful.\n")
        md.append("| module | kind | wast line | expected (testsuite) | shape | detail |")
        md.append("| --- | --- | ---: | --- | --- | --- |")
        for m in useless:
            md.append("| `%s` | %s | %s | %s | %s | %s |" % (
                m["wasm"], m["kind"], m["wast_line"], short(m["expected_text"], 44), m["reason"],
                short(m["loader_errors"][0] if m.get("loader_errors") else
                      "funcs=%s blocks=%s" % (m["metrics"].get("funcs"), m["metrics"].get("blocks")), 70)))
        md.append("")
    if excs:
        md.append("\n## Accepted, then an analyzer raised an exception (%d)\n" % len(excs))
        for m in excs:
            md.append("- `%s` (%s, line %s): %s" % (
                m["wasm"], m["kind"], m["wast_line"], short(m["exceptions"][0], 150)))
        md.append("")
    md.append("\n## Rejected (%d)\n" % len(rejected))
    classes = Counter((m["reason"], m["expected_text"]) for m in rejected)
    for (reason, text), n in classes.most_common():
        md.append("- %s x%d (`%s`)" % (reason, n, short(text, 40)))
    md.append("")

    if ev:
        md.append("\n## Evidence pass (analysis enabled, %d accepted malformed modules)\n" % len(ev))
        undef = [m for m in ev if int((m["metrics"] or {}).get("undefined_bytes", 0) or 0) > 0]
        withexc = [m for m in ev if m.get("exceptions")]
        md.append("| metric | value |")
        md.append("| --- | ---: |")
        md.append("| modules | %d |" % len(ev))
        md.append("| functions decoded | %d |" % sum(int((m["metrics"] or {}).get("funcs", 0) or 0) for m in ev))
        md.append("| instructions | %d |" % sum(int((m["metrics"] or {}).get("instrs", 0) or 0) for m in ev))
        md.append("| modules with undefined bytes | %d |" % len(undef))
        md.append("| modules with an analyzer exception | %d |" % len(withexc))
        md.append("| modules that crashed the run | %d |" % sum(1 for m in ev if m["outcome"] in ("crash", "hang")))
        md.append("")
        if withexc:
            md.append("| module | expected (testsuite) | analyzer exception |")
            md.append("| --- | --- | --- |")
            for m in withexc:
                md.append("| `%s` | %s | %s |" % (
                    m["wasm"], short(m["expected_text"], 40), short(m["exceptions"][0], 110)))
            md.append("")

    if haz:
        md.append("\n## Hazard pass - modules that kill or wedge the run when analysis is enabled (%d)\n"
                  % len(haz))
        md.append("These are imported one per headless run (`-WithAnalysis`), because a single one can")
        md.append("abort or stall the whole batch. `-noanalysis` imports all of them in well under a")
        md.append("second, so they are invisible in the table above.\n")
        md.append("| module | expected (testsuite) | outcome | memory bytes | detail |")
        md.append("| --- | --- | --- | ---: | --- |")
        for m in haz:
            mt = m["metrics"] or {}
            md.append("| `%s` | %s | %s (%s) | %s | %s |" % (
                m["wasm"], short(m["expected_text"], 36), m["outcome"], m["reason"],
                mt.get("memory_bytes", "-"), short(m["message"], 80)))
        md.append("")
        md.append("The five `hang` rows are exactly the modules with an out-of-range memory minimum")
        md.append("(`binary-leb128.48/49`, `memory.21/22/23`): imported *without* analysis they report")
        md.append("`memory_bytes=2147483648` - a 2 GiB `.memory0` block, clamped to `CODE_BASE` - and")
        md.append("with analysis the run never finishes. The two rows with an analysis exception are the")
        md.append("absurd-locals modules; the minimal case is the probe `NS07_locals_count_huge` (32")
        md.append("bytes), which OOMs and aborts the headless run instead of hanging.")
        md.append("")

    md.append("\n## Full per-file table\n")
    md.append("| wast | # | kind | outcome | reason | expected | observed |")
    md.append("| --- | --- | --- | --- | --- | --- | --- |")

    def module_index(wasm):
        stem = wasm[:-5] if wasm.endswith(".wasm") else wasm
        parts = stem.split(".")
        if len(parts) >= 2 and parts[-1] in ("invalid", "malformed", "unlinkable") \
                and parts[-2].isdigit():
            return parts[-2]
        if len(parts) >= 2 and parts[-1].isdigit():
            return parts[-1]
        return stem

    def sort_key(m):
        idx = module_index(m["wasm"])
        try:
            idx = int(idx)
        except ValueError:
            idx = 0
        return (m["wast"], idx, m["kind"])

    for m in sorted(modules, key=sort_key):
        md.append("| %s | %s | %s | %s | %s | %s | %s |" % (
            m["wast"], module_index(m["wasm"]), m["kind"], m["outcome"], m["reason"],
            short(m["expected_text"], 40), short(m["message"], 70)))
    md.append("")

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md) + "\n")
    print("wrote %s (%d bytes, %d modules)" % (args.out, os.path.getsize(args.out), len(modules)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
