#!/usr/bin/env python3
"""Classify the negative spec-test import logs into rejected / accepted / crash / hang.

Reads the chunk records + headless logs produced by ``run_spectest_negative.ps1`` together with the
``modules.json`` manifest from ``prepare_spec_negative.py`` and writes ``negative.json`` (machine
readable) and ``negative.md`` (the per-file table + summary) next to them.

Outcome rules (per module, over all chunk logs):

* ``accepted`` - SpecNegativeReport.java emitted a ``SPECNEG`` line for it: the loader built a
  program from a module that a correct implementation must reject. A *silent acceptance*.
* ``rejected`` - one of the headless rejection diagnostics names the file:
  ``The ProgramLoader could not successfully load`` (no loader matched: bad magic / version / too
  short), ``No memory blocks were defined for file`` (the WasmLoader threw before creating the
  module block) or ``Import failed for file:`` (generic).
* ``hang`` / ``crash`` - the module was retried on its own and the headless run still timed out
  (hang) or died (crash); supplied by the runner in ``unresolved.json``.

Usage:
    python parse_spec_negative.py --chunks <chunks.json> --modules <modules.json>
                                  [--unresolved <unresolved.json>] --out <workdir>
                                  [--merge <previous negative.json>]
"""
import argparse
import json
import os
import re
import sys
from collections import Counter, OrderedDict, defaultdict

IMPORTING = re.compile(r"IMPORTING: file:///\S*?/([^/?]+\.(?:wasm|wat))")
SPECNEG = re.compile(r"SPECNEG name=(\S+) (.*)")
KV = re.compile(r"(\w+)=(\S*)")
OOM = re.compile(r"OutOfMemoryError")

NO_LOADER = re.compile(r"The ProgramLoader could not successfully load\s+(\S+)")
IMPORT_FAILED = re.compile(r"Import failed for file:\s*(\S+)")
NO_BLOCKS = re.compile(r"No memory blocks were defined for file\s+(\S+)")
LOADER_EXC = re.compile(r"Failed to load Wasm module(?:\s*\(WasmLoader\))?\s*(.*)")

EXC_PATTERNS = [
    ("ValidationException", re.compile(r"ValidationException")),
    ("IllegalArgumentException", re.compile(r"IllegalArgumentException")),
    ("IllegalStateException", re.compile(r"IllegalStateException")),
    ("NullPointerException", re.compile(r"NullPointerException")),
    ("IndexOutOfBounds", re.compile(r"IndexOutOfBoundsException|ArrayIndexOutOfBounds")),
    ("StackOverflowError", re.compile(r"StackOverflowError")),
    ("OutOfMemoryError", re.compile(r"OutOfMemoryError")),
    ("EOFException", re.compile(r"EOFException")),
    ("IOException", re.compile(r"java\.io\.IOException")),
]


def basename(ref):
    """Strip the ?MD5= query and any directory prefix from a file: URL or path."""
    ref = ref.split("?")[0]
    ref = ref.rstrip(")")
    return ref.replace("\\", "/").rsplit("/", 1)[-1]


def parse_kv(text):
    return {k: v for k, v in KV.findall(text)}


def classify_chunk(rec, results):
    """Fold one chunk log into `results` (name -> dict)."""
    log = rec.get("log")
    if not log or not os.path.isfile(log):
        for n in rec.get("modules", []):
            results.setdefault(n, {"log_missing": True})
        return
    with open(log, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    lines = text.splitlines()

    current = None
    attributed_exc = defaultdict(list)
    attributed_loader = defaultdict(list)
    for line in lines:
        m = IMPORTING.search(line)
        if m:
            current = m.group(1)
            continue
        m = SPECNEG.search(line)
        if m:
            name = m.group(1)
            fields = parse_kv(m.group(2))
            fields = {k: (int(v) if re.fullmatch(r"-?\d+", v) else v) for k, v in fields.items()}
            r = results.setdefault(name, {})
            r["accepted"] = True
            r["metrics"] = fields
            # The same module can appear in several chunk logs (a chunk that was retried); the
            # metrics are deterministic, so the last write wins.
            continue
        m = NO_LOADER.search(line)
        if m:
            name = basename(m.group(1))
            results.setdefault(name, {})["rejection"] = "no-loader"
            results[name].setdefault("messages", []).append(line.strip()[:300])
            continue
        m = NO_BLOCKS.search(line)
        if m:
            name = basename(m.group(1))
            results.setdefault(name, {})["rejection"] = "loader-exception"
            results[name].setdefault("messages", []).append(line.strip()[:300])
            continue
        m = IMPORT_FAILED.search(line)
        if m:
            name = basename(m.group(1))
            r = results.setdefault(name, {})
            r.setdefault("rejection", "import-failed")
            r.setdefault("messages", []).append(line.strip()[:300])
            continue
        m = LOADER_EXC.search(line)
        if m:
            attributed_loader[current].append(m.group(1).strip()[:200])
            continue
        for label, pat in EXC_PATTERNS:
            if pat.search(line):
                attributed_exc[current].append(label + ": " + line.strip()[:200])
                break

    for name, errs in attributed_loader.items():
        if name is None:
            continue
        r = results.setdefault(name, {})
        r.setdefault("loader_errors", []).extend(errs)
    for name, excs in attributed_exc.items():
        if name is None:
            continue
        r = results.setdefault(name, {})
        r.setdefault("exceptions", []).extend(excs)
    return


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chunks", required=True)
    ap.add_argument("--modules", required=True)
    ap.add_argument("--unresolved", default="")
    ap.add_argument("--out", required=True)
    ap.add_argument("--merge", default="", help="previous negative.json to merge into this run")
    args = ap.parse_args()

    with open(args.modules, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    with open(args.chunks, "r", encoding="utf-8") as fh:
        chunks = json.load(fh)
    if isinstance(chunks, dict):
        chunks = [chunks]
    unresolved = {}
    if args.unresolved and os.path.isfile(args.unresolved):
        with open(args.unresolved, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            unresolved = data

    merged = {}
    if args.merge and os.path.isfile(args.merge):
        with open(args.merge, "r", encoding="utf-8") as fh:
            prev = json.load(fh)
        merged = {m["wasm"]: m for m in prev.get("modules", [])}

    results = {}
    for rec in chunks:
        classify_chunk(rec, results)

    in_run = set()
    oom_runs = set()
    module_runs = defaultdict(list)
    for rec in chunks:
        run = rec.get("run")
        log = rec.get("log")
        if log and os.path.isfile(log):
            try:
                with open(log, "r", encoding="utf-8", errors="replace") as fh:
                    if OOM.search(fh.read()):
                        oom_runs.add(run)
            except OSError:
                pass
        for n in rec.get("modules", []):
            in_run.add(n)
            module_runs[n].append(run)

    modules = []
    for m in manifest:
        wasm = m["wasm"]
        r = results.get(wasm, {})
        accepted = bool(r.get("accepted"))
        rejection = r.get("rejection")
        if accepted:
            outcome = "accepted"
        elif rejection:
            outcome = "rejected"
        elif wasm in unresolved and unresolved[wasm] in ("hang", "crash"):
            outcome = unresolved[wasm]
        elif wasm not in in_run:
            if wasm in merged and merged[wasm].get("outcome") in ("rejected", "accepted",
                                                                 "crash", "hang"):
                modules.append(merged[wasm])
                continue
            outcome = "not_in_run"
        else:
            outcome = "crash"
        oom = any(r in oom_runs for r in module_runs.get(wasm, []))

        metrics = r.get("metrics", {}) or {}
        reason = rejection or ("accepted" if accepted else outcome)
        if accepted:
            if r.get("loader_errors"):
                reason = "accepted-partial"
            elif int(metrics.get("funcs", 0) or 0) == 0 and int(metrics.get("blocks", 0) or 0) <= 1:
                reason = "accepted-empty"
            else:
                reason = "accepted-shape"
        if outcome in ("hang", "crash"):
            reason = "headless-%s" % outcome

        msg = ""
        if outcome in ("hang", "crash"):
            if oom:
                msg = "OutOfMemoryError during analysis (headless aborts the run)"
            elif outcome == "hang":
                msg = "headless run timed out (analysis did not finish)"
            else:
                msg = "headless run exited without a verdict for this module"
        elif r.get("messages"):
            msg = r["messages"][0]
        elif r.get("loader_errors"):
            msg = "loader: " + r["loader_errors"][0]
        elif r.get("exceptions"):
            msg = r["exceptions"][0]
        elif accepted:
            msg = "funcs=%s blocks=%s module=%s" % (metrics.get("funcs", "?"),
                                                    metrics.get("blocks", "?"),
                                                    metrics.get("module_block", "?"))
        modules.append({
            "id": m["id"],
            "wasm": wasm,
            "wast": m["wast"],
            "wast_line": m.get("wast_line"),
            "kind": m["kind"],
            "module_type": m.get("module_type", "binary"),
            "expected_text": m.get("text", ""),
            "outcome": outcome,
            "reason": reason,
            "message": msg,
            "loader_errors": r.get("loader_errors", []),
            "exceptions": r.get("exceptions", []),
            "metrics": metrics,
        })

    # drop "not_in_run" duplicates from the merge to avoid double counting the same file
    seen = OrderedDict()
    for m in modules:
        seen[m["wasm"]] = m
    modules = list(seen.values())

    counts = Counter(m["outcome"] for m in modules)
    by_kind = defaultdict(Counter)
    for m in modules:
        by_kind[m["kind"]][m["outcome"]] += 1
    reasons = Counter(m["reason"] for m in modules if m["outcome"] == "accepted")
    rej_reasons = Counter(m["reason"] for m in modules if m["outcome"] == "rejected")
    crash_like = [m for m in modules if m["outcome"] in ("crash", "hang")]
    accepted_bad = [m for m in modules if m["outcome"] == "accepted"
                    and m["reason"] in ("accepted-empty", "accepted-partial")]
    accepted_exc = [m for m in modules if m["outcome"] == "accepted" and m.get("exceptions")]

    out = {
        "totals": {
            "modules": len(modules),
            "rejected": counts.get("rejected", 0),
            "accepted": counts.get("accepted", 0),
            "crash": counts.get("crash", 0),
            "hang": counts.get("hang", 0),
            "not_in_run": counts.get("not_in_run", 0),
            "accepted_useless": len(accepted_bad),
            "accepted_with_analyzer_exception": len(accepted_exc),
        },
        "by_kind": {k: dict(v) for k, v in by_kind.items()},
        "accepted_reasons": dict(reasons),
        "rejected_reasons": dict(rej_reasons),
        "unresolved": unresolved,
        "modules": modules,
    }
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "negative.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)

    exc_kinds = Counter()
    for m in accepted_exc:
        for e in m["exceptions"]:
            exc_kinds[e.split(":")[0]] += 1

    md = []
    t = out["totals"]
    md.append("# Negative spec-test results (rejection behaviour)\n")
    md.append("**Summary: %d rejected / %d accepted / %d crash / %d hang** "
              "(of %d modules inspected)\n" % (
                  t["rejected"], t["accepted"], t["crash"], t["hang"], t["modules"]))
    md.append("- accepted but useless (empty shell or partial load): **%d**" % len(accepted_bad))
    md.append("- accepted and then raised an analyzer exception: **%d**" % len(accepted_exc))
    md.append("")
    md.append("| kind | modules | rejected | accepted | crash | hang |")
    md.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    for k in ("invalid", "malformed", "unlinkable"):
        if k not in by_kind:
            continue
        v = by_kind[k]
        n = sum(v.values())
        md.append("| %s | %d | %d | %d | %d | %d |" % (
            k, n, v.get("rejected", 0), v.get("accepted", 0), v.get("crash", 0), v.get("hang", 0)))
    md.append("")
    md.append("Accepted-program shapes: " + (", ".join(
        "%s=%d" % (k, v) for k, v in sorted(reasons.items())) or "(none)"))
    md.append("")
    md.append("Rejection diagnostics: " + (", ".join(
        "%s=%d" % (k, v) for k, v in sorted(rej_reasons.items())) or "(none)"))
    if exc_kinds:
        md.append("")
        md.append("Analyzer exceptions raised after acceptance: " + ", ".join(
            "%s=%d" % (k, v) for k, v in exc_kinds.most_common()))
    md.append("")

    if crash_like:
        md.append("\n## Crash / hang (%d)\n" % len(crash_like))
        for m in crash_like:
            md.append("- **%s** (%s.%s, line %s) -> %s" % (
                m["wasm"], m["wast"], m["kind"], m["wast_line"], m["outcome"]))
    if accepted_bad:
        md.append("\n## Silent acceptances with a useless program (%d)\n" % len(accepted_bad))
        for m in accepted_bad[:120]:
            mt = m.get("metrics", {})
            extra = (" loader=" + m["loader_errors"][0]) if m.get("loader_errors") else ""
            md.append("- `%s` (%s, line %s) %s: funcs=%s blocks=%s module_size=%s%s" % (
                m["wasm"], m["kind"], m["wast_line"], m["reason"],
                mt.get("funcs", "?"), mt.get("blocks", "?"), mt.get("module_size", "?"), extra))
    if accepted_exc:
        md.append("\n## Accepted, then analyzer exception (%d)\n" % len(accepted_exc))
        for m in accepted_exc[:60]:
            md.append("- `%s` (%s, line %s) expected \"%s\" -> %s" % (
                m["wasm"], m["kind"], m["wast_line"], m["expected_text"][:50],
                m["exceptions"][0][:160]))

    md.append("\n## Per-file table\n")
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
        idx = module_index(m["wasm"])
        msg = m["message"].replace("|", "\\|")[:150]
        exp = (m.get("expected_text") or "").replace("|", "\\|")[:50]
        md.append("| %s | %s | %s | %s | %s | %s | %s |" % (
            m["wast"], idx, m["kind"], m["outcome"], m["reason"], exp, msg))
    md.append("")

    with open(os.path.join(args.out, "negative.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(md) + "\n")

    print("Summary: %d rejected / %d accepted / %d crash / %d hang (of %d inspected)" % (
        t["rejected"], t["accepted"], t["crash"], t["hang"], t["modules"]))
    print("  accepted but useless: %d, accepted+analyzer exception: %d" % (
        len(accepted_bad), len(accepted_exc)))
    for k in sorted(by_kind):
        v = by_kind[k]
        print("  %-11s modules=%d rejected=%d accepted=%d crash=%d hang=%d" % (
            k, sum(v.values()), v.get("rejected", 0), v.get("accepted", 0),
            v.get("crash", 0), v.get("hang", 0)))
    if reasons:
        print("  accepted shapes: " + ", ".join("%s=%d" % kv for kv in sorted(reasons.items())))
    print("wrote %s and %s" % (os.path.join(args.out, "negative.json"),
                               os.path.join(args.out, "negative.md")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
