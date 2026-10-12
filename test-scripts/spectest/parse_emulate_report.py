#!/usr/bin/env python3
"""Aggregate the per-command RESULT lines written by ghidra_scripts/spectest.py.

Each `<dir>/<wast>.txt` is the `--report` file of one emulation run and contains lines

    RESULT <command-type> <ok|fail|skip> <detail>

This script turns them into `<outdir>/emulate-summary.md` / `.json`: per-suite counts and the
concrete failing commands (bug leads). Stdlib only (Python 3.10+).
"""
import json
import os
import sys


def parse(path):
    counts = {}
    fails = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("RESULT "):
                continue
            parts = line.split(" ", 3)
            if len(parts) != 4:
                continue
            _, ctype, status, detail = parts
            counts[(ctype, status)] = counts.get((ctype, status), 0) + 1
            if status == "fail":
                fails.append("%s %s" % (ctype, detail))
    return counts, fails


def main():
    if len(sys.argv) < 3:
        print("usage: parse_emulate_report.py <report-dir> <out-dir>", file=sys.stderr)
        return 2
    rep_dir, out_dir = sys.argv[1], sys.argv[2]

    suites = {}
    types = set()
    statuses = set()
    for name in sorted(os.listdir(rep_dir)):
        if not name.endswith(".txt"):
            continue
        wast = name[:-4]
        counts, fails = parse(os.path.join(rep_dir, name))
        if not counts:
            continue
        suites[wast] = {"counts": {"%s/%s" % k: v for k, v in counts.items()}, "fails": fails}
        for ctype, status in counts:
            types.add(ctype)
            statuses.add(status)

    types = sorted(types)
    statuses = sorted(statuses)
    order = [t for t in ("module", "action", "assert_return", "assert_trap", "assert_exhaustion",
                         "assert_invalid", "assert_malformed", "assert_uninstantiable",
                         "assert_unlinkable", "register") if t in types] + \
            [t for t in types if t not in ("module", "action", "assert_return", "assert_trap",
                                           "assert_exhaustion", "assert_invalid", "assert_malformed",
                                           "assert_uninstantiable", "assert_unlinkable", "register")]

    lines = ["# Spec emulation result table", "",
             "Per-suite counts of the commands `ghidra_scripts/spectest.py` reports (see",
             "`run_emulate.ps1` for the exact invocation). `skip` = by-design (the runner does not",
             "execute `assert_invalid` / `assert_malformed` / `assert_uninstantiable` /",
             "`assert_unlinkable` / `assert_exhaustion`).", ""]
    header = "| suite | " + " | ".join(
        "%s ok/fail/skip" % t for t in order) + " |"
    lines.append(header)
    lines.append("| --- " * (len(order) + 1) + "|")

    totals = {}
    for wast, data in suites.items():
        cells = []
        for t in order:
            ok = data["counts"].get(t + "/ok", 0)
            fail = data["counts"].get(t + "/fail", 0)
            skip = data["counts"].get(t + "/skip", 0)
            totals[(t, "ok")] = totals.get((t, "ok"), 0) + ok
            totals[(t, "fail")] = totals.get((t, "fail"), 0) + fail
            totals[(t, "skip")] = totals.get((t, "skip"), 0) + skip
            if ok or fail or skip:
                cells.append("%d/%d/%d" % (ok, fail, skip))
            else:
                cells.append("-")
        lines.append("| %s | %s |" % (wast, " | ".join(cells)))

    cells = []
    for t in order:
        cells.append("%d/%d/%d" % (totals.get((t, "ok"), 0), totals.get((t, "fail"), 0),
                                   totals.get((t, "skip"), 0)))
    lines.append("| **total** | " + " | ".join(cells) + " |")

    lines += ["", "## Failing commands (bug leads)", ""]
    any_fail = False
    for wast, data in suites.items():
        for fail in data["fails"]:
            lines.append("* `%s`: %s" % (wast, fail))
            any_fail = True
    if not any_fail:
        lines.append("(none)")

    with open(os.path.join(out_dir, "emulate-summary.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    with open(os.path.join(out_dir, "emulate-summary.json"), "w", encoding="utf-8") as fh:
        json.dump({"suites": suites,
                   "totals": {"%s/%s" % k: v for k, v in sorted(totals.items())}},
                  fh, indent=2, sort_keys=True)

    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
