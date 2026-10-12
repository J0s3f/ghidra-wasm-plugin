#!/usr/bin/env python3
"""Type-recovery quality metric (proxy) for decompiled WebAssembly functions.

Counts the *struct-access signal* in decompiled C: constant-offset field accesses of the
form `*(type *)(base + 0xNN)` / `*(type *)(base - 0xNN)`, grouped by base. That is the
signal a type-recovery pass (Retypd-style, or an SROA-like struct synthesis) would have to
type: bases with several distinct constant offsets are the candidate structures.

Input: the log of `test-scripts/DumpAll.java` (all functions of one program).
Optional: the log of `test-scripts/DumpStackVars.java` (post-SROA atom statistics).

Usage:
    python3 test-scripts/type_recovery_metric.py --decomp <dumpall.log> [--stackvars <stackvars.log>] [--json out.json]

Output (stdout): a compact report with
  * functions analysed / decompile failures,
  * total constant-offset field accesses and their bases,
  * candidate structures: bases with >= 2 (and >= 3) distinct offsets,
  * base classification: parameter (param_*/in_*), local (local_*/uVar*/iVar*/lVar*/sVar*),
    global (DAT_*/ram_*/_DAT*), other,
  * pointer-typed parameter count from the prototypes,
  * stack-atom totals from DumpStackVars when given.
This is a *proxy*: it does not use DWARF ground truth (that needs a DWARF parser for the
wasm custom sections). It is enough to decide whether a Retypd-style pass has work to do.
"""
import argparse
import collections
import json
import re
import sys

FUNC_RE = re.compile(r"^---- (?P<name>\S+) (?:prototype: (?P<proto>.*)|DECOMPILE FAILED:.*)$")
HARNESS_PREFIX_RE = re.compile(r"^\S+\s+\S+\.java>\s*")
HARNESS_SUFFIX_RE = re.compile(r"\s*\(GhidraScript\)\s*$")
# *(type *)(base + 0xNN) / *(type *)(base - 0xNN) / (type *)(base + 0xNN) in casts
FIELD_RE = re.compile(
    r"\*\(\s*[A-Za-z_][\w \t\*]*\)\s*\(\s*(?P<base>[A-Za-z_][\w\.\[\]]*)\s*(?P<sign>[+\-])\s*0x(?P<off>[0-9a-fA-F]+)\s*\)"
)
PTR_PARAM_RE = re.compile(r"\*\s*(?:param\d+|in_\d+|in_stack_\d+)")
STACKVAR_RE = re.compile(
    r"aggregate=\[[^\]]*\)\s*accesses=(?P<acc>\d+)\s*atoms=(?P<atoms>\d+)\s*splits=(?P<splits>\d+)\s*merges=(?P<merges>\d+)"
)


def classify_base(base: str) -> str:
    if re.match(r"^(param\d+|in_\d+|in_stack_\d+)", base):
        return "parameter"
    if base.startswith(("local_", "uVar", "iVar", "lVar", "sVar", "cVar", "bVar", "fVar", "dVar",
                        "uStack", "abStack", "Stack")):
        return "local"
    if base.startswith(("DAT_", "ram_", "_DAT", "PTR_", "UNK_", "uRam", "iRam", "RAM")):
        return "global"
    if base.startswith(("extraout_", "unaff_", "register0x", "register")):
        return "register/other"
    return "other"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--decomp", required=True, help="DumpAll.java log")
    ap.add_argument("--stackvars", default=None, help="DumpStackVars.java log (optional)")
    ap.add_argument("--json", default=None, help="write the metrics as JSON to this path")
    args = ap.parse_args()

    funcs = 0
    failures = 0
    ptr_params = 0
    accesses = 0
    base_offsets = collections.defaultdict(set)
    base_counts = collections.Counter()
    base_kind_counts = collections.Counter()
    per_func = []
    current = None
    body_lines = 0

    def flush():
        nonlocal body_lines
        if current is None:
            return
        body_lines = 0

    with open(args.decomp, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = HARNESS_SUFFIX_RE.sub("", HARNESS_PREFIX_RE.sub("", raw.rstrip("\n")))
            m = FUNC_RE.match(line)
            if m:
                flush()
                funcs += 1
                current = m.group("name")
                proto = m.group("proto") or ""
                if not proto:
                    failures += 1
                else:
                    # pointer-typed parameters in the prototype
                    ptr_params += len(PTR_PARAM_RE.findall(proto))
                continue
            if current is None:
                continue
            body_lines += 1
            for fm in FIELD_RE.finditer(line):
                accesses += 1
                base = fm.group("base")
                off = int(fm.group("off"), 16)
                if fm.group("sign") == "-":
                    off = -off
                base_offsets[base].add(off)
                base_counts[base] += 1
                base_kind_counts[classify_base(base)] += 1
        flush()

    multi2 = [b for b, o in base_offsets.items() if len(o) >= 2]
    multi3 = [b for b, o in base_offsets.items() if len(o) >= 3]
    top = sorted(base_offsets.items(), key=lambda kv: (-len(kv[1]), -base_counts[kv[0]]))[:10]

    stack = {}
    if args.stackvars:
        acc = atoms = splits = merges = 0
        with open(args.stackvars, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = STACKVAR_RE.search(line)
                if m:
                    acc += int(m.group("acc"))
                    atoms += int(m.group("atoms"))
                    splits += int(m.group("splits"))
                    merges += int(m.group("merges"))
        stack = {"accesses": acc, "atoms": atoms, "splits": splits, "merges": merges}

    report = {
        "functions": funcs,
        "decompile_failures": failures,
        "pointer_typed_params": ptr_params,
        "constant_offset_field_accesses": accesses,
        "distinct_bases": len(base_offsets),
        "candidate_structures_ge2_offsets": len(multi2),
        "candidate_structures_ge3_offsets": len(multi3),
        "accesses_by_base_kind": dict(base_kind_counts),
        "top_bases": [
            {"base": b, "kind": classify_base(b), "distinct_offsets": len(o), "accesses": base_counts[b]}
            for b, o in top
        ],
        "stack_atoms": stack,
    }

    print("type-recovery metric (proxy)")
    print(f"  functions analysed        : {funcs} ({failures} decompile failures)")
    print(f"  pointer-typed parameters  : {ptr_params}")
    print(f"  constant-offset accesses  : {accesses} over {len(base_offsets)} distinct bases")
    print(f"  candidate structures      : {len(multi2)} with >=2 offsets, {len(multi3)} with >=3 offsets")
    print("  accesses by base kind     : " + ", ".join(f"{k}={v}" for k, v in base_kind_counts.most_common()))
    if stack:
        print(f"  stack atoms (post-SROA)   : {stack['accesses']} accesses -> {stack['atoms']} atoms "
              f"(splits={stack['splits']}, merges={stack['merges']})")
    print("  top bases:")
    for b, o in top:
        print(f"    {b:<24} {classify_base(b):<10} offsets={len(o):<3} accesses={base_counts[b]}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
        print(f"  json: {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
