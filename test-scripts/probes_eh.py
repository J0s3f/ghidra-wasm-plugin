#!/usr/bin/env python3
"""Probes owned by the *new exception handling* workstream (workstream F) - roadmap item 5.

Covers the exception-handling proposal as emitted by LLVM >= 19: `try_table` (0x1f), `throw_ref`
(0x0a) and the `exnref` value type (0x69). The legacy encoding (probe `10`) is exercised here too,
but its baseline result lives in `gen_feature_probes.py` (frozen).

Only valid modules belong here: each one must import, disassemble with `undefined_bytes == 0`, and
decompile. `catch` clauses branch to a label of the *enclosing* block, so the expected stack of the
label (its result type, or its params for a loop) has to match the clause's caught values:
`catch` -> tag params, `catch_ref` -> tag params + exnref, `catch_all` -> [], `catch_all_ref` -> [exnref].

Expected results are recorded in REPORT-F.md.

Usage: python probes_eh.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])

# ---------------------------------------------------------------- new-EH helpers (local to this file)

def throw_(tag):
    """throw tag"""
    return b"\x08" + uleb(tag)


def throw_ref():
    """throw_ref (0x0a): pops an exnref."""
    return b"\x0A"


def ref_null_exn():
    """ref.null exn (heaptype exn = 0x69)."""
    return b"\xD0" + _ht_exn_bytes()


def _ht_exn_bytes():
    # s33 encoding of the abstract heap type `exn` is byte-identical to the 0x69 shorthand.
    return sleb(HT_EXN - 0x80)


def catch_clause(tag, label):
    """0x00 catch tagidx labelidx"""
    return b"\x00" + uleb(tag) + uleb(label)


def catch_ref_clause(tag, label):
    """0x01 catch_ref tagidx labelidx"""
    return b"\x01" + uleb(tag) + uleb(label)


def catch_all_clause(label):
    """0x02 catch_all labelidx"""
    return b"\x02" + uleb(label)


def catch_all_ref_clause(label):
    """0x03 catch_all_ref labelidx"""
    return b"\x03" + uleb(label)


def try_table(blocktype=0x40, clauses=(), body=b""):
    """try_table blocktype catch* instruction* end.

    blocktype is 0x40 (empty), a valtype byte (0x69 = exnref included) or a type index.
    """
    if blocktype in (0x40, I32, I64, F32, F64, V128, FUNCREF, EXTERNREF, HT_EXN):
        bt = bytes([blocktype])
    else:
        bt = sleb(blocktype)
    return b"\x1F" + bt + vec(list(clauses)) + body + END


def code_with_locals(bodies):
    """Like code_section, but each entry is the full function body (locals + code), i.e.
    built with `body(code, locals_)`."""
    return section(10, vec(list(bodies)))


# ---------------------------------------------------------------- (a) try_table, empty clause vector

# 30. Mirrors the frozen baseline probe 11: a try_table with no catch clauses behaves like `block`.
write("30_eh2_try_table_empty.wasm", module(
    type_section(functype([], [])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([try_table(0x40, []) + END]),
))


# ---------------------------------------------------------------- (b) one probe per clause kind

# 31. catch: the caught value is the tag's i32 payload; the label (the enclosing block) has result i32.
write("31_eh2_try_table_catch.wasm", module(
    type_section(functype([I32], []), functype([], [I32])),  # 0 = tag (i32)->(), 1 = f ()->i32
    tag_section([(0x00, 0)]),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([b"\x02\x7F"             # block (result i32) -- catch label 0
                  + try_table(0x40, [catch_clause(0, 0)], i32_const(7) + throw_(0))
                  + i32_const(-1)         # normal path
                  + END                   # end block
                  + END]),                # end function
))

# 32. catch_ref: label expects the payload plus an exnref. throw_ref inside the body (exnref param).
write("32_eh2_try_table_catch_ref.wasm", module(
    type_section(functype([I32], []),            # 0 = tag (i32)->()
                 functype([HT_EXN], []),         # 1 = f (exnref)->()
                 functype([], [I32, HT_EXN])),   # 2 = block ()->(i32 exnref)
    tag_section([(0x00, 0)]),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([b"\x02\x02"             # block (type 2) -- catch_ref label 0
                  + try_table(0x40, [catch_ref_clause(0, 0)], local_get(0) + throw_ref())
                  + i32_const(-1)
                  + ref_null_exn()
                  + END                   # end block
                  + drop() + drop()       # drop exnref, drop i32
                  + END]),                # end function
))

# 33. catch_all: pushes nothing; the enclosing block has result [].
write("33_eh2_try_table_catch_all.wasm", module(
    type_section(functype([I32], []), functype([], [])),  # 0 = tag (i32)->(), 1 = f ()->()
    tag_section([(0x00, 0)]),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([b"\x02\x40"             # block (empty) -- catch_all label 0
                  + try_table(0x40, [catch_all_clause(0)], i32_const(5) + throw_(0))
                  + END                   # end block
                  + END]),                # end function
))

# 34. catch_all_ref: pushes an exnref; the enclosing block has result (exnref).
write("34_eh2_try_table_catch_all_ref.wasm", module(
    type_section(functype([I32], []),        # 0 = tag (i32)->()
                 functype([], []),           # 1 = f ()->()
                 functype([], [HT_EXN])),    # 2 = block ()->(exnref)
    tag_section([(0x00, 0)]),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([b"\x02\x02"             # block (type 2) -- catch_all_ref label 0
                  + try_table(0x40, [catch_all_ref_clause(0)], i32_const(5) + throw_(0))
                  + ref_null_exn()        # normal path
                  + END                   # end block
                  + drop()
                  + END]),                # end function
))


# ---------------------------------------------------------------- (c) throw_ref

# 35. throw_ref with an exnref parameter and a second, defined exnref local.
write("35_eh2_throw_ref_param.wasm", module(
    type_section(functype([HT_EXN], [])),  # 0 = f (exnref)->()
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_with_locals([body(local_get(0) + local_set(1) + local_get(1) + throw_ref() + END,
                           [(1, HT_EXN)])]),
))


# ---------------------------------------------------------------- (d) nested try_table, branches out of both

# 36. Two nested try_tables inside a block; one br leaves both, one br leaves the outer one.
write("36_eh2_nested_try_table.wasm", module(
    type_section(functype([I32], []), functype([], [I32])),  # 0 = tag (i32)->(), 1 = f ()->i32
    tag_section([(0x00, 0)]),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([b"\x02\x7F"                       # block (result i32) -- L0, catch label
                  + try_table(0x40, [catch_clause(0, 0)],       # TT1: label 0 = L0
                              try_table(0x40, [catch_clause(0, 1)],  # TT2: label 1 = L0
                                        i32_const(1) + br(2))    # leave TT2 and TT1 -> L0
                              + i32_const(2) + br(1))            # leave TT1 -> L0
                  + i32_const(3)                 # normal path
                  + END                          # end block
                  + END]),                # end function
))


# ---------------------------------------------------------------- (e) legacy try/catch and try_table side by side

# 37. Function 0 uses legacy try/catch/throw (same bytes as frozen probe 10); function 1 uses try_table.
write("37_eh2_mixed_legacy_new.wasm", module(
    type_section(functype([], [])),
    tag_section([(0x00, 0)]),
    func_section([0, 0]),
    export_section([("legacy", 0, 0), ("new", 0, 1)]),
    code_section([
        b"\x06\x40" + b"\x08\x00" + b"\x07\x00" + END + END,     # legacy try; throw 0; catch 0; end; end
        try_table(0x40, [catch_all_clause(0)], throw_(0)) + END,  # new: try_table; throw 0; end; end
    ]),
))


# ---------------------------------------------------------------- (f) exnref in a global

# 38. An imported exnref global, a defined mutable exnref global initialized from it, and a function
#     that throws the global's exception reference with throw_ref.
write("38_eh2_exnref_global.wasm", module(
    type_section(functype([], [])),
    import_section([("env", "e", 3, bytes([HT_EXN, 0x00]))]),  # kind 3 = global, exnref, immutable
    func_section([0]),
    global_section([(HT_EXN, True, global_get(0))]),           # (global (mut exnref) (global.get 0))
    export_section([("f", 0, 0)]),
    code_section([global_get(1) + throw_ref() + END]),
))


# ---------------------------------------------------------------- extra: multi-clause vector lengths

# 39. Two clauses of different kinds (3-byte catch + 2-byte catch_all), so the clause vector's bytes
#     have to be consumed exactly; the second clause's label skips the block the first clause uses.
write("39_eh2_try_table_multi_clause.wasm", module(
    type_section(functype([], []), functype([], [])),  # 0 = tag ()->(), 1 = f ()->()
    tag_section([(0x00, 0)]),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([b"\x02\x40"                                             # L0 -- catch_all label 1
                  + b"\x02\x40"                                           # L1 -- catch label 0
                  + try_table(0x40, [catch_clause(0, 0), catch_all_clause(1)], throw_(0))
                  + END                                                   # end L1
                  + END                                                   # end L0
                  + END]),                                                # end function
))
