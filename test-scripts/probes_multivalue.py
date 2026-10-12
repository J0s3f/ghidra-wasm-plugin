#!/usr/bin/env python3
"""Probes owned by the *multi-value returns* workstream - roadmap item 7.

A function with more than one result returns all of its results as a packed
struct in the output register block (oN registers, cspec pentry at
register 0x30000000). The struct is named wasm_ret_<type>_<type>... with
fields f0, f1, ... (packed, so field i sits at the sum of the sizes of
the previous fields - exactly where the epilogue writes it).

Each probe here consumes *all* of a call's results (storing them to
globals or locals, or combining them arithmetically), so a result that
silently disappears shows up as a missing/undefined value in the
decompiled C. The frozen baseline probe 16_multivalue_return (gen_feature_probes.py)
is the (i32, i32) prototype case; probe 17 (multi-result block) must keep
passing - a multi-result block stays entirely on the operand stack and is
unaffected by the return ABI.

Expected results are recorded in REPORT-MV.md.

Usage: python probes_multivalue.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

I32_ADD = b"\x6A"   # i32.add
I32_MUL = b"\x6C"   # i32.mul


def mutable_globals(*valtypes):
    """(valtype, mutable, i32.const 0 / i64.const 0 / f64.const 0) entries."""
    zero = {I32: i32_const(0), I64: i64_const(0), F32: f32_const(0.0), F64: f64_const(0.0)}
    return [(vt, True, zero[vt]) for vt in valtypes]


def code_with_locals(bodies):
    """Like code_section, but each entry is a full function body (locals + code),
    i.e. built with `body(code, locals_)`."""
    return section(10, vec(list(bodies)))


# ---------------------------------------------------------------------------
# (a) the canonical case: (i32, i32), both results stored to globals
# ---------------------------------------------------------------------------

# M01. wasm_ret_i32_i32 f(void); caller stores both results into globals.
# Results are popped top-first, so g0 = f().f1 and g1 = f().f0.
write("M01_multivalue_i32_i32.wasm", module(
    type_section(functype([], [I32, I32]), functype([], [])),
    func_section([0, 1]),
    global_section(mutable_globals(I32, I32)),
    export_section([("pair", 0, 0), ("f", 0, 1), ("g0", 3, 0), ("g1", 3, 1)]),
    code_section([
        i32_const(1) + i32_const(2) + END,                    # pair: (1, 2)
        call(0) + global_set(0) + global_set(1) + END,          # f: call pair, store both
    ]),
))

# ---------------------------------------------------------------------------
# (b) three or more results
# ---------------------------------------------------------------------------

# M02. (i32, i32, i32) -> wasm_ret_i32_i32_i32 (12 bytes, still one 16-byte slot)
write("M02_multivalue_three_i32.wasm", module(
    type_section(functype([], [I32, I32, I32]), functype([], [])),
    func_section([0, 1]),
    global_section(mutable_globals(I32, I32, I32)),
    export_section([("triple", 0, 0), ("f", 0, 1),
                    ("g0", 3, 0), ("g1", 3, 1), ("g2", 3, 2)]),
    code_section([
        i32_const(1) + i32_const(2) + i32_const(3) + END,
        call(0) + global_set(0) + global_set(1) + global_set(2) + END,
    ]),
))

# M03. four results (i32 x4) -> 16 bytes, exactly one full output slot
write("M03_multivalue_four_i32.wasm", module(
    type_section(functype([], [I32, I32, I32, I32]), functype([], [])),
    func_section([0, 1]),
    global_section(mutable_globals(I32, I32, I32, I32)),
    export_section([("quad", 0, 0), ("f", 0, 1),
                    ("g0", 3, 0), ("g1", 3, 1), ("g2", 3, 2), ("g3", 3, 3)]),
    code_section([
        i32_const(1) + i32_const(2) + i32_const(3) + i32_const(4) + END,
        call(0) + global_set(0) + global_set(1) + global_set(2) + global_set(3) + END,
    ]),
))

# ---------------------------------------------------------------------------
# (c) mixed result types
# ---------------------------------------------------------------------------

# M04. (i32, f64) -> wasm_ret_i32_f64 (12 bytes packed)
write("M04_multivalue_mixed_i32_f64.wasm", module(
    type_section(functype([], [I32, F64]), functype([], [])),
    func_section([0, 1]),
    global_section(mutable_globals(I32, F64)),
    export_section([("pair", 0, 0), ("f", 0, 1), ("gi", 3, 0), ("gd", 3, 1)]),
    code_section([
        i32_const(7) + f64_const(2.5) + END,
        # results pop top-first: global_set(1) takes the f64, global_set(0) the i32
        call(0) + global_set(1) + global_set(0) + END,
    ]),
))

# M05. (i64, i32) -> wasm_ret_i64_i32 (12 bytes packed)
write("M05_multivalue_i64_i32.wasm", module(
    type_section(functype([], [I64, I32]), functype([], [])),
    func_section([0, 1]),
    global_section(mutable_globals(I64, I32)),
    export_section([("pair", 0, 0), ("f", 0, 1), ("gl", 3, 0), ("gi", 3, 1)]),
    code_section([
        i64_const(0x1122334455667788) + i32_const(-5) + END,
        # results pop top-first: global_set(1) takes the i32, global_set(0) the i64
        call(0) + global_set(1) + global_set(0) + END,
    ]),
))

# M06. (i32, i64) -> wasm_ret_i32_i64 (12 bytes packed; the 8-byte field is
# at offset 4, i.e. unaligned - the packed struct matches the pcode layout)
write("M06_multivalue_i32_i64.wasm", module(
    type_section(functype([], [I32, I64]), functype([], [])),
    func_section([0, 1]),
    global_section(mutable_globals(I32, I64)),
    export_section([("pair", 0, 0), ("f", 0, 1), ("gi", 3, 0), ("gl", 3, 1)]),
    code_section([
        i32_const(0x12345678) + i64_const(0x9ABCDEF012345678) + END,
        # results pop top-first: global_set(1) takes the i64, global_set(0) the i32
        call(0) + global_set(1) + global_set(0) + END,
    ]),
))

# M07. (f64, f64) -> wasm_ret_f64_f64 (16 bytes, one full slot)
write("M07_multivalue_f64_f64.wasm", module(
    type_section(functype([], [F64, F64]), functype([], [])),
    func_section([0, 1]),
    global_section(mutable_globals(F64, F64)),
    export_section([("pair", 0, 0), ("f", 0, 1), ("gd0", 3, 0), ("gd1", 3, 1)]),
    code_section([
        f64_const(1.5) + f64_const(-2.25) + END,
        call(0) + global_set(0) + global_set(1) + END,
    ]),
))

# ---------------------------------------------------------------------------
# (d) a caller that combines both results
# ---------------------------------------------------------------------------

# M08. caller stores both results in locals, then returns (a+b, a*b):
# both results are consumed arithmetically.
write("M08_multivalue_caller_arith.wasm", module(
    type_section(functype([], [I32, I32]), functype([], [I32, I32])),
    func_section([0, 1]),
    export_section([("pair", 0, 0), ("f", 0, 1)]),
    code_with_locals([
        body(i32_const(3) + i32_const(4) + END, []),          # pair: (3, 4)
        body(call(0) + local_set(1) + local_set(0) +            # f: b -> local1, a -> local0
             local_get(0) + local_get(1) + I32_ADD +           #   a + b
             local_get(0) + local_get(1) + I32_MUL + END,      #   a * b
             [(2, I32)]),                                      #   2 i32 locals
    ]),
))

# ---------------------------------------------------------------------------
# (e) multi-result blocks (operand-stack only; frozen probe 17 must keep passing)
# ---------------------------------------------------------------------------

# M09. block with a type-index blocktype returning (i32, i32); both block
# results are stored to globals. Like frozen probe 17: type 0 is the
# function's own (empty) result list, type 1 is the block's result list.
write("M09_multivalue_block.wasm", module(
    type_section(functype([], []), functype([], [I32, I32])),
    func_section([0]),
    global_section(mutable_globals(I32, I32)),
    export_section([("f", 0, 0), ("g0", 3, 0), ("g1", 3, 1)]),
    code_section([
        block(1, i32_const(10) + i32_const(20)) +              # block (type 1) -> (10, 20)
        global_set(0) + global_set(1) + END,                   # f: store both block results
    ]),
))

# ---------------------------------------------------------------------------
# (f) multi-result import
# ---------------------------------------------------------------------------

# M10. imported function with two results, called; both results are consumed.
write("M10_multivalue_import.wasm", module(
    type_section(functype([], [I32, I32]), functype([], [I32])),
    import_section([("env", "pair", 0, uleb(0))]),             # import func 0: () -> (i32, i32)
    func_section([1]),                                          # func 1: () -> i32
    export_section([("f", 0, 1)]),
    code_with_locals([
        body(call(0) + local_set(1) + local_set(0) +            # b -> local1, a -> local0
             local_get(0) + local_get(1) + I32_ADD + END,      # a + b
             [(2, I32)]),
    ]),
))

# ---------------------------------------------------------------------------
# (g) tail call of a multi-result function (return_call)
# ---------------------------------------------------------------------------

# M11. return_call: the tail-callee's results are the caller's results.
write("M11_multivalue_return_call.wasm", module(
    type_section(functype([], [I32, I32])),
    func_section([0, 0]),
    export_section([("pair", 0, 0), ("tail", 0, 1)]),
    code_section([
        i32_const(1) + i32_const(2) + END,                     # pair: (1, 2)
        return_call(0) + END,                                   # tail: return pair()
    ]),
))

# ---------------------------------------------------------------------------
# (h) call_indirect through a table with a multi-result type
# ---------------------------------------------------------------------------

# M12. call_indirect with a (i32, i32) result type; both results are consumed.
write("M12_multivalue_call_indirect.wasm", module(
    type_section(functype([], [I32, I32]), functype([], [I32])),
    func_section([0, 1]),
    table_section([(FUNCREF, 0x00, 1)]),
    elem_section([b"\x00" + i32_const(0) + END + uleb(1) + uleb(0)]),
    export_section([("f", 0, 1)]),
    code_with_locals([
        body(i32_const(5) + i32_const(6) + END, []),           # pair (func 0): (5, 6)
        body(i32_const(0) + call_indirect(0, 0) +              # call func 0 via table 0
             local_set(1) + local_set(0) +                     # b -> local1, a -> local0
             local_get(0) + local_get(1) + I32_ADD + END,      # a + b
             [(2, I32)]),
    ]),
))
