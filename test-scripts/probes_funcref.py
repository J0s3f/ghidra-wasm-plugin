#!/usr/bin/env python3
"""Function-references probe modules (proposal: function-references).

Covers the five typed-function-reference instructions that share the existing
control/call machinery:

  * 0x14 call_ref        typeidx          - call through a typed function reference
  * 0x15 return_call_ref typeidx          - tail-call through a typed function reference
  * 0xD4 ref.as_non_null                  - null -> non-null reference
  * 0xD5 br_on_null      labelidx          - branch if the reference is null
  * 0xD6 br_on_non_null  labelidx          - branch if the reference is non-null

The frozen baseline probe `12_call_ref.wasm` (gen_feature_probes.py) is the
minimal call_ref case; these probes add the remaining opcodes plus combinations
with a table/table.get and with ordinary call/call_indirect.

Usage: python probes_funcref.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])


# ---------------------------------------------------------------- local helpers
# wasm_probe_lib.py has call_ref/return_call/ref_null/ref_/functype; a few
# function-references encodings are not there yet, so they live here (the shared
# library is not edited by this probe file).

def return_call_ref(typeidx) -> bytes:
    """0x15 typeidx."""
    return b"\x15" + uleb(typeidx)


def ref_as_non_null() -> bytes:
    """0xD4 - no immediates."""
    return b"\xD4"


def br_on_null(label) -> bytes:
    """0xD5 labelidx."""
    return b"\xD5" + uleb(label)


def br_on_non_null(label) -> bytes:
    """0xD6 labelidx."""
    return b"\xD6" + uleb(label)


def table_get(i) -> bytes:
    """0x25 tableidx."""
    return b"\x25" + uleb(i)


def ref_func(i) -> bytes:
    """0xD2 funcidx."""
    return b"\xD2" + uleb(i)


def type_section_multi(*type_bytes) -> bytes:
    """A type section whose entries are given as raw bytes (multi-byte valtypes)."""
    return section(1, vec(list(type_bytes)))


def _vt(t) -> bytes:
    """A valtype as bytes: an int byte or an already-encoded (multi-byte) valtype."""
    return bytes([t]) if isinstance(t, int) else t


def ftype(params, results) -> bytes:
    """functype where params/results may mix int valtypes and encoded (ref ...) bytes."""
    return b"\x60" + vec([_vt(p) for p in params]) + vec([_vt(r) for r in results])


def active_elem_funcs(funcidxs) -> bytes:
    """Active element segment (flags=0): table 0 at i32.const 0, then funcidx*."""
    return b"\x00" + i32_const(0) + END + vec([uleb(f) for f in funcidxs])


# =============================================================================================
# 0x14 call_ref is covered by the frozen 12_call_ref.wasm; the probes below start with the
# remaining four opcodes and then combine them.
# =============================================================================================

# F01: return_call_ref. type0 = (i32)->(i32) is the callee/reference type;
#      type1 = ((ref null 0) i32)->(i32) is the caller. local 0 = ref, local 1 = i32.
#      Stack order for a call: arguments first, then the reference on top.
write("F01_return_call_ref.wasm", module(
    type_section(
        functype([I32], [I32]),                                   # 0
        ftype([ref_null(0), I32], [I32])),                        # 1
    func_section([1, 0]),
    export_section([("f", 0, 0)]),
    code_section([
        local_get(1) + local_get(0) + return_call_ref(0) + END,   # tail call through local 0
        local_get(0) + END,                                       # callee: (i32)->(i32)
    ]),
))

# F02: ref.as_non_null. type0 = ((ref null 0))->(). Same 4-byte width, so the
#      decompiler sees the reference pass through unchanged (documented in REPORT-FR.md).
write("F02_ref_as_non_null.wasm", module(
    type_section(b"\x60" + vec([ref_null(0)]) + vec([])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([local_get(0) + ref_as_non_null() + drop() + END]),
))

# F03: br_on_null - branch to the enclosing block's end (the "taken" direction);
#      the fall-through path drops the non-null reference.
write("F03_br_on_null.wasm", module(
    type_section(b"\x60" + vec([ref_null(0)]) + vec([])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([block(0x40, local_get(0) + br_on_null(0) + drop()) + END]),
))

# F04: br_on_null with both outcomes observable: the branch to the function's own label
#      carries the i32 below the reference (the "taken"/null result), while the fall-through
#      drops the now non-null reference and produces a different i32.
#      type 0 = ((ref null 0)) -> (i32).
write("F04_br_on_null_fallthrough.wasm", module(
    type_section_multi(ftype([ref_null(0)], [I32])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        i32_const(1) + local_get(0) + br_on_null(0) +   # null -> return 1
        drop() + drop() + i32_const(2) +                # non-null -> return 2
        END,
    ]),
))

# F05: br_on_non_null - block 0 has type ()->(ref null 0), so the non-null branch carries
#      the reference to the block's end while the null fall-through supplies its own
#      reference; ref.is_null then makes the two paths produce 0 and 1.
#      type 0 = () -> (ref null 0);  type 1 = ((ref null 0)) -> (i32).
write("F05_br_on_non_null.wasm", module(
    type_section_multi(
        ftype([], [ref_null(0)]),                                 # 0: () -> (ref null 0)
        ftype([ref_null(0)], [I32])),                             # 1: ((ref null 0)) -> (i32)
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([
        block(0, local_get(0) + br_on_non_null(0) + local_get(0)) +
        b"\xD1" +                                                 # ref.is_null
        END,
    ]),
))

# F06: call_ref through a table-loaded function. The reference comes from table.get,
#      which the loader resolves to the function address stored by the element segment.
write("F06_call_ref_through_table.wasm", module(
    type_section(
        functype([I32], [I32]),      # 0: (i32)->(i32)
        functype([], [I32])),        # 1: ()->(i32)
    func_section([0, 1]),
    table_section([(FUNCREF, 0x00, 1)]),
    export_section([("f", 0, 1)]),
    elem_section([active_elem_funcs([0])]),
    code_section([
        local_get(0) + END,                                    # func 0: callee
        i32_const(42) + i32_const(0) + table_get(0) + call_ref(0) + END,  # func 1
    ]),
))

# F07: a function-references module mixing typed refs with ordinary call/call_indirect.
#      func 0 = (i32)->(i32) callee; func 1/exported f = ((ref null 0))->(), its body
#      does a direct call, a call_indirect through table 0, a call_ref through its
#      reference parameter, and a call_ref through ref.func (a statically known target).
write("F07_funcref_mixed.wasm", module(
    type_section(
        functype([I32], [I32]),                                   # 0: (i32)->(i32)
        b"\x60" + vec([ref_null(0)]) + vec([])),                  # 1: ((ref null 0))->()
    func_section([0, 1]),
    table_section([(FUNCREF, 0x00, 1)]),
    export_section([("f", 0, 1)]),
    elem_section([active_elem_funcs([0])]),
    code_section([
        local_get(0) + END,                                       # func 0
        i32_const(5) + call(0) + drop() +                         # direct call
        i32_const(0) + i32_const(3) + call_indirect(0, 0) + drop() +  # table call
        i32_const(9) + local_get(0) + call_ref(0) + drop() +      # typed call through the param
        i32_const(4) + ref_func(0) + call_ref(0) + drop() +       # typed call to a known function
        END,
    ]),
))
