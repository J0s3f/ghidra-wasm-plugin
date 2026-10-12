#!/usr/bin/env python3
"""Probes owned by the *parsers/types* workstream (agent B).

Add new probes here - never edit `gen_feature_probes.py` (frozen baseline) or `probes_analysis.py`
(owned by the other agent). Use the helpers from `wasm_probe_lib`:

    write("B01_limits_shared_max.wasm", module(...))

Each probe should be a *valid* module for the feature it exercises, and its expected result should be
written down in REPORT-B.md (funcs / instrs / undefined_bytes / decompiled, plus the disassembly or
decompiled C when type/signature correctness is the point).

Usage: python probes_types.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])

# ---------------------------------------------------------------------------------------------
# Limits probes: shared / memory64 / custom-page-size flag combinations, several memories/tables
# in one section so a parse desync would be visible
# ---------------------------------------------------------------------------------------------

# B01: shared memory with maximum (flags=3)
write("B01_limits_shared_max.wasm", module(
    type_section(functype([], [])),
    memory_section([(0x03, 10, 20)]),  # flags=3: shared + has_max
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([END]),
))

# B02: memory64 with maximum (flags=5 = 64-bit + has_max)
write("B02_limits_memory64_max.wasm", module(
    type_section(functype([], [])),
    memory_section([(0x05, 10, 20)]),  # flags=5: 64-bit + has_max
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([END]),
))

# B03: custom page size (flags=8 = page-size flag, followed by exponent)
write("B03_limits_custom_page_size.wasm", module(
    type_section(functype([], [])),
    memory_section([(0x08, 10, 0, 4)]),  # flags=8: custom page size, exponent=4 (64 KiB pages)
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([END]),
))

# B04: shared memory64 (flags=6 = shared + 64-bit)
write("B04_limits_shared_memory64.wasm", module(
    type_section(functype([], [])),
    memory_section([(0x06, 10)]),  # flags=6: shared + 64-bit
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([END]),
))

# B05: two memories in one section (flags 0 and 3) - tests desync
write("B05_limits_two_memories.wasm", module(
    type_section(functype([], [I32])),
    memory_section([(0x00, 1), (0x03, 5, 10)]),  # memory 0: plain; memory 1: shared+max
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x3F\x01" + END]),  # memory.size 1
))

# B06: two tables in one section - tests desync for tables too
write("B06_limits_two_tables.wasm", module(
    type_section(functype([], [EXTERNREF])),
    table_section([(EXTERNREF, 0x00, 2), (FUNCREF, 0x01, 3, 5)]),  # table 0: plain; table 1: shared+max
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x25\x01" + END]),  # table.get 1
))

# ---------------------------------------------------------------------------------------------
# Constant expression probes: extended-const, v128.const, ref.null/ref.func, unknown opcode
# ---------------------------------------------------------------------------------------------

# B07: extended-const i32.add in global initializer
write("B07_const_i32_add.wasm", module(
    type_section(functype([], [I32])),
    global_section([(I32, False, i32_const(10) + i32_const(32) + b"\x6A")]),  # 10 + 32 = 42
    export_section([("g", 3, 0)]),
    func_section([0]),
    code_section([global_get(0) + END]),
))

# B08: extended-const i64.add in global initializer
write("B08_const_i64_add.wasm", module(
    type_section(functype([], [I64])),
    global_section([(I64, False, i64_const(100) + i64_const(200) + b"\x7C")]),  # 100 + 200 = 300
    export_section([("g", 3, 0)]),
    func_section([0]),
    code_section([global_get(0) + END]),
))

# B09: extended-const i32.mul in global initializer
write("B09_const_i32_mul.wasm", module(
    type_section(functype([], [I32])),
    global_section([(I32, False, i32_const(6) + i32_const(7) + b"\x6C")]),  # 6 * 7 = 42
    export_section([("g", 3, 0)]),
    func_section([0]),
    code_section([global_get(0) + END]),
))

# B10: v128.const in global initializer
write("B10_const_v128.wasm", module(
    type_section(functype([], [V128])),
    global_section([(V128, False, v128_const(bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]))) ]),
    export_section([("g", 3, 0)]),
    func_section([0]),
    code_section([global_get(0) + END]),
))

# B11: ref.func in global initializer
write("B11_const_ref_func.wasm", module(
    type_section(functype([], []), functype([], [])),
    func_section([0, 1]),
    global_section([(FUNCREF, False, b"\xD2\x01")]),  # ref.func 1
    export_section([("g", 3, 0)]),
    code_section([END, END]),
))

# B12: ref.null externref in global initializer
write("B12_const_ref_null_extern.wasm", module(
    type_section(functype([], [EXTERNREF])),
    global_section([(EXTERNREF, False, b"\xD0\x6F")]),  # ref.null externref
    export_section([("g", 3, 0)]),
    func_section([0]),
    code_section([global_get(0) + END]),
))

# B13: ref.null funcref in global initializer
write("B13_const_ref_null_func.wasm", module(
    type_section(functype([], [FUNCREF])),
    func_section([0]),
    global_section([(FUNCREF, False, b"\xD0\x70")]),  # ref.null funcref
    export_section([("g", 3, 0)]),
    code_section([global_get(0) + END]),
))

# B14: unknown opcode in constant expression (GC struct.new) - must not fail import
write("B14_const_unknown_gc.wasm", module(
    type_section(struct_type([(I32, False)])),
    global_section([(I32, False, gc_op(0) + uleb(0) + END)]),  # struct.new 0 - unknown in const expr
    export_section([("g", 3, 0)]),
    func_section([0]),
    code_section([global_get(0) + END]),
))

# B15: ref.null with custom heap type (multi-byte) in const expr
write("B15_const_ref_null_typeidx.wasm", module(
    type_section(struct_type([(I32, False)])),
    global_section([(ref_null(1), False, b"\xD0" + ref_null(1) + END)]),  # ref.null $type1
    export_section([("g", 3, 0)]),
    func_section([0]),
    code_section([global_get(0) + END]),
))

# ---------------------------------------------------------------------------------------------
# Value type probes: (ref null $t) / (ref $t) params/results/locals/globals/tables, GC types
# Note: For multi-byte valtypes in function types, we need to write raw type sections
# ---------------------------------------------------------------------------------------------

# Helper to write a type section with multi-byte valtypes
def type_section_multi(*type_bytes):
    return section(1, vec(list(type_bytes)))

# Helper to write raw table section with multi-byte elemtype
def table_section_raw(tables):
    """tables: list of (elemtype_bytes, flags, initial[, maximum])"""
    out = []
    for t in tables:
        elemtype, flags, initial = t[0], t[1], t[2]
        body = elemtype + bytes([flags]) + uleb(initial)
        if len(t) > 3:
            body += uleb(t[3])
        out.append(body)
    return section(4, vec(out))

# B16: (ref null $t) as function parameter + call_ref
# type 0: (ref null 0) -> (), type 1: () -> ()
write("B16_valtype_ref_null_param.wasm", module(
    type_section_multi(
        b"\x60" + vec([ref_null(0)]) + vec([]),
        functype([], [])
    ),
    func_section([0, 1]),
    export_section([("f", 0, 0), ("callee", 0, 1)]),
    code_section([local_get(0) + call_ref(0) + END, END]),
))

# B17: (ref $t) as function parameter (non-nullable)
# type 0: (ref 0) -> (), type 1: () -> ()
write("B17_valtype_ref_param.wasm", module(
    type_section_multi(
        b"\x60" + vec([ref_(0)]) + vec([]),
        functype([], [])
    ),
    func_section([0, 1]),
    export_section([("f", 0, 0), ("callee", 0, 1)]),
    code_section([local_get(0) + call_ref(0) + END, END]),
))

# B18: (ref null $t) as function result
# type 0: () -> (), type 1: () -> (ref null 0)
write("B18_valtype_ref_null_result.wasm", module(
    type_section_multi(
        functype([], []),
        b"\x60" + vec([]) + vec([bytes([0x63]) + sleb(0)])
    ),
    func_section([0, 1]),
    export_section([("f", 0, 0), ("maker", 0, 1)]),
    code_section([call(1) + drop() + END, ref_null(0) + END]),
))

# B19: exnref as parameter and local
write("B19_valtype_exnref.wasm", module(
    type_section(functype([0x69], [0x69])),  # exnref param, exnref result
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x20\x00" + END]),  # local.get 0 (exnref param)
))

# B20: anyref as parameter
write("B20_valtype_anyref.wasm", module(
    type_section(functype([0x6E], [0x6E])),  # anyref param, anyref result
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x20\x00" + END]),
))

# B21: eqref as parameter
write("B21_valtype_eqref.wasm", module(
    type_section(functype([0x6D], [0x6D])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x20\x00" + END]),
))

# B22: i31ref as parameter
write("B22_valtype_i31ref.wasm", module(
    type_section(functype([0x6C], [0x6C])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x20\x00" + END]),
))

# B23: structref as parameter
write("B23_valtype_structref.wasm", module(
    type_section(functype([0x6B], [0x6B])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x20\x00" + END]),
))

# B24: arrayref as parameter
write("B24_valtype_arrayref.wasm", module(
    type_section(functype([0x6A], [0x6A])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x20\x00" + END]),
))

# B25: exnref as global
write("B25_valtype_exnref_global.wasm", module(
    type_section(struct_type([])),
    global_section([(0x69, False, b"\xD0\x69" + END)]),  # global exnref = ref.null exnref
    export_section([("g", 3, 0)]),
    func_section([0]),
    code_section([global_get(0) + drop() + END]),
))

# B26: table with (ref null $t) element type
write("B26_valtype_table_ref_null.wasm", module(
    type_section_multi(
        b"\x60" + vec([]) + vec([ref_null(0)])  # type 0: () -> (ref null 0)
    ),
    table_section_raw([
        (bytes([0x63]) + sleb(0), 0x00, 2)  # table of (ref null 0)
    ]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x41\x00\x25\x00" + END]),  # i32.const 0; table.get 0
))

# B27: table with (ref $t) element type
write("B27_valtype_table_ref.wasm", module(
    type_section_multi(
        b"\x60" + vec([]) + vec([ref_(0)])  # type 0: () -> (ref 0)
    ),
    table_section_raw([
        (bytes([0x64]) + sleb(0), 0x00, 2)  # table of (ref 0)
    ]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x41\x00\x25\x00" + END]),
))

# B28: function type referencing GC struct type
# type 0: struct { i32, mut i64 }, type 1: (ref null 0) -> (ref 0)
write("B28_valtype_func_gc_struct.wasm", module(
    type_section_multi(
        struct_type([(I32, False), (I64, True)]),
        b"\x60" + vec([ref_null(0)]) + vec([ref_(0)])
    ),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([ref_null(0) + END]),
))

# B29: multiple value types in one function (mixed)
# type 0: i32, externref, anyref, structref, i31ref -> arrayref, eqref
write("B29_valtype_mixed.wasm", module(
    type_section_multi(
        b"\x60" + vec([bytes([I32]), bytes([EXTERNREF]), bytes([0x6E]), bytes([0x6B]), bytes([0x6C])]) + 
        vec([bytes([0x6A]), bytes([0x6D])])
    ),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x20\x00\x20\x01\x20\x02\x20\x03\x20\x04" + drop() + drop() + drop() + drop() + drop() + END]),
))