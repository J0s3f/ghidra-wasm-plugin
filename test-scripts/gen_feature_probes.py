#!/usr/bin/env python3
"""FROZEN baseline probes - do not edit.

These 21 modules are the baseline recorded in MODERN_WASM_GAPS.md (section 2.4). They must keep
producing the recorded metrics so that the inventory stays comparable over time; new probes for new
work go into `probes_analysis.py` or `probes_types.py` instead.

Usage: python gen_feature_probes.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])

# 1. baseline: (func (export "f") (param i32) (result i32) local.get 0)
write("01_baseline_i32.wasm", module(
    type_section(functype([I32], [I32])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x20\x00" + END]),
))

# 2. reference types: externref parameter (MVP + reference-types)
write("02_externref_param.wasm", module(
    type_section(functype([EXTERNREF], [I32])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x41\x01" + END]),
))

# 3. externref table + table.get
write("03_externref_table.wasm", module(
    type_section(functype([], [EXTERNREF])),
    table_section([(EXTERNREF, 0x00, 1)]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x41\x00\x25\x00" + END]),  # i32.const 0; table.get 0
))

# 4. threads: shared memory + atomic load
write("04_shared_memory_atomic.wasm", module(
    type_section(functype([I32], [I32])),
    memory_section([(0x03, 1, 1)]),  # flags=3 -> shared, has max
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x20\x00" + atomic_op(0x10) + b"\x02\x00" + END]),  # i32.atomic.load align=2 off=0
))

# 5. memory64: 64-bit memory, i64 address operand
write("05_memory64.wasm", module(
    type_section(functype([], [I32])),
    memory_section([(0x04, 1)]),  # flags=4 -> 64-bit index, no max
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x42\x00" + b"\x28\x02\x00" + END]),  # i64.const 0; i32.load align=2 off=0
))

# 6. multi-memory: two memories, load from memory 1 (memarg memidx), memory.size 1
write("06_multi_memory.wasm", module(
    type_section(functype([], [I32])),
    memory_section([(0x00, 1), (0x00, 1)]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x41\x00" + b"\x28" + b"\x42\x01\x00" +     # i32.const 0; i32.load memidx=1 align=2 off=0
                  b"\x3F\x01" +                                   # memory.size 1
                  b"\x6A" + END]),                                # i32.add
))

# 7. data count section + active data + memory.init / data.drop (bulk memory)
write("07_data_count_bulk_memory.wasm", module(
    type_section(functype([], [])),
    memory_section([(0x00, 1)]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    data_count_section(1),
    code_section([b"\x41\x00\x41\x00\x41\x03" + misc_op(8) + b"\x00\x00" + misc_op(9) + b"\x00" + END]),
    data_section([active_data(b"\x41\x00" + END, b"abc")]),
))

# 8. GC: struct type (no GC instructions yet)
write("08_gc_struct_type.wasm", module(
    type_section(struct_type([(I32, False)]), functype([], [])),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([END]),
))

# 9. GC: struct.new
write("09_gc_struct_new.wasm", module(
    type_section(struct_type([(I32, False)]), functype([], [])),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([b"\x41\x01" + gc_op(0) + uleb(0) + END]),  # i32.const 1; struct.new 0
))

# 10. exception handling (legacy): tag + try/catch/throw
write("10_eh_legacy_try_catch.wasm", module(
    type_section(functype([], [])),
    tag_section([(0x00, 0)]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x06\x40" + b"\x08\x00" + b"\x07\x00" + END + END]),  # try; throw 0; catch 0; end; end
))

# 11. exception handling (new proposal): try_table
write("11_eh_try_table.wasm", module(
    type_section(functype([], [])),
    tag_section([(0x00, 0)]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x1F\x40" + vec([]) + END + END]),  # try_table (empty) ; end ; end
))

# 12. typed function references: (ref null $t) parameter + call_ref
write("12_call_ref.wasm", module(
    type_section(b"\x60" + vec([ref_null(0)]) + vec([])),  # type 0 = ((ref null 0)) -> ()
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([local_get(0) + call_ref(0) + END]),
))

# 13. tail calls: return_call
write("13_tail_call.wasm", module(
    type_section(functype([], [])),
    func_section([0, 0]),
    export_section([("f", 0, 0)]),
    code_section([return_call(1) + END, END]),
))

# 14. relaxed SIMD: i8x16.relaxed_swizzle
write("14_relaxed_simd.wasm", module(
    type_section(functype([], [])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([v128_const(bytes(16)) + v128_const(bytes(16)) + simd_op(0x100) + drop() + END]),
))

# 15. SIMD (baseline vector ops): i32x4.add (0xFD + LEB128 u32 174)
write("15_simd.wasm", module(
    type_section(functype([], [])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([v128_const(bytes(16)) + v128_const(bytes(16)) + simd_op(174) + drop() + END]),
))

# 16. multi-value: function returning (i32, i32), called and both results dropped
write("16_multivalue_return.wasm", module(
    type_section(functype([], [I32, I32]), functype([], [])),
    func_section([0, 1]),
    export_section([("f", 0, 0)]),
    code_section([i32_const(1) + i32_const(2) + END,
                  call(0) + drop() + drop() + END]),
))

# 17. multi-value block: block with a type-index blocktype
write("17_multivalue_block.wasm", module(
    type_section(functype([], [I32]), functype([], [I32, I32])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([block(1, i32_const(1) + i32_const(2)) + b"\x6A" + END]),
))

# 18. shared memory followed by a second memory: multi-memory + shared limits
write("18_shared_then_plain_memory.wasm", module(
    type_section(functype([], [I32])),
    memory_section([(0x03, 1, 1), (0x00, 7)]),  # memory 0 shared, memory 1 = 7 pages
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x3F\x01" + END]),  # memory.size 1
))

# 19. extended-const: global initializer using i32.add
write("19_extended_const_global.wasm", module(
    global_section([(I32, False, i32_const(1) + i32_const(2) + b"\x6A")]),
    export_section([("g", 3, 0)]),
))

# 20. GC in a constant expression: (global (ref 0) (struct.new 0))
write("20_gc_global_init.wasm", module(
    type_section(struct_type([])),
    global_section([(ref_(0), False, gc_op(0) + uleb(0))]),
    export_section([("g", 3, 0)]),
))

# 21. component model binary: magic + version 13 / layer 1 (not a core module)
write("21_component_model.wasm", raw_module(bytes([0x0D, 0x00, 0x01, 0x00])))
