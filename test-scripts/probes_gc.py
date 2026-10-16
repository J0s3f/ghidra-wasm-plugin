#!/usr/bin/env python3
"""Probes owned by the GC workstream (workstream E): valid modules for the WebAssembly GC
proposal (type-section records + 0xFB instructions).

Uses only the helpers from `wasm_probe_lib.py` (`struct_type`, `array_type`, `rectype`,
`subtype`, `gc_op`, `ref_null`, `ref_`, ...). Every probe is a spec-valid core module so that
a correct loader/analyzer reports `undefined_bytes == 0` and decompiles every function.

Usage: python probes_gc.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])

HT_STRUCT, HT_ARRAY = 0x6B, 0x6A
HT_ANY, HT_EQ, HT_I31 = 0x6E, 0x6D, 0x6C


def passive_elem_funcs(funcidxs):
    """Passive element segment of funcref (flags=1, elemkind=0)."""
    return b"\x01\x00" + vec([uleb(f) for f in funcidxs])


# =============================================================================================
# Type-section encodings
# =============================================================================================

# E01: struct with mixed storage types, including packed i8/i16 and both multi-byte ref forms
#      ((ref null 0) = 0x63 0x00, (ref 0) = 0x64 0x00). Empty function.
_e01_struct = b"\x5F" + vec([
    bytes([I32]) + b"\x00",
    bytes([I64]) + b"\x01",
    bytes([F32]) + b"\x00",
    bytes([F64]) + b"\x01",
    bytes([V128]) + b"\x00",
    bytes([0x78]) + b"\x01",          # i8 (packed)
    bytes([0x77]) + b"\x00",          # i16 (packed)
    ref_null(0) + b"\x00",            # (ref null 0)
    ref_(0) + b"\x01",                # (ref 0)
])
write("E01_gc_struct_type.wasm", module(
    type_section(_e01_struct, functype([], [])),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([END]),
))

# E02: arrays of i32 / i8 / funcref / (ref null 0). Empty function.
write("E02_gc_array_type.wasm", module(
    type_section(
        array_type(I32, True),
        array_type(0x78, True),
        array_type(FUNCREF, False),
        b"\x5E" + ref_null(0) + b"\x01",
        functype([], [])),
    func_section([4]),
    export_section([("f", 0, 0)]),
    code_section([END]),
))

# E03: rec group (0x4E) containing a struct, a sub final struct and a func type, followed by a
#      bare sub (0x50) function type and a sub final (0x4F) struct.
write("E03_gc_rec_subtype.wasm", module(
    type_section(
        rectype(
            subtype(struct_type([(I32, True)]), final=False),         # non-final: a supertype below
            subtype(struct_type([(I64, False)]), final=True),         # 0x4F sub final
            functype([], [I32])),
        subtype(functype([], []), final=False),                       # 0x50 sub
        subtype(struct_type([(I32, True), (F32, True)]), [0], final=True),  # sub final 0: supertype field + extra
    ),
    func_section([2, 3]),
    export_section([("f", 0, 0), ("g", 0, 1)]),
    code_section([i32_const(1) + END, END]),
))

# E04: abstract heap-type shorthands 0x69-0x74, both directly as a storage type and inside
#      (ref null ht) / (ref ht). Empty function.
write("E04_gc_abstract_heaptypes.wasm", module(
    type_section(
        b"\x5F" + vec([
            bytes([HT_EXN]) + b"\x00",        # exnref (0x69)
            bytes([HT_ARRAY]) + b"\x00",      # arrayref (0x6a)
            bytes([HT_STRUCT]) + b"\x01",     # structref (0x6b)
            bytes([HT_I31]) + b"\x00",        # i31ref (0x6c)
            bytes([HT_EQ]) + b"\x00",         # eqref (0x6d)
            bytes([HT_ANY]) + b"\x01",        # anyref (0x6e)
            bytes([0x6F]) + b"\x00",          # externref (0x6f)
            bytes([0x70]) + b"\x00",          # funcref (0x70)
            bytes([0x71]) + b"\x00",          # none (0x71)
            bytes([0x72]) + b"\x00",          # noextern (0x72)
            bytes([0x73]) + b"\x00",          # nofunc (0x73)
            bytes([0x74]) + b"\x00",          # noexn (0x74)
            ref_null(HT_FUNC) + b"\x00",      # (ref null func)
            ref_(HT_EXTERN) + b"\x01",        # (ref extern)
            ref_null(HT_ANY) + b"\x00",       # (ref null any)
        ]),
        functype([], [])),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([END]),
))

# =============================================================================================
# struct instructions
# =============================================================================================
write("E10_gc_struct_new_get_set.wasm", module(
    type_section(struct_type([(I32, True)]), functype([], [I32])),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([
        i32_const(7) + gc_op(0) + uleb(0) +          # i32.const 7; struct.new 0
        gc_op(2) + uleb(0) + uleb(0) +               # struct.get 0 0  -> i32
        drop() +
        i32_const(7) + gc_op(0) + uleb(0) +          # i32.const 7; struct.new 0
        i32_const(9) + gc_op(5) + uleb(0) + uleb(0) +  # i32.const 9; struct.set 0 0
        gc_op(1) + uleb(0) +                         # struct.new_default 0
        drop() +
        i32_const(3) + END]),
))

# E18: struct.get_s / struct.get_u on a packed-field struct
write("E18_gc_struct_get_su.wasm", module(
    type_section(struct_type([(0x78, True)]), functype([], [I32])),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([
        i32_const(7) + gc_op(0) + uleb(0) +
        gc_op(3) + uleb(0) + uleb(0) +               # struct.get_s 0 0
        drop() +
        i32_const(7) + gc_op(0) + uleb(0) +
        gc_op(4) + uleb(0) + uleb(0) +               # struct.get_u 0 0
        drop() +
        i32_const(0) + END]),
))

# =============================================================================================
# array instructions
# =============================================================================================

# E11: array.new / array.new_default / array.new_fixed / array.get / array.len
write("E11_gc_array_new_get_len.wasm", module(
    type_section(array_type(I32, True), functype([], [I32])),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([
        i32_const(5) + i32_const(3) + gc_op(6) + uleb(0) +      # array.new 0
        i32_const(0) + gc_op(11) + uleb(0) +                    # array.get 0
        drop() +
        i32_const(10) + gc_op(7) + uleb(0) +                    # i32.const 10; array.new_default 0
        gc_op(15) +                                             # array.len
        drop() +
        i32_const(1) + i32_const(2) + i32_const(3) +
        gc_op(8) + uleb(0) + uleb(3) +                          # array.new_fixed 0 3
        drop() +
        i32_const(0) + END]),
))

# E12: array.set / array.fill / array.copy
write("E12_gc_array_set_fill_copy.wasm", module(
    type_section(array_type(I32, True), functype([], [I32])),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([
        i32_const(5) + i32_const(3) + gc_op(6) + uleb(0) +      # array
        i32_const(1) + i32_const(42) + gc_op(14) + uleb(0) +    # array.set 0
        i32_const(5) + i32_const(3) + gc_op(6) + uleb(0) +      # array (dst)
        i32_const(0) + i32_const(7) + i32_const(2) +
        gc_op(16) + uleb(0) +                                   # array.fill 0
        i32_const(5) + i32_const(3) + gc_op(6) + uleb(0) +      # dst
        i32_const(0) +
        i32_const(5) + i32_const(3) + gc_op(6) + uleb(0) +      # src
        i32_const(0) + i32_const(3) +
        gc_op(17) + uleb(0) + uleb(0) +                         # array.copy 0 0
        i32_const(0) + END]),
))

# E13: packed array get_s / get_u (i8 array)
write("E13_gc_array_packed.wasm", module(
    type_section(array_type(0x78, True), functype([], [I32])),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([
        i32_const(5) + i32_const(3) + gc_op(6) + uleb(0) +
        i32_const(0) + gc_op(12) + uleb(0) +                    # array.get_s 0
        drop() +
        i32_const(5) + i32_const(3) + gc_op(6) + uleb(0) +
        i32_const(0) + gc_op(13) + uleb(0) +                    # array.get_u 0
        drop() +
        i32_const(0) + END]),
))

# =============================================================================================
# reference instructions
# =============================================================================================

# E14: ref.test (null + non-null), ref.cast (null + non-null), ref.i31, i31.get_s/u, ref.eq
write("E14_gc_ref_test_cast.wasm", module(
    type_section(struct_type([(I32, True)]), functype([], [I32])),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([
        b"\xD0" + bytes([HT_STRUCT]) + gc_op(0x14) + uleb(0) +  # ref.null structref; ref.test 0
        drop() +
        b"\xD0" + bytes([HT_STRUCT]) + gc_op(0x15) + uleb(0) +  # ref.test (ref null 0)
        drop() +
        b"\xD0" + bytes([HT_STRUCT]) + gc_op(0x16) + uleb(0) +  # ref.cast 0
        drop() +
        b"\xD0" + bytes([HT_STRUCT]) + gc_op(0x17) + uleb(0) +  # ref.cast (ref null 0)
        drop() +
        i32_const(5) + gc_op(0x1C) +                            # ref.i31
        gc_op(0x1D) +                                           # i31.get_s
        drop() +
        i32_const(5) + gc_op(0x1C) + gc_op(0x1E) +              # i31.get_u
        drop() +
        b"\xD0" + bytes([HT_EQ]) + b"\xD0" + bytes([HT_EQ]) + b"\xD3" +  # ref.eq
        drop() +
        i32_const(0) + END]),
))

# E15: br_on_cast / br_on_cast_fail around a block whose signature is the multi-byte valtype
#      (ref null struct) (0x63 0x6B). br_on_cast flags=0x01 (ht1 nullable), label 0,
#      ht1 = struct (0x6B), ht2 = type 0 (the struct type). Each block body leaves a
#      (ref null struct) (`ref.null struct`); the results are dropped and the function returns i32.
write("E15_gc_br_on_cast.wasm", module(
    type_section(struct_type([(I32, True)]), functype([], [I32])),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([
        block(ref_null(HT_STRUCT),
              b"\xD0" + bytes([HT_STRUCT]) +
              gc_op(0x18) + b"\x01" + uleb(0) + bytes([HT_STRUCT]) + sleb(0) +  # br_on_cast
              drop() + b"\xD0" + bytes([HT_STRUCT])) +
        drop() +
        block(ref_null(HT_STRUCT),
              b"\xD0" + bytes([HT_STRUCT]) +
              gc_op(0x19) + b"\x01" + uleb(0) + bytes([HT_STRUCT]) + sleb(0) +  # br_on_cast_fail
              drop() + b"\xD0" + bytes([HT_STRUCT])) +
        drop() +
        i32_const(0) + END]),
))

# E16: any.convert_extern / extern.convert_any
write("E16_gc_convert.wasm", module(
    type_section(functype([EXTERNREF], [I32])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        local_get(0) + gc_op(0x1A) +                            # any.convert_extern
        gc_op(0x1B) +                                          # extern.convert_any
        b"\xD1" +                                              # ref.is_null
        END]),
))

# =============================================================================================
# array.new_data / array.init_data / array.new_elem / array.init_elem
# =============================================================================================

# E17: data + element backed array instructions
write("E17_gc_array_data_elem.wasm", module(
    type_section(
        array_type(I32, True),            # type 0
        array_type(FUNCREF, True),        # type 1
        functype([], [I32])),             # type 2
    func_section([2]),
    export_section([("f", 0, 0)]),
    data_count_section(1),
    elem_section([passive_elem_funcs([0])]),
    code_section([
        i32_const(0) + i32_const(4) + gc_op(9) + uleb(0) + uleb(0) +   # array.new_data 0 0
        drop() +
        i32_const(5) + i32_const(3) + gc_op(6) + uleb(0) +             # array.new 0
        i32_const(0) + i32_const(0) + i32_const(4) +
        gc_op(0x12) + uleb(0) + uleb(0) +                              # array.init_data 0 0
        i32_const(0) + i32_const(1) + gc_op(0x0A) + uleb(1) + uleb(0) +  # array.new_elem 1 0
        drop() +
        i32_const(5) + i32_const(1) + gc_op(6) + uleb(1) +              # array.new 1 (funcref array)
        i32_const(0) + i32_const(0) + i32_const(1) +
        gc_op(0x13) + uleb(1) + uleb(0) +                              # array.init_elem 1 0
        i32_const(0) + END]),
))

# =============================================================================================
# mixed module: GC function type + struct/array types + call/br around GC instructions
# =============================================================================================

# E20: two functions; type 0 = struct(i32,i32), type 1 = array(i32), type 2 = (param anyref)->i32,
#      type 3 = ()->i32.  func 0 exercises call/br/ref.test around GC values; func 1 struct.new.
write("E20_gc_mixed.wasm", module(
    type_section(
        struct_type([(I32, False), (I32, True)]),        # 0
        array_type(I32, True),                           # 1
        functype([HT_ANY], [I32]),                       # 2
        functype([], [I32])),                            # 3
    func_section([2, 3]),
    export_section([("f", 0, 0), ("g", 0, 1)]),
    code_section([
        # func 0: (param anyref) -> i32
        block(I32,
              local_get(0) + gc_op(0x14) + uleb(0) +     # local.get 0; ref.test 0
              br(0)) +                                   # br 0 (block result i32)
        call(1) + b"\x6A" +                              # call 1; i32.add
        END,
        # func 1: ()->i32
        i32_const(1) + i32_const(2) + gc_op(0) + uleb(0) + drop() + i32_const(3) + END,
    ]),
))
