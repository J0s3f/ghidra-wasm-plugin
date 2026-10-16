#!/usr/bin/env python3
"""Probes for the JS string builtins / stringref opcodes (0xFB 0x80..0xB7), wide arithmetic
(0xFC 0x13..0x16) and memory.discard (0xFC 0x12), workstream H5.

Each module imports with `undefined_bytes == 0` and decompiles, and the listing must show the real
mnemonics with their operands (a memidx for the memory-taking forms, a string index for
string.const).

Awkward instructions here: `string.const $idx` reads the stringref proposal's string table (section
14, `stringrefs ::= 0x00 vec(vec(u8))`). This plugin's loader does not model that section, but it
skips unknown section ids cleanly (WasmSection.createSection returns null), so the sections below
carry a small string table and the module still imports.

Usage: python probes_strings.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])

# ---------------------------------------------------------------- helpers (local)

def str_op(n):
    """0xFB-prefixed string opcode (the numeric sub-opcode is LEB128-encoded, two bytes >= 0x80)."""
    return b"\xFB" + uleb(n)


def stringrefs_section(strings):
    """Section 14: 0x00 vec(vec(u8)). Skipped by this loader, but keeps the module spec-shaped."""
    return section(14, b"\x00" + vec([uleb(len(s)) + s for s in strings]))


def one_memory():
    return memory_section([(0x00, 1)])


END = b"\x0b"


# ---------------------------------------------------------------- S01: string.const / concat / eq
write("S01_str_const_concat_eq.wasm", module(
    type_section(functype([], [])),
    stringrefs_section([b"ab", b"cd"]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        (str_op(0x82) + uleb(0) + str_op(0x82) + uleb(1) + str_op(0x88) + drop()   # const; const; concat
             + str_op(0x82) + uleb(0) + str_op(0x82) + uleb(1) + str_op(0x89) + drop()  # const; const; eq
             + END),
    ]),
))

# ---------------------------------------------------------------- S02: new_utf8 / measure / encode
write("S02_str_new_measure_encode.wasm", module(
    type_section(functype([], [])),
    one_memory(),
    stringrefs_section([b"hello"]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        (i32_const(0) + i32_const(4) + str_op(0x80) + uleb(0) + drop()      # new_utf8 0
             + i32_const(0) + i32_const(4) + str_op(0x81) + uleb(0) + drop()    # new_wtf16 0
             + i32_const(0) + i32_const(4) + str_op(0x8B) + uleb(0) + drop()    # new_lossy_utf8 0
             + i32_const(0) + i32_const(4) + str_op(0x8C) + uleb(0) + drop()    # new_wtf8 0
             + str_op(0x82) + uleb(0) + str_op(0x83) + drop()                   # const; measure_utf8
             + str_op(0x82) + uleb(0) + str_op(0x84) + drop()                   # const; measure_wtf8
             + str_op(0x82) + uleb(0) + str_op(0x85) + drop()                   # const; measure_wtf16
             + str_op(0x82) + uleb(0) + str_op(0x8A) + drop()                   # const; is_usv_sequence
             + str_op(0x82) + uleb(0) + i32_const(0) + str_op(0x86) + uleb(0) + drop()   # const; ptr; encode_utf8
             + str_op(0x82) + uleb(0) + i32_const(0) + str_op(0x87) + uleb(0) + drop()   # encode_wtf16
             + str_op(0x82) + uleb(0) + i32_const(0) + str_op(0x8D) + uleb(0) + drop()   # encode_lossy_utf8
             + str_op(0x82) + uleb(0) + i32_const(0) + str_op(0x8E) + uleb(0) + drop()   # encode_wtf8
             + END),
    ]),
))

# ---------------------------------------------------------------- S03: stringview_wtf8
write("S03_str_view_wtf8.wasm", module(
    type_section(functype([], [])),
    one_memory(),
    stringrefs_section([b"hello"]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        (str_op(0x82) + uleb(0) + str_op(0x90) + drop()                         # const; as_wtf8
             + str_op(0x82) + uleb(0) + str_op(0x90) + i32_const(0) + i32_const(4)  # view pos bytes
             + str_op(0x91) + drop()                                                # advance
             + str_op(0x82) + uleb(0) + str_op(0x90) + i32_const(0) + i32_const(4)  # view start end
             + str_op(0x93) + drop()                                                # slice
             + str_op(0x82) + uleb(0) + str_op(0x90) + i32_const(0) + i32_const(0) + i32_const(4)
             + str_op(0x92) + uleb(0) + b"\x6A" + drop()                            # encode_utf8: add the 2 results
             + str_op(0x82) + uleb(0) + str_op(0x90) + i32_const(0) + i32_const(0) + i32_const(4)
             + str_op(0x94) + uleb(0) + drop() + drop()                             # encode_lossy_utf8
             + str_op(0x82) + uleb(0) + str_op(0x90) + i32_const(0) + i32_const(0) + i32_const(4)
             + str_op(0x95) + uleb(0) + drop() + drop()                             # encode_wtf8
             + END),
    ]),
))

# ---------------------------------------------------------------- S04: stringview_wtf16
write("S04_str_view_wtf16.wasm", module(
    type_section(functype([], [])),
    one_memory(),
    stringrefs_section([b"hello"]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        (str_op(0x82) + uleb(0) + str_op(0x98) + drop()                         # const; as_wtf16
             + str_op(0x82) + uleb(0) + str_op(0x98) + str_op(0x99) + drop()        # length
             + str_op(0x82) + uleb(0) + str_op(0x98) + i32_const(0) + str_op(0x9A) + drop()   # get_codeunit
             + str_op(0x82) + uleb(0) + str_op(0x98) + i32_const(0) + i32_const(0) + i32_const(4)
             + str_op(0x9B) + uleb(0) + drop()                                      # encode
             + str_op(0x82) + uleb(0) + str_op(0x98) + i32_const(0) + i32_const(2)  # view start end
             + str_op(0x9C) + drop()                                                # slice
             + END),
    ]),
))

# ---------------------------------------------------------------- S05: stringview_iter
write("S05_str_view_iter.wasm", module(
    type_section(functype([], [])),
    stringrefs_section([b"hello"]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        (str_op(0x82) + uleb(0) + str_op(0xA0) + drop()                         # const; as_iter
             + str_op(0x82) + uleb(0) + str_op(0xA0) + str_op(0xA1) + drop()        # next
             + str_op(0x82) + uleb(0) + str_op(0xA0) + i32_const(2) + str_op(0xA2) + drop()   # advance
             + str_op(0x82) + uleb(0) + str_op(0xA0) + i32_const(1) + str_op(0xA3) + drop()   # rewind
             + str_op(0x82) + uleb(0) + str_op(0xA0) + i32_const(2) + str_op(0xA4) + drop()   # slice
             + END),
    ]),
))

# ---------------------------------------------------------------- S06: GC array <-> string
def ref_null_array():
    """ref.null array (heaptype array = 0x6a) - the arrayref operand of the *_array ops."""
    return b"\xD0" + sleb(HT_ARRAY - 0x80)


write("S06_str_arrays.wasm", module(
    type_section(functype([], [])),
    stringrefs_section([b"hello"]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        (ref_null_array() + i32_const(0) + i32_const(4) + str_op(0xB0) + drop()      # new_utf8_array
             + ref_null_array() + i32_const(0) + i32_const(4) + str_op(0xB1) + drop()    # new_wtf16_array
             + ref_null_array() + i32_const(0) + i32_const(4) + str_op(0xB4) + drop()    # new_lossy_utf8_array
             + ref_null_array() + i32_const(0) + i32_const(4) + str_op(0xB5) + drop()    # new_wtf8_array
             + str_op(0x82) + uleb(0) + ref_null_array() + i32_const(0) + str_op(0xB2) + drop()  # encode_utf8_array
             + str_op(0x82) + uleb(0) + ref_null_array() + i32_const(0) + str_op(0xB3) + drop()  # encode_wtf16_array
             + str_op(0x82) + uleb(0) + ref_null_array() + i32_const(0) + str_op(0xB6) + drop()  # encode_lossy_utf8_array
             + str_op(0x82) + uleb(0) + ref_null_array() + i32_const(0) + str_op(0xB7) + drop()  # encode_wtf8_array
             + END),
    ]),
))

# ---------------------------------------------------------------- S07: wide arithmetic + memory.discard
# i64.add128 / sub128: [i64 i64 i64 i64] -> [i64 i64]; mul_wide_s/u: [i64 i64] -> [i64 i64];
# memory.discard: [addr size] -> [].
write("S07_wide_memdiscard.wasm", module(
    type_section(functype([], [])),
    one_memory(),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        (i64_const(1) + i64_const(0) + i64_const(2) + i64_const(0)
             + misc_op(0x13) + drop() + drop()                                  # i64.add128
             + i64_const(5) + i64_const(0) + i64_const(1) + i64_const(0)
             + misc_op(0x14) + drop() + drop()                                  # i64.sub128
             + i64_const(6) + i64_const(7) + misc_op(0x15) + drop() + drop()    # i64.mul_wide_s
             + i64_const(6) + i64_const(7) + misc_op(0x16) + drop() + drop()    # i64.mul_wide_u
             + i32_const(0) + i32_const(16) + misc_op(0x12) + uleb(0)           # memory.discard memidx=0
             + END),
    ]),
))

# ---------------------------------------------------------------- S08: mixed with ordinary code
# Ordinary arithmetic around string and wide arithmetic ops, so a wrong immediate length shows up
# as a spurious instruction or undefined bytes.
write("S08_strings_mixed.wasm", module(
    type_section(functype([], []), functype([I32], [I32])),
    one_memory(),
    stringrefs_section([b"mixed"]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        (i32_const(1) + i32_const(2) + b"\x6A" + drop()
             + str_op(0x82) + uleb(0) + str_op(0x83) + drop()                   # const; measure_utf8
             + i32_const(0) + i32_const(4) + str_op(0x80) + uleb(0) + drop()    # new_utf8 memidx=0
             + i64_const(1) + i64_const(2) + misc_op(0x16) + drop() + drop()    # i64.mul_wide_u
             + i32_const(0) + i32_const(8) + misc_op(0x12) + uleb(0)            # memory.discard
             + i32_const(3) + i32_const(4) + b"\x6A" + drop()
             + END),
    ]),
))

# ---------------------------------------------------------------- S09: reserved sub-opcodes
# Every byte in 0x80..0xB7 decodes: the unassigned sub-opcodes (0x8F, 0x9E here) render as
# `unimplemented 0xfb:NN string (reserved)` with no immediates, so the following ordinary code
# still decodes (undefined_bytes == 0).
write("S09_str_reserved.wasm", module(
    type_section(functype([], [])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        (i32_const(1) + drop()
             + str_op(0x8F) + drop()            # reserved (would need no operand if defined)
             + str_op(0x9E) + i32_const(2) + drop()
             + END),
    ]),
))

# ---------------------------------------------------------------- S10: the two encode results reach the caller
# stringview_wtf8.encode_utf8 returns (next_pos, bytes). The function returns i32, so the
# decompiler must show both results of the single callother (its 8-byte output is split into the
# two i32 result slots) rather than dropping them.
write("S10_str_encode_units.wasm", module(
    type_section(functype([], [I32])),
    one_memory(),
    stringrefs_section([b"hello"]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        (str_op(0x82) + uleb(0) + str_op(0x90)          # const; as_wtf8 -> view
             + i32_const(0) + i32_const(0) + i32_const(4)
             + str_op(0x92) + uleb(0)                    # encode_utf8 -> (next_pos, bytes)
             + b"\x6A"                                   # i32.add of the two results
             + END),
    ]),
))
