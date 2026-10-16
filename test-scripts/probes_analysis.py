#!/usr/bin/env python3
"""Probes owned by the *decoder/loader* workstream (workstream A).

Add new probes here - never edit `gen_feature_probes.py` (frozen baseline) or `probes_types.py`
(owned by the other workstream). Use the helpers from `wasm_probe_lib`:

    write("A01_multi_memory_memidx.wasm", module(...))

Each probe should be a *valid* module for the feature it exercises, and its expected result should be
written down in REPORT-A.md (funcs / instrs / undefined_bytes / decompiled, plus the disassembly when
decode correctness is the point).

Usage: python probes_analysis.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])

# ---------------------------------------------------------------------------------------------
# Multi-memory (R1.4) and unknown-opcode degradation (R1.1) probes.
#
#   A01-A04  multi-memory: memarg with a memory index (scalar, SIMD, atomic), the
#            memory.init/copy/fill memidx operands, and the loader's per-memory blocks.
#   A05-A09  unknown opcodes: each body is "<unknown instruction>; i32.const 1; drop; end",
#            so the disassembly must show the unknown one as `unimplemented` and the three
#            following instructions intact with undefined_bytes == 0.
# ---------------------------------------------------------------------------------------------


def memarg(align, memidx=None, offset=0):
    """Encode a memarg immediate.

    A memory index is present when bit 6 of the flags/alignment value is set (core spec,
    binary/instructions.html#binary-memarg): flags = align | 0x40, then memidx, then offset.
    """
    if memidx is None:
        return uleb(align) + uleb(offset)
    return uleb(align | 0x40) + uleb(memidx) + uleb(offset)


def two_memories():
    return memory_section([(0x00, 1), (0x00, 1)])


# A01: every scalar load/store width against memory 1 (i32/i64/f32/f64, load8_u), memory 0 unset.
write("A01_mm_scalar_memarg.wasm", module(
    type_section(functype([I32], [I32])),
    two_memories(),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        local_get(0) + b"\x28" + memarg(2, 1) +        # i32.load  align=2 memidx=1 off=0  -> i32 (result)
        local_get(0) + b"\x29" + memarg(3, 1) + drop() +   # i64.load  align=3 memidx=1
        local_get(0) + b"\x2D" + memarg(0, 1) + drop() +   # i32.load8_u align=0 memidx=1
        local_get(0) + b"\x2A" + memarg(2, 1) + drop() +   # f32.load  align=2 memidx=1
        local_get(0) + b"\x2B" + memarg(3, 1) + drop() +   # f64.load  align=3 memidx=1
        local_get(0) + i32_const(7) + b"\x36" + memarg(2, 1) +   # i32.store align=2 memidx=1
        local_get(0) + i64_const(8) + b"\x37" + memarg(3, 1) +   # i64.store align=3 memidx=1
        local_get(0) + b"\x2D" + memarg(0, 0) + drop() +   # i32.load8_u memidx=0 (plain mix)
        END
    ]),
))

# A02: SIMD and atomic loads with a memory index (v128.load, v128.load8_lane, i32.atomic.load).
write("A02_mm_simd_atomic_memarg.wasm", module(
    type_section(functype([I32], [])),
    two_memories(),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        local_get(0) + simd_op(0x00) + memarg(4, 1) + drop() +          # v128.load align=4 memidx=1
        local_get(0) + v128_const(bytes(16)) + simd_op(0x54) + memarg(0, 1) + bytes([0]) + drop() +
        local_get(0) + atomic_op(0x10) + memarg(2, 1) + drop() +        # i32.atomic.load align=2 memidx=1
        END
    ]),
))

# A03: bulk-memory instructions whose memidx operand is non-zero, plus a passive data segment.
write("A03_mm_memory_ops.wasm", module(
    type_section(functype([], [])),
    two_memories(),
    func_section([0]),
    export_section([("f", 0, 0)]),
    data_count_section(1),
    code_section([
        i32_const(0) + i32_const(0) + i32_const(0) + misc_op(8) + uleb(0) + uleb(1) +  # memory.init 0 memidx=1
        i32_const(0) + i32_const(0) + i32_const(0) + misc_op(10) + uleb(1) + uleb(0) +  # memory.copy 1 -> 0
        i32_const(0) + i32_const(0) + i32_const(0) + misc_op(11) + uleb(1) +            # memory.fill memidx=1
        END
    ]),
    data_section([passive_data(b"abc")]),
))

# A04: three memories (0..2) with different sizes; the block sizes are checked via PROBE-BLOCK.
# Also loads from memory 2, i.e. from the third block.
write("A04_mm_three_memories.wasm", module(
    type_section(functype([I32], [I32])),
    memory_section([(0x00, 1), (0x00, 2), (0x00, 3)]),  # 65536 / 131072 / 196608 bytes
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        local_get(0) + b"\x28" + memarg(2, 2) +         # i32.load align=2 memidx=2 off=0
        local_get(0) + b"\x28" + memarg(2, 1) + b"\x6A" +   # + i32.load align=2 memidx=1
        END
    ]),
))

# A05-A09: unknown opcodes. Each is followed by i32.const 1; drop; end, so a decode that
# consumes the wrong number of bytes is immediately visible (spurious instructions).
def _tail():
    return i32_const(1) + drop() + END


def _unimp_module(body):
    return module(
        type_section(functype([], [])),
        func_section([0]),
        export_section([("f", 0, 0)]),
        code_section([body]),
    )


# A05: stack switching, cont.new (0xE0) with one typeidx immediate.
write("A05_unimp_cont_new.wasm", _unimp_module(b"\xE0" + uleb(0) + _tail()))

# A06: JS string builtins, string.new_utf8 (0xFB 0x80) with one memidx immediate.
write("A06_unimp_string_new_utf8.wasm", _unimp_module(gc_op(0x80) + uleb(0) + _tail()))

# A07: memory.discard (0xFC 0x12) with one memidx immediate.
write("A07_unimp_memory_discard.wasm", _unimp_module(misc_op(0x12) + uleb(0) + _tail()))

# A08: stack switching, cont.bind (0xE1) with two typeidx immediates.
write("A08_unimp_cont_bind.wasm", _unimp_module(b"\xE1" + uleb(0) + uleb(0) + _tail()))

# A09: wide arithmetic, i64.mul_wide_u (0xFC 0x16), no immediates.
write("A09_unimp_mul_wide_u.wasm", _unimp_module(misc_op(0x16) + _tail()))

# A10: the stack model after an unimplemented instruction is unknown, so a validation error it
# causes (here i32.add with an empty stack) must not blank the body: the whole function still
# disassembles (undefined_bytes == 0) and decompiles.
write("A10_unimp_then_stack_error.wasm", _unimp_module(b"\xE0" + uleb(0) + b"\x6A" + _tail()))
