#!/usr/bin/env python3
"""Probes owned by the memory64 workstream (agent N).

64-bit linear memories (`(memory i64 N)`, limits flag bit 2 set) put an *i64* on the stack
where a 32-bit memory has an i32: the memarg/address operand of every load and store, the
delta and result of memory.grow, the result of memory.size, and the length/destination
operands of memory.fill / memory.init / memory.copy (core spec, valid/instructions.html).

That width is a property of the *memory declaration*, not of the instruction byte stream, so
it cannot be decoded by SLEIGH alone: WasmFunctionAnalysis records it in the ctx_mem64
context register and the SLEIGH memarg/memory constructors pick the matching operand width.

These probes pin

  M64_01  the baseline case (the frozen probe 05 in `gen_feature_probes.py` is the same
          shape; its metric must drop from undefined_bytes=6 to 0),
  M64_02  i32/i64/f32/f64 loads and stores through a 64-bit memory,
  M64_03  memory.size / memory.grow with a 64-bit memory (i64 -> i64),
  M64_04  memory.fill / memory.init / memory.copy with a 64-bit memory,
  M64_05  64-bit memory 0 + 32-bit memory 1 (flagged memarg with memidx 0 and 1),
  M64_06  32-bit memory 0 + 64-bit memory 1 (the mixed case),
  M64_07  a 64-bit memory with a > 4 GiB static offset (the truncation limit),
  M64_08  SIMD/atomic memargs (loadaddr2 / atomicaddr3) with a 64-bit index.

Unlike the frozen generators, these modules are emitted with the sections in the order the
core spec requires (type, function, memory, export, data count, code, data), so they can be
validated independently with `wasmtime.Module(...)`; every module here passes that check.

Recorded metrics (Ghidra 12.1.4, this worktree; also in REPORT-N.md and
test-scripts/expected-results.json):

    probe                              funcs instrs undefined_bytes decompiled
    M64_01_baseline_i64_load               1      4        0          1/0
    M64_02_scalar_loads_stores             1     28        0          1/0
    M64_03_memory_size_grow                1      6        0          1/0
    M64_04_bulk_memory                     1     15        0          1/0
    M64_05_i64_then_i32_memidx             1     13        0          1/0
    M64_06_i32_then_i64_memidx             1     11        0          1/0
    M64_07_large_static_offset             1      7        0          1/0
    M64_08_simd_atomic                     1     17        0          1/0

Every probe also creates its `.memoryN` block(s) (65536 bytes for one page), and each listing
marks the 64-bit-indexed form with `" (i64 index)"`.

Usage: python probes_memory64.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])


def memarg(align, memidx=None, offset=0):
    """Encode a memarg immediate.

    A memory index is present when bit 6 of the flags/alignment value is set (core spec,
    binary/instructions.html#binary-memarg): flags = align | 0x40, then memidx, then offset.
    The offset is a u32 for a 32-bit memory and a u64 for a 64-bit one.
    """
    if memidx is None:
        return uleb(align) + uleb(offset)
    return uleb(align | 0x40) + uleb(memidx) + uleb(offset)


# ---------------------------------------------------------------------------------------------
# M64_01: baseline shape of the frozen probe 05 - one 64-bit memory, an i64 address operand.
# ---------------------------------------------------------------------------------------------
write("M64_01_baseline_i64_load.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    memory_section([(0x04, 1)]),                      # flags=4 -> 64-bit index, no maximum
    export_section([("f", 0, 0)]),
    code_section([i64_const(0) + b"\x28" + memarg(2) + END]),   # i64.const 0; i32.load align=2 off=0
))

# ---------------------------------------------------------------------------------------------
# M64_02: every scalar width through a 64-bit memory (i32/i64/f32/f64 loads and stores,
# load8_u). The address operand of each instruction is the memory's i64 index type.
# (func (param i64) (result i32))
# ---------------------------------------------------------------------------------------------
write("M64_02_scalar_loads_stores.wasm", module(
    type_section(functype([I64], [I32])),
    func_section([0]),
    memory_section([(0x04, 1)]),
    export_section([("f", 0, 0)]),
    code_section([
        local_get(0) + b"\x29" + memarg(3, offset=0x10) + drop() +     # i64.load  align=3 off=0x10
        local_get(0) + b"\x2D" + memarg(0, offset=0x20) + drop() +     # i32.load8_u align=0 off=0x20
        local_get(0) + b"\x2A" + memarg(2, offset=0x24) + drop() +     # f32.load  align=2 off=0x24
        local_get(0) + b"\x2B" + memarg(3, offset=0x28) + drop() +     # f64.load  align=3 off=0x28
        local_get(0) + i32_const(7) + b"\x36" + memarg(2, offset=0x30) +    # i32.store align=2 off=0x30
        local_get(0) + i64_const(8) + b"\x37" + memarg(3, offset=0x38) +    # i64.store align=3 off=0x38
        local_get(0) + f32_const(1.5) + b"\x38" + memarg(2, offset=0x40) +  # f32.store align=2 off=0x40
        local_get(0) + f64_const(2.5) + b"\x39" + memarg(3, offset=0x48) +  # f64.store align=3 off=0x48
        local_get(0) + b"\x28" + memarg(2, offset=0x50) +              # i32.load  align=2 off=0x50 (result)
        END
    ]),
))

# ---------------------------------------------------------------------------------------------
# M64_03: memory.size / memory.grow on a 64-bit memory: both are i64-typed.
# (func (param i64) (result i64) local.get 0; memory.grow 0; drop; memory.size 0)
# ---------------------------------------------------------------------------------------------
write("M64_03_memory_size_grow.wasm", module(
    type_section(functype([I64], [I64])),
    func_section([0]),
    memory_section([(0x05, 1, 4)]),                   # 64-bit index + maximum (flags 0x05)
    export_section([("f", 0, 0)]),
    code_section([
        local_get(0) + b"\x40" + uleb(0) + drop() +   # memory.grow 0   (i64 delta -> i64)
        b"\x3F" + uleb(0) +                           # memory.size 0   (-> i64, result)
        END
    ]),
))

# ---------------------------------------------------------------------------------------------
# M64_04: bulk memory with a 64-bit memory.
#   memory.init 0 0 : [at i32 i32]  (destination offset is i64, source/len stay i32)
#   memory.fill 0   : [at i32 at]
#   memory.copy 0 0 : [at1 at2 min(at1,at2)]
# (func (param i64 i64 i64) (result i64))
# ---------------------------------------------------------------------------------------------
write("M64_04_bulk_memory.wasm", module(
    type_section(functype([I64, I64, I64], [I64])),
    func_section([0]),
    memory_section([(0x04, 1)]),
    export_section([("f", 0, 0)]),
    data_count_section(1),
    code_section([
        local_get(0) + i32_const(0) + i32_const(3) + misc_op(8) + uleb(0) + uleb(0) +
        local_get(0) + i32_const(65) + local_get(2) + misc_op(11) + uleb(0) +
        local_get(0) + local_get(1) + local_get(2) + misc_op(10) + uleb(0) + uleb(0) +
        b"\x3F" + uleb(0) +                           # memory.size 0 (i64 result)
        END
    ]),
    data_section([passive_data(b"abc")]),
))

# ---------------------------------------------------------------------------------------------
# M64_05: 64-bit memory 0 + 32-bit memory 1, so the two instructions in the same body have
# *different* address-operand widths (unflagged memarg addresses memory 0, the flagged form
# with memidx=1 addresses memory 1).
# (func (param i64 i32) (result i32))
# ---------------------------------------------------------------------------------------------
write("M64_05_i64_then_i32_memidx.wasm", module(
    type_section(functype([I64, I32], [I32])),
    func_section([0]),
    memory_section([(0x04, 1), (0x00, 1)]),           # memory 0 = memory64, memory 1 = i32
    export_section([("f", 0, 0)]),
    code_section([
        local_get(0) + b"\x28" + memarg(2) +                       # i32.load mem 0 (i64 address)
        local_get(1) + b"\x28" + memarg(2, 1) + b"\x6A" +          # + i32.load memidx=1 (i32 address)
        local_get(0) + i32_const(1) + b"\x36" + memarg(2) +        # i32.store mem 0 (i64 address)
        local_get(1) + i32_const(2) + b"\x36" + memarg(2, 1) +     # i32.store memidx=1 (i32 address)
        END
    ]),
))

# ---------------------------------------------------------------------------------------------
# M64_06: the mixed case the other way round - memory 0 is 32-bit, memory 1 is 64-bit, and a
# flagged memarg with memidx=1 must take an i64 address while memidx=0 stays i32.
# (func (param i32 i64) (result i32))
# ---------------------------------------------------------------------------------------------
write("M64_06_i32_then_i64_memidx.wasm", module(
    type_section(functype([I32, I64], [I32])),
    func_section([0]),
    memory_section([(0x00, 1), (0x04, 1)]),
    export_section([("f", 0, 0)]),
    code_section([
        local_get(0) + b"\x28" + memarg(2) +                       # i32.load mem 0 (i32 address)
        local_get(1) + b"\x28" + memarg(2, 1) + b"\x6A" +          # + i32.load memidx=1 (i64 address)
        b"\x3F" + uleb(1) + drop() +                               # memory.size 1 -> i64 (dropped)
        b"\x3F" + uleb(0) + drop() +                               # memory.size 0 -> i32 (dropped)
        END
    ]),
))

# ---------------------------------------------------------------------------------------------
# M64_07: a 64-bit memory with a static memarg offset above 4 GiB. The offset itself decodes
# as a u64 (5-byte LEB here); the *effective* address is computed in 64 bits and truncated
# into the 32-bit `ram` space, so the 4 GiB bit leaves no trace in the computed address
# (documented limit, see REPORT-N.md). The offset must not desync the byte stream.
# (func (result i32))
# ---------------------------------------------------------------------------------------------
write("M64_07_large_static_offset.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    memory_section([(0x04, 1)]),
    export_section([("f", 0, 0)]),
    code_section([
        i64_const(0) + b"\x28" + memarg(2, offset=0x12345678) + drop() +    # a large u32 offset
        i64_const(0) + b"\x28" + memarg(2, offset=0x100000000) +            # exactly 4 GiB
        END
    ]),
))

# ---------------------------------------------------------------------------------------------
# M64_08: SIMD and atomic memargs through a 64-bit memory.
#   v128.load       (loadaddr)  : [at] -> [v128]
#   v128.load8_lane (loadaddr2) : [at v128] -> [v128]
#   i32.atomic.rmw.add          : [at i32] -> i32      (uses loadaddr/storeaddr)
#   i32.atomic.rmw.cmpxchg      : [at i32 i32] -> i32  (uses atomicaddr3)
# Atomic instructions require a shared memory, so this module declares one (64-bit + shared
# + maximum = flags 0x07).
# (func (param i64 i64) (result i32))
# ---------------------------------------------------------------------------------------------
write("M64_08_simd_atomic.wasm", module(
    type_section(functype([I64, I64], [I32])),
    func_section([0]),
    memory_section([(0x07, 1, 4)]),                   # shared + 64-bit + maximum
    export_section([("f", 0, 0)]),
    code_section([
        local_get(0) + simd_op(0x00) + memarg(4) + drop() +                 # v128.load
        local_get(0) + v128_const(bytes(16)) + simd_op(0x54) + memarg(0) + bytes([0]) + drop() +
        local_get(0) + i32_const(5) + atomic_op(0x1E) + memarg(2) + drop() +        # i32.atomic.rmw.add
        local_get(0) + i32_const(1) + i32_const(2) + atomic_op(0x48) + memarg(2) +  # i32.atomic.rmw.cmpxchg
        END
    ]),
))
