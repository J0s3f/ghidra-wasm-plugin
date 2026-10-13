#!/usr/bin/env python3
"""Probes for the dedicated `memory` address space (feat/memory-space).

Before the dedicated space, linear memory N was placed at N * MEMORY_STRIDE in the
32-bit `ram` space, which also holds the module at CODE_BASE (0x80000000). Memory 8
landed exactly on the code base and could not be created (the loader logged the
failure), and the 32-bit space could not hold many memories at 256 MiB stride.

With the dedicated 64-bit `memory` space (WebAssembly.slaspec: `define space memory
type=ram_space size=8`), memory index >= 8 no longer collides with the code. The
SLEIGH memory accesses now target `*[memory]:N addr` instead of `*:N addr`, and the
loader creates memory blocks in the `memory` space.

These probes verify:
  MS_01  10 memories, read/write memory 9 (the first index that used to collide
         with CODE_BASE). Must import, create blocks, and decode with
         undefined_bytes=0.
  MS_02  17 memories, read/write memory 16 (well past the old 8-memory limit).
         Validates that the 64-bit space holds many memories.
  MS_03  10 memories with data segments into memory 9, verifying data-segment
         placement lands in the `memory` space at the right offset.

Usage: python probes_memspace.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])


def memarg(align, memidx=None, offset=0):
    """Encode a memarg immediate (core spec, binary/instructions.html#binary-memarg).

    A memory index is present when bit 6 of the flags/alignment value is set:
    flags = align | 0x40, then memidx, then offset.
    """
    if memidx is None:
        return uleb(align) + uleb(offset)
    return uleb(align | 0x40) + uleb(memidx) + uleb(offset)


def memories_with_blocks(count, *nonzero):
    """`count` 32-bit memories (memidx 0..count-1).

    Only the indices in `nonzero` get a non-zero initial size; the rest declare
    zero pages. A zero-page memory materialises no block, which keeps the probe's
    address map to exactly the blocks it needs.
    """
    return memory_section([(0x00, 1 if i in nonzero else 0) for i in range(count)])


# =============================================================================================
# MS_01: 10 memories, read/write memory 9 (the first index that used to collide)
# =============================================================================================

# (func (param i32) (result i32)
#   local.get 0
#   i32.load   align=2 memidx=9 offset=0     ;; load from memory 9
#   local.get 0
#   i32.const 42
#   i32.store  align=2 memidx=9 offset=4     ;; store to memory 9
#   i32.const 0
#   i32.load   align=2 memidx=0 offset=0     ;; also access memory 0
#   ;; stack: [load_from_mem9, load_from_mem0] -> need to return only one
#   drop                                          ;; drop the mem0 load result
# )
write("MS_01_mem9_load_store.wasm", module(
    type_section(functype([I32], [I32])),
    func_section([0]),
    memories_with_blocks(10, 0, 9),
    export_section([("f", 0, 0)]),
    code_section([
        local_get(0) + b"\x28" + memarg(2, 9) +            # i32.load align=2 memidx=9 off=0
        local_get(0) + i32_const(42) + b"\x36" + memarg(2, 9, offset=4) +  # i32.store memidx=9 off=4
        i32_const(0) + b"\x28" + memarg(2, 0) +            # i32.load memidx=0 off=0
        drop() +                                            # drop the mem0 result, keep mem9 result
        END
    ]),
))

# =============================================================================================
# MS_02: 17 memories, read/write memory 16 (well past the old 8-memory limit)
# =============================================================================================

# (func (result i32)
#   i32.const 0
#   i32.load align=2 memidx=16 offset=0
# )
write("MS_02_mem16_load.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    memories_with_blocks(17, 0, 16),
    export_section([("f", 0, 0)]),
    code_section([
        i32_const(0) + b"\x28" + memarg(2, 16) +           # i32.load align=2 memidx=16 off=0
        END
    ]),
))

# =============================================================================================
# MS_03: 10 memories with data segments into memory 9
# =============================================================================================

# (memory 10) (data (memory 9) (i32.const 0) "ABCD") (data (memory 0) (i32.const 0) "WXYZ")
# (func (result i32) i32.const 0; i32.load memidx=9 off=0)
write("MS_03_mem9_data_segment.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    memories_with_blocks(10, 0, 9),
    export_section([("f", 0, 0)]),
    code_section([
        i32_const(0) + b"\x28" + memarg(2, 9) +            # i32.load align=2 memidx=9 off=0
        END
    ]),
    data_section([
        active_data(i32_const(0) + END, b"ABCD", memidx=9),       # data into memory 9 at offset 0
        active_data(i32_const(0) + END, b"WXYZ", memidx=0),       # data into memory 0 at offset 0
    ]),
))
