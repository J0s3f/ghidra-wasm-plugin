#!/usr/bin/env python3
"""Probes owned by the memidx/table64 workstream (agent H4).

Two loader/decoder gaps (see MODERN_WASM_GAPS.md and the open-items list):

  B3  multi-memory memarg with a memory index. A load/store memarg whose alignment
      field has bit 6 set (0x40) carries a ULEB memidx before the offset. The walker
      must consume it and the listing must show the right index with no shifted
      boundaries. Probes here use indices 9, 127, 128 (two-byte LEB) and 1000.

  B8  table64 and >4 GiB memory64.
      (a) a table whose limits flags carry bit 0x04 (64-bit table index) must be
          decoded, recorded and not desync the entries that follow.
      (b) a memory64 declaration with an initial size > 4 GiB must import with a clear
          diagnostic (no OOM, no silent nonsense) and the code section must still
          decode (undefined_bytes=0).

Usage: python probes_memidx_table64.py <output-dir>
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
    flags = align | 0x40, then memidx, then offset. The offset is a u32 for a 32-bit
    memory and a u64 for a 64-bit one.
    """
    if memidx is None:
        return uleb(align) + uleb(offset)
    return uleb(align | 0x40) + uleb(memidx) + uleb(offset)


def memories_with_blocks(count, *nonzero):
    """`count` 32-bit memories (memidx 0..count-1).

    Only the indices in `nonzero` get a non-zero initial size; the rest declare zero pages.
    A zero-page memory materialises no block (`WasmLoader.createMemoryBlock` returns early),
    which keeps the probe's address map to exactly the blocks it needs: the loader maps
    memory N at N * MEMORY_STRIDE and clamps indices >= 16 (16 * 256 MiB > 4 GiB) to the top
    of the 32-bit `ram` space, so declaring 1001 one-page memories would log ~1000 failed
    block creations. Index 9 is given a page so a block is mapped *above* the module image
    (0x90000000 > CODE_BASE) - the condition that used to break the analysis re-parse.
    """
    return memory_section([(0x00, 1 if i in nonzero else 0) for i in range(count)])


# =============================================================================================
# B3 - multi-memory memarg, memory index >= 9
# =============================================================================================

# B3_01: memidx 9 (single-byte LEB). Ten memories so index 9 is valid.
# (func (result i32) i32.const 0; i32.load align=2 memidx=9 off=0)
write("B3_01_memidx9_load.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    memories_with_blocks(10, 0, 9),
    export_section([("f", 0, 0)]),
    code_section([
        i32_const(0) + b"\x28" + memarg(2, 9) +   # i32.load align=2 memidx=9 off=0
        END
    ]),
))

# B3_02: memidx 127 (single-byte LEB, the largest one-byte index).
write("B3_02_memidx127_store.wasm", module(
    type_section(functype([I32], [])),
    func_section([0]),
    memories_with_blocks(128, 0, 9),
    export_section([("f", 0, 0)]),
    code_section([
        local_get(0) + i32_const(1) + b"\x36" + memarg(2, 127) +   # i32.store align=2 memidx=127 off=0
        END
    ]),
))

# B3_03: memidx 128 (two-byte LEB 0x80 0x01).
write("B3_03_memidx128_load.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    memories_with_blocks(129, 0, 9),
    export_section([("f", 0, 0)]),
    code_section([
        i32_const(0) + b"\x28" + memarg(2, 128) +   # i32.load align=2 memidx=128 off=0
        END
    ]),
))

# B3_04: memidx 1000 (two-byte LEB 0xE8 0x07), a load and a store in one body.
write("B3_04_memidx1000_load_store.wasm", module(
    type_section(functype([I32], [I32])),
    func_section([0]),
    memories_with_blocks(1001, 0, 9),
    export_section([("f", 0, 0)]),
    code_section([
        i32_const(0) + b"\x28" + memarg(2, 1000, offset=4) +          # i32.load memidx=1000 off=4
        local_get(0) + b"\x36" + memarg(2, 1000, offset=8) +          # i32.store memidx=1000 off=8
        i32_const(0) + b"\x28" + memarg(2, 0) +                       # i32.load memidx=0 (unflagged, 2 LEBs)
        END
    ]),
))


# =============================================================================================
# B8 - table64 and >4 GiB memory64
# =============================================================================================

def elem_active(tableidx, offset_expr, funcidxs):
    """Active element segment (flags 0x02): explicit table index, offset expr, elemkind, funcidxs."""
    return (b"\x02" + uleb(tableidx) + offset_expr + END + b"\x00"
            + uleb(len(funcidxs)) + b"".join(uleb(f) for f in funcidxs))


# B8_01: a 64-bit table (table64: limits flag 0x04) with an active element segment. The segment's
# offset must be i64-typed because the table's index type is i64; the loader used to read only
# asI32() and silently dropped the segment.
# (table i64 2 funcref) (elem (i64.const 0) func 0)
write("B8_01_table64_elem.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    table_section([(FUNCREF, 0x04, 2)]),           # 64-bit index, initial 2
    export_section([("f", 0, 0)]),
    elem_section([elem_active(0, i64_const(0), [0])]),
    code_section([i32_const(0) + END]),
))

# B8_02: a table64 that declares 2^32 elements. Valid per table64 (the index type is i64), but far
# beyond what the loader materialises: it must be skipped with a diagnostic that names the 64-bit
# index type, and the code section must still decode.
write("B8_02_table64_huge_skipped.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    table_section([(FUNCREF, 0x04, 0x100000000)]),
    export_section([("f", 0, 0)]),
    code_section([i32_const(0) + END]),
))

# B8_03: a table64 followed by an ordinary 32-bit table (and an element segment on each), so the
# entries *after* a 64-bit table are shown not to mis-parse.
write("B8_03_table64_then_table32.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    table_section([(FUNCREF, 0x04, 1), (FUNCREF, 0x00, 2)]),   # table 0 = table64, table 1 = table32
    export_section([("f", 0, 0)]),
    elem_section([
        elem_active(0, i64_const(0), [0]),          # i64 offset -> table 0 (64-bit)
        elem_active(1, i32_const(0), [0]),          # i32 offset -> table 1 (32-bit)
    ]),
    code_section([i32_const(0) + END]),
))

# B8_04: memory64 with an initial size above 4 GiB (70000 pages = 4,587,520,000 bytes = ~4.27 GiB).
# Valid per memory64; must import with a clear diagnostic, no OOM, and the code must decode. The
# load uses an i64 dynamic address above 4 GiB plus a static offset (EA 0x100000030).
write("B8_04_mem64_over4g.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    memory_section([(0x04, 70000)]),                # 64-bit index, initial 70000 pages
    export_section([("f", 0, 0)]),
    code_section([
        i64_const(0x100000020) + b"\x28" + memarg(2, offset=0x10) +  # EA 0x100000030
        END
    ]),
))

# B8_05: memory64 with an initial size just above 4 GiB (65537 pages = 4,295,032,832 bytes), the
# smallest over-4-GiB declaration; a large static offset exercises EA 0x100000010.
write("B8_05_mem64_just_over4g.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    memory_section([(0x04, 65537)]),
    export_section([("f", 0, 0)]),
    code_section([
        i64_const(0) + b"\x28" + memarg(2, offset=0x100000010) +  # EA 0x100000010
        END
    ]),
))
