#!/usr/bin/env python3
"""Probes owned by the section-id / 64-bit-data-offset workstream (agent H1).

Two independent loader correctness items are pinned here.

B1 - section id / duplicate-section diagnostics (REPORT-HARD.md finding B4)

  `WasmSection.createSection()` used to return `null` for a section id outside the modelled enum
  and `WasmModule`'s loop merely `continue`d, so an out-of-range section id was skipped *silently*;
  a duplicate non-custom section silently overwrote the earlier one via `sectionMap.put`. Both are
  malformed WebAssembly and must now fail the import with a diagnostic naming the id/section and the
  file offset. Nothing here rejects a *valid* module: an odd section order is tolerated (a warning at
  most) and an omitted section is still fine.

    H1_01_control_valid.wasm          canonical, valid module          -> import_ok
    H1_02_unknown_section_id.wasm     section id 0x2a (42)             -> import_failed
                                      "Unsupported section id 0x2a at file offset 0x8"
    H1_03_duplicate_type_section.wasm two type sections (id 1)         -> import_failed
                                      "Duplicate section SEC_TYPE ..."
    H1_04_duplicate_code_section.wasm two code sections (id 10)        -> import_failed
                                      "Duplicate section SEC_CODE ..."
    H1_13_duplicate_datacount.wasm    two data-count sections (id 12)   -> import_failed
                                      "Duplicate section SEC_DATACOUNT ..." (id 12 has no
                                      section class, so the check keys on the raw id)
    H1_05_out_of_order_sections.wasm  memory(5) before type(1)         -> import_ok + warning

B2 - active data segments with a 64-bit offset (REPORT-N.md section 7 item 8)

  `ConstantExpression.asI32()` could not read an `i64.const` offset, so an active data segment of a
  memory64 memory was dropped before the loader placed the bytes. `ConstantExpression` now exposes
  the value of an i32/i64 const (and the loader resolves a `global.get` of a defined const global);
  the segment is placed with the existing `ram`-space truncation rule. Above 4 GiB the address is
  clamped to the top of the 32-bit `ram` space and logged (the bytes cannot be represented), and an
  offset that cannot be resolved statically still degrades to "segment skipped + warning".

    H1_06_i64_const_offset.wasm       memory64, i64.const 0x10   -> bytes at ram:0x10
    H1_07_i64_const_offset_4k.wasm    memory64, i64.const 0x1000 -> bytes at ram:0x1000
    H1_08_i64_global_offset.wasm      memory64, global i64 = 0x40 -> bytes at ram:0x40
    H1_09_unresolved_global_offset.wasm  offset = imported i64 global -> import_ok, segment skipped
    H1_10_mem1_i64_offset.wasm        memory 1 = memory64, i64.const 0x20 -> ram:0x10000020
    H1_11_i32_control.wasm            32-bit memory, i32.const 0x18 (unchanged behaviour)
    H1_12_i64_offset_above_4gib.wasm  memory64, i64.const 0x100000000 -> clamped + logged

Every valid probe must show `undefined_bytes=0` and decompile. `test-scripts/DumpMemory.java` prints
the memory blocks so the placement can be checked byte-for-byte.

Usage: python probes_sections_i64.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])


def memarg(align, memidx=None, offset=0):
    """Encode a memarg immediate (bit 6 of the flags byte signals an explicit memory index)."""
    if memidx is None:
        return uleb(align) + uleb(offset)
    return uleb(align | 0x40) + uleb(memidx) + uleb(offset)


I32_LOAD = b"\x28"

# =====================================================================================
# B1 - valid control
# (func (result i32) i32.const 42)
# =====================================================================================
write("H1_01_control_valid.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([i32_const(42) + END]),
))

# =====================================================================================
# B1 - out-of-range section id 0x2a (42): must fail the import, naming id + file offset.
# The bad section is the first thing after the 8-byte header, so the offset is 0x8.
# =====================================================================================
write("H1_02_unknown_section_id.wasm", module(
    section(0x2A, b"\x00"),
))

# =====================================================================================
# B1 - two type sections (id 1): the second must fail the import as a duplicate.
# =====================================================================================
write("H1_03_duplicate_type_section.wasm", module(
    type_section(functype([], [])),
    type_section(functype([], [I32])),
))

# =====================================================================================
# B1 - two code sections (id 10): the second must fail the import as a duplicate.
# =====================================================================================
write("H1_04_duplicate_code_section.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    code_section([i32_const(7) + END]),
    code_section([]),
))

# =====================================================================================
# B1 - two data-count sections (id 12). Id 12 has no section class (the loader skips its
# content), so this also pins that the duplicate check keys on the raw section id.
# =====================================================================================
write("H1_13_duplicate_datacount.wasm", module(
    data_count_section(0),
    data_count_section(0),
))

# =====================================================================================
# B1 - sections out of the canonical order (memory id 5 before type id 1) but otherwise
# valid: must still import (tolerated; the loader may log a warning).
# =====================================================================================
write("H1_05_out_of_order_sections.wasm", module(
    memory_section([(0x00, 1)]),                       # id 5 before id 1
    type_section(functype([], [I32])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([i32_const(7) + END]),
))

# =====================================================================================
# B2 - H1_06: memory64, active data segment at i64.const 0x10.
# (func (result i32) i64.const 0x10; i32.load)
# =====================================================================================
write("H1_06_i64_const_offset.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    memory_section([(0x04, 1)]),                       # flags 4 = 64-bit index, 1 page
    export_section([("f", 0, 0)]),
    code_section([i64_const(0x10) + I32_LOAD + memarg(2) + END]),
    data_section([active_data(i64_const(0x10) + END, b"H1-DATA-64BIT")]),
))

# =====================================================================================
# B2 - H1_07: memory64, a larger non-zero i64.const offset (0x1000).
# =====================================================================================
write("H1_07_i64_const_offset_4k.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    memory_section([(0x04, 1)]),
    export_section([("f", 0, 0)]),
    code_section([i64_const(0x1000) + I32_LOAD + memarg(2) + END]),
    data_section([active_data(i64_const(0x1000) + END, b"B2-NONZERO-OFFSET!")]),
))

# =====================================================================================
# B2 - H1_08: memory64, offset = global.get of a defined immutable i64 global (0x40).
# =====================================================================================
write("H1_08_i64_global_offset.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    memory_section([(0x04, 1)]),
    global_section([(I64, 0, i64_const(0x40))]),
    export_section([("f", 0, 0)]),
    code_section([i64_const(0x40) + I32_LOAD + memarg(2) + END]),
    data_section([active_data(global_get(0) + END, b"GLOBAL-I64-OFFSET")]),
))

# =====================================================================================
# B2 - H1_09: offset = global.get of an *imported* i64 global. The value is not known
# until instantiation, so the loader must skip the segment with a warning (no crash).
# =====================================================================================
write("H1_09_unresolved_global_offset.wasm", module(
    type_section(functype([], [I32])),
    import_section([("env", "g", 3, bytes([I64, 0x00]))]),   # imported immutable i64 global
    func_section([0]),
    memory_section([(0x04, 1)]),
    export_section([("f", 0, 0)]),
    code_section([i64_const(0) + I32_LOAD + memarg(2) + END]),
    data_section([active_data(global_get(0) + END, b"UNRESOLVED")]),
))

# =====================================================================================
# B2 - H1_10: multi-memory. memory 0 is 32-bit, memory 1 is 64-bit; the active data
# segment lives in memory 1 at i64.const 0x20 -> ram:(1*MEMORY_STRIDE + 0x20) = 0x10000020.
# =====================================================================================
write("H1_10_mem1_i64_offset.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    memory_section([(0x00, 1), (0x04, 1)]),
    export_section([("f", 0, 0)]),
    code_section([i64_const(0x20) + I32_LOAD + memarg(2, 1) + END]),
    data_section([active_data(i64_const(0x20) + END, b"MEM1-DATA", memidx=1)]),
))

# =====================================================================================
# B2 - H1_11: 32-bit control - an ordinary i32.const offset; behaviour must be unchanged.
# =====================================================================================
write("H1_11_i32_control.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    memory_section([(0x00, 1)]),
    export_section([("f", 0, 0)]),
    code_section([i32_const(0x18) + I32_LOAD + memarg(2) + END]),
    data_section([active_data(i32_const(0x18) + END, b"CTRL-32BIT")]),
))

# =====================================================================================
# B2 - H1_12: a memory64 data segment at exactly 4 GiB. The 32-bit `ram` space cannot
# represent it, so the address is clamped to 0xffffffff and the placement is logged as a
# failure; the module still imports (graceful degradation, documented above).
# =====================================================================================
write("H1_12_i64_offset_above_4gib.wasm", module(
    type_section(functype([], [I32])),
    func_section([0]),
    memory_section([(0x04, 1)]),
    export_section([("f", 0, 0)]),
    code_section([i64_const(0) + I32_LOAD + memarg(2) + END]),
    data_section([active_data(i64_const(0x100000000) + END, b"ABOVE-4GIB")]),
))
