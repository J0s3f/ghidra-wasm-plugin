#!/usr/bin/env python3
"""Generate padded-LEB memarg regression fixtures (outside the 222-probe gate).

Usage: python test-scripts/memarg-padding-fixtures.py <private scratch directory>

Every memarg immediate here uses a NON-MINIMAL (padded) LEB128 encoding, which the
binary integer rules permit: a u32 LEB may pad with zero chunks up to 5 bytes, a u64
up to 10. The multi-memory memarg splits on bit 6 of the DECODED flags value:

  unflagged  align (bit 6 clear)        -> align LEB + offset LEB
  flagged    flags 64..127 (bit 6 set)  -> flags LEB + memidx LEB + offset LEB

A padded encoding of a flagged value (e.g. 0xC0 0x80 0x80 0x80 0x00 = 64) used to be
matched by the UNFLAGGED multi-byte SLEIGH forms, which consumed the memory index as
the offset and misaligned everything after it. These fixtures pin the fixed decode.

memarg_padding.wasm    two 32-bit memories: scalar loads, one store + load-back and
                       one atomic load with padded flagged memargs (2..5 byte flags),
                       padded unflagged aligns, and the plain single-byte forms as
                       controls. All accesses land in the 32-bit `memory` space.
                       wabt-valid.
memarg_padding64.wasm  one 32-bit + one 64-bit-indexed memory: the v128.load case
                       (padded 0xfd sub-opcode + fully padded memarg = 26 bytes, the
                       emulator's worst-case instruction) plus scalar/plain controls.
                       The memidx=1 accesses land in the `memory64` space. wabt-valid.
memarg_padding_lenient.wasm
                       one deliberately wabt-INVALID module (alignment hint 130 > the
                       natural alignment): a padded unflagged align whose higher LEB
                       chunks are non-zero. Kept to pin that such spec-invalid modules
                       still import and still decode as unflagged.

Expected results (little-endian i32 at the accessed address):
  memory 0 @ 0 = 11 22 33 44 -> 0x44332211
  memory 1 @ 0 = 55 66 77 88 -> 0x88776655   (module A, 32-bit memory 1)
  memory 1 @ 0 = 99 aa bb cc -> 0xccbbaa99   (module B, 64-bit memory 1)
  store_pad stores 0x12345678 at memory 1 @ 4 and loads it back.
"""
import sys
from pathlib import Path
from wasm_probe_lib import *

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)


def padded(n: int, length: int) -> bytes:
    """Unsigned LEB128 of n, padded with zero chunks to exactly `length` bytes."""
    data = bytearray(uleb(n))
    assert len(data) < length, f"padded({n}, {length}): already minimal or longer"
    data[-1] |= 0x80
    data.extend([0x80] * (length - len(data) - 1))
    data.append(0x00)
    return bytes(data)


def unflagged(align: int, offset: int, align_len: int = 5, off_len: int = 10) -> bytes:
    """Padded unflagged memarg: align LEB (bit 6 of the value clear) + offset LEB."""
    return padded(align, align_len) + padded(offset, off_len)


def flagged(align: int, memidx: int, offset: int,
            align_len: int = 5, idx_len: int = 5, off_len: int = 10) -> bytes:
    """Padded flagged memarg: flags LEB (value align|0x40 in 64..127) + memidx + offset."""
    return padded(align | 0x40, align_len) + padded(memidx, idx_len) + padded(offset, off_len)


# ---------------------------------------------------------------- module A
# Two 32-bit memories, one page each; both mapped into the 32-bit `memory` space
# (memory 1 at 1 * MEMORY_STRIDE). Every function is () -> i32.
bodies, exports = [], []


def add(name, code):
    exports.append((name, 0, len(bodies)))
    bodies.append(code + END)


# i32.load, flags padded to 2 bytes (C2 00 = 0x42), memidx/offset padded to 2:
# align=2 memidx=1 offset=0 -> memory 1 @ 0. Instruction length 1+2+2+2 = 7.
add("scalar_pad2", i32_const(0) + b"\x28" + flagged(2, 1, 0, align_len=2, idx_len=2, off_len=2))
# i32.load, flags/memidx padded to 5 bytes, offset padded to 10 (u64 max):
# align=2 memidx=1 offset=0 -> memory 1 @ 0. Instruction length 1+5+5+10 = 21.
add("scalar_pad5", i32_const(0) + b"\x28" + flagged(2, 1, 0))
# Plain single-byte flagged form (unchanged control): align=2 memidx=1 offset=0.
add("scalar_plain_flag", i32_const(0) + b"\x28" + uleb(2 | 0x40) + uleb(1) + uleb(0))
# Plain single-byte unflagged form (unchanged control): align=2 offset=0 -> memory 0 @ 0.
add("scalar_plain_unflag", i32_const(0) + b"\x28" + uleb(2) + uleb(0))
# Padded UNFLAGGED align (bit 6 of the value clear): align=2 padded to 5 bytes, offset
# padded to 10. Must stay unflagged - no memidx is consumed. Length 1+5+10 = 16.
add("scalar_unflag_pad", i32_const(0) + b"\x28" + unflagged(2, 0))
# i32.atomic.load (0xfe 0x10), fully padded flagged memarg:
# align=2 memidx=1 offset=0 -> memory 1 @ 0. Length 2+5+5+10 = 22.
add("atomic_pad", i32_const(0) + b"\xfe\x10" + flagged(2, 1, 0))
# i32.store align=2 memidx=1 offset=4 (padded to 5), then the same padded memarg loads
# the value back: proves the store and the load agree on the padded effective address.
add("store_pad", i32_const(0) + i32_const(0x12345678) + b"\x36" + flagged(2, 1, 4, off_len=5)
    + i32_const(0) + b"\x28" + flagged(2, 1, 4, off_len=5))

(out / "memarg_padding.wasm").write_bytes(module(
    type_section(functype([], [I32])), func_section([0] * len(bodies)),
    memory_section([(0, 1), (0, 1)]), export_section(exports), code_section(bodies),
    data_section([active_data(i32_const(0) + END, bytes.fromhex("11223344")),
                  active_data(i32_const(0) + END, bytes.fromhex("55667788"), 1)])))
print(f"memarg_padding.wasm: {len(bodies)} functions, two 32-bit memories (wabt-valid)")

# ---------------------------------------------------------------- module B
# One 32-bit memory (index 0) and one 64-bit-indexed memory (index 1). Memory 1 is
# mapped into the 64-bit `memory64` space at 1 * MEMORY_STRIDE, so its memidx=1
# accesses take the "(i64 index)" decoders. Every function is () -> i32.
bodies, exports = [], []

# v128.load (0xfd, sub-opcode padded to 5 bytes) with a fully padded flagged memarg:
# align=4 memidx=1 offset=0 -> memory64 @ 0x8000000. Length 1+5+5+5+10 = 26 - the
# longest possible load/store instruction, i.e. the emulator's worst case. The
# i32x4.extract_lane 0 after it returns the low 4 bytes of the loaded v128 and pins
# the instruction boundary after the 26-byte load.
add("simd_pad_v128", i64_const(0) + b"\xfd" + padded(0, 5) + flagged(4, 1, 0)
    + b"\xfd\x1b\x00")
# i32.load from the 64-bit memory with a fully padded flagged memarg (i64 index path):
# align=2 memidx=1 offset=0 -> memory64 @ 0x8000000. Length 1+5+5+10 = 21.
add("scalar_pad_mem64", i64_const(0) + b"\x28" + flagged(2, 1, 0))
# Plain single-byte forms on the same memory (unchanged controls).
add("simd_plain", i64_const(0) + b"\xfd\x00" + uleb(0x40) + uleb(1) + uleb(0)
    + b"\xfd\x1b\x00")

(out / "memarg_padding64.wasm").write_bytes(module(
    type_section(functype([], [I32])), func_section([0] * len(bodies)),
    memory_section([(0, 1), (4, 1)]), export_section(exports), code_section(bodies),
    data_section([active_data(i32_const(0) + END, bytes.fromhex("11223344")),
                  active_data(i64_const(0) + END, bytes.fromhex("99aabbcc"), 1)])))
print(f"memarg_padding64.wasm: {len(bodies)} functions, one 32-bit + one 64-bit memory"
      " (wabt-valid)")

# ---------------------------------------------------------------- module C
# Deliberately wabt-INVALID (the only invalid fixture here, by design): a padded
# unflagged align whose value has a non-zero higher LEB chunk. align=130 is not a legal
# alignment hint (2^130 >> the natural alignment of an i32.load), but the binary
# encoding is well-formed, and the module must still import and still decode the memarg
# as UNFLAGGED (bit 6 of 130 is clear) with the full value 130 = 0x82. This pins both
# the value reconstruction of the unflagged multi-byte forms and the "accept
# spec-invalid modules" rule. Length 1+5+1 = 7.
bodies, exports = [], []
add("scalar_unflag_pad130", i32_const(0) + b"\x28" + padded(130, 5) + uleb(0))

(out / "memarg_padding_lenient.wasm").write_bytes(module(
    type_section(functype([], [I32])), func_section([0] * len(bodies)),
    memory_section([(0, 1)]), export_section(exports), code_section(bodies),
    data_section([active_data(i32_const(0) + END, bytes.fromhex("11223344"))])))
print(f"memarg_padding_lenient.wasm: {len(bodies)} function, deliberately wabt-invalid"
      " (alignment hint 130) - pins lenient unflagged decode")
