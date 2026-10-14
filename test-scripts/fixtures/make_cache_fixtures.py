#!/usr/bin/env python3
"""Byte generator for the call-store / stale-address-cache emulator fixtures.

The two evidence fixtures are copied verbatim from the re-review bundle:

    cache32.wasm  sha256 186395c5a22ba43528aafd4d344b7264263a540b753e97249bc632f5616c7617
    cache64.wasm  sha256 302b11260f10185c745cd877483ff149e1ff56860e9bcb844249ea514d0095a3

This script reproduces them byte-for-byte (a provenance check: run it and compare the
hashes) and additionally emits the direct / no-call control fixtures that the N1
regression requires but that the evidence bundle does not contain:

    cache32_controls.wasm / cache64_controls.wasm

Each control module has one-page memory with low-address data 78 56 34 12 and four
exports that perform the same accesses as the call fixtures *without* an intervening
call, so they pin down that the fix does not change the direct paths:

    direct_load       i32.const 0; i32.load                  -> 0x12345678
    direct_simd       i32.const 0; v128.load; extract_lane 0 -> 0x12345678
    direct_rmw        i32.const 0; i32.const 1; i32.atomic.rmw.add -> 0x12345678
    direct_overflow   i32.const -1; i32.load offset=1        -> MUST trap
                      ("out of bounds memory access")

Usage:  python make_cache_fixtures.py [output_dir]     (default: this directory)
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wasm_probe_lib import *  # noqa: F401,F403


def build_base(out: Path, wide: bool) -> None:
    const = i64_const if wide else i32_const
    bodies = []
    exports = []

    def add(n, b):
        exports.append((n, 0, len(bodies)))
        bodies.append(b + END)

    # The helpers overwrite s0 in the same address width then drop it.
    add('load_after_call', const(0) + b'\x10\x03' + b'\x28\x02\x00')
    add('simd_after_call', const(0) + b'\x10\x03' + b'\xfd\x00\x04\x00' + b'\xfd\x1b\x00')
    add('rmw_after_call', const(0) + b'\x10\x03' + i32_const(1) + b'\xfe\x1e\x02\x00')
    bodies.append(const(-1) + drop() + END)
    add('overflow_after_call', const(-1) + b'\x10\x05' + b'\x28\x02\x01')
    bodies.append(const(0) + drop() + END)

    blob = module(
        type_section(functype([], [I32]), functype([], [])),
        func_section([0, 0, 0, 1, 0, 1]),
        memory_section([(4 if wide else 0, 1)]),
        export_section(exports),
        code_section(bodies),
        data_section([active_data(const(0) + END, bytes.fromhex('78563412'))]),
    )
    (out / ('cache64.wasm' if wide else 'cache32.wasm')).write_bytes(blob)


def build_controls(out: Path, wide: bool) -> None:
    const = i64_const if wide else i32_const
    bodies = []
    exports = []

    def add(n, b):
        exports.append((n, 0, len(bodies)))
        bodies.append(b + END)

    add('direct_load', const(0) + b'\x28\x02\x00')
    add('direct_simd', const(0) + b'\xfd\x00\x04\x00' + b'\xfd\x1b\x00')
    add('direct_rmw', const(0) + i32_const(1) + b'\xfe\x1e\x02\x00')
    add('direct_overflow', const(-1) + b'\x28\x02\x01')

    blob = module(
        type_section(functype([], [I32])),
        func_section([0, 0, 0, 0]),
        memory_section([(4 if wide else 0, 1)]),
        export_section(exports),
        code_section(bodies),
        data_section([active_data(const(0) + END, bytes.fromhex('78563412'))]),
    )
    (out / ('cache64_controls.wasm' if wide else 'cache32_controls.wasm')).write_bytes(blob)


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
    out.mkdir(parents=True, exist_ok=True)
    for wide in (False, True):
        build_base(out, wide)
        build_controls(out, wide)


if __name__ == '__main__':
    main()
