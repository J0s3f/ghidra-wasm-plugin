#!/usr/bin/env python3
"""WebAssembly component-model loader probes.

Generates spec-valid component-model fixtures (8-byte preamble `\\0asm` + version 0x0d + layer 0x01,
followed by `id:u8 size:u32-LEB128 payload` sections) for the loader in
`src/main/java/wasm/WasmComponentLoader.java`.

Fixtures (names are fixed - the acceptance run in DIAGNOSIS.md imports them by name):

  component_with_module.wasm   preamble + one core-module section (id 1) whose payload is the
                               complete `01_baseline_i32` core module (exported function `f`),
                               plus a trailing component custom section (id 0). The nested module
                               itself contains a type section with id 1, so a parser that re-scans a
                               payload instead of skipping it by its declared size reports a
                               phantom second core module.
  bare_component_header.wasm   preamble only (8 bytes, no sections).
  truncated_component.wasm     preamble + a core-module section that declares 0x40 payload bytes
                               but is cut off after 16 - a truncated component.

Usage: python probes_component.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

# Component preamble: magic + version 0x0d 0x00 + layer 0x01 0x00 (8 bytes total).
COMPONENT_PREAMBLE = b"\x00asm" + bytes([0x0D, 0x00, 0x01, 0x00])

# The nested core module - byte-identical to gen_feature_probes.py probe 01
# (`01_baseline_i32.wasm`): (func (export "f") (param i32) (result i32) local.get 0).
CORE_MODULE = module(
    type_section(functype([I32], [I32])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x20\x00" + END]),
)


def write_component_with_module(base_dir: str) -> str:
    """preamble + core-module section (id 1) + trailing custom section (id 0)."""
    preamble_len = len(COMPONENT_PREAMBLE)
    core_header = section(1, CORE_MODULE)
    core_payload_off = preamble_len + 1 + len(uleb(len(CORE_MODULE)))
    trailing = custom_section("probe", b"component")
    blob = COMPONENT_PREAMBLE + core_header + trailing

    path = write("component_with_module.wasm", blob)
    print(f"  component_with_module.wasm: {len(blob)} bytes")
    marks = [
        (0, "preamble (\\0asm, version 0x000d, layer 0x0001)"),
        (preamble_len, f"section id 1 (core:module), size={len(CORE_MODULE)} (0x{len(CORE_MODULE):x})"),
        (core_payload_off, f"nested core module payload ({len(CORE_MODULE)} bytes, \\0asm + version 1)"),
        (core_payload_off + 8, "  (inside payload) nested core type section id 1 - must NOT be re-scanned"),
        (core_payload_off + len(CORE_MODULE), "section id 0 (component custom section \"probe\")"),
    ]
    for off, text in sorted(marks):
        print(f"      0x{off:04x}  {text}")
    return path


def write_bare_component_header(base_dir: str) -> str:
    """A component preamble with no sections at all."""
    blob = COMPONENT_PREAMBLE
    path = write("bare_component_header.wasm", blob)
    print(f"  bare_component_header.wasm: {len(blob)} bytes (preamble only, no sections)")
    return path


def write_truncated_component(base_dir: str) -> str:
    """preamble + a core-module section header that declares more bytes than are present."""
    blob = COMPONENT_PREAMBLE + bytes([0x01, 0x40]) + CORE_MODULE[:16]
    path = write("truncated_component.wasm", blob)
    print(f"  truncated_component.wasm: {len(blob)} bytes "
          f"(section id 1 declares 0x40 payload bytes, only {len(CORE_MODULE[:16])} present)")
    return path


# -- Generate fixtures when run directly ---------------------------------
if __name__ == "__main__":
    base_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    set_output_dir(base_dir)

    print("Generating component-model probe fixtures...")
    write_component_with_module(base_dir)
    write_bare_component_header(base_dir)
    write_truncated_component(base_dir)
    print("Fixtures ready for import testing.")
