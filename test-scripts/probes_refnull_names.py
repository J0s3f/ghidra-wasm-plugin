#!/usr/bin/env python3
"""Probes for named abstract heap types in `ref.null` (0xD0) function bodies.

MODERN_WASM_GAPS.md §2.3: `ref.null` abstract heap types printed numerically
(`ref.null heaptype=-0x15`). The SLEIGH fix adds named constructors per abstract
heap type byte (0x69..0x74) alongside the generic s33 form. These probes exercise
every abstract heap type in a function body so the disassembly evidence is complete:

  RN01 exn (0x69)       RN05 eq (0x6D)       RN09 none (0x71)
  RN02 array (0x6A)     RN06 any (0x6E)      RN10 noextern (0x72)
  RN03 struct (0x6B)    RN07 extern (0x6F)   RN11 nofunc (0x73)
  RN04 i31 (0x6C)       RN08 func (0x70)     RN12 noexn (0x74)

Each function is `() -> <reftype>` with body `ref.null <ht>; end`. The `ref.null`
pushes a `(ref null <ht>)` which matches the return type (the valtype shorthand
for `(ref null <ht>)` is the same byte as the heap type encoding).

Byte encodings verified against the Wasm 3.0 spec
(https://webassembly.github.io/spec/core/binary/types.html):
  absheaptype ::= 0x69=>exn | 0x6A=>array | 0x6B=>struct | 0x6C=>i31 | 0x6D=>eq
                | 0x6E=>any | 0x6F=>extern | 0x70=>func | 0x71=>none
                | 0x72=>noextern | 0x73=>nofunc | 0x74=>noexn

Usage: python probes_refnull_names.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])

# ValType shorthand bytes for the bottom heap types (Wasm 3.0).
NONEREF, NOEXTERNREF, NOFUNCREF, NOEXNREF = 0x71, 0x72, 0x73, 0x74


def ref_null_body(ht_byte, reftype_byte):
    """One function: () -> reftype, body = ref.null ht; end."""
    return module(
        type_section(functype([], [reftype_byte])),
        func_section([0]),
        export_section([("f", 0, 0)]),
        code_section([b"\xD0" + bytes([ht_byte]) + END]),
    )


# exn (0x69) -> exnref (0x69)
write("RN01_refnull_exn.wasm", ref_null_body(0x69, 0x69))

# array (0x6A) -> arrayref (0x6A)
write("RN02_refnull_array.wasm", ref_null_body(0x6A, 0x6A))

# struct (0x6B) -> structref (0x6B)
write("RN03_refnull_struct.wasm", ref_null_body(0x6B, 0x6B))

# i31 (0x6C) -> i31ref (0x6C)
write("RN04_refnull_i31.wasm", ref_null_body(0x6C, 0x6C))

# eq (0x6D) -> eqref (0x6D)
write("RN05_refnull_eq.wasm", ref_null_body(0x6D, 0x6D))

# any (0x6E) -> anyref (0x6E)
write("RN06_refnull_any.wasm", ref_null_body(0x6E, 0x6E))

# extern (0x6F) -> externref (0x6F)
write("RN07_refnull_extern.wasm", ref_null_body(0x6F, 0x6F))

# func (0x70) -> funcref (0x70)
write("RN08_refnull_func.wasm", ref_null_body(0x70, 0x70))

# none (0x71) -> noneref (0x71)
write("RN09_refnull_none.wasm", ref_null_body(NONEREF, NONEREF))

# noextern (0x72) -> noexternref (0x72)
write("RN10_refnull_noextern.wasm", ref_null_body(NOEXTERNREF, NOEXTERNREF))

# nofunc (0x73) -> nofuncref (0x73)
write("RN11_refnull_nofunc.wasm", ref_null_body(NOFUNCREF, NOFUNCREF))

# noexn (0x74) -> noexnref (0x74)
write("RN12_refnull_noexn.wasm", ref_null_body(NOEXNREF, NOEXNREF))
