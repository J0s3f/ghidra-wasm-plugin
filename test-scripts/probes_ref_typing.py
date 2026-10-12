#!/usr/bin/env python3
"""Probes for the reference-type model (precise heap-type mapping + subtype-aware validation).

These exercise the fix to `WasmEnums.ValType.readFromReader` / `readHeapType` and the
subtype-aware `popValue`:

  * a multi-byte `(ref null struct)` block signature and a `ref.null struct` flowing through it
    (`R01`),
  * the funcref side: a `(ref null func)` block signature and `ref.null nofunc` (the bottom of
    the func hierarchy) accepted where `funcref` is expected (`R02`),
  * the subtype rule itself: a `structref` accepted where `anyref` / `eqref` is expected
    (`R04`),
  * the negative: an `anyref` where `eqref` is expected must still be rejected (`R03`).

Usage: python probes_ref_typing.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])

# Abstract heap types not already named in wasm_probe_lib.
HT_NOFUNC = 0x73      # nofunc (bottom of the func hierarchy)
HT_NOEXTERN = 0x72    # noextern (bottom of the extern hierarchy)

ANYREF, EQREF = 0x6E, 0x6D


def ref_null_ht(ht_byte):
    """`ref.null <abstract heap type>`: 0xD0 followed by the (single-byte) s33 heap type."""
    return b"\xD0" + bytes([ht_byte])


# =============================================================================================
# (ref null struct): multi-byte block signature + ref.null struct through the block
# =============================================================================================

# R01: func 0 = (ref null struct) -> (ref null struct), body returns the parameter through a
#      block whose signature is the multi-byte valtype (ref null struct) (0x63 0x6B);
#      func 1 = () -> (ref null struct), body is `block (ref null struct) { ref.null struct }`.
write("R01_ref_typing_struct_block.wasm", module(
    section(1, vec([
        b"\x60" + vec([ref_null(HT_STRUCT)]) + vec([ref_null(HT_STRUCT)]),   # 0
        b"\x60" + vec([]) + vec([ref_null(HT_STRUCT)]),                     # 1
    ])),
    func_section([0, 1]),
    export_section([("f", 0, 0), ("g", 0, 1)]),
    code_section([
        block(ref_null(HT_STRUCT), local_get(0)) + END,
        block(ref_null(HT_STRUCT), ref_null_ht(HT_STRUCT)) + END,
    ]),
))

# =============================================================================================
# funcref side: (ref null func) block signature + ref.null nofunc (bottom) as funcref
# =============================================================================================

# R02: func 0 = (ref null func) -> (ref null func) through a (ref null func) block;
#      func 1 = () -> funcref, body is `block funcref { ref.null nofunc }` (nofunc <: funcref).
write("R02_ref_typing_funcref_mix.wasm", module(
    section(1, vec([
        b"\x60" + vec([ref_null(HT_FUNC)]) + vec([ref_null(HT_FUNC)]),      # 0
        b"\x60" + vec([]) + vec([bytes([FUNCREF])]),                        # 1
    ])),
    func_section([0, 1]),
    export_section([("f", 0, 0), ("g", 0, 1)]),
    code_section([
        block(ref_null(HT_FUNC), local_get(0)) + END,
        block(bytes([FUNCREF]), ref_null_ht(HT_NOFUNC)) + END,
    ]),
))

# =============================================================================================
# subtype acceptance: structref where anyref / eqref is expected
# =============================================================================================

# R04: two functions, each `block <supertype> { ref.null struct }` (structref <: anyref, eqref).
write("R04_ref_typing_subtype_accept.wasm", module(
    section(1, vec([functype([], []), functype([], [])])),
    func_section([0, 1]),
    export_section([("f", 0, 0), ("g", 0, 1)]),
    code_section([
        block(bytes([ANYREF]), ref_null_ht(HT_STRUCT)) + drop() + END,
        block(bytes([EQREF]), ref_null_ht(HT_STRUCT)) + drop() + END,
    ]),
))

# =============================================================================================
# negative: anyref is NOT a subtype of eqref, so it must still be rejected
# =============================================================================================

# R03: `block (ref null eq) { ref.null any }` - anyref is a supertype of eqref, so this is
#      spec-invalid. The pre-analyzer must reject it (the body is left undecoded) rather than
#      silently accepting the value.
write("R03_ref_typing_anyref_where_eqref.wasm", module(
    section(1, vec([functype([], [])])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        block(bytes([EQREF]), ref_null_ht(HT_ANY)) + drop() + END,
    ]),
))
