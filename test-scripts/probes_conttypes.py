#!/usr/bin/env python3
"""Probes for the stack-switching `cont` composite type in the type section (workstream CT).

The stack-switching proposal adds a composite type to the type section:

    comptype ::= functype | structtype | arraytype | conttype
    conttype ::= 0x5D typeidx          (cont <func typeidx>)

Binary encoding verified against binaryen version_133 (`wasm-dis --all-features` accepts
`0x5D <typeidx>` and prints `(type $N (cont $M))`; wabt 1.0.42 rejects it as an "unexpected type
form"). Before this change the plugin's GC type parser threw on 0x5D, so a module that declared a
continuation type failed to import entirely; now the type is accepted and a continuation type
resolves to the function type it references (so `cont.new`/`resume`/`cont.bind`/`switch` model the
referenced signature, exactly as before - the instruction metrics of the H probes are unchanged).

Probes:
    CT01_cont_new_valid.wasm       cont type + cont.new referencing it -> decodes, undefined_bytes=0
    CT02_cont_resume_signature.wasm cont type referenced by resume, signature from the func type
    CT03_cont_bad_index.wasm       cont type with an out-of-range type index -> degraded, no crash
    CT04_cont_absent_index.wasm    cont type with an absent type index (truncated) -> rejected
    CT05_cont_index_ge64.wasm      cont type referencing index 64 (multi-byte s33) -> decodes

Usage: python probes_conttypes.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])


def cont_type(funcidx):
    """0x5D cont $ft: the continuation composite type referencing function type `funcidx` (s33)."""
    return b"\x5D" + sleb(funcidx)


def cont_new(typeidx):
    """0xE0 cont.new $ct."""
    return b"\xE0" + uleb(typeidx)


def resume(ct, handlers=()):
    """0xE3 resume $ct hdl*."""
    return b"\xE3" + uleb(ct) + vec(list(handlers))


def on_label(tag, label):
    """Handler clause 0x00 tagidx labelidx."""
    return b"\x00" + uleb(tag) + uleb(label)


def ref_func(funcidx):
    """ref.func x: pushes a funcref (the argument of cont.new)."""
    return b"\xD2" + uleb(funcidx)


def ftype(params, results):
    """functype whose params/results may be ints or multi-byte valtype bytes (e.g. `ref_(1)`)."""
    enc = lambda xs: vec([bytes([x]) if isinstance(x, int) else x for x in xs])
    return b"\x60" + enc(params) + enc(results)


UNREACH = b"\x00"  # unreachable


# ---------------------------------------------------------------- CT01: cont type + cont.new
# type 0 = []->[], type 1 = (cont 0). cont.new replaces the function reference with a continuation
# reference, which is dropped: the module must decode with undefined_bytes = 0.
write("CT01_cont_new_valid.wasm", module(
    type_section(functype([], []), cont_type(0)),
    func_section([0, 0]),
    export_section([("f", 0, 1)]),
    code_section([
        END,                                        # func 0: the continuation target
        ref_func(0) + cont_new(1) + drop() + END,   # func 1
    ]),
))

# ---------------------------------------------------------------- CT02: cont type's signature
# type 0 = []->[], type 1 = [i32]->[i32] (continuation target), type 2 = (cont 1),
# type 3 = []->[i32 (ref 2)] (the handler label's block type, `[t1* (ref $ct)]`).
# resume $ct pops the continuation reference and the i32 parameter, and pushes the i32 result, so
# the signature must be taken from the referenced function type (type 1), not from an empty
# continuation.
write("CT02_cont_resume_signature.wasm", module(
    type_section(functype([], []), functype([I32], [I32]), cont_type(1), ftype([], [I32, ref_(2)])),
    tag_section([(0x00, 1)]),
    func_section([1, 0]),
    code_section([
        local_get(0) + END,                            # func 0: continuation target ([i32]->[i32])
        block(3, i32_const(3) + ref_func(0) + cont_new(2) + resume(2, [on_label(0, 0)]) + UNREACH)
        + drop() + drop() + END,
    ]),
))

# ---------------------------------------------------------------- CT03: bad type index (degraded)
# type 0 = []->[], type 1 = (cont 5) - the referenced index 5 does not exist. The type-section
# parser must accept the entry without crashing; the continuation resolves to no signature (empty
# parameter/return tuple), so the body still decodes.
write("CT03_cont_bad_index.wasm", module(
    type_section(functype([], []), cont_type(5)),
    func_section([0, 0]),
    export_section([("f", 0, 1)]),
    code_section([
        END,
        ref_func(0) + cont_new(1) + drop() + END,
    ]),
))

# ---------------------------------------------------------------- CT04: absent type index (rejected)
# A `cont` type whose type index byte is missing: the type section is the last section, so the read
# runs off the end of the module. The loader must reject the module cleanly (no crash, no partial
# program).
write("CT04_cont_absent_index.wasm", module(
    type_section(functype([], []), b"\x5D"),
))

# ---------------------------------------------------------------- CT05: multi-byte (s33) type index
# The referenced type index is an s33 (like a heap type), so index 64 must be encoded as 0xC0 0x00,
# not the single-byte uleb 0x40 (binaryen reads 0x40 as -64 and rejects the module). 65 function
# types, then a cont type referencing index 64, used by cont.new.
write("CT05_cont_index_ge64.wasm", module(
    type_section(*([functype([], [])] * 65), cont_type(64)),
    func_section([0, 64]),
    code_section([
        END,                                          # func 0: the continuation target
        ref_func(0) + cont_new(65) + drop() + END,    # func 1
    ]),
))
