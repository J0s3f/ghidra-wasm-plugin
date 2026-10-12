#!/usr/bin/env python3
"""Probes for the stack-switching / JSPI opcodes (0xE0-0xE6), workstream H5.

Each module imports with `undefined_bytes == 0` and decompiles; the listing must show the real
mnemonics (cont.new / cont.bind / suspend / resume / resume_throw / resume_throw_ref / switch) and,
for the resume family, the handler-vector clauses as their own `on tag=.. label=..` / `on tag=..
switch` directive instructions.

Encoding (stack-switching proposal, "Binary format"):
    0xE0 cont.new $ct              $ct:u32
    0xE1 cont.bind $ct $ct'        $ct:u32 $ct':u32
    0xE2 suspend $t                $t:u32
    0xE3 resume $ct hdl*           $ct:u32 hdl*
    0xE4 resume_throw $ct $e hdl*  $ct:u32 $e:u32 hdl*
    0xE5 resume_throw_ref $ct hdl* $ct:u32 hdl*
    0xE6 switch $ct1 $t            $ct1:u32 $t:u32
    hdl* = vec(clause); clause = 0x00 tagidx labelidx | 0x01 tagidx

Note on the type index: `cont.new $ct` / `resume $ct` name a continuation type `(cont $ft)`. This
plugin's type-section reader rejects a `cont` composite type (0x5D would be an "unsupported wasm
type form"), so the probes point those indices at an ordinary (0x60) function type. The decoder
does not care - it models the continuation's stack effect from that function type's parameters and
results - see REPORT-H5.md.

Usage: python probes_stackswitch.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])

# ---------------------------------------------------------------- instruction helpers (local)

def cont_new(typeidx):
    """0xE0 cont.new $ct."""
    return b"\xE0" + uleb(typeidx)


def cont_bind(t1, t2):
    """0xE1 cont.bind $ct $ct'."""
    return b"\xE1" + uleb(t1) + uleb(t2)


def suspend(tag):
    """0xE2 suspend $t."""
    return b"\xE2" + uleb(tag)


def on_label(tag, label):
    """Handler clause 0x00 tagidx labelidx."""
    return b"\x00" + uleb(tag) + uleb(label)


def on_switch(tag):
    """Handler clause 0x01 tagidx."""
    return b"\x01" + uleb(tag)


def resume(ct, handlers=()):
    """0xE3 resume $ct hdl*."""
    return b"\xE3" + uleb(ct) + vec(list(handlers))


def resume_throw(ct, tag, handlers=()):
    """0xE4 resume_throw $ct $e hdl*."""
    return b"\xE4" + uleb(ct) + uleb(tag) + vec(list(handlers))


def resume_throw_ref(ct, handlers=()):
    """0xE5 resume_throw_ref $ct hdl*."""
    return b"\xE5" + uleb(ct) + vec(list(handlers))


def switch(ct, tag):
    """0xE6 switch $ct1 $t."""
    return b"\xE6" + uleb(ct) + uleb(tag)


def _ht_exn_bytes():
    """s33 encoding of the abstract heap type `exn` (byte 0x69)."""
    return sleb(HT_EXN - 0x80)


def ref_null_exn():
    """ref.null exn: pushes an exnref (needed by resume_throw_ref)."""
    return b"\xD0" + _ht_exn_bytes()


def ref_func(funcidx):
    """ref.func x: pushes a funcref (the argument of cont.new)."""
    return b"\xD2" + uleb(funcidx)


# ---------------------------------------------------------------- H01: cont.new
# []->(): ref.func 0 pushes the function reference, cont.new replaces it with the continuation
# reference, which is then dropped.
write("H01_ss_cont_new.wasm", module(
    type_section(functype([], [])),
    func_section([0, 0]),
    export_section([("f", 0, 1)]),
    code_section([
        END,                                         # function 0: the continuation target
        ref_func(0) + cont_new(0) + drop() + END,    # function 1
    ]),
))

# ---------------------------------------------------------------- H02: cont.bind (bound prefix = 1)
# type 0: []->[], type 1: [i32]->[]. cont.bind 1 0 binds one i32 to a (cont [i32]->[]) and yields
# a (cont []->[]): the i32 sits below the continuation reference.
write("H02_ss_cont_bind.wasm", module(
    type_section(functype([], []), functype([I32], [])),
    func_section([0, 0]),
    export_section([("f", 0, 1)]),
    code_section([
        END,
        i32_const(7) + ref_func(0) + cont_new(1) + cont_bind(1, 0) + drop() + END,
    ]),
))

# ---------------------------------------------------------------- H03: suspend (tag [i32]->[i32])
# suspend pops the tag's i32 parameter and pushes its i32 result.
write("H03_ss_suspend.wasm", module(
    type_section(functype([], []), functype([I32], [I32])),
    tag_section([(0x00, 1)]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([i32_const(5) + suspend(0) + drop() + END]),
))

# ---------------------------------------------------------------- H04: resume + one `on <tag> <label>`
# cont type = type 0 ([]->[]): resume pops the continuation reference and pushes nothing. The
# handler clause is a directive instruction that must be consumed exactly (the `end` follows it).
write("H04_ss_resume.wasm", module(
    type_section(functype([], [])),
    tag_section([(0x00, 0)]),
    func_section([0, 0]),
    export_section([("f", 0, 1)]),
    code_section([
        END,
        ref_func(0) + cont_new(0) + resume(0, [on_label(0, 0)]) + END,
    ]),
))

# ---------------------------------------------------------------- H05: resume with both clause kinds
# Two handler clauses (on <tag> <label> and on <tag> switch); ordinary code follows the vector.
write("H05_ss_resume_handlers.wasm", module(
    type_section(functype([], []), functype([I32], [])),
    tag_section([(0x00, 0), (0x00, 1)]),
    func_section([0, 0]),
    export_section([("f", 0, 1)]),
    code_section([
        END,
        ref_func(0) + cont_new(0) + resume(0, [on_label(0, 0), on_switch(1)])
        + i32_const(1) + drop() + END,
    ]),
))

# ---------------------------------------------------------------- H06: resume_throw (tag payload = 1)
# [te* (ref null $ct)] -> [t2*]: the i32 tag payload sits below the continuation reference.
write("H06_ss_resume_throw.wasm", module(
    type_section(functype([], []), functype([I32], [])),
    tag_section([(0x00, 1)]),
    func_section([0, 0]),
    export_section([("f", 0, 1)]),
    code_section([
        END,
        i32_const(9) + ref_func(0) + cont_new(0) + resume_throw(0, 0, [on_label(0, 0)]) + END,
    ]),
))

# ---------------------------------------------------------------- H07: resume_throw_ref
# [exnref (ref null $ct)] -> [t2*]: a null exnref below the continuation reference.
write("H07_ss_resume_throw_ref.wasm", module(
    type_section(functype([], [])),
    tag_section([(0x00, 0)]),
    func_section([0, 0]),
    export_section([("f", 0, 1)]),
    code_section([
        END,
        ref_null_exn() + ref_func(0) + cont_new(0) + resume_throw_ref(0, [on_label(0, 0)]) + END,
    ]),
))

# ---------------------------------------------------------------- H08: switch
# switch $ct1 $t has no handler vector.
write("H08_ss_switch.wasm", module(
    type_section(functype([], [])),
    tag_section([(0x00, 0)]),
    func_section([0, 0]),
    export_section([("f", 0, 1)]),
    code_section([
        END,
        ref_func(0) + cont_new(0) + switch(0, 0) + END,
    ]),
))

# ---------------------------------------------------------------- H09: mixed with ordinary code
# Ordinary arithmetic interleaved with cont.new / suspend / resume, so a mis-sized immediate or a
# mis-consumed handler vector shows up as a spurious instruction or undefined bytes.
write("H09_ss_mixed.wasm", module(
    type_section(functype([], []), functype([I32], [I32])),
    tag_section([(0x00, 1)]),
    func_section([0, 0, 0]),
    export_section([("f", 0, 2)]),
    code_section([
        END,                                                  # func 0: continuation target ([]->[])
        i32_const(1) + i32_const(2) + b"\x6A" + drop() + END,  # func 1: ordinary code
        # func 2: ordinary code around the stack-switching ops
        i32_const(1) + i32_const(2) + b"\x6A" + drop()
        + ref_func(0) + cont_new(0) + drop()                   # cont.new, result dropped
        + i32_const(5) + suspend(0) + i32_const(1) + b"\x6A" + drop()   # suspend + ordinary add
        + i32_const(3) + ref_func(0) + cont_new(1)             # [param (ref null $ct)]: param first
        + resume(1, [on_label(0, 0)]) + drop()                 # resume pops param + ref, pushes i32
        + END,
    ]),
))

# ---------------------------------------------------------------- H10: a resume result reaches the caller
# The enclosing function returns i32, so the decompiler must show the value produced by
# wasm_resume (shape p=1,r=1) rather than dropping it.
write("H10_ss_resume_result.wasm", module(
    type_section(functype([], []), functype([I32], [I32]), functype([], [I32])),
    tag_section([(0x00, 0)]),
    func_section([0, 2]),
    export_section([("f", 0, 1)]),
    code_section([
        END,                                                     # func 0: continuation target
        i32_const(3) + ref_func(0) + cont_new(1) + resume(1, [on_label(0, 0)]) + END,
    ]),
))
