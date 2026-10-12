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

The type index in `cont.new $ct` / `cont.bind $ct $ct'` / `resume $ct` / `switch $ct1` names a
continuation type `(cont $ft)`, so every probe declares a real `cont` composite type (0x5D) in the
type section and points the instruction at it. The pre-analyzer resolves a continuation type to the
function type it references, so the stack effect is modelled from that function type's parameters
and results (see REPORT-H5.md / REPORT-CT.md). The H01-H03 modules changed only in the type index
(their instruction metrics are identical to before); H04-H10 were additionally restructured so the
modules are *valid* under the proposal - binaryen 133 then accepts them and wabt 1.0.42 rejects
them as an "unexpected type form" (class `wabt-gap`). A `resume` handler `(on $t $l)` branches to
a label whose block type must be `[t1* (ref $ct)]`, so those probes wrap the resume in a block (or
use the function's own result) and mark the fallthrough `unreachable`; `switch $ct1 $t` requires
`$ct1`'s function type to take at least the continuation argument.

Usage: python probes_stackswitch.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])

# ---------------------------------------------------------------- instruction helpers (local)

UNREACH = b"\x00"  # unreachable


def cont_type(funcidx):
    """0x5D cont $ft: the continuation composite type referencing function type `funcidx` (s33)."""
    return b"\x5D" + sleb(funcidx)


def ftype(params, results):
    """functype whose params/results may be ints or multi-byte valtype bytes (e.g. `ref_(1)`)."""
    enc = lambda xs: vec([bytes([x]) if isinstance(x, int) else x for x in xs])
    return b"\x60" + enc(params) + enc(results)


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
# reference, which is then dropped. type 1 = (cont 0).
write("H01_ss_cont_new.wasm", module(
    type_section(functype([], []), cont_type(0)),
    func_section([0, 0]),
    export_section([("f", 0, 1)]),
    code_section([
        END,                                         # function 0: the continuation target
        ref_func(0) + cont_new(1) + drop() + END,    # function 1
    ]),
))

# ---------------------------------------------------------------- H02: cont.bind (bound prefix = 1)
# type 0: []->[], type 1: [i32]->[], type 2: (cont 1), type 3: (cont 0). cont.bind 2 3 binds one i32
# to a (cont [i32]->[]) and yields a (cont []->[]): the i32 sits below the continuation reference.
write("H02_ss_cont_bind.wasm", module(
    type_section(functype([], []), functype([I32], []), cont_type(1), cont_type(0)),
    func_section([0, 0]),
    export_section([("f", 0, 1)]),
    code_section([
        END,
        i32_const(7) + ref_func(0) + cont_new(2) + cont_bind(2, 3) + drop() + END,
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
# type 0 ([]->[]) is the continuation target, type 1 is (cont 0), type 2 is []->[(ref 1)] - the
# handler label's block type, `[t1* (ref $ct)]` for the empty tag. The resume fallthrough (the
# continuation returning) is unreachable; the block yields the suspended continuation reference.
write("H04_ss_resume.wasm", module(
    type_section(functype([], []), cont_type(0), ftype([], [ref_(1)])),
    tag_section([(0x00, 0)]),
    func_section([0, 0]),
    code_section([
        END,
        block(2, ref_func(0) + cont_new(1) + resume(1, [on_label(0, 0)]) + UNREACH) + drop() + END,
    ]),
))

# ---------------------------------------------------------------- H05: resume with both clause kinds
# Two handler clauses (on <tag> <label> and on <tag> switch). The switch clause requires its tag to
# be []->[] (so it contributes no stack values); ordinary code follows the block.
write("H05_ss_resume_handlers.wasm", module(
    type_section(functype([], []), cont_type(0), ftype([], [ref_(1)])),
    tag_section([(0x00, 0), (0x00, 0)]),
    func_section([0, 0]),
    code_section([
        END,
        block(2, ref_func(0) + cont_new(1) + resume(1, [on_label(0, 0), on_switch(1)]) + UNREACH)
        + drop() + i32_const(1) + drop() + END,
    ]),
))

# ---------------------------------------------------------------- H06: resume_throw (tag payload = 1)
# type 0 ([]->[]), type 1 ([i32]->[]) is the exn tag, type 2 is (cont 0), type 3 is the label type
# []->[(ref 2)]. [te* (ref null $ct)] -> [t2*]: the i32 tag payload sits below the continuation
# reference.
write("H06_ss_resume_throw.wasm", module(
    type_section(functype([], []), functype([I32], []), cont_type(0), ftype([], [ref_(2)])),
    tag_section([(0x00, 0), (0x00, 1)]),
    func_section([0, 0]),
    code_section([
        END,
        block(3, i32_const(9) + ref_func(0) + cont_new(2) + resume_throw(2, 1, [on_label(0, 0)]) + UNREACH)
        + drop() + END,
    ]),
))

# ---------------------------------------------------------------- H07: resume_throw_ref
# [exnref (ref null $ct)] -> [t2*]: a null exnref below the continuation reference.
write("H07_ss_resume_throw_ref.wasm", module(
    type_section(functype([], []), cont_type(0), ftype([], [ref_(1)])),
    tag_section([(0x00, 0)]),
    func_section([0, 0]),
    code_section([
        END,
        block(2, ref_null_exn() + ref_func(0) + cont_new(1) + resume_throw_ref(1, [on_label(0, 0)]) + UNREACH)
        + drop() + END,
    ]),
))

# ---------------------------------------------------------------- H08: switch
# switch $ct1 $t: type 0 ([]->[]), type 1 (cont 0) = $ct2, type 2 = [(ref null 1)]->[] = $ct1's
# function type (it must take the switched continuation argument), type 3 = (cont 2). The switch
# consumes a (ref null $ct1) and yields $ct1's results (none).
write("H08_ss_switch.wasm", module(
    type_section(functype([], []), cont_type(0), ftype([ref_null(1)], []), cont_type(2)),
    tag_section([(0x00, 0)]),
    func_section([2, 0]),
    code_section([
        END,                                          # function 0: the $ct1 continuation target
        ref_func(0) + cont_new(3) + switch(3, 0) + END,
    ]),
))

# ---------------------------------------------------------------- H09: mixed with ordinary code
# Ordinary arithmetic interleaved with cont.new / suspend / resume, so a mis-sized immediate or a
# mis-consumed handler vector shows up as a spurious instruction or undefined bytes.
write("H09_ss_mixed.wasm", module(
    type_section(functype([], []), functype([I32], [I32]), cont_type(0), cont_type(1),
                 ftype([], [I32, ref_(3)])),
    tag_section([(0x00, 1)]),
    func_section([0, 1, 0]),
    code_section([
        END,                                                   # func 0: continuation target ([]->[])
        local_get(0) + END,                                    # func 1: continuation target ([i32]->[i32])
        # func 2: ordinary code around the stack-switching ops
        i32_const(1) + i32_const(2) + b"\x6A" + drop()
        + ref_func(0) + cont_new(2) + drop()                    # cont.new (cont 0), result dropped
        + i32_const(5) + suspend(0) + drop()                    # suspend + drop result
        + block(4, i32_const(3) + ref_func(1) + cont_new(3)     # [i32 (ref null $ct1)]: param first
                + resume(3, [on_label(0, 0)]) + UNREACH)        # resume under a handler
        + drop() + drop()                                       # the handler label yields [i32 (ref 3)]
        + END,
    ]),
))

# ---------------------------------------------------------------- H10: a resume result reaches the caller
# type 1 ([i32]->[i32]) is the continuation target, type 2 is (cont 1), type 3 is []->[i32]. The
# enclosing function returns i32, so the decompiler must show the value produced by wasm_resume
# (shape p=1,r=1) rather than dropping it.
write("H10_ss_resume_result.wasm", module(
    type_section(functype([], []), functype([I32], [I32]), cont_type(1), ftype([], [I32])),
    func_section([1, 3]),
    code_section([
        local_get(0) + END,                                      # func 0: continuation target ([i32]->[i32])
        i32_const(3) + ref_func(0) + cont_new(2) + resume(2, []) + END,
    ]),
))
