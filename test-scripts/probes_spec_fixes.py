#!/usr/bin/env python3
"""Probes owned by the *spec-suite findings* workstream (branch `fix/spec-findings`).

These target the three ranked findings of the official spec-suite run in
`MODERN_WASM_GAPS.md` §6 / `REPORT-G.md` §3 / `test-scripts/spectest-BASELINE.md` §3:

  SF01  `select` (0x1B) is not decoded after an unconditional terminator
        (`unreachable`, `br`, `br_table`, `return`). The opcode's *encoding* is
        type-independent; only the stack-width context (`ctx_operand_size`) must be
        resolved, and it must default to 32-bit when the stack is polymorphic.
        Mirrors the spec suite's `unwind.wast` functions `select-after-*` (there the
        `select` byte is adjacent to the terminator, with no context-setting
        instruction in between).

  SF02  `WasmStackVariableAnalyzer` throws and logs a warning for
        (a) loads/stores whose instruction has no Register input object
            (`Index 0 out of bounds for length 0`) and
        (b) `local.set` whose first input object is an Address, not a Register
            (`GenericAddress cannot be cast to Register`).
        Both must analyse without any logged exception.

  SF03  a very large `br_table` body (the spec suite's `br_table.wast` `large`
        function, ~16k case labels) makes the native decompiler process die.
        The pre-analyzer must bound the number of branch instructions it materialises
        for one `br_table` and report the truncation instead of crashing.

Every module is spec-valid. Expected metrics live in `test-scripts/expected-results.json`
(regenerate with `check-local.ps1 -Update`).

Usage: python probes_spec_fixes.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])

UNREACHABLE = b"\x00"
SELECT = b"\x1b"
RETURN = b"\x0f"


def br_table_enc(labels):
    """Encode `br_table`.

    `labels` is the full label vector: `labels[:-1]` are the case labels and
    `labels[-1]` is the default label, i.e. the wire form is
    `count = len(labels) - 1`, then every label (case labels followed by the default).
    (`wasm_probe_lib.br_table` writes `vec(labels)`, which drops the default label.)
    """
    return b"\x0e" + uleb(len(labels) - 1) + b"".join(uleb(l) for l in labels)


# ---------------------------------------------------------------------------------------------
# SF01 - select after an unconditional terminator (the spec suite's select-after-* functions).
#        Each body puts `select` immediately after the terminator, with no value-producing
#        instruction in between (which would re-establish the operand-size context).
#
#   f0 select-after-unreachable : f32.const 0; f64.const 1; i64.const 0; unreachable; select
#   f1 select-after-br          : block (result i32) { f32.const 0; f64.const 1; i64.const 0;
#                                                      i32.const 9; br 0; select }
#   f2 select-after-return      : f32.const 0; f64.const 1; i64.const 1; i32.const 9; return; select
#   f3 select-after-br_table    : block (result i32) { f32.const 0; f64.const 1; i64.const 0;
#                                                      i32.const 9; i32.const 0; br_table 0; select }
#   f4 select-then-drop         : i32.const 1; i32.const 2; unreachable; select; drop
#
# Before the fix the 0x1B byte below the terminator stays undefined in f0/f1/f2/f3/f4.
# ---------------------------------------------------------------------------------------------
write("SF01_select_after_terminator.wasm", module(
    type_section(functype([], [I32]), functype([], [])),
    func_section([0, 0, 0, 0, 1]),
    export_section([("f0", 0, 0), ("f1", 0, 1), ("f2", 0, 2), ("f3", 0, 3), ("f4", 0, 4)]),
    code_section([
        # f0
        f32_const(0) + f64_const(1) + i64_const(0) + UNREACHABLE + SELECT + END,
        # f1
        block(I32, f32_const(0) + f64_const(1) + i64_const(0) + i32_const(9) + br(0) + SELECT) + END,
        # f2
        f32_const(0) + f64_const(1) + i64_const(1) + i32_const(9) + RETURN + SELECT + END,
        # f3
        block(I32, f32_const(0) + f64_const(1) + i64_const(0) + i32_const(9) + i32_const(0) +
              br_table_enc([0]) + SELECT) + END,
        # f4
        i32_const(1) + i32_const(2) + UNREACHABLE + SELECT + drop() + END,
    ]),
))

# ---------------------------------------------------------------------------------------------
# SF02 - WasmStackVariableAnalyzer crash paths. The trigger (see spec suite `return.wast`) is an
#        instruction in *unreachable* code: after a terminator the stack is polymorphic, the
#        pre-analyzer records ctx_sp = 0, and the modelled stack-register slot (REG_STACK_BASE-16,
#        i.e. index -1) is not a defined register, so getInputObjects() yields an Address rather
#        than a Register. Then:
#          (a) a load/store with no Register input object hit `getRegisters(...).get(0)`
#              -> `Index 0 out of bounds for length 0`;
#          (b) `local.set` hit `(Register) getInputObjects()[0]`
#              -> `GenericAddress cannot be cast to Register`.
#        Each function below is valid (everything after `unreachable` is polymorphic) and must
#        analyse without a logged WasmStackVariableAnalyzer exception.
# ---------------------------------------------------------------------------------------------
def _unreachable_fn(rest):
    return module(
        type_section(functype([I32], [])),
        func_section([0]),
        export_section([("f", 0, 0)]),
        code_section([UNREACHABLE + rest + END]),
    )


write("SF02_stackvar_local_set.wasm", _unreachable_fn(local_set(0)))
write("SF02_stackvar_f32_load.wasm", _unreachable_fn(b"\x2a" + uleb(2) + uleb(0) + drop()))
write("SF02_stackvar_i64_store.wasm", _unreachable_fn(b"\x37" + uleb(3) + uleb(0)))
write("SF02_stackvar_i64_load8_s.wasm", _unreachable_fn(b"\x30" + uleb(0) + uleb(0) + drop()))
write("SF02_stackvar_i64_store16.wasm", _unreachable_fn(b"\x3d" + uleb(1) + uleb(0)))

# ---------------------------------------------------------------------------------------------
# SF03 - a very large br_table (bounded-degradation target). 4000 case labels plus the default,
#        all branching to the enclosing block; before the fix the ~4000 case-directive
#        instructions make the native decompiler process die.
# ---------------------------------------------------------------------------------------------
_N = 4000
write("SF03_large_br_table.wasm", module(
    type_section(functype([I32], [])),
    func_section([0]),
    export_section([("large", 0, 0)]),
    code_section([
        block(0x40, local_get(0) + br_table_enc([0] * (_N + 1))) + END,
    ]),
))
