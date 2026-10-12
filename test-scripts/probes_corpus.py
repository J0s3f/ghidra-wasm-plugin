#!/usr/bin/env python3
"""Probes owned by the *real-world corpus* workstream (REPORT-H.md).

Each probe reduces one measurement from the corpus sweep to a minimal module, so the behaviour
cannot silently change. They are deliberately tiny and self-contained; the expected metrics are
recorded in REPORT-H.md section 5 and repeated next to each probe.

    C01_import_thunk        imported functions get a 4-byte placeholder body -> undefined_bytes
    C02_invalid_body        a malformed body is rejected but leaves a bogus instruction behind
    C03_import_shared_mem   an imported shared memory still yields a sized .memory0 and decodes

Run with the normal runner:  pwsh test-scripts/run_probes.ps1 -Generators probes_corpus.py
Usage: python probes_corpus.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])

# ---------------------------------------------------------------------------------------------
# C01 - the corpus invariant: every imported function becomes a 4-byte, zero-instruction body,
# which is counted as `undefined_bytes`. Rasterbator has 39 imports -> undef = 156; SQL.js 38 ->
# 152; avif 31 -> 124. A module with 2 imports and 1 defined function must therefore report
# funcs=3, undefined_bytes=8, empty_bodies=2, and the defined function must decode cleanly.
#
# (global.get/... unaffected; the important part is `4 * imports`.)
# ---------------------------------------------------------------------------------------------
write("C01_import_thunk.wasm", module(
    type_section(functype([], [I32])),
    import_section([
        ("env", "a", 0, uleb(0)),
        ("env", "b", 0, uleb(0)),
    ]),
    func_section([0]),
    export_section([("f", 0, 2)]),
    code_section([i32_const(0) + END]),
))

# ---------------------------------------------------------------------------------------------
# C02 - a function body that is syntactically present but invalid (empty body with a declared i32
# result; V8 rejects this with "expected 1 elements on the stack for fallthru"). The pre-analyzer
# raises ValidationException, yet a Function is still created over the 2-byte body range starting at
# the *locals-count* byte, which is then decoded as `unreachable`, leaving 1 undefined byte. The
# second function in the module must still analyse and decompile, i.e. the failure stays contained.
#
# Expected: funcs=2, undefined_bytes=1, decompiled=2/0, one WasmPreAnalyzer ERROR mentioning
# "Validation error ... pop from empty stack", and `unreachable` at the bad body's entry.
# ---------------------------------------------------------------------------------------------
write("C02_invalid_body.wasm", module(
    type_section(functype([I32, I32], [I32]), functype([], [I32])),
    func_section([0, 1]),
    export_section([("bad", 0, 0), ("good", 0, 1)]),
    code_section([END, i32_const(7) + END]),
))

# ---------------------------------------------------------------------------------------------
# C03 - positive regression pin reduced from `squoosh_oxipng_bg_parallel.wasm` (wasm-bindgen +
# rayon) and `web-tree-sitter.wasm` (Emscripten SIDE_MODULE): both define *no* memory of their own
# and import one instead. The plugin must still create a `.memory0` sized to the declared initial
# page count and decode memory accesses without desync.
#
# Shared memory (flags 0x03 = has-maximum | shared), initial 1 page (65536 B), max 2 pages.
# Expected: .memory0 size=65536, funcs=1, undefined_bytes=0.
# ---------------------------------------------------------------------------------------------
write("C03_import_shared_mem.wasm", module(
    type_section(functype([], [I32])),
    import_section([("env", "memory", 2, bytes([0x03]) + uleb(1) + uleb(2))]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([i32_const(0) + b"\x28\x02\x00" + END]),   # i32.const 0; i32.load align=2 offset=0
))
