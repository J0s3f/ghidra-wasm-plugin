#!/usr/bin/env python3
"""Regenerate the small *committed* fixture module used by the CI decompiler baseline.

The feature probes under `test-scripts/` are synthetic single-opcode modules: they exercise the
*decoder* (valtypes, sections, GC/EH/const-expr). They do not prove that the decompiler can turn a
real function body into C. This fixture is a tiny but *ordinary* module - two integer functions, a
memory load and store, a mutable global - whose `SUMMARY` line is recorded in
`test-scripts/expected-results.json`. `test-scripts/check-results.py` compares the SUMMARY of a fresh
DumpDecomp run of this file against that record, so a decompiler regression fails CI even though no
probe changed.

Only constructs the current plugin analyzes cleanly are used (functions with parameters, arithmetic,
`call`, a `block`/`br_if`, and memory load/store). Extra locals and loops are deliberately avoided:
at commit 1e2328b the function analyzer rejects them (`IndexOutOfBoundsException` / undefined bytes),
so a fixture using them would record a broken baseline instead of a regression signal.

Usage: python test-scripts/fixtures/make_fixture.py [output-dir]
Default output dir is the directory containing this script.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wasm_probe_lib import *  # noqa: F401,F403

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
set_output_dir(OUT)

I32_EQZ = b"\x45"
I32_ADD = b"\x6A"
I32_LOAD_ALIGN2_OFF0 = b"\x28\x02\x00"
I32_STORE_ALIGN2_OFF0 = b"\x36\x02\x00"

# add(i32, i32) -> i32 : a + b
ADD = local_get(0) + local_get(1) + I32_ADD + END

# main() -> i32 : if (arg == 0) return add(7, 8) - exercises a call and a block/br_if.
MAIN = (block(0x40, local_get(0) + I32_EQZ + br_if(0))
        + i32_const(7) + i32_const(8) + call(0) + END)

# load() -> i32 : return *(i32*)4
LOAD = i32_const(4) + I32_LOAD_ALIGN2_OFF0 + END

# store(i32) -> () : *(i32*)global0 = value
STORE = global_get(0) + local_get(0) + I32_STORE_ALIGN2_OFF0 + END

write("wasm_fixture.wasm", module(
    type_section(
        functype([I32, I32], [I32]),   # type 0: add
        functype([I32], [I32]),        # type 1: main
        functype([], [I32]),           # type 2: load
        functype([I32], []),           # type 3: store
    ),
    func_section([0, 1, 2, 3]),
    memory_section([(0x00, 1)]),
    global_section([(I32, True, i32_const(0))]),
    export_section([("add", 0, 0), ("main", 0, 1), ("load", 0, 2), ("store", 0, 3)]),
    code_section([ADD, MAIN, LOAD, STORE]),
))
