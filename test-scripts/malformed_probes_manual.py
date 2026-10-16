#!/usr/bin/env python3
"""Reproduction probes that MUST be imported one per headless JVM (workstream J, robustness findings).

Do not put this file's modules into a shared `run_probes.ps1` batch:
  * J01 builds a 2 GiB `.memory0` block (analysis then exceeds the per-file timeout), and
  * J02 makes the JVM throw an escaping `OutOfMemoryError` that aborts the whole headless process.

`test-scripts/robustness-sweep.ps1` runs exactly these one-per-JVM and classifies the outcome.
This file does not match the `probes_*.py`/`gen_*.py` globs on purpose.

Usage: python malformed_probes_manual.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])

T1 = functype([], [])            # (func) -> ()

# ---------------------------------------------------------------------------------------------
# J01 - linear memory with an absurd initial page count (severity a: hang/timeout).
# loadMemories() sizes the block as Math.min(initial * 65536, CODE_BASE=0x80000000), so
# initial=0xFFFFFFFF pages requests a 2 GiB initialized .memory0 block that the loader happily
# builds (observed: PROBE-BLOCK .memory0 size=2147483648). Auto-analysis then walks a 2 GiB address
# space and hits the per-file analysis timeout. No "initial <= maximum" check either (see the
# corpus M01 probe). Regression signal: the block is built at all / the load+analysis becomes slow.
# ---------------------------------------------------------------------------------------------
write("J01_mem_initial_4G_pages.wasm", module(memory_section([(0x00, 0xFFFFFFFF)])))

# ---------------------------------------------------------------------------------------------
# J02 - a single locals group declaring 0x40000000 i32 locals (severity b: process death).
# THE headline finding. WasmLocalEntry.getCount() casts the LEB long to int and
# WasmCodeEntry.getLocals() does new ValType[count] with no bound. WasmAnalysis.getFunctions()
# calls it (WasmAnalysis.java:145) while the decompiler initialises; the resulting
# java.lang.OutOfMemoryError is an Error, is not caught by the analyser wrapper, and aborts the
# entire headless run (exit 1, "Abort due to Headless analyzer error: Java heap space").
# NOTE: 0xFFFFFFFF (i.e. -1, see J03) is swallowed as NegativeArraySizeException; a large
# *positive* count is what aborts.
# build the code entry directly: wasm_probe_lib.code_section() always wraps its argument in a fresh
# (locals-less) body, so a body with locals must be placed in the section by hand.
# ---------------------------------------------------------------------------------------------
write("J02_locals_count_overflow.wasm", module(
    type_section(T1),
    func_section([0]),
    section(10, vec([body(END, locals_=[(0x40000000, I32)])]))))

print("done")