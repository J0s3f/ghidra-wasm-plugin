#!/usr/bin/env python3
"""Permanent reproduction probes for the malformed-input robustness findings (workstream J).

These modules are *intentionally invalid*. Unlike every other ``probes_*.py`` file, the probes here
must NOT import cleanly: each one pins a specific loader misbehaviour so a future regression is
caught. This file keeps only the cases that are safe inside a shared ``run_probes.ps1`` batch;
the two that need their own headless JVM (J01: 2 GiB memory allocation, J02: escaping
``OutOfMemoryError``) live in ``malformed_probes_manual.py`` and are swept by
``robustness-sweep.ps1``.

Measured outcomes (Ghidra 12.1.4, GHIDRA_HEADLESS_MAXMEM=1500M, analysis ON; see REPORT-J.md):

    J03  locals group count = 0xFFFFFFFF    -> import_ok: caught NegativeArraySizeException,
                                    nonsense program produced (SEC-c)
    J04  table initial = 0xFFFFFFFF elems   -> import_ok: Ghidra 16 GiB guard throws (caught), no table
    J05  func-type param count = 0xFFFFFFFF -> import_failed: NegativeArraySizeException caught at
                                    section-parse time (good behaviour - guards against it becoming Error)

Every one of these is invalid WebAssembly. A robust loader should reject each with a bounded
"Import failed" message and a bounded amount of work.

Usage: python probes_malformed.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])

T1 = functype([], [])            # (func) -> ()

# ---------------------------------------------------------------------------------------------
# J03 - a single locals group declaring 0xFFFFFFFF i32 locals (severity c: silent acceptance).
# (int) 0xFFFFFFFF == -1 -> new ValType[-1] -> NegativeArraySizeException, which *is* caught per
# analyser (Analysis Task: Wasm Pre-Analyzer - -1 ... WasmCodeEntry.getLocals(WasmCodeEntry.java:71)).
# The module still imports and a nonsense function is produced (funcs=1 instrs=1 undefined_bytes=7).
# Same root cause as J02 (see malformed_probes_manual.py); this face is the "silently accepted" one.
# ---------------------------------------------------------------------------------------------
write("J03_locals_count_neg.wasm", module(
    type_section(T1),
    func_section([0]),
    section(10, vec([body(END, locals_=[(0xFFFFFFFF, I32)])]))))

# ---------------------------------------------------------------------------------------------
# J04 - table with an absurd initial element count (neighbour of J01).
# createTableBlock() computes byteSize = elementDataType.getLength() * numElements with no cap
# (~32 GiB for funcref) and then casts the count to int for ArrayDataType. Only Ghidra's global
# 16 GiB program-size guard stops it; the IllegalStateException is caught and the module is still
# accepted, silently without a table. Regression signal: exit code / log of the load.
# ---------------------------------------------------------------------------------------------
write("J04_table_initial_4G_elems.wasm", module(table_section([(FUNCREF, 0x00, 0xFFFFFFFF)])))

# ---------------------------------------------------------------------------------------------
# J05 - a function type whose parameter vector count is 0xFFFFFFFF.
# WasmFuncType() does new ValType[(int) pcount] with no bound; this throws at *section parse* time,
# inside the WasmLoader.load() catch, so today it is a clean "Import failed" (good behaviour). The
# probe guards against that path ever turning into an unhandled Error (same class of bug as J02).
# ---------------------------------------------------------------------------------------------
write("J05_functype_param_overflow.wasm", module(
    section(1, vec([b"\x60" + b"\xff\xff\xff\xff\x0f" + vec([])]))))

print("done")
