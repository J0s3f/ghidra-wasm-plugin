#!/usr/bin/env python3
"""Probes owned by the *decoder/loader* workstream (agent A).

Add new probes here - never edit `gen_feature_probes.py` (frozen baseline) or `probes_types.py`
(owned by the other agent). Use the helpers from `wasm_probe_lib`:

    write("A01_multi_memory_memidx.wasm", module(...))

Each probe should be a *valid* module for the feature it exercises, and its expected result should be
written down in REPORT-A.md (funcs / instrs / undefined_bytes / decompiled, plus the disassembly when
decode correctness is the point).

Usage: python probes_analysis.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])

# ---------------------------------------------------------------------------------------------
# Add probes below. Examples of what belongs in this file:
#   * multi-memory: memarg memidx variants (load/store, all widths, SIMD, atomics),
#     memory.size/grow/copy/init/fill with memidx, and memory blocks created for index >= 1
#   * unknown/unsupported opcodes that must degrade to a visible `unimplemented` instruction
#     without desyncing the rest of the function
#     (GC 0xFB, new EH 0x1F, 0xE0-range stack switching, 0xFC >= 0x12, JS string builtins, ...)
# ---------------------------------------------------------------------------------------------
