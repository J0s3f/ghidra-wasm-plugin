#!/usr/bin/env python3
"""Probes owned by the *parsers/types* workstream (agent B).

Add new probes here - never edit `gen_feature_probes.py` (frozen baseline) or `probes_analysis.py`
(owned by the other agent). Use the helpers from `wasm_probe_lib`:

    write("B01_limits_shared_max.wasm", module(...))

Each probe should be a *valid* module for the feature it exercises, and its expected result should be
written down in REPORT-B.md (funcs / instrs / undefined_bytes / decompiled, plus the disassembly or
decompiled C when type/signature correctness is the point).

Usage: python probes_types.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])

# ---------------------------------------------------------------------------------------------
# Add probes below. Examples of what belongs in this file:
#   * limits: shared / memory64 / custom-page-size flag combinations, several memories/tables in
#     one section so a parse desync would be visible
#   * constant expressions: extended-const arithmetic, v128.const, ref.null/ref.func of typed refs,
#     GC initializers, and unknown-opcode initializers that must not fail the import
#   * value types: (ref null $t) / (ref $t) parameters and results, GC reference types,
#     exnref, multi-byte valtypes, locals/globals/tables that use them
# ---------------------------------------------------------------------------------------------
