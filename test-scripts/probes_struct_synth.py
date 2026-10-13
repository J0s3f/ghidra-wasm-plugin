#!/usr/bin/env python3
"""Probes for the wasm call-graph-aware struct synthesis pass (WasmStructSynthAnalyzer).

Probe prefix: ST (struct synthesis).

  ST01  A pointer is passed along a 2-function call chain (main -> reader,
        main -> writer) and fields are accessed at several offsets.  A struct
        must be synthesized and the params retyped to PointerDataType(struct).

  ST02  Two independent pointers flow through separate call chains.  Two
        structs must be synthesized (no cross-talk between the two classes).

  ST03  Accesses go through a global.get (not a local).  Documented behaviour:
        no struct is synthesized (globals are skipped in v1).

Usage: python probes_struct_synth.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])


# ---------------------------------------------------------------- helpers

def i32_load(offset, align=2):
    """i32.load align=A offset=O"""
    return b"\x28" + uleb(align) + uleb(offset)


def i32_store(offset, align=2):
    """i32.store align=A offset=O"""
    return b"\x36" + uleb(align) + uleb(offset)


def i64_load(offset, align=3):
    """i64.load align=A offset=O"""
    return b"\x29" + uleb(align) + uleb(offset)


def i64_store(offset, align=3):
    """i64.store align=A offset=O"""
    return b"\x37" + uleb(align) + uleb(offset)


# ---------------------------------------------------------------- ST01: call chain -> one struct

# Three functions:
#   func 0 (main):   (param i32) -> ()       calls func1(ptr), func2(ptr, 42)
#   func 1 (reader): (param i32) -> (i32)    loads at offsets 0, 4, 8
#   func 2 (writer): (param i32, i32) -> ()  stores at offsets 0, 4
#
# Types:
#   type 0: (i32) -> (i32)
#   type 1: (i32, i32) -> ()
#   type 2: (i32) -> ()

ST01_TYPES = type_section(
    functype([I32], [I32]),       # type 0: reader
    functype([I32, I32], []),     # type 1: writer
    functype([I32], []),          # type 2: main
)

ST01_FUNCS = func_section([2, 0, 1])  # func0=main(type2), func1=reader(type0), func2=writer(type1)

ST01_MEMORY = memory_section([(0x00, 1)])

ST01_EXPORTS = export_section([("main", 0, 0)])

# func 1 (reader): local.get 0; i32.load offset=0; local.get 0; i32.load offset=4; i32.add;
#                  local.get 0; i32.load offset=8; i32.add; end
ST01_READER = (
    local_get(0) + i32_load(0) +
    local_get(0) + i32_load(4) +
    b"\x6A" +  # i32.add
    local_get(0) + i32_load(8) +
    b"\x6A" +  # i32.add
    END
)

# func 2 (writer): local.get 0; local.get 1; i32.store offset=0;
#                  local.get 0; local.get 1; i32.store offset=4; end
ST01_WRITER = (
    local_get(0) + local_get(1) + i32_store(0) +
    local_get(0) + local_get(1) + i32_store(4) +
    END
)

# func 0 (main): local.get 0; call 1; drop; local.get 0; i32.const 42; call 2; end
ST01_MAIN = (
    local_get(0) + call(1) + drop() +
    local_get(0) + i32_const(42) + call(2) +
    END
)

write("ST01_call_chain_struct.wasm", module(
    ST01_TYPES,
    ST01_FUNCS,
    ST01_MEMORY,
    ST01_EXPORTS,
    code_section([ST01_MAIN, ST01_READER, ST01_WRITER]),
))


# ---------------------------------------------------------------- ST02: two independent pointers -> two structs

# Four functions:
#   func 0 (main):   (param i32, i32) -> ()   calls func1(ptrA), func2(ptrB)
#   func 1 (readerA): (param i32) -> (i32)    loads at offsets 0, 4
#   func 2 (readerB): (param i32) -> (i32)    loads at offsets 0, 8
#
# Types:
#   type 0: (i32) -> (i32)        -- readers
#   type 1: (i32, i32) -> ()      -- main

ST02_TYPES = type_section(
    functype([I32], [I32]),       # type 0: readers
    functype([I32, I32], []),     # type 1: main
)

ST02_FUNCS = func_section([1, 0, 0])  # func0=main(type1), func1=readerA(type0), func2=readerB(type0)

ST02_MEMORY = memory_section([(0x00, 1)])

ST02_EXPORTS = export_section([("main", 0, 0)])

# func 1 (readerA): local.get 0; i32.load offset=0; local.get 0; i32.load offset=4; i32.add; end
ST02_READER_A = (
    local_get(0) + i32_load(0) +
    local_get(0) + i32_load(4) +
    b"\x6A" +  # i32.add
    END
)

# func 2 (readerB): local.get 0; i32.load offset=0; local.get 0; i32.load offset=8; i32.add; end
ST02_READER_B = (
    local_get(0) + i32_load(0) +
    local_get(0) + i32_load(8) +
    b"\x6A" +  # i32.add
    END
)

# func 0 (main): local.get 0; call 1; drop; local.get 1; call 2; drop; end
ST02_MAIN = (
    local_get(0) + call(1) + drop() +
    local_get(1) + call(2) + drop() +
    END
)

write("ST02_two_independent_structs.wasm", module(
    ST02_TYPES,
    ST02_FUNCS,
    ST02_MEMORY,
    ST02_EXPORTS,
    code_section([ST02_MAIN, ST02_READER_A, ST02_READER_B]),
))


# ---------------------------------------------------------------- ST03: global-based access -> no struct (documented)

# One function:
#   func 0 (main): () -> (i32)
#     global.get 0; i32.load offset=0; global.get 0; i32.load offset=4; i32.add; end
#
# Global 0: i32, immutable, init = i32.const 1024
#
# The accesses go through a global, not a local.  In v1 the analyzer skips
# global-based accesses (documented behaviour), so no struct is synthesized.

ST03_TYPES = type_section(
    functype([], [I32]),          # type 0: main
)

ST03_FUNCS = func_section([0])

ST03_MEMORY = memory_section([(0x00, 1)])

ST03_GLOBALS = global_section([
    (I32, False, i32_const(1024)),  # global 0: immutable i32 = 1024
])

ST03_EXPORTS = export_section([("main", 0, 0)])

# func 0 (main): global.get 0; i32.load offset=0; global.get 0; i32.load offset=4; i32.add; end
ST03_MAIN = (
    global_get(0) + i32_load(0) +
    global_get(0) + i32_load(4) +
    b"\x6A" +  # i32.add
    END
)

write("ST03_global_address_no_struct.wasm", module(
    ST03_TYPES,
    ST03_FUNCS,
    ST03_MEMORY,
    ST03_GLOBALS,
    ST03_EXPORTS,
    code_section([ST03_MAIN]),
))


# ---------------------------------------------------------------- ST04: offset via i32.const + i32.add

# Tests the "local.get N; i32.const K; i32.add; i32.load offset=O" pattern.
# The effective offset is K + O.
#
#   func 0 (main): (param i32) -> (i32)
#     local.get 0; i32.const 4; i32.add; i32.load offset=0;   ;; access at offset 4
#     local.get 0; i32.const 8; i32.add; i32.load offset=0;   ;; access at offset 8
#     i32.add; end

ST04_TYPES = type_section(
    functype([I32], [I32]),       # type 0: main
)

ST04_FUNCS = func_section([0])

ST04_MEMORY = memory_section([(0x00, 1)])

ST04_EXPORTS = export_section([("main", 0, 0)])

# func 0 (main): local.get 0; i32.const 4; i32.add; i32.load offset=0;
#                local.get 0; i32.const 8; i32.add; i32.load offset=0; i32.add; end
ST04_MAIN = (
    local_get(0) + i32_const(4) + b"\x6A" + i32_load(0) +   # ptr+4
    local_get(0) + i32_const(8) + b"\x6A" + i32_load(0) +   # ptr+8
    b"\x6A" +  # i32.add
    END
)

write("ST04_const_offset_add.wasm", module(
    ST04_TYPES,
    ST04_FUNCS,
    ST04_MEMORY,
    ST04_EXPORTS,
    code_section([ST04_MAIN]),
))
