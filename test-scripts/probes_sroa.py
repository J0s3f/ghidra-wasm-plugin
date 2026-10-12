#!/usr/bin/env python3
"""Probes for the stack-as-aggregate + SROA workstream (branch `feat/stack-sroa`).

`WasmStackVariableAnalyzer` models the wasm frame as one aggregate (the region of the guessed C
stack the function touches) and splits it into *atoms* - one stack variable per distinct observed
(width, offset) access (the NotDec paper section 3.2.3 / the Decompilation Wiki's Aggregate
Structure Identification recipe). These probes pin the atom rule:

  SROA01  struct-like frame: a distinct write (and read-back) at offsets 0 (i32/4), 4 (i64/8),
          12 (f32/4) and 16 (v128/16), plus a repeated i32 access at offset 0. The frame must
          split into four non-overlapping atoms of widths 4/8/4/16, and the repeated access must
          merge into the atom at offset 0 (no duplicate variable).
  SROA02  unaligned/overlapping frame: an i32 at 0 and an i64 at 2. The two atoms overlap, so
          the atom is widened to the union [0,10) and falls back to an undefined blob of that
          size. It must not crash and must be deterministic (independent of instruction order).
  SROA03  unreachable-code load/store (the SF02 crash path): a load, a store and a `local.set`
          after `unreachable`, where the stack is polymorphic and the modelled stack register is
          not defined, so the instructions have no Register input object. Analysis must stay
          clean (no logged exception, `undefined_bytes == 0`).

The accesses are relative to the guessed C stack pointer, so each module has a mutable i32
global 0 used as the address base (the pre-analyzer guesses it automatically) and a memory.

Usage: python probes_sroa.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])

# Scalar / SIMD load-store opcodes.
I32_LOAD, I64_LOAD, F32_LOAD = b"\x28", b"\x29", b"\x2a"
I32_STORE, I64_STORE, F32_STORE = b"\x36", b"\x37", b"\x38"
V128_LOAD = simd_op(0x00)
V128_STORE = simd_op(0x0b)
UNREACHABLE = b"\x00"


def memarg(align, offset=0):
    """A memory-0 memarg immediate: flags/alignment byte, then the offset."""
    return uleb(align) + uleb(offset)


def stack_global():
    """The mutable i32 global 0 that the pre-analyzer guesses as the C stack pointer."""
    return global_section([(I32, True, i32_const(0))])


# ---------------------------------------------------------------------------------------------
# SROA01 - struct-like frame access pattern. Offsets 0/4/12/16 are chosen so the four atoms do
# not overlap (the i64 at 4 spans [4,12), so the f32 sits at 12, just past it): the listing must
# show four separate stack variables with widths 4/8/4/16. The second i32 read at offset 0
# exercises "a repeated access at the same offset with the same width merges".
# ---------------------------------------------------------------------------------------------
write("SROA01_struct_frame.wasm", module(
    type_section(functype([], [I32])),
    memory_section([(0x00, 1)]),
    stack_global(),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        global_get(0) + i32_const(0x11223344) + I32_STORE + memarg(2, 0) +    # i32 @ 0
        global_get(0) + i64_const(0x2222222222222222) + I64_STORE + memarg(3, 4) +  # i64 @ 4
        global_get(0) + f32_const(1.5) + F32_STORE + memarg(2, 12) +          # f32 @ 12
        global_get(0) + v128_const(bytes(range(16))) + V128_STORE + memarg(4, 16) +  # v128 @ 16
        global_get(0) + I32_LOAD + memarg(2, 0) + drop() +                    # read back i32
        global_get(0) + I64_LOAD + memarg(3, 4) + drop() +                    # read back i64
        global_get(0) + F32_LOAD + memarg(2, 12) + drop() +                   # read back f32
        global_get(0) + V128_LOAD + memarg(4, 16) + drop() +                  # read back v128
        global_get(0) + I32_LOAD + memarg(2, 0) +                             # repeated i32 @ 0
        END,
    ]),
))

# ---------------------------------------------------------------------------------------------
# SROA02 - unaligned/overlapping pattern. The i32 at 0 ([0,4)) and the i64 at 2 ([2,10)) overlap:
# the atom must widen to the union [0,10) deterministically and analysis must not crash. The
# accesses are emitted in both orders (store i64 before i32, then read back) so the result cannot
# depend on instruction order.
# ---------------------------------------------------------------------------------------------
write("SROA02_unaligned_overlap.wasm", module(
    type_section(functype([], [I32])),
    memory_section([(0x00, 1)]),
    stack_global(),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        global_get(0) + i64_const(0x5566778899aabbcc) + I64_STORE + memarg(0, 2) +  # i64 @ 2 (unaligned)
        global_get(0) + i32_const(0x11223344) + I32_STORE + memarg(0, 0) +          # i32 @ 0
        global_get(0) + I32_LOAD + memarg(0, 0) + drop() +                          # read back i32
        global_get(0) + I64_LOAD + memarg(0, 2) + drop() +                          # read back i64
        i32_const(0) +
        END,
    ]),
))

# ---------------------------------------------------------------------------------------------
# SROA03 - unreachable-code load/store (the SF02 crash path). After `unreachable` the operand
# stack is polymorphic, the pre-analyzer records ctx_sp = 0 and the modelled stack register
# (REG_STACK_BASE-16) is not a defined register, so these instructions have no Register input
# object: the analyzer used to index an empty register list (`Index 0 out of bounds`) or cast a
# dynamic Address to Register (`GenericAddress cannot be cast to Register`). This must analyse
# cleanly.
# ---------------------------------------------------------------------------------------------
write("SROA03_unreachable_access.wasm", module(
    type_section(functype([I32], [])),
    memory_section([(0x00, 1)]),
    stack_global(),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        UNREACHABLE +
        I32_STORE + memarg(2, 8) +        # store with no register input
        I32_LOAD + memarg(2, 4) + drop() +  # load with no register input
        local_set(0) +                    # local.set whose input is a dynamic Address
        END,
    ]),
))
