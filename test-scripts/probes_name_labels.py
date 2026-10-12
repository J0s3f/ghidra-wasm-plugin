#!/usr/bin/env python3
"""Probes owned by the *.name label targets* workstream (open item B6).

The extended-name-section label-name subsection (id 3) names the labels a function's body
introduces, indexed in *source order* (the function-wide label index space), not by the scoped
index a branch instruction uses. `WasmNameApplyAnalyzer` turns those names into real Ghidra
labels at the address each label branches to (a loop's start, otherwise the construct's `end`),
so the decompiler shows them as branch targets rather than as a function comment.

    L01  a function with a `block` (label 0), a `loop` (label 1) and an `if` (label 2), all
         branched to, plus a `.name` section whose label-name subsection names all three with
         the correct indices -> the listing/symbol table must carry the three names at the
         block's end, the loop's start and the if's end;
    L02  the same body with a `.name` section whose label-name subsection carries an
         out-of-range label index (99), an out-of-range function index (9) and a deliberately
         malformed trailing subsection -> the import must still succeed and the function must
         still decode (the applier tolerates unresolvable names; see the comment fallback).

The helper `_name_section` uses the binary custom-section name "name" (not ".name"): the loader
recognises "name", and the ".name" seen in the Ghidra tree is only the block/structure name.

Usage: python probes_name_labels.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])


def _name_section(*subsections) -> bytes:
    """Wrap name subsections in the `.name` custom section (binary name "name")."""
    return custom_section("name", b"".join(subsections))


def _labelled_body() -> bytes:
    """One function with a block/loop/if, each branched to.

    Function-wide label indices (source order): 0 = block, 1 = loop, 2 = if.
    Scoped branch indices:
      inside the loop: 0 = loop, 1 = block -> `br_if 1` exits the block;
      inside the if:   0 = if, 1 = loop, 2 = block -> `br 2` exits the block;
      back in the loop: `br_if 0` jumps to the loop start.
    """
    code = block(0x40, loop(0x40,
        i32_const(1) + br_if(1) +
        i32_const(1) + if_(0x40, i32_const(2) + br(2)) +
        i32_const(1) + br_if(0)
    )) + END
    return body(code)


def _base_sections() -> list:
    """The module body shared by L01 and L02 (identical bytes; only the `.name` section differs)."""
    return [
        type_section(functype([], [])),                     # type 0
        func_section([0]),                                  # function 0 -> type 0
        # _labelled_body() already carries its size prefix, so wrap it with vec() directly.
        section(10, vec([_labelled_body()])),
    ]


# ---------------------------------------------------------------------------------------------
# L01: label names for a block, a loop and an if - they must become real labels at the targets
# ---------------------------------------------------------------------------------------------
write("L01_name_labels.wasm", module(
    *_base_sections(),
    _name_section(
        name_subsection(0, name("label_probe_module")),                 # 0 module
        name_subsection(1, name_map([(0, "labelled_func")])),           # 1 function
        # 3 label: funcidx -> (function-wide labelidx -> name)
        label_names([(0, [(0, "outer_block"), (1, "retry_loop"), (2, "maybe_if")])]),
    ),
))

# ---------------------------------------------------------------------------------------------
# L02: negative case. The label-name subsection carries an out-of-range label index and an
#      out-of-range function index. The import must still succeed and the function must still
#      decode; the out-of-range names are not applied to any address (the applier skips the
#      unknown function and keeps the unresolvable label name as a comment fallback).
# ---------------------------------------------------------------------------------------------
write("L02_name_labels_bad_index.wasm", module(
    *_base_sections(),
    _name_section(
        name_subsection(0, name("label_probe_module")),
        name_subsection(1, name_map([(0, "labelled_func")])),
        # func 0, label 0 resolves; label 99 is out of range. func 9 does not exist.
        label_names([(0, [(0, "outer_block"), (99, "ghost_label")]), (9, [(0, "no_such_func")])]),
    ),
))

# ---------------------------------------------------------------------------------------------
# L03: negative case, malformed label subsection. The label-name subsection declares 4 entries
#      but only carries 1, so parsing runs off the end of the subsection. The loader must
#      degrade the subsection to raw bytes, the import must still succeed, and the function must
#      still decode (with no label applied).
# ---------------------------------------------------------------------------------------------
write("L03_name_labels_malformed.wasm", module(
    *_base_sections(),
    _name_section(
        name_subsection(0, name("label_probe_module")),
        name_subsection(1, name_map([(0, "labelled_func")])),
        # label map: claims 4 (funcidx, namemap) pairs, carries one.
        name_subsection(3, uleb(4) + uleb(0) + name_map([(0, "outer_block")])),
    ),
))
