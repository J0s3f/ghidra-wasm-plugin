#!/usr/bin/env python3
"""Probes owned by the *.name extras* workstream - roadmap item 9.

Add new probes here - never edit `gen_feature_probes.py` (frozen baseline). The helpers used are
`wasm_probe_lib`'s `name_subsection`, `name_map` and `label_names` together with the local
`_name_section` wrapper (see its docstring for why the custom section name is "name", not ".name").

The three probes are:

    N01  a module with a deliberately full `.name` section (subsections 0..11, every one with a
         recognisable name) -> the applier analyzer must turn the table/memory/elem/data names
         into Ghidra labels and the module/type/field/tag names plus the label names into comments;
    N02  the exact same module *without* a `.name` section -> a control: the import metrics must
         be byte-for-byte what they are for N01;
    N03  a module whose `.name` section is malformed (a function name map that claims more entries
         than the subsection contains) -> the import must still succeed, with the names parsed
         before the malformed subsection still applied.

Usage: python probes_names.py <output-dir>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import *  # noqa: F401,F403

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])


def _name_section(*subsections) -> bytes:
    """Wrap name subsections in the `.name` custom section.

    `wasm_probe_lib.name_section` writes the custom section name as the literal ".name"; the loader
    (WasmCustomSection.create) recognizes the binary custom section name "name", and the ".name" seen
    in the Ghidra tree is only the block/structure name. Use the real name here so the plugin parses
    the subsections.
    """
    return custom_section("name", b"".join(subsections))


def _full_name_section() -> bytes:
    """Subsections 0..11 - module/function/local/label/type/table/memory/global/elem/data/
    field/tag - each with a recognisable name."""
    return _name_section(
        name_subsection(0, name("probe_module")),                       # 0 module
        name_subsection(1, name_map([(0, "main_func")])),               # 1 function
        # 2 local: funcidx -> (localidx -> name)
        name_subsection(2, vec([uleb(0) + name_map([(0, "local_counter")])])),
        # 3 label: funcidx -> (labelidx -> name)
        label_names([(0, [(0, "outer_block"), (1, "inner_loop")])]),
        name_subsection(4, name_map([(0, "sig_void"), (1, "pair_struct")])),   # 4 type
        name_subsection(5, name_map([(0, "func_table")])),              # 5 table
        name_subsection(6, name_map([(0, "linear_mem")])),              # 6 memory
        name_subsection(7, name_map([(0, "global_counter")])),          # 7 global
        name_subsection(8, name_map([(0, "elem_segment")])),            # 8 elem
        name_subsection(9, name_map([(0, "data_segment")])),            # 9 data
        # 10 field: typeidx -> (fieldidx -> name); applies to the struct type at index 1
        name_subsection(10, vec([uleb(1) + name_map([(0, "field_left"),
                                                     (1, "field_right")])])),
        name_subsection(11, name_map([(0, "tag_error")])),              # 11 tag
    )


def _body() -> bytes:
    """One function with a block and a loop (labels 0 and 1) and one i32 local."""
    code = block(0x40, loop(0x40)) + END
    return body(code, [(1, I32)])


def _base_sections() -> list:
    """The module body shared by N01 and N02 (identical bytes; only the `.name` section differs)."""
    return [
        type_section(
            functype([], []),                                        # type 0
            struct_type([(I32, True), (F64, False)]),                # type 1
        ),
        func_section([0]),
        table_section([(FUNCREF, 0x00, 2)]),
        memory_section([(0x00, 1)]),
        tag_section([(0, 0)]),
        global_section([(I32, True, i32_const(42))]),
        export_section([("run", 0, 0), ("tbl", 1, 0), ("mem", 2, 0), ("g", 3, 0), ("e", 4, 0)]),
        elem_section([b"\x00" + i32_const(0) + END + vec([uleb(0)])]),   # active, table 0, offset 0
        # NB: _body() already carries its size prefix, so wrap it with vec() directly - passing it
        # through code_section() would size-prefix it a second time.
        section(10, vec([_body()])),
        data_section([active_data(i32_const(0) + END, b"hello")]),       # active, memory 0, offset 0
    ]


# ---------------------------------------------------------------------------------------------
# N01: every .name subsection with a recognisable name
# ---------------------------------------------------------------------------------------------
write("N01_full_name_section.wasm", module(*_base_sections(), _full_name_section()))

# ---------------------------------------------------------------------------------------------
# N02: the same module without any .name section - the control
# ---------------------------------------------------------------------------------------------
write("N02_no_name_section.wasm", module(*_base_sections()))

# ---------------------------------------------------------------------------------------------
# N03: malformed .name section. The module subsection is valid; the function subsection declares
#      3 name entries but only carries 1, so parsing runs off the end of the subsection.
# ---------------------------------------------------------------------------------------------
_bad_function_map = uleb(3) + uleb(0) + name("only_one")
write("N03_malformed_name_subsection.wasm", module(
    *_base_sections(),
    _name_section(
        name_subsection(0, name("malformed_module")),
        name_subsection(1, _bad_function_map),
    ),
))
