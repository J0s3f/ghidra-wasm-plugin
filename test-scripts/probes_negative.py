#!/usr/bin/env python3
"""Minimal negative probes: modules that a correct WebAssembly implementation must **reject**.

These are the reduced reproducers for the worst findings in ``REPORT-NS.md`` / ``test-scripts/spectest-NEGATIVE.md``.
Unlike the other ``probes_*.py`` generators they are *not* valid modules: a correct loader rejects every
one of them, so a run through the probe harness shows them as import failures / silent acceptances,
never as decoded programs.

    python probes_negative.py <output-dir> --emit

Why ``--emit`` is opt-in: ``test-scripts/run_probes.ps1`` globs ``probes_*.py`` and imports whatever
they write, and ``test-scripts/check-results.py`` fails the run for any probe that is absent from
``expected-results.json`` ("UNEXPECTED"). Emitting by default would therefore break the existing probe
gate. Turning these probes into a permanent gate is an integrator decision and needs
``check-results.py --update`` (see REPORT-NS.md §6).

Expected behaviour of each probe is recorded in REPORT-NS.md. "Reject" = the harness must classify it
as ``rejected``; "accept" = today's (measured) behaviour, which is the defect.
"""
import binascii
import os
import sys

MAGIC = "0061736d01000000"          # \00asm + version 1


def hexmod(name, body, note):
    """A module written as raw hex, so the malformed bytes stay readable."""
    return name, binascii.unhexlify(MAGIC + body.replace(" ", "")), note


# ---------------------------------------------------------------------------------------------
# NS01/NS02 - out-of-range section id.
#   core spec (binary/modules): a section id outside the known set is "malformed section id".
#   Measured: WasmSection.createSection() returns null for any id >= SEC_TAG+1 and the module loop
#   simply skips the section -> the loader ACCEPTS the module and produces an empty program
#   (only the .module block, 0 functions).
# ---------------------------------------------------------------------------------------------
PROBES = [
    hexmod("NS01_bad_section_id_0x0e.wasm", "0e 01 00",
           "section id 14 == first out-of-range id; spec: malformed section id -> expect reject"),
    hexmod("NS02_bad_section_id_0x7f.wasm", "7f 01 00",
           "section id 127, size 1 -> spec: malformed section id -> expect reject"),

    # NOTE: id 0x80.. is a one-byte id followed by a *LEB128* size; \80\01\00 means id=0x80, the
    # size LEB is 0x01 (1), content \00. Also out of range.
    hexmod("NS03_bad_section_id_leb.wasm", "80 01 00 01 01 00",
           "id 0x80 + size LEB + a second out-of-range section -> expect reject"),

    # ---------------------------------------------------------------------------------------------
    # NS04 - two sections with the same id (sections must appear at most once).
    #   Measured: sectionMap.put() silently overwrites; the second section is invisible -> ACCEPT.
    # ---------------------------------------------------------------------------------------------
    hexmod("NS04_duplicate_section.wasm", "03 01 00 03 01 00",
           "two empty function sections (id 3) -> spec: unexpected content after last section"),

    # ---------------------------------------------------------------------------------------------
    # NS05 - init expression with a missing end marker (spec testsuite binary.wast:111).
    #   The global's init expression runs into the next section id (0x0a) which is not a valid
    #   opcode there: "illegal opcode". Measured: the global block is still created, the code
    #   section is decoded normally (2 instructions), undefined_bytes == 0 -> ACCEPT, silently
    #   mis-modelling the global.
    # ---------------------------------------------------------------------------------------------
    hexmod("NS05_global_no_end.wasm",
           "01 04 01 60 00 00" "03 02 01 00" "06 05 01 7f 00 41 00" "0a 04 01 02 00 0b",
           "type+func+global(i32, missing END)+code -> spec: illegal opcode -> expect reject"),

    # ---------------------------------------------------------------------------------------------
    # NS06 - "too many locals" (spec testsuite binary.wast:351 / 367).
    #   Locals vector count 0xffffffff. Measured: the ACCEPTED module then makes
    #   WasmPreAnalyzer throw IllegalArgumentException "fromIndex(0) > toIndex(-1)".
    # ---------------------------------------------------------------------------------------------
    hexmod("NS06_too_many_locals.wasm",
           "01 04 01 60 00 00" "03 02 01 00" "0a 0c 01 0a 02 ff ff ff ff 0f 7f 02 7e 0b",
           "locals count 0xffffffff -> spec: too many locals; measured: accepted + analyzer exception"),
    hexmod("NS07_locals_count_huge.wasm",
           "01 04 01 60 00 00" "03 02 01 00" "0a 0c 01 0a 02 80 80 80 80 04 7f 02 7e 0b",
           "locals count 0x40000000 -> measured: accepted + ArrayIndexOutOfBounds(1073741824)"),

    # ---------------------------------------------------------------------------------------------
    # NS08 - control: a truncated section (the loader does reject this one, through the accident of
    #   "No memory blocks were defined" rather than a validation error). Kept as a regression
    #   probe for the rejection path itself.
    # ---------------------------------------------------------------------------------------------
    hexmod("NS08_truncated_section.wasm", "01",
           "section id with no size/content -> expect reject (loader throws before the module block)"),

    # ---------------------------------------------------------------------------------------------
    # NS09 - custom section whose name is not valid UTF-8 (spec testsuite utf8-custom-section-id,
    #   26 of 176 modules behave like this).
    #   Measured: WasmCustomSection.create -> StructureBuilder builds a DataType named
    #   ".custom.\uFFFD" -> IllegalArgumentException("Invalid DataType name") escapes doLoad.
    #   load() swallows it, so the import is reported as SUCCESS while everything after the failing
    #   section (functions, memory, data, globals) is never loaded: funcs=0, blocks=1.
    # ---------------------------------------------------------------------------------------------
    hexmod("NS09_custom_name_bad_utf8.wasm", "00 03 02 c2 7f",
           "custom section name 0xc2 0x7f is not valid UTF-8 -> spec: malformed; measured: accepted-empty"),

    # ---------------------------------------------------------------------------------------------
    # NS10 - table whose declared minimum is 0xffffffff (spec testsuite table.wast:23,
    #   "size minimum must not be greater than maximum").
    #   Measured: createTableBlock asks for 0xffffffff*4 bytes, Ghidra refuses
    #   ("New memory block NOT added: would cause total number of initialized program bytes to
    #   exceed the maximum program size"), the error is logged and the load *continues*: the
    #   accepted program silently has no table block at all.
    # ---------------------------------------------------------------------------------------------
    hexmod("NS10_table_overflow.wasm", "04 09 01 70 01 ff ff ff ff 0f 00",
           "table min 0xffffffff -> spec: invalid; measured: accepted, table block silently missing"),

    # ---------------------------------------------------------------------------------------------
    # NS11 - the consequence of NS09: the custom section comes *before* the code section, so the
    #   swallowed exception hides the module's only function. Measured: funcs=0 (the same module
    #   without the 5-byte custom section gives funcs=1) - silent data loss on a module the loader
    #   reports as imported successfully.
    # ---------------------------------------------------------------------------------------------
    hexmod("NS11_bad_custom_hides_code.wasm",
           "00 03 02 c2 7f" "01 04 01 60 00 00" "03 02 01 00" "0a 04 01 02 00 0b",
           "bad-UTF8 custom section before a 1-function code section -> expect reject; "
           "measured: accepted with funcs=0 (function lost)"),

    # ---------------------------------------------------------------------------------------------
    # NS12 - memory limits with a 5-byte LEB that the spec rejects as "integer too large"
    #   (spec testsuite binary-leb128.wast:534). min = 1073741826 pages.
    #   Measured: the loader clamps the linear memory to CODE_BASE and materialises a 2 GiB
    #   `.memory0` block (SPECNEG memory_bytes=2147483648). The plain import survives, but with
    #   analysis enabled the run never finishes (killed after 240 s in the spec set) - i.e. the
    #   default interactive import of this malformed module wedges Ghidra.
    # ---------------------------------------------------------------------------------------------
    hexmod("NS12_memory_min_2g.wasm", "05 07 01 00 82 80 80 80 40",
           "malformed u32 memory min (1073741826 pages) -> spec: malformed; measured: accepted, "
           "2 GiB memory block (analysis wedges)"),
]

USAGE = __doc__


def main(argv):
    if len(argv) < 2:
        print(USAGE)
        return 2
    outdir = argv[1]
    emit = "--emit" in argv
    if not emit:
        print("probes_negative.py: %d negative probes are defined but NOT written "
              "(pass --emit to write them into %s)." % (len(PROBES), outdir))
        print("Reason: run_probes.ps1 globs probes_*.py and check-results.py fails on any probe "
              "missing from expected-results.json; wiring these in is an integrator step "
              "(see REPORT-NS.md section 6).")
        return 0
    os.makedirs(outdir, exist_ok=True)
    for name, data, note in PROBES:
        path = os.path.join(outdir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        print("%-32s %2d bytes  %s" % (name, len(data), note))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
