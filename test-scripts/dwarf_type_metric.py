#!/usr/bin/env python3
"""DWARF-based type-recovery metric for decompiled WebAssembly functions.

Ground truth comes from the DWARF ``.debug_info`` carried by the subject
module itself (never from hand-written expectations): struct types with field
offsets/sizes, and function parameter types. The plugin's recovered types come
from a headless run of ``test-scripts/DumpTypes.java`` (synthesized
``wasm_struct_*`` structures + retyped prototypes) over the same module, with
an optional ``test-scripts/DumpAll.java`` log for the full prototype list and
decompile-failure context.

What is measured (Decompilation Wiki variable-typing methodology: recovered
variables/types compared against DWARF ground truth):

  * DWARF structs/fields found in the module (with known field offsets),
  * recovered ``wasm_struct_*`` structures and their (offset, size) fields,
  * field-offset recall: fraction of DWARF fields present at the same offset
    in the best-matching recovered structure (micro- and macro-averaged),
  * exact (offset+size) recall as a secondary, stricter number,
  * parameter-type recovery: DWARF-typed pointer-to-struct parameters whose
    Ghidra prototype retypes that parameter index to the right struct.

Usage (analyse already-collected logs)::

    python3 test-scripts/dwarf_type_metric.py \\
        --wasm <module.wasm> --types-log <dumptypes.log> \\
        [--decomp-log <dumpall.log>] [--json out.json]

End-to-end (generate the struct-bearing fixture, run the plugin headlessly on
the pinned Ghidra install, then score)::

    python3 test-scripts/dwarf_type_metric.py --run [--wasm <module.wasm>]
        [--no-decomp] [--out-dir <dir>] [--json out.json]

The default subject is the small generated fixture from
``test-scripts/make_dwarf_fixture.ps1`` (``fixture_dwarf.wasm``, built with
``-C debuginfo=2`` and extended with ``repr(C)`` structs passed by pointer).
Any other module WITH ``.debug_info`` (e.g. the corpus ``rust_debuginfo``
build) can be passed via ``--wasm``. Fixtures are always regenerated, never
committed, so the command works offline after the first generation.

DWARF reader: a minimal built-in DWARF version-4 reader for the
``.debug_info``/``.debug_abbrev``/``.debug_str`` subset rustc/LLVM emits
(structure/class/union types, members, subprograms, formal parameters,
typedef/const/pointer/base-type chains). ``llvm-dwarfdump`` (rustup
``llvm-tools`` component) is deliberately NOT required: it is not installed
in this toolchain and the built-in reader keeps the command offline and
dependency-free. The command FAILS LOUDLY (exit 2, no silent zeros) when
ground truth is unavailable: no ``.debug_info`` section, an unsupported DWARF
version, or no usable struct DIEs (e.g. a ``line-tables-only`` module).
"""

import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys

# ---------------------------------------------------------------------------
# wasm module parsing (custom sections + export names)
# ---------------------------------------------------------------------------

DWARF_SECTIONS = (".debug_info", ".debug_abbrev", ".debug_str")


def read_uleb(buf, pos):
    shift = 0
    value = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated uleb128")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


def read_sleb(buf, pos):
    shift = 0
    value = 0
    size = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated sleb128")
        byte = buf[pos]
        pos += 1
        size += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40:
                value -= 1 << (size * 7)
            return value, pos


def read_wasm_sections(path):
    """Return (custom_sections dict name->bytes, export_func_names list)."""
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:4] != b"\x00asm" or data[4:8] != b"\x01\x00\x00\x00":
        raise ValueError("not a wasm module: %s" % path)
    pos = 8
    custom = {}
    exports = []
    while pos < len(data):
        section_id = data[pos]
        pos += 1
        size, pos = read_uleb(data, pos)
        body = data[pos:pos + size]
        if len(body) < size:
            raise ValueError("truncated section id %d" % section_id)
        if section_id == 0:
            name_len, p = read_uleb(body, 0)
            name = body[p:p + name_len].decode("utf-8", "replace")
            custom[name] = body[p + name_len:]
        elif section_id == 7:  # export section
            count, p = read_uleb(body, 0)
            for _ in range(count):
                nlen, p = read_uleb(body, p)
                name = body[p:p + nlen].decode("utf-8", "replace")
                p += nlen
                kind = body[p]
                p += 1
                _, p = read_uleb(body, p)
                if kind == 0:
                    exports.append(name)
        pos += size
    return custom, exports


# ---------------------------------------------------------------------------
# Minimal DWARF version-4 reader (rustc/LLVM .debug_info subset)
# ---------------------------------------------------------------------------
#
# Handles: compile units (v4 header), DIE trees for structure/class/union
# types + members, subprograms + formal parameters, and the type chains that
# connect them (typedef, const, volatile, restrict, pointer, reference,
# base types, arrays with constant bounds). Attribute forms: addr, data1/2/4/8,
# udata, sdata, string, strp, ref1/2/4/8, ref_udata, sec_offset, exprloc,
# flag, flag_present. Anything else (including other DWARF versions) raises
# instead of silently mis-parsing.

# Tags we resolve. The struct/member/subprogram/param/pointer/typedef/
# const/base/array tags below are verified against real rustc/LLVM wasm
# output (the metric's ground truth resolves through them); the qualifier
# tags are best-recall DWARF numbers and degrade gracefully to "other" when
# absent (they never affect struct/param scoring).
T_COMPILE_UNIT = 0x11
T_STRUCT = 0x13
T_UNION = 0x17
T_CLASS = 0x1D
T_MEMBER = 0x0D
T_SUBPROGRAM = 0x2E
T_SUBROUTINE = 0x15
T_FORMAL_PARAM = 0x05
T_POINTER = 0x0F
T_REFERENCE = 0x10
T_RVALUE_REF = 0x42
T_CONST = 0x26
T_VOLATILE = 0x35
T_RESTRICT = 0x37
T_TYPEDEF = 0x16
T_BASE = 0x24
T_ENUM = 0x04
T_ARRAY = 0x01
T_SUBRANGE = 0x21
T_NAMESPACE = 0x39
T_INLINED = 0x0B
T_LEXBLOCK = 0x2F
T_VARIABLE = 0x34
T_UNSPEC_PARAMS = 0x18

# Attributes we read.
A_NAME = 0x03
A_BYTE_SIZE = 0x0B
A_TYPE = 0x49
A_MEMBER_LOC = 0x38
A_LINKAGE_NAME = 0x6E  # DW_AT_MIPS_linkage_name (what LLVM emits)
A_LOW_PC = 0x11
A_HIGH_PC = 0x12
A_ARTIFICIAL = 0x34
A_DECLARATION = 0x3C
A_UPPER_BOUND = 0x2F
A_COUNT = 0x37
A_ALIGNMENT = 0x88  # DWARF5 attribute LLVM also emits in v4 units

# Forms (DWARF4 section 7.5.5).
F_ADDR = 0x01
F_DATA2 = 0x05
F_DATA4 = 0x06
F_DATA8 = 0x07
F_STRING = 0x08
F_DATA1 = 0x0B
F_FLAG = 0x0C
F_SDATA = 0x0D
F_STRP = 0x0E
F_UDATA = 0x0F
F_REF1 = 0x10
F_REF2 = 0x11
F_REF4 = 0x12
# NOTE (empirical, validated four ways on rustc/LLVM wasm output): every
# CU-relative reference in this emission uses form code 0x13 with a 4-byte
# value (DWARF4 nominally assigns 0x13 to 8-byte ref8). Reading 4 bytes keeps
# the whole unit aligned - linkage/name strings, parameter names and target
# DIEs (e.g. the u32 base type) all resolve, and the per-CU
# exact-consumption check passes - while 8 bytes desyncs immediately.
# Ghidra's own DWARF importer reads the same file cleanly, so both consumers
# agree. The exact-consumption check fails loudly if a future emission ever
# needs true 8-byte references.
F_REF4_WASM = 0x13
F_REF_UDATA = 0x14
F_SEC_OFFSET = 0x17
F_EXPRLOC = 0x18
F_FLAG_PRESENT = 0x19
F_REF_SIG8 = 0x20

FORM_SIZES = {F_DATA1: 1, F_DATA2: 2, F_DATA4: 4, F_DATA8: 8}

DW_OP_PLUS_UCONST = 0x23


class DwarfError(Exception):
    pass


class DwarfReader:
    def __init__(self, sections):
        for name in DWARF_SECTIONS:
            if name not in sections:
                raise DwarfError(
                    "module has no %s section; rebuild the subject with "
                    "-C debuginfo=2 (line-tables-only carries no type info)"
                    % name)
        self.info = sections[".debug_info"]
        self.abbrev = sections[".debug_abbrev"]
        self.strings = sections[".debug_str"]
        self._abbrev_cache = {}

    # -- abbrev tables ----------------------------------------------------
    def abbrev_table(self, offset):
        if offset in self._abbrev_cache:
            return self._abbrev_cache[offset]
        table = {}
        pos = offset
        while True:
            code, pos = read_uleb(self.abbrev, pos)
            if code == 0:
                break
            tag, pos = read_uleb(self.abbrev, pos)
            if pos >= len(self.abbrev):
                raise DwarfError("truncated .debug_abbrev")
            has_children = self.abbrev[pos]
            pos += 1
            attrs = []
            while True:
                attr, pos = read_uleb(self.abbrev, pos)
                form, pos = read_uleb(self.abbrev, pos)
                if attr == 0 and form == 0:
                    break
                attrs.append((attr, form))
            table[code] = (tag, has_children, attrs)
        self._abbrev_cache[offset] = table
        return table

    # -- attribute values ---------------------------------------------------
    def _read_attr(self, form, pos, addr_size):
        buf = self.info
        if form in FORM_SIZES:
            n = FORM_SIZES[form]
            return int.from_bytes(buf[pos:pos + n], "little"), pos + n
        if form == F_UDATA:
            return read_uleb(buf, pos)
        if form == F_SDATA:
            return read_sleb(buf, pos)
        if form == F_STRING:
            end = buf.index(b"\x00", pos)
            return buf[pos:end].decode("utf-8", "replace"), end + 1
        if form == F_STRP:
            # Positions are authoritative, values are advisory: a dead
            # (gc'd but unrelocated) DIE can carry a strp that points
            # nowhere. Never let a bad offset abort the walk - the byte
            # position is unaffected, so substitute a placeholder that can
            # never match an export name and continue.
            off = int.from_bytes(buf[pos:pos + 4], "little")
            try:
                end = self.strings.index(b"\x00", off)
            except ValueError:
                return "<bad-strp-0x%x>" % off, pos + 4
            return self.strings[off:end].decode("utf-8", "replace"), pos + 4
        if form == F_ADDR:
            return int.from_bytes(buf[pos:pos + addr_size], "little"), pos + addr_size
        if form in (F_REF1, F_REF2, F_REF4, F_REF4_WASM):
            n = {F_REF1: 1, F_REF2: 2, F_REF4: 4, F_REF4_WASM: 4}[form]
            return ("ref", int.from_bytes(buf[pos:pos + n], "little")), pos + n
        if form == F_REF_UDATA:
            value, pos = read_uleb(buf, pos)
            return ("ref", value), pos
        if form == F_SEC_OFFSET:
            return int.from_bytes(buf[pos:pos + 4], "little"), pos + 4
        if form == F_EXPRLOC:
            length, pos = read_uleb(buf, pos)
            return ("expr", bytes(buf[pos:pos + length])), pos + length
        if form == F_FLAG:
            return bool(buf[pos]), pos + 1
        if form == F_FLAG_PRESENT:
            return True, pos
        raise DwarfError("unsupported DWARF form 0x%x "
                         "(only the rustc/LLVM v4 subset is implemented)" % form)

    # -- compilation units --------------------------------------------------
    def compilation_units(self):
        """Yield (cu_base, addr_size, top-level DIE list) per unit.

        Each DIE is a dict with keys: off (CU-relative), tag, attrs
        (attr->value), children. Sibling/parent links are structural.
        """
        pos = 0
        info = self.info
        while pos + 4 <= len(info):
            cu_base = pos
            (unit_length,) = struct.unpack_from("<I", info, pos)
            pos += 4
            if unit_length == 0:
                break
            end = pos + unit_length
            if end > len(info):
                raise DwarfError("truncated compilation unit at offset %d" % cu_base)
            version = int.from_bytes(info[pos:pos + 2], "little")
            if version != 4:
                raise DwarfError(
                    "unsupported DWARF version %d at offset %d "
                    "(this reader implements DWARF v4 only)" % (version, cu_base))
            abbrev_offset = int.from_bytes(info[pos + 2:pos + 6], "little")
            addr_size = info[pos + 6]
            if addr_size not in (4, 8):
                raise DwarfError("unsupported address size %d" % addr_size)
            table = self.abbrev_table(abbrev_offset)
            pos += 7
            # The top-level DIE list (the unit's contributions) is delimited
            # by the unit length, not by a null terminator: a single-CU
            # section simply ends after the root DIE's closing null.
            dies, pos = self._read_children(table, pos, end, addr_size,
                                            require_terminator=False)
            if pos != end:
                raise DwarfError("unit at offset %d ends at %d, expected %d"
                                 % (cu_base, pos, end))
            yield cu_base, addr_size, dies

    def _read_children(self, table, pos, end, addr_size,
                         require_terminator=True):
        children = []
        while pos < end:
            die_off = pos  # DIE offset: at the abbrev code (refs point here)
            code, pos = read_uleb(self.info, pos)
            if code == 0:
                return children, pos
            try:
                tag, has_children, attrs = table[code]
            except KeyError:
                raise DwarfError("abbrev code %d not in table" % code)
            values = {}
            for attr, form in attrs:
                values[attr], pos = self._read_attr(form, pos, addr_size)
            die = {"off": die_off, "tag": tag, "attrs": values, "children": []}
            if has_children:
                die["children"], pos = self._read_children(table, pos, end, addr_size)
            children.append(die)
        if require_terminator:
            raise DwarfError("DIE list not terminated before end of unit")
        return children, pos

    # -- type graph ---------------------------------------------------------
    def collect(self):
        """Return (structs, subprograms).

        structs: list of dicts {name, size, fields:[{name, offset, size}]}.
        Only definitions (not declarations) with at least one member whose
        offset is known are kept; duplicates across CUs collapse.
        subprograms: list of dicts {name, params:[{name, type_desc}]} where
        type_desc = (kind, struct_name_or_None) with kind in
        {"struct_ptr", "other_ptr", "by_value_struct", "scalar"}.
        """
        dies_by_off = {}
        structs = []
        subprograms = []
        seen_structs = set()
        for cu_base, addr_size, tops in self.compilation_units():
            self._index(tops, cu_base, dies_by_off)
            for die in tops:
                self._walk(die, cu_base, addr_size, dies_by_off,
                           structs, subprograms, seen_structs,
                           in_subprogram=None)
        return structs, subprograms

    def _index(self, dies, cu_base, index):
        for die in dies:
            # CU-relative offset of the DIE start: refs are relative to the
            # start of the unit header (the length field itself).
            index[(cu_base, die["off"] - cu_base)] = die
            self._index(die["children"], cu_base, index)

    def _ref_target(self, value, cu_base, dies_by_off):
        if isinstance(value, tuple) and value[0] == "ref":
            return dies_by_off.get((cu_base, value[1]))
        return None

    def _resolve(self, die, cu_base, dies_by_off, depth=0):
        """Follow typedef/const/volatile/restrict chains.

        Returns (kind, node) where kind is "struct" (node has name/size),
        "pointer" (node is the pointer DIE), "base", "enum", "array",
        "other" or "unknown".
        """
        if depth > 32 or die is None:
            return "unknown", None
        tag = die["tag"]
        if tag in (T_STRUCT, T_UNION, T_CLASS):
            if die["attrs"].get(A_DECLARATION):
                return "other", None
            return "struct", die
        if tag in (T_POINTER, T_REFERENCE, T_RVALUE_REF):
            return "pointer", die
        if tag in (T_TYPEDEF, T_CONST, T_VOLATILE, T_RESTRICT):
            inner = self._ref_target(die["attrs"].get(A_TYPE), cu_base, dies_by_off)
            return self._resolve(inner, cu_base, dies_by_off, depth + 1)
        if tag == T_BASE:
            return "base", die
        if tag == T_ENUM:
            return "enum", die
        if tag == T_ARRAY:
            return "array", die
        return "other", None

    def _pointee_struct(self, ptr_die, cu_base, dies_by_off):
        inner = self._ref_target(ptr_die["attrs"].get(A_TYPE), cu_base, dies_by_off)
        kind, node = self._resolve(inner, cu_base, dies_by_off)
        if kind == "struct":
            name = node["attrs"].get(A_NAME)
            size = node["attrs"].get(A_BYTE_SIZE, 0) or 0
            return (name or "<anonymous>", size)
        if kind in ("base", "enum"):
            return (None, node["attrs"].get(A_BYTE_SIZE, 0) or 0)
        return (None, 0)

    def _struct_size(self, die):
        size = die["attrs"].get(A_BYTE_SIZE, 0) or 0
        return size

    def _member_offset(self, member):
        loc = member["attrs"].get(A_MEMBER_LOC)
        if isinstance(loc, bool):
            return None
        if isinstance(loc, int):
            return loc
        if isinstance(loc, tuple) and loc[0] == "expr":
            expr = loc[1]
            # DW_OP_plus_uconst <uleb>: the member's constant offset.
            if len(expr) >= 1 and expr[0] == DW_OP_PLUS_UCONST:
                value, _ = read_uleb(expr, 1)
                return value
            # A bare empty location means offset 0 in practice, but do not
            # guess: only plus_uconst is interpreted.
            return None
        return None

    def _walk(self, die, cu_base, addr_size, dies_by_off,
              structs, subprograms, seen_structs, in_subprogram):
        tag = die["tag"]
        attrs = die["attrs"]
        if tag in (T_STRUCT, T_UNION, T_CLASS):
            if not attrs.get(A_DECLARATION):
                fields = []
                for child in die["children"]:
                    if child["tag"] != T_MEMBER:
                        continue
                    target = self._ref_target(child["attrs"].get(A_TYPE),
                                              cu_base, dies_by_off)
                    kind, node = self._resolve(target, cu_base, dies_by_off)
                    if kind == "struct":
                        size = self._struct_size(node)
                    elif kind in ("base", "enum", "pointer"):
                        size = node["attrs"].get(A_BYTE_SIZE, addr_size) or addr_size
                    elif kind == "array":
                        size = self._struct_size(node)
                    else:
                        size = None
                    fields.append({
                        "name": child["attrs"].get(A_NAME),
                        "offset": self._member_offset(child),
                        "size": size,
                        "type": (node["attrs"].get(A_NAME)
                                 if kind == "struct" else None),
                    })
                known = [f for f in fields if f["offset"] is not None]
                if known:
                    key = (attrs.get(A_NAME),
                           attrs.get(A_BYTE_SIZE, 0) or 0,
                           tuple(sorted((f["offset"], f["size"] if f["size"] is not None else -1)
                                        for f in known)))
                    if key not in seen_structs:
                        seen_structs.add(key)
                        structs.append({
                            "name": attrs.get(A_NAME) or "<anonymous>",
                            "size": attrs.get(A_BYTE_SIZE, 0) or 0,
                            "fields": known,
                        })
            for child in die["children"]:
                self._walk(child, cu_base, addr_size, dies_by_off,
                           structs, subprograms, seen_structs, in_subprogram)
            return
        if tag == T_SUBPROGRAM:
            linkage = attrs.get(A_LINKAGE_NAME)
            name = attrs.get(A_NAME)
            params = []
            for child in die["children"]:
                if child["tag"] == T_FORMAL_PARAM:
                    if child["attrs"].get(A_ARTIFICIAL):
                        continue
                    params.append(child)
                elif child["tag"] == T_UNSPEC_PARAMS:
                    params.append(child)
            if params and (linkage or name):
                subprograms.append({
                    "name": linkage or name,
                    "alt_name": name if linkage and name != linkage else None,
                    "params": [self._describe_param(p, cu_base, addr_size, dies_by_off)
                               for p in params],
                })
            for child in die["children"]:
                self._walk(child, cu_base, addr_size, dies_by_off,
                           structs, subprograms, seen_structs, in_subprogram)
            return
        for child in die["children"]:
            self._walk(child, cu_base, addr_size, dies_by_off,
                       structs, subprograms, seen_structs, in_subprogram)

    def _describe_param(self, param, cu_base, addr_size, dies_by_off):
        if param["tag"] == T_UNSPEC_PARAMS:
            return {"name": "...", "kind": "varargs", "pointee": None}
        name = param["attrs"].get(A_NAME)
        target = self._ref_target(param["attrs"].get(A_TYPE), cu_base, dies_by_off)
        kind, node = self._resolve(target, cu_base, dies_by_off)
        if kind == "pointer":
            pointee = self._pointee_struct(node, cu_base, dies_by_off)
            if pointee[0] is not None:
                return {"name": name, "kind": "struct_ptr", "pointee": pointee[0]}
            return {"name": name, "kind": "other_ptr", "pointee": None}
        if kind == "struct":
            return {"name": name, "kind": "by_value_struct",
                    "pointee": node["attrs"].get(A_NAME)}
        return {"name": name, "kind": "scalar", "pointee": None}


# ---------------------------------------------------------------------------
# Plugin log parsing (DumpTypes.java, DumpAll.java)
# ---------------------------------------------------------------------------

HARNESS_PREFIX_RE = re.compile(r"^\S+\s+\S+\.java>\s*")
HARNESS_SUFFIX_RE = re.compile(r"\s*\(GhidraScript\)\s*$")
STRUCT_RE = re.compile(r"^STRUCT\s+(?P<name>\S+)\s+size=(?P<size>\d+)\s*$")
FIELD_RE = re.compile(r"^FIELD\s+(?P<off>\d+)\s+\S+\s+\S+\s+\((?P<size>\d+) bytes\)\s*$")
RETYPED_RE = re.compile(r"^RETYPED\s+(?P<func>\S+)\s+:\s+(?P<proto>.*)$")
FUNC_RE = re.compile(r"^---- (?P<name>\S+) (?:prototype: (?P<proto>.*)|DECOMPILE FAILED:.*)$")
RECOVERED_STRUCT_RE = re.compile(r"wasm_struct_\d+")


def strip_harness(line):
    return HARNESS_SUFFIX_RE.sub("", HARNESS_PREFIX_RE.sub("", line.rstrip("\n")))


def parse_types_log(path):
    """Parse a DumpTypes.java log.

    Returns {"structs": {name: {"size": int, "fields": [(off, size)]}},
    "retyped": {func: prototype}, "struct_count": int, "retyped_count": int}.
    """
    structs = {}
    retyped = {}
    struct_count = None
    retyped_count = None
    current = None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = strip_harness(raw).strip()
            m = STRUCT_RE.match(line)
            if m:
                current = m.group("name")
                structs[current] = {"size": int(m.group("size")), "fields": []}
                continue
            m = FIELD_RE.match(line)
            if m and current is not None:
                structs[current]["fields"].append(
                    (int(m.group("off")), int(m.group("size"))))
                continue
            if line.startswith("STRUCT_COUNT"):
                try:
                    struct_count = int(line.split()[-1])
                except ValueError:
                    struct_count = None
                current = None
                continue
            m = RETYPED_RE.match(line)
            if m:
                retyped[m.group("func")] = m.group("proto").strip()
                continue
            if line.startswith("RETYPED_COUNT"):
                try:
                    retyped_count = int(line.split()[-1])
                except ValueError:
                    retyped_count = None
                continue
    return {"structs": structs, "retyped": retyped,
            "struct_count": struct_count, "retyped_count": retyped_count}


def parse_decomp_log(path):
    """Parse a DumpAll.java log.

    Returns {"functions": {name: prototype_or_None}, "failures": int}.
    """
    functions = {}
    failures = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = strip_harness(raw).strip()
            m = FUNC_RE.match(line)
            if m:
                proto = m.group("proto")
                functions[m.group("name")] = (proto.strip() if proto else None)
                if not proto:
                    failures += 1
    return {"functions": functions, "failures": failures}


def split_prototype_args(proto):
    """Split a Ghidra prototype string's argument list at top-level commas."""
    if proto is None:
        return None
    start = proto.find("(")
    end = proto.rfind(")")
    if start < 0 or end < 0 or end < start:
        return None
    inner = proto[start + 1:end].strip()
    if inner in ("", "void"):
        return []
    args = []
    depth = 0
    current = []
    for ch in inner:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    args.append("".join(current).strip())
    return args


# ---------------------------------------------------------------------------
# Metric
# ---------------------------------------------------------------------------

def find_llvm_dwarfdump():
    """Locate llvm-dwarfdump in the rustup sysroot (informational).

    Returns (path_or_None, reason). The metric does not need it (the
    built-in reader is primary); this documents the toolchain state.
    """
    rustc = shutil.which("rustc")
    if rustc is None:
        return None, "rustc not on PATH"
    try:
        sysroot = subprocess.run(
            [rustc, "--print", "sysroot"], capture_output=True, text=True,
            timeout=60).stdout.strip()
        host = subprocess.run(
            [rustc, "-vV"], capture_output=True, text=True,
            timeout=60).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "could not query rustc: %s" % exc
    triple = None
    for line in host.splitlines():
        if line.startswith("host:"):
            triple = line.split(":", 1)[1].strip()
    candidates = []
    if sysroot and triple:
        exe = "llvm-dwarfdump.exe" if os.name == "nt" else "llvm-dwarfdump"
        candidates.append(os.path.join(sysroot, "lib", "rustlib", triple, "bin", exe))
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate, "found"
    return None, ("absent (llvm-tools component not installed for %s; "
                   "using the built-in DWARF reader)" % (triple or "unknown host"))


def compute_metric(dwarf_structs, dwarf_subprograms, types, decomp, export_names):
    recovered = types["structs"]
    rec_offsets = {name: {off for off, _ in info["fields"]}
                   for name, info in recovered.items()}
    rec_exact = {name: {(off, size) for off, size in info["fields"]}
                 for name, info in recovered.items()}

    struct_rows = []
    total_fields = 0
    total_offset_hits = 0
    total_exact_hits = 0
    for struct in dwarf_structs:
        want_offsets = {f["offset"] for f in struct["fields"]}
        want_exact = {(f["offset"], f["size"]) for f in struct["fields"]
                      if f["size"] is not None}
        total_fields += len(struct["fields"])
        # Best match by Jaccard similarity of the offset sets: raw overlap
        # alone always prefers the biggest recovered struct, which makes
        # "the right struct" meaningless. Ties (exact duplicate layouts)
        # are all kept for the parameter check.
        best_score = -1.0
        best_names = []
        for name, offs in rec_offsets.items():
            union = want_offsets | offs
            score = (len(want_offsets & offs) / len(union)) if union else 1.0
            if score > best_score + 1e-12:
                best_score = score
                best_names = [name]
            elif abs(score - best_score) <= 1e-12:
                best_names.append(name)
        best = best_names[0] if best_names else None
        overlap = len(want_offsets & rec_offsets[best]) if best else 0
        exact = len(want_exact & rec_exact[best]) if best else 0
        total_offset_hits += overlap
        total_exact_hits += exact
        struct_rows.append({
            "dwarf_struct": struct["name"],
            "dwarf_size": struct["size"],
            "dwarf_fields": [{"offset": f["offset"], "size": f["size"]}
                             for f in struct["fields"]],
            "best_match": best,
            "best_jaccard": best_score if best else 0.0,
            "offset_recall": (overlap / len(struct["fields"])
                              if struct["fields"] else 1.0),
            "exact_recall": (exact / len(struct["fields"])
                             if struct["fields"] else 1.0),
        })

    # Best-match sets (Jaccard ties kept) for the parameter check.
    best_sets = {}
    for row, struct in zip(struct_rows, dwarf_structs):
        want = {f["offset"] for f in struct["fields"]}
        if row["best_match"] is None:
            best_sets[struct["name"]] = set()
            continue
        ref = rec_offsets[row["best_match"]]
        ref_union = want | ref
        ref_score = (len(want & ref) / len(ref_union)) if ref_union else 1.0
        tied = []
        for name, offs in rec_offsets.items():
            union = want | offs
            score = (len(want & offs) / len(union)) if union else 1.0
            if abs(score - ref_score) <= 1e-12:
                tied.append(name)
        best_sets[struct["name"]] = set(tied)

    ghidra_names = set((decomp or {}).get("functions", {}))
    param_rows = []
    hits = 0
    denom = 0
    unscored = 0
    for sub in dwarf_subprograms:
        gname = None
        for candidate in (sub["name"], sub["alt_name"]):
            if candidate and (candidate in ghidra_names
                              or candidate in types["retyped"]
                              or candidate in export_names):
                gname = candidate
                break
        for idx, param in enumerate(sub["params"]):
            if param["kind"] != "struct_ptr":
                continue
            proto = types["retyped"].get(sub["name"])
            if proto is None and decomp is not None:
                proto = decomp["functions"].get(sub["name"])
            if proto is None and sub["alt_name"]:
                proto = types["retyped"].get(sub["alt_name"])
                if proto is None and decomp is not None:
                    proto = decomp["functions"].get(sub["alt_name"])
            if gname is None or proto is None:
                unscored += 1
                param_rows.append({
                    "function": sub["name"], "index": idx,
                    "param": param["name"], "pointee": param["pointee"],
                    "ghidra_function": gname, "result": "unscored",
                    "detail": "no matching Ghidra function/prototype",
                })
                continue
            args = split_prototype_args(proto)
            if args is None or idx >= len(args):
                unscored += 1
                param_rows.append({
                    "function": sub["name"], "index": idx,
                    "param": param["name"], "pointee": param["pointee"],
                    "ghidra_function": gname, "result": "unscored",
                    "detail": "prototype has %s for %d params"
                              % ("no args" if args is None else len(args), idx + 1),
                })
                continue
            denom += 1
            actual = args[idx]
            m = RECOVERED_STRUCT_RE.search(actual)
            ok = bool(m) and m.group(0) in best_sets.get(param["pointee"], set()) \
                and "*" in actual
            if ok:
                hits += 1
            # Coverage detail: how much of the DWARF struct the param's own
            # struct explains, independent of the best-match verdict.
            coverage = None
            if m and m.group(0) in rec_offsets:
                want = next((st for st in dwarf_structs
                             if st["name"] == param["pointee"]), None)
                if want:
                    w = {f["offset"] for f in want["fields"]}
                    got = w & rec_offsets[m.group(0)]
                    coverage = "%d/%d offsets" % (len(got), len(w))
            param_rows.append({
                "function": sub["name"], "index": idx,
                "param": param["name"], "pointee": param["pointee"],
                "ghidra_function": gname, "result": "hit" if ok else "miss",
                "detail": "arg%d '%s' %s best-match %s%s"
                          % (idx, actual,
                             "in" if ok else "not in",
                             sorted(best_sets.get(param["pointee"], set())),
                             ("; covers " + coverage) if coverage else ""),
            })

    macro_recall = (sum(r["offset_recall"] for r in struct_rows) / len(struct_rows)
                    if struct_rows else 1.0)
    macro_exact = (sum(r["exact_recall"] for r in struct_rows) / len(struct_rows)
                   if struct_rows else 1.0)

    # Focus scope: structs the module's interface actually exposes - the
    # pointees of matched exported functions' struct-pointer params, plus
    # their transitive struct-typed members (e.g. Rect -> Point). Derived
    # from DWARF + the export section only, never from expectations.
    members_of = {}
    for struct in dwarf_structs:
        members_of.setdefault(struct["name"], set()).update(
            f["type"] for f in struct["fields"] if f.get("type"))
    focus = set()
    frontier = [pr["pointee"] for pr in param_rows if pr["ghidra_function"]]
    while frontier:
        name = frontier.pop()
        if name in focus:
            continue
        focus.add(name)
        frontier.extend(members_of.get(name, ()))
    focus_rows = [r for r in struct_rows if r["dwarf_struct"] in focus]
    focus_fields = sum(len(r["dwarf_fields"]) for r in focus_rows)
    focus_hits = sum(int(r["offset_recall"] * len(r["dwarf_fields"]))
                     for r in focus_rows)
    focus_exact = sum(int(round(r["exact_recall"] * len(r["dwarf_fields"])))
                      for r in focus_rows)
    return {
        "focus_structs": sorted(focus),
        "dwarf_structs": len(dwarf_structs),
        "dwarf_fields": total_fields,
        "recovered_structures": len(recovered),
        "field_offset_recall_micro":
            (total_offset_hits / total_fields if total_fields else 1.0),
        "field_offset_recall_macro": macro_recall,
        "field_exact_recall_micro":
            (total_exact_hits / total_fields if total_fields else 1.0),
        "field_exact_recall_macro": macro_exact,
        "param_struct_hits": hits,
        "param_struct_total": denom,
        "param_struct_unscored": unscored,
        "param_struct_recall": (hits / denom if denom else None),
        "focus_field_offset_recall":
            (focus_hits / focus_fields if focus_fields else None),
        "focus_field_exact_recall":
            (focus_exact / focus_fields if focus_fields else None),
        "structs": struct_rows,
        "params": param_rows,
    }


def print_report(report, metric, dwarf_subprograms, decomp):
    print("dwarf type-recovery metric")
    print("  subject module            : %s" % report["subject"])
    print("  DWARF reader              : %s" % report["dwarf_reader"])
    print("  dwarf structs w/ fields   : %d (%d fields, %d subprograms, "
          "%d struct-ptr params)" % (
              metric["dwarf_structs"], metric["dwarf_fields"],
              len(dwarf_subprograms),
              sum(1 for s in dwarf_subprograms for p in s["params"]
                  if p["kind"] == "struct_ptr")))
    print("  recovered structures      : %d" % metric["recovered_structures"])
    print("  field-offset recall       : micro %.3f  macro %.3f" % (
        metric["field_offset_recall_micro"], metric["field_offset_recall_macro"]))
    print("  field-exact recall        : micro %.3f  macro %.3f" % (
        metric["field_exact_recall_micro"], metric["field_exact_recall_macro"]))
    if metric["focus_field_offset_recall"] is not None:
        print("  focus structs %s: offset %.3f exact %.3f" % (
            metric["focus_structs"], metric["focus_field_offset_recall"],
            metric["focus_field_exact_recall"]))
    if metric["param_struct_recall"] is None:
        print("  parameter-type recovery   : n/a (no scorable struct-ptr params)")
    else:
        print("  parameter-type recovery   : %d/%d = %.3f (%d unscored)" % (
            metric["param_struct_hits"], metric["param_struct_total"],
            metric["param_struct_recall"], metric["param_struct_unscored"]))
    if decomp is not None:
        print("  decomp context            : %d functions, %d failures" % (
            len(decomp["functions"]), decomp["failures"]))
    print("  per-struct best match:")
    for row in metric["structs"]:
        print("    %-28s fields=%d offset=%.3f exact=%.3f jacc=%.3f best=%s" % (
            row["dwarf_struct"], len(row["dwarf_fields"]),
            row["offset_recall"], row["exact_recall"],
            row["best_jaccard"], row["best_match"]))
    if metric["params"]:
        print("  per-param:")
        for p in metric["params"]:
            print("    %s[%d] (%s -> %s): %s (%s)" % (
                p["function"], p["index"], p["param"], p["pointee"],
                p["result"], p["detail"]))


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------

def die_loud(message):
    print("dwarf_type_metric: ERROR: %s" % message, file=sys.stderr)
    return 2


def cmd_analyze(args):
    if not os.path.isfile(args.wasm):
        return die_loud("subject module not found: %s" % args.wasm)
    if not os.path.isfile(args.types_log):
        return die_loud("DumpTypes log not found: %s" % args.types_log)
    decomp = None
    if args.decomp_log:
        if not os.path.isfile(args.decomp_log):
            return die_loud("DumpAll log not found: %s" % args.decomp_log)
        decomp = parse_decomp_log(args.decomp_log)
        if not decomp["functions"]:
            return die_loud("DumpAll log %s contains no function prototypes; "
                            "rerun DumpAll.java on the subject module"
                            % args.decomp_log)
    try:
        custom, export_names = read_wasm_sections(args.wasm)
    except (OSError, ValueError) as exc:
        return die_loud("cannot read subject module: %s" % exc)
    missing = [s for s in DWARF_SECTIONS if s not in custom]
    if missing:
        return die_loud("subject module has no %s; it carries no DWARF type "
                        "ground truth (rebuild with -C debuginfo=2)"
                        % ", ".join(missing))
    try:
        reader = DwarfReader(custom)
        dwarf_structs, dwarf_subprograms = reader.collect()
    except (DwarfError, ValueError, IndexError) as exc:
        return die_loud("cannot parse .debug_info: %s" % exc)
    if not dwarf_structs:
        return die_loud("no struct/class/union DIEs with known field offsets "
                        "in .debug_info (module built without type debuginfo, "
                        "e.g. debuginfo=line-tables-only?)")
    types = parse_types_log(args.types_log)
    if not types["structs"] and types["struct_count"] is None:
        return die_loud("DumpTypes log %s has no STRUCT lines and no "
                        "STRUCT_COUNT; rerun DumpTypes.java on the subject "
                        "module" % args.types_log)
    dwarfdump, reason = find_llvm_dwarfdump()
    metric = compute_metric(dwarf_structs, dwarf_subprograms, types, decomp,
                            set(export_names))
    report = {
        "subject": os.path.abspath(args.wasm),
        "dwarf_reader": ("built-in DWARF4 reader (primary; llvm-dwarfdump %s)"
                         % reason),
        "llvm_dwarfdump": dwarfdump,
        "exports": export_names,
        "dwarf_subprograms": [
            {"name": s["name"],
             "params": [{"name": p["name"], "kind": p["kind"],
                         "pointee": p["pointee"]} for p in s["params"]]}
            for s in dwarf_subprograms],
        "recovered": {
            "structures": {n: {"size": i["size"], "fields": i["fields"]}
                           for n, i in types["structs"].items()},
            "struct_count": types["struct_count"],
            "retyped_functions": types["retyped"],
            "retyped_count": types["retyped_count"],
        },
        "metric": metric,
    }
    print_report(report, metric, dwarf_subprograms, decomp)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
        print("  json: %s" % args.json)
    return 0


def run_headless(ghidra_dir, script_path, wasm, out_dir, with_decomp):
    headless = os.path.join(ghidra_dir, "support",
                            "analyzeHeadless.bat" if os.name == "nt"
                            else "analyzeHeadless")
    if not os.path.isfile(headless):
        return die_loud("analyzeHeadless not found under %s" % ghidra_dir), None
    project_dir = os.path.join(out_dir, "ghidra-project")
    shutil.rmtree(project_dir, ignore_errors=True)
    os.makedirs(project_dir, exist_ok=True)
    log_path = os.path.join(out_dir, "headless.log")
    scripts = ["DumpTypes.java"] + (["DumpAll.java"] if with_decomp else [])
    cmd = [headless, project_dir, "Reg", "-import", os.path.abspath(wasm),
           "-scriptPath", os.path.abspath(script_path)]
    for script in scripts:
        cmd += ["-postScript", script]
    cmd += ["-deleteProject"]
    with open(log_path, "w", encoding="utf-8") as log:
        proc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT,
                              timeout=900)
    if proc.returncode != 0:
        return die_loud("analyzeHeadless exited %d (see %s)"
                        % (proc.returncode, log_path)), None
    return 0, log_path


def cmd_run(args):
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pin_file = os.path.join(repo, "test-scripts", ".ghidra-install")
    ghidra_dir = args.ghidra_dir
    if not ghidra_dir and os.path.isfile(pin_file):
        with open(pin_file, encoding="utf-8") as fh:
            ghidra_dir = fh.read().strip().splitlines()[0].strip()
    if not ghidra_dir:
        return die_loud("no Ghidra install: pass --ghidra-dir (the branch pin "
                        "file test-scripts/.ghidra-install is missing)")
    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)
    wasm = args.wasm
    if wasm is None:
        pwsh = shutil.which("pwsh") or shutil.which("powershell")
        if pwsh is None:
            return die_loud("need PowerShell to generate the fixture; pass "
                            "--wasm with an existing debuginfo module")
        fixture_dir = os.path.join(out_dir, "fixture")
        maker = os.path.join(repo, "test-scripts", "make_dwarf_fixture.ps1")
        print("generating fixture via make_dwarf_fixture.ps1 ...")
        proc = subprocess.run(
            [pwsh, "-NoProfile", "-NonInteractive", "-File", maker,
             "-OutDir", fixture_dir],
            capture_output=True, text=True, timeout=600)
        print(proc.stdout.strip())
        if proc.returncode != 0:
            print(proc.stderr.strip(), file=sys.stderr)
            return die_loud("make_dwarf_fixture.ps1 failed (%d)"
                            % proc.returncode)
        wasm = os.path.join(fixture_dir, "fixture_dwarf.wasm")
    print("importing %s headlessly ..." % wasm)
    rc, log_path = run_headless(ghidra_dir,
                                os.path.join(repo, "test-scripts"),
                                wasm, out_dir, not args.no_decomp)
    if rc != 0:
        return rc
    args.wasm = wasm
    args.types_log = log_path
    args.decomp_log = log_path if not args.no_decomp else None
    return cmd_analyze(args)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--wasm", default=None, help="subject module WITH .debug_info")
    ap.add_argument("--types-log", default=None, help="DumpTypes.java log")
    ap.add_argument("--decomp-log", default=None, help="DumpAll.java log (optional)")
    ap.add_argument("--json", default=None, help="write the report as JSON here")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--run", action="store_true",
                    help="end-to-end: generate the fixture (unless --wasm), "
                         "run the plugin headlessly, then score")
    ap.add_argument("--out-dir", default=None,
                    help="--run working dir (default: %%TEMP%%/dwarf-metric)")
    ap.add_argument("--no-decomp", action="store_true",
                    help="--run without the DumpAll.java pass (faster; "
                         "prototypes then come from DumpTypes RETYPED lines)")
    ap.add_argument("--ghidra-dir", default=None,
                    help="--run Ghidra install (default: the branch pin file)")
    args = ap.parse_args()
    if args.run:
        if args.out_dir is None:
            tmp = os.environ.get("TEMP") or os.environ.get("TMPDIR") or "/tmp"
            args.out_dir = os.path.join(tmp, "dwarf-metric")
        return cmd_run(args)
    if not args.wasm or not args.types_log:
        ap.print_usage(sys.stderr)
        print("dwarf_type_metric: --wasm and --types-log are required "
              "(or use --run)", file=sys.stderr)
        return 2
    return cmd_analyze(args)


if __name__ == "__main__":
    sys.exit(main())
