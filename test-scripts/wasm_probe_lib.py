#!/usr/bin/env python3
"""Shared byte-level helpers for building tiny WebAssembly probe modules.

Probe files (`gen_feature_probes.py`, `probes_analysis.py`, `probes_types.py`, ...) import this
module, call `set_output_dir()` and then `write("NN_name.wasm", module(...))`.

All prefixed opcodes are LEB128-encoded u32 values after the prefix byte, so helpers like
`simd_op(n)`, `misc_op(n)`, `gc_op(n)` and `atomic_op(n)` take the *numeric* opcode.

Encoding conventions used here follow the current core spec + proposals:
  section ids: 0 custom, 1 type, 2 import, 3 function, 4 table, 5 memory, 6 global, 7 export,
               8 start, 9 element, 10 code, 11 data, 12 data count, 13 tag
  prefixes:    0xFB GC, 0xFC misc, 0xFD SIMD, 0xFE atomics
"""
import os
import struct

OUT = "."


def set_output_dir(path):
    global OUT
    OUT = path
    os.makedirs(OUT, exist_ok=True)


def write(fname, blob):
    path = os.path.join(OUT, fname)
    with open(path, "wb") as f:
        f.write(blob)
    print(f"{fname}: {len(blob)} bytes")


# ---------------------------------------------------------------- numbers

def uleb(n: int) -> bytes:
    """Unsigned LEB128."""
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(n: int) -> bytes:
    """Signed LEB128 (also used for s33 block types and type indices)."""
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if (n == 0 and not (b & 0x40)) or (n == -1 and (b & 0x40)):
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def vec(items) -> bytes:
    return uleb(len(items)) + b"".join(items)


def name(s: str) -> bytes:
    raw = s.encode()
    return uleb(len(raw)) + raw


# ---------------------------------------------------------------- types

I32, I64, F32, F64, V128 = 0x7F, 0x7E, 0x7D, 0x7C, 0x7B
FUNCREF, EXTERNREF = 0x70, 0x6F
# heap type shorthands (GC / function-references)
HT_FUNC, HT_EXTERN = 0x70, 0x6F          # -0x10, -0x11 as s33
HT_ANY, HT_EQ, HT_I31 = 0x6E, 0x6D, 0x6C
HT_STRUCT, HT_ARRAY = 0x6B, 0x6A
HT_NONE, HT_NOEXTERN = 0x71, 0x72
HT_EXN = 0x69                            # exnref (legacy/new EH)


def functype(params, results) -> bytes:
    """0x60 params results; params/results are lists of single-byte valtypes."""
    return b"\x60" + vec([bytes([p]) for p in params]) + vec([bytes([r]) for r in results])


def _heaptype_enc(ht) -> bytes:
    """Encode a heap type as an s33.

    Small non-negative values are concrete type indices; the abstract heap types are passed as their
    single-byte shorthands (0x69 exn, 0x6A array, 0x6B struct, 0x6C i31, 0x6D eq, 0x6E any,
    0x6F extern, 0x70 func, 0x71 none, 0x72 noextern, 0x73 nofunc, 0x74 noexn) and encode as the
    equivalent negative s33 (which is byte-identical to the shorthand).
    """
    if isinstance(ht, bytes):
        return ht
    if 0x69 <= ht <= 0x74:
        return sleb(ht - 0x80)
    if ht < 0:
        return sleb(ht)
    return sleb(ht)


def ref_null(heaptype) -> bytes:
    """(ref null <heaptype>) - heaptype is a byte shorthand or a concrete type index."""
    return b"\x63" + _heaptype_enc(heaptype)


def ref_(heaptype) -> bytes:
    """(ref <heaptype>) - non-nullable reference."""
    return b"\x64" + _heaptype_enc(heaptype)


def struct_type(fields) -> bytes:
    """0x5F; fields is a list of (storage_valtype_byte, mutable)."""
    return b"\x5F" + vec([bytes([st, 0x01 if mut else 0x00]) for (st, mut) in fields])


def array_type(storage, mutable) -> bytes:
    """0x5E."""
    return b"\x5E" + bytes([storage, 0x01 if mutable else 0x00])


def rectype(*types) -> bytes:
    """0x4E rec group."""
    return b"\x4E" + vec(list(types))


def subtype(inner, supertypes=(), final=True) -> bytes:
    """0x50 (sub) / 0x4F (sub final)."""
    return (b"\x4F" if final else b"\x50") + vec([uleb(s) for s in supertypes]) + inner


# ---------------------------------------------------------------- prefixed opcodes

def gc_op(n) -> bytes:
    """0xFB-prefixed opcode (struct.new = 0, array.new = 6, ref.cast = 0x16, ...)."""
    return b"\xFB" + uleb(n)


def misc_op(n) -> bytes:
    """0xFC-prefixed opcode (trunc_sat 0-7, bulk memory 8-17, memory.discard 0x12, ...)."""
    return b"\xFC" + uleb(n)


def simd_op(n) -> bytes:
    """0xFD-prefixed opcode (v128.const = 12, i32x4.add = 174, relaxed = >= 0x100)."""
    return b"\xFD" + uleb(n)


def atomic_op(n) -> bytes:
    """0xFE-prefixed opcode (i32.atomic.load = 0x10, memory.atomic.notify = 0, ...)."""
    return b"\xFE" + uleb(n)


# ---------------------------------------------------------------- instructions

END = b"\x0b"


def local_get(i) -> bytes:
    return b"\x20" + uleb(i)


def local_set(i) -> bytes:
    return b"\x21" + uleb(i)


def local_tee(i) -> bytes:
    return b"\x22" + uleb(i)


def global_get(i) -> bytes:
    return b"\x23" + uleb(i)


def global_set(i) -> bytes:
    return b"\x24" + uleb(i)


def i32_const(v) -> bytes:
    """i32.const; v may be any 32-bit bit pattern (wrapped to its signed value)."""
    return b"\x41" + sleb(((v + (1 << 31)) % (1 << 32)) - (1 << 31))


def i64_const(v) -> bytes:
    """i64.const; v may be any 64-bit bit pattern (wrapped to its signed value)."""
    return b"\x42" + sleb(((v + (1 << 63)) % (1 << 64)) - (1 << 63))


def f32_const(v: float) -> bytes:
    return b"\x43" + struct.pack("<f", v)


def f64_const(v: float) -> bytes:
    return b"\x44" + struct.pack("<d", v)


def v128_const(raw16: bytes) -> bytes:
    assert len(raw16) == 16
    return simd_op(12) + raw16


def drop() -> bytes:
    return b"\x1A"


def call(funcidx) -> bytes:
    return b"\x10" + uleb(funcidx)


def call_ref(typeidx) -> bytes:
    return b"\x14" + uleb(typeidx)


def return_call(funcidx) -> bytes:
    return b"\x12" + uleb(funcidx)


def call_indirect(typeidx, tableidx=0) -> bytes:
    return b"\x11" + uleb(typeidx) + uleb(tableidx)


def return_call_indirect(typeidx, tableidx=0) -> bytes:
    return b"\x13" + uleb(typeidx) + uleb(tableidx)


def block(blocktype=0x40, body=b"") -> bytes:
    """blocktype is 0x40 (empty), a valtype byte, multi-byte valtype bytes, or a type index."""
    if isinstance(blocktype, bytes):
        return b"\x02" + blocktype + body + END
    if blocktype in (0x40, I32, I64, F32, F64, V128, FUNCREF, EXTERNREF):
        return b"\x02" + bytes([blocktype]) + body + END
    return b"\x02" + sleb(blocktype) + body + END


def loop(blocktype=0x40, body=b"") -> bytes:
    if isinstance(blocktype, bytes):
        return b"\x03" + blocktype + body + END
    if blocktype in (0x40, I32, I64, F32, F64, V128, FUNCREF, EXTERNREF):
        return b"\x03" + bytes([blocktype]) + body + END
    return b"\x03" + sleb(blocktype) + body + END


def if_(blocktype=0x40, then=b"", else_=None) -> bytes:
    bt = bytes([blocktype]) if blocktype in (0x40, I32, I64, F32, F64, V128, FUNCREF, EXTERNREF) \
        else sleb(blocktype)
    out = b"\x04" + bt + then
    if else_ is not None:
        out += b"\x05" + else_
    return out + END


def br(label) -> bytes:
    return b"\x0C" + uleb(label)


def br_if(label) -> bytes:
    return b"\x0D" + uleb(label)


def br_table(labels) -> bytes:
    return b"\x0E" + vec([uleb(l) for l in labels])


def select_t(valtype) -> bytes:
    return b"\x1C" + vec([bytes([valtype])])


# ---------------------------------------------------------------- sections

def section(sid: int, payload: bytes) -> bytes:
    return bytes([sid]) + uleb(len(payload)) + payload


def custom_section(name_str: str, payload: bytes) -> bytes:
    return section(0, name(name_str) + payload)


# Canonical core-module section order. Non-custom section ids ascend, with two
# exceptions to the id order: the data count section (12) must precede the code
# section (10), and the tag section (13) sits between the memory (5) and global (6)
# sections. Custom sections (0) may appear anywhere, so they keep their exact
# positions; only the non-custom sections are reordered into the canonical sequence.
# Pass sort=False for a module that is deliberately misordered (see
# make_malformed_corpus.py, probes_sections_i64.py).
_SECTION_RANK = {1: 10, 2: 20, 3: 30, 4: 40, 5: 50, 13: 55, 6: 60, 7: 70, 8: 80, 9: 90,
                 12: 100, 10: 110, 11: 120}


def module(*sections: bytes, sort: bool = True) -> bytes:
    if sort:
        ordered = sorted((s for s in sections if s[0] != 0),
                         key=lambda s: _SECTION_RANK.get(s[0], 1000 + s[0]))
        it = iter(ordered)
        sections = tuple(next(it) if s[0] != 0 else s for s in sections)
    return b"\x00asm" + struct.pack("<I", 1) + b"".join(sections)


def type_section(*types) -> bytes:
    return section(1, vec(list(types)))


def import_section(imports) -> bytes:
    """imports: list of (module_name, field_name, kind_byte, descriptor_bytes)."""
    out = []
    for (mod, field, kind, desc) in imports:
        out.append(name(mod) + name(field) + bytes([kind]) + desc)
    return section(2, vec(out))


def func_section(typeidxs) -> bytes:
    return section(3, vec([uleb(t) for t in typeidxs]))


def table_section(tables) -> bytes:
    """tables: list of (elemtype_byte, flags, initial[, maximum])."""
    out = []
    for t in tables:
        elemtype, flags, initial = t[0], t[1], t[2]
        body = bytes([elemtype]) + bytes([flags]) + uleb(initial)
        if len(t) > 3:
            body += uleb(t[3])
        out.append(body)
    return section(4, vec(out))


def memory_section(mems) -> bytes:
    """mems: list of (flags, initial[, maximum]); flags bit0=max, bit1=shared, bit2=64-bit."""
    out = []
    for m in mems:
        flags, initial = m[0], m[1]
        body = bytes([flags]) + uleb(initial)
        if len(m) > 2:
            body += uleb(m[2])
        out.append(body)
    return section(5, vec(out))


def memory_custom_page(flags: int, initial: int, maximum, exponent: int) -> bytes:
    """One memory entry with a custom page size (limits flag 0x08).

    Binary encoding (verified against wabt 1.0.42 + binaryen version_133): the
    flags byte, the initial page count, the maximum page count when bit 0 is set,
    then the page-size *exponent* (page size = 2**exponent bytes). Both oracles
    accept exponents 0 (1 byte) and 16 (64 KiB) and reject anything else.
    `maximum` is None when the entry carries no maximum (bit 0 clear).
    """
    body = bytes([flags]) + uleb(initial)
    if flags & 0x01:
        assert maximum is not None, "flags request a maximum but none was given"
        body += uleb(maximum)
    body += uleb(exponent)
    return body


def memory_section_custom(mems) -> bytes:
    """mems: list of (flags, initial, maximum-or-None, exponent); see memory_custom_page."""
    return section(5, vec([memory_custom_page(f, i, m, e) for (f, i, m, e) in mems]))


def global_section(globals_) -> bytes:
    """globals_: list of (valtype, mutable, init_expr_bytes) - the `end` is appended.

    valtype may be an int (single-byte valtype) or bytes (multi-byte, e.g. `ref_null(0)`).
    """
    out = []
    for (vt, mut, init) in globals_:
        prefix = bytes([vt]) if isinstance(vt, int) else vt
        out.append(prefix + (b"\x01" if mut else b"\x00") + init + END)
    return section(6, vec(out))


def export_section(exports) -> bytes:
    """exports: list of (name, kind, idx) with kind 0=func, 1=table, 2=memory, 3=global, 4=tag."""
    return section(7, vec([name(n) + bytes([k]) + uleb(i) for (n, k, i) in exports]))


def start_section(funcidx) -> bytes:
    return section(8, uleb(funcidx))


def elem_section(segments) -> bytes:
    return section(9, vec(list(segments)))


def body(code: bytes, locals_=()) -> bytes:
    """locals_: list of (count, valtype) groups."""
    if locals_:
        inner = vec([uleb(c) + bytes([vt]) for (c, vt) in locals_]) + code
    else:
        inner = uleb(0) + code
    return uleb(len(inner)) + inner


def code_section(bodies) -> bytes:
    return section(10, vec([body(b) if isinstance(b, bytes) else b for b in bodies]))


def data_count_section(count) -> bytes:
    return section(12, uleb(count))


def data_section(segments) -> bytes:
    return section(11, vec(list(segments)))


def active_data(offset_expr: bytes, data: bytes, memidx=0) -> bytes:
    """Active data segment, memory 0 (or a given index when non-zero)."""
    if memidx:
        return b"\x02" + uleb(memidx) + offset_expr + uleb(len(data)) + data
    return b"\x00" + offset_expr + uleb(len(data)) + data


def passive_data(data: bytes) -> bytes:
    return b"\x01" + uleb(len(data)) + data


def tag_section(tags) -> bytes:
    """tags: list of (attribute, typeidx)."""
    return section(13, vec([bytes([a]) + uleb(t) for (a, t) in tags]))


# ---------------------------------------------------------------- name section

def name_subsection(sid, payload: bytes) -> bytes:
    return bytes([sid]) + uleb(len(payload)) + payload


def name_map(entries) -> bytes:
    """entries: list of (index, name_str) - the name-map subsection payload."""
    return vec([uleb(i) + name(n) for (i, n) in entries])


def name_section(*subsections) -> bytes:
    """Wraps subsections in the `.name` custom section (ids: 0 module, 1 function, 2 local,
    3 label, 4 type, 5 table, 6 memory, 7 global, 8 elem, 9 data, 10 field, 11 tag)."""
    return custom_section(".name", b"".join(subsections))


def label_names(entries) -> bytes:
    """(label names, id 3) entries: list of (funcidx, [(labelidx, name)])."""
    out = []
    for (funcidx, labels) in entries:
        indirect = vec([uleb(i) + name(n) for (i, n) in labels])
        out.append(uleb(funcidx) + indirect)
    return name_subsection(3, vec(out))


# ---------------------------------------------------------------- misc

def raw_module(version_bytes: bytes) -> bytes:
    """Header with an arbitrary version/layer, e.g. b'\\x0d\\x00\\x01\\x00' for a component."""
    return b"\x00asm" + version_bytes
