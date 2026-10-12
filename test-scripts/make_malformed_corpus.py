#!/usr/bin/env python3
"""Malformed / hostile WebAssembly module generator (robustness corpus, agent J).

Emits structurally broken or hostile modules into the directory given as sys.argv[1]. The modules
exercise the *error paths* of the Ghidra WebAssembly loader: truncation, bad LEB128, section-size
lies, absurd counts, out-of-range indices, duplicate/out-of-order/unknown sections, exploding
function bodies and locals, bad constant expressions, contradictory limits, and magic/version
variants.

This file is stdlib-only and self-contained: it does not import (and therefore cannot mutate)
`wasm_probe_lib.py`. The handful of byte helpers below are small copies of the encoders in that
library, kept verbatim so the emitted bytes are identical.

Usage:
    python gen_malformed_probes.py <output-dir> [all|core]

`all` (default) emits the full corpus (~56 modules). `core` emits only CORE_NAMES, a curated
representative subset (~25 modules) covering every distinct failure mode, which is what the
sweep uses by default: each malformed module is imported in its own headless JVM and the JVM
startup (~10 s) dominates, so the full corpus would take ~11 minutes to sweep while the core
set finishes in ~5.
"""
import os
import struct
import sys

# --------------------------------------------------------------------------------------------------
# byte helpers (small copies of wasm_probe_lib encoders)
# --------------------------------------------------------------------------------------------------

OUT = "."
MODE = "all"
EMITTED = []

# Curated subset used by `robustness-sweep.ps1` (one representative per failure mode, plus the
# V00 control). Kept in sync with the ranked table in robustness-RESULTS.md.
CORE_NAMES = {
    "V00_valid_passthrough.wasm",       # control: valid module must import cleanly
    "T01_empty.wasm",
    "T04_trunc_mid_sectionid.wasm",
    "T05_trunc_mid_payload.wasm",
    "L03_leb_count_overflow32.wasm",
    "L05_leb_unterminated_eof.wasm",
    "S02_size_declared_larger.wasm",
    "S04_size_2p28.wasm",
    "C01_count_type_ffffffff.wasm",
    "C03_count_code_ffffffff.wasm",
    "C05_count_memory_ffffffff.wasm",
    "C09_count_func_code_mismatch.wasm",
    "O05_globalidx_oor.wasm",
    "O08_typeidx_huge_ref.wasm",
    "D03_unknown_section_id.wasm",
    "D04_sections_wrong_order.wasm",
    "B02_body_exceeds_section.wasm",
    "B03_locals_ffffffff.wasm",
    "B04_locals_1G_alloc.wasm",
    "X01_expr_no_end.wasm",
    "X03_expr_nested_unterminated.wasm",
    "M01_mem_initial_gt_max.wasm",
    "M03_mem_huge_initial.wasm",
    "M04_table_huge_initial.wasm",
    "H01_bad_magic.wasm",
    "H03_version13_component.wasm",
}


def set_output_dir(path):
    global OUT
    OUT = path
    os.makedirs(OUT, exist_ok=True)


def write(fname, blob):
    path = os.path.join(OUT, fname)
    with open(path, "wb") as f:
        f.write(blob)
    print(f"{fname}: {len(blob)} bytes")


def emit(fname, blob):
    """Record a probe; `flush` actually writes the ones selected by MODE."""
    EMITTED.append((fname, blob))


def flush():
    n = 0
    for fname, blob in EMITTED:
        if MODE == "core" and fname not in CORE_NAMES:
            continue
        write(fname, blob)
        n += 1
    print(f"[{MODE}] {n}/{len(EMITTED)} modules written")


def uleb(n: int) -> bytes:
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


I32, I64, F32, F64, V128 = 0x7F, 0x7E, 0x7D, 0x7C, 0x7B
FUNCREF, EXTERNREF = 0x70, 0x6F
END = b"\x0b"
HEADER = b"\x00asm" + struct.pack("<I", 1)


def section(sid: int, payload: bytes) -> bytes:
    return bytes([sid]) + uleb(len(payload)) + payload


def custom_section(name_str: str, payload: bytes) -> bytes:
    return section(0, name(name_str) + payload)


def module(*sections: bytes) -> bytes:
    return HEADER + b"".join(sections)


def functype(params, results) -> bytes:
    return b"\x60" + vec([bytes([p]) for p in params]) + vec([bytes([r]) for r in results])


def type_section(*types) -> bytes:
    return section(1, vec(list(types)))


def func_section(typeidxs) -> bytes:
    return section(3, vec([uleb(t) for t in typeidxs]))


def code_section(entries) -> bytes:
    """entries are already-built code entries (use body(...) for a normal one)."""
    return section(10, vec(list(entries)))


def body(code: bytes, locals_=()) -> bytes:
    if locals_:
        inner = vec([uleb(c) + bytes([vt]) for (c, vt) in locals_]) + code
    else:
        inner = uleb(0) + code
    return uleb(len(inner)) + inner


def memory_section(mems) -> bytes:
    out = []
    for m in mems:
        flags, initial = m[0], m[1]
        b = bytes([flags]) + uleb(initial)
        if len(m) > 2:
            b += uleb(m[2])
        out.append(b)
    return section(5, vec(out))


def table_section(tables) -> bytes:
    out = []
    for t in tables:
        elemtype, flags, initial = t[0], t[1], t[2]
        b = bytes([elemtype]) + bytes([flags]) + uleb(initial)
        if len(t) > 3:
            b += uleb(t[3])
        out.append(b)
    return section(4, vec(out))


def export_section(exports) -> bytes:
    return section(7, vec([name(n) + bytes([k]) + uleb(i) for (n, k, i) in exports]))


def global_section(globals_) -> bytes:
    out = []
    for (vt, mut, init) in globals_:
        prefix = bytes([vt]) if isinstance(vt, int) else vt
        out.append(prefix + (b"\x01" if mut else b"\x00") + init + END)
    return section(6, vec(out))


def elem_section(segments) -> bytes:
    return section(9, vec(list(segments)))


def data_section(segments) -> bytes:
    return section(11, vec(list(segments)))


def i32_const(v) -> bytes:
    return b"\x41" + sleb(v)


def active_data(offset_expr: bytes, data: bytes, memidx=0) -> bytes:
    if memidx:
        return b"\x02" + uleb(memidx) + offset_expr + uleb(len(data)) + data
    return b"\x00" + offset_expr + uleb(len(data)) + data


# --------------------------------------------------------------------------------------------------

if len(sys.argv) > 1:
    set_output_dir(sys.argv[1])
if len(sys.argv) > 2:
    MODE = sys.argv[2].lower()
    if MODE not in ("all", "core"):
        raise SystemExit(f"unknown set {MODE!r} (expected 'all' or 'core')")

T1 = functype([], [])            # (func) -> ()
T1i = functype([I32], [I32])     # (i32) -> i32

# ---- sanity check: a *valid* module so the harness itself can be validated ---------------------------------
emit("V00_valid_passthrough.wasm", module(
    type_section(T1i),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([body(b"\x20\x00" + END)]),
))

# ==================================================================================================
# 1. truncation
# ==================================================================================================
emit("T01_empty.wasm", b"")
emit("T02_trunc_mid_header.wasm", b"\x00as\x6d")            # 4 bytes of the 8-byte header
emit("T03_trunc_mid_version.wasm", b"\x00asm\x01\x00")      # magic + 2 of 4 version bytes
emit("T04_trunc_mid_sectionid.wasm", HEADER + b"\x01")      # section id, no length

# mid-section-payload / mid-function-body: build a valid module, then physically truncate it.
_valid_body = module(type_section(T1), func_section([0]), code_section([body(b"\x41\x2a" + END)]))
emit("T05_trunc_mid_payload.wasm", HEADER + b"\x01" + uleb(20) + uleb(2) + T1)  # wants 2 types, 1 present
emit("T06_trunc_mid_body.wasm", _valid_body[:-2])           # last 2 bytes of the code entry removed

# ==================================================================================================
# 2. bad LEB128
# ==================================================================================================
emit("L01_leb_overlong_pad_len.wasm", HEADER + b"\x01" + b"\x80\x80\x80\x80\x00" + vec([T1]))
emit("L02_leb_len_gt5bytes.wasm", HEADER + b"\x01" + b"\x80\x80\x80\x80\x80\x00" + vec([T1]))
emit("L03_leb_count_overflow32.wasm", HEADER + b"\x01" + uleb(5) + b"\xff\xff\xff\xff\x7f")  # count=0xFFFFFFFF
emit("L04_leb_len_overflow64.wasm", HEADER + b"\x01" + b"\xff" * 9 + b"\x7f" + b"\x60\x00\x00")
emit("L05_leb_unterminated_eof.wasm", HEADER + b"\x01" + b"\xff\xff\xff\xff")

# ==================================================================================================
# 3. section size mismatches
# ==================================================================================================
emit("S01_size_declared_smaller.wasm", HEADER + b"\x01" + uleb(1) + vec([T1]))            # real payload 5
emit("S02_size_declared_larger.wasm", HEADER + b"\x01" + uleb(30) + vec([T1]))            # real payload 5
emit("S03_size_zero.wasm", HEADER + b"\x01\x00" + vec([T1]))
emit("S04_size_2p28.wasm", HEADER + b"\x01" + uleb(1 << 28) + vec([T1]))

# ==================================================================================================
# 4. absurd counts
# ==================================================================================================
emit("C01_count_type_ffffffff.wasm", HEADER + section(1, uleb(0xFFFFFFFF)))
emit("C02_count_func_ffffffff.wasm", module(type_section(T1), section(3, uleb(0xFFFFFFFF))))
emit("C03_count_code_ffffffff.wasm", module(type_section(T1), func_section([0]), section(10, uleb(0xFFFFFFFF))))
emit("C04_count_table_ffffffff.wasm", HEADER + section(4, uleb(0xFFFFFFFF)))
emit("C05_count_memory_ffffffff.wasm", HEADER + section(5, uleb(0xFFFFFFFF)))
emit("C06_count_global_ffffffff.wasm", HEADER + section(6, uleb(0xFFFFFFFF)))
emit("C07_count_element_ffffffff.wasm", HEADER + section(9, uleb(0xFFFFFFFF)))
emit("C08_count_data_ffffffff.wasm", HEADER + section(11, uleb(0xFFFFFFFF)))
# function section declares 3 functions, code section provides 1 body -> mismatch
emit("C09_count_func_code_mismatch.wasm", module(
    type_section(T1), func_section([0, 0, 0]), code_section([body(END)])))

# ==================================================================================================
# 5. out-of-range indices
# ==================================================================================================
emit("O01_typeidx_oor.wasm", module(type_section(T1), func_section([0xFFFF])))
emit("O02_funcidx_oor.wasm", module(type_section(T1), func_section([0]),
      code_section([body(b"\x10" + uleb(0xFFFFFFFF) + END)])))            # call 0xFFFFFFFF
emit("O03_tableidx_oor.wasm", module(type_section(T1), table_section([(FUNCREF, 0x00, 1)]), func_section([0]),
      code_section([body(b"\x41\x00" + b"\x11" + uleb(0) + uleb(0xFFFFF) + END)])))  # call_indirect t0 tbl 0xFFFFF
emit("O04_memidx_oor.wasm", module(type_section(T1), func_section([0]),
      data_section([b"\x02" + uleb(0xFFFF) + i32_const(0) + END + uleb(1) + b"A"])))  # data memidx 0xFFFF
emit("O05_globalidx_oor.wasm", module(type_section(T1), func_section([0]),
      code_section([body(b"\x23" + uleb(0xFFFF) + b"\x1a" + END)])))      # global.get 0xFFFF; drop
emit("O06_elem_funcidx_oor.wasm", module(type_section(T1), table_section([(FUNCREF, 0x00, 1)]),
      elem_section([b"\x00" + i32_const(0) + END + uleb(1) + uleb(0xFFFF)])))
emit("O07_tagidx_oor.wasm", module(type_section(T1), section(13, vec([b"\x00" + uleb(0xFFFF)]))))
emit("O08_typeidx_huge_ref.wasm", module(type_section(T1), func_section([0]),
      code_section([body(b"\x41\x00" + b"\x11" + uleb(0x7FFFFFFF) + uleb(0) + END)])))

# ==================================================================================================
# 6. duplicate / out-of-order / unknown sections
# ==================================================================================================
emit("D01_two_type_sections.wasm", module(type_section(T1), type_section(T1i)))
emit("D02_two_code_sections.wasm", module(type_section(T1), func_section([0]),
      code_section([body(END)]), code_section([body(END)])))
emit("D03_unknown_section_id.wasm", HEADER + b"\x2a" + uleb(3) + b"\x00\x00\x00")   # id 42
emit("D04_sections_wrong_order.wasm", module(code_section([body(END)]), func_section([0]), type_section(T1)))
emit("D05_repeat_custom_sections.wasm", module(
    custom_section("aa", b"x"), custom_section("aa", b"y"), custom_section("bb", b"z")))

# ==================================================================================================
# 7. function bodies / locals
# ==================================================================================================
emit("B01_zero_length_body.wasm", module(type_section(T1), func_section([0]), code_section([b"\x00"])))
# declared code size 0xFFFF but only a couple of bytes follow
emit("B02_body_exceeds_section.wasm", module(type_section(T1), func_section([0]),
      section(10, uleb(1) + uleb(0xFFFF) + b"\x00" + b"\x0b")))
# one locals group declaring 0xFFFFFFFF i32 locals  -> getLocals() -> new ValType[(int)0xFFFFFFFF] == -1
emit("B03_locals_ffffffff.wasm", module(type_section(T1), func_section([0]),
      code_section([body(END, locals_=[(0xFFFFFFFF, I32)])])))
# one locals group declaring 0x40000000 i32 locals  -> ~1G-element reference array
emit("B04_locals_1G_alloc.wasm", module(type_section(T1), func_section([0]),
      code_section([body(END, locals_=[(0x40000000, I32)])])))

# ==================================================================================================
# 8. bad constant expressions
# ==================================================================================================
# global i32 (mut) = i32.const 0   with the terminating `end` and everything else missing
emit("X01_expr_no_end.wasm", HEADER + section(6, vec([bytes([I32, 0x01]) + i32_const(0)])))
# global i32 = i32.const <10-byte overflow sleb> ; end
emit("X02_expr_overflow_value.wasm", HEADER + section(6, vec([bytes([I32, 0x00]) + b"\x41" + b"\xff" * 9 + b"\x7f" + END])))
# global i32 = block block block  (never closed, file ends)
emit("X03_expr_nested_unterminated.wasm", HEADER + section(6, vec([bytes([I32, 0x00]) + b"\x02\x40" * 3])))

# ==================================================================================================
# 9. limits / data segments
# ==================================================================================================
emit("M01_mem_initial_gt_max.wasm", HEADER + memory_section([(0x01, 5, 1)]))
emit("M02_mem_max_2p32.wasm", HEADER + memory_section([(0x01, 1, 1 << 32)]))
emit("M03_mem_huge_initial.wasm", HEADER + memory_section([(0x00, 0xFFFFFFFF)]))     # ~2^32 pages
emit("M04_table_huge_initial.wasm", HEADER + table_section([(FUNCREF, 0x00, 0xFFFFFFFF)]))
emit("M05_data_offset_oor.wasm", module(
    memory_section([(0x01, 1, 1)]),
    data_section([active_data(i32_const(0x7FFFFFF0) + END, b"AAAA")])))
emit("M06_data_overlap.wasm", module(
    memory_section([(0x01, 1, 1)]),
    data_section([active_data(i32_const(0) + END, b"AAAA"), active_data(i32_const(0) + END, b"BBBB")])))

# ==================================================================================================
# 10. magic / version variants
# ==================================================================================================
emit("H01_bad_magic.wasm", b"\x00basm" + struct.pack("<I", 1))
emit("H02_version0.wasm", b"\x00asm" + b"\x00\x00\x00\x00")
emit("H03_version13_component.wasm", b"\x00asm" + b"\x0d\x00\x00\x00")
emit("H04_version0d_layer1.wasm", b"\x00asm" + b"\x0d\x00\x01\x00")
emit("H05_all_zeros.wasm", b"\x00" * 16)

flush()
