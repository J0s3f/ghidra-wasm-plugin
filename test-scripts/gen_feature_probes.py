#!/usr/bin/env python3
"""Generate tiny WebAssembly modules that exercise specific modern proposals.

Each module is valid (or, where noted, minimally structured) per the current
WebAssembly spec + proposal encoding, so it can be used to probe how much of
modern wasm a loader/analyzer understands.
"""
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "."
os.makedirs(OUT, exist_ok=True)

I32, I64, F32, F64, V128 = 0x7F, 0x7E, 0x7D, 0x7C, 0x7B
FUNCREF, EXTERNREF = 0x70, 0x6F


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


def section(sid: int, payload: bytes) -> bytes:
    return bytes([sid]) + uleb(len(payload)) + payload


def module(*sections: bytes) -> bytes:
    return b"\x00asm" + struct.pack("<I", 1) + b"".join(sections)


def functype(params, results) -> bytes:
    return b"\x60" + vec([bytes([p]) for p in params]) + vec([bytes([r]) for r in results])


def type_section(*types) -> bytes:
    return section(1, vec(list(types)))


def func_section(typeidxs) -> bytes:
    return section(3, vec([uleb(t) for t in typeidxs]))


def table_section(tables) -> bytes:
    # tables: list of (elemtype, flags, initial[, maximum])
    out = []
    for t in tables:
        elemtype, flags, initial = t[0], t[1], t[2]
        body = bytes([elemtype]) + bytes([flags]) + uleb(initial)
        if len(t) > 3:
            body += uleb(t[3])
        out.append(body)
    return section(4, vec(out))


def memory_section(mems) -> bytes:
    # mems: list of (flags, initial[, maximum])
    out = []
    for m in mems:
        flags, initial = m[0], m[1]
        body = bytes([flags]) + uleb(initial)
        if len(m) > 2:
            body += uleb(m[2])
        out.append(body)
    return section(5, vec(out))


def export_section(exports) -> bytes:
    # exports: list of (name, kind, idx)
    return section(7, vec([name(n) + bytes([k]) + uleb(i) for (n, k, i) in exports]))


def body(code: bytes) -> bytes:
    inner = uleb(0) + code  # 0 local groups
    return uleb(len(inner)) + inner


def code_section(bodies) -> bytes:
    return section(10, vec([body(b) for b in bodies]))


def data_section(segments) -> bytes:
    return section(11, vec(list(segments)))


def tag_section(tags) -> bytes:
    # tags: list of (attribute, typeidx)
    return section(13, vec([bytes([a]) + uleb(t) for (a, t) in tags]))


def active_data(offset_expr: bytes, data: bytes) -> bytes:
    return b"\x00" + offset_expr + uleb(len(data)) + data


def write(fname, blob):
    path = os.path.join(OUT, fname)
    with open(path, "wb") as f:
        f.write(blob)
    print(f"{fname}: {len(blob)} bytes")


END = b"\x0b"

# 1. baseline: (func (export "f") (param i32) (result i32) local.get 0)
write("01_baseline_i32.wasm", module(
    type_section(functype([I32], [I32])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x20\x00" + END]),
))

# 2. reference types: externref parameter (MVP + reference-types)
write("02_externref_param.wasm", module(
    type_section(functype([EXTERNREF], [I32])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x41\x01" + END]),
))

# 3. externref table + table.get
write("03_externref_table.wasm", module(
    type_section(functype([], [EXTERNREF])),
    table_section([(EXTERNREF, 0x00, 1)]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x41\x00\x25\x00" + END]),  # i32.const 0; table.get 0
))

# 4. threads: shared memory + atomic load
write("04_shared_memory_atomic.wasm", module(
    type_section(functype([I32], [I32])),
    memory_section([(0x03, 1, 1)]),  # flags=3 -> shared, has max
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x20\x00" + b"\xFE\x10" + b"\x02\x00" + END]),  # i32.atomic.load align=2 off=0
))

# 5. memory64: 64-bit memory, i64 address operand
write("05_memory64.wasm", module(
    type_section(functype([], [I32])),
    memory_section([(0x04, 1)]),  # flags=4 -> 64-bit index, no max
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x42\x00" + b"\x28\x02\x00" + END]),  # i64.const 0; i32.load align=2 off=0
))

# 6. multi-memory: two memories, load from memory 1 (memarg memidx), memory.size 1
write("06_multi_memory.wasm", module(
    type_section(functype([], [I32])),
    memory_section([(0x00, 1), (0x00, 1)]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x41\x00" + b"\x28" + b"\x42\x01\x00" +     # i32.const 0; i32.load memidx=1 align=2 off=0
                  b"\x3F\x01" +                                   # memory.size 1
                  b"\x6A" + END]),                                # i32.add
))

# 7. data count section + active data + memory.init / data.drop (bulk memory)
write("07_data_count_bulk_memory.wasm", module(
    type_section(functype([], [])),
    memory_section([(0x00, 1)]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    section(12, uleb(1)),  # data count
    code_section([b"\x41\x00\x41\x00\x41\x03" + b"\xFC\x08\x00\x00" + b"\xFC\x09\x00" + END]),
    data_section([active_data(b"\x41\x00" + END, b"abc")]),
))

# 8. GC: struct type + i31.new/struct.new would need more; keep the type section GC-typed
write("08_gc_struct_type.wasm", module(
    type_section(b"\x5F" + vec([bytes([I32]) + b"\x00"]),  # (struct (field i32))
                 functype([], [])),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([END]),
))

# 9. GC: struct.new + ref.cast on a struct type
write("09_gc_struct_new.wasm", module(
    type_section(b"\x5F" + vec([bytes([I32]) + b"\x00"]),
                 functype([], [])),
    func_section([1]),
    export_section([("f", 0, 0)]),
    code_section([b"\x41\x01" + b"\xFB\x00\x00" + END]),  # i32.const 1; struct.new 0
))

# 10. exception handling (legacy): tag + try/catch/throw
write("10_eh_legacy_try_catch.wasm", module(
    type_section(functype([], [])),
    tag_section([(0x00, 0)]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x06\x40" + b"\x08\x00" + b"\x07\x00" + END + END]),  # try; throw 0; catch 0; end; end
))

# 11. exception handling (new proposal): try_table
write("11_eh_try_table.wasm", module(
    type_section(functype([], [])),
    tag_section([(0x00, 0)]),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x1F\x40" + vec([]) + END + END]),  # try_table (empty) ; end ; end
))

# 12. typed function references: (ref null $t) parameter + call_ref
write("12_call_ref.wasm", module(
    # type 0 = ((ref null 0)) -> ()
    type_section(b"\x60" + vec([b"\x63" + sleb(0)]) + vec([])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x20\x00" + b"\x14\x00" + END]),  # local.get 0; call_ref 0
))

# 13. tail calls: return_call
write("13_tail_call.wasm", module(
    type_section(functype([], [])),
    func_section([0, 0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x12\x01" + END, END]),  # return_call 1 ; end   /  end
))

# 14. relaxed SIMD: i8x16.relaxed_swizzle
write("14_relaxed_simd.wasm", module(
    type_section(functype([], [])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([
        b"\xFD\x0C" + bytes(16) +      # v128.const i32x4 0 0 0 0
        b"\xFD\x0C" + bytes(16) +      # v128.const i32x4 0 0 0 0
        b"\xFD\x80\x02" +              # i8x16.relaxed_swizzle (0x100)
        b"\x1A" + END]),               # drop
))

# 15. SIMD (baseline vector ops): i32x4.add (0xFD + LEB128 u32 174 = AE 01)
write("15_simd.wasm", module(
    type_section(functype([], [])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\xFD\x0C" + bytes(16) + b"\xFD\x0C" + bytes(16) + b"\xFD\xAE\x01" + b"\x1A" + END]),
))

# 16. multi-value: function returning (i32, i32), called and both results dropped
write("16_multivalue_return.wasm", module(
    type_section(functype([], [I32, I32]), functype([], [])),
    func_section([0, 1]),
    export_section([("f", 0, 0)]),
    code_section([
        b"\x41\x01\x41\x02" + END,            # i32.const 1; i32.const 2
        b"\x10\x00" + b"\x1A\x1A" + END,      # call 0; drop; drop
    ]),
))

# 17. multi-value block: block with a type-index blocktype
write("17_multivalue_block.wasm", module(
    type_section(functype([], [I32]), functype([], [I32, I32])),
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x02" + sleb(1) + b"\x41\x01\x41\x02" + END + b"\x6A" + END]),
))

# 18. shared memory followed by a second memory: does the limits desync corrupt it?
write("18_shared_then_plain_memory.wasm", module(
    type_section(functype([], [I32])),
    memory_section([(0x03, 1, 1), (0x00, 7)]),  # memory 0 shared, memory 1 = 7 pages
    func_section([0]),
    export_section([("f", 0, 0)]),
    code_section([b"\x3F\x01" + END]),  # memory.size 1
))

# 19. extended-const: global initializer using i32.add (valid since the extended-const proposal)
def global_section(globals_):
    # globals_: list of (valtype, mutable, init_expr)
    out = []
    for (vt, mut, init) in globals_:
        out.append(bytes([vt, 0x01 if mut else 0x00]) + init + END)
    return section(6, vec(out))


write("19_extended_const_global.wasm", module(
    global_section([(I32, False, b"\x41\x01\x41\x02\x6A")]),  # i32.add (i32.const 1) (i32.const 2)
    export_section([("g", 3, 0)]),
))

# 20. GC in a constant expression: (global (ref 0) (struct.new 0))
write("20_gc_global_init.wasm", module(
    type_section(b"\x5F" + vec([])),  # (struct) empty
    global_section([(0x64, False, b"\xFB\x00\x00")]),  # (ref 0) = struct.new 0
    export_section([("g", 3, 0)]),
))

# 21. component model binary: magic + version 13 / layer 1 (not a core module)
write("21_component_model.wasm", b"\x00asm" + bytes([0x0D, 0x00, 0x01, 0x00]))
