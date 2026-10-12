#!/usr/bin/env python3
"""Structural validation of the multivalue probe modules.

Decodes each generated .wasm, checks function/code section consistency,
and simulates the operand stack (types only) to catch encoding bugs
before running Ghidra.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_probe_lib import uleb, I32, I64, F32, F64

OUT = sys.argv[1] if len(sys.argv) > 1 else "."

VT = {0x7F: "i32", 0x7E: "i64", 0x7D: "f32", 0x7C: "f64",
      0x70: "funcref", 0x6F: "externref"}


class Reader:
    def __init__(self, b, off=0):
        self.b, self.off = b, off

    def u8(self):
        v = self.b[self.off]
        self.off += 1
        return v

    def uleb(self):
        r, s = 0, 0
        while True:
            x = self.u8()
            r |= (x & 0x7F) << s
            if not (x & 0x80):
                return r
            s += 7

    def name(self):
        n = self.uleb()
        s = self.b[self.off:self.off + n].decode()
        self.off += n
        return s

    def bytes(self, n):
        s = self.b[self.off:self.off + n]
        self.off += n
        return s


def read_type(r):
    assert r.u8() == 0x60, "not a functype"
    ps = [VT[r.u8()] for _ in range(r.uleb())]
    rs = [VT[r.u8()] for _ in range(r.uleb())]
    return (ps, rs)


def check(fname):
    data = open(os.path.join(OUT, fname), "rb").read()
    assert data[:4] == b"\x00asm", "bad magic"
    r = Reader(data, 8)
    types, funcs, imports, exports = [], [], [], []
    code_bodies = None
    tables = []
    while r.off < len(data):
        sid = r.u8()
        size = r.uleb()
        end = r.off + size
        sr = Reader(data, r.off)
        if sid == 1:
            for _ in range(sr.uleb()):
                types.append(read_type(sr))
        elif sid == 2:
            for _ in range(sr.uleb()):
                sr.name(); sr.name()
                kind = sr.u8()
                if kind == 0:
                    imports.append(("func", sr.uleb()))
                else:
                    sr.uleb()  # skip limit flags
                    sr.uleb()
                    if kind in (1, 2):
                        pass
        elif sid == 3:
            for _ in range(sr.uleb()):
                funcs.append(sr.uleb())
        elif sid == 4:
            for _ in range(sr.uleb()):
                sr.u8()
                flags = sr.u8()
                sr.uleb()
                if flags & 1:
                    sr.uleb()
                tables.append("table")
        elif sid == 6:
            for _ in range(sr.uleb()):
                sr.u8()  # valtype (single-byte in these probes)
                sr.u8()  # mutability
                while sr.u8() != 0x0B:  # init expr until end
                    pass
        elif sid == 9:
            for _ in range(sr.uleb()):
                flags = sr.u8()
                if flags == 0 or flags == 4:  # active, table 0 / table idx
                    if flags == 4:
                        sr.uleb()
                    while sr.u8() != 0x0B:  # offset expr
                        pass
                    for _ in range(sr.uleb()):
                        sr.uleb()  # funcidx
                else:
                    raise AssertionError(f"unhandled elem flags {flags}")
        elif sid == 7:
            for _ in range(sr.uleb()):
                nm = sr.name()
                kind = sr.u8()
                idx = sr.uleb()
                exports.append((nm, kind, idx))
        elif sid == 10:
            code_bodies = []
            for _ in range(sr.uleb()):
                bsz = sr.uleb()
                code_bodies.append(sr.bytes(bsz))
        assert sr.off == end, f"section {sid} size mismatch"
        r.off = end

    n_defined = len(funcs)
    n_imported_funcs = sum(1 for k, _ in imports if k == "func")
    problems = []
    if code_bodies is not None and len(code_bodies) != n_defined:
        problems.append(f"func section declares {n_defined} functions but code section has {len(code_bodies)} bodies")

    # stack-simulate each defined function body
    for i, body in enumerate(code_bodies or []):
        br = Reader(body)
        nloc = br.uleb()
        for _ in range(nloc):
            br.uleb()
            br.u8()
        ftype = types[funcs[i]]
        stack = list(ftype[0])
        ret = ftype[1]
        # crude simulation: only tracks arity, not full control flow
        depth = 0
        while br.off < len(body):
            op = br.u8()
            if op in (0x02, 0x03, 0x04):  # block/loop/if: blocktype
                bt = br.u8()
                if bt not in (0x40, 0x7F, 0x7E, 0x7D, 0x7C, 0x70, 0x6F):
                    # s33 type index - rewind
                    br.off -= 1
                    br.uleb()  # consume (assume single byte for small indices)
            elif op == 0x10:  # call
                fi = br.uleb()
                if fi < n_imported_funcs:
                    sig = types[imports[fi][1]]
                else:
                    sig = types[funcs[fi - n_imported_funcs]]
                for _ in range(len(sig[0])):
                    if not stack:
                        problems.append(f"func {i}: call {fi} pops from empty stack")
                    else:
                        stack.pop()
                stack.extend(sig[1])
            elif op == 0x11:  # call_indirect
                ti = br.uleb()
                br.uleb()
                sig = types[ti]
                if stack:
                    stack.pop()  # table index
                for _ in range(len(sig[0])):
                    if not stack:
                        problems.append(f"func {i}: call_indirect pops from empty stack")
                    else:
                        stack.pop()
                stack.extend(sig[1])
            elif op == 0x12:  # return_call
                fi = br.uleb()
                if fi < n_imported_funcs:
                    sig = types[imports[fi][1]]
                else:
                    sig = types[funcs[fi - n_imported_funcs]]
                for _ in range(len(sig[0])):
                    if not stack:
                        problems.append(f"func {i}: return_call pops from empty stack")
                    else:
                        stack.pop()
                stack = list(sig[1])
            elif op == 0x0F:  # return
                for _ in range(len(ret)):
                    if not stack:
                        problems.append(f"func {i}: return pops from empty stack")
                    else:
                        stack.pop()
                stack = []
            elif op == 0x1A:  # drop
                if not stack:
                    problems.append(f"func {i}: drop on empty stack")
                else:
                    stack.pop()
            elif op == 0x20:  # local.get
                br.uleb()
                stack.append("?")
            elif op in (0x21, 0x22):  # local.set/tee
                br.uleb()
                if op == 0x21:
                    if not stack:
                        problems.append(f"func {i}: local.set pops from empty stack")
                    else:
                        stack.pop()
            elif op == 0x23:  # global.get
                br.uleb()
                stack.append("?")
            elif op == 0x24:  # global.set
                gi = br.uleb()
                if not stack:
                    problems.append(f"func {i}: global.set({gi}) pops from empty stack")
                else:
                    stack.pop()
            elif op in (0x41,):  # i32.const
                br.uleb()
                stack.append("i32")
            elif op in (0x42,):  # i64.const
                br.uleb()
                stack.append("i64")
            elif op in (0x43, 0x44):  # f32/f64.const
                br.bytes(4 if op == 0x43 else 8)
                stack.append("f32" if op == 0x43 else "f64")
            elif op in (0x6A, 0x6C):  # i32.add/mul
                for _ in range(2):
                    if not stack:
                        problems.append(f"func {i}: binop pops from empty stack")
                    else:
                        stack.pop()
                stack.append("i32")
            elif op == 0x0B:  # end
                pass
            elif op == 0x01:  # nop
                pass
            else:
                problems.append(f"func {i}: unhandled opcode 0x{op:02x} at {br.off}")
                break
        if stack and not ret:
            problems.append(f"func {i}: {len(stack)} values left on stack at end (expected none)")
        elif len(stack) != len(ret):
            problems.append(f"func {i}: {len(stack)} values at end, type declares {len(ret)} results")

    status = "OK" if not problems else "FAIL"
    print(f"{fname}: {status}")
    for p in problems:
        print(f"    - {p}")
    return not problems


ok = True
for f in sorted(os.listdir(OUT)):
    if f.startswith("M") and f.endswith(".wasm"):
        ok &= check(f)
sys.exit(0 if ok else 1)
