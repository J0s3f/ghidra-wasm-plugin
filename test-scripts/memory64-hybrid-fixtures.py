#!/usr/bin/env python3
"""Generate auxiliary hybrid constructor/emulation checks (outside the 222-probe gate).
Usage: python test-scripts/memory64-hybrid-fixtures.py <private scratch directory>
"""
import sys
from pathlib import Path
from wasm_probe_lib import *

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)

def arg(align, index, offset=0):
    return uleb(align | 0x40) + uleb(index) + uleb(offset)

bodies, exports = [], []
def add(name, code):
    exports.append((name, 0, len(bodies)))
    bodies.append(code + END)

for index in (0, 1):
    prefix = "m64_" if index else "m32_"
    address = i64_const(0x100000020) if index else i32_const(0x20)
    for op in range(0x28, 0x3f):
        code = address
        if op >= 0x36:
            code += ({0x37: i64_const(7), 0x38: f32_const(7), 0x39: f64_const(7),
                      0x3c: i64_const(7), 0x3d: i64_const(7), 0x3e: i64_const(7)}
                     .get(op, i32_const(7)))
        code += bytes([op]) + arg(0, index, 0x10)
        if op < 0x36:
            code += drop()
        add(prefix + "scalar_" + str(op), code)
    for op in list(range(12)) + list(range(84, 94)):
        code = address
        if op == 11 or 84 <= op <= 91:
            code += v128_const(bytes(16))
        code += simd_op(op) + arg(0, index, 0x10)
        if 84 <= op <= 91:
            code += b"\x00"  # lane 0
        if op != 11 and not 88 <= op <= 91:
            code += drop()
        add(prefix + "simd_" + str(op), code)
    for op in [0, 1, 2] + list(range(16, 79)):
        code = address
        if op <= 2:
            code += i32_const(0) if op != 2 else i64_const(0)
            if op != 0:
                code += i64_const(0)
            align = 3 if op == 2 else 2
        else:
            shape = ((op - 16) % 7 if op <= 29 else
                     (op - 30) % 7 if op <= 71 else op - 72)
            wide = shape in (1, 4, 5, 6)
            width = [4, 8, 1, 2, 1, 2, 4][shape]
            align = width.bit_length() - 1
            value = i64_const(7) if wide else i32_const(7)
            if op >= 23:
                code += value
            if op >= 72:
                code += value
        code += b"\xfe" + uleb(op) + arg(align, index, 0x10)
        if not 23 <= op <= 29:
            code += drop()
        add(prefix + "atomic_" + str(op), code)
    for op in (128,129,139,140,134,135,141,142,146,148,149,155):
        string = b"\xfb" + uleb(130) + uleb(0)
        if op in (128,129,139,140):
            code = address + i32_const(1)
        elif op in (134,135,141,142):
            code = string + address
        else:
            code = string + address + i32_const(0) + i32_const(1)
        code += b"\xfb" + uleb(op) + uleb(index) + drop()
        if op in (146,148,149):
            code += drop()
        add(prefix + "string_" + str(op), code)

(out / "hybrid_matrix.wasm").write_bytes(module(
    type_section(functype([], [])), func_section([0] * len(bodies)),
    memory_section([(3,1,1), (7,1,1)]), export_section(exports), code_section(bodies)))

bodies, exports = [], []
def load(address, offset=0, index=0):
    return address + b"\x28" + arg(2, index, offset)
add("high_dynamic", load(i64_const(0x100000020), 0x10))
add("high_static", load(i64_const(0), 0x100000010))
add("high_store", i64_const(0x100000020) + i32_const(0x12345678) + b"\x36" +
    arg(2, 0, 0x10) + load(i64_const(0x100000020), 0x10))
add("low64", load(i64_const(0)))
add("low32", load(i32_const(0), index=1))
add("oob64", load(i64_const(70000 * 65536)))
add("overflow64", load(i64_const(-1), 1))
add("overflow32", load(i32_const(-1), 1, 1))
add("high_signbit", load(i64_const(-(1 << 63))))
(out / "hybrid_emulation.wasm").write_bytes(module(
    type_section(functype([], [I32])), func_section([0] * len(bodies)),
    memory_section([(4,70000), (0,1)]), export_section(exports), code_section(bodies),
    data_section([active_data(i64_const(0) + END, bytes.fromhex("44332211")),
                  active_data(i32_const(0) + END, bytes.fromhex("88776655"), 1)])))
print("hybrid fixtures: 246 constructor functions + 9 emulation functions")

# Regression: numeric/relaxed opcodes sharing the low LEB byte with memory ops.
# Use the original constructor stack-shape comments to form valid typed operands.
import re
prefix_bodies, prefix_exports = [], []
for filename in ("VectorOps.sinc", "RelaxedSimdOps.sinc"):
    text = (Path(__file__).resolve().parent.parent / "data/languages" / filename).read_text(encoding="utf-8")
    pattern = r"(?m)^# \[([^\]]*)\] -> \[([^\]]*)\]\n:([^ \n]+)[^\n]*opc2_(\d+);"
    shapes = re.findall(pattern, text)
    if filename == "RelaxedSimdOps.sinc":
        shapes = []
        for mnemonic, number, header in re.findall(r"(?m)^:([^ \n]+)[^\n]*opc2_(\d+);([^\n]+)", text):
            arity = max(int(n) for n in re.findall(r"sp(\d+)_128", header))
            shapes.append((" ".join(["v128"] * arity), "v128", mnemonic, number))
    for inputs, outputs, mnemonic, number in shapes:
        number = int(number)
        if filename == "VectorOps.sinc" and not (128 <= number <= 139 or 212 <= number <= 221):
            continue
        operands = {"v128": v128_const(bytes(16)), "i32": i32_const(0)}
        code = b"".join(operands[t] for t in inputs.split()) + simd_op(number)
        code += drop() * len(outputs.split()) + END
        prefix_exports.append(("prefix_" + mnemonic.replace(".", "_", 1), 0, len(prefix_bodies)))
        prefix_bodies.append(code)
(out / "hybrid_simd_prefixes.wasm").write_bytes(module(
    type_section(functype([], [])), func_section([0] * len(prefix_bodies)),
    export_section(prefix_exports), code_section(prefix_bodies)))
print("SIMD shared-prefix regression functions:", len(prefix_bodies))
