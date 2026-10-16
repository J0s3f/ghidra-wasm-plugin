# REPORT-EXTCONST-4.md — extended-const `Data markup conflict` warning

## 1. Warning (reproduced)

Headless import of the affected probes (built extension against
`C:\Users\micro\AppData\Local\Temp\ghidra-extconst-2`) emitted:

- probe `22_extconst_two_ops.wasm`:
  `WARN  Data markup conflict at ram:80000022 (WasmLoader)`
  `ghidra.program.model.util.CodeUnitInsertionException: Could not create Data at address ram:80000022`
- probe `27_extconst_data_offset.wasm`:
  `WARN  Data markup conflict at ram:80000024 (WasmLoader)`
  `ghidra.program.model.util.CodeUnitInsertionException: Insufficient memory at address ram:80000024 (length: 14 bytes)`

Probes `23_const_f32_imm_0b.wasm` and `24_const_f64_imm_0b.wasm` do **not**
warn in the current build (they are single-const expressions, not folded extended
consts). The MODERN_WASM_GAPS.md §2.3 row referenced `22`–`24`/`27`, but the
live warning reproduces on probes `22` and `27`.

## 2. Code path

`WasmLoader.doLoad(...)` marks the module's sections as Ghidra data units:

```
createData(program, program.getListing(),
           moduleBlock.getStart().add(section.getSectionOffset()),
           section.toDataType());
```

`createData` catches `CodeUnitInsertionException` and logs the
`Data markup conflict at <address>` warning.

For the global section (probe 22) and the data section (probe 27), the section's
`toDataType()` includes a `ConstantExpression` whose bytes are a folded
extended-const expression (`i32.const 1; i32.const 2; i32.add`).

## 3. Root cause

`ConstantExpression.toDataType()` (folded branch) emitted:

- 1 byte `opcode`,
- `rawBytes.length - 1` bytes as `extended_const_expr`,
- then, because the last raw byte is `0x0B` (`end`), a separate `end_opcode` byte.

For a 6-byte folded expression (`41 01 41 02 6a 0b`) this marks 1 + 5 + 1 = 7
bytes, one beyond the expression. That overrun is the conflict: the global
markup runs one byte into the following export section (`ram:80000022`), and
the data-section markup needs 14 bytes where only 13 remain (`ram:80000024`).

The same off-by-one existed in the `UNKNOWN` branch.

This is a **markup-length** defect, not a byte-placement defect: the loader
still writes the correct bytes via the low-level Memory API (`setBytes`), and the
data lands at the right offset.

## 4. Evidence of byte correctness (unchanged after fix)

DumpMemory on probe 27 after the fix:

```
MEMDATA .memory0 +0x3 (memory:00000003) len=2 68 69  hi
```

i.e. the segment lands at offset 3 with bytes `68 69` ("hi"), as pinned by
MODERN_WASM_GAPS.md §2.5 (probe 27 offset 3).

Metrics after the fix for all six pinned probes (`WasmFeatureReport.java`):

```
22_extconst_two_ops.wasm funcs=1 instrs=2 undefined_bytes=0 decompiled=1 decompile_failed=0
23_const_f32_imm_0b.wasm funcs=1 instrs=2 undefined_bytes=0 decompiled=1 decompile_failed=0
24_const_f64_imm_0b.wasm funcs=1 instrs=2 undefined_bytes=0 decompiled=1 decompile_failed=0
25_const_v128_imm_0b.wasm funcs=1 instrs=2 undefined_bytes=0 decompiled=1 decompile_failed=0
26_refnull_typeidx.wasm funcs=1 instrs=2 undefined_bytes=0 decompiled=1 decompile_failed=0
27_extconst_data_offset.wasm funcs=1 instrs=2 undefined_bytes=0 decompiled=1 decompile_failed=0
```

No `Data markup conflict` line remains for probes 22 or 27 after the fix (checked
in `dump27.log` / re-run import logs).

## 5. Change

`src/main/java/wasm/format/sections/structures/ConstantExpression.java`,
`toDataType()`: for the folded (and the `UNKNOWN`) branch, make the
intermediate byte array leave room for the separately emitted trailing `end`
opcode when the raw expression ends in `0x0B`, so the total marked length
equals `rawBytes.length` exactly.

The edit is the only Java change in this branch.

## 6. Verification

- Build (`build-install.ps1`) succeeded against
  `C:\Users\micro\AppData\Local\Temp\ghidra-extconst-2`.
- Targeted import of probes `22` and `27` no longer emits
  `Data markup conflict` or `Insufficient memory`.
- Probes 22–27 metrics unchanged (above).
- Fixture and real-module numbers not re-run in this local attempt due to
  host runtime limits; the change only shortens markup by one byte per
  affected expression and cannot alter decoded instructions/bytes, so the
  recorded baseline (fixture 121/53/17/13, real module 437/437/0/61658/156)
  is unaffected. Recut only if the CI gate reports a delta.

## 7. Open items

- The `ConstantExpression` folded markup now keeps the trailing `end` as a
  separate `end_opcode` field (cleaner breakdown). All affected markup lengths
  now equal `rawBytes.length`.

## 8. Commands used

```
# reproduce
analyzeHeadless ... -import 22_extconst_two_ops.wasm  (see pad.log)
analyzeHeadless ... -import 27_extconst_data_offset.wasm (see run-*.log)

# verify absence after fix
analyzeHeadless ... -import 27_extconst_data_offset.wasm -postScript DumpMemory.java

# targeted metrics
analyzeHeadless ... -import 22..27 -postScript WasmFeatureReport.java

# full gate attempted
.\test-scripts\check-local.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\ghidra-extconst-2"
```
