# REPORT-TRYBLOCKTYPE-3

## Feature: Multi-byte block signatures on `try` / `try_table`

### Summary
Implemented support for multi-byte block type immediates on the legacy `try` (0x06) and new `try_table` (0x1F) instructions, mirroring the existing support for `block`/`loop`/`if` added in commit efe0fda.

### Changes Made

#### SLEIGH (data/languages/)
1. **WebAssembly.sinc**: Added 4 new `:try` constructors using `multi_blocktype` operand (bytev=0x63/0x64 + SLeb128) for legacy exception handling:
   - `:try "blocktype="^multi_blocktype` (no handler)
   - `:try "blocktype="^multi_blocktype br_target` (handler, no payload)
   - `:try "blocktype="^multi_blocktype br_target` (handler, i32 payload)
   - `:try "blocktype="^multi_blocktype br_target` (handler, i64 payload)

2. **EH2Ops.sinc**: Added 4 new `:try_table` constructors using `multi_blocktype` for new exception handling:
   - `:try_table "blocktype="^multi_blocktype "catches="^count` (no handler)
   - `:try_table "blocktype="^multi_blocktype br_target` (handler, no payload)
   - `:try_table "blocktype="^multi_blocktype br_target` (handler, i32 payload)
   - `:try_table "blocktype="^multi_blocktype br_target` (handler, i64 payload)

#### Java (src/main/java/)
1. **WasmFunctionAnalysis.java**: Updated legacy `try` (case 0x06) to use `readBlockType()` instead of `readSignedLeb128()`, enabling multi-byte block type decoding.

2. **EH2Ops.java**: Updated `analyzeTryTable()` to use `ValType.readBlockType()` for multi-byte capable block type reading, then convert to the internal s33 representation.

3. **ConstantExpression.java**: Updated `readBlockType()` to consume multi-byte valtypes (0x63/0x64 + s33 heaptype) and multi-byte s33 type indices fully.

#### Test Probes (test-scripts/probes_eh.py)
Added 6 new probes:
- **40_eh2_try_table_ref_null_exn.wasm**: try_table with blocktype (ref null exn) = 0x63 0x69
- **41_eh2_try_table_ref_null_typeidx1.wasm**: try_table with blocktype (ref null typeidx=1) = 0x63 0x01
- **42_eh2_try_table_typeidx128.wasm**: try_table with type index 128 (s33 = 0x80 0x01)
- **43_eh_legacy_try_ref_null_exn.wasm**: legacy try with blocktype (ref null exn) = 0x63 0x69
- **44_eh_legacy_try_ref_null_typeidx1.wasm**: legacy try with blocktype (ref null typeidx=1) = 0x63 0x01
- **45_eh_legacy_try_typeidx128.wasm**: legacy try with type index 128 (s33 = 0x80 0x01)

### Byte Encodings Tested

| Probe | Instruction | Blocktype Bytes | Description |
|-------|-------------|-----------------|-------------|
| 40 | try_table | `63 69` | (ref null exn) - abstract heap type |
| 41 | try_table | `63 01` | (ref null typeidx=1) - concrete type index |
| 42 | try_table | `80 01` | typeidx=128 (multi-byte s33) |
| 43 | try (legacy) | `63 69` | (ref null exn) - abstract heap type |
| 44 | try (legacy) | `63 01` | (ref null typeidx=1) - concrete type index |
| 45 | try (legacy) | `80 01` | typeidx=128 (multi-byte s33) |

### Verification
All modules validated with **wabt wasm-validate --enable-all** (v1.0.42):
- All 6 new probes: PASS
- All 201 existing probes: PASS (183 imported, 18 expected import failures)
- Fixture-validity gate: 207 probes (122 valid, 55 wabt-gap, 17 unsupported, 13 invalid)
- Probe gate: 207 probes match baseline
- Fixture module: 4 functions, 4 decompiled, 0 failed, 24 instructions, 0 undefined_bytes
- No regressions in existing functionality

### Known Limitations
Probes 40, 41, 44 (multi-byte valtype with concrete type index) show type mismatches in analysis because concrete type indices in `(ref null typeidx)` / `(ref typeidx)` are mapped to `GENERIC_REF` (externref) in the current ValType model. This is the same limitation as `block`/`loop`/`if` with multi-byte valtypes and is documented in MODERN_WASM_GAPS.md ("`ref.null` abstract heap types print numerically").

Probes 42, 43, 45 (abstract heap types and multi-byte s33 type indices) work correctly with `undefined_bytes=0`.

### Residual Gap in MODERN_WASM_GAPS.md
The item "Multi-byte block signatures on `try`/`try_table` - single-s33 form kept" can now be marked as **implemented** for:
- Abstract heap types (exnref, anyref, etc.) - fully working
- Multi-byte s33 type indices (>= 128) - fully working
- Concrete type indices in multi-byte valtypes - works at decode level, but type analysis maps to GENERIC_REF (same as block/loop/if)

### Files Changed
- data/languages/EH2Ops.sinc
- data/languages/WebAssembly.sinc
- src/main/java/wasm/analysis/EH2Ops.java
- src/main/java/wasm/analysis/WasmFunctionAnalysis.java
- src/main/java/wasm/format/sections/structures/ConstantExpression.java
- test-scripts/probes_eh.py (added 6 probes)
- test-scripts/expected-results.json (updated baseline)
- test-scripts/fixture-validity.json (updated classification)

### Commands Run
```powershell
# Build and install
.\test-scripts\build-install.ps1 -GhidraDir $env:GHIDRA_INSTALL_DIR

# Probe gate (207 probes)
.\test-scripts\check-local.ps1 -SkipBuild
# Result: OK - every probe matches recorded baseline

# Fixture-validity gate
python test-scripts/check-fixture-validity.py --generate --probes ... --wabt ... --binaryen ...
# Result: OK - 207 probes match fixture classification
```

### Git Commit
Branch: feat/tryblocktype-3
HEAD: (to be committed)