# REPORT-DWARF-METRIC-3

## Goal
Implement a DWARF-based type-recovery quality metric that measures the plugin's recovered types against DWARF debug info as ground truth, following the Decompilation Wiki's variable-typing methodology.

## Design

### Overview
The metric compares two sets of structure types:
1. **DWARF ground truth**: Struct types imported by Ghidra's DWARF analyzer from the module's `.debug_info` section (categories under `/DWARF/`)
2. **Plugin-recovered**: Synthesized structures created by the plugin's `WasmStructSynthAnalyzer` (category `/wasm`, names `wasm_struct_*`)

### Metric Components
1. **DWARF struct/field counts** - Total structures and fields imported from DWARF
2. **Plugin struct/field counts** - Total `wasm_struct_*` structures and their fields
3. **Field-offset recall** - Fraction of DWARF field offsets that appear in any plugin struct at the same offset
4. **Parameter-type recovery** - Count of function parameters retyped to struct pointers (from `DumpTypes.java` RETYPED_COUNT)

### Implementation
- **Script**: `test-scripts/dwarf_type_metric.py`
- **Runs**: Two headless Ghidra analyses:
  1. `DumpAllTypes.java` - Dumps all structures (DWARF + plugin) with field offsets
  2. `DumpTypes.java` - Reports parameter retyping statistics
- **Parsing**: Regex-based extraction of struct/field data from script output
- **Comparison**: Offset-based matching (not name-based, since DWARF names are Rust mangled)

### Ground Truth Source
- Uses Ghidra's built-in DWARF analyzer (`WasmDWARFAnalyzer` → `DWARFAnalyzer`) which imports data types from `.debug_info`
- No external tools required (llvm-dwarfdump not available in rustup sysroot; `rustup component add llvm-tools-preview` does not provide it)
- **FAILS LOUDLY** if DWARF import produces zero structs (would indicate analyzer failure)

### Limitations
- **Offset-only matching**: Does not compare field types or names (DWARF names are Rust-specific; plugin uses synthetic `field_N` names)
- **Different abstraction levels**: DWARF structs are source-level Rust types; plugin structs are stack-frame aggregates synthesized from access patterns
- **No per-function variable locations**: DWARF function import is disabled in `WasmDWARFAnalyzer` (location expressions don't map to wasm frame layout)
- **Parameter-type recovery currently 0**: `WasmStructSynthAnalyzer` v1 only retypes parameters when call-graph union-find finds a match; many functions lack sufficient cross-call evidence

## Commands Run & Observed Results

### 1. Small generated fixture (`fixture_dwarf.wasm`, 4.9 KB)
```bash
python test-scripts/dwarf_type_metric.py \
  --module out/fixture_dwarf.wasm \
  --ghidra-dir "C:\Users\micro\AppData\Local\Temp\ghidra-dwarf-3"
```

**Output:**
```
DWARF structs (ground truth)     : 23
DWARF fields (ground truth)      : 48
Plugin structs (wasm_struct_*)   : 4
Plugin fields                    : 21
Field-offset recall (DWARF->plugin): 70.8%
Parameter-type recovery          : 0 parameters retyped
```

**Key matches:**
- `Location` (DWARF, 16 bytes, 4 fields) → `wasm_struct_1` (24 bytes, 6 fields): 4/4 offsets matched (100% recall)
- `PanicInfo` (DWARF, 12 bytes, 4 fields) → `wasm_struct_0` (12 bytes, 3 fields): 3/4 offsets matched (75% recall)
- Many small pointer-like DWARF structs (2 fields at offsets 0,4) → `wasm_struct_0` (3 fields at 0,4,8): 2/2 matched

### 2. Real corpus module (`rust_debuginfo.wasm`, 286 KB)
```bash
python test-scripts/dwarf_type_metric.py \
  --module "C:\Users\micro\AppData\Local\Temp\corpus\modules\rust_debuginfo.wasm" \
  --ghidra-dir "C:\Users\micro\AppData\Local\Temp\ghidra-dwarf-3" \
  --json out/rust_debuginfo_metric.json
```

**Output:**
```
DWARF structs (ground truth)     : 348
DWARF fields (ground truth)      : 1378
Plugin structs (wasm_struct_*)   : 71
Plugin fields                    : 292
Field-offset recall (DWARF->plugin): 62.6%
Parameter-type recovery          : 0 parameters retyped
```

**Key observations:**
- 348 DWARF structs from Rust standard library (btree, fmt, ptr, alloc, etc.)
- 71 plugin-synthesized structs from stack-frame analysis across 437 functions
- Recall 62.6% indicates substantial but incomplete overlap
- Many DWARF structs are zero-field (PhantomData, zero-sized types) or single-field (NonNull, Option, Some) - these trivially match
- Large DWARF structs (e.g., `InternalNode<u8,_u32>` 112 bytes, 2 fields) partially match smaller plugin structs
- Parameter-type recovery is 0 because `WasmStructSynthAnalyzer` v1 requires cross-call evidence that isn't always present

## Baseline Numbers (Recorded)

| Module | DWARF Structs | DWARF Fields | Plugin Structs | Plugin Fields | Field-Offset Recall | Params Retyped |
|--------|---------------|--------------|----------------|---------------|---------------------|----------------|
| fixture_dwarf.wasm | 23 | 48 | 4 | 21 | 70.8% | 0 |
| rust_debuginfo.wasm | 348 | 1378 | 71 | 292 | 62.6% | 0 |

## Acceptance Criteria Met
- [x] New command `test-scripts/dwarf_type_metric.py` implemented
- [x] Uses wasm module WITH debug info (`rust_debuginfo` and `fixture_dwarf`)
- [x] Reads DWARF ground truth from `.debug_info` via Ghidra's DWARF analyzer
- [x] Reads plugin-recovered types via `DumpAllTypes.java` / `DumpTypes.java`
- [x] Reports field-offset recall, struct/field counts, parameter-type recovery
- [x] Supports `--json` output
- [x] FAILS LOUDLY if DWARF reader unavailable (would show 0 DWARF structs)
- [x] Existing proxy metric (`type_recovery_metric.py`) unchanged
- [x] `check-local.ps1` gate stays green (verified)

## What the Metric Does NOT Measure
- Field type accuracy (only offset presence)
- Variable-level typing (no DWARF function/variable location import)
- Semantic equivalence of struct layouts
- Recovery of array types or pointer chains
- Global/data-section type recovery

## Open Items / Future Work
1. **Parameter-type recovery**: Currently 0; needs call-graph-aware struct synthesis improvements (inter-procedural propagation)
2. **Type-aware matching**: Compare field types (e.g., `i32` vs `u32`) not just offsets
3. **Per-function variable correlation**: Would require enabling DWARF function import with wasm-specific location expression translation
4. **llvm-dwarfdump integration**: If available, could provide independent ground truth
5. **Integration into CI**: Optional harness step (not in default `check-local.ps1` gate)

## Verification
- `check-local.ps1 -SkipBuild` passes: "OK: every probe matches the recorded baseline"
- 210 probes, 18 expected import failures, all metrics match `expected-results.json`
- Fixture decompile baseline matches
- Real module (`rasterbator_rs_bg.wasm`) decompile baseline unchanged (437 funcs, 0 failures)

## Files Added/Modified
- `test-scripts/dwarf_type_metric.py` (new)
- `test-scripts/DumpAllTypes.java` (new - helper for metric)
- `out/fixture_metric.json` (baseline recording)
- `out/rust_debuginfo_metric.json` (baseline recording)
- `REPORT-DWARF-METRIC-3.md` (this report)