# REPORT-STRUCTS: Call-graph-aware struct synthesis for WebAssembly

## Summary

Implemented `WasmStructSynthAnalyzer` — a wasm-specific, call-graph-aware struct
synthesis pass that recovers pointee types for linear-memory pointer parameters.
On the real module (`rasterbator_rs_bg.wasm`, 437 functions) it creates **352
structures** and retypes **255 parameters** to `PointerDataType(struct)` in
**~700-960 ms**. The 186-probe gate still passes (now 190 with 4 new probes),
the fixture and real-module SUMMARY lines are unchanged, and both
fixture-validity modes are updated.

## Design

Three phases, all deterministic and cheap:

1. **Collect accesses** — for each function, simulate the wasm operand stack
   linearly. Track abstract values: `Local(idx)`, `Const(v)`,
   `Add(Local, delta)`, `Global`, `Unknown`. For `i32.load`/`i32.store` (and
   i64/f32/f64/sub-word variants) whose base address resolves to a plain
   `local.get N` (or `local.get N; i32.const K; i32.add`), record
   `(funcIdx, localIdx, effectiveOffset, width)`. For `call F`, pop the callee's
   parameter count of arguments and record `(callerFunc, callerLocal) ->
   (calleeFunc, calleeParam)` links when the argument is a plain `local.get`.

2. **Pointer identity (call graph)** — union-find over `(funcIdx, localIdx)`
   nodes. Each direct-call link merges the caller's argument local with the
   callee's parameter. Deterministic iteration order (sorted roots).

3. **Synthesize** — for every union-find class with accesses at >= 2 distinct
   offsets (cap: 64 fields), create a `StructureDataType` named
   `wasm_struct_<n>` in the `/wasm` category with fields at the observed
   offsets/widths (gaps filled with `undefined1[n]`), then retype the member
   functions' **parameters** to `PointerDataType(struct)`. Never clobbers a
   non-undefined existing type.

## Coverage / limits (v1)

| Aspect | Behaviour |
|--------|-----------|
| Direct `call` | Followed; caller local linked to callee param |
| `call_indirect` | **Skipped** (documented) |
| Args with delta (`local.get N; i32.const K; i32.add`) | **Skipped** at call sites (delta not propagated through call graph) |
| Accesses via computed address (not plain local) | Skipped |
| Accesses via `global.get` | **Skipped** (documented — see ST03) |
| Only parameters retyped | Non-parameter locals left as-is (documented) |
| Max fields per struct | 64 (documented) |
| Stack simulation | Linear; clears on unrecognised instructions (conservative) |
| Sub-word loads/stores | Supported (i32.load8_u, i32.store16, etc.) |
| SIMD lane loads/stores | Skipped (v1) |
| Atomic loads/stores | Supported (treated as base-width access) |

## Files changed

| File | Change |
|------|--------|
| `src/main/java/wasm/analysis/WasmStructSynthAnalyzer.java` | **New** — the analyzer (auto-discovered by Ghidra, no explicit registration needed) |
| `test-scripts/DumpTypes.java` | **New** — evidence tool: prints created structures, fields, and retyped function prototypes |
| `test-scripts/DumpAll.java` | Added `decompileWithRetry` helper (same as `DumpDecomp.java`) |
| `test-scripts/probes_struct_synth.py` | **New** — 4 probes (ST01-ST04) |
| `test-scripts/expected-results.json` | Updated: +4 ST probe entries (190 total) |
| `test-scripts/fixture-validity.json` | Updated: +4 ST probe entries (190 total) |

## Probes

| Probe | Description | funcs | instrs | ub | dec | fail | Structs | Retyped |
|-------|-------------|-------|--------|----|-----|------|---------|---------|
| `ST01_call_chain_struct.wasm` | Pointer passed along 2-function call chain; fields at offsets 0,4,8 | 3 | 26 | 0 | 3 | 0 | 1 (`wasm_struct_0`, 12 bytes) | 3 params |
| `ST02_two_independent_structs.wasm` | Two independent pointers; no cross-talk | 3 | 22 | 0 | 3 | 0 | 2 (`wasm_struct_0` 8B, `wasm_struct_1` 12B) | 4 params |
| `ST03_global_address_no_struct.wasm` | Accesses via `global.get`; no struct (documented) | 1 | 7 | 0 | 1 | 0 | 0 | 0 |
| `ST04_const_offset_add.wasm` | `local.get N; i32.const K; i32.add; i32.load` pattern | 1 | 11 | 0 | 1 | 0 | 1 (`wasm_struct_0`, 12B, fields at 4,8) | 1 param |

All 4 probes are **valid** under both wabt 1.0.42 and binaryen 133.

### ST01 evidence (DumpTypes)

```
STRUCT wasm_struct_0 size=12
  FIELD 0 field_0 undefined4 (4 bytes)
  FIELD 4 field_4 undefined4 (4 bytes)
  FIELD 8 field_8 undefined4 (4 bytes)
STRUCT_COUNT 1
```

Prototypes (from listing):
- `void main(wasm_struct_0 * param1)`
- `int unnamed_function_1(wasm_struct_0 * param1)`
- `void unnamed_function_2(wasm_struct_0 * param1, undefined4 param2)`

### ST02 evidence (DumpTypes)

```
STRUCT wasm_struct_0 size=8
  FIELD 0 field_0 undefined4 (4 bytes)
  FIELD 4 field_4 undefined4 (4 bytes)
STRUCT wasm_struct_1 size=12
  FIELD 0 field_0 undefined4 (4 bytes)
  FIELD 4 pad_4 undefined1 (1 bytes)
  FIELD 8 field_8 undefined4 (4 bytes)
STRUCT_COUNT 2
```

Prototypes:
- `void main(wasm_struct_0 * param1, wasm_struct_1 * param2)`
- `int unnamed_function_1(wasm_struct_0 * param1)`
- `int unnamed_function_2(wasm_struct_1 * param1)`

### ST03 evidence

```
STRUCT_COUNT 0
RETYPED_COUNT 0
```
No struct synthesized — accesses go through `global.get 0`, not a local.

### ST04 evidence (DumpTypes)

```
STRUCT wasm_struct_0 size=12
  FIELD 0 pad_0 undefined1 (1 bytes)
  FIELD 4 field_4 undefined4 (4 bytes)
  FIELD 8 field_8 undefined4 (4 bytes)
STRUCT_COUNT 1
```

## Real module (`rasterbator_rs_bg.wasm`, 437 functions)

### Analyzer runtime

**685–962 ms** wall-clock (two runs; the variance is JVM warmup and system load).

### Struct synthesis results

- **352 structures** created (`wasm_struct_0` through `wasm_struct_351`)
- **255 parameters** retyped to `PointerDataType(struct)`

### Type-recovery metric (before → after)

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| Constant-offset field accesses | 591 | **437** | **-154 (-26%)** |
| Pointer-typed parameters | 0 | **255** | **+255** |
| Candidate structures (≥2 offsets) | ~16 | **11** | -5 |
| Candidate structures (≥3 offsets) | — | **8** | — |
| Distinct bases | — | 27 | — |
| Accesses by kind | param-heavy | parameter=329, local=95, other=13 | — |

Top bases after:
- `param1`: 139 accesses across 25 offsets (was 187 across 38)
- `param2`: 167 accesses across 11 offsets (was 232)
- `param5`: 8 accesses across 7 offsets
- `iVar3` (local): 25 accesses across 5 offsets
- `iVar6` (local): 18 accesses across 4 offsets

The remaining constant-offset accesses are predominantly through **locals**
(iVar*) which v1 does not retype — only parameters are retyped. This is the
documented coverage limit.

### Gate results

| Check | Result |
|-------|--------|
| 190-probe gate | **OK**: every probe matches the recorded baseline |
| Fixture (`wasm_fixture.wasm`) | `functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0` |
| Real module SUMMARY | `functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156` |
| Fixture-validity (wabt + binaryen) | 190 probes, all classified correctly |

## What was NOT done (documented limits)

1. **`call_indirect` not followed** — only direct `call` instructions link
   caller locals to callee parameters.
2. **Delta arguments skipped at call sites** — `local.get N; i32.const K; i32.add`
   as a call argument is not linked (the delta is not propagated through the
   call graph).
3. **Only parameters retyped** — non-parameter locals (declared wasm locals)
   are left as `undefined4/8`. The remaining 95 local-kind accesses in the
   metric come from these.
4. **Global-based accesses skipped** — `global.get N; i32.load` does not
   produce a struct (see ST03).
5. **SIMD lane loads/stores skipped** — `v128.load8_lane` etc. are not
   analysed for struct field accesses.
6. **Linear stack simulation** — the simulated operand stack is cleared on
   any unrecognised instruction (conservative: misses accesses but never
   produces wrong ones). Control-flow merges are not handled.
7. **No struct merging** — two classes with identical field layouts get
   separate structs (no deduplication).
8. **No field type inference** — all fields are `undefinedN` (no int/float/
   pointer distinction).
