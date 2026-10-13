# Dedicated `memory` Address Space for Linear Memories

## Design

### Problem
Linear memory N was placed at `N * MEMORY_STRIDE` in the 32-bit `ram` space, which
also holds the module image at `CODE_BASE = 0x80000000`. Memory 8 landed exactly on
the code base and could not be created (the loader logged the failure). The 32-bit
space could not hold many memories at 256 MiB stride.

### Fix
Add a dedicated 32-bit `memory` address space to `WebAssembly.slaspec`:

```
define space memory  type=ram_space  size=4;
```

The SLEIGH memory accesses target `*[memory]:N addr` instead of `*:N addr`.
With `MEMORY_STRIDE = 0x08000000` (128 MiB), memory indices 0..31 fit in the
32-bit space (memory 31 = 0xF8000000), so memory index >= 8 no longer
collides with the module image in `ram` at `CODE_BASE = 0x80000000`.

All 32-bit memory address arithmetic stays in 32 bits (`addr:4`), so the
decompiled C has no ZEXT noise. memory64 addresses are computed in 64 bits
and truncated to 32 bits (same as the pre-`memory`-space behaviour).

The Java loader creates memory blocks in the `memory` space via
`getMemoryAddress()`, which uses `getAddressSpace("memory")`.

## Files Changed

### SLEIGH / SLASPEC
- **`data/languages/WebAssembly.slaspec`** (line 28): Added `define space memory type=ram_space size=4;`
  (32-bit space; see Regression/Fix above for why not 64-bit).
- **`data/languages/WebAssembly.sinc`** (line 33-40): Updated `@@MM` comment to describe
  the `memory` space (32-bit, no collision with `ram` at CODE_BASE; 128 MiB stride).
  `MEMORY_STRIDE` = `0x08000000`.
- **`data/languages/BasicOps.sinc`**:
  - `loadaddr`/`storeaddr` constructors: `addr:4` for 32-bit memories (32-bit
    arithmetic, no `zext`); `addr:4 = full:4` (truncate) for memory64.
  - All load/store instructions: `*:N addr` → `*[memory]:N addr`.
- **`data/languages/VectorOps.sinc`**:
  - `loadaddr2` constructor: same 32-bit address change.
  - All SIMD load/store instructions: `*:N addr` → `*[memory]:N addr`.
- **`data/languages/AtomicOps.sinc`**:
  - `atomicaddr3` constructor: same 32-bit address change.
  - All atomic load/store/RMW/cmpxchg instructions: `*:N addr` → `*[memory]:N addr`.

### Java
- **`src/main/java/wasm/WasmLoader.java`**:
  - `getMemoryAddress()`: uses `getAddressSpace("memory")` instead of `"ram"`.
  - `MEMORY_STRIDE` = `0x08000000L` (128 MiB, fits 32 memories in 32 bits).
  - `MEMORY_MAX_ADDRESS` = `0xffffffffL` (32-bit space).
  - `createMemoryBlock()`: memory64 comment updated (SLEIGH truncates to 32 bits).
  - `loadMemories()`: comments updated for the 32-bit `memory` space.
- **`src/main/java/ghidra/program/emulation/WasmEmulateInstructionStateModifier.java`**:
  - `checkMemoryBounds()`: `getAddressSpace("ram")` → `getAddressSpace("memory")`.
  - `checkAddressInMemory()`: zeroing uses `"memory"` space.
  - `checkMemoryBounds64()`: zeroing uses `"memory"` space.
  - `reverseComputeLoadBase()`: `getAddressSpace("ram")` → `getAddressSpace("memory")`.
- **`src/main/java/wasm/pcode/PcodeOpEmitter.java`**:
  - `emitUnrolledCopy()`: uses `getAddressSpace("memory")` instead of default (`ram`).
- **`src/main/java/wasm/analysis/WasmAnalysis.java`**: Comment updated.
- **`src/main/java/wasm/analysis/WasmPreAnalyzer.java`**: Comment updated.

### Tests
- **`test-scripts/probes_memspace.py`** (new): Three probes:
  - `MS_01_mem9_load_store.wasm`: 10 memories, read/write memory 9 + memory 0.
    Metrics: `funcs=1 instrs=10 undefined_bytes=0 decompiled=1 decompile_failed=0`.
  - `MS_02_mem16_load.wasm`: 17 memories, read memory 16.
    Metrics: `funcs=1 instrs=4 undefined_bytes=0 decompiled=1 decompile_failed=0`.
  - `MS_03_mem9_data_segment.wasm`: 10 memories, data segments into memory 9 and 0.
    Metrics: `funcs=1 instrs=4 undefined_bytes=0 decompiled=1 decompile_failed=0`.
- **`test-scripts/expected-results.json`**: Updated baseline (201 probes, +3 MS probes).
- **`test-scripts/fixture-validity.json`**: Updated manifest (201 probes).

## Before/After Evidence

### Memory blocks
Before: memory blocks were in `ram` space. Memory 8+ could not be created (collision
with CODE_BASE at 0x80000000 in `ram`).

After: memory blocks are in `memory` space. MS_01 creates `.memory0` (65536 bytes)
and `.memory9` (65536 bytes). MS_02 creates `.memory0` and `.memory16`. MS_03
creates `.memory0` and `.memory9` with data segments placed correctly.

### Probe gate
```
== running 201 probe(s) ==
probes: 183 imported, 18 import failure(s); baseline has 201
OK: every probe matches the recorded baseline.
```

### Fixture (wasm_fixture.wasm)
```
SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0
```
(Unchanged from baseline.)

### Real module (rasterbator_rs_bg.wasm)
```
SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156
```
(Unchanged from baseline.)

### Fixture validity
```
probes: 201  valid: 118  wabt-gap: 53  unsupported: 17  invalid: 13
OK: every probe matches the recorded fixture classification.
```

### Memory probe metrics (all `undefined_bytes=0`)
| Probe | funcs | instrs | ub | decomp | fail |
|-------|-------|--------|----|--------|------|
| 05_memory64 | 1 | 4 | 0 | 1 | 0 |
| 06_multi_memory | 1 | 6 | 0 | 1 | 0 |
| 18_shared_then_plain_memory | 1 | 3 | 0 | 1 | 0 |
| M64_01–M64_08 | 1 | 4–28 | 0 | 1 | 0 |
| A01–A04 | 1 | 7–25 | 0 | 1 | 0 |
| B01–B06 | 1 | 2–4 | 0 | 1 | 0 |
| B3_01–B3_04 (memidx 9/127/128/1000) | 1 | 4–8 | 0 | 1 | 0 |
| B8_01–B8_05 (table64 / >4 GiB) | 1 | 3–4 | 0 | 1 | 0 |
| MS_01 (mem9 load/store) | 1 | 10 | 0 | 1 | 0 |
| MS_02 (mem16 load) | 1 | 4 | 0 | 1 | 0 |
| MS_03 (mem9 data segment) | 1 | 4 | 0 | 1 | 0 |

## Regression (post-change, measured by the integrator)

The first version of this change widened every exported address to 64 bits
(`addr:8` with explicit `zext` for 32-bit memories) because the `memory`
space was 64-bit (`size=8`). SLEIGH requires the pointer size to match
the space size, so this was the only way to make `*[memory]:N` compile.

Consequence in the real module's decompiled C (`DumpAll` of
`rasterbator_rs_bg.wasm`):
- `ZEXT`/`zext` lines in the C: **7 before the change → 570 after**;
- variable types degraded: `bool`, `int`, `char *`, `uint *` became
  `undefined4`/`undefined8`;
- instruction counts, decompile success and undefined_bytes are unchanged
  (which is why the gates stayed green — but the C is materially worse).

## Fix: 32-bit `memory` space + 128 MiB stride

The `memory` space does not need to be 64-bit for the common cases:
- 32-bit memories (the overwhelmingly common case) fit in 32 bits;
- with `MEMORY_STRIDE = 0x08000000` (128 MiB), memory indices 0..31 fit
  in 32 bits (memory 31 = 0xF8000000), so >= 8 memory support is preserved
  (MS_02: 17 memories / mem16 works);
- memory64 addresses above 4 GiB wrap — the same modelling choice as the
  pre-`memory`-space behaviour (see REPORT-N.md).

Changes:
- `WebAssembly.slaspec`: `memory` space `size=8` → `size=4` (32-bit).
- `WebAssembly.sinc`: `MEMORY_STRIDE` `0x10000000` → `0x08000000`.
- `BasicOps.sinc` / `VectorOps.sinc` / `AtomicOps.sinc`: address
  constructors use `addr:4` (32-bit arithmetic, no `zext`) for 32-bit
  memories; memory64 truncates (`addr:4 = full:4`).
- `WasmLoader.java`: `MEMORY_STRIDE` `0x10000000L` → `0x08000000L`;
  `MEMORY_MAX_ADDRESS` `Long.MAX_VALUE` → `0xffffffffL`.

### Before/After ZEXT counts (real module `rasterbator_rs_bg.wasm`)

| Script | Pre-change | Broken (64-bit space) | After fix |
|--------|-----------|----------------------|-----------|
| DumpAll (all 437 funcs) | 56 | 570 | **47** |
| DumpDecomp (biggest 3 funcs) | 7 | — | **3** (all 437 funcs) |

Variable types restored: `bool`, `int`, `char *`, `uint *` are back
(were `undefined4`/`undefined8` in the broken version).

### Gate results (after fix)

- 201-probe gate: **OK** (183 imported, 18 import failures; baseline 201)
- Fixture: `functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0` ✓
- Real module: `functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156` ✓
- Fixture validity: `probes: 201 valid: 118 wabt-gap: 53 unsupported: 17 invalid: 13` ✓
- Spec-suite core decode: 271 modules, 2747 functions, 33222 instructions, 428 undefined_bytes, 0 decompile_failed ✓
- MS_01 (10 memories/mem9): `funcs=1 instrs=10 ub=0 decomp=1 fail=0` ✓
- MS_02 (17 memories/mem16): `funcs=1 instrs=4 ub=0 decomp=1 fail=0` ✓
- MS_03 (mem9 data segment): `funcs=1 instrs=4 ub=0 decomp=1 fail=0` ✓

### What remains 64-bit (with reason)

- **memory64 address computation**: the SLEIGH computes memory64 effective
  addresses in 64 bits (`memoffset:8 + sp1_64`) and truncates to 32 bits
  (`addr:4 = full:4`). This is the same modelling choice as the pre-change
  `ram`-space behaviour. Only memory64 accesses above 4 GiB wrap.
- **Table space** (`size=8`): unchanged — table addressing was already
  64-bit before this change and is not part of the regression.

## What Was NOT Done

- Did not touch `WasmStackVariableAnalyzer.java`, `WasmStructSynthAnalyzer.java`,
  the emulation modifier's trap logic, or the `cont`-type code (per contract).
- Did not keep the `memory` space 64-bit (see Regression/Fix above: a 64-bit
  space forced `zext` on every 32-bit address, regressing the decompiled C).
  The space is 32-bit with a 128 MiB stride, which supports memories 0..31.
- Did not change `MAX_MEMORY_BLOCK_BYTES` (still `MEMORY_STRIDE` = 128 MiB cap
  per memory).
- Did not change the `table` or `global` spaces.
- Did not push, merge, or tag.

## Headline Numbers

- **Probe count**: 201 (198 baseline + 3 new MS probes)
- **Changed baseline entries**: 3 new (MS_01, MS_02, MS_03); 0 existing entries changed
- **Real-module summary**: `functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156`
- **ZEXT count (real module DumpAll)**: 47 (pre-change: 56, broken: 570)
- **ZEXT count (real module DumpDecomp)**: 3 (pre-change: 7 for 3 funcs only)
- **Memory-9+ probe result**: MS_01 (mem9) and MS_02 (mem16) import, create blocks,
  and decode with `undefined_bytes=0`. Memory 16 is at 0x80000000 (fits in 32 bits
  with 128 MiB stride).
- **`memory` space**: 32-bit (`size=4`), `MEMORY_STRIDE = 0x08000000` (128 MiB).
