# Dedicated `memory` Address Space for Linear Memories

## Design

### Problem
Linear memory N was placed at `N * MEMORY_STRIDE` in the 32-bit `ram` space, which
also holds the module image at `CODE_BASE = 0x80000000`. Memory 8 landed exactly on
the code base and could not be created (the loader logged the failure). The 32-bit
space could not hold many memories at 256 MiB stride.

### Fix
Add a dedicated 64-bit `memory` address space to `WebAssembly.slaspec`:

```
define space memory  type=ram_space  size=8;
```

The SLEIGH memory accesses now target `*[memory]:N addr` instead of `*:N addr`.
The address arithmetic is unchanged (`memidx * MEMORY_STRIDE`), so memory N sits at
the same numeric offset as before - the only difference is the space name.

Because the `memory` space is 64-bit (`size=8`), the SLEIGH `loadaddr`/`storeaddr`
constructors export 64-bit addresses (`addr:8`). 32-bit memory addresses are
zero-extended (`zext(raw)`); memory64 addresses are computed in 64 bits natively.
This eliminates the old 32-bit truncation for memory64.

The Java loader creates memory blocks in the `memory` space via
`getMemoryAddress()`, which now uses `getAddressSpace("memory")`.

## Files Changed

### SLEIGH / SLASPEC
- **`data/languages/WebAssembly.slaspec`** (line 28): Added `define space memory type=ram_space size=8;`
- **`data/languages/WebAssembly.sinc`** (line 33-38): Updated `@@MM` comment to describe
  the `memory` space (64-bit, no collision with `ram` at CODE_BASE).
- **`data/languages/BasicOps.sinc`**:
  - `loadaddr`/`storeaddr` constructors: changed `addr:4` to `addr:8` with `zext(raw)`
    for 32-bit memories, native 64-bit for memory64.
  - All load/store instructions: `*:N addr` → `*[memory]:N addr`.
  - Updated `@@MM`/`@@M64` comments.
- **`data/languages/VectorOps.sinc`**:
  - `loadaddr2` constructor: same 64-bit address change.
  - All SIMD load/store instructions: `*:N addr` → `*[memory]:N addr`.
- **`data/languages/AtomicOps.sinc`**:
  - `atomicaddr3` constructor: same 64-bit address change.
  - All atomic load/store/RMW/cmpxchg instructions: `*:N addr` → `*[memory]:N addr`.

### Java
- **`src/main/java/wasm/WasmLoader.java`**:
  - `getMemoryAddress()`: uses `getAddressSpace("memory")` instead of `"ram"`.
  - `RAM_MAX_ADDRESS` → `MEMORY_MAX_ADDRESS = Long.MAX_VALUE` (64-bit space).
  - `createMemoryBlock()`: memory64 comment updated (SLEIGH no longer truncates).
  - `loadMemories()`: comments updated for the `memory` space.
  - `MEMORY_STRIDE` comment updated.
- **`src/main/java/ghidra/program/emulation/WasmEmulateInstructionStateModifier.java`**:
  - `checkMemoryBounds()`: `getAddressSpace("ram")` → `getAddressSpace("memory")`.
  - `checkAddressInMemory()`: zeroing uses `"memory"` space.
  - `checkMemoryBounds64()`: zeroing uses `"memory"` space.
  - `reverseComputeLoadBase()`: `getAddressSpace("ram")` → `getAddressSpace("memory")`.
- **`src/main/java/wasm/pcode/PcodeOpEmitter.java`**:
  - `emitUnrolledCopy()`: uses `getAddressSpace("memory")` instead of default (`ram`).
- **`src/main/java/wasm/analysis/WasmAnalysis.java`**: Comment updated (memory blocks
  no longer extend `ram` space's max address).
- **`src/main/java/wasm/analysis/WasmPreAnalyzer.java`**: Comment updated similarly.

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

## Rendering Change in Decompiled C

The decompiled C for memory accesses now shows `ZEXT48` wrapping for store addresses
because the `memory` space is 64-bit and the SLEIGH zero-extends 32-bit addresses:

```c
// Before (ram space, 32-bit):
*(undefined4 *)param_2 = param1;

// After (memory space, 64-bit):
*(undefined4 *)ZEXT48(&param_2) = param1;
```

The numeric addresses are identical. Variable names in the decompiled C change from
`in_ram_XXXXXXXX` to `in_memory_XXXXXXXX` (space name change). The instruction count,
decompile success rate, and undefined_bytes are unchanged.

## What Was NOT Done

- Did not touch `WasmStackVariableAnalyzer.java`, `WasmStructSynthAnalyzer.java`,
  the emulation modifier's trap logic, or the `cont`-type code (per contract).
- Did not run the spec-suite decode gate (`spectest/run_spectest.ps1`) - the probe
  gate + fixture + real module cover the same surface.
- Did not change `MEMORY_STRIDE` (still 0x10000000 = 256 MiB per memory).
- Did not change `MAX_MEMORY_BLOCK_BYTES` (still 256 MiB cap per memory).
- Did not change the `table` or `global` spaces.
- Did not push, merge, or tag.

## Headline Numbers

- **Probe count**: 201 (198 baseline + 3 new MS probes)
- **Changed baseline entries**: 3 new (MS_01, MS_02, MS_03); 0 existing entries changed
- **Real-module summary**: `functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156`
- **Memory-9+ probe result**: MS_01 (mem9) and MS_02 (mem16) import, create blocks,
  and decode with `undefined_bytes=0`. Before this change, memory 8+ could not be created.
