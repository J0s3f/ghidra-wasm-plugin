# REPORT-N — memory64 (64-bit linear memories)

Worktree: `D:\code\ghidra-wt-n`, branch `feat/memory64`, base `c02b6b9`
(multi-memory, limits flags incl. the 64-bit flag, constant-expression scanner, GC / new-EH /
function-reference types and unknown-opcode degradation already merged).
Ghidra 12.1.4 (`C:\Users\micro\AppData\Local\Temp\opencode\ghidra-e`), Gradle 9.2.1, JDK 25.

Scope: roadmap item 8 of `MODERN_WASM_GAPS.md` — make 64-bit memories (`(memory i64 N)`,
`wasm64` / Emscripten `MEMORY64` output) analyze correctly. Touched: the pre-analyzer, the
SLEIGH memarg/address computation and the loader. `WasmResizableLimits` (which already exposes
`is64Bit()`), the constant-expression scanner, the signature/stack analyzers and every other
workstream's file were left untouched.

---

## 1. The problem, in one paragraph

A 64-bit memory does not change a single opcode: `i32.load` is still `0x28`. What changes is
the *type of the address operand* — an i64 for a 64-bit memory and an i32 for a 32-bit one —
and therefore also the type of `memory.size`'s result, `memory.grow`'s delta, and the length /
destination operands of `memory.fill` / `memory.init` / `memory.copy` (core spec,
`valid/instructions.html`). That width is a property of the **memory declaration** (the limits
flag bit 2), not of the instruction byte stream, so SLEIGH cannot see it. The old code
hardwired every address operand to `sp1_32`/`sp2_32`/`sp3_32` and the pre-analyzer to
`ValType.i32`, so `i64.const 0; i32.load` failed validation
(`pop type mismatch: got i64, expected i32`) and the whole body was dropped — probe `05` was
`instrs=1 undefined_bytes=6`.

## 2. Index-type propagation (design)

Three pieces, one per layer that needs the width:

**(a) The pre-analyzer reads the module** (`WasmFunctionAnalysis`). `memoryIndexType(analysis,
memidx)` resolves the memory index against the module's memory declarations — imported memories
first (`module.getImports(EXT_MEMORY)`), then `module.getNonImportedMemories()` — and returns
`ValType.i64` when `WasmResizableLimits.is64Bit()` is set, else `ValType.i32`. The memory index
itself now comes from `readMemarg()`, which returns the memidx it decoded (0 when the memarg has
no flags), and from the explicit memidx immediates of `memory.size`/`grow`/`fill`/`init`/`copy`.
Every accessor is public API that already existed, so no other file had to change.

**(b) The stack model uses it.** The operands are typed exactly as the spec's validation rules
require, so a valid module can no longer trip the walker:

| instruction | type | which operand gets the index type |
| --- | --- | --- |
| `t.load x` / `t.store x` | `[at] -> [t]` / `[at t] -> []` | the address |
| SIMD `v128.load*` / `v128.store` | `[at] -> [v128]` / `[at v128] -> []` | the address |
| SIMD `v128.loadN_lane` / `v128.storeN_lane` | `[at v128] -> [v128]` / `[at v128] -> []` | the address (the second operand, `sp2`) |
| atomics `0xFE` | `[at ...]` | the address (`sp1`/`sp2`/`sp3` depending on the op) |
| `memory.size x` | `[] -> [at]` | the result |
| `memory.grow x` | `[at] -> [at]` | delta and result |
| `memory.fill x` | `[at i32 at] -> []` | length and destination |
| `memory.init x y` | `[at i32 i32] -> []` | destination only (source/len stay i32) |
| `memory.copy x1 x2` | `[at1 at2 min(at1,at2)] -> []` | one width per source/destination memory |

`at` (address type) is `i64` for a 64-bit memory, `i32` for a 32-bit one; `min(i32,i64) = i32`.

**(c) The width reaches SLEIGH through one new context field.** `WasmFunctionAnalysis` records a
2-bit code in `ctx_mem64` at the address of every memory instruction (`ContextRegister`, the
same mechanism that already carries `ctx_operand_size` / `ctx_sp`), and `WebAssembly.slaspec`
declares the matching field:

```
ctx_mem64 = (14, 15) noflow      # 0 = i32 index, 1/2 = memory.copy dst/src i64, 3 = i64 index
```

* code `0` (the default, never written) = the historical 32-bit form. 32-bit modules therefore
  have a byte-identical context and match the untouched constructors.
* code `3` = i64 index, used by loads/stores/atomics/SIMD, `memory.size`/`grow`/`fill`/`init`
  and by `memory.copy` when both memories are 64-bit.
* codes `1`/`2` = `memory.copy` with only the destination (1) or only the source (2) 64-bit;
  the length is the minimum, i32, in both. One 2-bit field is enough because
  `memory.copy` is the only instruction with two differently-typed memories.

SLEIGH then has one constructor (or table entry) per code, e.g.

```
loadaddr: memalign memoffset " (i64 index)" is memalign; memoffset; ctx_mem64=3; sp1_64 { ... }
```

so a 64-bit-indexed load really consumes an `i64` operand — and the listing says so. Because
the context is committed before `disassembler.disassemble(...)` runs (`WasmPreAnalyzer` →
`WasmFunctionAnalysis.applyContext`), the disassembler picks the right constructor; the default
context (0) keeps every other address on the old path.

## 3. Address computation: 64-bit arithmetic truncated into a 32-bit space

**Strategy (a) of the brief: compute the address in 64 bits, then truncate/mask it into the
existing 32-bit `ram` address space.** `WebAssembly.ldefs`/`.pspec` are unchanged
(`Wasm:LE:32:default`, `ram size=4`); the addressing base of a memory block is unchanged
(`N * MEMORY_STRIDE`, memory 0 at 0).

```
loadaddr: memalign memoffset " (i64 index)" is memalign; memoffset; ctx_mem64=3; sp1_64 {
	local full:8 = memoffset:8 + sp1_64;          # u64 offset + i64 index, 64-bit add
	addr:4 = full:4;                             # low 32 bits -> `ram`
	export addr;
}
```

The same shape is used by `storeaddr`, `loadaddr2` (SIMD lane ops) and `atomicaddr3` (atomic
cmpxchg/wait), and the multi-memory form adds `memidx * MEMORY_STRIDE` in 64 bits before the
truncation. Mathematically the truncation is `(offset + index + N*MEMORY_STRIDE) mod 2^32`, so
the model is **exact for every effective address below 4 GiB** and wraps above it.

Why not strategy (b), widening the address space? A separate 64-bit `memory` space (like the
existing `table` space, which is already `size=8`) would remove the 4 GiB limit, but it would
move *all* memories — including memory 0 of every one of the 437 functions in the real-module
regression — into a new space that the `ram`-relative C-stack/heap analysis, the data-segment
loader, the DWARF analyzer and every `*[ram]` expression in ~2000 lines of SLEIGH would have to
learn in the same change. The plugin's value today is that memory 0 is byte-for-byte what it
was; a half-migrated second space risks silently breaking the 32-bit corpus to gain a case
(multi-GiB data) that cannot be represented in a Ghidra database anyway without setting a
`ram`-sized block aside. So: truncation now, documented and visible, and widening the address
space is left as explicit future work (§7, item 2).

### 3.1 What happens for memories larger than 4 GiB, and what the decompiler sees

* **Listing**: the operand is visibly marked — `i32.load align=0x2 offset=0x0  (i64 index)` —
  and the memarg offset is printed as the full u64 (a static offset of `0x100000000`, i.e.
  4 GiB, prints as `offset=0x100000000` even though the computed address wraps to 0). No
  instruction silently pretends to be 32-bit.
* **Loader**: a 64-bit memory whose declared size does not fit the 32-bit space, a block base
  (`memidx * MEMORY_STRIDE`) that would be past `0xffffffff`, or a data segment at such an
  offset, is clamped and the clamp is logged with `Msg.warn` ("does not fit the 32-bit `ram`
  address space; clamping to 0xffffffff ..." / "declares N byte(s) but is mapped to M byte(s)
  ... accesses beyond the mapped size are not modelled"). A 64-bit memory that fits is logged
  once with `Msg.info` (index type and block base), and its block carries a comment saying that
  only addresses below 4 GiB are represented. Nothing crashes and no address overflows: the
  size computation saturates (`memoryByteSize`) and `getMemoryAddress()` clamps to
  `RAM_MAX_ADDRESS = 0xffffffff` with a warning instead of wrapping into a negative offset.
  (One offset form is *not* clamped because it never reaches the loader at all — an
  `i64.const` data-segment offset is dropped earlier, §7 item 8.)
* **Decompiler**: a 64-bit-indexed access renders as a 64-bit index value (`i64` parameter /
  local / constant) feeding the address computation; the computation is a 64-bit add whose
  result is truncated to 32 bits before the load, exactly the model above. For addresses below
  4 GiB — every module whose memory fits the `ram` limit — the decompiled C is the same as a
  32-bit memory's, which is the intent. For ≥ 4 GiB the effective address wrapped, and the
  listing offset is the evidence of what was in the module.

## 4. Loader: bounded, documented representation

`WasmLoader`:

* `memoryByteSize(pages)` computes `pages * 65536` with saturation: a u64 page count that does
  not fit a `long` (or `pages < 0`, i.e. a value above `2^63` after `LEB128Info.asLong()`) is
  returned as `Long.MAX_VALUE`, so the existing clamp (`CODE_BASE` for memory 0, `MEMORY_STRIDE`
  otherwise) can never be defeated by an overflow. 32-bit memories compute exactly the same
  `Math.min(initial * 65536, clamp)` as before.
* `createMemoryBlock(..., boolean is64Bit, ...)` — only the 64-bit case gains a block comment
  (`64-bit (memory64) linear memory: ... addresses below 4 GiB ...`); 32-bit memories get no new
  comment, no new flags and the same size, i.e. byte-identical blocks.
* `getMemoryAddress()` keeps `memidx * MEMORY_STRIDE + offset` for everything that fits and
  clamps to `RAM_MAX_ADDRESS` (with `Msg.warn`) otherwise.

## 5. Probes

`test-scripts/probes_memory64.py` (new file) generates 8 modules. Unlike the frozen generators,
they emit the sections in the order the core spec requires, so every one of them is
independently validated with `wasmtime` (`wasmtime.Module(...)` accepts all 8; that check also
independently confirms the operand typing of §2b, since the probes are ordinary spec-valid
modules).

| probe | what it pins | expected |
| --- | --- | --- |
| `M64_01_baseline_i64_load` | the frozen probe 05 shape `(memory i64 1)` + `i64.const 0; i32.load` | `undefined_bytes=0`, decompiles |
| `M64_02_scalar_loads_stores` | i32/i64/f32/f64 loads **and stores** + `load8_u` through a 64-bit memory, with non-zero offsets | all decode, `undefined_bytes=0` |
| `M64_03_memory_size_grow` | `memory.grow`/`memory.size` on a 64-bit memory (i64 → i64) | `undefined_bytes=0` |
| `M64_04_bulk_memory` | `memory.init`/`memory.fill`/`memory.copy` with i64 operands | `undefined_bytes=0` |
| `M64_05_i64_then_i32_memidx` | memory 0 = 64-bit, memory 1 = 32-bit; both accessed in one body | two different operand widths in one function |
| `M64_06_i32_then_i64_memidx` | memory 0 = 32-bit, memory 1 = 64-bit; `i32.load memidx=1` + `memory.size 1`/`0` | the mixed case the other way round |
| `M64_07_large_static_offset` | memarg offsets `0x12345678` and `0x100000000` (4 GiB) | 5-byte LEB offset decodes, no desync |
| `M64_08_simd_atomic` | `v128.load`, `v128.load8_lane`, `i32.atomic.rmw.add`, `i32.atomic.rmw.cmpxchg` with a 64-bit (shared) memory | `loadaddr2`/`atomicaddr3` get i64 address operands |

## 6. Evidence

### 6.0 Build / install

```powershell
& D:\code\ghidra-wt-n\test-scripts\build-install.ps1 `
    -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-e"
# BUILD SUCCESSFUL in 18s; created ghidra_12.1.4_PUBLIC_20261012_ghidra-wt-n.zip; installed
```

SLEIGH compile checked in isolation (~10 s, `support\sleigh.bat -c WebAssembly.slaspec` in a copy
of `data/languages`): exit 0, no new warnings. The only warnings are the pre-existing ones
(1293 NOP constructors, `VectorOps.sinc` `shuf0`/`shuf1` operand collision, unreferenced
`opc2_*` tables).

### 6.1 Probes: before / after and the 64-bit listings

```powershell
& D:\code\ghidra-wt-n\test-scripts\run_probes.ps1 `
    -OutDir "C:\Users\micro\AppData\Local\Temp\opencode\probes-n" `
    -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-e" `
    -Generators gen_feature_probes.py,probes_memory64.py -Detail
# == running 35 probe(s) ==
```

Frozen baseline probe `05` (the acceptance case) — recorded metrics before, real listing after:

```
before (base c02b6b9)                                  after
PROBE 05_memory64.wasm funcs=1 instrs=1                LISTING 05_memory64.wasm
      undefined_bytes=6 decompiled=1/0                 function f @ ram:80000023 int f(void)
the body aborted: "Validation error ... pop            ram:80000023  .locals
type mismatch: got i64, expected i32", so the           ram:80000024  i64.const 0x0
function was left with one instruction and six          ram:80000026  i32.load align=0x2 offset=0x0  (i64 index)
undefined bytes                                          ram:80000029  end
                                                       PROBE 05_memory64.wasm funcs=1 instrs=4
                                                             undefined_bytes=0 decompiled=1/0
                                                       PROBE-BLOCK 05_memory64.wasm .memory0 size=65536
```

Decompiled C for the 64-bit cases (`DumpAll.java`):

```c
/* 05_memory64: (memory i64 1); i64.const 0; i32.load align=2 */
int export::f(void) { return _UNK_ram_00000000; }

/* M64_02: i32/i64/f32/f64 stores then an i32.load through a 64-bit memory.
   The 64-bit index is truncated into `ram`, which shows up as the (int) cast. */
int export::f(undefined8 param1)
{
  *(undefined4 *)((int)param1 + 0x30) = 7;
  *(undefined8 *)((int)param1 + 0x38) = 8;
  *(undefined4 *)((int)param1 + 0x40) = 0x3fc00000;
  *(undefined8 *)((int)param1 + 0x48) = 0x4004000000000000;
  return *(int *)((int)param1 + 0x50);
}

/* M64_03: memory.grow/memory.size on a 64-bit memory are i64-typed (longlong). */
longlong export::f(undefined8 param1)
{
  longlong lVar1;
  memory_grow(0,param1);
  lVar1 = memory_size(0);
  return lVar1;
}

/* M64_04: memory.init/memory.fill/memory.copy with i64 operands. */
longlong export::f(undefined8 param1,undefined8 param2,undefined8 param3)
{
  longlong lVar1;
  memory_init(0,0,3,0,param1);
  memory_fill(0,param3,0x41,param1);
  memcpy(param1,param2,param3);
  lVar1 = memory_size(0);
  return lVar1;
}

/* M64_05: 64-bit memory 0 + 32-bit memory 1 in one function: `param1` (i64) addresses
   memory 0, `param2` (i32) addresses memory 1 at its 0x10000000 block base. */
int export::f(undefined8 param1,int param2)
{
  int iVar1, iVar2;
  iVar1 = *(int *)param1;
  iVar2 = *(int *)(param2 + 0x10000000);
  *(int *)param1 = 1;
  *(undefined4 *)(param2 + 0x10000000) = 2;
  return iVar1 + iVar2;
}

/* M64_06: the mirror image - memory 0 i32, memory 1 (i64 index) at 0x10000000. */
int export::f(int *param1,undefined8 param2)
{
  memory_size(1);
  memory_size(0);
  return *param1 + *(int *)((int)param2 + 0x10000000);
}

/* M64_08: SIMD/atomic memargs through a 64-bit (shared) memory. */
int export::f(undefined8 param1,undefined8 param2)
{
  int iVar1;
  *(int *)param1 = *(int *)param1 + 5;
  iVar1 = *(int *)param1;
  if (iVar1 == 1) *(int *)param1 = 2;
  return iVar1;
}
```

The listings that matter (`ListProgram.java`) — note that the 64-bit operands are *visible*
(`(i64 index)`), so a reader can tell a 64-bit-indexed access from a 32-bit one without
decompiling, including the > 4 GiB static offset in `M64_07`:

```
05_memory64          ram:80000026  i32.load align=0x2 offset=0x0  (i64 index)
M64_02               ram:80000027  i64.load align=0x3 offset=0x10  (i64 index)
                     ram:80000041  i32.store align=0x2 offset=0x30  (i64 index)
                     ram:80000060  f64.store align=0x3 offset=0x48  (i64 index)
M64_03               ram:80000028  memory.grow 0x0  (i64 index)
                     ram:8000002b  memory.size 0x0  (i64 index)
M64_04               ram:80000030  memory.init 0x0 0x0  (i64 index)
                     ram:8000003b  memory.fill 0x0  (i64 index)
                     ram:80000044  memory.copy 0x0 0x0  (i64 index)
M64_05 (mem 0 = i64) ram:8000002a  i32.load align=0x2 offset=0x0  (i64 index)
       (mem 1 = i32) ram:8000002f  i32.load align=0x2 memidx=0x1 offset=0x0
M64_06 (mem 0 = i32) ram:8000002a  i32.load align=0x2 offset=0x0
       (mem 1 = i64) ram:8000002f  i32.load align=0x2 memidx=0x1 offset=0x0  (i64 index)
                     ram:80000034  memory.size 0x1  (i64 index)
                     ram:80000037  memory.size 0x0
M64_07               ram:80000026  i32.load align=0x2 offset=0x12345678  (i64 index)
                     ram:80000030  i32.load align=0x2 offset=0x100000000  (i64 index)   # 4 GiB u64 offset
M64_08               ram:80000029  v128.load align=0x4 offset=0x0  (i64 index)
                     ram:80000042  v128.load8_lane align=0x0 offset=0x0  (i64 index) 0x0
                     ram:80000057  i32.atomic.rmw.cmpxchg align=0x2 offset=0x0  (i64 index)
```

Metrics of the eight new probes (all `funcs=1`, all `decompiled=1`, `decompile_failed=0`,
all `undefined_bytes=0`) and the loader's block evidence:

```
PROBE M64_01_baseline_i64_load.wasm    funcs=1 instrs=4  undefined_bytes=0 decompiled=1/0
PROBE-BLOCK M64_01_baseline_i64_load.wasm .memory0 size=65536
PROBE M64_02_scalar_loads_stores.wasm  funcs=1 instrs=28 undefined_bytes=0 decompiled=1/0
PROBE-BLOCK M64_02_scalar_loads_stores.wasm .memory0 size=65536
PROBE M64_03_memory_size_grow.wasm     funcs=1 instrs=6  undefined_bytes=0 decompiled=1/0
PROBE-BLOCK M64_03_memory_size_grow.wasm .memory0 size=65536
PROBE M64_04_bulk_memory.wasm          funcs=1 instrs=15 undefined_bytes=0 decompiled=1/0
PROBE-BLOCK M64_04_bulk_memory.wasm .memory0 size=65536
PROBE M64_05_i64_then_i32_memidx.wasm  funcs=1 instrs=13 undefined_bytes=0 decompiled=1/0
PROBE-BLOCK M64_05_i64_then_i32_memidx.wasm .memory0 size=65536
PROBE-BLOCK M64_05_i64_then_i32_memidx.wasm .memory1 size=65536
PROBE M64_06_i32_then_i64_memidx.wasm  funcs=1 instrs=11 undefined_bytes=0 decompiled=1/0
PROBE-BLOCK M64_06_i32_then_i64_memidx.wasm .memory0 size=65536
PROBE-BLOCK M64_06_i32_then_i64_memidx.wasm .memory1 size=65536
PROBE M64_07_large_static_offset.wasm  funcs=1 instrs=7  undefined_bytes=0 decompiled=1/0
PROBE-BLOCK M64_07_large_static_offset.wasm .memory0 size=65536
PROBE M64_08_simd_atomic.wasm          funcs=1 instrs=17 undefined_bytes=0 decompiled=1/0
PROBE-BLOCK M64_08_simd_atomic.wasm .memory0 size=65536
```

Independent validity check of the probe modules (`wasmtime`, not the plugin):

```python
wasmtime.Module(wasmtime.Engine(), open(path,"rb").read())
# VALID for all 8 modules: M64_01 .. M64_08
```

(The frozen probes are *not* all spec-valid — several emit the memory/table section before the
function section, which `wasmtime` rejects with "section out of order". The new probes are
ordered correctly, which is what makes the independent validation possible.)

The loader annotations produced for a 64-bit memory (raw log line):

```
INFO  Memory 0 has a 64-bit (i64) index type; its 65536 byte(s) are mapped into the
      32-bit `ram` space at 0x0 (addresses/offsets >= 4 GiB wrap; see REPORT-N.md) (WasmLoader)
```

### 6.2 Frozen probes: no regression

All 27 frozen probes of `gen_feature_probes.py` keep their recorded metrics except `05`
(the one the roadmap allows to change): `01`, `02`, `03`, `04`, `06`-`18`, `22`-`27` are
identical to `MODERN_WASM_GAPS.md` §2.4/§2.5 (e.g. `06 funcs=1 instrs=6 undefined_bytes=0`,
`12 funcs=1 instrs=4 undefined_bytes=1`, `13 funcs=2 instrs=5`), `19`/`20` import with no
functions, `21` still fails to import. The full CI check of §6.3 is the authoritative statement.

### 6.3 Real-module regression and the CI gate (expected-results.json)

**Real-module regression** (179 KiB Rust `wasm-bindgen` module, 437 functions):

```powershell
New-Item -ItemType Directory -Force "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-e\proj-n"
& "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-e\support\analyzeHeadless.bat" `
    "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-e\proj-n" Reg `
    -import "D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm" `
    -scriptPath "D:\code\ghidra-wt-n\test-scripts" -postScript DumpDecomp.java -max-cpu 2 -deleteProject
```

```
INFO  DumpDecomp.java> SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156
```

Exactly the recorded baseline (`SUMMARY functions=437 decompiled=437 failed=0
instructions=61658`), i.e. 61658 instructions means the new SLEIGH constructors neither shadowed
nor added a decode in a real module, and `undefined_bytes=156` is the recorded import-stub noise.
(Only the pre-existing "Unable to disassemble EXTERNAL block location" decompiler warnings
appear, as before.)

**CI gate** — first the baseline update (the only way `expected-results.json` may change), with a
unique output dir (several agents share the host; `-SkipBuild` reuses the install from §6.0):

```powershell
& .\test-scripts\check-local.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-e" `
    -SkipBuild -Update -OutDir "C:\Users\micro\AppData\Local\Temp\opencode\probes-ci-n"
```

```
== probe suite ==
== generating probes ==
-- gen_feature_probes.py
-- probes_analysis.py
-- probes_component.py
-- probes_eh.py
-- probes_gc.py
-- probes_memory64.py
-- probes_types.py
== running 101 probe(s) ==
...
== DumpDecomp wasm_fixture.wasm -> fixture-run.log ==
...
SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0
== check-results.py ==
updated D:\code\ghidra-wt-n\test-scripts\expected-results.json: 98 probe(s) with metrics,
3 expected import failure(s)
```

The resulting baseline diff is exactly the intended one — a scripted comparison of the committed
and the regenerated `expected-results.json`:

```
probe_count 93 -> 101
added:  M64_01_baseline_i64_load.wasm, M64_02_scalar_loads_stores.wasm,
        M64_03_memory_size_grow.wasm, M64_04_bulk_memory.wasm,
        M64_05_i64_then_i32_memidx.wasm, M64_06_i32_then_i64_memidx.wasm,
        M64_07_large_static_offset.wasm, M64_08_simd_atomic.wasm
removed: (none)
changed: 05_memory64.wasm  {instrs: 1, undefined_bytes: 6}
                       -> {instrs: 4, undefined_bytes: 0}      (funcs/decompiled unchanged)
fixture:     functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0   (unchanged)
real_module: functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156 (unchanged)
```

i.e. **no other probe's metrics moved** — 92 recorded probes re-measured identically, the one
allowed probe (`05`) improved, and the 8 new probes are recorded. The committed fixture and the
real-module entry are byte-identical, so the update did not paper over any change there.

Then the plain check (no `-Update`), which must agree with the recorded baseline:

```powershell
& .\test-scripts\check-local.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-e" `
    -SkipBuild -OutDir "C:\Users\micro\AppData\Local\Temp\opencode\probes-ci-n2"
```

```
== probe suite ==
...
== check-results.py ==
SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0
probes: 98 imported, 3 import failure(s); baseline has 101
OK: every probe matches the recorded baseline.
```

(`98 imported + 3 expected import failures = 101` probes; exit code 0.)

### 6.4 Loader bounds / robustness (throwaway modules, not committed)

Four extra modules (generated into a temp dir, imported with
`analyzeHeadless … -postScript WasmFeatureReport.java`, all four also accepted by
`wasmtime.Module` where noted) probe the *loader* claims of §3.1/§4. They are not part of
`probes_memory64.py`; the generator body is:

```python
# X1: (memory i64 1) + active data segment at offset 2^32 (4 GiB) + i64.const 0; i32.load
# X2: (memory 1)(memory i64 4097)          -> 4097 pages = 268500992 B > MEMORY_STRIDE
# X3: (memory i64 0)                       -> zero pages, no block
# X4: 17 memories, memory 16 = (memory i64 1)  -> block base 16*MEMORY_STRIDE = 2^32
#     + an active data segment for memory 16
```

```
X1_data_offset_4gib    PROBE funcs=1 instrs=4 undefined_bytes=0 decompiled=1/0
                       INFO  Memory 0 has a 64-bit (i64) index type; its 65536 byte(s) are mapped
                             into the 32-bit `ram` space at 0x0 ... (WasmLoader)
X2_huge_declared_size  PROBE funcs=1 instrs=4 undefined_bytes=0 decompiled=1/0
                       WARN  Memory 1 (i64 index) declares 268500992 byte(s) but is mapped to
                             268435456 byte(s) (32-bit `ram` space / MEMORY_STRIDE limit);
                             accesses beyond the mapped size are not modelled (WasmLoader)
X3_zero_pages          PROBE funcs=1 instrs=4 undefined_bytes=0 decompiled=1/0
                       INFO  Memory 0 has a 64-bit (i64) index type; its 0 byte(s) are mapped ...
X4_memidx_past_ram     WARN  Address memidx=16 offset=0x0 does not fit the 32-bit `ram` address
                             space; clamping to 0xffffffff (memory64 addresses/data above 4 GiB
                             are not modelled; see REPORT-N.md)
                       ERROR Failed to create memory block 16 at ram:ffffffff
                             (AddressOverflowException: Address Overflow in add: ram:ffffffff 0xffff)
                       ERROR Failed to initialize memory 16 with data segment 0 at ram:ffffffff
                             (MemoryAccessException: Address ram:ffffffff does not exist in memory)
                       ERROR Failed to create memory block 8 at ram:80000000
                             (MemoryConflictException — the documented index>=8 limit of
                              REPORT-A-DS.md §3.2, unchanged by this work)
```

i.e. every out-of-range size/offset is clamped and logged, every failure is caught, and the
module still imports and analyzes (no crash, no overflow, no negative-size block). X1's data
segment at 4 GiB is not an error path at all: see §7 item 8 — `ConstantExpression.asI32()` cannot
represent an `i64.const` offset, so the segment is skipped before the loader sees an offset.

X4's *function body* is undefined (7 bytes) because of a **pre-existing** module re-parse limit
that has nothing to do with memory64: `WasmAnalysis.getState` re-reads the module image through a
`MemoryByteProvider` whose length comes from the program's memory map, so once a *memory block
lies above the module image* (memory index >= 9 with the current layout) the section loop runs
past the `.module` block and throws `Address ram:… does not exist in memory`. X5/X6 prove it is
independent of this change — the same 17-memory shape with **only 32-bit memories** fails
identically:

```
X5_32bit_17memories         PROBE funcs=1 instrs=1 undefined_bytes=7 decompiled=1/0
X6_32bit_17memories_nodata  PROBE funcs=1 instrs=1 undefined_bytes=7 decompiled=1/0
```

Both are spec-valid (`wasmtime` accepts them) and neither contains a single 64-bit memory, so no
`ctx_mem64` value is ever written for them. Recorded here as a finding for the integrator (§7
item 9).

## 7. What is deliberately not implemented

1. **`table64`** (64-bit tables, limits flag bit 2 on a *table*). `WasmTableType` shares
   `WasmResizableLimits`, so the flag is decoded, and the `table` address space is already
   `size=8`; but `table.get/set/size/grow/fill/copy/init` and `call_indirect` are still typed
   with an i32 index in the pre-analyzer and `sp1_32`/`sp2_32` in SLEIGH. A table64 module would
   trip exactly the validation error this change fixes for memories. Out of scope here — it is
   the same design applied to `ctx_mem64`, and the `table` space does not need truncation.
2. **Memories and addresses ≥ 4 GiB.** §3: the address space stays 32-bit; addresses wrap at
   4 GiB, blocks and data segments that do not fit are clamped to the top of `ram` and logged.
   A multi-GiB *data* image is not represented at all. Widening the address space is future
   work, not a silent limitation: every affected module produces a log line and a listing
   marker.
3. **`memory.discard` (`0xFC 0x12`) is still `unimplemented`**, so it has no stack effect and
   gets no `ctx_mem64` value. It is *pinned* that way by frozen probe `A07`
   (`instrs=5 undefined_bytes=0`, listing `unimplemented 0xfc:18 memory.discard memidx=0x0`),
   whose module declares no memory at all: modelling `[at i32 at] -> []` would make that probe
   fail validation and blank its body. Its one-Leb `memidx` operand is consumed correctly, so
   the byte stream stays aligned.
4. **`memory.copy`'s .rodata unrolling** (`WasmMemoryCopyAnalyzer`) still resolves operand
   values with `& 0xFFFFFFFFL`, i.e. its constant-source classification is 32-bit-based. Only
   the "copy a constant initializer" fast path is affected; dynamic copies (the normal case for
   64-bit memories) decompile to `memcpy(dst, src, len)` with i64 operands.
5. **Cross-memory `memory.copy`** still ignores its two memidx operands inside the pcode
   injection (inherited limitation of the multi-memory workstream, `REPORT-A-DS.md` §3.2); both
   source and destination are already `ram` addresses, so a same-memory copy is correct.
6. **No range check of the runtime index.** Static analysis cannot know whether an `i64` index
   stays inside the memory; a value ≥ 4 GiB wraps in the model and the listing shows the
   wrapped operand/offset. Nothing is *silently* wrong: the `(i64 index)` marker plus the
   loader/`msg` warnings are the visible signal.
7. Shared + 64-bit limits are decoded and used (the probe `M64_08` memory is
   `flags=0x07`), but the "shared requires a maximum" rule is not validated (the plugin does not
   validate modules in general).
8. **Active data segments of a 64-bit memory are not mapped.** `WasmDataSegment.getMemoryOffset()`
   resolves the segment's offset expression with `ConstantExpression.asI32()`, which returns a
   value *only* for `I32_CONST`; a memory64 active segment's offset is an `i64.const`
   (`ConstantExpression.asBytes()` knows it, `asI32()` does not), so `getMemoryOffset()` returns
   `null` and `WasmLoader.loadDataSegments` skips the segment. Consequence: for a real
   `wasm64`/Emscripten `MEMORY64` module the constant data is absent from `.memoryN`, so a
   decompiled reference to it reads as undefined bytes — a silent mis-model of exactly the kind
   this workstream is meant to remove (X1 in §6.4 shows the import succeeding with the segment
   silently dropped). Fix (outside this workstream's file set — `ConstantExpression.java` is
   explicitly off-limits and `WasmDataSegment.java` is not owned): resolve the offset as a 64-bit
   value (`asBytes(module)` / an `asI64()` helper) and hand it to
   `WasmLoader.getMemoryAddress()`, which already clamps and logs offsets >= 4 GiB. The
   *instruction*-level memarg offsets (the in-scope case) are handled, see §3 and `M64_07`.
9. **Pre-existing:** a memory block above the module image (memory index >= 9 with the current
   `MEMORY_STRIDE` layout, or a clamped block at `ram:ffffffff`) makes the `WasmAnalysis` module
   re-parse read past the `.module` block and abort the pre-analyzer
   (`Address ram:… does not exist in memory`), which leaves the function bodies undefined.
   Reproduced without any 64-bit memory (X5/X6, §6.4), so it is unrelated to this change; it is a
   consequence of `MemoryByteProvider` deriving its length from the program memory map rather than
   from the `.module` block, and it is worth fixing before memories >= 9 or very large memories
   are used. Not fixed here (different files/behaviour, and it needs its own regression coverage).
10. `resume`-class stack-switching opcodes, table64, JS string builtins etc. remain as recorded
    by the other workstreams; this change neither adds nor removes an `unimplemented` path.

## 8. Files changed

| File | Change |
| --- | --- |
| `src/main/java/wasm/analysis/WasmFunctionAnalysis.java` | `readMemarg()` returns the memidx; `memoryIndexType()`/`setMemoryIndexContext()`/`setMemoryCopyContext()`; spec-typed operands for loads/stores, SIMD, atomics, `memory.size/grow/fill/init/copy`; `ctx_mem64` in `ContextRegister` |
| `data/languages/WebAssembly.slaspec` | `ctx_mem64 = (14, 15) noflow` context field |
| `data/languages/BasicOps.sinc` | 64-bit-index variants of `loadaddr`/`storeaddr` (unflagged and memidx forms) |
| `data/languages/VectorOps.sinc` | 64-bit-index variants of `loadaddr2` |
| `data/languages/AtomicOps.sinc` | 64-bit-index variants of `atomicaddr3` |
| `data/languages/WebAssembly.sinc` | 64-bit-index variants of `memory.size`/`grow`/`init`/`copy` (one per width pair) and `fill` |
| `src/main/java/wasm/WasmLoader.java` | `MEMORY_PAGE_SIZE`/`RAM_MAX_ADDRESS`, saturating `memoryByteSize()`, bounds-checked `getMemoryAddress()`, `is64Bit` block annotation + load-time log |
| `test-scripts/probes_memory64.py` | new: 8 probes (M64_01..M64_08) |
| `test-scripts/expected-results.json` | regenerated by `check-results.py --update` (probe 05 + the 8 new probes) |
| `REPORT-N.md` | this report |

No `.ldefs`/`.pspec`/`.cspec`/`build.gradle` change; no new dependency; `WasmResizableLimits`,
`WasmEnums`, `ConstantExpression`, `WasmFuncType`, `WasmTypeSection`, the signature/stack/DWARF
analyzers, `WasmComponentLoader`, the other probe generators and the CI scripts are untouched.
