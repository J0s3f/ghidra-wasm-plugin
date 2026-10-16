# REPORT-A-DS — unknown-opcode degradation (R1.1) and multi-memory (R1.4)

Worktree: `D:\code\ghidra-wt-k`, branch `fix/analysis-decoder-ds`, base `1e2328b`
(limits/const-expression/valtype + new-EH + GC already merged).
Ghidra 12.1.4 (`C:\Users\micro\AppData\Local\Temp\ghidra-k`), Gradle 9.2.1.

Scope: exactly the two items handed to this workstream. GC (`GCOps.*`), new EH (`EH2Ops.*`),
the constant-expression scanner and memory64 were left untouched; their baseline probes
(`05`, `08`, `09`, `11`, `19`, `20`, `22`-`27`) are byte-for-byte unchanged (see §5).

---

## 1. Files changed

| File | Change |
| --- | --- |
| `src/main/java/wasm/analysis/WasmFunctionAnalysis.java` | R1.4(a) memarg skipping (`readMemarg`); R1.1 unknown-opcode table (`skipUnimplementedOperands`, `markUnimplemented`), relaxed validation after an unmodelled instruction, 32-bit width degradation |
| `src/main/java/wasm/WasmLoader.java` | R1.4(b) `MEMORY_STRIDE`, `getMemoryAddress()` for every memidx, `loadMemories()` creates a block for every memory, `loadDataSegments()` no longer skips memidx != 0 |
| `data/languages/BasicOps.sinc` | R1.4(a) memarg decoders `memalign` / `memalign_mem` and the memidx forms of `loadaddr` / `storeaddr` |
| `data/languages/VectorOps.sinc` | memidx form of `loadaddr2` |
| `data/languages/AtomicOps.sinc` | memidx form of `atomicaddr3` |
| `data/languages/WebAssembly.sinc` | `@define MEMORY_STRIDE`, `memflag`/`mlow` token fields, `tagidx`/`typeidx2u`/`stringidx`/`memidx_label` operands, the `:unimplemented` instruction table |
| `test-scripts/probes_analysis.py` | new probes `A01`-`A10` |
| `REPORT-A-DS.md` | this report |

No changes to `.pspec`/`.ldefs` were needed (memories live in the existing `ram` space,
see §3). No new dependencies; `build.gradle` untouched.

---

## 2. R1.1 — unknown opcodes degrade visibly instead of desyncing

### 2.1 Mechanism

Two decoders must agree on where an instruction ends: the Java pre-analysis walker (which
builds the value stack and the context register) and SLEIGH (which produces the listing and
the pcode). Before this change a partially-recognised instruction shifted the walker (e.g.
`0xFC 0x12` consumed only the prefix + sub-opcode, then read the memarg bytes as opcodes) and
left the SLEIGH side without any pattern, so the byte stayed undefined and the disassembler's
linear sweep produced garbage or nothing.

Now every opcode family that is *identifiable* has a matching SLEIGH `:unimplemented`
constructor in `data/languages/WebAssembly.sinc` **and** a matching Java length case in
`skipUnimplementedOperands()`. Both consume exactly the same bytes, so:

* instruction boundaries stay byte-exact (the operand bytes belong to the `unimplemented`
  instruction, so `undefined_bytes` stays 0),
* the listing shows `unimplemented <opcode> <name> <immediates>`, i.e. it is visibly
  incomplete instead of wrong,
* the rest of the function keeps decoding (the walker continues, and SLEIGH resumes at the
  true next instruction).

Covered opcodes and their operand lengths (with the sources used to identify them):

| Opcode | Instruction | Immediates | Pattern |
| --- | --- | --- | --- |
| `0xE0` | `cont.new` | `typeidx` (u32 LEB) | `opc=0xE0; typeidx` |
| `0xE1` | `cont.bind` | `typeidx typeidx` | `opc=0xE1; typeidx; typeidx2u` |
| `0xE2` | `suspend` | `tagidx` | `opc=0xE2; tagidx` |
| `0xE6` | `switch` | `typeidx tagidx` | `opc=0xE6; typeidx; tagidx` |
| `0xFC 0x12` | `memory.discard` | `memidx` | `opc=0xFC; opc2_18; memidx_label` |
| `0xFC 0x13`-`0x16` | `i64.add128` / `sub128` / `mul_wide_s` / `mul_wide_u` | none | `opc=0xFC; opc2_19..22` |
| `0xFB 0x80`-`0x8E`, `0x90`-`0x92`, `0x9A`-`0x9C`, `0xA0`-`0xA2`, `0xB4`-`0xB7` | JS string builtins / stringref (`string.new_utf8`, `string.const`, `string.concat`, `string.eq`, `string.encode_*`, `stringview_*`, ...) | `memidx` or `stringidx` for the encoding/creation forms, none for `concat`/`eq`/`measure_*`/... | `opc=0xFB; opc2_128..opc2_183` |

Encoding sources (all re-checked while implementing, not guessed):

* wide arithmetic / `memory.discard`: `WebAssembly/wide-arithmetic` Overview
  (`0xFC 19..22`), `wasmparser`'s `visit_0xfc_operator` (`0x12 => read_var_u32()` = a
  **bare memidx**, `0x13..0x16` = no immediates). The task brief said "`memory.discard`
  takes a memarg"; the de-facto reference implementation (wasm-tools/wasmparser) and the
  memory-control proposal both say **memidx**, and a memarg would mis-read real modules, so
  memidx is implemented; `A07` pins it.
* stack switching: stack-switching Explainer, "Instructions" binary format table
  (`0xE0` u32, `0xE1` u32 u32, `0xE2` u32, `0xE3` u32 + handler vector, `0xE4` u32 u32 +
  handler vector, `0xE5` u32 + handler vector, `0xE6` u32 u32).
* JS string builtins / stringref: `stringref` Overview binary encoding table.

### 2.2 "Fail safe" cases (documented limits)

These opcodes have no statically decodable length and are deliberately left untouched: the
opcode byte stays undefined (as today) and the rest of the function continues to decode. No
bytes are consumed, so no wrong instruction is invented:

* `resume 0xE3`, `resume_throw 0xE4`, `resume_throw_ref 0xE5` — the trailing handler vector
  (`vec(on <tag> <label> | on <tag> switch)`, see wasmparser `ResumeTable`) has a
  data-dependent length. Reaching exactness would need one SLEIGH *directive* instruction per
  handler clause (the trick used for `try_table` catch clauses), which is more machinery than
  this workstream should add for three rare opcodes.
* any opcode that is not in the table above (e.g. `0x14 call_ref` / `0x15 return_call_ref`,
  `0xD4`-`0xD6`, `0xE7`+, unassigned `0xFC`/`0xFD`/`0xFE` sub-opcodes): the Java walker logs
  `Illegal opcode 0xNN ... (operand length unknown; not consuming following bytes)` and
  consumes nothing. Probe `12_call_ref` of the frozen baseline demonstrates exactly this
  behaviour and is unchanged (see §5): `0x14` stays undefined, the following `unreachable`
  and `end` still decode.
  This is the deliberate reading of the brief's "where a length is genuinely unknown, prefer
  failing safe"; it is also what keeps probes 05/12 at their recorded metrics.
* `flag != 0` memargs whose alignment LEB is *non-minimal* (e.g. `0xC0 0x00` = value 64):
  the Java side follows the spec's value-based rule and reads a memidx, but the SLEIGH
  `memalign_mem` only matches the single-byte form `0x40..0x7F`. Such encodings are not
  produced in practice (the flagged value range is exactly `2^6 <= n < 2^7`, which is a
  single byte when encoded minimally).

### 2.3 Stack model after an `unimplemented` instruction

The unmodelled instruction has no stack effect, so the value stack from there on is a guess.
The walker therefore:

* tolerates a stack underflow / type mismatch (`popValue`) and a leftover operand at a block
  end (`popBlock`) once the function contains such an instruction (`hasUnimplementedOps`),
* degrades an *unknown* operand width to 32-bit (`ContextRegister.setOperandSize`,
  `degradeWidths`) instead of leaving the disassembler an inherited `ctx_operand_size`,
* wraps the per-opcode step in a `ValidationException` handler that logs
  (`Ignoring validation error after an unimplemented instruction ...`) and keeps walking;
  rethrowing is preserved when no unmodelled instruction was seen, which is why probe `05`
  (memory64, a genuine type mismatch with no unknown opcode) still blanks its body exactly as
  recorded. A progress guard prevents a runaway loop.

Probe `A10` shows this: `cont.new; i32.add; i32.const 1; drop; end` (the `i32.add` underflows)
still disassembles (`instrs=6`, `undefined_bytes=0`) and decompiles.

---

## 3. R1.4 — multi-memory

### 3.1 Memarg decoding

`memarg ::= align:u32 offset:u64` (no memory index) if `align < 2^6`, and
`flags:u32 memidx:u32 offset:u64` if `2^6 <= flags < 2^7` (core spec,
`binary/instructions.html#binary-memarg`).

* Java: `readMemarg()` replaces the old "two LEBs" pairs in `memoryLoad`/`memoryStore`, the
  SIMD lane/zero loads and stores, and the `0xFE` atomic group. It reads the flags, reads a
  memidx when `flags >= 0x40 && flags < 0x80` (the spec's value-based rule, matching
  wasmparser), then reads the offset.
* SLEIGH: `memalign` (unflagged: single byte with bit 6 clear, plus multi-byte LEBs) and
  `memalign_mem` (flagged: single byte with bit 6 set and bit 7 clear, the display shows the
  alignment *without* the flag) are disjoint by construction, so the two-entry `loadaddr`,
  `storeaddr`, `loadaddr2` and `atomicaddr3` tables cannot both match a memarg. The
  instruction list itself (`:i32.load loadaddr`, `:v128.load loadaddr`, `:i32.atomic.load
  loadaddr`, ...) is untouched - the operand tables absorb the new form.

Result: probe `06` lists
`i32.load align=0x2 memidx=0x1 offset=0x0` (no `align=0x42`, no spurious `unreachable`), and
`i32.load8_u ... memidx=0x0` (the flagged encoding with memory 0) also decodes correctly.
`memory.size/grow/copy/init/fill` already carried a memidx operand and are unchanged.

### 3.2 Address scheme and limits

Linear memory `N` is mapped into the existing `ram` space at

```
address = N * MEMORY_STRIDE + offset        MEMORY_STRIDE = 0x10000000 (256 MiB)
```

* `N = 0` ⇒ offset 0, i.e. memory 0 keeps its address, byte for byte, as before. This is why
  the C-stack/heap analysis, the data-segment loading and the 437-function regression are
  unaffected.
* The SLEIGH address computation is `memoffset + sp + memidx * MEMORY_STRIDE`, so a memory
  index of 0 (legal, if unusual, in the flagged form) also computes the right address, and no
  new address space / `.pspec` / `.ldefs` change was necessary.
* `WasmLoader.getMemoryAddress()` now handles every index; `loadMemories()` creates
  `.memory0`, `.memory1`, ... and `loadDataSegments()` no longer skips `memidx != 0`.
* Limits (documented, not enforced):
  - indices `0..7` stay below `WasmLoader.CODE_BASE` (0x80000000), where the module image
    lives; memory 8+ would collide with it,
  - a single memory should be ≤ 256 MiB: memories ≥ 1 are clamped to `MEMORY_STRIDE` for that
    reason, but memory 0 keeps its historical clamp (`CODE_BASE`, 2 GiB), so a *huge* memory 0
    (initial > 256 MiB) can still overlap memory 1's region. Such a module is rejected by
    Ghidra's block creation with an error log rather than silently overlapped,
  - `WasmLoader.MEMORY_STRIDE` and `@define MEMORY_STRIDE` (WebAssembly.sinc) must stay in
    sync (both carry a comment saying so),
  - the `memory.copy` pcode injection ignores the two memidx operands; since both source and
    destination are already translated to ram addresses, a same-memory copy is correct, while
    a cross-memory copy is modelled as a plain `memcpy` between two ram regions.
  - memory64 is untouched (baseline probe `05` unchanged); addresses stay 32-bit.

---

## 4. New probes (`test-scripts/probes_analysis.py`, prefix `A`)

| # | Probe | What it pins |
| --- | --- | --- |
| A01 | `mm_scalar_memarg` | i32/i64/f32/f64 loads, `i32.load8_u`, i32/i64 stores with `memidx=1`, and the flagged form with `memidx=0` |
| A02 | `mm_simd_atomic_memarg` | `v128.load`, `v128.load8_lane` and `i32.atomic.load` with `memidx=1` |
| A03 | `mm_memory_ops` | `memory.init`/`memory.copy`/`memory.fill` with a non-zero memidx |
| A04 | `mm_three_memories` | memories 0..2, block sizes via `PROBE-BLOCK`, loads from memory 1 and 2 |
| A05 | `unimp_cont_new` | `0xE0` (stack switching, 1 immediate) → `unimplemented 0xe0 cont.new type=0x0` |
| A06 | `unimp_string_new_utf8` | `0xFB 0x80` (JS string builtin, 1 immediate) → `unimplemented 0xfb:128 string.new_utf8 memidx=0x0` |
| A07 | `unimp_memory_discard` | `0xFC 0x12` (1 immediate) → `unimplemented 0xfc:18 memory.discard memidx=0x0` |
| A08 | `unimp_cont_bind` | `0xE1` (2 immediates) → `unimplemented 0xe1 cont.bind type=0x0 type2=0x0` |
| A09 | `unimp_mul_wide_u` | `0xFC 0x16` (no immediate) → `unimplemented 0xfc:22 i64.mul_wide_u` |
| A10 | `unimp_then_stack_error` | an unimplemented instruction whose unknown stack effect makes the next instruction (`i32.add`) invalid: the body must still disassemble and decompile |

A05-A10 each continue with `i32.const 1; drop; end`, so a wrong operand length shows up
immediately as a spurious instruction or as `undefined_bytes > 0`.

---

## 5. Evidence (exact commands and observed output)

### 5.1 Build / install

```powershell
& D:\code\ghidra-wt-k\test-scripts\build-install.ps1 `
    -GhidraDir "C:\Users\micro\AppData\Local\Temp\ghidra-k"
# BUILD SUCCESSFUL; installed: ghidra-wt-k
```

Note for the integrator: do not pipe `build-install.ps1` through
`Select-Object -First N` - PowerShell then cancels the script after the Nth output line and
the install step never runs (this cost me one debugging cycle; a SLEIGH compile error that
"reappeared" was simply a stale extension copy).

SLEIGH diagnostics can be reproduced in isolation (~10 s) with

```powershell
& "$GhidraDir\support\sleigh.bat" -c WebAssembly.slaspec   # in a copy of data/languages
# no ERROR lines; the only warnings are the pre-existing NOP/unreferenced-table ones and
# the pre-existing VectorOps.sinc:88 'shuf0'/'shuf1' operand collision
```

### 5.2 Probes

```powershell
& D:\code\ghidra-wt-k\test-scripts\run_probes.ps1 `
    -OutDir "C:\Users\micro\AppData\Local\Temp\probes-k-final2" `
    -GhidraDir "C:\Users\micro\AppData\Local\Temp\ghidra-k" `
    -Generators gen_feature_probes.py,probes_analysis.py
```

Probe `06` (the R1.4 acceptance probe):

```
before (base 1e2328b)                                 after
PROBE 06_multi_memory.wasm funcs=1 instrs=7           PROBE 06_multi_memory.wasm funcs=1 instrs=6
      undefined_bytes=0 decompiled=1/0                        undefined_bytes=0 decompiled=1/0
PROBE-BLOCK 06_multi_memory.wasm .memory0 size=65536  PROBE-BLOCK 06_multi_memory.wasm .memory0 size=65536
                                                      PROBE-BLOCK 06_multi_memory.wasm .memory1 size=65536
function f @ ram:80000025 int f(void)                 function f @ ram:80000025 int f(void)
ram:80000025  .locals                                  ram:80000025  .locals
ram:80000026  i32.const 0x0                            ram:80000026  i32.const 0x0
ram:80000028  i32.load align=0x42 offset=0x1           ram:80000028  i32.load align=0x2 memidx=0x1 offset=0x0
ram:8000002b  unreachable            <- spurious       ram:8000002c  memory.size 0x1
ram:8000002c  memory.size 0x1                          ram:8000002e  i32.add
ram:8000002e  i32.add                                  ram:8000002f  end
ram:8000002f  end
```

Probe `18` (the other improved probe):

```
PROBE 18_shared_then_plain_memory.wasm funcs=1 instrs=3 undefined_bytes=0 decompiled=1/0
PROBE-BLOCK 18_shared_then_plain_memory.wasm .memory0 size=65536
PROBE-BLOCK 18_shared_then_plain_memory.wasm .memory1 size=458752      # = 7 pages
```

New probes (all `undefined_bytes=0`, all `decompiled=1`, `funcs=1`):

```
PROBE A01_mm_scalar_memarg.wasm        instrs=25 undefined_bytes=0
PROBE-BLOCK A01_mm_scalar_memarg.wasm .memory0 size=65536
PROBE-BLOCK A01_mm_scalar_memarg.wasm .memory1 size=65536
PROBE A02_mm_simd_atomic_memarg.wasm   instrs=12 undefined_bytes=0
PROBE A03_mm_memory_ops.wasm           instrs=14 undefined_bytes=0
PROBE A04_mm_three_memories.wasm       instrs=7  undefined_bytes=0
PROBE-BLOCK A04_mm_three_memories.wasm .memory0 size=65536
PROBE-BLOCK A04_mm_three_memories.wasm .memory1 size=131072
PROBE-BLOCK A04_mm_three_memories.wasm .memory2 size=196608
PROBE A05_unimp_cont_new.wasm          instrs=5  undefined_bytes=0
PROBE A06_unimp_string_new_utf8.wasm   instrs=5  undefined_bytes=0
PROBE A07_unimp_memory_discard.wasm    instrs=5  undefined_bytes=0
PROBE A08_unimp_cont_bind.wasm         instrs=5  undefined_bytes=0
PROBE A09_unimp_mul_wide_u.wasm        instrs=5  undefined_bytes=0
PROBE A10_unimp_then_stack_error.wasm  instrs=6  undefined_bytes=0
```

Listings that matter (`run_probes.ps1 ... -Only <name> -Detail`):

```
A01  function f @ ram:80000026 int f(undefined4 param1)
       ram:80000029  i32.load align=0x2 memidx=0x1 offset=0x0
       ram:8000002f  i64.load align=0x3 memidx=0x1 offset=0x0
       ram:80000036  i32.load8_u align=0x0 memidx=0x1 offset=0x0
       ram:8000003d  f32.load align=0x2 memidx=0x1 offset=0x0
       ram:80000044  f64.load align=0x3 memidx=0x1 offset=0x0
       ram:8000004d  i32.store align=0x2 memidx=0x1 offset=0x0
       ram:80000055  i64.store align=0x3 memidx=0x1 offset=0x0
       ram:8000005b  i32.load8_u align=0x0 memidx=0x0 offset=0x0   <- flagged memidx=0 form

A02  ram:80000028  v128.load align=0x4 memidx=0x1 offset=0x0
     ram:80000042  v128.load8_lane align=0x0 memidx=0x1 offset=0x0 0x0
     ram:8000004b  i32.atomic.load align=0x2 memidx=0x1 offset=0x0

A03  ram:8000002e  memory.init 0x0 0x1
     ram:80000038  memory.copy 0x1 0x0
     ram:80000042  memory.fill 0x1

A04  ram:8000002b  i32.load align=0x2 memidx=0x2 offset=0x0
     ram:80000031  i32.load align=0x2 memidx=0x1 offset=0x0

A05  ram:8000001e  unimplemented 0xe0 cont.new type=0x0
     ram:80000020  i32.const 0x1 / ram:80000022  drop / ram:80000023  end

A06  ram:8000001e  unimplemented 0xfb:128 string.new_utf8 memidx=0x0
     ram:80000022  i32.const 0x1 / ... / end

A07  ram:8000001e  unimplemented 0xfc:18 memory.discard memidx=0x0
     ram:80000021  i32.const 0x1 / ... / end

A08  ram:8000001e  unimplemented 0xe1 cont.bind type=0x0 type2=0x0
     ram:80000021  i32.const 0x1 / ... / end

A09  ram:8000001e  unimplemented 0xfc:22 i64.mul_wide_u
     ram:80000020  i32.const 0x1 / ... / end

A10  ram:8000001e  unimplemented 0xe0 cont.new type=0x0
     ram:80000020  i32.add              <- invalid before the change; body is kept
     ram:80000021  i32.const 0x1 / drop / end
     (warning: "Unimplemented opcode 0xe0 (stack switching) at ram:8000001e
                 (operands skipped, no semantics modelled)")
```

Frozen baseline 01-27 after the change (identical to `MODERN_WASM_GAPS.md` §2.4/§2.5 except
06/18, which improve as shown above):

```
05_memory64            funcs=1 instrs=1 undefined_bytes=6 decompiled=1/0   (unchanged, out of scope)
08_gc_struct_type      funcs=1 instrs=2 undefined_bytes=0
09_gc_struct_new       funcs=1 instrs=4 undefined_bytes=0
10_eh_legacy_try_catch funcs=1 instrs=6 undefined_bytes=0
11_eh_try_table        funcs=1 instrs=4 undefined_bytes=0
12_call_ref            funcs=1 instrs=4 undefined_bytes=1 decompiled=1/0   (unchanged: 0x14 is a
                       fail-safe unknown, see §2.2)
13_tail_call ... 27_extconst_data_offset: all as recorded
19/20 import (no functions), 21_component_model still fails to import (by design)
```

### 5.3 Real-module regression

```powershell
& "$GhidraDir\support\analyzeHeadless.bat" "$GhidraDir\proj" Reg `
  -import "D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm" `
  -scriptPath "D:\code\ghidra-wt-k\test-scripts" -postScript DumpDecomp.java -max-cpu 2 -deleteProject

SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156
```

`instructions=61658` is bit-for-bit the recorded number, i.e. the new SLEIGH patterns did not
shadow any existing decode in a real module. (The `$GhidraDir\proj` directory must exist;
`analyzeHeadless` aborts with "Directory not found" otherwise.)

---

## 6. What is not finished / known gaps

1. `resume`/`resume_throw`/`resume_throw_ref` are fail-safe unknowns (handler vector, §2.2).
2. No `unimplemented` rendering for opcodes with unknown operand length; their byte stays
   undefined (that is what keeps baseline probes 05/12 intact). If the integrator prefers
   "render every unknown byte as `unimplemented` of length 1", it is a two-line change in the
   two `default:` branches (call `markUnimplemented()` + a length-1 pattern), but it moves
   probe `12` from `(instrs=4, undefined=1)` to `(5, 0)`.
3. `0xFD`/`0xFE` sub-opcodes beyond the known ranges have no length table (nothing in the
   brief, no length source), so they remain fail-safe.
4. Memory indices ≥ 8, memories larger than 256 MiB and memory 0 above 256 MiB can overlap
   another region (§3.2). A dedicated `memory` address space (like `table`) would remove the
   limit but was rejected here because memory 0 must keep its exact current placement and the
   `.pspec`/cspec userops would have to learn a second space.
5. Multi-memory `memory.copy`/`init`/`fill`: the decoded listing is correct, but the pcode
   injection of `memory_copy` ignores the memidx operands (§3.2, last bullet).

## 7. Cross-workstream hooks

* Function references (0x14/0x15, 0xD4-0xD6) is explicitly *not* touched: `WasmSignatureAnalyzer`/
  `call_ref` remain the other workstream's item, and baseline probe `12` keeps its metric.
  Whoever adds it will very likely drop `undefined_bytes` in probe 12 from 1 to 0 - expected,
  and outside this report's acceptance.
* The constant-expression scanner (integrator-owned) is untouched. If it should also skip
  these proposal opcodes, the length table now exists twice (`skipUnimplementedOperands` in
  `WasmFunctionAnalysis` and the `:unimplemented` constructors); a shared Java helper would
  be the clean way, but it would have to live in a file this workstream does not own.
* `WasmLoader.MEMORY_STRIDE` (Java) and `@define MEMORY_STRIDE` (SLEIGH) are the only two
  places that know the multi-memory layout; keep them in sync.
