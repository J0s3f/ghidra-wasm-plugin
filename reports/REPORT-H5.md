# REPORT-H5 — real semantics for the last `unimplemented` opcode group

Worktree: `D:\code\ghidra-wt-h5`, branch `feat/stackswitch-strings`, base `main` @ `c3a7bc2`.
Ghidra 12.1.4 (`C:\Users\micro\AppData\Local\Temp\ghidra-h5`, pinned via
`test-scripts/.ghidra-install`), Gradle 9.2.1, PowerShell 7, Python 3.14.

Scope: give the opcodes that used to decode as `unimplemented` a real instruction, a real operand
list and a modelled stack effect, so the decompiler shows the operation and its result:

* stack switching / JSPI — `cont.new` (0xE0), `cont.bind` (0xE1), `suspend` (0xE2), `resume` (0xE3),
  `resume_throw` (0xE4), `resume_throw_ref` (0xE5), `switch` (0xE6);
* JS string builtins / stringref — every assigned sub-opcode of `0xFB 0x80..0xB7` (plus the
  unassigned ones as visible `unimplemented ... (reserved)`);
* wide arithmetic — `i64.add128` / `i64.sub128` / `i64.mul_wide_s` / `i64.mul_wide_u`
  (`0xFC 0x13..0x16`);
* `memory.discard` (`0xFC 0x12`).

The graceful `unimplemented` fallback is kept for everything else (see §7).

---

## 1. Headline results

| Check | Result |
| --- | --- |
| New probes (`probes_stackswitch.py`, `probes_strings.py`) | 20 probes, all `undefined_bytes=0`, all functions decompiled (`decompile_failed=0`) |
| `probes_analysis.py` A05-A09 (were `unimplemented`) | now show the real mnemonics; **metrics unchanged** (instrs 5/5/5/5/5) |
| `probes_analysis.py` A10 | also unchanged (instrs 6) — the relaxed-validation fallback still covers it |
| Frozen 136-probe baseline | **0 changed entries**; only 20 additions (my new files) |
| Baseline count | 136 → 156 (`expected-results.json`, regenerated with `-Update`) |
| Fixture (`wasm_fixture.wasm`) | unchanged: `functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0` |
| Real module (`rasterbator_rs_bg.wasm`) | unchanged: `SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156` |
| CI gate | `OK: every probe matches the recorded baseline.` |

---

## 2. Files changed

| File | Change |
| --- | --- |
| `data/languages/StackSwitchOps.sinc` | **new** — the 7 stack-switching instructions + the handler-vector clause directive |
| `data/languages/StringOps.sinc` | **new** — the 0xFB 0x80..0xB7 string instructions (+ reserved sub-opcodes) |
| `data/languages/WideArithOps.sinc` | **new** — `memory.discard` and the four wide-arithmetic instructions |
| `data/languages/WebAssembly.sinc` | removed the now-modelled `:unimplemented` constructors, added `sp4_32`/`sp4_64`, added the three `@include`s |
| `data/languages/WebAssembly.slaspec` | new `ctx_ss_shape` context field (bits 16-19) |
| `src/main/java/wasm/analysis/WasmFunctionAnalysis.java` | real decoding + stack effects for all four groups, the handler-vector walker, `usesProposalOps` relaxation, `skipUnimplementedOperands` trimmed to the true fallbacks |
| `src/main/java/wasm/format/WasmEnums.java` | two placeholder value types (`contref`, `stringref`), width 4 / `Undefined4DataType` |
| `test-scripts/probes_stackswitch.py` | **new** — 10 probes (H01-H10) |
| `test-scripts/probes_strings.py` | **new** — 10 probes (S01-S10) |
| `test-scripts/expected-results.json` | regenerated with `-Update` (20 additions, no other change) |
| `REPORT-H5.md` | this report |

No `.cspec` change was needed (see §5.4). No changes to `WasmLoader.java`, `WasmAnalysis.java`,
`WasmCodeEntry.java`, `ConstantExpression.java`, the section/module classes, `WasmSignatureAnalyzer`,
`GCOps.*`, `EH2Ops.*`, `run_probes.ps1`, `check-local.ps1`, `check-results.py`, `build-install.ps1`,
other `probes_*.py`, `spectest/**`, other reports, `README.md`, `MERGE_NOTES.md`,
`MODERN_WASM_GAPS.md`, `.github/**` or `build.gradle`.

---

## 3. Encodings implemented (and two corrections to the brief)

All encodings were re-checked against the proposals themselves, not taken from the brief:

| Group | Source |
| --- | --- |
| stack switching | `WebAssembly/stack-switching`, `Overview.md` → "Binary format" table |
| JS string builtins / stringref | `WebAssembly/stringref`, `Overview.md` → "Binary encoding" table |
| wide arithmetic | `WebAssembly/wide-arithmetic`, `Overview.md` → "Binary Format" |
| `memory.discard` | `WebAssembly/memory-control`, `discard.md` |

### 3.1 `switch` is 0xE6, and 0xE5 is `resume_throw_ref`

The task text lists `switch (0xE5)`. The authoritative table (and the pre-existing `REPORT-A-DS.md`
§2.1) is:

```
0xE0 cont.new $ct              $ct:u32
0xE1 cont.bind $ct $ct'        $ct:u32 $ct':u32
0xE2 suspend $t                $t:u32
0xE3 resume $ct hdl*           $ct:u32 hdl*
0xE4 resume_throw $ct $e hdl*  $ct:u32 $e:u32 hdl*
0xE5 resume_throw_ref $ct hdl* $ct:u32 hdl*
0xE6 switch $ct1 $t            $ct1:u32 $t:u32
```

So `0xE6` is `switch` and `0xE5` is `resume_throw_ref`; both are modelled. (The brief's own
"handler vector" wording for `resume`/`resume_throw` matches the spec and is implemented — see §3.2.)

### 3.2 The handler vector *is* statically decodable

`REPORT-A-DS.md` §2.2 left `resume`/`resume_throw`/`resume_throw_ref` as fail-safe unknowns because
"the trailing handler vector has no statically decodable length". The vector is in fact a counted
`vec(handler)`:

```
hdl* = vec(clause)
clause = 0x00 tagidx labelidx   (on <tag> <label>)
       | 0x01 tagidx            (on <tag> switch)
```

All three are now decoded exactly. The clause vector is decoded like `try_table`'s catch clauses:
the pre-analyzer consumes the vector and marks each clause's address with a new directive type
(`DIRECTIVE_SS_HANDLER = 6`, `ContextRegister.setSsHandler`), and each clause is its own byte-only
SLEIGH directive (`:.ss_handler`). The continuation body therefore starts exactly after the vector.
The clauses are *not* turned into branch targets — a `suspend` is a run-time event, not a static
branch — but the listing names them.

### 3.3 `memory.discard` takes a bare memidx, not a memarg; two operands, not three

The brief says "`memory.discard` (`0xFC 0x12`, memarg)" and "pops 3 i32". The memory-control
proposal and the reference decoder (wasmparser `visit_0xfc_operator`: `0x12 => read_var_u32()`)
agree on a **bare memidx** immediate and the type `[addr:idx size:idx] -> []`, i.e. **two**
operands. Implementing a memarg or a third pop would mis-read real modules and reject a valid body,
so the spec-correct form is implemented (`A07` and `S07` pin it).

### 3.4 Wide arithmetic is 4×i64 → 2×i64 (not "4 i32 slots")

`i64.add128`/`i64.sub128` : `[i64 i64 i64 i64] -> [i64 i64]` (the two 128-bit operands are
low/high i64 pairs); `i64.mul_wide_s`/`u` : `[i64 i64] -> [i64 i64]`. The stack model uses i64
slots accordingly.

---

## 4. Stack effects modelled in the pre-analyzer

`WasmFunctionAnalysis.java` (`// @@SS/@@STR/@@WA` region) applies the exact effect:

| Opcode | Effect |
| --- | --- |
| `cont.new $ct` | pop `(ref null $ft)` (1 ref); push `contref` |
| `cont.bind $ct $ct'` | pop `(ref null $ct)`; pop `t3*` with `n = |params($ct)| - |params($ct')|`; push `contref` |
| `suspend $t` | pop the tag's parameters; push the tag's results |
| `resume $ct` | pop `(ref null $ct)`; pop `params($ct)`; push `results($ct)` |
| `resume_throw $ct $e` | pop `(ref null $ct)`; pop the tag's parameters; push `results($ct)` |
| `resume_throw_ref $ct` | pop `(ref null $ct)`; pop `exnref`; push `results($ct)` |
| `switch $ct1 $t` | pop `(ref null $ct1)`; pop `params($ct1)`; push the tag's results |
| `string.new_utf8 $m` … | pop `[ptr:address i32]`; push `stringref` |
| `string.const $idx` | push `stringref` |
| `string.measure_*` / `is_usv_sequence` | pop `stringref`; push `i32` |
| `string.encode_* $m` | pop `[stringref ptr:address]`; push `i32` |
| `string.concat` / `string.eq` | pop 2 `stringref`; push `stringref` / `i32` |
| `string.as_wtf8/wtf16/iter` | pop `stringref`; push `stringref` (the view placeholder) |
| `stringview_wtf8.advance` / `slice` | pop `[view i32 i32]`; push `i32` / `stringref` |
| `stringview_wtf8.encode_* $m` | pop `[view ptr:address i32 i32]`; push `i32 i32` |
| `stringview_wtf16.length` / `get_codeunit` / `encode` / `slice` | as the spec table |
| `stringview_iter.next/advance/rewind/slice` | as the spec table |
| `string.*_array` / `string.encode_*_array` | as the spec table |
| `memory.discard $m` | pop `[at(addr) at(size)]` (i32 here) |
| `i64.add128` / `i64.sub128` | pop 4 i64; push 2 i64 |
| `i64.mul_wide_s` / `u` | pop 2 i64; push 2 i64 |

The continuation/`cont.bind` type index is resolved through `WasmAnalysis.getType()`; a `cont`
composite type cannot appear in the type section without a loader change (see §7.1), so the probes
point those indices at ordinary `0x60` function types — the walker then reads the continuation's
parameter/result lists from that function type.

### 4.1 Keeping the frozen A05-A10 probes decoding

A05-A09 were written for the old `unimplemented` fallback and therefore do **not** supply the
operands these instructions consume (e.g. A09 is `i64.mul_wide_u; i32.const 1; drop; end` on an
empty stack). Now that the instructions are modelled, a *valid* module gets exact validation, but
those invalid bodies must still disassemble so the probes show the real mnemonics with unchanged
metrics. This uses the same graceful-degradation idea as the existing `hasUnimplementedOps`: the
first proposal instruction sets a parallel `usesProposalOps` flag, which relaxes underflow, type
mismatch and a leftover operand at a function's `end` (see `popValue`, `popBlock`) — **without**
marking the instruction `unimplemented`, so the listing shows the real mnemonic. All six metrics are
therefore unchanged (see §5.1). The exact effect is still applied, so a valid module validates
exactly as before.

---

## 5. Pcode

Each instruction emits one dedicated `callother`, named after the operation, with declared
inputs/outputs that mirror the modelled stack effect:

```
define pcodeop wasm_cont_new; wasm_cont_bind; wasm_suspend; wasm_resume;
                wasm_resume_throw; wasm_resume_throw_ref; wasm_switch;
                memory_discard; i64_add128; i64_sub128; i64_mul_wide_s; i64_mul_wide_u;
                string_new_utf8; ...; sv_wtf8_encode_utf8; ...; string_encode_wtf8_array;
```

### 5.1 Evidence: A05-A10 before / after

`A05`-`A09` used to render `unimplemented ...`; now they render the real instruction. Metrics are
identical (the `unimplemented` text lives only in the listing).

```
before (base c3a7bc2)                          after
A05 ram:8000001e unimplemented 0xe0 cont.new   A05 ram:8000001e cont.new type=0x0
A06 ram:8000001e unimplemented 0xfb:128 ...    A06 ram:8000001e string.new_utf8 memidx=0x0
A07 ram:8000001e unimplemented 0xfc:18 ...     A07 ram:8000001e memory.discard memidx=0x0
A08 ram:8000001e unimplemented 0xe1 cont.bind  A08 ram:8000001e cont.bind type=0x0 type2=0x0
A09 ram:8000001e unimplemented 0xfc:22 ...     A09 ram:8000001e i64.mul_wide_u
A10 ram:8000001e unimplemented 0xe0 ...        A10 ram:8000001e cont.new type=0x0
    ram:80000020 i32.add                           ram:80000020 i32.add
```

Probe metrics before/after (from `expected-results.json`, unchanged):

```
A05 funcs=1 instrs=5 undefined_bytes=0 decompiled=1   (unchanged)
A06 funcs=1 instrs=5 undefined_bytes=0 decompiled=1   (unchanged)
A07 funcs=1 instrs=5 undefined_bytes=0 decompiled=1   (unchanged)
A08 funcs=1 instrs=5 undefined_bytes=0 decompiled=1   (unchanged)
A09 funcs=1 instrs=5 undefined_bytes=0 decompiled=1   (unchanged)
A10 funcs=1 instrs=6 undefined_bytes=0 decompiled=1   (unchanged)
```

### 5.2 Variable-arity operations and `ctx_ss_shape`

`resume`/`resume_throw`/`resume_throw_ref`/`switch`/`suspend`/`cont.bind` have type-dependent
arity. The pre-analyzer always applies the *exact* effect; the callother signature is selected by a
new 4-bit context field `ctx_ss_shape` (bits 16-19), which encodes `p*2+r` with p/r the modelled
parameter/result counts (each clamped to 0/1). Every op therefore has up to four SLEIGH variants
plus the byte layout is identical across them, so **an unsupported arity never leaves bytes
undefined** — it just degrades the callother's signature to ≤1 param / ≤1 result (documented limit).

### 5.3 Evidence: listings + decompiled C

```
H02 ram:8000002a cont.new type=0x1
    ram:8000002c cont.bind type=0x1 type2=0x0

H05 ram:8000002f cont.new type=0x0
    ram:80000031 resume type=0x0 handlers=0x2
    ram:80000034 .ss_handler on tag=0x0 label=0x0
    ram:80000037 .ss_handler on tag=0x1 switch

S07 ram:8000002b i64.add128
    ram:80000037 i64.sub128
    ram:8000003f i64.mul_wide_s
    ram:80000047 i64.mul_wide_u
    ram:8000004f memory.discard memidx=0x0

S09 ram:80000021 unimplemented 0xfb:143 string (reserved)
    ram:80000025 unimplemented 0xfb:158 string (reserved)
```

Decompiled C (`DumpAll.java`):

```c
// H10_ss_resume_result.wasm — the resume result reaches the caller (shape p=1,r=1)
int export::f(void) {
  undefined4 uVar2 = wasm_cont_new(1,0x8000002c);
  int iVar1 = wasm_resume(1,3,uVar2);
  return iVar1;
}

// S10_str_encode_units.wasm — both results of one callother (8-byte output split into 2 i32)
int export::f(void) {
  undefined4 uVar2 = string_const(0);
  uVar2 = string_as_wtf8(uVar2);
  undefined8 uVar1 = sv_wtf8_encode_utf8(0,uVar2,0,0,4);
  return (int)uVar1 + (int)((ulonglong)uVar1 >> 0x20);
}

// S07_wide_memdiscard.wasm
i64_add128(1,0,2,0);
i64_sub128(5,0,1,0);
i64_mul_wide_s(6,7);
i64_mul_wide_u(6,7);
memory_discard(0,0,0x10);
```

SLEIGH cannot assign two outputs from one callother, so the two i32 results of the
`stringview_wtf8.encode_*` family and the two i64 halves of a 128-bit wide-arithmetic result come
from a single packed (8- or 16-byte) callother output that is then split — S10 above shows both
halves reaching the caller.

### 5.4 No `.cspec` change was needed

The task says to add callother names to the `.cspec` fixups "as needed". It was not needed: the
decompiler renders an undeclared `callother` by its `define pcodeop` name, exactly as the existing
GC ops (`struct_new`, `array_get`, …) already do without cspec entries — and the evidence above
shows the names, inputs and results. Adding a `<callotherfixup>` would have to carry a `<pcode>`
body and would *inject* pcode rather than declare the op, changing behaviour for no benefit.

---

## 6. Value types

`WasmEnums.ValType` gained one contiguous, commented block:

```java
contref(0x68),   // (ref null $ct): continuation reference (stack switching)
stringref(0x67); // stringref / stringview_*: JS string builtins reference
```

Both are 4-byte opaque references (`getSize()` → 4, `asDataType()` → `Undefined4DataType`,
`isReferenceType()` → true), like the other reference types, so `getSize()`/`asDataType()` stay
total. The byte values are internal placeholders: the type-section reader never produces them
(0x63/0x64 remain the GC `(ref null ht)/(ref ht)` prefixes; the stringref draft's 0x64 spelling
collides with that prefix, so 0x67 is used). `stringview_wtf8/wtf16/iter` results reuse the
`stringref` placeholder.

---

## 7. Deliberately left as `unimplemented` / known limits

1. **`cont` composite type (0x5D) in the type section.** `WasmGCType.parseSubType` throws
   `unsupported wasm type form 0x5d`, so a module whose type section really contains `(cont $ft)`
   fails to import. Fixing that is a `WasmGCType`/`WasmTypeSection` change outside this workstream's
   ownership, so the continuation opcodes' type indices are resolved as ordinary function types
   (§4). This is the only place where the model is not byte-faithful to the proposal.
2. **Unassigned `0xFB` sub-opcodes outside `0x80..0xB7`** (`0xB8..0xBF`), unassigned `0xFB < 0x80`,
   `0xE7`+, and unassigned `0xFC`/`0xFD`/`0xFE` sub-opcodes: the operand length is genuinely
   unknown, so nothing is consumed ("fail safe"): the byte stays undefined and the rest of the
   function still decodes. `skipUnimplementedOperands` was trimmed to exactly these cases.
3. **Unassigned sub-opcodes inside `0x80..0xB7`** (`0x8F`, `0x96`, `0x97`, `0x9D`-`0x9F`,
   `0xA5`-`0xAF`) are decoded as `unimplemented 0xfb:NN string (reserved)` with no immediates, so
   literally every byte in the stringref range decodes (probe `S09`).
4. **Callother signature arity** is modelled up to 1 parameter and 1 result (§5.2); larger arities
   keep the exact stack walk but show a reduced callother signature.
5. **memory64 address operands** of `memory.discard` and the memory-taking string ops are modelled
   as i32 (a 64-bit memory index degrades to 32-bit for these instructions only).
6. **Continuation/tag semantics are not a runtime**: references are opaque 4-byte values, nothing is
   allocated or suspended, and the handler clauses are not branch targets (§3.2). This matches the
   project's stated goal ("a faithful signature is the goal, not a runtime").

---

## 8. New probes

`test-scripts/probes_stackswitch.py` (H) and `test-scripts/probes_strings.py` (S). All 20 import
with `undefined_bytes=0`, all functions decompile.

```
H01_ss_cont_new          funcs=2 instrs=7  u=0 d=2      S01_str_const_concat_eq     funcs=1 instrs=10 u=0 d=1
H02_ss_cont_bind         funcs=2 instrs=9  u=0 d=2      S02_str_new_measure_encode  funcs=1 instrs=46 u=0 d=1
H03_ss_suspend           funcs=1 instrs=5  u=0 d=1      S03_str_view_wtf8           funcs=1 instrs=41 u=0 d=1
H04_ss_resume            funcs=2 instrs=8  u=0 d=2      S04_str_view_wtf16          funcs=1 instrs=27 u=0 d=1
H05_ss_resume_handlers   funcs=2 instrs=11 u=0 d=2      S05_str_view_iter           funcs=1 instrs=24 u=0 d=1
H06_ss_resume_throw      funcs=2 instrs=9  u=0 d=2      S06_str_arrays              funcs=1 instrs=42 u=0 d=1
H07_ss_resume_throw_ref  funcs=2 instrs=9  u=0 d=2      S07_wide_memdiscard         funcs=1 instrs=29 u=0 d=1
H08_ss_switch            funcs=2 instrs=7  u=0 d=2      S08_strings_mixed           funcs=1 instrs=25 u=0 d=1
H09_ss_mixed             funcs=3 instrs=28 u=0 d=3      S09_str_reserved            funcs=1 instrs=9  u=0 d=1
H10_ss_resume_result     funcs=2 instrs=9  u=0 d=2      S10_str_encode_units        funcs=1 instrs=9  u=0 d=1
```

* `H01`-`H08`: one valid module per stack-switching opcode family (cont.new, cont.bind with a
  bound prefix, suspend with a `[i32]->[i32]` tag, resume, resume with both clause kinds,
  resume_throw, resume_throw_ref, switch), each followed by ordinary code.
* `H09`/`S08`: the "mixing them with ordinary code" probes (arithmetic interleaved with the new
  ops, so a mis-sized immediate or a mis-consumed handler vector shows up as a spurious instruction
  or undefined bytes).
* `H10`/`S10`: prove the callother's *result* reaches the caller.
* `S01`-`S06`: every assigned string sub-opcode; `S07`: wide arithmetic + memory.discard;
  `S09`: the reserved sub-opcodes; `S10`: the two-result encode.
* `string.const` probes carry a small stringrefs section (id 14, `0x00 vec(vec(u8))`). The loader
  skips unknown section ids cleanly, so the module still imports.

---

## 9. Exact commands and observed output

Build / install:

```powershell
cd D:\code\ghidra-wt-h5
& .\test-scripts\build-install.ps1          # pinned to ...\ghidra-h5
# BUILD SUCCESSFUL; installed: ghidra-wt-h5
```

SLEIGH diagnostics in isolation (`data/languages` copied to a scratch dir):

```powershell
& "$GhidraDir\support\sleigh.bat" -c WebAssembly.slaspec
# 0 ERROR lines; 15 WARN lines, all pre-existing (NOP constructors, the VectorOps.sinc:88
# shuf0/shuf1 collision, unreferenced opc2_* tables). No warning mentions the new files.
```

New probes:

```powershell
& .\test-scripts\run_probes.ps1 -OutDir "$env:TEMP\probes-h5" `
    -Generators gen_feature_probes.py,probes_analysis.py,probes_stackswitch.py,probes_strings.py -Detail
```

Baseline regeneration + gate (the acceptance commands):

```powershell
$env:GHIDRA_INSTALL_DIR = "C:\Users\micro\AppData\Local\Temp\ghidra-h5"
& .\test-scripts\check-local.ps1 -OutDir "$env:TEMP\ci-h5" -Update `
    -RealModule "D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm"
# 156 probe(s): 151 with metrics, 5 expected import failures
# fixture: functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0
# real   : functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156

& .\test-scripts\check-local.ps1 -OutDir "$env:TEMP\ci-h5-verify" `
    -RealModule "D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm"
# probes: 151 imported, 5 import failure(s); baseline has 156
# OK: every probe matches the recorded baseline.
```

(`check-local.ps1` reads `GHIDRA_INSTALL_DIR`; `build-install.ps1`/`run_probes.ps1` enforce the
`.ghidra-install` pin. The real-module `SUMMARY` line is bit-identical to the recorded one.)

### 9.1 Baseline entries that changed

**None.** A structural comparison of `expected-results.json` against `HEAD` shows 136 → 156 probes,
20 additions (the H/S probes) and **zero changed entries**; the `real_module` and `fixture` blocks
are byte-identical. In particular A05-A10 kept their exact metrics (§5.1), so requirement 6's
"update those probes only if their metrics change" needed no update at all.

---

## 10. Cross-workstream notes

* `WasmFunctionAnalysis` now owns the handler-vector walker for stack switching. The constant-
  expression scanner (integrator-owned) is untouched; if it should also skip these opcodes it can
  reuse the same length logic, which now lives in one place (`stringBuiltin` +
  `readHandlerVector` + the explicit opcode cases).
* The `cont` composite-type gap (§7.1) is the one thing that would need a change outside this
  workstream's file ownership (`WasmGCType`/`WasmTypeSection`) to make continuation modules fully
  spec-valid.
* `ctx_ss_shape` (bits 16-19) is a new context-register field; it must stay in sync between
  `ContextRegister.REG_SS_SHAPE` and `WebAssembly.slaspec`.
