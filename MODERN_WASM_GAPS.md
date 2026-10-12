# Modern WebAssembly support: inventory, gaps and roadmap

Status of this document: **inventory complete; implementation in progress**. See the status table
below. The inventory was produced from `merged-upstream-prs` (commit `430cbe2`, plugin built against
Ghidra 12.1.4) and is intended as the working base for extending the plugin's coverage toward current
WebAssembly (Wasm 3.0 + active proposals).

| Roadmap item | State |
| --- | --- |
| R1.2 limits flags · R1.3 constant expressions · R1.5 unknown value types | **merged** (`REPORT-B.md`; plus an integrator rewrite of the expression scanner - see §2.5) |
| 5. new exception handling (`try_table`, `throw_ref`, `exnref`) | **merged** (`REPORT-F.md`) |
| 6. garbage collection (type section, `0xFB` instructions, GC initializers) | **merged** (`REPORT-E.md`) |
| 0/1/2 multi-memory + unknown-opcode degradation · 8 memory64 | in flight (decoder/loader workstream) |
| 9. `.name` extras + application | in flight |
| 7. multi-value returns | in flight |
| 10. component model loader | in flight |
| 4. spec-test harness · real-world corpus · CI probe gate · robustness sweep · DWARF line info | queued |

## 1. How this inventory was produced

Two independent sources, so that a claim can always be re-checked:

1. **Code inventory** — the SLEIGH opcode tables (`data/languages/*.sinc`, `WebAssembly.slaspec`), the
   module/section parsers (`src/main/java/wasm/format/**`) and the analyzers
   (`src/main/java/wasm/analysis/**`).
2. **Empirical probes** — 21 hand-encoded modules, one per feature, imported headlessly into Ghidra
   and measured. `test-scripts/gen_feature_probes.py` generates them; `test-scripts/WasmFeatureReport.java`
   reports `funcs/instrs/undefined_bytes/decompiled` per program, `ListProgram.java` prints the
   disassembly and `DumpAll.java` the decompiled C.

Reproduce everything:

```bash
# 1. generate the probe modules
python test-scripts/gen_feature_probes.py /tmp/wasm-probes

# 2. import them all at once and report
args=(); for f in /tmp/wasm-probes/*.wasm; do args+=(-import "$f"); done
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /tmp/wasm-probes/project FeatureProbe "${args[@]}" \
    -scriptPath test-scripts -postScript WasmFeatureReport.java -deleteProject

# 3. (optional) per-program disassembly / decompilation
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /tmp/wasm-probes/project Detail \
    -import /tmp/wasm-probes/06_multi_memory.wasm -scriptPath test-scripts \
    -postScript ListProgram.java -postScript DumpAll.java -deleteProject
```

`undefined_bytes` is the key metric: a healthy module has `0`. Non-zero means the function body was
not (fully) disassembled at all, which is worse than a wrong mnemonic.

## 2. Coverage summary

### 2.1 Fully working (verified by probe)

| Feature | Probe |
| --- | --- |
| MVP / WebAssembly 1.0, all opcodes | `01` |
| Bulk memory: `memory.init`, `data.drop`, `memory.copy/fill`, `table.*`, data-count section | `07` |
| Reference types v1: `externref` params/globals/tables, `table.get/set/grow/size/fill`, `ref.null/func/is_null`, typed `select` (0x1C) | `02`, `03` |
| Non-trapping float→int conversions (`trunc_sat`, 0xFC 0x00-0x07) | code |
| SIMD (0xFD, all) and relaxed SIMD (0xFD ≥ 0x100) | `14`, `15` |
| Atomics/threads (0xFE: loads, stores, RMW, `wait`/`notify`, `fence`) | `04` |
| Tail calls: `return_call`, `return_call_indirect` | `13` |
| Legacy exception handling: `try`/`catch`/`catch_all`/`throw`/`rethrow`/`delegate`, tag section | `10` |
| Multi-value blocks and type-index blocktypes | `17` |
| Function / global / local names from `.name`; DWARF types | code |

### 2.2 Loads and disassembles, but the result is wrong (highest risk)

| Feature | Symptom | Root cause |
| --- | --- | --- |
| Multi-memory (memarg `memidx`) | `i32.load align=0x42 offset=0x1` plus a spurious `unreachable`; instruction boundaries shift | alignment bit 6 (`0x40`) is not interpreted; only two LEB fields are read (`loadaddr`/`storeaddr`/`loadaddr2`/`atomicaddr3` in the `.sinc` files, `readLeb128` pairs in `WasmFunctionAnalysis.java`) |
| Multi-memory (loading) | only `.memory0` is created; `(memory 1)(memory 7)` loses the second memory entirely | the loader deliberately refuses non-zero memory indices: `WasmLoader.getMemoryAddress()` throws for `memidx != 0` and `loadMemories()` `continue`s past them (tables *do* support multiple indices, via the `table` address space) |
| memory64 | Pre-analyzer aborts: `Validation error … pop type mismatch: got i64, expected i32` → body undefined (probe `05`: 1 instr, 6 undefined bytes) | address operands are hardwired to 32-bit (`sp1_32`); the index type is unknown; memory blocks are additionally clamped to `CODE_BASE` (0x80000000) in `WasmLoader`, which cannot represent ≥ 2 GiB memories |
| Shared / 64-bit / custom-page-size limits | shared/`maximum`/index-type fields are dropped from the parsed limits, and a following limits entry desyncs | `WasmResizableLimits` only reads a `maximum` when `flags == 1` (shared = 3, memory64 = 4/5, page-size = 8) |
| Multi-value returns | `(func (result i32 i32))` becomes `int f(void)`; extra results disappear, callers drop into nothing | `WasmSignatureAnalyzer` still has upstream's `TODO handle multiple returns`; only `returns[0]` is applied |
| GC `struct`/`array` type entries | type section loads, but a `0x5F` struct is parsed as a function type (form byte read, value ignored) | `WasmFuncType` assumes `0x60`; `WasmTypeSection` has no `rec`/`sub`/`struct`/`array` handling |
| `.name` subsections | label (3) explicitly `TODO`; field (10)/tag (11) become `WasmNameUnknownSubsection`; type/table/memory/elem/data names are parsed but never applied to symbols | `WasmNameSubsection.createSubsection`, `WasmLoader` (only function/global/local names are applied) |

### 2.3 Not supported (function body undefined, or import fails)

| Feature (proposal) | Symptom | Class |
| --- | --- | --- |
| New exception handling: `try_table` (0x1F), `throw_ref` (0x0A), `exnref` (0x69), `catch_ref` clauses | `Validation error … pop from empty stack`; body undefined (probe `11`: 1 instr, 5 undefined bytes) | analysis failure |
| Typed function references: `(ref null $t)` / `(ref $t)`, `call_ref` (0x14), `return_call_ref` (0x15), `br_on_null`, `br_on_non_null`, `ref.as_non_null` | `NullPointerException` in `WasmSignatureAnalyzer` (`ValType.asDataType()` on `null`), then `ValType.getSize()` NPE inside the decompiler process → **decompilation fails entirely** (probe `12`) | crash |
| GC instructions (0xFB): `struct.*`, `array.*`, `i31.*`, `ref.test/cast`, `br_on_cast*`, `any/extern.convert_*` | `0xFB` is not an opcode in any table; desync (probe `09`: 1 undefined byte) | decode gap |
| Extended-const constant expressions (`i32.add` etc. in globals/offsets) | **Import fails**: `IllegalArgumentException: Missing end byte` (probe `19`) | hard load failure |
| GC constant expressions (`struct.new`, `ref.i31` in globals/offsets) | **Import fails**: `Invalid instruction opcode 251 in constant expression` for an inline `0xFB` opcode, or `… opcode 0 …` once a 2-byte `(ref 0)` valtype precedes it (the valtype is unhandled so the initializer parse is misaligned) — probe `20` | hard load failure |
| Custom page sizes (`memory.discard`), wide arithmetic | `0xFC` coverage stops at sub-opcode `0x11` | decode gap |
| Stack switching / JSPI (`cont.new`, `cont.bind`, `suspend`, `resume`, `switch`, contref types) | no mnemonics (Emscripten `-sASYNCIFY=2` emits this) | decode gap |
| JS string builtins / stringref (`string.new_utf8`, `string.concat`, …) | no mnemonics (0xFB ≥ 0x80) | decode gap |
| Shared-everything threads (shared tables/globals, `global.atomic.*`) | no mnemonics; also blocked by the limits bug | decode gap |
| Component model binaries | **Import fails**: `No load spec found` — loader requires core-module version 1 (probe `21`) | loader gap |

Probe expectations for regression testing live in `test-scripts/gen_feature_probes.py`; each roadmap
item below names the probes that must change when it is finished.

### 2.4 Observed baseline (reproducible with the commands above)

Recorded on the Ghidra 12.1.4 build of commit `430cbe2`; `u=` is `undefined_bytes`, `d=` is
`decompiled/failed`. Use this as the before-picture when implementing a roadmap item.

Note: probe `20` was hardened after the first inventory — it is now a spec-valid module
(`(global (ref 0) (struct.new 0))`); the earlier revision was missing the heap-type byte of the
`(ref 0)` valtype, which made the parser report a different opcode. Re-measure a probe whenever its
bytes change.

| # | Probe | funcs | instrs | u | d | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| 01 | `baseline_i32` | 1 | 3 | 0 | 1/0 | ok |
| 02 | `externref_param` | 1 | 3 | 0 | 1/0 | ok |
| 03 | `externref_table` | 1 | 4 | 0 | 1/0 | ok (`.table0` created) |
| 04 | `shared_memory_atomic` | 1 | 4 | 0 | 1/0 | **fixed (R1.2)**: limits flags decode fully (`shared`/`maximum`/64-bit/page-size preserved) |
| 05 | `memory64` | 1 | **1** | **6** | 1/0 | analysis aborts (`i64`/`i32` mismatch), body undefined |
| 06 | `multi_memory` | 1 | 7 | 0 | 1/0 | **wrong**: `i32.load align=0x42 offset=0x1` + spurious `unreachable` |
| 07 | `data_count_bulk_memory` | 1 | 7 | 0 | 1/0 | ok |
| 08 | `gc_struct_type` | 1 | 2 | 0 | 1/0 | **fixed (GC)**: `type_0` is now a real `gc_struct_type` with named fields |
| 09 | `gc_struct_new` | 1 | 5 | **1** | 1/0 | `0xFB` undefined, desync (`unreachable` ×2) |
| 10 | `eh_legacy_try_catch` | 1 | 6 | 0 | 1/0 | ok |
| 11 | `eh_try_table` | 1 | **4** | **0** | 1/0 | **fixed (new EH)**: real `try_table` with clause handling |
| 12 | `call_ref` | 1 | 4 | 1 | **1/0** | **mostly fixed (R1.5)**: `(ref null $t)` parses, no NPEs, decompiles; the `call_ref` *instruction* (0x14) is still undecoded (function-references workstream) |
| 13 | `tail_call` | 2 | 5 | 0 | 2/0 | ok |
| 14 | `relaxed_simd` | 1 | 6 | 0 | 1/0 | ok |
| 15 | `simd` | 1 | 6 | 0 | 1/0 | ok |
| 16 | `multivalue_return` | 2 | 9 | 0 | 2/0 | decodes, but only the first result appears in the prototype |
| 17 | `multivalue_block` | 1 | 7 | 0 | 1/0 | ok |
| 18 | `shared_then_plain_memory` | 1 | 3 | 0 | 1/0 | limits **fixed (R1.2)**; the loader still skips `memidx != 0` (multi-memory workstream) |
| 19 | `extended_const_global` | – | – | – | – | **import failed** (`Missing end byte`) |
| 20 | `gc_global_init` (`(global (ref 0) (struct.new 0))`) | – | – | – | – | **import failed** (`Invalid instruction opcode 0 in constant expression` — the 2-byte `(ref 0)` valtype is unhandled, so the initializer parse is misaligned) |
| 21 | `component_model` | – | – | – | – | **import failed** (`No load spec found`) |

## 3. Why this matters by toolchain

* **Classic Emscripten / `wasm-bindgen` (Rust) output** — MVP + 2.0 + SIMD + threads + tail calls:
  covered today (a 179 KiB Rust module decompiles 437/437 functions cleanly).
* **Kotlin/Wasm, Dart, Java (TeaVM/J2CL), OCaml, .NET** — emit **GC** modules with **typed function
  references**: currently unusable, and `(ref null $t)` parameters actively break decompilation.
* **Clang/LLVM ≥ 19** — emits the **new EH** (`try_table`); the legacy EH that the plugin implements
  is the deprecated encoding.
* **Emscripten `-pthread`** — works, but the shared-memory limits bug can silently drop memories.
* **Emscripten `MEMORY64` / wasm64 targets** — function bodies are left undefined.
* **Emscripten `-sASYNCIFY=2` (JSPI)** — stack switching, unsupported.

## 4. Roadmap

Ordered by leverage. "Effort" is a rough size estimate (S ≈ hours, M ≈ a day, L ≈ several days).

### 0. Graceful degradation for unknown opcodes (effort S, highest leverage)

Today one unknown encoding shifts the byte stream and can blank out an entire function. Add a generic
"unsupported" instruction (e.g. `unimpl` / `unimp`) plus a minimal opcode-length table in the Java
walker so that any unrecognized opcode is consumed with the correct number of operand bytes and
emitted as an unimplemented instruction, keeping the rest of the function intact. This makes every
future proposal degrade to a readable listing instead of a broken one, and it turns "unsupported" from
"silently wrong" into "visibly unimplemented".

*Where*: `WasmFunctionAnalysis.java` (the opcode switch), `data/languages/WebAssembly.sinc`.
*Acceptance*: probes `09`, `11` keep `undefined_bytes == 0` with the unsupported instruction rendered
as `unimplemented`.

### 1. Limits flags: shared / memory64 / custom page size (effort S)

*Where*: `src/main/java/wasm/format/sections/structures/WasmResizableLimits.java` (shared with
`WasmTableType`, so table64/shared tables come along).
*What*: decode flags bit 0 = has maximum, bit 1 = shared, bit 2 = 64-bit index, bit 3 = custom page
size (an exponent follows); model them in `toDataType()` and expose `isShared()`/`is64Bit()`.
*Acceptance*: a new probe with a shared memory followed by a plain memory parses both limits
correctly, and a table probe with a `maximum` followed by a second table keeps both entries aligned
(tables are already multi-index in the loader, so this is observable today).

### 2. Multi-memory (effort M)

*Where*: `BasicOps.sinc` (`loadaddr`, `storeaddr`), `VectorOps.sinc` (`loadaddr2`), `AtomicOps.sinc`
(`atomicaddr3`), every place the Java walker skips a memarg (`WasmFunctionAnalysis.java`), and the
loader (`WasmLoader.getMemoryAddress()`, `loadMemories()`, `createMemoryBlock()`).
*What*: when alignment bit 6 is set, consume a `memidx`, expose it, and compute the address from that
memory's base. Today the loader only maps memory 0 into the `ram` address space; give memories the
same treatment as tables (a dedicated `memory` address space with `memidx << 32` stride, or a fixed
stride in `ram`) and drop the `memidx != 0` guards. `memory.size/grow/copy/init` already carry a
memidx operand.
*Acceptance*: probe `06` lists `i32.load … memidx=1` with no spurious `unreachable` and
`undefined_bytes == 0`; probe `18` creates both `.memory0` and `.memory1` (7 pages = 458752 bytes);
add a probe that accesses memory 0 and memory 1 and checks both references resolve.

### 3. Never crash on unknown value types; then typed references (effort M)

*Where*: `WasmEnums.ValType` (add the multi-byte `ref null <heaptype>` / `ref <heaptype>` forms plus
`exnref`, `anyref`, `eqref`, `i31ref`, `structref`, `arrayref`, `none`, `noextern`, `noexpn`),
`WasmFuncType` (multi-byte valtype parsing), `WasmSignatureAnalyzer` (null guard),
`WasmLoader`/`WasmPreAnalyzer` (no NPEs).
*What*: short term, map unknown reference types onto a width-correct placeholder (i32/pointer) so the
module still disassembles and decompiles; long term, model `(ref $t)` as a typed function pointer.
*Acceptance*: probe `12` decompiles without failures; a new probe with `call_ref` + `return_call_ref`
disassembles as `call_ref`/`return_call_ref`.

### 4. Constant expressions must not fail the import (effort S)

*Where*: `src/main/java/wasm/format/sections/structures/ConstantExpression.java`.
*What*: accept the extended-const ops (`i32`/`i64` `add`/`sub`/`mul`) and skip unknown opcodes by
scanning to the matching `end` with a length table instead of throwing. Record the raw bytes so the
listing shows "unparsed initializer" rather than losing the whole module. Also worth handling:
`ref.i31`, `struct.new`/`array.new*` in initializers (GC), `global.get` of reference types.
*Acceptance*: probes `19` and `20` import successfully.

### 5. New exception handling (effort M)

*Where*: `WebAssembly.sinc` (`try_table` 0x1F with `catch`/`catch_ref`/`catch_all`/`catch_all_ref`
clauses, `throw_ref` 0x0A), `WasmEnums.ValType` (`exnref`), `WasmFunctionAnalysis` control frames
(the `TRY`/`CATCH` `BlockKind`s added for legacy EH are a good base), `WasmTagSection` (already parses
tags), `WasmFunctionAnalysis` catch-clause stack effects.
*Acceptance*: probe `11` yields a typed `try_table` instruction; add probes for a catch clause, a
multi-clause `try_table` and `throw_ref`.

### 6. Garbage collection (effort L)

*Where*: `WasmTypeSection`/`WasmFuncType` (rec groups `0x4E`, sub types `0x50`/`0x4F`, `struct`
`0x5F`, `array` `0x5E`, storage types), `WasmEnums.ValType` (GC reference types), a new `0xFB`
opcode table in `data/languages/GC.*`, stack effects in `WasmFunctionAnalysis`, and Ghidra type
mapping for refs (likely pointer/undefined placeholders plus informative data types for
`struct`/`array` definitions).
*Acceptance*: probes `08`, `09` produce zero undefined bytes; add probes for `array.new`, `array.len`,
`ref.cast`, `br_on_cast`, `i31.get_s`.

### 7. Multi-value returns (effort M)

*Where*: `WasmSignatureAnalyzer` (all results, not just `returns[0]`), the cspec output block
(`WebAssembly.cspec` already declares a contiguous output register range), call fixups/injection
(`PcodeInjectLibraryWasm`, `InjectPayloadWasmCallPrologue`).
*Acceptance*: probe `16` shows both results in the prototype and the caller consumes both.

### 8. Name section extras (effort S-M)

*Where*: `WasmNameSubsection` (labels = 3, field = 10, tag = 11), `WasmLoader`/`WasmNameSection`
(apply type/table/memory/elem/data names as symbols; today only function/global/local names are used).
*Acceptance*: a probe with a full `.name` section shows labels as label symbols (or at least not as
`WasmNameUnknownSubsection`) and named tables/memories/data.

### 9. DWARF line info (effort M)

The fork currently disables `.debug_line` import to avoid an `AddressOutOfBounds` failure. Re-enable
once the address-range handling for the wasm code block is fixed.
*Where*: `WasmDWARFAnalyzer` + the `.debug_*` memory-block layout in `WasmLoader`.

### 10. Longer-term / lower priority for binary RE

Stack switching (JSPI), JS string builtins, wide arithmetic, `memory.discard`, shared-everything
threads, and the component model. For the component model, the pragmatic first step is a loader that
recognizes the component header, reports a clear error, and (optionally) extracts nested core modules
so they can be imported and analyzed individually — instead of today's `No load spec found`.

## 5. Adding a probe (how to extend this document)

`test-scripts/gen_feature_probes.py` has byte-level helpers (`uleb`, `sleb`, `vec`, `section`,
`module`, `functype`, `type_section`, `func_section`, `memory_section`, `global_section`, …). To add a
feature:

1. append a `write("<nn>_<feature>.wasm", module(...))` block,
2. re-run the batch import,
3. record `funcs/instrs/undefined_bytes/decompiled` and — if the listing is wrong —
   `ListProgram.java` output in the table above,
4. add the probe to the acceptance list of the relevant roadmap item.

Remember that SIMD/relaxed-SIMD opcodes (0xFD) and prefixes are **LEB128-encoded** opcodes: `0xAE` is
`i32x4.add (174)` only as `FD AE 01`.

## 6. Spec-suite baseline (new, added after the harness landed)

A headless harness for the *official* WebAssembly spec testsuite now exists under
`test-scripts/spectest/` (see `REPORT-G.md` and `test-scripts/spectest-BASELINE.md`). It is a
measurement tool, not a fix; metrics below were reproduced by the integrator.

* **core subset** (73 `.wast`): 271 valid modules, **271 imported (100 %)**, 33192 instructions,
  2746/2747 functions decompiled, 458 undefined bytes = 428 import-stub bytes + **30 real decode-gap
  bytes**.
* **all subset incl. SIMD** (147 `.wast`): 257 modules, 257 imported, 48005 instructions, 210
  undefined bytes = 176 stub + **34 real**; the SIMD suite is clean (99 modules, 0 gaps).

Ranked findings (bug leads for the next rounds):

1. **`select` (0x1B) is not decoded after an unconditional terminator** (`unreachable`, `br`,
   `br_table`, `return`) - the only real decode gap. Repro: `unwind.wast`, functions
   `select-after-unreachable` / `select-after-br` / `select-after-br_table` / `select-after-return`;
   `select-after-br_if` decodes fine, which isolates the trigger (suspect the
   `ctx_operand_size`-conditioned `select` constructors).
2. **Decompiler process death** on a very large function body (`br_table.0.wasm`, 16172-byte body).
3. **`WasmStackVariableAnalyzer` exceptions**: `Index 0 out of bounds for length 0`
   (`i64.store`, `i64.store16`, `f32.load`, `i64.load8_s`) and `GenericAddress cannot be cast to
   Register` (`local.set`).
4. **Import stubs are modelled as 4-byte body-less functions** (428 bytes of `EXTERNAL` block noise
   per importing module).
5. Emulation-based `assert_*` execution is still blocked (`funcEntryCallOther requires two inputs`
   under PyGhidra), so this baseline covers loading, disassembly and decompilation only;
   `assert_invalid`/`assert_malformed` rejection behaviour and the proposal suites (`proposals/`) are
   follow-ups.

## 7. References

* WebAssembly 3.0 / core spec: <https://webassembly.github.io/spec/core/>
* Proposals (GC, tail calls, exception handling, memory64, multi-memory, relaxed SIMD, threads,
  function references, stack switching, custom page sizes, wide arithmetic):
  <https://github.com/WebAssembly/proposals>
* Extended name section: <https://github.com/WebAssembly/extended-name-section>

### 2.5 Constant-expression scanner regressions (probes 22-27)

Added after the constant-expression scanner was rewritten to *decode* instructions instead of scanning
bytes (a byte scan misreads immediates as opcodes/`end` bytes). All six must stay green.

| # | Probe | funcs | instrs | u | d | Expected |
| --- | --- | --- | --- | --- | --- | --- |
| 22 | `extconst_two_ops` (`i32.const 1; i32.const 2; i32.add`) | 1 | 2 | 0 | 1/0 | imports; global folds to `03000000` |
| 23 | `const_f32_imm_0b` (immediate byte `0x0B`) | 1 | 2 | 0 | 1/0 | imports; global = `0b000000` |
| 24 | `const_f64_imm_0b` | 1 | 2 | 0 | 1/0 | imports; global = `0b00000000000000` |
| 25 | `const_v128_imm_0b` (16 x `0x0B`) | 1 | 2 | 0 | 1/0 | imports; global = 16 x `0b` |
| 26 | `refnull_typeidx` (`ref.null $t`) | 1 | 2 | 0 | 1/0 | imports |
| 27 | `extconst_data_offset` (folded segment offset) | 1 | 2 | 0 | 1/0 | imports; data segment lands at offset 3 |