# Modern WebAssembly support: inventory, gaps and roadmap

Status of this document: **inventory complete; implementation in progress**. (The per-workstream
`REPORT-*.md` files referenced throughout live on the `archive/reports` branch; the machine-checked
expectations stay here as data: `test-scripts/expected-results.json` for the probe gate.) See the status table
below. The inventory was produced from `main` (originally commit `430cbe2`, plugin built against
Ghidra 12.1.4) and is intended as the working base for extending the plugin's coverage toward current
WebAssembly (Wasm 3.0 + active proposals).

| Roadmap item | State |
| --- | --- |
| R1.2 limits flags · R1.3 constant expressions · R1.5 unknown value types | **merged** (`REPORT-B.md`; plus an integrator rewrite of the expression scanner - see §2.5) |
| 5. new exception handling (`try_table`, `throw_ref`, `exnref`) | **merged** (`REPORT-F.md`) |
| 6. garbage collection (type section, `0xFB` instructions, GC initializers) | **merged** (`REPORT-E.md`) |
| spec-suite findings (select after terminator, stack-variable crashes, oversized br_table) | **merged** (`REPORT-SF.md`; spec core suite now has 0 real undefined bytes and 0 decompiler failures) |
| function-references instructions (`call_ref`, `return_call_ref`, `ref.as_non_null`, `br_on_null`, `br_on_non_null`) | **merged** (`REPORT-FR.md`; probe `12` reaches 0 undefined bytes) |
| 0/1/2 unknown-opcode degradation + multi-memory | **merged** (`REPORT-A-DS.md`; probe 06 decodes `memidx`, probe 18 creates both memory blocks) |
| 8. memory64 | **merged** (`REPORT-N.md`): index-type propagation, `ctx_mem64` widths, 64-bit address computation truncated into `ram` (exact below 4 GiB, documented), loader bounds; probe `05` decodes, 8 new `M64_*` probes |
| 9. `.name` extras + application | **merged** (`REPORT-D.md`; subsections 3/10/11 parsed, `WasmNameApplyAnalyzer` applies table/memory/elem/data labels + module/type/field/tag and label-name comments; malformed name sections no longer break imports) |
| 4. negative spec tests (`assert_invalid`/`assert_malformed`) | **merged** (`REPORT-NS.md` + §6.4) |
| loader hardening (locals/memory/table bounds, honest failures) | **merged** (`REPORT-HARD.md` + §6.2; B1/B2/B3/B5 fixed, B4 documented) |
| 7. multi-value returns | **merged** (`REPORT-MV.md`): functions return a packed struct, all results visible, callers consume them (7 multi-result functions in the real module now carry `wasm_ret_i32_i32*` prototypes) |
| 10. component model loader | **merged** (`REPORT-C2.md`; embedded core modules import as real programs) |
| 4. spec-test harness | **merged** (`REPORT-G.md`; see §6) |
| 4. CI probe gate (probes + fixture baseline) | **merged** (`.github/workflows/probes.yml`, `expected-results.json` - 93 probes) |
| 4. real-world corpus sweep | **merged** (`REPORT-H.md`; 15/15 modules import, 5591/5591 functions decompile - see §6.1) |
| 4. robustness sweep (malformed inputs) | **merged** (`REPORT-J.md`; 56-module corpus - see §6.2; two real bugs found and reproduced) |
| 9. DWARF line info | **merged** (`REPORT-DW.md`; source lines map with a `CODE_BASE + code-section-start` fixup - see §6.3) |

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
| memory64 | **fixed** (`REPORT-N.md`): the index type propagates to the pre-analyzer and to the SLEIGH address computation (`ctx_mem64`); addresses are computed in 64-bit pcode and truncated into the 32-bit `ram` space (exact below 4 GiB, wraps above — documented, and the listing marks the form `(i64 index)`); probe `05` now decodes with `undefined_bytes=0` | index type used to be hardwired to 32-bit (`sp1_32`) and the loader clamped every memory to `CODE_BASE` |
| Shared / 64-bit / custom-page-size limits | shared/`maximum`/index-type fields are dropped from the parsed limits, and a following limits entry desyncs | `WasmResizableLimits` only reads a `maximum` when `flags == 1` (shared = 3, memory64 = 4/5, page-size = 8) |
| Multi-value returns | **fixed** (`REPORT-MV.md`): results are returned as a packed struct through the `__wasm` output pentry (plus tail-padding zeroing in the epilogue), so every result is visible and callers consume them all | `WasmSignatureAnalyzer` used to apply only `returns[0]` |
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
| Component model binaries | **fixed**: components are unpacked and the embedded core module imports as a real program (`REPORT-C2.md`); probe `21` (bare header, no modules) still fails by design | loader gap (resolved) |

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
| 05 | `memory64` | 1 | **4** | **0** | 1/0 | **fixed (memory64)**: 64-bit index decodes and the body analyses cleanly |
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

### 6.1 Real-world corpus baseline

`test-scripts/corpus/` + `test-scripts/corpus-sweep.ps1` sweep 15 real-world modules (10 pinned npm
packages incl. `@jsquash/*`, `sql.js`, `web-tree-sitter`; 3 rustc `wasm32-unknown-unknown` builds with
`debuginfo`/`+simd128`; 2 local Rasterbator modules) with V8 verdicts and hash checks:

* **15/15 imported, 0 import failures; 5591/5591 functions decompiled; 1,465,308 instructions.**
* `undefined_bytes` = 933 total = 932 import-placeholder bytes (4 x 233 imports) + **1 real byte** -
  every V8-valid module decodes completely (0 unimplemented instructions).
* Findings: (1) imported functions are 4-byte empty bodies in an `EXTERNAL` block, inflating the
  `undefined_bytes` metric and producing decompiler noise; (2) `WasmStackVariableAnalyzer` skips 22
  instructions across 4 valid modules on partial-overlap / different-width stack slots;
  (3) a malformed body leaves a bogus `unreachable` at the locals-count byte (containment otherwise
  good); (4) a core-Ghidra `PngDataType` analyzer error on `.memory0` is noise, not ours.
* Nothing in the corpus exercises a documented unsupported feature - mainstream wasm-bindgen /
  Emscripten output is MVP + 2.0 (+ SIMD), which is why it all decodes.

### 6.2 Robustness baseline (malformed inputs) — **partly fixed by `REPORT-HARD.md`**

`test-scripts/make_malformed_corpus.py` (56 modules) + `test-scripts/robustness-sweep.ps1` +
`test-scripts/robustness-RESULTS.md` classify every case as import_ok / import_failed / process_died /
hang. Original 56-module run: 27 `import_ok` (one the valid control), 27 `import_failed` (all caught and
reported), **1 `process_died`**, **1 timeout**, 0 hangs.

**Integrator-reproduced, then fixed** (hardening workstream, `REPORT-HARD.md`; fixes verified against
its own pinned install):

1. **`B04`/`J02` (30 bytes) used to abort the analysis process** with an escaping
   `java.lang.OutOfMemoryError` from an unbounded `locals` count. Now bounded (1,000,000 locals per
   function, 10,000,000 per module): the module fails with
   `Import failed: Function declares more than 1000000 locals (the loader's per-function limit)` and the
   headless run exits 0.
2. **`M03`/`J01`/`NS12` (17 bytes) used to materialize a 2 GiB memory block** and never finish analysis.
   Limits are now validated (`initial <= maximum`, 32-bit <= 65536 pages, 64-bit <= 2^48, block capped at
   256 MiB): `Import failed: initial size N page(s) exceeds the 32-bit limit of 65536 page(s)` in ~10 s.
   Tables are bounded the same way (B5: `initial <= maximum`, > 64 MiB skipped with a diagnostic).

Aggregate effect (from the hardening report): the 56-module sweep went from
27 ok / 1 timeout / 27 failed / **1 died** to 24 ok / 0 timeout / 32 failed / **0 died**, and the
2948-module negative suite from 59 rejected / 2889 accepted / 53 accepted-partial / 0 crash / 0 hang to
**130 rejected / 2818 accepted / 0 accepted-partial / 0 crash / 0 hang**.

### 6.3 DWARF line info

`WasmDWARFAnalyzer` re-enables source-line import using the public
`DWARFProgram.setProgramBaseAddressFixup(CODE_BASE + code-section content start)` (stock Ghidra never
sets it, so every row landed at `ram:0x0` and was rejected as non-executable) and skips out-of-range
rows instead of throwing (`0xffffffff` relocations in `wasm-ld` output previously produced 33-bit
addresses and an `AddressOutOfBoundsException` that aborted the import). Verified with `rustc`-built
fixtures: e.g. `ram:8000009b -> fixture.rs:12`, plus inlined `core` lines; 27 entries, 3 out-of-range
skipped; real-module regression unchanged.

### 6.4 Negative-test baseline (invalid / malformed modules)

`test-scripts/spectest/` gained an additive negative harness (`prepare_spec_negative.py`,
`run_spectest_negative.ps1`, `SpecNegativeReport.java`, `parse_spec_negative.py`); the full per-file
table is `test-scripts/spectest-NEGATIVE.md` and the analysis is `REPORT-NS.md`. All **2948 binary
negative modules** of the pinned testsuite were classified (import-only): **59 rejected / 2889 accepted
/ 0 crash / 0 hang**, plus a hazard pass (analysis on, one JVM per module) on the 9 extreme-metadata
modules which produced **5 analysis hangs**.

Integrator-reproduced, ranked (all three from the original run were **fixed** by the hardening
workstream - see §6.2 - and the fixes were re-verified by the integrator):

1. **B3 - silent truncation (high severity, new class). → FIXED.** `WasmLoader.load()` used to swallow
   every exception from `doLoad`, so a malformed custom-section name (bad UTF-8, 53 spec modules)
   produced `Import succeeded` with **`funcs=0`** - everything after the failing section was lost
   without a diagnostic. It now fails honestly:
   `Import failed: Failed to create markup for section .custom.\uFFFD (id SEC_CUSTOM) at file offset 0x8: Invalid DataType name`.
2. **B1/J02/B04 - absurd `locals` count (high). → FIXED.** Bounded (1M/function, 10M/module); clean
   import failure, no escaping `OutOfMemoryError`, no nonsense program.
3. **B2/J01/M03/NS12 - absurd memory minimum (high). → FIXED.** Limits validated (`initial <= maximum`,
   32-bit <= 65536 pages, 64-bit <= 2^48) and blocks capped at 256 MiB; ~10 s bounded rejection instead
   of a 2 GiB block and an analysis wedge.
4. **B4 (medium) - out-of-range section ids and duplicate sections dropped invisibly: OPEN.** The exact
   patch is documented in `REPORT-HARD.md` but needs `WasmSection.java`/`WasmModule.java`.
   **B5 fixed** (table limits validated; oversized tables skipped with a diagnostic);
   **B6** (219 modules accepted as bare bytes) is by design in a lenient loader.
5. **B7 (low) - rejections are now deliberate loader diagnostics** for the paths that were fixed
   (section markup, locals, memory/table limits) instead of "no loader matched" / "no memory blocks".

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