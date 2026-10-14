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
| Section diagnostics + 64-bit data offsets | **merged** (`REPORT-H1.md`): out-of-range/duplicate sections rejected with a diagnostic; i64 offsets placed, ≥ 4 GiB clamped with a log |
| Spec-suite gates (positive + negative) | **merged** (`REPORT-G.md`, `REPORT-NS.md`): 271 core modules, 0 real undefined bytes, 0 decompile failures; 2948 negative modules classified |
| Spec assert emulation | **merged** (`REPORT-H3.md`): 33 `.wast` suites, 92/92 modules; assert_return 2511/4, assert_trap 183/0 (4 `br_table large` cases are the deliberate `MAX_BR_TABLE_CASES` bound) |
| Stack switching / strings / wide arith / `memory.discard` | **merged** (`REPORT-H5.md`): all decode; `cont` types parse (`REPORT-CT.md`) |
| Name-section label targets | **merged** (`REPORT-H6.md`): label names become real label symbols at branch targets |
| Reference typing + `cont` types | **merged** (`REPORT-H7.md`, `REPORT-CT.md`): precise `(ref null ht)` model; subtype-aware validation; `cont` types in the type section |
| Stack-as-aggregate SROA | **merged** (`REPORT-SROA.md`): frames modelled as aggregates, split by (width, offset) access |
| Call-graph struct synthesis | **merged** (`REPORT-STRUCTS.md`): 352 structs, 255 retyped parameters on the real module; 591 → 437 raw offset accesses |
| Dedicated memory address space | **merged** (`REPORT-MEMSPACE.md`): 32-bit `memory` space, 128 MiB stride, ≥ 8 memories supported |
| B9 warning | **merged** (`REPORT-HARD.md`): "Module accepted but nothing was decoded" when a module declares content but yields nothing |
| Fixture-validity gate | **merged**: 210 probes — 125 valid / 55 wabt-gap / 17 unsupported / 13 invalid; `oracle_skip` for runaway binaryen cases; `--timeout` support |

## 1. How this inventory was produced

Two independent sources, so that a claim can always be re-checked:

1. **Code inventory** — the SLEIGH opcode tables (`data/languages/*.sinc`, `WebAssembly.slaspec`), the
   module/section parsers (`src/main/java/wasm/format/**`) and the analyzers
   (`src/main/java/wasm/analysis/**`).
2. **Empirical probes** — 210 hand-encoded modules, one per feature, imported headlessly into Ghidra
   and measured. `test-scripts/gen_feature_probes.py` + `test-scripts/probes_*.py` generate them;
   `test-scripts/WasmFeatureReport.java` reports `funcs/instrs/undefined_bytes/decompiled` per
   program, `ListProgram.java` prints the disassembly and `DumpAll.java` the decompiled C.

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
| New exception handling: `try_table`, `throw_ref`, `exnref` | `11`, `30`-`39` |
| GC: `rec`/`sub`/`struct`/`array` types, `0xFB` instructions (`struct.*`/`array.*`/`i31.*`/`ref.test|cast`/`br_on_cast*`/`any|extern.convert_*`), GC initializers | `08`, `09`, `E01`-`E20` |
| Typed function references: `call_ref`, `return_call_ref`, `ref.as_non_null`, `br_on_null`, `br_on_non_null` | `12`, `F01`-`F07` |
| Multi-memory (memarg `memidx`, several memories, dedicated `memory` address space) | `06`, `18`, `A01`-`A04`, `B05`, `MEM_*` |
| memory64 (index-type propagation, 64-bit pcode truncated into 32-bit `memory` space) | `05`, `M64_01`-`M64_08` |
| Extended-const (`i32`/`i64` `add`/`sub`/`mul`) and GC constant expressions | `19`, `20`, `22`-`27`, `B07`-`B15` |
| Stack switching / JSPI (`cont.new`/`cont.bind`/`resume`/`suspend`/`switch`) + `cont` types | `H01`-`H10`, `CT01`-`CT05` |
| JS string builtins / stringref (`0xFB` ≥ 0x80) | `S01`-`S10` |
| Wide arithmetic (`i64.add128`/`sub128`/`mul_wide_s`/`mul_wide_u`) | `A07`, `A09` |
| `memory.discard` (0xFC 0x12) | `S07` |
| `.name` extras: label names as real symbols, table/memory/elem/data names, field/tag names | `N01`-`N*` |

### 2.2 Fixed by the modern-WASM waves (previously wrong or unsupported)

Every row of the original inventory that is not listed as open in 2.3 is now fixed and covered by
probes; the per-workstream evidence lives in the archived reports (`archive/reports`) and the
machine-checked expectations in `test-scripts/expected-results.json`.

| Feature | Status |
| --- | --- |
| Multi-memory (memarg `memidx`, several memories, loading) | fixed (`REPORT-A-DS`/`REPORT-N`): alignment bit 6 consumed, `memidx` exposed, one block per memory; probes `06`, `A01`-`A04`, `B05`, `18` |
| memory64 | fixed (`REPORT-N`): index type propagates, 64-bit address pcode truncated into `ram` (exact below 4 GiB); probes `05`, `M64_01`-`M64_08` |
| Shared / 64-bit / custom-page-size limits | fixed (`REPORT-B`): flags decoded fully, following limits entries stay aligned |
| Custom memory page sizes (block sizing) | fixed (`REPORT-PAGESIZE-MUSESPARK.md`): the declared page size (limits flag `0x08`, log2 exponent) sizes the memory block as pages x page_size, with page-aware cap/overrun diagnostics; probes `B03b`-`B03d` |
| Multi-byte block signatures on `try`/`try_table` | fixed (`REPORT-TRYBLOCKTYPE-NEMOTRON.md`): `(ref null ht)`/`(ref ht)` value types and multi-byte s33 type indices decode on both `try` and `try_table`; probes `40`-`45` |
| Multi-value returns | fixed (`REPORT-MV`): results returned as a packed struct; probes `M01`-`M12`, `16`, `17` |
| GC type entries (`struct`/`array`/`rec`/`sub`) | fixed (`REPORT-E`): real Ghidra structures/arrays; probes `E01`-`E20` |
| GC instructions (`0xFB`) | fixed (`REPORT-E`): `struct.*`/`array.*`/`i31.*`/`ref.test|cast`/`br_on_cast*`/`any|extern.convert_*`; probes `E10`-`E18` |
| New exception handling (`try_table`, `throw_ref`, `exnref`) | fixed (`REPORT-F`): probes `11`, `30`-`39` |
| Typed function references (`call_ref`, `return_call_ref`, `br_on_null`, `ref.as_non_null`, ...) | fixed (`REPORT-FR`): probes `12`, `F01`-`F07`; the *type model* is still coarse (see 2.3) |
| Extended-const and GC constant expressions | fixed (`REPORT-SF` + `B14`): probes `19`, `20`, `22`-`27`, `B07`-`B15` |
| Stack switching / JSPI (`cont.new` ... `switch`) | fixed (`REPORT-H5` + `REPORT-CT`): probes `H01`-`H10` (continuation *types* now parse too, so all ten classify as `wabt-gap`) |
| JS string builtins / stringref (`0xFB >= 0x80`) | fixed (`REPORT-H5`): probes `S01`-`S10`; unassigned sub-opcodes render as `unimplemented (reserved)` |
| Wide arithmetic (`0xFC 0x13`-`0x16`), `memory.discard` (`0xFC 0x12`) | fixed (`REPORT-H5`): probes `A07`, `A09`, `S07` |
| `.name` subsections 3/10/11 | parsed (`REPORT-D`); label names are now **real symbols** at the branch targets (`REPORT-H6`); the remaining subsections are comment-only |
| Component model binaries | fixed (`REPORT-C2`): header recognised, embedded core modules import as real programs |
| DWARF line info | fixed (`REPORT-DW`) |
| Loader hardening (locals/memory/table bounds, honest failures) | fixed (`REPORT-HARD`, see 6.2) |
| Section id/order/duplicate diagnostics, 64-bit data-segment offsets | fixed (`REPORT-H1`): out-of-range/duplicate sections are rejected with a diagnostic; i64 offsets are placed, `>= 4 GiB` clamped with a log |

### 2.3 Still open

| Item | State / evidence |
| --- | --- |
| **Custom page sizes** - the limits flag decodes and the declared page size sizes the block (see 2.2) | fixed (semantic, `REPORT-PAGESIZE-MUSESPARK.md`); residual: exotic (non-0/16) exponents are honoured leniently, oracles accept only 1 B / 64 KiB |
| **Shared-everything threads** - `global.atomic.*`, shared tables/`table.atomic.*` have no mnemonics (the `0xFE` atomic *memory* ops are implemented) | open (unimplemented fallback) |
| **Component-model semantics** - canonical ABI, `canon` ops, component types are not modelled (core-module extraction only) | by design |
| **`br_table large` assertion cases** - 4 `assert_return` failures in the emulation harness are the deliberate `MAX_BR_TABLE_CASES` bound (decode-side) | open (deliberate bound) |
| **Struct-synthesis v1 limits** - `call_indirect` targets not followed, delta arguments skipped, only parameters retyped, globals/SIMD lanes skipped, fields are `undefinedN` | open (v1 scope, documented in `REPORT-STRUCTS.md`) |
| **128 MiB materialisation cap** - memories larger than 128 MiB are clamped (with a warning); the SLEIGH truncates effective addresses to 32 bits, so decoded accesses above 4 GiB wrap | documented limitation |
| **`ref.null` abstract heap types** print numerically (`ref.null heaptype=-0x15`) - restoring names needs named constructors per abstract byte alongside the s33 form, if SLEIGH's pattern rules allow it | cosmetic, open |
| **Multi-byte block signatures on `try`/`try_table`** - decode multi-byte valtypes/type indices now (see 2.2); the typed `BlockTypeInfo` path (grafted from `feat/tryblocktype-catjam`) fully decodes the ref-typed cases (`undefined_bytes` 8 -> 0 on probes `40`/`41`) | fixed (`REPORT-TRYBLOCKTYPE-NEMOTRON.md`) |
| **Extended-const `Data markup conflict` warning** - `WasmLoader.createData` logged "Data markup conflict" on probes `19`, `22`, `27`, `B07`-`B09`, `B14`, `B25` (the row originally named `22`-`24`/`27`; measurement shows it fires on every probe whose global/data initializer is a multi-instruction constant expression, not on the single-instruction const probes `23`/`24`) | fixed (`REPORT-EXTCONST-MISTRAL.md`): `ConstantExpression.toDataType()` double-counted the terminating `end` byte for folded extended-const and unparsed initializers, sizing the enclosing section's `.module` structure one byte too long so it collided with the next section's markup (or overran the `.module` block when the section was last) and left a whole section undissected; the raw-byte array now excludes the trailing `end` byte. Placed bytes/offsets were already correct - only the `.module` structural markup was wrong |
| **Emulation coverage** - 4 remaining `assert_return` gaps (all `br_table large`); the other 9 recorded spec-`assert_*` gaps are resolved | emulator coverage, not decoder gaps |

### 2.4 Observed baseline (reproducible with the commands above)

The authoritative per-probe expectations are machine-checked data, not prose:

* `test-scripts/expected-results.json` - the probe gate (**204 probes**: 186 probed-imported
  + 18 expected import failures; `funcs`/`instrs`/`undefined_bytes`/`decompiled`/`decompile_failed`
  per probe), enforced by `.github/workflows/probes.yml` and locally by `test-scripts/check-local.ps1`.
* `test-scripts/fixture-validity.json` - the external-oracle classification of every probe (see 6.5):
  **121 valid / 53 wabt-gap / 17 unsupported / 13 invalid**; 13 probes carry
  `oracle_skip: ["binaryen"]`.
* Real module `rasterbator_rs_bg.wasm`: `functions=437 decompiled=437 failed=0 instructions=61658
  undefined_bytes=156` - the 156 bytes are 39 import stubs x 4, i.e. **0 real decode gaps**; checked on
  every local run with `-RealModule`.
* Spec suite (core subset): 271/271 imported, 2747/2747 functions decompiled,
  33222 instructions, 428 undefined bytes (all import stubs), 0 decompile failures
  (`test-scripts/spectest-expected.json`, `.github/workflows/spectest.yml`).
* Emulation assertion harness: 33 `.wast` suites, 92/92 modules;
  **assert_return 2511/4**, **assert_trap 183/0** (the 4 remaining assert_return
  failures are the `br_table large` cases - the deliberate `MAX_BR_TABLE_CASES`
  bound, decode-side).

Metric caveat: `instrs` counts the pre-analyzer's marker instructions too (`.locals`, `.local`,
`.case`, `.default`); the real module's 61,658 counted instructions are 60,556 real wasm instructions
+ 1,102 markers - verified byte-exactly against WABT `wasm-objdump` (see
`archive/reports/research/notdec-reuse-analysis.md`).

## 3. Why this matters by toolchain

* **Classic Emscripten / `wasm-bindgen` (Rust) output** — MVP + 2.0 + SIMD + threads + tail calls:
  fully covered (a 179 KiB Rust module decompiles 437/437 functions cleanly).
* **Kotlin/Wasm, Dart, Java (TeaVM/J2CL), OCaml, .NET** — emit **GC** modules with **typed function
  references**: now covered (GC type section, `0xFB` instructions, `call_ref` family, precise
  `(ref null ht)` model).
* **Clang/LLVM ≥ 19** — emits the **new EH** (`try_table`): covered (plus `throw_ref`, `exnref`).
* **Emscripten `-pthread`** — works; shared-memory limits flags decode fully.
* **Emscripten `MEMORY64` / wasm64 targets** — covered below 4 GiB (exact); above 4 GiB the
  `memory` space truncates (documented).
* **Emscripten `-sASYNCIFY=2` (JSPI)** — stack switching decodes (`cont.new`/`resume`/`switch`);
  `cont` types parse.

## 4. Roadmap

**Status: items 0-10 below were implemented by the modern-WASM waves (see 2.2). What remains open is listed in 2.3; this section is kept as the original task breakdown and acceptance criteria.**

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

~~Stack switching (JSPI), JS string builtins, wide arithmetic, `memory.discard`, shared-everything
threads, and the component model.~~ Most of these are now implemented (see 2.1/2.2). What remains:
shared-everything threads (unimplemented fallback), component-model semantics (by design —
core-module extraction only), and custom page sizes (see 2.3).

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
`test-scripts/spectest/` (see `REPORT-G.md`). It is a measurement tool, not a fix; metrics below
were reproduced by the integrator and are enforced by `.github/workflows/spectest.yml`.

Both decompile harnesses (`DumpDecomp.java`, `spectest/SpecModuleReport.java`) retry a failed
decompilation once with a much larger budget (120 s → 600 s): the heaviest spec functions
(`br_table.0.wasm`, the ~16k-label function) can exceed the first budget on a loaded CI runner,
which showed up as a flaky `decompiled 2747 → 2746` on Linux. The retry removes the flake without
loosening any expected metric.

* **core subset** (73 `.wast`): 271 valid modules, **271 imported (100 %)**, 33222 instructions,
  **2747/2747 functions decompiled**, 428 undefined bytes = 428 import-stub bytes + **0 real
  decode-gap bytes**, 0 decompile failures.
* **all subset incl. SIMD** (147 `.wast`): SIMD suite is clean (128 modules, 0 gaps).

Ranked findings (all resolved):

1. ~~**`select` (0x1B) is not decoded after an unconditional terminator**~~ — **FIXED** (SF workstream).
2. ~~**Decompiler process death** on a very large function body (`br_table.0.wasm`, 16172-byte body)~~ — **FIXED** (`MAX_BR_TABLE_CASES` bound; modelled cases capped at 1024).
3. ~~**`WasmStackVariableAnalyzer` exceptions**~~ — **FIXED** (SROA workstream; stack-as-aggregate model).
4. ~~**Import stubs are modelled as 4-byte body-less functions**~~ — documented (428 bytes of `EXTERNAL` block noise per importing module; by design).
5. **Emulation-based `assert_*` execution** — **IMPLEMENTED** (`run_emulate.ps1` + PyGhidra; 33 suites, 92/92 modules; assert_return 2511/4, assert_trap 183/0; the 4 remaining are `br_table large` cases).

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

### 6.2 Robustness baseline (malformed inputs) — **fixed by `REPORT-HARD.md`**

`test-scripts/make_malformed_corpus.py` (56 modules) + `test-scripts/robustness-sweep.ps1` +
`test-scripts/robustness-RESULTS.md` classify every case as import_ok / import_failed / process_died /
hang.

**Fixed** (hardening workstream, `REPORT-HARD.md`; fixes verified against its own pinned install):

1. **`B04`/`J02` (30 bytes) used to abort the analysis process** with an escaping
   `java.lang.OutOfMemoryError` from an unbounded `locals` count. Now bounded (1,000,000 locals per
   function, 10,000,000 per module): the module fails with
   `Import failed: Function declares more than 1000000 locals (the loader's per-function limit)` and the
   headless run exits 0.
2. **`M03`/`J01`/`NS12` (17 bytes) used to materialize a 2 GiB memory block** and never finish analysis.
   Limits are now validated (`initial <= maximum`, 32-bit <= 65536 pages, 64-bit <= 2^48, block capped at
   128 MiB): `Import failed: initial size N page(s) exceeds the 32-bit limit of 65536 page(s)` in ~10 s.
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
negative modules** of the pinned testsuite were classified (import-only): after the hardening
workstream, **130 rejected / 2818 accepted / 0 accepted-partial / 0 crash / 0 hang** (originally
59 rejected / 2889 accepted / 53 accepted-partial / 0 crash / 0 hang).

All three originally-ranked findings were **fixed** by the hardening workstream (see §6.2):

1. **B3 - silent truncation (high severity). → FIXED.** `WasmLoader.load()` used to swallow
   every exception from `doLoad`, so a malformed custom-section name (bad UTF-8, 53 spec modules)
   produced `Import succeeded` with **`funcs=0`**. It now fails honestly:
   `Import failed: Failed to create markup for section .custom.\uFFFD (id SEC_CUSTOM) at file offset 0x8: Invalid DataType name`.
2. **B1/J02/B04 - absurd `locals` count (high). → FIXED.** Bounded (1M/function, 10M/module).
3. **B2/J01/M03/NS12 - absurd memory minimum (high). → FIXED.** Limits validated and blocks
   capped at 128 MiB.
4. **B4 (medium) - out-of-range section ids and duplicate sections. → FIXED** (`REPORT-H1.md`:
   `WasmSection`/`WasmModule` reject them with a diagnostic).
   **B5 fixed** (table limits validated; oversized tables skipped with a diagnostic);
   **B9** (219 modules accepted as bare bytes) is by design in a lenient loader — since B9 it
   warns explicitly ("Module accepted but nothing was decoded"), see 2.3.
5. **B7 (low)** - rejections are now deliberate loader diagnostics for the paths that were fixed.

### 6.5 Fixture-validity baseline (every probe must be a valid module)

The probe suite is the evidence base for feature support, so every probe that exercises a feature
must itself be a valid module. Two external oracles verify that:

* **wabt 1.0.42** `wasm-validate --enable-all` (pinned + sha256-verified by
  `test-scripts/spectest/fetch_spectest_tools.ps1`; the probes workflow fetches it with `-WabtOnly`)
* **binaryen version_133** `wasm-dis --all-features` (111 MB release asset, local/full checks only:
  `--binaryen <dir>`)

`test-scripts/check-fixture-validity.py` regenerates the probes, validates each one and compares the
verdicts against `test-scripts/fixture-validity.json` (recorded from a real run, never hand-written).
A probe that is not recorded, or whose verdict changes, fails the gate; `--update` re-records, and
both-reject probes must be declared `--invalid` or `--unsupported`, so a real bug cannot be recorded
silently.

Classification of the **204 probes** (current state):

| class | count | meaning |
| --- | --- | --- |
| `valid` | 121 | accepted by both oracles |
| `wabt-gap` | 53 | wabt 1.0.42 is behind the final GC / typed-reference / stack-switching encodings; binaryen accepts |
| `unsupported` | 17 | neither oracle implements the feature (components, string builtins, `memory.discard`) |
| `invalid` | 13 | deliberately invalid negative probes (malformed / overflowing bodies) |

13 probes carry `oracle_skip: ["binaryen"]` (binaryen's `wasm-dis` runs away on the malformed
J03 family, so it is never invoked on them; the checker also supports `--timeout`).

Fixtures fixed to reach this state: section-order canonicalisation in `wasm_probe_lib.module()`
(36 probes), the multivalue export kind (8), plus 15 individual bugs - `M06` (out-of-range i64
constant), `SF02` x4 (memory instructions without a memory), `A09` (missing operands), `B04`/`B06`
(limits flags / missing table index), `B14`/`B15`/`B25` (`ref.null` immediate and a duplicate `END`
in the global initialiser), `B16`/`B17`/`B18`/`B29`/`12_call_ref` (missing `call_ref` arguments,
reftype used where the `ref.null` instruction belongs), `E03` (a final type used as a supertype),
`F06` (typed table + expression element segment). `E15`'s typing bug was fixed at the time, but the
conformant reference-typed block signature it needs was blocked by the reference-typing gap below;
that gap is now closed (`REPORT-H7.md`), so `E15` uses its conformant form again and is classified
`wabt-gap`. Only fixture bytes changed; the recorded probe metrics for those modules were
regenerated with `check-local.ps1 -Update`.

**Reference-typing gap (resolved in `REPORT-H7.md`):** the pre-analyzer's reference type model was
too coarse to validate conformant reference-typed signatures. `ValType.readFromReader` mapped
*every* multi-byte `(ref null <ht>)` / `(ref <ht>)` to `externref` (a documented placeholder) while
`ref.null` produced a different type, so a module with a reference-typed block or function result
failed validation with `pop type mismatch` and its body was left undecoded (`E15_gc_br_on_cast` in
conformant form: `instrs 1, undefined_bytes 27`). `REPORT-H7.md` maps each abstract heap type to its
`ValType` (concrete indices keep one generic placeholder), types `ref.null` precisely, makes
`popValue`/`popValues`/`popBlock` subtype-aware, and decodes multi-byte block signatures and the
`ref.null` s33 immediate in SLEIGH; `E15` now decodes with `instrs 17, undefined_bytes 0`.

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