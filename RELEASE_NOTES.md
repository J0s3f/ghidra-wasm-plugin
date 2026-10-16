# Ghidra-WASM 2.8.4

WebAssembly loader/plugin for Ghidra (disassembly + decompilation), maintained as a fork of
[nneonneo/ghidra-wasm-plugin](https://github.com/nneonneo/ghidra-wasm-plugin).

## Download

Use the asset that matches your Ghidra version - the name begins with `ghidra_12.1.4_PUBLIC_` for
Ghidra 12.1.4 or `ghidra_12.1.3_PUBLIC_` for 12.1.3. Install with
**File → Install Extensions → +** and restart Ghidra. You do not need to unzip the file.

The release assets are *cleaned* zips: the development harness (`test-scripts/`), CI
configuration (`.github/`) and internal documentation (`REPORT-*.md`) are excluded via
`build.gradle`.

## New in 2.8.4 (since 2.8.3)

* Constant expressions decode `array.new_fixed` and `select t*` immediates exactly, so a
  GC global or element initializer whose type index or count is 11 no longer ends early
  and fails the import.
* Modules whose function and code sections disagree in count load and analyse the
  functions that have bodies, instead of failing every analyzer.
* Element segments with multi-byte reference types (`(ref null $t)`) resolve their element
  type and get complete listing markup.
* Table64 limits are compared unsigned, so a valid maximum above 2^63 is accepted.
* `array.new_fixed` with a huge count in unreachable code no longer stalls pre-analysis or
  the decompiler's constructor injection.
* An exported `__main_argc_argv` is named `main` directly; an existing `main` in any
  namespace is respected.
* Label names from the name section are created per function, so a name repeated across
  functions labels each of them; names that cannot be applied are listed in a comment.
* Unknown `0xFD`/`0xFE` sub-opcodes no longer consume guessed operands or discard the rest
  of the function's analysis.
* A component binary without a usable core module fails the import instead of producing
  an empty program. The component loader is now named **WebAssembly Component**.
* Export lookups are indexed, removing a functions x exports cost on large modules.
* The DWARF analyzer skips the import if this Ghidra version no longer allows it to be
  restricted to data types.
* Local verification passed 69,326 integration assertions and 35 parser assertions.

**Upgrade:** reimport existing Wasm programs after installing this patch.

## New in 2.8.3 (since 2.8.2)

* Load active data above the 128 MiB eager zero prefix into sparse memory blocks,
  preserving overlapping segments and high memory32/memory64 addresses. Memory64
  size and bounds arithmetic retain the full unsigned extent.
* Execute GC structures, arrays, bulk array operations, casts, recursive-type identity,
  i31 values, extern conversions, GC initializers and passive segments in the emulator.
  Preserve mixed scalar/vector widths and packed-field signedness. Nominal subtype,
  variance and nullability checks emit diagnostics while imports remain lenient.
* Preserve caller locals and live operand slots when direct callees are marked inline,
  including nested calls. Changing or clearing the C-stack global rebuilds instruction
  context and removes stale inferred stack variables while preserving user-defined ones.
* Recover structure views across interior-pointer arguments and safe indirect calls;
  infer local/global bases, scalar field types and narrow SIMD accesses. Retain the
  eight-byte ABI of memory64 pointers and exclude conflicting alias constraints.
* Print released block/heap type operands by name and batch equal context updates.
  Unchanged reanalysis preserves disassembly and inferred variables.
* Add 37 CI probes, independent Node execution/trap checks, nominal validation cases,
  native decompilation checks and a 20,000-link pointer-constraint regression. Local
  verification passed 69,297 integration assertions, all 260 probe expectations,
  WABT/Binaryen fixture classifications and the committed decompiler fixture.

**Upgrade:** reimport existing Wasm programs after installing this patch to regenerate
memory blocks, instruction context and inferred types. The emulator and conservative
structure inference are analysis tools, rather than a complete validator or runtime.

## New in 2.8.2 (since 2.8.1)

* Isolate every linear memory in its own address space. Scalar, SIMD, atomic, and
  bulk-copy operations preserve memory identity at high offsets and high indices.
  Zero-sized and grown secondary memories also have independent emulator banks.
* Preserve all large `br_table` cases and the default. A selector table coalesces
  repeated targets, avoiding the former 1,023-case truncation and large control-flow graphs.
* Add behavioral tests for 128 MiB boundaries, memory index 32, memory64 addresses
  above 4 GiB, SIMD, atomics, copies, zero-sized memories, trapping stores, and
  16,384-case tables with i64 and mixed i64/v128 label arguments. Node independently
  checks the results; Ghidra tests cover import, emulation, and native decompilation.

**Upgrade:** reimport existing Wasm programs after installing this patch. The memory
spaces, instruction context, and selector data require a fresh import.

## New in 2.8.1 (since 2.8.0)

This patch addresses all 28 findings from the repository-wide review.

* Fix linear-memory global and C-stack classification, reference-branch argument movement,
  typed locals/select, concrete reference families, table initializers, and table64 operand widths.
* Preserve overlap semantics and memory indices in `memory.copy`; correct vararg memory access,
  named-local types, memarg offsets, and overlapping struct layout.
* Correct saturating and unsigned float conversions, ties-to-even rounding, signed-zero min/max,
  truncation boundaries, memory-growth overflow, and trapping stores that previously changed memory.
* Bound parser allocations and container reads, and preserve complete type encodings in listings.
* Preserve unrelated Ghidra extensions during installation, validate disposable-install destinations,
  and make emulation failures and missing reports fail the test run.

Validation includes 2,601 integration assertions, 22 bounded-heap parser assertions, 195 independent
Node checks, installer and harness tests, and the unchanged 223-probe baseline. The new regression
suite runs in CI. See the [fix report and regression coverage](https://github.com/J0s3f/ghidra-wasm-plugin/blob/archive/reports/reports/full-code-review-2026-10-15/FIXES.md).

## New in 2.8.0 (since 2.7.0)

### memory64: hybrid address spaces (full 64-bit effective addresses)

* The dedicated 32-bit `memory` space and its i32 arithmetic are **unchanged**; a second,
  64-bit-indexed `memory64` space now carries full i64 effective addresses, so decoded accesses
  above 4 GiB no longer truncate. Per-instruction selection uses the memory declaration's index
  type (`ctx_mem64`), including modules that mix i32- and i64-indexed memories.
* All memory-access constructor families have i64 variants (23 scalar + 22 SIMD + 66 atomic, plus
  string builtins and `memory.discard`), the loader places blocks/data/name labels in the matching
  space, and the emulator decodes each instruction's real `memidx` (instead of inferring it from
  the address) with unsigned bounds math.
* The i32 path is byte-identical - verified by before/after pcode fingerprints over the fixture,
  the hybrid matrix (1588 ops) and the reference Rust module (93594 ops).

### Custom page sizes

* The limits flag `0x08` (page-size exponent) sizes the memory block by the declared page size,
  and the addressable **page-count bound now follows the page size** (a 1-byte-page memory with
  65537 pages imports; previously rejected by the legacy 65536-page bound). Exotic exponents are
  honoured leniently; the external oracles only exercise 1 B / 64 KiB.

### Decoder fixes and additions

* **Padded LEB memargs** (review fix): non-minimal u32 encodings of the multi-memory flags value
  now decode correctly - the flagged/unflagged memarg families are disjoint on the first byte, in
  every permitted LEB length. A related emulator buffer (26-byte fully padded instruction) was
  fixed with it.
* **`try`/`try_table` multi-byte block signatures**: `(ref null ht)` / `(ref ht)` value types and
  multi-byte s33 type indices decode on both instructions (probes `40`-`45`).
* **Extended-const markup**: the `Data markup conflict` warning is fixed
  (`ConstantExpression.toDataType()` double-counted the terminating `end` byte, sizing the
  enclosing `.module` structure one byte too long). The warning had fired on probes
  `19`, `22`, `27`, `B07`-`B09`, `B14`, `B25`; placed bytes were always correct.
* **`ref.null` abstract heap types** now print by name (`ref.null exn`, `ref.null struct`, ...)
  for all 12 Wasm 3.0 abstract heap-type bytes, with concrete type indices unchanged; 12 new
  probes (`RN01`-`RN12`) pin every abstract type.

### Emulator correctness (semantic gates, enforced in CI)

* **Valid store after a call** no longer falsely traps out of bounds (the unwrapped-EA check used
  a stale cached stack-slot value after the shadow-stack restore; stores now read the live
  register).
* **`br_table` default target**: the `MAX_BR_TABLE_CASES` expansion bound applied to *all* labels
  including the default, so a table with 1024 explicit cases silently lost its default target.
  The bound now covers case targets only and the default is always modelled; the `br_table`
  spec-emulation suite went **145/4 → 148/1**.
* These fixes - and the memory64 hybrid matrix - are pinned by semantic regression checks that run
  in the probes workflow.

### Verification infrastructure

* **223-probe CI gate**: `probes.yml` enforces every probe's `funcs`/`instrs`/`undefined_bytes`/
  `decompiled` metrics plus the fixture and real-module decompile baselines, and now also runs the
  semantic checks above.
* **Fixture-validity gate**: wabt `wasm-validate` (CI) and binaryen `wasm-dis` (local) classify
  every probe; recorded state: **129 valid / 64 wabt-gap / 17 unsupported / 13 invalid**
  (13 probes carry `oracle_skip: ["binaryen"]`).
* **Spec-suite CI gate** (`spectest.yml`): 271 core modules, **2747/2747 functions decompiled**,
  33222 instructions, 428 undefined bytes (all import stubs), 0 decompile failures.
* **Emulation assertion harness**: 33 `.wast` suites, 92/92 modules; **assert_return 2514/1**,
  **assert_trap 183/0**. The single remaining failure is the `br_table large` `large(10000)` case
  (a case index at or past the modelled-case cap).
* **Tooling hardening**: the build helper's settings sweep is scoped to the selected Ghidra
  version's settings directory (other versions' extension copies are kept and reported;
  `-CleanAllVersions` opts into the old cross-version sweep), and the release workflow verifies
  that a manual dispatch's tag resolves to the exact commit being published (no default tag,
  explicit overwrite).

## Also included in earlier releases

* **2.7.0**: dedicated 32-bit `memory` address space with a 128 MiB stride (≥ 8 memories), section
  diagnostics, 64-bit data-segment offsets, precise `(ref null ht)` typing and `cont` types,
  the "nothing was decoded" warning, stack-switching/JSPI and JS-string-builtin decoding, wide
  arithmetic, `memory.discard`, `.name` label targets, stack-as-aggregate SROA and call-graph
  struct synthesis (352 structs, 255 parameters retyped on the reference module).
* **2.6.1**: graceful degradation for unknown opcodes, multi-memory, memory64 index-type
  propagation, function-references instructions, spec-suite fixes, multi-value returns, `.name`
  extras, DWARF source line info, loader hardening.
* **2.6.0**: garbage collection, new exception handling, component-model unwrapping, memory/table
  limit flags, constant-expression decoding.

## Upgrading from 2.7.0

Projects saved with 2.7.0 reopen and analyze unchanged for i32 modules (verified byte-identical on
the fixture and the reference Rust module). A saved memory64 project keeps its 2.7.0-era memory
block in the 32-bit `memory` space; freshly imported memory64 modules use the new `memory64` space.
Reimport a memory64 module if you want the full 64-bit addressing model
(`REPORT-UPGRADE-COMPAT-2.md`).

## Known open items

* **128 MiB materialisation cap**: memory blocks are capped at 128 MiB with a warning. Decoded
  addressing is exact (memory64 hybrid); data outside the materialised prefix is reported, not
  materialised. Memories remain independent beyond the materialised prefix.
* **Shared-everything threads**: `global.atomic.*` and shared tables / `table.atomic.*` have no
  mnemonics (the `0xFE` atomic *memory* ops are implemented).
* **Component-model semantics**: canonical ABI, `canon` ops and component types are not modelled
  (core-module extraction only, by design).
* **Struct-synthesis v1 limits**: `call_indirect` targets not followed, delta arguments skipped,
  only parameters retyped, globals/SIMD lanes skipped, fields are `undefinedN`.
* **Cosmetic listings**: `blocktype=-0xNN` on `block`/`loop`/`if`/`try`/`try_table` and the
  `ht=` operands of `ref.test`/`ref.cast`/`br_on_cast*` still print numerically.

All are documented in
[MODERN_WASM_GAPS.md](https://github.com/J0s3f/ghidra-wasm-plugin/blob/main/MODERN_WASM_GAPS.md).

## Build

```bash
export GHIDRA_INSTALL_DIR=<path to Ghidra install directory>
gradle buildExtension   # produces dist/ghidra_<ghidra version>_<date>_Ghidra-WASM.zip
```

After an intentional behaviour change, refresh the probe baseline with
`test-scripts/check-local.ps1 -Update` and commit `test-scripts/expected-results.json`.
