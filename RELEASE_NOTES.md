# Ghidra-WASM 2.7.0

WebAssembly loader/plugin for Ghidra (disassembly + decompilation), maintained as a fork of
[nneonneo/ghidra-wasm-plugin](https://github.com/nneonneo/ghidra-wasm-plugin).

## Download

Use the asset that matches your Ghidra version — the name begins with `ghidra_12.1.4_PUBLIC_` for
Ghidra 12.1.4 or `ghidra_12.1.3_PUBLIC_` for 12.1.3. Install with
**File → Install Extensions → +** and restart Ghidra. You do not need to unzip the file.

The release assets are *cleaned* zips: the development harness (`test-scripts/`), CI
configuration (`.github/`) and internal documentation (`REPORT-*.md`) are excluded via
`build.gradle`.

## New in 2.7.0 (since 2.6.1)

### Decoder / loader

* **Dedicated 32-bit `memory` address space** with a 128 MiB stride between memory indices
  (memory 0 at offset 0, memory N at `N * 0x08000000`). This supports **≥ 8 memories** without
  colliding with the module image in `ram` at `CODE_BASE`. All 32-bit memory address arithmetic
  stays in 32 bits, so decompiled C has no ZEXT noise. memory64 addresses above 4 GiB wrap
  (documented).
* **Section diagnostics + 64-bit data offsets**: out-of-range and duplicate sections are rejected
  with a clear diagnostic naming the section, id and file offset. 64-bit (memory64) data-segment
  offsets are placed; offsets ≥ 4 GiB are clamped with a log.
* **Reference typing + `cont` types**: precise `(ref null ht)` / `(ref ht)` type model with
  subtype-aware validation. `ref.null` types match precisely. `cont` types (`0x5D cont <s33
  typeidx>`) parse in the type section and resolve to the referenced function type.
* **B9 warning**: a module that declares content but yields no functions, memories or tables
  logs "Module accepted but nothing was decoded" with the declared/loaded counts.
* **128 MiB materialisation cap**: every memory block is capped at 128 MiB (`MAX_MEMORY_BLOCK_BYTES
  = MEMORY_STRIDE`). A larger declared memory is clamped with a warning rather than rejected, so a
  spec-valid module with a very large memory still imports — just with a bounded block.

### New feature coverage

* **Stack switching / JSPI**: `cont.new`, `cont.bind`, `resume`, `suspend`, `switch` all decode;
  `cont` types parse. (Semantics are not emulated — decode only.)
* **JS string builtins** (stringref, `0xFB` ≥ 0x80): decoded. Unassigned sub-opcodes render as
  `unimplemented (reserved)`.
* **Wide arithmetic** (`0xFC` 0x13–0x16): `i64.add128`, `i64.sub128`, `i64.mul_wide_s`,
  `i64.mul_wide_u`.
* **`memory.discard`** (`0xFC` 0x12): decoded.
* **`.name` label targets**: label names from `.name` subsection 3 become real label symbols at
  the branch targets (not just comments).

### Decompiler quality

* **Stack-as-aggregate SROA**: `WasmStackVariableAnalyzer` models each function frame as one
  aggregate and splits it by (width, offset) access, so Ghidra's VSA can propagate types through
  stack slots. This eliminates the previous `Index 0 out of bounds` / `GenericAddress cannot be
  cast to Register` failures.
* **Call-graph-aware struct synthesis**: `WasmStructSynthAnalyzer` clusters constant-offset
  accesses per pointer class across the call graph, synthesizes Ghidra structs, and retypes
  parameters. On the reference Rust module: **352 structs** created, **255 parameters** retyped,
  cutting raw constant-offset accesses **591 → 437 (−26 %)**.

### Verification infrastructure

* **201-probe CI gate** (up from 136): `probes.yml` enforces the committed fixture and a
  real-module decompile baseline. A metric drift, a new probe without a baseline, an unexpected
  import result or a decompiler regression fails the build.
* **Fixture-validity gate**: every probe is validated by wabt `wasm-validate` (CI) and optionally
  binaryen `wasm-dis` (local). The recorded classification (`fixture-validity.json`) is:
  **118 valid / 53 wabt-gap / 17 unsupported / 13 invalid**. 13 probes carry
  `oracle_skip: ["binaryen"]` (binaryen's `wasm-dis` runs away on the malformed J03 family).
  The checker supports `--timeout`.
* **Spec-suite CI gate** (`spectest.yml`): 271 core modules imported, **2747/2747 functions
  decompiled**, 33222 instructions, 428 undefined bytes (all import stubs), 0 decompile failures.
* **Emulation assertion harness**: 33 `.wast` suites, 92/92 modules; **assert_return 2514/1**,
  **assert_trap 183/0**. The 1 remaining `assert_return` failure is the `br_table large`
  `large(10000)` case (a case target past the modelled-case cap). The `MAX_BR_TABLE_CASES` bound no
  longer drops the DEFAULT target — `br_table` alone went 145/4 → 148/1 (`REPORT-R5-BRTABLE.md`).
  Needs a PyGhidra venv (provisioned automatically by `run_emulate.ps1`).
* **Type-recovery proxy metric** (`test-scripts/type_recovery_metric.py`): counts
  constant-offset field accesses in decompiled C, grouped by base — the signal a type-recovery
  pass would type.
* The test tooling pins each checkout to one Ghidra install and refuses to measure a stale build.

## Also included in earlier releases

* **2.6.1**: graceful degradation for unknown opcodes, multi-memory, memory64, function-references
  instructions, spec-suite fixes (`select` after terminator, stack-variable crashes, oversized
  `br_table`), multi-value returns, `.name` extras, DWARF source line info, loader hardening.
* **2.6.0**: garbage collection, new exception handling, component-model unwrapping, memory/table
  limit flags, constant-expression decoding.

## Known open items

* **Custom page sizes**: the page size is fixed at 64 KiB.
* **Shared-everything threads**: `global.atomic.*`, shared tables / `table.atomic.*` have no
  mnemonics (the `0xFE` atomic *memory* ops are implemented).
* **Component-model semantics**: canonical ABI, `canon` ops, component types are not modelled
  (core-module extraction only, by design).
* **`br_table large` assertion cases**: 1 remaining `assert_return` failure in the emulation
  harness (the `large(10000)` case, a case target past the modelled-case cap). The bound no longer
  drops the DEFAULT target (`REPORT-R5-BRTABLE.md`).
* **Struct-synthesis v1 limits**: `call_indirect` targets not followed, delta arguments skipped,
  only parameters retyped, globals/SIMD lanes skipped, fields are `undefinedN`.
* **128 MiB materialisation cap**: memories larger than 128 MiB are clamped (with a warning);
  memory64 addresses above 4 GiB wrap.
* **`ref.null` abstract heap types** print numerically (`ref.null heaptype=-0x15`).
* **Multi-byte block signatures** on `try`/`try_table` (single-s33 form kept).
* **Extended-const `Data markup conflict`** warning lead.

All are documented in
[MODERN_WASM_GAPS.md](https://github.com/J0s3f/ghidra-wasm-plugin/blob/main/MODERN_WASM_GAPS.md).

## Build

```bash
export GHIDRA_INSTALL_DIR=<path to Ghidra install directory>
gradle buildExtension   # produces dist/ghidra_<ghidra version>_<date>_Ghidra-WASM.zip
```

After an intentional behaviour change, refresh the probe baseline with
`test-scripts/check-local.ps1 -Update` and commit `test-scripts/expected-results.json`.
