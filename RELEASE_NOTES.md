# Ghidra-WASM 2.6.0

WebAssembly loader/plugin for Ghidra (disassembly + decompilation), maintained as a fork of
[nneonneo/ghidra-wasm-plugin](https://github.com/nneonneo/ghidra-wasm-plugin). This release lands the
whole "wrong analysis" tier plus the two biggest missing feature areas, and adds a machine-checked
correctness gate for all of it.

## Download

Use the asset that matches your Ghidra version - the name begins with `ghidra_12.1.4_PUBLIC_` for
Ghidra 12.1.4. Install with **File → Install Extensions → +** and restart Ghidra. You do not need to
unzip the file.

## New in 2.6.0

**No more silently wrong analysis (the "wrong analysis" tier):**

* **Unknown opcodes degrade gracefully.** An opcode the plugin does not implement is now decoded as a
  visible `unimplemented` instruction that consumes exactly the right number of operand bytes
  (stack switching `cont.new`/`cont.bind`/`suspend`/`switch`, JS string builtins, wide arithmetic,
  `memory.discard`, ...), instead of shifting the byte stream and blanking the function. Functions
  containing them still disassemble and decompile.
* **Multi-memory**: memarg memory indices (alignment bit 6) are decoded (`i32.load align=2 memidx=1
  offset=0`) and **every** memory gets a block (`MEMORY_STRIDE`-based placement; memory 0 keeps its
  original address), so `(memory 1)(memory 7)` no longer loses the second memory.
* **Memory/table limit flags**: shared, 64-bit and custom-page-size flags are decoded instead of
  desyncing the section (fixes silently dropped `maximum`/`shared` and misparsed following entries).
* **Constant expressions** are decoded instead of byte-scanned: extended-const chains are accepted
  *and folded* (`i32.const 1; i32.const 2; i32.add` becomes `3`), immediates containing `0x0B`
  (`f32`/`f64`/`v128.const`) no longer break the import, and unsupported initializers degrade to
  "unparsed" instead of aborting the whole module.
* **Unknown/typed reference types no longer crash**: `(ref null $t)` / `(ref $t)` parse with a
  width-correct placeholder, so GC/typed-reference modules import and decompile instead of throwing
  NPEs in the signature analyzer and the decompiler.

**New feature coverage:**

* **Garbage collection**: `rec`/`sub`/`struct`/`array` types (with named fields in the listing) and
  the `0xFB` instruction set (`struct.*`, `array.*`, `i31.*`, `ref.test/cast`, `br_on_cast*`,
  `any/extern.convert_*`, `ref.eq`), including GC values in initializer expressions.
* **New exception handling**: `try_table` with all four catch-clause kinds, `throw_ref` and the
  `exnref` type (`try_table` was previously an undefined byte that blanked the function).
* **Component model binaries** are no longer "no load spec found": the loader parses the component
  header and section framing, extracts the embedded core module and loads it as a real program.

**Verification infrastructure (why this release can be trusted):**

* `test-scripts/probes_*.py` + `run_probes.ps1` generate and measure **93 probe modules** covering the
  features above; `test-scripts/expected-results.json` records every metric.
* `.github/workflows/probes.yml` enforces the baseline on every push: a probe metric drift, a new
  probe without a baseline, a probe that unexpectedly imports (or fails to), or a decompiler
  regression on the committed fixture **fails the build**.
* `test-scripts/spectest/` runs the **official WebAssembly spec testsuite** headlessly: core subset
  271/271 modules imported, 33192 instructions, 2746/2747 functions decompiled, with the ranked
  findings documented in `MODERN_WASM_GAPS.md` §6 and `test-scripts/spectest-BASELINE.md`.

## Still open (tracked in `MODERN_WASM_GAPS.md`)

memory64 (64-bit addressing), multi-value *returns* (extra results are still dropped, work in
progress), `.name` label/field/tag names and name application (work in progress), typed-function
references' instruction (`call_ref`, `return_call_ref`), stack-switching/string-builtin *semantics*
(they decode as `unimplemented`), DWARF line info, and emulation-based spec `assert_*` execution. The
spec-suite findings also list smaller bugs (e.g. `select` after an unconditional terminator).

## Install / build

```bash
export GHIDRA_INSTALL_DIR=<path to Ghidra install directory>
gradle buildExtension   # produces dist/ghidra_<version>_<date>_ghidra-wasm-plugin.zip
```

The plugin now also keeps a per-probe correctness baseline; after an intentional behaviour change,
regenerate it with `test-scripts/check-local.ps1 -Update`.
