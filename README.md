Module to load WebAssembly files into Ghidra, supporting disassembly and decompilation
of modern WebAssembly (Wasm 3.0 + active proposals).

> **Fork note:** this fork (`main`) merges the outstanding upstream pull requests and
> the useful work found in downstream forks, and extends the plugin with substantial
> modern-WASM support (GC, new EH, function references, memory64, multi-memory,
> stack switching, JS string builtins, wide arithmetic, component-model extraction,
> and more). It is verified to build and run against Ghidra 12.1.x (12.1.3 and 12.1.4).
> Prebuilt extensions are attached to the
> [releases](https://github.com/J0s3f/ghidra-wasm-plugin/releases) of this fork. See
> [MERGE_NOTES.md](MERGE_NOTES.md) for the list of merged changes and verification results
> (the detailed per-workstream reports live on the [archive/reports](../../tree/archive/reports/reports) branch),
> and
> [MODERN_WASM_GAPS.md](MODERN_WASM_GAPS.md) for a feature-by-feature inventory of modern WebAssembly
> support (with a probe harness and roadmap for extending it).

## Features

### Core (WebAssembly 1.0 / MVP)

- Support for all WebAssembly 1.0 opcodes
- Cross-references for function calls and branches
- Cross-references for table entries and globals containing function pointers
- Recovery of the C stack, when the stack pointer is stored in a global variable
  (typical for compilers like Emscripten)
- Graceful degradation: unknown opcodes are decoded as visible `unimplemented`
  instructions that consume exactly the encoded operand bytes, so one unsupported
  instruction does not blank the rest of the function

### Modern WebAssembly proposals

- **Bulk memory**: `memory.init`, `data.drop`, `memory.copy`/`memory.fill`,
  `table.init`/`copy`/`fill`/`grow`/`size`, data-count section
- **Reference types**: `externref`/`funcref` params/globals/tables,
  `table.get`/`set`, `ref.null`/`ref.func`/`ref.is_null`, typed `select`
- **SIMD** (0xFD, all opcodes) and **relaxed SIMD** (0xFD ≥ 0x100)
- **Threads & atomics** (0xFE: loads, stores, RMW, `wait`/`notify`, `fence`)
- **Tail calls**: `return_call`, `return_call_indirect`
- **Legacy exception handling**: `try`/`catch`/`catch_all`/`throw`/`rethrow`/`delegate`,
  tag section
- **New exception handling**: `try_table`, `throw_ref`, `exnref`,
  `catch`/`catch_ref`/`catch_all`/`catch_all_ref` clauses
- **Garbage collection**: `rec`/`sub`/`struct`/`array` types, the full `0xFB`
  instruction set (`struct.new`/`struct.get`/`array.new`/`array.get`/`i31.*`,
  `ref.test`/`ref.cast`/`br_on_cast`/`br_on_cast_fail`, `any.convert_extern`/
  `extern.convert_any`), GC constant expressions
- **Function references**: `call_ref`, `return_call_ref`, `ref.as_non_null`,
  `br_on_null`, `br_on_non_null`; precise `(ref null ht)` / `(ref ht)` type model
- **Multi-value**: blocks with type-index blocktypes, functions returning multiple
  results as a packed struct visible to the decompiler
- **Multi-memory**: every declared memory has an independent address space, including
  zero-sized memories, large offsets, and memory indices above 31
- **memory64**: full 64-bit effective addresses in `memory64` and per-memory spaces;
  scalar, SIMD, atomic, and copy operations preserve the selected memory
- **Extended constant expressions**: `i32`/`i64` `add`/`sub`/`mul` in initializers
- **Stack switching / JSPI**: `cont.new`, `cont.bind`, `resume`, `suspend`, `switch`
  (decoded; `cont` types parse in the type section)
- **JS string builtins** (stringref, 0xFB ≥ 0x80): decoded
- **Wide arithmetic** (0xFC 0x13–0x16): `i64.add128`/`i64.sub128`/`i64.mul_wide_s`/`i64.mul_wide_u`
- **`memory.discard`** (0xFC 0x12): decoded
- **Component model**: component binaries recognised; embedded core modules import
  as real programs
- **DWARF source line info**: `.debug_line` rows map to source files and lines
- **`.name` section**: function/global/local/table/memory/elem/data/type/field/tag
  names; label names become real label symbols at branch targets
- **Stack-as-aggregate SROA**: `WasmStackVariableAnalyzer` models each frame as one
  aggregate and splits it by (width, offset) access, so Ghidra's VSA can propagate
  types through stack slots
- **Call-graph-aware struct synthesis**: `WasmStructSynthAnalyzer` clusters
  constant-offset accesses per pointer class across the call graph, synthesizes
  Ghidra structs, and retypes parameters (352 structs, 255 retyped parameters,
  591 → 437 raw offset accesses on the reference module)
- **B9 warning**: a module that declares content but yields nothing decoded logs
  "Module accepted but nothing was decoded"

![Sample disassembly and decompilation](sample.png)

## Installing

### Prebuilt Extension

The easiest way to install the plugin is as a Ghidra extension. Grab a
[release](https://github.com/J0s3f/ghidra-wasm-plugin/releases) that is
compatible with your version of Ghidra — for example, if you're using Ghidra
12.1.4, download the file beginning with `ghidra_12.1.4_PUBLIC`. You don't need
to unzip the file: simply launch Ghidra, go to "File → Install Extensions",
select the + icon, and select the zip file. Restart Ghidra to load the extension
and you should be good to go. **Note:** if you upgrade your version of Ghidra,
you will need to upgrade your plugin too.

### Custom Build

If there is no release for your version of Ghidra, or you want to install a
modified version, you may build and install from source instead. You'll need
Gradle and a Java compiler. Run the following commands from the root of this
repository:

```bash
export GHIDRA_INSTALL_DIR=<path to Ghidra install directory>
gradle buildExtension
```

`GHIDRA_INSTALL_DIR` should be the directory that contains the Ghidra
installation, i.e. the directory containing `Extensions`, `Ghidra`, `ghidraRun`,
`support` and so on.

If all goes well, the zipped plugin will be placed in the `dist` directory and
can be installed using "File → Install Extensions" as before.

The release assets are *cleaned* zips: the development harness
(`test-scripts/`), CI configuration (`.github/`) and internal documentation
(`REPORT-*.md`) are excluded via `build.gradle`.

## Test harness

The plugin ships a comprehensive test harness under `test-scripts/`:

| Script / tool | What it does |
| --- | --- |
| `check-local.ps1` | The local gate: build + install, run the full probe suite, check the fixture decompile baseline and the real-module baseline. Enforces the pinned Ghidra install and build stamp. |
| `run_probes.ps1` | Generates all probe modules (`gen_*.py` + `probes_*.py`), imports them headlessly, and reports per-program metrics. |
| `gen_feature_probes.py` + `probes_*.py` | Byte-level probe generators for every supported feature (223 probes). |
| `check-results.py` | Compares probe-run metrics against `expected-results.json`; `--update` re-records. |
| `check-fixture-validity.py` | External-oracle classification of every probe (wabt `wasm-validate`, optionally binaryen `wasm-dis`); supports `--timeout`, `--update`, `oracle_skip`. |
| `spectest/run_spectest.ps1` | Runs the official WebAssembly spec testsuite (core subset) through the loader/decompiler headlessly. |
| `spectest/check-spectest.py` | CI gate for the spec-suite baseline (`spectest-expected.json`). |
| `spectest/run_spectest_negative.ps1` | Negative harness: `assert_invalid`/`assert_malformed` modules. |
| `spectest/run_emulate.ps1` | Emulation assertion harness: runs `assert_return`/`assert_trap` from `.wast` suites through the Ghidra emulator (needs a PyGhidra venv). |
| `spectest/parse_emulate_report.py` | Aggregates per-command emulation results. |
| `corpus-sweep.ps1` | Imports a real-world wasm corpus and reports where it breaks. |
| `robustness-sweep.ps1` | Imports malformed modules and classifies outcomes. |
| `make_malformed_corpus.py` | Generates the malformed-input corpus. |
| `probes_negative.py` | Reduced reproducers for the worst negative-suite findings. |
| `type_recovery_metric.py` | Type-recovery proxy metric over decompiled C. |
| `DumpDecomp.java`, `DumpAll.java`, `DumpNames.java`, `DumpStackVars.java`, `DumpTypes.java`, `ListProgram.java`, `WasmFeatureReport.java`, `EmulateExport.java` | Headless dump/report tools. |

### CI workflows

| Workflow | What it enforces |
| --- | --- |
| `.github/workflows/build.yml` | Builds the extension against Ghidra 12.1.4 and 12.1.3. |
| `.github/workflows/probes.yml` | Runs the 223-probe suite + fixture decompile baseline + fixture-validity gate (wabt). |
| `.github/workflows/spectest.yml` | Runs the spec core subset (271 modules) and checks the decode/decompile baseline. |
| `.github/workflows/release.yml` | Builds and publishes release assets on tag push (`v*`). |

## Tips

- Many Wasm programs, especially those compiled by Emscripten or Clang, use a
  global variable to store the C stack pointer. This plugin will attempt to
  automatically detect the C stack pointer during analysis; if it fails, you may
  need to set it yourself before performing initial analysis by setting the "C
  Stack Pointer" in the Wasm Pre-Analyzer settings.
- By default, the C stack is assumed to grow in the negative direction, i.e.
  towards smaller addresses. However, compilers are actually free to choose either
  stack direction, and both positive and negative-growing stacks have been
  observed in real-world samples. If your C stack grows upwards (e.g. indicated by
  an add operation to the C stack pointer in the function prologue rather than a
  subtract), select the `pos-stack` compiler when importing the file, or via `Set
  Language...` on an existing file in the project window.
- Emscripten will usually translate function pointer calls into calls to
  exported `dyncall_` functions, which take a call-type-specific index as the
  first parameter. The index is used to index a sub-section of the main function
  table (table0) to find the function to call. The included script
  `analyze_dyncalls.py` can analyze the `dyncall_` functions, extract the indices,
  and rename referenced functions according to their call type and function index
  (which will often serve as function pointer values in memory). This can be used
  to resolve function pointer references, for example.
- Element segments may be passive, or have offset expressions that depend on
  imported globals. In this case, the element segments are not automatically
  loaded to the table. You can manually load these segments by calling
  `WasmLoader.loadElementsToTable`. For example, to load element segment #0 to
  table #1 at offset 2 in Python:

  ```python
  from wasm import WasmLoader
  from wasm.analysis import WasmAnalysis
  from ghidra.util.task import ConsoleTaskMonitor
  monitor = ConsoleTaskMonitor()
  WasmLoader.loadElementsToTable(currentProgram, WasmAnalysis.getState(currentProgram).module, 0, 1, 2, monitor)
  ```
- Similarly, data segments can be manually loaded as well. For example, to load
  data segment #5 to memory #0 at offset 0x1000, do the following in Python:

  ```python
  from wasm import WasmLoader
  from wasm.analysis import WasmAnalysis
  from ghidra.util.task import ConsoleTaskMonitor
  monitor = ConsoleTaskMonitor()
  WasmLoader.loadDataToMemory(currentProgram, WasmAnalysis.getState(currentProgram).module, 5, 0, 0x1000, monitor)
  ```

## Limitations and Known Bugs

See [MODERN_WASM_GAPS.md](MODERN_WASM_GAPS.md) for a feature-by-feature inventory of what the plugin
does and does not understand in modern WebAssembly, how each gap was measured, and the planned
fix order. In summary, the still-open items are:

- **Shared-everything threads**: `global.atomic.*`, shared tables / `table.atomic.*` have no
  mnemonics (the 0xFE atomic *memory* ops are implemented).
- **Component-model semantics**: canonical ABI, `canon` ops, component types are not modelled
  (core-module extraction only, by design).
- **Struct-synthesis v1 limits**: `call_indirect` targets not followed, delta arguments skipped,
  only parameters retyped, globals/SIMD lanes skipped, fields are `undefinedN`.
- **128 MiB materialisation cap**: the loader maps at most 128 MiB per memory and
  reports data outside that prefix. Addressing and emulator banks remain independent
  beyond the mapped prefix; large memories no longer alias neighboring memories.
- **Cosmetic listings**: `blocktype=-0xNN` on `block`/`loop`/`if`/`try`/`try_table` and the `ht=`
  operands of `ref.test`/`ref.cast`/`br_on_cast*` still print numerically (`ref.null` abstract heap
  types now print by name).

In addition:

- Currently, inlining functions (via marking them "In Line") is not supported
  and will confuse the decompiler. This is because the inlined function's
  references to stack and local variables will affect the caller. I tried to solve
  this limitation by injecting code to save and restore stack and locals on
  function entry/exit, but ran into a Ghidra limitation — the decompiler does not
  inject "uponentry" Pcode into inlined functions.
- Currently, there is no way to change the C stack pointer after initial analysis
  (attempting to re-analyze the program with a new C stack pointer will not change
  anything).
- Initial analysis and disassembly can be very slow. This is primarily because
  Ghidra is quite slow at setting large numbers of context registers.

## Internals

This module uses a pre-analyzer (WasmPreAnalyzer) to analyze all functions and
opcodes, providing contextual information to the SLEIGH disassembler to enable
correct disassembly (for example, operand sizes when they depend on the types in
the value stack, branch target addresses, etc). In order to support recovery of
the C stack, this module converts Wasm stack operations into operations on a
register file. This frees up the decompiler's stack analysis to focus on the
behaviour of the C stack, since the decompiler only supports a single stack.
Additionally, parameter passing and returns are handled by virtual input/output
registers which are copied to/from the stack and locals registers via Pcode
injection.

Four different types of "registers" are defined: input (iN), output (oN), stack
(sN) and locals (lN). Of these, only the locals will be visible in the
disassembly; stack registers will appear in the PCode, and input/output
registers will appear in function types.

Memory 0 uses the 32-bit `memory` or 64-bit `memory64` space, according to its
declared index type. Each secondary memory uses a program overlay named `memory_N`
or `memory64_N`. Effective addresses are offsets within that space, without a stride.
Dynamic pcode fixups resolve memory accesses to the correct program space; the
emulator maintains independent banks, including unmapped and newly grown pages.

Large `br_table` vectors use a read-only selector table in the `brtable` space.
Repeated labels share one modeled branch and its stack relocation. Every case and
the default remain represented, while the control-flow graph scales with distinct
labels rather than the vector length.

After upgrading to 2.8.2, **reimport existing Wasm programs** to regenerate memory
spaces, instruction context, and large-table selector data. Saved programs from
earlier versions retain their previous layout and context.

## Acknowledgements

- This plugin borrows loader functionality from this repo: https://github.com/andr3colonel/ghidra_wasm
- This plugin was directly based on https://github.com/garrettgu10/ghidra-wasm-plugin
- Upstream: https://github.com/nneonneo/ghidra-wasm-plugin (GPL-3.0)

## License

GPL-3.0 (same as upstream nneonneo/ghidra-wasm-plugin). See [LICENSE](LICENSE).
