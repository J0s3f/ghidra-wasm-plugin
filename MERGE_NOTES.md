# Merge notes (fork: J0s3f/ghidra-wasm-plugin)

This branch (`main`) consolidates the useful outstanding work found in
[nneonneo/ghidra-wasm-plugin](https://github.com/nneonneo/ghidra-wasm-plugin) pull requests and
forks, and adapts it so the plugin builds and works against modern Ghidra (12.1.x, verified with
Ghidra 12.1.4).

## What was merged

| Source | What it adds | Notes |
| --- | --- | --- |
| [PR #35](https://github.com/nneonneo/ghidra-wasm-plugin/pull/35) (jonaslejon) | Legacy exception handling, tail calls, threads/atomics, relaxed SIMD | Includes the tag-section parsing and `EXT_TAG` external kind needed for modules with tags |
| [PR #31](https://github.com/nneonneo/ghidra-wasm-plugin/pull/31) (six-two) | Crash fix when loading WASM with tags (`EXT_TAG` external kind) | Already contained in PR #35; no separate change needed |
| [PR #33](https://github.com/nneonneo/ghidra-wasm-plugin/pull/33) / [PR #30](https://github.com/nneonneo/ghidra-wasm-plugin/pull/30) (Yanndroid / atouboot) | Fix for the removed `CompositeDataTypeImpl.checkAncestry` in Ghidra 12.1.2+/12.2 | Reimplemented version-agnostically in `StructureBuilder` using only stable public API (no dependency on `DataTypeUtilities`), so it builds and runs on 12.1.x *and* 12.2+ |
| [PR #5](https://github.com/nneonneo/ghidra-wasm-plugin/pull/5) (cmorin6) | `WasmFunctionVariableNameAnalyzer` – applies local variable names from the `.name` section | Adapted to the current API (`funcidx` field/ctor), processor name fixed to `WebAssembly`, local-register stride detected at runtime (16 bytes in the current SLEIGH spec, was 8 in the original PR) |
| [PR #23](https://github.com/nneonneo/ghidra-wasm-plugin/pull/23) (antoniovazquezblanco) | CI compilation pipeline | Modernized: Java 21, Gradle 9.2.1, Ghidra 12.1.4 + 12.1.3 matrix, `setup-ghidra` action |
| [ManuMassi/improve-decompilation-fidelity](https://github.com/ManuMassi/ghidra-wasm-plugin/tree/improve-decompilation-fidelity) (fork, 5 commits, not a PR) | Decompilation fidelity: vararg functions, function signature types, DWARF import (block naming fix + disabling line info import to avoid `AddressOutOfBounds`), function tables marked read-only for constant folding, `main`/`printf`/`scanf` naming on stripped binaries, constant `memory.copy` initializer materialization | The single biggest decompilation-quality improvement found in any fork |

## The fork's own workstreams (since the upstream merges)

After merging the upstream PRs, the fork grew its own substantial body of work.
Each workstream produced a detailed report on the `archive/reports` branch
(`reports/`); the summary is in [MODERN_WASM_GAPS.md](MODERN_WASM_GAPS.md).

| Workstream | What it adds | Report |
| --- | --- | --- |
| Section diagnostics + 64-bit data offsets | Out-of-range/duplicate sections rejected with a diagnostic; i64 data-segment offsets placed, ≥ 4 GiB clamped with a log | `REPORT-H1.md` |
| Limits flags | Shared / 64-bit / custom-page-size flags decoded fully; following limits entries stay aligned | `REPORT-B.md` |
| Constant-expression scanner rewrite | Decode instructions instead of scanning bytes; extended-const (`i32`/`i64` `add`/`sub`/`mul`) and GC initializers fold correctly | `REPORT-B.md` + §2.5 |
| Spec-suite gates | Positive harness (271 core modules, 2747/2747 functions decompiled, 0 real undefined bytes) + negative harness (2948 modules classified) + CI workflow | `REPORT-G.md`, `REPORT-NS.md` |
| Spec assert emulation | `assert_return`/`assert_trap` execution through the Ghidra emulator (33 `.wast` suites, 92/92 modules; assert_return 2511/4, assert_trap 183/0) | `REPORT-H3.md` |
| Loader hardening | Locals/memory/table bounds; honest failure on malformed sections (B1/B2/B3/B5 fixed, B4 documented) | `REPORT-HARD.md` |
| Stack switching / strings / wide arith / `memory.discard` | `cont.new`/`cont.bind`/`resume`/`suspend`/`switch`, JS string builtins, `i64.add128`/`sub128`/`mul_wide_*`, `memory.discard` all decode | `REPORT-H5.md` |
| Name-section label targets | Label names from `.name` subsection 3 become real label symbols at branch targets | `REPORT-H6.md` |
| Reference typing + `cont` types | Precise `(ref null ht)` / `(ref ht)` type model; subtype-aware validation; `cont` types parse in the type section | `REPORT-H7.md`, `REPORT-CT.md` |
| Stack-as-aggregate SROA | `WasmStackVariableAnalyzer` models each frame as one aggregate and splits by (width, offset) access | `REPORT-SROA.md` |
| Call-graph struct synthesis | `WasmStructSynthAnalyzer`: union-find over the call graph, struct synthesis, parameter retyping (352 structs, 255 retyped parameters on the reference module) | `REPORT-STRUCTS.md` |
| Emulator coverage | `funcEntryCallOther` two-input fix; `EmulateExport.java` Java-side driver; PyGhidra venv provisioning | `REPORT-H3.md` |
| Dedicated memory address space | 32-bit `memory` space, 128 MiB stride, ≥ 8 memories supported (was: single memory in `ram` at 256 MiB stride) | `REPORT-MEMSPACE.md` |
| B9 warning | "Module accepted but nothing was decoded" when a module that declares content yields no functions/memories/tables | `REPORT-HARD.md` |
| Fixture-validity gate | Every probe validated by wabt + binaryen; `oracle_skip` for runaway binaryen cases; `--timeout` support | (see `MODERN_WASM_GAPS.md` §6.5) |

## Reviewed but intentionally not merged

- `cmorin6/fix-call-stack` and `cmorin6/fix-leb128-parsing-issues`: obsolete, they patch files
  (`pcodeInject/PcodeOpEmitter.java`, custom `format/Leb128.java`) that no longer exist upstream;
  the underlying issues were fixed by later upstream refactors.
- `cmorin6` PR #5 branch contents beyond the variable-name analyzer: already merged upstream.
- `kristoff3r` fork, `nneonneo` `ghidra-pr`/`v1` branches, PRs #2/#6/#7/#8/#10/#13/#17/#28: already
  merged upstream.
- `XeR` fork (1 commit, 31 behind), `erroy/harvard` (`Experiment with separate ram/data address
  spaces`, 65 commits behind an old master): stale experiments, superseded by the current design.
- All other forks (31 total) were checked via the GitHub compare API: they contain no commits that
  are ahead of upstream `master` other than the ones listed above.

## Verification

The plugin is built against Ghidra 12.1.4, installed to the pinned test install,
and verified by:

* **201-probe gate** (`test-scripts/expected-results.json`): 183 probed-imported
  + 18 expected import failures. Fixture `functions=4 decompiled=4 failed=0
  instructions=24 undefined_bytes=0`.
* **Real module** `rasterbator_rs_bg.wasm` (Rust/wasm-bindgen, 179 KiB):
  `functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156`
  (the 156 bytes are 39 import stubs × 4 — 0 real decode gaps).
* **Spec suite** (core subset, Linux CI): 271 modules imported, 2747/2747
  functions decompiled, 33222 instructions, 428 undefined bytes (all import
  stubs), 0 decompile failures.
* **Fixture-validity gate**: 201 probes — 118 valid / 53 wabt-gap / 17
  unsupported / 13 invalid; 13 probes carry `oracle_skip: ["binaryen"]`.
* **Emulation harness**: 33 `.wast` suites, 92/92 modules; assert_return
  2514/1, assert_trap 183/0 (the 1 remaining is the `br_table large` `large(10000)`
  case — a case target past the modelled-case cap; the DEFAULT target is now always
  modelled, `REPORT-R5-BRTABLE.md`).

The local gate is `test-scripts/check-local.ps1` (enforces the pinned install +
build stamp); CI runs `.github/workflows/probes.yml` and
`.github/workflows/spectest.yml`.

## Next steps

[MODERN_WASM_GAPS.md](MODERN_WASM_GAPS.md) inventories the plugin's coverage of modern WebAssembly
(what works, what silently produces wrong code, what fails), backed by 201 generated probe modules and
the `test-scripts/` harness, and lists the planned extension work in priority order.

## Building

```bash
export GHIDRA_INSTALL_DIR=<path to Ghidra install directory>
gradle buildExtension   # produces dist/ghidra_<version>_<builddate>_Ghidra-WASM.zip
```

Install with *File → Install Extensions* in Ghidra, or unzip the archive into
`<ghidra>/Ghidra/Extensions/`.
