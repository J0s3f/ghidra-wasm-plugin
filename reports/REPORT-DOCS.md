# REPORT-DOCS: documentation pass for the 2.7.0 release

Workstream: docs (workstream). Branch: `docs/pre-release` (based on main @ 81cf985).
Date: 2026-10-13.

## What was updated

### 1. README.md — full rewrite

- Updated the description: loader + disassembler + decompiler for modern WebAssembly (Wasm 3.0 + active proposals).
- Added the complete supported-feature list (MVP through GC, new EH, function references, memory64,
  multi-memory, stack switching, JS string builtins, wide arithmetic, `memory.discard`, component-model
  extraction, DWARF line info, `.name` labels, stack SROA, call-graph struct synthesis, B9 warning).
- Added the test harness inventory (all scripts, dump tools, CI workflows).
- Updated install instructions (Ghidra 12.1.4 / 12.1.3 assets, File → Install Extensions).
- Added build-from-source instructions.
- Updated known limitations to the current 2.3 list.
- Added the dedicated `memory` address space description to the Internals section.
- Added license (GPL-3.0) and upstream credits.

### 2. MERGE_NOTES.md — added the fork's own workstreams

- Added a new table section "The fork's own workstreams (since the upstream merges)" listing all
  14 workstreams with their reports: section diagnostics + 64-bit data offsets, limits flags,
  constant-expression scanner rewrite, spec-suite gates, spec assert emulation, loader hardening,
  stack switching/strings/wide arith/`memory.discard`, name-section label targets, reference typing
  + `cont` types, stack SROA, call-graph struct synthesis, emulator coverage, dedicated memory space,
  B9 warning, fixture-validity gate.
- Updated the Verification section: 201-probe gate (183 imported + 18 expected failures), fixture
  baseline, real module (437/437, 156 stub bytes = 0 real gaps), spec suite (271 modules, 2747/2747),
  fixture-validity (118/53/17/13), emulation harness (33 suites, 92/92, assert_return 2511/4,
  assert_trap 183/0).
- Updated "Next steps" probe count: 21 → 201.

### 3. MODERN_WASM_GAPS.md — final pass

- Roadmap table: added 10 new rows for the fork's workstreams (all marked **merged**).
- §1: probe count 21 → 201; added `probes_*.py` to the generator list.
- §2.1: expanded the "Fully working" table with all newly-covered features (new EH, GC, typed
  function references, multi-memory, memory64, extended-const, stack switching, JS string builtins,
  wide arithmetic, `memory.discard`, `.name` label targets).
- §2.3: rewrote the "Still open" table to list only what is actually still open (custom page sizes,
  shared-everything threads, component-model semantics, `br_table large` assertion cases,
  struct-synthesis v1 limits, 128 MiB cap, `ref.null` numeric printing, multi-byte block signatures
  on `try`/`try_table`, extended-const `Data markup conflict`, emulation coverage). Removed all
  fixed items (B3, B8, reference-typing precision, `ref.null` concrete type, `cont` types, memory
  index >= 8, `guessCStackGlobalForFunction`, type-recovery, B9 warning).
- §2.4: updated all counts (201 probes, 118/53/17/13 classification, 33222 instructions, 428
  undefined bytes, emulation harness stats).
- §3: updated toolchain relevance (GC/funcref now covered, new EH covered, memory64 covered below
  4 GiB, JSPI decodes).
- §4: updated status line (items 0-10 implemented).
- §6: updated spec-suite baseline (0 real undefined bytes, 0 decompile failures, 2747/2747);
  marked all 5 ranked findings as resolved.
- §6.2: removed "partly fixed" qualifier (now fully fixed).
- §6.4: updated negative-test baseline (130 rejected / 2818 accepted / 0 partial / 0 crash / 0 hang).
- §6.5: updated fixture-validity classification (201 probes: 118 valid / 53 wabt-gap / 17
  unsupported / 13 invalid; 13 `oracle_skip` entries).
- §10: updated longer-term section (most items now implemented).

### 4. RELEASE_NOTES.md — wrote the 2.7.0 body

- Headline: "Ghidra-WASM 2.7.0".
- Download/install instructions (12.1.4/12.1.3, cleaned zips).
- New in 2.7.0 sections: Decoder/loader (dedicated memory space, section diagnostics + 64-bit data
  offsets, reference typing + cont types, B9 warning, 128 MiB cap), New feature coverage (stack
  switching, JS string builtins, wide arithmetic, `memory.discard`, `.name` label targets),
  Decompiler quality (stack SROA, call-graph struct synthesis), Verification infrastructure
  (201-probe gate, fixture-validity gate, spec-suite CI gate, emulation harness, type-recovery
  metric).
- "Also included in earlier releases" section (2.6.1, 2.6.0 summaries).
- Known open items (the 2.3 list).
- Build instructions.

### 5. src/main/help/help/topics/WebAssembly/help.md — updated in-Ghidra help

- Updated the description and feature list to match the README.
- Removed the stale "Multiple return values are untested" limitation (multi-value returns are
  implemented since 2.6.1).
- Added the current known limitations (custom page sizes, shared-everything threads,
  component-model semantics, 128 MiB cap, stack switching decode-only, `ref.null` numeric
  printing).
- Added the dedicated `memory` address space description to the Internals section.
- Added upstream credits.

### 6. test-scripts/spectest/README.md — swept for stale instructions

- Added `-WabtOnly` flag to the fetch instructions.
- Added `wasm-validate` to the wabt tools list.
- Added `simd` and `all` to the `-Subset` options.
- Added a new §4 "CI gate" section documenting `check-spectest.py`.
- Added a new §5 "Emulation assertions" section documenting `run_emulate.ps1`,
  `parse_emulate_report.py`, and their flags.
- Renumbered the negative tests section (5 → 7).
- Fixed the typo "module/fuction" → "module/function".

### 7. REUSE_OPPORTUNITIES.md — swept for stale instructions

- §2.1: added "STATUS: DONE" with current 201-probe classification.
- §2.2: marked as documented.
- §2.3: marked as refreshed.
- §2.4: marked as still open.
- §2.5: marked as FIXED.
- §5: updated all items — item 1 (fixture-validity gate) now says 201 probes / 118-53-17-13;
  item 2 (stale doc rows) marked DONE; item 3 (Data markup conflict) marked still open; item 4
  (decode-oracle comparison) marked done in research; item 5 (SROA) marked DONE; Retypd decision
  updated with the implemented struct-synthesis replacement.

### 8. Source comment fix (mechanical only)

- `src/main/java/wasm/WasmLoader.java` line 108: fixed stale comment "256 MiB" → "128 MiB"
  (MEMORY_STRIDE is now 0x08000000 = 128 MiB; memories live in the dedicated `memory` space).

## Commands verified

All script names, flags, and workflow names in the docs were verified by reading the actual
files:

- `test-scripts/check-local.ps1` — `-SkipBuild`, `-RealModule`, `-Update`, `-GhidraDir`
- `test-scripts/run_probes.ps1` — `-OutDir`, `-GhidraDir`, `-Generators`, `-Only`, `-Detail`,
  `-NoAnalysis`, `-MaxCpu`, `-MaxMem`, `-Force`
- `test-scripts/check-fixture-validity.py` — `--probes`, `--wabt`, `--binaryen`, `--expected`,
  `--generate`, `--update`, `--timeout`, `--invalid`, `--unsupported`; `oracle_skip` in JSON
- `test-scripts/spectest/run_spectest.ps1` — `-Subset`, `-Files`, `-MaxPerWast`, `-Detail`,
  `-NoPrepare`, `-ToolsDir`, `-OutDir`, `-GhidraDir`, `-MaxCpu`, `-MaxMem`, `-SkipFetch`
- `test-scripts/spectest/check-spectest.py` — `--summary`, `--expected`, `--subset`, `--update`
- `test-scripts/spectest/run_emulate.ps1` — `-Files`, `-MaxCommands`, `-MaxSteps`, `-OutDir`,
  `-GhidraDir`, `-PythonExe`, `-NoPrepare`, `-Force`
- `test-scripts/spectest/run_spectest_negative.ps1` — `-Kinds`, `-MaxPerWastPerKind`, `-ChunkSize`,
  `-TimeoutSec`, `-WithAnalysis`, `-SkipPrepare`, `-ImportDir`, `-ModulesJson`
- `test-scripts/spectest/fetch_spectest_tools.ps1` — `-ToolsDir`, `-WabtOnly`
- `test-scripts/spectest/parse_emulate_report.py` — `<report-dir> <out-dir>`
- `test-scripts/corpus-sweep.ps1` — exists, verified
- `test-scripts/robustness-sweep.ps1` — exists, verified
- `test-scripts/make_malformed_corpus.py` — exists, verified
- `test-scripts/probes_negative.py` — exists, verified
- `test-scripts/type_recovery_metric.py` — `--decomp`, `--stackvars`, `--json`
- Dump tools: `DumpDecomp.java`, `DumpAll.java`, `DumpNames.java`, `DumpStackVars.java`,
  `DumpTypes.java`, `ListProgram.java`, `WasmFeatureReport.java`, `EmulateExport.java` — all exist
- Probe generators: `gen_feature_probes.py` + 24 `probes_*.py` files — all exist
- Workflows: `.github/workflows/build.yml`, `probes.yml`, `spectest.yml`, `release.yml` — all exist
- `test-scripts/expected-results.json`: 201 probes (183 import_ok + 18 import failures)
- `test-scripts/fixture-validity.json`: 201 probes (118 valid / 53 wabt-gap / 17 unsupported /
  13 invalid; 13 `oracle_skip: ["binaryen"]`)
- `test-scripts/spectest-expected.json`: core subset (271 imported, 2747/2747 decompiled,
  33222 instructions, 428 undefined bytes, 0 real undefined bytes, 0 decompile failures)
- `build.gradle`: excludes `test-scripts/**`, `.github/**`, `MERGE_NOTES.md`, `MODERN_WASM_GAPS.md`,
  `RELEASE_NOTES.md`, `REPORT-*.md` from the release zip

## What was NOT done

- Did NOT touch `test-scripts/expected-results.json`, `test-scripts/fixture-validity.json`,
  the probes, or the CI workflows.
- Did NOT push, merge or tag.
- Did NOT add any `REPORT-*.md` files to main (this `REPORT-DOCS.md` stays on the
  `docs/pre-release` branch only).
- Did NOT run `build-install.ps1` + the gate after the source comment fix (the pinned Ghidra
  install at `C:\Users\micro\AppData\Local\Temp\ghidra-h3` may not be available in
  this workstream's environment; the comment change is a one-word fix that cannot affect
  behaviour).
- Did NOT verify the `run_emulate.ps1` PyGhidra venv provisioning (needs a Windows host with
  `py -3.13`).

## Anything unverified

- The `build-install.ps1` + `check-local.ps1 -SkipBuild -RealModule ...` gate was not run after
  the WasmLoader.java comment fix (the pinned Ghidra install path may not be accessible from
  this workstream). The fix is a comment-only change (one word: "256 MiB" → "128 MiB") and cannot
  affect behaviour.
- The `ghidra_scripts/spectest.py` PyGhidra script was not re-read in full; its existence was
  confirmed by glob.
- The `test-scripts/corpus/`, `test-scripts/fixtures/` directories were not re-verified (not
  needed for the docs pass).
