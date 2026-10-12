# What to reuse from other WebAssembly projects

Two research passes asked the same question of two very different codebases - *NotDec* (a research
decompiler, with its paper) and *Binaryen* (the reference C++ WebAssembly toolkit) - and then ran
experiments against **our** plugin. Full reports live on the `archive/reports` branch
(`reports/research/notdec-reuse-analysis.md`, `reports/research/binaryen-reuse-analysis.md`); this is
the actionable summary.

## 1. Independent cross-engine validation of our decoder (the best news)

Both passes measured our loader against an independent implementation:

| Oracle | Module | Result |
| --- | --- | --- |
| WABT 1.0.42 `wasm-objdump -d` | `rasterbator_rs_bg.wasm` | **60,556 / 60,556 real instruction starts byte-exact, 0 divergences** (437 functions = 39 imports + 398 bodies) |
| WABT | `rust_plain.wasm` / `rust_simd128.wasm` | 8542/8542 and 26/26 exact |
| Binaryen `wasm-dis` (release 133) | `rasterbator`, `rust_plain`, `rust_simd128`, one npm corpus module | **function counts exactly 437 / 1917 / 72 / 2**; all `undefined_bytes` are import stubs (0 real gaps) |
| Binaryen | probes | agrees our multi-memory fix: `i32.load align=0x2 memidx=0x1 offset=0x0` |

So the remaining work is fixture hygiene and analyzer quality - **not** decoding.

## 2. Our defects that the oracles exposed

1. **Invalid probe fixtures** (highest value fix, effort S).
   * Binaryen rejects **37 of our 127 probes**. Two concrete classes:
     * `test-scripts/probes_multivalue.py` writes the export kind byte as `1` (table) instead of `0`
       (function) in 8 places (`("f", 1, 1)` - bytes `66 01 01`) - those modules are invalid, yet they
       are the evidence base for `REPORT-MV.md`;
     * 8 probes emit the Table/Memory section *before* the Function section (section-order violation);
       even `wasm-validate --enable-all` rejects them. Our loader is lenient, so nothing complained.
   * Fix the generators, then re-baseline. **Then add a cross-engine validity gate** to the harness
     (`wasm-dis --all-features` accept/reject, wrapping it like the probes gate does) so an invalid
     fixture can never enter the baseline again.
   * Note: `wasm-opt` must **not** be the rejection oracle - in release 133 it aborts
     (`0xC0000409`) instead of failing cleanly. `wasm-dis` is the reliable one.
2. **Metric semantics**: our `instrs` metric counts pre-analyzer marker instructions
   (`.locals`, `.local`, `.case`, `.default`) - the reference module is **61,658 counted = 60,556 real
   wasm instructions + 1,102 markers**. Either expose `real_instrs` in `WasmFeatureReport.java` or
   document it; do not compare the raw count against other tools.
3. **Stale rows** in `MODERN_WASM_GAPS.md` §2.4 (probes 09/12/19/20) predate the GC/funcref work -
   refresh from a run.
4. **New minor bug lead**: `WasmLoader.createData` logs a `Data markup conflict` warning on the three
   extended-const probes (`22`-`24`/`27`) - worth a look.
5. **Binaryen confirmed open item B4** from the other direction: duplicate sections, section id 99,
   function-section-before-type and a declared-size mismatch were all *accepted* by our loader.
   The `h1` workstream addresses this (23 of 24 such modules now reject with a diagnostic).

## 3. What is worth porting (ranked)

| Candidate | Source / how it enters our plugin | Effort | Value | Licence |
| --- | --- | --- | --- | --- |
| **Cross-engine validity + decode oracle** in `test-scripts/` (WABT `wasm-objdump`/`wasm-validate`, Binaryen `wasm-dis`) | external tools fetched like the spec harness does; compare function counts, instruction start addresses, accept/reject | S | catches invalid fixtures and decode regressions on *real* modules | Apache-2.0 (tools used, not linked) |
| **Section/limit decoding rules** (`wasm-binary.h` invariants: section-loop `seenSections`, payload length, memarg bit 6, `getResizableLimits`, data offsets as expressions) | reimplement in Java, provenance-commented | S | closes B4-class leniency; mostly done by `h1` | Apache-2.0, reimplemented |
| **Intra-procedural type recovery via Retypd** (`retypd-ghidra-plugin`) | port the Java+Python halves, inter-procedural propagation **off** | L | the paper measures our ancestor at **9.24 % struct recovery vs 85 %** with this approach | GPL-3.0 - copyable into our GPL-3.0 project |
| **Stack-as-aggregate + SROA** (paper §3.2.3) | reimplement in `WasmStackVariableAnalyzer`; model the frame as one aggregate and split by (width, offset) | M | targets the known `Index 0 out of bounds` / `GenericAddress cannot be cast to Register` failures and the 22 skipped instructions | algorithm only (paper is CC BY-NC-ND: cite, do not copy) |
| **Test corpus** | Binaryen `test/lit` + WABT testsuite as extra probe inputs | S-M | broadens real-world coverage | Apache-2.0 |

## 4. What not to port

* **Any NotDec code**: the repository has **no licence at all** ("all rights reserved") and
  `NotDec-llvm2c` likewise - it cannot be copied into a GPL-3.0 project. Its lifter is also MVP+SIMD
  only and `std::abort()`s on modern opcodes, so it is useless even as a decode oracle. Only the
  *algorithms* described in the paper are usable, and the paper itself is CC BY-NC-ND (cite it; never
  copy text or figures).
* **Binaryen raw instruction/IR counts** as a gate: Binaryen is not byte-faithful - `IRBuilder`
  invents `$scratch` locals (proved by raw-parsing a function that declares 0 locals while `wasm-dis`
  prints a scratch local). Compare validity, semantics and function counts instead.
* **Inter-procedural Retypd** as a first step: the paper's own evaluation hits >24 h timeouts.
* **`wasm-decompile`**: it no longer exists in the Binaryen tree or release 133.

## 5. Suggested order of work

1. Fix the probe fixtures (multivalue export kind, section order) and re-baseline; add the
   `wasm-dis`-based fixture-validity check to the harness/CI. *(S, prevents invalid evidence)*
2. Refresh the stale doc rows and document the `instrs`-vs-real-instructions distinction. *(S)*
3. Investigate the extended-const `Data markup conflict` warning. *(S)*
4. Add the WABT/Binaryen decode-oracle comparison for the real corpus to the suite that already exists
   (`corpus-sweep.ps1`), so "our decode matches a second engine on real modules" becomes a checked
   property. *(S-M)*
5. Then the quality work: stack-as-aggregate + SROA (`WasmStackVariableAnalyzer`), and - if that
   leaves a struct-recovery gap worth closing - the intra-procedural Retypd port. *(M/L)*
