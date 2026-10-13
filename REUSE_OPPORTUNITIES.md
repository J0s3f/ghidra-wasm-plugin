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
   * Fix recipe (verified against the sources): the shared assembler
     `test-scripts/wasm_probe_lib.py:module()` concatenates its arguments without ordering, so every
     call site that passes `table_section`/`memory_section` before `func_section`, or
     `global`/`export` before `func`, emits a non-conformant module. ~23 call sites are affected
     (`gen_feature_probes.py` x6, `probes_types.py` x15, `probes_analysis.py`, `probes_multivalue.py`).
     Canonicalise inside `module()` with a rank map (custom sections first; **`datacount` (12) before
     `code` (10)** - the one id-order exception) plus a `sort=False` opt-out for the modules that are
     *deliberately* misordered (`D04_sections_wrong_order.wasm` in `make_malformed_corpus.py`, and any
     same-purpose case in the negative/section probe sets). The loader is order-independent, so the
     regenerated baseline should be byte-identical - any metric that moves is a finding in itself.
     Also fix the 8 export entries in `probes_multivalue.py` (`("f", 1, 1)` -> `("f", 0, 1)`; kind 1 is
     a table index). Re-run the scan over the *merged* tree, since per-agent probe files add new sites.
    * **STATUS: DONE.** All 201 probes now classify as 118 valid / 53 wabt-gap / 17 unsupported /
      13 invalid under wabt + binaryen; `test-scripts/check-fixture-validity.py` +
      `test-scripts/fixture-validity.json` lock in the classification and
      `.github/workflows/probes.yml` enforces it with wabt.
2. **Metric semantics**: our `instrs` metric counts pre-analyzer marker instructions
   (`.locals`, `.local`, `.case`, `.default`) - the reference module is **61,658 counted = 60,556 real
   wasm instructions + 1,102 markers**. Either expose `real_instrs` in `WasmFeatureReport.java` or
   document it; do not compare the raw count against other tools. *(Documented in MODERN_WASM_GAPS.md §2.4.)*
3. **Stale rows** in `MODERN_WASM_GAPS.md` §2.4 (probes 09/12/19/20) predate the GC/funcref work -
   **refreshed** (201 probes, current counts).
4. **New minor bug lead**: `WasmLoader.createData` logs a `Data markup conflict` warning on the three
   extended-const probes (`22`-`24`/`27`) - **still open**, worth a look.
5. **Binaryen confirmed open item B4** from the other direction: duplicate sections, section id 99,
   function-section-before-type and a declared-size mismatch were all *accepted* by our loader.
   **FIXED** by the `h1` workstream (23 of 24 such modules now reject with a diagnostic).

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

1. ~~Fix the probe fixtures (multivalue export kind, section order) and re-baseline; add the
   `wasm-dis`-based fixture-validity check to the harness/CI.~~ **DONE** (`MODERN_WASM_GAPS.md` 6.5):
   `wasm_probe_lib.module()` now canonicalises section order (custom sections keep their positions;
   `datacount` before `code`, `tag` between `memory` and `global`), the multivalue export kind is
   fixed, and 15 further individual fixture bugs were fixed. All 201 probes classify as
   118 valid / 53 wabt-gap / 17 unsupported / 13 invalid; `test-scripts/check-fixture-validity.py`
   + `test-scripts/fixture-validity.json` lock in the classification and
   `.github/workflows/probes.yml` enforces it with wabt.
2. ~~Refresh the stale doc rows and document the `instrs`-vs-real-instructions distinction. *(S)*~~
   **DONE** (2026-10-13, docs pass).
3. Investigate the extended-const `Data markup conflict` warning. *(S)* — **still open.**
4. Add the WABT/Binaryen decode-oracle comparison for the real corpus to the suite that already exists
   (`corpus-sweep.ps1`), so "our decode matches a second engine on real modules" becomes a checked
   property. *(S-M)* — **done in research** (`REUSE_OPPORTUNITIES.md` §1; byte-exact match on the
   reference module).
5. ~~**Stack-as-aggregate + SROA** (`WasmStackVariableAnalyzer`) *(M)*~~ **DONE** (`REPORT-SROA.md`).

   **Retypd port - decision: measure before porting** (assessment written after reading the
   Retypd pipeline at
   <https://decompilation.wiki/fundamentals/type-recovery/lattice-constraint-simp/>). The page
   documents the whole machinery: capability labels with variance (`load`/`σN@k` covariant,
   `store`/`in` contravariant), constraint generation from six IR pattern categories, a quotient
   graph with unification (including the `load`/`store` compatibility pairing), Add/Sub fixpoint
   propagation, initial sketches, and a pushdown system with Caucal saturation (O(n^3)) plus SCC
   breaking to expose recursive types. Three reasons not to port it wholesale:
   * Its value proposition is *polymorphic type inference from untyped machine code* (register
     moves, pointer arithmetic, unknown constants). WebAssembly is typed at the instruction level
     and our loader already emits real Ghidra datatypes (GC structs/arrays, DWARF, signatures,
     named labels), so most of Retypd's input signal is already available to Ghidra's own
     decompiler, which performs lattice-style type propagation internally.
   * The paper's 9.24 % -> 85 % struct-recovery number compares *NotDec* (a weak LLVM-IR-based
     decompiler) with and without Retypd. It does not transfer to Ghidra's decompiler; treating it
     as our target would be apples-to-oranges.
   * The engine is a Python package (GPL-3.0, so copyable, but a Python runtime/venv inside a Java
     Ghidra extension is a heavy deployment dependency), and a full Java reimplementation of the
     solver is L+ with permanent maintenance cost.

   **Decision (measured 2026-10-13 on the real module post-SROA): do NOT port Retypd.**
   `test-scripts/type_recovery_metric.py` over the decompiled C of all 437 functions found **591
   constant-offset field accesses** (`*(type *)(base + 0xNN)`), dominated by pointer-like
   parameters: `param2` 232 accesses, `param1` 187 across **38 distinct offsets**, `param3` 23,
   `param5`/`param6` 15 - i.e. ~77 % of the signal sits on ~5 parameter bases, with ~16 candidate
   structures (>= 2 offsets) and 10 with >= 3. Retypd's *intra-procedural* subset would type each
   function's `paramN` independently, producing many partial per-function structs for what is one
   shared struct per pointer in the source; the inter-procedural agreement that would merge them is
   the part the paper's own evaluation times out on. Porting a general polymorphic solver (Python
   engine with a venv inside a Java extension, or an L-sized Java reimplementation) is
   disproportionate for 591 accesses, and wasm already gives us the type/call-graph structure that
   Retypd has to infer.
   **Replacement (wasm-specific, M): call-graph-aware struct synthesis — IMPLEMENTED**
   (`REPORT-STRUCTS.md`): `WasmStructSynthAnalyzer` (call-graph union-find + struct synthesis)
   creates **352 structs** and retypes **255 parameters** on the real module, cutting
   constant-offset accesses **591 → 437 (−26 %)**. v1 limits documented in
   `MODERN_WASM_GAPS.md` 2.3.

## 6. External input: the Decompilation Wiki (read for the type-recovery decision)

Pages read: type-recovery/overview, type-recovery/var-detection, lattice-constraint-simp,
cfg-recovery/lifting, cfg-recovery/jump-resolving, structuring/overview,
structuring/schema-based/switch-structuring, structuring/gotoless, evaluation, applied-research/symbol-recovery,
applications/program-reconstruction (<https://decompilation.wiki/>). What it changes for us:

**A. A concrete recipe for the SROA workstream (adopt).** The variable-detection page describes
DIVINE's *Aggregate Structure Identification*: infer the frame size from the stack-pointer
adjustment, then split the region into **atoms** from the observed accesses - fixed-offset accesses
from a pointer (`[eax]`, `[eax+4]`, `[eax+16]`) are structure fields, and strided/affine patterns
become arrays - then iterate with value-set analysis. The same page notes **Ghidra performs VSA
intraprocedurally**, so the leverage is in feeding it a proper memory model, not in replacing its
typing. This is exactly what stack-as-aggregate + SROA does: size the aggregate from the frame
layout, then materialise one variable/field per observed (width, offset) access so Ghidra's own VSA
can propagate types through them. The SROA workstream should follow this recipe and evidence each
step.

**B. Two new feature candidates (recorded, not committed).**
1. *Toolchain/runtime symbol recognition*: wasm modules come from ~3 toolchains; recognizing
   wasm-bindgen (`__wbindgen_*`), Emscripten runtime/`dynCall_*`/`emscripten_*`, musl
   (`malloc`/`free`/`memcpy`...), Rust alloc/panic shims by name patterns plus structural
   fingerprints, and applying real names/signatures, is high-value for wasm RE. (The wiki's
   symbol-recovery page is ML-focused, which we deliberately do not adopt; the goal is validated,
   the method is classic fingerprinting.) *Effort M.*
2. *Array recovery from strided/affine access patterns in linear memory*: group computed addresses
   by base/stride (`4[8,22]`-style) to suggest arrays in linear memory (Emscripten/Rust heap
   buffers), using the wiki's strided-interval and affine-relation ideas. *Effort M.*

**C. Evaluation: add a quality metric, not just success metrics (adopt).** Our harness measures
decode/decompile *success* (functions decompiled, undefined bytes, instructions). The evaluation
page's variable-typing methodology is ground truth from **DWARF** compared against recovered
variable locations/types; we already ship DWARF line info and have debug-info-bearing corpus
modules, so a DWARF-based type/variable-recovery metric is cheap (S-M) and is exactly the
measurement needed for the Retypd decision in section 5. Also noted: source-relative structuring
metrics (gotos, boolean expressions, calls, graph edit distance - SAILR) and full-function
recompilability; a cheap proxy for us is counting gotos/labels in the decompiled C. Long-term
option: emulation-based differential correctness (we have the spec-assertion harness from h3).

**D. Confirmations (no action).** Lifting: P-Code is one of the listed ILs; our SLEIGH language +
pre-analyzer is the lifter. Jump resolving: wasm's indirect calls are typed and resolvable from
element segments, which the loader already does. Switch structuring: `br_table` makes the
compiler's switch lowering explicit, so jump-table recovery is unnecessary - but materialising the
case values for the decompiler is what makes Ghidra emit a `switch`, which the pre-analyzer already
does (bounded for huge tables, see SF03). Type recovery: wasm supplies the "type sinks" (explicit
signatures) for free, and lattice-based push-down typing is what Ghidra already performs internally
- further support for "SROA first, Retypd only if measured".
