# NotDec → Ghidra-WASM: reuse / port analysis

Scope: what of **NotDec** (repo + ICSE'26 paper) is worth taking into this GPL-3.0 Ghidra WASM
plugin, on what port path, at what cost, and where the licence forbids it. Everything below was
measured on this machine; commands and raw numbers in §4. Files were read, not modified — the
plugin repo is untouched.

---

## 1. What NotDec and the paper are

**NotDec** (`github.com/NotDec/NotDec`, default branch head `0399bf0`, 2026-01-07, C++, ~38 `.cpp`
in the top-level repo) is a *from-scratch* WebAssembly→C decompiler built as a three-stage compiler
pipeline (paper Fig. 1). The **front end is a separate, MIT-licensed repo**
(`NotDec-wasm2llvm`, pinned `c3c2c18`) that parses with **WABT** as a library
(`wabt/binary-reader-ir.h`) and lifts bytecode to *deliberately naive* LLVM-14 IR: locals and
globals become mutable memory, linear memory becomes one global byte array, the operand stack is
resolved directly into LLVM SSA values, `br_table` becomes a `switch`, and each element-segment
table becomes a global array of function pointers for `call_indirect`
(`lib/notdec-wasm2llvm/parser-instruction.cpp`, 2151 lines). The **middle end**
(`src/Passes/*.cpp`, `src/TypeRecovery/**`) runs LLVM optimisations, matches low-level patterns
(stack-pointer adjust → stack allocation; runs of same-value stores → memset; `src/Passes/StackAlloca.cpp`,
`StackPointerFinder.cpp`, `MemOpMatcher.cpp`, `DSROA.cpp` = a modified copy of LLVM's `SROA`
pass for runtime-sized stack frames), then does **type recovery** and writes an optimized IR plus
an IR-value→C-type map. The **back end** (`NotDec-llvm2c`, pinned `316dfbb`, **no licence**) walks
the Clang AST to print C, using Memory SSA to decide when a load needs a temporary and a
semantics-preserving structurer (Brumley'13 / SAILR'24) to rebuild `if`/`while`.

The paper (*NotDec: WebAssembly Decompilation With Inter-Procedural Type Recovery*, ICSE'26,
arXiv 2608.03286v1, **CC BY-NC-ND 4.0**) supplies the two ideas that matter technically.
(i) **Retypd** (Noonan et al. 2016) is applied to WebAssembly: the constraint graph is generated
from the lifted IR (`src/Passes/ConstraintGenerator.cpp`, 140 KB — emits the constraints as JSON and
shells out to the GPL-3.0 Python `retypd` solver via `src/Passes/notdec_retypd_provider/`, which is
itself a copy of GrammaTech's `retypd-ghidra-plugin`), then Sketches are converted to C types
(`SketchToCTypeBuilder.cpp`). Because Retypd needs to know which integers are addresses, the paper
adds **PNDiff** (§3.2.2, Tables 1–2; implemented in `src/TypeRecovery/PointerNumberIdentification.cpp`
and `src/TypeRecovery/mlsub/PNDiff.cpp`): a pointer/numeric dataflow with rule-based worklist
inference (Ptr+Num=Ptr, Ptr+Ptr=Num-by-alias, equality-aware rules, node merging on assignment).
(ii) **Stack SROA**: each function's linear-memory frame is modelled as one aggregate and split
into variables by SROA (§3.2.3), which is what turns pointer arithmetic into struct member access.
Measured claims: 100 % recompilation success on 5,241 Juliet samples vs Ghidra's 45.95 %, 85.33 %
of struct-member accesses recovered (vs Ghidra 9.24 %) on Howard, 15.9× faster / 4.8× less memory
than Ghidra; the full inter-procedural variant times out (**>24 h** on grep/gzip/lighttpd/wget at
`-O0`) and only the intra-procedural `NotDec_F` scales (§4.1, Fig. 6). Limitations are stated
openly in §6: no indirect-call targets, heuristics for stack/libc/variadic patterns, PNDiff can miss
pointer arithmetic, Memory SSA is conservative, and non-C languages need new patterns/backends.

**Relevant to us, the sharpest finding is negative:** NotDec's own lifter is an *MVP+SIMD* lifter.
Scanning `parser-instruction.cpp` for `Opcode::` identifiers gives 389 hits with **zero** references
to atomic, GC (`struct.*`/`array.*`/`i31`), exception-handling (`try`/`catch`/`throw`), typed
function references (`call_ref`/`br_on_null`/`ref.as_non_null`), tail calls, multi-memory, stack
switching or stringref opcodes, and its expression visitor ends in
`default: … "Error: Unsupported expr type" … std::abort();`. So NotDec cannot serve as an oracle for
the proposals our plugin is actively extending; WABT (its dependency) can, and is better.

---

## 2. Coverage: NotDec vs this plugin

"ours" was re-measured today with the built extension
`dist/ghidra_12.1.4_PUBLIC_20261012_Ghidra-WASM.zip` (Ghidra 12.1.4, headless). "NotDec" claims are
from the paper, the repo source, and a scan of the pinned lifter revision.

| Area | NotDec (repo `0399bf0` + lifter `c3c2c18`) | ours (build 2026-10-12) | delta |
|---|---|---|---|
| **Decoding** | delegated to WABT; lifter handles MVP+SIMD only and `abort()`s on anything else (0 refs to atomics/GC/EH/refs/tail-call/multimem/cont/string) | MVP, 2.0 bulk memory, ref types, SIMD+relaxed SIMD, atomics, tail calls, legacy+new EH, GC `0xFB`, function refs, memory64, multi-memory, component model; unknown opcodes degrade via a length table | **ours much wider**; NotDec unusable as a modern-decode oracle |
| **Control flow** | structured CFG in IR; `br_table`→`switch`; Brumley'13/SAILR structuring at the back end | SLEIGH blocks + upstream Ghidra structurer; branch/target cross-refs; one known real decode gap (`select` after unconditional terminator, `MODERN_WASM_GAPS.md` §6) | comparable for MVP/SIMD; ours has 1 open decode bug, NotDec has 0 measured |
| **Types** | Retypd + PNDiff + Sketches → C structs; **85.33 %** struct-member recovery | **none** — signature/local/GC-type annotations only; linear-memory accesses stay `i32`+cast (paper measures this ancestor at 9.24 %) | **largest real gap in our favour of porting** |
| **GC** | none (lifter aborts; `0xfb` unhandled) | `0xFB` decodes (`struct.new` on probe 09, 0 undefined bytes), GC type-section entries, `(struct.new …)` in a global initialiser imports (probe 20; logs a `Data markup conflict` warning) | ours ahead — ahead of WABT 1.0.42 too |
| **EH** | none | legacy `try/catch/delegate` + new `try_table`/`throw_ref` merged; probe 11 clean | ours ahead |
| **Stack switching / JSPI** | none | no mnemonics, but length-correct graceful degradation | both absent |
| **JS string builtins** | none | no mnemonics; length-correct degradation (`0xFB ≥ 0x80`) | both absent |
| **Multi-value** | not discussed; IR is register-based so multi-result is representable | merged: packed-struct returns, callers consume all results | ours ahead in packaging |
| **Tables / memory64** | tables via global fn-ptr arrays for `call_indirect`; no memory64/multi-memory | multi-memory **wrong** (memarg align bit 6 not read → boundary shift, §2.2); memory64 partial (`ctx_mem64`, exact <4 GiB); `table64`/`>4 GiB` open | ours ahead; NotDec's table handling is a design analogue only |
| **Name / debug info** | `FunctionRenamer.cpp` renames 1-call thunks (`jmp_X`); no `.name`/DWARF handling seen | all `.name` subsections applied + DWARF `.debug_line` (base-address fixup) | ours ahead |
| **Tests** | Python `unittest`, compile→decompile→**recompile→run→compare output** (`.out`/`.expected`), 220 c-testsuite `.c` + SysY suite + handcrafted + WasmBench download script | probe gate (27 probes), spec-suite harness (2948 negative modules classified), 15-module real corpus sweep, CI; **no run-based / recompile-based semantic check** | NotDec's *methodology* is the gap; ours has far more inputs |

---

## 3. Port candidates (ranked)

Licence verdict rule: our project is GPL-3.0-only, so **MIT is fine (keep the notice), GPL-3.0 is
fine (whole work stays GPL-3.0), Apache-2.0 is fine with NOTICE + patent terms, unlicensed/"all
rights reserved" is not usable at all** (ideas/algorithms are, code is not).

| # | Candidate (pointer) | How it enters our plugin | Effort | Value | Licence | Risk |
|---|---|---|---|---|---|---|
| 1 | **WABT as decode oracle** — `wasm-objdump -d`, `wasm-validate` (WABT 1.0.42; NotDec's parser dependency, `NotDec-wasm2llvm/lib/notdec-wasm2llvm/parser.cpp`) | New `test-scripts/oracle/` gate: for each corpus/probe module, compare *instruction start addresses* per function with the listing (my `compare5.py` is ~120 lines and already produces exactly this table); add `wasm-validate --enable-all` for spec-validity and `--enable-*` flags per proposal | **S** (½ day) | Unlocks: an independent, byte-level ground truth for the decoder + a spec-validity gate for probe modules. Today it already found that our listing is **byte-exact on 60,556/60,556 instructions** of the Rust module (0 divergences) and that four `MODERN_WASM_GAPS.md` rows (09, 12, 19, 20) are stale | Apache-2.0 (with LLVM exception) — safe as an *external tool*; if a binary is committed, ship `NOTICE`. Prefer download-in-CI | Low: another tool in the harness; no runtime dependency |
| 2 | **GrammaTech `retypd-ghidra-plugin`** (GPL-3.0, `814bbe2`) — the *original Ghidra* integration that NotDec copied into `src/Passes/notdec_retypd_provider/`: Java `GhidraRetypd/src/main/java/ghidraretypd/{RetypdGenerate,RetypdRunner,RetypdTypes}.java` + Python `ghidra_retypd_provider/{type_inference,type_serialization}.py` + script `ghidra_scripts/Retypd.java` | Reimplement the Java half against our program model: emit retypd constraints from P-code/`HighFunction` instead of their `.pcode` JSON; run the solver as a PyGhidra/GPL-3.0 external step; apply returned structs/flags via `StructureBuilder` + our GC type data types. NotDec's own `ConstraintGenerator.cpp` is the reference for *what* to emit | **L** (1–2 weeks) | Unlocks the 9.24 %→85 % struct/array recovery class of capability for stripped, non-DWARF modules (Kotlin/Wasm, C/C++ without debug info). This is the only candidate that closes a *headline* capability gap | GPL-3.0 (both halves) — **can be copied**, keep copyright headers; the `retypd` Python package is GPL-3.0 but **has no PyPI release** (`pypi.org/pypi/retypd` → 404) → vendoring + GPL source-distribution duty | High: upstream unmaintained (last push 2023-07, repo archived? no — but dormant), Python+C++ dep, `>24 h` blow-up if inter-procedural is enabled (paper §4.1) — must run intra-procedural/`NotDec_F`-style |
| 3 | **PNDiff rules** — paper §3.2.2 Tables 1–2; impl. `src/TypeRecovery/PointerNumberIdentification.cpp`, `src/TypeRecovery/mlsub/PNDiff.cpp` | Reimplement the 6 add-subtract rules + 7 sub rules + the alias/equality rules as a Java worklist over Ghidra `HighFunction` varnodes (pointer-vs-numeric lattice, node merging on `COPY`). Feeds #2 (or directly biases pointer-typed struct candidates) | **M** (2–4 days) | Distinguishes `ram:` addresses from plain integers inside linear memory: fewer bogus structs, better member offsets; is the enabling analysis for #2 | Code is **unlicensed** → do **not** copy. Implementing the published rules is fine; cite the paper | Medium: our IR (P-code) differs, `or disjoint`/`InstCombine` canonicalisation notes in NotDec's CHANGELOG show LLVM-specific traps |
| 4 | **Stack-as-aggregate + SROA decomposition** — paper §3.2.3; `src/Passes/DSROA.cpp` (a modified LLVM SROA), `src/Passes/StackAlloca.cpp`, `StackPointerFinder.cpp` | Reimplement the *heuristic* in `WasmStackVariableAnalyzer`: match the per-function stack-pointer adjust, treat `[sp-floor, sp)` as one aggregate, split by access width/offset, and only then create stack variables. Directly targets our documented analyzer failures (`Index 0 out of bounds for length 0` on `i64.store`/`f32.load`; `GenericAddress cannot be cast to Register` on `local.set`; 22 instructions skipped across 4 real modules, §6.1) | **M** | Fewer skipped instructions + better variable names/sizes; measurable via the existing corpus sweep | Code unlicensed (and `DSROA.cpp` is itself an LLVM-Apache derivative with no header) → reimplement; reference only | Medium: Ghidra's decompiler re-does stack analysis; benefit shows up as *better inputs*, not guaranteed fewer crashes |
| 5 | **Recompilation-success metric** — paper §4.2 Table 5/6 methodology (and the paper's Ghidra baseline = our plugin's ancestor at **45.95 %**) | Add to `test-scripts/`: decompile every function to C, wrap, `gcc -fsyntax-only` (or full compile + run where the module is runnable) and report a recompile rate per module. No NotDec code needed | **M** | Turns "does it decompile" into "is the C valid C", and gives us a number comparable to a peer-reviewed baseline (and to the "reason for assertions" gap in our spec harness) | Paper is **CC BY-NC-ND 4.0 → do not copy text/figures/tables into our docs**, cite and re-measure. No code involved | Low |
| 6 | **memcpy/memset pattern matcher** — `src/Passes/MemOpMatcher.cpp` (cyclic-constant test, consecutive-store run collapsing, offset decomposition via `matchOffset`) | Reimplement in `WasmMemoryCopyAnalyzer` to catch the manual store loops our `memory.copy` initializer materialisation misses | **S–M** | Marginal: only helps decompiler noise on initialiser-like loops | Unlicensed → reimplement | Low |
| 7 | **Stack-pointer voting** — `src/Passes/StackPointerFinder.cpp` (`__stack_pointer` name hint, per-function pattern match, vote, plus pos/neg-growth counting) | Small scoring improvement to our existing C-stack detection (we already have the `pos-stack` compiler choice) | **S** | Small: fewer failed auto-detections on unusual toolchains | Unlicensed → reimplement | Low |
| 8 | **Test corpora** — `test/wasm/c-testsuite/functional` (220 `.c` + `.expected`/`.tags`), `test/wasm/sysy/functional` (~100), `test/wasm/WasmBench/download_dataset.sh`, `experiment/dataset/dataset-SAC-2022.tar.xz` | Add a run-and-compare corpus to `test-scripts/corpus` (they exercise control flow/stack frames heavily, unlike wasm-bindgen output which "exercises no unsupported feature") | **S–M** | Better regression coverage of *semantics*, not just decoding | **Mixed/unclear**: the vendored copies sit in an unlicensed repo; upstream c-testsuite/SysY/WasmBench have their own terms — go to the upstream project, verify, then vendor | Low–medium (attribution bookkeeping) |
| 9 | **`NotDec-wasm2llvm` lifter (MIT, `c3c2c18`)** — `lib/notdec-wasm2llvm/parser-instruction.cpp` | Use as a *reading reference* for MVP instruction semantics (offset/align, sign-extension, `memory.size/grow`, `call_indirect` tables); not as a buildable dependency | **L** to integrate, **S** to read | Low for us: WABT + the spec are already the reference, and the lifter aborts on everything modern | MIT — copyable with notice | High if integrated (LLVM 14 toolchain, `std::abort()` on unsupported input, dormant submodule pinned by an unlicensed parent) |
| — | **NotDec middle/back end** (`ConstraintGenerator.cpp`, `DSROA.cpp`, `simplesub.cpp`, `retdec-stack/*`, `NotDec-llvm2c`) | — | — | — | **No licence in the repo** (no `LICENSE`, no statement in README/CMake/Contributing; GitHub API `license: null`) and `NotDec-llvm2c` also unlicensed ⇒ **cannot be incorporated into a GPL-3.0 project at all**, in either direction | — |

---

## 4. Experiment

### 4a. NotDec itself: **not runnable**
- `api.github.com/repos/NotDec/NotDec/releases` → **0 releases**; the two sub-projects
  (`NotDec-wasm2llvm`, `NotDec-llvm2c`) → **0 releases each**. There is no prebuilt binary, no CI
  artifact, no Python port of the pipeline.
- Building it needs LLVM 14 built from source (`scripts/build-debug-llvm.sh`), a wasi-sdk-20
  toolchain, WABT and Boost; the README itself warns "you may encounter errors about no memory
  during linking". Out of scope under the "no long C++/LLVM builds" constraint.
- Its dev-facing Python entry point (`src/Passes/notdec_retypd_provider/`) needs the GPL-3.0
  `retypd` package, which is **not on PyPI** (404), plus a JSON constraint file produced by its own
  C++ — so it cannot be driven standalone either.

### 4b. Substitute oracle (executed): WABT vs our decoder, per function
WABT is NotDec's parser (`wabt/binary-reader-ir.h` in the lifter) and is what a decode-comparison
would be built on; it is also the only part of the NotDec stack that supports modern proposals.

```powershell
# 1. tool (prebuilt release; no build)
#    https://github.com/WebAssembly/wabt/releases/download/1.0.42/wabt-1.0.42-windows-x64.tar.gz
tar -xzf wabt.zip -C wabt
# 2. ground-truth per-function instruction streams
wabt\wabt-1.0.42\bin\wasm-objdump.exe -d <module> > od_<name>.txt
wabt\wabt-1.0.42\bin\wasm-validate.exe         <module>        # + --enable-all for proposals
# 3. our listing (script written to the temp dir, NOT the plugin repo)
%GHIDRA%\support\analyzeHeadless.bat proj RB -import <module> -scriptPath <tempdir> ^
    -postScript DumpListing.java -deleteProject      > listing.log
# 4. compare instruction *address sets* per function (DumpListing log vs objdump)
python compare5.py listing.log od_<name>.txt <module>
```

`wasm-objdump` output must be post-processed: long immediates are wrapped onto a second line with an
empty mnemonic, and the locals declaration is printed as `local[...]` pseudo-lines — a naive
line-count parser is off by ~440 lines on a 61 k-instruction module (I hit this first).

**Results (rasterbator_rs_bg.wasm, 179,782 B, Rust/wasm-bindgen):**

| metric | value | note |
|---|---|---|
| our `WasmFeatureReport`: `funcs=437 instrs=61658 undefined_bytes=156 decompiled=437/437` | reproduces `MERGE_NOTES.md` exactly | 21 s headless import |
| functions | 437 = 39 import stubs + **398** defined bodies; WABT: `Import[39]`, `Function[398]` | the "437 functions" number *includes* imports |
| `undefined_bytes=156` | **= 39 × 4** — exactly the import-stub bodies | the only undefined bytes are import placeholders |
| instructions | our listing has 61,658 = **60,556 real** + **1,102 marker pseudo-instructions** (`.locals` 398, `.local` 357, `.case` 291, `.default` 56) | the `instrs` metric is inflated 1.8 % by pre-analyzer markers |
| decode agreement | **398/398 functions identical, 60,556/60,556 instruction start addresses identical, 0 divergences** | byte-exact agreement with WABT on the whole module |
| rust_plain.wasm | 72/72 functions, 8,542/8,542 instructions, **0 divergences** | corpus module |
| rust_simd128.wasm | 2/2 functions, 26/26 instructions, **0 divergences** | corpus module |

**Probes** (`python test-scripts/gen_feature_probes.py …`, one headless run over all 27):

- **26 of 27 probes imported successfully** (only 21 fails, by design: "component header detected
  but no core module sections"). 24 of them have a code section. Two of the doc's "import failed"
  rows are **stale**: probe 19 (extended-const `i32.add` initialiser) *and* probe 20
  (`(global (ref 0) (struct.new 0))`) now import; 19/20 are global-only modules, which is why they
  contribute no functions.
- 16 of the 24 code-bearing probes are comparable with WABT; 15 agree instruction-for-instruction
  (01, 02, 08, 12, 13, 14, 15, 16, 17, 22–27).
- The other 8 code-bearing probes are **not comparable and not spec-valid**: `wasm-validate --enable-all` rejects
  03, 04, 05, 06, 07, 10, 11, 18 with `error: section Function out of order`. Cause is in our own
  generator: e.g. `gen_feature_probes.py:37-39` emits `table_section`/`memory_section` **before**
  `func_section`, and section ids 4/5 must follow id 3. Our loader tolerates this, WABT does not —
  so those probe verdicts are measured on non-conformant inputs.
- 1 divergence, and it is **in our favour**: probe 09 (`struct.new`),
  ours `I 24 3 struct.new type=0x0` (bodies exactly right) vs WABT
  `0000025: error: unexpected opcode: 0xfb` — WABT 1.0.42 refuses to decode `0xFB` at all.
  Similarly probe 12: ours `call_ref type=0x0` @ `0x22`, WABT `call_ref (ref null 0)` @ `0x22`
  (identical boundaries). Both `MODERN_WASM_GAPS.md` §2.4 rows (09: "0xFB undefined, desync",
  12: "`call_ref` still undecoded") are **stale against build 2026-10-12**.
- WABT `--enable-all` also rejects probe 12 itself (`reference 0 is out of range (max: 0)` +
  `type mismatch in call_ref`) — a second probe-quality item for the same generator.

Bug leads produced by this exercise (all reproducible with the commands above):
1. `WasmFeatureReport`/`DumpDecomp` `instrs` counts pre-analyzer marker pseudo-instructions
   (`.locals`/`.local`/`.case`/`.default`) as instructions → any "instructions decoded" budget in
   `MODERN_WASM_GAPS.md` over-counts by ~1.8 % (398+357+291+56 on rasterbator).
2. `gen_feature_probes.py` emits Table/Memory sections before the Function section → 8 probes are
   invalid per the spec; verdicts recorded for them are on inputs no engine would accept.
3. `MODERN_WASM_GAPS.md` §2.4 is stale for probes 09, 12 and 19 on the current build.
4. (existing, confirmed) imported functions are 4-byte `EXTERNAL` bodies that dominate
   `undefined_bytes` (156 = 39×4 here).
5. **New: `WasmLoader.createData` logs a markup conflict on every extended-const module** —
   `WARN Data markup conflict at ram:80000013 … CodeUnitInsertionException: Could not create Data
   at address ram:80000013` (`WasmLoader.java:317`, from `doLoad`), on probes 19 (`ram:80000013`),
   22 (`ram:80000022`) and 27 (`ram:80000024`) — i.e. precisely the three probes that exercise the
   rewritten constant-expression scanner (§2.5). Import still succeeds, so it is noise today, but it
   means the folded initialiser is *not* materialised where the loader expects it. Reproduce with the
   command block above (grep `Data markup conflict` in the headless log).

---

## 5. Recommendations

**R1 — Add a WABT-backed decode oracle to the test harness, and make it the gate that owns
`MODERN_WASM_GAPS.md` §2.4.** First concrete step: drop `compare5.py` (address-set diff) +
`DumpListing.java` into `test-scripts/oracle/`, add `wasm-objdump -d` / `wasm-validate --enable-all`
invocations to `corpus-sweep.ps1`, and re-generate the §2.4 table for build 2026-10-12. It is a
half-day, costs nothing at runtime, has already proved the decoder byte-exact on 60,556
instructions and already caught four stale rows and two probe defects. (WABT: Apache-2.0 —
download in CI, do not vendor without a NOTICE.)

**R2 — Close the type-recovery gap by porting the GPL-3.0 GrammaTech `retypd-ghidra-plugin`
path, restricted to intra-procedural analysis.** First concrete step: copy
`GhidraRetypd/src/main/java/ghidraretypd/RetypdGenerate.java` + `ghidra_retypd_provider/` into a
throwaway worktree, run it on `rust_plain.wasm` with inter-procedural propagation **off**, and check
that (a) structs come out of the `ram` accesses our decompiler currently renders as `i32`
arithmetic, and (b) it does not regress the 398-function corpus. This is the only candidate that
moves the 9.24 %→85 % struct-member metric the paper measures on exactly our ancestor plugin.
GPL-3.0 in, GPL-3.0 out: keep the headers and ship the `retypd` sources (no PyPI release exists, so
vendoring is mandatory).

**R3 — Fix the known stack-variable failure class by reimplementing the stack-as-aggregate
heuristic (paper §3.2.3 / `DSROA.cpp`), *then* measure with the paper's recompilation metric.**
First concrete step: in `WasmStackVariableAnalyzer`, replace the ad-hoc slot creation with
"match the stack-pointer adjust once per function → treat the frame as one aggregate → split by
(distinct width, offset) accesses", and add the paper's `gcc -fsyntax-only` recompile-rate
(`test-scripts/`) so the change is judged on the C output, not on the listing. Targets the documented
`Index 0 out of bounds` / `GenericAddress cannot be cast to Register` exceptions and the 22 skipped
instructions; gives us a number comparable to the published 45.95 % (our ancestor) / 100 % (NotDec).

**Do not port:**
- **Any NotDec source file, and `NotDec-llvm2c`** — the repos carry **no licence at all** (GitHub
  `license: null`, no `LICENSE`, no statement anywhere in the tree). "All rights reserved" is
  incompatible with a GPL-3.0 project; only the *algorithms* (PNDiff rules, stack-SROA idea,
  Memory-SSA trade-off) may be reimplemented from the paper, with citation.
- **NotDec's lifter as a dependency or oracle** — it is MVP+SIMD only, ends in `std::abort()` on
  anything else (verified: zero GC/EH/atomic/ref/tail-call/multimem/cont/string opcode references),
  and needs a from-source LLVM 14.
- **Full inter-procedural Retypd** — the paper's own RQ1: >24 h timeouts, exponential in call depth
  (Fig. 6), plus a ~9 GB-memory class of failure in the LLM baseline; intra-procedural only.
- **`ConstraintGenerator.cpp` / `simplesub.cpp` / `retdec-stack/*` as code** — unlicensed, LLVM-14/IR
  bound, and duplicative: Ghidra's decompiler already owns SSA, structuring and stack analysis, so
  porting the *IR-side* of NotDec would mean reimplementing the decompiler we already have.
- **Paper text/figures/tables** — CC BY-NC-ND 4.0: cite, do not copy into the repo docs.

---

## 6. Sources

Repos read (shallow clone in `%TEMP%\opencode\research-notdec`), with the exact revisions:

| What | Revision | Licence (verified) |
|---|---|---|
| `https://github.com/NotDec/NotDec` | `0399bf0aec0f26247fee99097cb9442e4414bb0f` (2026-01-07, default branch head; shallow clone) | **none** — `api.github.com/repos/NotDec/NotDec` → `license: null`; no `LICENSE`, no licence text in README/CMakeLists/Contributing; GitHub reports 0 releases |
| `external/NotDec-wasm2llvm` (gitlink) | `c3c2c189f5aaa66c2f211bc3b8b7dbe34e1ee696` | MIT (`LICENSE`, "Copyright (c) 2024 NotDec") |
| `external/NotDec-llvm2c` (gitlink) | `316dfbbf9bb12c4ddad300ab01036e616b23f229` | **none** (API `license: null`) |
| `src/Passes/notdec_retypd_provider/{type_inference,type_serialization}.py` | in-tree copies of GrammaTech code | **GPL-3.0 headers** ("Copyright (C) 2022 GrammaTech, Inc."), README says "Based on …/retypd-ghidra-plugin/f466b30" |
| `https://github.com/GrammaTech/retypd-ghidra-plugin` | `814bbe20cf4e52ac6e4e798c71fb49b6ff835cd5` (2023-07-06) | GPL-3.0 |
| `https://github.com/GrammaTech/retypd` | (metadata only) | GPL-3.0; **no PyPI package** (`pypi.org/pypi/retypd` → 404) |
| `https://github.com/WebAssembly/wabt` — release `1.0.42`, asset `wabt-1.0.42-windows-x64.tar.gz` | used: `wasm-objdump.exe`, `wasm-validate.exe` | Apache-2.0 (with LLVM exception) |
| Paper | arXiv **2608.03286v1** (ICSE'26, DOI 10.1145/3744916.3787762), HTML read in full | **CC BY-NC-ND 4.0** |
| Our plugin | read-only at `D:\code\Ghidra-WASM` (`MODERN_WASM_GAPS.md`, `README.md`, `MERGE_NOTES.md`, `src/main/java/wasm/analysis/WasmFunctionAnalysis.java`, `data/languages/WebAssembly.sinc`, `test-scripts/**`); extension built from `dist/ghidra_12.1.4_PUBLIC_20261012_Ghidra-WASM.zip` against Ghidra 12.1.4 at `C:\Tools\ghidra_12.1.4_PUBLIC` | GPL-3.0 (`LICENSE`) |

Artefacts produced by this analysis (in `C:\Users\micro\AppData\Local\Temp\opencode\research-notdec\`,
nothing written into the plugin repo): `DumpListing.java`, `DumpListing2.java`, `PerFuncReport.java`,
`objdump_perfunc.py`, `compare.py`, `compare2.py`, `compare3.py`, `compare4.py`, `compare5.py`,
`compare_all.py`, `ghidra_rasterbator.log`, `listing_rasterbator.log`, `listing_probes.log`,
`od_rasterbator.txt`, `odw/*.txt`, `probes/*.wasm`, `wabt/`.

Not verified (stated honestly): I did not build or execute NotDec (no releases/artefacts, LLVM-14
build out of scope), did not fetch or read the full `NotDec-wasm2llvm` / `NotDec-llvm2c` sources
(only the pinned lifter file and repo listings via the GitHub API), and did not run the corpus sweep
on the other 12 real-world modules or the spec suite — the decode comparison covers rasterbator,
`rust_plain`, `rust_simd128` and the 27 feature probes.
