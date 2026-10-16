# Binaryen reuse / port analysis for the Ghidra-WASM plugin

**Author:** workstream (reuse/port analysis, not implementation)
**Scope:** what parts of [WebAssembly/binaryen](https://github.com/WebAssembly/binaryen) are worth porting into
`D:\code\Ghidra-WASM`, what must stay an external tool, and what to leave alone. Every number below was measured
in this session unless marked "from archive".
**Binaryen revision studied:** `6de3a0bd2655952d8e08db4d03a6c7b4a3d7fde3` (2026-10-09), **version 133**
(`CMakeLists.txt: project(binaryen ... VERSION 133)`, shallow clone, submodules not initialised).
**Plugin revision read:** `main` @ `be75626`, plugin installed for Ghidra 12.1.4 at
`C:\Tools\ghidra_12.1.4_PUBLIC\Ghidra\Extensions\Ghidra-WASM`.

---

## 1. What Binaryen is, its licence, and its reader/IR (three paragraphs)

**What it is.** Binaryen is the reference C++ *toolkit* for WebAssembly: a compiler/optimizer IR plus a family of
command-line tools that every wasm toolchain rehearses against. The tools relevant to us are `wasm-opt`
(optimizer + validator; `--metrics`, `--func-metrics`, `--fuzz-exec`), `wasm-dis` (binary → `.wat`),
`wasm-as` (`.wat`/`.wast` → binary), `wasm-shell` (a `.wast` script interpreter that executes the spec
`assert_*` commands), `wasm-metadce`, `wasm2js`, `wasm-ctor-eval`, `wasm-merge`, `wasm-split`, `wasm-reduce`
and the fuzzing harnesses. The core is the `wasm` library (`src/wasm*.h`, `src/wasm/`) with a C API
(`src/binaryen-c.h`, 200 KB) and a JS API. The tree is ~3,090 files; the entire Windows x64 tool family is
131.5 MB on disk (single `wasm-opt.exe` 10.3 MB, `wasm-dis.exe` 9.4 MB).

**Licence.** Binaryen is **Apache-2.0** (`LICENSE`, 206 lines; file headers read
`Copyright <year> WebAssembly Community Group participants`, Apache-2.0 boilerplate). There is **no `NOTICE`
file** anywhere in the tree, so Apache-2.0 §4(d) has nothing to propagate. For our **GPL-3.0** plugin:
Apache-2.0 is on the FSF's list of GPLv3-compatible licences, so we *may* copy code into the plugin, but the
combined work is then distributed under GPL-3.0 while the copied files keep their Apache-2.0 terms: we must
(a) keep the Apache-2.0 licence text and every copyright/licence notice on the ported portions, (b) state
clearly that files were changed and when (§4(b)), and (c) not imply endorsement. Apache-2.0 §3 grants a
patent licence that flows to us and our users. Merely **invoking the binaries** as external tools imposes no
obligation on our source at all; **redistributing** the binaries (e.g. vendoring `wasm-dis.exe` into CI) means
shipping Binaryen's `LICENSE` + attribution. `test/spec/*.wast` is also Apache-2.0; the vendored
`test/spec/testsuite` is a separate submodule (`WebAssembly/testsuite`) with its own licence — check it
separately before committing those bytes.

**Binary reader and IR.** The reader is `src/wasm/wasm-binary.cpp` (5,698 lines) + header `src/wasm-binary.h`
(1,671 lines). `struct BinaryConsts` in the header is a complete, human-readable constant catalogue: `enum
Section` (Custom=0 … Tag=13, Strings=14), `enum EncodedType` (i32..`struct`=0x5f/`array`=0x5e/`sub`=0x50/
`rec`=0x4e, `contref`=0x68, `stringref`=0x67), `enum EncodedHeapType`, `namespace CustomSections::Subsection`
(NameModule..NameTag = 0..11, including **label=3, field=10, tag=11**), limits flags
(`HasMaximum=1<<0, IsShared=1<<1, Is64=1<<2, HasCustomPageSize=1<<3`), memarg flag bits
(`HasMemoryOrderMask=1<<4, HasBackingArrayMask=1<<5, HasMemoryIndexMask=1<<6`), `enum ASTNodes` (the full
opcode map) and `enum SegmentFlag`. `class WasmBinaryReader` decodes in one pass: `read()` walks sections with
a `std::unordered_set<uint8_t> seenSections` and a `default: throwError("unrecognized section ID")`;
`readMemoryAccess()` implements the multi-memory alignment-bit-6 rule; `getResizableLimits()` decodes all four
limit flags plus custom page size; `readDataSegments()` reads the offset as a full **constant expression**
(so 64-bit offsets are natural) and handles `HasIndex`; `readExports()` resolves every export index through
`getTableName()/getFunctionName()/…` and rejects out-of-range ones. The IR/type system lives in `src/wasm.h`
(the expression hierarchy), `src/wasm-type.h` (`Type`, `HeapType`, typed references, subtyping),
`src/wasm-builder.h`, `src/wasm-ir-builder.h` (the `IRBuilder` that constructs IR from the bytecode and, notably,
*materialises its own* `scratch` locals) and `src/wasm/wasm-validator.cpp` (196 KB; `struct WasmValidator`,
`FunctionValidator`, `validateExports`). **This header/reader pair is the single richest source of exact
modern-wasm decoding rules available to us.**

---

## 2. Port / borrow candidates (ranked)

| # | Candidate | Upstream file / function | How it enters our plugin | Effort | Value | Licence / attribution | Risk |
|---|---|---|---|---|---|---|---|
| 1 | **Decoding rules + opcode/type tables** | `src/wasm-binary.h`: `BinaryConsts::{Section, EncodedType, EncodedHeapType, CustomSections::Subsection, ASTNodes, SegmentFlag}`, limits + `HasMemoryIndexMask`; `src/wasm/wasm-binary.cpp`: `WasmBinaryReader::read()`, `readMemoryAccess()`, `getResizableLimits()`, `readDataSegments()`, `readExports()`, `readTypes()` | Re-implement as Java data tables in `WasmEnums` / a new `wasm/binaryen/` table package, and as the operand-length table the roadmap's item-0 "unknown-opcode degradation" needs; feed `data/languages/*.sinc` where the SLEIGH mnemonic set is derived | **M** | High: fixes/locks section-id+duplicate rules, 64-bit data-segment offsets, memarg bit-6 memidx, all limits flags, GC/ref valtypes, and turns every future proposal into a safe `unimplemented` | Apache-2.0: keep header comment + `THIRD_PARTY_NOTICES` entry naming upstream file & revision | Translation drift if pasted wholesale; keep it as **small, provenance-commented tables**, not a C++ transliteration |
| 2 | **Ground-truth decode/validate oracle in CI** | `wasm-dis` (sets `FeatureSet::All` unconditionally), `wasm-opt` (`--metrics`, `--func-metrics`) | External tool fetched by the harness (like wabt already is); compare function counts / accept-vs-reject verdicts, never raw counts | **S** | High: catches decoder leniency and bad probes automatically (this session found 37/127 bad probes in minutes) | No source obligation if we call it; ship Binaryen `LICENSE` only if we vendor the exe | 131.5 MB download; `wasm-opt` **crashes** on parse errors in this release build (use `wasm-dis`); IR normalisation means counts differ |
| 3 | **Validation semantics catalogue → negative probes + loader diagnostics** | `src/wasm/wasm-validator.cpp` (`validateExports`, `FunctionValidator`), reader `throwError` sites ("section seen more than once", "unrecognized section ID", "invalid table index", "bad section size", "data count and data sections disagree", "shared memory must have max size") | Turn each rule into a byte-crafted malformed module in `test-scripts/probes_negative.py` / `make_malformed_corpus.py`, and into an explicit `WasmLoader`/`WasmModule` diagnostic | **M** | High: closes the open **B4** (duplicate/out-of-range sections discarded invisibly) and lifts the 2948-module negative suite from "accepted" to "rejected" | Apache-2.0 (rules/strings), attribution if copied | Must not make the lenient loader strict for real-world modules; gate behind the existing "honest failure" policy |
| 4 | **Spec `assert_*` execution oracle** | `wasm-shell` (`src/tools/wasm-shell.cpp`, `src/shell-interface.h`, `src/tools/spec-wrapper.h`) | Call `wasm-shell` from `test-scripts/spectest/` to provide the *expected* side of our `assert_*` emulation (gap §6.5: "emulation-based assert_* execution is still blocked") | **S** | High for the spec harness: gives reference pass/fail per `.wast` without us re-implementing the interpreter | Call-only → no obligation; ship `LICENSE` if vendored | Different testsuite pin (Binaryen pins `WebAssembly/testsuite@4b24564c…`, our harness pins `d76759e7…`); interpreter support lags the newest proposals |
| 5 | **Test corpus** | `test/lit/**` (1,252 `.wast`, 94 `.wat`; `test/lit/binary/` 46 files, `test/lit/validation/` 59, `test/lit/exec/` 64), `test/passes/` 554 files, `test/spec/*.wast` 110 + `threads/`, `stack-switching/` | Import as a second corpus in `corpus-sweep` / a new "binaryen-lit" sweep; each `test/lit/validation/*.wast` is a ready-made negative case | **S** | High: far wider than our hand probes; `test/lit/binary` and `validation` are exactly the shapes our negative harness wants | Apache-2.0 for `test/spec/*`; submodule licence for `test/spec/testsuite` — attribute both | Corpus is optimiser-oriented (many files assume Binaryen IR, not raw bytes); needs triage; adds runtime to CI |
| 6 | **Type system reference for GC / typed refs / multi-value** | `src/wasm.h`, `src/wasm-type.h` (`Type`, `HeapType`, `Signature`), `src/wasm/wasm-type.cpp` | Reference (not a port) for `WasmTypeSection`/`WasmFuncType`/`WasmEnums.ValType` rec/sub/struct/array parsing and for modelling `(ref $t)` as a typed function pointer | **S** (parse) / **L** (Ghidra modelling) | High for Kotlin/Wasm, Dart, OCaml, .NET output — currently the worst gap class | Copy = Apache-2.0; reference-only = none | Ghidra has no subtype/recursive-type model; expect placeholder types, not fidelity |
| 7 | **`--fuzz-exec` differential oracle** | `src/tools/wasm-opt.cpp`, `src/tools/fuzzing/`, `src/wasm-interpreter.h` | Run `wasm-opt --fuzz-exec` on our tiny probe modules to confirm they are *executable*, not just parseable | **S** | Medium: validates probe semantics (complements #2's validity-only check) | Call-only | Needs exported functions; prints to stdout and still exits 0 with "no passes" warnings; not a memory-safety oracle for our pcode |
| 8 | **Text output as ground truth for our disassembly** | `src/passes/Print.cpp` (`PrintSExpression`, `visitBlock/visitIf/visitTry/visitTryTable`, `printExpressionContents`) via `wasm-dis` | Diff/eyeball our `ListProgram.java` listing against `wasm-dis` output (memarg `offset=`/`align=`, `$N` naming, `(;N;)`) | **S** | Medium: format/naming consistency, and a semantic second opinion on boundaries | Call-only | Binaryen prints post-IR-normalisation text (synthetic `$scratch` locals), so it is *not* a byte-exact listing |
| 9 | **`wasm-decompile`** | absent from the tree (and from the v133 release `bin/`) | — | — | — | — | **Not available** in v133; nothing to port. Historical versions existed, but current Binaryen ships no decompiler |
| 10 | `wasm-ctor-eval`, `wasm-metadce`, `wasm-merge`, `wasm-split`, `wasm2js`, `wasm-reduce` | `src/tools/*` | — | — | Low/none for a loader+decompiler plugin | — | Different problem domain |

---

## 3. Experiment (exact commands, numbers, disagreements)

### 3.1 Setup

```powershell
git clone --depth 1 --recurse-submodules=no https://github.com/WebAssembly/binaryen.git
# -> rev 6de3a0bd2655952d8e08db4d03a6c7b4a3d7fde3, VERSION 133

# prebuilt Windows x64 release (the asset is a .tar.gz, not a .zip):
Invoke-WebRequest -Uri https://github.com/WebAssembly/binaryen/releases/download/version_133/binaryen-version_133-x86_64-windows.tar.gz -OutFile bin133.tar.gz
# 111,045,528 bytes; sha256 17a2cbeac6b5693c5fbafab3838d3c65fd9c1eb38b05f5baec6c657e8c84995b
# (matches the published .sha256); tar -xzf -> binaryen-version_133/bin/{wasm-opt,wasm-dis,wasm-shell,…}.exe
```

Decoder sweep over our probes:

```powershell
python test-scripts/gen_feature_probes.py <out>     # + probes_analysis/memory64/gc/eh/funcref/multivalue/names/types/spec_fixes -> 127 probes
wasm-dis  --all-features -o out.wat probe.wasm      # decode oracle (also enables All internally)
wasm-opt  --all-features probe.wasm -o out.wasm     # validate oracle
wasm-opt  --metrics / --func-metrics --all-features module -o NUL
```

Our loader, for comparison (Ghidra 12.1.4 headless):

```powershell
$env:GHIDRA_INSTALL_DIR="C:\Tools\ghidra_12.1.4_PUBLIC"
analyzeHeadless <proj> <name> -import module.wasm -scriptPath test-scripts `
    -postScript ListProgram.java -postScript DumpDecomp.java -deleteProject
```

### 3.2 Function- and instruction-level agreement on real modules

| module | our funcs | our instrs | our `undefined_bytes` | Binaryen funcs (imports+defined) | Binaryen IR nodes | verdict |
|---|---|---|---|---|---|---|
| `rasterbator_rs_bg.wasm` (179,782 B) | **437** | **61,658** | 156 (=39 import stubs×4, **0 real**) | **39 + 398 = 437** | 59,259 | funcs agree exactly; instrs +4.0 % |
| `sql-wasm.wasm` (sql.js 1.14.2, 658,410 B) | **1,917** | **291,207** | 152 (=38×4, **0 real**) | **38 + 1,879 = 1,917** | 276,146 | funcs agree exactly; instrs +5.5 % |
| `rust_plain.wasm` (119,118 B) | 72 (archive) | 8,691 (archive) | 0 | 72 | 8,217 | funcs agree; instrs +5.8 % |
| `rust_simd128.wasm` (80,655 B) | **2** | **29** | **0** | **2** | 24 | funcs agree; module is 87 B of code + 78 KB DWARF |

Our own `DumpDecomp` re-run reproduced the documented rasterbator line byte-for-byte:
`SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156`.
`undefined_bytes` on all four modules equals **exactly the import-stub bytes** (39×4, 38×4) — i.e. **zero real
decode gaps** in mainstream toolchain output, which is what §6.1 of the gap inventory already claimed.

**Per-function analysis of the 437-function module** (`--func-metrics` mapped 1:1 onto `ListProgram.java` output
by definition order; wasm index = 39 + Binaryen defined index):
`(our_instrs − Binaryen_nodes)` has min **−2**, max **+131**, 5 functions negative (by 1–2), 14 exactly zero; the
mode is +2. The positive offset is structural markers our listing prints and Binaryen's IR does not count
(`.locals`/`.local` decls, `end`/`else`); the 5 negative cases are Binaryen's *own* IR-lowering artefacts.
No function anywhere shows truncation or a boundary shift. Instruction-level spot checks (e.g. `$242`,
`$215`) matched operand-for-operand: `i32.store offset=4 / offset=0 / offset=12 / offset=8`, `i32.const
1052404`, `call $210`, `i64.const 21474836480`, memarg alignment — identical on both sides.

### 3.3 Probes: what agrees, what Binaryen accepts/rejects

Requested probes, our current build vs Binaryen v133:

| probe | our listing (measured now) | Binaryen | note |
|---|---|---|---|
| `06_multi_memory` | `i32.const 0` / **`i32.load align=0x2 memidx=0x1 offset=0x0`** / `memory.size 0x1` / `i32.add` — 6 instrs, 0 undefined | `(i32.add (i32.load $1 (i32.const 0)) (memory.size $1))` — OK | **Agrees.** The §2.2 memarg bug (`align=0x42` + spurious `unreachable`) is **fixed** in the current build; this is no longer a bug lead |
| `08_gc_struct_type` | 1/2/0 | OK | agrees |
| `11_eh_try_table` | `try_table blocktype=0x40 catches=0x0` | `(try_table)` OK | agrees |
| `09_gc_struct_new` | `struct.new type=0x0` decoded, 0 undefined | decodes, but **validation fails** | we decode more than we validate; module is invalid |
| `12_call_ref` | `call_ref type=0x0`, 0 undefined | **rejects**: "popping from empty stack (0:36)" | our probe is malformed (see bug leads) |
| `A05_unimp_cont_new` | `unimplemented 0xe0 cont.new type=0x0` then `i32.const 1 / drop` | **rejects**: "expected continuation type (0:32)" | Binaryen knows `cont.new` but the probe's type is not a continuation type |
| `M64_01_baseline_i64_load` | `i64.const 0` / `i32.load … (i64 index)` | OK | agrees |
| `19_extended_const_global`, `20_gc_global_init` | **0 functions** | no code section at all (global-only modules) | our "0 funcs" is *correct*, not a truncation |

Whole-suite sweep (all 127 generated probes, `--all-features`): **90 accepted, 37 rejected** = 34 decode
failures + 3 validate-only failures. The rejects include the 8 multivalue probes (`M01`–`M08`), 4
`SF02_stackvar_*` reproductions, `12_call_ref`, `21_component_model`, the six `A05`–`A10` "unknown opcode"
probes, most `B14`–`B29` valtype/limits probes, `E03`/`E15`/`F06` and `N03`.

**Honest negative result:** I found **no case where Binaryen accepts a module that our plugin renders as
`unimplemented`.** The disagreements run the other way — Binaryen rejects modules our lenient loader accepts, and
several of our probes are not spec-valid. On the newest proposals both are equally incomplete: `A06`
(`0xFB 0x80`, JS-string) gives Binaryen *"unknown GC operation 128"* and `A07` (`0xFC 0x12`) *"unknown misc
operation: 18"*, i.e. **Binaryen v133 has neither stringref nor `memory.discard` either.**

### 3.4 Bug leads (ranked, each with exact evidence)

1. **`probes_multivalue.py` M01–M08 are invalid modules — they export a non-existent table named `f`.**
   `wasm_probe_lib.export_section` takes `(name, kind, idx)`, but all eight probes write `("f", 1, 1)`, i.e.
   *kind=table, idx=1* (byte-level proof: `… 66 01 01 …` = `"f"`, kind `0x01`, index `0x01`; the module has no
   tables). Binaryen: `[parse exception: invalid table index (at 0:51)]`. Changing the tuple to
   `("f", 0, 1)` makes Binaryen accept it (exit 0). The exact site is `src/wasm/wasm-binary.cpp:3084`
   (`getTableName` → "invalid table index"). This is the evidence base for `REPORT-MV.md`, so the multivalue
   metrics (e.g. "M01 = 2/9/0/2") were produced from modules no real engine accepts. **Fix the 8 probes** and
   re-record.
2. **The loader silently accepts four malformed section layouts (the open B4 item).** Byte-crafted tests
   (`malformed/S0*.wasm`), imported with `-noanalysis` and then with analysis:

   | case | Binaryen | our loader |
   |---|---|---|
   | S01 duplicate type section | `[parse exception: section seen more than once: 1 (0:16)]` | **Import succeeded**, 1 func / 2 instrs |
   | S02 section id 99 | `[parse exception: unrecognized section ID: 99 (0:10)]` | **Import succeeded**, 1 func / 2 instrs |
   | S03 function section before type section | `[parse exception: invalid type index 0 / 0 (0:12)]` | **Import succeeded**, 1 func / 2 instrs |
   | S04 declared section size 5, 4 present | `[parse exception: Section extends beyond end of input (0:10)]` | **Import succeeded** as an **empty module (0 funcs)** — silent truncation |
   | S05 payload length past EOF | rejected | Import failed (`EOFException`) — agrees |

   Binaryen's rules are `WasmBinaryReader::read()` (`seenSections`, `default: throwError`, and the exact
   `pos != oldPos + payloadLen` check). Port as `WasmModule`/`WasmSection` diagnostics.
3. **`minrepro_a_i32.wasm`, the corpus "sanity floor" module, is not a valid module.** The corpus manifest itself
   records `v8: invalid`; Binaryen rejects it: `[parse exception: popping from empty stack (at 0:34)]`. Our loader
   imports it and reports 1 function. Either replace it with a valid 34-byte module or document that the floor
   test deliberately exercises invalid input.
4. **~27 % of the probe corpus is not spec-valid.** Beyond the multivalue eight, the sweep shows other
   malformed generations: `B25_valtype_exnref_global` → *"bad section size, started at 15 plus payload 7 not
   being equal to new position 21"* (a real encoding bug in the probe); `B28_valtype_func_gc_struct` →
   *"invalid signature type … (struct …)"*; `B04_limits_shared_memory64` → *"shared memory must have max size"*;
   `SF02_stackvar_f32_load` → *"Memory index out of range while reading memory alignment"*; `E03_gc_rec_subtype`
   → *"invalid type: Heap type has an invalid supertype"*. Each is either a probe-generation bug or a case our
   lenient loader accepts but a real engine refuses. All are cheap to triage with lead #2.
5. **Oracle caveat (not a plugin bug): `wasm-opt.exe` in the v133 release build aborts on parse errors.**
   `rc = 0xC0000409` with `Assertion failed: *currp, file wasm-traversal.h, line 297` — so an
   accept/reject oracle must use **`wasm-dis`** (exits 1 cleanly and prints `[parse exception: …]`) and may use
   `wasm-opt` only for modules that already parse.
6. **Oracle caveat: Binaryen's IR/text is not byte-faithful.** `IRBuilder::addScratchLocal`
   (`src/wasm/wasm-ir-builder.cpp:104`, `Names::getValidLocalName(*func, "scratch")`) invents scratch locals and
   the corresponding `local.set`/`local.get` nodes. Proof: raw parsing the code section
   (`rawparse.py`, authoritative) shows **function 254 declares 0 locals** and our listing reads exactly
   `.locals` + the body with 0 undefined bytes, while `wasm-dis` prints `(local $scratch i32)`. Our total
   declared locals (1,398, summed from the listing) equals the raw-parse total (1,398). ⇒ compare *semantics and
   validity*, never raw instruction counts.

---

## 4. Recommendation: Binaryen as a ground-truth oracle (and how to borrow rules & corpus)

### 4.1 Oracle in the test harness / CI

* **Which binaries:** `wasm-dis.exe` (primary: accept/reject + `.wat` ground truth) and `wasm-shell.exe`
  (spec-script `assert_*` oracle). Avoid `wasm-opt` for rejections (it aborts, §3.4 #5); use it only for
  `--metrics`/`--func-metrics`/`--fuzz-exec` on already-parsing modules.
* **How to fetch it:** mirror `test-scripts/spectest/fetch_spectest_tools.ps1`. Pin **`version_133`**, download
  `binaryen-version_133-x86_64-windows.tar.gz` from the release URL, verify
  `sha256 17a2cbeac6b5693c5fbafab3838d3c65fd9c1eb38b05f5baec6c657e8c84995b`, `tar -xzf` into
  `$env:TEMP\binaryen133\bin`. (The `...windows.tar.gz` asset is the correct target; there is no plain `.zip`.)
  Vendor *only* `wasm-dis.exe` + `wasm-shell.exe` (+ Binaryen `LICENSE`) if reproducibility matters more than
  131 MB.
* **How to compare, with tolerances:**
  1. *Accept/reject*: for every module in every sweep, run `wasm-dis --all-features -o NUL` and record
     `rc == 0` (accept) vs `rc != 0` + the `[parse exception: …]` text. Gate: **a module Binaryen rejects must not
     be reported as a clean pass by our harness**, and a module Binaryen accepts must import (currently true for
     all real-world modules).
  2. *Function counts*: `wasm-dis` output `\n (func $` count + `(import … (func` count must **equal** our
     `DumpDecomp` `functions=`. This matched exactly on 437, 1,917, 72 and 2 — use it as a hard gate with **zero
     tolerance**.
  3. *Instruction counts*: **not** a hard gate. Binaryen counts post-normalisation IR nodes, so allow the
     measured band: our_instrs ∈ [nodes, nodes + ~12 %] per module (measured +4.0 %, +5.5 %, +5.8 % for the three
     large modules; tiny modules deviate more — 29 vs 24 for the 2-function `rust_simd128`), and per
     function allow `−2 … +131`. Flag only *negative* deviations or a module where our count < Binaryen's nodes.
  4. *Spec suite*: run `wasm-shell` on the same `.wast` subset and compare its pass/fail to our
     `assert_*` expectations; accept differences only where `wasm-shell` itself lacks the proposal.
* **Cost:** ~15–30 s per real module for `wasm-dis`; the 127-probe sweep took well under a minute. Keep the oracle
  **out of the default unit gate** and in a separate "cross-engine" workflow step, so a missing/updated download
  cannot break the core CI.

### 4.2 Borrowing decoding rules

Port **tables, not control flow**. Concretely: add a `wasm/binaryen/` package (or comments in the existing
classes) holding (i) the `Section`, `EncodedType`, `EncodedHeapType`, name-subsection and limits/memarg-flag
constants; (ii) the operand-length table the roadmap's item-0 degradation needs; (iii) the four small algorithms
from `wasm-binary.cpp` — the section-loop invariants (`seenSections`, exact payload-length check), the memarg
rule (*clear bit 6 before reading alignment, then read `memidx`*), `getResizableLimits` (four flags + page-size
exponent), and data-segment parsing (offset = constant expression; `HasIndex` → memidx). Each copied fragment gets
a one-line header: *"Adapted from Binaryen `<path>` @ `6de3a0bd…` (Apache-2.0)"* plus a `THIRD_PARTY_NOTICES`
entry. Do **not** port `readInst()`'s giant switch — our decoder is Java/SLEIGH and its unknowns must remain
`unimplemented` (item 0 already does this well).

### 4.3 Borrowing the test corpus

Add a `binaryen-lit` source to `test-scripts/corpus/`: copy `test/lit/binary/*` (46), `test/lit/validation/*` (59)
and a sampled subset of `test/passes/*.wast`, plus `test/spec/*.wast` (110). Split into *valid* and *invalid*
by running `wasm-dis` once (lead #2 gives the exact expectation) and feed the invalid half to the existing
negative harness (`run_spectest_negative.ps1` + `parse_spec_negative.py`). Attribute Apache-2.0 for `test/spec/*`;
for the `WebAssembly/testsuite` submodule, fetch it directly at a **chosen** pin and record that pin in
`manifest.json` (Binaryen's is `4b24564c844e3d34bf46dfcb3c774ee5163e31cc`; ours is `d76759e7…` — pick one and
state it).

---

## 5. Top 3 recommendations, and what I would *not* port

**1 — Add `wasm-dis` (+ `wasm-shell`) as a cross-engine validity oracle in the harness.**
*First step:* copy `fetch_spectest_tools.ps1` to download `binaryen-version_133-x86_64-windows.tar.gz`, verify the
sha256, and wrap `wasm-dis --all-features -o NUL` in a `check-binaryen.ps1` that, run over `allprobes/` and
`corpus/modules/`, prints an accept/reject table. Point it at the existing 127 probes first: it will reproduce the
37 rejections above in under a minute and immediately exposes leads #1 and #4.

**2 — Port the decoding *rules* from `wasm-binary.h`/`wasm-binary.cpp` as small provenance-commented tables.**
*First step:* land two things from source, with one negative probe each: (a) the section-loop invariants
(`seenSections` + `pos == start + payloadLen`) mapped to `WasmModule`/`WasmSection`, with the five `S0*.wasm`
cases as the regression test — this closes the open B4; (b) the `readMemoryAccess` bit-6 memidx rule as a comment
+ assertion wherever `WasmFunctionAnalysis` skips a memarg (defends the just-fixed probe-06 behaviour).

**3 — Replace the accidentally-invalid probes and re-baseline.**
*First step:* one-line fix in `test-scripts/probes_multivalue.py` (`("f", 1, 1)` → `("f", 0, 1)` in all eight
sites), regenerate M01–M08, re-run the probe gate, and update `expected-results.json`. Then triage the other
~20 Binaryen-rejected probes with the oracle from #1 (each is either a probe bug or a deliberate leniency
decision to record).

**What I would NOT port:**
* **`wasm-opt` as the rejection oracle** — it aborts (`0xC0000409`, `wasm-traversal.h:297`) instead of failing
  cleanly; `wasm-dis` is the correct choice.
* **Binaryen's IR/optimiser, the passes (`src/passes/`, 146 files) and `wasm2js`** — irrelevant to a
  loader+decompiler, and a 131 MB dependency for nothing.
* **`readInst()`'s monolithic decode switch** — our Java+SLEIGH split is the right architecture; only the
  *rules/tables* are worth copying.
* **`wasm-decompile`** — it does not exist in v133 (no source, not in the release `bin/`); there is nothing to
  port, and Binaryen's remaining text output is `wat`, which our listing already approximates.
* **Binaryen's scratch-local/IR normalisation behaviour** — porting it would make our decoder *less* byte-faithful;
  we are the correct side here (§3.4 #6).
* **The `WebAssembly/testsuite` submodule contents wholesale** — large, differently pinned, and licensed
  separately; sample it and record the pin instead.

---

## 6. Sources

* Binaryen repository — <https://github.com/webassembly/binaryen>, cloned shallow at
  **`6de3a0bd2655952d8e08db4d03a6c7b4a3d7fde3`** (committed 2026‑10‑09), `CMakeLists.txt` `VERSION 133`.
* Release — tag **`version_133`** (<https://github.com/WebAssembly/binaryen/releases/tag/version_133>),
  asset **`binaryen-version_133-x86_64-windows.tar.gz`**,
  <https://github.com/WebAssembly/binaryen/releases/download/version_133/binaryen-version_133-x86_64-windows.tar.gz>
  (111,045,528 bytes, sha256 `17a2cbeac6b5693c5fbafab3838d3c65fd9c1eb38b05f5baec6c657e8c84995b`, verified against
  the published `.sha256`). Extracted tools report `wasm-opt version 133 (version_133)` etc.
* Key upstream files read: `src/wasm-binary.h` (`BinaryConsts`), `src/wasm/wasm-binary.cpp`
  (`WasmBinaryReader::read/getResizableLimits/readMemoryAccess/readDataSegments/readExports/validateBinary`),
  `src/wasm/wasm-validator.cpp` (`validateExports`), `src/wasm/wasm-ir-builder.cpp` (`addScratchLocal`),
  `src/wasm-features.h`, `src/passes/Print.cpp`, `src/tools/wasm-dis.cpp`, `src/shell-interface.h`,
  `scripts/test/spectest.js`, `LICENSE`, `.gitmodules`, `test/spec/testsuite` gitlink `4b24564c…`.
* Plugin sources read: `MODERN_WASM_GAPS.md`, `README.md`, `MERGE_NOTES.md`, `test-scripts/spectest/README.md`,
  `test-scripts/probes_multivalue.py`, `test-scripts/wasm_probe_lib.py`, `test-scripts/ListProgram.java`,
  `test-scripts/DumpDecomp.java`, `test-scripts/corpus/manifest.json`; archived per-module numbers from
  `archive/reports:reports/corpus-RESULTS.md` and `archive/reports:reports/REPORT-MV.md`.
* Local artefacts produced this session (in `C:\Users\micro\AppData\Local\Temp\research-binaryen\`):
  `sweep-allprobes.txt`, `funcmetrics.txt`, `funcmap.json`, `rasterbator-ghidra.txt`, `sqljs-ghidra.txt`,
  `rust_simd128-ghidra.txt`, `malformed-ghidra.txt`, `malformed2-ghidra.txt`, `exp-ghidra.txt`, and the helper
  scripts `sweep.py`, `diag.py`, `funcmap.py`, `stats.py`, `spot.py`, `rawparse.py`, `sections.py`,
  `mkmalformed.py`, `run_ghidra*.cmd`.
