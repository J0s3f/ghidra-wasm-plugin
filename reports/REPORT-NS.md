# REPORT-NS - negative-test baseline (rejection behaviour)

Scope: measure what this plugin does with the modules the WebAssembly spec testsuite says a correct
implementation must **reject** (`assert_invalid` / `assert_malformed` / `assert_unlinkable`), and
report defects. **No plugin source (`src/**`, `data/**`) was modified.** Branch `test/spec-negative`,
base `c02b6b9`.

Artifacts:

| file | role |
| --- | --- |
| `test-scripts/spectest/prepare_spec_negative.py` | selects the negative commands' modules; copies them as `<wast>.<n>.<invalid\|malformed\|unlinkable>.wasm` + `modules.json` |
| `test-scripts/spectest/SpecNegativeReport.java` | one `SPECNEG` line per program the loader **accepted** (funcs / blocks / memory & table bytes / data) |
| `test-scripts/spectest/run_spectest_negative.ps1` | chunked headless import with hard timeouts; a chunk that wedges/dies is split and retried |
| `test-scripts/spectest/parse_spec_negative.py` | classifies every module `rejected` / `accepted` / `crash` / `hang` |
| `test-scripts/spectest/select_negative_subset.py` | filtered import dir + manifest (analysis evidence pass, hazard pass) |
| `test-scripts/spectest/render_negative_doc.py` | renders `test-scripts/spectest-NEGATIVE.md` |
| `test-scripts/spectest-NEGATIVE.md` | the per-file table + summary + exact repro commands |
| `test-scripts/probes_negative.py` | 12 reduced reproducers (`--emit`, see §6) |

Everything under `test-scripts/spectest/**` is **additive**: `prepare_spec_tests.py`,
`run_spectest.ps1`, `parse_spec_results.py` and `SpecModuleReport.java` are untouched, and the
positive baseline still runs unchanged (§7).

**Environment note (measurement validity).** The shared `ghidra-l` install in place when this work
started contained an extension built from a *different* worktree - its `WasmLoader` was
pre-multi-memory (`getMemoryAddress` threw for `memidx != 0`, no `MEMORY_STRIDE`). Nothing in a
headless run reveals that, so every number below was taken **after**
`test-scripts/build-install.ps1 -GhidraDir <ghidra-l>` installed *this* worktree's build
(`dist/ghidra_12.1.4_PUBLIC_20261012_ghidra-wt-q.zip`, `lib/ghidra-wt-q.jar`, sha256
`d43de914d7c9ede3...`). The rule for anyone re-running this: **build-install immediately before the
run**, and check `Ghidra\Extensions\` afterwards (a second workstream installing into the same Ghidra
replaces the extension for everyone).

## 1. Headline

All **2948 binary negative modules** of testsuite `d76759e7` were imported (wabt 1.0.42,
`wast2json --no-check`), i.e. the full set, no sampling:

| kind | modules | rejected | accepted | crash | hang |
| --- | ---: | ---: | ---: | ---: | ---: |
| `assert_invalid` | 2146 | 0 | 2146 | 0 | 0 |
| `assert_malformed` | 719 | 59 | 660 | 0 | 0 |
| `assert_unlinkable` | 83 | 0 | 83 | 0 | 0 |
| **total** | **2948** | **59** | **2889** | **0** | **0** |

`module_type: text` commands (1091 `assert_malformed` on the *text* format, emitted as `.wat`) were
excluded: they are not WebAssembly binaries, this plugin has no text parser, and a binary loader
rejects them trivially. `--include-text` covers them if wanted.

Accepted programs split into `accepted-shape` 2617, `accepted-empty` 219, `accepted-partial` 53.
`accepted-empty` means the program has nothing but the raw-byte `.module` block; `accepted-partial`
means the loader logged `Failed to load Wasm module` **and the import was still reported as
successful**. 52 of the 53 partial ones are empty as well, so **271 modules are accepted and hand the
user essentially nothing**; the 53rd (`ref_func.2.invalid.wasm`) has two body-less functions.

The 59 rejections come from two mechanisms only: 28 "no loader matched" (bad magic / bad version /
file shorter than the header - `findSupportedLoadSpecs` is the only gate) and 31 "the module block
was never created because an exception escaped `WasmModule` parsing" (`No memory blocks were
defined`). There is **no validation and no rejection diagnostic of the loader's own**.

With analysis enabled - the default for an interactive import - the picture is worse. A separate
*hazard pass* imported the 9 modules with the most extreme declared metadata one per headless run:
**5 hang** (killed after 90 s) - `binary-leb128.48/49` and `memory.21/22/23` - and 2 of the other 4
make `WasmPreAnalyzer` throw (`binary.53`, `binary.54`). The minimal probe `NS07` (locals count
`0x40000000`) goes further and kills the run with `OutOfMemoryError`. Those 9 modules are invisible
in the table above because `-noanalysis` imports all of them in well under a second (§3, findings
NS-1 and NS-2).

## 2. What "accepted" means here (and why it is not automatically a bug)

The plugin is a loader/disassembler, and it is deliberately lenient: unknown section ids are
skipped, unknown opcodes degrade to `unimplemented`, names are sanitised. A reverse-engineering tool
must not refuse to open a binary just because the *type checker* would reject it, so:

* accepting all 2146 `assert_invalid` modules (type errors, out-of-range indices, bad limits) with a
  plausible program is **defensible by design** - it is listed but not ranked as a defect;
* the same for the 83 `assert_unlinkable` modules (they are valid modules that fail to *link*; this
  plugin does not link);
* accepting *malformed* (not merely invalid) binaries is where it gets interesting, because the
  bytes cannot be trusted - and that is where every finding below lives.

The defect line I use: **an accepted module is a defect when the resulting program is empty,
incomplete, or only obtainable by silently swallowing an error** - i.e. when the plugin reports
success but does not give the user what the file actually contains.

## 3. Ranked findings

### NS-1 (high) - a malformed/huge linear-memory minimum is clamped to 2 GiB and wedges analysis

*Spec input:* memory limits with an out-of-range minimum: `binary-leb128.48/49` (5-byte LEB that the
spec rejects as "integer too large") and the `assert_invalid` modules `memory.21/22/23`
("memory size must be at most 65536 pages (4GiB)"). Measured minimums: 30064771074 / 17179869186 /
65537 / 2147483648 / 4294967295 pages.

*Behaviour:* `WasmLoader.loadMemories` clamps memory 0 to `CODE_BASE` (`0x80000000`) and calls
`createInitializedBlock(".memory0", 0x80000000 bytes)`. The plain import succeeds and is fast
(`SPECNEG ... blocks=2 memory=1 memory_bytes=2147483648`), but with analysis - the default for an
interactive import - **all five hang**: in the hazard pass each was killed after 90 s with the log
stopped right after `Applied data type archive: generic_clib` (a 240 s timeout behaves the same). A
user opening such a file in Ghidra gets a wedged analyser.

*Repro:* `test-scripts/probes_negative.py ... --emit` -> `NS12_memory_min_2g.wasm` (17 bytes),
import with analysis: the run must be killed (measured: timeout at 60-240 s). Without analysis the
same module imports in <0.2 s with a 2 GiB `.memory0` block.

### NS-2 (high) - an absurd locals count OOMs or breaks the analysis

*Spec input:* `binary.51-54.malformed.wasm`, i.e. `binary.wast`'s "integer too large" / "too many
locals" cases; the code section declares locals counts from 0x40000000 up to 2^32.

*Behaviour (same root cause - `WasmCodeEntry.getLocals()` / `WasmAnalysis.getFunctions()`
materialise the declared locals vector - four different outcomes):*

| module (hazard pass, analysis on) | outcome |
| --- | --- |
| `binary.51`, `binary.52` | accepted, analysis completes without an exception |
| `binary.53` | accepted; `WasmPreAnalyzer` throws `IllegalArgumentException: fromIndex(0) > toIndex(-1)` (caught by the analysis framework, logged as an analysis-task error) |
| `binary.54` | accepted; `WasmPreAnalyzer` throws `ArrayIndexOutOfBoundsException: Array index out of range: 1073741824` |
| probe `NS06` (locals 0xffffffff) | accepted; same `IllegalArgumentException` |
| probe `NS07` (locals 0x40000000) | accepted by the loader; **`OutOfMemoryError: Java heap space`** at `WasmCodeEntry.getLocals(WasmCodeEntry.java:71)` -> "Abort due to Headless analyzer error" -> the whole headless run dies |

The module is *accepted* in every case; only `-noanalysis` avoids the blast radius.

A secondary harness detail worth knowing: after the abort, `analyzeHeadless.bat` runs `pause`, so
without stdin EOF the process never exits and a crash looks like a hang. The harness now redirects
`< nul`, which turns it into a fast non-zero exit.

*Repro:* `NS06_too_many_locals.wasm`, `NS07_locals_count_huge.wasm` (32 bytes each).

### NS-3 (high) - a swallowed loader exception silently truncates the module

*Spec input:* the "malformed UTF-8 encoding" custom-section names, `utf8-custom-section-id.*` (26
modules) and `utf8-import-module.*` (26 modules) - e.g. 13 bytes: `0061736d01000000 0003 02 c2 7f`.

*Behaviour:* `WasmCustomSection` -> `StructureBuilder` builds a `DataType` named `.custom.\uFFFD` ->
`IllegalArgumentException: Invalid DataType name`. The exception escapes `doLoad`, is caught by
`WasmLoader.load()` (which only logs `Failed to load Wasm module`), and the import is then reported
as **successful**: `SPECNEG ... funcs=0 blocks=1`. Because the section-markup loop runs before
`loadFunctions`/`loadMemories`/`loadDataSegments`/`loadGlobals`, everything after the offending
section is lost.

*Reduced proof of the consequence* (`NS11_bad_custom_hides_code.wasm`): a module with a 5-byte
bad-UTF8 custom section **followed by** a valid type+function+code section is accepted with
`funcs=0`; the identical module without the custom section imports with `funcs=1 instrs=2
undefined_bytes=0`. The user's function disappears and nothing in the UI says so - and with analysis
on, `WasmSignatureAnalyzer` then reports `NullPointerException: Failed to set function signature for
unnamed_function_0`, i.e. the analysers run against the truncated program.

### NS-4 (medium) - 219 accepted modules produce a program with nothing but the raw bytes

Accepted with `blocks=1` (only `.module`), i.e. no functions, no sections with content. Dominant
classes (by the testsuite's own expected message):

| expected (testsuite) | modules |
| --- | ---: |
| malformed UTF-8 encoding (custom-section names) | 150 |
| unexpected content after last section | 20 |
| unknown memory (incl. "unknown memory N") | 11 |
| integer representation too long | 6 |
| malformed section id | 5 |
| integer too large | 5 |
| duplicate export name | 5 |
| unknown table | 4 |
| multiple memories | 3 |
| memory size must be at most 65536 pages (4GiB) | 3 |
| data count and data section have inconsistent lengths | 2 |
| (tail, one module each) | 5 |

Root cause for the section-id group: `WasmSection.createSection` returns `null` for any id
>= `SEC_TAG+1` (14) and `WasmModule`'s loop just `continue`s (the pointer still advances, so no
infinite loop) - the section vanishes instead of being reported. `binary.wast:48-52` is exactly this
test (`\0e\01\00`, `\7f\01\00`, `\80\01\00...`, `\81\01\00...`, `\ff\01\00...`), and all five are
accepted. Duplicate/out-of-order sections are equally invisible: `sectionMap.put()` overwrites.

For modules that contain *only* a custom section (the 150), an empty program is arguably correct;
the defect is that "malformed" is indistinguishable from "empty module". For the 20
"unexpected content after last section" and the out-of-range ids it is a genuine missing rejection.

*Repro:* `NS01`/`NS02`/`NS03` (out-of-range section ids), `NS04` (duplicate section),
`NS09` (bad-UTF8 custom name).

### NS-5 (medium) - a table whose minimum is 0xffffffff loses its table silently

*Spec input:* `table.12.invalid.wasm`, 19 bytes:
`0061736d01000000 0409 01 70 01 ffffffff 0f 00` - the testsuite expects "size minimum must not be
greater than maximum".

*Behaviour:* `createTableBlock` requests `0xffffffff * 4` bytes; Ghidra refuses with
`IllegalStateException: New memory block NOT added: would cause total number of initialized program
bytes to exceed the maximum program size`. The error is logged, the load continues, and the accepted
program simply has no `.table0` block (`funcs=0 blocks=1`).

Related, same shape: `call_indirect.36.invalid.wasm` -> `Failed to initialize table 0 with element
segment 0 at offset 0: IndexOutOfBoundsException: Index: 0` (caught per segment; the accepted
program has a table with no elements).

*Repro:* `NS10_table_overflow.wasm`.

### NS-6 (low) - accepted programs with no code, and lenient mis-decodes

* 157 of the 2229 accepted `assert_invalid`/`assert_unlinkable` modules produce a program with
  `funcs=0` (they only declare memory/globals/tables). Expected for those modules, but it means
  "accepted" carries no information about whether anything was decoded.
* The lenient decode path is visible in the evidence pass: e.g. `binary.40.malformed.wasm`
  ("illegal opcode" - an init expression without its `end` marker) is accepted and the whole body
  decodes with `undefined_bytes=0`, `instrs=2` (`.locals`, `end`) - a plausible-looking but wrong
  program rather than a diagnostic. This is the same "graceful degradation" the positive baseline
  relies on (see `REPORT-A-DS.md` R1.1), so it is recorded, not ranked as a bug.

### Observation - the rejection path itself is accidental

`WasmLoader.load()` wraps `doLoad` in `try { ... } catch (Exception e) { Msg.error("Failed to load
Wasm module", e); }` and never rethrows. Rejection therefore only happens when

1. `findSupportedLoadSpecs` produces no `LoadSpec` (magic/version/short header), or
2. the exception is thrown before the `.module` block is created (`WasmModule`'s constructor), so
   Ghidra's "No memory blocks were defined for file ..." check fires.

Everything thrown after that point is silently swallowed (NS-3, NS-5). A malformed file whose
sections happen to parse is indistinguishable from a valid one.

## 4. Evidence pass (analysis enabled, bounded)

`-noanalysis` cannot show decode quality, so an evidence pass re-imported a bounded sample with
analysis: **250 accepted malformed modules**, i.e. the whole `align`/`binary`/`binary-leb128`/
`custom`/`global` groups plus a slice of `utf8-*`, minus the 9 hazard modules of NS-1/NS-2 (those are
characterised individually by the hazard pass). Result (`%TEMP%\specneg-evidence`, 1.6 min):

| metric | value |
| --- | ---: |
| modules | 250 (59 of them declare any code at all) |
| functions decoded | 63 |
| instructions decoded | 216 |
| undefined bytes (the real decode gap) | 66, across 19 modules |
| modules where an analyser threw | **14** |

The 14 exception classes are `IndexOutOfBoundsException` x6 and `EOFException` x5 from
`WasmPreAnalyzer` (e.g. `Failed to analyze function unnamed_function_0 @ ram:8000001b`, and
`Index 1 out of bounds for length 1` for the "function and code section have inconsistent lengths"
cases), `ValidationException` x2 (also `WasmPreAnalyzer`, on `align.112/113`), and one
`IllegalStateException` from a custom-section memory block. Ghidra catches these per analysis task,
logs them, and carries on - so the user gets a program that is silently only partly analysed, on a
module the harness counted as `accepted`.

Take-aways:

* Accepted malformed modules mostly *do* decode (66 undefined bytes over 250 modules): the defect is
  not the decode but NS-3/NS-4 - accepted modules whose program is empty or truncated.
* ~5.6 % of the accepted malformed modules (14/250) make an analyser throw, and NS-1/NS-2 show that
  a handful of them stall or kill the run outright.
* The bounded evidence pass deliberately excludes the 9 hazard modules; with them included it does
  not finish (measured: 24 unresolved modules after a 240 s chunk timeout).

## 5. Coverage and limits

* **All** 2948 binary negative modules were imported; nothing was sampled for the classification
  table. The evidence pass is the bounded part (250 of 660 accepted malformed modules).
* 1091 text-format `assert_malformed` modules were not imported (`--include-text` to add them).
* Proposal directories (`proposals/gc`, `proposals/exception-handling`, ...) are not wired in,
  same as the positive harness.
* `assert_unlinkable` is reported separately because "accepted" is the expected outcome there.
* Determinism: the classification is a function of the loader, but the *timing-dependent* outcomes
  (crash/hang) can vary with machine load and with `GHIDRA_HEADLESS_MAXMEM`; the harness records
  timeouts and exit codes per chunk in `chunks.json`.

## 6. Permanent regression probes

`test-scripts/probes_negative.py` holds 12 minimal modules (9-32 bytes) with the measured outcome
documented in the docstring of each entry. It **writes nothing unless `--emit` is passed**, because
`run_probes.ps1` globs `probes_*.py` and `check-results.py` fails on any probe missing from
`expected-results.json`:

```powershell
python test-scripts\probes_negative.py "$env:TEMP\specneg-probes\import" --emit
```

| probe | bytes | spec expectation | import-only (`-noanalysis`) | analysis on (interactive default) |
| --- | ---: | --- | --- | --- |
| `NS01_bad_section_id_0x0e` | 11 | malformed section id | accepted, empty program | accepted, empty |
| `NS02_bad_section_id_0x7f` | 11 | malformed section id | accepted, empty program | accepted, empty |
| `NS03_bad_section_id_leb` | 14 | malformed section id | accepted, empty program | accepted, empty |
| `NS04_duplicate_section` | 14 | unexpected content after last section | accepted, empty program | accepted, empty |
| `NS05_global_no_end` | 31 | illegal opcode | accepted, global mis-modelled, funcs=1 | accepted, 2 instrs, 0 undefined bytes |
| `NS06_too_many_locals` | 32 | too many locals | accepted, funcs=1 | accepted + `WasmPreAnalyzer IllegalArgumentException` |
| `NS07_locals_count_huge` | 32 | malformed integer (too many locals) | accepted, funcs=1 | **`OutOfMemoryError` kills the run** (`crash`) |
| `NS08_truncated_section` | 9 | malformed (EOF) | **rejected** (`No memory blocks`) | rejected (control: the rejection path works) |
| `NS09_custom_name_bad_utf8` | 13 | malformed UTF-8 | accepted, loader exception swallowed | accepted, `accepted-partial` |
| `NS10_table_overflow` | 19 | invalid limits | accepted, `.table0` missing | accepted + `IllegalStateException` (table block refused) |
| `NS11_bad_custom_hides_code` | 29 | malformed UTF-8 | accepted with **funcs=0** (function lost; control without the custom section: funcs=1) | accepted + `WasmSignatureAnalyzer NullPointerException` |
| `NS12_memory_min_2g` | 17 | malformed (integer too large) | accepted, 2 GiB `.memory0` (`memory_bytes=2147483648`) | **hangs** (killed after 60 s, `hang`) |

Both columns are measured (probe pass without analysis: all 12 in a single import run; probe pass with
analysis: one module per headless run, 3.5 min total).

Wiring these into `run_probes.ps1`/`expected-results.json` (and `check-results.py --update`) is an
integrator decision; the probe names are stable and the harness already reads import failures.

## 7. Positive baseline is unchanged

The negative harness is additive and does not touch the positive pipeline. `run_spectest.ps1
-Subset smoke -MaxPerWast 2` was re-run after the changes (10 valid modules, 25 s):

```
modules: 10 selected, 10 imported, 0 not imported
functions: 467, instructions: 4410, undefined_bytes: 5, decompiled: 467, decompile_failed: 0
```

i.e. exactly the expected result: 10/10 imported, no decompile failures, and `undefined_bytes=5` is
the known `select`-after-unconditional-terminator decode gap already documented in
`test-scripts/spectest-BASELINE.md`. `prepare_spec_tests.py`, `parse_spec_results.py`,
`SpecModuleReport.java` and `run_spectest.ps1` were not modified (the new negative scripts are
separate files; `prepare_spec_negative.py` merely *imports* `SUBSETS` from
`prepare_spec_tests.py`, which has no side effects).

## 8. Bug list for the integrator (no fixes applied here)

Severity order. "Repro" is a probe from `test-scripts/probes_negative.py` (`--emit`) or a module name
from the testsuite run; the exact byte content of the probes is in the file's docstring.

**B1 (high) - analysis OOMs or throws on an absurd `locals` count.**
`wasm/format/sections/structures/WasmCodeEntry.java:66` (`getLocals`) is reached from
`wasm/analysis/WasmAnalysis.java:73/129` (`getFunctions`) via `WasmPreAnalyzer.added`; the declared
locals vector is materialised without a sanity check. Repro: `binary.51-54.malformed.wasm`
(`binary.wast` "integer too large" / "too many locals"), probes `NS06`, `NS07`. Measured:
`IllegalArgumentException: fromIndex(0) > toIndex(-1)`, `ArrayIndexOutOfBoundsException: Array index
out of range: 1073741824`, and `OutOfMemoryError: Java heap space` (which aborts the whole headless
run). Expected: validate/clamp the count, or leave the function undecoded.

**B2 (high) - a malformed/huge memory minimum becomes a 2 GiB block and wedges analysis.**
`wasm/WasmLoader.java:554-561` clamps memory 0 to `CODE_BASE` and then creates an initialised block
of that size. Repro: `binary-leb128.48/49.malformed.wasm`, `memory.21/22/23.invalid.wasm`, probe
`NS12`. Measured: `SPECNEG ... memory_bytes=2147483648`; the import succeeds in <0.2 s, but with
analysis the run never returns (killed after 90-240 s depending on the harness timeout, log stops
after `Applied data type archive: generic_clib`). This is the default interactive import path.
Expected: reject the limits, or do not materialise an initialised block for an implausible size.

**B3 (high) - a swallowed loader exception silently truncates the module.**
`wasm/WasmLoader.java:713-723`: `load()` catches every `Exception` from `doLoad` and only logs
`Failed to load Wasm module`. One trigger is a custom/import name that is not valid UTF-8, which
makes `StructureBuilder` build a `DataType` named `.custom.\uFFFD` ->
`IllegalArgumentException: Invalid DataType name`. Repro: `utf8-custom-section-id.*` (26),
`utf8-import-module.*` (26), `ref_func.2.invalid.wasm`, probe `NS11`. Measured: the import is
reported as **successful** while everything after the failing section is lost (`funcs=0`); the
control module without the 5 bad bytes imports with `funcs=1`. Expected: sanitise the name, or fail
the import, or mark the program as incomplete.

**B4 (medium) - out-of-range section ids and duplicate sections are silently dropped.**
`wasm/format/sections/WasmSection.java:56-57` returns `null` for any id >= 14 and
`wasm/format/WasmModule.java:63-75` `continue`s (pointer still advances, so no infinite loop);
`sectionMap.put` overwrites duplicates. Repro: `binary.wast:48-52` (ids `0x0e`, `0x7f`, `0x80`,
`0x81`, `0xff` - the spec's "malformed section id" test), probes `NS01`-`NS04`. Measured: accepted,
empty program; the user cannot tell "malformed" from "no such section".

**B5 (medium) - a refused table block leaves the program without its table, silently.**
`wasm/WasmLoader.java:306-332`. Repro: `table.12.invalid.wasm` (min `0xffffffff`), probe `NS10`.
Measured: `IllegalStateException: New memory block NOT added: would cause total number of
initialized program bytes to exceed the maximum program size` is logged, the load continues, and the
accepted program has no `.table0`. Expected: reject, or clamp, or expose the failure in the program.

**B6 (medium) - "accepted" says nothing about whether anything was understood.** 219 of the accepted
modules yield a program with only the raw-byte `.module` block (and 52 more produce an empty program
*after* an internal error). A user (or the harness) sees `Import succeeded` and gets nothing. A
loader that decides to be lenient should still surface "N sections skipped / M bytes not modelled".

**B7 (low) - the rejection path is accidental.** 59 rejections = 28 "no loader matched"
(`findSupportedLoadSpecs` is the only gate) + 31 "Ghidra noticed the program had no memory blocks"
because `WasmModule`'s constructor happened to throw first. Neither is a loader diagnostic. A
malformed file whose first section parses is never reported as malformed.

**Not defects (recorded for context, no action requested):** accepting all 2146 `assert_invalid`
and all 83 `assert_unlinkable` modules with a plausible program - a disassembler is not a validator
or a linker, and `REPORT-A-DS.md` documents the deliberate "degrade instead of reject" policy
(unknown opcodes decode as `unimplemented`). The 1091 text-format `assert_malformed` modules are out
of scope for a binary loader.

**Harness note for whoever reproduces this:** `analyzeHeadless.bat` finishes with
`pause`, so an aborted run (e.g. the `OutOfMemoryError` of B1) does not exit; the harness redirects
`< nul` and records a non-zero exit code instead of an eternal "hang".
