# REPORT-J - WebAssembly loader robustness (malformed-input sweep)

Worktree `D:\code\ghidra-wt-j` (branch `test/robustness`); plugin built from this worktree and
installed into `C:\Users\micro\AppData\Local\Temp\opencode\ghidra-j` (Ghidra 12.1.4, private
install). No file under `src/**` or `data/**`, and no other workstream's file, was modified - this
workstream only added test tooling and this report.

Deliverables (all owned by this workstream):

| file | purpose |
| --- | --- |
| `test-scripts/make_malformed_corpus.py` (renamed from gen_malformed_probes.py during integration so the CI probe glob does not pull in the 56-module corpus) | stdlib-only generator of the malformed corpus (`all` = 56, `core` = 26) |
| `test-scripts/robustness-sweep.ps1` | per-file headless import sweep + outcome classifier |
| `test-scripts/robustness-RESULTS.md` | the per-module outcome table (56-module corpus, analysis ON) |
| `test-scripts/probes_malformed.py` (J03-J05, CI-safe) + `test-scripts/malformed_probes_manual.py` (J01/J02, one JVM per import) | permanent reproduction probes for the worst findings |
| `REPORT-J.md` | this report |

## 0. Headline

* **Primary run: the full 56-module corpus, analysis ON**, one headless JVM per module,
  `-analysisTimeoutPerFile 60`, hard 180 s wall bound. Counts: **27 `import_ok`** (one is the valid
  control), **27 `import_failed`**, **1 `process_died`**, **1 `import_ok_analysis_timeout`**,
  **0 hangs**. (The sweep also supports a fast **26-module `core`** subset imported with
  `-noanalysis`; see §1.)
* **Control** `V00_valid_passthrough.wasm` → `import_ok` (funcs=1, instrs=3, decompiled=1): the
  harness is sane. (During development an early generator bug produced an unwrapped function body;
  the control immediately exposed it as `import_failed` - which is why it exists.)
* **One process-level crash (real bug):** `B04_locals_1G_alloc` - a 30-byte module with a locals
  group count of `0x40000000` makes the decompiler throw `OutOfMemoryError`, which is **not**
  caught and aborts the whole headless run (exit code 1; reproduced 3/3).
* **One resource-exhaustion bug:** `M03_mem_huge_initial` - a 17-byte module with memory
  `initial = 0xFFFFFFFF` pages is accepted and builds a **2 GiB** `.memory0` block. Auto-analysis
  then does not finish within 60 s (`import_ok_analysis_timeout`, wall 71 s); even import-only it
  materialises the full 2 GiB block.
* **No uncaught exception on the loader's own import path:** every structural parse error was
  caught and reported as a normal `Import failed` (27 modules). The crash comes from the *analysis*
  path, not from decoding.

## 1. Method (exact command)

The corpus is generated (56 modules) and then every module is imported in **its own** headless
Ghidra process - a crash or hang of one module cannot mask the rest:

```
cd D:\code\ghidra-wt-j
.\test-scripts\robustness-sweep.ps1 -CorpusMode all -Analyze -WallSeconds 180
```

which, for each `*.wasm`, runs (unique project dir per file; unique per-run work dir):

```
analyzeHeadless <proj>\<module> Robustness \
  -import <module>.wasm \
  -scriptPath D:\code\ghidra-wt-j\test-scripts \
  -postScript WasmFeatureReport.java \
  -max-cpu 2 -analysisTimeoutPerFile 60 -deleteProject     # GHIDRA_HEADLESS_MAXMEM=1500M
```

* **Analysis ON for the primary run** (`-Analyze`). This is necessary to observe the real failures:
  `M03`'s timeout and `B03`/`C09`/`O*`'s caught analyzer exceptions only appear when the analyzers
  and the `WasmFeatureReport` decompile step run.
* **Fast variant:** the sweep defaults to the curated **26**-module `core` subset with
  `-noanalysis` (JVM startup, ~10-16 s/file, dominates). That baseline is bounded and reproducible;
  every module that fails (or succeeds) at *load* time behaves identically, so the load-level
  outcomes are unchanged. The analysis-only failures are then covered by the `-Analyze` run here.
* **Hard wall bound, no orphans:** `Start-Process` + `WaitForExit(180_000)`; on overrun the PID
  tree is killed (`taskkill /T /F`) and the file recorded as `hang`, and after the loop any
  `java.exe` still referencing the run's unique work directory is killed. The sweep always exits
  (0, or 2 when a severe outcome was seen), so a wedged child cannot stall or leak the run.

Outcomes: `import_ok`, `import_ok_analysis_timeout`, `import_failed`, `process_died` (JVM exit != 0,
or an uncaught exception / `OutOfMemoryError` at process level), `hang`, `unknown`.

## 2. Corpus design (56 modules; `core` selects a 26-module representative subset)

| prefix | category | n | files |
| --- | --- | --- | --- |
| `V` | sanity control | 1 | valid `(i32)->i32` module |
| `T` | truncation | 6 | empty; mid-header; mid-version; mid-section-id; mid-payload; mid-function-body |
| `L` | bad LEB128 | 5 | overlong padding; >5-byte length; count `0xFFFFFFFF`; 10-byte length overflow; unterminated LEB at EOF |
| `S` | section size mismatch | 4 | declared smaller; declared larger; size 0; size 2^28 |
| `C` | absurd counts | 9 | type / function / code / table / memory / global / element / data = `0xFFFFFFFF`; function-vs-code mismatch |
| `O` | out-of-range indices | 8 | type, function, table, memory, global, element-func, tag, huge `call_indirect` type idx |
| `D` | duplicates / order / unknown | 5 | two type; two code; unknown section id; code/function/type reversed; repeated custom sections |
| `B` | body / locals | 4 | zero-length body; body size > section; `0xFFFFFFFF` i32 locals; `0x40000000` i32 locals |
| `X` | bad constant expressions | 3 | missing `end`; 10-byte overflow `i32.const`; three never-terminated nested blocks |
| `M` | limits / data | 6 | initial > maximum; maximum = 2^32; memory initial `0xFFFFFFFF` pages; table initial `0xFFFFFFFF`; data offset out of range; overlapping active segments |
| `H` | magic / version | 5 | wrong magic; version 0; version 13; version 0x0D layer 1; all zeros |

The `core` subset is: `V00`, `T01/T04/T05`, `L03/L05`, `S02/S04`, `C01/C03/C05/C09`, `O05/O08`,
`D03/D04`, `B02/B03/B04`, `X01/X03`, `M01/M03/M04`, `H01/H03`.

## 3. Where the loader's risk lives (static read, confirmed by the sweep)

`WasmLoader.load` (`WasmLoader.java:702-712`) wraps `doLoad` in `catch (Exception e)` and logs
"Failed to load Wasm module"; it does **not** catch `Error`, so an `OutOfMemoryError` arising while
a program is being built/analysed escapes. By construction, a module whose *structure* decodes but
whose *values* are invalid still yields a program (the "silent acceptance" class).

* **Section framing ignores the declared size** - `WasmSection.createSection` (`WasmSection.java:50-91`)
  advances the outer reader past `id + leb(size) + size` (line 54) but parses the body from a
  `reader.clone(sectionOffset)` (line 59) that is **not bounded by the declared size**. A lying size
  therefore desyncs the *next* section instead of being rejected (`S02`, `S04`).
* **Unknown / repeated sections are silently handled** - `createSection` returns `null` for
  `id >= enum length` (`WasmSection.java:56`); `WasmModule` does `continue` (`WasmModule.java:65-66`);
  repeated non-custom sections overwrite each other in an `EnumMap` (`WasmModule.java:73`).
* **Unvalidated allocation sizes** - memory `Math.min(initial*65536, CODE_BASE=2 GiB)`
  (`WasmLoader.java:546`); table `elementSize * numElements` with no cap (`WasmLoader.java:298`);
  locals `new ValType[sum of int-cast LEB counts]` (`WasmCodeEntry.java:66-78`,
  `WasmLocalEntry.java:38-40`); func-type params `new ValType[(int) pcount]` (`WasmFuncType.java:41,47`);
  GC supertype vectors `new long[(int) n]` (`WasmGCType.java:265`).
* **Unvalidated indices** - `WasmFunctionAnalysis` indexes `getLocals()[localidx]`
  (`WasmFunctionAnalysis.java:879,886,893`); bad type/global indices throw inside the analyzers,
  which catch per analyzer and log.

## 4. Per-case outcomes

The full per-module table is in [`test-scripts/robustness-RESULTS.md`](test-scripts/robustness-RESULTS.md).
Totals for the primary 56-module, analysis-ON run:

| outcome | count | modules |
| --- | --- | --- |
| `import_ok` | 27 | V00 (control) + 26 accepted-but-invalid |
| `import_ok_analysis_timeout` | 1 | M03 |
| `import_failed` | 27 | T*, most C*, H*, B01, B02, L03-L05, S01, X01, X03 |
| `process_died` | 1 | B04 |
| `hang` | 0 | - |
| `unknown` | 0 | - |
| **total** | **56** | |

Selected rows (see RESULTS.md for all 56):

| module | bytes | outcome | evidence |
| --- | --- | --- | --- |
| `V00_valid_passthrough` | 35 | import_ok | funcs=1 instrs=3 decompiled=1 |
| `B04_locals_1G_alloc` | 30 | **process_died** | `OutOfMemoryError` aborts headless (exit 1) |
| `M03_mem_huge_initial` | 17 | **import_ok_analysis_timeout** | `.memory0 size=2147483648`; `Analysis timed out at 60 seconds` (wall 71 s) |
| `B03_locals_ffffffff` | 30 | import_ok | caught `NegativeArraySizeException`; funcs=1 instrs=1 undefined_bytes=7 |
| `C09_count_func_code_mismatch` | 26 | import_ok | caught `IndexOutOfBoundsException: Index 1 out of bounds for length 1`; funcs=1 |
| `M04_table_huge_initial` | 18 | import_ok | 16 GiB guard throws (caught); no table |
| `M05_data_offset_oor` | 30 | import_ok | `MemoryAccessException: Address ram:7ffffff0 does not exist in memory` (caught) |
| `M06_data_overlap` | 35 | import_ok | overlapping active data segments both accepted |

### 4.1 Clean failures (`import_failed`, correct behaviour)

Two mechanisms, both bounded and reported:

* **No load spec / bad header** - `findSupportedLoadSpecs` requires magic `\0asm` **and** version 1,
  so `T01_empty`, `T02/T03` (truncated header), `H01_bad_magic` (wrong magic), `H02_version0`,
  `H03_version13_component` (version `0x0d`), `H04_version0d_layer1` and `H05_all_zeros` never match;
  Ghidra prints the generic *"The ProgramLoader could not successfully load file ..."*.
* **Structural parse error** - every truncated/lying/overflowing section throws inside the parsers;
  `WasmLoader.load` catches it and logs *"Failed to load Wasm module"* + stack. Examples from the run:
  * `L05_leb_unterminated_eof`, `T04_trunc_mid_sectionid`, `S01_size_declared_smaller`:
    `java.io.EOFException` at `WasmSection.createSection(WasmSection.java:53)`.
  * `T05`, `L03`, `C01`: `IOException: Unable to read past EOF` at `WasmTypeSection.<init>:43`.
  * `B01` (0-length body): `EOFException` at `WasmCodeEntry.<init>:42`; `B02`, `C03`, `T06`:
    `Unable to read past EOF` at `WasmCodeEntry.<init>:46`.
  * `C02`: `WasmFunctionSection.<init>:36`; `C04`/`C06`: `ValType.readFromReader`; `C05`:
    `WasmResizableLimits.<init>:44`; `C07`: `WasmElementSegment.<init>:57`; `C08`:
    `WasmDataSegment.<init>:37`; `L04`: `Unsupported LEB128 value, too large ... 64bit` at
    `WasmSection.createSection:53`; `X01`, `X03`: `ConstantExpression.readExpression:110`.

All 27 are the desired behaviour for a static loader.

## 5. Ranked severity

### (a) Hangs / timeouts

* **No module hits the 180 s wall bound** (0 hangs); the slowest import is `M03` at ~71 s.
* **A1 - `M03_mem_huge_initial.wasm`: a 17-byte module that does not finish analysis.**
  Bytes: `00 61 73 6D 01 00 00 00 05 07 01 00 FF FF FF FF 0F` (1 memory, flags `0x00`,
  initial = `0xFFFFFFFF` pages, no maximum). Observed: import **succeeds** and
  `PROBE-BLOCK .memory0 size=2147483648` (2 GiB); auto-analysis then runs against a 2 GiB address
  space and the run ends with `REPORT: Analysis timed out at 60 seconds. Processing not
  completed for file ...` (wall ≈71 s). Root cause: `WasmLoader.loadMemories`
  (`WasmLoader.java:546`) clamps to `CODE_BASE` (2 GiB) and never checks `initial <= maximum` or a
  sane page ceiling; the resulting block makes every address-space walk O(2 GiB). This is an
  **unbounded-work / resource-exhaustion bug**, not merely a slow load. (The same bytes materialise
  the 2 GiB block even with `-noanalysis`.)

### (b) Process-level crashes - CRITICAL

**B1. `B04_locals_1G_alloc.wasm` - `OutOfMemoryError` escapes to the process.**
Bytes (30): `00 61 73 6D 01 00 00 00 01 04 01 60 00 00 03 02 01 00 0A 0A 01 08 01 80 80 80 80 04 7F 0B`
(one function, a single locals group: count `0x40000000` = 1 073 741 824, type `i32`).
Observed: `process_died`, exit code **1**, wall ≈12 s, reproduced 3/3:

```
ERROR Abort due to Headless analyzer error: Java heap space (HeadlessAnalyzer) java.lang.OutOfMemoryError: Java heap space
    at wasm.format.sections.structures.WasmCodeEntry.getLocals(WasmCodeEntry.java:71)
    at wasm.analysis.WasmAnalysis.getFunctions(WasmAnalysis.java:145)
    at wasm.analysis.WasmAnalysis.<init>(WasmAnalysis.java:73)
    at wasm.analysis.WasmAnalysis.lambda$getState$0(WasmAnalysis.java:62)
    at ghidra.app.plugin.core.analysis.TransientProgramProperties.getProperty(...)
    at wasm.analysis.WasmAnalysis.getState(WasmAnalysis.java:50)
    at wasm.pcode.InjectPayloadWasmPop.emitPops(InjectPayloadWasmPop.java:52)
    at ghidra.app.decompiler.DecompileCallback.getPcodeInject(DecompileCallback.java:330)
    at ghidra.app.decompiler.DecompInterface.decompileFunction(...)
    at WasmFeatureReport.run(WasmFeatureReport.java:42)
    at ghidra.app.util.headless.HeadlessAnalyzer.runScript(...)
```

Root cause: `WasmLocalEntry.getCount()` casts the LEB `long` to `int` with no bound
(`WasmLocalEntry.java:38-40`); `WasmCodeEntry.getLocals()` sums those ints and allocates
`new ValType[localCount]` (`WasmCodeEntry.java:66-78`). `WasmAnalysis` eagerly materialises every
function's locals (`WasmAnalysis.java:129-154`, line 145), reached on the first decompile via the
`WasmPop` pcode injector. `OutOfMemoryError` is an `Error`, so neither `WasmLoader.load`'s
`catch (Exception)` nor the decompiler callback catches it - the whole headless run aborts.
**This is the single most severe finding: a ~30-byte file kills the headless process.**

### (c) Silent acceptance of invalid modules (nonsense programs)

| rank | module | size | what is accepted | observed |
| --- | --- | --- | --- | --- |
| 1 | `M03_mem_huge_initial` | 17 B | memory `initial = 0xFFFFFFFF` pages; no `initial <= max` check | `.memory0 size=2147483648` (2 GiB); analysis timeout (A1) |
| 2 | `M04_table_huge_initial` | 18 B | table `initial = 0xFFFFFFFF` elements | `IllegalStateException: ... exceed the maximum program size of 16 GBytes` at `WasmLoader.createTableBlock:301`; **caught**, import_ok **with no table** |
| 3 | `S04_size_2p28` | 18 B | declared section size `2^28` (body parsed anyway) | import_ok, type section decoded |
| 4 | `S02_size_declared_larger` | 14 B | declared size 30 for a 5-byte payload | import_ok |
| 5 | `B03_locals_ffffffff` | 30 B | locals count `0xFFFFFFFF` (→ `int -1`) | import_ok; `new ValType[-1]` → `NegativeArraySizeException`, caught per analyzer; funcs=1, nonsense body |
| 6 | `C09_count_func_code_mismatch` | 26 B | function section declares 3 funcs, code supplies 1 | import_ok **funcs=1**, no error; declared functions silently dropped |
| 7 | `M05_data_offset_oor` | 30 B | active data segment at offset `0x7FFFFFF0` in a 1-page memory | `MemoryAccessException` caught; segment silently skipped |
| 8 | `M06_data_overlap` | 35 B | two overlapping active data segments | import_ok; both applied (second wins) |
| 9 | `O01..O08` (out-of-range indices) | 20-37 B | type/function/table/memory/global/element/tag indices past the declared counts | exceptions caught per analyzer (`IndexOutOfBoundsException ...`); partial/nonsense program |
| 10 | `D01..D05` (duplicates/order/unknown) | 13-30 B | two type sections, two code sections, unknown id 42, reversed order | import_ok; unknown skipped, duplicates overwritten |
| 11 | `L01`, `L02`, `S03` | 14-19 B | overlong / lying section-size LEBs | import_ok; `createData` "markup conflict" warnings from the desync |
| 12 | `M01`, `M02` | 14-18 B | memory `initial=5, maximum=1`; `maximum = 2^32` | import_ok |
| 13 | `X02_expr_overflow_value` | 25 B | 10-byte overflow `i32.const` in a global initializer | import_ok funcs=0, no diagnostic |
| 14 | `O07_tagidx_oor` | 21 B | tag type index `0xFFFF` with 1 type | import_ok funcs=0 |

On ranks 3-4 and 11 (framing): the declared length only mis-positions the *next* section; it never
limits decoding, so a lie is accepted and the outer pointer desyncs (sometimes surfacing later as
`createData` "markup conflict" warnings).

### (d) Clean `import_failed` - 27 modules (see §4.1)

Correct: an invalid module is refused with a bounded amount of work and the process stays up.

## 6. Expected behaviour vs genuine bugs

* **Expected / fine:** rejecting structurally invalid modules (`T*`, count cases in `C*`, `H*`,
  `B01`, `B02`, `X01`, `X03`, `L03`-`L05`, `S01`); rejecting magic/version mismatches in
  `findSupportedLoadSpecs`; a *caught* per-analyzer exception that is logged
  (`Analysis Task: ... NegativeArraySizeException / IndexOutOfBoundsException`) is
  degraded-but-survivable, not a crash.
* **Genuine robustness bugs:**
  1. an unbounded allocation that escapes as `OutOfMemoryError` and kills the process (**B1**);
  2. an unbounded memory block that turns import into a 2 GiB allocation and analysis into a
     de-facto hang (**A1/M03**);
  3. silent acceptance of invalid modules that produce nonsense programs (§5c) - the loader should
     validate counts, indices, limits and section sizes, and either reject the module or skip the
     offending entity *without* feeding absurd sizes to allocations. The allocation-driven members
     (`B03`) share B1's root cause and only differ in the sign of the overflow, which is what keeps
     them survivable.
* **Benign leniency:** `D03` (unknown id), `D04` (section order), `M01`/`M02` (contradictory
  limits) are spec-invalid but harmless for a static-analysis loader that is deliberately not a
  strict validator.

## 7. Permanent probes - `test-scripts/probes_malformed.py`

The worst findings are pinned as five probes (built with `wasm_probe_lib` helpers); each is
byte-identical to its corpus source and matches its documented outcome.

| probe | corpus source | expected result (verified) |
| --- | --- | --- |
| `J01_mem_initial_4G_pages.wasm` | `M03` (byte-identical) | `import_ok_analysis_timeout`: `.memory0 size=2147483648` (2 GiB); analysis timeout |
| `J02_locals_count_overflow.wasm` | `B04` (byte-identical) | **`process_died`**: `OutOfMemoryError` at `WasmCodeEntry.getLocals:71` |
| `J03_locals_count_neg.wasm` | `B03` (byte-identical) | `import_ok`: caught `NegativeArraySizeException`; nonsense function (funcs=1) |
| `J04_table_initial_4G_elems.wasm` | `M04` (byte-identical) | `import_ok`, 16 GiB guard throws (caught), no table |
| `J05_functype_param_overflow.wasm` | caught parse guard | `import_failed`: `NegativeArraySizeException` at `WasmFuncType.<init>:41` |

**Runner caveat:** `J02` aborts the headless JVM, so these probes must be run **one per process**
(`robustness-sweep.ps1`); do not let a shared `run_probes.ps1` batch pick them up, or one probe
takes the whole batch down. This is stated in the probe file's docstring.

## 8. Suggested fixes (for the integrator; no source changed here)

1. **Bound allocation sizes** before allocating (root of B1/A1/C1):
   * `WasmLocalEntry.getCount()` (`WasmLocalEntry.java:38-40`): keep the count as `long` (or validate
     `<=` a sane ceiling, e.g. 1e6) instead of an unchecked `int` cast; in
     `WasmCodeEntry.getLocals()` (`WasmCodeEntry.java:66-78`) reject the module if the summed locals
     exceed a cap, and guard `new ValType[count]` against negative/oversized values.
   * `WasmFuncType` (`WasmFuncType.java:41,47`), `WasmGCType.parseSubType` (`WasmGCType.java:265`),
     `WasmElementSegment.getInitData` (`WasmElementSegment.java:165-168`): the same check before
     `new ValType[(int) pcount]` / `new long[(int) n]` / `new byte[count*elemSize]`.
2. **Validate memory/table limits** in `WasmLoader.loadMemories` / `createTableBlock`
   (`WasmLoader.java:294-320,523-548`): require `initial <= maximum`, require a sane page ceiling,
   and refuse (or clamp with a warning) rather than materialising a multi-GiB `.memory0`. Fixes A1.
3. **Do not let a hostile module abort the run**: `WasmLoader.load` (`WasmLoader.java:702-712`) and
   the `WasmAnalysis.getState` entry point should not let an `OutOfMemoryError`/`StackOverflowError`
   from attacker-sized allocation tear down the process (bound the allocation first - item 1 - and/or
   fail the import with a reported message).
4. **Validate indices and counts at load time**: compare the function-section and code-section
   counts; bounds-check type/function/table/memory/global/element/tag indices; reject duplicate
   non-custom sections instead of overwriting them (`WasmModule.java:69-74`).
5. **Enforce the declared section size** when decoding a section body - bound the `sectionReader` to
   `[sectionOffset + header, sectionOffset + header + contentLength]` - and reject unknown non-custom
   section ids rather than returning `null` (`WasmSection.java:50-59,56`).

## 9. Reproduce

```
# full corpus with the analyzers enabled (regenerates robustness-RESULTS.md) - the primary run
cd D:\code\ghidra-wt-j
.\test-scripts\robustness-sweep.ps1 -CorpusMode all -Analyze -WallSeconds 180

# fast baseline: curated 26-module core subset, import-only
.\test-scripts\robustness-sweep.ps1 -CorpusMode core -WallSeconds 60

# the five permanent probes, one process per file
python .\test-scripts\probes_malformed.py $env:TEMP\j-probes
.\test-scripts\robustness-sweep.ps1 -SkipGenerate -CorpusDir $env:TEMP\j-probes -WallSeconds 60
```

Per-module logs from the primary run are under
`%TEMP%\wasm-robustness\<timestamp>-<pid>\logs\` (stdout+stderr per module), with a `results.csv`
next to them.

## 10. Note on concurrent work

The `test/robustness` branch advanced during this task: the integrator committed an earlier WIP
(`610c4c3`), an import-only harness revision (`50b82dc`), the M05/M06 generator fix and the J01-J05
probe set (`3535a24`, `77757b0`), and a report (`0505022`). This report reconciles the two: the
**primary artifact is the full 56-module analysis-ON run** (the table in `robustness-RESULTS.md`),
with the fast 26-module import-only `core` subset documented as the quick baseline. All findings
above are unchanged between the two modes except that `B03`/`C09`/`O*` analyzer exceptions and the
`M03` timeout are visible only with analysis ON.
