# REPORT-G — spec-test harness + correctness baseline

Scope: build a reproducible harness that runs the official WebAssembly spec testsuite against the
plugin in this worktree, and record a correctness baseline. **No plugin source (`src/**`, `data/**`)
was modified.** Branch `feat/spec-test-harness`, base `1e2328b`.

## 1. What I built

New, all under `test-scripts/spectest/` (plus the modernised emulation driver):

| file | role |
| --- | --- |
| `test-scripts/spectest/fetch_spectest_tools.ps1` | download + checksum + extract the pinned wabt and testsuite into `$env:TEMP\spectest-tools` (never into the repo) |
| `test-scripts/spectest/prepare_spec_tests.py` | run `wast2json` per `.wast`; copy only the **valid** modules into a flat import dir; emit `modules.json` |
| `test-scripts/spectest/SpecModuleReport.java` | headless post-script: one `SPECMODULE` line per program (funcs / instrs / undefined bytes / decompile pass-fail) plus `SPECFUNC` lines for functions with a decode gap or decompile failure |
| `test-scripts/spectest/SpecDisasm.java` | `-Detail`: instruction listing + decompiled C per program |
| `test-scripts/spectest/parse_spec_results.py` | parse the headless log into `summary.json` / `summary.md` (totals, per-suite coverage, ranked failures, crash classification) |
| `test-scripts/spectest/run_spectest.ps1` | orchestrate fetch → prepare → `analyzeHeadless` → parse |
| `test-scripts/spectest/README.md` | usage |
| `test-scripts/spectest-BASELINE.md` | the pass/fail table + ranked failure classes |
| `ghidra_scripts/spectest.py` | modernised emulation driver (see §6) |

Pipeline: `wast2json` → valid `*.wasm` in one directory → `analyzeHeadless -import <dir> -recursive
-postScript SpecModuleReport.java -max-cpu 2 -deleteProject` → parse log → `summary.md`.

## 2. Exact reproduction

Toolchain (host, pinned; fetched by `fetch_spectest_tools.ps1` into `$env:TEMP\spectest-tools`):

* **wabt 1.0.42** — `https://github.com/WebAssembly/wabt/releases/download/1.0.42/wabt-1.0.42-windows-x64.tar.gz`
  sha256 `62f1eb2b51aa57cf0f0b8ba333bf2c72a049930aa9c5de01dcad271c4fe48c88` (immutable release asset;
  the script hard-fails on mismatch). Provides `wast2json`, `wasm2wat`, `wasm-objdump`.
* **spec testsuite** `d76759e746f3564a03f6106ae19679742f2a1831` —
  `https://github.com/WebAssembly/spec/archive/d76759e746f3564a03f6106ae19679742f2a1831.tar.gz`
  sha256 `2f119457c429604619a422f0329afac2a90c7fa17361c5842f662dda184ec37b` (recorded; GitHub
  regenerates archives so the script only warns on mismatch). This commit is the one wabt 1.0.42
  pins in its `third_party/testsuite` submodule, i.e. the testsuite that release is known to parse.
  147 `.wast` files, all of which `wast2json --no-check` parses.

Environment: Ghidra 12.1.4 (`$env:TEMP\opencode\ghidra-g`), PowerShell 7, host Python 3.14,
Gradle 9.2.1, Java 21/25.

```powershell
# 1. tools
.\test-scripts\spectest\fetch_spectest_tools.ps1
# 2. build + install the plugin
.\test-scripts\build-install.ps1 -GhidraDir "$env:TEMP\opencode\ghidra-g"
# 3. measure the core subset (~3.5 min, 271 modules)
$env:GHIDRA_INSTALL_DIR="$env:TEMP\opencode\ghidra-g"
.\test-scripts\spectest\run_spectest.ps1 -Subset core -MaxPerWast 10 -OutDir "$env:TEMP\spectest-core"
```

Raw command the runner issues (for reference):

```
analyzeHeadless <projdir> SpecRun -import <out>\import -recursive \
  -scriptPath D:\code\ghidra-wt-g\test-scripts\spectest -postScript SpecModuleReport.java \
  -max-cpu 2 -deleteProject
```

## 3. Results

Full details and the ranked failure list are in **`test-scripts/spectest-BASELINE.md`**. Two runs
(both ~4 min, `-max-cpu 2`):

| | core (`-Subset core -MaxPerWast 10`, 73 files) | all (`-Subset all -MaxPerWast 3`, 147 files) |
| --- | ---: | ---: |
| modules imported | **271 / 271 (100%)** | **257 / 257 (100%)** |
| PASS / PARTIAL / FAIL | 264 / 6 / 1 | 249 / 7 / 1 |
| functions / instructions | 2747 / 33192 | 3750 / 48005 |
| undefined bytes (ext-stub + real gap) | 458 (428 + **30**) | 210 (176 + **34**) |
| decompiled / failed | 2746 / **1** | 3749 / **1** |

* SIMD across the all-run: 99 modules, 1222 functions, 9012 instructions — **0 undefined bytes, 0
  decompile failures**.
* The loader accepted **528/528** valid modules with **0 rejections**.

Ranked failure classes (details/examples in the baseline doc):

1. **`select` (0x1B) not decoded after an unconditional terminator** — 30 / 34 bytes, 24 / 28 funcs,
   in `br`, `br_table`, `call_indirect`, `return`, `select`, `unreachable`, `unreached-valid`,
   `unwind`. The core testsuite has dedicated functions for exactly this
   (`unwind.wast`: `select-after-unreachable` @ `ram:80000785`, `select-after-br` @ `ram:8000079a`,
   `select-after-br_table` @ `ram:800007c9`, `select-after-return` @ `ram:800007e7`) and all four
   leave the `select` byte undefined. Root cause: the `ctx_operand_size`-conditioned `select`
   constructors in `WebAssembly.sinc:415/418/421` have no context on an unreachable path; `select`
   after the conditional `br_if` decodes fine, which isolates the trigger to unconditional terminators.
2. **Decompiler process death** on `br_table.0.wasm:large` @ `ram:800006af` (16172-byte body) —
   a single function, but a hard crash of the native decompiler.
3. **`WasmStackVariableAnalyzer` failures** — `Index 0 out of bounds for length 0` on `i64.store` /
   `i64.store16` / `f32.load` / `i64.load8_s`; `GenericAddress cannot be cast to Register` on `local.set`.
4. **Import stubs modelled as functions** with 4 undefined bytes each (107 funcs / 428 bytes in core)
   and `Unable to disassemble EXTERNAL block location` noise.
5. **Emulation driver blocked** — see §6; no `assert_return` can run yet.

## 4. Coverage limits

* Valid modules only; `assert_invalid` / `assert_malformed` (loader *should* reject) are excluded and
  are a follow-up (the harness already emits their binaries from `wast2json`).
* The core subset cuts at 10 modules per `.wast`. `-Subset all` / `-Subset simd` cover all 147 files
  (including SIMD); proposal directories (`proposals/gc`, `proposals/exception-handling`,
  `proposals/threads`, …) are **not** wired in yet — that is where GC/EH/atomics coverage should come
  from next.
* `-MaxPerWast` trades runtime for coverage; the whole 147-file suite with `-MaxPerWast 3` is ~250
  modules (≈4 min on this box, 2 CPUs).

## 5. CI feasibility

Feasible, and the repo is already most of the way there:

* `.github/workflows/build.yml` already provisions Java 21, Gradle 9.2.1 and Ghidra 12.1.4/12.1.3 via
  `antoniovazquezblanco/setup-ghidra@v2` on `ubuntu-latest`. The harness can run right after
  `gradle buildExtension` + install-into-Ghidra.
* **wabt can be fetched on a GitHub runner**: switch the platform in `fetch_spectest_tools.ps1` to
  `wabt-1.0.42-linux-x64.tar.gz` (same release, same immutability), or `apt-get install wabt` /
  `npm i -g wabt`. The testsuite tarball is a plain GitHub archive. Both are reachable from
  GitHub-hosted runners.
* **Decode/decompile harness (the primary artifact) needs only Ghidra's Java headless** plus a host
  Python 3 for `prepare_spec_tests.py` / `parse_spec_results.py` (both stdlib-only; 3.12/3.13/3.14
  fine). No PyGhidra required. This is the recommended CI job.
* **Runtime**: ~3.5 min for 271 modules with `-max-cpu 2`; the import phase is the cost. A CI run
  should pin `-Subset core` (or smaller) and compare `summary.json` against a stored baseline.
* **Emulation driver (`spectest.py`) in CI is not ready**: it needs PyGhidra and a Python 3.10–3.13
  (PyGhidra 3.1.0 ships jpype wheels for cp39–cp313; **3.14 has no wheel** — I used a 3.13 venv),
  and it is currently blocked by the emulator defect (§6).
* Determinism caveat: `.sla` (re)compilation and analyzer warnings vary slightly between runs; compare
  the parsed metrics, not the raw log.

## 6. `ghidra_scripts/spectest.py` (emulation driver)

Ghidra 12 removed Jython, so the upstream script could not run: `.py` scripts now run under PyGhidra
(CPython 3 + JPype). I modernised it (kept upstream behaviour, mechanical changes only):

* headless invocation: reads the `.json` path from script args (falls back to `askFile`), plus
  `--max-commands=N`, `--report=<path>`, `--decode-only`; writes a machine-readable `RESULT` line per
  command.
* PyGhidra compatibility: `EmulatedProgram` no longer **subclasses** the Java `FlatProgramAPI`
  (JPype: "Java classes cannot be extended in Python") — it now *composes* it and delegates.
* `simulateCall` gets an explicit `java.math.BigInteger[]` (JPype cannot pick between the `long[]`
  and `BigInteger[]` overloads from a Python list).
* uses the module-level `monitor` (no `self.monitor`), Python-3 `unicode` fallback, `esc()` for names.
* always prints per-module decode metrics (`MODULE-METRICS …`) so an emulation run doubles as a
  decode report.

Launch (verified to load modules and resolve exports):

```powershell
$env:GHIDRA_INSTALL_DIR="$env:TEMP\opencode\ghidra-g"
& "$env:TEMP\spectest-tools\pyghidra-venv\Scripts\python.exe" -m pyghidra `
  --install-dir $env:GHIDRA_INSTALL_DIR --project-path <tmp> --project-name spectest --skip-analysis `
  ghidra_scripts/spectest.py <out>\json\nop.json --max-commands=30 --report <tmp>\report.txt
```

**Blocked**: every `invoke` aborts at the first executed instruction with
`Emulation stopped: funcEntryCallOther requires two inputs` (`WasmEmulateInstructionStateModifier`
`FuncEntryOpBehaviour` expects 3 pcode inputs for `funcEntryCallOther(&i0,&l0)`, `WebAssembly.sinc:238`;
the emulator observed 1 operand). Until that is resolved, no spec `assert_return`/`assert_trap` can be
evaluated, so this baseline measures loading/disassembly/decompilation only.

## 7. Open questions

1. Is the `funcEntryCallOther` arity mismatch in the SLEIGH `.locals` directive, in
   `PcodeInjectLibraryWasm`, or the result of a stale `WebAssembly.sla`? (Repro: run `spectest.py`
   on `nop.json`; it fails on the first `invoke`.)
2. Should imported functions create body-less functions with 4 undefined bytes at `ram:7f000000`, or
   be excluded from listings/decompilation (and from `undefined_bytes`)?
3. Is `select`-in-unreachable worth fixing by giving the `select` constructors an unconditional
   fallback (`ctx_operand_size` default), or by decoding unreachable bytes with a permissive pass?
4. Do the 6 `assert_invalid`/`assert_malformed` rejections behave as `wast2json` expects? (separate pass)
5. Does the `br_table:large` decompiler death reproduce on other large functions, and is it a Ghidra
   core limit (function size) or plugin-generated pcode?
