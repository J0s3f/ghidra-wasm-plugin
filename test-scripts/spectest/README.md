# Spec-test harness (`test-scripts/spectest/`)

Runs a subset of the official WebAssembly spec testsuite through this plugin's loader / analyzers /
decompiler, headlessly, and reports per-module decode + decompile metrics.

This is a *measurement* harness: it does not modify plugin sources.

## 1. Fetch the pinned toolchain

```powershell
.\test-scripts\spectest\fetch_spectest_tools.ps1        # -> $env:TEMP\spectest-tools
```

* wabt `1.0.42` (windows-x64 release asset) — `wast2json`, `wasm2wat`, `wasm-objdump`
* WebAssembly spec testsuite `d76759e746f3564a03f6106ae19679742f2a1831`
  (the commit pinned by wabt 1.0.42's `third_party/testsuite` submodule)

Exact URLs and checksums are in the script and in `REPORT-G.md`.

## 2. Run

```powershell
$env:GHIDRA_INSTALL_DIR = "<ghidra install>"
.\test-scripts\spectest\run_spectest.ps1 -Subset core -MaxPerWast 10 -OutDir "$env:TEMP\spectest-core"
```

Pipeline:

1. `prepare_spec_tests.py` runs `wast2json` on each selected `.wast`, then copies only the **valid**
   modules (the ones a `"module"` command points at) into `<OutDir>\import\` as `<wast>.<n>.wasm`.
2. `analyzeHeadless` imports that directory (`-import <dir> -recursive`) and runs
   `SpecModuleReport.java` once per program.
3. `parse_spec_results.py` turns the headless log into `<OutDir>\summary.json` / `summary.md`.

Options:

| flag | meaning |
| --- | --- |
| `-Subset smoke\|numeric\|control\|memory\|table\|core` | predefined `.wast` selections |
| `-Files a,b,c` | explicit `.wast` basenames (overrides `-Subset`) |
| `-MaxPerWast N` | take at most N valid modules per `.wast` (bounds runtime; 0 = unlimited) |
| `-Detail` | also run `SpecDisasm.java` (full listing + decompiled C) — only for small selections |
| `-NoPrepare` | reuse a previous `<OutDir>` import set |

## 3. Outputs

`summary.json` carries totals, per-`.wast` coverage, crash/warning classes and concrete
module/fuction examples. `summary.md` is the human-readable version. Per-function rows appear as
`SPECFUNC` lines only when a function has undefined bytes or fails to decompile.

## 4. Known environment notes

* A headless run accepts **one** `-scriptPath` only; use the harness' own `SpecDisasm.java` instead of
  combining directories.
* `analyzeHeadless` can run Java scripts directly. Python scripts (`ghidra_scripts/spectest.py`) need
  the PyGhidra launcher (Ghidra 12 removed Jython).

## 5. Negative tests (rejection behaviour)

The sibling harness for the modules a correct implementation must **reject**
(`assert_invalid` / `assert_malformed` / `assert_unlinkable`). Measurement only; the existing
positive scripts are unchanged.

```powershell
# bounded smoke run
.\test-scripts\spectest\run_spectest_negative.ps1 -Kinds malformed -MaxPerWastPerKind 1 `
    -OutDir "$env:TEMP\specneg-smoke"
# the whole binary negative set (invalid + malformed + unlinkable, ~2.9k modules)
.\test-scripts\spectest\run_spectest_negative.ps1 -OutDir "$env:TEMP\specneg-all"
```

| file | role |
| --- | --- |
| `prepare_spec_negative.py` | collects the negative commands' modules into `<OutDir>\import` as `<wast>.<n>.<invalid|malformed|unlinkable>.wasm` (+ `modules.json`); `module_type: text` commands are skipped unless `--include-text` |
| `SpecNegativeReport.java` | one `SPECNEG` line per program the loader **accepted** (funcs / blocks / .module block / data), so a silent acceptance is measurable; never decompiles |
| `run_spectest_negative.ps1` | chunked `analyzeHeadless` import with a hard timeout; a chunk whose run wedges/dies is split and retried, so one bad module cannot hide the rest |
| `parse_spec_negative.py` | classifies every module as `rejected` / `accepted` (empty / partial / shape) / `crash` / `hang` and writes `negative.json` / `negative.md` |
| `select_negative_subset.py` | builds a filtered import dir + manifest from a previous `negative.json` (used for the analysis evidence pass) |

Options: `-Kinds`, `-MaxPerWastPerKind`, `-ChunkSize`, `-TimeoutSec`, `-WithAnalysis` (evidence pass:
adds `instrs`/`undefined_bytes` and lets the analysers see the accepted modules), `-SkipPrepare`,
`-ImportDir` + `-ModulesJson`.

Findings and the reduced probes: `test-scripts/spectest-NEGATIVE.md`, `REPORT-NS.md`,
`test-scripts/probes_negative.py`.

### Negative harness environment notes

* `analyzeHeadless.bat` ends with `pause`; the runner redirects `< nul` so a headless **abort**
  (e.g. `OutOfMemoryError` while analysing a nonsense program) exits with a non-zero code instead of
  wedging the batch forever.
* Without `-noanalysis` the loader-created functions have no instructions, so `-noanalysis` is the
  default for the bulk classification run; `-WithAnalysis` is for the (bounded) evidence pass.

