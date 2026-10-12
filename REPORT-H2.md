# REPORT-H2 — positive spec-suite CI gate + Linux-clean harness

Scope: wire the **positive** WebAssembly spec-suite run into GitHub Actions as a decode/decompile
regression gate, record a real baseline, and make the harness Linux-clean.

* Worktree: `D:\code\ghidra-wt-h2` (branch `ci/spec-suite-gate`, base `main` @ `c3a7bc2`)
* Ghidra install (pinned by `test-scripts/.ghidra-install`): `C:\Users\micro\AppData\Local\Temp\opencode\ghidra-h2` (12.1.4 PUBLIC)
* **No plugin source (`src/**`, `data/**`) or probe-baseline file was touched.**

---

## 1. What I added / changed

| file | change |
| --- | --- |
| `test-scripts/spectest-expected.json` | **new.** Recorded metrics for the `core` subset (enforced) and `simd` subset (recorded reference). Generated from real local runs via `--update` — never hand-written. |
| `test-scripts/check-spectest.py` | **new.** stdlib-only gate: reads the harness `summary.json` (or `summary.md`, or the run dir) + the expectation file; exits `1` with a readable diff on a metric regression, `2` on a setup problem (missing expectation file / subset / non-integer value); `--update` regenerates one subset. |
| `.github/workflows/spectest.yml` | **new.** Separate workflow: Java 21 + Gradle 9.2.1 + Ghidra 12.1.4 (exactly like `build.yml`), `gradle buildExtension`, install the extension like `probes.yml`, fetch the pinned wabt + testsuite, run `-Subset core`, run `check-spectest.py`, upload summary + logs (`if: always()`). |
| `test-scripts/spectest/fetch_spectest_tools.ps1` | host-aware **wabt asset selection** (`linux-x64` vs `windows-x64`, with the linux sha256), `wast2json` vs `wast2json.exe`, `curl` vs `curl.exe`, `[IO.Path]::GetTempPath()` default dir. |
| `test-scripts/spectest/run_spectest.ps1` | host-aware **python launcher** (`python3` on Linux), `wast2json[.exe]` name, forward-slash `wabt-1.0.42/bin/...` path, `GetTempPath()` defaults. Headless launcher selection was already host-aware (kept). |
| `test-scripts/spectest/run_spectest_negative.ps1` | same minimal host-awareness (python + wabt exe name + forward-slash path). Its chunk runner still uses `cmd.exe`/`taskkill` — see §5. |
| `REPORT-H2.md` | this report. |

`prepare_spec_tests.py` and `parse_spec_results.py` needed **no changes** — both are stdlib-only, use
`os.path`, and contain no Windows-isms (verified by inspection; they ran unmodified on Windows and
are what the worktree already used on Linux reasoning in REPORT-G §5).

### Metric mapping (`summary.json` → expectation)

| expectation key | source in `summary.json` |
| --- | --- |
| `files` | `len(summary.per_wast)` (distinct `.wast` files) |
| `imported` / `not_imported` | `totals.modules_imported` / `totals.modules_not_imported` |
| `instructions` | `totals.instructions` |
| `undefined_bytes` | `totals.undefined_bytes` (import-stub bytes **+** real decode gaps) |
| `real_undefined_bytes` | `totals.decode_gap_bytes` (import stubs removed — the metric that must stay 0) |
| `decompiled` / `decompile_failed` | `totals.decompiled` / `totals.decompile_failed` |
| `modules_selected`, `functions`, `external_stub_bytes` | extra, recorded for a clearer diff |

Timing fields are never recorded, so a slow/fast runner cannot fail the gate.

---

## 2. Local evidence (Windows, exact output)

### 2.1 Build + install

```
> D:\code\ghidra-wt-h2\test-scripts\build-install.ps1
== using the pinned Ghidra install: C:\Users\micro\AppData\Local\Temp\opencode\ghidra-h2 ==
== building (GHIDRA_INSTALL_DIR=...) ==
...
BUILD SUCCESSFUL in 27s
== installing ghidra_12.1.4_PUBLIC_20261012_ghidra-wt-h2.zip into ...\ghidra-h2\Ghidra\Extensions ==
```

### 2.2 Harness run (core subset, the CI parameters)

```
> .\test-scripts\spectest\run_spectest.ps1 -Subset core -MaxPerWast 10 -OutDir <tmp>\spectest-h2-core -GhidraDir <ghidra-h2>
== preparing spec modules ==
selected wast files : 73
valid modules       : 271
wast2json failures  : 0
== importing 271 module(s) ==
== summarising ==
modules: 271 selected, 271 imported, 0 not imported
functions: 2747, instructions: 33222, undefined_bytes: 428, decompiled: 2747, decompile_failed: 0
log failure patterns: 0
EXIT=0
```

> **Note vs the `REPORT-G`/`spectest-BASELINE.md` numbers.** The old baseline measured 458
> undefined bytes (428 stub + **30 real `select`-in-unreachable** gap) and **1** decompile failure
> (`br_table` large function). On the current `main` @ `c3a7bc2` the tree is **clean**:
> `decode_gap_bytes = 0`, `decompile_failed = 0`, `undefined_bytes = 428` (= exactly the import-stub
> bytes). So this gate locks in the *already-fixed* state: the real gap and the decompiler death are
> the two regressions it will now catch if they come back. The expectation file therefore records
> `real_undefined_bytes: 0` and `decompile_failed: 0`.

### 2.3 `check-spectest.py` → PASS

```
> python test-scripts/check-spectest.py --summary <tmp>\spectest-h2-core\summary.json --subset core
subset: core  (<tmp>\spectest-h2-core\summary.json)
  metric                   expected        run
  decompile_failed                0          0
  decompiled                   2747       2747
  external_stub_bytes           428        428
  files                          73         73
  functions                    2747       2747
  imported                      271        271
  instructions                33222      33222
  modules_selected              271        271
  not_imported                    0          0
  real_undefined_bytes            0          0
  undefined_bytes               428        428

OK: subset 'core' matches spectest-expected.json.
EXIT=0
```

### 2.4 Perturb one expected metric → FAIL (exit 1)

`decompiled` changed 2747 → 2746 in `spectest-expected.json`:

```
  metric                   expected        run
  decompile_failed                0          0
  decompiled                   2746       2747  <-- differs
  ...
FAIL: DIFF decompiled: expected 2746, got 2747 (delta +1)

1 problem(s) - the positive spec-suite baseline does not match the run.
If the change is intended, regenerate with:
  python3 test-scripts/check-spectest.py --summary <tmp>\spectest-h2-core\summary.json --subset core --update
EXIT=1
```

### 2.5 Restore → PASS again

`check-spectest.py --update` regenerated the `core` subset from the run (leaving `simd` intact);
re-verification returned `EXIT=0` with the identical table as §2.3.

### 2.6 Other failure paths (all verified)

| command | result |
| --- | --- |
| `--expected <missing file>` | `error: expectation file not found: ...` → **exit 2** |
| expectation records a metric the run does not emit (`ghost_metric`) | `FAIL: METRIC MISSING: 'ghost_metric' ...` → **exit 1** |
| `--subset simd` while the file only had `core` | `error: subset 'simd' is not recorded ...` → **exit 2** |
| `--summary <run dir>` and `--summary <summary.md>` | both parsed back to the same numbers → **exit 0** |

### 2.7 SIMD subset (recorded reference, "if cheap")

```
> .\test-scripts\spectest\run_spectest.ps1 -Subset simd -MaxPerWast 10 ...
selected wast files : 57
modules: 128 selected, 128 imported, 0 not imported
functions: 1271, instructions: 9318, undefined_bytes: 0, decompiled: 1271, decompile_failed: 0
ELAPSED_MIN=1.4
```

Clean SIMD run (0 undefined bytes, 0 decompile failures) → recorded as the `simd` subset. The CI
workflow enforces `core` only; `simd` is documented in the file's `comment` and checked locally via
`--subset simd`.

### 2.8 No false positives — the existing gate stays green

```
> .\test-scripts\check-local.ps1 -SkipBuild -OutDir <unique tmp dir> -GhidraDir <ghidra-h2>
probes: 131 imported, 5 import failure(s); baseline has 136
OK: every probe matches the recorded baseline.
EXIT=0  ELAPSED_MIN=6.4
```

The 136-probe gate (131 imported + 5 expected import failures) and the fixture `SUMMARY
functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0` both still pass. The real-module
regression (`SUMMARY functions=437 decompiled=437 failed=0 instructions=61658`) is **not re-verified
locally** — the payload (`rasterbator_rs_bg.wasm`) is deliberately not committed; nothing I changed
touches it (see §5).

---

## 3. Linux-cleanliness

By construction, the workflow is Linux-clean because every script it invokes now selects host-idiomatic
names; no shim (unlike `probes.yml`'s `analyzeHeadless.bat` symlink + `python` symlink) is needed.

* `fetch_spectest_tools.ps1`: `Windows → windows-x64.tar.gz` (`bin\wast2json.exe`, sha
  `62f1eb2b…`), `Linux → linux-x64.tar.gz` (`bin/wast2json`, sha
  `84895407a6bbb80e918f33b16b2fb2206021c150b6bc9ff6f761263a745ab131`, downloaded and hashed locally).
  `curl` vs `curl.exe`; `tar -xzf` works on both; extraction root `wabt-1.0.42/` is identical.
* `run_spectest.ps1`: `python3` off Windows / `python` on Windows; `wabt-1.0.42/bin/wast2json[.exe]`
  (forward slashes — a separator on Windows too); `analyzeHeadless` (not `.bat`) on Linux; temp
  defaults via `[IO.Path]::GetTempPath()` (`/tmp` on Linux) instead of `$env:TEMP`.
* `run_spectest_negative.ps1`: python + wabt exe name + forward-slash path (minimal fix).
* Python scripts: already host-agnostic (stdlib + `os.path`).

Sanity checks run locally: `& fetch_spectest_tools.ps1` on Windows still resolves the existing
extraction and prints the same JSON contract; all three `.ps1` files parse with zero PowerShell
parser errors.

---

## 4. What the integrator must verify after pushing (I cannot run Actions here)

1. `.github/workflows/spectest.yml` triggers on push/PR and the `spectest` job goes green on
   `ubuntu-latest`.
2. The `Fetch pinned wabt + spec testsuite` step downloads the **linux-x64** asset and prints
   `sha256 ok: 84895407…`.
3. The harness step reaches `modules: 271 selected, 271 imported, 0 not imported` /
   `functions: 2747, instructions: 33222, undefined_bytes: 428, decompiled: 2747, decompile_failed: 0`
   — i.e. the Linux run reproduces the Windows metrics exactly. **This is the main unverified
   assumption** (cross-OS determinism of decode/decompile counts). If Linux differs, regenerate the
   baseline from a Linux `summary.json` with `--update` rather than loosening the check.
4. `check-spectest.py` prints `OK: subset 'core' matches spectest-expected.json.` and the job exits 0.
5. The `spectest-core` artifact contains `summary.json`, `summary.md`, `headless.log`, `modules.json`.
6. Deliberately break one metric (or re-introduce a `select`-in-unreachable regression) and confirm
   the job fails with a `DIFF …` line — validates the gate end-to-end in CI.
7. The existing `Build` and `Probes` workflows remain green (my changes do not touch their inputs).

YAML was validated locally with PyYAML 6.0.3 (`yaml.safe_load`) and every path referenced by the
workflow exists. Action refs (`checkout@v7`, `setup-java@v6`, `setup-gradle@v6`, `setup-ghidra@v2`,
`upload-artifact@v7`) are byte-identical to `build.yml`/`probes.yml`.

---

## 5. Open questions / limitations

1. **Cross-OS determinism** is assumed, not proven (§4.3). Ghidra `.sla` compilation and analyzer
   ordering can vary slightly; if the counts differ on Linux the baseline must be regenerated there.
2. **Negative harness on Linux** is not made host-agnostic: `run_spectest_negative.ps1`'s chunk runner
   shells out to `cmd.exe`/`taskkill` and writes a `.cmd` wrapper. That is a non-trivial rewrite of a
   script outside the CI gate, so only the cheap fixes (python/wabt names) were applied and the
   Windows-only path is documented inline. The positive workflow does not use it.
3. **`simd` is recorded but not enforced by CI** (the workflow runs `core` to keep runtime ~4-6 min).
   It is available via `--subset simd`; if it should be enforced, add a second job or extend the core
   job (and pin the same `-MaxPerWast`).
4. **`probes.yml` still carries two Linux shims** (`python` symlink, `analyzeHeadless.bat` symlink)
   for `run_probes.ps1`. Those could be dropped with the same host-selection idiom now used here, but
   `run_probes.ps1` is not mine to edit.
5. **Real-module regression** (`SUMMARY functions=437 …`) was not re-run locally because the payload
   is not committed; it is unaffected by this work (no plugin, probe or baseline file changed).
6. The expectation file does not encode its generator parameters; the exact invocations
   (`-Subset core -MaxPerWast 10`, `-Subset simd -MaxPerWast 10`) are recorded in the file's
   `comment` and here. A future multi-parameter matrix would need them stored per subset.
