# REPORT-I — CI enforcement for the WebAssembly probe suite

Worktree: `D:\code\ghidra-wt-i`, branch `ci/probe-suite`, base `1e2328b`.
Everything below was produced on this worktree with the private Ghidra 12.1.4 install at
`C:\Users\micro\AppData\Local\Temp\ghidra-i`; nothing was pushed and no Actions run was
executed (see “What CI cannot verify” at the end).

## 1. What was added

| File | Purpose |
| --- | --- |
| `.github/workflows/probes.yml` | New workflow: build the extension for Ghidra 12.1.4, install it, run the probe suite headlessly with `run_probes.ps1`, dump the committed fixture with `DumpDecomp.java`, then run `check-results.py`. Logs are uploaded as the `probe-run-log` artifact. |
| `test-scripts/expected-results.json` | Machine-readable baseline: one entry per probe (`funcs`, `instrs`, `undefined_bytes`, `decompiled`, `decompile_failed`, `import_ok`), plus `real_module` and `fixture` `SUMMARY` records. **Generated from an actual run, not hand-written** (`check-results.py --update`). |
| `test-scripts/check-results.py` | Stdlib-only gate. Parses a `probe-run.log` (+ `fixture-run.log`, optional `real-run.log`), diffs it against the JSON and exits non-zero with a readable reason. `--update` regenerates the JSON from fresh logs. |
| `test-scripts/fixtures/make_fixture.py` | Regenerates the committed fixture module (127 bytes). |
| `test-scripts/fixtures/wasm_fixture.wasm` | The committed fixture: 4 ordinary functions (integer add, a `block`/`br_if`, a memory load and store through a mutable global) that decompile to C. |
| `test-scripts/check-local.ps1` | One-command local twin of the workflow (build+install → probes → fixture dump → check). |

Not touched: plugin sources, `gen_feature_probes.py`, `wasm_probe_lib.py`, `run_probes.ps1`, the Java
report scripts, the other probe generators, `MODERN_WASM_GAPS.md`, `build.yml`, `release.yml`,
`build.gradle`. `expected-results.json` was produced *by* a run, so the enforced numbers can differ
from the prose tables in `MODERN_WASM_GAPS.md` §2.4 — that document was deliberately left alone.

## 2. The recorded baseline

* **80 probes** from `gen_feature_probes.py`, `probes_types.py`, `probes_eh.py`, `probes_gc.py`
  (27 + 29 + 10 + 14) — the exact generator list used locally and in CI.
* 79 probes import and report metrics; **1 expected import failure**: `21_component_model.wasm`
  (`No load spec found`, loader gap documented in §2.4) — recorded as `import_ok: false`.
* Fixture: `SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0`.
* Real module (`rasterbator_rs_bg.wasm`, external, **not committed**):
  `functions=437 decompiled=437 failed=0 instructions=61658` (`undefined_bytes=156`). It is recorded
  for reference and only checked when a DumpDecomp log is supplied with `--real-module-log`.

The baseline matches `MODERN_WASM_GAPS.md` §2.4/§2.5 for every probe except three, all of them
*improvements* already documented as landed in that file’s header — i.e. the machine-generated
baseline is the post-GC / post-const-expr picture, which is the point of generating instead of
copying the prose table:

| Probe | §2.4 (before) | recorded run |
| --- | --- | --- |
| `09_gc_struct_new` | `instrs=5 undefined_bytes=1` | `instrs=4 undefined_bytes=0` |
| `19_extended_const_global` | import failed | imports (`funcs=0`) |
| `20_gc_global_init` | import failed | imports (`funcs=0`) |

Probes 22–27 (§2.5) all reproduce §2.5 exactly.

## 3. How to run it locally

```powershell
# everything (build + install + probes + fixture + check) — exit 0 = baseline matches
.\test-scripts\check-local.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\ghidra-i" `
    -OutDir "C:\Users\micro\AppData\Local\Temp\probes-ci-i"

# optional: also verify/record the external real module
.\test-scripts\check-local.ps1 -SkipBuild -RealModule "D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm"

# just the gate, against an existing run
python test-scripts\check-results.py --log <out>\probe-run.log --fixture-log <out>\fixture-run.log --require-fixture

# regenerate the baseline after an intended change (never hand-edit the JSON)
python test-scripts\check-results.py --update --log <out>\probe-run.log --fixture-log <out>\fixture-run.log
```

`check-results.py` fails on: a probe that is missing from the log, changed metrics, an expected
import failure that starts importing, a probe that must import but failed, a duplicated `PROBE`
line, a changed fixture `SUMMARY` (including a `DECOMPILE FAIL` line), and a probe in the log with no
recorded baseline. That last rule means **adding a probe without regenerating the JSON fails CI**
(`--allow-extra` downgrades it to a warning) — deliberate, so a new probe cannot sit untested.

## 4. Local evidence

All commands ran with the worktree as CWD. Order as executed:

1. **Build + install** (`test-scripts\build-install.ps1`) → `BUILD SUCCESSFUL in 33s`, extension
   installed into `...\ghidra-i\Ghidra\Extensions\ghidra-wt-i`.
2. **Probe run** (`run_probes.ps1 -OutDir ...\probes-i -Generators gen_feature_probes.py,probes_types.py,probes_eh.py,probes_gc.py`)
   → `== running 80 probe(s) ==`, 79 `PROBE` lines, 1 `Import failed ... 21_component_model.wasm`.
3. **Baseline generation**: `check-results.py --update` →
   `updated test-scripts\expected-results.json: 79 probe(s) with metrics, 1 expected import failure(s)`.
4. **Full loop** `check-local.ps1` (rebuild + 80 probes + fixture dump + gate), tail:

   ```
   SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0
   probes: 79 imported, 1 import failure(s); baseline has 80
   OK: every probe matches the recorded baseline.
   check-local exit=0
   ```
5. **Real-module baseline** — `analyzeHeadless ... -postScript DumpDecomp.java` on
   `rasterbator_rs_bg.wasm` printed
   `SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156`, and
   `check-results.py --real-module-log real-run.log` → `OK`, exit 0.
6. **Perturbation (fail path)** — `05_memory64.wasm` `instrs` changed `1 → 2` in
   `expected-results.json`, same logs:

   ```
   FAIL: DIFF 05_memory64.wasm: instrs expected 2, got 1
   1 problem(s) - the probe baseline does not match the run.
   exit=1
   ```

   Restored the file from a backup → `OK: every probe matches the recorded baseline.` `exit=0`.
7. **Other fail paths** (each exit 1, driven off copies of the JSON so the committed baseline stayed
   clean): missing probe → `FAIL: MISSING ZZ_never_generated.wasm: expected import + metrics, found
   nothing in the log`; expected import failure that succeeded → `FAIL: IMPORT UNEXPECTEDLY SUCCEEDED
   01_baseline_i32.wasm: expected an import failure, but it imported (funcs=1 instrs=3)`; fixture
   drift → `FAIL: FIXTURE SUMMARY ...: expected 'functions=9 decompiled=9 failed=0 instructions=99',
   got 'SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0'`;
   `--require-fixture` with a missing fixture log → exit 1.
8. `expected-results.json` re-validated as JSON; `probes.yml` parsed with PyYAML
   (`jobs: ['probes']`, 11 steps).

### Why the fixture looks the way it does

The fixture is deliberately plain. I first built one with an extra local and a `loop`; at `1e2328b`
the plugin’s function analyzer rejects both, so the run was `SUMMARY functions=3 decompiled=3 failed=0
instructions=9 undefined_bytes=46` with `IndexOutOfBoundsException: Index: 1` on the loop function and
a `ValidationException: pop from empty stack`. Recording that would bake a *broken* baseline into CI,
so the fixture uses only constructs that analyze cleanly today: parameters, integer arithmetic with a
`call`, a `block`/`br_if`, and a memory load/store through a mutable global. Those are enough for a
decompiler regression (`decompiled`/`instructions`/`undefined_bytes`) to show up while keeping the
numbers stable and meaningful.

## 5. What CI cannot verify from here

* **The Actions run itself.** This worktree was never pushed and `gh workflow` was not used, so
  `probes.yml` has only been validated as YAML and by mirroring its steps locally on Windows. The
  first real `ubuntu-latest` execution is unverified — the integrator must watch that run.
* **Platform independence of the numbers.** I verified all metrics on Windows only. The JSON assumes
  the SLEIGH/loader/decompiler results are identical on Linux + Temurin 21; if any instruction count
  differs, the CI job will fail legitimately and `expected-results.json` must be regenerated from a
  CI-produced log (uploaded as the `probe-run-log` artifact) rather than from a Windows run.
* **`run_probes.ps1`’s Linux path handling.** The script resolves the launcher with
  `Join-Path $GhidraDir "support\analyzeHeadless.bat"`; a backslash is not a path separator on Linux,
  so this would throw before importing anything. I did not edit the frozen script; `probes.yml`
  symlinks the real launcher under the literal name `support\analyzeHeadless.bat`. If the integrator
  prefers, the clean fix is a one-character change to `support/` in `run_probes.ps1`, after which the
  shim step can be deleted.
* **`GHIDRA_INSTALL_DIR` being exported by `setup-ghidra@v2`.** The workflow relies on it (as
  `build.yml`’s Gradle build already does) and fails fast with `setup-ghidra did not export
  GHIDRA_INSTALL_DIR` if it is not.
* **The fixture check is a decompiler check, not a correctness check.** A change that keeps
  `decompiled`/`instructions` constant but silently produces wrong C would not be caught; catching
  that needs snapshotting the C text, which is out of scope here (and would be brittle).

## 6. Assumptions about runner capabilities

* `ubuntu-latest` ships `pwsh`, `python3`, `unzip`, `grep`, `tee`; `run_probes.ps1` shells out to
  `python`, so the workflow symlinks `python → python3` if `python` is absent.
* `actions/checkout@v7`, `actions/setup-java@v6`, `gradle/actions/setup-gradle@v6`,
  `antoniovazquezblanco/setup-ghidra@v2`, `actions/upload-artifact@v7` — the same versions
  `build.yml`/`release.yml` use. No new action version was invented.
* Only Ghidra **12.1.4** is probed (the version the baseline was recorded on); `build.yml` continues
  to cover 12.1.3 for compilation.
* Memory/CPU: `run_probes.ps1` keeps `-max-cpu 2` and `GHIDRA_HEADLESS_MAXMEM=1500M`; the fixture
  step exports the same heap cap. 80 tiny modules import in one directory batch (`-recursive`) so the
  Windows/Linux command-line limit is not an issue.
* The workflow runs on `push` (all branches) and `pull_request`, plus `workflow_dispatch`, matching
  `build.yml`. It was not given a `concurrency` group so it cannot cancel anything else.

## 7. Handover checklist for the integrator

1. Push `ci/probe-suite` (or merge it) and inspect the first **Probes** run.
2. If the probes job fails on metrics that the Windows run recorded differently, download the
   `probe-run-log` artifact and regenerate with
   `python test-scripts/check-results.py --update --log probe-run.log --fixture-log fixture-run.log`,
   then commit that JSON — do not hand-edit it.
3. Confirm the `probe-run-log` artifact is attached for both passing and failing runs, and that the
   Linux shim step (`support\analyzeHeadless.bat`) still matches `run_probes.ps1`.
