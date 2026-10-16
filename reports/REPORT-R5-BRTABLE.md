# REPORT-R5-BRTABLE.md — `br_table` expansion bound dropped the DEFAULT target

Branch: `fix/r5-brtable-default` · Worktree:
`C:\Users\micro\worktrees\ghidra-wt-r5-brtable-ds`
Pinned install: `C:\Users\micro\AppData\Local\Temp\ghidra-r5-brtable-ds`

## 1. Defect

`src/main/java/wasm/analysis/WasmFunctionAnalysis.java`, `case 0x0E: /* br_table */` (the expansion
loop). A `br_table` is encoded as `count` explicit case labels followed by **one** default label, so
the loop runs `count + 1` times and the last iteration (`i == count`) is the default.

The cap was checked as

```java
if (i >= MAX_BR_TABLE_CASES) {      // MAX_BR_TABLE_CASES == 1024
    ... setBrTableCaseIgnored(caseAddress); continue;
}
```

With exactly `MAX_BR_TABLE_CASES` (1024) explicit cases the default sits at `i == 1024`, which is
`>= 1024`, so the default was routed through the byte-only `.case_ignored` directive and **emitted
no branch at all**. The modelled switch then had 1024 cases and no default: an input that matched
no case fell through the ignored label bytes to whatever followed the `br_table`.

The class Javadoc / `MODERN_WASM_GAPS.md` described the bound as "harness-only" / "decode-side
deliberate bound". That is wrong: the pre-analyzer drives the **real** control-flow graph, so
decompilation and emulation are affected for any `br_table` with `>= 1024` explicit cases. The
authoritative review artefact `brcap.wasm` (`D:\code\Ghidra-WASM\build\release-review-sol\`) is
exactly such a table: 1024 cases all targeting the inner block (`return 1`) and a default targeting
the outer block (`return 2`); with input `1024` (out of range) the correct result is **2**.

## 2. Fix

Bound the expansion on **case** targets only and always model the default:

```java
boolean isDefault = (i == count);
if (!isDefault && i >= MAX_BR_TABLE_CASES - 1) {
    if (i == MAX_BR_TABLE_CASES - 1) { Msg.warn(this, "... only the first "
        + (MAX_BR_TABLE_CASES - 1) + " case targets are modelled as branches (the default target"
        + " is always modelled; the remaining labels are decoded without control flow)"); }
    contextreg.setBrTableCaseIgnored(caseAddress);
    continue;
}
contextreg.setBrTableCase(caseAddress, isDefault ? -1 : i);
...
if (!isDefault) { pushValues(caseAddress, actualArgs); }
```

* The bound stays `MAX_BR_TABLE_CASES == 1024` and still emits at most 1024 branch instructions
  (`MAX_BR_TABLE_CASES - 1` cases + the default), so the pathological `br_table large`
  (~16k labels) still cannot explode the decompiler's CFG.
* Tables with `< MAX_BR_TABLE_CASES` labels are byte-identical to before: no case is ignored and
  the default is modelled exactly as it was (the ignore condition `!isDefault && i >= 1023` is
  false for every case when `count <= 1023`).
* The diagnostic about skipped labels is kept (reworded). The `.case_ignored` SLEIGH comment and
  the `MAX_BR_TABLE_CASES` / `setBrTableCaseIgnored` Javadocs were corrected.

**Residual limit (documented):** the dropped labels are the *trailing* cases
(`MAX_BR_TABLE_CASES - 1 <= index <= count - 1`). For an input equal to a dropped case index the
modelled switch now takes the **default** target instead of that case's target. That is strictly
better than before (the default is the correct answer for the out-of-range and default cases, and
the only wrong inputs are the dropped in-range case indices), but it is still a modelling
approximation. Case targets beyond the cap remain unmodelled.

## 3. Evidence

### 3.1 Reproduction with `brcap.wasm` (before the fix, pinned install)

```
$gh = "C:\Users\micro\AppData\Local\Temp\ghidra-r5-brtable-ds"
& "$gh\support\analyzeHeadless.bat" "$env:TEMP\r5-brtable\proj-before" Before `
    -import "$env:TEMP\r5-brtable\brcap.wasm" -noanalysis `
    -scriptPath "<repo>\test-scripts" -postScript EmulateExport.java default_branch
```

Observed (buggy build):

```
WARN  br_table at ram:80000035 has 1025 labels; only the first 1024 are modelled as branches
      (the rest are decoded without control flow) (WasmFunctionAnalysis)
FUNC      default_branch @ ram:8000002d
RESULT    0100000000000000...
RETURN    i32=0x1
STATUS    ok
```

`i32=0x1` — the default target was dropped and the function fell through to `return 1`.

### 3.2 After the fix

```
.\test-scripts\check-brtable-default.ps1 -SkipBuild -OutDir "$env:TEMP\r5-brtable\check2"
  FUNC      default_branch @ ram:8000002d
  RESULT    0200000000000000...
  RETURN    i32=0x2
  STATUS    ok
PASS: default_branch returned 2 (expected 2); br_table default target is modelled
exit 0
```

Warning after the fix (still emitted, reworded):

```
WARN  br_table at ram:80000035 has 1025 labels; only the first 1023 case targets are modelled as
      branches (the default target is always modelled; the remaining labels are decoded without
      control flow) (WasmFunctionAnalysis)
```

### 3.3 Regression fixture

* `test-scripts/fixtures/brtable_default.wasm` — committed fixture, **byte-identical** (SHA-256
  `73a2ac27b83b8a5be35b38877d0aeca99f98223f38eb4a9d39d5778c4d7de343`, 1089 bytes) to the review
  artefact `brcap.wasm`.
* `test-scripts/fixtures/make_brtable_default_fixture.py` — regenerates it (self-contained, uses
  `wasm_probe_lib`; the `br_table` bytes are built explicitly because `wasm_probe_lib.br_table()`
  packs the default into the vector length, which is not the spec encoding — noted as an
  observation, not changed).
* `test-scripts/check-brtable-default.ps1` — standalone emulation check; imports the fixture with
  the pinned install, runs `EmulateExport.java default_branch`, asserts `RETURN i32=0x2`, exits
  non-zero on any failure. Verified exit 0 on the fixed build.

## 4. Spec-test emulation harness

The harness was **not** pre-provisioned (no `%TEMP%\spectest-tools\pyghidra-venv`), but the wabt +
testsuite toolchain was present and the offline PyGhidra wheels (`cp313` win_amd64) were available,
so `run_emulate.ps1` provisioned the venv itself. `br_table` is the suite that carried all four
known `br_table large` `assert_return` failures.

| build | `br_table` assert_return | failing lines |
| --- | --- | --- |
| before (stashed fix) | **145 / 4 / 0** | `br_table.wast:1071–1074`, each `got 4294967295` |
| after (fix) | **148 / 1 / 0** | `br_table.wast:1071` only: `large(10000)` `got 1, expected 0` |

Command (both runs): `.\test-scripts\spectest\run_emulate.ps1 -Files br_table -OutDir <dir>`.

So the fix resolves **3 of the 4** known failures. The one remaining is the residual above:
`large(10000)` expects label 0 (index 10000 is an even case target), but index 10000 is past the
1023-case cap and is now modelled as the default (label 1). Before the fix that same input returned
garbage (`0xFFFFFFFF`). The recorded aggregate (33 suites, `assert_return 2511/4`) therefore
becomes `2514/1` — the delta is exact because only the `large` function in `br_table.wast` exceeds
the cap; the full 33-suite aggregate was **not** re-run in this worktree (only `br_table` was).

## 5. Documentation corrections

`MODERN_WASM_GAPS.md`:

* §2.1 "Spec assert emulation" row: `assert_return 2511/4` → `2514/1`, with the `br_table`
  145/4 → 148/1 delta and the residual.
* §2.3 "`br_table large` assertion cases" row: from "open (deliberate bound) / decode-side" to
  **fixed**, stating the production impact (default target dropped) and the fix (≤ 1023 case
  targets modelled, default always modelled), residual = case indices past the cap.
* §2.3 "Emulation coverage" row: 4 remaining → 1 remaining (the `large(10000)` case).
* §2.4 emulation baseline: `2511/4` → `2514/1`, with the measured `br_table` delta and the note
  that the aggregate was derived, not re-run.
* §6 ranked finding 2 and finding 5: corrected to "≤ 1023 *case* targets; default always modelled"
  and `assert_return 2514/1`.

The same stale "decode-side deliberate bound" claim also appeared in `README.md` (known open
items), `RELEASE_NOTES.md` (2.7.0, twice) and `MERGE_NOTES.md`; all were corrected to the same
precise statement (1 residual `large(10000)` case; the default target is now always modelled).

## 6. Gate

```
.\test-scripts\check-local.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\ghidra-r5-brtable-ds" `
    -OutDir "$env:TEMP\r5-gate" `
    -RealModule "D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm"
```

Result (exit 0):

* probes: **204 imported, 18 import failures; baseline 222 — "OK: every probe matches the recorded
  baseline."** (no metric drift; in particular `SF03_large_br_table.wasm` is unchanged at
  `funcs=1 instrs=4007 undefined_bytes=0 decompiled=1`)
* fixture: `SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0` → **4/4/0/24/0**
* real module: `SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156`
  → **437/437/0/61658/156**

`.\test-scripts\check-brtable-default.ps1` exits **0**.

## 7. CI wiring (not applied here)

`.github/workflows/*` and `test-scripts/check-local.ps1` were **not** edited (per the task). The
exact wiring to add:

* **Locally** — after the build/install step, before `check-results.py`:

  ```powershell
  & .\test-scripts\check-brtable-default.ps1 -SkipBuild -OutDir "$env:TEMP\r5-gate\brtable"
  if ($LASTEXITCODE -ne 0) { throw "br_table default-target check failed" }
  ```

* **CI** — a step in `.github/workflows/probes.yml` after "Install the built extension into
  Ghidra" (the runner is `ubuntu-latest`; the script falls back to `support/analyzeHeadless` and
  `.ghidra-install` is git-ignored so the pin check is skipped and `-GhidraDir` is used):

  ```yaml
      - name: br_table default-target emulation check
        run: |
          set -euxo pipefail
          export GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:?setup-ghidra did not export GHIDRA_INSTALL_DIR}"
          export GHIDRA_HEADLESS_MAXMEM=1500M
          pwsh -NoProfile -Command '& ./test-scripts/check-brtable-default.ps1 -SkipBuild -GhidraDir "$env:GHIDRA_INSTALL_DIR" -OutDir "$env:RUNNER_TEMP/brtable-check"'
  ```

  (No new toolchain is needed: the check only imports the committed fixture and emulates it, unlike
  `run_emulate.ps1` which needs the spec suite + a PyGhidra venv.)

## 8. Residual limits / uncertainties

* Case targets at indices `>= MAX_BR_TABLE_CASES - 1` are still unmodelled; for those exact inputs
  the modelled switch takes the default. One spec `assert_return` (`large(10000)`) therefore
  remains wrong by design of the bound.
* The 33-suite emulation aggregate (`2514/1`) is **inferred** from the measured `br_table` delta
  (145/4 → 148/1) applied to the recorded `2511/4`; only `br_table` was re-run here.
* `wasm_probe_lib.br_table()` encodes a non-spec `br_table` (vector length includes the default);
  the new generator avoids it. The helper is unused elsewhere in the repo, so it was left alone.
* The build emits pre-existing javac "removal"/deprecation warnings (e.g. `MemoryState`); no new
  errors.

## 9. Files changed

| file | change |
| --- | --- |
| `src/main/java/wasm/analysis/WasmFunctionAnalysis.java` | cap applies to case targets; default always modelled; Javadocs |
| `data/languages/WebAssembly.sinc` | `.case_ignored` comment corrected |
| `test-scripts/fixtures/brtable_default.wasm` | new committed fixture (== `brcap.wasm`) |
| `test-scripts/fixtures/make_brtable_default_fixture.py` | new generator |
| `test-scripts/check-brtable-default.ps1` | new standalone emulation check |
| `MODERN_WASM_GAPS.md` | rows corrected (§2.1, §2.3 ×2, §2.4, §6 ×2) |
| `README.md`, `RELEASE_NOTES.md`, `MERGE_NOTES.md` | stale "decode-side deliberate bound" claims corrected |
