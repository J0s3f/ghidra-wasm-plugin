# REPORT-HARD — malformed-input hardening (B1/B2/B3, B5)

Worktree `D:\code\ghidra-wt-s` (branch `fix/hardening`, base = merged `7efbab5`), Ghidra 12.1.4 private
install `C:\Users\micro\AppData\Local\Temp\ghidra-c`. Only owned files were changed; the
build is installed from this worktree immediately before every measurement below.

| file | change |
| --- | --- |
| `src/main/java/wasm/format/sections/structures/WasmCodeEntry.java` | per-function locals limit + non-lossy declared-local count |
| `src/main/java/wasm/format/sections/structures/WasmLocalEntry.java` | `getCountLong()` (unsigned count, no `int` cast) |
| `src/main/java/wasm/WasmLoader.java` | `load()` no longer swallows `doLoad` failures; memory/table limit validation; bounded memory/table materialisation; module-wide locals budget |
| `test-scripts/expected-results.json` | re-recorded with `check-local.ps1 -Update` (11 records changed — see §5) |
| `REPORT-HARD.md` | this report |

No file outside the ownership list was edited. `WasmFunctionAnalysis.java`, `data/languages/**`,
`WasmEnums.java`, `ConstantExpression.java`, `WasmSignatureAnalyzer.java`, `WasmFuncType.java`,
`WasmTypeSection.java`, `WasmSection.java`, `WasmModule.java`, the probe generators, the harness
scripts and the other reports are untouched.

Environment note (mechanically-enforced pinning arrived mid-task): **all** measurements were taken
against `C:\Users\micro\AppData\Local\Temp\ghidra-c`. One sub-measurement (§5.1, proving the
funcref probe diffs pre-existed) temporarily installed a pristine `7efbab5` build — built from a
throwaway `git worktree` that has since been removed — into **that same `ghidra-c` install**; the
`fix/hardening` build was reinstalled into `ghidra-c` immediately afterwards and before every
subsequent measurement. No other install (`ghidra-l/m/e/merge`, `C:\Tools\ghidra_12.1.4_PUBLIC`) was
ever used or written to.

## 0. Chosen bounds and why

| constant | value | where | rationale |
| --- | --- | --- | --- |
| `WasmCodeEntry.MAX_FUNCTION_LOCALS` | 1 000 000 | `WasmCodeEntry` | no function in the 747-module regression corpus declares more than **84** locals; V8 caps a function at 50 000, so 1e6 can never reject a module a real engine runs, while bounding the `ValType[]` to ≤ 4 MB |
| `WasmCodeEntry.MAX_MODULE_LOCALS` | 10 000 000 | `WasmLoader.validateLocalsBudget` | the largest *module* total in the corpus is **1398**; a hostile module could otherwise spread the per-function budget over thousands of tiny bodies |
| `WasmLoader.MAX_MEMORY_BLOCK_BYTES` | 256 MiB (= existing `MEMORY_STRIDE`) | `loadMemories` | the largest declared memory in the corpus is **17 pages** (1.1 MiB); a memory larger than the bound is *clamped with a warning* (not rejected), so a spec-valid large memory still imports |
| `MAX_MEMORY32_PAGES` | 65 536 | `validateMemoryLimits` | core-spec limit for a 32-bit memory (4 GiB); malformed `initial` values are rejected |
| `MAX_MEMORY64_PAGES` | 2^48 | `validateMemoryLimits` | memory64 implementation limit; generous enough that no valid memory64 module is rejected |
| `WasmLoader.MAX_TABLE_BLOCK_BYTES` | 64 MiB | `createTableBlock` | the largest table in the corpus is **1024** entries; a table bigger than this is skipped with an explicit diagnostic instead of being lost silently |

The corpus scan used to pick the numbers (`747` modules = the testsuite's valid core modules, the 3
committed corpus modules and `rasterbator_rs_bg.wasm`) is a throwaway helper in
`%TEMP%\wasmstats.py`; it is not part of the repo.

---

## 1. B3 / NS09 / NS11 — silent truncation via a swallowed load exception

**Root cause.** `WasmLoader.load()` wrapped `doLoad` in `catch (Exception e) { Msg.error(...); }` and
never rethrew. `doLoad` creates the `.module` block *before* it models each section, so an exception
thrown after that point (a custom-section name that is not a valid Ghidra `DataType` name:
`.custom.\uFFFD`, from a name that is not valid UTF-8) left the module block in place and the import
was then reported as **successful** with everything after the failing section missing —
`NS11_bad_custom_hides_code.wasm` imported with `funcs=0` while the identical module without the 5 bad
bytes imports with `funcs=1`.

**Fix.** `load()` now reports the failure and rethrows it as an `IOException`, so the import fails
honestly. The section-markup loop adds the section name/id/offset to the message before rethrowing. A
separate `catch (OutOfMemoryError)` converts an OOM into an ordinary import failure as a last line of
defence (the allocations are bounded now, so it should be unreachable).

```java
} catch (Exception e) {
    settings.monitor().setMessage("Error");
    Msg.error(this, "Failed to load Wasm module: " + e.getMessage(), e);
    throw new IOException("Failed to load Wasm module: " + e.getMessage(), e);
}
```

**Before / after (`ghidra-c`, analysis ON).**

| module | before | after |
| --- | --- | --- |
| `NS09_custom_name_bad_utf8` | `import_ok`, loader exception swallowed (`accepted-partial`) | **`import_failed`**: `Failed to load Wasm module: Failed to create markup for section .custom.\uFFFD (id SEC_CUSTOM) at file offset 0x8: Invalid DataType name: .custom.\uFFFD` |
| `NS11_bad_custom_hides_code` | `import_ok` with **`funcs=0`** (function lost) | **`import_failed`**, same clear reason; no `funcs=0` program presented as success |

The acceptance offered "reported as failed **or** the truncation made impossible"; I chose the former
because it also makes *any* future mid-`doLoad` failure honest (an alternative, more lenient design —
log-and-continue past a failing section markup so `funcs` is still recovered — is discussed in §7).
Legitimate loads are unaffected: the 271-module core spec suite, the 133-probe suite and the
real-module regression all import exactly as before (a module that currently truncates is, by
definition, not fully recovered, and none of the regression modules is in that state).

---

## 2. B1 / J02 / J03 / NS06 / NS07 — unbounded locals allocation

**Root cause.** `WasmLocalEntry.getCount()` cast a LEB128 to `int` and `WasmCodeEntry.getLocals()`
summed those counts and did `new ValType[count]` with no bound. `0x40000000` (J02/`B04`) is a large
*positive* count and escaped as `java.lang.OutOfMemoryError` from
`WasmAnalysis.getFunctions()` — an `Error`, so neither the loader's `catch (Exception)` nor the
decompiler caught it and the whole headless run aborted (exit 1). `0xFFFFFFFF` (J03/`B03`) is `int -1`
and produced a caught `NegativeArraySizeException` / a nonsense program instead.

**Fix.** The count is kept as a `long` and validated while the code section is parsed (so the failure
happens at *load* time, before the module block exists):
* group count ≤ remaining bytes (each `count,type` pair is ≥ 2 bytes);
* per-function declared locals ≤ `MAX_FUNCTION_LOCALS`, checked with overflow-safe arithmetic;
* a module-wide total ≤ `MAX_MODULE_LOCALS` (`WasmLoader.validateLocalsBudget`, computed with the new
  non-allocating `WasmCodeEntry.getDeclaredLocalCount()`).

`getLocals()` re-checks the bound defensively and throws a clear unchecked exception (unreachable,
since the constructor already rejects), so no allocation is ever sized from an unchecked count.

**Before / after (`ghidra-c`, analysis ON).**

| module | before | after |
| --- | --- | --- |
| `J02_locals_count_overflow` (= `B04`) | **`process_died`**, `OutOfMemoryError` aborts the run (exit 1) | **`import_failed`**, exit 0: `Function declares more than 1000000 locals (the loader's per-function limit; see REPORT-HARD.md)` |
| `J03_locals_count_neg` (= `B03`) | `import_ok`, caught `NegativeArraySizeException`, nonsense `funcs=1` | **`import_failed`**, same clear message |
| `NS06_too_many_locals`, `NS07_locals_count_huge`, `binary.51-54.malformed` | accepted (+ analyzer exceptions / OOM) | **`import_failed`** |

---

## 3. B2 / J01 / M03 / NS12 / M01 / M02 — absurd memory limits / 2 GiB block

**Root cause.** `loadMemories` clamped memory 0 to `CODE_BASE` (2 GiB) and materialised an initialised
block of that size; `initial <= maximum` was never checked and no page ceiling was applied. A 17-byte
module (`initial = 0xFFFFFFFF` pages) built a **2 GiB** `.memory0` and analysis never returned.

**Fix.** `validateMemoryLimits` rejects (I/O error → import fails) `initial > maximum`, `initial` above
the index type's page limit (`65536` for 32-bit, `2^48` for 64-bit) and `maximum` above that limit.
Every materialised memory is then capped at `MAX_MEMORY_BLOCK_BYTES` (256 MiB) with a warning; the old
2 GiB clamp for memory 0 is gone. Memory64 and multi-memory are unaffected — the probes use 1–7 pages.

**Before / after (`ghidra-c`, analysis ON).**

| module | before | after |
| --- | --- | --- |
| `J01_mem_initial_4G_pages`, `M03_mem_huge_initial`, `NS12_memory_min_2g` | `import_ok` (`import_ok_analysis_timeout` for M03), **2 GiB `.memory0`**, analysis wedged | **`import_failed`**: `Memory 0 is invalid: initial size 4294967295 page(s) exceeds the 32-bit limit of 65536 page(s)` (NS12: `17179869186 page(s)`); no block materialised, wall ≈ 10 s |
| `M01_mem_initial_gt_max` | `import_ok` | **`import_failed`**: `initial size 5 page(s) exceeds the declared maximum 1 page(s)` |
| `M02_mem_max_2p32` | `import_ok` | **`import_failed`**: `maximum size 4294967296 page(s) exceeds the 32-bit limit` |
| `binary-leb128.48/49`, `memory.21/22/23` (the hazard-pass hangs) | killed after 90–240 s (5 hangs) | **`import_failed`**, all 9 hazard modules rejected in a single 10.8 s JVM (§6.2) |

---

## 4. B5 / J04 / NS10 — a table with `min = 0xffffffff` silently lost

**Root cause.** `createTableBlock` computed `elementSize * numElements` with no cap and handed it to
Ghidra, whose 16 GiB guard refused the block; the error was caught and the accepted program simply had
no table.

**Fix.** `validateTableLimits` rejects `initial > maximum` (→ `NS10_table_overflow` now
`import_failed`); `createTableBlock` skips a table whose byte size exceeds `MAX_TABLE_BLOCK_BYTES`
(64 MiB) with an explicit `Msg.error` instead of an unhelpful Ghidra guard message.

**Before / after.** `M04_table_huge_initial` / `J04_table_initial_4G_elems`: `import_ok` with no table
(only Ghidra's 16 GiB guard in the log) → `import_ok` with
`Table 0 declares 4294967295 element(s); this exceeds the loader's table limit of 67108864 byte(s), so the table is not materialised (see REPORT-HARD.md)`.
`NS10_table_overflow`: accepted without a table → **`import_failed`**.

### B4 (out-of-range section ids / duplicate sections) — **not changed, needs an un-owned file**

`NS01`–`NS04` are still accepted (empty program). The fix belongs in `WasmSection.createSection`
(return `null` for any id ≥ `SEC_TAG+1`, `WasmSection.java:56`) and `WasmModule`'s constructor
(`continue` for a null section; `sectionMap.put` overwriting duplicates, `WasmModule.java:63-74`) —
neither file is in this workstream's ownership list. Exact change for the integrator:

```java
// WasmSection.createSection(...), after reading id and contentLength:
if (id >= WasmSectionId.values().length) {
    throw new IOException("Malformed section id " + id + " at file offset 0x"
        + Long.toHexString(sectionOffset));
}
// WasmModule constructor, in the else branch:
if (sectionMap.putIfAbsent(section.getId(), section) != null) {
    throw new IOException("Duplicate section id " + section.getId()
        + " at file offset 0x" + Long.toHexString(section.getSectionOffset()));
}
```

This is a *diagnostic*, not spec-exactness: a lenient loader may still choose to skip the section —
but the skip should be logged. Measured effect today: out-of-range ids give an empty program with no
diagnostic.

---

## 5. Probe baseline (`check-local.ps1`) — 11 records changed, gate green

`test-scripts/expected-results.json` was regenerated with
`& .\test-scripts\check-local.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\ghidra-c" -SkipBuild -Update`
(133 probes: 128 imported, 5 expected failures), followed by a plain run that prints
`OK: every probe matches the recorded baseline.`

Exactly 11 probe records differ from the committed baseline:

| probe | changed field | old → new | caused by |
| --- | --- | --- | --- |
| `J03_locals_count_neg.wasm` | `import_ok` | `true` → **`false`** | **this workstream** (B1) |
| `12_call_ref.wasm` | `undefined_bytes` | 1 → 0 | pre-existing (§5.1) |
| `B16_valtype_ref_null_param.wasm` | `undefined_bytes` | 1 → 0 | pre-existing |
| `B17_valtype_ref_param.wasm` | `undefined_bytes` | 1 → 0 | pre-existing |
| `F01_return_call_ref.wasm` | `undefined_bytes` | 1 → 0 | pre-existing |
| `F02_ref_as_non_null.wasm` | `undefined_bytes`, `instrs` | 1 → 0, 4 → 5 | pre-existing |
| `F03_br_on_null.wasm` | `undefined_bytes` | 1 → 0 | pre-existing |
| `F04_br_on_null_fallthrough.wasm` | `undefined_bytes` | 1 → 0 | pre-existing |
| `F05_br_on_non_null.wasm` | `undefined_bytes` | 1 → 0 | pre-existing |
| `F06_call_ref_through_table.wasm` | `undefined_bytes` | 1 → 0 | pre-existing |
| `F07_funcref_mixed.wasm` | `undefined_bytes` | 2 → 0 | pre-existing |

`J04_table_initial_4G_elems` (still `funcs=0`), `J05_functype_param_overflow` (still `import_failed`)
and every other probe are unchanged.

### 5.1 Why the 10 funcref diffs are pre-existing (measured, not assumed)

The committed baseline expects a 1-byte `call_ref` decode gap that the merged function-references
workstream had already closed: `REPORT-FR.md` §1/§4 records `12_call_ref` at 0 undefined bytes and
F01–F07 all at 0 with F02 at 5 instrs, and commit `a559dbe` ("CI baseline: … gate verified") is the
tip of worktree **`ghidra-wt-r` (`feat/name-section-2`)**, whose build did not contain the funcref
instruction decode — i.e. the 133-probe baseline was recorded against a stale extension, the same
hazard the task warns about. To confirm, I built pristine `7efbab5` (a temporary `git worktree`, since
removed, installed into `ghidra-c`) and imported the funcref probes: it produced **identical** results
(`12_call_ref undefined_bytes=0`; `F02 instrs=5 undefined_bytes=0`; F01–F07 all 0). So neither the
diff nor the change is caused by this workstream. Re-recording the 10 entries is required to leave the
CI gate green; it encodes already-merged, already-documented behaviour.

---

## 6. Regression evidence (`ghidra-c`, `fix/hardening` installed immediately before each run)

### 6.1 Positive suite, real module, probes

| check | result |
| --- | --- |
| 133-probe suite + fixture | `OK: every probe matches the recorded baseline.` (§5) |
| `run_spectest.ps1 -Subset core -MaxPerWast 10` | **271 selected, 271 imported, 0 not imported**; functions 2747, instructions 33222, `undefined_bytes 428` (= import-stub bytes only, **0 real**), decompiled 2747, `decompile_failed 0` |
| real module (`rasterbator_rs_bg.wasm`, `DumpDecomp.java`) | `SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156` — **exactly** the recorded baseline |
| `M64_01..08` (memory64 / multi-memory) | all import with their 1–2 `.memoryN` blocks (65536 bytes each), `undefined_bytes=0` |

For reference the spec-core positive suite matches the acceptance target (271/271, 0 real undefined
bytes); its `undefined_bytes=428` are the documented 4-byte import-stub bodies, not decode gaps.

### 6.2 Robustness sweep, before → after (56 modules, analysis ON, one JVM per module)

Before = committed `test-scripts/robustness-RESULTS.md`; after =
`robustness-sweep.ps1 -CorpusMode all -Analyze -WallSeconds 180 -ResultsFile %TEMP%\hardening-robustness-after.md`.

| outcome | before | after |
| --- | ---: | ---: |
| `import_ok` | 27 | **24** |
| `import_ok_analysis_timeout` | 1 | **0** |
| `import_failed` | 27 | **32** |
| `process_died` | 1 | **0** |
| `hang` | 0 | 0 |
| total | 56 | 56 |

Changed rows: `B04_locals_1G_alloc` `process_died` → `import_failed`; `M03_mem_huge_initial`
`import_ok_analysis_timeout` → `import_failed`; `B03_locals_ffffffff`, `M01_mem_initial_gt_max`,
`M02_mem_max_2p32` `import_ok` → `import_failed`; `M04_table_huge_initial` stays `import_ok` but now
carries the explicit table diagnostic. `M05`/`M06`/`C09`/`O*`/`D*`/`L*`/`S*`/`X02` are unchanged (their
per-analyzer exceptions remain caught, which is the documented lenient behaviour).

### 6.3 Negative harness, before → after (import-only, full 2948-module binary set)

Before = `REPORT-NS.md` / `test-scripts/spectest-NEGATIVE.md`; after =
`run_spectest_negative.ps1 -SkipPrepare -ImportDir %TEMP%\specneg-all\import` (2948 modules, 15 chunks,
all rc=0, no re-splits).

| metric | before | after |
| --- | ---: | ---: |
| rejected | 59 | **130** |
| accepted | 2889 | **2818** |
| `accepted-partial` (loader failed but import "succeeded") | 53 | **0** |
| `accepted-empty` | 219 | 215 |
| crash / hang | 0 / 0 | **0 / 0** |
| rejection diagnostics | 28 no-loader + 31 "no memory blocks" | 28 no-loader + **102 loader diagnostics** |

The 102 real loader diagnostics come from: `initial > maximum`, out-of-range memory/table limits and
too-large locals (this workstream) and the bad-UTF-8 custom-name markup failures that used to be
swallowed (B3). All 9 hazard modules (`binary-leb128.48/49`, `memory.21/22/23`, `binary.51-54`) — the
5 previous analysis hangs and 2 previous analyzer-exception cases — are now **rejected at load**;
imported together with analysis ON they finish in **10.8 s** with 9 `Import failed` and 0 `SPECNEG`
acceptances.

The remaining 215 `accepted-empty` are dominated by malformed-UTF-8 custom names whose decoded string
happens to be an *acceptable* Ghidra DataType name (e.g. `\x80` → a lone U+FFFD is accepted; `\xc2\x7f`
→ U+FFFD + DEL is not), and by out-of-range section ids / duplicate sections (B4). Those modules no
longer truncate anything — nothing throws for them — they are genuinely empty binaries the loader is
lenient about by design.

---

## 7. Open questions / for the integrator

1. **B4 is implemented only as an analysis + proposed patch** (un-owned `WasmSection.java` /
   `WasmModule.java`, §4). Until it lands, out-of-range section ids and duplicate sections are still
   swallowed without a diagnostic (215 `accepted-empty` include them).
2. **B3 design choice.** I rethrow and fail the import for *any* mid-`doLoad` failure. The alternative
   the acceptance also allows — keep the import, but wrap the per-section markup so a failure is
   logged and decoding continues (then `NS11` imports with `funcs=1` instead of failing) — is arguably
   friendlier for odd-but-valid modules with a custom-section name that is not a legal DataType name.
   Say the word if you prefer it; it is a small, contained change to the markup loop.
3. **`C09_count_func_code_mismatch`** (function section declares more functions than the code section
   supplies) still imports and raises a caught `IndexOutOfBoundsException` in the pre-analyzer. It is
   outside the three named defects, but `WasmAnalysis.getFunctions` / `WasmLoader.getFunctionAddressOffset`
   would need a bounds guard to make it a clean rejection.
4. **Stale recorded baselines.** Besides `expected-results.json` (§5.1), the spec-core
   `undefined_bytes` (428 now vs 458 recorded) and `instrs` (33222 vs 33192) also lag the merged
   `select`-after-terminator fix; the *acceptance* figure (0 real undefined bytes) already matches.
   `test-scripts/spectest-BASELINE.md` is the stale document if the integrator wants it refreshed.
5. **Very large *valid* memories** are now clamped to 256 MiB with a warning (a documented rule), not
   rejected — a deliberate trade-off (the old 2 GiB clamp produced the M03 wedge). A module declaring
   a 300 MiB–4 GiB memory that used to get a 2 GiB block now gets a 256 MiB one.
