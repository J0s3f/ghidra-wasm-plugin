# REPORT-EMU — emulator coverage workstream (handover status)

Branch `fix/emulator-coverage` (base `main` @ `066bfcc`), worktree
`C:\Users\micro\.local\share\opencode\worktree\b64b36\ghidra-wt-emu`, pinned Ghidra
`C:\Users\micro\AppData\Local\Temp\opencode\ghidra-h5`.

**Status: incomplete.** Classes 1, 2, 3, 5 are verified fixed by harness runs. Class 4 is
implemented but never exercised by a run. Classes 6, 8, 9 are reworked but **not built and not
tested** (the pinned install is stale — see "Exact workspace state"). Class 7 was investigated and
is out of scope. The source changes are **uncommitted** and the pinned install contains an older
build than the source.

---

## 0. Reproduction of the baseline (done)

Provisioned the PyGhidra venv (it did not exist before this session):

```powershell
py -3.13 -m venv "$env:TEMP\spectest-tools\pyghidra-venv"
& "$env:TEMP\spectest-tools\pyghidra-venv\Scripts\python.exe" -m pip install --no-index `
    -f "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-h5\Ghidra\Features\PyGhidra\pypkg\dist" pyghidra
# -> pyghidra 3.1.0, jpype 1.5.2
```

Built + installed, then ran the exact 33-suite baseline from REPORT-H3 §3.3:

```powershell
$env:GHIDRA_INSTALL_DIR="C:\Users\micro\AppData\Local\Temp\opencode\ghidra-h5"
.\test-scripts\build-install.ps1
.\test-scripts\spectest\run_emulate.ps1 -Files @("address","align","block","br","br_if","br_table",`
  "call","call_indirect","endianness","fac","forward","func","global","i32","i64","if","int_literals",`
  "labels","load","local_get","local_set","local_tee","loop","memory","nop","return","select","stack",`
  "store","switch","table","traps","unreachable") -OutDir "$env:TEMP\emu-base"
```

* **WALL_SECONDS = 780** (13 min) for all 33 suites.
* Totals from `$env:TEMP\emu-base\emulate-summary.json` — **exactly the recorded baseline**:
  `assert_return 2489 ok / 26 fail`, `assert_trap 79 ok / 104 fail`, `module 92 ok / 0 fail`,
  `assert_exhaustion 5 skip`, `assert_invalid 893 skip`, `assert_malformed 203 skip`.

Gotcha: `run_emulate.ps1 -Files` is a `[string[]]`; passing a single comma-joined string (e.g.
`-Files "i32,i64"`) is treated as **one** filename and warns `no such wast`. Pass a PowerShell array
literal: `-Files @("i32","i64")`.

`check-local.ps1` (the 182-probe gate / fixture / real module) was **never run** in this session —
see caveats.

---

## 1. Findings per gap class (REPORT-H3 §3.4)

All fixes below are **emulator-side** (`WasmEmulateInstructionStateModifier` + `spectest.py`); no
pcode/SLEIGH/loader/analysis change was made, so the decompiler gates should be untouched (but see
caveats).

### Class 1 — `assert_trap` did-not-trap: out-of-bounds linear memory (64) — **FIXED (verified)**

Implementation: `checkMemoryBounds()` in `postExecuteCallback`. It scans the executed instruction's
pcode for `LOAD`/`STORE` in the `ram` space, reads the effective address and access size from the
live varnodes, and compares against the declared memory size (`WasmFunctionAnalysisProvider` now
reads the memories out of the module it re-parses from the emulator memory state). Single-memory
modules (the whole core suite) always use memory 0, so the effective address is used directly even
when it is `0xffffffff`.

Evidence (`$env:TEMP\emu-sub` run, 7 suites, WALL 188s):
* `address.wast`: `assert_return 206/0`, `assert_trap 0/49` → **49/49 traps now pass**.
* `traps.wast`: the 14 `no_dce.*.load*` traps and the `align.wast` store trap pass.
* The `align.wast` wrong-value `load` (class 9) is also fixed by this: the OOB i64 store at 65532
  no longer writes the in-bounds low 4 bytes, so the follow-up load reads 0.

### Class 2 — `assert_trap` did-not-trap: call_indirect type mismatch (10) — **FIXED (verified)**

Implementation: `checkCallIndirect()`. When the executed instruction's first byte is `0x11`/
`0x13` (`call_indirect`/`return_call_indirect`), it decodes the `typeidx`/`tableidx` ULEB128s from
the code bytes, finds the table LOAD in the pcode to get the element address/index, and compares
`module.getType(typeidx)` with `module.getFunctionType(funcidx)` (structural: param/return type
arrays). Function-address → funcidx comes from `WasmLoader.getFunctionAddressOffset`; the loader
stores element segments as function addresses (`WasmElementSegment.getInitData`), so this mapping
is exact.

Evidence: the `call_indirect` suite produced **no failing traps** in the `$env:TEMP\emu-sub` run
(baseline had 17 fail, including the runaway at `call_indirect.wast:530` that hit the step budget;
that is now a clean `indirect call type mismatch`).

### Class 3 — wrong trap: `uninitialized element` instead of `undefined element` (11) — **FIXED (verified)**

Same `checkCallIndirect()`: index ≥ table size → `undefined element`; null element → `uninitialized
element`; type mismatch → `indirect call type mismatch`, in spec order. Evidence: `call.wast`,
`global.wast`, `if.wast`, `select.wast` `as-call_indirect-last` traps and the `call_indirect` suite
pass.

### Class 4 — `assert_return` emu-error: `Unimplemented CALLOTHER (memory_grow / memory_size)` (17) — **IMPLEMENTED, NOT VERIFIED**

Added `MemorySizeOpBehaviour` and `MemoryGrowOpBehaviour`, registered for `memory_size` /
`memory_grow`. `memory_size` returns `currentPages`; `memory_grow` returns the previous size or
`-1` when `old+delta > max`, tracking a mutable page counter in the provider (page size honours a
custom page-size exponent; 32-bit default max 65536 pages, 64-bit 2^48). **This compiles but was
never run against the suites that exercise it** (`memory`, `nop`, `block`, `if`, `loop`, `select`,
`load`, `call`, `call_indirect`, `global` all had `as-memory.grow-*`/`memsize` failures at
baseline).

### Class 5 — `assert_trap` did-not-trap: integer div/rem by zero + `div_s(INT_MIN,-1)` (10) — **FIXED (verified)**

Implementation: `checkArithmeticTraps()` scans the pcode for `INT_DIV`/`INT_REM`/`INT_SDIV`/
`INT_SREM`; divisor 0 → `integer divide by zero`; `INT_SDIV` with numerator `INT_MIN` and divisor
`-1` → `integer overflow`. (Ghidra core already throws for signed `/0` and `%0`; unsigned `/0` and
`%0` return 0 silently, and `INT_MIN/-1` wraps.)

Evidence: `i32.wast` and `i64.wast` `assert_trap` went from `7/3` to `7/7`; `traps.wast`
`no_dce.*.div_u/div_s/rem_*` all pass.

### Class 6 — `assert_trap` did-not-trap: float→int `trunc` out of range/NaN (8) — **PARTIAL, reworked but unverified**

`checkTruncTrap()` reads the instruction opcode byte to distinguish the trapping conversions
(`0xA8..0xAB`, `0xAE..0xB1`) from the non-trapping `trunc_sat` family (`0xFC`), then applies the
signed/unsigned range and NaN checks.

* **First attempt fixed only 2 of 8** (`i32.trunc_f64_s/u`); the other 6 still did-not-trap.
  Debug tracing proved why: the Wasm operand-stack slots are **direct register-space varnodes**
  (e.g. `register:50000000:4`), and an in-place conversion (`sp1_32 = trunc(sp1_32)`,
  `sp1_64 = trunc(sp1_32)`, `sp1_64 = trunc(sp1_64)`) overwrites its own input, so
  `memState.getValue(input)` at `postExecuteCallback` returns the *result* (0), not the NaN.
  Observed trace: `TRUNCDBG ... opcode=0xa8 inSize=4 outSize=4 raw=0x0` vs
  `opcode=0xaa inSize=8 outSize=4 raw=0x7ff8000000000000` (the only passing one).
* **Rework (untested):** added a `regSlotValues` map (offset+size → last value) maintained by
  `recordRegisterWrites()` at the end of every instruction; `operandValue()` falls back to it when
  the operand and output share the same address. Expected to fix all 6 remaining NaN traps.

### Class 7 — `assert_return` wrong value on `br_table large` (4) — **NOT ADDRESSED (out of scope)**

Root cause identified: `MAX_BR_TABLE_CASES` (the `@@BRTABLE_CAP` in
`src/main/java/wasm/analysis/WasmFunctionAnalysis.java:1384`) bounds the modelled br_table labels;
`br_table.wast`'s `large` function has ~16k labels and indices ≥ 10000 fall through to the
`-1` default. This is a **decode/analysis** gap in a file owned by another concurrent agent
(reference typing), and there is no emulator-side hook (the pre-analyzer simply emits no pcode for
those labels). **Do not touch `WasmFunctionAnalysis.java`.** This should be re-classified as
"decode gap, not an emulator gap" in the final report.

### Class 8 — `assert_return` wrong value: mutable/imported globals (3) — **PARTIAL, reworked but unverified**

`global.wast` imports `spectest.global_i32/i64` (the spec host defines 666). The harness never
instantiated imports, so they read 0.

* First rework wrote the spectest host values into the emulator's `global` space
  (`init_spectest_globals` in `spectest.py`). Verified in the `$env:TEMP\emu-dbg` run: `global`
  went from `53/4` to `55/2`; **`as-compare-operand` now passes**, and `as-call_indirect-last` /
  `as-memory.grow-value` pass via classes 3/4.
* `get-z1`/`get-z2` still read 0 because the *defined* globals `$z1`/`$z2` are initialised by
  `global.get 0/1`; the loader cannot evaluate an imported global and creates them uninitialised.
  **Rework (untested):** after writing the imported globals, walk `module.getNonImportedGlobals()`
  and, for each whose `entry.asGlobalGet()` is non-null, copy the source global's bytes from the
  emulator memory into the defined global's address.
* Bug found and fixed along the way: `JArray(JByte)(list(bytes))` raises
  `OverflowError: Cannot convert value to Java byte` for bytes >127; map 0..255 onto -128..127.

### Class 9 — `assert_return` wrong value: NaN payload / load (2) — **PARTIAL, reworked but unverified**

* `align.wast` load: **fixed by class 1** (verified).
* `local_tee.wast as-unary-operand` (`f32.neg` of `nan:0x0f1e2` → got canonical `0xffc00000`):
  Ghidra's `FLOAT_NEG`/`FLOAT_ABS` decode to a host double and re-encode, canonicalising the NaN.
  First attempt (recompute from the input varnode at `postExecuteCallback`) failed for the same
  in-place reason as class 6 (`NEGDBG ... in=register:50000000:4 out=register:50000000:4
  same=true val=0xffc00000`). **Rework (untested):** `checkFloatPurity()` now reads the
  pre-instruction value from `regSlotValues`, flips/clears the sign bit, and writes the corrected
  value back to the output register varnode (plus any STORE of it).

---

## 2. Exact workspace state (uncommitted)

### `src/main/java/ghidra/program/emulation/WasmEmulateInstructionStateModifier.java` — ~470 added lines

Compiles (`gradle compileJava` succeeds). Contents:
* `WasmFunctionAnalysisProvider` extended with memory page size/pages/max and a
  function-address→funcidx map, plus accessors (`getMemoryCount`, `getMemorySizeBytes`,
  `getMemoryPageSize`, `growMemory`, `getTableSize`, `getFuncidxByAddress`, `getModule`).
* Trap-text constants and the checks `checkMemoryBounds`, `checkArithmeticTraps`,
  `checkTruncTrap`, `checkCallIndirect`, `checkFloatPurity`, `recordRegisterWrites`, plus helpers
  `spaceOf`, `readBytes`, `readInstructionByte`, `decodeULEB`, `sameVarnode`, `slotKey`,
  `operandValue`, `operandValueOrNull`.
* `MemorySizeOpBehaviour` / `MemoryGrowOpBehaviour`, registered in the constructor.
* `postExecuteCallback` now calls the checks then `recordRegisterWrites`.
* **Important:** the version currently *installed* in the pinned Ghidra was built **with temporary
  `System.err.println("TRUNCDBG"/"NEGDBG")` debug lines and the old (pre-`regSlotValues`) trunc/neg
  logic**. Those debug lines are removed in the source, and `regSlotValues` is added, but the
  source has **not been rebuilt/reinstalled since**. The install is stale relative to the source.

### `ghidra_scripts/spectest.py` — ~70 added lines

* `WASM_TRAP_TEXTS` frozenset; `run_function()` maps an emulator error that is exactly one of the
  spec trap texts to `EmulationError(err)` (so `assert_trap` compares verbatim) while keeping the
  existing `halt_trap`→`unreachable` and `Divide by 0`/`Remainder by 0`→`integer divide by zero`
  mappings.
* `init_spectest_globals()` called from `import_program()` (host global values + defined-global
  propagation, see class 8).
* Python syntax checked with `py -3.13 -c "import ast; ast.parse(open(...).read())"` → OK; the
  runtime behaviour of the newest (defined-global) part is **unverified**.

### `test-scripts/DumpFuncPcode.java` — ABANDONED, delete it

A temporary diagnostic meant to dump a function's pcode. It never printed anything useful
(`getSymbolTable().getSymbols(name)` found the symbol only in a `-noanalysis` run with no
instructions, and after in-script analysis it printed nothing), so it produced no evidence. **Delete
this file before continuing.** (The `TRUNCDBG`/`NEGDBG` evidence that actually solved classes 6/9
came from temporary prints in the modifier, which have since been removed.)

### Build / run commands

```powershell
# compile only (safe, does not touch the install)
cd C:\Users\micro\.local\share\opencode\worktree\b64b36\ghidra-wt-emu
$env:GHIDRA_INSTALL_DIR="C:\Users\micro\AppData\Local\Temp\opencode\ghidra-h5"
& C:\Tools\gradle-9.2.1\bin\gradle.bat --no-daemon compileJava

# build + install into the pinned install (MUST be done before any harness run)
.\test-scripts\build-install.ps1

# run the harness (array literal for -Files!)
.\test-scripts\spectest\run_emulate.ps1 -Files @("traps","local_tee","global") -OutDir "$env:TEMP\emu-dbg"
```

Run outputs so far: `$env:TEMP\emu-base` (baseline), `$env:TEMP\emu-sub` (first fix round),
`$env:TEMP\emu-dbg` (debug round). Logs are `<OutDir>\reports\<suite>.log` (stderr, includes
`ERROR:` lines with the expected trap text) and `<OutDir>\reports\<suite>.txt` (`RESULT` lines);
aggregate in `emulate-summary.json`/`.md`.

---

## 3. What did NOT work / dead ends

* **`postExecuteCallback` reading the operation's input varnode** for in-place instructions
  (`trunc`, `neg`) — the input slot is already overwritten. This wasted the first attempt at
  classes 6 and 9. The fix is the `regSlotValues` pre-instruction snapshot.
* **`test-scripts/DumpFuncPcode.java`** — the symbol lookup / in-script-analysis approach never
  produced output; abandoned.
* **`JArray(JByte)(list(value))`** — overflows for bytes >127; must be mapped to signed.
* **`run_emulate.ps1 -Files "a,b,c"`** — treated as one filename; use `@("a","b","c")`.
* **Hypothesis that trunc's input survives at `postExecute` because in/out varnodes differ** — false;
  the SLEIGH resolves the stack operands to direct register-space varnodes and in-place ops clobber.
* **Considering a SLEIGH/pcode change** (e.g. copying the operand to a temp before `trunc`, or a
  `callotherfixup` like `funcEntryCallOther`) — rejected for now: it would touch the decompiler
  path and needs the full 182-probe + fixture + real-module + decode gates, and the `regSlotValues`
  approach should be sufficient.
* **CI integration** — not attempted. The full 33-suite run is ~13 min and needs a PyGhidra venv;
  `run_emulate.ps1` also hardcodes `py -3.13` (no Linux `py` launcher), so the workflow would need
  a Linux interpreter path and a baseline checker. Probably leave the harness manual (document the
  wall time).

---

## 4. Exact next steps

1. Delete `test-scripts/DumpFuncPcode.java`.
2. `.\test-scripts\build-install.ps1` (the install is stale).
3. Run the focused subset and confirm classes 4, 6, 8, 9:
   ```powershell
   .\test-scripts\spectest\run_emulate.ps1 -Files @("traps","local_tee","global","memory","nop",`
     "block","if","loop","select","load","call","call_indirect") -OutDir "$env:TEMP\emu-sub2"
   ```
   Expected: `traps` 32/0, `local_tee` 55/0, `global` 57/0 (or 55/2 if defined-global propagation
   still fails), and no `memory_grow`/`memory_size` emu-errors anywhere.
4. If class 6/9 still fail, add a temporary `System.err.println` in `checkTruncTrap`/
   `checkFloatPurity` printing the `regSlotValues` lookup result and the slot key, run `traps` +
   `local_tee`, and inspect `reports\*.log`. If the map is empty, the previous instruction did not
   write the slot with a register-space output/STORE — check `recordRegisterWrites`.
5. Full 33-suite run to `$env:TEMP\emu-fixed` (~13 min); compare `emulate-summary.json` totals with
   the baseline (`2489/26`, `79/104`). Expected remaining failures: only `br_table` (4, class 7).
6. Run the gates (all were skipped this session): `check-local.ps1` 182 probes + fixture + real
   module + both fixture-validity modes, and the spec-suite decode gate if reachable. No
   pcode/SLEIGH change was made, so they should be unaffected — but **prove it**.
7. Write the per-class before/after table, decide CI (likely manual), commit small focused commits
   (do NOT push/merge/tag).

---

## 5. Caveats / surprises

* **Harness wall time:** full 33 suites = **780 s (13 min)**; 7-suite subset = 188 s; 3-suite subset
  ≈ 60 s. One PyGhidra JVM per `.wast`.
* **PyGhidra venv:** created this session at `$env:TEMP\spectest-tools\pyghidra-venv`
  (Python 3.13, pyghidra 3.1.0, jpype1 1.5.2). Toolchain (wabt 1.0.42 + pinned testsuite
  `spec-d76759e746f3564a03f6106ae19679742f2a1831`) already present under
  `$env:TEMP\spectest-tools`.
* **The pinned install is stale:** it holds a build *with debug prints and the pre-`regSlotValues`
  trunc/neg code*. Any harness run before `build-install.ps1` will measure the wrong code.
* **No pcode/SLEIGH/loader/analysis file was modified** by this workstream, so the decompiler gates
  are almost certainly unaffected — but they were never run, so this is an assumption, not evidence.
* **Ownership:** `WasmStackVariableAnalyzer.java` (stack SROA) and
  `WasmEnums.java`/`WasmFunctionAnalysis.java` (reference typing) belong to other agents; the
  class-7 root cause lives in `WasmFunctionAnalysis.java` and must not be edited here.
* Class 4 (memory_grow/size) is the largest *unverified* win: 17 baseline `assert_return`
  emu-errors, plus it unblocks `call`/`global`/`if`/`select`/`load`/`nop`/`memory`/`block`/`loop`.
* The class-8 fix is a *harness* change (instantiating the spec host's imported globals), which is
  faithful to the spec host rather than a loosening; document it as such.
