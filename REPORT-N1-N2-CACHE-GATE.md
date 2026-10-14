# REPORT — N1/N2: emulator stale operand-slot cache and the call-store gate

Branch: `fix/n1-emulator-cache` (single writer)
Base: `a068983682f23f15412c1908d7c79559b0d9041f` (the re-reviewed HEAD)
Scope: the two release-blocking findings of the 2.8.0 pre-release re-review
(`release-rereview.md`; `release-rereview-sol.md` S1 + S2).

Everything below was run locally in this worktree against the pinned install
`C:\Users\micro\AppData\Local\Temp\opencode\ghidra-n1-cache`
(`test-scripts\.ghidra-install`). No shared install, no other worktree, no `D:\code\Ghidra-WASM`
was written. No pushes, no merges.

---

## 1. Findings

| # | Severity | Finding |
| --- | --- | --- |
| N1 | P1 | After a call returns, the emulator's operand-slot value cache can disagree with the live register. Loads and atomic RMWs overwrite their address slot, so the post-instruction unwrapped-EA check reads the stale cached value: valid accesses falsely trap, and a required overflow trap can be missed. Affects scalar i32/i64, v128.load and i32.atomic.rmw.add. |
| N2 | P2 | `test-scripts/check-call-store-semantics.ps1` reported success unless a console line began with `PASS:`/`FAIL:`. Ghidra prints `INFO  CallStoreTest.java> FAIL: ... (GhidraScript)`, so failing assertions and a non-zero launcher exit were ignored and the gate exited 0. |

---

## 2. N1 — root cause

`WasmEmulateInstructionStateModifier` keeps `regSlotValues`, a map
`(slot offset,size) -> last value written`, so that an instruction which overwrites its own
operand slot (a load/RMW writing its result, an in-place op like `f32.neg`) can be checked
against the value the slot held *before* the instruction. The map is populated by
`recordRegisterWrites`, which only inspects the **instruction's pcode outputs**.

The call/return machinery does not write through pcode. `CallEpilogueOpBehaviour` (and
`CallPrologueOpBehaviour`, `PushOpBehaviour`, `PopOpBehaviour`, `FuncEntryOpBehaviour`) write
operand slots directly through `MemoryState` via `WasmEmulationHelper.copyRegisters` /
`popShadowStackRegs`. In particular the epilogue restores the caller's saved operand stack with
`popShadowStackRegs(memState, getStackOffset(0))` (pre-fix line 483). Those writes are invisible
to `recordRegisterWrites`, so after a call returns the live register holds the caller's address
again while `regSlotValues` still holds the callee's value.

Trigger (the re-review fixtures): the caller keeps an address on the stack across a void call; the
callee pushes/drops a value into the same physical slot; the epilogue restores the register but not
the cache. The following load/RMW overwrites the slot, and `checkMemoryBounds64` takes the address
from the stale cache (pre-fix lines 983–988) for the overwriting branch. The store branch was
already fixed for R1 by reading the live register (pre-fix lines 997–1002); loads, SIMD lane loads
and atomic RMWs take the cached branch instead. The scalar i32 path had this bug in v2.7.0; the
memory64 hybrid extended it to i64/SIMD/atomic.

---

## 3. N1 — fix (code mechanism)

`src/main/java/ghidra/program/emulation/WasmEmulateInstructionStateModifier.java`

Added a cache refresher and called it at every register-space write performed by a CALLOTHER
behaviour, so the cache stays synchronized with the live slots:

```java
private static final int[] SYNC_SIZES = { 1, 2, 4, 8, 16 };

private void syncRegisterSlots(MemoryState memState, AddressSpace register, long startOffset, int count) {
    if (count <= 0) return;
    for (int i = 0; i < count; i++) {
        long slot = startOffset + (long) i * WasmLoader.REG_SIZE;
        for (int size : SYNC_SIZES) {
            regSlotValues.put(slotKey(slot, size), memState.getValue(register, slot, size));
        }
    }
}
```

Sync points added (each right after the behaviour's write):

* `CallEpilogueOpBehaviour` — after popping outputs to `o*`; **after `popShadowStackRegs` restores
  the caller stack** (the fix for N1); after pushing outputs back onto the stack; after restoring
  locals.
* `CallPrologueOpBehaviour` — after popping params to `i*`.
* `PushOpBehaviour` / `PopOpBehaviour` — after the branch stack↔temp moves (`doBranch`).
* `FuncEntryOpBehaviour` — after copying params to `l*` and zeroing the remaining locals.

This refreshes **all** tracked views of each slot (1/2/4/8/16 bytes), covering the 4- and 8-byte
address views. It does **not** drop cache entries and does **not** skip the memory64/SIMD/RMW
checks — the cache is corrected, so the required overflow trap still fires (verified below and by
the hybrid harness, which explicitly asserts overflow traps).

---

## 4. N1 — before/after runtime evidence (all eight cache cases)

Fixtures: `test-scripts/fixtures/cache32.wasm`, `cache64.wasm` (byte-identical copies of the
re-review evidence fixtures) plus the direct/no-call controls described in §7.
Each case is one exported function run through the real `EmulatorHelper` /
`WasmEmulationHelper` path.

Command (both runs):

```powershell
pwsh -NoProfile -File test-scripts\check-call-store-semantics.ps1 -OutDir "$env:TEMP\n1-callstore"
```

**Before** (same source with the N1 edit temporarily reverted via `git stash`, rebuilt + installed;
this reproduces `release-rereview-evidence\sol\newcases.log`):

```
cache32.wasm / cache64.wasm
FAIL: load_after_call     emulation did not return (steps=7, error=out of bounds memory access)
FAIL: simd_after_call     emulation did not return (steps=7, error=out of bounds memory access)
FAIL: rmw_after_call      emulation did not return (steps=8, error=out of bounds memory access)
FAIL: overflow_after_call expected trap 'out of bounds memory access' but returned (steps=9)
```

Steps 7/7/8 and the missed trap at step 9 with the exact trap text match `newcases.log`.

**After** (fixed build):

```
cache32.wasm / cache64.wasm
PASS: load_after_call     returned=0x12345678 steps=9
PASS: simd_after_call     returned=0x12345678 steps=10
PASS: rmw_after_call      returned=0x12345678 steps=10
PASS: overflow_after_call trapped='out of bounds memory access' steps=7

cache32_controls.wasm / cache64_controls.wasm  (unchanged on both builds)
PASS: direct_load         returned=0x12345678 steps=4
PASS: direct_simd         returned=0x12345678 steps=5
PASS: direct_rmw          returned=0x12345678 steps=5
PASS: direct_overflow     trapped='out of bounds memory access' steps=2
```

Summary: the six valid exports (load/SIMD/RMW × i32/i64) return `0x12345678` and the two
required-trap exports (overflow × i32/i64) trap with `out of bounds memory access`.

---

## 5. N2 — root cause

`check-call-store-semantics.ps1` (pre-fix lines 88–93) matched `^(PASS|FAIL):` at the start of a
line only. Ghidra prefixes script output, so every record was ignored; `$allPassed` started `true`
(pre-fix line 72); the launcher's `$LASTEXITCODE` was never checked; and no fixture was required to
produce a passing record. Sol's controlled mock (`gate-failure.log`) reproduced a byte-identical
wrapper reporting `All call-store semantics tests PASSED` with exit 0 while the mock printed
prefixed `FAIL` lines and exited 1.

---

## 6. N2 — fix

`test-scripts/check-call-store-semantics.ps1`

* Parses the script-specific record **anywhere** in the line:
  `$line -match '(?:^|\s)(PASS|FAIL):'`.
* Per fixture, requires **all** of: launcher `$LASTEXITCODE -eq 0`; no `FAIL` record; a non-empty
  result; and every expected `PASS: <name>` record present. Success is no longer the default.
* A missing fixture, a launcher exception, an uncaptured exit code, a non-zero exit, any `FAIL`
  record, a missing result, or a missing expected record each fail the gate (exit 1).

`test-scripts/CallStoreTest.java` (extended)

* Executes **every** export of a fixture through the emulator and asserts trap-versus-return, not
  just result bytes: valid exports must return their value, the required-trap exports must trap
  with `out of bounds memory access`.
* Emits an explicit `PASS: <name> ...` / `FAIL: <name> ...` per case, fails on an unexpected or
  missing export, and **throws** at the end when any case failed (so the headless log also shows a
  script error). The wrapper still requires the explicit PASS marker, because a headless script
  exception does not reliably yield a non-zero launcher exit.

`test-scripts/test-call-store-gate.ps1` (new, self-contained; no Ghidra)

* Builds a private mock install under `%TEMP%` whose `support/analyzeHeadless.bat` emits controlled
  output/exit codes, mirrors `test-scripts` (wrapper + `CallStoreTest.java` + fixtures + a
  `.ghidra-install` pinning the mock), and runs the **unmodified** wrapper for four scenarios.

`.github/workflows/probes.yml`: exactly one added line in the existing semantic step:

```yaml
pwsh -NoProfile -File test-scripts/test-call-store-gate.ps1 -OutDir "$RUNNER_TEMP/semantics-call-store-gate"
```

---

## 7. N2 — gate negative-test matrix

`pwsh -NoProfile -File test-scripts\test-call-store-gate.ps1 -OutDir "$env:TEMP\gate-meta"` → exit 0.

| Scenario | Mock output | Mock exit | Required wrapper exit | Observed |
| --- | --- | ---: | --- | ---: |
| A | prefixed `FAIL` record | 1 | non-zero | **1** |
| B | no `PASS`/`FAIL` record | 0 | non-zero | **1** |
| C | prefixed `PASS` records | 1 | non-zero | **1** |
| D | prefixed `PASS` records | 0 | 0 | **0** |

In A–C the wrapper prints the specific reason (`launcher exited N`, `N FAIL record(s) emitted`,
`no PASS record produced`, `missing PASS record '<name>'`) and exits 1. In D it reports
`exit 0, no FAIL, all N record(s) present` and exits 0.

---

## 8. Fixtures

Copied byte-identical from the re-review bundle (SHA-256 shown with the evidence hashes):

| File | SHA-256 | Evidence |
| --- | --- | --- |
| `test-scripts/fixtures/cache32.wasm` | `186395c5a22ba43528aafd4d344b7264263a540b753e97249bc632f5616c7617` | matches `cache32.wasm` in `release-rereview-evidence\sol` |
| `test-scripts/fixtures/cache64.wasm` | `302b11260f10185c745cd877483ff149e1ff56860e9bcb844249ea514d0095a3` | matches `cache64.wasm` in `release-rereview-evidence\sol` |
| `test-scripts/fixtures/cache32_controls.wasm` | `77dcd35cae4c3f0221e24179107b270a08442c02beb8fb8c3b0c0dd93c0176fe` | new (direct/no-call controls) |
| `test-scripts/fixtures/cache64_controls.wasm` | `945e197a989bcc95ab17e9a459f2006ed05287401dd0c9c2240a9149f6dcb8c5` | new (direct/no-call controls) |

`test-scripts/fixtures/make_cache_fixtures.py` regenerates all four; its `cache32`/`cache64` output
is byte-identical to the two evidence hashes above (verified). All four modules are accepted by
WABT 1.0.42 `wasm-validate --enable-all` (exit 0).

**Deviation, stated explicitly:** the task described the two evidence fixtures as also containing
direct/no-call controls. They do not — each contains the two `clobber_*` helpers and the four named
exports only. To keep `cache32.wasm`/`cache64.wasm` byte-identical I added the controls as two
separate fixtures (`cache32_controls.wasm`/`cache64_controls.wasm`) rather than editing the evidence
bytes. The controls exercise the same four accesses with no intervening call; they pass on both the
unfixed and fixed builds, pinning down that the fix does not alter the direct paths.

---

## 9. Gate numbers (fixed build)

| Check | Command | Result |
| --- | --- | --- |
| Full local gate | `.\test-scripts\check-local.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-n1-cache" -OutDir "$env:TEMP\n1-gate" -RealModule "D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm"` | **exit 0** |
| Probe suite | (inside the gate) | `probes: 205 imported, 18 import failure(s); baseline has 223` — `OK: every probe matches the recorded baseline.` |
| Fixture baseline | (inside the gate) | `SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0` |
| Real module | (inside the gate) | `SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156` |
| Memory64 hybrid | `.\test-scripts\check-memory64-hybrid.ps1 -OutDir "$env:TEMP\n1-hybrid"` | **exit 0** (`HYBRID-EMU ... oob64/overflow64/overflow32/high_signbit trap=out of bounds memory access passed`) |
| br_table default | `.\test-scripts\check-brtable-default.ps1 -SkipBuild -OutDir "$env:TEMP\n1-brtable"` | **exit 0** (`default_branch returned 2`) |
| Padded memargs | `.\test-scripts\check-memarg-padding.ps1 -OutDir "$env:TEMP\n1-memarg"` | **exit 0** (`MEMARG-PADDING-OK scalar_unflag_pad130 result=0x44332211`) |
| Call-store wrapper | `pwsh -NoProfile -File test-scripts\check-call-store-semantics.ps1 -OutDir "$env:TEMP\n1-callstore-final"` | **exit 0** — all 6 fixtures: exit 0, no FAIL, all expected records present |
| Gate negative tests | `pwsh -NoProfile -File test-scripts\test-call-store-gate.ps1 -OutDir "$env:TEMP\gate-meta2"` | **exit 0** — A/B/C/D all as required |

---

## 10. Residual limits

* **`WasmEmulationHelper.simulateReturn`** writes operand slots directly and is not synchronized
  with the modifier's cache (the public helper has no reference to it). It is used by the demo
  script `ghidra_scripts/emulate_writev.py` to simulate an imported function's return. If a load
  then takes its address from a slot written only by such a simulation, the stale-cache effect
  could still occur. Not exercised by the gate; the call/return machinery inside the modifier is
  covered.
* **Controls are separate fixtures**, as stated in §8 — the evidence fixtures were left
  byte-identical.
* **Baseline note:** no v2.7.0 binary was available; the "before" run reverts only the N1 source
  edit (same toolchain) and reproduces `newcases.log` exactly. This is a same-source regression
  demonstration, not a v2.7.0 binary comparison.
* The fix refreshes the cache at the modifier's CALLOTHER write points. Any future out-of-band
  register write outside those behaviours would need the same `syncRegisterSlots` treatment.

---

## 11. Commands used (selection)

```powershell
# build + clean install into the pinned install
.\test-scripts\build-install.ps1

# fixtures / provenance
python test-scripts\fixtures\make_cache_fixtures.py <dir>   # reproduces cache32/64 byte-identically
& <wabt>\wasm-validate.exe --enable-all test-scripts\fixtures\cache32.wasm   # exit 0

# N1 before/after
git stash push -- src/main/java/ghidra/program/emulation/WasmEmulateInstructionStateModifier.java
.\test-scripts\build-install.ps1
pwsh -NoProfile -File test-scripts\check-call-store-semantics.ps1 -OutDir "$env:TEMP\n1-callstore-before"
git stash pop ; .\test-scripts\build-install.ps1
pwsh -NoProfile -File test-scripts\check-call-store-semantics.ps1 -OutDir "$env:TEMP\n1-callstore-final"

# N2
pwsh -NoProfile -File test-scripts\test-call-store-gate.ps1 -OutDir "$env:TEMP\gate-meta"

# Part C
.\test-scripts\check-local.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-n1-cache" `
    -OutDir "$env:TEMP\n1-gate" -RealModule "D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm"
.\test-scripts\check-memory64-hybrid.ps1 -OutDir "$env:TEMP\n1-hybrid"
```
