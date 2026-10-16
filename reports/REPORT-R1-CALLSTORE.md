# REPORT-R1-CALLSTORE: False Trap on Valid Store After Call

## Defect Summary
A regression introduced by the memory64-hybrid change caused valid stores after a function call to falsely trap with "out of bounds memory access". Both i32 and i64 fixtures were affected.

## Root Cause
In `WasmEmulateInstructionStateModifier.java`, the `checkMemoryBounds64` method (around line 974) reconstructs the unwrapped effective address (EA) for memory operations. The code maintained a cache (`regSlotValues`) of the last value written to each operand-stack slot to handle in-place instructions (loads, SIMD lane loads, atomic RMWs) that overwrite their address slot.

The bug: for **stores** (which do NOT overwrite their address slot), the code incorrectly preferred the cached value over the live register. After a call returns, the shadow-stack restore puts the caller's address back in the register, but the cache still held the callee's value (e.g., -1 from `i32.const -1; drop`).

```java
// Buggy logic (before fix):
Long saved = regSlotValues.get(slotKey(slot, addressBytes));
if (saved != null) {
    dynamicBase = saved;  // Wrong for stores! Uses stale callee value.
} else if (!overwritesAddress) {
    dynamicBase = liveRegisterValue;  // Correct path, but never reached for stores.
}
```

## The Fix
Restructured the logic to prefer the **live register** for stores (where `overwritesAddress == false`), and only use the cached value for loads/lane-loads/atomic-RMWs (where `overwritesAddress == true`):

```java
// Fixed logic:
if (overwritesAddress) {
    // Loads: address slot overwritten by result, must use cached address
    Long saved = regSlotValues.get(slotKey(slot, addressBytes));
    if (saved != null) { dynamicBase = saved; }
    else if (!is64Bit && opcode >= 0x28 && opcode <= 0x35) {
        dynamicBase = reverseComputeLoadBase(emulate, pcode);
    } else { return; }
} else {
    // Stores: address slot still holds the address, use live register
    dynamicBase = emulate.getMemoryState().getValue(register, slot, addressBytes);
}
```

**File changed:** `src/main/java/ghidra/program/emulation/WasmEmulateInstructionStateModifier.java` (lines 971-986)

## Reproduction Evidence

### Before Fix (runtime.log from pre-release review)
```
call32.wasm: ERROR Emulation failure ... LowlevelError: out of bounds memory access
    at WasmEmulateInstructionStateModifier.checkMemoryBounds64(...:1005)
call64.wasm: ERROR Emulation failure ... LowlevelError: out of bounds memory access
    at WasmEmulateInstructionStateModifier.checkMemoryBounds64(...:1005)
```

### After Fix
```powershell
# call32.wasm
REVIEW returned=true result=7 steps=12 error=null address=ram:80000000

# call64.wasm
REVIEW returned=true result=7 steps=12 error=null address=ram:80000000
```

**Commands used:**
```cmd
analyzeHeadless.bat <proj> test_proj -import call32.wasm -postScript ReviewRuntime.java -deleteProject
analyzeHeadless.bat <proj> test_proj -import call64.wasm -postScript ReviewRuntime.java -deleteProject
```

## New Regression Gate

### Fixtures Committed
- `test-scripts/fixtures/call32.wasm` — i32 memory, caller pushes 0, calls helper (pushes -1, drops), stores 7 at address 0, loads back
- `test-scripts/fixtures/call64.wasm` — i64 (memory64) memory, same pattern with i64.const/i64.store32/i64.load32_s

### Check Script
`test-scripts/check-call-store-semantics.ps1`
- Imports each fixture with the pinned Ghidra install
- Emulates `store_after_call` function
- Asserts: emulation returns, no trap, stored value 7 read back from memory address 0
- Exits non-zero on any failure

**Command to run:**
```powershell
.\test-scripts\check-call-store-semantics.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\ghidra-r1-callstore" -OutDir "$env:TEMP\r1-callstore-gate"
```

**Output:**
```
== Testing call32.wasm ==
...
CallStoreTest.java> PASS: returned=true result=7 steps=12
== Testing call64.wasm ==
...
CallStoreTest.java> PASS: returned=true result=7 steps=12
== All call-store semantics tests PASSED ==
```

## Full Gate Verification

### check-local.ps1 (222 probes + real module)
```powershell
.\test-scripts\check-local.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\ghidra-r1-callstore" -OutDir "$env:TEMP\r1-gate" -RealModule "D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm"
```
**Result:** PASS
- Probes: 204 imported, 18 import failures (expected malformed), **222/222 match baseline**
- Fixture: `wasm_fixture.wasm` → functions=4, decompiled=4, failed=0, instructions=24, undefined_bytes=0
- Real module: `rasterbator_rs_bg.wasm` → functions=437, decompiled=437, failed=0, instructions=61658, undefined_bytes=156

### check-memory64-hybrid.ps1 (9 emulation cases)
```powershell
.\test-scripts\check-memory64-hybrid.ps1 -OutDir "$env:TEMP\r1-hybrid" -GhidraDir "C:\Users\micro\AppData\Local\Temp\ghidra-r1-callstore"
```
**Result:** PASS (exit 0)
- HYBRID-COPY: three index-width pairs passed
- HYBRID-MATRIX: 246 functions, 358 accesses passed
- HYBRID-EMU: 9/9 cases passed (including expected OOB/overflow traps)
- HYBRID-SIMD-PREFIX: 41 functions passed

## CI Wiring Note (for integrator)
Add the new check to the CI pipeline by invoking:
```yaml
- name: Call-store semantics regression test
  run: |
    .\test-scripts\check-call-store-semantics.ps1 -GhidraDir "<pinned-ghidra>" -OutDir "$env:TEMP\r1-callstore-gate"
```
No changes to `.github/workflows/*` or `test-scripts/check-local.ps1` required — this is a standalone gate.

## Commit Information
- **Branch:** `fix/r1-callstore-trap`
- **HEAD SHA:** (to be filled after commit)
- **Verdict:** FIXED — both fixtures pass, all existing gates green, no regressions
- **Evidence Summary:**
  - Before: both fixtures trap "out of bounds memory access" at checkMemoryBounds64:1005
  - After: both fixtures return successfully, result=7 (correct stored value)
  - check-local: 222/222 probes match baseline
  - check-memory64-hybrid: 9/9 emulation cases pass (including expected traps)
  - New regression gate: check-call-store-semantics.ps1 exits 0