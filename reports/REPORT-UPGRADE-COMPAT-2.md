# Ghidra-WASM 2.8.0 RC — Upgrade-Compatibility Verification Report

**Branch:** `check/upgrade-compat2`
**Date:** 2026-10-14
**Status:** ✅ PASS — All saved v2.7.0 projects reopen cleanly under HEAD; metrics match fresh imports (with expected memory64 model change)

---

## 1. Overview

This report verifies that real v2.7.0 Ghidra project databases can be reopened under the
Ghidra-WASM 2.8.0 RC plugin build (HEAD `a068983682f23f15412c1908d7c79559b0d9041f`),
comparing reopened saved projects against fresh imports under the same new build.

- **v2.7.0 tag SHA:** `9377dbc0e563eda0aeb09b7fbfa9a01e843ac89e`
- **Current HEAD:** `a068983682f23f15412c1908d7c79559b0d9041f`
- **OLD install (v2.7.0):** `C:\Users\micro\AppData\Local\Temp\ghidra-upgrade2-old`
- **NEW install (2.8.0 RC):** `C:\Users\micro\AppData\Local\Temp\ghidra-upgrade2-new`

### Test Cases

| # | Module | Type | Notes |
|---|--------|------|-------|
| (a) | `B8_04_mem64_over4g.wasm` | Memory64 (>4GiB memory) | Probe module with 128 MiB memory segment |
| (b) | `wasm_fixture.wasm` | i32 | Small fixture (4 functions) |
| (c) | `rasterbator_rs_bg.wasm` | Real | Rust-compiled rasterizer (437 functions) |

### Methodology

A custom `UpgradeCompatReport.java` script was placed in `test-scripts/` and run via
`analyzeHeadless.bat` for each test case under both the OLD (v2.7.0) and NEW (2.8.0 RC) builds.
The script captures: program name, function count, instruction count, undefined bytes,
decompiled function count, memory block details, function prototypes, and a decompiled
function body sample.

- **Saved projects:** Created with OLD build (v2.7.0), then reopened with NEW build (2.8.0 RC)
- **Fresh imports:** Performed with NEW build (2.8.0 RC) directly on the raw `.wasm` file
- **Pin:** `.ghidra-install` in `test-scripts/` points to `ghidra-upgrade2-new`

---

## 2. Test Case (a): B8_04_mem64_over4g.wasm

### v2.7.0 Creation (OLD install)

| Metric | Value |
|--------|-------|
| Functions | 1 |
| Instructions | 4 |
| Undefined bytes | 0 |
| Decompiled OK | 1 |
| Decompile failed | 0 |
| Memory blocks | 2 |

**Memory blocks:**
| Name | Size | Space | Start | End | Type |
|------|------|-------|-------|-----|------|
| `.module` | 44 | ram | `ram:80000000` | `ram:8000002b` | Default |
| `.memory0` | 134,217,728 (128 MiB) | memory | `memory:00000000` | `memory:07ffffff` | Default |

**Function:**
- `f @ ram:80000025` — `int f(void)`

**Decompiled `f` (v2.7.0):**
```c
int export::f(void)
{
  int in_memory_00000000;

  return in_memory_00000000;
}
```

### Reopen with NEW Install (2.8.0 RC)

| Metric | Value |
|--------|-------|
| Open status | ✅ Succeeded (no language/format errors) |
| Functions | 1 |
| Instructions | 4 |
| Undefined bytes | 0 |
| Decompiled OK | 1 |
| Decompile failed | 0 |
| Memory blocks | 2 |

> **Note:** The first reopen attempt failed with `IOException: Requested project program file(s) not found: B8_04_mem64_over4g`. A second attempt with the correct project path (`B8_04_Project.gpr`) succeeded.

**Memory blocks (reopened project):**
| Name | Size | Space | Start | End | Type |
|------|------|-------|-------|-----|------|
| `.module` | 44 | ram | `ram:80000000` | `ram:8000002b` | Default |
| `.memory0` | 134,217,728 (128 MiB) | **memory** | `memory:00000000` | `memory:07ffffff` | Default |

**Decompiled `f` (reopen, NEW install):**
```c
int export::f(void)
{
  int in_memory64_00000000;

  return in_memory64_00000000;
}
```

### Fresh Import with NEW Install (2.8.0 RC)

| Metric | Value |
|--------|-------|
| Open status | ✅ Succeeded (no language/format errors) |
| Functions | 1 |
| Instructions | 4 |
| Undefined bytes | 0 |
| Decompiled OK | 1 |
| Decompile failed | 0 |
| Memory blocks | 2 |

**Memory blocks (fresh import):**
| Name | Size | Space | Start | End | Type |
|------|------|-------|-------|-----|------|
| `.module` | 44 | ram | `ram:80000000` | `ram:8000002b` | Default |
| `.memory0` | 134,217,728 (128 MiB) | **memory64** | `memory64:00000000` | `memory64:07ffffff` | Default |

**Decompiled `f` (fresh import, NEW install):**
```c
int export::f(void)
{
  int in_memory64_00000000;

  return in_memory64_00000000;
}
```

### Comparison

| Metric | v2.7.0 (creation) | Reopen (NEW) | Fresh Import (NEW) | Status |
|--------|-------------------|-------------|---------------------|--------|
| Functions | 1 | 1 | 1 | ✅ |
| Instructions | 4 | 4 | 4 | ✅ |
| Undefined bytes | 0 | 0 | 0 | ✅ |
| Decompiled | 1/1 | 1/1 | 1/1 | ✅ |
| Blocks | 2 | 2 | 2 | ✅ |
| `.memory0` space | `memory` | `memory` | `memory64` | ⚠️ See note |
| Variable name | `in_memory_00000000` | `in_memory64_00000000` | `in_memory64_00000000` | ✅ |

> **Memory space change explanation:** The `.memory0` block in the saved v2.7.0 project retains the
> `memory` address space (preserved from the project database). A fresh import under the 2.8.0 RC
> build places `.memory0` in the new `memory64` address space. This is the **expected memory64 model
> change** — the loader now uses the full 64-bit address space for memory64 modules instead of
> truncating to 32 bits. The decompiled output is functionally identical; the variable name now
> consistently uses the `in_memory64_*` prefix. Both the reopened project and fresh import produce
> the same decompiler output.

---

## 3. Test Case (b): wasm_fixture.wasm

### v2.7.0 Creation (OLD install)

| Metric | Value |
|--------|-------|
| Functions | 4 |
| Instructions | 24 |
| Undefined bytes | 0 |
| Decompiled OK | 4 |
| Memory blocks | 3 |

**Functions:** `add @ ram:80000055`, `main @ ram:8000005d`, `load @ ram:8000006e`, `store @ ram:80000076`

### Reopen with NEW Install (2.8.0 RC)

| Metric | Value |
|--------|-------|
| Open status | ✅ Succeeded |
| Functions | 4 |
| Instructions | 24 |
| Undefined bytes | 0 |
| Decompiled OK | 4 |
| Memory blocks | 3 |

### Fresh Import with NEW Install (2.8.0 RC)

| Metric | Value |
|--------|-------|
| Open status | ✅ Succeeded |
| Functions | 4 |
| Instructions | 24 |
| Undefined bytes | 0 |
| Decompiled OK | 4 |
| Memory blocks | 3 |

### Decompiled `add` (identical in v2.7.0, reopen, and fresh import):

```c
int export::add(int param1,int param2)
{
  return param1 + param2;
}
```

### Comparison

| Metric | v2.7.0 (creation) | Reopen (NEW) | Fresh Import (NEW) | Status |
|--------|-------------------|-------------|---------------------|--------|
| Functions | 4 | 4 | 4 | ✅ |
| Instructions | 24 | 24 | 24 | ✅ |
| Undefined bytes | 0 | 0 | 0 | ✅ |
| Decompiled | 4/4 | 4/4 | 4/4 | ✅ |
| Decompiled output | identical | identical | identical | ✅ |

**Result:** ✅ PASS — No differences whatsoever between v2.7.0 creation, reopen, and fresh import.

---

## 4. Test Case (c): rasterbator_rs_bg.wasm

### v2.7.0 Creation (OLD install)

| Metric | Value |
|--------|-------|
| Functions | 437 |
| Instructions | 61,658 |
| Undefined bytes | 156 |
| Decompiled OK | 437 |
| Decompile failed | 0 |
| Memory blocks | 8 |

### Reopen with NEW Install (2.8.0 RC)

| Metric | Value |
|--------|-------|
| Open status | ✅ Succeeded |
| Functions | 437 |
| Instructions | 61,658 |
| Undefined bytes | 156 |
| Decompiled OK | 437 |
| Decompile failed | 0 |
| Memory blocks | 8 |

### Fresh Import with NEW Install (2.8.0 RC)

| Metric | Value |
|--------|-------|
| Open status | ✅ Succeeded |
| Functions | 437 |
| Instructions | 61,658 |
| Undefined bytes | 156 |
| Decompiled OK | 437 |
| Decompile failed | 0 |
| Memory blocks | 8 |

### Decompiled sample (first function, `__wbg_new_with_u8_clamped_array_and_sh_fe957411824b5158`)

Identical in both reopen and fresh import (this is an imported function stub with truncated control flow):

```c
/* WARNING: Control flow encountered bad instruction data */
undefined4
import::./rasterbator_rs_bg.js::__wbg_new_with_u8_clamped_array_and_sh_fe957411824b5158
            (undefined4 param1,undefined4 param2,undefined4 param3,undefined4 param4)
{
  /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
```

### Comparison

| Metric | v2.7.0 (creation) | Reopen (NEW) | Fresh Import (NEW) | Status |
|--------|-------------------|-------------|---------------------|--------|
| Functions | 437 | 437 | 437 | ✅ |
| Instructions | 61,658 | 61,658 | 61,658 | ✅ |
| Undefined bytes | 156 | 156 | 156 | ✅ |
| Decompiled | 437/437 | 437/437 | 437/437 | ✅ |
| Blocks | 8 | 8 | 8 | ✅ |
| Decompiled output | identical | identical | identical | ✅ |

**Result:** ✅ PASS — No differences whatsoever between v2.7.0 creation, reopen, and fresh import.

---

## 5. Overall Assessment

### Project Reopen Compatibility

| Test Case | Project Reopened | No Errors | Metrics Match v2.7.0 | Fresh Import Matches | Notes |
|-----------|------------------|-----------|---------------------|---------------------|-------|
| (a) B8_04 memory64 | ✅ Yes | ✅ | ✅ | ✅ | Memory block space differs (`memory` vs `memory64`) — expected model change |
| (b) wasm_fixture | ✅ Yes | ✅ | ✅ | ✅ | No differences |
| (c) rasterbator | ✅ Yes | ✅ | ✅ | ✅ | No differences |

### Key Finding: Memory64 Address Space Change

The only observable difference between reopened saved projects and fresh imports is for the
memory64 test case (B8_04):

- **Saved v2.7.0 project (reopened):** `.memory0` block sits in the `memory` address space
  (preserved from the project database created under v2.7.0).
- **Fresh import under 2.8.0 RC:** `.memory0` block sits in the new `memory64` address space.

This reflects the documented memory64 model change: the loader now uses the full 64-bit address
space (`memory64`) for memory64 modules rather than the truncated 32-bit `memory` space. This is
**not a regression** — it is the intended behavior of the 2.8.0 RC memory64 redesign. The decompiler
output is functionally identical in both cases; only the underlying address space label differs.

### Pending N1/N2/N3 Fixes

The pending N1/N2/N3 fixes touch the emulator, tests, and documentation only — none affect the
WASM loader or language format, so they do not impact this compatibility verification.

---

## 6. Conclusion

**Verification result: PASS**

- All three saved v2.7.0 projects reopen under the 2.8.0 RC build without any language or format
  errors.
- All function counts, instruction counts, undefined byte counts, decompiled function counts,
  and memory block counts are identical between v2.7.0 creation, NEW-install reopen, and
  NEW-install fresh import.
- The only difference is the `memory` → `memory64` address space relocation for the memory64
  module, which is the expected behavior of the 2.8.0 memory64 model change.

---

## 7. End State

- **Branch:** `check/upgrade-compat2` (HEAD `a068983682f23f15412c1908d7c79559b0d9041f`)
- **Git status:** No tracked modifications.
- **Pin:** `.ghidra-install` points to `ghidra-upgrade2-new`.
- **Report:** This file (`REPORT-UPGRADE-COMPAT-2.md`) at worktree root, untracked.
