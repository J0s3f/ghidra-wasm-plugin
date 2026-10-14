# Upgrade-Compatibility Report: v2.7.0 → HEAD (8f962e5)

## Objective

Verify that projects saved by the released v2.7.0 build can be reopened and
analyzed by the current HEAD (8f962e5, "memory64-hybrid" release candidate),
and that fresh imports with HEAD produce equivalent or expected-different
results.

## Environment

| Item | Value |
|---|---|
| OLD install | Ghidra 12.1.4_PUBLIC + plugin v2.7.0 (jar 297 KB) |
| NEW install | Ghidra 12.1.4_PUBLIC + plugin HEAD 8f962e5 (jar 301 KB) |
| Headless entry | `analyzeHeadless.bat`, 2 CPU |
| Inspection script | `InspectWasm.java` (C:\temp), lists memory blocks, functions, and decompiles the top 5 by body size |
| Branch | `check/upgrade-compat` |
| Pin | `.ghidra-install` → `ghidra-upgrade-new` |

## Methodology

For each test module, three runs were performed:

1. **OLD fresh-import** — v2.7.0 plugin installed; fresh `-import` + auto-analyze + `InspectWasm.java` postScript.
2. **NEW reopen** — HEAD plugin installed; reopened the v2.7.0-saved project via `-process` + `InspectWasm.java` postScript.
3. **NEW fresh-import** — HEAD plugin installed; fresh `-import` + auto-analyze + `InspectWasm.java` postScript (new project directory).

### Test Modules

| Module | File | Memory model |
|---|---|---|
| mem64-m6402 | `M64_02_scalar_loads_stores.wasm` | 64-bit indexed (memory64) |
| i32-fixture | `wasm_fixture.wasm` | 32-bit indexed (i32) |
| rasterbator | `rasterbator_rs_bg.wasm` | 32-bit indexed (i32) |

---

## Results

### 1. mem64-m6402 (`M64_02_scalar_loads_stores.wasm`)

**Verdict: Compatible (with documented behavioral diff)**

| Metric | OLD v2.7.0 | NEW reopen | NEW fresh-import |
|---|---|---|---|
| Project opens | — | ✅ No language-version refusal | — |
| Memory block space | `memory` (truncated to 32-bit) | `memory` (preserved from saved proj) | `memory64` (new hybrid model) |
| Loader note | "SLEIGH truncates effective addresses to 32 bits" | N/A (project already loaded) | No truncation message |
| Functions | 1 (`f`) | 1 (`f`) | 1 (`f`) |
| Instructions | 28 | 28 | 28 |
| Decompiled | 1 | 1 | 1 |
| Failed | 0 | 0 | 0 |

**Decompilation: OLD v2.7.0 (32-bit truncated address model)**

```c
int export::f(wasm_struct_0 *param1)
{
  *(undefined4 *)&param1->pad_64 = 7;
  *(undefined8 *)(param1 + 1) = 8;
  *(undefined4 *)&param1[1].field_16 = 0x3fc00000;
  param1[1].pad_24 = 0;
  param1[1].field_32 = 0;
  param1[1].pad_33 = 0;
  param1[1].field_0x13 = 0;
  param1[1].field_36 = 0x40040000;
  return *(int *)&param1[1].field_40;
}
```

**Decompilation: NEW HEAD (64-bit hybrid address model)**

```c
int export::f(wasm_struct_0 *param1)
{
  longlong lVar1;
  undefined4 in_register_20000004;

  lVar1 = CONCAT44(in_register_20000004, param1);
  *(undefined4 *)(lVar1 + 0x30) = 7;
  *(undefined8 *)(lVar1 + 0x38) = 8;
  *(undefined4 *)(lVar1 + 0x40) = 0x3fc00000;
  *(undefined8 *)(lVar1 + 0x48) = 0x4004000000000000;
  return *(int *)(lVar1 + 0x50);
}
```

**Analysis:** The decompilation output differs between OLD and NEW because v2.7.0
truncated 64-bit effective addresses to 32 bits (mapping the memory into the
`memory` address space with truncated addresses), while HEAD implements a hybrid
memory64 model that preserves full 64-bit addressing via `CONCAT44` and 64-bit
offset arithmetic. The NEW reopen and NEW fresh-import produce identical
decompilation output, confirming consistency. Both outputs are semantically valid
representations of the same WASM semantics.

**Project format compatibility:** ✅ v2.7.0-saved project reopens cleanly in
HEAD with no language-version or format refusal. The saved memory block retains
the old `memory` space (not `memory64`), because the project was created with the
truncated model. A fresh import with HEAD uses the new `memory64` space.

### 2. i32-fixture (`wasm_fixture.wasm`)

**Verdict: Fully compatible (identical results)**

| Metric | OLD v2.7.0 | NEW reopen | NEW fresh-import |
|---|---|---|---|
| Project opens | — | ✅ No language-version refusal | — |
| Memory block space | `memory` | `memory` | `memory` |
| Functions | 4 (add, main, load, store) | 4 | 4 |
| Instructions | 24 | 24 | 24 |
| Decompiled | 4 | 4 | 4 |
| Failed | 0 | 0 | 0 |

**Decompilation: identical across all three runs**

```c
int export::main(int param1)
{
  int iVar1;
  iVar1 = add(7,8);
  return iVar1;
}

void export::store(undefined4 param1, undefined4 param_2)
{
  *(undefined4 *)register0x00000008 = param1;
  return;
}

int export::add(int param1, int param2)
{
  return param1 + param2;
}

int export::load(void)
{
  int in_memory_00000004;
  return in_memory_00000004;
}
```

**Analysis:** Since this module uses 32-bit indexed memory, the hybrid memory64
model in HEAD does not affect its analysis. Results are byte-for-byte identical
across OLD-fresh, NEW-reopen, and NEW-fresh-import. ✅

### 3. rasterbator (`rasterbator_rs_bg.wasm`)

**Verdict: Fully compatible (identical results)**

| Metric | OLD v2.7.0 | NEW reopen | NEW fresh-import |
|---|---|---|---|
| Project opens | — | ✅ No language-version refusal | — |
| Memory block space | `memory` | `memory` | `memory` |
| Memory block size | 1114112 | 1114112 | 1114112 |
| Functions | 437 | 437 | 437 |
| Instructions | 61658 | 61658 | 61658 |
| Decompiled | 5 | 5 | 5 |
| Failed | 0 | 0 | 0 |

**Decompilation (top function `unnamed_function_276`):** Identical across all
three runs — same variable declarations, same local struct array sizes, same
`/* WARNING: Type propagation algorithm not settling */` warning. The full
decompilation is structurally identical between OLD-fresh, NEW-reopen, and
NEW-fresh-import.

**Analysis:** This is a 32-bit memory module (no memory64 index type), so the
hybrid model change does not affect it. All function counts, instruction counts,
decompilation counts, and the first decompiled function are identical across
all three runs. ✅

---

## Summary

| Module | OLD v2.7.0 → NEW HEAD reopen | NEW fresh-import vs OLD |
|---|---|---|
| mem64-m6402 | ✅ Opens; decompilation differs (32-bit vs 64-bit) — expected behavioral change | ✅ Functional equivalence; decompiler output reflects new hybrid model |
| i32-fixture | ✅ Identical on all dimensions | ✅ Identical |
| rasterbator | ✅ Identical on all dimensions | ✅ Identical |

### Conclusion

Projects saved by the released v2.7.0 build reopen and analyze successfully under
HEAD (8f962e5) with no project-format rejection or language-version refusal.
The only observable difference is in the mem64-m6402 module, where the hybrid
memory64 model in HEAD produces different (but semantically valid) decompilation
output compared to v2.7.0's 32-bit-truncated model. This is an expected and
documented consequence of the hybrid memory64 design merged in HEAD.

**Overall verdict: PASS — upgrade is compatible.**

## Files Produced

| Log file | Description |
|---|---|
| `C:\Users\micro\AppData\Local\Temp\upgrade-projects\mem64-m6402_old.log` | OLD v2.7.0 fresh-import + InspectWasm |
| `C:\Users\micro\AppData\Local\Temp\upgrade-projects\mem64-m6402_new.log` | NEW HEAD reopen OLD-saved project + InspectWasm |
| `C:\Users\micro\AppData\Local\Temp\upgrade-projects\i32-fixture_old.log` | OLD v2.7.0 fresh-import + InspectWasm |
| `C:\Users\micro\AppData\Local\Temp\upgrade-projects\i32-fixture_new.log` | NEW HEAD reopen OLD-saved project + InspectWasm |
| `C:\Users\micro\AppData\Local\Temp\upgrade-projects\real-rasterbator_old.log` | OLD v2.7.0 fresh-import + InspectWasm |
| `C:\Users\micro\AppData\Local\Temp\upgrade-projects\real-rasterbator_new.log` | NEW HEAD reopen OLD-saved project + InspectWasm |
| `C:\Users\micro\AppData\Local\Temp\upgrade-fresh\fresh-mem64-m6402_new.log` | NEW HEAD fresh-import + InspectWasm |
| `C:\Users\micro\AppData\Local\Temp\upgrade-fresh\fresh-i32-fixture_new.log` | NEW HEAD fresh-import + InspectWasm |
| `C:\Users\micro\AppData\Local\Temp\upgrade-fresh\fresh-real-rasterbator_new.log` | NEW HEAD fresh-import + InspectWasm |
