# REPORT-H1 — section-id / duplicate-section diagnostics + 64-bit data-segment offsets

Worktree `D:\code\ghidra-wt-h1`, branch `fix/sections-i64-offsets` (base `main` @ `c3a7bc2`).
Ghidra install pinned by `test-scripts/.ghidra-install`: `C:\Users\micro\AppData\Local\Temp\opencode\ghidra-h1`.
All measurements below were taken after `test-scripts/build-install.ps1` had just been run in this checkout.

Two independent loader-correctness items:

* **B1** (from `REPORT-HARD.md`, finding B4) — out-of-range section ids and duplicate non-custom
  sections were dropped **silently**.
* **B2** (from `REPORT-N.md` §7 item 8) — an active data segment with a 64-bit (`i64.const`) offset
  was **dropped** before the loader placed its bytes.

---

## 1. B1 — section-id / duplicate-section diagnostics

### 1.1 Root cause

`WasmSection.createSection()` read the section id as an unsigned byte and, for any id outside the
modelled enum, returned `null`:

```java
if(id >= WasmSectionId.values().length)
    return null;
```

`WasmModule`'s constructor then did `if (section == null) continue;`, so the malformed section was
skipped with **no diagnostic at all** — the module imported as an empty program (`funcs=0`). Separately,
duplicate non-custom sections were collapsed by `sectionMap.put(...)`, which silently overwrote the
earlier section. Both are malformed WebAssembly (core spec, *binary/modules*: an id outside the known
set is a *malformed section id*; a non-custom section may appear at most once).

### 1.2 Fix

`src/main/java/wasm/format/sections/WasmSection.java` — an out-of-range id fails the import:

```java
if (id >= WasmSectionId.values().length) {
    throw new IOException("Unsupported section id 0x" + Integer.toHexString(id)
            + " at file offset 0x" + Long.toHexString(sectionOffset));
}
```

`src/main/java/wasm/format/WasmModule.java` — a duplicate non-custom section fails the import, and an
odd section order is only warned about. The duplicate check keys on the **raw section id** (peeked
with a read/rewind) rather than on the parsed `WasmSection`, because a known-but-unmodelled id
(`SEC_DATACOUNT`, id 12) produces no section object and would otherwise escape the check (the negative
suite contains exactly this case, `binary.116`):

```java
long sectionStart = reader.getPointerIndex();
int rawId = reader.readNextUnsignedByte();
reader.setPointerIndex(sectionStart);
WasmSection section = WasmSection.createSection(reader);
if (rawId != 0 && !seenNonCustom.add(rawId)) {
    throw new IOException("Duplicate section " + name + " (id " + rawId
            + ") at file offset 0x" + Long.toHexString(sectionStart)
            + ": a non-custom section may appear at most once");
}
...
int rank = canonicalRank(section.getId());
if (rank < lastRank) {
    Msg.warn(WasmModule.class, "Section " + section.getId() + " ... is out of the canonical section "
            + "order (it follows " + lastOrdered + "); tolerated by this loader (see REPORT-H1.md)");
}
```

Design points (verified against the real code, not just the `REPORT-HARD.md` sketch):

* The id is a single byte in the binary format, so `readNextUnsignedByte()` is correct.
* `SEC_DATACOUNT` (id 12) is *in* the enum but has no section class; the switch `default` returns
  `null` and `WasmModule` still skips it. This is deliberate: the data-count section is common in
  real modules and the loader does not need its content. It is a **known** id, so the new range check
  does not fire for it. (The task's "any id the plugin does not model" is therefore read as "any id
  outside the known id set"; the enum models ids 0..13.)
* `canonicalRank()` encodes the core-spec order, with the exception-handling tag section between the
  memory and global sections and the data-count section between element and code. The rank is used
  **only** to warn; it never rejects.
* Omitted sections are not checked at all (there is nothing to warn about), and an odd order is
  tolerated — matching the "lenient for real-world modules" requirement.

### 1.3 Evidence (before / after)

`probes_sections_i64.py` (new file, see §3) emits the section probes. Before/after import of the same
12 modules against the pinned install:

Before (unmodified `main` build; every malformed module **accepted silently**):

```
PROBE H1_02_unknown_section_id.wasm      funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0
PROBE H1_03_duplicate_type_section.wasm  funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0
PROBE H1_04_duplicate_code_section.wasm  funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0
# (no "Import failed" line for any of them; H1_04 additionally raised caught
#  IndexOutOfBoundsException from the pre-/signature/name analyzers)
```

After:

```
Import failed for file: .../H1_02_unknown_section_id.wasm
  IOException: Unsupported section id 0x2a at file offset 0x8
Import failed for file: .../H1_03_duplicate_type_section.wasm
  IOException: Duplicate section SEC_TYPE (id 1) at file offset 0xe: a non-custom section may appear at most once
Import failed for file: .../H1_04_duplicate_code_section.wasm
  IOException: Duplicate section SEC_CODE (id 10) at file offset 0x1b: a non-custom section may appear at most once
```

Out-of-order (tolerated, warning only) — `H1_05` still imports, and the log carries:

```
WARN  SEC_TYPE (id 1) at file offset 0xd is out of the canonical section order (it follows SEC_LINEARMEMORY);
      tolerated by this loader (see REPORT-H1.md) (WasmModule)
WARN  SEC_FUNCTION (id 3) at file offset 0x14 is out of the canonical section order (it follows SEC_TYPE); ...
PROBE H1_05_out_of_order_sections.wasm funcs=1 instrs=3 undefined_bytes=0 decompiled=1 decompile_failed=0
```

(The warning also fires on a number of pre-existing probes whose generators emit sections in a
non-canonical order — see §5 — which is harmless: it does not affect any recorded metric.)

---

## 2. B2 — 64-bit data-segment offsets

### 2.1 Root cause

`WasmDataSegment.getMemoryOffset()` returned `offsetExpr.asI32()`, and `ConstantExpression.asI32()`
only reads an `I32_CONST`. An `i64.const` offset (or **any** `global.get` offset) therefore returned
`null`, and `WasmLoader.loadDataSegments()` did `if (offset == null) continue;` — the segment was
dropped before any address was computed, so the bytes never landed (`REPORT-N.md` §7 item 8 measured
exactly this: "the segment is skipped before the loader sees an offset").

### 2.2 Fix

* `ConstantExpression.asConstValue()` — returns the value for **both** `i32.const` and `i64.const`
  (an i64 value ≥ 2^63 comes back negative, which the existing `getMemoryAddress` clamp handles).
* `WasmDataSegment.getMemoryOffset()` now uses `asConstValue()`; new `getOffsetGlobalIndex()`,
  `isActive()` and `hasUnknownOffset()` accessors.
* `WasmLoader.loadDataSegments()` resolves the offset via a new `resolveDataSegmentOffset()`:
  * `i32.const` / `i64.const` → used directly (i32 path identical to before);
  * `global.get` of a **defined, immutable i64** global whose initializer is a constant → the 8
    initializer bytes are read little-endian (`WasmGlobalEntry.asBytes(module)` already returns the
    right bytes, including for an extended-const fold);
  * `global.get` of an **imported** global (value unknown until instantiation) or an unparsed
    expression → `null` → the segment is **skipped with a warning**, never a crash.
* Address handling is unchanged: `getMemoryAddress()` maps memory N to `N*MEMORY_STRIDE + offset` and
  clamps anything ≥ 4 GiB to `RAM_MAX_ADDRESS` (0xffffffff) with a warning. Above 4 GiB the bytes
  therefore cannot be represented in the 32-bit `ram` space; the placement is attempted at the clamp
  address and its `MemoryAccessException` is caught and logged (`Failed to initialize memory ...`),
  so the module still imports.

### 2.3 Evidence (before / after, `DumpMemory.java`)

`test-scripts/DumpMemory.java` (new helper) prints every `.memoryN` block and every non-zero byte run
in it. Before the fix all these blocks were all-zero (segment dropped); after the fix:

```
H1_06_i64_const_offset.wasm     MEMDATA .memory0 +0x10   (ram:00000010) len=13  48 31 2d ... "H1-DATA-64BIT"
H1_07_i64_const_offset_4k.wasm  MEMDATA .memory0 +0x1000 (ram:00001000) len=18  "B2-NONZERO-OFFSET!"
H1_08_i64_global_offset.wasm    MEMDATA .memory0 +0x40   (ram:00000040) len=17  "GLOBAL-I64-OFFSET"
H1_09_unresolved_global_offset  (no MEMDATA — imported global, skipped with a warning)
H1_10_mem1_i64_offset.wasm      MEMDATA .memory1 +0x20   (ram:10000020) len=9   "MEM1-DATA"
H1_11_i32_control.wasm          MEMDATA .memory0 +0x18   (ram:00000018) len=10  "CTRL-32BIT"      (unchanged)
H1_12_i64_offset_above_4gib     (no MEMDATA — clamped to ram:ffffffff and logged)
```

Unresolved / above-4-GiB diagnostics (after):

```
WARN  Skipping active data segment 0 (memory 0): its offset expression could not be resolved
      statically (see REPORT-H1.md) (WasmLoader)                                  # H1_09
WARN  Address memidx=0 offset=0x100000000 does not fit the 32-bit `ram` address space;
      clamping to 0xffffffff (memory64 addresses/data above 4 GiB are not modelled; see REPORT-N.md)
ERROR Failed to initialize memory 0 with data segment 0 at ram:ffffffff ...          # H1_12
```

Every `H1_06`–`H1_12` module keeps `funcs=1 instrs=4 undefined_bytes=0 decompiled=1 decompile_failed=0`.

### 2.4 32-bit behaviour

For an `i32.const` offset the code path (`asConstValue()` on an `I32_CONST`) returns exactly what
`asI32()` returned; `H1_11` (32-bit control) shows identical placement before and after
(`CTRL-32BIT` at `ram:0x18`). A `global.get` offset of an **i32** global was already dropped by the
old code and is deliberately **left** dropped (see §5, open question) so that 32-bit-memory placement
is byte-for-byte unchanged.

---

## 3. Probes (`test-scripts/probes_sections_i64.py`) — 12 new probes

| probe | shape | result |
| --- | --- | --- |
| `H1_01_control_valid.wasm` | canonical valid module | import_ok `funcs=1 instrs=3 ub=0 dec=1/0` |
| `H1_02_unknown_section_id.wasm` | section id 0x2a | **import_failed** `Unsupported section id 0x2a at file offset 0x8` |
| `H1_03_duplicate_type_section.wasm` | two type sections | **import_failed** `Duplicate section SEC_TYPE (id 1) ...` |
| `H1_04_duplicate_code_section.wasm` | two code sections | **import_failed** `Duplicate section SEC_CODE (id 10) ...` |
| `H1_05_out_of_order_sections.wasm` | memory before type | import_ok + ordering warning |
| `H1_06_i64_const_offset.wasm` | memory64, `i64.const 0x10` | import_ok, bytes at `ram:0x10` |
| `H1_07_i64_const_offset_4k.wasm` | memory64, `i64.const 0x1000` | import_ok, bytes at `ram:0x1000` |
| `H1_08_i64_global_offset.wasm` | memory64, defined i64 global = 0x40 | import_ok, bytes at `ram:0x40` |
| `H1_09_unresolved_global_offset.wasm` | memory64, imported i64 global | import_ok, segment skipped + warning |
| `H1_10_mem1_i64_offset.wasm` | memory 1 is memory64, `i64.const 0x20` | import_ok, bytes at `ram:0x10000020` |
| `H1_11_i32_control.wasm` | 32-bit memory, `i32.const 0x18` | import_ok, bytes at `ram:0x18` (unchanged) |
| `H1_12_i64_offset_above_4gib.wasm` | memory64, `i64.const 0x100000000` | import_ok, clamped + logged |

All 9 valid probes: `undefined_bytes=0`, `decompiled=1`, `decompile_failed=0`.
`test-scripts/DumpMemory.java` is the small dump script used to verify the placements.

---

## 4. CI gate and regression

### 4.1 Commands (exact)

```powershell
$env:GHIDRA_INSTALL_DIR = "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-h1"
& D:\code\ghidra-wt-h1\test-scripts\build-install.ps1
& .\test-scripts\check-local.ps1 -OutDir "$env:TEMP\ci-h1" -Update `
    -RealModule "D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm"
& .\test-scripts\check-local.ps1 -OutDir "$env:TEMP\ci-h1" `
    -RealModule "D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm"
```

(`check-local.ps1` rebuilds+reinstalls before each run; it requires `GHIDRA_INSTALL_DIR`, which must
be set to the pinned folder. Both runs rebuilt and installed immediately before measuring.)

### 4.2 Output (tails)

`-Update`:

```
== running 148 probe(s) ==
SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0
SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156
updated D:\code\ghidra-wt-h1\test-scripts\expected-results.json: 140 probe(s) with metrics, 8 expected import failure(s)
```

Plain (verify):

```
== running 148 probe(s) ==
SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0
SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156
probes: 140 imported, 8 import failure(s); baseline has 148
OK: every probe matches the recorded baseline.
EXIT=0
```

**Real-module regression: exactly `SUMMARY functions=437 decompiled=437 failed=0 instructions=61658`**
(`undefined_bytes=156`, unchanged).

### 4.3 Every changed baseline entry

`probe_count` changed `136 -> 148`; the only other changes are the **12 new `H1_*` entries** (9
`import_ok:true` with their metrics, 3 `import_ok:false`). **No pre-existing probe's metrics changed.**
The three new expected-import-failure entries:

| probe | recorded |
| --- | --- |
| `H1_02_unknown_section_id.wasm` | `import_ok=false` |
| `H1_03_duplicate_type_section.wasm` | `import_ok=false` |
| `H1_04_duplicate_code_section.wasm` | `import_ok=false` |

New passing entries: `H1_01` (1/3/0/1/0), `H1_05` (1/3/0/1/0), `H1_06` (1/4/0/1/0), `H1_07`
(1/4/0/1/0), `H1_08` (1/4/0/1/0), `H1_09` (1/4/0/1/0), `H1_10` (1/4/0/1/0), `H1_11` (1/4/0/1/0),
`H1_12` (1/4/0/1/0) — order `funcs/instrs/undefined_bytes/decompiled/decompile_failed`.

`git diff test-scripts/expected-results.json`: `97 insertions(+), 1 deletion(-)` (the deletion is the
`probe_count` line).

### 4.4 Corpus (real-world modules)

```powershell
& .\test-scripts\corpus-sweep.ps1 -CorpusDir "$env:TEMP\ci-h1\corpus" `
    -Only minrepro_a_i32,rust_plain,rust_simd128 -OutMd "$env:TEMP\ci-h1\corpus-after.md" `
    -WorkDir "$env:TEMP\ci-h1\corpus-work"
```

The three modules committed offline (the other 12 need network) match `corpus-RESULTS.md` exactly:

| module | funcs | instrs | undef | decomp | status |
| --- | ---: | ---: | ---: | ---: | --- |
| `minrepro_a_i32` | 1 | 1 | 1 | 1/0 | UNDEFINED-BYTES (pre-existing, unchanged) |
| `rust_plain` | 72 | 8691 | 0 | 72/0 | OK |
| `rust_simd128` | 2 | 29 | 0 | 2/0 | OK |

Only difference: `rust_simd128` now shows `warn=1` — the **pre-existing DWARF** message
`WASM DWARF: no source line entries could be mapped to the program` (the recorded baseline was
generated in a different worktree/run); it is not produced by this change and no core metric moved.

---

## 5. Open questions / notes for the integrator

1. **32-bit `global.get` data offsets stay dropped.** An active data segment of a *32-bit* memory
   whose offset is `global.get` of an i32 global was already dropped before this change and is still
   dropped (only i64 global.get offsets are resolved). This was chosen deliberately so 32-bit-memory
   placement is byte-for-byte unchanged, per the task. Fixing it would be an easy follow-up in the
   same helper (`resolveDataSegmentOffset`) and is a genuine (already-existing) limitation.
2. **`i64.const` offset in a 32-bit memory.** Such a module is malformed (the offset type must match
   the memory's index type). `getMemoryOffset()` now returns the value, so the segment is placed
   (truncated into `ram`) instead of being dropped. Valid 32-bit modules are unaffected.
3. **`SEC_DATACOUNT` (id 12)** is a known id but has no section class; it is still skipped silently.
   This keeps common real modules (`data count` before `code`) importing unchanged.
4. **Ordering warnings are noisy on some existing probes** (e.g. the frozen probes that emit
   `function` before `type`, or `export` before `element`). They are warnings only and change no
   metric, but if the integrator prefers a quieter log the `canonicalRank` warning can be dropped
   entirely — the task allows "a warning at most".
5. **Above 4 GiB** the address is clamped to `ram:ffffffff`, so the bytes are not represented; the
   placement fails with a caught `MemoryAccessException` that is logged. This is the documented
   `ram`-space truncation rule (`REPORT-N.md`), unchanged by this work — the fix only makes the
   *attempt* happen (and the warning appear) instead of dropping the segment before the offset is
   ever read.
6. **No un-owned file needed changing.** Everything landed in the owned files; `WasmGlobalEntry` /
   `WasmGlobalSection` are used read-only (`asBytes`, `getGlobalType`).

### Credits / files

* Sources: `WasmSection.java`, `WasmModule.java`, `ConstantExpression.java`, `WasmDataSegment.java`,
  `WasmLoader.java` (data-segment placement only).
* Tests: `test-scripts/probes_sections_i64.py`, `test-scripts/DumpMemory.java`,
  `test-scripts/expected-results.json` (regenerated only via `check-local.ps1 -Update`).
