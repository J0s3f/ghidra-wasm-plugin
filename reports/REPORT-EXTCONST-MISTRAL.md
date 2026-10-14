# REPORT-EXTCONST-MISTRAL.md — Extended-const `Data markup conflict` warning

Worktree/branch: `ghidra-wt-extconst-mistral` @ `fix/extconst-datamarkup-mistral`.
Pinned Ghidra install: `C:\Users\micro\AppData\Local\Temp\opencode\ghidra-extconst-mistral`
(recorded in `test-scripts/.ghidra-install`; `build-install.ps1`/`run_probes.ps1` refuse any other).
Scope: MODERN_WASM_GAPS.md §2.3 row "Extended-const `Data markup conflict` warning on probes
`22`-`24`/`27`". Verdict: **real defect (wrong `.module` markup), fixed**.

---

## 1. The warning, reproduced

Importing the probes headlessly with the pinned install logs, from
`wasm.WasmLoader.createData` (`src/main/java/wasm/WasmLoader.java:333`), a caught
`ghidra.program.model.util.CodeUnitInsertionException`:

```
WARN  Data markup conflict at ram:80000022 (WasmLoader) ... CodeUnitInsertionException: Could not create Data at address ram:80000022
WARN  Data markup conflict at ram:80000024 (WasmLoader) ... CodeUnitInsertionException: Insufficent memory at address ram:80000024 (length: 14 bytes)
```

`CODE_BASE = 0x80000000` (`WasmLoader.java:82`), so these are file offsets inside the `.module`
block (the whole-file image in the `ram` space):

| Probe | Warning address | File offset | Byte at that offset | Exception |
| --- | --- | --- | --- | --- |
| `22_extconst_two_ops` | `ram:80000022` | 0x22 (34) | `07` = export-section id byte | `Could not create Data` |
| `27_extconst_data_offset` | `ram:80000024` | 0x24 (36) | `0b` = data-section id byte | `Insufficent memory (length: 14 bytes)` |

Probes `23_const_f32_imm_0b` and `24_const_f64_imm_0b` (single-instruction `f32`/`f64.const`)
produce **no** warning. So the §2.3 row's "`22`-`24`/`27`" over-lists: the warning fires only on
probes whose global/data initializer is a **multi-instruction** constant expression.

Running the **full 210-probe suite** before the fix (`test-scripts/run_probes.ps1`) shows the
warning is broader than the §2.5 probes — **8** occurrences, all with a multi-instruction
const initializer:

| Probe | Address | Kind | Initializer |
| --- | --- | --- | --- |
| `19_extended_const_global` | `ram:80000013` | folded | `i32.const 1; i32.const 2; i32.add` |
| `22_extconst_two_ops` | `ram:80000022` | folded | `i32.const 1; i32.const 2; i32.add` |
| `27_extconst_data_offset` | `ram:80000024` | folded | `i32.const 1; i32.const 2; i32.add` (data offset) |
| `B07_const_i32_add` | `ram:8000001e` | folded | `i32.const 10; i32.const 32; i32.add` |
| `B08_const_i64_add` | `ram:80000020` | folded | `i64.const 100; i64.const 200; i64.add` |
| `B09_const_i32_mul` | `ram:8000001e` | folded | `i32.const 6; i32.const 7; i32.mul` |
| `B14_const_unknown_gc` | `ram:80000022` | unparsed (UNKNOWN) | `i32.const 0; struct.new 0` |
| `B25_valtype_exnref_global` | `ram:8000001c` | unparsed (UNKNOWN) | `ref.null exnref` (`D0 69`) |

## 2. The emitting code path, and why it fires

`WasmLoader.doLoad` (`WasmLoader.java:1144`) creates the `.module` block (whole file image at
`ram:CODE_BASE`, line 1152), marks the header (line 1153), then marks each section (lines
1155-1168):

```java
createData(program, program.getListing(),
        moduleBlock.getStart().add(section.getSectionOffset()), section.toDataType());
```

`WasmSection.toDataType()` (`WasmSection.java:107`) = `id` (BYTE) + `size` (LEB128) + the section
content. `getSectionOffset()` is the offset of the section-id byte. The content embeds a
`ConstantExpression` for any initializer:

* global section → `WasmGlobalEntry.toDataType()` → `builder.add(expr, "expr")`
  (`WasmGlobalEntry.java:59`);
* data section → `WasmDataSegment.toDataType()` → `builder.add(offsetExpr, "offset")`
  (`WasmDataSegment.java:125`).

`WasmLoader.createData` (`WasmLoader.java:324`) only creates data when none exists or the existing
type is not equivalent; otherwise it calls
`DataUtilities.createData(..., ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA)`, which throws
`CodeUnitInsertionException` when the slot holds defined data of a different type
("Could not create Data") or the type would overrun the block ("Insufficient memory"). The catch
(line 332) logs `Data markup conflict at <addr>`.

**Root cause** — `ConstantExpression.toDataType()` (`ConstantExpression.java:682`).
`rawBytes` is the full expression **including** the terminating `end` (`0x0B`); `readExpression`
always ends on `end`, so `rawBytes` always ends with `0x0B`. The structure is built as:

```
opcode            (1 byte, the first byte)
<array>           folded: "extended_const_expr"  = rawBytes.length - 1 bytes  ← INCLUDES the end byte
                  unknown: "remaining_bytes"      = rawBytes.length - 1 bytes  ← INCLUDES the end byte
end_opcode        (1 byte, added whenever the last raw byte is 0x0B)
```

For a **folded** extended-const expression (multi-instruction `i32`/`i64.const` + `add`/`sub`/`mul`,
`foldExtendedConst` sets `folded=true`, `ConstantExpression.java:548`) and for an **UNKNOWN**
(unparsed) expression, the array length `rawBytes.length - 1` already includes the `end` byte, and
`end_opcode` then adds it **again**: structure length = `1 + (len-1) + 1 = len + 1`. The `end` byte
is double-counted, so the structure is **one byte too long**.

(The single-instruction known cases — `I32_CONST`, `F32_CONST`, `V128_CONST`, `REF_NULL`, … — are
correct, because their `value` field holds only the immediate, excluding the `end` byte, and
`end_opcode` adds it once. That is why probes 23/24 never warned.)

**Consequence.** The enclosing section's structure is 1 byte too long:

* When the section is **followed by another section**, its structure swallows the next section's
  id byte. The loop then tries to create the next section's structure at that byte, finds it
  already defined (part of the previous structure) → `Could not create Data at ram:<next section
  id byte>`, and that whole section is left as raw `undefined` bytes — **undissected**.
  (Probes 19, 22, B07, B08, B09, B14, B25.)
* When the section is **last** in the file, its +1 structure overruns the `.module` block →
  `Insufficient memory at ram:<section id byte> (length: <section size + 1> bytes)`, and the section
  is left as raw `undefined` bytes — **undissected**. (Probe 27, the `.data` section.)

So "what is in conflict" is **overlapping markup**: a section structure mis-sized by +1 colliding
with the following section's markup (or overrunning the block when last).

## 3. Decision: real defect (wrong markup); placed bytes were already correct

Evidence gathered with a scratch Ghidra script `DumpModuleListing.java` (prints every `.module`
code unit with its data type + bytes, the `.global*` data, and `.memory0` non-zero runs), run
headlessly per probe against the pinned install.

**Placed bytes / offsets are correct (unchanged by the bug):**

* Probe 22: `.global0` holds `undefined4` = `03 00 00 00` — the correctly folded value `1 + 2 = 3`.
* Probe 27: `.memory0` non-zero run `MEMRUN +0x3 len=2 bytes=[68 69]` — the data segment
  ("hi") lands at linear-memory offset **3** (the folded `1 + 2`), exactly as §2.5 pins.

The folding (`foldExtendedConst`) and placement (`asBytes`, `resolveDataSegmentOffset`,
`loadDataToMemory`) never used `toDataType()`, so the actual bytes/offsets were never wrong.

**The `.module` structural markup is wrong (the defect):**

* Probe 22, before: `.global` DATA `len=12` `06 09 01 7f 00 41 01 41 02 6a 0b 07` — it swallowed
  the export-section id byte `07` at +0x22. The `.export` section was then 11 × `undefined`
  (+0x23..+0x2c) — **not dissected**.
* Probe 27, before: the `.data` section (+0x24..+0x30, 13 bytes `0b 0b 01 00 41 01 41 02 6a 0b
  02 68 69`) was 13 × `undefined` — **not dissected** (structure creation failed, "length: 14
  bytes").
* Probe 23 (contrast, single-instruction `f32.const`): `.global` DATA `len=11`, `.export` DATA
  `len=11`, no warning, `.global0` = `float 0b 00 00 00`. Correct and unaffected.

A whole section being left as raw `undefined` in the plugin's structural dissection of the file
(and the preceding section claiming a foreign byte) is **wrong markup**, not benign cosmetic
re-markup. Real defect → fix.

## 4. The fix (minimal)

`src/main/java/wasm/format/sections/structures/ConstantExpression.java`, `toDataType()`: in the
`folded` branch and the `UNKNOWN`/`default` branch, the raw-byte array must hold the bytes
**strictly between** the leading `opcode` and the trailing `end` (which `end_opcode` already
represents). Changed `rawBytes.length - 1` → `rawBytes.length - 2`, and the guard `> 1` → `> 2`,
in both branches. `StructureBuilder.addArray` is a no-op for `numElements <= 0`, and `rawBytes`
always ends with `0x0B`, so the structure is now exactly `1 + (len-2) + 1 = len` bytes. The
single-instruction known cases are untouched.

No gate semantics changed; no new rejection added (policy: keep accepting spec-invalid modules).
The fix only changes `.module` structural markup lengths; it does not touch function-body
decoding, folding, or placement. `undefined_bytes` is function-body-scoped
(`test-scripts/WasmFeatureReport.java:26-35`), so no pinned probe metric can shift.

## 5. Verification on the target probes (after the fix)

Re-imported probes 22/23/27 headlessly with `DumpModuleListing.java` against the rebuilt pinned
install:

* **No** `Data markup conflict` warning on any of them.
* Probe 22: `.global` DATA `len=11` `06 09 01 7f 00 41 01 41 02 6a 0b`; `.export` DATA `len=11`
  `07 09 02 01 66 00 00 01 67 03 00` (now dissected); sections tile to 51 bytes; `.global0`
  still `03 00 00 00`.
* Probe 27: `.data` DATA `len=13` `0b 0b 01 00 41 01 41 02 6a 0b 02 68 69` (now dissected);
  `.memory0` still `+0x3 [68 69]`.
* Probe 23: unchanged (`.global` 11, `.export` 11, `.global0` = `float 0b 00 00 00`).

## 6. Exact commands

```powershell
# 0. worktree + pinned install (test-scripts/.ghidra-install -> ghidra-extconst-mistral)
cd C:\Users\micro\.local\share\opencode\worktree\b64b36\ghidra-wt-extconst-mistral

# 1. build this worktree into the pinned install
.\test-scripts\build-install.ps1

# 2. generate the probes
python test-scripts\gen_feature_probes.py $env:TEMP\extconst-repro\probes   # 22-27
# (B07-B15/B25 come from test-scripts/probes_types.py)

# 3. reproduce: import 22,23,24,27 + WasmFeatureReport, capture the log
#    (see scratch repro.ps1; analyzeHeadless <proj> ProbeRun -import <each .wasm> \
#       -scriptPath test-scripts -postScript WasmFeatureReport.java -deleteProject)

# 4. per-probe evidence: analyzeHeadless <proj> Dump -import <probe.wasm> \
#       -scriptPath <scratch> -postScript DumpModuleListing.java -deleteProject

# 5. full 210-probe suite, BEFORE the fix (warning scope)
.\test-scripts\run_probes.ps1 -OutDir $env:TEMP\extconst-before

# 6. full gate, AFTER the fix (build + 210 probes + fixture + real module)
.\test-scripts\check-local.ps1 -RealModule `
    C:\Users\micro\AppData\Local\Temp\opencode\corpus\rasterbator_rs_bg.wasm
```

The real module `rasterbator_rs_bg.wasm` is an external payload (not committed); it was copied
read-only from the manifest URL `D:\code\Rasterbator\analysis\reference\site\assets\` into the
scratch corpus dir and its sha256 verified against `test-scripts/corpus/manifest.json`
(`6c90739c94dc0bc5bd3cb037feb33cd8b13d13f437fd21d4bd0a0247dd556138`, 179782 bytes).

## 7. Gate results (observed)

Full gate `.\test-scripts\check-local.ps1 -GhidraDir <pinned> -RealModule
<corpus>/rasterbator_rs_bg.wasm`, run against the rebuilt pinned install (fixed extension):

* **exit 0** (`GATE_EXIT=0`, ~11.5 min).
* Build: `BUILD SUCCESSFUL`; installed `ghidra-wt-extconst-mistral` (jar 299064 bytes); stamp = this worktree.
* Probe suite: `probes: 192 imported, 18 import failure(s); baseline has 210` →
  `OK: every probe matches the recorded baseline.` (check-results.py exit 0).
* **`Data markup conflict` warnings across all 210 probes: 0** (was **8** before the fix:
  probes `19`, `22`, `27`, `B07`, `B08`, `B09`, `B14`, `B25`).
* §2.5 pin intact — probes `22`-`27` all `funcs=1 instrs=2 undefined_bytes=0 decompiled=1 decompile_failed=0`.
* Fixture: `SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0`
  (matches `expected-results.json`).
* Real module `rasterbator_rs_bg.wasm`: `SUMMARY functions=437 decompiled=437 failed=0
  instructions=61658 undefined_bytes=156`, 0 `DECOMPILE FAIL` — exactly the pinned
  `437/437/0/61658/156`.

Fixture-validity gate (`check-fixture-validity.py --generate --probes <dir> --wabt
<wabt-1.0.42/bin>`, offline wabt): **exit 0** — `probes: 210  valid: 125  wabt-gap: 55
unsupported: 17  invalid: 13` → `OK: every probe matches the recorded fixture classification
(fixture-validity.json).` Unchanged by this fix (no probe bytes or generators were touched).

Note: the first gate attempt died mid-probe-suite (the analyzeHeadless JVM exited at probe
~187/210, during `SROA03`'s `WasmFeatureReport`, with no OOM/crash signature and ~10 GB system
RAM free) — a borderline cumulative-memory flake of the 210-program single-project import under
the 1500M heap on this shared box, unrelated to the fix (the changed probes `19`/`22`/`B07`-…
import early and cleanly; the single-instruction probes `23`/`24` never warned). The re-run
completed green.

## 8. Open items

* Degenerate empty initializer (`rawBytes = [0x0B]`, length 1) would still size 2; it is invalid
  wasm and not exercised by any probe — left as-is (the loader stays lenient; no rejection added).
* The `.module` structural view is now correct for folded/unparsed initializers; no probe-level
  assertion captures the warning itself (it is a loader log line, not a metric), so the regression
  guard is the absence of `Data markup conflict` in the probe log plus the corrected section
  structures documented in §5.
* (Observation, pre-existing, out of scope for this fix.) MODERN_WASM_GAPS.md §2.4/§6.5 prose
  still says "204 probes (… 121 valid / 53 wabt-gap / 17 unsupported / 13 invalid)", but the suite
  and both machine-checked baselines are at **210** probes (192 imported + 18 expected import
  failures; fixture-validity `125 / 55 / 17 / 13`). The machine-checked `expected-results.json`
  (`probe_count: 210`) and `fixture-validity.json` are authoritative and both gates pass against
  them; the prose counts are simply stale. Left untouched here (only the §2.3 row was in scope).
