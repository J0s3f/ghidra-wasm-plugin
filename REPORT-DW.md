# REPORT-DW.md — re-enable DWARF source line-info import for wasm

Roadmap item 9 of `MODERN_WASM_GAPS.md`. Branch `feat/dwarf-lineinfo` (base `aa656ce`).

Files touched (only files this workstream owns):

| File | Change |
| --- | --- |
| `src/main/java/wasm/analysis/WasmDWARFAnalyzer.java` | rewritten: types via stock analyzer, source-line import done here with a wasm address fixup |
| `test-scripts/make_dwarf_fixture.ps1` | new; regenerates the DWARF fixtures (~1.5 KB / ~4.8 KB) |
| `test-scripts/DumpSourceMap.java` | new; headless evidence dump of the source map (+ decompiled C) |
| `REPORT-DW.md` | new; this report |

No other source file was modified (`git diff --stat` = `WasmDWARFAnalyzer.java | 327 +++--`).
No change to `WasmLoader.java` is required; see §6.

---

## 1. Root cause (two independent defects)

### 1.1 Wrong address base — the reason there were *no* lines

A wasm DWARF line table does **not** store program addresses. It stores code addresses as
offsets **relative to the start of the code section's contents** (the byte holding the function
count). For the fixtures this was verified byte-for-byte:

| function | code-section-relative offset in `.debug_line` | `WasmCodeEntry.getOffset()` (file offset) | code-section content start |
| --- | --- | --- | --- |
| `add_three` | `0x2` | `0x77` | `0x75` |
| `mixup` | `0x46` | `0xbb` | `0x75` |
| `loopsum` | `0x29` | `0x9e` | `0x75` |

The loader maps the whole module image at `WasmLoader.CODE_BASE = 0x80000000` and places a
function at `CODE_BASE + WasmCodeEntry.getOffset()` (a file offset), so the line-table offset `A`
must become `CODE_BASE + codeSectionContentStart + A`. Ghidra's DWARF importer converts line
addresses with

```java
// ghidra.app.util.bin.format.dwarf.DWARFProgram
public Address getCodeAddress(long offset) {
    return program.getAddressFactory().getDefaultAddressSpace()
        .getAddress(offset + programBaseAddressFixup, true);
}
```

and `programBaseAddressFixup` defaults to `0` and is **never set by anything in Ghidra**. So with
the plugin as shipped every line-table offset landed at `ram:0x0..0xNNNN`, i.e. inside
`.memory0` (which the loader marks non-executable) or in no block at all. `DWARFImporter`
(line 278) tested `getExecuteSet().contains(addr)`, failed, and silently dropped every row —
hence "DWARF types import works but source lines do not".

### 1.2 Unresolved line-table relocations — the `AddressOutOfBoundsException`

`wasm-ld` leaves `.debug_line` addresses at `0xffffffff` for CUs that were garbage-collected
(the pre-compiled `core` CUs get their `R_WASM_FUNCTION_OFFSET_I32` relocations pinned to `-1`).
Ghidra's line-program executor keeps *accumulating* `DW_LNS_advance_pc` on top of `0xffffffff`,
producing 33-bit values. The first such row makes `getCodeAddress()` call
`ram.getAddress(offset, true)` with an offset above the 32-bit space, which throws — and that
call in `DWARFImporter.addSourceLineInfo()` and in the stock `DWARFLineInfoSourceMapScript` is
**not** inside a try/catch, so it aborts the whole DWARF import (the modal error in the GUI).

Reproduced exactly with the stock Ghidra script on a plain `rustc --crate-type=cdylib` module
(`out/big/fixture_dwarf.wasm`), i.e. with `programBaseAddressFixup == 0`:

```
SCRIPT ERROR: ghidra.program.model.address.AddressOutOfBoundsException:
  Offset must be between 0x0 and 0xffffffff, got 0x100000002 instead!
    at DWARFLineInfoSourceMapScript.addSourceLineInfo(DWARFLineInfoSourceMapScript.java:153)
    at DWARFLineInfoSourceMapScript.run(DWARFLineInfoSourceMapScript.java:69)
```

`0x100000002 == 0xffffffff + 3`: this is the exact value quoted in the disable comment
(“33-bit addresses (`0x1_0000_0002…`)”). The commit that disabled line info is
`486f624 Disable DWARF source line-info import to fix AddressOutOfBounds error` (emmanuele,
2026-07-17); its *cause* analysis (“wasm code lives at synthesized 33-bit addresses”) is a
misdiagnosis — `WasmLoader` already used `CODE_BASE = 0x80000000` then. The 33-bit value comes
from the DWARF data itself.

---

## 2. The fix (route taken: supported API)

`WasmDWARFAnalyzer` now:

1. keeps the stock analyzer for **types** (`setImportDataTypes(true)`, `setImportFuncs(false)`,
   `setOutputSourceLineInfo(false)`) — unchanged behaviour; and
2. after `super.added(...)`, runs its **own** line-info pass using Ghidra's public
   `DWARFProgram.setProgramBaseAddressFixup(long)`. This is the documented hook for exactly this
   case (“necessary if the program's built-in base address is overridden at import time”).

The fixup is `CODE_BASE + codeSectionContentStart`, where the content start comes from the
loaded module:

```java
WasmModule module = WasmAnalysis.getState(program).getModule();
WasmSection code = module.getSection(WasmSectionId.SEC_CODE);
long contentStart = code.getSectionOffset() + code.getSectionSize() - code.getContentSize();
long fixup = WasmLoader.CODE_BASE + contentStart;
```

`candidateFixups()` returns `{CODE_BASE + contentStart, CODE_BASE}`; the first candidate that
yields ≥1 executable entry wins, so a producer that emits module-file offsets instead of
code-section offsets still works.

Every address conversion is additionally guarded: `getCodeAddress()` is wrapped in
`try { } catch (RuntimeException) { }`, so the `0xffffffff`-derived rows are **skipped** instead
of aborting the import. Rows that do not land in `getExecuteSet()` are skipped (as the stock
importer does). The reader mirrors Ghidra's own `DWARFLineInfoSourceMapScript`
(`getAllSourceFileInfos` / `getAllSourceFileAddrInfo` / same file normalisation and 1000-byte
length cap), only with the fixup and the guard added.

This is *not* a post-hoc patch of the source map: it uses Ghidra's intended base-address API and
leaves `WasmLoader` untouched.

---

## 3. Fixture

`test-scripts/make_dwarf_fixture.ps1` writes the Rust source and builds two modules with
`rustc 1.99.0` / `wasm32-unknown-unknown`:

* `fixture_dwarf.wasm` — `-C debuginfo=2` (4 797 B)
* `fixture_dwarf_lineonly.wasm` — `-C debuginfo=line-tables-only` (1 530 B)

Both contain three `#[no_mangle] pub extern "C"` functions (`add_three`, `mixup`, `loopsum`)
with a couple of statements each. Build:

```powershell
cd D:\code\ghidra-wt-m
.\test-scripts\make_dwarf_fixture.ps1 -OutDir out
# fixture_dwarf_lineonly.wasm  1530 bytes
# fixture_dwarf.wasm           4797 bytes
```

The plain single-invocation form suggested in the task
(`rustc --target wasm32-unknown-unknown --crate-type=cdylib -C debuginfo=2 -C opt-level=0`)
produces a valid module but pulls in the pre-compiled `core` crate and its ~630 KB of debug
info; `-BigLink` reproduces it (`.\test-scripts\make_dwarf_fixture.ps1 -OutDir out\big -BigLink`).
The default two-step path (`rustc --emit=obj` then the toolchain's `rust-lld -flavor wasm`) links
only the fixture object, so the module is a few KB while still carrying a fully relocated
`.debug_line` table produced by the same rustc/LLVM. Both variants were tested (§4); the small
fixtures are regenerated by the script and **not** committed.

Fixture `fixture.rs` line layout (used to interpret the mapping): `add_three` line 12 (body
13/14/15), `mixup` 19 (body 20/21/22), `loopsum` 26 (body 27/28/29/30/31/33).

---

## 4. Observed evidence

Build+install, then headless import + `DumpSourceMap.java` (project dirs and log files are under
`out/`, unique per run):

```powershell
& .\test-scripts\build-install.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-m"

$proj="D:\code\ghidra-wt-m\out\dwproj1"; New-Item -ItemType Directory -Force $proj | Out-Null
& "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-m\support\analyzeHeadless.bat" `
    $proj DW1 -import "D:\code\ghidra-wt-m\out\fixture_dwarf.wasm" `
    -scriptPath "D:\code\ghidra-wt-m\test-scripts" -postScript "DumpSourceMap.java" `
    -max-cpu 2 -deleteProject
```

Analyzer log lines (all three modules in one run, `out\dw4.log`):

```
DWARF: fixup 0x80000072: 27 entries,     3 out-of-range, 0 non-executable, 0 rejected   (debuginfo=2,  small)
DWARF: fixup 0x80000072: 23 entries,     2 out-of-range, 0 non-executable, 0 rejected   (line-tables-only)
DWARF: fixup 0x80000075: 48 entries, 19898 out-of-range, 0 non-executable, 0 rejected   (plain cdylib, 632 KB)
WASM DWARF: base-address fixup 0x80000072 produced 27 source map entries
```

`out-of-range` = the `0xffffffff`-derived rows that used to abort the import; they are now
skipped. `0 non-executable` = every address that survived the fixup landed inside the executable
`.module` block.

Complete source map for the small `debuginfo=2` fixture (`out\dw1.log`):

```
SOURCEFILES 3
SRCMAP ram:80000074 -> .../library/core/src/intrinsics/mod.rs:2211 len=28 exec=true
SRCMAP ram:80000090 -> .../library/core/src/intrinsics/mod.rs:2215 len=7  exec=true
SRCMAP ram:80000097 -> .../library/core/src/intrinsics/mod.rs:2215 len=1  exec=true
SRCMAP ram:80000098 -> .../library/core/src/intrinsics/mod.rs:2216 len=2  exec=true
SRCMAP ram:8000009b -> D:/code/ghidra-wt-m/out/fixture.rs:12 len=35 exec=true   <- add_three
SRCMAP ram:800000be -> D:/code/ghidra-wt-m/out/fixture.rs:13 len=14 exec=true
SRCMAP ram:800000cc -> D:/code/ghidra-wt-m/out/fixture.rs:14 len=14 exec=true
SRCMAP ram:800000da -> D:/code/ghidra-wt-m/out/fixture.rs:15 len=5  exec=true
SRCMAP ram:800000df -> D:/code/ghidra-wt-m/out/fixture.rs:16 len=2  exec=true
SRCMAP ram:800000e2 -> D:/code/ghidra-wt-m/out/fixture.rs:26 len=21 exec=true   <- loopsum
SRCMAP ram:800000f7 -> D:/code/ghidra-wt-m/out/fixture.rs:27 len=7  exec=true
SRCMAP ram:800000fe -> D:/code/ghidra-wt-m/out/fixture.rs:28 len=7  exec=true
SRCMAP ram:80000105 -> D:/code/ghidra-wt-m/out/fixture.rs:29 len=17 exec=true
SRCMAP ram:80000116 -> D:/code/ghidra-wt-m/out/fixture.rs:33 len=5  exec=true
SRCMAP ram:8000011b -> D:/code/ghidra-wt-m/out/fixture.rs:34 len=1  exec=true
SRCMAP ram:8000011d -> D:/code/ghidra-wt-m/out/fixture.rs:30 len=7  exec=true
SRCMAP ram:80000124 -> D:/code/ghidra-wt-m/out/fixture.rs:30 len=9  exec=true
SRCMAP ram:8000012d -> D:/code/ghidra-wt-m/out/fixture.rs:31 len=13 exec=true
SRCMAP ram:8000013a -> D:/code/ghidra-wt-m/out/fixture.rs:29 len=2  exec=true
SRCMAP ram:8000013f -> D:/code/ghidra-wt-m/out/fixture.rs:19 len=36 exec=true   <- mixup
SRCMAP ram:80000163 -> D:/code/ghidra-wt-m/out/fixture.rs:20 len=28 exec=true
SRCMAP ram:8000017f -> .../library/core/src/num/uint_macros.rs:475  len=12 exec=true  (inlined rotate_left)
SRCMAP ram:8000018b -> D:/code/ghidra-wt-m/out/fixture.rs:21 len=25 exec=true
SRCMAP ram:800001a4 -> .../library/core/src/num/uint_macros.rs:2728 len=11 exec=true
SRCMAP ram:800001af -> D:/code/ghidra-wt-m/out/fixture.rs:23 len=15 exec=true
SOURCEMAP total=27 executable=27
```

The addresses agree with the loader's own scheme: the decompiler's function entries in the same
run are `add_three @ ram:8000009b`, `loopsum @ ram:800000e2`, `mixup @ ram:8000013f` — i.e. each
function's entry point carries exactly the line numbers of its own source lines (12–15, 26–31/33,
19–23) plus the inlined `core` lines. Line `0` entries exist (4 of them) and come from DWARF rows
with `line == 0`; Ghidra's own importer produces the same.

`DumpSourceMap.java` also prints the decompiled C of the first functions. In this headless
harness the C output does **not** carry source-line comments (Ghidra renders them from the same
source map only in the GUI); the source map above is the authoritative evidence. The decompiled
bodies themselves are correct, e.g.:

```
int export::add_three(int param1,int param2,int param3) { return param1 + param2 + param3 + 1; }
```

### Controls / negative results worth recording

* Stock `DWARFLineInfoSourceMapScript.java` (fixup `0`, the historical configuration) on the
  632 KB module: prints `entry for non-executable address; skipping … ram:00000002` for every
  row and then throws `AddressOutOfBoundsException … got 0x100000002` (quoted in §1.2).
* The same script on the small fixture adds 0 entries (all `ram:0x2..` rows are non-executable).
* The line-tables-only variant maps correctly (23 entries, all executable) — the fixup does not
  depend on `.debug_info` richness.

---

## 5. Regression / frozen baseline

Real-module regression (`DumpDecomp.java` on
`D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm`):

```
SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156
```

— the required `functions=437 decompiled=437 failed=0 instructions=61658` is unchanged.

Probe suite (`test-scripts\run_probes.ps1 -OutDir D:\code\ghidra-wt-m\out\probes-dwarf`,
83 probe modules, all generators incl. the other workstreams'). Metrics for the frozen probes
01–27:

```
01_baseline_i32              funcs=1 instrs=3  u=0 d=1/0
02_externref_param           funcs=1 instrs=3  u=0 d=1/0
03_externref_table           funcs=1 instrs=4  u=0 d=1/0
04_shared_memory_atomic      funcs=1 instrs=4  u=0 d=1/0
05_memory64                  funcs=1 instrs=1  u=6 d=1/0
06_multi_memory              funcs=1 instrs=7  u=0 d=1/0
07_data_count_bulk_memory    funcs=1 instrs=7  u=0 d=1/0
08_gc_struct_type            funcs=1 instrs=2  u=0 d=1/0
09_gc_struct_new             funcs=1 instrs=4  u=0 d=1/0
10_eh_legacy_try_catch       funcs=1 instrs=6  u=0 d=1/0
11_eh_try_table              funcs=1 instrs=4  u=0 d=1/0
12_call_ref                  funcs=1 instrs=4  u=1 d=1/0
13_tail_call                 funcs=2 instrs=5  u=0 d=2/0
14_relaxed_simd              funcs=1 instrs=6  u=0 d=1/0
15_simd                      funcs=1 instrs=6  u=0 d=1/0
16_multivalue_return         funcs=2 instrs=9  u=0 d=2/0
17_multivalue_block          funcs=1 instrs=7  u=0 d=1/0
18_shared_then_plain_memory  funcs=1 instrs=3  u=0 d=1/0
19_extended_const_global     funcs=0 instrs=0  u=0 d=0/0    (imports now; was "import failed" at 430cbe2)
20_gc_global_init            funcs=0 instrs=0  u=0 d=0/0    (imports now; was "import failed" at 430cbe2)
21_component_model           import failed (bare header, no embedded core module)
22_extconst_two_ops          funcs=1 instrs=2  u=0 d=1/0
23_const_f32_imm_0b          funcs=1 instrs=2  u=0 d=1/0
24_const_f64_imm_0b          funcs=1 instrs=2  u=0 d=1/0
25_const_v128_imm_0b         funcs=1 instrs=2  u=0 d=1/0
26_refnull_typeidx           funcs=1 instrs=2  u=0 d=1/0
27_extconst_data_offset      funcs=1 instrs=2  u=0 d=1/0
```

Rows 09/19/20 differ from the *old* table in `MODERN_WASM_GAPS.md` §2.4 (recorded at `430cbe2`,
before the GC / new-EH / const-expression work was merged) but that is expected: those fixes are
already in the base commit `aa656ce`. All §2.5 rows (22–27) match exactly, as do 01–08, 10–18
and 21.

Proof that this workstream cannot perturb any probe: **no probe module contains a `.debug_`
section** (checked all 83 bytes), and the DWARF analyzer only runs when
`DWARFSectionProviderFactory` finds one; the only source file changed is
`WasmDWARFAnalyzer.java`. So the probe metrics are identical to the base-commit build.

`test-scripts/expected-results.json` and `check-results.py` do **not** exist in this worktree
(`git ls-files` and a recursive search both come up empty), so the CI gate itself could not be
executed here; the numbers above are the data a satisfiable gate would need. I deliberately did
**not** add `test-scripts/probes_dwarf.py`: `run_probes.ps1` globs `probes_*.py`, so adding one
would inject new probes into the frozen suite and change its baseline.

---

## 6. Loader-side change required by the integrator

**None.** `WasmLoader.java` was not modified and does not need to be. The line-table offsets are
relative to the code-section contents while the loader (correctly) maps file offsets, so the
translation belongs in the DWARF importer, which is where it now lives.

Two notes for the integrator:

1. The only genuinely “cleaner than a custom importer” fix would be **upstream Ghidra**:
   `DWARFAnalyzer.added()` hard-codes `new DWARFProgram(program, importOptions, dsp)` and never
   exposes `programBaseAddressFixup`, so a wasm-specific base cannot be injected into the stock
   pass. A one-line upstream hook (e.g. `protected long getProgramBaseAddressFixup(Program)`)
   would let this class drop the private line import entirely. That is a Ghidra change, not a
   change in this repo.
2. Do not try to “fix” this from the loader by moving the `.module` block or changing
   `CODE_BASE`: `getFunctionAddressOffset()` and the `.module`/`.memory*` blocks depend on the
   current file-offset mapping and are shared with function analysis, decompilation and the
   component-model loader.

---

## 7. Open questions / limitations

* The primary fixup assumes the LLVM/rustc convention “code-section-content-relative”. The
  `CODE_BASE` fallback covers whole-file-offset producers; a producer using some third base would
  still need a new candidate. Both candidates are tried automatically and the successful fixup is
  logged.
* The line import runs as a second `DWARFProgram.init()` (the stock analyzer does not expose its
  instance). Cost measured on the 632 KB module: DWARF total elapsed 61 ms; re-reading the line
  tables is a small fraction of that. For very large modules this is duplicated DIE indexing.
* `must have exclusive access`: like Ghidra’s own import, source-map writes need a writable
  program; if `added()` is ever called without it the pass is skipped with a log message rather
  than throwing.
* Decompiler line comments could not be demonstrated headlessly (see §4); the populated source
  map is what Ghidra’s Listing and GUI Decompiler render line info from.
* `out/` (generated fixtures, parser scratch scripts, projects, logs) is not git-ignored; I did
  not touch `.gitignore`. Nothing under `out/` is committed — only the three files listed at the
  top.
