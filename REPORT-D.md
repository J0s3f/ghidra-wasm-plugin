# REPORT-D - roadmap item 9: `.name` extras + name application

Branch: `feat/name-section-2` (base `a559dbe`).
Worktree: `D:\code\ghidra-wt-r`. Ghidra install: `C:\Users\micro\AppData\Local\Temp\opencode\ghidra-m`
(the pinned install; **no other worktree/install was used at any point**).

## 1. What was done

| Area | Change |
|---|---|
| parser | `.name` subsections 3 (labels), 10 (fields), 11 (tags) implemented; malformed subsections can no longer fail the import |
| application | new `wasm.analysis.WasmNameApplyAnalyzer` turns table/memory/elem/data names into labels, and module/type/field/tag/label names into comments |
| probes | `test-scripts/probes_names.py` (N01 full `.name`, N02 no `.name`, N03 malformed) |
| evidence | `test-scripts/DumpNames.java` (symbols + comments dump) |

## 2. Parser changes per subsection id

`WasmNameSubsectionId` gained `NAME_FIELD` (10) and `NAME_TAG` (11); the enum order is the wire id
order and now covers ids 0-11:

| id | class | payload | before |
|---|---|---|---|
| 0 | `WasmNameModuleSubsection` | name | ok |
| 1 | `WasmNameMapSubsection("function")` | name map | ok |
| 2 | `WasmNameLocalSubsection` | indirect map | ok |
| 3 | **`WasmNameLabelSubsection`** | indirect map `funcidx -> {labelidx -> name}` | `TODO` -> unknown |
| 4 | `WasmNameMapSubsection("type")` | name map | ok |
| 5 | `WasmNameMapSubsection("table")` | name map | ok |
| 6 | `WasmNameMapSubsection("memory")` | name map | ok |
| 7 | `WasmNameMapSubsection("global")` | name map | ok |
| 8 | `WasmNameMapSubsection("elem")` | name map | ok |
| 9 | `WasmNameMapSubsection("data")` | name map | ok |
| 10 | **`WasmNameFieldSubsection`** | indirect map `typeidx -> {fieldidx -> name}` | fell into unknown |
| 11 | **`WasmNameMapSubsection("tag")`** | name map | fell into unknown |

The two indirect-map subsections reuse `WasmNameIndirectMap`; its per-entry structure name is now
parameterised (`namemap_func_labels_`, `namemap_type_fields_`) so label/field/local maps cannot
collide if the section structure is ever applied. `WasmNameIndirectMap` also gained `getMap()`
(outer index -> inner map) for the applier.

`WasmNameSection` gained accessors for the new/existing subsections (`getLabelName(s)`,
`getFieldName(s)`, `getTypeName`, `getTableName`, `getMemoryName`, `getElemName`, `getTagName`,
`getNameMap(id)`, `getLabelSubsection()`, `getFieldSubsection()`).

### Robustness (subsection must not break the import)

* `WasmNameSubsection.createSubsection` bounds the declared content length to the reader length
  (`min(afterHeader + size, reader.length())`) and wraps the dispatch in
  `catch (IOException | RuntimeException)` -> degrade to `WasmNameUnknownSubsection` (or `null`
  if even the raw bytes cannot be read).
* `WasmNameSection` also catches around `createSubsection` and breaks out on a malformed
  id/size encoding, and refuses to loop if the reader did not advance.
* An unparseable **known** subsection is kept in the listing as an unknown subsection but is
  **not** registered in the id map, so the typed getters (`getFunctionName`, ...) cannot be handed
  a `WasmNameUnknownSubsection` and throw `ClassCastException`. (Before this fix the malformed
  N03 module failed to import with exactly that CCE in `WasmLoader.getFunctionName` - verified,
  then fixed.)

## 3. Application: how each name class reaches Ghidra

New `wasm.analysis.WasmNameApplyAnalyzer` (`AbstractAnalyzer`, `AnalyzerType.DATA_ANALYZER`,
priority `DATA_TYPE_PROPOGATION`, `SourceType.IMPORTED`, one-time analysis). It is discovered by
Ghidra's class search like the other `wasm.analysis.*` analyzers - no registration file.

| name class | applied as | notes |
|---|---|---|
| module (0) | **comment** on the `.module` block (`WasmLoader.getModuleAddress`) | program name deliberately *not* changed: probe/fixture logs key on `currentProgram.getName()` |
| table (5) | **label** at `WasmLoader.getTableAddress(idx, 0)` | sits next to the loader's `table0` label |
| memory (6) | **label** at `WasmLoader.getMemoryAddress(idx, 0)` | |
| elem (8) | **label** at `getTableAddress(segment.tableidx, segment.offset)` | passive segments (offset == null) are skipped |
| data (9) | **label** at `getMemoryAddress(segment.memidx, segment.offset)` | passive segments skipped |
| type (4) | **comment** on the `.module` block: `type0=..., type1=...` | *not* applied as a Ghidra data type: the plugin never materialises wasm type entries as `DataType`s (function signatures use `ValType.asSignatureDataType()` directly; only multi-value return tuples get a `/wasm` struct), so there is no type object to rename |
| field (10) | **comment** on the `.module` block: `field_1_0=..., field_1_1=...` | same reason; struct field names have no target type |
| tag (11) | **comment** on the `.module` block: `tag0=...` | tags are not mapped to any address/block |
| label (3) | **plate comment** on the containing function: `WebAssembly label names: [0]=... [1]=...` | the pre-analyzer resolves a label to an address only inside a *transient* context register (`REG_BR_TARGET`); the mapping `labelidx -> address` is not retained after analysis, so no label can be created at the branch target. The names are still visible on the function. |

Guards: a label is only created when the address lies in a memory block, no symbol at that address
is `USER_DEFINED` (user symbols are never overwritten), and no symbol of that exact name already
exists in the global namespace. Comments are appended (existing comments are preserved) and are
idempotent (the one-time analyzer can be scheduled more than once; the duplicate-comment bug was
observed and fixed).

Function/global names are still applied by `WasmLoader` (unchanged), local names by
`WasmFunctionVariableNameAnalyzer` (unchanged).

## 4. Probes (`test-scripts/probes_names.py`)

All three are `wasmtime.Module()`-valid (validated with the local wasmtime 3x).

* `N01_full_name_section.wasm` - one function (block+loop, one local), table, memory, global,
  active elem, active data, tag; `.name` with subsections 0-11 all carrying recognisable names.
* `N02_no_name_section.wasm` - the **same module body without the `.name` section** (control).
* `N03_malformed_name_subsection.wasm` - valid module subsection, then a function name map that
  declares 3 entries but only carries 1 (parse runs off the end of the subsection).

```
probe                                   funcs instrs undefined_bytes decompiled decompile_failed
N01_full_name_section.wasm                  1      7               0          1                0
N02_no_name_section.wasm                    1      7               0          1                0
N03_malformed_name_subsection.wasm          1      7               0          1                0
```

`N03` imports and decompiles; `N01`/`N02` metrics are identical, i.e. the `.name` section changes
nothing but the names.

> Note: `wasm_probe_lib.name_section()` wraps the payload in a custom section whose *binary* name is
> the literal `".name"`. The loader (`WasmCustomSection.create`) only recognises the custom section
> name `"name"` (the `.name` seen in the Ghidra tree is the block/structure name). `probes_names.py`
> therefore uses a local `_name_section()` wrapper with `custom_section("name", ...)` and still uses
> the shared `name_subsection` / `name_map` / `label_names` helpers. `wasm_probe_lib.py` was **not**
> edited (not owned).

## 5. Evidence

`check-local` / `run_probes` runs a `DumpNames.java` post-script (project `Names`, imports all three
probes). Excerpt (full log: `%TEMP%\opencode\names-dump\names-run.log`):

```
NAMES program=N01_full_name_section.wasm
NAMES BLOCK .module @ ram:80000000 size=353
NAMES BLOCK-COMMENT .module @ ram:80000000 :: WebAssembly module name: probe_module | WebAssembly type0=sig_void, type1=pair_struct, field_1_0=field_left, field_1_1=field_right, tag0=tag_error
NAMES BLOCK .table0 @ table:00000000 size=8
NAMES FUNC-COMMENT main_func @ ram:8000005a :: WebAssembly label names: [0]=outer_block [1]=inner_loop
NAMES SYMBOL linear_mem @ ram:00000000 source=IMPORTED ns=Global          <- memory name  (sub 6)
NAMES SYMBOL func_table @ table:00000000 source=IMPORTED ns=Global        <- table name   (sub 5)
NAMES SYMBOL elem_segment @ table:00000000 source=IMPORTED ns=Global      <- elem name    (sub 8)
NAMES SYMBOL data_segment @ ram:00000000 source=IMPORTED ns=Global        <- data name    (sub 9)
NAMES SYMBOL main_func @ ram:8000005a source=IMPORTED ns=export          <- function name (loader)
NAMES SYMBOL global_counter @ global:00000000 source=IMPORTED ns=export  <- global name  (loader)

NAMES program=N02_no_name_section.wasm
NAMES BLOCK .module @ ram:80000000 size=113
NAMES SYMBOL run @ ram:8000005a source=IMPORTED ns=export                <- no .name-derived names
NAMES SYMBOL table0 @ table:00000000 source=IMPORTED ns=Global
NAMES SYMBOL g @ global:00000000 source=IMPORTED ns=export

NAMES program=N03_malformed_name_subsection.wasm
NAMES BLOCK-COMMENT .module @ ram:80000000 :: WebAssembly module name: malformed_module
NAMES SYMBOL run @ ram:8000005a source=IMPORTED ns=export
...                                                                      <- no CCE, import OK, the names before the malformed subsection survive
```

(The dump also prints the `.memory0`/`.global0` blocks; truncated here for readability.)

## 6. CI gate

Commands run from `D:\code\ghidra-wt-r` (with a **unique** `-OutDir`, because the default
`%TEMP%\wasm-probes-ci` is shared between agents and was observed being clobbered mid-run):

```
& .\test-scripts\check-local.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-m" `
    -OutDir "C:\Users\micro\AppData\Local\Temp\opencode\ci-r" -SkipBuild -Update
...
== running 136 probe(s) ==
== DumpDecomp wasm_fixture.wasm -> fixture-run.log ==
SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0
updated ...\expected-results.json: 132 probe(s) with metrics, 4 expected import failure(s)

& .\test-scripts\check-local.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-m" `
    -OutDir "C:\Users\micro\AppData\Local\Temp\opencode\ci-r" -SkipBuild
...
SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0
probes: 132 imported, 4 import failure(s); baseline has 136
OK: every probe matches the recorded baseline.
```

`build-install.ps1 -GhidraDir ...ghidra-m` was run immediately before measuring (BUILD SUCCESSFUL).

### Baseline diff

`expected-results.json`: `133 -> 136` probes, **+36/-12 lines**.

* Additive (my work): the three `N0x` entries + `probe_count`.
* **Not additive (pre-existing, NOT caused by this item):** 10 entries are corrected to the values
  a fresh build of the *unmodified* base produces:

  | probe | recorded at `a559dbe` | fresh build |
  |---|---|---|
  | `12_call_ref.wasm` | `undefined_bytes=1` | `undefined_bytes=0` |
  | `B16_valtype_ref_null_param.wasm` | `undefined_bytes=1` | `0` |
  | `B17_valtype_ref_param.wasm` | `undefined_bytes=1` | `0` |
  | `F01..F07` | `undefined_bytes=1` (F07 `2`) | `0` |
  | `F02_ref_as_non_null.wasm` | `instrs=4, undefined_bytes=1` | `instrs=5, undefined_bytes=0` |

  Control experiment (decisive): I stashed *all* my changes (`git stash push -u`, so the installed
  jar contained none of my classes - confirmed with `jar tf`), rebuilt, and ran the gate:

  ```
  probes: 129 imported, 4 import failure(s); baseline has 133
  FAIL: DIFF 12_call_ref.wasm: undefined_bytes expected 1, got 0
  FAIL: DIFF B16_valtype_ref_null_param.wasm: undefined_bytes expected 1, got 0
  FAIL: DIFF B17_valtype_ref_param.wasm: undefined_bytes expected 1, got 0
  FAIL: DIFF F01_return_call_ref.wasm: undefined_bytes expected 1, got 0
  FAIL: DIFF F02_ref_as_non_null.wasm: instrs expected 4, got 5; undefined_bytes expected 1, got 0
  FAIL: DIFF F03_br_on_null.wasm: undefined_bytes expected 1, got 0
  FAIL: DIFF F04_br_on_null_fallthrough.wasm: undefined_bytes expected 1, got 0
  FAIL: DIFF F05_br_on_non_null.wasm: undefined_bytes expected 1, got 0
  FAIL: DIFF F06_call_ref_through_table.wasm: undefined_bytes expected 1, got 0
  FAIL: DIFF F07_funcref_mixed.wasm: undefined_bytes expected 2, got 0
  ```

  So the recorded `a559dbe` baseline is **already inconsistent with a fresh build of `a559dbe`**.
  Git archaeology agrees: commit `514762b` (the funcref workstream's own baseline) records
  `12_call_ref.undefined_bytes=0` and `F02.instrs=5, undefined_bytes=0`, i.e. exactly what the
  current tree produces; `a559dbe` records the worse values. This looks like a stale baseline
  written by an earlier `-Update` run against a different install (the `build-install.ps1` warning
  about a stale `WebAssembly.sla`, or the same shared-`OutDir` clobber I hit). The only *frozen*
  probe (01-27) affected is `12_call_ref`; the change is an improvement (1 -> 0 undefined bytes)
  and the recorded `1` cannot be reproduced by any build of the current tree.

## 7. Real-module regression

```
& analyzeHeadless <proj> Reg -import D:\code\Rasterbator\...\rasterbator_rs_bg.wasm `
    -scriptPath test-scripts -postScript DumpDecomp.java -max-cpu 2 -deleteProject
INFO  DumpDecomp.java> SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156
```

Matches the recorded regression exactly (`functions=437 decompiled=437 failed=0
instructions=61658`). The `Wasm name section applier` ran (0.000 secs) with no errors; the real
module has no `.name` section (stripped), so nothing was applied and nothing changed.

## 8. Open questions

1. **Stale frozen baseline** (section 6): the integrator must decide whether to accept the 10
   pre-existing corrections (`12_call_ref` among `01-27`) or re-record the baseline on a clean
   install first. They are not caused by, and do not depend on, this item.
2. **Label names have no address target.** The plugin resolves `labelidx -> address` only in the
   transient pre-analyzer context; exposing a persistent `funcidx/labelidx -> Address` map (e.g.
   from `WasmFunctionAnalysis`) would let the applier create real labels at branch targets instead
   of a function comment. Left as a comment for now (as the task allows).
3. **Type/field names have no DataType target** (section 3). If wasm type entries are ever
   materialised as Ghidra `DataType`s, these comments should become renames.
4. `wasm_probe_lib.name_section()` writes the custom-section name `".name"`, which the loader does
   not recognise; a future probe generator using it as-is would silently produce no names.
   Suggested follow-up (outside my ownership): change it to `custom_section("name", ...)`.
