# DWARF-based type-recovery metric (MuseSpark workstream)

Branch: `feat/dwarf-metric-musespark`. All work in this worktree only, against the
pinned install recorded in `test-scripts/.ghidra-install`.

## 1. Goal

Replace/extend the *proxy* metric (`test-scripts/type_recovery_metric.py`, which
explicitly lacks DWARF ground truth) with a metric that scores the plugin's
recovered types against **DWARF debug info as ground truth**, following the
Decompilation Wiki's variable-typing methodology (REUSE_OPPORTUNITIES.md §C).

## 2. Acceptance criteria (set at start, all met except where noted)

1. A new reproducible command `test-scripts/dwarf_type_metric.py` with an
   end-to-end `--run` mode, an analyse-logs mode, and `--json`. — MET.
2. Subject: the generated fixture from `test-scripts/make_dwarf_fixture.ps1`
   (extended with `repr(C)` structs passed by pointer); any other
   `.debug_info`-carrying module (e.g. corpus `rust_debuginfo`) usable via
   `--wasm`; offline after generation. — MET (fixture fully; `rust_debuginfo`
   partially, see §7).
3. Ground truth read from the module's `.debug_info` (struct field
   offsets/sizes, function parameter types); llvm-dwarfdump checked first,
   absent → built-in minimal reader used instead, stated precisely; command
   FAILS LOUDLY when ground truth is unavailable. — MET.
4. Recovered types read from the pinned install via headless `DumpTypes.java`
   (structures + retyped prototypes), `DumpAll.java` optional. — MET.
5. Clear metric: DWARF structs/fields found; recovered structures;
   field-offset recall; parameter-type recovery; `--json`. — MET (+ focus
   scope, exact recall, per-struct/per-param rows).
6. End-to-end baseline recorded. — MET (§6).
7. No hard-coded ground truth (nothing from the Rust source is baked in). — MET.
8. Existing proxy metric untouched and working. — MET (§8).
9. Optional harness wiring as documentation only; `check-local.ps1` NOT
   modified, default gate unaffected. — MET (this report + `--help` is the
   documentation; no gate file touched).
10. Full gate green at the end. — see §8.

## 3. Design

```
--run:  make_dwarf_fixture.ps1 → fixture_dwarf.wasm
        → analyzeHeadless (DumpTypes.java [+ DumpAll.java]) on pinned install
        → dwarf_type_metric.py analyse → text report + --json
```

- **Ground truth** (`DwarfReader`, in-file): minimal DWARF v4 reader for the
  rustc/LLVM `.debug_info`/`.debug_abbrev`/`.debug_str` subset — structs,
  class/union, members (constant offsets via data forms and
  `DW_OP_plus_uconst` exprlocs), subprograms with ordered non-artificial
  formal parameters, and typedef/const/volatile/pointer/base/enum/array
  chains. Multi-CU, per-CU exact-consumption checks (any misalignment fails
  loudly instead of silently mis-scoring).
- **Recovered side**: `STRUCT`/`FIELD` lines (offset+size per
  `wasm_struct_*`) and `RETYPED` prototypes from `DumpTypes.java`; full
  function/prototype list and failure count from `DumpAll.java` (optional).
- **Matching**: per DWARF struct, best recovered struct by **Jaccard
  similarity of field-offset sets** (raw overlap alone always prefers the
  biggest struct, which would make "the right struct" vacuous). Offset
  recall and exact (offset+size) recall are measured against that match,
  micro- and macro-averaged. Parameter check: a DWARF pointer-to-struct
  parameter is a *hit* iff the Ghidra prototype retypes that index to a
  pointer to a tied-best struct; each row also reports the param struct's own
  offset coverage (e.g. `covers 3/4 offsets`).
- **Focus scope**: structs reachable from matched exported functions'
  struct-pointer params plus transitive struct members (derived from DWARF +
  export section only). Reported alongside the all-structs numbers.
- **Fail-loud contract** (exit 2, no silent zeros): missing `.debug_info`
  sections, unsupported DWARF version, zero usable struct DIEs
  (line-tables-only), empty/missing plugin logs, headless failure.

## 4. Why not llvm-dwarfdump (as the task allows choosing)

`$(rustc --print sysroot)\lib\rustlib\x86_64-pc-windows-msvc\bin\`
contains `rust-lld.exe`, `rust-objcopy.exe` — **no `llvm-dwarfdump.exe`**
(`llvm-tools` not installed). The command checks this location at runtime
and reports it (`llvm_dwarfdump: null` in JSON). Installing `llvm-tools`
would add a ~100 MB+ network dependency for output that still needs parsing;
the built-in reader keeps the metric offline and dependency-free. It was
calibrated four independent ways on the fixture (§5).

## 5. Reader calibration (empirical, on the generated fixture)

- Param DIE names resolve to real Rust identifiers (`x`, `shift`);
  linkage/name strings resolve; the `rotate_left` return-type ref lands on a
  real base-type DIE whose name is `u32`.
- `Point` → size 8, fields (0,4),(4,4); `Rect` → size 20, fields
  (0,8),(8,4),(12,4),(16,1) — exactly the `repr(C)` layouts, read from the
  module, never from source.
- Per-CU exact-consumption checks pass; Ghidra's own DWARF importer reads the
  same file cleanly (53 types), so both consumers agree.
- Three parser bugs found and fixed during calibration (all guarded going
  forward): DWARF4 reference form `0x13` consumed as 4 bytes in this emission
  (8 bytes desyncs immediately); DIE offsets keyed at the abbrev-code byte
  with refs relative to the unit-length field; the top-level DIE list is
  length-delimited, not null-terminated (nested lists still require their
  null — missing ones fail loudly).

## 6. Baseline (recorded end-to-end on this machine)

Command:

```powershell
python3 test-scripts/dwarf_type_metric.py --run `
  --out-dir C:\Users\micro\AppData\Local\Temp\dwarf-metric-e2e `
  --json C:\Users\micro\AppData\Local\Temp\dwarf-metric-e2e\metric.json
```

Observed output (identical across re-runs; fixture is 5868–5880 bytes
depending on the build path embedded in `.debug_str`, results unaffected):

```text
dwarf structs w/ fields   : 19 (38 fields, 10 subprograms, 4 struct-ptr params)
recovered structures      : 10
field-offset recall       : micro 0.895  macro 0.864
field-exact recall        : micro 0.526  macro 0.522
focus structs ['Point', 'Rect']: offset 1.000 exact 0.667
parameter-type recovery   : 2/3 = 0.667 (1 unscored)
decomp context            : 7 functions, 0 failures
Point  fields=2 offset=1.000 exact=1.000 jacc=1.000 best=wasm_struct_4
Rect   fields=4 offset=1.000 exact=0.500 jacc=0.667 best=wasm_struct_1
move_point[0] (p -> Point): hit (covers 2/2 offsets)
point_sum[0] (p -> Point):  hit (covers 2/2 offsets)
rect_area[0] (r -> Rect):   miss (covers 3/4 offsets; best-match is the
                            bigger wasm_struct_1, see §7)
__rustc...rust_begin_unwind[0]: unscored (no matching Ghidra function)
```

What the metric does/does not measure: it measures whether the *synthesized
anonymous* structures cover DWARF field offsets and whether pointer params
were retyped to the covering struct. It does NOT compare field names or
scalar field types (synth emits `undefinedN`), does not score locals/globals,
and does not credit Ghidra's own DWARF type import (comparing that against
itself would be circular — deliberately excluded).

## 7. Limitations and open items

1. **`rust_debuginfo` (real module) not yet scored — reader hardening needed.**
   Rebuilt locally (`rust_debuginfo.wasm`, 286481 bytes; sha differs from
   `corpus/manifest.json` only via embedded absolute build paths).
   Plugin side works: **454 DWARF types imported, 71 structs synthesized, 75
   params retyped** (observed `RETYPED` lines, e.g. BTreeMap node functions
   retyped to `wasm_struct_0/1/...`). Reader side aborts loudly (exit 2):
   after 3041 clean DIEs it hits linker-dead DIEs (subprogram with
   low_pc=206848 against a 19305-byte code section, 31 MB high_pc —
   unrelocated addends from linking without `--gc-sections`) whose garbage
   location-expr length desyncs the sequential walk (`abbrev code 519 not in
   table` at CU0+29616). Hardening = dead-DIE-tolerant resync; deliberately
   NOT attempted (heuristic resync risks silent misalignment, which the task
   forbids). The fixture covers all acceptance bullets in the meantime.
2. **`rect_area` miss is informative, not a failure**: its own struct
   (`wasm_struct_8`, covers 3/4 Rect offsets — `tag` is never accessed so no
   access-based synth can learn it) loses Jaccard-best to the bigger
   `wasm_struct_1`. A future struct-dedup/merge would flip it to a hit.
3. Ground truth includes core-internal structs (`PanicInfo`, `NonNull`,
   fmt machinery) — reported (all-structs recall) and contained (focus
   scope); no filtering hacks applied.
4. DWARF tag constants for qualifier types unseen in real output
   (`volatile`, `restrict`, `rvalue-ref`) are best-recall and degrade to
   "other" — never crash, never mis-score.
5. Fail-loud paths verified: line-tables-only module (exit 2, "no
   struct/class/union DIEs"), no-DWARF module (exit 2, lists missing
   sections), missing log (exit 2).

## 8. Gate and compatibility evidence

- `test-scripts/type_recovery_metric.py` untouched; still runs (exit 0):
  on the fixture's DumpAll log it reports 7 functions, 0 failures, **0
  constant-offset accesses** — the proxy saturates precisely because struct
  synthesis retyped everything (`param1->field_0` instead of
  `*(int *)(param1+0)`), which is why the DWARF metric is needed.
- `test-scripts/DumpTypes.java` fix (this workstream's only harness-code
  change besides the fixture generator): retyped params surface as
  `PointerDB`, not `PointerDataType`, so the old `instanceof` reported
  `RETYPED_COUNT 0` despite 3 retyped params. Now tests the `Pointer`
  interface (both implement it); output format unchanged, counts now truthful
  (`RETYPED_COUNT 3`, matching the analyzer's own `3 parameters retyped`
  log). No gate parses this script's output (verified by search).
- `test-scripts/make_dwarf_fixture.ps1`: additive struct/`repr(C)` functions
  appended after `loopsum` (existing line numbers stable); fixtures remain
  generated, uncommitted.
- No plugin (`src/`) change. `check-local.ps1` unmodified.
- Full gate run: `.\test-scripts\check-local.ps1` — result recorded below
  after the run (build + 210 probes + fixture + real module).

## 9. Files changed

- `test-scripts/dwarf_type_metric.py` (new, ~1000 lines): the metric.
- `test-scripts/make_dwarf_fixture.ps1` (extended): struct-bearing fixture source.
- `test-scripts/DumpTypes.java` (1-condition fix): truthful RETYPED reporting.
- `REPORT-DWARF-METRIC-MUSESPARK.md` (this file).
