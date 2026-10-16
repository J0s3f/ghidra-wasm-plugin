# DWARF-based type-recovery metric

Branch: `feat/dwarf-metric-2`. All work in this worktree only, against the
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
   `--wasm`; offline after generation. — MET (fixture via the built-in
   reader; `rust_debuginfo` via the secondary Ghidra-DWARF ground truth,
   §6b).
3. Ground truth read from the module's `.debug_info` (struct field
   offsets/sizes, function parameter types); llvm-dwarfdump checked first,
   absent → built-in minimal reader used instead, stated precisely; command
   FAILS LOUDLY when ground truth is unavailable. — MET (plus a labelled
   secondary mode reusing Ghidra-imported DWARF types where the reader
   cannot parse; the mode is always stated in output + JSON).
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
        → analyzeHeadless (DumpTypes.java [+ DumpAll.java] + DumpDwarfTypes.java)
        → dwarf_type_metric.py analyse → text report + --json
```

Two ground-truth modes (`--ground-truth`, always stated in output + JSON):
`dwarf-reader` (default) parses the module's `.debug_info` with the built-in
reader — most independent; `ghidra-dwarf` reuses the DWARF types Ghidra
itself imported (`/DWARF/` category via `DumpDwarfTypes.java`, secondary —
see caveat in §6b).

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
and in `dwarf-reader` mode does not credit Ghidra's own DWARF type import
(comparing that against itself would be circular — deliberately excluded;
that comparison is exactly what the secondary `ghidra-dwarf` mode does, with
its caveat stated).

## 6b. Baseline: real module `rust_debuginfo` (secondary ground truth)

Scored binary (generated into scratch, NOT committed):
`C:\Users\micro\AppData\Local\Temp\dwarf-metric-corpus\rust_debuginfo.wasm`,
sha256 `FC0CDB5C9BBEF6CA0B9935F87B17DE51F6A91D656926FB963A91D5FF24A06C29`,
286481 bytes (manifest `6FE0…` differs only via embedded absolute build
paths; ground truth comes from the binary itself). Built with
`test-scripts/corpus/rust-src/build.ps1` (this also rebuilt `rust_plain` and
`rust_simd128` byte-identical to the manifest).

Command:

```powershell
python3 test-scripts/dwarf_type_metric.py --run --wasm <above> --no-decomp `
  --ground-truth ghidra-dwarf --out-dir <scratch> --json <scratch>\metric.json
```

Observed output (headless: 454 DWARF types imported, 71 structs created,
75 parameters retyped across 51 functions):

```text
ground truth              : Ghidra-imported DWARF types (/DWARF/ category)
dwarf structs w/ fields   : 239 (1076 fields, 0 subprograms, 0 struct-ptr params)
recovered structures      : 71
retyped functions         : 51 (with struct-typed params)
field-offset recall       : micro 0.614  macro 0.831
field-exact recall        : micro 0.335  macro 0.351
parameter-type recovery   : n/a (Ghidra does not import DWARF function signatures)
```

Caveats (stated by the tool on every run): the ground truth is Ghidra's own
DWARF import, so this measures the import against the synthesis rather than
the module against it — less independent than §6. Param/focus scoring need
DWARF subprogram signatures, which Ghidra does not import, so they are n/a
here (the fixture covers them). `DWARFSTRUCT_COUNT` was 348 raw (25 on the
fixture); dedupe + field-less filtering leaves the scored 239.

Methodology check: on the fixture both modes agree — reader mode
(19 structs, micro 0.895/macro 0.864) vs ghidra mode (21 structs, micro
0.741/macro 0.879); `Point`/`Rect` resolve identically in both
(size 8/20, same offsets, Jaccard-1.0 `wasm_struct_4` for Point).

## 7. Limitations and open items

1. **Built-in reader hardened but still not enough for `rust_debuginfo`.**
   Added: tolerant bad-strp substitution (positions authoritative, values
   advisory), per-DIE validity (strings resolve, refs in range, addresses
   sane), `DW_FORM_ref_sig8` consume, validation-gated resync (first
   position starting 6 consecutive fully-valid DIEs; every skip reported;
   per-CU exact-consumption still rejects misalignment), depth cap.
   Fixture output is byte-identical with zero resyncs (regression proof).
   On `rust_debuginfo` the resync fires past the dead cluster but resumes at
   the wrong nesting depth (values validate, depth is unverifiable locally),
   ending the top-level list early — still a loud abort, never a silent
   number. Fixing that needs backtracking search (unbounded time); the
   secondary ground-truth mode (§6b) was used instead. Resync machinery stays
   (helps other modules, always reported).
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
- `test-scripts/DumpTypes.java` fix (harness-code change): retyped params surface as
  change: retyped params surface as
  `PointerDB`, not `PointerDataType`, so the old `instanceof` reported
  `RETYPED_COUNT 0` despite 3 retyped params. Now tests the `Pointer`
  interface (both implement it); output format unchanged, counts now truthful
  (`RETYPED_COUNT 3`, matching the analyzer's own `3 parameters retyped`
  log). No gate parses this script's output (verified by search).
- `test-scripts/DumpDwarfTypes.java` (new): dumps Ghidra-imported `/DWARF/`
  structures (offset/size/typename per field) plus a category survey; feeds
  the secondary ground-truth mode. Also collected by `--run` (cheap, no
  decompilation).
- `test-scripts/make_dwarf_fixture.ps1`: additive struct/`repr(C)` functions
  appended after `loopsum` (existing line numbers stable); fixtures remain
  generated, uncommitted.
- No plugin (`src/`) change. `check-local.ps1` unmodified.
- Full gate run: `.\test-scripts\check-local.ps1` — result: **GREEN (exit 0)** — build OK; 210 probes (192 imported +
  18 import failures) all match expected-results.json; fixture SUMMARY
  functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0;
  real module SUMMARY functions=437 decompiled=437 failed=0
  instructions=61658 undefined_bytes=156 (matches the MODERN_WASM_GAPS
  section 2.4 baseline exactly).

## 9. Files changed

- `test-scripts/dwarf_type_metric.py` (new, ~1400 lines): the metric, both
  ground-truth modes, resync-hardened reader.
- `test-scripts/DumpDwarfTypes.java` (new): `/DWARF/` type dump for the
  secondary mode.
- `test-scripts/make_dwarf_fixture.ps1` (extended): struct-bearing fixture source.
- `test-scripts/DumpTypes.java` (1-condition fix): truthful RETYPED reporting.
- `REPORT-DWARF-METRIC-2.md` (this file).
