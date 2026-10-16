# REPORT-SROA: stack-as-aggregate + SROA in `WasmStackVariableAnalyzer`

Branch: `feat/stack-sroa` (based on `main` @ `066bfcc`). Worktree:
`ghidra-wt-sroa`. All numbers below were produced against the pinned install
`C:\Users\micro\AppData\Local\Temp\ghidra-h1` with the real module
`rasterbator_rs_bg.wasm`.

## 1. What changed

`src/main/java/wasm/analysis/WasmStackVariableAnalyzer.java` only. The old analyzer created a
stack variable *while* walking the instructions, once per access, with `createVar()` skipping an
offset that an already-created variable contained. That made the frame layout depend on
instruction order: a narrow access emitted before a wider one at the same region produced several
byte-sized variables, while the wider access was silently swallowed (and vice versa).

The analyzer now runs in three phases:

1. **Collect** (`collectAccesses`) - one pass over the function body turns every frame access into
   an `Access` record: `(offset, width, datatype, refType, instruction)`. Nothing is written to the
   program yet, so the access set cannot depend on creation order. A load/store contributes
   `stackDepth(base) + memarg offset` (the `offset=O` operand), a `local.get`/`local.set` whose
   register value is SP-relative contributes `stackDepth(register)`.
2. **Atomize** (`atomize`) - split the accesses into **atoms** (see the rule below).
3. **Apply** (`applyAtoms`) - the second pass: materialize one variable per atom, then add one
   stack reference per observed access at the access's own offset. Because every access lies inside
   exactly one atom, an overlapping/unaligned access cannot produce a duplicate variable or an
   out-of-range reference.

The frame is modelled as **one aggregate**: `createStackPointerVariables` computes the observed
extent `[low, high)` over all accesses (the region of the guessed C stack the function touches) and
the atom list is the split of that aggregate. The aggregate itself is not materialized as a Ghidra
variable (that would overlap every atom) - it is the model the atoms are derived from, and the log
line reports it per function.

The `local.get`/`local.set` crash guards (`firstRegister`, no register input) and the `align=A
offset=O` parsing are unchanged, so the SF02 crash paths stay fixed.

## 2. The atom rule

An **atom** is a maximal, non-overlapping `(offset, width)` region of the frame:

* one atom per distinct `(offset, width)` access;
* a repeated access at the same offset with the same width **merges** into the existing atom (its
  count is reported as `merges`);
* a **wider access covering a smaller one wins**: the two are unified into the wider extent and the
  wider access's datatype is kept. The widening is recorded as a `split`;
* an overlapping/unaligned pair that neither access describes (e.g. `i32` at 0 + `i64` at 2) widens
  the atom to the union `[0,10)` and falls back to an undefined blob of exactly that width, so the
  result is deterministic;
* because a widened atom can newly overlap a third atom, the unify step is repeated to a fixpoint;
* a fixed-offset access from the C stack pointer is a structure field; strided patterns are left as
  separate atoms (array recovery is a separate item).

The datatype of a finished atom is the winning access's datatype when it is exactly the atom's
width, otherwise an undefined blob of the atom's width (`undefined4`/`undefined8`/`undefined1[n]`).

## 3. New probes (`test-scripts/probes_sroa.py`)

| probe | metrics (`funcs/instrs/undefined_bytes/decompiled`) | analyzer (`aggregate`, accesses -> atoms, splits, merges) | frame variables |
|---|---|---|---|
| `SROA01_struct_frame.wasm` | 1 / 28 / 0 / 1 | `[0,32)`, 9 -> **4**, splits=0, merges=5 | `0/4 undefined4`, `4/8 undefined8`, `12/4 float4`, `16/16 undefined1[16]` |
| `SROA02_unaligned_overlap.wasm` | 1 / 15 / 0 / 1 | `[0,10)`, 4 -> **1**, splits=1, merges=3 | `0/10 undefined1[10]` |
| `SROA03_unreachable_access.wasm` | 1 / 7 / 0 / 1 | no accesses -> **0** atoms | (none) |

* **SROA01** writes (and reads back) an i32 at 0, an i64 at 4, an f32 at 12 and a v128 at 16, plus a
  second i32 read at 0. The four writes produce four separate stack variables with widths 4/8/4/16
  (the f32 sits at 12 because the i64 at 4 spans `[4,12)`; the task's illustrative offset 8 for the
  f32 is inside that span and would be subsumed by the wider-wins rule, so 12 is used to keep four
  distinct fields). The repeated i32 access merges (merges=5 counts the four read-backs plus the
  repeated i32). The decompiled prototype shows the four typed fields
  (`undefined4 param_1, undefined8 param_2, float4 param_3, undefined1[16] param_4`).
* **SROA02** stores an i64 at 2 then an i32 at 0 (unaligned overlap) and reads both back. The two
  atoms overlap, so the single atom is widened to `[0,10)` and becomes `undefined1[10]`; analysis
  does not crash and the result is order-independent.
* **SROA03** is the SF02 crash path (`unreachable` followed by a store, a load and a `local.set`,
  none of which have a Register input object). It analyses cleanly, `undefined_bytes == 0`, and the
  decompiler succeeds. No `WasmStackVariableAnalyzer` warning is logged.

Evidence tool: `test-scripts/DumpStackVars.java` (new) prints each function's stack-frame variables
(`off/size/type`) and a `STACKSUM` line, and `ListProgram.java` / `DumpAll.java` print the listing
and decompiled C.

## 4. Before/after on the real module

Real module `rasterbator_rs_bg.wasm` (pinned install, `-SkipBuild`):

| metric | before | after |
|---|---|---|
| functions with frame variables | 198 | 198 |
| total frame variables (`DumpStackVars` STACKSUM) | 1636 | **1567** |
| accesses atomised (`SROA-TOTAL`) | - | 3678 -> **1567 atoms** (splits=105, merges=2065) |
| fixture `SUMMARY` | `functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0` | unchanged |
| real `SUMMARY` | `functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156` | unchanged |

The variable count *falls* because the SROA pass unifies overlapping accesses (105 splits) and
folds repeated `(offset, width)` accesses (2065 merges); the old code created a variable per access
offset opportunistically, which fragmented a single field into byte-sized variables. The number is
not the goal - the widths are.

Qualitative before/after (`DumpStackVars`), `unnamed_function_50` (frame 20):

```
before (18 vars, byte-fragmented, order-dependent)      after (4 atoms, correct widths)
  -20/2 undefined2   -18/1 undefined1   -17/1 ...         -20/8 undefined8
  -16/1 ... -15/1 ... -14/1 ... -13/1 ... -12/1 ...       -12/2 ushort
  -11/1 ... -10/2 undefined2   -8/1 ... -7/1 ...          -10/8 undefined8
  -6/1 ... -5/1 ... -4/1 ... -3/1 ... -2/1 ... -1/1       -2/2 ushort
```

The other large-frame function, `unnamed_function_39`, went from 81 to 76 variables; e.g. two
adjacent single bytes became one 2-byte field (`abStack_383e[2]`) because a 16-bit access now wins
over the two byte accesses, and two `undefined2` fields became `ushort`. The large `auStack_*` blobs
in that function are unchanged: they are regions reached only through pointers passed to imported
functions (`memcpy` targets), i.e. no fixed-offset access exists for the analyzer to atomise.

## 5. Gates

* 185-probe gate: `OK: every probe matches the recorded baseline.` (168 imported + 17 expected
  import failures). `expected-results.json` gained exactly the 3 new probes and
  `probe_count` 182 -> 185; **0 existing entries changed** (regenerated with `check-local.ps1
  -Update` + a plain `OK` run, never hand-edited).
* Fixture: `functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0` (unchanged).
* Real module: `functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156`
  (unchanged).
* Fixture-validity: 185 probes, `valid: 111 wabt-gap: 36 unsupported: 26 invalid: 12`, `OK: every
  probe matches the recorded fixture classification`. `fixture-validity.json` gained exactly the 3
  new probes, all `valid` (no `--invalid`/`--unsupported` needed).

## 6. What I did NOT do

* No array/strided-pattern recovery: strided accesses are left as separate atoms (a later item).
* The single aggregate is not materialized as one Ghidra stack variable - it is the model, and the
  atoms are what is written; a real aggregate variable would overlap every atom.
* No type propagation between atoms (no struct/union types); each atom is its own variable.
* No changes to `WasmEnums.java` / `WasmFunctionAnalysis.java` (reference typing) or the emulation
  files.
* No push, merge or tag.
