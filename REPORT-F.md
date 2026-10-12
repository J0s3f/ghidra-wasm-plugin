# REPORT-F - New WebAssembly exception handling (`try_table`, `throw_ref`, `exnref`)

Roadmap item **5** of `MODERN_WASM_GAPS.md` (§2.3 new-EH row, §2.4 probe 11, §4 item 5).
Branch `feat/new-eh`, worktree `D:\code\ghidra-wt-f`, base commit `58a4742`.

## 0. Headline

| | before | after |
| --- | --- | --- |
| probe `11_eh_try_table` (frozen baseline) | 1 instr, **5 undefined bytes**, body blanked (`ValidationException: pop from empty stack`) | 4 instrs, **0 undefined bytes**, `try_table blocktype=0x40 catches=0x0`, decompiles |
| `try_table` / `throw_ref` / `exnref` | unsupported (0x1F falls into the `default:` "Illegal opcode" arm; 0x0A likewise; 0x69 is an unknown valtype) | decoded, disassembled, stack-checked, decompiled |
| new probe file `probes_eh.py` | - | 10 probes (30-39), **all `undefined_bytes=0`, all decompile** |
| legacy EH (`throw`/`catch`/`catch_all`/`rethrow`/`delegate`, probe 10) | 1 / 6 / 0 / 1-0 | **unchanged**: 1 / 6 / 0 / 1-0, byte-identical listing and identical decompiled C |
| everything else (probes 01-09, 12-21) | §2.4 | **unchanged**, row for row |
| real-module regression (`rasterbator_rs_bg.wasm`) | `functions=437 decompiled=437 failed=0 instructions=61658` | **`functions=437 decompiled=437 failed=0 instructions=61658`** |

## 1. Design

### 1.1 `try_table` (0x1F): decoding

Encoding: `0x1F blocktype vec(catch) instr* end`. The pre-analyzer side lives in a new class
`wasm/analysis/EH2Ops.java` (reached from two new, tiny `case` entries in
`WasmFunctionAnalysis.analyzeOpcode`), and the SLEIGH side in a new
`data/languages/EH2Ops.sinc`.

* `blocktype` is read exactly like `block`/`if`/`try` (`LEB128::signed`, so 0x40 = empty, a negative
  shorthand = a valtype, a non-negative number = a type index).
* The clause vector is read as `count` then, per clause, the 1-byte kind plus a tag index
  (`catch`/`catch_ref`) and a label index. All operands are LEB128, so the byte length is exact.

**Clause bytes are modelled as their own directive instructions.** A clause vector has a
variable, kind-dependent length, which SLEIGH cannot express with a fixed pattern. The established
idiom in this language is `br_table`: the main instruction consumes the count and each operand
becomes a separate pseudo-instruction (`.case`/`.default`) selected by a directive context
register. `try_table` follows exactly that:

* `:try_table ... is opc=0x1f; ULeb128; count; ...` consumes opcode + blocktype + clause count;
* one new directive type (`@define DIRECTIVE_EH_CLAUSE 4`, mirrored by
  `ContextRegister.DIRECTIVE_EH_CLAUSE`) is set by the pre-analyzer at each clause address;
* four constructors consume one clause each and consume exactly its bytes:
  `:.catch tag label` (0x00), `:.catch_ref tag label` (0x01), `:.catch_all label` (0x02),
  `:.catch_all_ref label` (0x03).

So the instruction stream reads `try_table`, then one pseudo-instruction per clause, then the body -
the same shape as `br_table` + `.case`. The body starts at the correct address because every clause
consumes exactly its own bytes.

### 1.2 `try_table`: handlers and branches

`try_table` is modelled as an ordinary block (`BlockKind.BLOCK`, the blocktype's params consumed and
pushed back), so **all existing branch machinery works unchanged**:

* `br 0` inside the body resolves to the end of the `try_table`;
* `br N` walks out to enclosing blocks/loops as usual (probe 36 has `br 2` leaving two nested
  `try_table`s and `br 1` leaving the outer one; both resolve to the enclosing block's `end`);
* labels that catch clauses branch to are just enclosing labels, so a `br` to such a label and the
  exception dispatch to it share one target.

Catch labels are resolved in the context **enclosing** the `try_table` (label 0 is the block around
the `try_table`, not the `try_table` itself). This is the spec's `Catch_ok` rule, confirmed against
the reference interpreter (`valid.ml`: `TryTable` calls `check_catch c ct ts2` with the *outer*
context `c`, before extending `c.labels` for the body). In `EH2Ops` the clauses are therefore read
*before* the `try_table` frame is pushed, and `BlockType`/`ControlFrame` stay untouched.

The exception dispatch is modelled like legacy `try` was for its first handler: the `try_table`
instruction is registered as a branch of the first clause's label
(`ControlFrame.addBranch(instAddress)`), and marked with `ctx_case_index=1` plus (when the clause
pushes exactly one value that fits) `ctx_operand_size`. Its `end` then sets `ctx_br_target`, and the
SLEIGH constructor behaves like `:try`'s handler variant:

```
nop();
local caught:1 = wasm_exception_caught();
if (caught == 0) goto inst_next;
sp0_32 = wasm_exception_payload();   # only when a single value is pushed
goto br_target;
```

Only the **first** clause becomes the dispatch target, because a single `ctx_br_target` context
register exists (legacy EH has the same first-handler limitation). Later clauses are decoded,
validated and listed, but are not modelled as branches - see §5.

### 1.3 `try_table`: stack effects / validation

Per clause, the values a handler must push are computed and compared with the label's expected stack
(the label's *branch arguments*: its results for `block`/`if`, its params for `loop`):

| clause | values pushed at the handler |
| --- | --- |
| `catch x l` | tag `x`'s params |
| `catch_ref x l` | tag `x`'s params **+ `exnref`** |
| `catch_all l` | none |
| `catch_all_ref l` | `exnref` |

The label target is an ordinary block, so the linear walk over that block already produces exactly
those values at its `end` (the block's results are pushed there by the existing `end` handling);
the clause check makes the invariant explicit. A mismatch is reported as a **warning**, not a hard
error, so an unexpected module still disassembles (this differs deliberately from `br`'s
`ValidationException`; see §5). Reading a label index that does not exist still raises
`ValidationException` (same as `br`).

### 1.4 `throw_ref` (0x0A)

* Pre-analyzer: `case 0x0A` -> `EH2Ops.analyzeThrowRef` -> pops one `exnref` and calls the same
  `markUnreachable` that legacy `throw`/`rethrow` use, i.e. it ends the current block's reachability
  identically.
* SLEIGH: `:throw_ref is opc=0x0a; sp1_32; { wasm_throw_ref(sp1_32); trap(); }`, with a new
  `define pcodeop wasm_throw_ref`, mirroring `:throw`.

### 1.5 `exnref` (0x69)

`ValType.exnref(0x69)`; `asDataType()` returns the width-correct 4-byte `Undefined4DataType` (the
same placeholder `externref` uses), and `getSize()`'s default already returns 4. That makes `exnref`
usable in **function params/results, blocktypes, locals, globals and clauses**. Nothing else needed
changing: `WasmFuncType`, `WasmCodeEntry`, `WasmGlobalType`, `WasmAnalysis`, `WasmSignatureAnalyzer`,
`InjectPayloadWasmEntry` and `WasmFunctionVariableNameAnalyzer` all go through
`ValType.fromByte`/`getSize`/`asDataType`, so `exnref` is picked up automatically (probe 35 lists
`.local count=0x1 type=0x69` and decompiles `void f(undefined4 param1)`).
The SLEIGH `attach names valtype` table gained `exnref` at 0x69 so `ref.null exnref` prints as such.

## 2. Files changed (and every `@@EH` hook)

| file | change |
| --- | --- |
| `src/main/java/wasm/analysis/EH2Ops.java` | **new**. `analyzeTryTable` (operand bytes, clause kinds, stack values, label resolution, handler registration, clause directives) and `analyzeThrowRef`. |
| `src/main/java/wasm/analysis/WasmFunctionAnalysis.java` | `case 0x1F` / `case 0x0A` dispatch to `EH2Ops` (2 entries, one `// @@EH` comment); one `// @@EH begin/end` block of package-private bridge methods (`ehBlockTypeParamCount`, `ehClauseLabelTypes`, `ehEnterTryTable`, `ehMarkClause`, `ehThrowRef`); one `// @@EH` hunk in `ContextRegister` (`DIRECTIVE_EH_CLAUSE = 4` + `setEhClause`). No existing declaration, control frame or legacy EH path was modified. |
| `data/languages/EH2Ops.sinc` | **new**. `@define DIRECTIVE_EH_CLAUSE 4`, `pcodeop wasm_throw_ref`, `eh_tag`/`eh_label`, the 4 `:try_table` variants, the 4 clause directives, `:throw_ref`. |
| `data/languages/WebAssembly.sinc` | exactly two hunks: `exnref` added at slot 0x69 of `attach names valtype` (end-of-line `# @@EH` marker; the only edit inside the table), and one `@include "EH2Ops.sinc"` line next to the other includes (`# @@EH`). |
| `src/main/java/wasm/format/WasmEnums.java` | **two** `// @@EH` hunks, both required for the one feature: `exnref(0x69)` as the last enum constant (so it is in `BY_BYTE`), and a `case exnref: return Undefined4DataType.dataType;` in `asDataType()` (without it, `exnref` would be `null` and reproduce the probe-12 NPE class). `getSize()` needed no case (its default is 4). |
| `test-scripts/probes_eh.py` | **new** probe file (10 probes, 30-39). `test-scripts/gen_feature_probes.py`, `wasm_probe_lib.py`, `run_probes.ps1`, the report/dump scripts and the other `probes_*.py` were **not** touched. |
| `REPORT-F.md` | this file. |

Everything except the two required valtype hunks is additive; `EH2Ops.sinc` is a new file, and
`WasmFunctionAnalysis.java`'s existing lines are untouched (the bridges are new methods in one
block).

## 3. Before/after probe table

`u` = `undefined_bytes`, `d` = `decompiled/failed`. Before-column values are `MODERN_WASM_GAPS.md`
§2.4 (measured on the base commit); after-column values were measured on this branch with
`run_probes.ps1 -GhidraDir <ghidra-f> -Generators gen_feature_probes.py,probes_eh.py`.

| # | probe | funcs | before instrs | before u | d | after instrs | after u | after d |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 10 | `eh_legacy_try_catch` | 1 | 6 | 0 | 1/0 | **6** | **0** | **1/0** |
| 11 | `eh_try_table` (frozen baseline) | 1 | 1 | **5** | 1/0 | **4** | **0** | **1/0** |
| 30 | `eh2_try_table_empty` | 1 | - | - | - | 4 | 0 | 1/0 |
| 31 | `eh2_try_table_catch` | 1 | - | - | - | 10 | 0 | 1/0 |
| 32 | `eh2_try_table_catch_ref` | 1 | - | - | - | 13 | 0 | 1/0 |
| 33 | `eh2_try_table_catch_all` | 1 | - | - | - | 9 | 0 | 1/0 |
| 34 | `eh2_try_table_catch_all_ref` | 1 | - | - | - | 11 | 0 | 1/0 |
| 35 | `eh2_throw_ref_param` | 1 | - | - | - | 7 | 0 | 1/0 |
| 36 | `eh2_nested_try_table` | 1 | - | - | - | 15 | 0 | 1/0 |
| 37 | `eh2_mixed_legacy_new` | 2 | - | - | - | 12 | 0 | 2/0 |
| 38 | `eh2_exnref_global` | 1 | - | - | - | 4 | 0 | 1/0 |
| 39 | `eh2_try_table_multi_clause` | 1 | - | - | - | 11 | 0 | 1/0 |

All other frozen probes (`01`-`09`, `12`-`21`) are unchanged, row for row, against §2.4 - including
`12_call_ref` still failing to decompile (its NPE is owned by another workstream) and `19`/`20`/`21`
still failing to import (`ConstantExpression` / loader, owned elsewhere).

### 3.1 Listings (control flow is the point)

Probe 11 - a `try_table` with an empty clause vector now decodes as a real instruction (was
`unreachable` + 5 undefined bytes):

```
ram:80000023  try_table blocktype=0x40 catches=0x0
ram:80000026  end
ram:80000027  end
```

Probe 31 - `catch` clause; the clause dispatches to the enclosing block's `end` (0x80000033), and the
body's `throw` also branches there:

```
ram:80000027  block blocktype=0x7f
ram:80000029  try_table blocktype=0x40 0x80000033
ram:8000002c  .catch tag=0x0 label=0x0
ram:8000002e  i32.const 0x7
ram:80000030  throw tag=0x0
ram:80000032  end
ram:80000033  end
```

Probe 34 - `catch_all_ref`; the clause pushes an `exnref`, so the enclosing block has result
`exnref` and the dispatch writes a value (`0x80000039` is that block's `end`):

```
ram:8000002d  try_table blocktype=0x40 0x80000039
ram:80000030  .catch_all_ref label=0x0
```

Probe 36 - two nested `try_table`s; both clauses dispatch to the enclosing block's `end`
(0x80000042), and both `br`s (including the one that leaves *both* blocks) resolve to it:

```
ram:80000028  block blocktype=0x7f
ram:8000002a  try_table blocktype=0x40 0x80000042
ram:8000002d  .catch tag=0x0 label=0x0
ram:80000030  try_table blocktype=0x40 0x80000042
ram:80000033  .catch tag=0x0 label=0x1
ram:80000036  i32.const 0x1
ram:80000038  br 0x80000042          <- leaves the inner try_table
ram:8000003a  end
ram:8000003b  i32.const 0x2
ram:8000003d  br 0x80000042          <- leaves the outer try_table
ram:8000003f  end
ram:80000040  i32.const 0x3
ram:80000042  end
ram:80000043  end
```

Probe 39 - two clauses of different kinds (a 3-byte `catch` followed by a 2-byte `catch_all`): the
body starts at 0x32, i.e. every clause consumed exactly its own bytes, and the second clause's
`label=0x1` resolves past the inner block to the outer one:

```
ram:80000026  block blocktype=0x40
ram:80000028  block blocktype=0x40
ram:8000002a  try_table blocktype=0x40 0x80000035
ram:8000002d  .catch tag=0x0 label=0x0
ram:80000030  .catch_all label=0x1
ram:80000032  throw tag=0x0
ram:80000034  end
ram:80000035  end
ram:80000036  end
ram:80000037  end
```

Probe 37 - function `legacy` (unchanged bytes, unchanged listing) and function `new` side by side:

```
function legacy @ ram:8000002e void legacy(void)
ram:8000002f  try blocktype=0x40 0x80000035
ram:80000031  throw tag=0x0
ram:80000033  catch tag=0x0 0x80000035
ram:80000035  end
function new @ ram:80000038 void new(void)
ram:80000039  try_table blocktype=0x40 0x80000041
ram:8000003c  .catch_all label=0x0
ram:8000003e  throw tag=0x0
ram:80000040  end
ram:80000041  end
```

Probe 38 - `exnref` global: `global.get` of the defined mutable `exnref` global, then `throw_ref`:

```
ram:80000032  global.get 0x00000010
ram:80000034  throw_ref
```

Probe 35 - `throw_ref` with an `exnref` parameter and an `exnref` local:

```
ram:8000001e  .locals
ram:8000001f  .local count=0x1 type=0x69
ram:80000021  local.get l0
ram:80000023  local.set l1
ram:80000025  local.get l1
ram:80000027  throw_ref
```

### 3.2 What the decompiler shows for the caught exception

The dispatch is the same pseudo-op pair the legacy `try` handler uses, so the decompiled C reads
naturally. Probe 31 (`catch`, i32 payload, function returns i32):

```c
int export::f(void)
{
  char cVar1;
  int iVar2;

  cVar1 = wasm_exception_caught();
  if (cVar1 != '\0') {
    iVar2 = wasm_exception_payload();      // the caught exception's payload
    return iVar2;
  }
  wasm_throw(0,7);                         // normal path
  do { halt_trap(); } while( true );
}
```

Probe 33 (`catch_all`, nothing pushed) - `if (caught) return;`; probe 34 (`catch_all_ref`) -
`if (caught) { wasm_exception_payload(); return; }` (the `exnref` is shown as the same
`wasm_exception_payload()` value); probe 36 (nested) decompiles to correctly nested
`if (wasm_exception_caught())` arms; probe 32 (body `throw_ref`) - `wasm_throw_ref(param1); trap`;
probe 35 - `wasm_throw_ref(param1); trap`.

## 4. Regression

* **Frozen EH baseline kept**: probe 10 unchanged (1 / 6 / 0 / 1-0), identical listing and identical
  decompiled C before/after; `throw`/`catch`/`catch_all`/`rethrow`/`delegate` code paths were not
  edited (the only change in `WasmFunctionAnalysis` near them is the two new `case`s placed after the
  `delegate` case).
* **Whole frozen probe set unchanged**: probes 01-09 and 12-21 match §2.4 row for row (run without
  editing `gen_feature_probes.py`).
* **Real module**: `rasterbator_rs_bg.wasm` ->
  `SUMMARY functions=437 decompiled=437 failed=0 instructions=61658` (unchanged; also
  `undefined_bytes=156`, the pre-existing value for that module). Command:

  ```
  analyzeHeadless <ghidra-f>\proj Reg -import <rasterbator_rs_bg.wasm> \
      -scriptPath D:\code\ghidra-wt-f\test-scripts -postScript DumpDecomp.java -max-cpu 2 -deleteProject
  ```

## 5. Deliberately not implemented

* **Only the first catch clause is a modelled branch target.** One `ctx_br_target` register exists
  per instruction, exactly the same constraint that limits legacy EH to its first handler. Later
  clauses are decoded, listed, stack-checked and (in `try_table`'s own listing) shown as directives,
  but no branch is drawn from the `try_table` to them, and the decompiler shows the single
  `wasm_exception_caught()` test. Modelling each clause would need extra context registers and a
  synthetic branch instruction per clause.
* **Precise `catch_ref`/`catch_all_ref` value typing.** An `exnref` is not a distinct value type in
  the p-code model: it is a 4-byte `undefined4`, and a dispatched `_ref` clause's value is shown as
  the same `wasm_exception_payload()` callother as a `catch` payload (no separate
  `wasm_exception_ref()`). No attempt is made to reconstruct the exception object.
* **No runtime/emulation semantics.** `wasm_throw_ref` is an opaque CALLOTHER (like `wasm_throw`)
  and `halt_trap` still follows it; there is no shadow-stack unwinding, no tag matching in the
  emulator, and no interaction with a real (V8/Wasmer) runtime.
* **Multi-value clauses are dispatched without a value** when the clause pushes more than one value
  (e.g. `catch_ref` with a payload -> `[i32 exnref]`) or when the `try_table` itself has params:
  like legacy `try`, `ctx_operand_size` is only set when exactly one value is pushed, there are no
  `try_table` params, and the value is <= 8 bytes. Such handlers take the `goto br_target` variant;
  the handler's values then come from the label's own block-result path in the linear walk.
* **Clause directives carry no p-code** (display only), exactly like `br_table`'s `.case`/`.default`.
* **Advisory clause validation.** A clause whose values do not match its label is a `Msg.warn`
  (listing stays), not a `ValidationException`. An *invalid label index* is still fatal, as for `br`.
* **GC-typed references** (`(ref null $t)`, `anyref`, ...) are untouched - other
  workstreams own those.
* **`ref.null exn` in a global initializer** is rejected by `ConstantExpression` (probe 38 therefore
  initializes its `exnref` global from an *imported* `exnref` global via `global.get`).
  `ConstantExpression.java` is explicitly off-limits for this workstream; this is a follow-up for
  its owner (it currently throws `Invalid ref.null reftype 105`).
* **No real LLVM >= 19 module with `try_table` was available** in this environment: probe bytes are
  hand-encoded from the proposal/spec, so real-toolchain output is unverified (see §6).
* Unknown clause kinds are not decoded further (warning + block still entered); general
  unknown-opcode graceful degradation is another workstream's item.

## 6. Open questions

1. **`_ref` display.** Would a distinct `wasm_exception_ref()` callother (and, if the decompiler can
   carry it, an `exnref` data type) be worth it, versus reusing `wasm_exception_payload()`? It would
   make `catch_ref` handlers readable but adds a pseudo-op for a value that is otherwise unused.
2. **`BlockKind.TRY_TABLE`.** `try_table` uses `BlockKind.BLOCK` (its label semantics are a block's,
   and this keeps the diff minimal). A distinct kind would let `delegate`/legacy `catch` reject a
   `try_table` frame explicitly and allow future try_table-specific handling. Worth adding when
   something actually needs it.
3. **Real-toolchain validation.** The next confidence step is to compile a small C++/Rust program
   with clang 19+ `-fwasm-exceptions` (or `wasm-opt`/`wat2wasm` from a hand-written `.wat`) and
   check the listing against the bytes. Not possible here (no LLVM 19+ wasm target in the sandbox),
   so the encoding is verified against the spec only.
4. **Multiple clauses.** If a future change adds a second branch-target context register, all clauses
   could be modelled; is that worth it given the decompiler would show a chain of
   `wasm_exception_caught()` tests anyway?
5. **Param-carrying `try_table`s.** A `try_table` with a blocktype index that has params enters and
   exits correctly, but the dispatch value is deliberately not written (see §5). A probe for that
   shape is not in the required list; worth adding if a real module exercises it.

## 7. How to reproduce

```powershell
# build + clean install
& D:\code\ghidra-wt-f\test-scripts\build-install.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-f"

# EH probes (frozen baseline 10/11 + this workstream's 30-39), with listings and decompiled C
& D:\code\ghidra-wt-f\test-scripts\run_probes.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-f" `
    -Generators gen_feature_probes.py,probes_eh.py -Only eh -Detail

# whole frozen suite (regression against MODERN_WASM_GAPS 2.4)
& D:\code\ghidra-wt-f\test-scripts\run_probes.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-f" `
    -Generators gen_feature_probes.py,probes_eh.py

# real-module regression
& "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-f\support\analyzeHeadless.bat" `
    "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-f\proj" Reg `
    -import "D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm" `
    -scriptPath "D:\code\ghidra-wt-f\test-scripts" -postScript DumpDecomp.java -max-cpu 2 -deleteProject
```

Note: `run_probes.ps1`'s default output directory is `%TEMP%\wasm-probes`, which several agents share;
pass `-OutDir` (this workstream used `%TEMP%\wasm-probes-f`) to avoid reading another agent's log.
`%TEMP%\opencode\ghidra-f\proj` must exist before the real-module command (it may be deleted by
`-deleteProject`).
