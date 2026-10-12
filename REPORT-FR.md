# REPORT-FR - Function-references instructions (`call_ref`, `return_call_ref`, `ref.as_non_null`, `br_on_null`, `br_on_non_null`)

Roadmap: the last **instruction** gap of the function-references proposal, on top of the already
merged reference *types* (multi-byte `(ref null $t)`/`(ref $t)` in `ValType.readFromReader`, GC
abstract types) and the new-EH/multi-memory/degradation work.

Branch `feat/funcref-instrs`, worktree `D:\code\ghidra-wt-p`, base commit `c02b6b9`.

## 0. Headline

| | before | after |
| --- | --- | --- |
| probe `12_call_ref` (frozen baseline) | 4 instrs, **1 undefined byte** (`0x14` never decodes; the `typeidx` byte `0x00` is misread as `unreachable`) | 4 instrs, **0 undefined bytes**, `call_ref type=0x0`, C `(*param1)();` |
| `call_ref` (0x14) | not decoded | decoded, stack-modelled, real call in the decompiler |
| `return_call_ref` (0x15) | not decoded | decoded, tail call in the decompiler |
| `ref.as_non_null` (0xD4) | not decoded | decoded, width-preserving identity |
| `br_on_null` (0xD5) / `br_on_non_null` (0xD6) | not decoded | decoded, branch targets resolved through the existing control-frame/context machinery |
| new probe file `probes_funcref.py` | - | 7 probes (`F01`-`F07`), **all `undefined_bytes=0`, all decompile** |
| everything else in the frozen 27-probe baseline (01-11, 13-27) | §2.4 | **unchanged**, row for row |
| `probes_types.py` B16/B17 (both contain a `call_ref`; not edited) | 6 instrs / **1 undefined byte** | 6 instrs / **0 undefined bytes** (side effect of 0x14 decoding) |
| real-module regression (`rasterbator_rs_bg.wasm`) | `functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156` | **identical** |

The CI gate passes after re-recording: `OK: every probe matches the recorded baseline.`

## 1. Decoding (SLEIGH) - `data/languages/WebAssembly.sinc`

Five constructors, all `ctx_is_directive=0`, all consuming exactly their encoded immediates so that
`undefined_bytes` drops to 0 and every following instruction stays at its true address.

### 1.1 `call_ref` / `return_call_ref` (0x14 / 0x15)

```sleigh
:call_ref "type="^typeidx is opc=0x14; typeidx; sp1_32; ctx_is_directive=0 {
	ref_target:4 = sp1_32;
	LR = inst_next;
	callPrologueCallOther(&i0);
	call [ref_target];
	pushCallOther(&o0);
}
:return_call_ref "type="^typeidx is opc=0x15; typeidx; sp1_32; ctx_is_directive=0 {
	ref_target:4 = sp1_32;
	LR = inst_next;
	callPrologueCallOther(&i0);
	call [ref_target];
	return [LR];
}
```

These are `call_indirect`/`return_call_indirect` with the table load replaced by the operand stack:

* Per the proposal the function reference is the **top operand-stack value** when the instruction
  executes (the arguments sit below it), exactly like `call_indirect`'s table index. So it is read
  from stack slot `ctx_sp - 1` (the existing `sp1_32` context-indexed register operand) and the call
  is **indirect through that value** (`call [ref_target]`), which is the same shape as
  `call_indirect`'s `call [val]`.
* The existing call machinery is reused unchanged: `callPrologueCallOther(&i0)`
  (`InjectPayloadWasmCallPrologue` -> `InjectPayloadWasmPop`) moves the arguments from the stack into
  the input registers, and `pushCallOther(&o0)` moves the results back.
  `PcodeInjectLibraryWasm`, the `call*` pcode injection and `WasmFuncSignature` are untouched.
* `return_call_ref` mirrors `return_call`: it ends with `return [LR]` (the callee's outputs are
  already in the output registers) instead of `pushCallOther`.

**How `call_ref` is modelled for the decompiler.** When the reference value is a *known function
address* the loader/decompiler resolve it and the call is a real call: `ref.func $f; call_ref $t`
decompiles to `f(arg)` (see `F07`: `unnamed_function_0(4)`), and a table-loaded reference decompiles
to a real indirect call through the table (`F06`: `(*(code *)table0[0])(0x2a)`). When the reference
is a runtime value (a parameter/local), the decompiler shows a call through that value (`12_call_ref`
-> `(*param1)();`, `F01` -> `iVar1 = (*param1)(param2);`). No branch target is recorded, because the
callee is dynamic - the same treatment `call_indirect` gets.

### 1.2 `ref.as_non_null` (0xD4)

```sleigh
:ref.as_non_null is opc=0xd4; sp1_32; ctx_is_directive=0 {
	ref_value:4 = sp1_32;
	sp1_32 = ref_value;
}
```

The value is read from the top stack slot and written back unchanged: a width-preserving identity.
`ValType` (a non-owned enum) carries **no nullability**, so there is nothing else to express; the
decompiler sees the reference pass through with no operation (probe `F02` decompiles to `return;`
around a dropped value). This is documented in the constructor comment and in §5.

### 1.3 `br_on_null` (0xD5) / `br_on_non_null` (0xD6)

```sleigh
:br_on_null br_target is opc=0xd5; ULeb128; br_target; sp1_32; ctx_is_directive=0 {
	nop();
	if (sp1_32 != 0) goto inst_next;
	doBranch(br_target);
}
:br_on_non_null br_target is opc=0xd6; ULeb128; br_target; sp1_32; ctx_is_directive=0 {
	nop();
	if (sp1_32 == 0) goto inst_next;
	doBranch(br_target);
}
```

`0xD5` branches when the reference is null (`0`), `0xD6` when it is non-null - the mirror images of
`if` and `br_if`. Only the existing `nop`/`goto inst_next`/`doBranch` idioms are used, so the branch
target is a normal context-register target: `br_target` is the shared `ctx_br_target` operand, which
the pre-analyzer fills in from the control frame (see §2.3).

## 2. Stack model - `src/main/java/wasm/analysis/WasmFunctionAnalysis.java`

### 2.1 `call_ref` (0x14) / `return_call_ref` (0x15)

New `case`s next to `call_indirect`/`return_call_indirect`:

```java
case 0x14: /* call_ref x */ {
	long typeidx = readLeb128(reader);
	WasmFuncType type = analysis.getType((int) typeidx);
	ValType[] params = type.getParamTypes();
	ValType[] returns = type.getReturnTypes();
	if (popReferenceAndArgs(instAddress, params)) {
		setStackEffect(instAddress, valueStack.size(), params, valueStack.size(), returns);
	}
	pushValues(instAddress, returns);
	break;
}
case 0x15: /* return_call_ref x */ {
	... same, then markUnreachable(instAddress);
}
```

* The type index is resolved with the existing `analysis.getType` (the same table `call_indirect`
  uses), so the argument and result types come from `WasmFuncType`.
* The function reference is the top operand-stack value and is popped first, then the arguments.
  **Only the arguments go into the recorded stack effect** - the reference is read directly from the
  stack by the SLEIGH `sp1_32` operand, and `InjectPayloadWasmPop.emitPops` reads `stackEffect`,
  whose `popHeight` is the height *after* both pops, so the arguments land in the right slots.
* The concrete referenced type `$t` is not modelled, so the popped reference is accepted as any type
  (not `funcref`): `(ref null $t)` parameters are currently folded onto the `externref` placeholder
  by `ValType.readFromReader`.

### 2.2 Two small helpers: tolerant pop for the typed-reference calls

The frozen `12_call_ref` probe is deliberately under-typed: its body pushes a single value
(`local.get 0`, the reference) while `call_ref 0` references a type `((ref null 0)) -> ()` that also
takes one argument. A strict `popValue` would throw `pop from empty stack` and blank the function
(which is exactly what a naive implementation does - see the "after2" experiment noted in §4).
Because the referenced type cannot be verified without heap-type information, the two calls degrade
a missing value instead of voiding the function:

```java
private ValType popValueTolerant(Address instAddress) {
	ControlFrame curBlock = getBlock(instAddress, 0);
	if (valueStack.size() <= curBlock.initialStack.size()) {
		return null;                     /* phantom value, no throw */
	}
	return valueStack.remove(valueStack.size() - 1);
}

private boolean popReferenceAndArgs(Address instAddress, ValType[] params) {
	boolean complete = popValueTolerant(instAddress) != null;
	for (int i = params.length - 1; i >= 0; i--) {
		if (popValueTolerant(instAddress) == null) {
			complete = false;
		}
	}
	return complete;
}
```

The stack effect is only recorded when every value was present (`complete`), so a degraded callsite
simply gets no injected argument pops rather than a wrong one. This follows the file's existing
"degrade instead of blank the function" policy (`markUnimplemented` / `hasUnimplementedOps`), just
scoped to the two instructions that need it.

### 2.3 `ref.as_non_null` (0xD4), `br_on_null` (0xD5), `br_on_non_null` (0xD6)

New `case`s next to `ref.eq` (0xD3):

```java
case 0xD4: { /* ref.as_non_null */
	ValType ref = popValue(instAddress);           /* same 4-byte reference */
	pushValue(instAddress, (ref != null) ? ref : ValType.externref);
	break;
}
case 0xD5: /* br_on_null l */ {
	long labelidx = readLeb128(reader);
	ValType ref = popValue(instAddress);
	ControlFrame block = getBlock(instAddress, labelidx);
	block.addBranch(instAddress);
	pushValue(instAddress, (ref != null) ? ref : ValType.externref);   /* fall-through keeps it */
	break;
}
case 0xD6: /* br_on_non_null l */ {
	long labelidx = readLeb128(reader);
	popValue(instAddress);
	ControlFrame block = getBlock(instAddress, labelidx);
	block.addBranch(instAddress);                  /* fall-through consumes the (null) reference */
	break;
}
```

Stack effects per the proposal:

| instruction | popped | fall-through | branch target receives |
| --- | --- | --- | --- |
| `ref.as_non_null` | `(ref null ht)` | `(ref ht)` | - |
| `br_on_null l` | `(ref null ht)` | `t* (ref ht)` | `t*` |
| `br_on_non_null l` | `(ref null ht)` | `t*` | `t* (ref ht)` |

Branch-target resolution reuses the existing control-frame machinery: `getBlock(instAddress, labelidx)`
resolves the label, and `block.addBranch(instAddress)` records the instruction so that
`ControlFrame.setEnd` writes the final target into the `ctx_br_target` context register - the same
path `br`/`br_if`/`br_on_cast` use. The listing then prints the resolved target address, e.g.
`br_on_null 0x80000027` and `br_on_non_null 0x8000002e`.

As with the existing `br_on_cast` handling (`gcConditionalRefBranch`), no `setStackEffect` is recorded
for the `br_on_*` forms, so the branch payload is not moved into the temporary registers. The
resulting CFG is still correct (see the `F04` C in §3); only a branch that needs to carry values
across would be less precise. `WasmSignatureAnalyzer` was **not** touched: no typed-ref application
turned out to be necessary (see §5).

## 3. Probe evidence

Probes: `test-scripts/probes_funcref.py` (new, own file), built on `wasm_probe_lib.py` (not edited).

| probe | before | after |
| --- | --- | --- |
| `12_call_ref` | 4 instrs / **1 undefined** | 4 instrs / **0 undefined** |
| `F01_return_call_ref` | 8 / 1 | 8 / 0 |
| `F02_ref_as_non_null` | 4 / 1 | 5 / 0 |
| `F03_br_on_null` | 7 / 1 | 7 / 0 |
| `F04_br_on_null_fallthrough` | 8 / 1 | 8 / 0 |
| `F05_br_on_non_null` | 8 / 1 | 8 / 0 |
| `F06_call_ref_through_table` | 9 / 1 | 9 / 0 |
| `F07_funcref_mixed` | 20 / **2** | 20 / 0 |

All "after" rows: `decompiled == funcs`, `decompile_failed == 0`.

Before/after captured by `git stash`-ing only the two source files, rebuilding + installing, running
`run_probes.ps1 -Generators probes_funcref.py,gen_feature_probes.py -Detail`, then restoring and
rebuilding.

### 3.1 `12_call_ref` (the baseline gap)

Before - the `0x14` byte is undefined, so Ghidra skips it and misreads the `typeidx` byte `0x00`
as `unreachable`:

```
function f @ ram:8000001f void f(undefined4 param1)
ram:8000001f  .locals
ram:80000020  local.get l0
ram:80000023  unreachable
ram:80000024  end
```
(and the decompiler log complains `pcode error at ram:80000022: Unable to resolve constructor`)

After:

```
function f @ ram:8000001f void f(undefined4 param1)
ram:8000001f  .locals
ram:80000020  local.get l0
ram:80000022  call_ref type=0x0
ram:80000024  end
```

```c
void f(undefined4 param1)
{
  (*param1)();
  return;
}
```

### 3.2 `F01_return_call_ref`

```
ram:80000028  local.get l1
ram:8000002a  local.get l0
ram:8000002c  return_call_ref type=0x0
ram:8000002e  end
```

```c
int f(undefined4 param1, undefined4 param2)
{
  int iVar1;
  iVar1 = (*param1)(param2);
  return iVar1;
}
```

### 3.3 `F02_ref_as_non_null`

```
ram:80000020  local.get l0
ram:80000022  ref.as_non_null
ram:80000023  drop
ram:80000024  end
```

```c
void f(undefined4 param1)
{
  return;
}
```

The reference passes through unchanged (it is immediately dropped); there is no operation to show,
which is the documented behaviour for a width-preserving, nullability-only change.

### 3.4 `F03_br_on_null` (branch to the enclosing block end)

```
ram:80000020  block blocktype=0x40
ram:80000022  local.get l0
ram:80000024  br_on_null 0x80000027     <- resolved branch target
ram:80000026  drop
ram:80000027  end
ram:80000028  end
```

### 3.5 `F04_br_on_null_fallthrough` (both outcomes observable)

The branch to the function's own label carries the i32 below the reference; the fall-through drops the
non-null reference and produces a different i32.

```
ram:80000021  i32.const 0x1
ram:80000023  local.get l0
ram:80000025  br_on_null 0x8000002b     <- resolved branch target
ram:80000027  drop
ram:80000028  drop
ram:80000029  i32.const 0x2
ram:8000002b  end
```

```c
int f(undefined4 param1)
{
  int iVar1;
  iVar1 = 1;
  if (param1 != 0) {
    iVar1 = 2;
  }
  return iVar1;
}
```

### 3.6 `F05_br_on_non_null`

```
ram:80000026  block blocktype=0x0
ram:80000028  local.get l0
ram:8000002a  br_on_non_null 0x8000002e  <- resolved branch target
ram:8000002c  local.get l0
ram:8000002e  end
ram:8000002f  ref.is_null
ram:80000030  end
```

```c
int f(undefined4 param1)
{
  return (uint)(param1 == 0);
}
```

### 3.7 `F06_call_ref_through_table` (reference from `table.get`)

```
ram:80000039  i32.const 0x2a
ram:8000003b  i32.const 0x0
ram:8000003d  table.get 0x00000000
ram:8000003f  call_ref type=0x0
ram:80000041  end
```

```c
int export::f(void)
{
  int iVar1;
  iVar1 = (*(code *)table0[0])(0x2a);
  return iVar1;
}
```

The loader resolves the element segment to the function address stored in table 0, so this is a real
call through the table - identical in shape to a `call_indirect`.

### 3.8 `F07_funcref_mixed` (function-references module mixing typed refs with `call`/`call_indirect`)

```
ram:8000003a  i32.const 0x5
ram:8000003c  call 0x80000034
ram:8000003e  drop
ram:8000003f  i32.const 0x0
ram:80000041  i32.const 0x3
ram:80000043  call_indirect type=0x0 0x00000000
ram:80000046  drop
ram:80000047  i32.const 0x9
ram:80000049  local.get l0
ram:8000004b  call_ref type=0x0
ram:8000004d  drop
ram:8000004e  i32.const 0x4
ram:80000050  ref.func 0x80000034
ram:80000052  call_ref type=0x0
ram:80000054  drop
ram:80000055  end
```

```c
void f(undefined4 param1)
{
  unnamed_function_0(5);            // call 0        (direct)
  (*_DAT_table_0000000c)(0);        // call_indirect (table 0)
  (*param1)(9);                     // call_ref through the typed reference parameter
  unnamed_function_0(4);            // call_ref through ref.func 0 -> resolved to the real function
  return;
}
```

The last one is the strongest evidence that `call_ref` reuses the real call machinery: a
`ref.func`-produced reference resolves to `unnamed_function_0` and is decompiled as a direct call
with the argument.

## 4. CI baseline

Commands (worktree as the working directory, private install, `-SkipBuild` because the extension was
already built and installed from this worktree):

```
& .\test-scripts\check-local.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-i" -SkipBuild -Update -OutDir "C:\Users\micro\AppData\Local\Temp\opencode\ci-p-update"
```

```
== probe suite ==
== generating probes ==
-- gen_feature_probes.py
-- probes_analysis.py
-- probes_component.py
-- probes_eh.py
-- probes_funcref.py
-- probes_gc.py
-- probes_types.py
== running 100 probe(s) ==
== results ==
== DumpDecomp wasm_fixture.wasm -> fixture-run.log ==
== check-results.py ==
SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0
updated D:\code\ghidra-wt-p\test-scripts\expected-results.json: 97 probe(s) with metrics, 3 expected import failure(s)
```

The recorded diff is exactly what the change implies - only `12_call_ref` in the frozen 27-probe
baseline, plus the two `probes_types.py` B-probes that embed a `call_ref`, plus the 7 new F-probes:

```
12_call_ref.wasm:              undefined_bytes 1 -> 0
B16_valtype_ref_null_param:    undefined_bytes 1 -> 0
B17_valtype_ref_param:         undefined_bytes 1 -> 0
+ F01..F07 (all undefined_bytes 0, all decompile)
probe_count: 93 -> 100
fixture: unchanged (functions=4 decompiled=4 failed=0 instructions=24)
```

Plain verification run (no `-Update`):

```
& .\test-scripts\check-local.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-i" -SkipBuild -OutDir "C:\Users\micro\AppData\Local\Temp\opencode\ci-p-check"
```

```
== probe suite ==
...
== running 100 probe(s) ==
== DumpDecomp wasm_fixture.wasm -> fixture-run.log ==
== check-results.py ==
SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0
probes: 97 imported, 3 import failure(s); baseline has 100
OK: every probe matches the recorded baseline.
```

(Exit code 0.)

## 5. Real-module regression

```
$h = "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-i\support\analyzeHeadless.bat"
& $h "$env:TEMP\opencode\real-p-proj" Reg -import "D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm" `
    -scriptPath "D:\code\ghidra-wt-p\test-scripts" -postScript DumpDecomp.java -max-cpu 2 -deleteProject
```

```
SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156
```

Identical to the recorded baseline (`functions=437 decompiled=437 failed=0 instructions=61658`, and
`undefined_bytes=156` in `expected-results.json`). No `DECOMPILE FAIL` lines.

## 6. What remains unsupported / not modelled

* **Concrete `call_ref` target typing.** The `typeidx` immediate is decoded and displayed
  (`call_ref type=0x0`) and is used for the argument/result *widths*, but it is not applied as a
  callee prototype: the visible call signature comes from the resolved callee address, or, when the
  reference is dynamic, from the injected argument pops. There is no callee/type placeholder
  synthesized - the decompiler simply sees an indirect call through the reference value. That is the
  deliberate "width-correct, no typing" choice requested; nothing in `WasmSignatureAnalyzer` had to
  change.
* **Nullability / typed reference refinement.** `ValType.readFromReader` folds every
  `(ref null $t)` / `(ref $t)` onto a single 4-byte reference placeholder (`externref`), so
  `ref.as_non_null` is a no-op and `br_on_null`/`br_on_non_null` do not refine the tracked type
  (the null test is still emitted, so the CFG is right - see `F04`). Tracking the concrete heap type
  would need either a new `ValType` representation (a non-owned file) or a parallel type lattice;
  out of scope here.
* **Branch payloads for `br_on_null`/`br_on_non_null`.** Like the pre-existing `br_on_cast`
  handling, no `StackEffect` is recorded, so the branch's carried values are not moved into the
  temporary registers. A `br_on_*` whose label consumes values (not exercised by the probes) would
  decompile less precisely than a `br`/`br_if`.
* **Tolerant `call_ref`/`return_call_ref` stack use.** A callsite that does not actually push the
  reference's arguments degrades to a phantom argument instead of failing validation. This is what
  makes the deliberately under-typed `12_call_ref` work; a strict implementation blanks that function.
* **table64 / 64-bit tables.** Untouched: table addressing in the language is still
  `&tableref + zext(sp1_32) * 4` (32-bit indices). `call_ref` itself takes no table index, but the
  `table.get`-fed form inherits the 32-bit restriction.
* **`ref.as_non_null` in the p-code is a self-copy.** Because there is no nullability in the type
  model there is no runtime check to emit; the instruction is a faithful width-preserving identity,
  not a trap-on-null.

## 7. Files changed

| file | change |
| --- | --- |
| `data/languages/WebAssembly.sinc` | 5 new constructors (`0x14`, `0x15`, `0xD4`, `0xD5`, `0xD6`) + comments |
| `src/main/java/wasm/analysis/WasmFunctionAnalysis.java` | 5 new `case`s, `popValueTolerant`/`popReferenceAndArgs` helpers + comments |
| `test-scripts/probes_funcref.py` | new probe generator, 7 probes |
| `test-scripts/expected-results.json` | re-recorded via `check-local.ps1 -Update` |
| `REPORT-FR.md` | this report |

No other file was edited (`WasmLoader`, `WasmEnums`, `WasmFuncType`, `WasmSignatureAnalyzer`,
the other probe generators, the CI scripts and scripts/CI config are untouched).
