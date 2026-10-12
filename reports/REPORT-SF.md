# REPORT-SF — closing the three ranked spec-suite findings

Branch `fix/spec-findings`, base `c02b6b9`. Worktree `D:\code\ghidra-wt-o`.
Plugin built and clean-installed into Ghidra 12.1.4 (`$env:TEMP\opencode\ghidra-g`) with
`test-scripts/build-install.ps1`.

Scope: the three ranked findings of the official spec-suite run in `MODERN_WASM_GAPS.md` §6 /
`REPORT-G.md` §3 / `test-scripts/spectest-BASELINE.md` §3:

1. `select` (0x1B) not decoded after an unconditional terminator (the only real decode gap).
2. `WasmStackVariableAnalyzer` exceptions (`Index 0 out of bounds for length 0`,
   `GenericAddress cannot be cast to Register`).
3. Decompiler process death on a very large function body (`br_table.0.wasm:large`).

Files changed (all in the owned set): `data/languages/WebAssembly.sinc`,
`data/languages/WebAssembly.slaspec`, `src/main/java/wasm/analysis/WasmFunctionAnalysis.java`,
`src/main/java/wasm/analysis/WasmStackVariableAnalyzer.java`, plus the new probe generator
`test-scripts/probes_spec_fixes.py`. No other file was edited.

---

## Finding 1 — `select` (0x1B) after an unconditional terminator

### Root cause

`select`'s *encoding* is a single opcode byte, independent of the operand type, but the three
SLEIGH constructors in `data/languages/WebAssembly.sinc` are guarded by `ctx_operand_size`
(`4`/`8`/`16`, i.e. `select32`/`select64`/`select128`). `ctx_operand_size` is a `noflow` context
field, so at any address where the pre-analyzer does not explicitly set it, the disassembler sees
the default value `0` and *no* `select` constructor matches — the byte stays undefined.

The pre-analyzer (`WasmFunctionAnalysis.analyzeOpcode`, `case 0x1B`) computes the result width from
the value stack and calls `ContextRegister.setOperandSize(...)`. In unreachable (polymorphic) code
the pops return `null`, so `setOperandSize(addr, null)` was a no-op (it returned early unless the
*unimplemented-opcode* `degradeWidths` flag was set). Hence every `select` whose byte is adjacent to
an unconditional terminator (`unreachable`, `br`, `br_table`, `return`) was left undefined — which
is exactly the shape of the spec suite's `unwind.wast` `select-after-*` functions. Any
value-producing instruction between the terminator and the `select` re-establishes the context,
which is why `select-after-br_if` (a *conditional* branch that never marks the block unreachable)
and ordinary reachable `select`s always decoded.

### Fix

`WasmFunctionAnalysis.ContextRegister.setOperandSize` now always degrades an unknown width to
32-bit (a defined `ctx_operand_size = 4`) instead of leaving the context unset. The `degradeWidths`
field/`setDegradeWidths` plumbing (previously needed only after an unimplemented opcode) is gone.
This is the "keep the operand-size context defined (default 32-bit) for unreachable code" option
from the finding; no SLEIGH change was needed for this finding.

```java
public void setOperandSize(Address address, ValType type) {
    if (type == null) {
        // ... unreachable (polymorphic) code, or an unmodelled stack effect:
        // the encoding is width-independent, but the ctx_operand_size-conditioned
        // constructors (select, local.*, global.*) need a defined value.
        type = ValType.i32;
    }
    setRegister(address, REG_OPERAND_SIZE, type.getSize());
}
```

Accepted limitation: a `select` whose real type is `i64`/`v128` and whose byte is only reachable
through unreachable code is decoded as the 32-bit variant (upper bits of the stack slot are lost).
That matches the fallback the tree already used for unmodelled instructions; the alternative (no
instruction at all) loses the byte entirely.

### Evidence

Probe `SF01_select_after_terminator.wasm` (`probes_spec_fixes.py`), five functions mirroring the
spec suite (`select` adjacent to the terminator): `f0` after `unreachable`, `f1` after `br`,
`f2` after `return`, `f3` after `br_table`, `f4` after `unreachable` then `drop`.

| probe | before | after |
| --- | --- | --- |
| `SF01_select_after_terminator.wasm` | `funcs=5 instrs=39 undefined_bytes=5 decompiled=5 decompile_failed=0` (one `0x1B` per function) | `funcs=5 instrs=44 undefined_bytes=0 decompiled=5 decompile_failed=0` |

Spec suite, focused run (`run_spectest.ps1 -Files unwind,br_table -MaxPerWast 10`):

| metric | before (`spectest-o-before`) | after (`spectest-o-after`) |
| --- | ---: | ---: |
| undefined_bytes | 6 | **0** |
| decode_gap_bytes | 6 | **0** |
| funcs_with_undef | 6 | **0** |
| instructions | 17475 | 17481 (+6: the six recovered `select` bytes) |
| decompiled / failed | 118 / 1 | **119 / 0** |
| `stackvar_failures` / `log_failure_lines` | 6 / 6 | **0 / 0** |

Before, all four `unwind.wast` `select-after-*` functions and both `br_table.wast` `as-select-*`
functions left the `select` byte undefined:

```
SPECFUNC ... fn=select-after-unreachable ... undef=1 undef_at=ram:80000797
SPECFUNC ... fn=select-after-br          ... undef=1 undef_at=ram:800007b1
SPECFUNC ... fn=select-after-br_table    ... undef=1 undef_at=ram:800007e3
SPECFUNC ... fn=select-after-return      ... undef=1 undef_at=ram:800007fb
```

After, the focused run emits **no `SPECFUNC` line at all** (no undefined byte, no
decompile failure) and both modules are clean:

```
SPECMODULE name=br_table.0.wasm funcs=70 instrs=17046 body_bytes=17547 undefined_bytes=0 undef_funcs=0 decompiled=70 decompile_failed=0
SPECMODULE name=unwind.0.wasm  funcs=49 instrs=435   body_bytes=778   undefined_bytes=0 undef_funcs=0 decompiled=49 decompile_failed=0
```

Full core subset (`run_spectest.ps1 -Subset core -MaxPerWast 10`, 271 modules), before (recorded
baseline) vs after:

| metric | before (`spectest-BASELINE.md`) | after (`spectest-o-core`) |
| --- | ---: | ---: |
| modules imported | 271 | 271 |
| functions / instructions | 2747 / 33192 | 2747 / 33222 (+30: the recovered `select` bytes) |
| undefined bytes | 458 (428 stub + **30 real**) | 428 (428 stub + **0 real**) |
| `decode_gap_funcs` / `decode_gap_bytes` | 24 / 30 | **0 / 0** |
| decompiled / failed | 2746 / **1** | **2747 / 0** |
| `stackvar_failures` / `log_failure_lines` | 23 / – | **0 / 0** |

---

## Finding 2 — `WasmStackVariableAnalyzer` exceptions

### Root cause

`src/main/java/wasm/analysis/WasmStackVariableAnalyzer.java` assumed both that a load/store
instruction always has at least one `Register` in `getInputObjects()`, and that
`getInputObjects()[0]` of a `local.get`/`local.set` is a `Register`:

```java
Register base = getRegisters(instr.getInputObjects()).get(0);   // Index 0 out of bounds for length 0
...
Register input = (Register) instr.getInputObjects()[0];          // GenericAddress cannot be cast to Register
```

The trigger is an instruction in *unreachable* code (the spec suite's `return.wast` has functions
named for exactly this: `as-load-address`, `as-loadN-address`, `as-local.set-value`, `as-store-*`).
After a terminator the pre-analyzer records `ctx_sp = 0`, so the modelled stack slot is at register
index `-1` (`REG_STACK_BASE - 16`), which is *not* a defined register. Ghidra then reports that
operand as a dynamic `GenericAddress` rather than a `Register`: the extracted register list is
empty (`.get(0)` → `IndexOutOfBoundsException`) or the cast to `Register` fails
(`ClassCastException`). Both were caught by the loop's `catch (Exception)` and logged as warnings,
so analysis continued but stack-variable recovery for those instructions was silently lost.

### Fix

Guard both shapes instead of indexing/casting unconditionally:

* load/store: `getRegisters(...)` is checked for emptiness before `get(0)`; the `offset=` operand
  is also read through a null-checked helper (`getMemoryOffset`) instead of a blind
  `(Scalar) instr.getOpObjects(0)[1]`.
* `local.get`/`local.set`: the first `Register` among the input objects is selected
  (`firstRegister(...)`); if there is none the instruction is skipped.

No behaviour change when a Register is present (identical objects/order to before).

### Evidence

Five probes in `probes_spec_fixes.py`, one per reported opcode, each in unreachable code
(`unreachable` immediately followed by the instruction):

`SF02_stackvar_local_set.wasm`, `SF02_stackvar_f32_load.wasm`, `SF02_stackvar_i64_store.wasm`,
`SF02_stackvar_i64_load8_s.wasm`, `SF02_stackvar_i64_store16.wasm`.

Before (WasmStackVariableAnalyzer warnings in `probe-run.log`):

```
WARN Failed to process instruction at ram:80000020: f32.load align=0x2 offset=0x0: Index 0 out of bounds for length 0
WARN Failed to process instruction at ram:80000020: i64.load8_s align=0x0 offset=0x0: Index 0 out of bounds for length 0
WARN Failed to process instruction at ram:80000020: i64.store align=0x3 offset=0x0: Index 0 out of bounds for length 0
WARN Failed to process instruction at ram:80000020: i64.store16 align=0x1 offset=0x0: Index 0 out of bounds for length 0
WARN Failed to process instruction at ram:80000020: local.set l0: class ghidra.program.model.address.GenericAddress cannot be cast to class ghidra.program.model.lang.Register
```

After: the same five programs import and analyse with **0** `WasmStackVariableAnalyzer` warnings
(`(Select-String -Pattern WasmStackVariableAnalyzer).Count == 0`) and
`decompiled=1 decompile_failed=0 undefined_bytes=0` each.

Spec suite (focused run) `WasmStackVariableAnalyzer failures by opcode`:

| before (`spectest-o-before`) | after (`spectest-o-after`) |
| --- | --- |
| `stackvar_fail: 4`, `class_cast: 2`; `local.set l0: 2`, `f32.load: 1`, `i64.load8_s: 1`, `i64.store: 1`, `i64.store16: 1` | **`stackvar_failures: 0`**, no `WasmStackVariableAnalyzer` line in `headless.log` |

(These exceptions were already non-fatal; the fix removes the logged warnings and restores the
stack-variable recovery that the exceptions skipped.)

---

## Finding 3 — decompiler death on a very large `br_table` body

### Root cause

`br_table.0.wasm`'s `large` function (spec `br_table.wast`) encodes ~16 000 case labels. The
pre-analyzer materialised **one directive instruction per label** (`setBrTableCase` → a `.case`
constructor), and each `.case` emits a conditional branch
(`if(BRTableInput != ctx_case_index) goto inst_next; doBranch(br_target)`). The result is a function
with ~16 000 instructions and ~16 000 basic blocks, all ending in a conditional branch to one of two
targets. The native decompiler cannot structure that CFG: on the spec module it died
(`Decompiler process died`); a reduced 4 001-label probe reproduced it as
`Exception while decompiling ram:80000024: process: timeout`. The pathology is the *number of
branches/blocks*, not the number of instructions.

### Fix

Bound the number of branch instructions the pre-analyzer emits for a single `br_table`
(`WasmFunctionAnalysis.MAX_BR_TABLE_CASES = 1024`). Past the cap the label bytes are still consumed
— keeping the byte stream aligned, so there are no undefined bytes — by a new byte-only directive
`:case_ignored` (`DIRECTIVE_CASE_IGNORED = 5`), which contributes no pcode and no basic block. A
single warning is logged naming the instruction and the truncation. The decoder and the
`:br_table`/`.case` semantics for every `br_table` with ≤ 1024 labels are unchanged.

Verified the `.slaspec` still compiles (Ghidra `sleigh` compiler, no new errors) and the
extension builds.

### Evidence

Probe `SF03_large_br_table.wasm` (4001 labels, all branching to the enclosing block):

| | before | after |
| --- | --- | --- |
| `SF03_large_br_table.wasm` | `instrs=4007 undefined_bytes=0 decompiled=0 decompile_failed=1`; `DECOMPILE FAILED: Exception while decompiling ram:80000024: process: timeout` | `instrs=4007 undefined_bytes=0 decompiled=1 decompile_failed=0` |

After-run warning (once, at the cap boundary):

```
WARN br_table at ram:80000029 has 4001 labels; only the first 1024 are modelled as branches (the rest are decoded without control flow)
```

Spec suite (`br_table.0.wasm`, function `large @ ram:800006af`, body 16172 bytes / 16164
instructions):

| | before | after |
| --- | --- | --- |
| `large` | `decompile=FAIL err=Exception_while_decompiling_ram:800006af:_Decompiler_process_died` | **decompiled (no `SPECFUNC` line); `br_table.0.wasm` reports `decompiled=70 decompile_failed=0`** |
| focused-run `decompile_failed` | 1 | **0** |

Accepted limitation: a `br_table` with more than 1024 labels is decoded without control flow for the
labels past the cap (the omitted case/index comparisons are not modelled), so its decompilation is
an over-approximation. The alternative is a converter crash. The threshold is a compile-time
constant (`MAX_BR_TABLE_CASES`). The full core subset confirms the effect end-to-end: its single
`decompile_failed` function was exactly this `large` function and it is now 0 (see the metric table
under finding 1).

---

## Frozen-baseline / CI-baseline status

* No frozen probe file was touched (`gen_feature_probes.py` unchanged); the new probes live in the
  new, owned `test-scripts/probes_spec_fixes.py` (7 modules), which `run_probes.ps1` and the CI
  workflow glob as `probes_*.py`.
* `test-scripts/expected-results.json` was regenerated with
  `check-local.ps1 -SkipBuild -GhidraDir ... -RealModule <rasterbator> -Update`
  (the only sanctioned way). The change is **purely additive**:
  `probe_count` 93 → **100**, 7 new probe entries (`SF01*`, `SF02*` ×5, `SF03*`), 3 expected import
  failures unchanged. **No pre-existing probe's expected metrics changed** (verified with
  `git diff test-scripts/expected-results.json`: the only non-addition line is `probe_count`).
  The `fixture` summary is unchanged (`functions=4 decompiled=4 failed=0 instructions=24`), and the
  `real_module` baseline is unchanged (`functions=437 decompiled=437 failed=0 instructions=61658`,
  `undefined_bytes=156`).

---

## Regression

`analyzeHeadless ... -postScript DumpDecomp.java` on
`D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm`:

Result: **unchanged and clean** - `SUMMARY functions=437 decompiled=437 failed=0
instructions=61658 undefined_bytes=156` (the required regression line, exactly as before; the 156
undefined bytes are the pre-existing external/import-stub modelling noise, not a decode gap). A
`sleigh`-level check confirms the cap cannot affect this module: the largest `br_table` in
`rasterbator_rs_bg.wasm` has **41** case labels (measured with a throwaway headless script), far
below `MAX_BR_TABLE_CASES = 1024`, so no `.case_ignored` instruction is emitted for it.

---

## How to reproduce

```powershell
# build + install
& D:\code\ghidra-wt-o\test-scripts\build-install.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-g"

# the 7 new probes (per-module metrics + listings + decompiled C)
& D:\code\ghidra-wt-o\test-scripts\run_probes.ps1 `
    -OutDir "C:\Users\micro\AppData\Local\Temp\opencode\probes-o" `
    -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-g" `
    -Generators gen_feature_probes.py,probes_spec_fixes.py -Detail

# focused spec-suite re-run (unwind + br_table)
& D:\code\ghidra-wt-o\test-scripts\spectest\run_spectest.ps1 -Files unwind,br_table `
    -MaxPerWast 10 -OutDir "$env:TEMP\spectest-o" `
    -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-g"

# full core subset
& D:\code\ghidra-wt-o\test-scripts\spectest\run_spectest.ps1 -Subset core -MaxPerWast 10 `
    -OutDir "$env:TEMP\spectest-o" -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-g"
```
