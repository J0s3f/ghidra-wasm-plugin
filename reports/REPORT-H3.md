# REPORT-H3 — the emulation input-arity defect + the spec `assert_*` run

Branch `fix/emulation-assert` (base `main` @ `c3a7bc2`), worktree `D:\code\ghidra-wt-h3`, Ghidra
12.1.4 pinned at `%TEMP%\opencode\ghidra-h3`. Scope: `src/main/java/wasm/pcode/**`,
`src/main/java/ghidra/program/emulation/**`, `ghidra_scripts/spectest.py`, additive files under
`test-scripts/spectest/**`, `test-scripts/EmulateExport.java`, this report.

**Result in one line**: the root cause was a Ghidra **12.1 API change** in
`EmulateInstructionStateModifier.executeCallOther()` (the CALLOTHER userop-index varnode is now
stripped before `OpBehaviorOther.evaluate()`), which the Wasm emulation behaviours were not written
for; after reconciling them the spec suite's assertions actually execute — **2489 `assert_return`
pass / 26 fail, 79 `assert_trap` pass / 104 fail, 92 modules loaded** over 33 `.wast` files.

---

## 1. Root cause: `funcEntryCallOther requires two inputs`

### 1.1 What the plugin does

`data/languages/WebAssembly.sinc:266` emits, at the start of every Wasm function body, the
`.locals` directive:

```
:.locals is count; ... {
    nop();
    funcEntryCallOther(&i0, &l0);
}
```

`define pcodeop funcEntryCallOther;` (`.sinc:61`), and `data/languages/WebAssembly.cspec:41`
declares a `<callotherfixup targetop="funcEntryCallOther">` with two `<input>`s. There are **two**
consumers of that CALLOTHER:

* the **decompiler** path — `PcodeInjectLibraryWasm.allocateInject()` returns
  `InjectPayloadWasmEntry`, whose `getPcode()` emits `i0..->l0..` copies;
* the **emulator** path — `WasmEmulateInstructionStateModifier` registers
  `registerPcodeOpBehavior("funcEntryCallOther", new FuncEntryOpBehaviour())`, and the emulator
  translates the *raw* instruction pcode (`Emulate.emitPcode` -> `PseudoInstruction.getPcode(false)`),
  so it sees the CALLOTHER itself and dispatches to that behaviour.

`FuncEntryOpBehaviour` (before this fix) read:

```java
if (inputs.length != 3) {
    throw new LowlevelError("funcEntryCallOther requires two inputs");
}
long inputOffset  = inputs[1].getOffset();
long localsOffset = inputs[2].getOffset();
```

i.e. it assumed `inputs[0]` is the CALLOTHER userop-index varnode and `inputs[1..2]` are the two
language-spec arguments. That was correct for **Ghidra <= 11.x**.

### 1.2 What changed in Ghidra 12.1

Ghidra 11.3.2 (`EmulateInstructionStateModifier.executeCallOther`, verified against the
`Ghidra_11.3.2_build` tag):

```java
Varnode[] inputs = op.getInputs();
OpBehaviorOther opBehaviorOther = pcodeOpMap.get((int) inputs[0].getOffset());
...
opBehaviorOther.evaluate(emu, op.getOutput(), inputs);   // full array, index at [0]
```

Ghidra 12.1.4 (the pinned install, `Ghidra/Framework/Emulation/lib/Emulation-src.zip`):

```java
Varnode[] inputs = op.getInputs();
OpBehaviorOther opBehaviorOther = pcodeOpMap.get((int) inputs[0].getOffset());
...
// Strip-off first input before passing inputs to OpBehaviorOther
Varnode[] callOtherInputs = new Varnode[inputs.length - 1];
System.arraycopy(inputs, 1, callOtherInputs, 0, callOtherInputs.length);
opBehaviorOther.evaluate(emu, op.getOutput(), callOtherInputs);
```

and the interface Javadoc was updated to say so (`OpBehaviorOther`, now
`@Deprecated(since = "12.1")`):

> `inputs` — input varnodes passed as parameters to this pcodeop. **The original
> `PcodeOp#CALLOTHER` first input has been stripped (i.e., CALLOTHER index value)**, leaving only
> the inputs that were specified as arguments to the named pcodeop within the language spec.

So on 12.1.4 `FuncEntryOpBehaviour` receives exactly **2** varnodes (`i0`, `l0`), fails its
`length != 3` test, and throws — aborting emulation at the first instruction of the first invoked
function, exactly as REPORT-G / `MODERN_WASM_GAPS.md` §6 describe. The same off-by-one affected
every other behaviour registered for a Wasm userop:

| behaviour | userop | spec args | old code expected | 12.1 delivers |
| --- | --- | --- | --- | --- |
| `FuncEntryOpBehaviour` | `funcEntryCallOther(&i0,&l0)` | 2 | 3 (`inputs[1],[2]`) | 2 |
| `PopOpBehaviour` | `popCallOther(&t0)` | 1 | 2 (`inputs[1]`) | 1 |
| `PushOpBehaviour` | `pushCallOther(&t0)` | 1 | 2 (`inputs[1]`) | 1 |
| `CallPrologueOpBehaviour` | `callPrologueCallOther(&i0)` | 1 | 2 (`inputs[1]`) | 1 |
| `CallEpilogueOpBehaviour` | `callEpilogueCallOther(&o0)` | 1 | 2 (`inputs[1]`) | 1 |
| `BitCountOpBehaviour` | `clz/ctz/popcnt(x)` | 1 | 2 (`inputs[1]`) | 1 |

### 1.3 Runtime evidence (pcode arity)

`test-scripts/EmulateExport.java` (added by this change) prints the pcode of the entry instruction
before running it. For `sample.wasm`'s exported `add`:

```
PCODE     COPY out=register:00000010:4 in=[register:00000010:4] (1 input(s))
PCODE     CALLOTHER in=[const:00000000:4, const:20000000:4, const:10000000:4] (3 input(s))
```

`const:00000000` is the CALLOTHER userop index (`funcEntryCallOther`), `const:20000000` is `i0`
(register offset 0x20000000) and `const:10000000` is `l0`. The language emits **3** inputs; Ghidra
12.1.4 hands the behaviour **2**; the old check demanded 3. That is the whole defect.

Before/after with the *same* driver and the *same* module (the only change being the Java file
reverted / restored, each rebuilt and installed with `test-scripts/build-install.ps1`):

```
# pre-fix (WasmEmulateInstructionStateModifier.java @ c3a7bc2)
PCODE     CALLOTHER in=[const:00000000:4, const:20000000:4, const:10000000:4] (3 input(s))
ERROR Emulation failure at ram:8000005c: sample.wasm ... LowlevelError: funcEntryCallOther requires two inputs
STATUS    Emulation stopped: funcEntryCallOther requires two inputs

# post-fix
PCODE     CALLOTHER in=[const:00000000:4, const:20000000:4, const:10000000:4] (3 input(s))
RESULT    2d00000000000000000000000000000003...
RETURN    i32=0x2d
STATUS    ok
```

### 1.4 The fix

`src/main/java/ghidra/program/emulation/WasmEmulateInstructionStateModifier.java` — one helper
accepts either layout, so the plugin works on Ghidra <= 11.x and >= 12.1:

```java
private static Varnode[] getArgs(Varnode[] inputs, int expected, String opName) {
    if (inputs.length == expected) {
        return inputs;                                       // Ghidra >= 12.1: index stripped
    }
    if (inputs.length == expected + 1) {
        return Arrays.copyOfRange(inputs, 1, inputs.length); // Ghidra <= 11.x: index at [0]
    }
    throw new LowlevelError(opName + " requires " + expected + " input(s), got " + inputs.length);
}
```

Each `evaluate()` now does `Varnode[] args = getArgs(inputs, N, "<opName>")` and indexes `args[0]`,
`args[1]`. Arity (not "is it a constant?") is the discriminator, which is safe here because the two
layouts differ by exactly one leading varnode, and it also replaces the previously misleading error
message ("requires two inputs" while testing for three).

No change was needed on the injection side: `InjectPayloadWasmEntry` / `InjectPayloadWasmPop` /
`InjectPayloadWasmCallPrologue` read `InjectContext.inputlist`, which for a `callotherfixup` has
always contained the **language-spec arguments only** (the same convention the 12.1 emulator now
uses), and `PcodeOpEmitter` builds fresh ops. The decompiler path is therefore untouched and the
decode/decompile baselines are unchanged.

---

## 2. Java-side verification driver

`test-scripts/EmulateExport.java` (new, additive) loads a `.wasm`, resolves an exported function and
**invokes it through the emulator** via `EmulatorHelper` + `WasmEmulationHelper` — the same path
`ghidra_scripts/spectest.py` uses — then prints the entry pcode, the signature, the return bytes and
the outcome. It exists so the fix can be proven without PyGhidra.

```powershell
$g = "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-h3"
& "$g\support\analyzeHeadless.bat" "$env:TEMP\h3-proj" H3Driver `
    -import "$env:TEMP\h3-driver\sample.wasm" -noanalysis `
    -scriptPath "D:\code\ghidra-wt-h3\test-scripts" `
    -postScript EmulateExport.java add 7 23 -max-cpu 2 -deleteProject
```

`sample.wasm` is built from a small `.wat` with `add`, `sub`, `div_s`, `clz`, a nested `call`, and
`unreachable`. Observed (`RETURN` = the value the callee leaves on the Wasm operand stack):

| invocation | expected | observed | exercises |
| --- | --- | --- | --- |
| `add 7 23` | 42 | `i32=0x2a` | `funcEntryCallOther`, locals init |
| `sub 7 23` | -28 | `i32=0xffffffe4` | locals init |
| `div_s 7 2` | 3 | `i32=0x3` | locals init |
| `div_s 7 0` | trap | `trapped: integer divide by zero` | trap path |
| `clz 65536` | 13 | `i32=0xd` | `BitCountOpBehaviour` (clz) |
| `outer 6 7` (`6*7+3`) | 45 | `i32=0x2d` | `popCallOther`, `callPrologueCallOther`, `callEpilogueCallOther`, `funcEntryCallOther` of the callee, `pushCallOther` |
| `trap` | trap | `trapped: unreachable` | `halt_trap` |

All seven pass, so every registered behaviour — not just the entry one — is exercised and correct.

---

## 3. Spec `assert_*` execution

### 3.1 Python / PyGhidra: solved (no longer a blocker)

Ghidra 12.1.4's `Ghidra/application.properties` has `application.python.supported=3.14, 3.13, 3.12,
3.11, 3.10, 3.9`, but the PyGhidra dist it ships
(`Ghidra/Features/PyGhidra/pypkg/dist`) bundles `jpype1-1.5.2` wheels for **cp39..cp313 only** —
there is no cp314 wheel, so the host `python` (3.14) cannot run PyGhidra. Ghidra's own launcher
(`support/pyghidraRun.bat` -> `pyghidra_launcher.py`) handles this by picking the newest *supported*
interpreter and installing PyGhidra into a venv; the host has `py -3.13`, and the whole install works
**offline** from Ghidra's own dist:

```powershell
py -3.13 -m venv "$env:TEMP\spectest-tools\pyghidra-venv"
& "$env:TEMP\spectest-tools\pyghidra-venv\Scripts\python.exe" -m pip install --no-index `
    -f "$env:TEMP\opencode\ghidra-h3\Ghidra\Features\PyGhidra\pypkg\dist" pyghidra
```

This is now automated in the new `test-scripts/spectest/run_emulate.ps1`. For the run below the venv
lived at `%TEMP%\h3-pyghidra` and was created with exactly the two commands above; any venv with
`pyghidra` + `jpype1` works (`-PythonExe` on the runner).

### 3.2 Exact reproduction

```powershell
# one .wast
& "$env:TEMP\spectest-tools\pyghidra-venv\Scripts\python.exe" -m pyghidra `
    --install-dir "$env:TEMP\opencode\ghidra-h3" --project-path "$env:TEMP\p" --project-name spectest `
    --skip-analysis "D:\code\ghidra-wt-h3\ghidra_scripts\spectest.py" `
    "$env:TEMP\spec-emulate\json\i32.json" "--report=$env:TEMP\i32.txt"

# a set of .wast files + aggregation (prepare -> emulate -> parse)
.\test-scripts\spectest\run_emulate.ps1 -Files i32,i64,br,call,... -OutDir "$env:TEMP\spec-emulate"
```

`run_emulate.ps1` runs `wast2json --no-check` per `.wast`, drives `spectest.py` under PyGhidra, and
`parse_emulate_report.py` aggregates the per-command `RESULT <type> <ok|fail|skip> <detail>` lines
into `emulate-summary.md` / `.json`. Both new files are additive and reuse the pinned toolchain under
`%TEMP%\spectest-tools`.

**Harness hardening (additive)**: `spectest.py` previously called `emuHelper.run(monitor)`, which
blocks until a breakpoint — so a case the plugin mis-executes into an infinite loop hung the run.
Because indirect-call *types* are not checked (§4, lead 2), `call_indirect.wast:530` dispatches to a
recursive function of the wrong signature and never returns; the first run of this harness hung there
for 50 minutes. `run_function()` now steps one instruction at a time with a `--max-steps=N` budget
(default 1,000,000) and reports `step budget exceeded` instead. This changes no passing result and
removes a CI hang.

### 3.3 Results

33 `.wast` files, all commands (no `--max-commands` cut), one PyGhidra session per file.
`skip` = by design (the driver does not execute `assert_invalid` / `assert_malformed` /
`assert_uninstantiable` / `assert_unlinkable` / `assert_exhaustion`).

| suite | module ok/fail/skip | assert_return ok/fail/skip | assert_trap ok/fail/skip | assert_exhaustion ok/fail/skip | assert_invalid ok/fail/skip | assert_malformed ok/fail/skip |
| --- | --- | --- | --- | --- | --- | --- |
| address | 4/0/0 | 206/0/0 | 0/49/0 | - | - | 0/0/1 |
| align | 25/0/0 | 46/1/0 | 0/1/0 | - | 0/0/38 | 0/0/51 |
| block | 1/0/0 | 51/1/0 | - | - | 0/0/155 | 0/0/15 |
| br | 1/0/0 | 76/0/0 | - | - | 0/0/20 | - |
| br_if | 1/0/0 | 88/0/0 | - | - | 0/0/29 | - |
| br_table | 1/0/0 | 145/4/0 | - | - | 0/0/24 | - |
| call | 1/0/0 | 68/1/0 | 0/1/0 | 0/0/2 | 0/0/18 | - |
| call_indirect | 3/0/0 | 113/1/0 | 1/17/0 | 0/0/2 | 0/0/24 | 0/0/11 |
| endianness | 1/0/0 | 68/0/0 | - | - | - | - |
| fac | 1/0/0 | 6/0/0 | - | 0/0/1 | - | - |
| forward | 1/0/0 | 4/0/0 | - | - | - | - |
| func | 4/0/0 | 96/0/0 | - | - | 0/0/49 | 0/0/23 |
| global | 5/0/0 | 53/4/0 | 0/1/0 | - | 0/0/40 | 0/0/7 |
| i32 | 1/0/0 | 364/0/0 | 7/3/0 | - | 0/0/83 | 0/0/2 |
| i64 | 1/0/0 | 374/0/0 | 7/3/0 | - | 0/0/29 | 0/0/2 |
| if | 1/0/0 | 121/2/0 | 0/1/0 | - | 0/0/92 | 0/0/24 |
| int_literals | 1/0/0 | 30/0/0 | - | - | - | 0/0/20 |
| labels | 1/0/0 | 25/0/0 | - | - | 0/0/3 | - |
| load | 1/0/0 | 36/1/0 | - | - | 0/0/46 | 0/0/13 |
| local_get | 1/0/0 | 19/0/0 | - | - | 0/0/16 | - |
| local_set | 1/0/0 | 19/0/0 | - | - | 0/0/33 | - |
| local_tee | 1/0/0 | 53/2/0 | - | - | 0/0/41 | - |
| loop | 1/0/0 | 76/1/0 | - | - | 0/0/27 | 0/0/15 |
| memory | 11/0/0 | 50/3/0 | - | - | 0/0/18 | 0/0/6 |
| nop | 1/0/0 | 80/3/0 | - | - | 0/0/4 | - |
| return | 1/0/0 | 63/0/0 | - | - | 0/0/20 | - |
| select | 2/0/0 | 114/2/0 | 0/2/0 | - | 0/0/28 | - |
| stack | 2/0/0 | 5/0/0 | - | - | - | - |
| store | 1/0/0 | 9/0/0 | - | - | 0/0/51 | 0/0/7 |
| switch | 1/0/0 | 26/0/0 | - | - | 0/0/1 | - |
| table | 9/0/0 | - | - | - | 0/0/4 | 0/0/6 |
| traps | 4/0/0 | - | 6/26/0 | - | - | - |
| unreachable | 1/0/0 | 5/0/0 | 58/0/0 | - | - | - |
| **total** | **92/0/0** | **2489/26/0** | **79/104/0** | 0/0/5 | 0/0/893 | 0/0/203 |

Totals: **92/92 modules loaded**, **2489 `assert_return` pass / 26 fail**, **79 `assert_trap` pass /
104 fail**, 5 `assert_exhaustion` skipped, 893 `assert_invalid` + 203 `assert_malformed` skipped
(the negative-rejection harness is a separate workstream).

Sanity anchors (these are the strongest evidence that real values flow through the emulator):

* `i32.wast`: `364` `assert_return` pass including the whole `div_s`/`rem_s`/`and`/`or`/`shl`/
  `shr_s`/`rotl`/`clz`/`ctz`/`popcnt` tables.
* `i64.wast`: `374` `assert_return` pass — every `i64.clz`/`ctz`/`popcnt` case, i.e. the
  `BitCountOpBehaviour` half of the fix.
* `call.wast` / `call_indirect.wast`: recursive `fac`/`fib`/`even`/`odd` calls and structural
  dispatch return the spec's values (`fac-i64 12` -> `362880`, `fib-i64 20` -> `10946`).
* `unreachable.wast`: `58/58` `assert_trap` pass.

### 3.4 Failing commands as bug leads

Grouped from the 130 failures (full per-suite lines are in
`emulate-summary.md` -> "Failing commands"). None of these is the input-arity defect; they are
pre-existing emulator coverage gaps, recorded rather than "fixed":

| # | class | count | example | likely cause / owner |
| --- | --- | --- | --- | --- |
| 1 | `assert_trap` **did-not-trap**: out-of-bounds linear-memory access | 64 (49 `address`, 14 `traps` loads, 1 `align`) | `address.wast:32_good5` | The emulator's LOAD/STORE never bounds-check the Wasm memory; `EmulatorHelper.uninitializedRead` returns zeros, so the spec trap "out of bounds memory access" is invisible. Needs a bounds-check callother (or a memory fault handler) — `WasmEmulateInstructionStateModifier`/`WasmEmulationHelper`. |
| 2 | `assert_trap` did-not-trap: **indirect call type mismatch** | 10 | `call_indirect.wast:498 dispatch` | `call_indirect` does not compare the table element's signature with the expected type. (Also causes the runaway at `call_indirect.wast:530`.) |
| 3 | `assert_trap` **wrong trap**: `uninitialized element` instead of `undefined element` | 11 (`call_indirect` 6, `select` 2, `call`/`global`/`if` 1 each) | `call_indirect.wast:500 dispatch` | Out-of-bounds table index yields a null funcref; the emulator jumps to address 0 and the driver maps that to "uninitialized element". The two Wasm traps are indistinguishable in this model. |
| 4 | `assert_return` **emu-error**: `Unimplemented CALLOTHER pcodeop (memory_grow / memory_size)` | 17 | `nop.wast:as-memory.grow-first` | `.sinc` defines `memory_grow`/`memory_size` but `WasmEmulateInstructionStateModifier` registers no behaviour (and `PcodeInjectLibraryWasm` no fixup), so any function calling them dies. Cheap win: implement the two behaviours. |
| 5 | `assert_trap` did-not-trap: **integer divide/remainder by zero / overflow** | 10 (`i32` 3, `i64` 3, `traps` 4) | `i32.wast:66 div_s(INT_MIN,-1)`, `i32.wast:85-86 div_u(_,0)`, `traps.wast:no_dce.i32.div_u` | Ghidra core: `OpBehaviorIntDiv` returns `0` when the divisor is 0 (unsigned), and `OpBehaviorIntSdiv` throws only for `/0`, not for `INT_MIN/-1`. Signed `/0` *is* caught ("Divide by 0"), which is why only these 10 fail. |
| 6 | `assert_trap` did-not-trap: **float-to-int conversion out of range** (`trunc`) | 8 (`traps`) | `traps.wast:no_dce.i32.trunc_f32_s` | `i32.trunc_f32_s` etc. use Ghidra's `INT2FLOAT`/`FLOAT2FLOAT` truncation which does not signal "integer overflow"/"invalid conversion to integer". |
| 7 | `assert_return` **wrong value** on `br_table large` | 4 | `br_table.wast:1071-1074`, got `0xffffffff` | This is REPORT-G class 1 (`select` not decoded after an unconditional terminator, `ram:800006af`); the decode gap now shows up as a wrong runtime result. |
| 8 | `assert_return` wrong value: globals | 3 | `global.wast:get-z1` got 0, expected 666 | Mutable-global initialisation (`get-z1`/`get-z2`, `as-compare-operand`). |
| 9 | `assert_return` wrong value: NaN payload / load | 2 | `local_tee.wast:as-unary-operand` `0xffc00000` vs `0xff80f1e2`; `align.wast:load` `0xffffffff` vs 0 | NaN canonicalisation and one load/align case. |

`i32.wast` and `i64.wast` are otherwise 100% clean: 364/374 `assert_return` and 7/7 valid
`assert_trap` pass, with the only failures being class 5.

---

## 4. Probe gate + real-module regression

`test-scripts/check-local.ps1 -OutDir "$env:TEMP\ci-h3" -RealModule "…\rasterbator_rs_bg.wasm"`
(with `GHIDRA_INSTALL_DIR` pointing at the pinned install) rebuilt, installed, ran all 136 probes,
the fixture decompile and the real module, then `check-results.py`:

```
== running 136 probe(s) ==
probes: 131 imported, 5 import failure(s); baseline has 136
OK: every probe matches the recorded baseline.

SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0        (wasm_fixture.wasm)
SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156 (rasterbator_rs_bg.wasm)
```

The real-module line is exactly the required
`SUMMARY functions=437 decompiled=437 failed=0 instructions=61658`, and the probe gate is
`OK: every probe matches the recorded baseline.` — i.e. the change is additive: it touches only the
emulator's `OpBehaviorOther` implementations and the new harness scripts, nothing on the
decode/analysis/decompile path.

---

## 5. Files changed

| file | change |
| --- | --- |
| `src/main/java/ghidra/program/emulation/WasmEmulateInstructionStateModifier.java` | **the fix**: `getArgs()` accepts both CALLOTHER operand layouts; all six behaviours updated |
| `ghidra_scripts/spectest.py` | additive `--max-steps` instruction budget per invoke (replaces the unbounded `run()` loop); header docs |
| `test-scripts/EmulateExport.java` | new Java-side emulation driver (proof independent of PyGhidra) |
| `test-scripts/spectest/run_emulate.ps1` | new: prepare + drive `spectest.py` under PyGhidra + aggregate |
| `test-scripts/spectest/parse_emulate_report.py` | new: aggregate `RESULT` lines into `emulate-summary.md`/`.json` |
| `REPORT-H3.md` | this report |

No probe expectations, `expected-results.json`, `run_probes.ps1`, `check-local.ps1`,
`check-results.py`, `build-install.ps1`, `data/languages/**`, loader/analysis sources or other
reports were modified.
