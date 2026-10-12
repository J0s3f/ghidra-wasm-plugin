# WebAssembly spec-test correctness baseline

Harness: `test-scripts/spectest/` (see `test-scripts/spectest/README.md`).
Plugin under test: this worktree at commit `1e2328b` (+ harness commits), built and clean-installed
into Ghidra 12.1.4 (`build-install.ps1`).
Toolchain: wabt `1.0.42`, testsuite `WebAssembly/spec @ d76759e746f3564a03f6106ae19679742f2a1831`.

This is a **measurement** baseline: nothing under `src/` or `data/` was changed.

## 1. Headline

Two runs, both on the same install:

* **core** = `-Subset core -MaxPerWast 10` — 73 `.wast` files, deep coverage of MVP + bulk-memory + tables.
* **all** = `-Subset all -MaxPerWast 3` — all 147 `.wast` files (adds SIMD, linking, binary, token, …).

| metric | core (73 files) | all (147 files) |
| --- | ---: | ---: |
| valid modules selected | 271 | 257 |
| modules imported (loader accepted) | **271 (100%)** | **257 (100%)** |
| modules rejected | 0 | 0 |
| PASS / PARTIAL / FAIL (module level) | 264 / 6 / 1 | 249 / 7 / 1 |
| functions analysed | 2747 | 3750 |
| instructions decoded | 33192 | 48005 |
| undefined bytes (total) | 458 | 210 |
| — external/import stubs (no body; modelling artifact) | 428 (107 funcs) | 176 (44 funcs) |
| — **real decode gaps** | **30 (24 funcs)** | **34 (28 funcs)** |
| functions decompiled OK | 2746 | 3749 |
| functions that failed to decompile | **1 (decompiler process died)** | **1 (same function)** |
| analyzer warning lines | 23 | 23 |

Headline: **the loader accepted every valid spec module in both runs (528/528 against 0 rejections).
SIMD is clean (99 modules, 1222 functions, 9012 instructions, 0 undefined bytes, 0 decompile
failures). The only disassembly gap is `select` in unreachable code, and there is exactly one
decompiler crash (a single oversized function).**

## 2. Pass/fail table

"PASS" = imported and no decode gap and no decompile failure. "PARTIAL" = imported but has a decode
gap. "FAIL" = not imported or a function failed to decompile.

| run | modules | PASS | PARTIAL | FAIL | functions | instrs | decode-gap bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| core (73 files) | 271 | 264 | 6 | 1 | 2747 | 33192 | 30 |
| all (147 files) | 257 | 249 | 7 | 1 | 3750 | 48005 | 34 |

Files with a decode gap (core): `br`, `br_table`, `call_indirect`, `return`, `select`,
`unreachable`, `unreached-valid`. The all-suite run adds `unwind`. The one FAIL in both runs is
`br_table.0.wasm` (decompiler crash; it also has a decode gap, counted once under FAIL). Every other
`.wast` in every run is clean — see the `summary.md` produced by each run for the full per-file table.

## 3. Ranked failure classes

### F1 — `select` (opcode `0x1B`) is not disassembled in unreachable code  (decode gap / desync)
Severity: high (silently leaves undefined bytes inside function bodies; the surrounding function is
otherwise fully decoded, so it is easy to miss).

* 30 bytes (core) / 34 bytes (all) across 24 / 28 functions in 7 / 8 suites — the **only** real decode
  gap in either run.
* Every instance is the byte `0x1B` (`select`) on a path that follows an **unconditional terminator**
  (`unreachable`, `br`, `br_table`, `return`). The stack-type context SLEIGH uses to pick the `select`
  overload (`WebAssembly.sinc:415/418/421`, `ctx_operand_size`) is not set on an unreachable path, so
  no constructor matches and the byte stays undefined. `select t` (`0x1C`, `WebAssembly.sinc:441`),
  `select` on a reachable path, and `select` after the *conditional* `br_if` all decode fine — which
  is why `i32.wast`, `nop.wast` etc. look clean.
* **Smoking-gun repro (core testsuite, `unwind.wast`):** the official suite contains functions named
  exactly for this — `select-after-unreachable`, `select-after-br`, `select-after-br_table`,
  `select-after-return` — and the plugin fails to decode the `select` byte in all four:

  | function (`unwind.0.wasm`) | function entry | `select` byte offset | undecoded address |
  | --- | --- | --- | --- |
  | select-after-unreachable | `ram:80000785` | `0x797` | `ram:80000797` |
  | select-after-br | `ram:8000079a` | `0x7b1` | `ram:800007b1` |
  | select-after-br_table | `ram:800007c9` | `0x7e3` | `ram:800007e3` |
  | select-after-return | `ram:800007e7` | `0x7fb` | `ram:800007fb` |

More examples (function / address / byte):

| module | function | function entry | undecoded address | byte |
| --- | --- | --- | --- | --- |
| `select.29.wasm` | unnamed_function_0 | `ram:8000002a` | `ram:8000002c` | `0x1b` |
| `select.29.wasm` | unnamed_function_4 | `ram:80000041` | `ram:80000043..80000045` | `0x1b 0x1b 0x1b` |
| `br.0.wasm` | as-select-second | `ram:8000078d` | `ram:80000798` | `0x1b` (after `br`) |
| `br.0.wasm` | as-select-all | `ram:800007ab` | `ram:800007b2` | `0x1b` |
| `return.0.wasm` | as-select-cond | `ram:80000604` | `ram:8000060c` | `0x1b` |
| `unreachable.0.wasm` | as-select-second | `ram:800005e3` | `ram:800005e9` | `0x1b` |
| `unreached-valid.0.wasm` | select-unreached | `ram:800000d5` | `ram:800000d7`, `ram:800000db` | `0x1b` |
| `call_indirect.37.wasm` | unnamed_function_9 | `ram:8000007c` | `ram:80000081` | `0x1b` |
| `br_table.0.wasm` | as-select-cond | `ram:80004747` | `ram:80004755` | `0x1b` |

Cross-check (`wasm-objdump -d select.29.wasm`): `00002b unreachable / 00002c select / 00002d end`.

### F2 — decompiler process dies on a very large function  (crash)
Severity: high.
* `br_table.0.wasm`, function `large` @ `ram:800006af`, body 16172 bytes / 16164 instructions.
* `SpecModuleReport` reports `decompile=FAIL err=Exception_while_decompiling_ram:800006af:_Decompiler_process_died`.
* This is a hard crash of the native decompiler process, not an "unable to decompile" result; it can
  take down the whole post-script batch, so it deserves priority even though it is a single function.

### F3 — `WasmStackVariableAnalyzer` fails on loads/stores and throws a ClassCastException on `local.set`  (analyzer crashes)
Severity: medium (analysis continues, but stack-variable recovery is wrong/missing).
* 23 warning lines: 20 × `Failed to process instruction at ram:…` and 3 × a real
  `ClassCastException`.
* Recurring opcodes (core subset): `i64.store align=0x3`, `i64.store16 align=0x1`,
  `f32.load align=0x2`, `i64.load8_s align=0x0` → `Index 0 out of bounds for length 0`.
  Example: `ram:80000884 f32.load align=0x2 offset=0x0: Index 0 out of bounds for length 0` (`return.0.wasm`).
* `local.set l0` → `class ghidra.program.model.address.GenericAddress cannot be cast to class
  ghidra.program.model.lang.Register`. Examples: `ram:80000859` (`return.0.wasm`), `ram:8000067a`.
  (Note the two different exception shapes: memory ops hit an empty operand list, `local.set` gets a
  GenericAddress where a Register is expected.)

### F4 — imported functions are modelled as body-less functions with 4 undefined bytes  (modelling artifact)
Severity: low/cosmetic, but it dominates the raw `undefined_bytes` number and spams the log.
* 107 functions in the core subset, 428 bytes, all at `ram:7f000000…` (the loader's external block).
* They have 0 instructions and 4 undefined bytes each, and the decompiler logs
  `Unable to disassemble EXTERNAL block location: ram:7f000000`.
* Affected suites: `imports` (104 bytes = 26 stubs), `table_copy` (180), `table_init` (120),
  `start` (12), `names` (8), `ref_func` (4).
* Bug lead: either don't create functions for imports, or exclude the external block from
  `undefined_bytes`/decompilation so the metric measures what it claims to.

### F5 — the emulation driver (`ghidra_scripts/spectest.py`) cannot run any assertion  (harness/emulator defect)
Severity: high for the "official spec pass/fail" goal; blocks `assert_return`/`assert_trap` entirely.
* `spectest.py` was modernised to run under PyGhidra (`pyghidra -m`, Python 3.13) and now loads
  modules and resolves exports, but **every** `invoke` aborts at the first executed instruction:
  `EmulationError: Emulation stopped: funcEntryCallOther requires two inputs`.
* The Java side (`WasmEmulateInstructionStateModifier.FuncEntryOpBehaviour`, line 198) requires
  `inputs.length == 3` (CALLOTHER + 2 operands), i.e. the SLEIGH `.locals` directive must emit
  `funcEntryCallOther(&i0, &l0)` (`WebAssembly.sinc:238`). At runtime the emulator sees only 1
  operand. Root cause not yet isolated (SLEIGH arity, `.sla` staleness, or the injection library).
* Consequence: **emulation-based pass/fail is currently 0 assertions executed**; this baseline
  measures loading / disassembly / decompilation only.

## 4. Coverage

* core: 73 `.wast` / 271 modules / 2747 functions, `-MaxPerWast 10`.
* all: 147 `.wast` / 257 modules / 3750 functions, `-MaxPerWast 3` — includes SIMD (99 modules,
  1222 functions, 9012 instructions — **clean**), `linking`, `binary`, `binary-leb128`, `token`,
  `custom`, `func_ptrs`, `left-to-right`, `inline-module`, `skip-stack-guard-page`, `unwind`.
* Bounded by `-MaxPerWast` (the largest suites have 400+ modules; a few per file still exercises every
  opcode in the file).
* Valid modules only. `assert_invalid` / `assert_malformed` modules (which the loader *should*
  reject) are deliberately excluded from these passes and are a separate follow-up — the harness
  already emits their binaries from `wast2json`.
* Not covered by either run: atomics/threads, GC, exception handling, tail-calls, multi-memory,
  memory64 — these live under `proposals/` in the testsuite. The harness can be pointed at those
  directories next (they need matching wabt `--enable-*` flags).

## 5. Repro

```powershell
# once
.\test-scripts\spectest\fetch_spectest_tools.ps1
# build + install the plugin (owned by another agent)
.\test-scripts\build-install.ps1 -GhidraDir "$env:TEMP\ghidra-g"
# measure
$env:GHIDRA_INSTALL_DIR="$env:TEMP\ghidra-g"
.\test-scripts\spectest\run_spectest.ps1 -Subset core -MaxPerWast 10 -OutDir "$env:TEMP\spectest-core"
.\test-scripts\spectest\run_spectest.ps1 -Subset all  -MaxPerWast 3  -OutDir "$env:TEMP\spectest-all"
# outputs: <OutDir>\summary.{md,json}, headless.log
```
