# REPORT-MV - Multi-value returns

Roadmap item **7** of `MODERN_WASM_GAPS.md` (§2.2 row "Multi-value returns", §4
item 7, acceptance: "probe 16 shows both results in the prototype and the caller
consumes both").
Branch `feat/multivalue-returns`, worktree `D:\code\ghidra-wt-f`, base commit
`2b0628c`.

## 0. Headline

| | before | after |
| --- | --- | --- |
| probe `16_multivalue_return` (frozen baseline) | 2 funcs, 9 instrs, 0 undefined bytes, decompiles; only the first result in the prototype (`TODO handle multiple returns` in `WasmSignatureAnalyzer`) | **unchanged metrics** (2/9/0/2); prototype is `wasm_ret_i32_i32 f(void)` and the caller consumes both: `wVar1 = export::f(); … wVar1.f0 / wVar1.f1` |
| probe `17_multivalue_block` (frozen baseline) | 1/7/0/1 | **unchanged** (multi-result blocks stay on the operand stack; unaffected by the return ABI) |
| `(func (result i32 i32))` | `int f(void)`; the second result disappears | `wasm_ret_i32_i32 f(void)`; the callee builds `wVar1.f0 = …; wVar1.f1 = …; return wVar1;` and the caller reads `wVar1.f0` / `wVar1.f1` |
| 3+ results, mixed types | only `returns[0]` | `wasm_ret_i32_i32_i32`, `wasm_ret_i32_i32_i32_i32`, `wasm_ret_i32_f64`, `wasm_ret_i64_i32`, `wasm_ret_i32_i64`, `wasm_ret_f64_f64` - all fields present, all consumed |
| callers | drop extra results | consume every result: stores to globals/locals, arithmetic on both (`wVar2.f0 = wVar1.f0 + wVar1.f1; wVar2.f1 = wVar1.f0 * wVar1.f1;`), `return_call` tails, `call_indirect`, multi-result **imports** |
| new probe file `probes_multivalue.py` | - | 12 probes (M01-M12), **all decompile (`decompile_failed=0`)** |
| everything else (probes 01-15, 17-27) | §2.4 of `MODERN_WASM_GAPS.md` | **unchanged**, row for row |
| real-module regression (`rasterbator_rs_bg.wasm`) | `functions=437 decompiled=437 failed=0 instructions=61658` | **`functions=437 decompiled=437 failed=0 instructions=61658`**; the module's 7 multi-result functions (`finish_pdf`, `generate_preview_page`, `begin_pdf`, `calculate_pages`, `generate_preview`, `process_image`, `generate_pdf_page`) now show `wasm_ret_i32_i32[_i32[_i32]]` prototypes and build the full struct |

## 1. Design

### 1.1 Representation: struct return by value

A function with `n > 1` results returns a **packed struct** named
`wasm_ret_<t>_<t>…` (category `/wasm`, fields `f0`, `f1`, …, one per result, in
result order). The struct is **packed** (`setPackingEnabled(true)`): field `i` sits
at the sum of the sizes of the previous fields - exactly where the epilogue writes
it. Types are registered in the program's data type manager and deduped by name, so
every function with the same result tuple shares one named type.

Why a struct and not "first result + extra output registers": the decompiler
substitutes sub-varnodes of the call's **output varnode** into the injected push
copies at the call site. With a struct return, the call's output varnode *is* the
struct, so the substitution yields `ret.f0` / `ret.f1` in the caller - all results
visible as one value. With separate output registers the caller would see undefined
values.

### 1.2 ABI: contiguous packing into the output register block

The `__wasm` prototype of `WebAssembly.cspec` declares the output (return) storage
as a pentry at register `0x30000000` (`minsize=1 maxsize=500 align=16`) - the
`oN` register block. The decompiler uses this pentry as the function's return
storage (the `RETURN` op's `[LR]` input is ignored).

* **Callee epilogue** (`callEpilogueCallOther` → `InjectPayloadWasmPop` with
  `packContiguously=true`): the results are copied from the stack slots
  (`s_{popHeight+i}`) **contiguously** into the output block - result `i` at
  `o0 + Σ sizes of results 0..i-1`.
* **Caller** (`pushCallOther(&o0)` at the end of `call`/`call_indirect` →
  `InjectPayloadWasmPush`): when the base register is `o0` (a call-result push,
  as opposed to a block-argument push at `t0`), the results are read back
  **contiguously** from the same offsets.

Both sides must agree on the layout; the old code used a 16-byte stride on both
sides, which left every result after the first outside the return varnode.
`popCallOther` (call arguments, block arguments) and the call prologue keep the
16-byte-stride layout (`i0, i1, …` / `t0, t1, …`), so only the return path
changed. The two layouts are distinguished by a constructor flag
(`InjectPayloadWasmPop(sourceName, packContiguously)`) and, on the push side, by
comparing the base register with `o0`'s address.

### 1.3 Tail padding

The decompiler reads the return storage **rounded up to the struct's alignment**
(its largest field), so a packed struct whose size is not a multiple of that
alignment - e.g. an `(i32, f64)` return: 12 bytes, alignment 8 - would otherwise
show the tail padding as undefined (`in_register_3000000c`). The epilogue therefore
zeroes the padding: after the contiguous result copies it emits one
`COPY 0 → o0+size` covering the bytes up to `roundUp(total, maxFieldSize)`.
Verified empirically: single-value returns (`longlong f(void)` → `return …;`) and
all-`i32` tuples never needed it; `(i64,i64,i32)` (20 bytes, alignment 8) padded
to 24 and showed `in_register_30000014` before the fix, `_20_4_ = 0` after.

## 2. Implementation

* `wasm/analysis/WasmSignatureAnalyzer.java` - `setFunctionSignature` now applies
  **all** results: 0 → `void`, 1 → the scalar type (unchanged), ≥2 →
  `multiValueReturnType()`, which builds/registers the packed struct.
* `wasm/pcode/InjectPayloadWasmPop.java` - new `packContiguously` flag; the
  epilogue packs results contiguously and zeroes the tail padding.
* `wasm/pcode/InjectPayloadWasmPush.java` - call-result pushes (base == `o0`)
  read the results back contiguously.
* `wasm/pcode/PcodeInjectLibraryWasm.java` - `callEpilogueCallOther` allocates
  `InjectPayloadWasmPop(sourceName, true)`; `popCallOther` keeps the stride
  layout.

No `.cspec` change was needed: the existing output pentry already covers a
contiguous block up to ~496 bytes (31 × 16-byte slots).

## 3. Probes (`test-scripts/probes_multivalue.py`, M01-M12)

All 12 decompile with `decompile_failed=0`. Results pop **top-first** in wasm, so
a `global_set`/`local_set` right after a call receives the *last* result - the
probes account for this (`global_set(1)` before `global_set(0)`, or the
`local_set(1); local_set(0)` idiom where local 0 = the first result).

| probe | module | result |
| --- | --- | --- |
| M01 | `(i32,i32)`, caller stores both to globals | `wasm_ret_i32_i32 pair(void)`; callee `wVar1.f0 = 1; wVar1.f1 = 2; return wVar1;`; caller `g0 = wVar1.f1; g1 = wVar1.f0;` (2/9/0/2) |
| M02 | `(i32,i32,i32)` | `wasm_ret_i32_i32_i32`, all three stored (2/11/0/2) |
| M03 | `(i32×4)` - exactly one full 16-byte slot | `wasm_ret_i32_i32_i32_i32`, all four stored (2/13/0/2) |
| M04 | `(i32,f64)` - 12 bytes packed, unaligned f64 | `wasm_ret_i32_f64`; `gd = wVar1._4_8_` (2.5), `gi = wVar1.f0` (7) (2/9/0/2) |
| M05 | `(i64,i32)` | `wasm_ret_i64_i32`; `gl = wVar1.f0` (0x1122334455667788), `gi = wVar1.f1` (-5) (2/9/0/2) |
| M06 | `(i32,i64)` - 8-byte field at offset 4 (unaligned) | `wasm_ret_i32_i64`; both consumed (2/9/0/2) |
| M07 | `(f64,f64)` - 16 bytes | `wasm_ret_f64_f64`; `gd0 = -2.25`, `gd1 = 1.5` (2/9/0/2) |
| M08 | caller combines both results | caller returns `(a+b, a*b)`: `wVar2.f0 = wVar1.f0 + wVar1.f1; wVar2.f1 = wVar1.f0 * wVar1.f1;` (2/16/0/2) |
| M09 | multi-result **block** (type-index blocktype) | stays on the operand stack; `f` stores both block results to globals (1/8/0/1) - frozen probe 17's mechanism, unaffected |
| M10 | multi-result **import** | import gets `wasm_ret_i32_i32 pair(void)`; caller `return wVar1.f0 + wVar1.f1;` (2/9/**4**/2; the 4 undefined bytes are the import's empty body at `ram:7f000000` - a single-value import shows the same 4) |
| M11 | `return_call` tail of a multi-result function | `wasm_ret_i32_i32 tail(void)` - the tail-callee's results become the caller's (2/7/0/2) |
| M12 | `call_indirect` with a `(i32,i32)` type | both results consumed via locals (2/14/0/2) |

`test-scripts/check_multivalue.py` structurally validates every generated module
(section consistency + an operand-stack type simulation) before running Ghidra.

## 4. Regression

* Frozen baseline probes 01-27 (`gen_feature_probes.py`): **identical metrics to
  the baseline**, row for row - including `16_multivalue_return` (2/9/0/2) and
  `17_multivalue_block` (1/7/0/1).
* Real module `rasterbator_rs_bg.wasm`:
  **`functions=437 decompiled=437 failed=0 instructions=61658`** (unchanged).
  The module has 76 function types, 9 of them multi-result, used by 7 defined
  functions; all 7 now carry `wasm_ret_*` prototypes, e.g.
  `wasm_ret_i32_i32_i32_i32 finish_pdf(void)` building
  `wVar1.f1 = local_154; wVar1.f0 = local_158; wVar1.f2 = local_68; wVar1.f3 = iVar2; return wVar1;`.

## 5. Limitations

* The output pentry covers ~496 bytes (31 × 16-byte slots), so result tuples up to
  ~496 bytes are supported; larger tuples exceed the return storage.
* For a packed tuple with an 8-byte field at an unaligned offset (e.g. `(i32,i64)`),
  the callee's decompiled body contains one redundant line for the zeroed padding
  (`wVar1.f1._4_4_ = 0;`) next to the correct 8-byte store. The values - and the
  caller's view - are correct; only the callee's body shows the extra line.
* An imported multi-result function's return values are undefined at analysis time
  (the import has no body), exactly as for single-value imports.
