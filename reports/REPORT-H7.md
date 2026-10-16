# REPORT-H7 - reference-type model: precise heap types + subtype-aware validation

Branch `fix/ref-typing`, worktree `ghidra-wt-h7`, based on main @ `e5157d4` (169 probes).
Owner: workstream `h7`. Scope: `WasmEnums.ValType`, the block/`ref.null` decoding in
`WasmFunctionAnalysis`, the SLEIGH `ref.null`/block-type constructors, and the reference-type
probes. **No edits** to the memarg region of `WasmFunctionAnalysis` (owned by `h4`).

## 1. Root cause

The pre-analyzer's reference-type model was too coarse to validate a conformant
reference-typed block or function signature:

* `WasmEnums.ValType.readFromReader()` read the s33 heap type of a multi-byte
  `(ref null <ht>)` / `(ref <ht>)` and then **discarded it**, returning `externref` for every
  such type ("For now, return externref as a 4-byte placeholder").
* `ref.null <ht>` (Java `case 0xD0`) reused `readFromReader` for a *heap-type* immediate, so a
  concrete type index (e.g. `ref.null 0`, immediate byte `0x00`) fell through to
  `fromByte(0x00)` and became **`i32`**.
* Validation compared types with identity (`actual != expected`), so any legitimate subtype
  relation (`structref` where `anyref` is expected, `nofuncref` where `funcref` is expected,
  ...) was a hard error.

Consequence: a module whose block/function signature used `(ref null struct)` while the body
pushed `ref.null struct` failed with `pop type mismatch: got i32, expected externref` (B18/B28)
or `pop type mismatch` (E15), the function body was left undecoded, and the SLEIGH listing
showed the whole body as undefined bytes.

Two decoder gaps compounded it:

* `WebAssembly.sinc`'s `:ref.null valtype is opc=0xd0; valtype` uses the `valtype` field, whose
  `attach names` table makes it match **only the named** abstract heap types `0x69..0x74`.
  A concrete index such as `ref.null 0` (`D0 00`) therefore matched no constructor and left its
  byte undefined (measured: `D0 00 1A 0B` -> `undefined_bytes=1`).
* A block type may itself be a multi-byte `(ref null ht)` value type (`0x63 0x6B`). Both the
  Java reader (`new BlockType(analysis, readSignedLeb128(reader))`) and the SLEIGH
  `:block/:loop/:if ...; ULeb128` form consumed only the **first** byte (`0x63`, a one-byte
  s33), desynchronising the rest of the body.

## 2. What changed

### `src/main/java/wasm/format/WasmEnums.java`

* `ValType.GENERIC_REF` - the single placeholder for a reference with a **concrete** heap type
  (non-negative s33). Kept as `externref` (the previous catch-all) so existing probes are
  unaffected.
* `ValType.forHeapType(long)` - maps an s33 heap type to its `ValType`. Abstract heap types are
  the bytes `0x69..0x74`, i.e. the negative s33 values `-0x17..-0x0c` (`func -0x10`, `extern
  -0x11`, `any -0x12`, `eq -0x13`, `i31 -0x14`, `struct -0x15`, `array -0x16`, `exn -0x17`,
  `none -0x0f`, `noextern -0x0e`, `nofunc -0x0d`, `noexn -0x0c`); the byte table is reused so the
  mapping is byte-identical to the `(ref ht)` valtype encoding. A non-negative heap type maps to
  `GENERIC_REF`.
* `ValType.readFromReader` now maps the heap type precisely (`(ref null struct)` -> `structref`).
* `ValType.readHeapType` - reads a **bare** s33 heap-type immediate (what `ref.null` takes).
* `ValType.readBlockType` + `BlockTypeInfo` - reads the empty type `0x40`, a single/multi-byte
  value type, or an s33 type index, consuming the whole immediate.
* `ValType.isSubtypeOf(expected)` - the explicit subtype table:
  `anyref >= eqref >= {i31ref, structref, arrayref}`, `funcref >= nofuncref`,
  `externref >= noexternref`, `exnref >= noexnref`, `none` as the bottom of the internal
  hierarchy, identical types always match. Numeric/vector types only match themselves.

### `src/main/java/wasm/analysis/WasmFunctionAnalysis.java`

* `popValue(expected)` accepts a value whose type is a subtype of the expected type
  (`!actual.isSubtypeOf(expected)` replaces `actual != expected`). `popValues` and `popBlock`
  route through `popValue`, so they inherit the rule.
* `case 0xD0` (`ref.null`) uses `ValType.readHeapType` instead of `readFromReader`.
* `case 0x02/0x03/0x04` (`block`/`loop`/`if`) use a new `readBlockType(analysis, reader)` helper
  that consumes multi-byte block signatures. `case 0x06` (`try`) is deliberately left on the
  single-s33 form, because the SLEIGH `:try` constructors were not extended (see section 5).

### `data/languages/WebAssembly.sinc`

* `ref_null_ht: SLeb128` + `:ref.null "heaptype="^ref_null_ht is opc=0xd0; ref_null_ht; ...` -
  accepts any s33 heap type, so `ref.null 0` decodes. (The `valtype` operand is gone: its names
  table is what restricted matching, and two whole-byte operands on the same opcode are an
  "identical patterns" error. Abstract heap types therefore print numerically, e.g.
  `ref.null heaptype=-0x15`; this is display-only - the pcode and the Java type are unchanged.)
* `multi_blocktype: SLeb128 is bytev=0x63; SLeb128` / `bytev=0x64` and matching `:block/:loop/:if`
  constructors - decode a multi-byte `(ref null ht)` block signature in full.

### Probes

* `test-scripts/probes_gc.py` - `E15_gc_br_on_cast.wasm` rebuilt in its **conformant** form:
  block signature `(ref null struct)` (`0x63 0x6B`), `br_on_cast`/`br_on_cast_fail` with
  `flags=0x01`, `label=0`, `ht1=struct`, `ht2=type 0`.
* `test-scripts/probes_ref_typing.py` (new, owned by this workstream) - `R01`..`R04`.
* `test-scripts/fixture-validity.json` - re-recorded (`E15` flipped `invalid` -> `wabt-gap`; the
  four `R0x` added). The stale `E15` entry was removed first so the recorder recomputed its class
  instead of short-circuiting on the old `invalid`.
* `test-scripts/expected-results.json` - regenerated with `check-local.ps1 -Update`.
* `MODERN_WASM_GAPS.md` section 6.5 - counts updated to 173 probes and the "open gap" paragraph
  replaced with the resolved note.

## 3. Before / after evidence

Build + install:

```
cd <worktree>; .\test-scripts\build-install.ps1
```

Gate (fresh shell needs the env var; `-SkipBuild` reuses the pinned install):

```
$env:GHIDRA_INSTALL_DIR = "C:\Users\micro\AppData\Local\Temp\ghidra-h3"
$env:GHIDRA_HEADLESS_MAXMEM = "1500M"
.\test-scripts\check-local.ps1 -OutDir "$env:TEMP\ci-h7" -SkipBuild `
    -RealModule "D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm"
```

Result (final run):

```
SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0      (fixture, unchanged)
SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156   (real module, unchanged)
probes: 156 imported, 17 import failure(s); baseline has 173
OK: every probe matches the recorded baseline.
```

Fixture validity:

```
python test-scripts/check-fixture-validity.py --generate --probes "$env:TEMP\h7-validity" `
  --wabt "C:\Users\micro\AppData\Local\Temp\spectest-tools\wabt-1.0.42\bin" `
  --binaryen "C:\Users\micro\AppData\Local\Temp\binaryen133\binaryen-version_133\bin"
```

Result: `probes: 173  valid: 96  wabt-gap: 41  unsupported: 26  invalid: 10` and
`OK: every probe matches the recorded fixture classification (fixture-validity.json).`

Probe metrics (baseline `expected-results.json`):

| probe | before (main) | after |
| --- | --- | --- |
| `E15_gc_br_on_cast.wasm` | `instrs=15 undefined_bytes=0 decompiled=1` (non-conformant form) | `instrs=17 undefined_bytes=0 decompiled=1` (conformant form) |
| `B18_valtype_ref_null_result.wasm` | `instrs=5 undefined_bytes=3` | `instrs=7 undefined_bytes=0` |
| `B28_valtype_func_gc_struct.wasm` | `instrs=1 undefined_bytes=3` | `instrs=3 undefined_bytes=0` |
| `R01_ref_typing_struct_block.wasm` | - | `funcs=2 instrs=10 undefined_bytes=0 decompiled=2` |
| `R02_ref_typing_funcref_mix.wasm` | - | `funcs=2 instrs=10 undefined_bytes=0 decompiled=2` |
| `R03_ref_typing_anyref_where_eqref.wasm` | - | `funcs=1 instrs=1 undefined_bytes=7 decompiled=1` (rejected) |
| `R04_ref_typing_subtype_accept.wasm` | - | `funcs=2 instrs=12 undefined_bytes=0 decompiled=2` |

`probe_count` 169 -> 173. Only B18, B28 and E15 changed among the pre-existing probes (verified
by the `expected-results.json` diff); every other probe's metrics are byte-identical, and the
fixture and real-module summaries are unchanged.

E15 conformant listing (via `run_probes.ps1 -Generators probes_gc.py -Only E15 -Detail`):

```
ram:80000023  block blocktype=-0x15          <- 02 63 6B (multi-byte block signature), 3 bytes
ram:80000026  ref.null heaptype=-0x15
ram:80000028  br_on_cast ht1=-0x15 ht2=0x0 0x80000031
...
ram:80000045  end
```

No `DECOMPILE FAIL` / "Wasm function analysis failed" for E15; `decompiled=1`.

Negative probe evidence (R03): the plugin rejects it - the probe-run log contains
`WasmPreAnalyzer ... ValidationException: Validation error ... pop type mismatch: got anyref,
expected eqref`, and the body is left undecoded (`undefined_bytes=7`). This is the intended
behaviour: `anyref` is a *supertype* of `eqref`, so it must not silently pass. Note that the
external oracles classify R03 as `wabt-gap` (wabt 1.0.42 rejects the block signature; binaryen
133 decodes `0x6E` as its bottom type `none`, which *is* a subtype of `eqref` - its heap-type
byte table predates the final GC encoding), so its recorded class is `wabt-gap`, not `invalid`.

## 4. Commits

Small focused commits on `fix/ref-typing` (not pushed/merged/tagged):
1. `WasmEnums` reference-type model (heap types, `ref.null`/block-type readers, subtype table).
2. `WasmFunctionAnalysis` + `WebAssembly.sinc` decoder fixes (`ref.null` s33, multi-byte block
   signatures, subtype-aware `popValue`).
3. Probes + baseline (`E15` conformant, `probes_ref_typing.py`, `fixture-validity.json`,
   `expected-results.json`, `MODERN_WASM_GAPS.md` 6.5).
4. `REPORT-H7.md`.

## 5. What I did NOT do

* **Multi-byte block signatures for `try` (legacy EH `0x06`) and `try_table` (`0x1F`)** are not
  supported. The Java `try` case was left on the single-s33 form to match the unchanged SLEIGH
  `:try` constructors; `EH2Ops.analyzeTryTable` and the SLEIGH `:try_table` constructors still
  read a single `ULeb128`. A `try`/`try_table` whose block type is a multi-byte `(ref null ht)`
  value type therefore still desynchronises. No probe covers it.
* **Named display for `ref.null` abstract heap types.** `ref.null struct` now prints
  `ref.null heaptype=-0x15` instead of `ref.null structref`. Keeping the name requires a second
  whole-byte operand on `opc=0xd0` (an "identical patterns" SLEIGH error) or a sub-constructor
  with mixed export sizes (an "inconsistent export size" SLEIGH error); the only clean
  alternatives were a numeric operand (chosen) or dropping multi-byte concrete indices. The
  operand value is display-only: the pcode (`sp0_32 = 0`) and the Java `ValType` pushed are
  unchanged, and no recorded metric or gate checks listing text.
* **`ConstantExpression.readBlockType`** (block types inside constant expressions) still reads a
  single s33. Not needed for the acceptance and not touched.
* **`select`'s "inconsistent types" check** still uses identity (`t1 != t2`); only
  `popValue`/`popValues`/`popBlock` were made subtype-aware, as requested.
* No changes to the memarg/`readLeb128` memarg region (owned by `h4`), no pushes, merges or tags.

## 6. Verification honesty

Verified: build + install into the pinned `ghidra-h3` install; the full 173-probe gate with the
real module; `check-fixture-validity.py` in both `--update` and check modes; per-probe listings
for E15 and the four new probes. Not independently verified: the exact wording of SLEIGH's
"identical patterns"/"inconsistent export size" diagnostics (observed empirically, not from
source).
