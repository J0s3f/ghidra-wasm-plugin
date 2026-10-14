# REPORT-REFNULL-MISTRAL: named abstract heap types in `ref.null`

**Branch:** `fix/refnull-names-mistral`
**Model:** Mistral Large 4 (subagent)
**Date:** 2026-10-14
**Gap:** MODERN_WASM_GAPS.md §2.3 - "`ref.null` abstract heap types print numerically (`ref.null heaptype=-0x15`)"

## Summary

Added named SLEIGH constructors per Wasm 3.0 abstract heap type byte (0x69–0x74) alongside
the existing generic s33 form for `ref.null` (0xD0). The disassembly now shows
`ref.null struct`, `ref.null exn`, `ref.null func`, etc. instead of `ref.null heaptype=-0xNN`.
Concrete type indices still decode via the s33 path, byte-identically.

## The change

**File:** `data/languages/WebAssembly.sinc` (+27 lines)

Added a `ref_null_ht_named` nonterminal with 12 named variants (one per abstract heap type
byte) and a constructor that uses it, placed before the generic s33 constructor:

```
ref_null_ht_named: "exn" is bytev=0x69 { }
ref_null_ht_named: "array" is bytev=0x6a { }
ref_null_ht_named: "struct" is bytev=0x6b { }
ref_null_ht_named: "i31" is bytev=0x6c { }
ref_null_ht_named: "eq" is bytev=0x6d { }
ref_null_ht_named: "any" is bytev=0x6e { }
ref_null_ht_named: "extern" is bytev=0x6f { }
ref_null_ht_named: "func" is bytev=0x70 { }
ref_null_ht_named: "none" is bytev=0x71 { }
ref_null_ht_named: "noextern" is bytev=0x72 { }
ref_null_ht_named: "nofunc" is bytev=0x73 { }
ref_null_ht_named: "noexn" is bytev=0x74 { }

:ref.null ref_null_ht_named is opc=0xd0; ref_null_ht_named; sp0_32; ctx_is_directive=0 {
    sp0_32 = 0;
}
:ref.null "heaptype="^ref_null_ht is opc=0xd0; ref_null_ht; sp0_32; ctx_is_directive=0 {
    sp0_32 = 0;
}
```

**Why SLEIGH's pattern disambiguation works:** each named variant constrains all 8 bits of
the byte (`bytev=0xNN`), making it strictly more specific than the generic single-byte
SLeb128 variant (which constrains only bit 7 via `topbit=0`). SLEIGH prefers the more
specific constructor, so `ref.null 0x6B` matches the `"struct"` variant while
`ref.null 0x01` (concrete type index 1) falls through to the generic s33 path.

**Byte encodings verified against the Wasm 3.0 spec**
(<https://webassembly.github.io/spec/core/binary/types.html>):

| byte | s33 | name | valtype shorthand |
|------|-----|------|-------------------|
| 0x69 | -0x17 | exn | exnref |
| 0x6A | -0x16 | array | arrayref |
| 0x6B | -0x15 | struct | structref |
| 0x6C | -0x14 | i31 | i31ref |
| 0x6D | -0x13 | eq | eqref |
| 0x6E | -0x12 | any | anyref |
| 0x6F | -0x11 | extern | externref |
| 0x70 | -0x10 | func | funcref |
| 0x71 | -0x0F | none | noneref |
| 0x72 | -0x0E | noextern | noexternref |
| 0x73 | -0x0D | nofunc | nofuncref |
| 0x74 | -0x0C | noexn | noexnref |

## Before/after evidence (ListProgram.java disassembly)

### Existing probes (abstract heap types in function bodies)

| Probe | Heap type | Before | After |
|-------|-----------|--------|-------|
| R01_ref_typing_struct_block | struct (0x6B) | `ref.null heaptype=-0x15` | `ref.null struct` |
| R02_ref_typing_funcref_mix | nofunc (0x73) | `ref.null heaptype=-0xd` | `ref.null nofunc` |
| R03_ref_typing_anyref_where_eqref | any (0x6E) | `ref.null heaptype=-0x12` | `ref.null any` |
| R04_ref_typing_subtype_accept | struct (0x6B) | `ref.null heaptype=-0x15` | `ref.null struct` |
| E14_gc_ref_test_cast | struct (0x6B) | `ref.null heaptype=-0x15` | `ref.null struct` |
| E14_gc_ref_test_cast | eq (0x6D) | `ref.null heaptype=-0x13` | `ref.null eq` |
| E15_gc_br_on_cast | struct (0x6B) | `ref.null heaptype=-0x15` | `ref.null struct` |
| 40_eh2_try_table_ref_null_exn | exn (0x69) | `ref.null heaptype=-0x17` | `ref.null exn` |
| 43_eh_legacy_try_ref_null_exn | exn (0x69) | `ref.null heaptype=-0x17` | `ref.null exn` |

### Concrete type index (s33 fallback — unchanged)

| Probe | Heap type | Before | After |
|-------|-----------|--------|-------|
| 41_eh2_try_table_ref_null_typeidx1 | type index 1 | `ref.null heaptype=0x1` | `ref.null heaptype=0x1` |
| 44_eh_legacy_try_ref_null_typeidx1 | type index 1 | `ref.null heaptype=0x1` | `ref.null heaptype=0x1` |

### New probes RN01–RN12 (all 12 abstract heap types in function bodies)

| Probe | Byte | Name shown |
|-------|------|------------|
| RN01_refnull_exn | 0x69 | `ref.null exn` |
| RN02_refnull_array | 0x6A | `ref.null array` |
| RN03_refnull_struct | 0x6B | `ref.null struct` |
| RN04_refnull_i31 | 0x6C | `ref.null i31` |
| RN05_refnull_eq | 0x6D | `ref.null eq` |
| RN06_refnull_any | 0x6E | `ref.null any` |
| RN07_refnull_extern | 0x6F | `ref.null extern` |
| RN08_refnull_func | 0x70 | `ref.null func` |
| RN09_refnull_none | 0x71 | `ref.null none` |
| RN10_refnull_noextern | 0x72 | `ref.null noextern` |
| RN11_refnull_nofunc | 0x73 | `ref.null nofunc` |
| RN12_refnull_noexn | 0x74 | `ref.null noexn` |

Each new probe: `() -> <reftype>`, body = `ref.null <ht>; end`, 34 bytes.
All 12 import successfully with `funcs=1 instrs=3 undefined_bytes=0 decompiled=1 decompile_failed=0`.

**Fixture-validity classification of the new probes:**
- `valid` (both oracles accept): RN01 (exn), RN07 (extern), RN08 (func)
- `wabt-gap` (wabt 1.0.42 rejects, binaryen accepts): RN02–RN06, RN09–RN12
  (wabt is behind the final GC/EH valtype encodings, same as the existing R-probes)

## Gate numbers

| Metric | Before | After |
|--------|--------|-------|
| Probe count | 210 | 222 (+12 RN probes) |
| Probes imported | 192 | 204 |
| Expected import failures | 18 | 18 (unchanged) |
| Fixture: functions | 4 | 4 (unchanged) |
| Fixture: decompiled | 4/4 | 4/4 (unchanged) |
| Fixture: instructions | 24 | 24 (unchanged) |
| Fixture: undefined_bytes | 0 | 0 (unchanged) |
| Fixture-validity: valid | 125 | 128 (+3) |
| Fixture-validity: wabt-gap | 55 | 64 (+9) |
| Fixture-validity: unsupported | 17 | 17 (unchanged) |
| Fixture-validity: invalid | 13 | 13 (unchanged) |

**Full gate:** `check-local.ps1` → "OK: every probe matches the recorded baseline."
**Fixture-validity gate:** `check-fixture-validity.py` → "OK: every probe matches the recorded fixture classification."

## Optional bonus: blocktype displays (skipped)

The `multi_blocktype` nonterminal (used by `block`/`loop`/`if`/`try`/`try_table`) still prints
numerically (e.g. `block blocktype=-0x15`). Extending the same named-constructor pattern there
would name those too, but the blocktype is a 2-byte sequence (0x63/0x64 + s33) and the
disambiguation is more involved (the named variants would need to match `bytev=0x63; bytev=0xNN`
as a 2-byte pattern). Left as a residual cosmetic item.

Similarly, `ref.test`/`ref.cast`/`br_on_cast*` `ht=` operands in GCOps.sinc print numerically
(e.g. `ref.test ht=0x0` for concrete type indices, `ref.test ht=-0x15` for abstract types).
The same named-constructor pattern could be applied to the `heaptype` nonterminal there.

## Files changed

- `data/languages/WebAssembly.sinc` (+27 lines: `ref_null_ht_named` nonterminal + constructor)
- `test-scripts/probes_refnull_names.py` (new: 12 probes RN01–RN12)
- `test-scripts/expected-results.json` (+12 probe entries, probe_count 210→222)
- `test-scripts/fixture-validity.json` (+12 probe entries)
- `MODERN_WASM_GAPS.md` (updated §2.3 row, probe counts)
