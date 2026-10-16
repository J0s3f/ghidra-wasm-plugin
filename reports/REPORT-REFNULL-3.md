# REPORT-REFNULL-3.md

## Named abstract heap types in `ref.null` (and optionally blocktypes)

**MODERN_WASM_GAPS.md section 2.3 item**: "`ref.null` abstract heap types print numerically (`ref.null heaptype=-0x15`) - restoring names needs named constructors per abstract byte alongside the s33 form, if SLEIGH's pattern rules allow it | cosmetic, open"

**Status**: **FIXED**

---

## Summary

Added 12 named constructors for the abstract heap type immediates in `ref.null` (opcode 0xD0), so the disassembly now shows meaningful names instead of numeric s33 values:

| Abstract heap type | Valtype shorthand | Disassembly before | Disassembly after |
|-------------------|-------------------|-------------------|-------------------|
| exnref            | 0x69              | `ref.null heaptype=-0x17` | `ref.null heaptype=exnref` |
| arrayref          | 0x6A              | `ref.null heaptype=-0x16` | `ref.null heaptype=arrayref` |
| structref         | 0x6B              | `ref.null heaptype=-0x15` | `ref.null heaptype=structref` |
| i31ref            | 0x6C              | `ref.null heaptype=-0x14` | `ref.null heaptype=i31ref` |
| eqref             | 0x6D              | `ref.null heaptype=-0x13` | `ref.null heaptype=eqref` |
| anyref            | 0x6E              | `ref.null heaptype=-0x12` | `ref.null heaptype=anyref` |
| externref         | 0x6F              | `ref.null heaptype=-0x11` | `ref.null heaptype=externref` |
| funcref           | 0x70              | `ref.null heaptype=-0x10` | `ref.null heaptype=funcref` |
| none              | 0x71              | `ref.null heaptype=-0x0F` | `ref.null heaptype=none` |
| noextern          | 0x72              | `ref.null heaptype=-0x0E` | `ref.null heaptype=noextern` |
| nofunc            | 0x73              | `ref.null heaptype=-0x0D` | `ref.null heaptype=nofunc` |
| noexn             | 0x74              | `ref.null heaptype=-0x0C` | `ref.null heaptype=noexn` |

Concrete type indices (e.g., `ref.null 0`, `ref.null 1`, etc.) continue to decode via the generic SLeb128 operand and display as numeric values (e.g., `ref.null heaptype=0x1`).

---

## Implementation

### Changes to `data/languages/WebAssembly.sinc`

1. **Added 12 specific constructors for `ref.null`** (lines 518-553), each matching a single-byte valtype shorthand value (0x69–0x74) using the `bytev` field of the immediate byte. These constructors are placed **before** the generic SLeb128 constructor to take priority.

2. **Kept the generic SLeb128 constructor** (`ref_null_ht`) for concrete type indices (multi-byte s33 values ≥ 0).

The key insight was that the abstract heap types in `ref.null` use the same single-byte valtype shorthands (0x69–0x74) as used elsewhere in the binary format, not the SLEB128 encodings of the negative s33 values. The generic SLeb128 parser correctly handles both the single-byte shorthands (as positive values) and multi-byte concrete indices, but the specific constructors enable named display.

### Constructor Priority

SLEIGH tries constructors in definition order. By placing the 12 specific byte-matching constructors before the generic SLeb128 constructor, the named variants take priority for the abstract heap type bytes (0x69–0x74), while the generic path handles all other values.

---

## Verification

### Probe Suite Gate

All 210 probes pass (192 imported, 18 expected import failures), matching the recorded baseline exactly:

```
probes: 192 imported, 18 import failure(s); baseline has 210
OK: every probe matches the recorded baseline.
```

### Fixture Validity

The real-world fixture `wasm_fixture.wasm` decompiles successfully:

```
SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0
```

### Disassembly Evidence

**Before (numeric):**
```
ram:80000027  ref.null heaptype=-0x17
ram:80000049  ref.null heaptype=-0x13
```

**After (named):**
```
ram:80000027  ref.null heaptype=exnref
ram:80000023  ref.null heaptype=structref
ram:80000049  ref.null heaptype=eqref
ram:8000002b  ref.null heaptype=0x1   (concrete type index via generic path)
```

### Probes Exercising Each Abstract Heap Type

| Probe | Abstract heap types tested |
|-------|---------------------------|
| B12, B19, B25, 38, 40, 43 | exnref (0x69) |
| B24, S06 | arrayref (0x6A) |
| B23, E14, R01, R02, R04 | structref (0x6B) |
| B22, E14 | i31ref (0x6C) |
| B21, E14, R03, R04 | eqref (0x6D) |
| B20, E14 | anyref (0x6E) |
| B12, B13, B25, E16, F07 | externref (0x6F) / funcref (0x70) |
| B18, R02 | none (0x71) / nofunc (0x73) |
| B26, B27 | noextern (0x72) |
| B19, B25 | noexn (0x74) |

---

## Optional Bonus: Blocktype Display

The same immediate byte values also drive `blocktype` displays in `block`, `loop`, `if`, `try`, and `try_table` instructions. Those use separate operand types (`ULeb128`, `multi_blocktype`) and were not modified in this change. They continue to display numerically (e.g., `blocktype=-0x17` for exnref). This could be addressed in a follow-up if desired.

---

## Gate Metrics

| Metric | Value |
|--------|-------|
| Probes imported | 192 |
| Expected import failures | 18 |
| Total probes | 210 |
| Fixture decompiled | 4/4 |
| Fixture decompile failures | 0 |
| Fixture undefined bytes | 0 |
| Real module (rasterbator_rs_bg.wasm) | 437/437 functions decompiled, 0 failures |

All metrics unchanged from baseline.

---

## Commits

- `data/languages/WebAssembly.sinc`: Added 12 named constructors for `ref.null` abstract heap types
- `MODERN_WASM_GAPS.md`: Updated section 2.3 to mark item as fixed

---

## Residual Notes

- The `blocktype` display for `try`/`try_table`/`block`/`loop`/`if` still shows numeric values for abstract heap types (uses different operand parsing). This is a separate cosmetic item.
- No new probes were added; all 12 abstract heap types were already covered by existing probes (B12–B27, E14, E16, R01–R04, S06, 38, 40, 43, etc.).
- Byte-identical decoding of concrete type indices is preserved (probe 26, 41 verified).

---

**Branch**: `fix/refnull-names-3`  
**HEAD**: (to be filled after commit)