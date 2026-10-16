# REPORT-R2-PAGEBOUND — custom page size 1-page over-bound rejection

## Defect

`WasmLoader.validateMemoryLimits` (src/main/java/wasm/WasmLoader.java) applied a single
page-count bound to every memory regardless of its page size:

- 32-bit memory: 65536 pages
- 64-bit memory: 2^48 pages

For a memory that declares a custom page size (limits flag `0x08`, exponent 0 => 1 byte per
page) with 65537 pages, the total is only 65537 bytes — well inside the 32-bit address space —
but the loader rejected it because 65537 > 65536 pages. The review fixture
`custom-page-65537.wasm` (1-byte pages, 65537 pages, 65537 bytes) therefore failed to import
with:

```
ERROR Failed to load Wasm module: Memory 0 is invalid: initial size 65537 page(s) exceeds the 32-bit limit of 65536 page(s)
```

Per the custom-page-sizes proposal the bound is on the *byte* size, not the page count.
Reference: https://github.com/WebAssembly/custom-page-sizes (proposals/custom-page-sizes/Overview.md).

## Reproduction (before fix)

Build was from the pre-fix tree via `test-scripts/build-install.ps1` into the pinned install
`C:\Users\micro\AppData\Local\Temp\ghidra-r2-pagebound`.

Command:
```
$gh = "C:\Users\micro\AppData\Local\Temp\ghidra-r2-pagebound"
& "$gh\support\analyzeHeadless.bat" $proj "Reg" -import "D:\code\Ghidra-WASM\build\release-review-luna\custom-page-65537.wasm" -deleteProject
```

Observed (in `.../before-import.log`):
```
ERROR Failed to load Wasm module: Memory 0 is invalid: initial size 65537 page(s) exceeds the 32-bit limit of 65536 page(s) (WasmLoader) java.io.IOException: ...
ERROR REPORT: Import failed for file: file:///D:/code/Ghidra-WASM/build/release-review-luna/custom-page-65537.wasm
```

## Fix

`validateMemoryLimits` now computes the bound from the page size:

- `maxPages = 2^(32 - pageSizeExponent)` for an i32-index memory
- `maxPages = 2^(64 - pageSizeExponent)` for an i64-index memory

The default exponent 16 reproduces the previous 65536 / 2^48 bounds. The same bound is applied
to both the initial and the maximum value. `initial > maximum` and genuinely over-bound
declarations are still rejected, and the independent 128 MiB materialisation cap
(`MAX_MEMORY_BLOCK_BYTES`) in `loadMemories` is untouched.

Overflow handling for tiny exponents:
- i64 with exponent 0 would be 2^64 pages, which does not fit in a signed `long`; it is
  saturated to the all-ones value (`-1L`, i.e. the maximum unsigned 64-bit page count), so no
  overflow occurs and every encodable page count is accepted.
- Exponents large enough to make the shift negative yield a bound of 0, so any positive
  declaration is rejected.
- Comparisons use `Long.compareUnsigned`, consistent with the unsigned page counts LEB-decoded
  for memory64.

Added public helper `WasmLoader.maxMemoryPages(WasmResizableLimits)` (used by
`WasmEmulateInstructionStateModifier` for its no-maximum fallback, replacing the hard-coded
`1L << 48` / `MAX_MEMORY32_PAGES`).

## Evidence (after fix)

Same import command on the fixed extension:

Observed (in `.../after-import.log`):
```
INFO  Memory 0 declares a custom page size of 1 byte(s) (2^0); its 65537 page(s) (65537 byte(s)) are mapped into the `memory` space at 0x0 (WasmLoader)
```

The import now succeeds and the block extent is 65537 bytes (below the 128 MiB cap). A gate log
records `PROBE-BLOCK B03e_custom_page_size_65537_pages.wasm .memory0 size=65537`.

Invalid modules still fail: a default-page-size memory declaring 65537 pages is still rejected
with `Memory 0 is invalid: initial size 65537 page(s) exceeds the 32-bit limit of 65536 page(s)`.

## Regression probe added

- `test-scripts/probes_types.py`: new probe `B03e_custom_page_size_65537_pages.wasm`
  (`memory_section_custom([(0x08, 65537, None, 0)])`), classed `valid`.
- `test-scripts/expected-results.json`: probe_count 222 -> 223; new entry
  `B03e_custom_page_size_65537_pages.wasm: funcs=1 instrs=2 undefined_bytes=0 decompiled=1
  decompile_failed=0 import_ok=true`.
- `test-scripts/fixture-validity.json`: +1 probe, new probe classified `valid`.

## Gate numbers (verify mode)

```
probes: 205 imported, 18 import failure(s); baseline has 223
OK: every probe matches the recorded baseline.
```
- Fixture summary: functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0.
- Fixture-validity: 223 probes, wabt-only mode = 129 valid / 64 wabt-gap / 17 unsupported / 13 invalid;
  binaryen mode also 129 valid / 64 wabt-gap / 17 unsupported / 13 invalid (new probe `valid` in both).
- Real module baseline unchanged: functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156.

`.\test-scripts\check-fixture-validity.py` exits 0 in both fixture-validity modes.

## Documentation

`MODERN_WASM_GAPS.md`: probe-count references 222 -> 223, valid count 128 -> 129, and the
custom-page-sizes row now covers probes `B03b`-`B03e`. `test-scripts/memory64-hybrid-fixtures.py`
comment updated to 223 probes.

## Open items

- The external oracles (wabt 1.0.42 and binaryen version_133) accept only page-size exponents
  0 and 16. Exotic exponents are still honoured leniently by the loader, with the new
  page-size-derived bound; no rejection is added for them (project policy: keep accepting).
- The i64 / exponent-0 bound is saturated to the all-ones long; any i64 declaration up to
  2^64-1 pages is therefore accepted (subject to the 128 MiB materialisation cap).
- The real module `rasterbator_rs_bg.wasm` was not locally available for a DumpDecomp run; its
  baseline (437/437/0/61658/156) is unchanged in the baseline JSON.
