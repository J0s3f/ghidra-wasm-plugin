# Custom memory page sizes – report

## Feature

Linear memories flagged with bit 3 (custom page size) of the resizable-limits flags are
now sized at `initial_pages x pageSize` instead of `initial_pages x 64 KiB`. The page
size is derived from the uleb128 exponent that follows the flags/initial (and optional
maximum): `pageSize = 2^exponent` bytes; modules without the flag keep the standard
64 KiB (`2^16`) page. The materialisation cap (128 MiB), the maximum-index
validation (4 GiB for i32 / 2^64 for i64, expressed in bytes and then in pages), the
declared-size warning and the mapping block sizing all honour the declared page size.
The emulation harness was already page-size aware.

## Verified spec encoding

Verified empirically with hand-crafted variants of `B03_limits_custom_page_size.wasm`
and the pinned oracles:

* flags byte bit 3 (`0x08`) marks a custom page size;
* the value that follows the initial (and maximum, when bit 0 is set) count is a
  uleb128 **exponent**: `page_size = 1 << exponent` bytes;
* wabt 1.0.42 and binaryen 133 only accept `exponent == 0` (1-byte pages) or
  `exponent == 16` (65536-byte pages, the standard size). wabt rejects any other
  exponent with `only page sizes of 1 B or 64 KiB are allowed`, so those two are the
  legal page sizes accepted by the current oracles. The loader itself accepts any
  exponent in `[0, 62]`.

Evidence from `wasm-dis --all-features`:
* exponent 0  -> `(memory $0 10 (pagesize 1))` (accepted)
* exponent 16 -> `(memory $0 10)` (accepted, standard 64 KiB)
* exponents 1..15, 17 -> rejected by both tools

The earlier fixture comment (`probes_types.py` said `exponent=4 (64 KiB pages)`) was
misleading; `exponent=4` means 16-byte pages, which neither oracle accepts. The
recorded `B03` probe uses exponent 0 (1-byte pages).

Encoding verified by generating 18 one-memory modules (exponents 0..16 and 12) and
validating each with `wabt wasm-validate --enable-all` and `binaryen wasm-dis
--all-features` (see scratch variants under `%TEMP%`).

## Files changed

* `src/main/java/wasm/format/sections/structures/WasmResizableLimits.java` – added
  `getPageSize()` (default 64 KiB, else `1L << exponent`, clamped to a sane range).
* `src/main/java/wasm/WasmLoader.java` – `memoryByteSize(pages, pageSize)`,
  `loadMemories()` uses `mem.getPageSize()` for declared bytes, page-size-aware
  validation limits, custom-page-size warning/info text.
* `test-scripts/probes_types.py` – rewrote the `B03` comment and added
  `B03b_custom_page_size_standard.wasm` and `B03c_custom_page_size_tiny_overflow.wasm`.
* `test-scripts/fixture-validity.json` – re-recorded (+2 valid probes, now 203).
* `test-scripts/expected-results.json` – recut by `check-local.ps1 -Update`
  (+2 probes).
* `MODERN_WASM_GAPS.md` – row updated.

## Probes added

* `B03_limits_custom_page_size.wasm` (pre-existing, exponent 0, 1-byte pages,
  10 pages -> a 10-byte `.memory0` block).
* `B03b_custom_page_size_standard.wasm` (exponent 16, 5 pages -> 327680 bytes).
* `B03c_custom_page_size_tiny_overflow.wasm` (exponent 0, 10 pages, active data
  segment at offset 98 with 9 bytes of data, which overruns the 10-byte block).

## Observable evidence (probe-scoped, recorded here, not the shared generator)

Using `DumpMemory.java` (post-script, no change to the shared generator):

* B03:   `MEMBLOCK ... .memory0 ... size=10`  (before the change it was 655360
  under the hard-wired 64 KiB page size).
* B03b:  `MEMBLOCK ... .memory0 ... size=327680`.
* B03c:  the loader logs
  `Failed to initialize memory 0 with data segment 0 at memory:00000062` with
  `MemoryAccessException: Address memory:00000062 does not exist in memory`, and
  `MEMBLOCK size=10`, proving the declared 1-byte page size bounds the block.

Built-in `WasmEmulateInstructionStateModifier` already uses
`(1L << limits.getPageSizeExponent())` for `memory.size`/`memory.grow` and was left
as-is but switched conceptually through the limits accessor (no behavioural change).

## Commands run with observed results

* `pwsh test-scripts/build-install.ps1 -GhidraDir ... -Gradle ...` -> BUILD SUCCESSFUL.
* `wasm-dis --all-features` / `wasm-validate --enable-all` on the 18 variants ->
  only exponents 0 and 16 accepted.
* `python test-scripts/check-fixture-validity.py --generate ... --update` ->
  `updated fixture-validity.json (203 probes)`; wabt/binaryen classify the two new
  probes as `valid`.
* `python test-scripts/check-fixture-validity.py` (no --update) -> expected OK
  (to be re-verified after the gate).
* `.\test-scripts\check-local.ps1 -Update` -> BUILD/INSTALL OK; 203 probes; check-results: `updated ... expected-results.json: 179 probe(s) with metrics, 24 expected import failure(s)`.
* `.\test-scripts\check-local.ps1` (no -Update, fresh outdir) -> OK: `probes: 179 imported, 24 import failure(s); baseline has 203`, `OK: every probe matches the recorded baseline.`; fixture `SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0`.
* `python test-scripts/check-fixture-validity.py` (wabt only) -> OK (203 probes: valid 120 / wabt-gap 53 / unsupported 17 / invalid 13).
* `python test-scripts/check-fixture-validity.py --binaryen ...` -> OK (same classification; binaryen skipped 13 recorded probes).

## Open items

* Only 1-byte and 64 KiB page sizes are accepted by the pinned oracles; larger
  stdlib changes would be needed if the spec later permits intermediate sizes.
  The loader already supports arbitrary exponents.
* Tables are unaffected (`WasmResizableLimits` custom-page flag is ignored for
  tables, as tables use element counts, not page sizes).
* Real-module memory numbers unchanged (no real module in the corpus exercises a
  custom page size).

## Update for full gate results

(to be filled in after the background gate completes)
