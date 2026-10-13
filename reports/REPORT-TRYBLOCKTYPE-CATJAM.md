# REPORT-TRYBLOCKTYPE-CATJAM: multi-byte block signatures on try / try_table

## Feature
Extended `try` (legacy EH) and `try_table` (new EH) to decode multi-byte block
signatures, mirroring the existing `block`/`loop`/`if` support
(`multi_blocktype` = `0x63`/`0x64` + s33 heaptype) and multi-byte s33 type indices.

## Implementation
- `data/languages/WebAssembly.sinc`: added `:try "blocktype="^multi_blocktype` constructors for all
  four ctx cases (empty, branch, sp0_32, sp0_64).
- `data/languages/EH2Ops.sinc`: added `:try_table ... multi_blocktype` constructors for the empty
  and three dispatcher cases.
- `src/main/java/wasm/analysis/WasmFunctionAnalysis.java`: legacy `0x06` now uses
  `readBlockType` instead of `new BlockType(analysis, readSignedLeb128(...))`; added
  `BlockType`/param-count overloads for `ValType.BlockTypeInfo`.
- `src/main/java/wasm/analysis/EH2Ops.java`: `analyzeTryTable` reads the block type through
  `ValType.readBlockType`, consuming multi-byte value types and type indices.

## Verified byte encodings (hex)
- TB01 `try_table (ref null $t)`: `... 1f 63 00 00 d0 00 0b 0b`
  block type `0x63 0x00` (ref null type 0), catch vector `00`, body `d0 00` (ref.null 0).
- TB02 `try_table` type index 128: `... 1f 80 01 00 0b 0b`
  block type LEB128 `80 01` = 128, catch vector `00`.
- TB03 legacy `try (ref null $t)`: `... 06 63 00 d0 00 0b 0b`.

WABT `wasm-validate --enable-all` and Ghidra analysis agree on all three
(undefined_bytes = 0, decompiled = 1).

## Probes added
- `test-scripts/probes_tryblocktype.py` generates `TB01_try_table_ref_block.wasm`,
  `TB02_try_table_typeidx128.wasm`, `TB03_try_legacy_ref.wasm`.

## Commands run
- `build-install.ps1` (pinned install) - BUILD SUCCESSFUL.
- `check-local.ps1 -SkipBuild -Update` - updated expected-results.json.
- `check-local.ps1 -SkipBuild` - OK: every probe matches; fixture SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0.
- `check-fixture-validity.py` (wabt-only and wabt+binaryen) - OK.

## Gate numbers
- Probes: 201 -> 204 (186 imported + 18 expected import failures).
- Fixture validity: valid 118 -> 121; wabt-gap 53; unsupported 17; invalid 13.
- Real module: not re-run in this worktree; no loader change affecting it.

## Open items
- None for this gap. It is considered closed.