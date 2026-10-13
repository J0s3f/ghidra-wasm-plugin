# REPORT-PAGESIZE-MUSESPARK.md — custom memory page sizes (feat/pagesize-musespark)

Branch: `feat/pagesize-musespark`. The one remaining real standardised WebAssembly 3.0 gap
(MODERN_WASM_GAPS.md §2.3, "Custom page sizes"): the limits flag decoded, but the page size was
hardwired to 64 KiB (`MEMORY_PAGE_SIZE` in `WasmLoader.java`), so block sizing and declared-size
semantics were wrong for modules declaring a custom page size.

## 1. Verified spec encoding (empirical, not assumed)

Oracles: wabt 1.0.42 (`wasm-validate --enable-all`, `wasm-objdump -x`) and binaryen version_133
(`wasm-dis --all-features`), fetched into `%TEMP%\opencode\pslc-scratch\` (wabt via
`test-scripts/spectest/fetch_spectest_tools.ps1 -WabtOnly`; binaryen release tarball, 111 MB).

Method: hand-crafted variants of the existing B03 probe (raw memory-section bytes, generated with
`test-scripts/wasm_probe_lib.py` helpers into scratch — never committed), inspected read-only with
`wasm-objdump -x` and validated with both oracles (`wasm-dis` only via `python subprocess` with a
60 s timeout, never bare).

Findings (both oracles agree on every point):

- **Which bit**: limits flags bit 3 (`0x08`) marks a custom page size.
- **What follows**: exactly one `uleb128` after the initial page count (after the maximum when bit 0
  is also set). Field order `flags, initial, [maximum], [exponent]` confirmed with flag
  combinations `0x09` (max), `0x0B` (shared+max), `0x0C` (memory64), `0x0D` (memory64+max) —
  `wasm-objdump` prints e.g. `initial=1 max=4 shared (pagesize 4096)` / `initial=1 i64 (pagesize 4096)`.
- **What the value denotes**: a log2 **exponent** — page size = 2^value bytes. `wasm-objdump -x`
  prints `(pagesize 1)` for value 0, `(pagesize 2/16/256/4096)` for values 1/4/8/12, and hides the
  annotation for value 16 (i.e. the default 64 KiB).
- **Legal values / minimum**: both oracles accept **only exponents 0 (1 byte) and 16 (64 KiB)**;
  any other value is rejected (`wabt: "only page sizes of 1 B or 64 KiB are allowed"` for 1–16
  except 16, `"malformed memory page size"` for > 16; `binaryen: "Memory page size is only allowed
  to be 1 or 64 KiB"`). So the **minimum legal page size is 1 byte** (exponent 0).
- **Pre-existing B03 note**: `probes_types.py` B03 passes `(0x08, 10, 0, 4)` but `memory_section()`
  only encodes `(flags, initial[, maximum])`, so the trailing `4` was silently dropped and the
  committed B03 is really flags=8/initial=10/**exponent=0** (10 one-byte pages). Both oracles accept
  it (`valid`). B03 is left byte-identical on purpose (see §4); the new probes use an explicit
  encoder.

## 2. Loader changes (`src/main/java/wasm/WasmLoader.java`)

- `getMemoryPageSize(WasmResizableLimits)` (new, public static): returns `MEMORY_PAGE_SIZE` (64 KiB)
  without the flag, else `1L << exponent`, saturating to `Long.MAX_VALUE` for exponents outside
  0–62 (a raw `1L << e` would go negative at 63 and wrap mod-64 above — a hostile exponent must
  never defeat the clamp or produce a negative block length).
- `memoryByteSize(pages)` kept, delegating to new overload `memoryByteSize(pages, pageSize)` with
  saturation (`pages * pageSize`, `Long.MAX_VALUE` on overflow). For the default page size the
  computation is literally identical to before.
- `loadMemories()`: `declared = pages × pageSize` (was `pages × 64 KiB`); the 128 MiB
  materialisation cap and its warning are unchanged for default-page-size memories (message text
  byte-identical — the page note `" (N page(s) of P byte(s))"` is appended only when the page size
  differs from 64 KiB). A memory declaring a custom page size now logs an info line naming the
  page size, page count and byte size (grep-able evidence, program bytes unaffected).
- `createMemoryBlock()`: new overload takes the page size + limits and sets a `Custom page size:
  P byte(s) per page (2^E)` block comment (plus the i64 note when combined); default-page-size
  blocks take the exact old path (5-arg overload delegates with `MEMORY_PAGE_SIZE`).
- `validateMemoryLimits()`: deliberately **unchanged** (doc note added): limits are counted in
  pages regardless of page size, and byte-size explosion is already bounded by the saturating
  multiply + the materialisation cap — so no new rejection is introduced (project keep-accepting
  policy). For every oracle-legal module (pages ∈ {1 B, 64 KiB}) the page-count limits are the
  binding ones anyway.
- `loadDataSegments()` failure path: on a placement failure the historical message is kept
  byte-identical for default page sizes; for custom-page-size memories a note names the
  page-derived declared size, e.g. `(memory declares 2 page(s) of 1 byte(s) = 2 byte(s); the
  8-byte segment at offset 0 does not fit)`. The block itself is now page-sized, so `setBytes`
  throwing *is* the page-aware bounds check (no separate pre-check needed; the clamped-huge-memory
  case keeps its pre-existing behaviour — documented §5).

## 3. Emulation harness (`WasmEmulateInstructionStateModifier.java`)

Evaluated: `memory.size`/`memory.grow` are modelled in **pages** (`memoryPages[]`, `growMemory`
compares against `memoryMaxPages[]`), so the page size only enters through `getMemorySizeBytes()`
(bounds checks). That path was already page-size aware; two safe hardenings, no behaviour change
for sane values:

- the provider now uses the shared `WasmLoader.getMemoryPageSize()` instead of its own
  `1L << exponent` shift (identical for exponents 0/16, bounded otherwise);
- `getMemorySizeBytes()` multiplies with saturation instead of a wrapping multiply.

The SLEIGH needs no change: linear addresses are byte offsets independent of page size, and
`memory.size`/`memory.grow` carry page counts. No analyzer references `MEMORY_PAGE_SIZE`
(grep-verified), and no other `65536 / 0x10000 / <<16` page-size assumption exists under
`data/languages` or `src` (only unrelated `0x10000000` register-base constants).

## 4. Probes (`test-scripts/probes_types.py`, helper in `wasm_probe_lib.py`)

- `wasm_probe_lib.py`: additive-only `memory_custom_page()` / `memory_section_custom()` encoder
  (existing `memory_section()` untouched, so every pre-existing probe byte is unchanged — including
  B03, which stays flags=8/initial=10/exponent=0 as generated before).
- `B03b_custom_page_size_tiny.wasm`: flags `0x08`, 8 pages, exponent 0 (1-byte pages) + 3-byte
  `"Hi!"` data segment at offset 0. Declared = 8 bytes.
- `B03c_custom_page_size_standard.wasm`: flags `0x08`, 2 pages, exponent 16 (explicit 64 KiB).
  Declared = 131072 bytes; must behave exactly like a default memory of that size.
- `B03d_custom_page_size_overrun.wasm`: flags `0x08`, 2 pages, exponent 0 + 8-byte `"OVERFLOW"`
  segment at offset 0. Declared = 2 bytes; placement must fail with the page-aware error.

All three classify `valid` under **both** oracles (verified pre-commit; recorded in
`fixture-validity.json`).

Observable evidence (from the gate log + a `DumpMemory.java` run against the pinned install):

- `PROBE-BLOCK B03b… .memory0 size=8` (old code: 524288), `B03… size=10` (old: 655360),
  `B03c… size=131072`, `B03d… size=2` — block extents are pages × page_size.
- Loader info lines, e.g. `Memory 0 declares a custom page size of 1 byte(s) (2^0); its 8 page(s)
  (8 byte(s)) are mapped into the 'memory' space at 0x0`.
- B03d log error: `Failed to initialize memory 0 with data segment 0 at memory:00000000 (memory
  declares 2 page(s) of 1 byte(s) = 2 byte(s); the 8-byte segment at offset 0 does not fit)`.
- `DumpMemory.java`: `MEMBLOCK B03b… size=8` + `MEMDATA .memory0 +0x0 … 48 69 21 Hi!`;
  `MEMBLOCK B03d… size=2` with no `MEMDATA` (segment did not fit).
- How observed: `run_probes.ps1` gate log (`PROBE-BLOCK` lines, already emitted by
  `WasmFeatureReport.java` — no shared-generator change) + one ad-hoc headless `DumpMemory.java`
  run on the two tiny probes; outputs quoted above.

## 5. Residual limitations / deliberately out of scope

- Exotic exponents (anything but 0/16) are honoured leniently (sized + clamped, never rejected)
  while both oracles reject them — consistent with project policy; recorded nowhere as valid.
- `validateMemoryLimits` stays page-count based (see §2 why).
- A data segment inside the *declared* size but past the 128 MiB *materialised* block still fails
  with the generic placement error (pre-existing behaviour for huge memories, unchanged).
- `memory64` × custom-page-size combinations parse and size correctly but have no dedicated probe
  (oracles only accept exponents 0/16, which are covered in 32-bit form; the code path is shared).
- The `memory` address-space stride (128 MiB) is unrelated to page size and untouched.

## 6. Gap-doc status

MODERN_WASM_GAPS.md: §2.2 gains a "Custom memory page sizes (block sizing) — fixed" row pointing
here; the §2.3 open row is closed with the residual noted above; probe/validity counts updated
(204 probes: 186 + 18; 121 valid / 53 wabt-gap / 17 unsupported / 13 invalid).

## 7. Commands run with observed results

- Oracle fetch: `fetch_spectest_tools.ps1 -WabtOnly` (wabt 1.0.42, sha ok) + binaryen
  `version_133` tarball (111,045,528 bytes) into `%TEMP%\opencode\pslc-scratch\`.
- Encoding: 14 hand-crafted variants → `wasm-objdump -x` + `wasm-validate --enable-all` +
  `wasm-dis --all-features` (via python, 60 s timeout): only exponents 0/16 accepted by both.
- Build/install: `build-install.ps1 -GhidraDir <pinned>` → BUILD SUCCESSFUL, extension installed
  (only pre-existing deprecation warnings).
- Targeted: `run_probes.ps1 -Generators probes_types.py -Only B03` → 4 probes, block sizes
  10/8/131072/2, info + overrun error lines as quoted in §4.
- `DumpMemory.java` ad-hoc run on B03b/B03d → MEMDATA `Hi!` at +0x0; B03d block size 2, no data.
- Full gate: `check-local.ps1 -GhidraDir <pinned> -OutDir <scratch>\gate1 -SkipBuild -Update` →
  204 probes, recut OK. Baseline diff: **only the 3 new probes added; 0 of 201 pre-existing entries
  changed; fixture unchanged** (verified by diffing `expected-results.json` against HEAD).
- Validity: `check-fixture-validity.py --generate --wabt … --binaryen … --update` → 204 probes,
  only the 3 new `valid` entries added; oracle header intact; no `oracle_skip` removed.
- Final verification: `check-local.ps1` (full, with rebuild) → OK (`probes: 186 imported,
  18 import failure(s); baseline has 204` / `OK: every probe matches the recorded baseline`;
  fixture `SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0`);
  validity wabt-only → OK (204: 121/53/17/13); validity both-oracle → OK (same counts, 13
  `oracle_skip` honoured).
- Real module (`rasterbator_rs_bg.wasm`, read-only import via the pinned install) →
  `SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156` —
  the recorded 437/437/0/61658/156 baseline, unchanged.
