# REPORT-H4 — multi-memory memarg (B3), table64 and >4 GiB memory64 (B8)

Branch `fix/memidx-table64` (based on `main` @ e5157d4). Worktree
`ghidra-wt-h4`, pinned Ghidra install `ghidra-h1`.

Two loader/decoder gaps from `MODERN_WASM_GAPS.md` / the open-items list were
reproduced, fixed and pinned with 9 new probes. No SLEIGH change turned out to be
needed for B3: the `memalign_mem` / `memidx_label` decoder and the
`memidx_label * MEMORY_STRIDE` address computation were already correct (see the
evidence below — `memidx=9` decompiles to `DAT_ram_90000000`, i.e.
`9 * 0x10000000`). The bug was in the Java *re-parse* of the module.

---

## B3 — memory index >= 9 breaks the analysis re-parse

### Root cause

`WasmAnalysis.getState()` re-parses the module from **program memory** to
reconstruct `WasmModule`. It used `new MemoryByteProvider(mem, moduleStart)`,
and that Ghidra constructor (verified with `javap -c` on
`Ghidra/Features/Base/lib/Base.jar`) sizes the provider with
`findAddressSpaceMax(memory, address)` — the maximum address of the **whole `ram`
address space**, not the end of the block containing `moduleStart`.

The module image is exactly one block at `CODE_BASE = 0x80000000`, and
`WasmLoader` maps linear memory N at `N * MEMORY_STRIDE`
(`MEMORY_STRIDE = 0x10000000`). So as soon as any memory block is mapped **above**
the module image — memory index >= 8, i.e. `N * 0x10000000 >= 0x80000000` — the
provider's `length()` reaches past the module. The section loop in `WasmModule`
(`while (reader.getPointerIndex() < reader.length())`) then tries to read one
section header past the module block and throws

```
java.io.IOException: Address ram:8000003d does not exist in memory
```

which propagates out of `WasmAnalysis.getState()`, so every analyzer that needs
the state fails and the whole body degrades to a stub `unreachable`.

A load/store with a memory index >= 9 needs at least ten declared memories, and
memory 9 is mapped at `0x90000000` (above `CODE_BASE`) — that is why the visible
trigger was "memidx >= 9". The memarg decode itself was never wrong.

### Before / after (exact commands)

Before (with the `MemoryByteProvider(mem, moduleStart)` form restored and rebuilt,
run against the committed probe set):

```
.\test-scripts\build-install.ps1
$env:GHIDRA_INSTALL_DIR="C:\Users\micro\AppData\Local\Temp\ghidra-h1"
$env:GHIDRA_HEADLESS_MAXMEM="1500M"
.\test-scripts\run_probes.ps1 -OutDir "$env:TEMP\h4-before" -Generators probes_memidx_table64.py
```

| probe | before | after |
|---|---|---|
| `B3_01_memidx9_load`   | `instrs=1 undefined_bytes=7`  | `instrs=4 undefined_bytes=0` |
| `B3_02_memidx127_store`| `instrs=1 undefined_bytes=9`  | `instrs=5 undefined_bytes=0` |
| `B3_03_memidx128_load` | `instrs=1 undefined_bytes=8`  | `instrs=4 undefined_bytes=0` |
| `B3_04_memidx1000_load_store` | `instrs=1 undefined_bytes=21` | `instrs=8 undefined_bytes=0` |

Before, each body listed as a single `unreachable` at the function entry
(`ram:80000035  unreachable`) and the log carried
`Address ram:8000003d does not exist in memory` (and, for the first draft that
declared 10 one-page memories, `Failed to create memory block 8 at
ram:80000000`).

After (`.\test-scripts\run_probes.ps1 -OutDir "$env:TEMP\h4-final" -Generators
probes_memidx_table64.py -Detail`):

```
function f @ ram:80000035 int f(void)
ram:80000035  .locals
ram:80000036  i32.const 0x0
ram:80000038  i32.load align=0x2 memidx=0x9 offset=0x0
ram:8000003c  end
DECOMP B3_01_memidx9_load.wasm
  return DAT_ram_90000000;
```

```
ram:80000128  i32.store align=0x2 memidx=0x7f offset=0x0        (B3_02)
ram:80000128  i32.load  align=0x2 memidx=0x80 offset=0x0        (B3_03)
ram:800007f9  i32.load  align=0x2 memidx=0x3e8 offset=0x4       (B3_04)
ram:80000800  i32.store align=0x2 memidx=0x3e8 offset=0x8       (B3_04)
ram:80000807  i32.load  align=0x2 memidx=0x0 offset=0x0         (B3_04)
```

The `DAT_ram_90000000` read confirms the SLEIGH side agrees with the loader:
`memidx=9` -> `9 * MEMORY_STRIDE = 0x90000000`, exactly where `.memory9` is
mapped. For `memidx >= 16` (`128`, `1000`) the computed address wraps in the
32-bit `ram` space (documented; the listing still shows the correct index and
`undefined_bytes=0`).

### Fix

`src/main/java/wasm/analysis/WasmAnalysis.java` — bound the re-parse to the
module image block:

```java
MemoryBlock moduleBlock = mem.getBlock(moduleStart);
ByteProvider memByteProvider = (moduleBlock != null)
        ? new MemoryByteProvider(mem, moduleStart, moduleBlock.getEnd())
        : new MemoryByteProvider(mem, moduleStart);
```

---

## B8(a) — table64

### What was already right

`WasmResizableLimits` already decodes limits flag bit `0x04`, so the table
section (and every entry after a 64-bit table) parsed without desync; the
`table` address space is 8 bytes wide (`define space table ... size=8`), so a
64-bit index fits. Probes `B8_01`/`B8_03` confirm a table64 followed by a
table32 parses and both tables are materialised (`.table0 size=4`, `.table1
size=8`).

### Gaps fixed

1. **Recorded the flag.** `WasmTableType.is64Bit()` now exposes the decoded
   flag, and `WasmLoader.createTableBlock()` names the index type:
   * materialised table -> the block comment says
     `64-bit (table64) table: the index type is i64; ...`;
   * skipped (huge) table -> the diagnostic is now
     `Table 0 (i64 index) declares 4294967296 element(s); this exceeds the
     loader's table limit of 67108864 byte(s), so the table is not materialised`.
2. **Element segments that reference a table64 were silently dropped.**
   `WasmElementSegment.getOffset()` returned `offset.asI32()`, which is `null`
   for an `i64.const` offset — and an active segment targeting a 64-bit table
   must use an i64 offset. `WasmLoader.loadElementSegments()` then did
   `if (offset == null) continue;` and dropped the segment. It now uses
   `asConstValue()`, which accepts `i32.const` and `i64.const` (and still
   returns `null` for `global.get` / unparsed expressions).

   Verified with a scratch `DumpTables.java` over `.table0`:

   | B8_01 `.table0` bytes | before | after |
   |---|---|---|
   | `table:00000000 size=8` | `00 00 00 00 00 00 00 00` | `2f 00 00 80 00 00 00 00` |

   `0x8000002f` is the referenced function's address, so the segment is applied
   after the fix and dropped before it.

### Probes

* `B8_01_table64_elem` — `(table i64 2 funcref)` + active element segment with an
  i64 offset. `.table0 size=8`, `undefined_bytes=0`, decompiles.
* `B8_02_table64_huge_skipped` — `(table i64 0x100000000 funcref)`; skipped with
  the `(i64 index)` diagnostic, `undefined_bytes=0`.
* `B8_03_table64_then_table32` — a table64 followed by a table32, each with an
  element segment; `.table0 size=4`, `.table1 size=8`, `undefined_bytes=0`.

---

## B8(b) — memory64 with a declared size > 4 GiB

A memory64 declaration with `initial > 4 GiB` is valid per the memory64 proposal
(`MAX_MEMORY64_PAGES = 2^48`). The loader already accepted it and was honest: it
computes the byte size with saturation, caps the block at
`MAX_MEMORY_BLOCK_BYTES` (256 MiB) and logs the mismatch. This was verified, and
the address-space behaviour is now documented in the code comment on
`WasmLoader.loadMemories()`:

* the declared byte count is computed as a `long` (never overflowing);
* the block is capped at 256 MiB and the mismatch is logged;
* the code section still decodes because nothing in the decode path depends on
  the memory's materialised size;
* `ram` is a 32-bit space, so addresses/offsets >= 4 GiB are clamped to the top of
  the space and logged by `WasmLoader.getMemoryAddress()` (never wrapped into a
  wrong address).

Observed diagnostics (final run):

```
WasmLoader: Memory 0 (i64 index) declares 4587520000 byte(s) but is mapped to
            268435456 byte(s) ... (B8_04, 70000 pages)
WasmLoader: Memory 0 (i64 index) declares 4295032832 byte(s) but is mapped to
            268435456 byte(s) ... (B8_05, 65537 pages)
```

Both probes: `.memory0 size=268435456`, `undefined_bytes=0`, decompiles.

---

## Probes and metrics

All in the one new file `test-scripts/probes_memidx_table64.py` (9 probes). All
nine are **valid** per both oracles (wabt 1.0.42 `wasm-validate --enable-all`,
binaryen 133 `wasm-dis --all-features`); none needed an `--unsupported`
declaration.

Recorded metrics (from the final gate run):

| probe | funcs | instrs | undefined_bytes | decompiled |
|---|---|---|---|---|
| `B3_01_memidx9_load` | 1 | 4 | 0 | 1/0 |
| `B3_02_memidx127_store` | 1 | 5 | 0 | 1/0 |
| `B3_03_memidx128_load` | 1 | 4 | 0 | 1/0 |
| `B3_04_memidx1000_load_store` | 1 | 8 | 0 | 1/0 |
| `B8_01_table64_elem` | 1 | 3 | 0 | 1/0 |
| `B8_02_table64_huge_skipped` | 1 | 3 | 0 | 1/0 |
| `B8_03_table64_then_table32` | 1 | 3 | 0 | 1/0 |
| `B8_04_mem64_over4g` | 1 | 4 | 0 | 1/0 |
| `B8_05_mem64_just_over4g` | 1 | 4 | 0 | 1/0 |

## Baseline changes

* `test-scripts/expected-results.json`: `probe_count` `169 -> 178`; **9 added
  entries** (the nine probes above, all `import_ok: true`,
  `undefined_bytes: 0`). **No existing entry changed.** Regenerated with
  `check-local.ps1 ... -Update` (never hand-edited).
* `test-scripts/fixture-validity.json`: **9 added entries**, all `valid`. No
  existing class changed (gate: `probes: 178  valid: 105  wabt-gap: 36
  unsupported: 26  invalid: 11`).

## Gate results

```
python test-scripts/check-fixture-validity.py --probes "$env:TEMP\h4-validity" \
    --wabt ... --binaryen ...
probes: 178  valid: 105  wabt-gap: 36  unsupported: 26  invalid: 11
OK: every probe matches the recorded fixture classification (fixture-validity.json).

.\test-scripts\check-local.ps1 -OutDir "$env:TEMP\ci-h4" -SkipBuild `
    -RealModule "D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm"
probes: 161 imported, 17 import failure(s); baseline has 178
OK: every probe matches the recorded baseline.
SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0
SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156
```

Fixture and real-module summaries are unchanged from the pre-existing baseline.

## Commits

* `fix(analysis): bound the module re-parse to the module image block` — `WasmAnalysis.java`
* `fix(loader): table64 index flag, i64 element-segment offsets, memory64 >4GiB doc` — `WasmLoader.java`, `WasmTableType.java`, `WasmElementSegment.java`
* `test: probes for memidx >= 9, table64 and >4 GiB memory64` — `probes_memidx_table64.py`, `expected-results.json`, `fixture-validity.json`

## What I did NOT do

* **No SLEIGH change.** The memarg decode and the `memidx_label *
  MEMORY_STRIDE` address computation were already correct; the `DAT_ram_90000000`
  decompilation for `memidx=9` is the evidence. The task's hypothesis (a
  `memalign_idx` token / `readLeb128` pair bug) was not the actual cause.
* **Did not change the multi-memory address map.** Memory index >= 8 still
  collides with the module image at `CODE_BASE` (memory 8's block cannot be
  created; the loader logs `Failed to create memory block 8`). The probes avoid
  depending on that block. This is the pre-existing `MEMORY_STRIDE` design, not a
  parse bug, and is out of scope for B3's acceptance (list the load/store with the
  right memidx, `undefined_bytes=0`).
* **Did not materialise huge table64 / >4 GiB memory64 blocks.** The loader still
  caps them (64 MiB tables, 256 MiB memories) and logs the mismatch, which matches
  the current design ("skip with a clear diagnostic"); the probes pin that.
* **Did not touch** `WasmPreAnalyzer.guessCStackGlobalForFunction`, which also
  uses an unbounded `MemoryByteProvider`. It only reads a handful of bytes from a
  function entry and catches `IOException`; bounding it could change the C-stack
  guess on existing modules and risk the 169-probe baseline, so it was left as is.
* **No `git push`, merge or tag**; only the three commits above on
  `fix/memidx-table64`.
