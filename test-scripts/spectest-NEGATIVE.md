# Negative spec-test results - rejection behaviour

Harness: `test-scripts/spectest/run_spectest_negative.ps1` (see `README.md` section 5).
Plugin under test: this worktree (plugin sources unchanged), built with
`test-scripts/build-install.ps1` into Ghidra 12.1.4.
Toolchain: wabt `1.0.42`, testsuite `WebAssembly/spec @ d76759e7`.
Raw machine-readable result: the `negative.json` of the run; the table below is the
same per-file data in Markdown. Ranked findings: **`REPORT-NS.md`**.

## Summary

**59 rejected / 2889 accepted / 0 crash / 0 hang** -- 2948 modules inspected.

| | |
| --- | --- |
| negative commands in the testsuite | 4039 |
| binary modules imported (this run) | 2948 |
| `module_type: text` modules skipped | 1091 |
| accepted but useless (empty shell / partial load) | 272 |
| accepted, then an analyzer raised an exception | 4 |

| kind | modules | rejected | accepted | crash | hang |
| --- | ---: | ---: | ---: | ---: | ---: |
| invalid | 2146 | 0 | 2146 | 0 | 0 |
| malformed | 719 | 59 | 660 | 0 | 0 |
| unlinkable | 83 | 0 | 83 | 0 | 0 |

Accepted-program shapes: `accepted-empty`=219, `accepted-partial`=53, `accepted-shape`=2617

Rejection diagnostics: `loader-exception`=31, `no-loader`=28

The `crash`/`hang` columns are for the import-only (`-noanalysis`) classification run:
none of the 2948 modules kills the *loader*. Five of them stall the *analysis* when it is
enabled (the default for an interactive import) - see the hazard pass at the end.


## Reproduction

```powershell
$env:GHIDRA_INSTALL_DIR = "<pinned Ghidra 12.1.4 install>"
cd <worktree>

# 1. fetch the pinned wabt + testsuite (once) -> %TEMP%\spectest-tools
.\test-scripts\spectest\fetch_spectest_tools.ps1
# 2. build + clean-install this worktree's plugin
.\test-scripts\build-install.ps1 -GhidraDir $env:GHIDRA_INSTALL_DIR
# 3. the whole binary negative set (2948 modules; ~8 min at -max-cpu 2)
#    -ChunkSize bounds one run; a chunk that wedges is split and retried automatically.
.\test-scripts\spectest\run_spectest_negative.ps1 -OutDir "$env:TEMP\specneg-all" -ChunkSize 5000
#    -> $env:TEMP\specneg-all\negative.json / negative.md

# bounded smoke run (one malformed module per .wast, ~1 min)
.\test-scripts\spectest\run_spectest_negative.ps1 -Kinds malformed -MaxPerWastPerKind 1 `
    -OutDir "$env:TEMP\specneg-smoke"

# hazard pass: the 9 modules whose analysis crashes/wedges the run are imported one per run
# (analysis on), because a single one can abort or stall the whole batch.
.\test-scripts\spectest\run_spectest_negative.ps1 -SkipPrepare -WithAnalysis `
    -ImportDir "$env:TEMP\specneg-hazard\import" -ChunkSize 1 -TimeoutSec 90 `
    -OutDir "$env:TEMP\specneg-hazard"

# optional evidence pass: re-import an accepted subset WITH analysis (instrs/undefined_bytes,
# analyzer exceptions, OOM). Bounded by --limit; --exclude drops the hazard modules above.
python test-scripts\spectest\select_negative_subset.py `
    --results "$env:TEMP\specneg-all\negative.json" --modules "$env:TEMP\specneg-all\modules.json" `
    --srcdir "$env:TEMP\specneg-all\import" --out "$env:TEMP\specneg-evidence" --kinds malformed `
    --limit 250 --exclude binary.51.malformed.wasm,binary.52.malformed.wasm,binary.53.malformed.wasm,binary.54.malformed.wasm,binary-leb128.48.malformed.wasm,binary-leb128.49.malformed.wasm
.\test-scripts\spectest\run_spectest_negative.ps1 -SkipPrepare `
    -ImportDir "$env:TEMP\specneg-evidence\import" -WithAnalysis -ChunkSize 100 `
    -OutDir "$env:TEMP\specneg-evidence"
```

One headless run per chunk:

```
analyzeHeadless <projdir> NegRun -import <chunkdir> -recursive \
  -scriptPath <worktree>\test-scripts\spectest -postScript SpecNegativeReport.java \
  -noanalysis -max-cpu 2 -deleteProject
```

(`-noanalysis` for the classification run: rejection happens at load. A chunk whose run
does not return every module's verdict is split in half and retried, so a module that
crashes/hangs the loader is isolated to a chunk of its own.)


## Per-.wast breakdown

| wast | modules | rejected | accepted-shape | accepted-empty | accepted-partial | crash | hang |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| align | 43 | 0 | 43 | 0 | 0 | 0 | 0 |
| binary | 116 | 46 | 37 | 33 | 0 | 0 | 0 |
| binary-leb128 | 58 | 8 | 43 | 7 | 0 | 0 | 0 |
| block | 155 | 0 | 155 | 0 | 0 | 0 | 0 |
| br | 20 | 0 | 20 | 0 | 0 | 0 | 0 |
| br_if | 29 | 0 | 29 | 0 | 0 | 0 | 0 |
| br_table | 24 | 0 | 24 | 0 | 0 | 0 | 0 |
| call | 18 | 0 | 18 | 0 | 0 | 0 | 0 |
| call_indirect | 24 | 0 | 24 | 0 | 0 | 0 | 0 |
| conversions | 25 | 0 | 25 | 0 | 0 | 0 | 0 |
| custom | 8 | 5 | 3 | 0 | 0 | 0 | 0 |
| data | 22 | 0 | 16 | 6 | 0 | 0 | 0 |
| elem | 26 | 0 | 26 | 0 | 0 | 0 | 0 |
| exports | 31 | 0 | 20 | 11 | 0 | 0 | 0 |
| f32 | 11 | 0 | 11 | 0 | 0 | 0 | 0 |
| f32_bitwise | 3 | 0 | 3 | 0 | 0 | 0 | 0 |
| f32_cmp | 6 | 0 | 6 | 0 | 0 | 0 | 0 |
| f64 | 11 | 0 | 11 | 0 | 0 | 0 | 0 |
| f64_bitwise | 3 | 0 | 3 | 0 | 0 | 0 | 0 |
| f64_cmp | 6 | 0 | 6 | 0 | 0 | 0 | 0 |
| func | 49 | 0 | 49 | 0 | 0 | 0 | 0 |
| func_ptrs | 7 | 0 | 6 | 1 | 0 | 0 | 0 |
| global | 44 | 0 | 44 | 0 | 0 | 0 | 0 |
| i32 | 83 | 0 | 83 | 0 | 0 | 0 | 0 |
| i64 | 29 | 0 | 29 | 0 | 0 | 0 | 0 |
| if | 92 | 0 | 92 | 0 | 0 | 0 | 0 |
| imports | 75 | 0 | 74 | 1 | 0 | 0 | 0 |
| labels | 3 | 0 | 3 | 0 | 0 | 0 | 0 |
| linking | 12 | 0 | 12 | 0 | 0 | 0 | 0 |
| load | 46 | 0 | 46 | 0 | 0 | 0 | 0 |
| local_get | 16 | 0 | 16 | 0 | 0 | 0 | 0 |
| local_set | 33 | 0 | 33 | 0 | 0 | 0 | 0 |
| local_tee | 41 | 0 | 41 | 0 | 0 | 0 | 0 |
| loop | 27 | 0 | 27 | 0 | 0 | 0 | 0 |
| memory | 18 | 0 | 10 | 8 | 0 | 0 | 0 |
| memory_copy | 64 | 0 | 64 | 0 | 0 | 0 | 0 |
| memory_fill | 64 | 0 | 64 | 0 | 0 | 0 | 0 |
| memory_grow | 7 | 0 | 7 | 0 | 0 | 0 | 0 |
| memory_init | 67 | 0 | 67 | 0 | 0 | 0 | 0 |
| memory_size | 2 | 0 | 2 | 0 | 0 | 0 | 0 |
| nop | 4 | 0 | 4 | 0 | 0 | 0 | 0 |
| ref_func | 3 | 0 | 2 | 0 | 1 | 0 | 0 |
| ref_is_null | 2 | 0 | 2 | 0 | 0 | 0 | 0 |
| return | 20 | 0 | 20 | 0 | 0 | 0 | 0 |
| select | 28 | 0 | 28 | 0 | 0 | 0 | 0 |
| simd_align | 12 | 0 | 12 | 0 | 0 | 0 | 0 |
| simd_bit_shift | 24 | 0 | 24 | 0 | 0 | 0 | 0 |
| simd_bitwise | 28 | 0 | 28 | 0 | 0 | 0 | 0 |
| simd_boolean | 12 | 0 | 12 | 0 | 0 | 0 | 0 |
| simd_conversions | 18 | 0 | 18 | 0 | 0 | 0 | 0 |
| simd_f32x4 | 8 | 0 | 8 | 0 | 0 | 0 | 0 |
| simd_f32x4_arith | 16 | 0 | 16 | 0 | 0 | 0 | 0 |
| simd_f32x4_cmp | 18 | 0 | 18 | 0 | 0 | 0 | 0 |
| simd_f32x4_pmin_pmax | 6 | 0 | 6 | 0 | 0 | 0 | 0 |
| simd_f32x4_rounding | 8 | 0 | 8 | 0 | 0 | 0 | 0 |
| simd_f64x2 | 8 | 0 | 8 | 0 | 0 | 0 | 0 |
| simd_f64x2_arith | 16 | 0 | 16 | 0 | 0 | 0 | 0 |
| simd_f64x2_cmp | 18 | 0 | 18 | 0 | 0 | 0 | 0 |
| simd_f64x2_pmin_pmax | 6 | 0 | 6 | 0 | 0 | 0 | 0 |
| simd_f64x2_rounding | 8 | 0 | 8 | 0 | 0 | 0 | 0 |
| simd_i16x8_arith | 11 | 0 | 11 | 0 | 0 | 0 | 0 |
| simd_i16x8_arith2 | 17 | 0 | 17 | 0 | 0 | 0 | 0 |
| simd_i16x8_cmp | 30 | 0 | 30 | 0 | 0 | 0 | 0 |
| simd_i16x8_extadd_pairwise_i8x16 | 4 | 0 | 4 | 0 | 0 | 0 | 0 |
| simd_i16x8_extmul_i8x16 | 12 | 0 | 12 | 0 | 0 | 0 | 0 |
| simd_i16x8_q15mulr_sat_s | 3 | 0 | 3 | 0 | 0 | 0 | 0 |
| simd_i16x8_sat_arith | 12 | 0 | 12 | 0 | 0 | 0 | 0 |
| simd_i32x4_arith | 11 | 0 | 11 | 0 | 0 | 0 | 0 |
| simd_i32x4_arith2 | 14 | 0 | 14 | 0 | 0 | 0 | 0 |
| simd_i32x4_cmp | 30 | 0 | 30 | 0 | 0 | 0 | 0 |
| simd_i32x4_dot_i16x8 | 3 | 0 | 3 | 0 | 0 | 0 | 0 |
| simd_i32x4_extadd_pairwise_i16x8 | 4 | 0 | 4 | 0 | 0 | 0 | 0 |
| simd_i32x4_extmul_i16x8 | 12 | 0 | 12 | 0 | 0 | 0 | 0 |
| simd_i32x4_trunc_sat_f32x4 | 4 | 0 | 4 | 0 | 0 | 0 | 0 |
| simd_i32x4_trunc_sat_f64x2 | 4 | 0 | 4 | 0 | 0 | 0 | 0 |
| simd_i64x2_arith | 11 | 0 | 11 | 0 | 0 | 0 | 0 |
| simd_i64x2_arith2 | 2 | 0 | 2 | 0 | 0 | 0 | 0 |
| simd_i64x2_cmp | 10 | 0 | 10 | 0 | 0 | 0 | 0 |
| simd_i64x2_extmul_i32x4 | 12 | 0 | 12 | 0 | 0 | 0 | 0 |
| simd_i8x16_arith | 8 | 0 | 8 | 0 | 0 | 0 | 0 |
| simd_i8x16_arith2 | 19 | 0 | 19 | 0 | 0 | 0 | 0 |
| simd_i8x16_cmp | 30 | 0 | 30 | 0 | 0 | 0 | 0 |
| simd_i8x16_sat_arith | 12 | 0 | 12 | 0 | 0 | 0 | 0 |
| simd_int_to_int_extend | 24 | 0 | 24 | 0 | 0 | 0 | 0 |
| simd_lane | 83 | 0 | 83 | 0 | 0 | 0 | 0 |
| simd_load | 5 | 0 | 5 | 0 | 0 | 0 | 0 |
| simd_load16_lane | 3 | 0 | 3 | 0 | 0 | 0 | 0 |
| simd_load32_lane | 3 | 0 | 3 | 0 | 0 | 0 | 0 |
| simd_load64_lane | 3 | 0 | 3 | 0 | 0 | 0 | 0 |
| simd_load8_lane | 3 | 0 | 3 | 0 | 0 | 0 | 0 |
| simd_load_extend | 12 | 0 | 12 | 0 | 0 | 0 | 0 |
| simd_load_splat | 8 | 0 | 8 | 0 | 0 | 0 | 0 |
| simd_load_zero | 4 | 0 | 4 | 0 | 0 | 0 | 0 |
| simd_splat | 22 | 0 | 22 | 0 | 0 | 0 | 0 |
| simd_store | 6 | 0 | 6 | 0 | 0 | 0 | 0 |
| simd_store16_lane | 3 | 0 | 3 | 0 | 0 | 0 | 0 |
| simd_store32_lane | 3 | 0 | 3 | 0 | 0 | 0 | 0 |
| simd_store64_lane | 3 | 0 | 3 | 0 | 0 | 0 | 0 |
| simd_store8_lane | 3 | 0 | 3 | 0 | 0 | 0 | 0 |
| start | 3 | 0 | 3 | 0 | 0 | 0 | 0 |
| store | 51 | 0 | 51 | 0 | 0 | 0 | 0 |
| switch | 1 | 0 | 1 | 0 | 0 | 0 | 0 |
| table | 4 | 0 | 2 | 2 | 0 | 0 | 0 |
| table-sub | 2 | 0 | 2 | 0 | 0 | 0 | 0 |
| table_fill | 9 | 0 | 9 | 0 | 0 | 0 | 0 |
| table_get | 5 | 0 | 5 | 0 | 0 | 0 | 0 |
| table_grow | 7 | 0 | 7 | 0 | 0 | 0 | 0 |
| table_init | 67 | 0 | 67 | 0 | 0 | 0 | 0 |
| table_set | 7 | 0 | 7 | 0 | 0 | 0 | 0 |
| table_size | 2 | 0 | 2 | 0 | 0 | 0 | 0 |
| unreached-invalid | 118 | 0 | 118 | 0 | 0 | 0 | 0 |
| utf8-custom-section-id | 176 | 0 | 0 | 150 | 26 | 0 | 0 |
| utf8-import-field | 176 | 0 | 176 | 0 | 0 | 0 | 0 |
| utf8-import-module | 176 | 0 | 150 | 0 | 26 | 0 | 0 |


## Silent acceptance with a useless program (272)

`accepted-empty` = the program contains nothing but the raw-byte `.module` block;
`accepted-partial` = the loader logged `Failed to load Wasm module` and the import was
still reported as successful.

| module | kind | wast line | expected (testsuite) | shape | detail |
| --- | --- | ---: | --- | --- | --- |
| `binary.32.malformed.wasm` | malformed | 48 | malformed section id | accepted-empty | funcs=0 blocks=1 |
| `binary.33.malformed.wasm` | malformed | 49 | malformed section id | accepted-empty | funcs=0 blocks=1 |
| `binary.34.malformed.wasm` | malformed | 50 | malformed section id | accepted-empty | funcs=0 blocks=1 |
| `binary.35.malformed.wasm` | malformed | 51 | malformed section id | accepted-empty | funcs=0 blocks=1 |
| `binary.36.malformed.wasm` | malformed | 52 | malformed section id | accepted-empty | funcs=0 blocks=1 |
| `binary.56.malformed.wasm` | malformed | 401 | function and code section have inconsiste... | accepted-empty | funcs=0 blocks=1 |
| `binary.62.malformed.wasm` | malformed | 454 | data count and data section have inconsis... | accepted-empty | funcs=0 blocks=1 |
| `binary.63.malformed.wasm` | malformed | 466 | data count and data section have inconsis... | accepted-empty | funcs=0 blocks=1 |
| `binary.74.malformed.wasm` | malformed | 661 | section size mismatch | accepted-empty | funcs=0 blocks=1 |
| `binary.87.malformed.wasm` | malformed | 814 | integer too large | accepted-empty | funcs=0 blocks=1 |
| `binary.88.malformed.wasm` | malformed | 824 | integer representation too long | accepted-empty | funcs=0 blocks=1 |
| `binary.92.malformed.wasm` | malformed | 860 | integer too large | accepted-empty | funcs=0 blocks=1 |
| `binary.93.malformed.wasm` | malformed | 869 | integer representation too long | accepted-empty | funcs=0 blocks=1 |
| `binary.116.malformed.wasm` | malformed | 1202 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.117.malformed.wasm` | malformed | 1212 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.118.malformed.wasm` | malformed | 1222 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.119.malformed.wasm` | malformed | 1232 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.120.malformed.wasm` | malformed | 1242 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.121.malformed.wasm` | malformed | 1252 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.122.malformed.wasm` | malformed | 1262 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.123.malformed.wasm` | malformed | 1272 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.124.malformed.wasm` | malformed | 1282 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.125.malformed.wasm` | malformed | 1292 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.126.malformed.wasm` | malformed | 1302 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.127.malformed.wasm` | malformed | 1312 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.128.malformed.wasm` | malformed | 1322 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.129.malformed.wasm` | malformed | 1332 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.130.malformed.wasm` | malformed | 1342 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.131.malformed.wasm` | malformed | 1352 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.132.malformed.wasm` | malformed | 1363 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.133.malformed.wasm` | malformed | 1374 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.134.malformed.wasm` | malformed | 1384 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary.135.malformed.wasm` | malformed | 1394 | unexpected content after last section | accepted-empty | funcs=0 blocks=1 |
| `binary-leb128.27.malformed.wasm` | malformed | 235 | integer representation too long | accepted-empty | funcs=0 blocks=1 |
| `binary-leb128.28.malformed.wasm` | malformed | 246 | integer representation too long | accepted-empty | funcs=0 blocks=1 |
| `binary-leb128.31.malformed.wasm` | malformed | 279 | integer representation too long | accepted-empty | funcs=0 blocks=1 |
| `binary-leb128.32.malformed.wasm` | malformed | 291 | integer representation too long | accepted-empty | funcs=0 blocks=1 |
| `binary-leb128.53.malformed.wasm` | malformed | 571 | integer too large | accepted-empty | funcs=0 blocks=1 |
| `binary-leb128.54.malformed.wasm` | malformed | 582 | integer too large | accepted-empty | funcs=0 blocks=1 |
| `binary-leb128.55.malformed.wasm` | malformed | 593 | integer too large | accepted-empty | funcs=0 blocks=1 |
| `data.41.invalid.wasm` | invalid | 299 | unknown memory | accepted-empty | funcs=0 blocks=1 |
| `data.42.invalid.wasm` | invalid | 307 | unknown memory 1 | accepted-empty | funcs=0 blocks=1 |
| `data.43.invalid.wasm` | invalid | 320 | unknown memory 0 | accepted-empty | funcs=0 blocks=1 |
| `data.44.invalid.wasm` | invalid | 331 | unknown memory 1 | accepted-empty | funcs=0 blocks=1 |
| `data.45.invalid.wasm` | invalid | 343 | unknown memory 1 | accepted-empty | funcs=0 blocks=1 |
| `data.46.invalid.wasm` | invalid | 365 | unknown memory 1 | accepted-empty | funcs=0 blocks=1 |
| `exports.15.invalid.wasm` | invalid | 39 | unknown function | accepted-empty | funcs=0 blocks=1 |
| `exports.35.invalid.wasm` | invalid | 96 | unknown global | accepted-empty | funcs=0 blocks=1 |
| `exports.58.invalid.wasm` | invalid | 151 | unknown table | accepted-empty | funcs=0 blocks=1 |
| `exports.59.invalid.wasm` | invalid | 155 | unknown table | accepted-empty | funcs=0 blocks=1 |
| `exports.61.invalid.wasm` | invalid | 163 | duplicate export name | accepted-empty | funcs=0 blocks=1 |
| `exports.62.invalid.wasm` | invalid | 167 | duplicate export name | accepted-empty | funcs=0 blocks=1 |
| `exports.65.invalid.wasm` | invalid | 179 | duplicate export name | accepted-empty | funcs=0 blocks=1 |
| `exports.80.invalid.wasm` | invalid | 207 | unknown memory | accepted-empty | funcs=0 blocks=1 |
| `exports.81.invalid.wasm` | invalid | 211 | unknown memory | accepted-empty | funcs=0 blocks=1 |
| `exports.83.invalid.wasm` | invalid | 219 | duplicate export name | accepted-empty | funcs=0 blocks=1 |
| `exports.86.invalid.wasm` | invalid | 236 | duplicate export name | accepted-empty | funcs=0 blocks=1 |
| `func_ptrs.1.invalid.wasm` | invalid | 32 | unknown table | accepted-empty | funcs=0 blocks=1 |
| `imports.99.invalid.wasm` | invalid | 496 | multiple memories | accepted-empty | funcs=0 blocks=1 |
| `memory.6.invalid.wasm` | invalid | 10 | multiple memories | accepted-empty | funcs=0 blocks=1 |
| `memory.7.invalid.wasm` | invalid | 11 | multiple memories | accepted-empty | funcs=0 blocks=1 |
| `memory.11.invalid.wasm` | invalid | 20 | unknown memory | accepted-empty | funcs=0 blocks=1 |
| `memory.12.invalid.wasm` | invalid | 21 | unknown memory | accepted-empty | funcs=0 blocks=1 |
| `memory.13.invalid.wasm` | invalid | 22 | unknown memory | accepted-empty | funcs=0 blocks=1 |
| `memory.24.invalid.wasm` | invalid | 67 | memory size must be at most 65536 pages (... | accepted-empty | funcs=0 blocks=1 |
| `memory.25.invalid.wasm` | invalid | 71 | memory size must be at most 65536 pages (... | accepted-empty | funcs=0 blocks=1 |
| `memory.26.invalid.wasm` | invalid | 75 | memory size must be at most 65536 pages (... | accepted-empty | funcs=0 blocks=1 |
| `ref_func.2.invalid.wasm` | invalid | 69 | unknown function 7 | accepted-partial | java.lang.IndexOutOfBoundsException: Index: 5 |
| `table.9.invalid.wasm` | invalid | 14 | unknown table | accepted-empty | funcs=0 blocks=1 |
| `table.12.invalid.wasm` | invalid | 23 | size minimum must not be greater than max... | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.0.malformed.wasm` | malformed | 7 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.1.malformed.wasm` | malformed | 17 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.2.malformed.wasm` | malformed | 27 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.3.malformed.wasm` | malformed | 37 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.4.malformed.wasm` | malformed | 47 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.5.malformed.wasm` | malformed | 57 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.6.malformed.wasm` | malformed | 69 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.7.malformed.wasm` | malformed | 79 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.8.malformed.wasm` | malformed | 89 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.9.malformed.wasm` | malformed | 101 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.10.malformed.wasm` | malformed | 111 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.11.malformed.wasm` | malformed | 121 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.12.malformed.wasm` | malformed | 131 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.13.malformed.wasm` | malformed | 141 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.14.malformed.wasm` | malformed | 151 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.15.malformed.wasm` | malformed | 161 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.16.malformed.wasm` | malformed | 171 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.17.malformed.wasm` | malformed | 181 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.18.malformed.wasm` | malformed | 191 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.19.malformed.wasm` | malformed | 201 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.20.malformed.wasm` | malformed | 211 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.21.malformed.wasm` | malformed | 223 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.22.malformed.wasm` | malformed | 233 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.23.malformed.wasm` | malformed | 243 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.24.malformed.wasm` | malformed | 253 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.25.malformed.wasm` | malformed | 263 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.26.malformed.wasm` | malformed | 275 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.27.malformed.wasm` | malformed | 285 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.28.malformed.wasm` | malformed | 295 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.29.malformed.wasm` | malformed | 305 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.30.malformed.wasm` | malformed | 315 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.31.malformed.wasm` | malformed | 325 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.32.malformed.wasm` | malformed | 335 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.33.malformed.wasm` | malformed | 345 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.34.malformed.wasm` | malformed | 355 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.35.malformed.wasm` | malformed | 365 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.36.malformed.wasm` | malformed | 375 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.37.malformed.wasm` | malformed | 385 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.38.malformed.wasm` | malformed | 395 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.39.malformed.wasm` | malformed | 405 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.40.malformed.wasm` | malformed | 415 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.41.malformed.wasm` | malformed | 425 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.42.malformed.wasm` | malformed | 435 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.43.malformed.wasm` | malformed | 445 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.44.malformed.wasm` | malformed | 455 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.45.malformed.wasm` | malformed | 465 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.46.malformed.wasm` | malformed | 475 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.47.malformed.wasm` | malformed | 485 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.48.malformed.wasm` | malformed | 495 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.49.malformed.wasm` | malformed | 505 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.50.malformed.wasm` | malformed | 515 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.51.malformed.wasm` | malformed | 525 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.52.malformed.wasm` | malformed | 535 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.53.malformed.wasm` | malformed | 545 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.54.malformed.wasm` | malformed | 555 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.55.malformed.wasm` | malformed | 565 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.56.malformed.wasm` | malformed | 575 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.57.malformed.wasm` | malformed | 585 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.58.malformed.wasm` | malformed | 597 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.59.malformed.wasm` | malformed | 607 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.60.malformed.wasm` | malformed | 617 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.61.malformed.wasm` | malformed | 627 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.62.malformed.wasm` | malformed | 637 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.63.malformed.wasm` | malformed | 647 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.64.malformed.wasm` | malformed | 657 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.65.malformed.wasm` | malformed | 667 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.66.malformed.wasm` | malformed | 677 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.67.malformed.wasm` | malformed | 687 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.68.malformed.wasm` | malformed | 697 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.69.malformed.wasm` | malformed | 707 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.70.malformed.wasm` | malformed | 717 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.71.malformed.wasm` | malformed | 727 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.72.malformed.wasm` | malformed | 737 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.73.malformed.wasm` | malformed | 747 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.74.malformed.wasm` | malformed | 757 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.75.malformed.wasm` | malformed | 767 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.76.malformed.wasm` | malformed | 777 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.77.malformed.wasm` | malformed | 787 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.78.malformed.wasm` | malformed | 797 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.79.malformed.wasm` | malformed | 807 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.80.malformed.wasm` | malformed | 817 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.81.malformed.wasm` | malformed | 827 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.82.malformed.wasm` | malformed | 839 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.83.malformed.wasm` | malformed | 849 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.84.malformed.wasm` | malformed | 859 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.85.malformed.wasm` | malformed | 869 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.86.malformed.wasm` | malformed | 879 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.87.malformed.wasm` | malformed | 889 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.88.malformed.wasm` | malformed | 899 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.89.malformed.wasm` | malformed | 911 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.90.malformed.wasm` | malformed | 921 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.91.malformed.wasm` | malformed | 931 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.92.malformed.wasm` | malformed | 941 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.93.malformed.wasm` | malformed | 951 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.94.malformed.wasm` | malformed | 961 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.95.malformed.wasm` | malformed | 971 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.96.malformed.wasm` | malformed | 981 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.97.malformed.wasm` | malformed | 991 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.98.malformed.wasm` | malformed | 1001 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.99.malformed.wasm` | malformed | 1011 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.100.malformed.wasm` | malformed | 1021 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.101.malformed.wasm` | malformed | 1031 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.102.malformed.wasm` | malformed | 1041 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.103.malformed.wasm` | malformed | 1051 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.104.malformed.wasm` | malformed | 1061 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.105.malformed.wasm` | malformed | 1071 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.106.malformed.wasm` | malformed | 1081 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.107.malformed.wasm` | malformed | 1091 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.108.malformed.wasm` | malformed | 1101 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.109.malformed.wasm` | malformed | 1111 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.110.malformed.wasm` | malformed | 1121 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.111.malformed.wasm` | malformed | 1131 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.112.malformed.wasm` | malformed | 1141 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.113.malformed.wasm` | malformed | 1151 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.114.malformed.wasm` | malformed | 1163 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.115.malformed.wasm` | malformed | 1173 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.116.malformed.wasm` | malformed | 1183 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.117.malformed.wasm` | malformed | 1193 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.118.malformed.wasm` | malformed | 1203 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.119.malformed.wasm` | malformed | 1213 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.120.malformed.wasm` | malformed | 1223 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.121.malformed.wasm` | malformed | 1233 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.122.malformed.wasm` | malformed | 1243 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.123.malformed.wasm` | malformed | 1253 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.124.malformed.wasm` | malformed | 1263 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.125.malformed.wasm` | malformed | 1273 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.126.malformed.wasm` | malformed | 1283 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.127.malformed.wasm` | malformed | 1293 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.128.malformed.wasm` | malformed | 1303 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.129.malformed.wasm` | malformed | 1313 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.130.malformed.wasm` | malformed | 1325 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.131.malformed.wasm` | malformed | 1335 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.132.malformed.wasm` | malformed | 1345 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.133.malformed.wasm` | malformed | 1355 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.134.malformed.wasm` | malformed | 1365 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.135.malformed.wasm` | malformed | 1375 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.136.malformed.wasm` | malformed | 1385 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.137.malformed.wasm` | malformed | 1395 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.138.malformed.wasm` | malformed | 1405 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.139.malformed.wasm` | malformed | 1415 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.140.malformed.wasm` | malformed | 1425 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.141.malformed.wasm` | malformed | 1435 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.142.malformed.wasm` | malformed | 1445 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.143.malformed.wasm` | malformed | 1455 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: .custom.... |
| `utf8-custom-section-id.144.malformed.wasm` | malformed | 1465 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.145.malformed.wasm` | malformed | 1475 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.146.malformed.wasm` | malformed | 1487 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.147.malformed.wasm` | malformed | 1497 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.148.malformed.wasm` | malformed | 1507 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.149.malformed.wasm` | malformed | 1517 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.150.malformed.wasm` | malformed | 1527 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.151.malformed.wasm` | malformed | 1537 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.152.malformed.wasm` | malformed | 1547 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.153.malformed.wasm` | malformed | 1557 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.154.malformed.wasm` | malformed | 1567 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.155.malformed.wasm` | malformed | 1579 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.156.malformed.wasm` | malformed | 1589 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.157.malformed.wasm` | malformed | 1601 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.158.malformed.wasm` | malformed | 1611 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.159.malformed.wasm` | malformed | 1621 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.160.malformed.wasm` | malformed | 1631 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.161.malformed.wasm` | malformed | 1641 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.162.malformed.wasm` | malformed | 1651 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.163.malformed.wasm` | malformed | 1661 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.164.malformed.wasm` | malformed | 1671 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.165.malformed.wasm` | malformed | 1681 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.166.malformed.wasm` | malformed | 1691 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.167.malformed.wasm` | malformed | 1701 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.168.malformed.wasm` | malformed | 1713 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.169.malformed.wasm` | malformed | 1723 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.170.malformed.wasm` | malformed | 1735 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.171.malformed.wasm` | malformed | 1745 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.172.malformed.wasm` | malformed | 1755 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.173.malformed.wasm` | malformed | 1765 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.174.malformed.wasm` | malformed | 1775 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-custom-section-id.175.malformed.wasm` | malformed | 1785 | malformed UTF-8 encoding | accepted-empty | funcs=0 blocks=1 |
| `utf8-import-module.14.malformed.wasm` | malformed | 221 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.18.malformed.wasm` | malformed | 281 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.27.malformed.wasm` | malformed | 420 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.35.malformed.wasm` | malformed | 540 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.39.malformed.wasm` | malformed | 600 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.43.malformed.wasm` | malformed | 660 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.51.malformed.wasm` | malformed | 780 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.55.malformed.wasm` | malformed | 840 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.59.malformed.wasm` | malformed | 902 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.63.malformed.wasm` | malformed | 962 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.67.malformed.wasm` | malformed | 1022 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.71.malformed.wasm` | malformed | 1082 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.75.malformed.wasm` | malformed | 1142 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.79.malformed.wasm` | malformed | 1202 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.90.malformed.wasm` | malformed | 1371 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.98.malformed.wasm` | malformed | 1491 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.102.malformed.wasm` | malformed | 1551 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.106.malformed.wasm` | malformed | 1611 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.115.malformed.wasm` | malformed | 1748 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.119.malformed.wasm` | malformed | 1808 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.123.malformed.wasm` | malformed | 1868 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.127.malformed.wasm` | malformed | 1928 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.131.malformed.wasm` | malformed | 1990 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.135.malformed.wasm` | malformed | 2050 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.139.malformed.wasm` | malformed | 2110 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |
| `utf8-import-module.143.malformed.wasm` | malformed | 2170 | malformed UTF-8 encoding | accepted-partial | java.lang.IllegalArgumentException: Invalid DataType name: import_\... |


## Accepted, then an analyzer raised an exception (4)

- `binary-leb128.54.malformed.wasm` (malformed, line 582): IndexOutOfBounds: ERROR Failed to load Wasm Custom section 1 (WasmLoader) java.lang.IndexOutOfBoundsException: Specified length extends beyond file...
- `binary-leb128.55.malformed.wasm` (malformed, line 593): IllegalStateException: ERROR Failed to load Wasm Custom section 123 (WasmLoader) java.lang.IllegalStateException: New memory block NOT added: would...
- `call_indirect.36.invalid.wasm` (invalid, line 1038): IndexOutOfBounds: ERROR Failed to initialize table 0 with element segment 0 at offset 0 (WasmLoader) java.lang.IndexOutOfBoundsException: Index: 0
- `table.12.invalid.wasm` (invalid, line 23): IllegalStateException: ERROR Failed to create table block 0 at table:00000000 (WasmLoader) java.lang.IllegalStateException: New memory block NOT ad...


## Rejected (59)

- no-loader x16 (`magic header not detected`)
- no-loader x6 (`unexpected end`)
- no-loader x6 (`unknown binary version`)
- loader-exception x6 (`malformed import kind`)
- loader-exception x6 (`unexpected end of section or function`)
- loader-exception x6 (`integer too large`)
- loader-exception x5 (`unexpected end`)
- loader-exception x4 (`length out of bounds`)
- loader-exception x4 (`integer representation too long`)


## Evidence pass (analysis enabled, 250 accepted malformed modules)

| metric | value |
| --- | ---: |
| modules | 250 |
| functions decoded | 63 |
| instructions | 213 |
| modules with undefined bytes | 15 |
| modules with an analyzer exception | 12 |
| modules that crashed the run | 0 |

| module | expected (testsuite) | analyzer exception |
| --- | --- | --- |
| `binary.56.malformed.wasm` | function and code section have incons... | IndexOutOfBounds: ERROR Analysis Task: Wasm Pre-Analyzer - Index: 0 (AnalysisTaskWrapper) java.lang.IndexOu... |
| `binary.58.malformed.wasm` | function and code section have incons... | IndexOutOfBounds: ERROR Analysis Task: Wasm Pre-Analyzer - Index 1 out of bounds for length 1 (AnalysisTask... |
| `binary.115.malformed.wasm` | unexpected content after last section | IndexOutOfBounds: ERROR Analysis Task: Wasm Pre-Analyzer - Index 1 out of bounds for length 1 (AnalysisTask... |
| `binary.131.malformed.wasm` | unexpected content after last section | IndexOutOfBounds: ERROR Analysis Task: Wasm Pre-Analyzer - Index out of range: 0 (AnalysisTaskWrapper) java... |
| `binary.132.malformed.wasm` | unexpected content after last section | IndexOutOfBounds: ERROR Analysis Task: Wasm Pre-Analyzer - Index out of range: 0 (AnalysisTaskWrapper) java... |
| `binary-leb128.40.malformed.wasm` | integer representation too long | EOFException: ERROR Failed to analyze function unnamed_function_0 @ ram:8000001b (WasmPreAnalyzer) java.io.... |
| `binary-leb128.54.malformed.wasm` | integer too large | IndexOutOfBounds: ERROR Failed to load Wasm Custom section 1 (WasmLoader) java.lang.IndexOutOfBoundsExcepti... |
| `binary-leb128.55.malformed.wasm` | integer too large | IllegalStateException: ERROR Failed to load Wasm Custom section 123 (WasmLoader) java.lang.IllegalStateExce... |
| `binary-leb128.65.malformed.wasm` | integer representation too long | EOFException: ERROR Failed to analyze function unnamed_function_0 @ ram:8000001b (WasmPreAnalyzer) java.io.... |
| `binary-leb128.66.malformed.wasm` | integer representation too long | EOFException: ERROR Failed to analyze function unnamed_function_0 @ ram:8000001b (WasmPreAnalyzer) java.io.... |
| `binary-leb128.71.malformed.wasm` | integer representation too long | EOFException: ERROR Failed to analyze function unnamed_function_0 @ ram:8000001b (WasmPreAnalyzer) java.io.... |
| `binary-leb128.72.malformed.wasm` | integer representation too long | EOFException: ERROR Failed to analyze function unnamed_function_0 @ ram:8000001b (WasmPreAnalyzer) java.io.... |


## Hazard pass - modules that kill or wedge the run when analysis is enabled (9)

These are imported one per headless run (`-WithAnalysis`), because a single one can
abort or stall the whole batch. `-noanalysis` imports all of them in well under a
second, so they are invisible in the table above.

| module | expected (testsuite) | outcome | memory bytes | detail |
| --- | --- | --- | ---: | --- |
| `binary-leb128.48.malformed.wasm` | integer too large | hang (headless-hang) | - | headless run timed out (analysis did not finish) |
| `binary-leb128.49.malformed.wasm` | integer too large | hang (headless-hang) | - | headless run timed out (analysis did not finish) |
| `binary.51.malformed.wasm` | integer too large | accepted (accepted-shape) | 0 | funcs=1 blocks=1 module=1 |
| `binary.52.malformed.wasm` | integer too large | accepted (accepted-shape) | 0 | funcs=1 blocks=1 module=1 |
| `binary.53.malformed.wasm` | too many locals | accepted (accepted-shape) | 0 | IllegalArgumentException: ERROR Analysis Task: Wasm Pre-Analyzer - fromIndex(... |
| `binary.54.malformed.wasm` | too many locals | accepted (accepted-shape) | 0 | IndexOutOfBounds: ERROR Analysis Task: Wasm Pre-Analyzer - Array index out of... |
| `memory.21.invalid.wasm` | memory size must be at most 65536... | hang (headless-hang) | - | headless run timed out (analysis did not finish) |
| `memory.22.invalid.wasm` | memory size must be at most 65536... | hang (headless-hang) | - | headless run timed out (analysis did not finish) |
| `memory.23.invalid.wasm` | memory size must be at most 65536... | hang (headless-hang) | - | headless run timed out (analysis did not finish) |

The five `hang` rows are exactly the modules with an out-of-range memory minimum
(`binary-leb128.48/49`, `memory.21/22/23`): imported *without* analysis they report
`memory_bytes=2147483648` - a 2 GiB `.memory0` block, clamped to `CODE_BASE` - and
with analysis the run never finishes. The two rows with an analysis exception are the
absurd-locals modules; the minimal case is the probe `NS07_locals_count_huge` (32
bytes), which OOMs and aborts the headless run instead of hanging.


## Full per-file table

| wast | # | kind | outcome | reason | expected | observed |
| --- | --- | --- | --- | --- | --- | --- |
| align | 69 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 70 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 71 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 72 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 73 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 74 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 75 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 76 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 77 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 78 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 79 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 80 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 81 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 82 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 83 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 84 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 85 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 86 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 87 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 88 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 89 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 90 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 91 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 92 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 93 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 94 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 95 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 96 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 97 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 98 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 99 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 100 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 101 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 102 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 103 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 104 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 105 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| align | 108 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| align | 109 | malformed | accepted | accepted-shape | malformed memop flags | funcs=1 blocks=2 module=1 |
| align | 110 | malformed | accepted | accepted-shape | malformed memop flags | funcs=1 blocks=2 module=1 |
| align | 111 | malformed | accepted | accepted-shape | malformed memop flags | funcs=1 blocks=2 module=1 |
| align | 112 | malformed | accepted | accepted-shape | malformed memop flags | funcs=1 blocks=2 module=1 |
| align | 113 | malformed | accepted | accepted-shape | malformed memop flags | funcs=1 blocks=2 module=1 |
| binary | 4 | malformed | rejected | no-loader | unexpected end | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 5 | malformed | rejected | no-loader | unexpected end | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 6 | malformed | rejected | no-loader | unexpected end | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 7 | malformed | rejected | no-loader | magic header not detected | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 8 | malformed | rejected | no-loader | magic header not detected | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 9 | malformed | rejected | no-loader | magic header not detected | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 10 | malformed | rejected | no-loader | magic header not detected | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 11 | malformed | rejected | no-loader | magic header not detected | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 12 | malformed | rejected | no-loader | magic header not detected | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 13 | malformed | rejected | no-loader | magic header not detected | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 14 | malformed | rejected | no-loader | magic header not detected | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 15 | malformed | rejected | no-loader | magic header not detected | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 16 | malformed | rejected | no-loader | magic header not detected | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 17 | malformed | rejected | no-loader | magic header not detected | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 18 | malformed | rejected | no-loader | magic header not detected | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 19 | malformed | rejected | no-loader | magic header not detected | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 20 | malformed | rejected | no-loader | magic header not detected | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 21 | malformed | rejected | no-loader | magic header not detected | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 22 | malformed | rejected | no-loader | magic header not detected | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 23 | malformed | rejected | no-loader | unexpected end | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 24 | malformed | rejected | no-loader | unexpected end | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 25 | malformed | rejected | no-loader | unexpected end | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 26 | malformed | rejected | no-loader | unknown binary version | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 27 | malformed | rejected | no-loader | unknown binary version | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 28 | malformed | rejected | no-loader | unknown binary version | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 29 | malformed | rejected | no-loader | unknown binary version | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 30 | malformed | rejected | no-loader | unknown binary version | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 31 | malformed | rejected | no-loader | unknown binary version | ERROR The ProgramLoader could not successfully load file:///C:/User... |
| binary | 32 | malformed | accepted | accepted-empty | malformed section id | funcs=0 blocks=1 module=1 |
| binary | 33 | malformed | accepted | accepted-empty | malformed section id | funcs=0 blocks=1 module=1 |
| binary | 34 | malformed | accepted | accepted-empty | malformed section id | funcs=0 blocks=1 module=1 |
| binary | 35 | malformed | accepted | accepted-empty | malformed section id | funcs=0 blocks=1 module=1 |
| binary | 36 | malformed | accepted | accepted-empty | malformed section id | funcs=0 blocks=1 module=1 |
| binary | 37 | malformed | accepted | accepted-shape | END opcode expected | funcs=2 blocks=1 module=1 |
| binary | 38 | malformed | accepted | accepted-shape | unexpected end of section or function | funcs=1 blocks=1 module=1 |
| binary | 39 | malformed | accepted | accepted-shape | section size mismatch | funcs=1 blocks=1 module=1 |
| binary | 40 | malformed | accepted | accepted-shape | illegal opcode | funcs=1 blocks=2 module=1 |
| binary | 41 | malformed | accepted | accepted-shape | zero byte expected | funcs=1 blocks=1 module=1 |
| binary | 42 | malformed | accepted | accepted-shape | zero byte expected | funcs=1 blocks=1 module=1 |
| binary | 43 | malformed | accepted | accepted-shape | zero byte expected | funcs=1 blocks=1 module=1 |
| binary | 44 | malformed | accepted | accepted-shape | zero byte expected | funcs=1 blocks=1 module=1 |
| binary | 45 | malformed | accepted | accepted-shape | zero byte expected | funcs=1 blocks=1 module=1 |
| binary | 46 | malformed | accepted | accepted-shape | zero byte expected | funcs=1 blocks=1 module=1 |
| binary | 47 | malformed | accepted | accepted-shape | zero byte expected | funcs=1 blocks=1 module=1 |
| binary | 48 | malformed | accepted | accepted-shape | zero byte expected | funcs=1 blocks=1 module=1 |
| binary | 49 | malformed | accepted | accepted-shape | zero byte expected | funcs=1 blocks=1 module=1 |
| binary | 50 | malformed | accepted | accepted-shape | zero byte expected | funcs=1 blocks=1 module=1 |
| binary | 51 | malformed | accepted | accepted-shape | integer too large | funcs=1 blocks=1 module=1 |
| binary | 52 | malformed | accepted | accepted-shape | integer too large | funcs=1 blocks=1 module=1 |
| binary | 53 | malformed | accepted | accepted-shape | too many locals | funcs=1 blocks=1 module=1 |
| binary | 54 | malformed | accepted | accepted-shape | too many locals | funcs=1 blocks=1 module=1 |
| binary | 56 | malformed | accepted | accepted-empty | function and code section have incons... | funcs=0 blocks=1 module=1 |
| binary | 57 | malformed | accepted | accepted-shape | function and code section have incons... | funcs=1 blocks=1 module=1 |
| binary | 58 | malformed | accepted | accepted-shape | function and code section have incons... | funcs=1 blocks=1 module=1 |
| binary | 59 | malformed | accepted | accepted-shape | function and code section have incons... | funcs=2 blocks=1 module=1 |
| binary | 62 | malformed | accepted | accepted-empty | data count and data section have inco... | funcs=0 blocks=1 module=1 |
| binary | 63 | malformed | accepted | accepted-empty | data count and data section have inco... | funcs=0 blocks=1 module=1 |
| binary | 64 | malformed | accepted | accepted-shape | data count and data section have inco... | funcs=0 blocks=2 module=1 |
| binary | 66 | malformed | accepted | accepted-shape | data count section required | funcs=1 blocks=1 module=1 |
| binary | 67 | malformed | accepted | accepted-shape | data count section required | funcs=1 blocks=1 module=1 |
| binary | 68 | malformed | accepted | accepted-shape | illegal opcode | funcs=1 blocks=1 module=1 |
| binary | 69 | malformed | accepted | accepted-shape | malformed reference type | funcs=1 blocks=1 module=1 |
| binary | 73 | malformed | rejected | loader-exception | length out of bounds | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary | 74 | malformed | accepted | accepted-empty | section size mismatch | funcs=0 blocks=1 module=1 |
| binary | 76 | malformed | rejected | loader-exception | malformed import kind | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary | 77 | malformed | rejected | loader-exception | malformed import kind | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary | 78 | malformed | rejected | loader-exception | malformed import kind | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary | 79 | malformed | rejected | loader-exception | malformed import kind | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary | 80 | malformed | rejected | loader-exception | malformed import kind | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary | 81 | malformed | rejected | loader-exception | malformed import kind | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary | 82 | malformed | rejected | loader-exception | unexpected end of section or function | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary | 83 | malformed | accepted | accepted-shape | section size mismatch | funcs=1 blocks=2 module=1 |
| binary | 85 | malformed | rejected | loader-exception | unexpected end of section or function | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary | 86 | malformed | rejected | loader-exception | integer too large | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary | 87 | malformed | accepted | accepted-empty | integer too large | funcs=0 blocks=1 module=1 |
| binary | 88 | malformed | accepted | accepted-empty | integer representation too long | funcs=0 blocks=1 module=1 |
| binary | 90 | malformed | rejected | loader-exception | unexpected end of section or function | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary | 91 | malformed | rejected | loader-exception | integer too large | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary | 92 | malformed | accepted | accepted-empty | integer too large | funcs=0 blocks=1 module=1 |
| binary | 93 | malformed | accepted | accepted-empty | integer representation too long | funcs=0 blocks=1 module=1 |
| binary | 94 | malformed | accepted | accepted-shape | integer representation too long | funcs=0 blocks=2 module=1 |
| binary | 96 | malformed | rejected | loader-exception | unexpected end of section or function | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary | 97 | malformed | accepted | accepted-shape | section size mismatch | funcs=0 blocks=2 module=1 |
| binary | 99 | malformed | rejected | loader-exception | length out of bounds | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary | 100 | malformed | accepted | accepted-shape | section size mismatch | funcs=2 blocks=1 module=1 |
| binary | 102 | malformed | rejected | loader-exception | unexpected end | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary | 103 | malformed | rejected | loader-exception | unexpected end | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary | 104 | malformed | accepted | accepted-shape | section size mismatch | funcs=1 blocks=2 module=1 |
| binary | 106 | malformed | rejected | loader-exception | unexpected end of section or function | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary | 107 | malformed | accepted | accepted-shape | section size mismatch | funcs=0 blocks=2 module=1 |
| binary | 108 | malformed | rejected | loader-exception | unexpected end of section or function | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary | 109 | malformed | accepted | accepted-shape | section size mismatch | funcs=0 blocks=2 module=1 |
| binary | 111 | malformed | accepted | accepted-shape | unexpected end | funcs=1 blocks=1 module=1 |
| binary | 113 | malformed | accepted | accepted-shape | unexpected content after last section | funcs=1 blocks=1 module=1 |
| binary | 114 | malformed | accepted | accepted-shape | unexpected content after last section | funcs=2 blocks=1 module=1 |
| binary | 115 | malformed | accepted | accepted-shape | unexpected content after last section | funcs=1 blocks=1 module=1 |
| binary | 116 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 117 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 118 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 119 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 120 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 121 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 122 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 123 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 124 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 125 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 126 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 127 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 128 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 129 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 130 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 131 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 132 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 133 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 134 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary | 135 | malformed | accepted | accepted-empty | unexpected content after last section | funcs=0 blocks=1 module=1 |
| binary-leb128 | 25 | malformed | accepted | accepted-shape | integer representation too long | funcs=0 blocks=2 module=1 |
| binary-leb128 | 26 | malformed | accepted | accepted-shape | integer representation too long | funcs=0 blocks=2 module=1 |
| binary-leb128 | 27 | malformed | accepted | accepted-empty | integer representation too long | funcs=0 blocks=1 module=1 |
| binary-leb128 | 28 | malformed | accepted | accepted-empty | integer representation too long | funcs=0 blocks=1 module=1 |
| binary-leb128 | 29 | malformed | accepted | accepted-shape | integer representation too long | funcs=0 blocks=2 module=1 |
| binary-leb128 | 30 | malformed | accepted | accepted-shape | integer representation too long | funcs=0 blocks=2 module=1 |
| binary-leb128 | 31 | malformed | accepted | accepted-empty | integer representation too long | funcs=0 blocks=1 module=1 |
| binary-leb128 | 32 | malformed | accepted | accepted-empty | integer representation too long | funcs=0 blocks=1 module=1 |
| binary-leb128 | 33 | malformed | accepted | accepted-shape | integer representation too long | funcs=1 blocks=2 module=1 |
| binary-leb128 | 34 | malformed | accepted | accepted-shape | integer representation too long | funcs=1 blocks=2 module=1 |
| binary-leb128 | 35 | malformed | accepted | accepted-shape | integer representation too long | funcs=1 blocks=2 module=1 |
| binary-leb128 | 36 | malformed | accepted | accepted-shape | integer representation too long | funcs=1 blocks=1 module=1 |
| binary-leb128 | 37 | malformed | accepted | accepted-shape | integer representation too long | funcs=1 blocks=1 module=1 |
| binary-leb128 | 38 | malformed | accepted | accepted-shape | integer representation too long | funcs=1 blocks=1 module=1 |
| binary-leb128 | 39 | malformed | accepted | accepted-shape | integer representation too long | funcs=1 blocks=2 module=1 |
| binary-leb128 | 40 | malformed | accepted | accepted-shape | integer representation too long | funcs=1 blocks=2 module=1 |
| binary-leb128 | 41 | malformed | accepted | accepted-shape | integer representation too long | funcs=1 blocks=2 module=1 |
| binary-leb128 | 42 | malformed | accepted | accepted-shape | integer representation too long | funcs=1 blocks=2 module=1 |
| binary-leb128 | 43 | malformed | rejected | loader-exception | integer representation too long | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary-leb128 | 44 | malformed | accepted | accepted-shape | integer representation too long | funcs=0 blocks=2 module=1 |
| binary-leb128 | 45 | malformed | accepted | accepted-shape | integer representation too long | funcs=0 blocks=2 module=1 |
| binary-leb128 | 46 | malformed | rejected | loader-exception | integer representation too long | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary-leb128 | 47 | malformed | rejected | loader-exception | integer representation too long | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary-leb128 | 48 | malformed | accepted | accepted-shape | integer too large | funcs=0 blocks=2 module=1 |
| binary-leb128 | 49 | malformed | accepted | accepted-shape | integer too large | funcs=0 blocks=2 module=1 |
| binary-leb128 | 50 | malformed | accepted | accepted-shape | integer too large | funcs=0 blocks=2 module=1 |
| binary-leb128 | 51 | malformed | accepted | accepted-shape | integer too large | funcs=0 blocks=2 module=1 |
| binary-leb128 | 52 | malformed | rejected | loader-exception | integer too large | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary-leb128 | 53 | malformed | accepted | accepted-empty | integer too large | funcs=0 blocks=1 module=1 |
| binary-leb128 | 54 | malformed | accepted | accepted-empty | integer too large | IndexOutOfBounds: ERROR Failed to load Wasm Custom section 1 (WasmL... |
| binary-leb128 | 55 | malformed | accepted | accepted-empty | integer too large | IllegalStateException: ERROR Failed to load Wasm Custom section 123... |
| binary-leb128 | 56 | malformed | rejected | loader-exception | integer too large | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary-leb128 | 57 | malformed | rejected | loader-exception | integer too large | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary-leb128 | 58 | malformed | accepted | accepted-shape | integer too large | funcs=1 blocks=2 module=1 |
| binary-leb128 | 59 | malformed | accepted | accepted-shape | integer too large | funcs=1 blocks=2 module=1 |
| binary-leb128 | 60 | malformed | accepted | accepted-shape | integer too large | funcs=1 blocks=2 module=1 |
| binary-leb128 | 61 | malformed | accepted | accepted-shape | integer too large | funcs=1 blocks=1 module=1 |
| binary-leb128 | 62 | malformed | accepted | accepted-shape | integer too large | funcs=1 blocks=1 module=1 |
| binary-leb128 | 63 | malformed | accepted | accepted-shape | integer too large | funcs=1 blocks=1 module=1 |
| binary-leb128 | 64 | malformed | rejected | loader-exception | integer too large | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| binary-leb128 | 65 | malformed | accepted | accepted-shape | integer representation too long | funcs=1 blocks=2 module=1 |
| binary-leb128 | 66 | malformed | accepted | accepted-shape | integer representation too long | funcs=1 blocks=2 module=1 |
| binary-leb128 | 67 | malformed | accepted | accepted-shape | integer too large | funcs=1 blocks=2 module=1 |
| binary-leb128 | 68 | malformed | accepted | accepted-shape | integer too large | funcs=1 blocks=2 module=1 |
| binary-leb128 | 69 | malformed | accepted | accepted-shape | integer too large | funcs=1 blocks=2 module=1 |
| binary-leb128 | 70 | malformed | accepted | accepted-shape | integer too large | funcs=1 blocks=2 module=1 |
| binary-leb128 | 71 | malformed | accepted | accepted-shape | integer representation too long | funcs=1 blocks=2 module=1 |
| binary-leb128 | 72 | malformed | accepted | accepted-shape | integer representation too long | funcs=1 blocks=2 module=1 |
| binary-leb128 | 73 | malformed | accepted | accepted-shape | integer too large | funcs=0 blocks=2 module=1 |
| binary-leb128 | 74 | malformed | accepted | accepted-shape | integer too large | funcs=0 blocks=2 module=1 |
| binary-leb128 | 75 | malformed | accepted | accepted-shape | integer too large | funcs=0 blocks=2 module=1 |
| binary-leb128 | 76 | malformed | accepted | accepted-shape | integer too large | funcs=0 blocks=2 module=1 |
| binary-leb128 | 77 | malformed | accepted | accepted-shape | integer too large | funcs=0 blocks=2 module=1 |
| binary-leb128 | 78 | malformed | accepted | accepted-shape | integer too large | funcs=0 blocks=2 module=1 |
| binary-leb128 | 79 | malformed | accepted | accepted-shape | integer too large | funcs=0 blocks=2 module=1 |
| binary-leb128 | 80 | malformed | accepted | accepted-shape | integer too large | funcs=0 blocks=2 module=1 |
| binary-leb128 | 82 | malformed | accepted | accepted-shape | integer representation too long | funcs=1 blocks=1 module=1 |
| binary-leb128 | 90 | malformed | rejected | loader-exception | integer representation too long | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| block | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 30 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 31 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 32 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 33 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 34 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 35 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 36 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 37 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 38 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 39 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 40 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 41 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 42 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 43 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 44 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 45 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 46 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 47 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 48 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 49 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 50 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 51 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 52 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 53 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 54 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 55 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 56 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 57 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 58 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 59 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 60 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 61 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 62 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 63 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 64 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 65 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 66 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 67 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 68 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 69 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 70 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 71 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 72 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 73 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 74 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 75 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 76 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 77 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 78 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 79 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 80 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 81 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 82 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 83 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 84 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 85 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 86 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 87 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 88 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 89 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 90 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 91 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 92 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 93 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 94 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 95 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 96 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 97 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 98 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 99 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 100 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 101 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 102 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 103 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 104 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 105 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 106 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 107 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 108 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 109 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 110 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 111 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 112 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 113 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 114 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 115 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 116 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 117 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 118 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 119 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 120 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 121 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 122 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 123 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 124 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 125 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 126 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 127 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 128 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 129 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 130 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 131 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 132 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 133 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 134 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 135 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 136 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 137 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 138 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 139 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 140 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 141 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 142 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 143 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 144 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 145 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 146 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 147 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 148 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 149 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 150 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 151 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 152 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 153 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 154 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 155 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 156 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 157 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 158 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 159 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 160 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 161 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 162 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 163 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 164 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 165 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| block | 166 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| br | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| br | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| br | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| br | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| br | 18 | invalid | accepted | accepted-shape | unknown label | funcs=1 blocks=1 module=1 |
| br | 19 | invalid | accepted | accepted-shape | unknown label | funcs=1 blocks=1 module=1 |
| br | 20 | invalid | accepted | accepted-shape | unknown label | funcs=1 blocks=1 module=1 |
| br_if | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_if | 27 | invalid | accepted | accepted-shape | unknown label | funcs=1 blocks=1 module=1 |
| br_if | 28 | invalid | accepted | accepted-shape | unknown label | funcs=1 blocks=1 module=1 |
| br_if | 29 | invalid | accepted | accepted-shape | unknown label | funcs=1 blocks=1 module=1 |
| br_table | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_table | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_table | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_table | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_table | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_table | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_table | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_table | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_table | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_table | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_table | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_table | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_table | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_table | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_table | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_table | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_table | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_table | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| br_table | 19 | invalid | accepted | accepted-shape | unknown label | funcs=1 blocks=1 module=1 |
| br_table | 20 | invalid | accepted | accepted-shape | unknown label | funcs=1 blocks=1 module=1 |
| br_table | 21 | invalid | accepted | accepted-shape | unknown label | funcs=1 blocks=1 module=1 |
| br_table | 22 | invalid | accepted | accepted-shape | unknown label | funcs=1 blocks=1 module=1 |
| br_table | 23 | invalid | accepted | accepted-shape | unknown label | funcs=1 blocks=1 module=1 |
| br_table | 24 | invalid | accepted | accepted-shape | unknown label | funcs=1 blocks=1 module=1 |
| call | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| call | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| call | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| call | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| call | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| call | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| call | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| call | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| call | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| call | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| call | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| call | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| call | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| call | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| call | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| call | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| call | 17 | invalid | accepted | accepted-shape | unknown function | funcs=1 blocks=1 module=1 |
| call | 18 | invalid | accepted | accepted-shape | unknown function | funcs=1 blocks=1 module=1 |
| call_indirect | 13 | invalid | accepted | accepted-shape | unknown table | funcs=1 blocks=1 module=1 |
| call_indirect | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| call_indirect | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| call_indirect | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| call_indirect | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| call_indirect | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| call_indirect | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| call_indirect | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| call_indirect | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| call_indirect | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| call_indirect | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| call_indirect | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| call_indirect | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| call_indirect | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| call_indirect | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| call_indirect | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| call_indirect | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| call_indirect | 30 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| call_indirect | 31 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| call_indirect | 32 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| call_indirect | 33 | invalid | accepted | accepted-shape | unknown type | funcs=1 blocks=1 module=1 |
| call_indirect | 34 | invalid | accepted | accepted-shape | unknown type | funcs=1 blocks=1 module=1 |
| call_indirect | 35 | invalid | accepted | accepted-shape | unknown type | funcs=1 blocks=2 module=1 |
| call_indirect | 36 | invalid | accepted | accepted-shape | unknown function | IndexOutOfBounds: ERROR Failed to initialize table 0 with element s... |
| conversions | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| conversions | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| custom | 3 | malformed | rejected | loader-exception | unexpected end | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| custom | 4 | malformed | rejected | loader-exception | unexpected end | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| custom | 5 | malformed | rejected | loader-exception | unexpected end | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| custom | 6 | malformed | rejected | loader-exception | length out of bounds | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| custom | 7 | malformed | accepted | accepted-shape | malformed section id | funcs=0 blocks=2 module=1 |
| custom | 8 | malformed | accepted | accepted-shape | function and code section have incons... | funcs=1 blocks=3 module=1 |
| custom | 9 | malformed | rejected | loader-exception | length out of bounds | ERROR REPORT: Error: No memory blocks were defined for file file://... |
| custom | 10 | malformed | accepted | accepted-shape | data count and data section have inco... | funcs=0 blocks=2 module=1 |
| data | 9 | invalid | accepted | accepted-shape | unknown global | funcs=0 blocks=3 module=1 |
| data | 10 | invalid | accepted | accepted-shape | unknown global | funcs=0 blocks=3 module=1 |
| data | 41 | invalid | accepted | accepted-empty | unknown memory | funcs=0 blocks=1 module=1 |
| data | 42 | invalid | accepted | accepted-empty | unknown memory 1 | funcs=0 blocks=1 module=1 |
| data | 43 | invalid | accepted | accepted-empty | unknown memory 0 | funcs=0 blocks=1 module=1 |
| data | 44 | invalid | accepted | accepted-empty | unknown memory 1 | funcs=0 blocks=1 module=1 |
| data | 45 | invalid | accepted | accepted-empty | unknown memory 1 | funcs=0 blocks=1 module=1 |
| data | 46 | invalid | accepted | accepted-empty | unknown memory 1 | funcs=0 blocks=1 module=1 |
| data | 47 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=2 module=1 |
| data | 48 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=2 module=1 |
| data | 49 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=2 module=1 |
| data | 50 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=2 module=1 |
| data | 51 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=3 module=1 |
| data | 52 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=3 module=1 |
| data | 53 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=2 module=1 |
| data | 54 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=2 module=1 |
| data | 55 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=2 module=1 |
| data | 56 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=2 module=1 |
| data | 57 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=3 module=1 |
| data | 58 | invalid | accepted | accepted-shape | unknown global 0 | funcs=0 blocks=2 module=1 |
| data | 59 | invalid | accepted | accepted-shape | unknown global 1 | funcs=0 blocks=3 module=1 |
| data | 60 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=3 module=1 |
| elem | 10 | invalid | accepted | accepted-shape | unknown global | funcs=1 blocks=3 module=1 |
| elem | 11 | invalid | accepted | accepted-shape | unknown global | funcs=1 blocks=3 module=1 |
| elem | 36 | invalid | accepted | accepted-shape | unknown table | funcs=1 blocks=1 module=1 |
| elem | 37 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=2 module=1 |
| elem | 38 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=2 module=1 |
| elem | 39 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=2 module=1 |
| elem | 40 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=2 module=1 |
| elem | 41 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=3 module=1 |
| elem | 42 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=3 module=1 |
| elem | 43 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=2 module=1 |
| elem | 44 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=2 module=1 |
| elem | 45 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=2 module=1 |
| elem | 46 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=2 module=1 |
| elem | 47 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=3 module=1 |
| elem | 48 | invalid | accepted | accepted-shape | unknown global 0 | funcs=0 blocks=2 module=1 |
| elem | 49 | invalid | accepted | accepted-shape | unknown global 1 | funcs=0 blocks=3 module=1 |
| elem | 50 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=3 module=1 |
| elem | 51 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=2 module=1 |
| elem | 52 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=2 module=1 |
| elem | 53 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=2 module=1 |
| elem | 54 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=2 module=1 |
| elem | 55 | invalid | accepted | accepted-shape | constant expression required | funcs=1 blocks=2 module=1 |
| elem | 61 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| elem | 62 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=2 module=1 |
| elem | 63 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| elem | 64 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| exports | 15 | invalid | accepted | accepted-empty | unknown function | funcs=0 blocks=1 module=1 |
| exports | 16 | invalid | accepted | accepted-shape | unknown function | funcs=1 blocks=1 module=1 |
| exports | 17 | invalid | accepted | accepted-shape | unknown function | funcs=1 blocks=2 module=1 |
| exports | 18 | invalid | accepted | accepted-shape | duplicate export name | funcs=1 blocks=1 module=1 |
| exports | 19 | invalid | accepted | accepted-shape | duplicate export name | funcs=2 blocks=1 module=1 |
| exports | 20 | invalid | accepted | accepted-shape | duplicate export name | funcs=1 blocks=2 module=1 |
| exports | 21 | invalid | accepted | accepted-shape | duplicate export name | funcs=1 blocks=1 module=1 |
| exports | 22 | invalid | accepted | accepted-shape | duplicate export name | funcs=1 blocks=1 module=1 |
| exports | 35 | invalid | accepted | accepted-empty | unknown global | funcs=0 blocks=1 module=1 |
| exports | 36 | invalid | accepted | accepted-shape | unknown global | funcs=0 blocks=2 module=1 |
| exports | 37 | invalid | accepted | accepted-shape | unknown global | funcs=0 blocks=2 module=1 |
| exports | 38 | invalid | accepted | accepted-shape | duplicate export name | funcs=0 blocks=2 module=1 |
| exports | 39 | invalid | accepted | accepted-shape | duplicate export name | funcs=0 blocks=3 module=1 |
| exports | 40 | invalid | accepted | accepted-shape | duplicate export name | funcs=1 blocks=2 module=1 |
| exports | 41 | invalid | accepted | accepted-shape | duplicate export name | funcs=0 blocks=2 module=1 |
| exports | 42 | invalid | accepted | accepted-shape | duplicate export name | funcs=0 blocks=2 module=1 |
| exports | 58 | invalid | accepted | accepted-empty | unknown table | funcs=0 blocks=1 module=1 |
| exports | 59 | invalid | accepted | accepted-empty | unknown table | funcs=0 blocks=1 module=1 |
| exports | 60 | invalid | accepted | accepted-shape | unknown table | funcs=0 blocks=2 module=1 |
| exports | 61 | invalid | accepted | accepted-empty | duplicate export name | funcs=0 blocks=1 module=1 |
| exports | 62 | invalid | accepted | accepted-empty | duplicate export name | funcs=0 blocks=1 module=1 |
| exports | 63 | invalid | accepted | accepted-shape | duplicate export name | funcs=1 blocks=1 module=1 |
| exports | 64 | invalid | accepted | accepted-shape | duplicate export name | funcs=0 blocks=2 module=1 |
| exports | 65 | invalid | accepted | accepted-empty | duplicate export name | funcs=0 blocks=1 module=1 |
| exports | 80 | invalid | accepted | accepted-empty | unknown memory | funcs=0 blocks=1 module=1 |
| exports | 81 | invalid | accepted | accepted-empty | unknown memory | funcs=0 blocks=1 module=1 |
| exports | 82 | invalid | accepted | accepted-shape | unknown memory | funcs=0 blocks=2 module=1 |
| exports | 83 | invalid | accepted | accepted-empty | duplicate export name | funcs=0 blocks=1 module=1 |
| exports | 84 | invalid | accepted | accepted-shape | duplicate export name | funcs=1 blocks=1 module=1 |
| exports | 85 | invalid | accepted | accepted-shape | duplicate export name | funcs=0 blocks=2 module=1 |
| exports | 86 | invalid | accepted | accepted-empty | duplicate export name | funcs=0 blocks=1 module=1 |
| f32 | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32 | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32 | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32 | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32 | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32 | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32 | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32 | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32 | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32 | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32 | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32_bitwise | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32_bitwise | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32_bitwise | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32_cmp | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32_cmp | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32_cmp | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32_cmp | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32_cmp | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f32_cmp | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64 | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64 | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64 | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64 | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64 | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64 | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64 | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64 | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64 | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64 | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64 | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64_bitwise | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64_bitwise | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64_bitwise | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64_cmp | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64_cmp | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64_cmp | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64_cmp | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64_cmp | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| f64_cmp | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 2 | invalid | accepted | accepted-shape | unknown type | funcs=4 blocks=1 module=1 |
| func | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 30 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 31 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 32 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 33 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 34 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 35 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 36 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 37 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 38 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 39 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 40 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 41 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 42 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 43 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 44 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 45 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 46 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 47 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 48 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 49 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 50 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 51 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 52 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 53 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 54 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 55 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 56 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 57 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 58 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 59 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 60 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 61 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 62 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func | 63 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| func_ptrs | 1 | invalid | accepted | accepted-empty | unknown table | funcs=0 blocks=1 module=1 |
| func_ptrs | 2 | invalid | accepted | accepted-shape | unknown table | funcs=1 blocks=1 module=1 |
| func_ptrs | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=2 module=1 |
| func_ptrs | 4 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=2 module=1 |
| func_ptrs | 5 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=2 module=1 |
| func_ptrs | 6 | invalid | accepted | accepted-shape | unknown type | funcs=1 blocks=1 module=1 |
| func_ptrs | 7 | invalid | accepted | accepted-shape | unknown type | funcs=1 blocks=2 module=1 |
| global | 1 | invalid | accepted | accepted-shape | global is immutable | funcs=1 blocks=2 module=1 |
| global | 2 | invalid | accepted | accepted-shape | global is immutable | funcs=1 blocks=2 module=1 |
| global | 5 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=2 module=1 |
| global | 6 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=2 module=1 |
| global | 7 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=2 module=1 |
| global | 8 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=2 module=1 |
| global | 9 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=2 module=1 |
| global | 10 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=2 module=1 |
| global | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=2 module=1 |
| global | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=2 module=1 |
| global | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=2 module=1 |
| global | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=3 module=1 |
| global | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=3 module=1 |
| global | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=0 blocks=3 module=1 |
| global | 17 | invalid | accepted | accepted-shape | unknown global | funcs=0 blocks=2 module=1 |
| global | 18 | invalid | accepted | accepted-shape | unknown global | funcs=0 blocks=3 module=1 |
| global | 19 | invalid | accepted | accepted-shape | unknown global | funcs=0 blocks=3 module=1 |
| global | 20 | invalid | accepted | accepted-shape | unknown global | funcs=0 blocks=3 module=1 |
| global | 21 | invalid | accepted | accepted-shape | unknown global | funcs=0 blocks=3 module=1 |
| global | 22 | invalid | accepted | accepted-shape | constant expression required | funcs=0 blocks=3 module=1 |
| global | 24 | malformed | accepted | accepted-shape | malformed mutability | funcs=0 blocks=2 module=1 |
| global | 25 | malformed | accepted | accepted-shape | malformed mutability | funcs=0 blocks=2 module=1 |
| global | 27 | malformed | accepted | accepted-shape | malformed mutability | funcs=0 blocks=2 module=1 |
| global | 28 | malformed | accepted | accepted-shape | malformed mutability | funcs=0 blocks=2 module=1 |
| global | 29 | invalid | accepted | accepted-shape | unknown global | funcs=1 blocks=1 module=1 |
| global | 30 | invalid | accepted | accepted-shape | unknown global | funcs=1 blocks=2 module=1 |
| global | 31 | invalid | accepted | accepted-shape | unknown global | funcs=1 blocks=2 module=1 |
| global | 32 | invalid | accepted | accepted-shape | unknown global | funcs=1 blocks=3 module=1 |
| global | 33 | invalid | accepted | accepted-shape | unknown global | funcs=1 blocks=1 module=1 |
| global | 34 | invalid | accepted | accepted-shape | unknown global | funcs=1 blocks=2 module=1 |
| global | 35 | invalid | accepted | accepted-shape | unknown global | funcs=1 blocks=2 module=1 |
| global | 36 | invalid | accepted | accepted-shape | unknown global | funcs=1 blocks=3 module=1 |
| global | 37 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| global | 38 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| global | 39 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| global | 40 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| global | 41 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| global | 42 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| global | 43 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| global | 44 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| global | 45 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| global | 46 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| global | 47 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| global | 48 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=3 module=1 |
| i32 | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| i32 | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| i32 | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| i32 | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| i32 | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 30 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 31 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 32 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 33 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 34 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 35 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 36 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 37 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 38 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 39 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| i32 | 40 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| i32 | 41 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| i32 | 42 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| i32 | 43 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 44 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 45 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 46 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 47 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| i32 | 48 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| i32 | 49 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 50 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 51 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 52 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 53 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| i32 | 54 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| i32 | 55 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 56 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 57 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 58 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 59 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 60 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 61 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 62 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 63 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 64 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 65 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 66 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 67 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 68 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 69 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 70 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 71 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 72 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 73 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 74 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 75 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 76 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 77 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 78 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 79 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 80 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 81 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 82 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i32 | 83 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| i64 | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 30 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 31 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 32 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 33 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 34 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 35 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 36 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 37 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 38 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 39 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 40 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 41 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 42 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 43 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 44 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 45 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 46 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 47 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 48 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 49 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 50 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 51 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 52 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 53 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 54 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 55 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 56 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 57 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 58 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 59 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 60 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 61 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 62 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 63 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 64 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 65 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 66 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 67 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 68 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 69 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 70 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 71 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 72 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 73 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 74 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 75 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 76 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 77 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 78 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 79 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 80 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 81 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 82 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 83 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 84 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 85 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 86 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 87 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 88 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| if | 89 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| if | 90 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 91 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 92 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| if | 93 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 94 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 95 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| if | 96 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 97 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 98 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 99 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 100 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 101 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 102 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| if | 103 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| imports | 2 | invalid | accepted | accepted-shape | unknown type | funcs=1 blocks=2 module=1 |
| imports | 12 | unlinkable | accepted | accepted-shape | unknown import | funcs=1 blocks=2 module=1 |
| imports | 13 | unlinkable | accepted | accepted-shape | unknown import | funcs=1 blocks=2 module=1 |
| imports | 14 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 15 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 16 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 17 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 18 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 19 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 20 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 21 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 22 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 23 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 24 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 25 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 26 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 27 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 28 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 29 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 30 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 31 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 32 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 33 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 34 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 35 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| imports | 40 | unlinkable | accepted | accepted-shape | unknown import | funcs=0 blocks=2 module=1 |
| imports | 41 | unlinkable | accepted | accepted-shape | unknown import | funcs=0 blocks=2 module=1 |
| imports | 42 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 43 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 44 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 45 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 46 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 47 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 48 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 49 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 50 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 51 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 52 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 53 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 54 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 55 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 56 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 57 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 58 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 59 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 83 | unlinkable | accepted | accepted-shape | unknown import | funcs=0 blocks=2 module=1 |
| imports | 84 | unlinkable | accepted | accepted-shape | unknown import | funcs=0 blocks=2 module=1 |
| imports | 85 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 86 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 87 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 88 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 89 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 90 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 91 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 92 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 93 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 94 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 97 | invalid | accepted | accepted-shape | multiple memories | funcs=0 blocks=2 module=1 |
| imports | 98 | invalid | accepted | accepted-shape | multiple memories | funcs=0 blocks=2 module=1 |
| imports | 99 | invalid | accepted | accepted-empty | multiple memories | funcs=0 blocks=1 module=1 |
| imports | 109 | unlinkable | accepted | accepted-shape | unknown import | funcs=0 blocks=2 module=1 |
| imports | 110 | unlinkable | accepted | accepted-shape | unknown import | funcs=0 blocks=2 module=1 |
| imports | 111 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 112 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 113 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 114 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 115 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 116 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 117 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 118 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 119 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 120 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 121 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 122 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| imports | 141 | unlinkable | accepted | accepted-shape | unknown import | funcs=10 blocks=6 module=1 |
| labels | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| labels | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| labels | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| linking | 3 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| linking | 4 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=1 blocks=2 module=1 |
| linking | 7 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| linking | 8 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| linking | 11 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| linking | 12 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| linking | 13 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| linking | 14 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| linking | 22 | unlinkable | accepted | accepted-shape | unknown import | funcs=1 blocks=3 module=1 |
| linking | 27 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| linking | 28 | unlinkable | accepted | accepted-shape | incompatible import type | funcs=0 blocks=2 module=1 |
| linking | 35 | unlinkable | accepted | accepted-shape | unknown import | funcs=1 blocks=3 module=1 |
| load | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 30 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 31 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 32 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 33 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 34 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 35 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 36 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 37 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 38 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 39 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 40 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 41 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 42 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| load | 43 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| load | 44 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| load | 45 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| load | 46 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| load | 47 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| load | 48 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| load | 49 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| load | 50 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| load | 51 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| load | 52 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| load | 53 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| load | 54 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| load | 55 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| load | 56 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| load | 57 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| load | 58 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| load | 59 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| local_get | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_get | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_get | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_get | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_get | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_get | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_get | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_get | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_get | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_get | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_get | 11 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| local_get | 12 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| local_get | 13 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| local_get | 14 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| local_get | 15 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| local_get | 16 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| local_set | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| local_set | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| local_set | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_set | 28 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| local_set | 29 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| local_set | 30 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| local_set | 31 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| local_set | 32 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| local_set | 33 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| local_tee | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| local_tee | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| local_tee | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| local_tee | 30 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 31 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 32 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| local_tee | 33 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 34 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 35 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| local_tee | 36 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| local_tee | 37 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| local_tee | 38 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| local_tee | 39 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| local_tee | 40 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| local_tee | 41 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| loop | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 30 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 31 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 32 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 33 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 34 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 35 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 36 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 37 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| loop | 38 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| memory | 6 | invalid | accepted | accepted-empty | multiple memories | funcs=0 blocks=1 module=1 |
| memory | 7 | invalid | accepted | accepted-empty | multiple memories | funcs=0 blocks=1 module=1 |
| memory | 11 | invalid | accepted | accepted-empty | unknown memory | funcs=0 blocks=1 module=1 |
| memory | 12 | invalid | accepted | accepted-empty | unknown memory | funcs=0 blocks=1 module=1 |
| memory | 13 | invalid | accepted | accepted-empty | unknown memory | funcs=0 blocks=1 module=1 |
| memory | 14 | invalid | accepted | accepted-shape | unknown memory | funcs=1 blocks=1 module=1 |
| memory | 15 | invalid | accepted | accepted-shape | unknown memory | funcs=1 blocks=1 module=1 |
| memory | 16 | invalid | accepted | accepted-shape | unknown memory | funcs=1 blocks=1 module=1 |
| memory | 17 | invalid | accepted | accepted-shape | unknown memory | funcs=1 blocks=1 module=1 |
| memory | 18 | invalid | accepted | accepted-shape | unknown memory | funcs=1 blocks=1 module=1 |
| memory | 19 | invalid | accepted | accepted-shape | unknown memory | funcs=1 blocks=1 module=1 |
| memory | 20 | invalid | accepted | accepted-shape | size minimum must not be greater than... | funcs=0 blocks=2 module=1 |
| memory | 21 | invalid | accepted | accepted-shape | memory size must be at most 65536 pag... | funcs=0 blocks=2 module=1 |
| memory | 22 | invalid | accepted | accepted-shape | memory size must be at most 65536 pag... | funcs=0 blocks=2 module=1 |
| memory | 23 | invalid | accepted | accepted-shape | memory size must be at most 65536 pag... | funcs=0 blocks=2 module=1 |
| memory | 24 | invalid | accepted | accepted-empty | memory size must be at most 65536 pag... | funcs=0 blocks=1 module=1 |
| memory | 25 | invalid | accepted | accepted-empty | memory size must be at most 65536 pag... | funcs=0 blocks=1 module=1 |
| memory | 26 | invalid | accepted | accepted-empty | memory size must be at most 65536 pag... | funcs=0 blocks=1 module=1 |
| memory_copy | 19 | invalid | accepted | accepted-shape | unknown memory 0 | funcs=1 blocks=1 module=1 |
| memory_copy | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 30 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 31 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 32 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 33 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 34 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 35 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 36 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 37 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 38 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 39 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 40 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 41 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 42 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 43 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 44 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 45 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 46 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 47 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 48 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 49 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 50 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 51 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 52 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 53 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 54 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 55 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 56 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 57 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 58 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 59 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 60 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 61 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 62 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 63 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 64 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 65 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 66 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 67 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 68 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 69 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 70 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 71 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 72 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 73 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 74 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 75 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 76 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 77 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 78 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 79 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 80 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 81 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_copy | 82 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 8 | invalid | accepted | accepted-shape | unknown memory 0 | funcs=1 blocks=1 module=1 |
| memory_fill | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 30 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 31 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 32 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 33 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 34 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 35 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 36 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 37 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 38 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 39 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 40 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 41 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 42 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 43 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 44 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 45 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 46 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 47 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 48 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 49 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 50 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 51 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 52 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 53 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 54 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 55 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 56 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 57 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 58 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 59 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 60 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 61 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 62 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 63 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 64 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 65 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 66 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 67 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 68 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 69 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 70 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_fill | 71 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_grow | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| memory_grow | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| memory_grow | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| memory_grow | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| memory_grow | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_grow | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_grow | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 4 | invalid | accepted | accepted-shape | unknown data segment | funcs=1 blocks=1 module=1 |
| memory_init | 5 | invalid | accepted | accepted-shape | unknown data segment | funcs=1 blocks=2 module=1 |
| memory_init | 9 | invalid | accepted | accepted-shape | unknown memory 0 | funcs=1 blocks=1 module=1 |
| memory_init | 10 | invalid | accepted | accepted-shape | unknown data segment 1 | funcs=1 blocks=2 module=1 |
| memory_init | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 30 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 31 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 32 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 33 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 34 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 35 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 36 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 37 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 38 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 39 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 40 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 41 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 42 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 43 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 44 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 45 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 46 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 47 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 48 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 49 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 50 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 51 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 52 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 53 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 54 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 55 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 56 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 57 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 58 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 59 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 60 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 61 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 62 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 63 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 64 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 65 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 66 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 67 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 68 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 69 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 70 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 71 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 72 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 73 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 74 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 75 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 76 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 77 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 78 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 79 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 80 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 81 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 82 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_init | 83 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_size | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| memory_size | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| nop | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| nop | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| nop | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| nop | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| ref_func | 2 | invalid | accepted | accepted-partial | unknown function 7 | loader: java.lang.IndexOutOfBoundsException: Index: 5 |
| ref_func | 4 | invalid | accepted | accepted-shape | undeclared function reference | funcs=1 blocks=1 module=1 |
| ref_func | 5 | invalid | accepted | accepted-shape | undeclared function reference | funcs=1 blocks=1 module=1 |
| ref_is_null | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| ref_is_null | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| return | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| return | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| return | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| return | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| return | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| return | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| return | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| return | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| return | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| return | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| return | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=1 module=1 |
| return | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| return | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| return | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| return | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| return | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| return | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| return | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| return | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| return | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 2 | invalid | accepted | accepted-shape | invalid result arity | funcs=1 blocks=1 module=1 |
| select | 3 | invalid | accepted | accepted-shape | invalid result arity | funcs=1 blocks=1 module=1 |
| select | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| select | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_align | 44 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| simd_align | 45 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=1 module=1 |
| simd_align | 46 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| simd_align | 47 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| simd_align | 48 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| simd_align | 49 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| simd_align | 50 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| simd_align | 51 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| simd_align | 52 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| simd_align | 53 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| simd_align | 54 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| simd_align | 55 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| simd_bit_shift | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 30 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 31 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 32 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 33 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 34 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 35 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 36 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 37 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 38 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 39 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bit_shift | 40 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_bitwise | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_boolean | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_boolean | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_boolean | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_boolean | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_boolean | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_boolean | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_boolean | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_boolean | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_boolean | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_boolean | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_boolean | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_boolean | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_conversions | 31 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_conversions | 32 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_conversions | 33 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_conversions | 34 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_conversions | 35 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_conversions | 36 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_conversions | 37 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_conversions | 38 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_conversions | 40 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_conversions | 41 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_conversions | 42 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_conversions | 43 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_conversions | 44 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_conversions | 45 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_conversions | 46 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_conversions | 47 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_conversions | 48 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_conversions | 49 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4 | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4 | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4 | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4 | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4 | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4 | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4 | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4 | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_arith | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_arith | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_arith | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_arith | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_arith | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_arith | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_arith | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_arith | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_arith | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_arith | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_arith | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_arith | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_arith | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_arith | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_arith | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_arith | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_cmp | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_cmp | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_cmp | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_cmp | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_cmp | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_cmp | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_cmp | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_cmp | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_cmp | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_cmp | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_cmp | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_cmp | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_cmp | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_cmp | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_cmp | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_cmp | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_cmp | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_cmp | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_pmin_pmax | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_pmin_pmax | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_pmin_pmax | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_pmin_pmax | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_pmin_pmax | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_pmin_pmax | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_rounding | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_rounding | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_rounding | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_rounding | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_rounding | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_rounding | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_rounding | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f32x4_rounding | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2 | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2 | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2 | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2 | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2 | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2 | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2 | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2 | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_arith | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_arith | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_arith | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_arith | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_arith | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_arith | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_arith | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_arith | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_arith | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_arith | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_arith | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_arith | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_arith | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_arith | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_arith | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_arith | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_cmp | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_cmp | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_cmp | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_cmp | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_cmp | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_cmp | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_cmp | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_cmp | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_cmp | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_cmp | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_cmp | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_cmp | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_cmp | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_cmp | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_cmp | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_cmp | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_cmp | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_cmp | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_pmin_pmax | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_pmin_pmax | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_pmin_pmax | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_pmin_pmax | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_pmin_pmax | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_pmin_pmax | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_rounding | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_rounding | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_rounding | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_rounding | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_rounding | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_rounding | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_rounding | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_f64x2_rounding | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith2 | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith2 | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith2 | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith2 | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith2 | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith2 | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith2 | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith2 | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith2 | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith2 | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith2 | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith2 | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith2 | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith2 | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith2 | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith2 | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_arith2 | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 30 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_cmp | 31 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_extadd_pairwise_i8x16 | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_extadd_pairwise_i8x16 | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_extadd_pairwise_i8x16 | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_extadd_pairwise_i8x16 | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_extmul_i8x16 | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_extmul_i8x16 | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_extmul_i8x16 | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_extmul_i8x16 | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_extmul_i8x16 | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_extmul_i8x16 | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_extmul_i8x16 | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_extmul_i8x16 | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_extmul_i8x16 | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_extmul_i8x16 | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_extmul_i8x16 | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_extmul_i8x16 | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_q15mulr_sat_s | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_q15mulr_sat_s | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_q15mulr_sat_s | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_sat_arith | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_sat_arith | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_sat_arith | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_sat_arith | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_sat_arith | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_sat_arith | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_sat_arith | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_sat_arith | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_sat_arith | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_sat_arith | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_sat_arith | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i16x8_sat_arith | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith2 | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith2 | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith2 | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith2 | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith2 | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith2 | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith2 | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith2 | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith2 | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith2 | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith2 | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith2 | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith2 | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_arith2 | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 30 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_cmp | 31 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_dot_i16x8 | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_dot_i16x8 | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_dot_i16x8 | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_extadd_pairwise_i16x8 | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_extadd_pairwise_i16x8 | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_extadd_pairwise_i16x8 | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_extadd_pairwise_i16x8 | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_extmul_i16x8 | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_extmul_i16x8 | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_extmul_i16x8 | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_extmul_i16x8 | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_extmul_i16x8 | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_extmul_i16x8 | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_extmul_i16x8 | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_extmul_i16x8 | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_extmul_i16x8 | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_extmul_i16x8 | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_extmul_i16x8 | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_extmul_i16x8 | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_trunc_sat_f32x4 | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_trunc_sat_f32x4 | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_trunc_sat_f32x4 | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_trunc_sat_f32x4 | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_trunc_sat_f64x2 | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_trunc_sat_f64x2 | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_trunc_sat_f64x2 | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i32x4_trunc_sat_f64x2 | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_arith | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_arith | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_arith | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_arith | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_arith | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_arith | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_arith | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_arith | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_arith | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_arith | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_arith | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_arith2 | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_arith2 | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_cmp | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_cmp | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_cmp | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_cmp | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_cmp | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_cmp | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_cmp | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_cmp | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_cmp | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_cmp | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_extmul_i32x4 | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_extmul_i32x4 | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_extmul_i32x4 | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_extmul_i32x4 | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_extmul_i32x4 | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_extmul_i32x4 | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_extmul_i32x4 | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_extmul_i32x4 | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_extmul_i32x4 | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_extmul_i32x4 | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_extmul_i32x4 | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i64x2_extmul_i32x4 | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_arith2 | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 30 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_cmp | 31 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_sat_arith | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_sat_arith | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_sat_arith | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_sat_arith | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_sat_arith | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_sat_arith | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_sat_arith | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_sat_arith | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_sat_arith | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_sat_arith | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_sat_arith | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_i8x16_sat_arith | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_int_to_int_extend | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 29 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 30 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 31 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 32 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 33 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 34 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 35 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 36 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 37 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 38 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 39 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 40 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 41 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 42 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 43 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 44 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 45 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 46 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 47 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 48 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 49 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 50 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 51 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 52 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 53 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 54 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 55 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 56 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 57 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 58 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 59 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 60 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 61 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 62 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 63 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 64 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 65 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 66 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 67 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 68 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 69 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 70 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 71 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 72 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 73 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 74 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 75 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 76 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 77 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 78 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 79 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 80 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 81 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 82 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 83 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 84 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 85 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 86 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 87 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 88 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 89 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 90 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 91 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 96 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=1 module=1 |
| simd_lane | 157 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 160 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 163 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 166 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 169 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 172 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 175 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 176 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 179 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 180 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 183 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 184 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 187 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 188 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 191 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 192 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 195 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 196 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_lane | 199 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| simd_load | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| simd_load | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| simd_load | 20 | invalid | accepted | accepted-shape | unknown local 2 | funcs=1 blocks=2 module=1 |
| simd_load | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| simd_load16_lane | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| simd_load16_lane | 2 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=2 module=1 |
| simd_load16_lane | 3 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| simd_load32_lane | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| simd_load32_lane | 2 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=2 module=1 |
| simd_load32_lane | 3 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| simd_load64_lane | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| simd_load64_lane | 2 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=2 module=1 |
| simd_load64_lane | 3 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| simd_load8_lane | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| simd_load8_lane | 2 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=2 module=1 |
| simd_load8_lane | 3 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| simd_load_extend | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_extend | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_extend | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_extend | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_extend | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_extend | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_extend | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_extend | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_extend | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_extend | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_extend | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_extend | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_splat | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_splat | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_splat | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_splat | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_splat | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_splat | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_splat | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_splat | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_zero | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_zero | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_zero | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_load_zero | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_splat | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_store | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| simd_store | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| simd_store | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| simd_store | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_store | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_store | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| simd_store16_lane | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| simd_store16_lane | 2 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=2 module=1 |
| simd_store16_lane | 3 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| simd_store32_lane | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| simd_store32_lane | 2 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=2 module=1 |
| simd_store32_lane | 3 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| simd_store64_lane | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| simd_store64_lane | 2 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=2 module=1 |
| simd_store64_lane | 3 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| simd_store8_lane | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| simd_store8_lane | 2 | invalid | accepted | accepted-shape | invalid lane index | funcs=1 blocks=2 module=1 |
| simd_store8_lane | 3 | invalid | accepted | accepted-shape | alignment must not be larger than nat... | funcs=1 blocks=2 module=1 |
| start | 0 | invalid | accepted | accepted-shape | unknown function | funcs=1 blocks=1 module=1 |
| start | 1 | invalid | accepted | accepted-shape | start function | funcs=1 blocks=1 module=1 |
| start | 2 | invalid | accepted | accepted-shape | start function | funcs=1 blocks=1 module=1 |
| store | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 30 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 31 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 32 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 33 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 34 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 35 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 36 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 37 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| store | 38 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| store | 39 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=3 module=1 |
| store | 40 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=3 module=1 |
| store | 41 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 42 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 43 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 44 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 45 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 46 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 47 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 48 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 49 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 50 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 51 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 52 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 53 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 54 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 55 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 56 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 57 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| store | 58 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| switch | 1 | invalid | accepted | accepted-shape | unknown label | funcs=1 blocks=1 module=1 |
| table | 9 | invalid | accepted | accepted-empty | unknown table | funcs=0 blocks=1 module=1 |
| table | 10 | invalid | accepted | accepted-shape | unknown table | funcs=1 blocks=1 module=1 |
| table | 11 | invalid | accepted | accepted-shape | size minimum must not be greater than... | funcs=0 blocks=2 module=1 |
| table | 12 | invalid | accepted | accepted-empty | size minimum must not be greater than... | IllegalStateException: ERROR Failed to create table block 0 at tabl... |
| table-sub | 0 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=3 module=1 |
| table-sub | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_fill | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_fill | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_fill | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_fill | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_fill | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| table_fill | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| table_fill | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| table_fill | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=3 module=1 |
| table_fill | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_get | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_get | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_get | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_get | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_get | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=3 module=1 |
| table_grow | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| table_grow | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| table_grow | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| table_grow | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| table_grow | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| table_grow | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_grow | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_init | 7 | invalid | accepted | accepted-shape | unknown elem segment 0 | funcs=1 blocks=1 module=1 |
| table_init | 8 | invalid | accepted | accepted-shape | unknown table 0 | funcs=1 blocks=1 module=1 |
| table_init | 9 | invalid | accepted | accepted-shape | unknown elem segment 4 | funcs=2 blocks=1 module=1 |
| table_init | 10 | invalid | accepted | accepted-shape | unknown table 0 | funcs=2 blocks=1 module=1 |
| table_init | 32 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 33 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 34 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 35 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 36 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 37 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 38 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 39 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 40 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 41 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 42 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 43 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 44 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 45 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 46 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 47 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 48 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 49 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 50 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 51 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 52 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 53 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 54 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 55 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 56 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 57 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 58 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 59 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 60 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 61 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 62 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 63 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 64 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 65 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 66 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 67 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 68 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 69 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 70 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 71 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 72 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 73 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 74 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 75 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 76 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 77 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 78 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 79 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 80 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 81 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 82 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 83 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 84 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 85 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 86 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 87 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 88 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 89 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 90 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 91 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 92 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 93 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_init | 94 | invalid | accepted | accepted-shape | type mismatch | funcs=2 blocks=2 module=1 |
| table_set | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_set | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_set | 3 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_set | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_set | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_set | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=3 module=1 |
| table_set | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_size | 1 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| table_size | 2 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=2 module=1 |
| unreached-invalid | 0 | invalid | accepted | accepted-shape | unknown local | funcs=1 blocks=1 module=1 |
| unreached-invalid | 1 | invalid | accepted | accepted-shape | unknown global | funcs=1 blocks=1 module=1 |
| unreached-invalid | 2 | invalid | accepted | accepted-shape | unknown function | funcs=1 blocks=1 module=1 |
| unreached-invalid | 3 | invalid | accepted | accepted-shape | unknown label | funcs=1 blocks=1 module=1 |
| unreached-invalid | 4 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 5 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 6 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 7 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 8 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 9 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 10 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 11 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 12 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 13 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 14 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 15 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 16 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 17 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 18 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 19 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 20 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 21 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 22 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 23 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 24 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 25 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 26 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 27 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 28 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 29 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 30 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 31 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 32 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 33 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 34 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 35 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 36 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 37 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 38 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 39 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 40 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 41 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 42 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 43 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 44 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 45 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 46 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 47 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 48 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 49 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 50 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 51 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 52 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 53 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 54 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 55 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 56 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 57 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 58 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 59 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 60 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 61 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 62 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 63 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 64 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 65 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 66 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 67 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 68 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 69 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 70 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 71 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 72 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 73 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 74 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 75 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 76 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 77 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 78 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 79 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 80 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 81 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 82 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 83 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 84 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 85 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 86 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 87 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 88 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 89 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 90 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 91 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 92 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 93 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 94 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 95 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 96 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 97 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 98 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 99 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 100 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 101 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 102 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 103 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 104 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 105 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 106 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 107 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 108 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 109 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 110 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 111 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 112 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 113 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 114 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 115 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 116 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| unreached-invalid | 117 | invalid | accepted | accepted-shape | type mismatch | funcs=1 blocks=1 module=1 |
| utf8-custom-section-id | 0 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 1 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 2 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 3 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 4 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 5 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 6 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 7 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 8 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 9 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 10 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 11 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 12 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 13 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 14 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 15 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 16 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 17 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 18 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 19 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 20 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 21 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 22 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 23 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 24 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 25 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 26 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 27 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 28 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 29 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 30 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 31 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 32 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 33 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 34 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 35 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 36 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 37 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 38 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 39 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 40 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 41 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 42 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 43 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 44 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 45 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 46 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 47 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 48 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 49 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 50 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 51 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 52 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 53 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 54 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 55 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 56 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 57 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 58 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 59 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 60 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 61 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 62 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 63 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 64 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 65 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 66 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 67 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 68 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 69 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 70 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 71 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 72 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 73 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 74 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 75 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 76 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 77 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 78 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 79 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 80 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 81 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 82 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 83 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 84 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 85 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 86 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 87 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 88 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 89 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 90 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 91 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 92 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 93 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 94 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 95 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 96 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 97 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 98 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 99 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 100 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 101 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 102 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 103 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 104 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 105 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 106 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 107 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 108 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 109 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 110 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 111 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 112 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 113 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 114 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 115 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 116 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 117 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 118 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 119 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 120 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 121 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 122 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 123 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 124 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 125 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 126 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 127 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 128 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 129 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 130 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 131 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 132 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 133 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 134 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 135 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 136 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 137 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 138 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 139 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 140 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 141 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 142 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 143 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-custom-section-id | 144 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 145 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 146 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 147 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 148 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 149 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 150 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 151 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 152 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 153 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 154 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 155 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 156 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 157 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 158 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 159 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 160 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 161 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 162 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 163 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 164 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 165 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 166 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 167 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 168 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 169 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 170 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 171 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 172 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 173 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 174 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-custom-section-id | 175 | malformed | accepted | accepted-empty | malformed UTF-8 encoding | funcs=0 blocks=1 module=1 |
| utf8-import-field | 0 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 1 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 2 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 3 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 4 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 5 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 6 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 7 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 8 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 9 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 10 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 11 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 12 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 13 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 14 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 15 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 16 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 17 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 18 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 19 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 20 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 21 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 22 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 23 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 24 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 25 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 26 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 27 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 28 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 29 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 30 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 31 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 32 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 33 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 34 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 35 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 36 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 37 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 38 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 39 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 40 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 41 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 42 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 43 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 44 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 45 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 46 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 47 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 48 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 49 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 50 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 51 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 52 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 53 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 54 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 55 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 56 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 57 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 58 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 59 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 60 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 61 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 62 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 63 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 64 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 65 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 66 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 67 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 68 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 69 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 70 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 71 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 72 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 73 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 74 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 75 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 76 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 77 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 78 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 79 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 80 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 81 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 82 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 83 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 84 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 85 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 86 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 87 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 88 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 89 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 90 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 91 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 92 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 93 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 94 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 95 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 96 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 97 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 98 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 99 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 100 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 101 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 102 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 103 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 104 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 105 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 106 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 107 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 108 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 109 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 110 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 111 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 112 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 113 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 114 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 115 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 116 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 117 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 118 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 119 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 120 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 121 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 122 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 123 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 124 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 125 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 126 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 127 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 128 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 129 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 130 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 131 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 132 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 133 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 134 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 135 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 136 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 137 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 138 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 139 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 140 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 141 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 142 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 143 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 144 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 145 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 146 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 147 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 148 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 149 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 150 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 151 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 152 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 153 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 154 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 155 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 156 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 157 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 158 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 159 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 160 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 161 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 162 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 163 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 164 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 165 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 166 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 167 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 168 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 169 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 170 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 171 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 172 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 173 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 174 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-field | 175 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 0 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 1 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 2 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 3 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 4 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 5 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 6 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 7 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 8 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 9 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 10 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 11 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 12 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 13 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 14 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 15 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 16 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 17 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 18 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 19 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 20 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 21 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 22 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 23 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 24 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 25 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 26 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 27 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 28 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 29 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 30 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 31 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 32 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 33 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 34 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 35 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 36 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 37 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 38 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 39 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 40 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 41 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 42 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 43 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 44 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 45 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 46 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 47 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 48 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 49 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 50 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 51 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 52 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 53 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 54 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 55 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 56 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 57 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 58 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 59 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 60 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 61 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 62 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 63 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 64 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 65 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 66 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 67 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 68 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 69 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 70 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 71 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 72 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 73 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 74 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 75 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 76 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 77 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 78 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 79 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 80 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 81 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 82 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 83 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 84 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 85 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 86 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 87 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 88 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 89 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 90 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 91 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 92 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 93 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 94 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 95 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 96 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 97 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 98 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 99 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 100 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 101 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 102 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 103 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 104 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 105 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 106 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 107 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 108 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 109 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 110 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 111 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 112 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 113 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 114 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 115 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 116 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 117 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 118 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 119 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 120 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 121 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 122 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 123 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 124 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 125 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 126 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 127 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 128 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 129 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 130 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 131 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 132 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 133 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 134 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 135 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 136 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 137 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 138 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 139 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 140 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 141 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 142 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 143 | malformed | accepted | accepted-partial | malformed UTF-8 encoding | loader: java.lang.IllegalArgumentException: Invalid DataType name: ... |
| utf8-import-module | 144 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 145 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 146 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 147 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 148 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 149 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 150 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 151 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 152 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 153 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 154 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 155 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 156 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 157 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 158 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 159 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 160 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 161 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 162 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 163 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 164 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 165 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 166 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 167 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 168 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 169 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 170 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 171 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 172 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 173 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 174 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |
| utf8-import-module | 175 | malformed | accepted | accepted-shape | malformed UTF-8 encoding | funcs=0 blocks=2 module=1 |

