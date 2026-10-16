# Real-world wasm corpus sweep - results

Manifest: `test-scripts/corpus/manifest.json`. Analysis: Ghidra headless, `-max-cpu 2`, heap 1500M, auto-analysis ON.

`undef` = all function-body bytes with no instruction (as WasmFeatureReport.java reports it).
`thunk` = the subset inside zero-instruction bodies, which is exactly the loader's placeholder for
*imported* functions and is expected (4 bytes per import). `undef*` = undef - thunk = the real
decode gap; a healthy module has 0. `decomp` = `decompiled/decompile_failed`. `unimpl` counts
unimplemented-placeholder instructions. Per-module logs: `C:\Users\micro\AppData\Local\Temp\corpus-run-h2\logs`.

| # | module | v8 | size | funcs | instrs | undef | thunk | undef* | decomp | fail | empty | unimpl | warn | err | s | status |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | `rasterbator_rs_bg` | valid | 179782 | 437 | 61658 | 156 | 156 | 0 | 437 | 0 | 39 | 0 | 42 | 0 | 42.9 | OK |
| 2 | `minrepro_a_i32` | invalid | 34 | 1 | 1 | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 1 | 14.2 | UNDEFINED-BYTES |
| 3 | `rust_plain` | valid | 119118 | 72 | 8691 | 0 | 0 | 0 | 72 | 0 | 0 | 0 | 0 | 0 | 22.6 | OK |
| 4 | `rust_debuginfo` | valid | 286436 | 72 | 8691 | 0 | 0 | 0 | 72 | 0 | 0 | 0 | 0 | 0 | 21.3 | OK |
| 5 | `rust_simd128` | valid | 80655 | 2 | 29 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 14 | OK |
| 6 | `jsquash_png_codec` | valid | 181088 | 220 | 59740 | 24 | 24 | 0 | 220 | 0 | 6 | 0 | 20 | 1 | 53.1 | OK |
| 7 | `jsquash_oxipng_codec` | valid | 164172 | 251 | 70053 | 4 | 4 | 0 | 251 | 0 | 1 | 0 | 3 | 0 | 77.3 | OK |
| 8 | `jsquash_oxipng_parallel` | valid | 236042 | 451 | 100088 | 56 | 56 | 0 | 451 | 0 | 14 | 0 | 17 | 0 | 89.3 | OK |
| 9 | `jsquash_jpeg_dec` | valid | 166470 | 235 | 77152 | 104 | 104 | 0 | 235 | 0 | 26 | 0 | 26 | 0 | 65.8 | OK |
| 10 | `jsquash_jpeg_enc` | valid | 251524 | 217 | 83907 | 112 | 112 | 0 | 217 | 0 | 28 | 0 | 28 | 0 | 83.9 | OK |
| 11 | `jsquash_webp_dec` | valid | 137960 | 174 | 64424 | 72 | 72 | 0 | 174 | 0 | 18 | 0 | 18 | 0 | 56.3 | OK |
| 12 | `jsquash_webp_enc_simd` | valid | 345584 | 321 | 134907 | 92 | 92 | 0 | 321 | 0 | 23 | 0 | 23 | 0 | 102.2 | OK |
| 13 | `jsquash_avif_dec` | valid | 1170930 | 929 | 409237 | 124 | 124 | 0 | 929 | 0 | 31 | 0 | 31 | 0 | 311.8 | OK |
| 14 | `sqljs` | valid | 658410 | 1917 | 291207 | 152 | 152 | 0 | 1917 | 0 | 38 | 0 | 38 | 0 | 219.3 | OK |
| 15 | `web_tree_sitter` | valid | 210415 | 292 | 95523 | 36 | 36 | 0 | 292 | 0 | 9 | 0 | 9 | 0 | 65.2 | OK |

## Blocks

- `rasterbator_rs_bg`: .custom.producers=114 .custom.target_features=91 .memory0=1114112 EXTERNAL=156 .module=179782 .table0=540 .table1=4096 .global0=4
- `minrepro_a_i32`: .module=34
- `rust_plain`: .debug_abbrev=1104 .debug_info=25915 .debug_ranges=4096 .debug_str=44276 .debug_line=14942 .custom.producers=67 .custom.target_features=132 .memory0=1114112 .module=119118 .table0=100 .global0=4
- `rust_debuginfo`: .debug_loc=11096 .debug_abbrev=2012 .debug_info=80198 .debug_ranges=6752 .debug_str=135863 .debug_line=21711 .custom.producers=67 .custom.target_features=132 .memory0=1114112 .module=286436 .table0=100 .global0=4
- `rust_simd128`: .debug_abbrev=1006 .debug_info=23062 .debug_ranges=3984 .debug_str=39346 .debug_line=12741 .custom.producers=67 .custom.target_features=141 .memory0=1048576 .module=80655 .table0=4
- `jsquash_png_codec`: .custom.producers=121 .custom.target_features=28 .memory0=1114112 EXTERNAL=24 .module=181088 .table0=284 .global0=4
- `jsquash_oxipng_codec`: .custom.producers=143 .custom.target_features=28 .memory0=1114112 EXTERNAL=4 .module=164172 .table0=280 .global0=4
- `jsquash_oxipng_parallel`: .custom.producers=127 .custom.target_features=50 .memory0=1179648 EXTERNAL=56 .module=236042 .table0=476 .global0=4 .global1=4 .global2=4
- `jsquash_jpeg_dec`: .memory0=16908288 EXTERNAL=104 .module=166470 .table0=624 .global0=4 .global1=4
- `jsquash_jpeg_enc`: .memory0=16973824 EXTERNAL=112 .module=251524 .table0=484 .global0=4 .global1=4
- `jsquash_webp_dec`: .memory0=16777216 EXTERNAL=72 .module=137960 .table0=476 .global0=4
- `jsquash_webp_enc_simd`: .memory0=16777216 EXTERNAL=92 .module=345584 .table0=828 .global0=4 .global1=4
- `jsquash_avif_dec`: .memory0=16777216 EXTERNAL=124 .module=1170930 .table0=2592 .global0=4 .global1=4
- `sqljs`: .memory0=22151168 EXTERNAL=152 .module=658410 .table0=1948 .global0=4
- `web_tree_sitter`: .custom.dylink.0=7 .custom.sourceMappingURL=25 .memory0=33554432 EXTERNAL=36 .module=210415 .table0=120 .global0=4 .global1=4 .global2=4 .global3=4 .global4=4 .global5=4 .global6=4 .global7=4 .global8=4 .global9=4 .global10=4 .global11=4 .global12=4 .global13=4 .global14=4

## Hash verification

- `rasterbator_rs_bg`: match
- `minrepro_a_i32`: match
- `rust_plain`: match
- `rust_debuginfo`: match
- `rust_simd128`: match
- `jsquash_png_codec`: match
- `jsquash_oxipng_codec`: match
- `jsquash_oxipng_parallel`: match
- `jsquash_jpeg_dec`: match
- `jsquash_jpeg_enc`: match
- `jsquash_webp_dec`: match
- `jsquash_webp_enc_simd`: match
- `jsquash_avif_dec`: match
- `sqljs`: match
- `web_tree_sitter`: match

## Import failures / messages

- none

## Analysis errors (SLEIGH compile chatter excluded)

- `minrepro_a_i32` (1): Failed to analyze function f @ ram:80000020 (WasmPreAnalyzer) wasm.analysis.ValidationException: Validation error at address ram:80000021: pop from empty stack
- `jsquash_png_codec` (1): Invalid PNG data at ram:0010e274 (PngDataType)

## Reproduce

```powershell
pwsh test-scripts/corpus-sweep.ps1 -CorpusDir C:\Users\micro\AppData\Local\Temp\corpus
```

