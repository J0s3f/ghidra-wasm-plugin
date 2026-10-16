# WebAssembly loader robustness sweep (workstream J)

headless Ghidra process (`-max-cpu 2`, -analysisTimeoutPerFile 60, hard wall bound `180`s)
from the `all` corpus in `C:\Users\micro\AppData\Local\Temp\jcorpus-all`. To exercise the analyzers as well, run with
`-Analyze`.

Outcome legend: **import_ok** = loader produced a program and the report ran; 
**import_ok_analysis_timeout** = program produced but analysis exceeded the per-file timeout; 
**import_failed** = loader rejected the module with a message; 
**process_died** = JVM exited non-zero / uncaught exception escaped; **hang** = wall clock exceeded.

## Totals

| outcome | count |
| --- | --- |
| import_ok | 27 |
| import_ok_analysis_timeout | 1 |
| import_failed | 27 |
| process_died | 1 |
| **total** | **56** |

## Per-module outcomes

| module | bytes | outcome | wall(s) | detail |
| --- | --- | --- | --- | --- |
| B01_zero_length_body.wasm | 22 | import_failed | 11.1 | Failed to load Wasm module java.io.EOFException / at wasm.format.sections.structures.WasmCodeEntry.<init>(WasmCodeEntry.java:42) |
| B02_body_exceeds_section.wasm | 26 | import_failed | 10.9 | Failed to load Wasm module java.io.IOException: Unable to read past EOF: 24, 65535 / at wasm.format.sections.structures.WasmCodeEntry.<init>(WasmCodeEntry.java:46) |
| B03_locals_ffffffff.wasm | 30 | import_ok | 14.9 | Analysis Task: Wasm Pre-Analyzer - -1 java.lang.NegativeArraySizeException: -1 / at wasm.format.sections.structures.WasmCodeEntry.getLocals(WasmCodeEntry.java:71) |
| B04_locals_1G_alloc.wasm | 30 | process_died | 12.0 | Abort due to Headless analyzer error: Java heap space java.lang.OutOfMemoryError: Java heap space / at wasm.format.sections.structures.WasmCodeEntry.getLocals(WasmCodeEntry.java:71) |
| C01_count_type_ffffffff.wasm | 15 | import_failed | 11.2 | Failed to load Wasm module java.io.IOException: Unable to read past EOF: 15, 1 / at wasm.format.sections.WasmTypeSection.<init>(WasmTypeSection.java:43) |
| C02_count_func_ffffffff.wasm | 21 | import_failed | 11.4 | Failed to load Wasm module java.io.EOFException / at wasm.format.sections.WasmFunctionSection.<init>(WasmFunctionSection.java:36) |
| C03_count_code_ffffffff.wasm | 25 | import_failed | 10.9 | Failed to load Wasm module java.io.EOFException / at wasm.format.sections.structures.WasmCodeEntry.<init>(WasmCodeEntry.java:40) |
| C04_count_table_ffffffff.wasm | 15 | import_failed | 12.8 | Failed to load Wasm module java.io.IOException: Unable to read past EOF: 15, 1 / at wasm.format.WasmEnums$ValType.readFromReader(WasmEnums.java:194) |
| C05_count_memory_ffffffff.wasm | 15 | import_failed | 14.5 | Failed to load Wasm module java.io.IOException: Unable to read past EOF: 15, 1 / at wasm.format.sections.structures.WasmResizableLimits.<init>(WasmResizableLimits.java:44) |
| C06_count_global_ffffffff.wasm | 15 | import_failed | 13.9 | Failed to load Wasm module java.io.IOException: Unable to read past EOF: 15, 1 / at wasm.format.WasmEnums$ValType.readFromReader(WasmEnums.java:194) |
| C07_count_element_ffffffff.wasm | 15 | import_failed | 13.1 | Failed to load Wasm module java.io.EOFException / at wasm.format.sections.structures.WasmElementSegment.<init>(WasmElementSegment.java:57) |
| C08_count_data_ffffffff.wasm | 15 | import_failed | 12.4 | Failed to load Wasm module java.io.EOFException / at wasm.format.sections.structures.WasmDataSegment.<init>(WasmDataSegment.java:37) |
| C09_count_func_code_mismatch.wasm | 26 | import_ok | 14.9 | Analysis Task: Wasm Pre-Analyzer - Index 1 out of bounds for length 1 java.lang.IndexOutOfBoundsException: Index 1 out of bounds for length 1 / at java.base/jdk.internal.util.Preconditions.outOfBounds(Preconditions.java:100) |
| D01_two_type_sections.wasm | 22 | import_ok | 15.1 | WasmFeatureReport.java> PROBE D01_two_type_sections.wasm funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 |
| D02_two_code_sections.wasm | 30 | import_ok | 15.1 | WasmFeatureReport.java> PROBE D02_two_code_sections.wasm funcs=1 instrs=2 undefined_bytes=0 decompiled=1 decompile_failed=0 |
| D03_unknown_section_id.wasm | 13 | import_ok | 14.5 | WasmFeatureReport.java> PROBE D03_unknown_section_id.wasm funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 |
| D04_sections_wrong_order.wasm | 24 | import_ok | 12.9 | WasmFeatureReport.java> PROBE D04_sections_wrong_order.wasm funcs=1 instrs=2 undefined_bytes=0 decompiled=1 decompile_failed=0 |
| D05_repeat_custom_sections.wasm | 26 | import_ok | 12.4 | WasmFeatureReport.java> PROBE D05_repeat_custom_sections.wasm funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 |
| H01_bad_magic.wasm | 9 | import_failed | 7.9 | The ProgramLoader could not successfully load file:///C:/Users/micro/AppData/Local/Temp/jcorpus-all/H01_bad_magic.wasm with the provided import parameters. Please ensure that any specified processor/cspec arguments are compatible with the loader that is used during import and try again. |
| H02_version0.wasm | 8 | import_failed | 8.5 | The ProgramLoader could not successfully load file:///C:/Users/micro/AppData/Local/Temp/jcorpus-all/H02_version0.wasm with the provided import parameters. Please ensure that any specified processor/cspec arguments are compatible with the loader that is used during import and try again. |
| H03_version13_component.wasm | 8 | import_failed | 9.4 | The ProgramLoader could not successfully load file:///C:/Users/micro/AppData/Local/Temp/jcorpus-all/H03_version13_component.wasm with the provided import parameters. Please ensure that any specified processor/cspec arguments are compatible with the loader that is used during import and try again. |
| H04_version0d_layer1.wasm | 8 | import_failed | 9.9 | The ProgramLoader could not successfully load file:///C:/Users/micro/AppData/Local/Temp/jcorpus-all/H04_version0d_layer1.wasm with the provided import parameters. Please ensure that any specified processor/cspec arguments are compatible with the loader that is used during import and try again. |
| H05_all_zeros.wasm | 16 | import_failed | 9.0 | The ProgramLoader could not successfully load file:///C:/Users/micro/AppData/Local/Temp/jcorpus-all/H05_all_zeros.wasm with the provided import parameters. Please ensure that any specified processor/cspec arguments are compatible with the loader that is used during import and try again. |
| L01_leb_overlong_pad_len.wasm | 18 | import_ok | 14.1 | Data markup conflict at ram:8000000e ghidra.program.model.util.CodeUnitInsertionException: Could not create Data at address ram:8000000e / at wasm.WasmLoader.createData(WasmLoader.java:261) |
| L02_leb_len_gt5bytes.wasm | 19 | import_ok | 14.5 | Data markup conflict at ram:8000000f ghidra.program.model.util.CodeUnitInsertionException: Could not create Data at address ram:8000000f / at wasm.WasmLoader.createData(WasmLoader.java:261) |
| L03_leb_count_overflow32.wasm | 15 | import_failed | 11.9 | Failed to load Wasm module java.io.IOException: Unable to read past EOF: 15, 1 / at wasm.format.sections.WasmTypeSection.<init>(WasmTypeSection.java:43) |
| L04_leb_len_overflow64.wasm | 22 | import_failed | 11.7 | Failed to load Wasm module java.io.IOException: Unsupported LEB128 value, too large to fit in 64bit java long variable / at wasm.format.sections.WasmSection.createSection(WasmSection.java:53) |
| L05_leb_unterminated_eof.wasm | 13 | import_failed | 10.3 | Failed to load Wasm module java.io.EOFException / at wasm.format.sections.WasmSection.createSection(WasmSection.java:53) |
| M01_mem_initial_gt_max.wasm | 14 | import_ok | 12.8 | WasmFeatureReport.java> PROBE M01_mem_initial_gt_max.wasm funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 |
| M02_mem_max_2p32.wasm | 18 | import_ok | 13.0 | WasmFeatureReport.java> PROBE M02_mem_max_2p32.wasm funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 |
| M03_mem_huge_initial.wasm | 17 | import_ok_analysis_timeout | 71.1 | REPORT: Analysis timed out at 60 seconds. Processing not completed for file: file:///C:/Users/micro/AppData/Local/Temp/jcorpus-all/M03_mem_huge_initial.wasm |
| M04_table_huge_initial.wasm | 18 | import_ok | 13.7 | Failed to create table block 0 at table:00000000 java.lang.IllegalStateException: New memory block NOT added: would cause total number of initialized program bytes to exceed the maximum program size of 16 GBytes / at wasm.WasmLoader.createTableBlock(WasmLoader.java:301) |
| M05_data_offset_oor.wasm | 30 | import_ok | 12.7 | Failed to initialize memory 0 with data segment 0 at ram:7ffffff0 ghidra.program.model.mem.MemoryAccessException: Address ram:7ffffff0 does not exist in memory / at wasm.WasmLoader.loadDataToMemory(WasmLoader.java:565) |
| M06_data_overlap.wasm | 35 | import_ok | 12.5 | WasmFeatureReport.java> PROBE M06_data_overlap.wasm funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 |
| O01_typeidx_oor.wasm | 20 | import_ok | 12.3 | Analysis Task: Wasm Pre-Analyzer - Index 65535 out of bounds for length 1 java.lang.IndexOutOfBoundsException: Index 65535 out of bounds for length 1 / at java.base/jdk.internal.util.Preconditions.outOfBounds(Preconditions.java:100) |
| O02_funcidx_oor.wasm | 30 | import_ok | 12.4 | Failed to analyze function unnamed_function_0 @ ram:80000016 java.lang.IndexOutOfBoundsException: Index -1 out of bounds for length 1 / at java.base/jdk.internal.util.Preconditions.outOfBounds(Preconditions.java:100) |
| O03_tableidx_oor.wasm | 37 | import_ok | 14.1 | Failed to analyze function unnamed_function_0 @ ram:8000001c java.lang.IndexOutOfBoundsException: Index 1048575 out of bounds for length 1 / at java.base/jdk.internal.util.Preconditions.outOfBounds(Preconditions.java:100) |
| O04_memidx_oor.wasm | 30 | import_ok | 13.7 | Analysis Task: Wasm Pre-Analyzer - Index: 0 java.lang.IndexOutOfBoundsException: Index: 0 / at java.base/java.util.Collections$EmptyList.get(Collections.java:4916) |
| O05_globalidx_oor.wasm | 29 | import_ok | 13.1 | Failed to analyze function unnamed_function_0 @ ram:80000016 java.lang.IndexOutOfBoundsException: Index: 65535 / at java.base/java.util.Collections$EmptyList.get(Collections.java:4916) |
| O06_elem_funcidx_oor.wasm | 31 | import_ok | 13.5 | Failed to initialize table 0 with element segment 0 at offset 0 java.lang.IndexOutOfBoundsException: Index: 65535 / at java.base/java.util.Collections$EmptyList.get(Collections.java:4916) |
| O07_tagidx_oor.wasm | 21 | import_ok | 13.5 | WasmFeatureReport.java> PROBE O07_tagidx_oor.wasm funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 |
| O08_typeidx_huge_ref.wasm | 33 | import_ok | 15.2 | Failed to analyze function unnamed_function_0 @ ram:80000016 java.lang.IndexOutOfBoundsException: Index: 0 / at java.base/java.util.Collections$EmptyList.get(Collections.java:4916) |
| S01_size_declared_smaller.wasm | 14 | import_failed | 13.3 | Failed to load Wasm module java.io.EOFException / at wasm.format.sections.WasmSection.createSection(WasmSection.java:53) |
| S02_size_declared_larger.wasm | 14 | import_ok | 15.3 | WasmFeatureReport.java> PROBE S02_size_declared_larger.wasm funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 |
| S03_size_zero.wasm | 14 | import_ok | 15.5 | Data markup conflict at ram:8000000a ghidra.program.model.util.CodeUnitInsertionException: Could not create Data at address ram:8000000a / at wasm.WasmLoader.createData(WasmLoader.java:261) |
| S04_size_2p28.wasm | 18 | import_ok | 15.5 | WasmFeatureReport.java> PROBE S04_size_2p28.wasm funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 |
| T01_empty.wasm | 0 | import_failed | 9.2 | The ProgramLoader could not successfully load file:///C:/Users/micro/AppData/Local/Temp/jcorpus-all/T01_empty.wasm with the provided import parameters. Please ensure that any specified processor/cspec arguments are compatible with the loader that is used during import and try again. |
| T02_trunc_mid_header.wasm | 4 | import_failed | 9.0 | The ProgramLoader could not successfully load file:///C:/Users/micro/AppData/Local/Temp/jcorpus-all/T02_trunc_mid_header.wasm with the provided import parameters. Please ensure that any specified processor/cspec arguments are compatible with the loader that is used during import and try again. |
| T03_trunc_mid_version.wasm | 6 | import_failed | 8.7 | The ProgramLoader could not successfully load file:///C:/Users/micro/AppData/Local/Temp/jcorpus-all/T03_trunc_mid_version.wasm with the provided import parameters. Please ensure that any specified processor/cspec arguments are compatible with the loader that is used during import and try again. |
| T04_trunc_mid_sectionid.wasm | 9 | import_failed | 11.8 | Failed to load Wasm module java.io.EOFException / at wasm.format.sections.WasmSection.createSection(WasmSection.java:53) |
| T05_trunc_mid_payload.wasm | 14 | import_failed | 12.7 | Failed to load Wasm module java.io.IOException: Unable to read past EOF: 14, 1 / at wasm.format.sections.WasmTypeSection.<init>(WasmTypeSection.java:43) |
| T06_trunc_mid_body.wasm | 24 | import_failed | 12.7 | Failed to load Wasm module java.io.IOException: Unable to read past EOF: 22, 4 / at wasm.format.sections.structures.WasmCodeEntry.<init>(WasmCodeEntry.java:46) |
| V00_valid_passthrough.wasm | 35 | import_ok | 14.4 | WasmFeatureReport.java> PROBE V00_valid_passthrough.wasm funcs=1 instrs=3 undefined_bytes=0 decompiled=1 decompile_failed=0 |
| X01_expr_no_end.wasm | 15 | import_failed | 11.3 | Failed to load Wasm module java.io.IOException: Unable to read past EOF: 15, 1 / at wasm.format.sections.structures.ConstantExpression.readExpression(ConstantExpression.java:110) |
| X02_expr_overflow_value.wasm | 25 | import_ok | 14.0 | WasmFeatureReport.java> PROBE X02_expr_overflow_value.wasm funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 |
| X03_expr_nested_unterminated.wasm | 19 | import_failed | 11.5 | Failed to load Wasm module java.io.IOException: Unable to read past EOF: 19, 1 / at wasm.format.sections.structures.ConstantExpression.readExpression(ConstantExpression.java:110) |

## Metrics (successful imports)

| module | metrics | note |
| --- | --- | --- |
| B03_locals_ffffffff.wasm | funcs=1 instrs=1 undefined_bytes=7 decompiled=1 decompile_failed=0 |  |
| C09_count_func_code_mismatch.wasm | funcs=1 instrs=1 undefined_bytes=1 decompiled=1 decompile_failed=0 |  |
| D01_two_type_sections.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 | no functions recovered |
| D02_two_code_sections.wasm | funcs=1 instrs=2 undefined_bytes=0 decompiled=1 decompile_failed=0 |  |
| D03_unknown_section_id.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 | no functions recovered |
| D04_sections_wrong_order.wasm | funcs=1 instrs=2 undefined_bytes=0 decompiled=1 decompile_failed=0 |  |
| D05_repeat_custom_sections.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 | no functions recovered |
| L01_leb_overlong_pad_len.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 | no functions recovered |
| L02_leb_len_gt5bytes.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 | no functions recovered |
| M01_mem_initial_gt_max.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 | no functions recovered |
| M02_mem_max_2p32.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 | no functions recovered |
| M03_mem_huge_initial.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 |  |
| M04_table_huge_initial.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 | no functions recovered |
| M05_data_offset_oor.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 | no functions recovered |
| M06_data_overlap.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 | no functions recovered |
| O01_typeidx_oor.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 | no functions recovered |
| O02_funcidx_oor.wasm | funcs=1 instrs=1 undefined_bytes=7 decompiled=1 decompile_failed=0 |  |
| O03_tableidx_oor.wasm | funcs=1 instrs=1 undefined_bytes=8 decompiled=1 decompile_failed=0 |  |
| O04_memidx_oor.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 | no functions recovered |
| O05_globalidx_oor.wasm | funcs=1 instrs=1 undefined_bytes=6 decompiled=1 decompile_failed=0 |  |
| O06_elem_funcidx_oor.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 | no functions recovered |
| O07_tagidx_oor.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 | no functions recovered |
| O08_typeidx_huge_ref.wasm | funcs=1 instrs=1 undefined_bytes=10 decompiled=1 decompile_failed=0 |  |
| S02_size_declared_larger.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 | no functions recovered |
| S03_size_zero.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 | no functions recovered |
| S04_size_2p28.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 | no functions recovered |
| V00_valid_passthrough.wasm | funcs=1 instrs=3 undefined_bytes=0 decompiled=1 decompile_failed=0 |  |
| X02_expr_overflow_value.wasm | funcs=0 instrs=0 undefined_bytes=0 decompiled=0 decompile_failed=0 | no functions recovered |

