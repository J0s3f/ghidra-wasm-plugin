# Review findings: fixes and regression coverage

Patch release **v2.8.1** addresses all 28 findings from [the original review](https://github.com/J0s3f/ghidra-wasm-plugin/blob/v2.8.1/reports/full-code-review-2026-10-15/REPORT.md). The six P1 findings were handled first. Validation did not modify the user's Ghidra installation.

## Fixes

| Finding | Result | Regression coverage |
| --- | --- | --- |
| F01 | Both compiler specs classify `memory` and `memory64` as global; the C stack uses `memory`; pointer inference covers both spaces. | Compiler-spec API assertions and decompilation of initialized mutable linear memory. |
| F02 | Reference branches record argument relocation, including preceding label arguments of different widths. | Executed `br_on_null` / `br_on_non_null`; stack effects and complete decoding for both GC cast branches. |
| F03 | Copy inference resolves the length and source by their actual pcode operand positions; stale inferred lengths are cleared. | Dynamic length with destination 16 remains dynamic; constant length 3 is recovered; stale metadata is removed. |
| F04 | Parameter, result, supertype, recursive-type, and struct-field counts are checked against physical bytes and an allocation budget before allocation. | Malicious tiny declarations reject under a 64 MiB heap with `IOException`. |
| F05 | The installer validates and stages an archive before replacing only Wasm copies, with rollback on failure. | Unrelated locked extension, malformed archive, name collision, locked Wasm copy, and a real built-archive installation into a disposable mock install. |
| F06 | Test-install replacement requires an ownership marker and safe source/destination relationship; linked ancestors are rejected; failed `robocopy` exits abort. | Equal, ancestor, descendant, unowned, and junction paths; owned destination; failed copy preserves source. |
| F07 | Pre-analysis and SLEIGH consume complete multibyte local reference types. | Decoding length and execution of a function with a typed reference local. |
| F08 | Typed `select` decodes the reference prefix and full heap-type immediate. | Instruction length, complete decoding, and executed result. |
| F09 | Concrete references retain their heap index until the module resolves their func/struct/array/cont family; GC producers use the matching family. | Concrete struct/array returns, i31 and extern conversion results, typed function table call, and parser resolution. |
| F10 | Defined tables parse the initializer prefix and expression; constant initializers populate the table. | Parsed table size/type, byte-faithful markup, initialized function pointer, and executed indirect call. |
| F11 | Table64 gets independent width context for get/set, indirect calls, grow/size/fill/init, and all mixed-width copy combinations. Grow also receives its reference initializer. | Complete table-operation fixture, exact pcode operand/result widths, and executed table64 get/size. |
| F12 | Unrolled copies load the entire source before writing; dynamic copies retain a Wasm intrinsic with overlap semantics. | Executed injected pcode produces the correct overlapping-range bytes; decompilation retains the dynamic intrinsic. |
| F13 | Expanded and dynamic copies preserve both memory indices and both address widths. | Copy injection exercised across i32/i64 width pairs and distinct source/destination memories. |
| F14 | Format lookup, injected vararg loads, and the writev example use linear memory. | `%d` recovered from linear memory and injected LOAD address-space assertion. |
| F15 | Local names use parameter-inclusive local indices, check declared bounds, and select i64/v128 register widths. | Named i64 local storage, v128 register selection, and invalid name indices. |
| F16 | Stack and struct analyzers obtain the final memarg scalar, including explicit-memory encodings. | Both analyzers recover offset 16 rather than memory index 1. |
| F17 | Struct synthesis preserves explicit gaps and coalesces overlapping accesses into their full storage span. | Contained overlap, crossing overlap, trailing field offsets, and padding. |
| F18 | All eight scalar saturating conversions handle NaN, lower/upper bounds, and unsigned ranges. | Executed cross-width numeric matrix checked independently by Python and Node. |
| F19 | Unsigned float truncation splits at the signed midpoint before conversion, preserving the upper half of the integer range. | Executed i64 conversion of 2^63 and the unsigned saturation matrix. |
| F20 | `nearest` rounds ties to even and retains the input sign for zero results. | Positive/negative half ties, signed zeros, infinities, and large exact values for f32/f64. |
| F21 | Min/max combine zero sign bits according to Wasm semantics. | Both operand orders, both zero signs, and unequal values for f32/f64. |
| F22 | Signed i32 truncation accepts representable fractions above -2147483649. | Executed truncation of -2147483648.5 returns INT_MIN. |
| F23 | Memory growth compares unsigned delta against maximum minus current size before addition. | Overflowing memory64 growth fails with the all-ones result. |
| F24 | The emulator checks the next memory access before execution; post-trap zeroing is removed. | Scalar i32, memory64, and SIMD stores trap while preserving initialized `ABCD`; existing valid and trapping call/cache fixtures also pass. |
| F25 | Listing structures use consumed type-encoding byte lengths and preserve the first recursive-group prefix. | One/multibyte heap indices in signatures, globals, locals, tables, and recursive function markup. |
| F26 | Section, function-body, and name-subsection readers are bounded to their declared payloads. | Cross-section type read, truncated skipped section, function locals crossing a body boundary, and malformed name subsections. |
| F27 | C-stack guessing uses unsigned counts/indices and complete local types; auto mode is resolved per program without overwriting the option. | Global index 64 and preservation of the auto setting after analysis. |
| F28 | Emulation failures raise; wrappers check native exits, remove stale reports, require fresh reports, and fail aggregation on failures or missing/empty suites. | Six report-process tests and four real-wrapper cases with a controlled native launcher. |

## Validation

The reproducible entry point is [run-regressions.ps1](https://github.com/J0s3f/ghidra-wasm-plugin/blob/v2.8.1/test-scripts/run-regressions.ps1). It compiles production Java and SLEIGH from this checkout and excludes installed extension classes and languages. The [suite README](https://github.com/J0s3f/ghidra-wasm-plugin/blob/v2.8.1/test-scripts/regressions/README.md) documents prerequisites and scope.

Local validation uses Ghidra 12.1.4, Java 25 with `--release 21`, Node 26.10.0, Python 3.14, and PowerShell 7. Full logs remain locally under `build/code-regressions`; the committed [validation receipt](https://github.com/J0s3f/ghidra-wasm-plugin/blob/v2.8.1/reports/full-code-review-2026-10-15/fix-validation-results.txt) records the results:

* 2,601 integration assertions, with no failed fixtures.
* 22 parser assertions under a 64 MiB heap.
* 195 independent Node fixture-validity and numeric-result assertions.
* Six Python report-exit tests, installer-preservation tests, four native-wrapper exit tests, and the existing settings-cleanup and stderr-capture tests.
* The existing 223-probe inventory matches its recorded baseline, including component-loader cases. The sweep used automatic analysis with all ten Wasm analyzers discovered from the built module; no baseline changes were needed.
* Successful offline Gradle `buildExtension`; the archive is produced under `dist/`.
* Successful built-archive installation into a disposable mock directory while an unrelated extension jar remained locked.

The probe workflow now runs the new source-compiled suite. Review reports are excluded from release archives.

Concrete GC references are resolved to abstract families; full nominal GC validation and GC heap emulation remain outside the plugin's model. Conflicting overlapping struct observations become one undefined storage span rather than invented displaced fields. Parser allocation limits are deliberate resource limits. The installer junction test requires a Windows environment that permits creating a temporary junction; it was run outside the restricted sandbox.
