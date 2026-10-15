# Review regression suite

Run from the repository root:

```powershell
pwsh -NoProfile -File test-scripts/run-regressions.ps1 -GhidraDir C:/Tools/ghidra_12.1.4_PUBLIC
```

Requirements: JDK 21 or later, Ghidra 12.1.4, Python 3, Node 26, and PowerShell 7.
`GHIDRA_INSTALL_DIR` or the local `.ghidra-install` file supplies the default installation.

The runner compiles all production Java and SLEIGH sources into `build/code-regressions`,
excludes installed extension jars and language modules, and never installs into Ghidra.
Pass `-OutDir` to retain receipts elsewhere. Every stage exits nonzero on failure.

* `ParserRegressionTest.java`: bounded-heap allocation attacks, container boundaries,
  multibyte listing structures, recursive type prefixes, and concrete reference resolution.
* `RegressionTest.java`: full instruction coverage of each valid fixture, reference-branch
  relocation, compiler specs, table64 pcode widths, table initialization, memory-copy
  inference/injection, named locals, memory offsets, struct layout, vararg loads, C-stack
  options, numeric execution, memory growth, and trapping-store preservation.
* `PatchRegressionTest.java`: independent memory spaces at high offsets and indices,
  zero-sized/grown memory initialization, scalar/SIMD/atomic accesses, cross-memory and
  overlapping multi-page copies, trapping stores, and complete 16,384-case branch tables
  with scalar and mixed-width arguments; native decompilation must remain compact.
* `make_fixtures.py`: deterministic fixtures and independent Python numeric expectations;
  includes the existing call/store, operand-cache, and large `br_table` fixtures.
* `oracle.mjs`: Node validates every positive/negative fixture and executes every numeric
  matrix function plus memory-isolation and large-table behavior independently of Ghidra.
* `test_emulate_reports.py`: report aggregation process exit codes, missing/empty reports,
  and stale unselected reports.

On Windows the runner also executes the installer-preservation, emulation-wrapper exit-code,
settings-cleanup, and stderr-capture PowerShell tests. The installer test creates one temporary
NTFS junction to verify rejection of linked ancestors; restricted sandboxes may deny its creation.
All installer fixtures and mock processes are confined to private directories under the output
directory. Existing directories are not used as fixtures. GC instructions are now checked for analysis, pcode, and heap execution;
see the released-core cases below.

The table64 cases follow the core specification's address-type rules, including an i32 source
offset/length for `table.init` and the narrower address type for the `table.copy` length.
See [the core specification](https://webassembly.github.io/spec/core/bikeshed/index.html).

## Released-core regressions

`../released_core_fixtures.py` is shared by the regression runner and
`../gen_released_core_probes.py`, so every behavioral module also enters the CI import/decompile
probe and external fixture-validity gates. There are 37 released-core probes:

| Cases | Observable property |
| --- | --- |
| RC01–RC04 | Sparse active data, overlap order, high memory32 and memory64 addresses |
| RC10 | Changing, switching and clearing C-stack context; unchanged reanalysis is idempotent |
| RC11–RC12 | Inline callees preserve caller locals and live scalar/vector slots, including nested calls |
| RC20–RC25 | Packed/mixed-width structures; wide/vector/fixed arrays; overlapping bulk operations |
| RC27–RC36 | Nullable and nominal casts, canonical recursive types, cast branches, i31 identity, extern conversions, GC globals, data and element segments |
| RC40 | Named block signatures |
| RC50–RC56 | Interior call arguments, field types, SIMD lane width, locals/globals, fixed table calls, memory64 ABI width and independent memories |
| RC60–RC65 | Null/cast/bounds/drop traps; a failed bulk copy leaves its destination unchanged |

Node 26 validates and executes the valid cases independently. The Java tests additionally
inspect decompiled inline results, synthesized layouts and preserved register widths. Tests
exercise the memory64 2^64-byte size arithmetic without requiring a huge host allocation.
Six negative modules under the generated `released-invalid` directory test mutable variance,
final supertypes, function parameter variance, mutable array invariance, unrelated references,
and nullability: Node rejects them; Ghidra keeps importing/decoding them and emits diagnostics.
A separate valid graph checks function contravariance/result covariance and array variance.

The emulator owns GC state per instance. Uniform arrays use sparse run storage; segment-backed
operations can still fail for host resource exhaustion. Structure inference deliberately stops
at unknown control flow and mutable/dynamic indirect targets. These tests do not assert a
complete validator, garbage-collector scheduling, host interop, or proposal-only semantics.

Receipts are written under `build/code-regressions` by default. The probe counts and external
oracle classes are pinned in `../expected-results.json` and `../fixture-validity.json`.
