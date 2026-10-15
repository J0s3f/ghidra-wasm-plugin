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
directory. Existing directories are not used as fixtures. GC instructions are checked for analysis
and pcode correctness; this suite does not implement a GC heap emulator.

The table64 cases follow the core specification's address-type rules, including an i32 source
offset/length for `table.init` and the narrower address type for the `table.copy` length.
See [the core specification](https://webassembly.github.io/spec/core/bikeshed/index.html).
