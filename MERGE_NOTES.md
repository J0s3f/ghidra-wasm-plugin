# Merge notes (fork: J0s3f/ghidra-wasm-plugin)

This branch (`merged-upstream-prs`) consolidates the useful outstanding work found in
[nneonneo/ghidra-wasm-plugin](https://github.com/nneonneo/ghidra-wasm-plugin) pull requests and
forks, and adapts it so the plugin builds and works against modern Ghidra (12.1.x, verified with
Ghidra 12.1.4).

## What was merged

| Source | What it adds | Notes |
| --- | --- | --- |
| [PR #35](https://github.com/nneonneo/ghidra-wasm-plugin/pull/35) (jonaslejon) | Legacy exception handling, tail calls, threads/atomics, relaxed SIMD | Includes the tag-section parsing and `EXT_TAG` external kind needed for modules with tags |
| [PR #31](https://github.com/nneonneo/ghidra-wasm-plugin/pull/31) (six-two) | Crash fix when loading WASM with tags (`EXT_TAG` external kind) | Already contained in PR #35; no separate change needed |
| [PR #33](https://github.com/nneonneo/ghidra-wasm-plugin/pull/33) / [PR #30](https://github.com/nneonneo/ghidra-wasm-plugin/pull/30) (Yanndroid / atouboot) | Fix for the removed `CompositeDataTypeImpl.checkAncestry` in Ghidra 12.1.2+/12.2 | Reimplemented version-agnostically in `StructureBuilder` using only stable public API (no dependency on `DataTypeUtilities`), so it builds and runs on 12.1.x *and* 12.2+ |
| [PR #5](https://github.com/nneonneo/ghidra-wasm-plugin/pull/5) (cmorin6) | `WasmFunctionVariableNameAnalyzer` – applies local variable names from the `.name` section | Adapted to the current API (`funcidx` field/ctor), processor name fixed to `WebAssembly`, local-register stride detected at runtime (16 bytes in the current SLEIGH spec, was 8 in the original PR) |
| [PR #23](https://github.com/nneonneo/ghidra-wasm-plugin/pull/23) (antoniovazquezblanco) | CI compilation pipeline | Modernized: Java 21, Gradle 9.2.1, Ghidra 12.1.4 + 12.1.3 matrix, `setup-ghidra` action |
| [ManuMassi/improve-decompilation-fidelity](https://github.com/ManuMassi/ghidra-wasm-plugin/tree/improve-decompilation-fidelity) (fork, 5 commits, not a PR) | Decompilation fidelity: vararg functions, function signature types, DWARF import (block naming fix + disabling line info import to avoid `AddressOutOfBounds`), function tables marked read-only for constant folding, `main`/`printf`/`scanf` naming on stripped binaries, constant `memory.copy` initializer materialization | The single biggest decompilation-quality improvement found in any fork |

## Reviewed but intentionally not merged

- `cmorin6/fix-call-stack` and `cmorin6/fix-leb128-parsing-issues`: obsolete, they patch files
  (`pcodeInject/PcodeOpEmitter.java`, custom `format/Leb128.java`) that no longer exist upstream;
  the underlying issues were fixed by later upstream refactors.
- `cmorin6` PR #5 branch contents beyond the variable-name analyzer: already merged upstream.
- `kristoff3r` fork, `nneonneo` `ghidra-pr`/`v1` branches, PRs #2/#6/#7/#8/#10/#13/#17/#28: already
  merged upstream.
- `XeR` fork (1 commit, 31 behind), `erroy/harvard` (`Experiment with separate ram/data address
  spaces`, 65 commits behind an old master): stale experiments, superseded by the current design.
- All other forks (31 total) were checked via the GitHub compare API: they contain no commits that
  are ahead of upstream `master` other than the ones listed above.

## Verification

The plugin was built against Ghidra 12.1.4, installed to
`C:\Tools\ghidra_12.1.4_PUBLIC\Ghidra\Extensions\`, and verified by importing
`rasterbator_rs_bg.wasm` (Rust/wasm-bindgen, 179 KiB) headlessly with
`test-scripts/DumpDecomp.java`:

```
SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156
```

All 437 recovered functions disassemble and decompile successfully.

## Next steps

[MODERN_WASM_GAPS.md](MODERN_WASM_GAPS.md) inventories the plugin's coverage of modern WebAssembly
(what works, what silently produces wrong code, what fails), backed by 21 generated probe modules and
the `test-scripts/` harness, and lists the planned extension work in priority order.

## Building

```bash
export GHIDRA_INSTALL_DIR=<path to Ghidra install directory>
gradle buildExtension   # produces dist/ghidra_<version>_<builddate>_Ghidra-WASM.zip
```

Install with *File → Install Extensions* in Ghidra, or unzip the archive into
`<ghidra>/Ghidra/Extensions/`.
