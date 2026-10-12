# Ghidra-WASM (fork release)

WebAssembly loader/plugin for Ghidra with disassembly and decompilation support, maintained as a
fork of [nneonneo/ghidra-wasm-plugin](https://github.com/nneonneo/ghidra-wasm-plugin) that merges
the outstanding upstream pull requests and downstream fork work, and is verified against modern
Ghidra (12.1.x).

## Download

Attach the zip that matches your Ghidra version — for example, if you are running Ghidra 12.1.4,
download the asset whose name begins with `ghidra_12.1.4_PUBLIC_`. Install it with
**File → Install Extensions → +** and restart Ghidra. You do not need to unzip the file.

## What is included

* **Ghidra 12.1.2+ compatibility** — `CompositeDataTypeImpl.checkAncestry` was removed in newer
  Ghidra releases; it is reimplemented in a version-independent way, so the plugin also builds
  against 12.2+.
* **Upstream PR [#35](https://github.com/nneonneo/ghidra-wasm-plugin/pull/35)** — lifting of legacy
  exception handling, tail calls, threads/atomics and relaxed SIMD, including parsing of the tag
  section (fixes crashes loading modules with tags, upstream PR
  [#31](https://github.com/nneonneo/ghidra-wasm-plugin/pull/31)).
* **Upstream PR [#5](https://github.com/nneonneo/ghidra-wasm-plugin/pull/5)** — auto-naming of
  function local variables from the `.name` section, ported to the current API and register layout.
* **Decompilation fidelity work from the `ManuMassi` fork** — vararg call support, function
  signature types, DWARF type import fixes, read-only function tables (constant folding of
  `call_indirect`), `main`/`printf`/`scanf` naming for stripped binaries, and materialization of
  constant `memory.copy` `.rodata` initializers.
* **CI** — every push builds the plugin against Ghidra 12.1.4 and 12.1.3.

Detailed merge decisions are documented in
[MERGE_NOTES.md](https://github.com/J0s3f/ghidra-wasm-plugin/blob/merged-upstream-prs/MERGE_NOTES.md).

## Verification

Built against Ghidra 12.1.4 and used to import a 179 KiB Rust/`wasm-bindgen` module headlessly:

```
SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156
```

All 437 recovered functions disassemble and decompile.
