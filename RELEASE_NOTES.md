# Ghidra-WASM 2.6.1

WebAssembly loader/plugin for Ghidra (disassembly + decompilation), maintained as a fork of
[nneonneo/ghidra-wasm-plugin](https://github.com/nneonneo/ghidra-wasm-plugin).

## Download

Use the asset that matches your Ghidra version - the name begins with `ghidra_12.1.4_PUBLIC_` for
Ghidra 12.1.4 or `ghidra_12.1.3_PUBLIC_` for 12.1.3. Install with
**File → Install Extensions → +** and restart Ghidra. You do not need to unzip the file.

## New in 2.6.1 (since 2.6.0)

**Decoder / loader**

* **Unknown opcodes degrade gracefully.** An opcode the plugin does not implement is decoded as a
  visible `unimplemented` instruction that consumes exactly the encoded operand bytes (stack
  switching `cont.new`/`cont.bind`/`suspend`/`switch`, JS string builtins, wide arithmetic,
  `memory.discard`, ...) instead of desyncing the byte stream and blanking the whole function.
* **Multi-memory**: memarg memory indices are decoded (`i32.load align=2 memidx=1 offset=0`) and
  **every** memory gets a block; memory 0 keeps its original placement.
* **memory64** (roadmap item 8): the memory's index type propagates to the pre-analyzer and to the
  SLEIGH address computation (`ctx_mem64`); addresses are computed in 64-bit pcode and truncated into
  the 32-bit `ram` space (exact below 4 GiB - documented, and the listing marks the form `(i64 index)`),
  with loader bounds so a hostile header cannot allocate wildly. Probe `05`: 0 undefined bytes.
* **Function-references instructions**: `call_ref`, `return_call_ref`, `ref.as_non_null`,
  `br_on_null`, `br_on_non_null` (probe `12` reaches 0 undefined bytes; `call_ref` decompiles to a
  real indirect call).
* **The three defects the official spec-suite run exposed** are fixed: `select` is decoded after an
  unconditional terminator (`unreachable`/`br`/`br_table`/`return`), `WasmStackVariableAnalyzer` no
  longer throws on unreachable-code stack slots, and a pathologically large `br_table` can no longer
  kill the decompiler (modelled cases capped at 1024, the rest still consumed). The spec core suite now
  reports **0 real undefined bytes and 0 decompiler failures**.

**New feature coverage**

* **Multi-value returns** (item 7): all results are returned as a packed struct through the `__wasm`
  output pentry (with tail-padding zeroing in the epilogue), so every result is visible to the
  decompiler and callers consume them all. In the reference Rust module, 7 multi-result functions now
  carry `wasm_ret_i32_i32*` prototypes instead of silently dropping results.
* **`.name` extras** (item 9): label (id 3), field (id 10) and tag (id 11) subsections are parsed, and
  a new analyzer applies table/memory/elem/data names as labels plus module/type/field/tag and
  label-name information as comments. Malformed name sections can no longer break an import (this also
  fixes a `ClassCastException` that made such modules fail).
* **DWARF source line info** is imported again: the fix supplies
  `programBaseAddressFixup = CODE_BASE + code-section content start` (stock Ghidra never sets it, so
  every row used to land at `ram:0x0` and be rejected) and skips unresolvable rows instead of aborting
  the import. Verified with `rustc`-built fixtures (`ram:8000009b -> fixture.rs:12`, incl. inlined
  `core` lines).

**Robustness against malformed input**

* Bounds everywhere a tiny module could previously allocate wildly: `locals` (1,000,000 per function,
  10,000,000 per module), memory limits (`initial <= maximum`, 32-bit <= 65536 pages, 64-bit <= 2^48,
  every materialised block capped at 256 MiB) and table limits (oversized tables skipped with a
  diagnostic). A 30-byte module can no longer abort the run with an escaping `OutOfMemoryError`, and a
  17-byte module can no longer materialise a 2 GiB block.
* `WasmLoader.load()` no longer swallows load failures: a malformed module fails with a diagnostic
  naming the section, id and file offset, instead of reporting `Import succeeded` on a truncated
  program (that bug could silently lose every function after a bad section).
* Aggregate effect: the 56-module malformed sweep went from 1 process death + 1 analysis timeout to
  **0 / 0**, and the 2948-module negative spec suite from 59 to **130 correctly rejected** modules,
  with no crashes and no hangs.

**Verification infrastructure**

* A **136-probe CI gate** (`probes.yml`) with a committed fixture and a real-module decompile baseline:
  a metric drift, a new probe without a baseline, an unexpected import result or a decompiler
  regression fails the build.
* Harnesses for the **official spec testsuite** (positive: 271/271 core modules imported, 0 real
  undefined bytes; SIMD clean), a **15-module real-world corpus** (15/15 imported, 5591/5591 functions
  decompiled, 1 real undefined byte in total), the malformed-input corpus and the negative spec suite.
* The test tooling now pins each checkout to one Ghidra install and refuses to measure a stale build.

## Also included in 2.6.0

If you are upgrading from 2.5.x: garbage collection (`rec`/`sub`/`struct`/`array` types and the `0xFB`
instruction set), the new exception handling (`try_table`, `throw_ref`, `exnref`), component-model
unwrapping (embedded core modules load as real programs), memory/table limit flags, constant-expression
decoding with extended-const folding and unknown-value-type safety.

## Known open items

Out-of-range section ids and duplicate sections still accepted silently; data segments of 64-bit
memories are dropped; memory indices >= 9 break the re-parse path; `table64` and `> 4 GiB` memory64
memories; stack-switching/string-builtin semantics (they decode as `unimplemented` by design); spec
`assert_*` emulation. All are documented in
[MODERN_WASM_GAPS.md](https://github.com/J0s3f/ghidra-wasm-plugin/blob/main/MODERN_WASM_GAPS.md).

## Build

```bash
export GHIDRA_INSTALL_DIR=<path to Ghidra install directory>
gradle buildExtension   # produces dist/ghidra_<version>_<date>_ghidra-wasm-plugin.zip
```

After an intentional behaviour change, refresh the probe baseline with
`test-scripts/check-local.ps1 -Update` and commit `test-scripts/expected-results.json`.
