# REPORT-H6 — `.name` label names become real label targets

Open item **B6**: the `.name` section's label-name subsection (extended-name-section id 3) was
parsed and applied as a *plate comment* on the containing function. This change makes the names
land as **real Ghidra labels at the address each label branches to**, so the symbol table and the
decompiler show them as branch targets.

Branch: `feat/name-labels` (based on `main` @ `e5157d4`).
Worktree: `ghidra-wt-h6`, pinned install `C:\Users\micro\AppData\Local\Temp\ghidra-h5`.

---

## 1. What changed

### `src/main/java/wasm/analysis/WasmFunctionAnalysis.java` (pre-analyzer)

The pre-analyzer already resolves every branch to an address (it writes the target into the
`ctx_br_target` context register that SLEIGH's `doBranch` uses). It now also *records* those
targets by label index:

* `ControlFrame` gains `int labelNameIndex = -1`.
* `pushBlock()` assigns the next **function-wide** label index to every `block` / `loop` / `if` /
  `try` frame (the function's own frame and reused `catch`/`else` frames are skipped). This is
  exactly the extended-name-section index space: "labels are indexed in the order they appear in
  the function body" (source order), which is *different* from the scoped label index a `br`
  uses.
* `setEnd()` records `labelNameIndex -> branchTarget` (the loop's **start** for a loop, otherwise
  the construct's **`end`**) into `labelNameTargets`.
* New public `Map<Integer, Address> getLabelTargets()` exposes the map to the name applier.

No existing context-register value is touched, so disassembly is byte-for-byte unchanged.

### `src/main/java/wasm/analysis/WasmNameApplyAnalyzer.java` (applier)

`applyLabelNames()` no longer writes the whole map as a comment. For each
`funcidx -> (labelidx -> name)` entry it now:

* looks the function up as before,
* asks the cached pre-analysis for its label targets (`state.getFunctionAnalysis(...)`,
  wrapped so a function the pre-analyzer could not analyse degrades to an empty map, never an
  exception),
* creates a real Ghidra label (`SourceType.IMPORTED`) at the target address via the existing
  `applyLabel()` (which never overwrites user symbols and skips duplicate names),
* keeps the old comment behaviour **only as a fallback** for names that cannot be resolved
  (unknown function index, label index past the last construct, or an unanalysable function),
  under the heading `WebAssembly label names (no address): ...`.

The class javadoc was updated accordingly.

### `test-scripts/probes_name_labels.py` (new, 3 probes)

* `L01_name_labels.wasm` — a function with a `block` (label 0), a `loop` (label 1) and an `if`
  (label 2), all branched to, plus a `.name` section naming all three.
* `L02_name_labels_bad_index.wasm` — the same body with an out-of-range label index (99) and an
  out-of-range function index (9). Negative: must not crash, must keep decoding.
* `L03_name_labels_malformed.wasm` — a malformed label subsection (declares 4 entries, carries
  1). Negative: must not crash, must keep decoding.

`test-scripts/probes_names.py` (N01/N02/N03) was **not** touched.

---

## 2. Evidence

### 2.1 Before (HEAD build: comment only)

Reverted the two Java files to `HEAD`, rebuilt/installed, then:

```
analyzeHeadless <proj> Before -import probes/L01_name_labels.wasm -import probes/L02_name_labels_bad_index.wasm \
  -scriptPath test-scripts -postScript DumpNames.java
```

```
NAMES program=L01_name_labels.wasm
NAMES BLOCK-COMMENT .module @ ram:80000000 :: WebAssembly module name: label_probe_module
NAMES FUNC-COMMENT labelled_func @ ram:80000016 :: WebAssembly label names: [0]=outer_block [1]=retry_loop [2]=maybe_if
NAMES SYMBOL labelled_func @ ram:80000016 source=IMPORTED ns=Global
NAMES program=L02_name_labels_bad_index.wasm
NAMES FUNC-COMMENT labelled_func @ ram:80000016 :: WebAssembly label names: [0]=outer_block [99]=ghost_label
NAMES SYMBOL labelled_func @ ram:80000016 source=IMPORTED ns=Global
```

There is **no** symbol at any label target — only the function name and a comment.

### 2.2 After (this change)

Rebuilt/installed the branch, then the same three probes with `DumpNames.java`,
`ListProgram.java` and `DumpDecomp.java`:

```
analyzeHeadless <proj> After -import probes/L01_name_labels.wasm -import probes/L02_name_labels_bad_index.wasm \
  -import probes/L03_name_labels_malformed.wasm -scriptPath test-scripts \
  -postScript DumpNames.java -postScript ListProgram.java -postScript DumpDecomp.java
```

**L01 — the names are now symbols at the branch targets:**

```
NAMES program=L01_name_labels.wasm
NAMES SYMBOL labelled_func @ ram:80000016 source=IMPORTED ns=Global
NAMES SYMBOL retry_loop   @ ram:80000019 source=IMPORTED ns=Global
NAMES SYMBOL maybe_if     @ ram:80000027 source=IMPORTED ns=Global
NAMES SYMBOL outer_block  @ ram:8000002d source=IMPORTED ns=Global
LISTING L01_name_labels.wasm
  function labelled_func @ ram:80000016 void labelled_func(void)
    ram:80000016  .locals
    ram:80000017  block blocktype=0x40      <- label 0 (outer_block)
    ram:80000019  loop blocktype=0x40       <- label 1 (retry_loop)
    ram:8000001b  i32.const 0x1
    ram:8000001d  br_if 0x8000002d          -> target 8000002d = outer_block
    ram:8000001f  i32.const 0x1
    ram:80000021  if blocktype=0x40         <- label 2 (maybe_if)
    ram:80000023  i32.const 0x2
    ram:80000025  br 0x8000002d             -> target 8000002d = outer_block
    ram:80000027  end                       <- maybe_if (if end)
    ram:80000028  i32.const 0x1
    ram:8000002a  br_if 0x80000019          -> target 80000019 = retry_loop
    ram:8000002c  end
    ram:8000002d  end                       <- outer_block (block end)
    ram:8000002e  end
SUMMARY functions=1 decompiled=1 failed=0 instructions=15 undefined_bytes=0
```

Every label symbol sits at exactly the address the branch instructions jump to
(`0x8000002d`, `0x80000019`, `0x80000027`) — i.e. these are real flow targets, not comments.
(The decompiled C is empty because the decompiler collapses this tiny void function; the symbol
is what the decompiler would render at the target if it emitted a `goto`. The branch operands in
the listing are the proof that the target addresses are real.)

**L02 — out-of-range indices are tolerated:**

```
NAMES FUNC-COMMENT labelled_func @ ram:80000016 :: WebAssembly label names (no address): [99]=ghost_label
NAMES SYMBOL labelled_func @ ram:80000016 source=IMPORTED ns=Global
NAMES SYMBOL outer_block  @ ram:8000002d source=IMPORTED ns=Global
LISTING ... same 15 instructions, all decoded ...
SUMMARY functions=1 decompiled=1 failed=0 instructions=15 undefined_bytes=0
```

Label 0 resolves to `outer_block`; label 99 (out of range) and func 9 (absent) are kept as the
comment fallback. No crash; the body decodes and decompiles.

**L03 — malformed label subsection:**

```
NAMES SYMBOL labelled_func @ ram:80000016 source=IMPORTED ns=Global   (no label symbols)
LISTING ... same 15 instructions, all decoded ...
SUMMARY functions=1 decompiled=1 failed=0 instructions=15 undefined_bytes=0
```

The subsection degrades to raw bytes (no label subsection), no labels are applied, no crash.

### 2.3 Probe / fixture gate

Full suite (build + install + 172 probes + fixture + real module):

```
$env:GHIDRA_INSTALL_DIR = "C:\Users\micro\AppData\Local\Temp\ghidra-h5"
$env:GHIDRA_HEADLESS_MAXMEM = "1500M"
.\test-scripts\check-local.ps1 -OutDir "$env:TEMP\ci-h6" -SkipBuild `
    -RealModule "D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm"
```

```
probes: 155 imported, 17 import failure(s); baseline has 172
SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0
SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156
OK: every probe matches the recorded baseline.
```

Fixture and real-module summaries are unchanged.

Fixture-validity gate:

```
python test-scripts/check-fixture-validity.py --generate --probes "$env:TEMP\h6-validity" \
  --wabt "C:\Users\micro\AppData\Local\Temp\spectest-tools\wabt-1.0.42\bin" \
  --binaryen "C:\Users\micro\AppData\Local\Temp\binaryen133\binaryen-version_133\bin" --update
python test-scripts/check-fixture-validity.py --generate --probes "$env:TEMP\h6-validity" \
  --wabt "C:\Users\micro\AppData\Local\Temp\spectest-tools\wabt-1.0.42\bin" \
  --binaryen "C:\Users\micro\AppData\Local\Temp\binaryen133\binaryen-version_133\bin"
```

```
probes: 172  valid: 99  wabt-gap: 36  unsupported: 26  invalid: 11
OK: every probe matches the recorded fixture classification (fixture-validity.json).
```

All three new probes are classified **`valid`** (wabt 1.0.42 does not implement id 3, so it warns
`unknown name subsection with id 3` but accepts the module; binaryen accepts it too). No
`--invalid`/`--unsupported` declaration was needed.

---

## 3. Baseline entries changed

Regenerated with `check-local.ps1 ... -Update` and
`check-fixture-validity.py ... --update` (never hand-edited).

`test-scripts/expected-results.json`:

* added `L01_name_labels.wasm` → `funcs=1 instrs=15 undefined_bytes=0 decompiled=1 decompile_failed=0 import_ok=true`
* added `L02_name_labels_bad_index.wasm` → `funcs=1 instrs=15 undefined_bytes=0 decompiled=1 decompile_failed=0 import_ok=true`
* added `L03_name_labels_malformed.wasm` → `funcs=1 instrs=15 undefined_bytes=0 decompiled=1 decompile_failed=0 import_ok=true`
* `probe_count`: 169 → **172**

No existing probe entry changed (`git diff` shows only the three additions and the count).
`fixture` and `real_module` are byte-identical.

`test-scripts/fixture-validity.json`: added the three probes, all `{"class": "valid"}`. No existing
entry changed.

---

## 4. What I did NOT do

* Did not edit `test-scripts/probes_names.py` or `gen_feature_probes.py` (N01/N02/N03 pass
  unchanged; N02 still matches N01 byte-for-byte).
* Did not change the module-name / type / field / tag comment behaviour.
* Did not add a label for the function's own implicit frame (the extended-name-section index
  space only covers labels written in the body — block/loop/if/try).
* Did not make the decompiler emit `goto`s in the probe C output: the probe functions are tiny
  and the decompiler collapses their control flow, so the C body is empty even though the label
  symbols exist at the real branch targets. Evidence is the symbol table + listing branch
  operands.
* Did not touch any other worktree/install, and did not push, merge, tag or touch other branches.
