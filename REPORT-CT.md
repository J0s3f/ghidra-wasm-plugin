# REPORT-CT - bounded C-stack guess provider + `cont` composite types

Branch `fix/cstack-conttypes` (based on main @ `8f2b67f`). Two correctness items:

* **Task A** - bound the `MemoryByteProvider` used by the C-stack guess provider (same bug class as
  the B3 fix).
* **Task B** - parse the stack-switching `cont <func typeidx>` composite type in the type section,
  update the stack-switching probes to declare real continuation types, add continuation-type
  probes, and re-record the fixture-validity manifest + probe baseline.

Nothing was pushed, merged or tagged. No file owned by the concurrent agents
(`WasmStackVariableAnalyzer.java`, `WasmEmulationInstructionStateModifier.java`,
`ghidra_scripts/spectest.py`, `test-scripts/spectest/run_emulate*.ps1`) was touched.

---

## Task A - bound the C-stack guess provider

`WasmPreAnalyzer.guessCStackGlobalForFunction` built `new MemoryByteProvider(program.getMemory(),
funcAddress)` with no end bound. `MemoryByteProvider(mem, start)` sizes itself from the *maximum
address of the whole `ram` address space*, not from the end of the block containing `start` - the
same defect the B3 fix corrected for `WasmAnalysis.getState()`. It is now bounded to the end of the
module image block containing the function address:

```java
Memory mem = program.getMemory();
MemoryBlock funcBlock = mem.getBlock(funcAddress);
ByteProvider provider = (funcBlock != null)
        ? new MemoryByteProvider(mem, funcAddress, funcBlock.getEnd())
        : new MemoryByteProvider(mem, funcAddress);
BinaryReader codeReader = new BinaryReader(provider, true);
```

Every function address is inside the single module image block (the loader creates one block at
`CODE_BASE = 0x80000000` holding the whole file), so its end is the correct bound.

### Why this is defensive (no probe added)

The guess reads only a few bytes at the *start* of a function (locals vector, then `global.get`),
which are inside the module. A read can only run past the module end if a body's locals vector is
malformed/oversized. In that case the address past the module end is **unmapped**, so the read
throws rather than returning wrong bytes:

* linear memories live at `N * MEMORY_STRIDE` (`MEMORY_STRIDE = 0x10000000`);
* memory 8's base is exactly `CODE_BASE`, so its block collides with the module image and is not
  created (`MODERN_WASM_GAPS.md` 2.3);
* the next mapped block is memory 9 at `0x90000000`, 256 MiB above `CODE_BASE`.

A module whose unbounded read reached a mapped block would therefore have to be ~256 MiB long - not
practical as a probe. So no probe reproduces a *wrong guess*; the change removes the latent
out-of-bounds read (and the associated error log) without altering the guess. The guess is proven
unchanged by the fixture, the real module and both decode gates below.

---

## Task B - `cont` composite types

### Encoding (verified, not assumed)

The stack-switching proposal's binary format ("Composite types") says:

```
| -0x23 | cont $ft | $ft : s33 |
```

i.e. byte `0x5D` followed by an **s33** type index (like a heap type). Verified against binaryen
`version_133`:

* `wasm-dis --all-features` accepts `0x5D 0x00` and prints `(type $1 (cont $0))`.
* With 65 function types, a `cont` type referencing index 64 is accepted when encoded `5D C0 00`
  (s33) and **rejected** when encoded `5D 40` (uleb): `invalid wasm heap type: -64`.
* wabt 1.0.42 rejects any `0x5D` with `unexpected type form (got -0x23)`.

### Changes

* `WasmGCType` - new `Kind.CONT`; the `0x5D` case reads an s33 type index (`LEB128::signed`) and
  records the continuation type. `getParamTypes()`/`getReturnTypes()` delegate to the referenced
  function type (a new `signatureSource()`), so a continuation type resolves to exactly the
  referenced signature - the pre-analyzer's `cont.new`/`cont.bind`/`resume`/`resume_throw`/
  `resume_throw_ref`/`switch` stack effects are unchanged. A byte-faithful listing (`gc_cont_type`)
  and `toString()` (`cont <idx>`) were added.
* `WasmTypeSection` - after the whole type section is parsed, `resolveContinuationTypes()` binds each
  CONT entry to the type index it references (forward references allowed). A missing/out-of-range
  index is left unresolved: the signature degrades to an empty tuple instead of throwing, so a
  malformed index does not crash the loader.

### No-regression evidence

All commands below ran in the pinned install (`ghidra-h3`). The environment's `JAVA_HOME` had to be
pointed at a supported JDK for the headless launcher (`C:\Users\micro\.jdks\temurin-25`; the default
Adoptium `jdk-25.0.4.101-hotspot` path is rejected by Ghidra's launcher), and a stray `wasm-dis`
process holding ~2 GB was killed - neither is a code change.

| check | command | before | after |
| --- | --- | --- | --- |
| probe gate | `check-local.ps1 -OutDir %TEMP%\ci-ct2 -SkipBuild -RealModule <rasterbator>` | `OK: every probe matches the recorded baseline.` (186) | `OK ...` (191) |
| fixture | (same run) | `functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0` | unchanged |
| real module | (same run) | `functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156` | unchanged |
| fixture validity (wabt+binaryen) | `check-fixture-validity.py --probes <dir> --wabt <wabt> --binaryen <bin>` | `OK` (186) | `OK` (191) |
| fixture validity (wabt only) | `check-fixture-validity.py --probes <dir> --wabt <wabt>` | `OK` (186) | `OK` (191) |
| spec-suite decode (`core`) | `run_spectest.ps1 -Subset core -SkipFetch` + `check-spectest.py --subset core` | `OK: subset 'core' matches spectest-expected.json.` | unchanged: `271 selected/imported/0`, `2747 functions`, `33222 instructions`, `428 undefined_bytes`, `0 decompile_failed` |

The spec-suite `core` run (271 real spec modules, 73 wast files) has **identical metrics**, which is
the strongest evidence that the type-section change is behaviour-preserving.

### Probe changes and metrics

`test-scripts/probes_stackswitch.py` (H01-H10):

* H01-H03 changed only their type index (a real `cont` type is declared and referenced); their
  instruction metrics are **identical** to before (`H01` 7, `H02` 9, `H03` 5), which directly shows
  the continuation resolution is unchanged.
* H04-H10 were additionally **restructured so the modules are valid under the proposal** - binaryen
  133 previously rejected them for a reason independent of the missing cont types: a `resume`
  handler `(on $t $l)` requires the target label to have the block type `[t1* (ref $ct)]` (the old
  probes branched to the function label, which has no continuation type), and `switch` requires the
  continuation's function type to take at least the continuation argument. Each is now wrapped in a
  properly typed block (fallthrough `unreachable`) or uses the function's own result; `H10` uses a
  `resume` with an empty handler vector so its `i32` result reaches the caller. This is what makes
  the class flip below possible.

`test-scripts/probes_conttypes.py` (new, owned by this workstream): CT01 valid `cont` type +
`cont.new` (`undefined_bytes=0`); CT02 `cont` type referenced by `resume` (signature from the
function type); CT03 `cont` type with an out-of-range index (accepted by the loader, signature
degrades - no crash); CT04 `cont` type with an absent index (module truncated - rejected cleanly);
CT05 `cont` type referencing index 64 (multi-byte s33 index).

### Changed baseline entries (`test-scripts/expected-results.json`, 186 -> 191 probes)

| probe | before | after |
| --- | --- | --- |
| `CT01_cont_new_valid.wasm` | (new) | `funcs=2 instrs=7 undefined_bytes=0 decompiled=2 decompile_failed=0 import_ok=true` |
| `CT02_cont_resume_signature.wasm` | (new) | `funcs=2 instrs=15 undefined_bytes=0 decompiled=2 decompile_failed=0 import_ok=true` |
| `CT03_cont_bad_index.wasm` | (new) | `funcs=2 instrs=7 undefined_bytes=0 decompiled=2 decompile_failed=0 import_ok=true` |
| `CT04_cont_absent_index.wasm` | (new) | `import_ok=false` (clean `EOFException`) |
| `CT05_cont_index_ge64.wasm` | (new) | `funcs=2 instrs=7 undefined_bytes=0 decompiled=2 decompile_failed=0 import_ok=true` |
| `H04_ss_resume.wasm` | `instrs=8` | `instrs=12` |
| `H05_ss_resume_handlers.wasm` | `instrs=11` | `instrs=15` |
| `H06_ss_resume_throw.wasm` | `instrs=9` | `instrs=13` |
| `H07_ss_resume_throw_ref.wasm` | `instrs=9` | `instrs=13` |
| `H09_ss_mixed.wasm` | `instrs=28` | `instrs=27` |

`H01` (7), `H02` (9), `H03` (5), `H08` (7) and `H10` (9) are unchanged. `funcs`,
`undefined_bytes`, `decompiled` and `decompile_failed` are unchanged for every H probe.

### Fixture-validity class flips (`test-scripts/fixture-validity.json`)

Re-recorded with:

```
python test-scripts/check-fixture-validity.py --generate \
  --probes <dir> \
  --wabt "C:\Users\micro\AppData\Local\Temp\spectest-tools\wabt-1.0.42\bin" \
  --binaryen "C:\Users\micro\AppData\Local\Temp\opencode\binaryen133\binaryen-version_133\bin" \
  --update --invalid CT03_cont_bad_index.wasm --invalid CT04_cont_absent_index.wasm
```

| probe(s) | class |
| --- | --- |
| `H01`, `H02`, `H04`, `H05`, `H06`, `H07`, `H08`, `H09`, `H10` | `unsupported` -> **`wabt-gap`** |
| `CT01_cont_new_valid.wasm`, `CT02_cont_resume_signature.wasm`, `CT05_cont_index_ge64.wasm` | (new) **`wabt-gap`** |
| `CT03_cont_bad_index.wasm`, `CT04_cont_absent_index.wasm` | (new) **`invalid`** (deliberately malformed) |
| `H03_ss_suspend.wasm` | `wabt-gap` (unchanged) |

Class counts: `valid 108 / wabt-gap 41 / unsupported 26 / invalid 11` ->
`valid 108 / wabt-gap 53 / unsupported 17 / invalid 13`. Note the `why` strings the recorder keeps
for the re-classified H probes still show the old wabt diagnostic (`unexpected opcode: 0xe0`); the
recorder preserves the previous `why` and only the class is authoritative, so this was left as the
tool produced it.

---

## What was NOT done

* No probe reproduces a *wrong C-stack guess* - see Task A above; the change is defensive.
* The `A05`/`A08`/`A10` "unimplemented opcode" probes (a different file, not owned here) still
  classify `unsupported`; they were left untouched.
* Nothing was pushed, merged or tagged.
* The environment's default `JAVA_HOME` (an Adoptium JDK-25 path Ghidra's launcher rejects) was not
  changed; a supported JDK was selected only for the local gate runs.
