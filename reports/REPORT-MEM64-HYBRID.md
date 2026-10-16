# Memory64 hybrid address spaces

2026-10-14; branch `feat/mem64-hybrid`; starting commit
`88552379f65eb6d5ce175798d57e73ace8244260`.
Worktree: `C:\Users\micro\worktrees\ghidra-wt-mem64`.
Pinned install: `C:\Users\micro\AppData\Local\Temp\ghidra-mem64`.

## Design as implemented

`MODERN_WASM_GAPS.md` item 11 was read before implementation. The original 32-bit
`memory` definition and i32 address arithmetic remain; `WebAssembly.slaspec` adds
`memory64 type=ram_space size=8` after the existing spaces, preserving their order.
Both spaces use `MEMORY_STRIDE=0x08000000` (128 MiB). Default ram, code, registers,
function/table/reference widths and default pointer layout are unchanged.

`ctx_mem64` remains bits 14-15, noflow: 0 selects i32/`memory`, 3 selects i64/`memory64`.
The existing `WasmFunctionAnalysis.setMemoryIndexContext` lookup already records each
scalar/SIMD/atomic instruction's memory index type, including imports and mixed memories.
It now also selects the space. String memory operands and `memory.discard` use that lookup.
Codes 1/2 keep their mixed destination/source roles for `memory.copy`.

| File | Change |
| --- | --- |
| `BasicOps.sinc` | 23 scalar constructors have gated i32/i64 variants; `loadaddr64`/`storeaddr64` export full 8-byte EAs |
| `VectorOps.sinc` | 22 SIMD memory constructors use matching spaces; lane loads use `loadaddr2_64`; default context guards balance numeric opcode patterns |
| `RelaxedSimdOps.sinc` | Default context guards balance all 20 relaxed-SIMD root patterns without changing their bodies |
| `AtomicOps.sinc` | 66 atomic constructors have both variants; cmpxchg/wait use `atomicaddr3_64`; notify/wait callothers carry full-width addresses |
| `StringOps.sinc` | 12 memory-taking callothers select pointer width; references/counts/results remain i32 |
| `WideArithOps.sinc` | `memory.discard` selects address and count widths |
| `WasmLoader.java` | Module-aware and explicit-index-type address overloads; blocks and active/passive data use the matching space; unsigned i64 offset bit patterns preserved; stride overflow rejected |
| `WasmNameApplyAnalyzer.java` | Memory/data names use module-aware addresses |
| `WasmEmulateInstructionStateModifier.java` | Decode instruction memidx instead of dividing high addresses by stride; check actual LOAD/STORE space; unsigned bounds and reconstructed scalar/SIMD/atomic EAs detect lost carries |
| `PcodeOpEmitter.java`, `InjectPayloadWasmMemoryCopy.java` | Constant-copy expansion with an i64 operand selects each side's space, width and stride independently; old all-i32 expansion retained |

Source comparison against `git show 88552379:...` verified 23 scalar + 22 SIMD + 66 atomic +
12 string i32 constructor bodies unchanged after removing the added `ctx_mem64=0` gate.
The i32 helpers, legacy three-argument loader mapping and all-i32 copy emitter keep their
original bodies. Fingerprints below confirm equivalent compiled i32 pcode, normalizing
only compiler-assigned unique offsets and numeric space IDs. A broader comparison also
verified all 534 original top-level constructors in those five files retain their original bodies
after removal of the added default guards.

## >4 GiB probe correction and before/after evidence

Both named probes originally declared >4 GiB memories but loaded address zero. Their
operands now actually exercise high EAs without adding instructions:

| Probe | Address expression | Before | After |
| --- | --- | --- | --- |
| `B8_04_mem64_over4g` | `0x100000020 + 0x10` | `memory:0x30`, address width 4 | `memory64:0x100000030`, width 8 |
| `B8_05_mem64_just_over4g` | `0 + 0x100000010` | `memory:0x10`, address width 4 | `memory64:0x100000010`, width 8 |

The same corrected bytes were measured against the original and hybrid builds.
`ListProgram.java pcode` and `DumpAll.java` observed:

```text
B8_04 before:
ram:80000026  i64.const 0x100000020
ram:8000002c  i32.load align=0x2 offset=0x10  (i64 index)
ACCESS space=memory address_bytes=4
return in_memory_00000030;
B8_04 after:
ram:80000026  i64.const 0x100000020
ram:8000002c  i32.load align=0x2 offset=0x10  (i64 index)
ACCESS space=memory64 address_bytes=8
return in_memory64_100000030;

B8_05 before:
ram:80000026  i64.const 0x0
ram:80000028  i32.load align=0x2 offset=0x100000010  (i64 index)
ACCESS space=memory address_bytes=4
return in_memory_00000010;
B8_05 after:
ram:80000026  i64.const 0x0
ram:80000028  i32.load align=0x2 offset=0x100000010  (i64 index)
ACCESS space=memory64 address_bytes=8
return in_memory64_100000010;
```

Each probe retains `funcs=1 instrs=4 undefined_bytes=0 decompiled=1 decompile_failed=0`.
No metrics/classifications were recut: both baseline JSON files are unchanged.
`ListProgram` adds pcode output only when explicitly given the `pcode` argument.

For original-build measurement, feature files were backed up under `%TEMP%\mem64-edits`,
the original scalar/loader files were restored temporarily using `git show HEAD:<path>`,
the pinned extension was rebuilt, and all feature edits were restored before proceeding.
The original installed build was used for the before gate/listings/fingerprints. It was
then replaced by the completed hybrid build.

## Commands and results

Commands ran in the designated worktree with PowerShell 7. `%TEMP%` for these runs was
`C:\Users\micro\AppData\Local\Temp`. Build shells set the following private settings path;
launch.properties also pins settings/cache/temp inside the designated install:

```powershell
$env:APPDATA = 'C:\Users\micro\AppData\Local\Temp\ghidra-mem64\settings'
```

Build and before gate (original implementation installed):

```powershell
.\test-scripts\build-install.ps1
.\test-scripts\run_probes.ps1 -Only 'B8_0[45]' -Detail -OutDir "$env:TEMP\mem64-before-corrected"
.\test-scripts\check-local.ps1 -SkipBuild `
  -GhidraDir 'C:\Users\micro\AppData\Local\Temp\ghidra-mem64' `
  -OutDir "$env:TEMP\mem64-baseline-gate" `
  -RealModule 'D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm'
```

Exit 0: **204 imported + 18 expected import failures = 222 matching probes**;
fixture `4/4/0/24/0`; real module `437/437/0/61658/156`
(functions/decompiled/failed/instructions/undefined_bytes).

Exact listing command was run twice, with `$phase` = `before` then `after`:

```powershell
$taskProject = "$env:TEMP\mem64-$phase-pcode"
New-Item -ItemType Directory -Force $taskProject | Out-Null
& 'C:\Users\micro\AppData\Local\Temp\ghidra-mem64\support\analyzeHeadless.bat' `
  $taskProject Detail `
  -import "$env:TEMP\mem64-before-corrected\probes\B8_04_mem64_over4g.wasm" `
  -import "$env:TEMP\mem64-before-corrected\probes\B8_05_mem64_just_over4g.wasm" `
  -scriptPath test-scripts -postScript ListProgram.java pcode -postScript DumpAll.java `
  -deleteProject *> "$env:TEMP\mem64-$phase-pcode.log"
```

The after command also passed `-postScript WasmFeatureReport.java` before `-deleteProject`.
Both runs exited 0; excerpts above are from these logs.

Hybrid assertion command (completed implementation installed):

```powershell
.\test-scripts\build-install.ps1
.\test-scripts\check-memory64-hybrid.ps1 -OutDir "$env:TEMP\mem64-assertions-balanced"
```

Exit 0; observed:

```text
HYBRID-MATRIX functions=246 accesses=358 passed
HYBRID-SIMD-PREFIX functions=41 passed
HYBRID-COPY three index-width pairs passed
HYBRID-EMU high_dynamic result=0x87654321 passed
HYBRID-EMU high_static result=0x87654321 passed
HYBRID-EMU high_store result=0x12345678 passed
HYBRID-EMU low64 result=0x11223344 passed
HYBRID-EMU low32 result=0x55667788 passed
HYBRID-EMU oob64 trap=out of bounds memory access passed
HYBRID-EMU overflow64 trap=out of bounds memory access passed
HYBRID-EMU overflow32 trap=out of bounds memory access passed
HYBRID-EMU high_signbit trap=out of bounds memory access passed
HYBRID-EMU functions=9 passed; loader high/unsigned/overflow checks passed
```

The 41-case SIMD-prefix fixture also passed both external oracles (exit 0). The commands
were invoked via Python `subprocess.run(..., timeout=10)`:

```text
wasm-validate.exe <TEMP>/mem64-assertions-balanced/fixtures/hybrid_simd_prefixes.wasm --enable-all
wasm-dis.exe <TEMP>/mem64-assertions-balanced/fixtures/hybrid_simd_prefixes.wasm --all-features -o <TEMP>/mem64-simd-prefixes.wat
```

Executables came from the pinned tool directories below. Both calls were timeout guarded.

The auxiliary fixtures are generated in private scratch outside the `gen_*.py`/`probes_*.py`
globs and the 222-probe baseline. The matrix covers every scalar/SIMD/atomic constructor and
12 string address variants in both index types. A further 41 functions check numeric/relaxed
SIMD shared LEB prefixes, including all 20 relaxed-SIMD operations. The mixed-memory emulation fixture verifies
loader active data in both spaces. High bytes are explicitly seeded in sparse emulator memory,
with different high/low values so wrapping is observable. The 128 MiB loader cap is unchanged.
Negative cases intentionally cause EmulatorHelper ERROR stack traces; the harness requires the
precise trap and checks pass markers rather than trusting headless's exit code alone.
Log: `%TEMP%\mem64-assertions-balanced\hybrid-check.log`.

Exact fingerprint command was also run before and after:

```powershell
python test-scripts/memory64-hybrid-fixtures.py "$env:TEMP\mem64-checks"
$taskProject = "$env:TEMP\mem64-$phase-fingerprints"
New-Item -ItemType Directory -Force $taskProject | Out-Null
& 'C:\Users\micro\AppData\Local\Temp\ghidra-mem64\support\analyzeHeadless.bat' `
  $taskProject Fingerprints -import "$env:TEMP\mem64-checks\hybrid_matrix.wasm" `
  -import test-scripts/fixtures/wasm_fixture.wasm `
  -import 'D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm' `
  -scriptPath test-scripts -postScript MemoryPcodeFingerprint.java -max-cpu 2 `
  -deleteProject *> "$env:TEMP\mem64-$phase-fingerprints.log"
```

Both exit 0. After the SIMD-pattern fix described below, the same command was rerun with
`$taskProject = "$env:TEMP\mem64-balanced-fingerprints"` and output
`$env:TEMP\mem64-balanced-fingerprints.log`. All fingerprints still match
(matrix excludes `m64_` functions):

| Input | Pcode operations | Identical before/after SHA-256 |
| --- | ---: | --- |
| `hybrid_matrix.wasm` | 1588 | `cf7da1809a50fd565fa3e6e0c3f14d69bae5b41d4b8ca79385a21c688e63e87d` |
| `wasm_fixture.wasm` | 45 | `8bb1575e22861873f79aab12fffa97d383bff73e87cf0451ca6fd47c3ef65526` |
| `rasterbator_rs_bg.wasm` | 93594 | `e6a9aa205fb69ac5b74db28655b39513d34a233afa4c1d3b3051706ed39f0f26` |

Final full gate command:

```powershell
.\test-scripts\check-local.ps1 `
  -GhidraDir 'C:\Users\micro\AppData\Local\Temp\ghidra-mem64' `
  -OutDir "$env:TEMP\mem64-gate" `
  -RealModule 'D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm'
```

The first complete hybrid gate had one mismatch: `14_relaxed_simd` reported one undefined byte
instead of zero; all other probe metrics and both fixture/real summaries matched. Detailed
listing showed its relaxed opcode failing and later bytes misdecoded. Ghidra's verbose
`SleighDebugLogger` showed the context-constrained `v128.load` root being chosen before
`i8x16.relaxed_swizzle`; its variable-length `opc2_0` subtable then rejected the actual
`0x80 0x02` opcode, without trying the remaining constructor. The numeric/relaxed roots now
carry the same explicit default `ctx_mem64=0` guard. The analyzer already gives every
non-memory instruction this default; only root-pattern precedence changes, not pcode bodies.

Commands after this fix:

```powershell
.\test-scripts\build-install.ps1
.\test-scripts\run_probes.ps1 -Only '14_relaxed_simd' -Detail -OutDir "$env:TEMP\mem64-relaxed-fixed"
.\test-scripts\check-memory64-hybrid.ps1 -OutDir "$env:TEMP\mem64-assertions-balanced"
```

The failing probe now reports `1/6/0/1/0` and lists `i8x16.relaxed_swizzle; drop; end` correctly.
The auxiliary harness and all three fingerprints passed again. The first failing full-probe
log is preserved at `%TEMP%\mem64-first-hybrid-probe-run.log`; the TEMP-only trace
is `%TEMP%\mem64-trace.log`. A complete full gate was then rerun on the fixed build.

Final rerun exit **0**. Every one of the **222 probes** matches the recorded baseline:
**204 imported / 18 expected import failures**; no per-probe metric differences. This includes
unchanged funcs/instrs/undefined_bytes/decompiled/decompile_failed for all i32-memory probes.

```text
SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0
SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156
probes: 204 imported, 18 import failure(s); baseline has 222
OK: every probe matches the recorded baseline.
```

Logs: `%TEMP%\mem64-gate\probe-run.log`, `fixture-run.log`, `real-run.log`;
console: `%TEMP%\mem64-gate-console.log`.
The final pinned install stamp names this exact worktree and extension zip,
SHA-256 `534541956BCB372E9888882565CF17148471142253D3AEB3A1E6A007E472EF49`.
`git diff 88552379 -- test-scripts/expected-results.json test-scripts/fixture-validity.json`
was empty.

An initial attempt was refused by the install preflight because an overlapping headless
measurement still held the private jar. Nothing was removed. After those processes exited,
the same command was rerun without overlap.

Both fixture-validity modes:

```powershell
.\test-scripts\spectest\fetch_spectest_tools.ps1 -ToolsDir "$env:TEMP\mem64-tools" -WabtOnly -Binaryen
python test-scripts/check-fixture-validity.py --generate --probes "$env:TEMP\mem64-vp" `
  --wabt "$env:TEMP\mem64-tools\wabt-1.0.42\bin" `
  --binaryen "$env:TEMP\mem64-tools\binaryen-version_133\bin" --timeout 10
python test-scripts/check-fixture-validity.py --generate --probes "$env:TEMP\mem64-vp-wabt" `
  --wabt "$env:TEMP\mem64-tools\wabt-1.0.42\bin" --timeout 10
```

Tools fetched and checksums verified: WABT 1.0.42 and Binaryen 133. Both checks exit 0:
**222 probes: 128 valid / 64 wabt-gap / 17 unsupported / 13 invalid**.
Full mode explicitly reports/honours all **13 recorded Binaryen `oracle_skip` cases**.
Binaryen ran only through the timeout-guarded validator, never unguarded wasm-dis.
Logs: `%TEMP%\mem64-validity-full.log`, `%TEMP%\mem64-validity-wabt.log`.

## Residual limits / open items

* **128 MiB materialisation** per memory remains. High data outside that prefix cannot be
  placed and produces a diagnostic. Decoding full addresses does not allocate large blocks.
* **128 MiB stride** remains. Memories of the same index type can alias beyond a stride; complete u64
  isolation per memory requires a different layout. A nonzero memory base reduces the
  available u64 coordinate range; the loader rejects stride overflow.
* i32 memory indices above 31 keep the legacy space/clamp limit.
* Raw pcode arithmetic is u32/u64. Emulator EA reconstruction traps lost carries; decompiled
  expressions are not a Wasm bounds-checking runtime. Existing declared-size saturation and
  post-store zeroing behavior remain.
* Bulk/string/wait/notify callothers retain existing emulator behavior coverage. No missing
  bulk/string/atomic-wait runtime is claimed. Auxiliary string cases verify decoding/widths;
  WABT does not implement those proposal opcodes.
* `MODERN_WASM_GAPS.md` item 11 and section 2.3 now distinguish fixed addressing from remaining
  cap/isolation limits. Baseline JSON files unchanged; no build outputs committed, no push/merge.

Implementation/test commit: `4671bfb5680392038ade35ef042e8653818786d1`.
Documentation/report committed separately after the same green gate. No required acceptance
item remains unresolved; the deliberate cap, stride and existing runtime-coverage limits above
remain. No push or merge was performed. `git diff --cached --check` passed before each commit;
final worktree cleanliness is verified with `git status --short` after the documentation commit.
