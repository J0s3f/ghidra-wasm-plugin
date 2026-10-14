# REPORT-R6-PADDEDMEMARG — padded (non-minimal) LEB memarg encodings corrupt instruction decoding

Branch: `fix/r6-padded-memarg` (worktree `ghidra-wt-r6-paddedleb`)
Pinned install: `C:\Users\micro\AppData\Local\Temp\opencode\ghidra-r6-paddedleb` (recorded in
`test-scripts/.ghidra-install`; every build/gate below used `test-scripts/build-install.ps1`, which
refuses any other install).
Review evidence (read-only, authoritative): `D:\code\Ghidra-WASM\build\release-review-sol\padded64.wasm`
(a valid padded `v128.load`: 26 bytes total, accesses memory 1 at offset 0; WABT 1.0.42 accepts it),
plus `padding.log` / `padding-details.log` (the mis-decoding) and `generate.py`.

## Verdict

Fixed. A valid padded (non-minimal) LEB encoding of the multi-memory memarg flag byte (flags value
64..127, e.g. `C0 80 80 80 00`) was matched by the *unflagged* multi-byte SLEIGH forms, which consumed
the memory index as the offset and misaligned every following instruction. The review fixture
`padded64.wasm` decoded as a 16-byte `v128.load align=0x40 offset=0x1` followed by nine bogus
`i64.div_u` and an `unreachable`, and emulation trapped with "out of bounds memory access"; the Java
pre-analyzer and SLEIGH disagreed about the instruction boundaries. After the fix the same fixture
lists as **one 26-byte `v128.load align=0x0 memidx=0x1 offset=0x0 (i64 index)`** reading `memory64`
at `0x08000000` (memory 1 at offset 0), the bogus instructions are gone, and emulation returns normally.

The review lead about the emulator's memarg read buffer was **real** and is fixed too: a fully padded
SIMD/atomic memarg instruction is 26 bytes, but `WasmEmulateInstructionStateModifier` re-parsed only 24
bytes, truncating the 10-byte offset LEB (`decodeULEB` → -1) and raising a spurious out-of-bounds trap
even with the SLEIGH fix in place (counterfactual reproduced, see below).

Full gate green: **222 probes all matching** (204 imported + 18 expected import failures),
fixture **4/4/0/24/0**, real module **437/437/0/61658/156**; hybrid matrix harness exits 0
(246 constructor functions, 9 emulation functions, 41 SIMD-prefix functions); the new
`test-scripts/check-memarg-padding.ps1` exits 0 (11 fixture functions verified: decode + memory
selection + emulation); the fixture-validity oracle gate (wabt 1.0.42) and the spec-suite core
subset both match their recorded baselines exactly.

## The defect

Multi-memory memarg (core spec, `binary/instructions.html#binary-memarg`):

```
memarg ::= align:u32 offset:u64                  if align < 2^6
         | flags:u32 memidx:u32 offset:u64       if 2^6 <= flags < 2^7
```

i.e. bit 6 of the **decoded value** of the alignment/flags field marks a memory index that precedes the
offset. The binary integer rules permit **non-minimal (padded) LEB encodings**: a u32 may be padded
with zero chunks up to 5 bytes (`0xC0 0x00` is a valid encoding of 64), a u64 up to 10 bytes.

In `data/languages/BasicOps.sinc` the `memalign` subtable matched the unflagged multi-byte LEB forms
(2..5 bytes) **without checking that bit 6 of the decoded value is clear**, and `memalign_mem` matched
only the single-byte flagged form (`0x40..0x7f`). A padded encoding of a flagged value therefore matched
an unflagged form: the flags LEB was consumed as the alignment, the following memidx LEB was consumed
as the offset, and everything after it misaligned. The Java pre-analyzer
(`WasmFunctionAnalysis.readMemarg`) decodes the full LEB value and range-checks it
(`flags >= 0x40 && flags < 0x80`), so it found the correct boundaries while SLEIGH did not — hence
the disagreement and the bogus listing.

Token fields (see `define token opbyte (8)` in `data/languages/WebAssembly.sinc`): `topbit = (7,7)` is
the LEB continuation bit, `v0..v9 = (0,6)` are the per-token 7-bit LEB chunks (v0 = first token's chunk,
v1 = second token's chunk, … — the positional names are how multi-token SLEIGH constructors bind
fields), `mflag = (6,6)` is bit 6 and `mlow = (0,5)` the low 6 bits of a token byte.

The review fixture `padded64.wasm` body (function `padded_memarg`, memory 1 is 64-bit indexed):

```
42 00                              i64.const 0
FD 80 80 80 80 00                  v128.load, sub-opcode padded to 5 bytes (= 0)
C0 80 80 80 00                     flags padded to 5 bytes = 0x40 (align 0, FLAGGED)
81 80 80 80 00                     memidx padded to 5 bytes = 1
80 80 80 80 80 80 80 80 80 00      offset padded to 10 bytes = 0
FD 1B 00                           i32x4.extract_lane 0
0B                                 end
```

Correct decode: one 26-byte `v128.load` (1 + 5 + 5 + 5 + 10), effective address
`0 + 0 + 1 * MEMORY_STRIDE(0x08000000)` = `0x08000000` in the `memory64` space (memory 1 at offset 0).

Mis-decode: the unflagged 5-byte form `topbit = 1 & v0; topbit = 1 & v1; topbit = 1 & v2; topbit = 1 &
v3; topbit = 0 & v4` matched `C0 80 80 80 00` (val = 0x40) because it never constrained `mflag`; the
memidx LEB `81 80 80 80 00` was then consumed by `memoffset` as offset = 1; the remaining 10 bytes of
the padded offset decoded as nine `i64.div_u` (`0x80`) and an `unreachable` (`0x00`); the EA was `1`
with **no** `memidx * MEMORY_STRIDE` term, so the emulator's bounds check (`checkMemoryBounds`,
memidx = 1 against the mis-decoded EA 1) wrapped `1 - 0x8000000` and trapped "out of bounds memory
access" (review `padding.log`).

### Before (reproduced with the pinned install, pre-fix build)

Exact commands (worktree `C:\Users\micro\.local\share\opencode\worktree\b64b36\ghidra-wt-r6-paddedleb`):

```
# 1. build the UNMODIFIED worktree into the pinned install
powershell -NoProfile -ExecutionPolicy Bypass -File test-scripts\build-install.ps1

# 2. import the review fixture and dump the listing (+ pcode)
$headless = "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-r6-paddedleb\support\analyzeHeadless.bat"
& $headless "$env:TEMP\r6-repro\project" R6Repro `
    -import "D:\code\Ghidra-WASM\build\release-review-sol\padded64.wasm" `
    -scriptPath "$PWD\test-scripts" -postScript ListProgram.java pcode -max-cpu 2 -deleteProject
```

Observed (matches the review's `padding-details.log` exactly):

```
LISTING padded64.wasm
  function padded_memarg @ ram:80000031 int padded_memarg(void)
    ram:80000031  .locals
    ram:80000032  i64.const 0x0
    ram:80000034  v128.load align=0x40 offset=0x1  (i64 index)      <-- 16 bytes (34..43), WRONG
      PCODE (unique, 0xb600, 8) INT_ADD (const, 0x1, 8) , (register, 0x50000000, 8)
      PCODE (register, 0x50000000, 16) LOAD (const, 0x431, 8) , (unique, 0xb600, 8)
      ACCESS space=memory64 address_bytes=8                         <-- EA 1, no memidx*stride
    ram:80000044  i64.div_u                                        <-- bogus x9 (44..4c)
    ram:8000004d  unreachable                                      <-- bogus
    ram:8000004e  i32x4.extract_lane 0x0
    ram:80000051  end
```

Emulation before the fix: the review's `padding.log` (its `ReviewRuntime.java` driving the same
fixture through the same emulator) reports `Emulation failure … checkMemoryBounds … out of bounds
memory access` — the trap is the mis-decode's missing `memidx * MEMORY_STRIDE` term (EA 1 checked
against memory 1, `1 - 0x8000000` wraps). After the fix, the same fixture emulated on the same
install with `-postScript EmulateExport.java padded_memarg` returns `STATUS ok`, `RETURN i32=0x0`.

## The fix

### 1. SLEIGH — `data/languages/BasicOps.sinc` (`memalign` / `memalign_mem`)

Both memarg families now exist in **every length a u32 LEB permits (1..5 bytes)**, split on the first
byte's `mflag` (bit 6 of the decoded value), which makes the families disjoint and the match exact:

* **unflagged `memalign`** — single byte (`topbit = 0 & mflag = 0`, unchanged) and multi-byte forms
  (2..5 bytes) that now additionally require **`mflag = 0` on the first token** (`topbit = 1 & mflag = 0
  & v0; …`), i.e. the decoded value keeps bit 6 clear. A padded encoding of a flagged value (64..127)
  no longer matches here.
* **flagged `memalign_mem`** — the single-byte form (`mflag = 1 & topbit = 0 & mlow`, unchanged) plus
  **new padded forms for 2..5 bytes**: first byte `topbit = 1 & mflag = 1 & v0` (its low 7 bits encode
  `0x40..0x7f`), every following byte a zero chunk (`topbit = 1 & vN = 0` … `topbit = 0 & vN = 0`).
  The exported `val` is the alignment *without* the flag in both forms: `v0 & 0x3f` for the padded
  forms (v0 = `0x40 | mlow`, so `v0 & 0x3f` = mlow — identical to the single-byte form's
  `val = (0 | mlow)`). `v0` is used because it is the proven positional binding for the first
  token's chunk (the same mechanism `ULeb128` uses).

`memoffset` (`ULeb128`, up to 10 bytes) and `memidx_label` (`ULeb128`) already accept padded encodings
and are untouched. The subtables are shared by scalar loads/stores (`BasicOps.sinc`), SIMD
loads/stores (`VectorOps.sinc`) and atomics (`AtomicOps.sinc`); string ops take a bare `memidx_label`
immediate (no memarg) and are unaffected. All callers keep the same exported-`val` semantics, so
the full gate and the hybrid matrix harness (which cover all of them) stay green.

### 2. Emulator — `WasmEmulateInstructionStateModifier.java`

Both memarg re-parse sites (`accessedMemoryIndex`, `checkMemoryBounds64`) read the instruction bytes
with `readBytes(emulate, instructionAddress, 24)`. The longest prefix they must parse is

```
opcode byte (0x28..0x3e, or 0xfd/0xfe)          1
padded u32 sub-opcode LEB after 0xfd/0xfe      ≤ 5
padded u32 flags/align LEB                     ≤ 5
padded u32 memidx LEB                          ≤ 5
padded u64 offset LEB                          ≤ 10
                                             ---
                                              26
```

so a fully padded SIMD/atomic memarg instruction (26 bytes) did not fit: `decodeULEB` hit the end of
the buffer while reading the offset and returned -1, which `checkMemoryBounds64` used as the u64 bit
pattern (`ea = dynamicBase + (-1)`), raising a **spurious** `out of bounds memory access` trap for a
perfectly valid instruction. Both sites now read `MAX_MEMARG_INSTRUCTION_BYTES = 26` (named constant
with the derivation in its comment). Scalar memargs (≤ 21 bytes) always fit; the 24-byte buffer was
already sufficient for `accessedMemoryIndex` (≤ 16 bytes), but both sites now share the one constant
that documents the worst case.

**Counterfactual (proof the emulator fix is real):** with the SLEIGH fix in place and the constant
temporarily set back to 24, rebuilding and re-running the same emulation of `padded64.wasm` traps
again — `STATUS Emulation stopped: out of bounds memory access` (failure reported at `ram:8000004e`,
i.e. during the 26-byte `v128.load`'s post-execute bounds check, whose 10-byte offset LEB starts at
byte 16 and needs bytes 16..25). With 26 it returns `STATUS ok`. The counterfactual build was reverted;
the shipped code has 26.

## After (fixed build)

Same commands as above, after editing the two files and re-running
`powershell -NoProfile -ExecutionPolicy Bypass -File test-scripts\build-install.ps1` (the installer
wipes `Ghidra\Extensions`, so the fresh `WebAssembly.sla` is compiled from the fixed sources on the
next import — no stale-language masking):

```
LISTING padded64.wasm
  function padded_memarg @ ram:80000031 int padded_memarg(void)
    ram:80000031  .locals
    ram:80000032  i64.const 0x0
    ram:80000034  v128.load align=0x0 memidx=0x1 offset=0x0  (i64 index)   <-- 26 bytes (34..4d)
      PCODE (unique, 0xbb00, 8) INT_ADD (const, 0x0, 8) , (register, 0x50000000, 8)
      PCODE (unique, 0xbc00, 8) INT_MULT (const, 0x1, 8) , (const, 0x8000000, 8)
      PCODE (unique, 0xbe00, 8) INT_ADD (unique, 0xbb00, 8) , (unique, 0xbc00, 8)
      PCODE (register, 0x50000000, 16) LOAD (const, 0x431, 8) , (unique, 0xbe00, 8)
      ACCESS space=memory64 address_bytes=8
    ram:8000004e  i32x4.extract_lane 0x0
    ram:80000051  end
```

One 26-byte load (`80000034` → next instruction `8000004e`), `align=0x0 memidx=0x1 offset=0x0`, ACCESS
space `memory64`, EA pcode `offset(0) + dynamic(0) + memidx(1) * 0x8000000` = `0x08000000` — memory 1
at offset 0, exactly as the review requires. The bogus `i64.div_u`/`unreachable` instructions are gone
and the boundaries agree with the Java pre-analyzer.

Emulation after the fix (`-postScript EmulateExport.java padded_memarg`, same install):
`STATUS ok`, `RETURN i32=0x0` — no trap (the review's `padding.log` recorded
`out of bounds memory access` for the same fixture before the fix).

## New regression check — `test-scripts/check-memarg-padding.ps1`

Standalone (same pattern as `check-memory64-hybrid.ps1`; deliberately **not** a `probes_*.py`/`gen_*.py`
generator, so the 222-probe baseline and the fixture-validity oracle gate are untouched):

* `test-scripts/memarg-padding-fixtures.py` — generates three fixtures into a private scratch dir:
  * `memarg_padding.wasm` (7 functions, wabt-valid): padded flagged scalar loads (flags padded to
    2 and to 5 bytes, offset padded to 10), a padded flagged `i32.store` + load-back at offset 4, a
    padded flagged `i32.atomic.load`, padded *unflagged* aligns (which must stay unflagged — no memidx
    consumed), and the plain single-byte flagged/unflagged forms as unchanged controls.
  * `memarg_padding64.wasm` (3 functions, wabt-valid): the review's v128 case — padded `0xfd`
    sub-opcode + fully padded flagged memarg = **26 bytes** (the emulator's worst case), a padded
    flagged scalar load on the 64-bit memory, and the plain single-byte SIMD control. Accesses land
    in `memory64` through the `(i64 index)` decoders.
  * `memarg_padding_lenient.wasm` (1 function, **deliberately wabt-invalid** — alignment hint 130):
    pins that a spec-invalid module still imports and still decodes as *unflagged* with the full
    multi-byte value (`align=0x82`), i.e. the "keep accepting spec-invalid modules" rule and the
    unflagged value reconstruction (`v1 << 7` with a non-zero chunk).
* `test-scripts/CheckMemargPadding.java` — per function asserts: the exact instruction sequence
  (mnemonic, byte length, align/memidx/offset operand text — i.e. boundaries and decode), the memory
  selection of every load/store (ACCESS space `memory`/`memory64`, address width 4/8, and the
  `memidx * MEMORY_STRIDE` `INT_MULT` present exactly for flagged forms), the static offset
  `INT_ADD`, and **execution** (emulated i32 result proves the effective address: which memory's
  bytes come back). Also asserts the `.memory1` block space per module.
* `test-scripts/check-memarg-padding.ps1 -OutDir <private dir>` — generates the fixtures, imports
  all three with the pinned install (`-noanalysis` + in-script analysis, like the hybrid harness),
  asserts the `MEMARG-PADDING … passed` lines and the headless exit code; **exits non-zero on any
  failure**.

Run (observed, exit 0):

```
.\test-scripts\check-memarg-padding.ps1 -OutDir "$env:TEMP\r6-check\run3"
MEMARG-PADDING-OK scalar_pad2 result=0x88776655
MEMARG-PADDING-OK scalar_pad5 result=0x88776655
MEMARG-PADDING-OK scalar_plain_flag result=0x88776655
MEMARG-PADDING-OK scalar_plain_unflag result=0x44332211
MEMARG-PADDING-OK scalar_unflag_pad result=0x44332211
MEMARG-PADDING-OK atomic_pad result=0x88776655
MEMARG-PADDING-OK store_pad result=0x12345678
MEMARG-PADDING memarg_padding.wasm functions=7 passed
MEMARG-PADDING-OK simd_pad_v128 result=0xccbbaa99
MEMARG-PADDING-OK scalar_pad_mem64 result=0xccbbaa99
MEMARG-PADDING-OK simd_plain result=0xccbbaa99
MEMARG-PADDING memarg_padding64.wasm functions=3 passed
MEMARG-PADDING-OK scalar_unflag_pad130 result=0x44332211
MEMARG-PADDING memarg_padding_lenient.wasm functions=1 passed
OK: padded memarg decode + emulation; log: …
```

(wabt 1.0.42 oracle status of the fixtures: `memarg_padding.wasm` VALID, `memarg_padding64.wasm`
VALID, `memarg_padding_lenient.wasm` INVALID by design — `error: invalid load alignment: 130`.)

### CI wiring (not applied — `.github/workflows/*` is out of scope for this fix)

`check-memory64-hybrid.ps1` is not wired into any workflow today; the same one-step addition wires
this check into `.github/workflows/probes.yml` (after "Run probe suite", the extension is already
installed; the script needs no build and uses only `python` + `pwsh`, both present on the runner):

```yaml
    - name: Padded memarg regression check
      run: |
        set -euxo pipefail
        export GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:?setup-ghidra did not export GHIDRA_INSTALL_DIR}"
        export GHIDRA_HEADLESS_MAXMEM=1500M
        pwsh -NoProfile -File test-scripts/check-memarg-padding.ps1 -OutDir "$RUNNER_TEMP/memarg-padding"
```

(`check-memarg-padding.ps1` uses `support/analyzeHeadless` (no `.bat`) on non-Windows, so unlike
`run_probes.ps1` it needs no Linux shim.)

## Verification (all observed on the pinned install, fixed build)

1. **Full gate** — `.\test-scripts\check-local.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-r6-paddedleb" -OutDir "$env:TEMP\r6-gate" -RealModule "D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm"`
   → exit 0:
   * probes: **222 all matching** (`probes: 204 imported, 18 import failure(s); baseline has 222` +
     `OK: every probe matches the recorded baseline.`) — no probe metric moved, no expected import
     failure started importing, no new rejection;
   * fixture `test-scripts/fixtures/wasm_fixture.wasm`: **4/4/0/24/0**
     (`SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0`);
   * real module `rasterbator_rs_bg.wasm`: **437/437/0/61658/156**
     (`SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156`).
2. **Hybrid memory64 harness** — `.\test-scripts\check-memory64-hybrid.ps1 -OutDir "$env:TEMP\r6-hybrid" -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-r6-paddedleb"`
   → exit 0: `HYBRID-MATRIX functions=246 accesses=358 passed`, `HYBRID-EMU functions=9 passed;
   loader high/unsigned/overflow checks passed`, `HYBRID-SIMD-PREFIX functions=41 passed`,
   `HYBRID-COPY three index-width pairs passed` — the shared scalar/SIMD/atomic/string memarg
   consumers are intact.
3. **New check** — `.\test-scripts\check-memarg-padding.ps1 -OutDir "$env:TEMP\r6-check\run3"` → exit 0
   (11 functions: decode boundaries/operands, ACCESS space + EA shape, emulated results — listing above).
4. **Review fixture** — lists as one 26-byte `v128.load align=0x0 memidx=0x1 offset=0x0 (i64 index)`
   in `memory64` at `0x08000000` (memory 1, offset 0); emulation `STATUS ok` (listing above).
5. **Emulator counterfactual** — fixed SLEIGH + 24-byte buffer ⇒ spurious out-of-bounds trap on the same
   fixture; fixed SLEIGH + 26-byte buffer ⇒ ok (both observed; the 24-byte build was reverted).
6. **Fixture-validity oracle gate** (the CI step from `probes.yml`, run locally with the pinned
   wabt 1.0.42) — `python test-scripts/check-fixture-validity.py --generate --probes
   "$env:TEMP\r6-validity\fixture-probes" --wabt "$env:TEMP\spectest-tools\wabt-1.0.42\bin"` → exit 0:
   `probes: 222  valid: 128  wabt-gap: 64  unsupported: 17  invalid: 13` +
   `OK: every probe matches the recorded fixture classification (fixture-validity.json).`
7. **Spec suite (core subset, the CI job from `spectest.yml`, run locally with the pinned wabt
   1.0.42 + spec testsuite)** — `.\test-scripts\spectest\run_spectest.ps1 -Subset core -MaxPerWast 10
   -MaxCpu 2 -ToolsDir "$env:TEMP\spectest-tools" -OutDir "$env:TEMP\r6-spectest" -GhidraDir "<pinned>"`
   → exit 0 (271 modules imported, 2747 functions, 33222 instructions, 428 undefined_bytes,
   2747 decompiled, 0 decompile failures), and `python test-scripts/check-spectest.py --summary
   "$env:TEMP\r6-spectest\summary.json" --subset core` → exit 0:
   `OK: subset 'core' matches spectest-expected.json.` — every metric identical to the recorded
   baseline, including the memarg-heavy wast files (`align`=10 modules, `load`, `store`, `memory`=10,
   `float_memory`=6, `memory_copy/fill/init/grow`, …).

## Residual limits

* **Spec-invalid flags values ≥ 128 with bit 6 set** (e.g. `C2 81 00` = 194) match *neither* family now:
  the multi-memory spec allows flags only in 64..127, so this is the specified split ("exclude flagged
  values — value bit 6 = 0 — from every unflagged multi-byte form"; flagged forms cover 64..127). Such
  modules **still import** — verified: a module whose memarg flags decode to 194 imports cleanly (the
  function is created; the memarg bytes no longer decode as a load, they disassemble as unrelated
  instructions/undefined bytes) — so there is no new rejection, but the pre-analyzer (which
  range-checks the value 64..127) and SLEIGH (undefined) disagree on those spec-invalid bytes: the
  same class of disagreement the defect had, now confined to invalid input. wabt rejects such modules
  (`invalid load alignment`).
* **Over-long LEBs** (a u32 align/flags LEB longer than 5 bytes, e.g. 6) are rejected by the binary
  integer rules ("integer too large") and match no form — unchanged from before (the old forms also
  capped at 5 bytes); the offset caps at 10 bytes as before.
* **Emulator short reads at block edges**: `readBytes` still returns fewer bytes (or null) when the
  instruction sits at the very end of the emulated `ram` block; the bounds check is then skipped, as
  before. The 26-byte buffer removes the *systematic* truncation for fully padded instructions, not
  this edge case.
* The **decode-oracle** CI step (wabt `wasm-objdump` + binaryen `wasm-dis` cross-check on the
  committed corpus modules `rust_plain` / `rust_simd128`) was not re-run (it needs the binaryen
  download; `wasm-dis` is never bare-run). The corpus modules are real Rust output with minimal LEB
  encodings, and the 222-probe gate + spec suite + real-module gate above cover the decoder
  empirically.
* The `align` value exported by `memalign`/`memalign_mem` is display-only (the stack-variable analyzer
  reads the *offset* operand); nothing else consumes it, so the padded forms' `val = v0 & 0x3f` is
  observationally identical to the single-byte form's `val = mlow`.

## Files changed

* `data/languages/BasicOps.sinc` — `memalign`: unflagged multi-byte forms require `mflag = 0` on the
  first byte; `memalign_mem`: new padded flagged forms for 2..5 bytes (`val = v0 & 0x3f`); comments
  rewritten to document both families, the token fields and the disjointness.
* `src/main/java/ghidra/program/emulation/WasmEmulateInstructionStateModifier.java` — new
  `MAX_MEMARG_INSTRUCTION_BYTES = 26` (with derivation); both memarg re-parse sites
  (`accessedMemoryIndex`, `checkMemoryBounds64`) read it instead of the literal 24.
* `test-scripts/memarg-padding-fixtures.py` — new (fixture generator, 3 modules).
* `test-scripts/CheckMemargPadding.java` — new (per-function decode/space/emulation assertions).
* `test-scripts/check-memarg-padding.ps1` — new (standalone check; exits non-zero on failure).
* `REPORT-R6-PADDEDMEMARG.md` — this report.

Not touched (as required): `.github/workflows/*`, `test-scripts/check-local.ps1`,
`test-scripts/expected-results.json`, `test-scripts/fixture-validity.json`, the 222-probe generators,
`D:\code\Ghidra-WASM`, other worktrees, `C:\Tools\ghidra_12.1.4_PUBLIC`.
