# Decode oracle (Mistral): "our decode matches a second engine on real modules" as a checked property

Workstream: WABT/Binaryen decode oracle for the corpus, checked in CI.
Branch: `feat/decode-oracle-mistral`. Work order step 4 / `REUSE_OPPORTUNITIES.md` section 1.

## Goal

An earlier manual cross-check found exact function counts against binaryen `wasm-dis` on
rasterbator/rust_plain/rust_simd128 and byte-exact instruction starts against WABT
`wasm-objdump -d` on the reference module. This workstream turns that into a **checked**
property: a comparison that runs in CI on a pinned, offline-available module set, comparing
the plugin's per-function decode against **two** independent reference decoders (WABT
`wasm-objdump` AND binaryen `wasm-dis`), exiting non-zero on any divergence.

## Design

Three new files plus a CI wiring change and a baseline:

| File | Role |
| --- | --- |
| `test-scripts/DecodeOracleReport.java` | Ghidra headless script. Prints per-program, per-defined-function **real** instruction counts, a normalized mnemonic histogram, and body/import totals. "Real" = wasm instructions excluding the pre-analyzer's marker pseudo-instructions (mnemonics beginning with `.`: `.locals`/`.local`/`.case`/`.default` — `MODERN_WASM_GAPS.md` 2.4). Does **not** decompile, so it is fast. |
| `test-scripts/decode-oracle.ps1` | PowerShell driver (mirrors `corpus-sweep.ps1`). Seeds the pinned, committed, valid corpus modules from `test-scripts/corpus/modules/`, verifies every sha256 against `test-scripts/corpus/manifest.json`, imports each module headlessly with the pinned Ghidra install running `DecodeOracleReport.java`, then invokes the checker. |
| `test-scripts/check-decode-oracle.py` | Python checker (mirrors `check-fixture-validity.py`). Runs WABT `wasm-objdump -d` + `-x` and binaryen `wasm-dis --all-features` (timeout-guarded) on the same modules, parses all three engines' outputs, cross-checks them against each other **and** against the recorded baseline, and exits non-zero on any divergence. `--update` re-records the baseline (refusing to record from a disagreeing run). |
| `test-scripts/decode-oracle-baseline.json` | The machine-checked baseline (recorded from a real run, never hand-written): per-module agreed facts, the per-fact list of oracles that produced each comparison, and the normalization note. |
| `test-scripts/spectest/fetch_spectest_tools.ps1` | Extended with a `-Binaryen` switch: a pinned, checksum-verified binaryen `version_133` fetch (per-OS x86_64 tarball, Windows + Linux). The existing `-WabtOnly` call is unchanged. |
| `.github/workflows/probes.yml` | Two new steps in the `probes` job: fetch binaryen, then run the decode oracle. |

### Pinned module set (offline in CI)

`rust_plain` + `rust_simd128` — both `v8: valid`, both `committed` under
`test-scripts/corpus/modules/`, so CI needs no downloads beyond the oracles. Together they
cover MVP (`rust_plain`, 72 bodies) and SIMD (`rust_simd128`, 2 bodies using `v128`).
`minrepro_a_i32` is **excluded**: it is deliberately invalid (`v8: invalid`; `wasm-validate`
rejects it with "type mismatch in implicit return"), so no reference decoder produces a decode
to compare against. (It remains in the corpus sweep / fixture-validity gate, where it belongs.)

### Facts compared, and which oracle produces each

| Fact | Oracles | Meaning |
| --- | --- | --- |
| `bodies` | plugin, wabt, binaryen | defined-function count (3-way) |
| `imports` | plugin, wabt, binaryen | imported-function count (3-way) |
| `real_instrs` | plugin, wabt | total real wasm instructions |
| `per_body_instrs` | plugin, wabt | per-function real instruction count, aligned by body ordinal |
| `opcode_histogram` | plugin, wabt | normalized mnemonic histogram |
| `binaryen_nodes_per_body` | **binaryen only** | **REGRESSION PIN** (see below) |

Binaryen is not byte-faithful (`IRBuilder` restructures the body and invents `$scratch`
locals), so instruction counts are compared against WABT only (`REUSE_OPPORTUNITIES.md`
section 4). Binaryen contributes the two function counts above **and** one regression pin:

**`binaryen_nodes_per_body` — a regression pin on binaryen's view, NOT an instruction count.**
For each top-level `(func ...)` definition in the `wasm-dis` output (a `(func` whose opening
paren sits directly inside `(module`, excluding `(func` inside `(type ...)` and
`(import ... (func ...))`), the checker counts the number of `(` characters **outside string
literals** from that opening paren through its matching close, aligned by body ordinal. This
pins the per-function folded-AST node counts binaryen prints. It is documented in the baseline
and the checker as a **regression pin only**: folded s-expressions are **not** flat
instructions and binaryen invents `$scratch` locals, so this fact must **never** be compared
for equality with `real_instrs` / `per_body_instrs` / `opcode_histogram`. (On `rust_plain` the
node total is 8549 vs 8542 real instructions — close but deliberately *not* equal, which is
exactly why the two metrics are kept separate.) Its purpose is to detect a change in binaryen's
view of the module: a corpus module update, or a binaryen version change, moves these counts and
fails the gate even though no instruction-level comparison involves binaryen.

### Normalization (WABT mnemonics differ from our SLEIGH listing text)

* An instruction's normalized mnemonic is the **first whitespace-delimited token** of the
  disassembly line, **lower-cased**; all operands/immediates are stripped. Our plugin already
  emits standard wasm mnemonics (`local.get`, `v128.load`, `i32x4.add`, `f32x4.extract_lane`,
  `end`, ...), which match WABT's first token after this normalization.
* The plugin's pre-analyzer **marker** pseudo-instructions (mnemonics beginning with `.`) are
  excluded from real-instruction counts and histograms.
* WABT's **locals-declaration** lines are not instructions and are excluded. WABT renders a
  function's locals as one line per contiguous same-type group: a single local is
  `local[2] type=v128`, a run is `local[1..3] type=i32`. (An earlier draft of the checker only
  excluded `local[N]`; the range form `local[N..M]` was the one bug the real-module run caught.)
* WABT's **empty-mnemonic continuation lines** (a multi-byte instruction whose bytes overflow
  onto a second `| ` line) are excluded.
* WABT function headers are `<addr> func[N]:` for an unnamed function (a stripped module has
  no `.name` section) and `<addr> func[N] <name>:` for a named/exported one; the name is
  optional. Body ordinal = order of appearance in the Code Disassembly = the plugin's
  address-sorted body order.

### Allow-list

`decode-oracle-baseline.json` carries a per-module `allow_list` for known/intentional
divergences (each entry `{"wabt": X, "plugin": Y, "reason": ...}` renames a WABT mnemonic to
its plugin equivalent before comparing histograms). **The allow-list is empty for every
module**: after the normalization above, the plugin and WABT histograms match exactly on all
three modules tested (rust_plain, rust_simd128, and the real reference module), so no
divergence needed to be excused. A future systematic mnemonic difference would be added here
with a justification, never silently.

## Exact commands run + observed results

Tools fetched with the extended script (checksum-verified, recorded from the run):

```
pwsh test-scripts/spectest/fetch_spectest_tools.ps1 -ToolsDir <tools> -WabtOnly -Binaryen
# wabt      : 1.0.42
# binaryen  : wasm-dis version 133 (version_133)
# sha256 ok: 17a2cbeac6b5693c5fbafab3838d3c65fd9c1eb38b05f5baec6c657e8c84995b   (windows x86_64)
# sha256 ok: 2dc9c7813f5375db93d96ead4b78222fcc3e2677bbb832297af4797782a37489   (linux x86_64)
```

### 1. Record the baseline (green run, pinned set)

```
pwsh test-scripts/decode-oracle.ps1 \
    -WabtDir <tools>/wabt-1.0.42/bin -BinaryenDir <tools>/binaryen-version_133/bin \
    -CorpusDir <corpus> -WorkDir <work> -Update
```

Observed:

```
== resolving pinned decode-oracle modules (2) ==
  seeded rust_plain from committed modules/rust_plain.wasm
  rust_plain  119118 bytes  sha256 ok
  seeded rust_simd128 from committed modules/rust_simd128.wasm
  rust_simd128  80655 bytes  sha256 ok
-- [1/2] plugin decode rust_plain
   -> bodies=72 imports=0 real=8542  (20.1s)
-- [2/2] plugin decode rust_simd128
   -> bodies=2 imports=0 real=26  (17.3s)
== check-decode-oracle.py ==
== rust_plain (rust_plain.wasm) ==
   bodies plugin=72 wabt=72 binaryen=72   real_instrs plugin=8542 wabt=8542
== rust_simd128 (rust_simd128.wasm) ==
   bodies plugin=2 wabt=2 binaryen=2   real_instrs plugin=26 wabt=26

updated test-scripts/decode-oracle-baseline.json (2 module(s))
DRIVER EXIT: 0
```

### 2. Green check (no `--update`) — the acceptance run

```
pwsh test-scripts/decode-oracle.ps1 -WabtDir <wabt/bin> -BinaryenDir <bin/bin> \
    -CorpusDir <corpus> -WorkDir <work>
```

Observed (exit 0):

```
== rust_plain (rust_plain.wasm) ==
   bodies plugin=72 wabt=72 binaryen=72   real_instrs plugin=8542 wabt=8542   binaryen_nodes bodies=72 total=8549
== rust_simd128 (rust_simd128.wasm) ==
   bodies plugin=2 wabt=2 binaryen=2   real_instrs plugin=26 wabt=26   binaryen_nodes bodies=2 total=33

OK: every module's decode matches the baseline and the engines agree (decode-oracle-baseline.json).
DRIVER EXIT: 0
```

Every compared fact agrees across the engines **and** matches the baseline: bodies (3-way),
imports (3-way), total real instructions, the full per-body instruction-count vector, the
normalized opcode histogram (73 mnemonics on rust_plain, 11 on rust_simd128), **and** the
binaryen node-count regression pin (72 entries / total 8549 on rust_plain; 2 entries /
total 33 on rust_simd128).

### 3. Divergence demo (the oracle actually checks something)

Perturb one expected count in the baseline (`rust_simd128.bodies` 2 -> 3), re-run the checker
against the same artifacts, then restore:

```
# baseline rust_simd128.bodies 2 -> 3
python3 test-scripts/check-decode-oracle.py --artifacts <work> --wabt <wabt/bin> \
    --binaryen <bin/bin> --baseline test-scripts/decode-oracle-baseline.json
# ...
1 divergence(s) - the decode oracle does not match the baseline:
  rust_simd128.bodies: baseline drift -> expected 3, engines agree on 2
CHECKER EXIT (perturbed): 1
# restore baseline
python3 test-scripts/check-decode-oracle.py --artifacts <work> --wabt <wabt/bin> \
    --binaryen <bin/bin> --baseline test-scripts/decode-oracle-baseline.json
# OK: every module's decode matches the baseline and the engines agree (...).
CHECKER EXIT (restored): 0
DEMO RESULT: perturbed=1 restored=0 (want 1 then 0)
```

The gate exits non-zero and prints the diff line when the decode does not match the baseline,
and returns to green once restored.

The same was demonstrated against the **binaryen node-count regression pin**: perturb one
pinned node count in the baseline (`rust_simd128.binaryen_nodes_per_body[0]` 11 -> 12),
re-run, then restore:

```
# baseline rust_simd128 binaryen_nodes_per_body[0] 11 -> 12
python3 test-scripts/check-decode-oracle.py --artifacts <work> --wabt <wabt/bin> \
    --binaryen <bin/bin> --baseline test-scripts/decode-oracle-baseline.json
# ...
1 divergence(s) - the decode oracle does not match the baseline:
  rust_simd128.binaryen_nodes_per_body: baseline drift -> expected [12, 22], engines agree on [11, 22]
CHECKER EXIT (perturbed): 1
# restore baseline
# OK: every module's decode matches the baseline and the engines agree (...).
CHECKER EXIT (restored): 0
DEMO RESULT: perturbed=1 restored=0 (want 1 then 0)
```

The pin is binaryen-only, so "engines agree on [11, 22]" is binaryen's own pinned value; a
moved node count (module update or binaryen version change) fails the gate with the diff line.

### 4. Extra local evidence: the real reference module (not in the CI set)

`rasterbator_rs_bg.wasm` is not committed (it lives outside the repo), so it is **not** in the
CI pinned set, but running the oracle on it locally exercises the **non-zero import** path
(39 imports) and the **stripped-module** (unnamed-function) WABT header path, neither of which
the committed set covers. Run with a throwaway baseline:

```
pwsh test-scripts/decode-oracle.ps1 -Modules rasterbator_rs_bg \
    -WabtDir <wabt/bin> -BinaryenDir <bin/bin> -CorpusDir <corpus3> -WorkDir <work3> \
    -Baseline <tmp-baseline> -Update        # then again without -Update
```

Observed (exit 0):

```
-- [1/1] plugin decode rasterbator_rs_bg
   -> bodies=398 imports=39 real=60556  (35.6s)
== rasterbator_rs_bg (rasterbator_rs_bg.wasm) ==
   bodies plugin=398 wabt=398 binaryen=398   real_instrs plugin=60556 wabt=60556

OK: every module's decode matches the baseline and the engines agree (...).
CHECK EXIT: 0
rasterbator_rs_bg: bodies=398 imports=39 real_instrs=60556 per_body_len=398 histo_keys=149 allow_list=0
```

This matches the known reference baseline exactly: **437 functions = 39 imports + 398 bodies,
60,556 real instructions** (`REUSE_OPPORTUNITIES.md` section 1 / `MODERN_WASM_GAPS.md` 2.4), with
all 398 per-body instruction counts and a 149-mnemonic opcode histogram matching WABT exactly
(`allow_list=0`). The first attempt on this module caught a real checker bug — WABT renders
stripped-module functions as `func[N]:` with no `<name>`, which the header regex initially
required — fixed by making the name optional (see Normalization).

The **binaryen node-count parser** was additionally validated on this module's saved
`wasm-dis` output: it counts exactly 398 body `(func ...)` spans (`nodes_len == bodies == 398`),
correctly **excluding** the 39 `(import ... (func ...))` forms (whose inner `(func` sits at
paren-depth 2, not 1) and ignoring parentheses inside the import/export string literals
(string-stripping). Node total 62194 vs 60556 real instructions — distinct, as documented for
the regression pin.

## Baseline

`test-scripts/decode-oracle-baseline.json` (recorded by `--update` from the green run):

```
comparisons:
  bodies                 oracles=[plugin, wabt, binaryen]   defined-function count
  imports                oracles=[plugin, wabt, binaryen]   imported-function count
  real_instrs            oracles=[plugin, wabt]              total real wasm instructions
  per_body_instrs        oracles=[plugin, wabt]              per-function real instruction count
  opcode_histogram       oracles=[plugin, wabt]              normalized mnemonic histogram
  binaryen_nodes_per_body oracles=[binaryen]                 REGRESSION PIN: per-function folded-AST
                                                               node count (NOT an instruction count)
modules:
  rust_plain:    bodies=72 imports=0 real_instrs=8542  per_body_instrs=[43,99,12,...] (72)
                 opcode_histogram (73 keys)  binaryen_nodes_per_body=[48,110,13,82,24,...] (72, total 8549)  allow_list=[]
  rust_simd128:  bodies=2  imports=0 real_instrs=26    per_body_instrs=[8,18]
                 opcode_histogram (11 keys)  binaryen_nodes_per_body=[11,22] (total 33)  allow_list=[]
```

The `binaryen_nodes_per_body` baseline excerpt (rust_simd128), pinned by `--update`:

```json
"binaryen_nodes_per_body": [11, 22]
```

and rust_plain's first entries: `[48, 110, 13, 82, 24, ...]` (72 entries, total 8549). The
allow-list is empty for every module — the node pin needs no divergence excusing.

## CI wiring

`.github/workflows/probes.yml` (`probes` job) gains two steps after the fixture-validity gate:

1. **Fetch binaryen (decode-oracle second engine)** —
   `fetch_spectest_tools.ps1 -ToolsDir $RUNNER_TEMP/spectest-tools -WabtOnly -Binaryen`
   (adds the pinned, checksum-verified binaryen `version_133` to the same tools dir; wabt is
   already present and skipped).
2. **Decode oracle (plugin == wabt == binaryen)** —
   `decode-oracle.ps1 -WabtDir <wabt/bin> -BinaryenDir <bin/bin> -CorpusDir <tmp> -WorkDir <tmp>`.
   Runs the full comparison on the committed modules; exits non-zero on any divergence.

CI runtime: the two oracle downloads (wabt ~5 MB, binaryen ~111 MB) plus two small headless
imports and three oracle invocations per module. No other downloads; the modules are committed.

## Robustness

* `wasm-dis` is run **only** on the pinned, valid, committed modules (never on malformed
  input), and every oracle invocation is wrapped in a per-module timeout (default 300 s,
  `--timeout`), so a runaway `wasm-dis` (>20 GB observed historically) cannot hang the gate.
* The checker honours a per-module `skip` list (e.g. `["binaryen"]`) for anything that
  misbehaves, mirroring `oracle_skip` in `check-fixture-validity.py`; none is needed for the
  pinned set.
* Outputs are deterministic: the Java report sorts bodies by address and the histogram by
  mnemonic (a `TreeMap`); the checker sorts keys and the baseline is written with
  `sort_keys=True`.
* The driver verifies every module's sha256 against the corpus manifest before importing, so a
  corrupted/updated module cannot silently change the decode.

## Full gate (unchanged semantics)

`test-scripts/check-local.ps1` (build + 210 probes + fixture + real module) and the
fixture-validity gate are untouched and must stay green; the numbers must match. Result:
**see "Full gate result" below.**

## Limitations

* The CI pinned set has **0 imports** (both committed modules are standalone), so the CI
  import-count check is `0 == 0 == 0`; the non-zero import path is validated locally on the
  real reference module (39 imports, section 4) but is not exercised in CI. Committing a tiny
  valid module with an import would close this; it was left out to avoid changing the corpus
  manifest / corpus sweep.
* Per-function instruction **counts** and opcode **histograms** catch a missing/extra/mis-decoded
  instruction and a wrong-mnemonic-same-count, but not two different wrong mnemonics that
  happen to... (in practice the histogram is exact, so any mnemonic change shows up). A
  byte-exact instruction-start comparison (like the manual WABT check in
  `REUSE_OPPORTUNITIES.md` section 1) is stronger still but needs address alignment, which the
  SLEIGH listing does not expose in a directly comparable form; counts + histograms were chosen
  as the robust, cheap core.
* `binaryen_nodes_per_body` is a **regression pin**, not a decode-equality check: it detects a
  change in binaryen's view of the module (corpus module update, binaryen version change) and
  is never compared to the instruction counts/histograms — folded AST nodes are not flat
  instructions and binaryen invents `$scratch` locals (on `rust_plain` the node total 8549
  differs from the 8542 real instructions for exactly this reason).
* The oracle checks **decode agreement**, not decompiler output quality; decompile metrics stay
  covered by `expected-results.json` / `corpus-RESULTS.md`.
* Only x86_64 Windows + Linux binaryen assets are pinned (the two CI runners); other hosts would
  need their asset + checksum added to `fetch_spectest_tools.ps1`.

## Open items

* (Optional) commit a tiny valid import-bearing module so CI exercises a non-zero import count.
* (Optional) extend the pinned CI set with another committed valid corpus module if one is
  added later.
* (Optional, stronger) a byte-exact instruction-start comparison against WABT (address-aligned).

## Full gate result

`test-scripts/check-local.ps1 -RealModule <rasterbator_rs_bg.wasm>` (build + 210 probes +
fixture + real module) on this branch, final run — **exit 0**, numbers unchanged:

```
== DumpDecomp wasm_fixture.wasm -> fixture-run.log ==
SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0
== DumpDecomp rasterbator_rs_bg.wasm -> real-run.log ==
SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156
== check-results.py ==
probes: 192 imported, 18 import failure(s); baseline has 210
OK: every probe matches the recorded baseline.
FULL GATE EXIT: 0
```

This matches the documented baseline (`MODERN_WASM_GAPS.md` 2.4): 210 probes (192 imported + 18
expected import failures), the fixture, and the real module's `437/437/0/61658/156`. The
fixture-validity gate (`check-fixture-validity.py`) is untouched and still enforced by wabt in
CI. Nothing in this workstream changes gate semantics or the probe/fixture/real-module numbers.

Re-confirmed **after** adding the `binaryen_nodes_per_body` pin (which does not touch the gate's
code path): same clean `exit 0`, same numbers — `probes: 192 imported, 18 import failure(s);
baseline has 210` / `OK: every probe matches the recorded baseline`, fixture
`functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0`, real module
`functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156`.

Note on a false alarm during that re-run: the first re-run reported `200 problem(s)` / `MISSING`
probes. That was **not** a regression — `check-local.ps1`'s default `-OutDir`
(`$env:TEMP\wasm-probes-ci`) is a shared scratch path, and a concurrent agent's run
(`ghidra-dwarf-nem`) overwrote `probe-run.log` in it, so `check-results.py` read the wrong log.
Re-running with a private `-OutDir` (the run above) gave the clean, correct result; the private
`probe-run.log` references only this worktree's pinned install (`ghidra-oracle-mistral`). The
node-pin changes (`check-decode-oracle.py`, `decode-oracle-baseline.json`) are not on the gate's
path, so the gate numbers are unchanged by construction and confirmed unchanged by the re-run.
