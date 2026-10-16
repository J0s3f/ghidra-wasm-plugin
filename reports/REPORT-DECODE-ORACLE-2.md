# Decode oracle (WABT + Binaryen) — implementation report

Branch: `feat/decode-oracle-2`. Workstream: "a WABT/Binaryen decode oracle
for the corpus, checked in CI" (REUSE_OPPORTUNITIES.md §5 step 4; the automation of
the manual cross-check in §1 that found exact function counts against binaryen
`wasm-dis` on rasterbator/rust_plain/rust_simd128).

## 0. Acceptance criteria (written before coding, per work order)

1. New comparison (`test-scripts/decode-oracle.ps1` + `test-scripts/check-decode-oracle.py`):
   imports each pinned module headlessly with the pinned install, runs WABT
   `wasm-objdump -d` and Binaryen `wasm-dis` on the same bytes, compares normalized
   function counts + per-function instruction counts (+ opcode-class histograms),
   records `test-scripts/decode-oracle-baseline.json` with a justified allow-list,
   exits non-zero on divergence.
2. CI wiring in `.github/workflows/probes.yml`: runs WABT **and** Binaryen comparisons
   (per integrator update: both decoders, not wabt-only); binaryen fetched pinned +
   checksum-verified; offline apart from the oracle downloads; reasonable runtime.
3. Robustness: per-module timeout for `wasm-dis`, `oracle_skip` honoured, never bare-run
   on malformed modules, deterministic output (sorting, stable JSON).
4. Evidence: green run pasted; caught-divergence demo (tampered baseline → non-zero exit
   + diff line, then restore).
5. Gates unchanged and green: full `check-local.ps1` (210 probes + fixture), existing
   `corpus-sweep.ps1` untouched and working.

## 1. Design

Three independent decoders of the same bytes, compared per module:

| Side | Source | Facts |
| --- | --- | --- |
| Plugin | headless import + new `test-scripts/DecodeOracleReport.java` (`ORACLE-FUNC` per function in entry-address order, `ORACLE-TOTAL`, `ORACLE-HIST`) | `funcs`, per-function `real = total − markers`, opcode histogram (first token of listing text) |
| WABT 1.0.42 | `wasm-objdump -d` | per-function flat instruction counts, opcode histogram |
| Binaryen version_133 | `wasm-dis --all-features` (timeout-guarded) | accept/reject verdict, top-level `(func` count, per-function folded-AST paren counts (baseline-pinned only) |

Checks per module (exit 1 on any): sha256 vs baseline; `funcs` agreement plugin ==
wabt == binaryen (a recorded `reject` verdict is itself the assertion, mirroring the
fixture-validity gate's `invalid` class); per-function `real` == wabt flat counts
index-aligned (**the** cross-engine decode check); histograms equal after recorded
`opcode-remap` allow entries; both sides' counts/hists also pinned against the baseline
(a same-value drift on both sides still fails); binaryen node counts vs baseline.

### Normalization (empirically derived, documented in `check-decode-oracle.py`)

- WABT prints `local[N..M] type=...` declaration lines: not instructions, skipped.
  Multi-line immediates (`i8x16.shuffle`) print continuation lines without `|`:
  belong to the previous instruction, ignored.
- Both engines print the function-closing `end` (and every block-closing `end`) as an
  instruction line — verified line-by-line on rust_simd128 — so no adjustment needed.
- The plugin additionally lists pre-analyzer marker pseudo-instructions (`.locals`,
  `.local`, `.case`, …); `real = total − markers` is the comparable figure (same
  distinction as MODERN_WASM_GAPS.md §2.4 for the `instrs` metric).
- Mnemonics turned out to be text-identical on the valid modules (e.g. `local.get`,
  `v128.load`, `i32x4.add`, `end`); only operands are formatted differently, so the
  first-token histogram compares directly. The one label-level divergence (minrepro)
  is allow-listed, not special-cased.

### Oracle set

The three `committed` modules from `test-scripts/corpus/manifest.json`
(`minrepro_a_i32.wasm`, `rust_plain.wasm`, `rust_simd128.wasm`): all offline in CI,
all import-free (function index == code index on every engine; the checker fails
otherwise rather than misaligning).

## 2. Commands run + observed results

Tools (local): pinned Ghidra `C:\…\Temp\ghidra-oracle-2`
(rebuilt+installed via `test-scripts\build-install.ps1`, stamp verified);
oracles under `C:\…\Temp\oracle-tools-2`
(`fetch_spectest_tools.ps1 -WabtOnly -Binaryen` → wabt 1.0.42, `wasm-dis version 133`).

```
pwsh test-scripts/decode-oracle.ps1 -WabtDir <wabt>/bin -BinaryenDir <binaryen>/bin `
    -WorkDir <temp>\oracle-run-2 -Update     # record baseline
pwsh test-scripts/decode-oracle.ps1 -WabtDir <wabt>/bin -BinaryenDir <binaryen>/bin `
    -WorkDir <temp>\oracle-run-2             # green check
```

Observed green run (full driver, both oracles):

```
== resolving oracle modules (3 module(s)) ==
-- [1/3] minrepro_a_i32 (34 bytes)   -> imported in 18s
-- [2/3] rust_plain (119118 bytes)   -> imported in 22,3s
-- [3/3] rust_simd128 (80655 bytes)  -> imported in 18,3s
modules: 3  oracles: wabt 1.0.42 + binaryen version_133
OK: every module matches the recorded decode baseline (decode-oracle-baseline.json).
DRIVER-EXIT:0
```

Headline numbers (baseline): rust_plain 72 funcs, **8542/8542** real instructions
plugin-vs-wabt with **identical per-function arrays** (incl. the 2149-instruction
function) and identical histograms (62 opcode classes); rust_simd128 2 funcs,
**26/26**; minrepro 1 func, 1/1 counts. Binaryen agrees on all function counts
(72, 2) and rejects minrepro (`[parse exception: popping from empty stack]`).
These reproduce the manual §1 numbers (8542, 26) exactly.

Caught-divergence demo: copied the baseline to temp, changed
`rust_simd128.wasm → wabt.per_func[0]` 8 → 7, re-ran the checker:

```
modules: 3  oracles: wabt 1.0.42 + binaryen version_133

1 problem(s):
  rust_simd128.wasm: wabt per-function counts diverge from the baseline:
    wabt:     [8, 18]
    baseline: [7, 18]

If the change is intended, re-record with --update (allow-list stays).
TAMPERED-EXIT:1
```

Tampered copy deleted afterwards; committed baseline untouched (verified `git diff`
shows only the intended allow-list addition). Note: the first version of the checker
compared only fresh-vs-fresh counts and passed the tampered baseline — fixed by also
pinning both sides against the recorded facts (this demo caught a real hole in the
first draft of the gate itself).

## 3. Baseline + allow-list

`test-scripts/decode-oracle-baseline.json` (oracles: wabt 1.0.42, binaryen
version_133): per module sha256, `funcs`, wabt `{funcs, per_func, total, hist}`,
plugin `{funcs, per_func_real, total_real, markers, hist}`, binaryen
`{verdict, funcs, per_func_nodes}` or `{verdict: reject, why}`.

One allow-list entry (`minrepro_a_i32.wasm`, `opcode-remap` plugin `unreachable` →
wabt `end`, count 1): minrepro is a deliberately invalid module — empty body with a
value-returning type. Binaryen rejects it (`popping from empty stack`) and our own
pre-analyzer logs `ValidationException: pop from empty stack`; our lenient loader
contains the undecodable body as one `unreachable` placeholder (the documented
"bogus `unreachable` at the locals-count byte" containment, MODERN_WASM_GAPS.md
§6.1), while `wasm-objdump -d` prints the raw `end` byte without validating. Counts
agree (1 == 1); only the opcode label differs. Binaryen side needs no allow-list:
its `reject` verdict is recorded and asserted.

## 4. CI wiring

`.github/workflows/probes.yml`: the existing fetch step is now `Fetch oracles
(wabt + binaryen)` (`-WabtOnly -Binaryen`), and a new `Decode oracle` step runs
`decode-oracle.ps1` with both `-WabtDir` and `-BinaryenDir` after the
fixture-validity gate. Runtime ≈ 3 small headless imports (~1 min) + seconds of
oracle time. `fetch_spectest_tools.ps1 -Binaryen` downloads the pinned
`binaryen-version_133` tarball per host OS with hard-fail sha256
(Windows `17a2cb…84995b`, Linux `2dc9c7…a37489`, both downloaded and hashed
2026-10-14) and verifies `wasm-dis --version`. The driver is Linux-clean (same
launcher lookup as `run_probes.ps1`; `Join-Path` everywhere; `python3` with
`python` fallback). Bash-quoting pitfall avoided: the new CI step uses `-File`
with bash variables (`$GHIDRA_INSTALL_DIR`, `$RUNNER_TEMP`), not `$env:`.

## 5. Limitations / open items

- Oracle set is the 3 committed modules only (import-free by construction). Larger
  corpus modules (rasterbator, npm packages) are not pinned — they need network and
  longer CI time; extending the set is a manifest/`--select` one-liner once wanted.
  Modules *with* imports would need funcidx-offset handling in the wabt parser
  (currently fails loudly instead of misaligning).
- Binaryen comparison is function counts + validity + node-count regression pin, never
  flat-instruction equality: `wasm-dis` prints folded AST and invents scratch locals
  (REUSE_OPPORTUNITIES.md §4) — a deliberate, documented scope limit.
- `DecodeOracleReport.java` sorts functions by entry address; on modules with import
  stubs the index mapping is unverified (see above).
- The Linux binaryen tarball hash was pinned by downloading (not by executing — no
  Linux host here); first green CI run confirms it.
- `check-local.ps1` real-module leg (`rasterbator_rs_bg.wasm`, external bytes) could
  not run here — those bytes are not in this sandbox; the leg self-skips without a
  log. The oracle covers two real modules against two engines instead.
- Two checker bugs found by testing and fixed: `ORACLE-HIST(.*)$` without
  `re.MULTILINE` only matched on the log's last line; `--update` swallowed problem
  details.

## 6. Files changed/added

- Added `test-scripts/DecodeOracleReport.java` (machine-readable per-function decode facts).
- Added `test-scripts/check-decode-oracle.py` (stdlib-only three-engine comparison gate).
- Added `test-scripts/decode-oracle.ps1` (headless-import driver; pin-aware, Linux-clean).
- Added `test-scripts/decode-oracle-baseline.json` (recorded from real runs + 1 justified allow entry).
- Extended `test-scripts/spectest/fetch_spectest_tools.ps1` (`-Binaryen` switch, pinned+verified).
- Extended `.github/workflows/probes.yml` (fetch both oracles; new decode-oracle step).
- Untouched: `check-local.ps1`, `corpus-sweep.ps1`, `expected-results.json`,
  `fixture-validity.json`, all 210 probes + fixture + real-module expectations.
