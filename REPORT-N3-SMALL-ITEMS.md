# N3 Small Items – Ghidra-WASM 2.8.0 pre-release re-review

Branch: `fix/n3-small-items`  
Checkout: `C:\Users\micro\.local\share\opencode\worktree\b64b36\ghidra-wt-n3-small`  
Pinned install: `C:\Users\micro\AppData\Local\Temp\opencode\ghidra-n3-small` (from `test-scripts\.ghidra-install`)  
Scope: the four smaller findings of the 2.8.0 re-review (README stale claims, cleanup-test relative `-OutDir`, release push-overwrite policy, B03e block extent assertion). The pre-release blockers N1 (cache) and N2 (call-store gate) are owned by other lanes and were not touched here.

## 1. README.md stale claims

Finding: README.md still listed as open limitations items fixed in 2.8.0:
custom page sizes ("fixed at 64 KiB"), `ref.null` abstract heap-type numerical printing,
multi-byte `try`/`try_table` block signatures, and the extended-const `Data markup conflict`
warning.

Fix: removed those four stale bullets from the "Limitations and Known Bugs" summary, and reconciled
the list with RELEASE_NOTES.md's "Known open items":
- kept 128 MiB materialisation cap/stride (now also notes that same-index-type memories can alias
  beyond a stride and that i32 memory indices above 31 exceed the legacy 32-bit space);
- kept `br_table large` (10000) residual, shared-everything threads, component-model semantics,
  struct-synthesis v1;
- kept cosmetic listings, reworded to the actual remaining cosmetic gap (`blocktype=-0xNN` on
  `block`/`loop`/`if`/`try`/`try_table` and the `ht=` operands of `ref.test`/`ref.cast`/
  `br_on_cast*` print numerically; `ref.null` abstract heap types now print by name);
- updated the probe count references from 201 to 223.

Files: `README.md`.

Observed checks: `rg`/`Select-String` no longer matches the stale strings in README:
`fixed at 64` / `block signatures` / `Data markup` removed from the limitations section; only
intentional non-limitation references remain (`ref.null` in feature list, `wrap` in the memory64
"documented wrap above" note).

## 2. Cleanup test relative `-OutDir` false negative

Finding: `test-scripts/test-build-install-cleanup.ps1` built `$nestedTargetDir` from a (possibly
relative) `$isolatedRoot`, while `Remove-ShadowingWasmExtensionCopies` records version directories via
`Get-ChildItem.FullName` (always absolute), so the literal equality check at the "sweep sees the
nested isolated-install layout" assertion failed on a relative `-OutDir` even though cleanup worked.

Fix: resolve `$nestedTargetDir` with `Resolve-Path` when constructing it, so both sides are absolute
and a relative `-OutDir` compares correctly.

Files: `test-scripts/test-build-install-cleanup.ps1` (line ~177).

Observed results:
- Absolute: `pwsh -NoProfile -File test-scripts/test-build-install-cleanup.ps1 -OutDir "$env:TEMP\n3-cleanup-abs"`
  -> exit 0, `PASS: the settings sweep removes only the selected installation's copy (mock trees under ...)`.
- Relative: `pwsh -NoProfile -File test-scripts/test-build-install-cleanup.ps1 -OutDir "build\cleanup-test-rel"`
  (run from the repo root) -> exit 0, `PASS: ... (mock trees under build\cleanup-test-rel)`.
- The relative run's mock tree was removed afterwards (`build\cleanup-test-rel` no longer exists).

## 3. Release workflow push-overwrite policy

Finding: `.github/workflows/release.yml` set `OVERWRITE=1` unconditionally on every `push` event, so a
deliberately moved tag (or a same-tag rerun against a moved tag) could overwrite an existing release's
assets without an explicit decision.

Fix: on `push`, when the release already exists, read its recorded target commit with
`gh release view "$TAG" --json targetCommitish`, resolve it to a commit SHA (directly if it is 40 hex,
otherwise via `gh api repos/$REPOSITORY/commits/$EXISTING_TARGET`), and compare it to the verified tag
commit `$TAG_SHA`:
- match -> allow the idempotent asset replacement (`OVERWRITE=1`, `gh release upload ... --clobber`);
- mismatch (moved tag) -> refuse with a clear `::error::` telling the maintainer to re-dispatch
  manually with `allow_overwrite=true`.
- if the release does not yet exist on push -> create path.
Manual dispatch rules are unchanged (`allow_overwrite` decides overwrite; refusal message preserved).

Truth table (new):
| event | release exists? | existing target == built commit? | allow_overwrite? | result |
| --- | --- | --- | --- | --- |
| push | no | n/a | n/a | create |
| push | yes | yes | n/a | replace (clobber) |
| push | yes | no | n/a | refuse; ask to re-dispatch |
| dispatch | any (handled) | n/a | true | replace (clobber) |
| dispatch | any (handled) | n/a | false | refuse if release exists |

Validation: `.github/workflows/release.yml` parses with `yaml.safe_load` -> "YAML OK".

Files: `.github/workflows/release.yml`.

## 4. B03e block-extent assertion

Finding: the 2.8.0 gate records `PROBE-BLOCK ... size=...` lines (e.g.
`PROBE-BLOCK B03e_custom_page_size_65537_pages.wasm .memory0 size=65537`) but `check-results.py`
never parsed them, so the materialised block extent of B03e was not pinned.

Fix:
- Extended `test-scripts/check-results.py` minimally:
  - added `BLOCK_RE` parsing `PROBE-BLOCK <probe> <block> size=<N>`;
  - `parse_probe_log` returns a fourth value, `blocks: probe -> {block: size}`;
  - `check_probes(..., blocks=...)` compares a probe's recorded `blocks`/`block_sizes`/`block_extents`
    entry against the parsed sizes when present (other probes unaffected, no blocks recorded in their
    baseline entries);
  - `--update` records `blocks` for probes that emit block lines.
- Pinned the extent in `test-scripts/expected-results.json` for `B03e_custom_page_size_65537_pages.wasm`:
  `"blocks": { ".memory0": 65537 }`.

Observed: the gate log contains
`PROBE-BLOCK B03e_custom_page_size_65537_pages.wasm .memory0 size=65537`,
and the gate passes with the new assertion in place (see gate numbers below).

Files: `test-scripts/check-results.py`, `test-scripts/expected-results.json`.

## Verification (full gate)

Command:
```
.\test-scripts\check-local.ps1 -GhidraDir "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-n3-small" -OutDir "$env:TEMP\n3-gate" -RealModule "D:\code\Rasterbator\analysis\reference\site\assets\rasterbator_rs_bg.wasm"
```
Observed:
- build successful (`BUILD SUCCESSFUL`, ~9s);
- probe suite: 223 probes, `probes: 205 imported, 18 import failure(s); baseline has 223`;
- `OK: every probe matches the recorded baseline.`;
- fixture: `SUMMARY functions=4 decompiled=4 failed=0 instructions=24 undefined_bytes=0`;
- real module: `SUMMARY functions=437 decompiled=437 failed=0 instructions=61658 undefined_bytes=156`;
- gate exit status: success (script completed; check-results.py returned 0).

Gate numbers requested: **223 probes all matching**, fixture **4/4/0/24/0**, real module **437/437/0/61658/156**.

Cleanup test numbers (above): absolute and relative runs both exit 0.

## Residual notes

- Only the four scoped findings were addressed; N1 (emulator load/atomic cache) and N2 (call-store
  gate false-green) remain owned by other lanes and were not modified.
- `test-scripts/check-call-store-semantics.ps1`, `CallStoreTest.java`, emulator source, and
  `probes.yml` were not modified.
- The B03e assertion is minimal and scoped: only that probe carries a `blocks` baseline entry; every
  other probe's (many) `PROBE-BLOCK` lines are parsed but not asserted, so existing baselines are
  unchanged aside from the one added entry.
- Build artefacts and the `%TEMP%\n3-gate` run tree are outside the repo; the repo working tree
  was kept clean aside from the intended source changes.