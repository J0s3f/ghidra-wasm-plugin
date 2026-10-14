# R34 install/release hardening

Branch: `fix/r34-install-release-hardening`
Base: `8f962e5cda82c4636a2832d043ac1d011b24047d` (main)
Scope: PowerShell scripts + GitHub workflow only. No Java, no SLEIGH, no Ghidra data changes.

Two pre-release tooling findings are fixed here:

| ID | File | Problem |
|----|------|---------|
| R3 | `test-scripts/build-install.ps1` | the extension-cleanup sweep deleted OTHER Ghidra versions' extension copies |
| R4 | `.github/workflows/release.yml` | a manual dispatch could replace an existing release's assets with another revision's build |

Both fixes are validated by tests that run without a Ghidra install and without touching GitHub.

---

## R3 - `build-install.ps1` removed other Ghidra versions' extension copies

### Finding

`build-install.ps1` (~lines 101-122 before this change) removed "shadowing" copies of the WebAssembly
extension from Ghidra's per-user settings directories. It collected the settings roots

* `%APPDATA%\ghidra`
* `$XDG_CONFIG_HOME\ghidra`
* `$HOME\.config\ghidra`
* `$HOME\.ghidra`
* `<GhidraDir>\settings` (isolated test installs)

and then, for **every** directory directly under each root, deleted any `Extensions\<name>` that
contains `data\languages\WebAssembly.slaspec`.

Those roots are shared by **every** Ghidra installation the user runs. Each root holds one version
directory per installed Ghidra release - on this machine, for example, `%APPDATA%\ghidra` contains
`ghidra_11.1.2_PUBLIC` and `ghidra_12.1.4_PUBLIC`. Running the helper for one selected
`-GhidraDir` therefore also uninstalled the extension for every other Ghidra version the user has.
That is far broader than "remove the copy that shadows the selected installation", and it is
invisible in the log (each removal is printed as a `removed shadowing extension copy:` line).

Secondary defect found while fixing this: the sweep never even reached an isolated install's real
settings tree. `new-test-install.ps1` sets `-Dapplication.settingsdir=<GhidraDir>\settings`, and
Ghidra then nests the version directory one level deeper:
`<GhidraDir>\settings\ghidra\ghidra_12.1.4_PUBLIC\Extensions\...`. The old code only looked at
`<GhidraDir>\settings\<version>\Extensions`, so a shadowing copy in an isolated install was never
removed - the very thing the sweep exists for.

### Fix

The cleanup is factored out of `build-install.ps1` into a new module,
`test-scripts/lib/wasm-settings-cleanup.ps1`, whose scope is derived from the selected installation
instead of from the whole settings root:

* `Get-GhidraSettingsRoots -GhidraDir` - the five roots above (unchanged set).
* `Get-GhidraSettingsVersionDirNames -GhidraDir` - the version directory names that belong to the
  selected installation, read from `<GhidraDir>\Ghidra\application.properties`
  (`application.version`, `application.release.name`, `application.name`). For the 12.1.4 PUBLIC
  install used here this is `ghidra_12.1.4_PUBLIC` plus the legacy dotted spelling
  `.ghidra_12.1.4_PUBLIC` and the no-release-name spellings `ghidra_12.1.4` / `.ghidra_12.1.4`.
  Matching is case-insensitive.
* `Get-GhidraAppDirName -GhidraDir` - `ghidra`, used to also resolve the
  `<root>\ghidra\<version-dir>` layout used by an isolated install.
* `Remove-ShadowingWasmExtensionCopies -SettingsRoots -VersionDirNames -AppDirName [-AllVersions]` -
  removes only `Extensions\<name>` that provide the WebAssembly language (marker:
  `data\languages\WebAssembly.slaspec`, the same marker as before) inside a version directory whose
  name is in scope. Unrelated extensions, copies belonging to other versions, and settings roots
  that do not exist are left alone. A removal that fails (locked file from a running Ghidra) is
  reported as a warning instead of aborting the install, and every path it saw but deliberately
  skipped is returned so the caller can print it (`kept (other Ghidra versions): ...`).

`build-install.ps1` keeps the behaviour the sweep exists for - the isolated install's own
`<GhidraDir>\settings` tree is still cleaned, now through the correct nested path - and gains one
new switch:

* `-CleanAllVersions` (default off) re-enables the old cross-version sweep and warns loudly when
  used. It is the only way to delete copies belonging to other Ghidra versions.

Fail-closed behaviour: if the selected install publishes no `application.version`,
`build-install.ps1` throws instead of sweeping, rather than silently widening the sweep to every
version (`REFUSED to sweep the shared settings directories`).

### Files

* `test-scripts/lib/wasm-settings-cleanup.ps1` (new, 250 lines) - the scoped sweep.
* `test-scripts/build-install.ps1` - dot-sources the module, derives the scope from the selected
  install, adds `-CleanAllVersions`, prints what was kept.
* `test-scripts/test-build-install-cleanup.ps1` (new) - the mock-tree regression test.

### Validation - mock-tree test

`pwsh -NoProfile -File test-scripts/test-build-install-cleanup.ps1` (exit 0, 28 checks).
Self-contained, everything under `%TEMP%` (`$env:TEMP\build-install-cleanup-test`), no Ghidra
needed. It builds mock installs with `Ghidra\application.properties` and mock settings roots holding
two version directories each (`ghidra_12.1.4_PUBLIC` = target, `ghidra_11.1.2_PUBLIC` = another
version the user also runs), each containing a fake WebAssembly extension, an unrelated extension,
plus a legacy root with the dotted spelling, and drives the real module:

```
ok  : the selected install's version directory name is derived
ok  : the legacy (dotted) spelling of the target version is derived
ok  : the other install's version directory name is NOT derived
ok  : the application directory inside a settings root is derived
ok  : the settings roots include the install's own settings directory
ok  : removed: <tree>\roots\appdata\ghidra_12.1.4_PUBLIC\Extensions\GhidraWasm
ok  : kept: <tree>\roots\appdata\ghidra_11.1.2_PUBLIC\Extensions\GhidraWasm
ok  : kept: <tree>\roots\appdata\ghidra_12.1.4_PUBLIC\Extensions\SomeOtherExtension
ok  : removed: <tree>\roots\xdg\ghidra_12.1.4_PUBLIC\Extensions\GhidraWasm
ok  : kept: <tree>\roots\xdg\ghidra_11.1.2_PUBLIC\Extensions\GhidraWasm
ok  : removed: <tree>\install-a\settings\ghidra\ghidra_12.1.4_PUBLIC\Extensions\GhidraWasm
ok  : kept: <tree>\install-a\settings\ghidra\ghidra_11.1.2_PUBLIC\Extensions\GhidraWasm
ok  : removed: <tree>\roots\legacy\.ghidra_12.1.4_PUBLIC\Extensions\GhidraWasm
ok  : kept: <tree>\roots\legacy\.ghidra_11.1.2_PUBLIC\Extensions\GhidraWasm
ok  : the sweep reports exactly the copies it removed
ok  : the sweep reports no warnings
ok  : the sweep reports the versions it deliberately left alone
ok  : the sweep sees the nested isolated-install layout
ok  : a settings root that does not exist is skipped without an error
ok  : an empty version-dir scope removes nothing
ok  : an empty version-dir scope leaves the other version's copy alone
ok  : -CleanAllVersions removes every version's copy
ok  : -CleanAllVersions still leaves unrelated extensions alone
ok  : a locked copy does not abort the sweep
ok  : a locked copy is reported as a warning
ok  : a locked copy survives
ok  : an install without application.version yields no scope
ok  : the pinned install (C:\Users\micro\AppData\Local\Temp\opencode\ghidra-r34-tooling) yields its version directory
note: settings root C:\Users\micro\AppData\Roaming\ghidra holds [ghidra_11.1.2_PUBLIC, ghidra_12.1.4_PUBLIC] -> in scope: ghidra_12.1.4_PUBLIC
note: settings root C:\Users\micro\.ghidra holds [.ghidra_10.2.3_PUBLIC] -> in scope:
PASS: the settings sweep removes only the selected installation's copy (mock trees under C:\Users\micro\AppData\Local\Temp\build-install-cleanup-test)
```

The two `note:` lines are a read-only probe of the real user settings roots: they confirm the
`ghidra_11.1.2_PUBLIC` directory that the old code would have swept exists on this machine, and that
the derived scope matches only `ghidra_12.1.4_PUBLIC`.

### Validation - the old behaviour, reproduced

Running the pre-fix algorithm (all version directories, no version filter) against the same mock
layout removes **both** copies:

```
before: ghidra_11.1.2_PUBLIC\Extensions\GhidraWasm | ghidra_12.1.4_PUBLIC\Extensions\GhidraWasm
removed shadowing extension copy: ghidra_11.1.2_PUBLIC\Extensions\GhidraWasm
removed shadowing extension copy: ghidra_12.1.4_PUBLIC\Extensions\GhidraWasm
after:
```

### Validation - end-to-end run against the pinned install

`pwsh -File test-scripts/build-install.ps1` with the pinned install
(`C:\Users\micro\AppData\Local\Temp\opencode\ghidra-r34-tooling`, exit 0):

```
== using the pinned Ghidra install: C:\Users\micro\AppData\Local\Temp\opencode\ghidra-r34-tooling ==
== building (GHIDRA_INSTALL_DIR=...) ==
...
BUILD SUCCESSFUL in 39s
== installing ghidra_12.1.4_PUBLIC_20261014_ghidra-wt-r34-tooling.zip into ...\Ghidra\Extensions ==
installed: ghidra-wt-r34-tooling  jar: ghidra-wt-r34-tooling.jar  (301087 bytes)
== settings sweep limited to version directory: ghidra_12.1.4_PUBLIC, .ghidra_12.1.4_PUBLIC, ghidra_12.1.4, .ghidra_12.1.4 ==
kept (other Ghidra versions): ghidra_11.1.2_PUBLIC, .ghidra_10.2.3_PUBLIC
stamp: ...\ghidra-wasm-install-stamp.json
```

`gradle buildExtension` still succeeds (only pre-existing deprecation warnings from
`WasmEmulateInstructionStateModifier`), the install still lands, and the sweep now reports the
`ghidra_11.1.2_PUBLIC` / `.ghidra_10.2.3_PUBLIC` directories it deliberately left alone.

---

## R4 - release.yml manual dispatch can replace an old release with current-ref artifacts

### Finding

`.github/workflows/release.yml`:

* `workflow_dispatch.inputs.tag` had `default: "v2.5.0"`.
* Both jobs used `actions/checkout@v7` with no `ref`, i.e. the dispatched ref/SHA was built, while
  the tag input only chose the upload destination.
* The publish step ran `gh release upload "$TAG" ... --clobber` whenever a release for `$TAG`
  already existed.

Dispatching from any branch with the default input therefore built that branch's commit and
overwrote the assets of the (already published) `v2.5.0` release. Concretely: `v2.5.0` is an
annotated tag that resolves to `430cbe287b381e7abb7355f7f5b145d4f690a163`, while this worktree's
`HEAD` is `8f962e5cda82c4636a2832d043ac1d011b24047d` - so a dispatch from here would have published
this revision's build as the 2.5.0 assets. The input's own description ("created at this commit if
it does not exist") describes the dangerous behaviour.

### Fix

1. **Intentional target tag.** `tag` keeps `required: true` but loses `default` entirely, so an
   accidental dispatch cannot fall back to a stale tag. The description now states the requirement.
   The script additionally rejects an empty/whitespace-only input with a `::error::`.
2. **The tag must exist and must be the commit that was built.** `TAG_SHA` is resolved with
   `gh api repos/$REPOSITORY/commits/$TAG` (which dereferences annotated tags) and compared with
   `github.sha`; the local checkout's `HEAD` is compared with `github.sha` too. Any mismatch, an
   unreadable tag, or a tag that does not resolve is a hard failure. The workflow never creates a
   tag - a missing tag is an error, not a silent creation.
3. **Replacing existing assets is explicit.** New input `allow_overwrite` (`type: boolean`,
   `default: false`). Overwriting an existing release requires it... except for a re-run of the
   *same* tag push, where the tag is the commit that was built, so re-attaching identical artifacts
   is idempotent. That path is gated on the same-revision check, which already refuses a tag that
   has been moved to a different commit (force-pushed tag case).
4. `actions/checkout@v7` in both jobs now pins `ref: ${{ github.sha }}` so "what is built" can never
   silently diverge from "what is published".
5. `gh release create` keeps `--target "$TARGET_SHA"`; `--clobber` is now only reachable behind the
   overwrite decision.

### Validation

* **YAML parses.** `python -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"`
  -> exit 0. (PyYAML resolves the unquoted `on:` key to `True` under YAML 1.1; parsed via `data[True]`.)
* **A structural validator** over the parsed workflow (25 checks, all `ok`) confirms: the push
  trigger still only matches `tags: ['v*']`, the input set is exactly
  `{tag, ghidra_versions, allow_overwrite}`, `tag` has no default and is required,
  `allow_overwrite` is `type: boolean` with `default: false`, the `ghidra_versions` default is
  unchanged, the release job still `needs: build` and the job still has `contents: write`, both
  checkouts pin `github.sha`, and `gh release create` still targets the built SHA.
* **`bash -n` on both embedded scripts is clean** (Git Bash 5.3.15).
* **Dry-run matrix.** The publish step was extracted verbatim from the YAML and executed ten times
  against a stubbed `gh` (logs its arguments, answers a tag->sha map and a "release exists" flag)
  in a throwaway git repository, with a fake `dist/`. No network, no real release, no dispatch.
  `gh release create` was also stubbed so the final `gh release view` succeeds.

| # | event | tag input | tag resolves to | release exists | allow_overwrite | result | exit |
|---|-------|-----------|-----------------|----------------|-----------------|--------|------|
| A | push of `v2.5.0` | `v2.5.0` (ref name) | built commit | yes | n/a | `gh release upload v2.5.0 ... --clobber` | 0 |
| B | push of `v2.5.0` | `v2.5.0` (ref name) | **another** commit | yes | n/a | `::error::tag 'v2.5.0' resolves to ... but this run built ...` | 1 |
| C | push of new `v2.7.0` | `v2.7.0` (ref name) | built commit | no | n/a | `gh release create v2.7.0 ... --target <built sha>` | 0 |
| D | dispatch | `v2.5.0` | built commit | yes | `false` | `::error::release 'v2.5.0' already exists ... re-dispatch with allow_overwrite=true` | 1 |
| E | dispatch | `v2.5.0` | built commit | yes | `true` | `gh release upload v2.5.0 ... --clobber` | 0 |
| F | dispatch | `v2.5.0` | **another** commit | yes | `false` | `::error::tag 'v2.5.0' resolves to ... but this run built ...` | 1 |
| G | dispatch | `v2.5.0` | does not resolve | yes | `false` | `::error::cannot read tag 'v2.5.0' ... never creates a tag` | 1 |
| H | dispatch | *(empty)* | - | - | `false` | `::error::no release tag given ... no default` | 1 |
| I | dispatch | `v2.5.0` | built commit | no | `false` | `gh release create v2.5.0 ... --target <built sha>` | 0 |
| J | dispatch | `"  v2.5.0  "` | built commit | yes | `false` | input trimmed, then refused as in D | 1 |

Case A is the normal push-tag path and the same-revision re-run; case C/I is the normal first
publish; case F is the exact R4 scenario and is now refused before any upload happens; case B is the
force-moved-tag variant.

### Dry-run reasoning (as requested)

* **Tag push (`push`, tag `v2.7.0`):** `TAG` comes from `github.ref_name`. The API resolves it to
  `github.sha` (for a tag push, GitHub sets `GITHUB_SHA` to the commit the tag points at), so the
  same-revision check passes and `git rev-parse HEAD` equals `github.sha` because the checkout is that
  SHA. `OVERWRITE` becomes 1 (push path). If no release exists yet, `gh release create` runs with
  `--target <sha>`; if it does (a re-run), assets are re-uploaded with `--clobber` - idempotent,
  because the artifacts are a rebuild of the very commit the tag names. If the tag was re-pushed at a
  different commit, `TAG_SHA != TARGET_SHA` aborts the job before any upload.
* **Manual dispatch with a matching tag:** `TAG` comes from `inputs.tag`, which has no default, so
  the operator must type it. The tag must exist and must resolve to `github.sha` - i.e. the revision
  being built is the revision the tag already names. If the release does not exist, it is created
  with `--target <built sha>` (case I). If it exists, the job stops with an actionable error unless
  `allow_overwrite=true` was passed (cases D/E).
* **Manual dispatch with a mismatching tag:** the tag either does not resolve (case G), resolves to
  a different commit (case F), or was not given (case H). In all three the job fails before any
  `gh release` mutation, so a branch build can never land in another tag's release.

---

## Files changed

```
test-scripts/build-install.ps1                  |  refactor cleanup onto the scoped module + -CleanAllVersions
test-scripts/lib/wasm-settings-cleanup.ps1      |  new: scoped sweep helpers
test-scripts/test-build-install-cleanup.ps1     |  new: mock-tree regression test (28 checks)
.github/workflows/release.yml                   |  R4 hardening
archive/reports/REPORT-R34-HARDENING.md         |  this report
```

## Residual notes

* `test-scripts/lib/` is a new directory. The repo has no existing PowerShell module convention; if
  one is preferred, the helpers can be moved, but they must stay dot-sourceable by the test.
* `build-install.ps1` now **fails** (instead of warning) when `<GhidraDir>\Ghidra\application.properties`
  is missing or has no `application.version`. That is deliberate - the alternative is a silent sweep
  of every version - but it means a stripped/renamed Ghidra layout must pass `-CleanAllVersions`.
* The version-directory spelling (`ghidra_<version>_<release.name>`, legacy `.ghidra_...`) was taken
  from Ghidra's own naming on this machine (`%APPDATA%\ghidra\ghidra_12.1.4_PUBLIC`,
  `%HOME%\.ghidra\.ghidra_10.2.3_PUBLIC`). A future Ghidra that changes the convention would make the
  scoped sweep a no-op (visible in the `kept (other Ghidra versions):` line and in the empty
  `Removed` list) rather than destructive; widening the scope is the `-CleanAllVersions` escape
  hatch.
* `gh api repos/.../commits/<tag>` is used for tag resolution because it dereferences both
  lightweight and annotated tags (this repo has both). It was not exercised against the real API
  here - no network calls to GitHub were made - the dry-run uses a stub. The dereference behaviour is
  documented GitHub API behaviour, not something this change introduced.
* `allow_overwrite=true` on a dispatch still publishes a build of the dispatched commit; it only
  skips the "release already exists" guard. The same-revision check is never bypassable.
* The release workflow was not dispatched, no `gh release` command was run, and no release was read
  or written. All `gh` invocations in this session went to a stub in `%TEMP%`.
* Nothing outside the worktree was modified. Scratch files live in `%TEMP%`
  (`r34-dryrun*`, `r34-old-sweep-demo.ps1`, `r34-release-validate.py`, `r34-extract-run.py`).
