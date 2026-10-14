<#
.SYNOPSIS
    Emulation regression check for the br_table DEFAULT-target expansion bound.

.DESCRIPTION
    The pre-analyzer caps how many br_table labels it materialises as branch instructions
    (MAX_BR_TABLE_CASES, see src/main/java/wasm/analysis/WasmFunctionAnalysis.java). Before the
    fix the cap truncated at the cap *including* the default label, so a br_table with exactly
    MAX_BR_TABLE_CASES (1024) explicit cases silently lost its DEFAULT target and the modelled
    control flow (decompiler + emulator) was wrong.

    This script imports test-scripts/fixtures/brtable_default.wasm with the pinned install,
    emulates the exported `default_branch` function through the real Ghidra emulator
    (test-scripts/EmulateExport.java), and asserts it returns 2 - the value reached only via the
    DEFAULT target (an out-of-range index 1024 selects the default; every case target returns 1).
    It exits 0 on success and non-zero on any failure. See REPORT-R5-BRTABLE.md.

    The fixture is byte-identical to the review artefact
    D:\code\Ghidra-WASM\build\release-review-sol\brcap.wasm; regenerate it with
    test-scripts/fixtures/make_brtable_default_fixture.py.

.EXAMPLE
    .\test-scripts\check-brtable-default.ps1
    # build is already installed and current:
    .\test-scripts\check-brtable-default.ps1 -SkipBuild -OutDir "$env:TEMP\brtable-check"
#>
param(
    [string]$GhidraDir = "",
    [string]$OutDir = "$env:TEMP\brtable-default-check",
    [string]$Fixture = "",
    [string]$Gradle = "C:\Tools\gradle-9.2.1\bin\gradle.bat",
    [int]$ExpectedReturn = 2,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$testScripts = Join-Path $repo "test-scripts"
if (-not $Fixture) { $Fixture = Join-Path $testScripts "fixtures\brtable_default.wasm" }

# --- install pinning (same rule as build-install.ps1 / check-local.ps1) -----------------------
$pinFile = Join-Path $testScripts ".ghidra-install"
if (Test-Path $pinFile) {
    $pinned = (Get-Content $pinFile -Raw).Trim()
    if (-not $GhidraDir) { $GhidraDir = $pinned }
    elseif ($GhidraDir -ne $pinned) {
        throw "REFUSED: this checkout is pinned to '$pinned' (test-scripts/.ghidra-install)."
    }
}
if (-not $GhidraDir) { $GhidraDir = $env:GHIDRA_INSTALL_DIR }
if (-not $GhidraDir) { throw "Set GHIDRA_INSTALL_DIR or pass -GhidraDir" }
if (-not (Test-Path $GhidraDir)) { throw "Ghidra install not found: $GhidraDir" }
if (-not (Test-Path $Fixture)) {
    throw "fixture not found: $Fixture (run python test-scripts/fixtures/make_brtable_default_fixture.py)"
}

if (-not $SkipBuild) {
    & (Join-Path $testScripts "build-install.ps1") -GhidraDir $GhidraDir -Gradle $Gradle
    if ($LASTEXITCODE -ne 0) { throw "build-install.ps1 failed ($LASTEXITCODE)" }
}

$supportDir = Join-Path $GhidraDir "support"
$headless = Join-Path $supportDir "analyzeHeadless.bat"
if (-not (Test-Path $headless)) { $headless = Join-Path $supportDir "analyzeHeadless" }
if (-not (Test-Path $headless)) { throw "analyzeHeadless not found under $supportDir" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$proj = Join-Path $OutDir "proj-brtable-default"
Remove-Item -Recurse -Force $proj -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $proj | Out-Null
$log = Join-Path $OutDir "brtable-default.log"

Write-Host ("== emulating default_branch in {0} ==" -f (Split-Path -Leaf $Fixture)) -ForegroundColor Cyan
# Native stderr must not abort the run (PS 7.3+ turns it into ErrorRecords that
# $ErrorActionPreference='Stop' would terminate on); capture with UTF-8 for the parser.
$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    & $headless $proj BrtableDefault -import $Fixture -noanalysis `
        -scriptPath $testScripts -postScript EmulateExport.java default_branch 2>&1 |
        Out-File -FilePath $log -Encoding utf8
}
finally { $ErrorActionPreference = $prevEap }
if ($LASTEXITCODE -ne 0) { throw "analyzeHeadless failed ($LASTEXITCODE)" }

$lines = Select-String -Path $log -Pattern "EmulateExport\.java> (FUNC|RETURN|STATUS|RESULT)" |
    ForEach-Object {
        ($_.Line -replace "^\S+\s+\S+\s+", "") -replace " \((GhidraScript|HeadlessAnalyzer)\).*$", ""
    }
$lines | ForEach-Object { Write-Host "  $_" }

$returnLine = $lines | Where-Object { $_ -like "RETURN *" } | Select-Object -First 1
$statusLine = $lines | Where-Object { $_ -like "STATUS *" } | Select-Object -First 1
if (-not $returnLine) { Write-Host "FAIL: no RETURN line found in $log" -ForegroundColor Red; exit 1 }
if ($statusLine -notmatch "STATUS\s+ok") {
    Write-Host ("FAIL: emulation did not finish ok ({0})" -f $statusLine) -ForegroundColor Red
    exit 1
}
if ($returnLine -notmatch "i32=0x([0-9a-fA-F]+)") {
    Write-Host ("FAIL: cannot parse return value from '{0}'" -f $returnLine) -ForegroundColor Red
    exit 1
}
$hex = $Matches[1]
$got = [Convert]::ToInt64($hex, 16)
if ($got -ne $ExpectedReturn) {
    Write-Host ("FAIL: default_branch returned {0} (0x{1}), expected {2}" -f $got, $hex, $ExpectedReturn) -ForegroundColor Red
    Write-Host "      the br_table DEFAULT target was not modelled (see REPORT-R5-BRTABLE.md)" -ForegroundColor Red
    exit 1
}

Write-Host ("PASS: default_branch returned {0} (expected {1}); br_table default target is modelled" -f $got, $ExpectedReturn) -ForegroundColor Green
exit 0
