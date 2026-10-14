<#
.SYNOPSIS
    Semantic regression gate for the call-store (R1) and stale operand-slot cache (N1) fixes.

.DESCRIPTION
    Imports the call/cache fixtures and executes every relevant export through the real
    emulator (CallStoreTest.java), then requires - per fixture - that the native launcher
    exited 0, that no FAIL record was produced, and that every expected PASS record is
    present. The PASS/FAIL records are GhidraScript.println output and therefore carry a
    log prefix ("INFO  CallStoreTest.java> PASS: ... (GhidraScript)"), so the record is
    matched anywhere in the line. Success is never the default state.

    Fixtures / expected PASS records:
      call32.wasm / call64.wasm          store_after_call
      cache32.wasm / cache64.wasm        load_after_call, simd_after_call,
                                         rmw_after_call, overflow_after_call
      cache32_controls.wasm              direct_load, direct_simd, direct_rmw,
      cache64_controls.wasm              direct_overflow

    Exit codes:
      0 = every fixture: exit 0, no FAIL record, all expected PASS records present
      1 = any fixture failed (FAIL record, missing PASS record, or non-zero exit)

.NOTES
    Requires the pinned Ghidra install (see test-scripts/.ghidra-install).
    Fixtures are in test-scripts/fixtures/.
    The failure paths are covered without Ghidra by test-scripts/test-call-store-gate.ps1.
#>
param(
    [string]$GhidraDir = "",
    [string]$OutDir = "$env:TEMP\r1-callstore-gate"
)

$ErrorActionPreference = "Stop"

# --- install pinning --------------------------------------------------------------
$pinFile = Join-Path $PSScriptRoot ".ghidra-install"
if (Test-Path $pinFile) {
    $pinned = (Get-Content $pinFile -Raw).Trim()
    if (-not $GhidraDir) {
        $GhidraDir = $pinned
        Write-Host "== using the pinned Ghidra install: $pinned ==" -ForegroundColor DarkGray
    }
    elseif ($GhidraDir -ne $pinned -and (Resolve-Path -LiteralPath $GhidraDir -ErrorAction SilentlyContinue).Path -ne (Resolve-Path -LiteralPath $pinned -ErrorAction SilentlyContinue).Path) {
        throw "REFUSED: this checkout is pinned to '$pinned' (test-scripts/.ghidra-install). Use the pinned folder."
    }
}
if (-not $GhidraDir) { $GhidraDir = $env:GHIDRA_INSTALL_DIR }
if (-not $GhidraDir) { throw "Set GHIDRA_INSTALL_DIR or pass -GhidraDir" }
if (-not (Test-Path $GhidraDir)) { throw "Ghidra install not found: $GhidraDir" }

$repo = Split-Path -Parent $PSScriptRoot
$fixturesDir = Join-Path (Join-Path $repo "test-scripts") "fixtures"

# --- fixture table: expected PASS record(s) per fixture ---------------------------
$fixtureSpecs = @(
    [pscustomobject]@{ File = "call32.wasm";           Records = @("store_after_call") },
    [pscustomobject]@{ File = "call64.wasm";           Records = @("store_after_call") },
    [pscustomobject]@{ File = "cache32.wasm";          Records = @("load_after_call", "simd_after_call", "rmw_after_call", "overflow_after_call") },
    [pscustomobject]@{ File = "cache64.wasm";          Records = @("load_after_call", "simd_after_call", "rmw_after_call", "overflow_after_call") },
    [pscustomobject]@{ File = "cache32_controls.wasm"; Records = @("direct_load", "direct_simd", "direct_rmw", "direct_overflow") },
    [pscustomobject]@{ File = "cache64_controls.wasm"; Records = @("direct_load", "direct_simd", "direct_rmw", "direct_overflow") }
)

# Create output directory
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

$testScript = Join-Path $PSScriptRoot "CallStoreTest.java"
$supportDir = Join-Path $GhidraDir "support"
if ([Environment]::OSVersion.Platform -eq "Win32NT") {
    $analyzeHeadless = Join-Path $supportDir "analyzeHeadless.bat"
    if (-not (Test-Path $analyzeHeadless)) { $analyzeHeadless = Join-Path $supportDir "analyzeHeadless" }
} else {
    $analyzeHeadless = Join-Path $supportDir "analyzeHeadless"
    if (-not (Test-Path $analyzeHeadless)) { $analyzeHeadless = Join-Path $supportDir "analyzeHeadless.bat" }
}
if (-not (Test-Path $analyzeHeadless)) { throw "analyzeHeadless not found under $supportDir" }

# Discover the installed extension's script dir (the directory name depends on the build:
# "Ghidra-WASM" for the integration checkout, the worktree name for a private install).
$extRoot = Join-Path (Join-Path $GhidraDir "Ghidra") "Extensions"
$extDir = Get-ChildItem $extRoot -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName "ghidra_scripts") } | Select-Object -First 1
if (-not $extDir) { throw "No installed WebAssembly extension under $extRoot (build-install.ps1 must have run)" }
$extScriptsDir = Join-Path $extDir.FullName "ghidra_scripts"
if (-not (Test-Path $extScriptsDir)) { throw "Extension scripts dir not found: $extScriptsDir (build-install.ps1 must have run)" }
Copy-Item $testScript -Destination (Join-Path $extScriptsDir "CallStoreTest.java") -Force

$allPassed = $true

foreach ($spec in $fixtureSpecs) {
    $fixturePath = Join-Path $fixturesDir $spec.File
    Write-Host "== Testing $($spec.File) ==" -ForegroundColor Cyan

    if (-not (Test-Path $fixturePath)) {
        Write-Host "FAIL: fixture not found: $fixturePath" -ForegroundColor Red
        $allPassed = $false
        continue
    }

    $projDir = Join-Path $OutDir "proj_$($spec.File)"
    if (Test-Path $projDir) { Remove-Item -Recurse -Force $projDir }
    New-Item -ItemType Directory -Path $projDir | Out-Null

    $lines = @()
    $exitCode = $null
    try {
        $lines = @(& $analyzeHeadless $projDir "test_proj" -import $fixturePath -postScript CallStoreTest.java $fixturePath -deleteProject 2>&1 | ForEach-Object { "$_" })
        $exitCode = $LASTEXITCODE
    }
    catch {
        Write-Host ("FAIL: analyzeHeadless failed for {0}: {1}" -f $spec.File, $_) -ForegroundColor Red
        $allPassed = $false
        continue
    }

    foreach ($line in $lines) { Write-Host $line }

    # Parse the script-specific prefixed records anywhere in the line.
    $passLines = @()
    $failLines = @()
    foreach ($line in $lines) {
        if ($line -match '(?:^|\s)(PASS|FAIL):') {
            if ($matches[1] -eq 'FAIL') { $failLines += $line } else { $passLines += $line }
        }
    }

    $fixtureOk = $true

    if ($null -eq $exitCode) {
        Write-Host ("FAIL: {0}: launcher exit code was not captured" -f $spec.File) -ForegroundColor Red
        $fixtureOk = $false
    }
    elseif ($exitCode -ne 0) {
        Write-Host ("FAIL: {0}: launcher exited {1}" -f $spec.File, $exitCode) -ForegroundColor Red
        $fixtureOk = $false
    }

    if ($failLines.Count -gt 0) {
        Write-Host ("FAIL: {0}: {1} FAIL record(s) emitted" -f $spec.File, $failLines.Count) -ForegroundColor Red
        $fixtureOk = $false
    }

    if ($passLines.Count -eq 0) {
        Write-Host ("FAIL: {0}: no PASS record produced" -f $spec.File) -ForegroundColor Red
        $fixtureOk = $false
    }

    foreach ($record in $spec.Records) {
        $pattern = 'PASS:\s*' + [regex]::Escape($record) + '\b'
        $hit = @($passLines | Where-Object { $_ -match $pattern })
        if ($hit.Count -eq 0) {
            Write-Host ("FAIL: {0}: missing PASS record '{1}'" -f $spec.File, $record) -ForegroundColor Red
            $fixtureOk = $false
        }
    }

    if ($fixtureOk) {
        Write-Host ("== {0}: exit 0, no FAIL, all {1} record(s) present ==" -f $spec.File, $spec.Records.Count) -ForegroundColor Green
    }
    else {
        $allPassed = $false
    }
}

if ($allPassed) {
    Write-Host "== All call-store semantics tests PASSED ==" -ForegroundColor Green
    exit 0
} else {
    Write-Host "== Some call-store semantics tests FAILED ==" -ForegroundColor Red
    exit 1
}
