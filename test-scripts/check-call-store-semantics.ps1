<#
.SYNOPSIS
    Semantic regression test for the call-store trap fix (R1).
    Verifies that a valid store after a call returns succeeds (no false trap).

.DESCRIPTION
    This script imports the call32.wasm and call64.wasm fixtures, emulates the
    store_after_call function, and asserts that:
    - Emulation returns successfully (no "out of bounds memory access" trap)
    - The stored value (7) is correctly read back from memory

    Exit codes:
    0 = all assertions passed
    1 = any assertion failed or script error

.NOTES
    Requires the pinned Ghidra install (see test-scripts/.ghidra-install).
    Fixtures are in test-scripts/fixtures/.
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
$call32 = Join-Path $fixturesDir "call32.wasm"
$call64 = Join-Path $fixturesDir "call64.wasm"
if (-not (Test-Path $call32)) { throw "Fixture not found: $call32" }
if (-not (Test-Path $call64)) { throw "Fixture not found: $call64" }

# Create output directory
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

$testScript = Join-Path $PSScriptRoot "CallStoreTest.java"
$supportDir = Join-Path $GhidraDir "support"
$analyzeHeadless = Join-Path $supportDir "analyzeHeadless.bat"
if (-not (Test-Path $analyzeHeadless)) { $analyzeHeadless = Join-Path $supportDir "analyzeHeadless" }
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

$fixtures = @(
    @($call32, "call32.wasm"),
    @($call64, "call64.wasm")
)

foreach ($pair in $fixtures) {
    $fixturePath = $pair[0]
    $fixtureName = $pair[1]
    Write-Host "== Testing $fixtureName ==" -ForegroundColor Cyan
    $projDir = Join-Path $OutDir "proj_$fixtureName"
    if (Test-Path $projDir) { Remove-Item -Recurse -Force $projDir }
    New-Item -ItemType Directory -Path $projDir | Out-Null
    
    try {
        & $analyzeHeadless $projDir "test_proj" -import $fixturePath -postScript CallStoreTest.java $fixturePath -deleteProject 2>&1 | ForEach-Object {
            $_
            if ($_ -match "^(PASS|FAIL):") {
                if ($_ -match "^FAIL:") { $script:allPassed = $false }
            }
        }
    } catch {
        Write-Error ("analyzeHeadless failed for {0}: {1}" -f $fixtureName, $_)
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
