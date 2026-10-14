<#
.SYNOPSIS
    Self-contained negative tests for test-scripts/check-call-store-semantics.ps1 (N2 gate).

.DESCRIPTION
    The call-store gate must never report success unless the native launcher exited 0 AND
    every expected PASS record was produced. This meta-test proves the failure paths without
    a Ghidra install: it builds a private mock install under %TEMP% whose
    support/analyzeHeadless.bat emits controlled output/exit codes, mirrors test-scripts
    (wrapper + CallStoreTest.java + fixtures + a .ghidra-install pinning the mock), and runs
    the *unmodified* wrapper against it for four scenarios:

      (a) prefixed FAIL record + exit 1   -> wrapper must exit non-zero
      (b) no PASS/FAIL record + exit 0    -> wrapper must exit non-zero (missing result)
      (c) prefixed PASS record + exit 1   -> wrapper must exit non-zero (bad exit code)
      (d) prefixed PASS record + exit 0   -> wrapper must exit 0

    Exit codes:
      0 = the wrapper behaved correctly in all four scenarios
      1 = a scenario did not match the expected wrapper exit code
#>
param(
    [string]$OutDir = "$env:TEMP\call-store-gate-meta"
)

$ErrorActionPreference = "Stop"

$wrapperName = "check-call-store-semantics.ps1"
$wrapperSrc = Join-Path $PSScriptRoot $wrapperName
$testSrc = Join-Path $PSScriptRoot "CallStoreTest.java"
$fixturesSrc = Join-Path $PSScriptRoot "fixtures"

if (-not (Test-Path $wrapperSrc)) { throw "wrapper not found: $wrapperSrc" }
if (-not (Test-Path $testSrc)) { throw "CallStoreTest.java not found: $testSrc" }
if (-not (Test-Path $fixturesSrc)) { throw "fixtures dir not found: $fixturesSrc" }

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$root = Join-Path $OutDir ("run-" + [guid]::NewGuid().ToString("N"))
$mock = Join-Path $root "mock-install"
$mirror = Join-Path $root "mirror"
$mirrorTs = Join-Path $mirror "test-scripts"
$mirrorFixtures = Join-Path $mirrorTs "fixtures"

Write-Host "== building mock install + mirror under $root ==" -ForegroundColor Cyan
New-Item -ItemType Directory -Force (Join-Path $mock "support") | Out-Null
New-Item -ItemType Directory -Force (Join-Path $mock "Ghidra\Extensions\Ghidra-WASM\ghidra_scripts") | Out-Null
New-Item -ItemType Directory -Force $mirrorFixtures | Out-Null

$mockBat = @'
@echo off
setlocal enabledelayedexpansion
set "FIX="
set "PREV="
for %%a in (%*) do (
  if "!PREV!"=="-import" set "FIX=%%~a"
  set "PREV=%%~a"
)
set "BASE="
for %%f in ("!FIX!") do set "BASE=%%~nxf"
set "NAMES="
if /I "!BASE!"=="call32.wasm" set "NAMES=store_after_call"
if /I "!BASE!"=="call64.wasm" set "NAMES=store_after_call"
if /I "!BASE!"=="cache32.wasm" set "NAMES=load_after_call simd_after_call rmw_after_call overflow_after_call"
if /I "!BASE!"=="cache64.wasm" set "NAMES=load_after_call simd_after_call rmw_after_call overflow_after_call"
if /I "!BASE!"=="cache32_controls.wasm" set "NAMES=direct_load direct_simd direct_rmw direct_overflow"
if /I "!BASE!"=="cache64_controls.wasm" set "NAMES=direct_load direct_simd direct_rmw direct_overflow"
if /I "%MOCK_MODE%"=="A" goto modeA
if /I "%MOCK_MODE%"=="B" goto modeB
if /I "%MOCK_MODE%"=="C" goto modeC
if /I "%MOCK_MODE%"=="D" goto modeD
echo MOCK_MODE not set or invalid: %MOCK_MODE%
exit /b 2
:modeA
echo INFO  CallStoreTest.java^> FAIL: emulation did not return (steps=8, error=out of bounds memory access) (GhidraScript)
exit /b 1
:modeB
echo INFO  Headless startup complete (AnalyzeHeadless)
exit /b 0
:modeC
for %%n in (!NAMES!) do echo INFO  CallStoreTest.java^> PASS: %%n returned=0x12345678 steps=9 (GhidraScript)
exit /b 1
:modeD
for %%n in (!NAMES!) do echo INFO  CallStoreTest.java^> PASS: %%n returned=0x12345678 steps=9 (GhidraScript)
exit /b 0
'@
Set-Content -Path (Join-Path $mock "support\analyzeHeadless.bat") -Value $mockBat -Encoding ascii

# Mirror test-scripts (the wrapper resolves fixtures via <mirror>/test-scripts/fixtures).
Copy-Item $wrapperSrc (Join-Path $mirrorTs $wrapperName) -Force
Copy-Item $testSrc (Join-Path $mirrorTs "CallStoreTest.java") -Force
Copy-Item (Join-Path $fixturesSrc "*.wasm") $mirrorFixtures -Force
Set-Content -Path (Join-Path $mirrorTs ".ghidra-install") -Value $mock -Encoding ascii -NoNewline

$mirrorWrapper = Join-Path $mirrorTs $wrapperName

$scenarios = @(
    [pscustomobject]@{ Mode = "A"; ExpectFail = $true;  Desc = "prefixed FAIL + exit 1" },
    [pscustomobject]@{ Mode = "B"; ExpectFail = $true;  Desc = "no result + exit 0" },
    [pscustomobject]@{ Mode = "C"; ExpectFail = $true;  Desc = "prefixed PASS + exit 1" },
    [pscustomobject]@{ Mode = "D"; ExpectFail = $false; Desc = "prefixed PASS + exit 0" }
)

$allOk = $true
foreach ($scenario in $scenarios) {
    Write-Host ("== scenario {0}: {1} ==" -f $scenario.Mode, $scenario.Desc) -ForegroundColor Cyan
    $env:MOCK_MODE = $scenario.Mode
    $out = Join-Path $root ("out-" + $scenario.Mode)
    $log = Join-Path $root ("wrapper-" + $scenario.Mode + ".log")

    $childOut = @(& pwsh -NoProfile -File $mirrorWrapper -OutDir $out *>&1 | ForEach-Object { "$_" })
    $code = $LASTEXITCODE
    $childOut | Set-Content -Path $log -Encoding utf8
    foreach ($line in $childOut) { Write-Host $line }

    $ok = if ($scenario.ExpectFail) { $code -ne 0 } else { $code -eq 0 }
    if ($ok) {
        Write-Host ("-- scenario {0} OK: wrapper exit {1} (expected {2})" -f $scenario.Mode, $code, ($(if ($scenario.ExpectFail) { "non-zero" } else { "0" }))) -ForegroundColor Green
    }
    else {
        Write-Host ("-- scenario {0} FAILED: wrapper exit {1} (expected {2}); log {3}" -f $scenario.Mode, $code, ($(if ($scenario.ExpectFail) { "non-zero" } else { "0" })), $log) -ForegroundColor Red
        $allOk = $false
    }
}

Remove-Item Env:\MOCK_MODE -ErrorAction SilentlyContinue

if ($allOk) {
    Write-Host "== All call-store gate negative tests PASSED ==" -ForegroundColor Green
    Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
    exit 0
} else {
    Write-Host "== Some call-store gate negative tests FAILED (scratch kept: $root) ==" -ForegroundColor Red
    exit 1
}
