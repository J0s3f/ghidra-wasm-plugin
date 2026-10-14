<#
.SYNOPSIS
    Generate and assert hybrid memory64 constructors and emulation in private scratch.
.EXAMPLE
    .\test-scripts\check-memory64-hybrid.ps1 -OutDir "$env:TEMP\mem64-checks"
#>
param(
    [Parameter(Mandatory=$true)][string]$OutDir,
    [string]$GhidraDir = ""
)
$ErrorActionPreference = "Stop"
$pinFile = Join-Path $PSScriptRoot ".ghidra-install"
if (Test-Path $pinFile) {
    $pin = (Get-Content $pinFile -Raw).Trim()
    if (-not $GhidraDir) { $GhidraDir = $pin }
    if ((Resolve-Path -LiteralPath $GhidraDir).Path -ne (Resolve-Path -LiteralPath $pin).Path) {
        throw "REFUSED: use this worktree's pinned Ghidra install: $pin"
    }
}
if (-not $GhidraDir) { $GhidraDir = $env:GHIDRA_INSTALL_DIR }
if (-not $GhidraDir) { throw "Set GHIDRA_INSTALL_DIR or pass -GhidraDir" }
if (-not (Test-Path $GhidraDir)) { throw "Ghidra install not found: $GhidraDir" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$fixtures = Join-Path $OutDir "fixtures"
& python (Join-Path $PSScriptRoot "memory64-hybrid-fixtures.py") $fixtures
if ($LASTEXITCODE -ne 0) { throw "fixture generation failed" }
$project = Join-Path $OutDir ("project-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $project | Out-Null
$log = Join-Path $OutDir "hybrid-check.log"
$headless = Join-Path $GhidraDir "support/analyzeHeadless.bat"
if ([Environment]::OSVersion.Platform -ne "Win32NT") {
    $headless = Join-Path $GhidraDir "support/analyzeHeadless"
}
$previous = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    & $headless $project Hybrid -import (Join-Path $fixtures "hybrid_matrix.wasm") `
        -import (Join-Path $fixtures "hybrid_emulation.wasm") `
        -import (Join-Path $fixtures "hybrid_simd_prefixes.wasm") -noanalysis `
        -scriptPath $PSScriptRoot -postScript CheckMemory64Hybrid.java `
        -max-cpu 2 -deleteProject 2>&1 | Out-File -FilePath $log -Encoding utf8
    $code = $LASTEXITCODE
} finally { $ErrorActionPreference = $previous }
$text = Get-Content -LiteralPath $log -Raw
Select-String -LiteralPath $log -Pattern "HYBRID-|I32-PCODE|ERROR" | ForEach-Object { $_.Line }
if ($code -ne 0 -or $text -notmatch "HYBRID-MATRIX functions=246 .* passed" -or
    $text -notmatch "HYBRID-EMU functions=9 passed; loader high/unsigned/overflow checks passed" -or
    $text -notmatch "HYBRID-SIMD-PREFIX functions=\d+ passed") {
    throw "Hybrid assertions failed; inspect $log"
}
Write-Host "OK: hybrid constructors, emulation, loader addresses and copy expansion; log: $log"
