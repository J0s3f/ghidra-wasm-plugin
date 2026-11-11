<#
.SYNOPSIS
    Regression check: struct synthesis must not create structures with a huge extent.

.DESCRIPTION
    Generates the struct-synthesis probes, imports the sparse-offset probe (ST05) with the pinned
    Ghidra install and runs CheckStructExtent.java, which fails if any synthesized /wasm structure
    is larger than 16 KiB. Exit code is non-zero on failure.

.EXAMPLE
    .\test-scripts\check-struct-extent.ps1 -OutDir "$env:TEMP\struct-extent"
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
& python (Join-Path $PSScriptRoot "probes_struct_synth.py") $fixtures
if ($LASTEXITCODE -ne 0) { throw "fixture generation failed" }
$project = Join-Path $OutDir ("project-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $project | Out-Null
$log = Join-Path $OutDir "struct-extent-check.log"
$headless = Join-Path $GhidraDir "support/analyzeHeadless.bat"
if ([Environment]::OSVersion.Platform -ne "Win32NT") {
    $headless = Join-Path $GhidraDir "support/analyzeHeadless"
}
$previous = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    & $headless $project StructExtent -import (Join-Path $fixtures "ST05_sparse_offsets_no_giant_struct.wasm") `
        -scriptPath $PSScriptRoot -postScript CheckStructExtent.java `
        -max-cpu 2 -deleteProject 2>&1 | Out-File -FilePath $log -Encoding utf8
    $code = $LASTEXITCODE
} finally { $ErrorActionPreference = $previous }
$text = Get-Content -LiteralPath $log -Raw
Select-String -LiteralPath $log -Pattern "STRUCT-EXTENT|ERROR|AssertionError" | ForEach-Object { $_.Line }
if ($code -ne 0 -or $text -notmatch "STRUCT-EXTENT ST05_sparse_offsets_no_giant_struct\.wasm structs=\d+ passed") {
    throw "Struct extent assertion failed; inspect $log"
}
Write-Host "OK: no oversized synthesized struct; log: $log"
