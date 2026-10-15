<#
.SYNOPSIS
    Create an isolated, disposable Ghidra install copy for testing a worktree in parallel.

.DESCRIPTION
    Copies the reference Ghidra install ($Source) to $Dest and makes it independent:
      * removes any installed extensions (so the worktree's own build is the only plugin visible),
      * appends private settings / cache / temp directories to support/launch.properties so
        concurrent agents cannot interfere with each other or with the user's real install.

.EXAMPLE
    .\test-scripts\new-test-install.ps1 -Dest C:\Users\micro\AppData\Local\Temp\opencode\ghidra-c
#>
param(
    [Parameter(Mandatory = $true)][string]$Dest,
    [string]$Source = "C:\Tools\ghidra_12.1.4_PUBLIC",
    [switch]$KeepExtensions
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot 'lib/wasm-install.ps1')
if (-not (Test-Path -LiteralPath (Join-Path $Source 'Ghidra/application.properties'))) { throw "source install not found: $Source" }
$Source = Get-WasmCanonicalPath $Source
$Dest = Assert-WasmTestInstallDestination $Source $Dest
if (Test-Path -LiteralPath $Dest) { Remove-Item -LiteralPath $Dest -Recurse -Force }
New-Item -ItemType Directory -Path $Dest | Out-Null
$marker = Join-Path $Dest '.ghidra-wasm-test-install.json'
@{ source = $Source } | ConvertTo-Json | Set-Content -LiteralPath $marker -Encoding utf8

Write-Host "== copying $Source -> $Dest ==" -ForegroundColor Cyan
robocopy $Source $Dest /E /NFL /NDL /NJH /NJS /MT:16 | Out-Null
if ($LASTEXITCODE -lt 0 -or $LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE); incomplete test install: $Dest" }
@{ source = $Source } | ConvertTo-Json | Set-Content -LiteralPath $marker -Encoding utf8

if (-not $KeepExtensions) {
    foreach ($extension in @(Get-ChildItem (Join-Path $Dest "Ghidra\Extensions") -ErrorAction SilentlyContinue)) {
        $checked = Assert-WasmChildPath $extension.FullName $Dest
        Remove-Item -LiteralPath $checked -Recurse -Force
    }
}

Add-Content -Path (Join-Path $Dest "support\launch.properties") -Value @"

# --- isolated dirs for this test install (added by new-test-install.ps1) ---
VMARGS=-Dapplication.settingsdir=$Dest`\settings
VMARGS=-Dapplication.cachedir=$Dest`\cache
VMARGS=-Dapplication.tempdir=$Dest`\tmp
"@

Write-Host ("ready: {0} ({1:N2} GB, extensions: {2})" -f $Dest,
    ((Get-ChildItem $Dest -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1GB),
    ((Get-ChildItem (Join-Path $Dest 'Ghidra\Extensions') -ErrorAction SilentlyContinue).Count))
