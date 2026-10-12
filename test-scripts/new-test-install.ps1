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
if (-not (Test-Path $Source)) { throw "source install not found: $Source" }
if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }

Write-Host "== copying $Source -> $Dest ==" -ForegroundColor Cyan
robocopy $Source $Dest /E /NFL /NDL /NJH /NJS /MT:16 | Out-Null

if (-not $KeepExtensions) {
    Get-ChildItem (Join-Path $Dest "Ghidra\Extensions") -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force
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
