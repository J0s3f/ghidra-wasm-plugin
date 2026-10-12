<#
.SYNOPSIS
    Build the WebAssembly extension from the current worktree and cleanly install it into a Ghidra
    install (so the freshly built jar is the only copy of the plugin that Ghidra can see).

.DESCRIPTION
    1. runs `gradle buildExtension` in the current directory with GHIDRA_INSTALL_DIR set,
    2. removes every previously installed extension under <GhidraDir>\Ghidra\Extensions,
    3. extracts the newly built zip there.

    Removing the old extension matters twice: two extension directories that both contain the
    `wasm.*` classes would be an ambiguous classpath, and a stale `WebAssembly.sla` can mask SLEIGH
    changes (the .sla is regenerated on the next run, which adds ~20-30s to the first import).

.EXAMPLE
    $env:GHIDRA_INSTALL_DIR = "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-a"
    .\test-scripts\build-install.ps1
#>
param(
    [string]$GhidraDir = $env:GHIDRA_INSTALL_DIR,
    [string]$Gradle = "C:\Tools\gradle-9.2.1\bin\gradle.bat",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
if (-not $GhidraDir) { throw "Set GHIDRA_INSTALL_DIR or pass -GhidraDir" }
if (-not (Test-Path $GhidraDir)) { throw "Ghidra install not found: $GhidraDir" }

$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try {
    if (-not $SkipBuild) {
        $env:GHIDRA_INSTALL_DIR = $GhidraDir
        Write-Host "== building (GHIDRA_INSTALL_DIR=$GhidraDir) ==" -ForegroundColor Cyan
        & $Gradle --no-daemon buildExtension
        if ($LASTEXITCODE -ne 0) { throw "gradle buildExtension failed ($LASTEXITCODE)" }
    }

    $zip = Get-ChildItem (Join-Path $repo "dist\*.zip") |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $zip) { throw "no zip in $repo\dist" }

    $extDir = Join-Path $GhidraDir "Ghidra\Extensions"
    Write-Host "== installing $($zip.Name) into $extDir ==" -ForegroundColor Cyan
    Get-ChildItem $extDir -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
    Expand-Archive -Path $zip.FullName -DestinationPath $extDir -Force

    Get-ChildItem $extDir | ForEach-Object {
        $jar = Join-Path $_.FullName "lib\Ghidra-WASM.jar"
        $stamp = if (Test-Path $jar) { (Get-Item $jar).LastWriteTime } else { "(no jar)" }
        Write-Host ("installed: {0}  jar: {1}" -f $_.Name, $stamp)
    }
}
finally {
    Pop-Location
}
