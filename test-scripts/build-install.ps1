<#
.SYNOPSIS
    Build the WebAssembly extension from the current worktree and cleanly install it into a Ghidra
    install (so the freshly built jar is the only copy of the plugin that Ghidra can see).

.DESCRIPTION
    1. runs `gradle buildExtension` in the current directory with GHIDRA_INSTALL_DIR set,
    2. replaces only previously installed WebAssembly copies under <GhidraDir>\Ghidra\Extensions,
    3. extracts the newly built zip there,
    4. removes shadowing copies from the per-user settings directories of THIS Ghidra version only
       (see -CleanAllVersions for the cross-version sweep).

    Removing the old extension matters twice: two extension directories that both contain the
    `wasm.*` classes would be an ambiguous classpath, and a stale `WebAssembly.sla` can mask SLEIGH
    changes (the .sla is regenerated on the next run, which adds ~20-30s to the first import).

.EXAMPLE
    $env:GHIDRA_INSTALL_DIR = "C:\Users\micro\AppData\Local\Temp\ghidra-a"
    .\test-scripts\build-install.ps1

.EXAMPLE
    .\test-scripts\build-install.ps1 -SkipBuild -CleanAllVersions
    # also purge the extension from every other Ghidra version's settings directory
#>
param(
    [string]$GhidraDir = "",
    [string]$Gradle = "C:\Tools\gradle-9.2.1\bin\gradle.bat",
    [switch]$SkipBuild,
    [switch]$Force,   # ignore the worktree's pinned install (see .ghidra-install)
    [switch]$CleanAllVersions   # opt in to the cross-version settings sweep (see R3 note below)
)

$ErrorActionPreference = "Stop"

# --- install pinning -------------------------------------------------------------------------
# Every worktree/checkout carries `test-scripts/.ghidra-install` naming the ONE Ghidra install it is
# allowed to use. This prevents two workstreams (or a workstream and the integrator) from building into each
# other's install, which produces "measurements against a stale/wrong extension" and is invisible in
# the logs. Pass -Force only when you deliberately want another folder.
$pinFile = Join-Path $PSScriptRoot ".ghidra-install"
if (Test-Path $pinFile) {
    $pinned = (Get-Content $pinFile -Raw).Trim()
    if (-not $GhidraDir) {
        $GhidraDir = $pinned
        Write-Host "== using the pinned Ghidra install: $pinned ==" -ForegroundColor DarkGray
    }
    elseif ($GhidraDir -ne $pinned -and (Resolve-Path -LiteralPath $GhidraDir -ErrorAction SilentlyContinue).Path -ne (Resolve-Path -LiteralPath $pinned -ErrorAction SilentlyContinue).Path -and -not $Force) {
        throw "REFUSED: this checkout is pinned to '$pinned' (test-scripts/.ghidra-install). Pass -Force to override, or use the pinned folder."
    }
}
if (-not $GhidraDir) { $GhidraDir = $env:GHIDRA_INSTALL_DIR }
if (-not $GhidraDir) { throw "Set GHIDRA_INSTALL_DIR or pass -GhidraDir" }
if (-not (Test-Path $GhidraDir)) { throw "Ghidra install not found: $GhidraDir" }

$repo = Split-Path -Parent $PSScriptRoot

# The settings cleanup lives in its own module so it can be unit-tested against mock settings trees
# (test-scripts\test-build-install-cleanup.ps1) without a Ghidra install.
. (Join-Path $PSScriptRoot 'lib' 'wasm-settings-cleanup.ps1')

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
    . (Join-Path $PSScriptRoot 'lib/wasm-install.ps1')
    $installed = @(Install-WasmExtensionArchive -Archive $zip.FullName -ExtensionRoot $extDir)
    $installed | ForEach-Object { Write-Host ('installed: ' + $_.Name) }

    # Ghidra also loads extensions from its per-user settings directory (an isolated test install
    # keeps that directory inside itself, see new-test-install.ps1). A second copy there - e.g. one
    # installed through Ghidra's GUI - shadows the freshly built extension: in particular it
    # silently supplies a STALE compiled language, because the zip's source files carry 1980
    # timestamps and a previously compiled .sla therefore always looks newer than the sources.
    #
    # R3: the sweep is scoped to the version directory that belongs to THIS install. The settings
    # roots are shared by every Ghidra the user runs, so a sweep that ignored the version directory
    # also deleted the extension copies of other Ghidra versions (and silently uninstalled the
    # extension there). -CleanAllVersions re-enables that cross-version purge on purpose.
    $settingsRoots = Get-GhidraSettingsRoots -GhidraDir $GhidraDir
    $versionDirNames = Get-GhidraSettingsVersionDirNames -GhidraDir $GhidraDir
    $appDirName = Get-GhidraAppDirName -GhidraDir $GhidraDir

    if ($CleanAllVersions) {
        Write-Warning "-CleanAllVersions: removing WebAssembly extension copies for EVERY Ghidra version under $($settingsRoots -join ', ')"
    }
    elseif (-not $versionDirNames) {
        throw ("cannot tell which Ghidra version $GhidraDir is (no application.version in {0}) - " +
               "refusing to sweep the shared settings directories. Pass -CleanAllVersions for a " +
               "cross-version purge, or install from a layout that ships application.properties." -f
               (Join-Path $GhidraDir 'Ghidra' 'application.properties'))
    }
    else {
        Write-Host ("== settings sweep limited to version directory: {0} ==" -f ($versionDirNames -join ", ")) -ForegroundColor Cyan
    }

    $cleanup = Remove-ShadowingWasmExtensionCopies -SettingsRoots $settingsRoots `
        -VersionDirNames $versionDirNames -AppDirName $appDirName -AllVersions:$CleanAllVersions
    foreach ($path in $cleanup.Removed) {
        Write-Host ("removed shadowing extension copy: {0}" -f $path) -ForegroundColor Yellow
    }
    if (-not $CleanAllVersions -and $cleanup.Ignored.Count -gt 0) {
        # Report what was deliberately left alone so a stale settings copy elsewhere is visible
        # instead of silent.
        Write-Host ("kept (other Ghidra versions): {0}" -f (($cleanup.Ignored | ForEach-Object { Split-Path -Leaf $_ }) -join ", ")) -ForegroundColor DarkGray
    }
    foreach ($warning in $cleanup.Warnings) { Write-Warning $warning }

    # Record which checkout this install now holds, so a later measurement can prove the extension
    # under test is the one that was built here (see the freshness guard in run_probes.ps1).
    $stampFile = Join-Path $GhidraDir "ghidra-wasm-install-stamp.json"
    $stamp = [pscustomobject]@{
        worktree  = $repo
        zip       = $zip.Name
        sha256    = (Get-FileHash $zip.FullName -Algorithm SHA256).Hash
        installed = (Get-Date).ToString("o")
    }
    $stamp | ConvertTo-Json | Set-Content -Path $stampFile -Encoding UTF8
    Write-Host "stamp: $stampFile"
}
finally {
    Pop-Location
}
