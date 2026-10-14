#!/usr/bin/env pwsh
<#
Regression test for R3: build-install.ps1 removed OTHER Ghidra versions' extension copies.

The bug
-------
The settings cleanup in build-install.ps1 walked every version directory under every Ghidra settings
root and deleted any extension that carries data\languages\WebAssembly.slaspec. Those roots
($APPDATA\ghidra, $XDG_CONFIG_HOME\ghidra, $HOME\.config\ghidra, $HOME\.ghidra and an isolated
install's <GhidraDir>\settings) are shared by EVERY Ghidra the user runs, so a run against one
selected installation uninstalled the extension from all of the user's other Ghidra versions.

The fix
-------
The sweep is scoped to the version directory that belongs to the selected installation, derived
from that installation's own Ghidra\application.properties (application.version +
application.release.name). Cross-version removal stays available behind -CleanAllVersions.

What this test does
-------------------
Builds mock settings trees in %TEMP% with two version directories per root - one for the target
version, one for another version - each holding a fake WebAssembly extension, then drives the real
cleanup module and asserts that ONLY the target version's copy is removed. No Ghidra install is
needed.

Usage: pwsh -NoProfile -File test-scripts/test-build-install-cleanup.ps1 [-OutDir <dir>]
#>
param(
    [string]$OutDir = (Join-Path ([IO.Path]::GetTempPath()) "build-install-cleanup-test")
)

$ErrorActionPreference = "Stop"

$lib = Join-Path $PSScriptRoot 'lib' 'wasm-settings-cleanup.ps1'
if (-not (Test-Path -LiteralPath $lib -PathType Leaf)) {
    Write-Host "FAIL: module under test not found: $lib" -ForegroundColor Red
    exit 1
}
. $lib

$onWindows = ($env:OS -eq 'Windows_NT')
if (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) { $onWindows = [bool]$IsWindows }

$failures = 0
function Check([string]$name, [bool]$cond, [string]$detail = "") {
    if ($cond) {
        Write-Host "ok  : $name" -ForegroundColor Green
    }
    else {
        Write-Host "FAIL: $name" -ForegroundColor Red
        if ($detail) { Write-Host "      $detail" -ForegroundColor Red }
        $script:failures++
    }
}

# --- mock builders ---------------------------------------------------------------------------

function New-MockInstall {
    <#
    A Ghidra install layout: <dir>\Ghidra\application.properties plus the isolated settings tree
    that new-test-install.ps1 creates (<dir>\settings).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Dir,
        [Parameter(Mandatory = $true)][string]$Version,
        [string]$ReleaseName = "PUBLIC",
        [string]$AppName = "Ghidra"
    )
    New-Item -ItemType Directory -Force -Path (Join-Path $Dir 'Ghidra') | Out-Null
    $lines = @(
        "application.name=$AppName",
        "application.version=$Version",
        "application.release.name=$ReleaseName"
    )
    Set-Content -LiteralPath (Join-Path $Dir 'Ghidra' 'application.properties') -Value $lines
    return $Dir
}

function New-MockWasmExtension {
    <#
    A WebAssembly extension copy as Ghidra's "Install Extensions" writes it: the zip's contents,
    i.e. data\languages\WebAssembly.slaspec plus the compiled WebAssembly.sla once Ghidra ran it.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ExtensionsDir,
        [string]$Name = "GhidraWasm"
    )
    $dir = Join-Path $ExtensionsDir $Name
    New-Item -ItemType Directory -Force -Path (Join-Path $dir 'data' 'languages') | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $dir 'lib') | Out-Null
    Set-Content -LiteralPath (Join-Path $dir 'data' 'languages' 'WebAssembly.slaspec') -Value "mock slaspec"
    Set-Content -LiteralPath (Join-Path $dir 'data' 'languages' 'WebAssembly.sla') -Value "mock compiled sla"
    Set-Content -LiteralPath (Join-Path $dir 'lib' "$Name.jar") -Value "mock jar"
    Set-Content -LiteralPath (Join-Path $dir 'extension.properties') -Value "name=$Name"
    return $dir
}

function New-MockForeignExtension {
    <#
    An unrelated extension in the same version directory. It must never be touched: the sweep only
    targets copies that provide the WebAssembly language.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ExtensionsDir,
        [string]$Name = "SomeOtherExtension"
    )
    $dir = Join-Path $ExtensionsDir $Name
    New-Item -ItemType Directory -Force -Path (Join-Path $dir 'lib') | Out-Null
    Set-Content -LiteralPath (Join-Path $dir 'lib' "$Name.jar") -Value "mock jar"
    return $dir
}

function New-MockVersionTree {
    <#
    Populate <Base> with one Extensions directory per version directory name, each holding a fake
    WebAssembly extension and an unrelated extension. -NestedUnderAppDir reproduces the layout an
    isolated install produces (<settingsdir>\ghidra\<version-dir>).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Base,
        [Parameter(Mandatory = $true)][string[]]$VersionDirs,
        [switch]$NestedUnderAppDir
    )
    foreach ($v in $VersionDirs) {
        $extBase = if ($NestedUnderAppDir) { Join-Path $Base 'ghidra' $v } else { Join-Path $Base $v }
        $extDir = Join-Path $extBase 'Extensions'
        New-Item -ItemType Directory -Force -Path $extDir | Out-Null
        New-MockWasmExtension -ExtensionsDir $extDir | Out-Null
        New-MockForeignExtension -ExtensionsDir $extDir | Out-Null
    }
}

# --- the mock world ---------------------------------------------------------------------------
#  install-a : Ghidra 12.1.4 PUBLIC  <- the SELECTED installation (the one being written to)
#  install-b : Ghidra 11.1.2 PUBLIC  <- another installation the user also runs (never written to)
#  roots     : two "default" roots (version directories directly under the root), the selected
#              install's own isolated settings root (version directories nested under <root>\ghidra)
#              and a legacy root using the dotted pre-11 directory spelling.

$work = Join-Path $OutDir "tree"
if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
New-Item -ItemType Directory -Force -Path $work | Out-Null

$installA = New-MockInstall -Dir (Join-Path $work 'install-a') -Version '12.1.4' -ReleaseName 'PUBLIC'
New-MockInstall -Dir (Join-Path $work 'install-b') -Version '11.1.2' -ReleaseName 'PUBLIC' | Out-Null

$targetVersionDir = 'ghidra_12.1.4_PUBLIC'
$otherVersionDir = 'ghidra_11.1.2_PUBLIC'

$defaultRoot = Join-Path $work 'roots' 'appdata'          # stands in for $APPDATA\ghidra
$xdgRoot = Join-Path $work 'roots' 'xdg'                  # stands in for $XDG_CONFIG_HOME\ghidra
$isolatedRoot = Join-Path $installA 'settings'            # -Dapplication.settingsdir of install-a
$legacyRoot = Join-Path $work 'roots' 'legacy'            # dotted pre-11 directory spelling

New-MockVersionTree -Base $defaultRoot -VersionDirs @($targetVersionDir, $otherVersionDir)
New-MockVersionTree -Base $xdgRoot -VersionDirs @($targetVersionDir, $otherVersionDir)
New-MockVersionTree -Base $isolatedRoot -VersionDirs @($targetVersionDir, $otherVersionDir) -NestedUnderAppDir
New-MockVersionTree -Base $legacyRoot -VersionDirs @(".ghidra_12.1.4_PUBLIC", ".ghidra_11.1.2_PUBLIC")

$roots = @($defaultRoot, $xdgRoot, $isolatedRoot, $legacyRoot, (Join-Path $work 'this-root-does-not-exist'))

# path -> must this copy be gone after a scoped sweep?
$scopedExpectation = [ordered]@{
    "$defaultRoot\$targetVersionDir\Extensions\GhidraWasm"              = $true    # target version, default layout
    "$defaultRoot\$otherVersionDir\Extensions\GhidraWasm"               = $false   # other Ghidra version
    "$defaultRoot\$targetVersionDir\Extensions\SomeOtherExtension"      = $false   # not a WebAssembly extension
    "$xdgRoot\$targetVersionDir\Extensions\GhidraWasm"                  = $true    # second default root
    "$xdgRoot\$otherVersionDir\Extensions\GhidraWasm"                   = $false
    "$isolatedRoot\ghidra\$targetVersionDir\Extensions\GhidraWasm"      = $true    # nested isolated layout
    "$isolatedRoot\ghidra\$otherVersionDir\Extensions\GhidraWasm"       = $false
    "$legacyRoot\.ghidra_12.1.4_PUBLIC\Extensions\GhidraWasm"           = $true    # dotted spelling of the target version
    "$legacyRoot\.ghidra_11.1.2_PUBLIC\Extensions\GhidraWasm"           = $false
}

$versionDirNames = Get-GhidraSettingsVersionDirNames -GhidraDir $installA
$appDirName = Get-GhidraAppDirName -GhidraDir $installA
$nestedTargetDir = (Resolve-Path -LiteralPath "$isolatedRoot\ghidra\$targetVersionDir").Path

# --- 1. the scope derived from the selected install -------------------------------------------
Check "the selected install's version directory name is derived" `
    ($versionDirNames -contains $targetVersionDir) `
    ("derived: {0}" -f ($versionDirNames -join ', '))
Check "the legacy (dotted) spelling of the target version is derived" `
    ($versionDirNames -contains ".ghidra_12.1.4_PUBLIC")
Check "the other install's version directory name is NOT derived" `
    (-not ($versionDirNames -contains $otherVersionDir))
Check "the application directory inside a settings root is derived" ($appDirName -eq 'ghidra') $appDirName
Check "the settings roots include the install's own settings directory" `
    ((Get-GhidraSettingsRoots -GhidraDir $installA) -contains $isolatedRoot)

# --- 2. the scoped sweep (the R3 fix) -----------------------------------------------------------
$result = Remove-ShadowingWasmExtensionCopies -SettingsRoots $roots -VersionDirNames $versionDirNames -AppDirName $appDirName

$expectedRemoved = @($scopedExpectation.Keys | Where-Object { $scopedExpectation[$_] })
foreach ($path in $scopedExpectation.Keys) {
    $shouldBeGone = [bool]$scopedExpectation[$path]
    $exists = Test-Path -LiteralPath $path -PathType Container
    if ($shouldBeGone) {
        Check ("removed: {0}" -f $path.Replace($work, '<tree>')) (-not $exists)
    }
    else {
        Check ("kept: {0}" -f $path.Replace($work, '<tree>')) $exists
    }
}

Check "the sweep reports exactly the copies it removed" `
    (@($result.Removed).Count -eq $expectedRemoved.Count) `
    ("removed: {0}" -f ((@($result.Removed) | ForEach-Object { $_.Replace($work, '<tree>') }) -join ', '))
Check "the sweep reports no warnings" (@($result.Warnings).Count -eq 0) ((@($result.Warnings)) -join '; ')
Check "the sweep reports the versions it deliberately left alone" `
    (@($result.Ignored | Where-Object { (Split-Path -Leaf $_) -eq $otherVersionDir }).Count -ge 3)
Check "the sweep sees the nested isolated-install layout" `
    (@($result.VersionDirs | Where-Object { $_ -eq $nestedTargetDir }).Count -eq 1) `
    ((@($result.VersionDirs) | ForEach-Object { $_.Replace($work, '<tree>') }) -join ', ')
Check "a settings root that does not exist is skipped without an error" ($true)

# --- 3. fail closed: an empty scope removes nothing ---------------------------------------------
$unscoped = Remove-ShadowingWasmExtensionCopies -SettingsRoots $roots -VersionDirNames @() -AppDirName $appDirName
Check "an empty version-dir scope removes nothing" (@($unscoped.Removed).Count -eq 0)
Check "an empty version-dir scope leaves the other version's copy alone" `
    (Test-Path -LiteralPath "$defaultRoot\$otherVersionDir\Extensions\GhidraWasm" -PathType Container)

# --- 4. -CleanAllVersions (the opt-in cross-version sweep) ---------------------------------------
$treeAll = Join-Path $OutDir "tree-all"
if (Test-Path -LiteralPath $treeAll) { Remove-Item -LiteralPath $treeAll -Recurse -Force }
New-Item -ItemType Directory -Force -Path $treeAll | Out-Null
New-MockInstall -Dir (Join-Path $treeAll 'install') -Version '12.1.4' | Out-Null
$rootAll = Join-Path $treeAll 'roots' 'appdata'
New-MockVersionTree -Base $rootAll -VersionDirs @($targetVersionDir, $otherVersionDir)
$allVersions = Remove-ShadowingWasmExtensionCopies -SettingsRoots @($rootAll) `
    -VersionDirNames @($targetVersionDir) -AppDirName $appDirName -AllVersions
Check "-CleanAllVersions removes every version's copy" `
    ((-not (Test-Path -LiteralPath "$rootAll\$targetVersionDir\Extensions\GhidraWasm" -PathType Container)) -and
     (-not (Test-Path -LiteralPath "$rootAll\$otherVersionDir\Extensions\GhidraWasm" -PathType Container)))
Check "-CleanAllVersions still leaves unrelated extensions alone" `
    (Test-Path -LiteralPath "$rootAll\$otherVersionDir\Extensions\SomeOtherExtension" -PathType Container)

# --- 5. a locked copy warns, it does not abort the install ---------------------------------------
$treeLock = Join-Path $OutDir "tree-locked"
if (Test-Path -LiteralPath $treeLock) { Remove-Item -LiteralPath $treeLock -Recurse -Force }
New-Item -ItemType Directory -Force -Path $treeLock | Out-Null
$rootLock = Join-Path $treeLock 'roots' 'appdata'
New-MockVersionTree -Base $rootLock -VersionDirs @($targetVersionDir)
$lockedJar = Join-Path $rootLock "$targetVersionDir\Extensions\GhidraWasm\lib\GhidraWasm.jar"

$lockThrew = $false
$lockWarnings = @()
$held = $null
try {
    if ($onWindows -and (Test-Path -LiteralPath $lockedJar -PathType Leaf)) {
        $held = [IO.File]::Open($lockedJar, 'Open', 'ReadWrite', 'None')
    }
    $lockResult = Remove-ShadowingWasmExtensionCopies -SettingsRoots @($rootLock) `
        -VersionDirNames @($targetVersionDir) -AppDirName $appDirName
    if ($lockResult) { $lockWarnings = @($lockResult.Warnings) }
}
catch {
    $lockThrew = $true
}
finally {
    if ($held) { $held.Close(); $held.Dispose() }
}

if ($onWindows -and $held) {
    Check "a locked copy does not abort the sweep" (-not $lockThrew)
    Check "a locked copy is reported as a warning" ($lockWarnings.Count -ge 1) ($lockWarnings -join '; ')
    Check "a locked copy survives" (Test-Path -LiteralPath $lockedJar -PathType Leaf)
}
else {
    Write-Host "skip: file-lock check needs Windows and an open jar handle" -ForegroundColor Yellow
}

# --- 6. an install without application.properties yields an empty scope ---------------------------
$badInstall = Join-Path $OutDir "install-bad"
New-Item -ItemType Directory -Force -Path (Join-Path $badInstall 'Ghidra') | Out-Null
$badNames = Get-GhidraSettingsVersionDirNames -GhidraDir $badInstall
Check "an install without application.version yields no scope" (@($badNames).Count -eq 0) ($badNames -join ', ')

# --- 7. optional: the derivation against the pinned real install (read-only) -----------------------
$pinnedFile = Join-Path $PSScriptRoot '.ghidra-install'
if (Test-Path -LiteralPath $pinnedFile -PathType Leaf) {
    $pinned = (Get-Content -LiteralPath $pinnedFile -Raw).Trim()
    $props = Join-Path $pinned 'Ghidra'
    $props = Join-Path $props 'application.properties'
    if ($pinned -and (Test-Path -LiteralPath $props -PathType Leaf)) {
        $realNames = Get-GhidraSettingsVersionDirNames -GhidraDir $pinned
        Check "the pinned install ($pinned) yields its version directory" (@($realNames).Count -gt 0) `
            ($realNames -join ', ')
        foreach ($realRoot in (Get-GhidraSettingsRoots -GhidraDir $pinned)) {
            if (-not (Test-Path -LiteralPath $realRoot -PathType Container)) { continue }
            $present = @(Get-ChildItem -LiteralPath $realRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
            $appDir = Join-Path $realRoot $appDirName
            if (Test-Path -LiteralPath $appDir -PathType Container) {
                $present += @(Get-ChildItem -LiteralPath $appDir -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
            }
            $match = @($present | Where-Object { $realNames -contains $_ })
            Write-Host ("note: settings root {0} holds [{1}] -> in scope: {2}" -f `
                $realRoot, ($present -join ', '), (($match -join ', ') + '')) -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host "skip: the pinned install path is not present on this machine" -ForegroundColor Yellow
    }
}
else {
    Write-Host "skip: no .ghidra-install pin in this checkout" -ForegroundColor Yellow
}

# --- verdict -------------------------------------------------------------------------------------
Write-Host ""
if ($failures -eq 0) {
    Write-Host "PASS: the settings sweep removes only the selected installation's copy (mock trees under $OutDir)" -ForegroundColor Green
    exit 0
}
Write-Host "FAIL: $failures check(s) failed (mock trees under $OutDir)" -ForegroundColor Red
exit 1
