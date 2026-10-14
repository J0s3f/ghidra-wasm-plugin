#!/usr/bin/env pwsh
# Shared helpers for the "shadowing extension copy" cleanup used by build-install.ps1.
#
# Ghidra resolves extensions from two places:
#   * the install itself:                 <GhidraDir>\Ghidra\Extensions
#   * the per-user settings directory:    <settingsRoot>\<version-dir>\Extensions
#       default roots: $APPDATA\ghidra, $XDG_CONFIG_HOME\ghidra, $HOME\.config\ghidra,
#                      $HOME\.ghidra  (Windows/macOS/Linux)
#       an isolated test install additionally sets -Dapplication.settingsdir=<GhidraDir>\settings,
#       which places the settings tree at <GhidraDir>\settings\ghidra\<version-dir>
#
# A second copy of this extension inside the settings tree shadows the freshly installed one: in
# particular it silently supplies a STALE compiled language, because the .sla is regenerated on the
# next run while the zip's source files carry 1980 timestamps, so a previously compiled .sla always
# looks newer than the sources.
#
# R3: those settings roots are shared by EVERY Ghidra installation the user runs, so the sweep has
# to be scoped to the version directory that belongs to the installation being written. A sweep that
# ignores the version directory also deletes extension copies installed for *other* Ghidra versions
# and silently uninstalls the extension there. -CleanAllVersions in build-install.ps1 opts back into
# the cross-version sweep for a deliberate purge.
#
# Usage (dot-source, then call):
#   . "$PSScriptRoot\lib\wasm-settings-cleanup.ps1"
#   $roots  = Get-GhidraSettingsRoots -GhidraDir $GhidraDir
#   $names  = Get-GhidraSettingsVersionDirNames -GhidraDir $GhidraDir
#   $appDir = Get-GhidraAppDirName -GhidraDir $GhidraDir
#   $result = Remove-ShadowingWasmExtensionCopies -SettingsRoots $roots -VersionDirNames $names -AppDirName $appDir
#   $result.Removed / $result.Ignored / $result.Warnings

# ---------------------------------------------------------------------------------------------
# application.properties
# ---------------------------------------------------------------------------------------------

function Read-GhidraApplicationProperties {
    <#
    .SYNOPSIS
        Parse GhidraDir\Ghidra\application.properties into a hashtable.
    .OUTPUTS
        Hashtable of key -> value. Empty when the file is missing (nothing is ever thrown, so a
        caller can decide how loudly to fail).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$GhidraDir
    )

    $props = @{}
    $file = Join-Path $GhidraDir 'Ghidra'
    $file = Join-Path $file 'application.properties'
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return $props }

    foreach ($line in @(Get-Content -LiteralPath $file)) {
        if ($null -eq $line) { continue }
        if ($line -match '^\s*#') { continue }
        $idx = $line.IndexOf('=')
        if ($idx -le 0) { continue }
        $key = $line.Substring(0, $idx).Trim()
        $val = $line.Substring($idx + 1).Trim()
        if (-not $key) { continue }
        if (-not $props.ContainsKey($key)) { $props[$key] = $val }
    }
    return $props
}

# ---------------------------------------------------------------------------------------------
# per-install settings scope
# ---------------------------------------------------------------------------------------------

function Get-GhidraSettingsRoots {
    <#
    .SYNOPSIS
        The Ghidra per-user settings roots a run may have written to.
    .DESCRIPTION
        These roots are shared by every Ghidra installation of the user - which is exactly why they
        must not be swept wholesale (see the header comment).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$GhidraDir
    )

    $roots = [System.Collections.Generic.List[string]]::new()
    if ($env:APPDATA) { $roots.Add((Join-Path $env:APPDATA 'ghidra')) }
    if ($env:XDG_CONFIG_HOME) { $roots.Add((Join-Path $env:XDG_CONFIG_HOME 'ghidra')) }
    if ($HOME) {
        $roots.Add((Join-Path $HOME '.config/ghidra'))
        $roots.Add((Join-Path $HOME '.ghidra'))
    }
    # Isolated test installs keep their settings inside the install (new-test-install.ps1 sets
    # -Dapplication.settingsdir=<GhidraDir>\settings).
    $roots.Add((Join-Path $GhidraDir 'settings'))
    return [string[]]$roots
}

function Get-GhidraAppDirName {
    <#
    .SYNOPSIS
        Name of the application directory inside a settings root ('ghidra' for stock Ghidra).
    .DESCRIPTION
        With -Dapplication.settingsdir=<dir>, Ghidra nests its settings tree one level deeper:
        <dir>\<app-dir>\<version-dir>. With a default root the version directory sits directly
        inside the root. Both spellings are produced by taking the application name from the
        install's own application.properties.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$GhidraDir
    )

    $props = Read-GhidraApplicationProperties -GhidraDir $GhidraDir
    $appName = $props['application.name']
    if (-not $appName) { $appName = 'Ghidra' }
    return $appName.ToLowerInvariant()
}

function Get-GhidraSettingsVersionDirNames {
    <#
    .SYNOPSIS
        Candidate names of the per-user settings version directory owned by one Ghidra install.
    .DESCRIPTION
        Ghidra names that directory after the application's release, e.g. ghidra_12.1.4_PUBLIC.
        Older releases used a leading dot (.ghidra_10.2.3_PUBLIC) and builds without a release name
        use just ghidra_12.1.4, so both spellings are returned. Matching is case-insensitive.
    .OUTPUTS
        string[] - empty when the install publishes no application.version (the caller must decide
        what to do rather than silently widening the sweep).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$GhidraDir
    )

    $names = [System.Collections.Generic.List[string]]::new()

    $props = Read-GhidraApplicationProperties -GhidraDir $GhidraDir
    $version = $props['application.version']
    if (-not $version) { return [string[]]$names }

    $prefix = (Get-GhidraAppDirName -GhidraDir $GhidraDir)
    $release = $props['application.release.name']

    $suffixes = [System.Collections.Generic.List[string]]::new()
    if ($release) { $suffixes.Add(($version + '_' + $release)) }
    $suffixes.Add($version)

    foreach ($suffix in $suffixes) {
        foreach ($lead in @('', '.')) {
            $name = ($lead + $prefix + '_' + $suffix)
            if (-not $names.Contains($name)) { $names.Add($name) }
        }
    }
    return [string[]]$names
}

# ---------------------------------------------------------------------------------------------
# the sweep
# ---------------------------------------------------------------------------------------------

function Test-WasmExtensionDir {
    <#
    .SYNOPSIS
        True when the given directory is an installed WebAssembly extension.
    .DESCRIPTION
        Recognised by its language definition - the file whose compiled form (.sla) is the thing a
        stale copy most dangerously supplies.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $false }
    $data = Join-Path $Path 'data'
    $langs = Join-Path $data 'languages'
    $marker = Join-Path $langs 'WebAssembly.slaspec'
    return (Test-Path -LiteralPath $marker -PathType Leaf)
}

function Remove-ShadowingWasmExtensionCopies {
    <#
    .SYNOPSIS
        Delete WebAssembly extension copies that shadow a freshly installed one.
    .DESCRIPTION
        Walks the given settings roots and removes Extensions\<name> directories that carry the
        WebAssembly language definition (data\languages\WebAssembly.slaspec).

        Without -AllVersions the walk is restricted to the version directories that belong to the
        selected installation (names from Get-GhidraSettingsVersionDirNames), so an extension
        installed for another Ghidra version is left alone. With -AllVersions every version
        directory under every root is swept - that is the pre-R3 behaviour and deletes copies the
        user still needs.
    .PARAMETER SettingsRoots
        Settings roots to sweep (see Get-GhidraSettingsRoots). Non-existing roots are skipped.
    .PARAMETER VersionDirNames
        Version directory names that are in scope. Ignored when -AllVersions is given.
    .PARAMETER AppDirName
        Application directory name inside a settings root (see Get-GhidraAppDirName); the extra
        nesting only exists for an overridden -Dapplication.settingsdir.
    .OUTPUTS
        pscustomobject with:
          VersionDirs - version directories that were in scope and exist
          Removed     - full paths of the extension copies that were deleted
          Ignored     - version directories seen but NOT in scope (other Ghidra versions)
          Warnings    - removal failures (never fatal: one locked copy must not abort the install)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$SettingsRoots,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$VersionDirNames,
        [string]$AppDirName = 'ghidra',
        [switch]$AllVersions
    )

    $inScope   = [System.Collections.Generic.List[string]]::new()
    $ignored   = [System.Collections.Generic.List[string]]::new()
    $removed   = [System.Collections.Generic.List[string]]::new()
    $warnings  = [System.Collections.Generic.List[string]]::new()

    foreach ($root in $SettingsRoots) {
        if (-not $root) { continue }
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }

        # Version directories directly under the root ...
        $candidates = [System.Collections.Generic.List[string]]::new()
        foreach ($child in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)) {
            $candidates.Add($child.FullName)
        }
        # ... plus the ones nested under the application directory (isolated installs).
        if ($AppDirName) {
            $appDir = Join-Path $root $AppDirName
            if (Test-Path -LiteralPath $appDir -PathType Container) {
                foreach ($child in @(Get-ChildItem -LiteralPath $appDir -Directory -ErrorAction SilentlyContinue)) {
                    $candidates.Add($child.FullName)
                }
            }
        }

        foreach ($dir in $candidates) {
            $name = Split-Path -Leaf $dir
            $wanted = $false
            if ($AllVersions) {
                $wanted = $true
            }
            else {
                foreach ($want in $VersionDirNames) {
                    if ($want -and $name.Equals($want, [StringComparison]::OrdinalIgnoreCase)) { $wanted = $true; break }
                }
            }
            if (-not $wanted) {
                $ignored.Add($dir)
                continue
            }
            $inScope.Add($dir)

            $extRoot = Join-Path $dir 'Extensions'
            if (-not (Test-Path -LiteralPath $extRoot -PathType Container)) { continue }
            foreach ($candidate in @(Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue)) {
                if (-not (Test-WasmExtensionDir -Path $candidate.FullName)) { continue }
                try {
                    Remove-Item -LiteralPath $candidate.FullName -Recurse -Force -ErrorAction Stop
                    $removed.Add($candidate.FullName)
                }
                catch {
                    $warnings.Add(("could not remove {0}: {1}" -f $candidate.FullName, $_.Exception.Message))
                }
            }
        }
    }

    return [pscustomobject]@{
        VersionDirs = [string[]]$inScope
        Removed     = [string[]]$removed
        Ignored     = [string[]]$ignored
        Warnings    = [string[]]$warnings
    }
}
