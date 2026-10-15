# File operations shared by the installer and its regression tests.
function Assert-WasmNoLinkedAncestors([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Refusing a filesystem link in install path: $current"
            }
        }
        $parent = Split-Path -Parent $current
        if ($parent -eq $current) { break }
        $current = $parent
    }
}

function Get-WasmCanonicalPath([string]$Path) {
    if (Test-Path -LiteralPath $Path) { return (Resolve-Path -LiteralPath $Path).ProviderPath.TrimEnd('\','/') }
    return [IO.Path]::GetFullPath($Path).TrimEnd('\','/')
}

function Assert-WasmChildPath([string]$Path, [string]$Parent) {
    $resolved = Get-WasmCanonicalPath $Path
    $root = Get-WasmCanonicalPath $Parent
    if (-not $resolved.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path '$resolved' is not a child of '$root'"
    }
    return $resolved
}

function Assert-WasmTestInstallDestination([string]$Source, [string]$Destination) {
    Assert-WasmNoLinkedAncestors $Source
    Assert-WasmNoLinkedAncestors $Destination
    $src = Get-WasmCanonicalPath $Source
    $dst = Get-WasmCanonicalPath $Destination
    $sep = [IO.Path]::DirectorySeparatorChar
    if ($src.Equals($dst, [StringComparison]::OrdinalIgnoreCase) -or
        $src.StartsWith($dst + $sep, [StringComparison]::OrdinalIgnoreCase) -or
        $dst.StartsWith($src + $sep, [StringComparison]::OrdinalIgnoreCase) -or
        $dst -eq [IO.Path]::GetPathRoot($dst).TrimEnd('\','/')) {
        throw "Unsafe test-install source/destination relationship: '$src' -> '$dst'"
    }
    if (Test-Path -LiteralPath $dst) {
        if ((Get-Item -LiteralPath $dst).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Test-install destination must not be a link: $dst"
        }
        $marker = Join-Path $dst '.ghidra-wasm-test-install.json'
        if (-not (Test-Path -LiteralPath $marker)) { throw "Refusing to replace an unowned directory: $dst" }
        $metadata = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
        if (-not $src.Equals([string]$metadata.source, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Test-install marker belongs to a different source: $dst"
        }
    }
    return $dst
}

function Install-WasmExtensionArchive([string]$Archive, [string]$ExtensionRoot) {
    Assert-WasmNoLinkedAncestors $ExtensionRoot
    New-Item -ItemType Directory -Force -Path $ExtensionRoot | Out-Null
    $root = Get-WasmCanonicalPath $ExtensionRoot
    $staging = Assert-WasmChildPath (Join-Path $root ('.wasm-install-' + [Guid]::NewGuid().ToString('N'))) $root
    New-Item -ItemType Directory -Path $staging | Out-Null
    $backups = @()
    $destination = $null
    $published = $false
    try {
        $unpacked = Join-Path $staging 'unpacked'
        Expand-Archive -LiteralPath $Archive -DestinationPath $unpacked -ErrorAction Stop
        $candidates = @(Get-ChildItem -LiteralPath $unpacked -Directory)
        if ($candidates.Count -ne 1 -or -not (Test-WasmExtensionDir $candidates[0].FullName) -or
            -not @(Get-ChildItem -LiteralPath (Join-Path $candidates[0].FullName 'lib') -Filter '*.jar' -File -ErrorAction SilentlyContinue)) {
            throw 'Archive must contain exactly one WebAssembly extension with a lib/*.jar'
        }
        $replacement = $candidates[0]
        $destination = Assert-WasmChildPath (Join-Path $root $replacement.Name) $root
        $oldCopies = @(Get-ChildItem -LiteralPath $root -Directory | Where-Object { Test-WasmExtensionDir $_.FullName })
        if ((Test-Path -LiteralPath $destination) -and -not (Test-WasmExtensionDir $destination)) {
            throw "An unrelated extension occupies $destination"
        }
        foreach ($old in $oldCopies) {
            $oldPath = Assert-WasmChildPath $old.FullName $root
            if ($old.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing to replace linked extension $oldPath" }
            foreach ($jar in @(Get-ChildItem -LiteralPath (Join-Path $oldPath 'lib') -Filter '*.jar' -File -ErrorAction SilentlyContinue)) {
                $stream = [IO.File]::Open($jar.FullName, 'Open', 'ReadWrite', 'None')
                $stream.Close()
            }
        }
        foreach ($old in $oldCopies) {
            $backup = Join-Path $staging ('backup-' + $backups.Count)
            Move-Item -LiteralPath $old.FullName -Destination $backup -ErrorAction Stop
            $backups += @{ original = $old.FullName; backup = $backup }
        }
        Move-Item -LiteralPath $replacement.FullName -Destination $destination -ErrorAction Stop
        $published = $true
        return Get-Item -LiteralPath $destination
    }
    catch {
        foreach ($backup in $backups) {
            if (Test-Path -LiteralPath $backup.backup) {
                Move-Item -LiteralPath $backup.backup -Destination $backup.original -ErrorAction Stop
            }
        }
        throw
    }
    finally {
        # Only our newly created staging directory is deleted; old installations were
        # moved here only after archive validation and are restored on a failed move.
        if (Test-Path -LiteralPath $staging) {
            $checked = Assert-WasmChildPath $staging $root
            if ($published -or $backups.Count -eq 0 -or -not @(Get-ChildItem -LiteralPath $checked -Directory -Filter 'backup-*')) {
                Remove-Item -LiteralPath $checked -Recurse -Force
            }
        }
    }
}
