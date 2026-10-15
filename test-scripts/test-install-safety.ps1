param([string]$OutDir = (Join-Path $PSScriptRoot '../build/install-safety'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib/wasm-settings-cleanup.ps1')
. (Join-Path $PSScriptRoot 'lib/wasm-install.ps1')
$root = Join-Path ([IO.Path]::GetFullPath($OutDir)) ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $root | Out-Null
function Assert($condition, $message) { if (-not $condition) { throw $message }; Write-Output "PASS $message" }
function Reject([scriptblock]$action, $message) {
    $rejected = $false
    try { & $action | Out-Null } catch { $rejected = $true }
    Assert $rejected $message
}
function MockExtension($parent, $name, $contents) {
    $dir = Join-Path $parent $name
    New-Item -ItemType Directory -Force (Join-Path $dir 'data/languages'), (Join-Path $dir 'lib') | Out-Null
    Set-Content -LiteralPath (Join-Path $dir 'data/languages/WebAssembly.slaspec') -Value 'fixture'
    Set-Content -LiteralPath (Join-Path $dir 'lib/test.jar') -Value $contents
    return $dir
}
$extensions = Join-Path $root 'Extensions'
$old = MockExtension $extensions 'old-wasm' 'old'
$other = Join-Path $extensions 'unrelated'
New-Item -ItemType Directory -Force $other | Out-Null
Set-Content -LiteralPath (Join-Path $other 'keep.jar') -Value 'keep'
$incoming = MockExtension (Join-Path $root 'incoming') 'new-wasm' 'new'
$zip = Join-Path $root 'extension.zip'
Compress-Archive -LiteralPath $incoming -DestinationPath $zip
$lock = [IO.File]::Open((Join-Path $other 'keep.jar'), 'Open', 'Read', 'None')
try { $installed = Install-WasmExtensionArchive $zip $extensions } finally { $lock.Close() }
Assert (Test-Path -LiteralPath (Join-Path $other 'keep.jar')) 'unrelated locked extension preserved'
Assert (-not (Test-Path -LiteralPath $old)) 'old Wasm copy replaced'
Assert ((Get-Content -LiteralPath (Join-Path $installed.FullName 'lib/test.jar') -Raw).Trim() -eq 'new') 'replacement installed'
$bad = Join-Path $root 'broken.zip'
Set-Content -LiteralPath $bad -Value 'not a zip'
Reject { Install-WasmExtensionArchive $bad $extensions } 'malformed archive rejected'
Assert (Test-Path -LiteralPath (Join-Path $installed.FullName 'lib/test.jar')) 'old installation survives failed extraction'
$source = Join-Path $root 'source'
New-Item -ItemType Directory $source | Out-Null
Reject { Assert-WasmTestInstallDestination $source $source } 'equal source/destination rejected'
Reject { Assert-WasmTestInstallDestination $source $root } 'source ancestor rejected'
Reject { Assert-WasmTestInstallDestination $source (Join-Path $source 'child') } 'source descendant rejected'
Reject { Assert-WasmTestInstallDestination $source $other } 'unowned destination rejected'
$owned = Join-Path $root 'owned'
New-Item -ItemType Directory $owned | Out-Null
@{source=(Get-WasmCanonicalPath $source)} | ConvertTo-Json | Set-Content (Join-Path $owned '.ghidra-wasm-test-install.json')
Assert ((Assert-WasmTestInstallDestination $source $owned) -eq $owned) 'owned destination accepted'
$alias = Join-Path $root 'source-alias'
New-Item -ItemType Junction -Path $alias -Target $source | Out-Null
try {
    Reject { Assert-WasmTestInstallDestination $source (Join-Path $alias 'child') } 'destination with a junction ancestor rejected'
} finally { Remove-Item -LiteralPath $alias -Force }
New-Item -ItemType Directory -Force (Join-Path $source 'Ghidra'), (Join-Path $source 'support') | Out-Null
Set-Content (Join-Path $source 'Ghidra/application.properties') 'application.version=fixture'
Set-Content (Join-Path $source 'support/launch.properties') 'fixture'
Set-Content (Join-Path $source 'source-sentinel') 'keep'
function robocopy { $global:LASTEXITCODE = 16 }
try {
    Reject { & (Join-Path $PSScriptRoot 'new-test-install.ps1') -Source $source -Dest (Join-Path $root 'failed-copy') } 'robocopy failure propagates'
    Assert ((Get-Content (Join-Path $source 'source-sentinel')) -eq 'keep') 'failed copy preserves source'
} finally { Remove-Item Function:\robocopy }
$collision = Join-Path $root 'collision'
New-Item -ItemType Directory -Force (Join-Path $collision 'new-wasm') | Out-Null
Set-Content (Join-Path $collision 'new-wasm/keep.txt') 'keep'
Reject { Install-WasmExtensionArchive $zip $collision } 'unrelated destination-name collision rejected'
Assert ((Get-Content (Join-Path $collision 'new-wasm/keep.txt')) -eq 'keep') 'name collision preserves unrelated content'
$lockedJar = Join-Path $installed.FullName 'lib/test.jar'
$lock = [IO.File]::Open($lockedJar, 'Open', 'Read', 'None')
try { Reject { Install-WasmExtensionArchive $zip $extensions } 'locked Wasm installation blocks replacement' } finally { $lock.Close() }
Assert ((Get-Content $lockedJar -Raw).Trim() -eq 'new') 'locked installation remains intact'
