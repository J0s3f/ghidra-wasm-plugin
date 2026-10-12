<#
.SYNOPSIS
    Fetch the pinned WebAssembly spec-test toolchain (wabt + spec testsuite) into a local directory.

.DESCRIPTION
    Downloads the exact versions recorded in REPORT-G.md, verifies checksums and extracts them.
    Nothing is written into the repository; everything lands under -ToolsDir.

    The wabt release asset is selected for the host OS (this is what makes the harness Linux-clean):

      Windows -> wabt-1.0.42-windows-x64.tar.gz  -> bin\wast2json.exe
      Linux   -> wabt-1.0.42-linux-x64.tar.gz    -> bin/wast2json

    Both are immutable GitHub release assets; the script hard-fails on an unexpected checksum.

    wabt         1.0.42 (windows-x64 / linux-x64 release asset, immutable)
    testsuite    WebAssembly spec @ d76759e746f3564a03f6106ae19679742f2a1831
                 (the commit pinned by wabt 1.0.42's third_party/testsuite submodule)

.EXAMPLE
    .\test-scripts\spectest\fetch_spectest_tools.ps1
#>
param(
    [string]$ToolsDir = (Join-Path ([IO.Path]::GetTempPath()) "spectest-tools"),
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Host selection: OSVersion.Platform is 'Win32NT' on Windows and 'Unix' on Linux/macOS.
$isWindowsOS = [System.Environment]::OSVersion.Platform -eq 'Win32NT'

$WabtVersion = "1.0.42"
if ($isWindowsOS) {
    $WabtPlatform = "windows-x64"
    $WabtSha256   = "62f1eb2b51aa57cf0f0b8ba333bf2c72a049930aa9c5de01dcad271c4fe48c88"
    $WabtExeName  = "wast2json.exe"
} else {
    $WabtPlatform = "linux-x64"
    $WabtSha256   = "84895407a6bbb80e918f33b16b2fb2206021c150b6bc9ff6f761263a745ab131"
    $WabtExeName  = "wast2json"
}
$WabtUrl       = "https://github.com/WebAssembly/wabt/releases/download/$WabtVersion/wabt-$WabtVersion-$WabtPlatform.tar.gz"
$SpecCommit    = "d76759e746f3564a03f6106ae19679742f2a1831"
$SpecUrl       = "https://github.com/WebAssembly/spec/archive/$SpecCommit.tar.gz"
$SpecSha256    = "2f119457c429604619a422f0329afac2a90c7fa17361c5842f662dda184ec37b"

# On Windows PowerShell `curl` is an alias for Invoke-WebRequest; call the real executable on both
# hosts so -sL behaves identically.
$curl = if ($isWindowsOS) { "curl.exe" } else { "curl" }

function Assert-Sha256($Path, $Expected) {
    $actual = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLower()
    if ($actual -ne $Expected) { throw "sha256 mismatch for $Path`: got $actual, expected $Expected" }
    Write-Host "  sha256 ok: $actual" -ForegroundColor Green
}

New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null
$wabtDir = Join-Path $ToolsDir "wabt-$WabtVersion"
$specDir = Join-Path $ToolsDir "spec-$SpecCommit"

# --- wabt ----------------------------------------------------------------------------------------
# Forward slashes are a path separator on Windows too, so one name works on both hosts.
$wabtExe = Join-Path $wabtDir "bin/$WabtExeName"
if ($Force -or -not (Test-Path $wabtExe)) {
    $tgz = Join-Path $ToolsDir "wabt-$WabtVersion-$WabtPlatform.tar.gz"
    Write-Host "downloading wabt $WabtVersion ($WabtPlatform)" -ForegroundColor Cyan
    & $curl -sL -o $tgz $WabtUrl
    Assert-Sha256 $tgz $WabtSha256
    if (Test-Path $wabtDir) { Remove-Item -Recurse -Force $wabtDir }
    tar -xzf $tgz -C $ToolsDir
    if (-not (Test-Path $wabtExe)) { throw "$WabtExeName not found after extracting $tgz" }
}
Write-Host ("wabt      : {0}" -f (& $wabtExe --version))

# --- spec testsuite ------------------------------------------------------------------------------
if ($Force -or -not (Test-Path (Join-Path $specDir "i32.wast"))) {
    $tgz = Join-Path $ToolsDir "spec-$SpecCommit.tar.gz"
    Write-Host "downloading spec testsuite @ $SpecCommit" -ForegroundColor Cyan
    & $curl -sL -o $tgz $SpecUrl
    # GitHub regenerated archives are not byte-stable forever; warn rather than fail.
    $actual = (Get-FileHash -Algorithm SHA256 -Path $tgz).Hash.ToLower()
    if ($actual -ne $SpecSha256) {
        Write-Warning "spec tarball sha256 differs from the recorded value ($actual vs $SpecSha256); continuing"
    }
    if (Test-Path $specDir) { Remove-Item -Recurse -Force $specDir }
    tar -xzf $tgz -C $ToolsDir
    if (-not (Test-Path (Join-Path $specDir "i32.wast"))) { throw "i32.wast not found after extracting $tgz" }
}
Write-Host ("testsuite : {0} ({1} .wast files)" -f $SpecCommit, (Get-ChildItem $specDir -Filter *.wast).Count)

[pscustomobject]@{
    ToolsDir  = $ToolsDir
    WabtDir   = $wabtDir
    SpecDir   = $specDir
    Wast2Json = $wabtExe
} | ConvertTo-Json | Write-Output
