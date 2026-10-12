<#
.SYNOPSIS
    Fetch the pinned WebAssembly spec-test toolchain (wabt + spec testsuite) into a local directory.

.DESCRIPTION
    Downloads the exact versions recorded in REPORT-G.md, verifies checksums and extracts them.
    Nothing is written into the repository; everything lands under -ToolsDir.

    wabt         1.0.42  (windows-x64 release asset, immutable)
    testsuite    WebAssembly spec @ d76759e746f3564a03f6106ae19679742f2a1831
                 (the commit pinned by wabt 1.0.42's third_party/testsuite submodule)

.EXAMPLE
    .\test-scripts\spectest\fetch_spectest_tools.ps1
#>
param(
    [string]$ToolsDir = "$env:TEMP\spectest-tools",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$WabtVersion   = "1.0.42"
$WabtUrl       = "https://github.com/WebAssembly/wabt/releases/download/$WabtVersion/wabt-$WabtVersion-windows-x64.tar.gz"
$WabtSha256    = "62f1eb2b51aa57cf0f0b8ba333bf2c72a049930aa9c5de01dcad271c4fe48c88"
$SpecCommit    = "d76759e746f3564a03f6106ae19679742f2a1831"
$SpecUrl       = "https://github.com/WebAssembly/spec/archive/$SpecCommit.tar.gz"
$SpecSha256    = "2f119457c429604619a422f0329afac2a90c7fa17361c5842f662dda184ec37b"

function Assert-Sha256($Path, $Expected) {
    $actual = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLower()
    if ($actual -ne $Expected) { throw "sha256 mismatch for $Path`: got $actual, expected $Expected" }
    Write-Host "  sha256 ok: $actual" -ForegroundColor Green
}

New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null
$wabtDir = Join-Path $ToolsDir "wabt-$WabtVersion"
$specDir = Join-Path $ToolsDir "spec-$SpecCommit"

# --- wabt ----------------------------------------------------------------------------------------
$wabtExe = Join-Path $wabtDir "bin\wast2json.exe"
if ($Force -or -not (Test-Path $wabtExe)) {
    $tgz = Join-Path $ToolsDir "wabt-$WabtVersion-windows-x64.tar.gz"
    Write-Host "downloading wabt $WabtVersion" -ForegroundColor Cyan
    curl.exe -sL -o $tgz $WabtUrl
    Assert-Sha256 $tgz $WabtSha256
    if (Test-Path $wabtDir) { Remove-Item -Recurse -Force $wabtDir }
    tar -xzf $tgz -C $ToolsDir
    if (-not (Test-Path $wabtExe)) { throw "wast2json.exe not found after extracting $tgz" }
}
Write-Host ("wabt      : {0}" -f (& $wabtExe --version))

# --- spec testsuite ------------------------------------------------------------------------------
if ($Force -or -not (Test-Path (Join-Path $specDir "i32.wast"))) {
    $tgz = Join-Path $ToolsDir "spec-$SpecCommit.tar.gz"
    Write-Host "downloading spec testsuite @ $SpecCommit" -ForegroundColor Cyan
    curl.exe -sL -o $tgz $SpecUrl
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
