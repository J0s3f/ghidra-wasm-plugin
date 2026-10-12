<#
.SYNOPSIS
    Run the whole probe/regression loop locally: build + install, probe suite, fixture decompile
    baseline, then check-results.py.

.DESCRIPTION
    This is the local twin of .github/workflows/probes.yml:

      1. build-install.ps1 -GhidraDir <dir>            (gradle buildExtension + clean install)
      2. run_probes.ps1 -OutDir <out> -Generators ...  (generate -> headless import -> metrics)
      3. analyzeHeadless ... DumpDecomp.java on test-scripts/fixtures/wasm_fixture.wasm -> SUMMARY
      4. python test-scripts/check-results.py --log <out>/probe-run.log --fixture-log ...
         (add -Update to rewrite expected-results.json from this run instead of checking it)

    Exit code is check-results.py's: 0 = baseline matches, 1 = regression, 2 = setup problem.

.EXAMPLE
    $env:GHIDRA_INSTALL_DIR = "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-i"
    .\test-scripts\check-local.ps1

.EXAMPLE
    # after intentionally changing a probe's expected numbers
    .\test-scripts\check-local.ps1 -SkipBuild -Update
#>
param(
    [string]$GhidraDir = $env:GHIDRA_INSTALL_DIR,
    [string]$OutDir = "$env:TEMP\wasm-probes-ci",
    [string]$Gradle = "C:\Tools\gradle-9.2.1\bin\gradle.bat",
    [string[]]$Generators = @(),   # empty = let run_probes.ps1 glob every gen_*.py + probes_*.py
    [string]$RealModule = "",       # optional real .wasm: also record/check its DumpDecomp SUMMARY
    [switch]$SkipBuild,
    [switch]$Update                # regenerate expected-results.json from this run
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$testScripts = Join-Path $repo "test-scripts"
if (-not $GhidraDir) { throw "Set GHIDRA_INSTALL_DIR or pass -GhidraDir" }

$fixture = Join-Path $testScripts "fixtures\wasm_fixture.wasm"

# Cross-platform headless launcher (forward slashes work on Windows and Linux).
$supportDir = Join-Path $GhidraDir "support"
$isWindowsOS = [System.Environment]::OSVersion.Platform -eq 'Win32NT'
if ($isWindowsOS) {
    $headless = Join-Path $supportDir "analyzeHeadless.bat"
} else {
    $headless = Join-Path $supportDir "analyzeHeadless"
}
if (-not (Test-Path $headless)) { $headless = Join-Path $supportDir "analyzeHeadless.bat" }
if (-not (Test-Path $headless)) { $headless = Join-Path $supportDir "analyzeHeadless" }
if (-not (Test-Path $headless)) { throw "analyzeHeadless not found under $supportDir" }

if (-not $SkipBuild) {
    & (Join-Path $testScripts "build-install.ps1") -GhidraDir $GhidraDir -Gradle $Gradle
    if ($LASTEXITCODE -ne 0) { throw "build-install.ps1 failed ($LASTEXITCODE)" }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Write-Host "== probe suite ==" -ForegroundColor Cyan
if ($Generators.Count -gt 0) { & (Join-Path $testScripts "run_probes.ps1") -OutDir $OutDir -GhidraDir $GhidraDir -Generators $Generators } else { & (Join-Path $testScripts "run_probes.ps1") -OutDir $OutDir -GhidraDir $GhidraDir }
if ($LASTEXITCODE -ne 0) { throw "run_probes.ps1 failed ($LASTEXITCODE)" }

# DumpDecomp.java full-run helper: unique throwaway project, SUMMARY + decompiled C into a log.
function Invoke-DumpDecomp([string]$Wasm, [string]$LogName) {
    $proj = Join-Path $OutDir ("proj-" + [IO.Path]::GetFileNameWithoutExtension($LogName))
    Remove-Item -Recurse -Force $proj -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $proj | Out-Null
    $log = Join-Path $OutDir $LogName
    Write-Host ("== DumpDecomp {0} -> {1} ==" -f (Split-Path -Leaf $Wasm), $LogName) -ForegroundColor Cyan
    & $headless $proj "Reg" -import $Wasm -scriptPath $testScripts -postScript DumpDecomp.java `
        -max-cpu 2 -deleteProject 2>&1 | Tee-Object -FilePath $log | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "analyzeHeadless failed for $Wasm ($LASTEXITCODE)" }
    Select-String -Path $log -Pattern "SUMMARY|DECOMPILE FAIL" |
        ForEach-Object { ($_.Line -replace "^\S+\s+\S+\s+", "") -replace " \((GhidraScript|HeadlessAnalyzer)\).*$", "" }
}

Invoke-DumpDecomp $fixture "fixture-run.log"

$realArgs = @()
if ($RealModule) {
    Invoke-DumpDecomp $RealModule "real-run.log"
    $realArgs = @("--real-module-log", (Join-Path $OutDir "real-run.log"))
}

Write-Host "== check-results.py ==" -ForegroundColor Cyan
$checkArgs = @((Join-Path $testScripts "check-results.py"),
               "--log", (Join-Path $OutDir "probe-run.log"),
               "--fixture-log", (Join-Path $OutDir "fixture-run.log"),
               "--require-fixture") + $realArgs
if ($Update) { $checkArgs = @($checkArgs[0], "--update") + $checkArgs[1..($checkArgs.Count - 1)] }
& python @checkArgs
exit $LASTEXITCODE
