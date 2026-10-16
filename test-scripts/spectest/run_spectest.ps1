<#
.SYNOPSIS
    Run a subset of the official WebAssembly spec testsuite against this plugin, headlessly.

.DESCRIPTION
    1. fetches/uses the pinned wabt + spec testsuite (see fetch_spectest_tools.ps1),
    2. converts the selected .wast files to wasm modules (prepare_spec_tests.py),
    3. imports every valid module into a throwaway Ghidra project and runs
       SpecModuleReport.java per program (instructions, undefined_bytes, decompile failures),
    4. parses the headless log into summary.json / summary.md.

    Decode/decompile measurement only - no emulation. For emulation assertions see
    ghidra_scripts/spectest.py (run with the PyGhidra launcher; see REPORT-G.md).

.EXAMPLE
    .\test-scripts\spectest\run_spectest.ps1 -Subset smoke
.EXAMPLE
    .\test-scripts\spectest\run_spectest.ps1 -Subset core -MaxPerWast 10
.EXAMPLE
    .\test-scripts\spectest\run_spectest.ps1 -Files i32,i64,f32,f64,memory,bulk -Detail
#>
param(
    [string]$ToolsDir = "$env:TEMP\spectest-tools",
    [string]$OutDir = "$env:TEMP\spectest-run",
    [string]$GhidraDir = $env:GHIDRA_INSTALL_DIR,
    [string]$Subset = "core",
    [string[]]$Files = @(),
    [int]$MaxPerWast = 10,
    [int]$MaxCpu = 2,
    [string]$MaxMem = "1500M",
    [switch]$SkipFetch,
    [switch]$NoPrepare,
    [switch]$Detail
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$repo = Split-Path -Parent (Split-Path -Parent $here)   # test-scripts/spectest -> repo root

if (-not $GhidraDir) { throw "Set GHIDRA_INSTALL_DIR or pass -GhidraDir" }
$env:GHIDRA_HEADLESS_MAXMEM = $MaxMem

# --- 1. tools -------------------------------------------------------------------------------------
$wast2json = Join-Path $ToolsDir "wabt-1.0.42\bin\wast2json.exe"
$specDir = Get-ChildItem $ToolsDir -Directory -Filter "spec-*" -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $SkipFetch -and (-not (Test-Path $wast2json) -or -not $specDir)) {
    & (Join-Path $here "fetch_spectest_tools.ps1") -ToolsDir $ToolsDir | Out-Null
    $specDir = Get-ChildItem $ToolsDir -Directory -Filter "spec-*" | Select-Object -First 1
}
if (-not (Test-Path $wast2json)) { throw "wast2json not found at $wast2json (run fetch_spectest_tools.ps1)" }
if (-not $specDir) { throw "spec testsuite not found under $ToolsDir (run fetch_spectest_tools.ps1)" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# --- 2. prepare -----------------------------------------------------------------------------------
if (-not $NoPrepare) {
    Write-Host "== preparing spec modules ==" -ForegroundColor Cyan
    $prepArgs = @((Join-Path $here "prepare_spec_tests.py"),
                  "--spec", $specDir.FullName, "--wast2json", $wast2json, "--out", $OutDir)
    if ($Files.Count -gt 0) { $prepArgs += @("--files", ($Files -join ",")) }
    else { $prepArgs += @("--subset", $Subset) }
    if ($MaxPerWast -gt 0) { $prepArgs += @("--max-per-wast", "$MaxPerWast") }
    & python @prepArgs
    if ($LASTEXITCODE -ne 0) { throw "prepare_spec_tests.py failed ($LASTEXITCODE)" }
}

$importDir = Join-Path $OutDir "import"
$count = (Get-ChildItem $importDir -Filter *.wasm -ErrorAction SilentlyContinue).Count
if ($count -eq 0) { throw "no .wasm modules in $importDir" }
Write-Host ("== importing {0} module(s) ==" -f $count) -ForegroundColor Cyan

# --- 3. headless ----------------------------------------------------------------------------------
$proj = Join-Path $OutDir "project"
Remove-Item -Recurse -Force $proj -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $proj | Out-Null

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

# ListProgram/DumpAll (owned by another workstream, read-only here) live in test-scripts, but a headless
# run accepts only ONE -scriptPath directory, so -Detail uses the harness' own SpecDisasm.java.
if ($Detail) {
    $scripts = @("-scriptPath", $here, "-postScript", "SpecModuleReport.java",
                 "-postScript", "SpecDisasm.java")
} else {
    $scripts = @("-scriptPath", $here, "-postScript", "SpecModuleReport.java")
}

$log = Join-Path $OutDir "headless.log"
$all = @($proj, "SpecRun", "-import", $importDir, "-recursive") + $scripts +
       @("-max-cpu", "$MaxCpu", "-deleteProject")
Write-Host ("run: {0} {1}" -f $headless, ($all -join " ")) -ForegroundColor DarkGray
& $headless @all 2>&1 | Tee-Object -FilePath $log | Out-Null

# --- 4. parse -------------------------------------------------------------------------------------
Write-Host "== summarising ==" -ForegroundColor Cyan
$dir = Split-Path -Parent $here
& python (Join-Path $here "parse_spec_results.py") `
    --log $log --modules (Join-Path $OutDir "modules.json") --out $OutDir
if ($LASTEXITCODE -ne 0) { throw "parse_spec_results.py failed ($LASTEXITCODE)" }

Write-Host ("summary: {0}" -f (Join-Path $OutDir "summary.md")) -ForegroundColor DarkGray
if ($Detail) {
    Write-Host "== SPECFUNC lines (undef or decompile failure) ==" -ForegroundColor Cyan
    Select-String -Path $log -Pattern "^.*SPECFUNC " | ForEach-Object { $_.Line -replace "^.*SPECFUNC ", "SPECFUNC " }
}
