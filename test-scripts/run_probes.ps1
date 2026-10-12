<#
.SYNOPSIS
    Generate and run the WebAssembly probe suite against a Ghidra install.

.DESCRIPTION
    1. runs every probe generator (gen_*.py, probes_*.py) found in -ScriptDir,
    2. imports all generated .wasm files into a throwaway Ghidra project,
    3. runs test-scripts/WasmFeatureReport.java (metrics per program) and, with -Detail,
       ListProgram.java + DumpAll.java (disassembly and decompiled C).

.EXAMPLE
    # full suite against the Ghidra install in GHIDRA_INSTALL_DIR
    .\test-scripts\run_probes.ps1

.EXAMPLE
    # only the agent-B probes, with disassembly + decompilation dumps
    .\test-scripts\run_probes.ps1 -Generators probes_types.py -Detail

.EXAMPLE
    # one specific probe module, full detail
    .\test-scripts\run_probes.ps1 -Only 06_multi_memory -Detail
#>
param(
    [string]$OutDir = "$env:TEMP\wasm-probes",
    [string]$GhidraDir = $env:GHIDRA_INSTALL_DIR,
    [string]$ScriptDir = "$PSScriptRoot",
    [string[]]$Generators,          # default: all gen_*.py + probes_*.py in $ScriptDir
    [string]$Only = "",             # wildcard filter on probe file names
    [switch]$Detail,                # also dump listings + decompiled C
    [switch]$NoAnalysis             # skip the auto-analysis (faster, for decode-only checks)
)

$ErrorActionPreference = "Stop"

if (-not $GhidraDir) { throw "Set GHIDRA_INSTALL_DIR or pass -GhidraDir" }
$headless = Join-Path $GhidraDir "support\analyzeHeadless.bat"
if (-not (Test-Path $headless)) { $headless = Join-Path $GhidraDir "support\analyzeHeadless" }
if (-not (Test-Path $headless)) { throw "analyzeHeadless not found under $GhidraDir\support" }

if (-not $Generators) {
    $Generators = @(Get-ChildItem -Path $ScriptDir -Filter "gen_*.py" | ForEach-Object { $_.Name }) +
                  @(Get-ChildItem -Path $ScriptDir -Filter "probes_*.py" | ForEach-Object { $_.Name })
}
if (-not $Generators) { throw "no probe generators found in $ScriptDir" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Write-Host "== generating probes ==" -ForegroundColor Cyan
foreach ($g in $Generators) {
    $path = Join-Path $ScriptDir $g
    Write-Host "-- $g"
    & python $path $OutDir
}

$probes = Get-ChildItem -Path $OutDir -Filter "*.wasm" | Sort-Object Name
if ($Only) { $probes = $probes | Where-Object { $_.Name -like "*$Only*" } }
if (-not $probes) { throw "no probe .wasm files in $OutDir" }
Write-Host ("== running {0} probe(s) ==" -f $probes.Count) -ForegroundColor Cyan

$proj = Join-Path $OutDir "project"
Remove-Item -Recurse -Force $proj -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $proj | Out-Null

$importArgs = @()
foreach ($p in $probes) { $importArgs += @("-import", $p.FullName) }
$scripts = @("-scriptPath", $ScriptDir, "-postScript", "WasmFeatureReport.java")
if ($Detail) { $scripts += @("-postScript", "ListProgram.java", "-postScript", "DumpAll.java") }
if ($NoAnalysis) { $scripts += "-noanalysis" }

$all = @($proj, "ProbeRun") + $importArgs + $scripts + @("-deleteProject")
& $headless @all 2>&1 | Tee-Object -FilePath (Join-Path $OutDir "probe-run.log") | Out-Null

Write-Host "== results ==" -ForegroundColor Cyan
$log = Get-Content (Join-Path $OutDir "probe-run.log")
$patterns = @("PROBE ", "PROBE-BLOCK ", "Import failed", "ValidationException", "IllegalArgumentException",
              "NullPointerException", "DECOMPILE FAILED", "DECOMP ", "LISTING ")
if ($Detail) { $patterns += "\(GhidraScript\)" }   # full script output: instruction listings + C code
$log | Where-Object { $line = $_; ($patterns | Where-Object { $line -match $_ }) } |
    ForEach-Object { ($_ -replace "^\S+\s+\S+\s+", "") -replace " \((GhidraScript|HeadlessAnalyzer)\)\s*$", "" }
Write-Host ("full log: {0}" -f (Join-Path $OutDir "probe-run.log")) -ForegroundColor DarkGray
