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
    [string]$GhidraDir = "",
    [string]$ScriptDir = "$PSScriptRoot",
    [string[]]$Generators,          # default: all gen_*.py + probes_*.py in $ScriptDir
    [string]$Only = "",             # wildcard filter on probe file names
    [switch]$Detail,                # also dump listings + decompiled C
    [switch]$NoAnalysis,            # skip the auto-analysis (faster, for decode-only checks)
    [int]$MaxCpu = 2,               # cap Ghidra analysis threads (many agents may run at once)
    [string]$MaxMem = "1500M",      # cap the headless JVM heap (GHIDRA_HEADLESS_MAXMEM)
    [switch]$Force                  # ignore the checkout's pinned install (see .ghidra-install)
)

$ErrorActionPreference = "Stop"

# --- install pinning -------------------------------------------------------------------------
# A checkout may only measure against the Ghidra install named in test-scripts/.ghidra-install.
# Measuring against another (possibly stale) install is the classic silent failure mode: the run
# looks fine but the extension under test is a different build.
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

# --- freshness guard -------------------------------------------------------------------------
# An install holds exactly one extension. Measuring a build other than this checkout's is the
# silent failure mode that once recorded ten wrong baseline entries: the run looks fine, but the
# extension under test is not the code being changed. build-install.ps1 leaves a stamp; verify it.
$repo = Split-Path -Parent $PSScriptRoot
$stampPath = Join-Path $GhidraDir "ghidra-wasm-install-stamp.json"
if (Test-Path $stampPath) {
    $stamp = Get-Content $stampPath -Raw | ConvertFrom-Json
    $newestZip = Get-ChildItem (Join-Path $repo "dist\*.zip") -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $zipHash = if ($newestZip) { (Get-FileHash $newestZip.FullName -Algorithm SHA256).Hash } else { "" }
    $sameWorktree = ($stamp.worktree -eq $repo)
    if ((-not $sameWorktree -or $zipHash -ne $stamp.sha256) -and -not $Force) {
        $why = if (-not $sameWorktree) { "it holds a build from '$($stamp.worktree)'" }
               else { "it holds '$($stamp.zip)' but this checkout's newest build is '$($newestZip.Name)'" }
        throw "STALE INSTALL: $GhidraDir - $why. Run build-install.ps1 in this checkout first, or pass -Force to measure anyway."
    }
}
elseif (-not $Force) {
    Write-Warning "no build stamp in $GhidraDir - results may come from a different build; run build-install.ps1 first (or pass -Force)."
}
$env:GHIDRA_HEADLESS_MAXMEM = $MaxMem
# Pick the launcher for the host OS: Ghidra ships BOTH "analyzeHeadless.bat" and
# "analyzeHeadless" on every platform, and PowerShell cannot execute a .bat on Linux.
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

if (-not $Generators) {
    $Generators = @(Get-ChildItem -Path $ScriptDir -Filter "gen_*.py" | ForEach-Object { $_.Name }) +
                  @(Get-ChildItem -Path $ScriptDir -Filter "probes_*.py" | ForEach-Object { $_.Name })
}
if (-not $Generators) { throw "no probe generators found in $ScriptDir" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$probeDir = Join-Path $OutDir "probes"
if (Test-Path $probeDir) { Remove-Item -Recurse -Force $probeDir }
New-Item -ItemType Directory -Force -Path $probeDir | Out-Null

Write-Host "== generating probes ==" -ForegroundColor Cyan
foreach ($g in $Generators) {
    $path = Join-Path $ScriptDir $g
    Write-Host "-- $g"
    & python $path $probeDir
}

$probes = Get-ChildItem -Path $probeDir -Filter "*.wasm" | Sort-Object Name
if ($Only) { $probes = $probes | Where-Object { $_.Name -like "*$Only*" } }
if (-not $probes) { throw "no probe .wasm files in $probeDir" }
Write-Host ("== running {0} probe(s) ==" -f $probes.Count) -ForegroundColor Cyan

$proj = Join-Path $OutDir "project"
Remove-Item -Recurse -Force $proj -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $proj | Out-Null

# Pass an explicit -import per file only for small selections; a large batch would exceed the
# Windows command-line limit, so import the whole probe directory instead.
if ($Only -or $probes.Count -le 25) {
    $importArgs = @()
    foreach ($p in $probes) { $importArgs += @("-import", $p.FullName) }
}
else {
    $importArgs = @("-import", $probeDir, "-recursive")
}
$scripts = @("-scriptPath", $ScriptDir, "-postScript", "WasmFeatureReport.java")
if ($Detail) { $scripts += @("-postScript", "ListProgram.java", "-postScript", "DumpAll.java") }
if ($NoAnalysis) { $scripts += "-noanalysis" }

$all = @($proj, "ProbeRun") + $importArgs + $scripts + @("-max-cpu", "$MaxCpu", "-deleteProject")
& $headless @all 2>&1 | Tee-Object -FilePath (Join-Path $OutDir "probe-run.log") | Out-Null

Write-Host "== results ==" -ForegroundColor Cyan
$log = Get-Content (Join-Path $OutDir "probe-run.log")
$patterns = @("PROBE ", "PROBE-BLOCK ", "Import failed", "ValidationException", "IllegalArgumentException",
              "NullPointerException", "DECOMPILE FAILED", "DECOMP ", "LISTING ")
if ($Detail) { $patterns += "\(GhidraScript\)" }   # full script output: instruction listings + C code
$log | Where-Object { $line = $_; ($patterns | Where-Object { $line -match $_ }) } |
    ForEach-Object { ($_ -replace "^\S+\s+\S+\s+", "") -replace " \((GhidraScript|HeadlessAnalyzer)\)\s*$", "" }
Write-Host ("full log: {0}" -f (Join-Path $OutDir "probe-run.log")) -ForegroundColor DarkGray
