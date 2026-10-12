<#
.SYNOPSIS
    Run the *negative* spec-test set (assert_invalid / assert_malformed / assert_unlinkable
    modules) against this plugin, headlessly, and classify each outcome as
    rejected / accepted / crash / hang.

.DESCRIPTION
    1. prepare_spec_negative.py copies every module a correct implementation must reject into
       <OutDir>\import as <wast>.<n>.<invalid|malformed|unlinkable>.wasm,
    2. the modules are imported in bounded chunks (one analyzeHeadless run per chunk, hard
       timeout). A chunk whose run wedges or dies is split and retried, so a single bad module is
       isolated to a chunk of its own and the rest of the set still gets measured,
    3. SpecNegativeReport.java emits one SPECNEG line per program the loader accepted,
    4. parse_spec_negative.py turns every chunk log + the manifest into
       <OutDir>\negative.json and <OutDir>\negative.md.

    Import-only (-noanalysis by default): rejection happens at load time, and a nonsense program
    must not be handed to the analysers/decompiler. Pass -WithAnalysis for the optional evidence
    pass (adds instrs / undefined_bytes to the SPECNEG lines).

.EXAMPLE
    # bounded smoke run: malformed only, first module of each .wast
    .\run_spectest_negative.ps1 -Kinds malformed -MaxPerWastPerKind 1 -OutDir "$env:TEMP\specneg-smoke"

.EXAMPLE
    # the full binary negative set (invalid + malformed + unlinkable)
    .\run_spectest_negative.ps1 -OutDir "$env:TEMP\specneg-all"

.EXAMPLE
    # evidence pass with analysis over a fixed import directory
    .\run_spectest_negative.ps1 -SkipPrepare -ImportDir "$env:TEMP\specneg-all\import" -WithAnalysis `
        -OutDir "$env:TEMP\specneg-analysis"
#>
param(
    [string]$ToolsDir = "$env:TEMP\spectest-tools",
    [string]$OutDir = "$env:TEMP\spectest-negative",
    [string]$GhidraDir = $env:GHIDRA_INSTALL_DIR,
    [string]$ScriptDir = $PSScriptRoot,
    [string]$ImportDir = "",                     # skip prepare, import this directory
    [string]$ModulesJson = "",                   # manifest for -ImportDir (default <ImportDir>\..\modules.json)
    [string[]]$Files = @(),
    [string]$Subset = "all",
    [string]$Kinds = "invalid,malformed,unlinkable",
    [int]$MaxPerWastPerKind = 0,
    [int]$ChunkSize = 200,
    [int]$TimeoutSec = 0,                         # 0 = auto (240 + 3s per module, max 1800)
    [int]$MaxRuns = 80,                          # safety cap on headless launches
    [int]$MaxCpu = 2,
    [string]$MaxMem = "1500M",
    [switch]$IncludeText,
    [switch]$SkipPrepare,
    [switch]$WithAnalysis
)

$ErrorActionPreference = "Stop"
$here = $ScriptDir

if (-not $GhidraDir) { throw "Set GHIDRA_INSTALL_DIR or pass -GhidraDir" }
$env:GHIDRA_HEADLESS_MAXMEM = $MaxMem

# --- 0. launcher ----------------------------------------------------------------------------------
$supportDir = Join-Path $GhidraDir "support"
$isWindowsOS = [System.Environment]::OSVersion.Platform -eq 'Win32NT'
# Host-agnostic tool names: wabt drops the `.exe` suffix on Linux, and Linux runners only guarantee
# `python3`. (The chunk runner below still uses cmd.exe/taskkill; that path is Windows-only.)
$python      = if ($isWindowsOS) { "python" } else { "python3" }
$wastExeName = if ($isWindowsOS) { "wast2json.exe" } else { "wast2json" }
if ($isWindowsOS) {
    $headless = Join-Path $supportDir "analyzeHeadless.bat"
} else {
    $headless = Join-Path $supportDir "analyzeHeadless"
}
if (-not (Test-Path $headless)) { $headless = Join-Path $supportDir "analyzeHeadless.bat" }
if (-not (Test-Path $headless)) { $headless = Join-Path $supportDir "analyzeHeadless" }
if (-not (Test-Path $headless)) { throw "analyzeHeadless not found under $supportDir" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$logDir = Join-Path $OutDir "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

# --- 1. prepare -----------------------------------------------------------------------------------
if ($ImportDir) {
    $importDir = (Resolve-Path $ImportDir).Path
    if (-not $ModulesJson) {
        $ModulesJson = Join-Path (Split-Path -Parent $importDir) "modules.json"
    }
} else {
    if (-not $SkipPrepare) {
        $wast2json = Join-Path $ToolsDir "wabt-1.0.42/bin/$wastExeName"
        $specDir = Get-ChildItem $ToolsDir -Directory -Filter "spec-*" -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if (-not (Test-Path $wast2json)) { throw "wast2json not found at $wast2json" }
        if (-not $specDir) { throw "spec testsuite not found under $ToolsDir" }
        Write-Host "== preparing negative modules ==" -ForegroundColor Cyan
        $prep = @((Join-Path $here "prepare_spec_negative.py"),
                  "--spec", $specDir.FullName, "--wast2json", $wast2json, "--out", $OutDir,
                  "--subset", $Subset, "--kinds", $Kinds)
        if ($Files.Count -gt 0) { $prep += @("--files", ($Files -join ",")) }
        if ($MaxPerWastPerKind -gt 0) { $prep += @("--max-per-wast-per-kind", "$MaxPerWastPerKind") }
        if ($IncludeText) { $prep += "--include-text" }
        & $python @prep
        if ($LASTEXITCODE -ne 0) { throw "prepare_spec_negative.py failed ($LASTEXITCODE)" }
    }
    $importDir = Join-Path $OutDir "import"
    if (-not $ModulesJson) { $ModulesJson = Join-Path $OutDir "modules.json" }
}

if (-not (Test-Path $ModulesJson)) { throw "manifest not found: $ModulesJson" }
$manifest = @(Get-Content $ModulesJson -Raw | ConvertFrom-Json)
if ($manifest.Count -eq 0) { throw "no negative modules in $ModulesJson" }
Write-Host ("== {0} negative module(s) to import ==" -f $manifest.Count) -ForegroundColor Cyan

# --- 2. chunked, timeout-guarded import -----------------------------------------------------------
$runsDir = Join-Path $OutDir "runs"
if (Test-Path $runsDir) { Remove-Item -Recurse -Force $runsDir }
New-Item -ItemType Directory -Force -Path $runsDir | Out-Null
$proj = Join-Path $OutDir "project"

$chunkRecords = New-Object System.Collections.ArrayList
$unresolvedFinal = @{}
$runNo = 0

function Get-Unresolved([string]$logPath, [string[]]$names) {
    $text = Get-Content -LiteralPath $logPath -Raw -ErrorAction SilentlyContinue
    if (-not $text) { return $names }
    $left = @()
    foreach ($n in $names) {
        $e = [regex]::Escape($n)
        $ok = $text.Contains("SPECNEG name=$n ") -or
              $text -match ("(?s)(could not successfully load|Import failed for file:|No memory blocks were defined for file)[^\r\n]*$e")
        if (-not $ok) { $left += $n }
    }
    return $left
}

function Invoke-Chunk([string[]]$names) {
    $script:runNo++
    $id = "{0:d3}" -f $script:runNo
    $chunkDir = Join-Path $runsDir "chunk_$id"
    New-Item -ItemType Directory -Force -Path $chunkDir | Out-Null
    foreach ($n in $names) { Copy-Item (Join-Path $importDir $n) $chunkDir -Force }
    $log = Join-Path $logDir "run_$id.log"

    Remove-Item -Recurse -Force $proj -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $proj | Out-Null

    $scripts = @("-scriptPath", $here, "-postScript", "SpecNegativeReport.java")
    $analysisArgs = if ($WithAnalysis) { @() } else { @("-noanalysis") }
    $all = @($proj, "NegRun", "-import", $chunkDir, "-recursive") + $scripts + $analysisArgs +
           @("-max-cpu", "$MaxCpu", "-deleteProject")

    # `< nul` matters: after an abort (e.g. OutOfMemoryError while analysing a nonsense program)
    # analyzeHeadless.bat runs `pause`, which without a stdin EOF would wedge the batch forever and
    # turn a crash into a fake hang.
    $inner = '"' + $headless + '" ' +
             (($all | ForEach-Object { '"' + $_ + '"' }) -join ' ') +
             ' > "' + $log + '" 2>&1 < nul'
    $wrapper = Join-Path $runsDir "run_$id.cmd"
    Set-Content -LiteralPath $wrapper -Value @("@echo off", $inner, "exit /b %ERRORLEVEL%") -Encoding ASCII

    $timeout = if ($TimeoutSec -gt 0) { $TimeoutSec } else { [Math]::Min(1800, 240 + 3 * $names.Count) }
    $p = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", ('"' + $wrapper + '"') -PassThru `
        -WindowStyle Hidden -WorkingDirectory $OutDir
    $timedOut = $false
    if (-not $p.WaitForExit($timeout * 1000)) {
        $timedOut = $true
        & taskkill /PID $p.Id /T /F 2>&1 | Out-Null
        Start-Sleep -Seconds 3
        try { $p.WaitForExit(30000) | Out-Null } catch { }
    }
    try { $p.Refresh() } catch { }
    $rc = if ($p.HasExited) { $p.ExitCode } else { -1 }

    $left = Get-Unresolved $log $names
    $col = (Get-ChildItem $chunkDir -Filter *.wasm).Count
    [void]$chunkRecords.Add([pscustomobject]@{
        run      = $script:runNo
        count    = $names.Count
        files    = $col
        rc       = $rc
        timed_out = $timedOut
        timeout  = $timeout
        log      = $log
        unresolved = @($left)
        modules  = @($names)
    })
    Remove-Item -Recurse -Force $chunkDir -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $proj -ErrorAction SilentlyContinue
    Write-Host ("  run {0}: {1} module(s) rc={2} timeout={3} unresolved={4}" -f `
        $script:runNo, $names.Count, $rc, $timedOut, $left.Count) -ForegroundColor DarkGray
    return [pscustomobject]@{ rc = $rc; timed_out = $timedOut; unresolved = @($left); log = $log }
}

$stack = New-Object System.Collections.Stack
# Push in reverse so the first chunk of the manifest is processed first.
$all = @($manifest | ForEach-Object { $_.wasm })
$groups = @()
for ($i = 0; $i -lt $all.Count; $i += $ChunkSize) {
    $groups += , @($all[$i..([Math]::Min($i + $ChunkSize - 1, $all.Count - 1))])
}
for ($g = $groups.Count - 1; $g -ge 0; $g--) { $stack.Push($groups[$g]) }

while ($stack.Count -gt 0) {
    if ($runNo -ge $MaxRuns) {
        Write-Host ("== hit -MaxRuns ({0}); remaining modules not measured ==" -f $MaxRuns) -ForegroundColor Yellow
        break
    }
    $names = @($stack.Pop())
    if ($names.Count -eq 0) { continue }
    $res = Invoke-Chunk $names
    if ($res.unresolved.Count -eq 0) { continue }
    if ($names.Count -eq 1) {
        # A single module neither imported nor produced a diagnostic: it killed the run.
        $unresolvedFinal[$names[0]] = if ($res.timed_out) { "hang" } elseif ($res.rc -ne 0) { "crash" } else { "crash" }
        continue
    }
    # Re-run only the modules we could not classify, in two halves so the culprit isolates itself.
    if ($res.unresolved.Count -eq 1) {
        $stack.Push(@($res.unresolved))
    } else {
        $half = [int][Math]::Ceiling($res.unresolved.Count / 2)
        $stack.Push(@($res.unresolved[$half..($res.unresolved.Count - 1)]))
        $stack.Push(@($res.unresolved[0..($half - 1)]))
    }
    # Any module that got *no* line at all but was not pushed (i.e. it is the only unresolved)
    # is handled by the Count==1 branch above on the next iteration.
}

$chunksFile = Join-Path $OutDir "chunks.json"
$chunkRecords | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $chunksFile -Encoding UTF8
$unresolvedFile = Join-Path $OutDir "unresolved.json"
$unresolvedFinal | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $unresolvedFile -Encoding UTF8

# --- 3. classify ----------------------------------------------------------------------------------
Write-Host "== classifying ==" -ForegroundColor Cyan
& python (Join-Path $here "parse_spec_negative.py") `
    --chunks $chunksFile --modules $ModulesJson --unresolved $unresolvedFile --out $OutDir
if ($LASTEXITCODE -ne 0) { throw "parse_spec_negative.py failed ($LASTEXITCODE)" }

Write-Host ("negative report: {0}" -f (Join-Path $OutDir "negative.md")) -ForegroundColor DarkGray
if (Test-Path (Join-Path $OutDir "negative.md")) {
    Get-Content (Join-Path $OutDir "negative.md") | Select-String -Pattern "^Summary|^Totals|^## " |
        Select-Object -First 20 | ForEach-Object { $_.Line }
}
