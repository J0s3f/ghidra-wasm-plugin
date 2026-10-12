<#
.SYNOPSIS
    Import the real-world wasm corpus through the WebAssembly plugin and report where it breaks.

.DESCRIPTION
    Reads test-scripts/corpus/manifest.json, verifies every module's sha256, then imports each module
    into its own throwaway Ghidra project with `analyzeHeadless`. Per module it collects:
      * the WasmFeatureReport.java metrics (funcs / instrs / undefined_bytes / decompiled / decompile_failed),
      * the CorpusProbe.java evidence (per-function undefined ranges, empty bodies, unimplemented instrs),
      * import failures, analysis warnings and errors, and wall-clock time.
    Results are written to test-scripts/corpus-RESULTS.md (table + failures) and printed.

    Fully offline: it never downloads. Modules are resolved from -CorpusDir; modules flagged
    "committed" in the manifest are copied from test-scripts/corpus/modules/ if the corpus dir is empty,
    so a fresh checkout sweeps at least three modules with no network.

.EXAMPLE
    # standard sweep, corpus already populated
    pwsh test-scripts/corpus-sweep.ps1 -CorpusDir C:\Users\micro\AppData\Local\Temp\opencode\corpus

.EXAMPLE
    # one module, with disassembly + decompiled C dumped into the log
    pwsh test-scripts/corpus-sweep.ps1 -Only rasterbator_rs_bg -Detail
#>
param(
    [string]$CorpusDir = "$env:TEMP\corpus",
    [string]$GhidraDir = $env:GHIDRA_INSTALL_DIR,
    [string]$Manifest  = "$PSScriptRoot\corpus\manifest.json",
    [string]$ScriptDir = "$PSScriptRoot",
    [string]$OutMd     = "$PSScriptRoot\corpus-RESULTS.md",
    [string]$WorkDir   = "$env:TEMP\wasm-corpus-run",
    [int]$MaxCpu = 2,
    [string]$MaxMem = "1500M",
    [int]$TimeoutSec = 1500,
    [string[]]$Only,                    # module names to sweep (default: all)
    [switch]$Detail,                    # also run ListProgram.java + DumpAll.java (big logs)
    [switch]$NoAnalysis,                # skip auto-analysis (decode-only; undefined_bytes is meaningless)
    [switch]$KeepProjects
)

$ErrorActionPreference = "Stop"

if (-not $GhidraDir) { throw "Set GHIDRA_INSTALL_DIR or pass -GhidraDir" }
$headless = Join-Path $GhidraDir "support\analyzeHeadless.bat"
if (-not (Test-Path $headless)) { throw "analyzeHeadless not found under $GhidraDir\support" }
if (-not (Test-Path $Manifest)) { throw "manifest not found: $Manifest" }

$corpusScripts = Join-Path $ScriptDir "corpus"
$env:GHIDRA_HEADLESS_MAXMEM = $MaxMem
New-Item -ItemType Directory -Force -Path $CorpusDir, $WorkDir | Out-Null
$logDir = Join-Path $WorkDir "logs"
if (Test-Path $logDir) { Remove-Item -Recurse -Force $logDir }
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$manifestData = Get-Content -Raw $Manifest | ConvertFrom-Json
$modules = $manifestData.modules
if ($Only) {
    # -File passes "a,b" as one token, so accept comma-separated lists too.
    $sel = @($Only | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
    $modules = $modules | Where-Object { $sel -contains $_.name }
}
if (-not $modules) { throw "no modules selected" }

# --- resolve + verify every module up front -------------------------------------------------------
Write-Host "== resolving corpus ($($modules.Count) module(s)) ==" -ForegroundColor Cyan
foreach ($m in $modules) {
    $target = Join-Path $CorpusDir $m.file
    if (-not (Test-Path $target) -and $m.committed) {
        $src = Join-Path $corpusScripts $m.committed
        if (Test-Path $src) {
            Copy-Item $src $target -Force
            Write-Host ("  seeded {0} from committed {1}" -f $m.name, $m.committed)
        }
    }
    if (-not (Test-Path $target)) {
        Write-Warning ("  MISSING {0} -> expected {1}" -f $m.name, $target)
    }
}

$importFailPatterns = @(
    'Failed to import', 'Import failed', 'Unable to import', 'No load spec found',
    'No Loader found', 'is not a valid', 'Cannot open file', 'AlreadyExistsException'
)

$results = @()
$idx = 0
foreach ($m in $modules) {
    $idx++
    $target = Join-Path $CorpusDir $m.file
    $row = [ordered]@{
        n = $idx; name = $m.name; file = $m.file; size = $m.size
        sha256 = $m.sha256; hash_ok = $null; v8 = $m.v8; status = ""; secs = 0
        funcs = ""; instrs = ""; undef = ""; undef_real = ""; thunk = ""; decompiled = ""; decompile_failed = ""
        empty_bodies = ""; unimpl = ""; warnings = 0; errors = 0
        analysis_errors = ""; message = ""; blocks = ""; log = ""
    }
    if (-not (Test-Path $target)) {
        $row.status = "MISSING"; $row.message = "not in corpus dir"
        $results += [pscustomobject]$row; continue
    }
    $actual = (Get-FileHash $target -Algorithm SHA256).Hash.ToLower()
    $row.hash_ok = ($actual -eq $m.sha256.ToLower())
    if (-not $row.hash_ok) { Write-Warning ("  {0}: sha256 mismatch (expected {1}, got {2})" -f $m.name, $m.sha256, $actual) }

    $projName = "corpus_" + ($m.name -replace '[^A-Za-z0-9_]', '_')
    # -scriptPath must name a directory whose *subdirectories* become java packages; CorpusProbe.java
    # is in test-scripts/corpus/ -> package corpus. Do NOT also pass the subdir itself (ambiguous).
    $cmdArgs = @($WorkDir, $projName, "-import", $target,
                 "-scriptPath", $ScriptDir,
                 "-postScript", "WasmFeatureReport.java",
                 "-postScript", "corpus/CorpusProbe.java")
    if ($Detail) { $cmdArgs += @("-postScript", "ListProgram.java", "-postScript", "DumpAll.java") }
    if ($NoAnalysis) { $cmdArgs += "-noanalysis" }
    $cmdArgs += @("-max-cpu", "$MaxCpu")
    if (-not $KeepProjects) { $cmdArgs += "-deleteProject" }

    $stdout = Join-Path $logDir "$($m.name).out.txt"
    $stderr = Join-Path $logDir "$($m.name).err.txt"
    $argLine = ($cmdArgs | ForEach-Object { if ($_ -match '[\s;]') { '"' + $_ + '"' } else { $_ } }) -join ' '

    Write-Host ("-- [{0}/{1}] {2} ({3} bytes)" -f $idx, $modules.Count, $m.name, $m.size) -ForegroundColor Yellow
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process -FilePath $headless -ArgumentList $argLine -NoNewWindow -PassThru `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $timedOut = $false
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        $timedOut = $true
        try { $p.Kill($true) } catch { }
    }
    $sw.Stop()
    $row.secs = [math]::Round($sw.Elapsed.TotalSeconds, 1)

    $logText = ""
    foreach ($f in @($stdout, $stderr)) { if (Test-Path $f) { $logText += (Get-Content -Raw $f) } }
    $merged = Join-Path $logDir "$($m.name).log.txt"
    Set-Content -Path $merged -Value $logText -Encoding UTF8
    $row.log = $merged

    if ($timedOut) {
        $row.status = "TIMEOUT"
        $row.message = "> $TimeoutSec s"
    }

    # --- metric extraction ------------------------------------------------------------------------
    $tot = [regex]::Matches($logText, 'CORPUSPROBE-TOTAL\s+\S+\s+funcs=(\d+)\s+instrs=(\d+)\s+undefined_bytes=(\d+)\s+empty_bodies=(\d+)\s+unimpl_instrs=(\d+)')
    $fr = [regex]::Matches($logText, 'PROBE\s+\S+\s+funcs=(\d+)\s+instrs=(\d+)\s+undefined_bytes=(\d+)\s+decompiled=(\d+)\s+decompile_failed=(\d+)')
    if ($fr.Count -gt 0) {
        $g = $fr[$fr.Count - 1].Groups
        $row.funcs = $g[1].Value; $row.instrs = $g[2].Value; $row.undef = $g[3].Value
        $row.decompiled = $g[4].Value; $row.decompile_failed = $g[5].Value
    }
    if ($tot.Count -gt 0) {
        $g = $tot[$tot.Count - 1].Groups
        $row.empty_bodies = $g[4].Value; $row.unimpl = $g[5].Value
        if ($row.funcs -eq "") { $row.funcs = $g[1].Value; $row.instrs = $g[2].Value; $row.undef = $g[3].Value }
    }
    $tk = [regex]::Matches($logText, 'CORPUSPROBE-TOTAL\s+\S+.*?\bthunk_bytes=(\d+)')
    if ($tk.Count -gt 0) {
        $row.thunk = $tk[$tk.Count - 1].Groups[1].Value
        if ($row.undef -ne "") { $row.undef_real = [string]([int64]$row.undef - [int64]$row.thunk) }
    }
    # CorpusProbe's BLOCK lines carry ` r=<read>`; WasmFeatureReport's PROBE-BLOCK lines do not, so
    # this pattern matches only the former (avoids listing every block twice).
    $row.blocks = (([regex]::Matches($logText, '(?m)\bBLOCK\s+\S+\s+(\S+)\s+size=(\d+)\s+r=') | ForEach-Object { $_.Groups[1].Value + "=" + $_.Groups[2].Value } | Select-Object -Unique) -join ' ')

    # Count analysis warnings/errors but exclude the one-time SLEIGH compile chatter (it is about the
    # .sla build, not this module) and the noisy loader INFO lines.
    $warnLines = [regex]::Matches($logText, '(?m)^\s*WARN\b[^\r\n]*') | ForEach-Object { $_.Value }
    $errLines  = [regex]::Matches($logText, '(?m)^\s*ERROR\b[^\r\n]*') | ForEach-Object { $_.Value }
    $row.warnings = ($warnLines | Where-Object { $_ -notmatch 'SleighCompile|Unreferenced table|NOP constructors|switch to list' }).Count
    $analysisErrs = $errLines | Where-Object { $_ -notmatch 'SleighCompile|Unreferenced table|NOP constructors|switch to list' }
    $row.errors = $analysisErrs.Count
    # Keep the first few distinct analysis error messages as evidence (full text stays in the log).
    $distinct = $analysisErrs | ForEach-Object { ($_ -replace '^\s*ERROR\s+', '').Trim() } | Select-Object -Unique
    $row.analysis_errors = ($distinct | Select-Object -First 4) -join ' || '

    if (-not $row.status) {
        if ($tot.Count -eq 0 -and $fr.Count -eq 0) {
            $row.status = "IMPORT-FAIL"
        } elseif ($row.undef_real -ne "" -and [int64]$row.undef_real -gt 0) {
            $row.status = "UNDEFINED-BYTES"
        } else {
            $row.status = "OK"
        }
    }
    foreach ($pat in $importFailPatterns) {
        $hit = [regex]::Match($logText, [regex]::Escape($pat) + '[^\r\n]*')
        if ($hit.Success) { $row.message = $hit.Value.Trim(); break }
    }
    if (-not $row.message -and $p.ExitCode -ne 0) { $row.message = "exit code $($p.ExitCode)" }

    $results += [pscustomobject]$row
    Write-Host ("   -> {0}  funcs={1} instrs={2} undef={3} decomp={4}/{5} ({6}s)" -f `
        $row.status, $row.funcs, $row.instrs, $row.undef, $row.decompiled, $row.decompile_failed, $row.secs) -ForegroundColor Gray
}

# --- markdown -------------------------------------------------------------------------------------
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine("# Real-world wasm corpus sweep - results")
[void]$sb.AppendLine()
[void]$sb.AppendLine("Generated by ``test-scripts/corpus-sweep.ps1`` on $(Get-Date -Format 'yyyy-MM-dd HH:mm').")
[void]$sb.AppendLine("Manifest: ``test-scripts/corpus/manifest.json``. Analysis: Ghidra headless, ``-max-cpu $MaxCpu``, heap $MaxMem, auto-analysis $(if ($NoAnalysis) { 'OFF' } else { 'ON' }).")
[void]$sb.AppendLine()
[void]$sb.AppendLine("``undef`` = all function-body bytes with no instruction (as WasmFeatureReport.java reports it).")
[void]$sb.AppendLine("``thunk`` = the subset inside zero-instruction bodies, which is exactly the loader's placeholder for")
[void]$sb.AppendLine("*imported* functions and is expected (4 bytes per import). ``undef*`` = undef - thunk = the real")
[void]$sb.AppendLine("decode gap; a healthy module has 0. ``decomp`` = ``decompiled/decompile_failed``. ``unimpl`` counts")
[void]$sb.AppendLine("unimplemented-placeholder instructions. Per-module logs: ``$logDir``.")
[void]$sb.AppendLine()
[void]$sb.AppendLine("| # | module | v8 | size | funcs | instrs | undef | thunk | undef* | decomp | fail | empty | unimpl | warn | err | s | status |")
[void]$sb.AppendLine("| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
foreach ($r in $results) {
    [void]$sb.AppendLine("| $($r.n) | ``$($r.name)`` | $($r.v8) | $($r.size) | $($r.funcs) | $($r.instrs) | $($r.undef) | $($r.thunk) | $($r.undef_real) | $($r.decompiled) | $($r.decompile_failed) | $($r.empty_bodies) | $($r.unimpl) | $($r.warnings) | $($r.errors) | $($r.secs) | $($r.status) |")
}
[void]$sb.AppendLine()
[void]$sb.AppendLine("## Blocks")
[void]$sb.AppendLine()
foreach ($r in $results) {
    if ($r.blocks) { [void]$sb.AppendLine("- ``$($r.name)``: $($r.blocks)") }
}
[void]$sb.AppendLine()
[void]$sb.AppendLine("## Hash verification")
[void]$sb.AppendLine()
foreach ($r in $results) {
    $ok = if ($r.hash_ok) { "match" } elseif ($r.hash_ok -eq $false) { "**MISMATCH**" } else { "n/a" }
    [void]$sb.AppendLine("- ``$($r.name)``: $ok")
}
[void]$sb.AppendLine()
[void]$sb.AppendLine("## Import failures / messages")
[void]$sb.AppendLine()
$anyMsg = $false
foreach ($r in $results) {
    if ($r.message) { [void]$sb.AppendLine("- ``$($r.name)`` ($($r.status)): $($r.message)"); $anyMsg = $true }
}
if (-not $anyMsg) { [void]$sb.AppendLine("- none") }
[void]$sb.AppendLine()
[void]$sb.AppendLine("## Analysis errors (SLEIGH compile chatter excluded)")
[void]$sb.AppendLine()
$anyErr = $false
foreach ($r in $results) {
    if ($r.analysis_errors) { [void]$sb.AppendLine("- ``$($r.name)`` ($($r.errors)): $($r.analysis_errors)"); $anyErr = $true }
}
if (-not $anyErr) { [void]$sb.AppendLine("- none") }
[void]$sb.AppendLine()
[void]$sb.AppendLine("## Reproduce")
[void]$sb.AppendLine()
[void]$sb.AppendLine('```powershell')
[void]$sb.AppendLine("pwsh test-scripts/corpus-sweep.ps1 -CorpusDir $CorpusDir")
[void]$sb.AppendLine('```')
Set-Content -Path $OutMd -Value $sb.ToString() -Encoding UTF8

$json = $results | ConvertTo-Json -Depth 4
Set-Content -Path (Join-Path $WorkDir "corpus-metrics.json") -Value $json -Encoding UTF8

Write-Host ""
Write-Host "== results ==" -ForegroundColor Cyan
Get-Content $OutMd | Write-Host
Write-Host ""
Write-Host "full metrics json: $(Join-Path $WorkDir 'corpus-metrics.json')" -ForegroundColor DarkGray
Write-Host "per-module logs:   $logDir" -ForegroundColor DarkGray
