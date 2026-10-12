<#
.SYNOPSIS
    Robustness sweep: import every malformed module in the corpus through the WebAssembly loader
    headlessly and record the per-file outcome.

.DESCRIPTION
    For every .wasm in the corpus this imports the module in its own headless Ghidra process, with a
    hard per-file wall-clock bound enforced from PowerShell (a wedged JVM is killed, tree and all,
    and recorded). By default the auto-analysis is skipped (`-noanalysis`): malformed modules fail
    (or succeed) at *load* time, and running the analyzers made each file take 30-60 s. With no
    analysis a file costs ~10-15 s (mostly JVM startup) and the 26-module core corpus finishes in
    ~5 minutes. Use `-Analyze` to also exercise the analyzers.

    Outcomes:

        import_ok                   the loader produced a program and the report script ran
        import_ok_analysis_timeout  the loader produced a program but analysis hit -AnalysisTimeoutPerFile
        import_failed               the loader rejected the module with a message (expected for bad input)
        process_died                the JVM exited non-zero or an uncaught exception / OutOfMemoryError
                                    escaped to the process level (SEVERE)
        hang                        the process did not finish within -WallSeconds (SEVERE)
        unknown                     no PROBE line and no import-failure diagnostic (needs triage)

    It writes a Markdown report to -ResultsFile and prints a summary table. Every child process is
    killed by PID tree on timeout, and a final sweep kills any analyser JVM still referencing this
    run's unique work directory, so a wedged child cannot be orphaned.

.EXAMPLE
    .\test-scripts\robustness-sweep.ps1
.EXAMPLE
    .\test-scripts\robustness-sweep.ps1 -SkipGenerate -MaxFiles 5
.EXAMPLE
    .\test-scripts\robustness-sweep.ps1 -CorpusMode all -Analyze
#>
param(
    [string]$GhidraDir = "C:\Users\micro\AppData\Local\Temp\opencode\ghidra-j",
    [string]$ScriptDir = $PSScriptRoot,
    [string]$CorpusDir = "$env:TEMP\wasm-malformed-corpus",
    [string]$WorkDir = "",
    [string]$ResultsFile = (Join-Path $PSScriptRoot "robustness-RESULTS.md"),
    [string]$Generator = "make_malformed_corpus.py",
    [ValidateSet("core", "all")][string]$CorpusMode = "core",
    [int]$WallSeconds = 60,
    [int]$AnalysisTimeoutPerFile = 60,
    [int]$MaxCpu = 2,
    [string]$MaxMem = "1500M",
    [int]$MaxFiles = 0,
    [switch]$SkipGenerate,
    [switch]$Analyze
)

$ErrorActionPreference = "Stop"
$env:GHIDRA_HEADLESS_MAXMEM = $MaxMem

$headless = Join-Path $GhidraDir "support\analyzeHeadless.bat"
if (-not (Test-Path $headless)) { $headless = Join-Path $GhidraDir "support\analyzeHeadless" }
if (-not (Test-Path $headless)) { throw "analyzeHeadless not found under $GhidraDir\support" }

# unique work directory per run - several agents may sweep concurrently
if (-not $WorkDir) {
    $WorkDir = Join-Path $env:TEMP ("wasm-robustness\" + (Get-Date -Format "yyyyMMdd-HHmmss") + "-" + $PID)
}
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$logDir = Join-Path $WorkDir "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$projRoot = Join-Path $WorkDir "project"
New-Item -ItemType Directory -Force -Path $projRoot | Out-Null

if (-not $SkipGenerate) {
    Write-Host "== generating corpus ($CorpusMode) into $CorpusDir ==" -ForegroundColor Cyan
    $gen = Join-Path $ScriptDir $Generator
    & python $gen $CorpusDir $CorpusMode
    if ($LASTEXITCODE -ne 0) { throw "corpus generator failed ($LASTEXITCODE)" }
}

$probes = Get-ChildItem -Path $CorpusDir -Filter "*.wasm" | Sort-Object Name
if ($MaxFiles -gt 0) { $probes = $probes | Select-Object -First $MaxFiles }
if (-not $probes) { throw "no .wasm files in $CorpusDir" }

$analysisArgs = if ($Analyze) { @("-analysisTimeoutPerFile", "$AnalysisTimeoutPerFile") } else { @("-noanalysis") }
Write-Host ("== sweeping {0} module(s); {1}; wall bound {2}s/file; analysis timeout {3}s ==" -f `
    $probes.Count, ($(if ($Analyze) { "analysis ON" } else { "analysis OFF (-noanalysis)" })), $WallSeconds, $AnalysisTimeoutPerFile) -ForegroundColor Cyan

function Get-Detail([string]$log, [string]$outcome) {
    $lines = @($log -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 })
    $err = $null
    if ($outcome -in @("process_died", "hang")) {
        $err = $lines | Where-Object { $_ -match "OutOfMemoryError|StackOverflowError|Exception in thread|Uncaught exception|SEVERE" } | Select-Object -First 1
    }
    if (-not $err) { $err = $lines | Where-Object { $_ -match "\bERROR\b" } | Select-Object -First 1 }
    if (-not $err) { $err = $lines | Where-Object { $_ -match "\bWARN\b" } | Select-Object -First 1 }
    if (-not $err) { $err = $lines | Where-Object { $_ -match "PROBE " } | Select-Object -First 1 }
    if (-not $err -and $outcome -eq "hang") { $err = $lines | Select-Object -Last 1 }
    if (-not $err) { $err = "(no diagnostic line)" }
    # strip log level and "(Producer)" tags anywhere in the line
    $err = $err -replace "\s*\(([A-Za-z]+Analyzer|HeadlessAnalyzer|ProgramLoader|WasmLoader|AnalysisTaskWrapper|DecompileCallback|Manager|TaskWrapper|GhidraScript|LocalFileSystem|User)\)", ""
    $err = $err -replace "^\s*(ERROR|WARN|INFO)\s+", ""
    # append the first wasm.* / java.* stack frame for exception detail
    $frame = $lines | Where-Object { $_ -match "^\s*at (wasm|java)\.\S+" } | Select-Object -First 1
    if ($frame) { $err = "$err | $($frame.Trim())" }
    $err = ($err -replace "\s+", " ").Trim()
    if ($err.Length -gt 400) { $err = $err.Substring(0, 400) + " ..." }
    return $err
}

$results = New-Object System.Collections.Generic.List[object]
$index = 0

foreach ($p in $probes) {
    $index++
    $projDir = Join-Path $projRoot ([IO.Path]::GetFileNameWithoutExtension($p.Name))
    New-Item -ItemType Directory -Force -Path $projDir | Out-Null
    $outLog = Join-Path $logDir ($p.BaseName + ".out.log")
    $errLog = Join-Path $logDir ($p.BaseName + ".err.log")
    Remove-Item $outLog, $errLog -ErrorAction SilentlyContinue

    $argList = @(
        $projDir, "Robustness",
        "-import", $p.FullName,
        "-scriptPath", $ScriptDir,
        "-postScript", "WasmFeatureReport.java",
        "-max-cpu", "$MaxCpu",
        "-deleteProject"
    ) + $analysisArgs

    Write-Host ("[{0}/{1}] {2}" -f $index, $probes.Count, $p.Name) -ForegroundColor Gray
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $proc = Start-Process -FilePath $headless -ArgumentList $argList -PassThru -NoNewWindow `
        -RedirectStandardOutput $outLog -RedirectStandardError $errLog
    $procId = $proc.Id
    $finished = $proc.WaitForExit($WallSeconds * 1000)
    $sw.Stop()
    $wall = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0:F1}", $sw.Elapsed.TotalSeconds)

    $exit = $null
    if ($finished) {
        try { $exit = $proc.ExitCode } catch { $exit = $null }
    }
    else {
        # wall-clock timeout: kill the whole process tree (analyzeHeadless.bat -> java -> ...)
        try { & taskkill.exe /T /F /PID $procId 2>&1 | Out-Null } catch { }
        try { $proc.WaitForExit(15000) | Out-Null } catch { }
        try { if (-not $proc.HasExited) { Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue } } catch { }
        Start-Sleep -Milliseconds 300
    }

    $log = ""
    foreach ($lf in @($outLog, $errLog)) {
        if (Test-Path $lf) { $log += (Get-Content -Raw $lf -ErrorAction SilentlyContinue) }
    }

    # ---- classify ----
    $hasProbe = $log -match ("PROBE\s+" + [regex]::Escape($p.BaseName))
    $importFailed = $log -match "Import failed for file" -or $log -match "Failed to load Wasm module" `
        -or $log -match "could not successfully load" -or $log -match "No loaders" `
        -or $log -match "not a wasm file" -or $log -match "Invalid wasm"
    $analysisTimeout = $log -match "Analysis timed out"
    $uncaught = $log -match "Exception in thread" -or $log -match "Uncaught exception" `
        -or $log -match "StackOverflowError" `
        -or ($log -match "OutOfMemoryError" -and $log -notmatch "Analysis Task:")
    $exitBad = $finished -and ($null -ne $exit) -and ($exit -ne 0)

    if (-not $finished) { $outcome = "hang" }
    elseif ($exitBad -or $uncaught) { $outcome = "process_died" }
    elseif ($importFailed) { $outcome = "import_failed" }
    elseif ($hasProbe -and $analysisTimeout) { $outcome = "import_ok_analysis_timeout" }
    elseif ($hasProbe) { $outcome = "import_ok" }
    else { $outcome = "unknown" }

    $detail = Get-Detail $log $outcome

    # ---- metrics from the PROBE line, when present ----
    $funcs = $null; $instrs = $null; $undef = $null; $decomp = $null; $decompFail = $null
    $m = [regex]::Match($log, "PROBE\s+\S+\s+funcs=(\d+)\s+instrs=(\d+)\s+undefined_bytes=(\d+)\s+decompiled=(\d+)\s+decompile_failed=(\d+)")
    if ($m.Success) {
        $funcs = [int]$m.Groups[1].Value; $instrs = [int]$m.Groups[2].Value
        $undef = [long]$m.Groups[3].Value; $decomp = [int]$m.Groups[4].Value; $decompFail = [int]$m.Groups[5].Value
    }
    $metrics = ""
    if ($m.Success) { $metrics = "funcs=$funcs instrs=$instrs undefined_bytes=$undef decompiled=$decomp decompile_failed=$decompFail" }

    # ---- silent-acceptance hint: imported, but produced a program with little/no recovery ----
    $note = ""
    if ($outcome -eq "import_ok") {
        if ($funcs -eq 0) { $note = "no functions recovered" }
        elseif ($instrs -eq 0) { $note = "no instructions recovered" }
    }

    $results.Add([pscustomobject]@{
        Name     = $p.Name
        Bytes    = $p.Length
        Outcome  = $outcome
        WallSec  = $wall
        ExitCode = $exit
        Funcs    = $funcs
        Instrs   = $instrs
        Undef    = $undef
        Decomp   = $decomp
        Metrics  = $metrics
        Note     = $note
        Detail   = $detail
        LogPath  = $outLog
    }) | Out-Null

    Remove-Item -Recurse -Force $projDir -ErrorAction SilentlyContinue
}

# ---- safety net: kill any analyser JVM still referencing this run's work dir ----
try {
    Get-CimInstance Win32_Process -Filter "Name = 'java.exe' OR Name = 'javaw.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*$WorkDir*" } |
        ForEach-Object {
            Write-Host ("killing leftover JVM pid {0}" -f $_.ProcessId) -ForegroundColor Yellow
            & taskkill.exe /T /F /PID $_.ProcessId 2>&1 | Out-Null
        }
} catch { }

# ---- summary ----
Write-Host ""
Write-Host "== summary ==" -ForegroundColor Cyan
$order = @("import_ok", "import_ok_analysis_timeout", "import_failed", "process_died", "hang", "unknown")
foreach ($o in $order) {
    $n = ($results | Where-Object { $_.Outcome -eq $o }).Count
    if ($n -gt 0) { Write-Host ("{0,-26} {1}" -f $o, $n) }
}
Write-Host ""

$table = $results | ForEach-Object {
    $d = $_.Detail -replace "\|", "/"
    "| {0} | {1} | {2} | {3} | {4} |" -f $_.Name, $_.Bytes, $_.Outcome, $_.WallSec, $d
}

$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine("# WebAssembly loader robustness sweep (agent J)")
[void]$md.AppendLine("")
[void]$md.AppendLine("Generated by ``test-scripts/robustness-sweep.ps1``. Each module was imported in its own")
[void]$md.AppendLine("headless Ghidra process (``-max-cpu $MaxCpu``, $(if ($Analyze) { "-analysisTimeoutPerFile $AnalysisTimeoutPerFile" } else { "-noanalysis" }), hard wall bound ``$WallSeconds``s)")
[void]$md.AppendLine("from the ``$CorpusMode`` corpus in ``$CorpusDir``. To exercise the analyzers as well, run with")
[void]$md.AppendLine("``-Analyze``.")
[void]$md.AppendLine("")
[void]$md.AppendLine("Outcome legend: **import_ok** = loader produced a program and the report ran; ")
[void]$md.AppendLine("**import_ok_analysis_timeout** = program produced but analysis exceeded the per-file timeout; ")
[void]$md.AppendLine("**import_failed** = loader rejected the module with a message; ")
[void]$md.AppendLine("**process_died** = JVM exited non-zero / uncaught exception escaped; **hang** = wall clock exceeded.")
[void]$md.AppendLine("")
[void]$md.AppendLine("## Totals")
[void]$md.AppendLine("")
[void]$md.AppendLine("| outcome | count |")
[void]$md.AppendLine("| --- | --- |")
foreach ($o in $order) {
    $n = ($results | Where-Object { $_.Outcome -eq $o }).Count
    if ($n -gt 0) { [void]$md.AppendLine("| $o | $n |") }
}
[void]$md.AppendLine("| **total** | **$($results.Count)** |")
[void]$md.AppendLine("")
[void]$md.AppendLine("## Per-module outcomes")
[void]$md.AppendLine("")
[void]$md.AppendLine("| module | bytes | outcome | wall(s) | detail |")
[void]$md.AppendLine("| --- | --- | --- | --- | --- |")
foreach ($line in $table) { [void]$md.AppendLine($line) }
[void]$md.AppendLine("")
[void]$md.AppendLine("## Metrics (successful imports)")
[void]$md.AppendLine("")
[void]$md.AppendLine("| module | metrics | note |")
[void]$md.AppendLine("| --- | --- | --- |")
foreach ($r in ($results | Where-Object { $_.Metrics })) { [void]$md.AppendLine("| $($r.Name) | $($r.Metrics) | $($r.Note) |") }

Set-Content -Path $ResultsFile -Value $md.ToString() -Encoding UTF8
Write-Host ("wrote {0}" -f $ResultsFile) -ForegroundColor Cyan

# machine-readable csv next to the logs
$results | Export-Csv -Path (Join-Path $WorkDir "results.csv") -NoTypeInformation -Encoding UTF8
Write-Host ("logs in {0}" -f $logDir) -ForegroundColor DarkGray

# exit non-zero if any severe outcome was seen, so callers can gate on it
$severe = ($results | Where-Object { $_.Outcome -in @("process_died", "hang") }).Count
if ($severe -gt 0) {
    Write-Host ("SEVERE outcomes: {0}" -f $severe) -ForegroundColor Red
    exit 2
}
exit 0
