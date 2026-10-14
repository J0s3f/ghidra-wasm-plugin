<#
.SYNOPSIS
    Cross-engine decode oracle: import the pinned corpus modules through the WebAssembly plugin,
    then check that the plugin's per-function decode matches WABT (wasm-objdump) and Binaryen
    (wasm-dis) on the same modules.

.DESCRIPTION
    This is the driver half of the decode oracle (the checker is check-decode-oracle.py; the
    per-function facts come from DecodeOracleReport.java). For a pinned set of valid, committed
    corpus modules it:

      1. seeds the committed modules from test-scripts/corpus/modules/ into -CorpusDir and verifies
         every sha256 against test-scripts/corpus/manifest.json (single source of truth),
      2. imports each module headlessly with the pinned Ghidra install, running
         DecodeOracleReport.java to capture the plugin's per-function decode (real instruction
         counts + normalized mnemonic histogram + body/import totals),
      3. writes <WorkDir>/modules.json + <WorkDir>/<module>/plugin.log, then invokes
         check-decode-oracle.py, which runs WABT wasm-objdump (-d and -x) and Binaryen wasm-dis
         (timeout-guarded) and compares all three engines against the recorded baseline
         (test-scripts/decode-oracle-baseline.json).

    Only valid, committed modules belong in the pinned set: the oracle needs a reference decode
    from every engine, so a module an oracle rejects (e.g. minrepro_a_i32, which is deliberately
    invalid) is excluded by default. The default set is rust_plain + rust_simd128 (MVP + SIMD),
    both valid and both committed, so CI runs fully offline.

    Fully offline apart from the oracles themselves: no downloads here.

.EXAMPLE
    # full oracle run (fetch the oracles first with fetch_spectest_tools.ps1 -WabtOnly -Binaryen)
    .\test-scripts\decode-oracle.ps1 `
        -WabtDir "$env:TEMP\spectest-tools\wabt-1.0.42\bin" `
        -BinaryenDir "$env:TEMP\spectest-tools\binaryen-version_133\bin"

.EXAMPLE
    # re-record the baseline after an intentional decode change
    .\test-scripts\decode-oracle.ps1 -WabtDir <bin> -BinaryenDir <bin> -Update
#>
param(
    [string]$GhidraDir = "",
    [string]$CorpusDir = "$env:TEMP\corpus",
    [string]$Manifest  = "$PSScriptRoot\corpus\manifest.json",
    [string]$ScriptDir = "$PSScriptRoot",
    [string]$WorkDir   = "$env:TEMP\wasm-decode-oracle",
    [string]$WabtDir,                 # directory containing wasm-objdump
    [string]$BinaryenDir,             # directory containing wasm-dis
    [string[]]$Modules = @("rust_plain", "rust_simd128"),  # pinned valid committed set
    [int]$MaxCpu = 2,
    [string]$MaxMem = "1500M",
    [int]$TimeoutSec = 1500,
    [string]$Baseline = "$PSScriptRoot\decode-oracle-baseline.json",
    [switch]$Update,
    [switch]$KeepProjects
)

$ErrorActionPreference = "Stop"

# --- Ghidra install ----------------------------------------------------------------------------
# Prefer an explicit -GhidraDir, then GHIDRA_INSTALL_DIR (what CI exports), then the worktree's
# pinned install (test-scripts/.ghidra-install) as a local convenience. The pin must NOT win over
# the env var: in CI the pin names a developer-local path that does not exist on the runner.
if (-not $GhidraDir) { $GhidraDir = $env:GHIDRA_INSTALL_DIR }
if (-not $GhidraDir) {
    $pinFile = Join-Path $PSScriptRoot ".ghidra-install"
    if (Test-Path $pinFile) { $GhidraDir = (Get-Content $pinFile -Raw).Trim() }
}
if (-not $GhidraDir) { throw "Set GHIDRA_INSTALL_DIR or pass -GhidraDir (or rely on the pinned .ghidra-install)" }

$supportDir = Join-Path $GhidraDir "support"
$isWindowsOS = [System.Environment]::OSVersion.Platform -eq 'Win32NT'
if ($isWindowsOS) { $headless = Join-Path $supportDir "analyzeHeadless.bat" } else { $headless = Join-Path $supportDir "analyzeHeadless" }
if (-not (Test-Path $headless)) { $headless = Join-Path $supportDir "analyzeHeadless.bat" }
if (-not (Test-Path $headless)) { $headless = Join-Path $supportDir "analyzeHeadless" }
if (-not (Test-Path $headless)) { throw "analyzeHeadless not found under $supportDir" }
if (-not (Test-Path $Manifest)) { throw "manifest not found: $Manifest" }
if (-not $WabtDir)     { throw "pass -WabtDir (directory containing wasm-objdump)" }
if (-not $BinaryenDir) { throw "pass -BinaryenDir (directory containing wasm-dis)" }

$env:GHIDRA_HEADLESS_MAXMEM = $MaxMem
$repo = Split-Path -Parent $PSScriptRoot
$corpusScripts = Join-Path $ScriptDir "corpus"
New-Item -ItemType Directory -Force -Path $CorpusDir, $WorkDir | Out-Null
if (Test-Path (Join-Path $WorkDir "modules.json")) { Remove-Item -Force (Join-Path $WorkDir "modules.json") }

# --- select + seed + verify the pinned modules ------------------------------------------------
$manifestData = Get-Content -Raw $Manifest | ConvertFrom-Json
$sel = @($Modules | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
# NOTE: do not name this $modules - PowerShell is case-insensitive and $Modules is the [string[]]
# param above; assigning the manifest objects to it would coerce them to strings.
$selectedModules = @($manifestData.modules | Where-Object { $sel -contains $_.name })
if (-not $selectedModules) { throw "no modules selected (requested: $($sel -join ', '))" }

Write-Host "== resolving pinned decode-oracle modules ($($selectedModules.Count)) ==" -ForegroundColor Cyan
$resolved = @()
foreach ($m in $selectedModules) {
    $target = Join-Path $CorpusDir $m.file
    if (-not (Test-Path $target) -and $m.committed) {
        $src = Join-Path $corpusScripts $m.committed
        if (Test-Path $src) { Copy-Item $src $target -Force; Write-Host ("  seeded {0} from committed {1}" -f $m.name, $m.committed) }
    }
    if (-not (Test-Path $target)) { throw "module not found: $($m.name) -> $target (committed=$($m.committed))" }
    $actual = (Get-FileHash $target -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $m.sha256.ToLower()) { throw "sha256 mismatch for $($m.name): expected $($m.sha256), got $actual" }
    if ($m.v8 -ne "valid") { Write-Warning ("  {0} is v8={1} (not valid) - the decode oracle needs a module every engine accepts" -f $m.name, $m.v8) }
    $resolved += [pscustomobject]@{ name = $m.name; file = (Resolve-Path $target).Path; file_name = $m.file; sha256 = $actual }
    Write-Host ("  {0}  {1} bytes  sha256 ok" -f $m.name, $m.size)
}

# --- run the plugin headlessly per module -----------------------------------------------------
$idx = 0
foreach ($r in $resolved) {
    $idx++
    $mdir = Join-Path $WorkDir $r.name
    New-Item -ItemType Directory -Force -Path $mdir | Out-Null
    $projName = "oracle_" + ($r.name -replace '[^A-Za-z0-9_]', '_')
    $cmdArgs = @($WorkDir, $projName, "-import", $r.file,
                 "-scriptPath", $ScriptDir,
                 "-postScript", "DecodeOracleReport.java")
    $cmdArgs += @("-max-cpu", "$MaxCpu")
    if (-not $KeepProjects) { $cmdArgs += "-deleteProject" }

    $stdout = Join-Path $mdir "plugin.out.txt"
    $stderr = Join-Path $mdir "plugin.err.txt"
    $argLine = ($cmdArgs | ForEach-Object { if ($_ -match '[\s;]') { '"' + $_ + '"' } else { $_ } }) -join ' '

    Write-Host ("-- [{0}/{1}] plugin decode {2}" -f $idx, $resolved.Count, $r.name) -ForegroundColor Yellow
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process -FilePath $headless -ArgumentList $argLine -NoNewWindow -PassThru `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $timedOut = $false
    if (-not $p.WaitForExit($TimeoutSec * 1000)) { $timedOut = $true; try { $p.Kill($true) } catch { } }
    $sw.Stop()
    $logText = ""
    foreach ($f in @($stdout, $stderr)) { if (Test-Path $f) { $logText += (Get-Content -Raw $f) } }
    Set-Content -Path (Join-Path $mdir "plugin.log") -Value $logText -Encoding UTF8

    $total = [regex]::Match($logText, 'ORACLE-TOTAL\s+bodies=(\d+)\s+imports=(\d+)\s+real=(\d+)')
    if ($timedOut) {
        Write-Host ("   -> TIMEOUT > {0}s" -f $TimeoutSec) -ForegroundColor Red
    } elseif (-not $total.Success) {
        Write-Host "   -> NO ORACLE-TOTAL (DecodeOracleReport.java did not run; see plugin.log)" -ForegroundColor Red
    } else {
        Write-Host ("   -> bodies={0} imports={1} real={2}  ({3}s)" -f $total.Groups[1].Value, $total.Groups[2].Value, $total.Groups[3].Value, [math]::Round($sw.Elapsed.TotalSeconds, 1)) -ForegroundColor Gray
    }
    if ($p.ExitCode -ne 0 -and -not $timedOut) { Write-Host ("   -> analyzeHeadless exit code {0}" -f $p.ExitCode) -ForegroundColor Red }
}

# --- modules.json for the checker -------------------------------------------------------------
$payload = [pscustomobject]@{ modules = $resolved }
Set-Content -Path (Join-Path $WorkDir "modules.json") -Value ($payload | ConvertTo-Json -Depth 4) -Encoding UTF8

# --- hand off to the Python checker (runs wabt + binaryen, compares against the baseline) ------
Write-Host "== check-decode-oracle.py ==" -ForegroundColor Cyan
# Prefer python3 (guaranteed on the Linux runner); fall back to python (the repo convention; the
# probes workflow's shim step symlinks it on Linux).
$pyExe = (Get-Command python3 -ErrorAction SilentlyContinue).Source
if (-not $pyExe) { $pyExe = (Get-Command python -ErrorAction SilentlyContinue).Source }
if (-not $pyExe) { throw "neither python3 nor python is on PATH (the checker is Python)" }
$pyArgs = @((Join-Path $ScriptDir "check-decode-oracle.py"),
            "--artifacts", $WorkDir,
            "--wabt", $WabtDir,
            "--binaryen", $BinaryenDir,
            "--baseline", $Baseline)
if ($Update) { $pyArgs += "--update" }
& $pyExe @pyArgs
exit $LASTEXITCODE
