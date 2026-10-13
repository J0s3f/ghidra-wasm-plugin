#!/usr/bin/env pwsh
# Regression test for the harness stderr-capture bug (fixed 2026-10-13).
#
# PowerShell 7.3+ turns a native command's stderr into ErrorRecords when it is merged with 2>&1.
# With $ErrorActionPreference = 'Stop' (the harness default) a harmless JVM warning (e.g.
# sun.misc.Unsafe / a JDK deprecation note) therefore *terminated* check-local.ps1,
# run_probes.ps1, run_spectest.ps1 and run_emulate.ps1 mid-run. Separately, the old capture used
# Tee-Object, whose encoding depends on the host (UTF-16 under Windows PowerShell 5.1), while
# check-results.py reads UTF-8.
#
# This test pins the properties the harness capture must have:
#   1. a native command's stderr does NOT abort the script,
#   2. both stdout and stderr end up in the log,
#   3. $LASTEXITCODE is preserved for the caller's error check,
#   4. the log is UTF-8 (no UTF-16 BOM, no NUL bytes).
#
# Usage: pwsh -NoProfile -File test-scripts/test-stderr-capture.ps1 [-OutDir <dir>]
param(
    [string]$OutDir = (Join-Path ([IO.Path]::GetTempPath()) "stderr-capture-test")
)

$ErrorActionPreference = "Stop"   # the harness default - the whole point of the test
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$child = Join-Path $PSHOME "pwsh"
if (-not (Test-Path $child)) { $child = Join-Path $PSHOME "pwsh.exe" }
if (-not (Test-Path $child)) { Write-Host "FAIL: cannot find pwsh under $PSHOME" -ForegroundColor Red; exit 1 }
$childScript = 'Write-Output "out-line"; [Console]::Error.WriteLine("stderr-warning: simulated JVM warning"); exit 3'

$failures = 0
function Check([string]$name, [bool]$cond) {
    if ($cond) { Write-Host "ok  : $name" -ForegroundColor Green }
    else { Write-Host "FAIL: $name" -ForegroundColor Red; $script:failures++ }
}

# --- 1. the OLD pattern (native stderr + 2>&1 + Tee-Object under Stop) --------------------------
$oldLog = Join-Path $OutDir "old.log"
$oldThrew = $false
try {
    & $child -NoProfile -NonInteractive -Command $childScript 2>&1 | Tee-Object -FilePath $oldLog | Out-Null
}
catch { $oldThrew = $true }
if ($oldThrew) {
    Write-Host "ok  : the old capture pattern reproduces the abort on this host" -ForegroundColor Green
}
else {
    Write-Host ("note: the old pattern did not abort here (the bug needs PowerShell >= 7.3; " +
                "this host is $($PSVersionTable.PSVersion)) - the checks below still apply") -ForegroundColor Yellow
}

# --- 2. the NEW pattern: prefer to let stderr through without aborting, log UTF-8 --------------
$newLog = Join-Path $OutDir "new.log"
$newThrew = $false
$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    & $child -NoProfile -NonInteractive -Command $childScript 2>&1 | Out-File -FilePath $newLog -Encoding utf8
}
catch { $newThrew = $true }
finally { $ErrorActionPreference = $prevEap }
$code = $LASTEXITCODE

Check "native stderr does not abort the capture" (-not $newThrew)
$text = Get-Content -Path $newLog -Raw
Check "stdout is captured" ($text -match "out-line")
Check "stderr is captured" ($text -match "stderr-warning")
Check "exit code is preserved for the caller (3)" ($code -eq 3)
$bytes = [IO.File]::ReadAllBytes($newLog)
Check "log has no UTF-16 BOM" (-not ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE))
Check "log has no NUL bytes (is not UTF-16)" (-not ($bytes -contains 0))

# --- 3. a UTF-16 log (Windows PowerShell 5.1's Tee-Object/Out-File) must still parse -------------
# This is the reproducible half of the bug: 5.1 writes UTF-16LE, and check-results.py's old
# utf-8-only reader then missed every SUMMARY line. The reader must tolerate it.
$repoRoot = Split-Path $PSScriptRoot -Parent
$utf16 = Join-Path $OutDir "utf16.log"
[IO.File]::WriteAllText($utf16,
    "INFO  first line`nSUMMARY functions=1 decompiled=1 failed=0 instructions=2 undefined_bytes=0`n",
    [Text.Encoding]::Unicode)
$py = Get-Command python -ErrorAction SilentlyContinue
if ($py) {
    $probe = 'import importlib.util as u, pathlib, sys; p = pathlib.Path(sys.argv[1]) / "test-scripts" / "check-results.py"; ' +
             's = u.spec_from_file_location("cr", p); m = u.module_from_spec(s); s.loader.exec_module(m); ' +
             'print("SUMMARY functions=1" in m.read_log(pathlib.Path(sys.argv[2])))'
    $out = & $py.Source -c $probe $repoRoot $utf16
    Check "a UTF-16 log (5.1 capture) still parses" ($out -match "True")
}
else {
    Write-Host "skip: python not on PATH, UTF-16 log check skipped" -ForegroundColor Yellow
}

Write-Host ""
if ($failures -eq 0) {
    Write-Host "PASS: harness stderr capture is robust (logs under $OutDir)" -ForegroundColor Green
    exit 0
}
Write-Host "FAIL: $failures check(s) failed (logs under $OutDir)" -ForegroundColor Red
exit 1
