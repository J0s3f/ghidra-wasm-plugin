# Exercise the real wrapper with a controlled native process, without starting Ghidra.
param([string]$OutDir = (Join-Path $PSScriptRoot '../build/emulate-exit-tests'))
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'The mock native launcher uses Windows cmd files.' }
$root = Join-Path ([IO.Path]::GetFullPath($OutDir)) ([Guid]::NewGuid().ToString('N'))
$tools = Join-Path $root 'spectest-tools'
$run = Join-Path $root 'run'
New-Item -ItemType Directory -Force (Join-Path $tools 'wabt-1.0.42/bin'),
    (Join-Path $tools 'spec-fixture'), (Join-Path $root 'ghidra'),
    (Join-Path $run 'json'), (Join-Path $run 'reports') | Out-Null
Set-Content (Join-Path $tools 'wabt-1.0.42/bin/wast2json.exe') 'unused with NoPrepare'
Set-Content (Join-Path $tools 'spec-fixture/suite.wast') 'fixture'
Set-Content (Join-Path $run 'json/suite.json') '{}'
$launcher = Join-Path $root 'fake-python.cmd'
$report = Join-Path $run 'reports/suite.txt'
function Invoke-Case([int]$Code, [string]$Result, [string]$ExpectedError) {
    $body = @('@echo off')
    if ($Result) { $body += ('echo RESULT assert_return ' + $Result + ' fixture>"' + $report + '"') }
    $body += "exit /b $Code"
    Set-Content -LiteralPath $launcher -Value $body -Encoding ascii
    $caught = $null
    try {
        & (Join-Path $PSScriptRoot 'spectest/run_emulate.ps1') -Files suite -NoPrepare `
            -GhidraDir (Join-Path $root 'ghidra') -Force -PythonExe $launcher -OutDir $run | Out-Null
    } catch { $caught = $_.Exception.Message }
    if ($ExpectedError) {
        if (-not $caught -or $caught -notlike "*$ExpectedError*") { throw "Expected '$ExpectedError', received '$caught'" }
    } elseif ($caught) { throw $caught }
    Write-Output "PASS native exit=$Code report=$Result expected=$ExpectedError"
}
$previousTemp = $env:TEMP
try {
    $env:TEMP = $root
    Invoke-Case 7 'ok' 'exit 7'
    Set-Content -LiteralPath $report 'RESULT assert_return ok stale'
    Invoke-Case 0 '' 'Missing emulation report'
    Invoke-Case 0 'fail' 'Spec emulation regression'
    Invoke-Case 0 'ok' ''
} finally { $env:TEMP = $previousTemp }
