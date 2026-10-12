<#
.SYNOPSIS
    Run the official WebAssembly spec testsuite's *assertions* through this plugin's emulator.

.DESCRIPTION
    ghidra_scripts/spectest.py drives the Wasm emulator over the `.json` emitted by wast2json and
    executes `assert_return` / `assert_trap` / `action` commands against real values. It needs
    PyGhidra, i.e. a CPython with a `jpype1` wheel. Ghidra 12.1.4 bundles wheels for cp39..cp313
    (Ghidra/Features/PyGhidra/pypkg/dist); the host `python` is 3.14, for which no jpype1 wheel
    exists, so this script provisions (once) a Python 3.13 venv under `$env:TEMP\spectest-tools`
    and installs PyGhidra into it fully offline from Ghidra's own dist directory.

    Steps per `.wast`:
      1. `wast2json --no-check <f>.wast -o <OutDir>\json\<f>.json`
      2. `<venv-python> -m pyghidra --install-dir <ghidra> --project-path <tmp> --project-name <f>
             --skip-analysis <repo>\ghidra_scripts\spectest.py <f>.json --report <OutDir>\reports\<f>.txt`
      3. `parse_emulate_report.py` aggregates the per-command RESULT lines into
         `<OutDir>\emulate-summary.md` / `.json`.

    The wabt / testsuite toolchain is shared with test-scripts/spectest/README.md; run
    `test-scripts\spectest\fetch_spectest_tools.ps1` first if `$env:TEMP\spectest-tools` is empty.

.EXAMPLE
    .\test-scripts\spectest\run_emulate.ps1 -Files i32,i64 -OutDir "$env:TEMP\spec-emulate"
#>
param(
    [string[]]$Files = @("i32", "i64"),
    [int]$MaxCommands = 0,
    [int]$MaxSteps = 0,
    [string]$OutDir = "$env:TEMP\spectest-emulate",
    [string]$GhidraDir = "",
    [string]$PythonExe = "",
    [switch]$NoPrepare,
    [switch]$Force   # allow a GhidraDir other than the one pinned in test-scripts/.ghidra-install
)

$ErrorActionPreference = "Stop"

# --- install pinning (same rule as build-install.ps1 / check-local.ps1) -----------------------
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$pinFile = Join-Path $repo "test-scripts\.ghidra-install"
if (Test-Path $pinFile) {
    $pinned = (Get-Content $pinFile -Raw).Trim()
    if (-not $GhidraDir) { $GhidraDir = $pinned }
    elseif ($GhidraDir -ne $pinned -and -not $Force) {
        throw "REFUSED: this checkout is pinned to '$pinned'. Pass -Force to override."
    }
}
if (-not $GhidraDir) { throw "no Ghidra install (pass -GhidraDir or set test-scripts/.ghidra-install)" }
if (-not (Test-Path $GhidraDir)) { throw "Ghidra install not found: $GhidraDir" }

# --- toolchain -------------------------------------------------------------------------------
$tools = Join-Path $env:TEMP "spectest-tools"
$wabt = Join-Path $tools "wabt-1.0.42\bin"
$specDir = Get-ChildItem $tools -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "spec-*" } | Select-Object -First 1
if (-not (Test-Path "$wabt\wast2json.exe") -or -not $specDir) {
    throw "toolchain missing under $tools - run test-scripts\spectest\fetch_spectest_tools.ps1 first"
}

# --- PyGhidra interpreter --------------------------------------------------------------------
if (-not $PythonExe) {
    $venv = Join-Path $tools "pyghidra-venv"
    $PythonExe = Join-Path $venv "Scripts\python.exe"
    if (-not (Test-Path $PythonExe)) {
        Write-Host "== provisioning PyGhidra venv (Python 3.13) at $venv ==" -ForegroundColor Cyan
        py -3.13 -m venv $venv
        $dist = Join-Path $GhidraDir "Ghidra\Features\PyGhidra\pypkg\dist"
        & $PythonExe -m pip install --no-index -f $dist pyghidra
        if ($LASTEXITCODE -ne 0) { throw "pip install pyghidra failed" }
    }
}

$jsonDir = Join-Path $OutDir "json"
$repDir = Join-Path $OutDir "reports"
$projRoot = Join-Path $OutDir "projects"
New-Item -ItemType Directory -Force $jsonDir, $repDir, $projRoot | Out-Null

$script = Join-Path $repo "ghidra_scripts\spectest.py"

foreach ($f in $Files) {
    $wast = Join-Path $specDir $f".wast"
    if (-not (Test-Path $wast)) { Write-Warning "no such wast: $f"; continue }
    $json = Join-Path $jsonDir "$f.json"
    $rep = Join-Path $repDir "$f.txt"
    if (-not $NoPrepare -or -not (Test-Path $json)) {
        Copy-Item $wast (Join-Path $jsonDir (Split-Path $wast -Leaf)) -Force
        Push-Location $jsonDir
        try { & "$wabt\wast2json.exe" --no-check (Split-Path $wast -Leaf) -o "$f.json" | Out-Null }
        finally { Pop-Location }
    }

    $proj = Join-Path $projRoot $f
    Remove-Item -Recurse -Force $proj -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $proj | Out-Null
    $extra = @()
    if ($MaxCommands -gt 0) { $extra += "--max-commands=$MaxCommands" }
    if ($MaxSteps -gt 0) { $extra += "--max-steps=$MaxSteps" }

    Write-Host "== emulating $f ==" -ForegroundColor Cyan
    & $PythonExe -m pyghidra --install-dir $GhidraDir --project-path $proj --project-name spectest `
        --skip-analysis $script $json "--report=$rep" @extra 2>&1 |
        Tee-Object (Join-Path $repDir "$f.log") |
        Select-String -Pattern "SUMMARY|ERROR:" | ForEach-Object { $_.Line }
    Remove-Item -Recurse -Force $proj -ErrorAction SilentlyContinue
}

Write-Host "== parsing reports ==" -ForegroundColor Cyan
& python (Join-Path $PSScriptRoot "parse_emulate_report.py") $repDir $OutDir
