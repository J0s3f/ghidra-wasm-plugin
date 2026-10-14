<#
.SYNOPSIS
    Regression check for padded (non-minimal) LEB memarg encodings.

.DESCRIPTION
    Generates the padded-memarg fixtures (memarg-padding-fixtures.py), imports them with
    the pinned Ghidra install and asserts, per function (CheckMemargPadding.java):

      * the exact instruction sequence - mnemonic, byte length and the align/memidx/offset
        operand text, i.e. the instruction boundaries and the memarg decode;
      * the memory selection of every load/store: the ACCESS space (memory vs memory64),
        the address width, and the memidx * MEMORY_STRIDE multiply in the pcode;
      * execution: the emulated i32 result, which proves the effective address (which
        memory's bytes come back).

    Coverage: padded flagged scalar loads/stores, the padded SIMD v128.load case (padded
    0xfd sub-opcode + fully padded memarg = 26 bytes, the emulator's worst case), a
    padded atomic load, padded unflagged align values (which must stay unflagged), the
    plain single-byte forms as unchanged controls, and one deliberately wabt-invalid
    module (alignment hint 130) that must still import and decode as unflagged.

    Exit code is non-zero on any failure (the Java check throws; the wrapper rethrows).

.EXAMPLE
    .\test-scripts\check-memarg-padding.ps1 -OutDir "$env:TEMP\memarg-padding"

    # CI wiring (probes.yml, after the "Run probe suite" step - the extension is already
    # installed there; this script needs no build):
    #   - name: Padded memarg regression check
    #     run: |
    #       set -euxo pipefail
    #       export GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:?setup-ghidra did not export GHIDRA_INSTALL_DIR}"
    #       export GHIDRA_HEADLESS_MAXMEM=1500M
    #       pwsh -NoProfile -File test-scripts/check-memarg-padding.ps1 -OutDir "$RUNNER_TEMP/memarg-padding"
#>
param(
    [Parameter(Mandatory=$true)][string]$OutDir,
    [string]$GhidraDir = ""
)
$ErrorActionPreference = "Stop"
$pin = (Get-Content (Join-Path $PSScriptRoot ".ghidra-install") -Raw).Trim()
if (-not $GhidraDir) { $GhidraDir = $pin }
if ((Resolve-Path -LiteralPath $GhidraDir).Path -ne (Resolve-Path -LiteralPath $pin).Path) {
    throw "REFUSED: use this worktree's pinned Ghidra install: $pin"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$fixtures = Join-Path $OutDir "fixtures"
& python (Join-Path $PSScriptRoot "memarg-padding-fixtures.py") $fixtures
if ($LASTEXITCODE -ne 0) { throw "fixture generation failed" }
$project = Join-Path $OutDir ("project-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $project | Out-Null
$log = Join-Path $OutDir "memarg-padding-check.log"
$headless = Join-Path $GhidraDir "support/analyzeHeadless.bat"
if ([Environment]::OSVersion.Platform -ne "Win32NT") {
    $headless = Join-Path $GhidraDir "support/analyzeHeadless"
}
$previous = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    & $headless $project MemargPadding -import (Join-Path $fixtures "memarg_padding.wasm") `
        -import (Join-Path $fixtures "memarg_padding64.wasm") `
        -import (Join-Path $fixtures "memarg_padding_lenient.wasm") -noanalysis `
        -scriptPath $PSScriptRoot -postScript CheckMemargPadding.java `
        -max-cpu 2 -deleteProject 2>&1 | Out-File -FilePath $log -Encoding utf8
    $code = $LASTEXITCODE
} finally { $ErrorActionPreference = $previous }
$text = Get-Content -LiteralPath $log -Raw
Select-String -LiteralPath $log -Pattern "MEMARG-PADDING|ERROR|AssertionError" |
    ForEach-Object { $_.Line }
if ($code -ne 0 -or $text -notmatch "MEMARG-PADDING memarg_padding\.wasm functions=7 passed" -or
    $text -notmatch "MEMARG-PADDING memarg_padding64\.wasm functions=3 passed" -or
    $text -notmatch "MEMARG-PADDING memarg_padding_lenient\.wasm functions=1 passed") {
    throw "Padded-memarg assertions failed; inspect $log"
}
Write-Host "OK: padded memarg decode + emulation; log: $log"
