<#
.SYNOPSIS
    Build the small WASM DWARF fixture(s) used to exercise source-line-info import.

.DESCRIPTION
    Generates a tiny Rust crate for wasm32-unknown-unknown with debug info and writes two
    wasm modules into -OutDir:
        fixture_dwarf.wasm              (-C debuginfo=2)
        fixture_dwarf_lineonly.wasm     (-C debuginfo=line-tables-only)

    The Rust source is emitted by this script, so the fixtures can always be regenerated and
    do not need to be committed.

    Linking is done in two steps (`rustc --emit=obj` then rust-lld) on purpose: a plain
    `rustc ... --crate-type=cdylib` link pulls the precompiled `core` crate into the module
    and with it ~630 KB of `core` debug info. Our object file alone needs no `core` symbols
    (overflow checks are off), so linking just it keeps the module at a few KB while still
    carrying a real, fully relocated `.debug_line` table from rustc/LLVM.

.EXAMPLE
    .\test-scripts\make_dwarf_fixture.ps1 -OutDir out
#>
param(
    [string]$OutDir = "out",
    [string]$Rustc = "rustc",
    [switch]$BigLink   # fall back to a plain single-invocation cdylib link (~630 KB)
)

$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
$out  = Join-Path $repo $OutDir
New-Item -ItemType Directory -Force -Path $out | Out-Null
$src  = Join-Path $out "fixture.rs"

$rs = @'
// Tiny DWARF fixture: three no_mangle functions with a few statements each so that
// rustc/LLVM emits a non-trivial .debug_line program.
#![no_std]
#![allow(dead_code)]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn add_three(a: i32, b: i32, c: i32) -> i32 {
    let s = a + b;
    let t = s + c;
    t + 1
}

#[no_mangle]
pub extern "C" fn mixup(a: u32, b: u32) -> u32 {
    let x = a ^ b;
    let y = x.rotate_left(3);
    y.wrapping_mul(2654435761u32)
}

#[no_mangle]
pub extern "C" fn loopsum(n: i32) -> i32 {
    let mut acc = 0i32;
    let mut i = 0i32;
    while i < n {
        acc += i;
        i += 1;
    }
    acc
}
'@

Set-Content -Path $src -Value $rs -Encoding UTF8

function Find-WasmLld {
    $lldName = if ($IsWindows) { "rust-lld.exe" } else { "rust-lld" }
    $sysroot = (& $Rustc --print sysroot).Trim()
    $hostTriple = (& $Rustc -vV | Select-String '^host:').ToString().Split(':')[1].Trim()
    $candidate = Join-Path $sysroot "lib\rustlib\$hostTriple\bin\$lldName"
    if (Test-Path $candidate) { return $candidate }
    return $null
}

$target = "wasm32-unknown-unknown"
$objName = Join-Path $out "fixture.o"

function Build-One([string]$debugFlag, [string]$outFile) {
    if ($BigLink) {
        & $Rustc "--target" $target "--crate-type=cdylib" "-C" "opt-level=0" "-C" "panic=abort" `
            "-C" "debuginfo=$debugFlag" "-o" $outFile $src
        if ($LASTEXITCODE -ne 0) { throw "rustc (debuginfo=$debugFlag) failed" }
        return
    }
    & $Rustc "--target" $target "--crate-type=cdylib" "--emit=obj" "-C" "opt-level=0" `
        "-C" "panic=abort" "-C" "overflow-checks=off" "-C" "debug-assertions=off" `
        "-C" "debuginfo=$debugFlag" "-o" $objName $src
    if ($LASTEXITCODE -ne 0) { throw "rustc --emit=obj (debuginfo=$debugFlag) failed" }

    $lld = Find-WasmLld
    if (-not $lld) {
        Write-Warning "rust-lld not found; falling back to a plain cdylib link (larger module)"
        & $Rustc "--target" $target "--crate-type=cdylib" "-C" "opt-level=0" "-C" "panic=abort" `
            "-C" "debuginfo=$debugFlag" "-o" $outFile $src
        if ($LASTEXITCODE -ne 0) { throw "rustc fallback (debuginfo=$debugFlag) failed" }
        return
    }
    & $lld -flavor wasm --no-entry --export-dynamic --gc-sections -o $outFile $objName
    if ($LASTEXITCODE -ne 0) { throw "rust-lld failed for debuginfo=$debugFlag" }
}

Build-One "2" (Join-Path $out "fixture_dwarf.wasm")
Build-One "line-tables-only" (Join-Path $out "fixture_dwarf_lineonly.wasm")

Get-ChildItem $out -Filter "fixture_dwarf*.wasm" | ForEach-Object {
    Write-Host ("{0}  {1} bytes" -f $_.Name, $_.Length)
}
