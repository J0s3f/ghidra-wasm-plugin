# Rebuilds the locally-compiled Rust corpus modules (rust_plain, rust_debuginfo, rust_simd128).
#
# The three modules are plain rustc cdylib builds - no Cargo, no wasm-bindgen, no wasm-opt - so the
# exact bytes depend on the rustc version recorded in manifest.json. Run this only if you need to
# regenerate them (e.g. rustc moved on); otherwise use the committed rust_plain/rust_simd128 and the
# manifest sha256.
#
# Usage (from the repo root):
#   pwsh test-scripts/corpus/rust-src/build.ps1 -OutDir C:\path\to\corpus\modules
param(
    [string]$OutDir = "$env:TEMP\corpus\modules",
    [string]$Rustc = "rustc"
)
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$common = @('--target', 'wasm32-unknown-unknown', '--crate-type', 'cdylib',
            '-C', 'opt-level=z', '-C', 'lto=fat', '-C', 'codegen-units=1', '-C', 'panic=abort')
Push-Location $here
try {
    & $Rustc @common -o (Join-Path $OutDir 'rust_plain.wasm') lib.rs
    & $Rustc @common -C debuginfo=2 -o (Join-Path $OutDir 'rust_debuginfo.wasm') lib.rs
    & $Rustc @common -C target-feature=+simd128 -o (Join-Path $OutDir 'rust_simd128.wasm') simd.rs
}
finally { Pop-Location }
Get-ChildItem $OutDir -Filter 'rust_*.wasm' |
    ForEach-Object { "{0,-24} {1,8}  {2}" -f $_.Name, $_.Length, (Get-FileHash $_.FullName -Algorithm SHA256).Hash }
