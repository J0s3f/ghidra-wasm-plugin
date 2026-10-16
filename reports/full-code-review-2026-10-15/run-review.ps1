param(
    [string]$GhidraDir = 'C:\Tools\ghidra_12.1.4_PUBLIC',
    [string]$OutDir = ''
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $OutDir) { $OutDir = Join-Path $repo 'build/full-code-review-replay' }
$OutDir = [IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$classes = Join-Path $OutDir 'classes'
New-Item -ItemType Directory -Force -Path $classes | Out-Null
$jars = (Get-ChildItem (Join-Path $GhidraDir 'Ghidra') -Recurse -File -Filter '*.jar' |
    Where-Object { $_.FullName -notlike '*\Extensions\*' }).FullName
$dependencies = $jars -join ';'
$sources = @(Get-ChildItem (Join-Path $repo 'src/main/java') -Recurse -File -Filter '*.java') +
    @(Get-Item (Join-Path $PSScriptRoot 'ReviewHarness.java'), (Join-Path $PSScriptRoot 'ParserReview.java'))
$compilerArgs = @('--release', '21', '-cp', ('"' + $dependencies.Replace('\','/') + '"'),
    '-d', ('"' + $classes.Replace('\','/') + '"')) +
    @($sources | ForEach-Object { '"' + $_.FullName.Replace('\','/') + '"' })
$argsFile = Join-Path $OutDir 'javac.args'
[IO.File]::WriteAllLines($argsFile, $compilerArgs, [Text.UTF8Encoding]::new($false))
& javac ('@' + $argsFile) *> (Join-Path $OutDir 'compile.txt')
if ($LASTEXITCODE -ne 0) { throw "Compilation failed; see $OutDir/compile.txt" }
$fixtures = Join-Path $OutDir 'fixtures'
& python (Join-Path $PSScriptRoot 'make_review_fixtures.py') $fixtures > (Join-Path $OutDir 'generation.txt')
if ($LASTEXITCODE -ne 0) { throw 'Fixture generation failed' }
& node (Join-Path $PSScriptRoot 'oracle.mjs') $fixtures > (Join-Path $OutDir 'oracle-results.json')
if ($LASTEXITCODE -ne 0) { throw 'Node oracle failed' }
$cp = $classes + ';' + $dependencies
& java -Xmx64m -cp $cp ParserReview (Join-Path $fixtures 'huge_params.wasm') `
    (Join-Path $fixtures 'truncated_datacount.wasm') (Join-Path $fixtures 'typed_signature.wasm') `
    (Join-Path $fixtures 'rec_functype.wasm') *> (Join-Path $OutDir 'parser-results.txt')
if ($LASTEXITCODE -ne 0) { throw 'Parser diagnostic process failed' }
$jvmOptions = @('-Djava.awt.headless=true', ('-Dreview.ghidra=' + $GhidraDir),
    ('-Dapplication.settingsdir=' + (Join-Path $OutDir 'settings')),
    ('-Dapplication.cachedir=' + (Join-Path $OutDir 'cache')),
    ('-Dapplication.tempdir=' + (Join-Path $OutDir 'tmp')))
$inputs = @(Get-ChildItem $fixtures -File -Filter '*.wasm' |
    Where-Object Name -ne 'huge_params.wasm' | Sort-Object Name | ForEach-Object FullName)
& java @jvmOptions -cp $cp ReviewHarness @inputs *> (Join-Path $OutDir 'integration-results.txt')
if ($LASTEXITCODE -ne 0) { throw 'Integration diagnostic process failed' }
Write-Output "Review receipts: $OutDir"
Write-Output 'These diagnostic programs record current behavior, including known failures; compare the results with REPORT.md.'
