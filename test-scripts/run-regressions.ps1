param([string]$GhidraDir = '', [string]$OutDir = '')
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $GhidraDir) { $GhidraDir = $env:GHIDRA_INSTALL_DIR }
if (-not $GhidraDir) { $GhidraDir = (Get-Content (Join-Path $PSScriptRoot '.ghidra-install') -Raw).Trim() }
if (-not $OutDir) { $OutDir = Join-Path $repo 'build/code-regressions' }
$OutDir = [IO.Path]::GetFullPath($OutDir)
$classes = Join-Path $OutDir 'classes'
$module = Join-Path $OutDir 'module/Ghidra-WASM'
New-Item -ItemType Directory -Force $classes, (Join-Path $module 'data/languages') | Out-Null
Copy-Item (Join-Path $repo 'Module.manifest') $module
Copy-Item (Join-Path $repo 'data/languages/*') (Join-Path $module 'data/languages') -Force
$jars = (Get-ChildItem (Join-Path $GhidraDir 'Ghidra') -Recurse -File -Filter '*.jar' |
    Where-Object { $_.FullName -notmatch '[\\/]Extensions[\\/]' }).FullName
$dependencies = $jars -join [IO.Path]::PathSeparator
$sources = @(Get-ChildItem (Join-Path $repo 'src/main/java') -Recurse -File -Filter '*.java') +
    @(Get-ChildItem (Join-Path $PSScriptRoot 'regressions') -File -Filter '*.java')
$compilerArgs = @('--release', '21', '-cp', ('"' + $dependencies.Replace('\','/') + '"'),
    '-d', ('"' + $classes.Replace('\','/') + '"')) +
    @($sources | ForEach-Object { '"' + $_.FullName.Replace('\','/') + '"' })
$argsFile = Join-Path $OutDir 'javac.args'
[IO.File]::WriteAllLines($argsFile, $compilerArgs, [Text.UTF8Encoding]::new($false))
& javac ('@' + $argsFile) *> (Join-Path $OutDir 'compile.txt')
if ($LASTEXITCODE -ne 0) { throw "Compilation failed; see $OutDir/compile.txt" }
& java -cp $dependencies ghidra.pcodeCPort.slgh_compile.SleighCompile `
    (Join-Path $module 'data/languages/WebAssembly.slaspec') `
    (Join-Path $module 'data/languages/WebAssembly.sla') *> (Join-Path $OutDir 'sleigh.txt')
if ($LASTEXITCODE -ne 0) { throw "SLEIGH compilation failed; see $OutDir/sleigh.txt" }
$fixtures = Join-Path $OutDir 'fixtures'
& python (Join-Path $PSScriptRoot 'regressions/make_fixtures.py') $fixtures > (Join-Path $OutDir 'generation.txt')
if ($LASTEXITCODE -ne 0) { throw 'Fixture generation failed' }
& node (Join-Path $PSScriptRoot 'regressions/oracle.mjs') $fixtures *> (Join-Path $OutDir 'oracle-results.txt')
if ($LASTEXITCODE -ne 0) { throw "Independent fixture oracle failed; see $OutDir/oracle-results.txt" }
$cp = $classes + [IO.Path]::PathSeparator + $dependencies
& java -Xmx64m -cp $cp ParserRegressionTest $fixtures *> (Join-Path $OutDir 'parser-results.txt')
if ($LASTEXITCODE -ne 0) { throw "Parser regression tests failed; see $OutDir/parser-results.txt" }
$jvmOptions = @('-Djava.awt.headless=true', ('-Dreview.ghidra=' + $GhidraDir),
    ('-Dwasm.test.module=' + $module),
    ('-Dapplication.settingsdir=' + (Join-Path $OutDir 'settings')),
    ('-Dapplication.cachedir=' + (Join-Path $OutDir 'cache')),
    ('-Dapplication.tempdir=' + (Join-Path $OutDir 'tmp')))
$inputs = @(Get-ChildItem $fixtures -File -Filter '*.wasm' |
    Where-Object Name -notin @('huge_params.wasm','truncated_datacount.wasm','cross_section_type.wasm') |
    Sort-Object Name | ForEach-Object FullName)
& java @jvmOptions -cp $cp RegressionTest @inputs *> (Join-Path $OutDir 'results.txt')
if ($LASTEXITCODE -ne 0) { throw "Regression tests failed; see $OutDir/results.txt" }
& python -m unittest discover -s (Join-Path $PSScriptRoot 'regressions') -p 'test_*.py' -v *> (Join-Path $OutDir 'report-tests.txt')
if ($LASTEXITCODE -ne 0) { throw "Report exit-code tests failed; see $OutDir/report-tests.txt" }
if ($IsWindows) {
    foreach ($test in @('test-install-safety','test-emulate-exit-codes','test-build-install-cleanup','test-stderr-capture')) {
        & pwsh -NoProfile -File (Join-Path $PSScriptRoot ($test + '.ps1')) -OutDir (Join-Path $OutDir $test) *> (Join-Path $OutDir ($test + '.txt'))
        if ($LASTEXITCODE -ne 0) { throw "$test failed; see $OutDir/$test.txt" }
    }
}
Write-Output "Regression receipts: $OutDir"
