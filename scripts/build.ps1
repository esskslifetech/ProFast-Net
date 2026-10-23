# Builds the native core, runs its tests, and reports what the host supports.
#
#   pwsh -File scripts/build.ps1
#   powershell -File scripts/build.ps1        # Windows PowerShell 5.1
#   pwsh -File scripts/build.ps1 -Python      # also install the CLI editable
#   pwsh -File scripts/build.ps1 -Clean

param(
    [switch]$Python,
    [switch]$Clean,
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$build = Join-Path $root "build/native"

if ($Clean -and (Test-Path $build)) {
    Write-Host "removing $build"
    Remove-Item -Recurse -Force $build
}

$generator = @()
if (Get-Command ninja -ErrorAction SilentlyContinue) {
    $generator = @("-G", "Ninja")
}

Write-Host "== configure ($Configuration)"
& cmake -S (Join-Path $root "native") -B $build @generator "-DCMAKE_BUILD_TYPE=$Configuration"
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed" }

Write-Host "== build"
& cmake --build $build --config $Configuration --parallel
if ($LASTEXITCODE -ne 0) { throw "cmake build failed" }

$exe = if ($IsWindows -or $env:OS -eq "Windows_NT") { "pfbench.exe" } else { "pfbench" }
$bench = Join-Path $build "bin/$exe"
if (-not (Test-Path $bench)) {
    # Multi-config generators place runtimes in a per-configuration directory.
    $found = Get-ChildItem -Path $build -Recurse -Filter $exe -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($found) { $bench = $found.FullName }
}
if (-not (Test-Path $bench)) { throw "$exe was not produced under $build" }

Write-Host "== known-answer vectors"
& $bench selftest
if ($LASTEXITCODE -ne 0) { throw "pfbench selftest failed" }

Write-Host "== native tests"
& ctest --test-dir $build -C $Configuration --output-on-failure
if ($LASTEXITCODE -ne 0) { throw "native tests failed" }

Write-Host "== environment"
& $bench bench

if ($Python) {
    Write-Host "== python control plane"
    & python -m pip install --upgrade pip
    & python -m pip install -e "$root/python[dev]"
    & python -m pytest -q (Join-Path $root "python")
    if ($LASTEXITCODE -ne 0) { throw "python tests failed" }
}

Write-Host ""
Write-Host "done. try:"
Write-Host "  $bench selftest"
Write-Host "  python -m profast.cli --embedded status"
