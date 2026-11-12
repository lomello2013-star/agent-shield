# Build and test the Rust port without Visual Studio Build Tools.
#
# Rust 1.100 MSVC target ships `rust-lld`; it only needs the Windows SDK import
# libraries. This script discovers the newest installed SDK, points LIB at its
# x64 libs, and runs Cargo. The Python implementation remains the reference.

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $CargoArgs
)

$ErrorActionPreference = "Stop"

if (-not $CargoArgs) {
    $CargoArgs = @("test")
}

$cargo = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
if (-not (Test-Path $cargo)) {
    $cargo = "cargo"
}

$programFilesX86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
$kitsLib = Join-Path $programFilesX86 "Windows Kits\10\Lib"
if (-not (Test-Path $kitsLib)) {
    throw "Windows SDK not found: $kitsLib"
}

$sdk = Get-ChildItem $kitsLib -Directory |
    Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
    Sort-Object { [version] $_.Name } -Descending |
    Select-Object -First 1
if (-not $sdk) {
    throw "No versioned Windows SDK under $kitsLib"
}

$env:LIB = "$($sdk.FullName)\um\x64;$($sdk.FullName)\ucrt\x64"
$env:RUSTFLAGS = "-C linker=rust-lld"

Write-Host "SDK:    $($sdk.Name)"
Write-Host "cargo:  $cargo"
Write-Host "cargo $($CargoArgs -join ' ')"

Push-Location $PSScriptRoot
$code = 0
try {
    & $cargo @CargoArgs --manifest-path (Join-Path $PSScriptRoot "Cargo.toml")
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}
$global:LASTEXITCODE = $code
return $code
