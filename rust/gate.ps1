# Rust quality gate: fmt, clippy, tests. Run from anywhere:
#   powershell -ExecutionPolicy Bypass -File .\rust\gate.ps1
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$cargo = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
$programFilesX86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
$kitsLib = Join-Path $programFilesX86 "Windows Kits\10\Lib"
$sdk = Get-ChildItem $kitsLib -Directory |
    Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
    Sort-Object { [version] $_.Name } -Descending |
    Select-Object -First 1
$env:LIB = "$($sdk.FullName)\um\x64;$($sdk.FullName)\ucrt\x64"
$env:RUSTFLAGS = "-C linker=rust-lld"
$manifest = Join-Path $root "Cargo.toml"
$results = @()
$ok = $true

Push-Location $root
try {
    Write-Host "== rust gate: fmt =="
    & $cargo fmt -- --check
    $code = $LASTEXITCODE
    $results += [ordered]@{ step = "fmt"; exit_code = $code; ok = ($code -eq 0) }
    if ($code -ne 0) { $ok = $false }

    if ($ok) {
        Write-Host "== rust gate: clippy =="
        & $cargo clippy --manifest-path $manifest --all-targets -- -D warnings
        $code = $LASTEXITCODE
        $results += [ordered]@{ step = "clippy"; exit_code = $code; ok = ($code -eq 0) }
        if ($code -ne 0) { $ok = $false }
    }
    if ($ok) {
        Write-Host "== rust gate: test =="
        & $cargo test --manifest-path $manifest
        $code = $LASTEXITCODE
        $results += [ordered]@{ step = "test"; exit_code = $code; ok = ($code -eq 0) }
        if ($code -ne 0) { $ok = $false }
    }
} finally {
    Pop-Location
}

$report = [ordered]@{
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    ok = $ok
    steps = $results
}
$artifact = Join-Path (Split-Path $root -Parent) "artifacts\rust_gate.json"
$report | ConvertTo-Json -Depth 5 | Set-Content -Path $artifact -Encoding utf8
if (-not $ok) { exit 1 }
