$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$Root = Split-Path $Root -Parent
$Out = Join-Path $Root "dist\windows"
$Wix = "C:\Program Files\WiX Toolset v7.0\bin\wix.exe"
if (-not (Test-Path $Wix)) {
    throw "WiX not found at $Wix; install WiXToolset.WiXCLI"
}
if (-not (Test-Path (Join-Path $Out "aidf-agent.exe"))) {
    throw "build the EXE first: packaging\windows\build_windows_exe.ps1"
}
& $Wix build -d SourceDir="$Out" -o (Join-Path $Out "aidf-agent.msi") `
    (Join-Path $PSScriptRoot "aidf-agent.wxs")
if ($LASTEXITCODE -ne 0) { throw "wix build failed: $LASTEXITCODE" }
Write-Output "built $Out\aidf-agent.msi"
