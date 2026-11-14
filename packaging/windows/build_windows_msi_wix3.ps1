$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$Root = Split-Path $Root -Parent
$Out = Join-Path $Root "dist\windows"
$Wix = Join-Path $Root ".tools\wix3"
if (-not (Test-Path (Join-Path $Wix "candle.exe"))) {
    throw "WiX 3 not found at $Wix; extract wix314-binaries.zip there"
}
if (-not (Test-Path (Join-Path $Out "aidf-agent.exe"))) {
    throw "build the EXE first: packaging\windows\build_windows_exe.ps1"
}
$Obj = Join-Path $Root "build\wix3"
$Tmp = Join-Path $Root "build\tmp"
New-Item -ItemType Directory -Force -Path $Obj, $Tmp | Out-Null
$env:TEMP = $Tmp
$env:TMP = $Tmp
& (Join-Path $Wix "candle.exe") -nologo -dSourceDir="$Out" `
    -out (Join-Path $Obj "agent.wixobj") (Join-Path $PSScriptRoot "aidf-agent-wix3.wxs")
if ($LASTEXITCODE -ne 0) { throw "candle failed: $LASTEXITCODE" }
& (Join-Path $Wix "light.exe") -nologo -sval -out (Join-Path $Out "aidf-agent.msi") `
    (Join-Path $Obj "agent.wixobj")
if ($LASTEXITCODE -ne 0) { throw "light failed: $LASTEXITCODE" }
Write-Output "built $Out\aidf-agent.msi"
