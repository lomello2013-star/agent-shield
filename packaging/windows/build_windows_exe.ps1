$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$Root = Split-Path $Root -Parent          # packaging/windows -> repo
$Out = Join-Path $Root "dist\windows"
$Work = Join-Path $Root "build\pyinstaller"
New-Item -ItemType Directory -Force -Path $Out, $Work | Out-Null

python -m PyInstaller --noconfirm --clean --onefile --name aidf-agent `
    --distpath $Out --workpath $Work --specpath $Work `
    --add-data "$Root\agent\gui;agent/gui" `
    --add-data "$Root\rules;rules" `
    --add-data "$Root\schemas;schemas" `
    "$Root\scripts\aidf_agent.py"

Copy-Item (Join-Path $PSScriptRoot "agent.toml") $Out -Force
Copy-Item (Join-Path $PSScriptRoot "install_aidf_agent.ps1") $Out -Force
Copy-Item (Join-Path $PSScriptRoot "uninstall_aidf_agent.ps1") $Out -Force
$Zip = Join-Path $Root "dist\aidf-agent-windows.zip"
if (Test-Path $Zip) { Remove-Item $Zip -Force }
Compress-Archive -Path (Join-Path $Out "*") -DestinationPath $Zip
Write-Output "built $Out\aidf-agent.exe and $Zip"
