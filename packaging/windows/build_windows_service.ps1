$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$Root = Split-Path $Root -Parent
$Out = Join-Path $Root "dist\windows"
$Work = Join-Path $Root "build\pyinstaller-service"
New-Item -ItemType Directory -Force -Path $Out, $Work | Out-Null

python -m PyInstaller --noconfirm --clean --onedir --name aidf-service `
    --distpath $Out --workpath $Work --specpath $Work `
    --add-data "$Root\rules;rules" `
    --add-data "$Root\schemas;schemas" `
    "$Root\scripts\aidf_service.py"

Copy-Item (Join-Path $PSScriptRoot "install_service.ps1") $Out -Force
Copy-Item (Join-Path $PSScriptRoot "uninstall_service.ps1") $Out -Force
Copy-Item (Join-Path $PSScriptRoot "install_product.ps1") $Out -Force
Write-Output "built $Out\aidf-service\aidf-service.exe"
