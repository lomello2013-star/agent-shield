$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$Root = Split-Path $Root -Parent
$Out = Join-Path $Root "dist\windows"
$Bundle = Join-Path $Root "dist\aidf-windows-pilot"
if (Test-Path $Bundle) { Remove-Item $Bundle -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Bundle | Out-Null

$files = @(
    "aidf-agent.exe", "agent.toml",
    "install_product.ps1", "install_service.ps1", "uninstall_service.ps1",
    "install_aidf_agent.ps1", "uninstall_aidf_agent.ps1",
    "install_sysmon.ps1", "sysmonconfig.xml",
    "harden_defender.ps1", "harden_service.ps1", "build_wdac_audit.ps1"
)
foreach ($name in $files) {
    $src = Join-Path $Out $name
    if (-not (Test-Path $src)) { $src = Join-Path $PSScriptRoot $name }
    if (Test-Path $src) { Copy-Item $src (Join-Path $Bundle $name) -Force }
    else { Write-Warning "missing $name" }
}
$svc = Join-Path $Out "aidf-service"
if (Test-Path $svc) { Copy-Item $svc $Bundle -Recurse -Force }
$zip = Join-Path $Root "dist\aidf-windows-pilot.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $Bundle "*") -DestinationPath $zip
Write-Output "built $zip"
Get-ChildItem $Bundle | Select-Object Name,Length
