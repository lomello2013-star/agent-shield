#requires -RunAsAdministrator
param(
    [string]$Source = (Join-Path $PSScriptRoot "aidf-service.exe"),
    [string]$InstallDir = "C:\Program Files\AIDefender"
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $Source)) { throw "missing $Source; run build_windows_service.ps1" }
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$existing = Get-Service AIDefender -ErrorAction SilentlyContinue
if ($existing) {
    Stop-Service AIDefender -Force -ErrorAction SilentlyContinue
    sc.exe delete AIDefender | Out-Null
    Start-Sleep -Seconds 2
}
$dest = Join-Path $InstallDir "aidf-service.exe"
Copy-Item $Source $dest -Force
# Service environment: Sysmon auto-detected; keep IPC enabled.
$envKey = "HKLM:\SYSTEM\CurrentControlSet\Services\AIDefender"
& sc.exe create AIDefender binPath= "`"$dest`"" start= auto DisplayName= "AIDefender Agent" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc create failed: $LASTEXITCODE" }
Set-ItemProperty -Path $envKey -Name Environment -Value @("AIDF_SYSMON=1","AIDF_COLLECT_INTERVAL_S=5") -Type MultiString
& sc.exe failure AIDefender reset= 86400 actions= restart/60000/restart/120000/none/0 | Out-Null
Start-Service AIDefender
Get-Service AIDefender | Format-Table Name,Status,StartType
Write-Output "AIDefender service installed from $dest"
