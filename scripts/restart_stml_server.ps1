#requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
Get-Process -Id 8716 -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2
Copy-Item (Join-Path $repo "scripts\run_stml_server.cmd") "C:\ProgramData\AIDefender\stml\run_server.cmd" -Force
if (Get-ScheduledTask -TaskName "AIDefender-STML-Server" -ErrorAction SilentlyContinue) {
    Restart-ScheduledTask -TaskName "AIDefender-STML-Server"
} else {
    & (Join-Path $repo "scripts\install_stml_server_task.ps1")
}
Write-Output "server restarted"
