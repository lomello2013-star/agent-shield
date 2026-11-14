#requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
Stop-ScheduledTask -TaskName "AIDefender-Agent" -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "AIDefender-Agent" -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item "C:\Program Files\AIDefender\aidf-agent.exe" -Force -ErrorAction SilentlyContinue
Write-Output "removed AIDefender-Agent (config/data kept under C:\ProgramData\AIDefender)"
