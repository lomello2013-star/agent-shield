#requires -RunAsAdministrator
param([string]$TaskName = "AIDefender-Watchdog", [int]$Minutes = 5)
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$script = Join-Path $here "watchdog_aidf.ps1"
if (-not (Test-Path $script)) { throw "missing $script" }
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $Minutes)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Force | Out-Null
Write-Output "installed $TaskName every $Minutes min"
