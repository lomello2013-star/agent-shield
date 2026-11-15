#requires -RunAsAdministrator
param([string]$TaskName = "AIDefender-Maintenance", [int]$Hour = 3)
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$script = Join-Path $here "maintain_logs.ps1"
if (-not (Test-Path $script)) { throw "missing $script" }
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`""
$trigger = New-ScheduledTaskTrigger -Daily -At ([datetime]::Today.AddHours($Hour))
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Force | Out-Null
Write-Output "installed $TaskName daily at $Hour:00"
