# Phase A: register the STML connector as a scheduled task (SYSTEM, at startup).
# Run from an elevated PowerShell. Adjust $Repo if needed.
$ErrorActionPreference = "Stop"
$Repo = "D:\ИИ защитник Вектор-защитник"
$Python = (Get-Command python.exe).Source
$Script = Join-Path $Repo "scripts\run_stml_connector.cmd"

$Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$Script`"" -WorkingDirectory $Repo
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
Register-ScheduledTask -TaskName "AIDefender-STML-Connector" -Action $Action -Trigger $Trigger `
    -Settings $Settings -User "SYSTEM" -RunLevel Highest -Force
Start-ScheduledTask -TaskName "AIDefender-STML-Connector"
