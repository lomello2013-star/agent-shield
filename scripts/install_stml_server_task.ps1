# Phase A: register the STML server as a scheduled task (SYSTEM, at startup).
# The script is copied to an ASCII path; the Cyrillic repo path is used via its
# 8.3 short form as WorkingDirectory (Task Scheduler/System has encoding issues).
$ErrorActionPreference = "Stop"
$ShortRepo = "D:\-528D~1"
$DataDir = "C:\ProgramData\AIDefender\stml"
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
Copy-Item (Join-Path $ShortRepo "scripts\run_stml_server.cmd") (Join-Path $DataDir "run_server.cmd") -Force

$Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$DataDir\run_server.cmd`"" -WorkingDirectory $ShortRepo
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
Register-ScheduledTask -TaskName "AIDefender-STML-Server" -Action $Action -Trigger $Trigger `
    -Settings $Settings -User "SYSTEM" -RunLevel Highest -Force
Start-ScheduledTask -TaskName "AIDefender-STML-Server"
