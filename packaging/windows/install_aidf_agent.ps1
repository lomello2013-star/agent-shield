#requires -RunAsAdministrator
param(
    [string]$Source = $PSScriptRoot,
    [string]$InstallDir = "C:\Program Files\AIDefender",
    [string]$DataDir = "C:\ProgramData\AIDefender"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir | Out-Null
Copy-Item (Join-Path $Source "aidf-agent.exe") (Join-Path $InstallDir "aidf-agent.exe") -Force
Copy-Item (Join-Path $PSScriptRoot "agent.toml") (Join-Path $DataDir "agent.toml") -Force
$exe = Join-Path $InstallDir "aidf-agent.exe"
$conf = Join-Path $DataDir "agent.toml"
$action = New-ScheduledTaskAction -Execute $exe -Argument "--config `"$conf`"" -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "AIDefender-Agent" -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName "AIDefender-Agent"
Write-Output "installed $exe; task AIDefender-Agent started"
