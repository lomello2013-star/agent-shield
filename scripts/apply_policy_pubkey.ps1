#requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
$dest = "C:\ProgramData\AIDefender\stml\run_server.cmd"
Copy-Item (Join-Path $repo "scripts\run_stml_server.cmd") $dest -Force
Restart-ScheduledTask -TaskName "AIDefender-STML-Server"
Write-Output "server task restarted with $dest"
