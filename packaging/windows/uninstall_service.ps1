#requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
Stop-Service AIDefender -Force -ErrorAction SilentlyContinue
sc.exe delete AIDefender | Out-Null
Remove-Item "C:\Program Files\AIDefender\aidf-service.exe" -Force -ErrorAction SilentlyContinue
Write-Output "AIDefender service removed; data under C:\ProgramData\AIDefender kept"
