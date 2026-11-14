#requires -RunAsAdministrator
<#
.SYNOPSIS
    Install (or remove) Sysmon, the optional Windows process-event source.
.DESCRIPTION
    Sysmon gives the agent process events with a PID, which Windows suspend needs.
    It is optional: without it detection still works, but suspend is action_skipped.
.PARAMETER ConfigPath
    Optional Sysmon XML config. Passed to -i on install or -c on update.
.PARAMETER Uninstall
    Remove the Sysmon service.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\setup_sysmon.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\setup_sysmon.ps1 -ConfigPath C:\sysmon.xml
#>
param(
    [string]$ConfigPath = "",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$dir = Join-Path $env:ProgramData "AIDefender\sysmon"
$exe = Join-Path $dir "Sysmon64.exe"

if ($Uninstall) {
    if (Test-Path $exe) { & $exe -u }
    else { Write-Warning "Sysmon64.exe not found in $dir" }
    return
}

New-Item -ItemType Directory -Force -Path $dir | Out-Null
if (-not (Test-Path $exe)) {
    $zip = Join-Path $dir "Sysmon.zip"
    Write-Host "Downloading Sysmon from Microsoft Sysinternals..."
    Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $dir -Force
}

$service = Get-Service Sysmon64 -ErrorAction SilentlyContinue
if ($service) {
    if ($ConfigPath) { & $exe -c $ConfigPath }
    else { Write-Host "Sysmon already installed; no config update requested." }
} else {
    if ($ConfigPath) { & $exe -accepteula -i $ConfigPath }
    else { & $exe -accepteula -i }
}

Get-Service Sysmon64 | Format-Table Name, Status -AutoSize
Write-Host "Enable the source: set AIDF_SYSMON=1 in the AIDefender service environment and restart it."
Write-Host "See docs/sysmon.md."
