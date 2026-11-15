#requires -RunAsAdministrator
<#
.SYNOPSIS
  Service recovery and folder ACL hardening for AIDefender.
  Dry run by default; -Apply changes the service and ACLs.
#>
param([switch]$Apply)
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run as administrator"
}
$svc = "AIDefender"
$data = "C:\ProgramData\AIDefender"
$plan = @(
    "sc failure $svc reset= 86400 actions= restart/60000/restart/120000/none/0",
    "icacls $data /inheritance:r /grant:r SYSTEM:(OI)(CI)F Administrators:(OI)(CI)F Users:(OI)(CI)RX",
    "Keep tokens.json/private keys restricted to SYSTEM/Administrators"
)
if (-not $Apply) {
    Write-Output "DRY RUN. Planned commands:"
    $plan | ForEach-Object { Write-Output "  $_" }
    return
}
& sc.exe failure $svc reset= 86400 actions= restart/60000/restart/120000/none/0
if ($LASTEXITCODE -ne 0) { throw "sc failure failed: $LASTEXITCODE" }
& icacls $data /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX"
if ($LASTEXITCODE -ne 0) { throw "icacls failed: $LASTEXITCODE" }
Write-Output "service recovery and base ACL applied; verify connector can still read its state."
