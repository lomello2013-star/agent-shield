#requires -RunAsAdministrator
<#
.SYNOPSIS
    Host-side runner for the 20-scenario Windows red-team slice.
.DESCRIPTION
    Copies redteam20_vm.ps1 into AIDF-Win11, runs it, pulls the JSON result.
    Env: AIDF_VM_USER, AIDF_VM_PASS, AIDF_ADMIN_TOKEN, AIDF_AUTHKEY.
#>
param(
    [string]$VMName = "AIDF-Win11",
    [string]$OutFile = (Join-Path (Split-Path $PSScriptRoot -Parent) "artifacts\redteam20_windows.json")
)

$ErrorActionPreference = "Stop"
$user = $env:AIDF_VM_USER; $pass = $env:AIDF_VM_PASS
$token = $env:AIDF_ADMIN_TOKEN; $auth = $env:AIDF_AUTHKEY
if (-not $user -or -not $pass) { throw "set AIDF_VM_USER / AIDF_VM_PASS" }
if (-not $token -or -not $auth) { throw "set AIDF_ADMIN_TOKEN / AIDF_AUTHKEY" }
$cred = [pscredential]::new($user, (ConvertTo-SecureString $pass -AsPlainText -Force))
if ((Get-VM $VMName).State -ne "Running") { Start-VM $VMName }
for ($i = 0; $i -lt 60; $i++) {
    $hb = (Get-VMIntegrationService -VMName $VMName | Where-Object { $_.Name -like "*Пульс*" -or $_.Name -like "*Heartbeat*" }).PrimaryStatusDescription
    if ($hb -eq "ОК" -or $hb -eq "OK") { break }
    Start-Sleep -Seconds 2
}
$head = (& git -C (Split-Path $PSScriptRoot -Parent) rev-parse --short HEAD).Trim()
$s = New-PSSession -VMName $VMName -Credential $cred
Copy-Item -ToSession $s -Path (Join-Path $PSScriptRoot "redteam20_vm.ps1") -Destination "C:\AIDefender\redteam20_vm.ps1" -Force
Remove-PSSession $s
Invoke-Command -VMName $VMName -Credential $cred -ArgumentList $token, $auth, $head -ScriptBlock {
    param($token, $auth, $head)
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\AIDefender\redteam20_vm.ps1" -Token $token -AuthKey $auth -Head $head
}
$s = New-PSSession -VMName $VMName -Credential $cred
New-Item -ItemType Directory -Force -Path (Split-Path $OutFile -Parent) | Out-Null
Copy-Item -FromSession $s -Path "C:\AIDefender\redteam20_result.json" -Destination $OutFile -Force
Remove-PSSession $s
Get-Content $OutFile -Raw
