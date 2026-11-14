#requires -RunAsAdministrator
<#
.SYNOPSIS
    Host-side driver for the Windows red-team emulation.
.DESCRIPTION
    Copies redteam_vm.ps1 into AIDF-Win11, runs it, and pulls the JSON result
    back to artifacts\redteam_windows.json. Credentials/token come from env:
      AIDF_VM_USER, AIDF_VM_PASS, AIDF_ADMIN_TOKEN, AIDF_AUTHKEY.
#>
param(
    [string]$VMName = "AIDF-Win11",
    [string]$OutFile = (Join-Path (Split-Path $PSScriptRoot -Parent) "artifacts\redteam_windows.json")
)

$ErrorActionPreference = "Stop"
$user = $env:AIDF_VM_USER
$pass = $env:AIDF_VM_PASS
$token = $env:AIDF_ADMIN_TOKEN
$auth = $env:AIDF_AUTHKEY
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
$session = New-PSSession -VMName $VMName -Credential $cred
Invoke-Command -Session $session { New-Item -ItemType Directory -Force -Path "C:\AIDefender" | Out-Null }
Copy-Item -ToSession $session -Path (Join-Path $PSScriptRoot "redteam_vm.ps1") -Destination "C:\AIDefender\redteam_vm.ps1" -Force
Remove-PSSession $session

Invoke-Command -VMName $VMName -Credential $cred -ArgumentList $token, $auth, $head -ScriptBlock {
    param($token, $auth, $head)
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\AIDefender\redteam_vm.ps1" -Token $token -AuthKey $auth -Head $head
}

$session = New-PSSession -VMName $VMName -Credential $cred
New-Item -ItemType Directory -Force -Path (Split-Path $OutFile -Parent) | Out-Null
Copy-Item -FromSession $session -Path "C:\AIDefender\redteam_result.json" -Destination $OutFile -Force
Remove-PSSession $session
Get-Content $OutFile -Raw
