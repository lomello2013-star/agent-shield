#requires -RunAsAdministrator
<#
.SYNOPSIS
    Install/load the AidfFilter minifilter inside the lab VM.
.DESCRIPTION
    Test-signed driver only. Run inside the Windows VM after copying
    AidfFilter.sys and aidf-test.cer to C:\AIDefender\driver.
#>
param(
    [string]$Name = "AidfFilter",
    [string]$SysPath = "C:\AIDefender\driver\AidfFilter.sys",
    [string]$CertPath = "C:\AIDefender\driver\aidf-test.cer",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

if ($Uninstall) {
    & fltmc.exe unload $Name 2>$null
    & sc.exe stop $Name 2>$null
    & sc.exe delete $Name 2>$null
    Write-Host "uninstalled $Name"
    return
}

Import-Certificate -FilePath $CertPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Import-Certificate -FilePath $CertPath -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
Copy-Item $SysPath "C:\Windows\System32\drivers\$Name.sys" -Force

$svc = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
if (Get-Service $Name -ErrorAction SilentlyContinue) {
    & sc.exe config $Name binPath= "\SystemRoot\System32\drivers\$Name.sys" start= demand | Out-Null
} else {
    & sc.exe create $Name type= filesys binPath= "\SystemRoot\System32\drivers\$Name.sys" start= demand error= normal | Out-Null
}

New-Item -Path "$svc\Instances\$Name" -Force | Out-Null
Set-ItemProperty -Path "$svc\Instances" -Name DefaultInstance -Value $Name
Set-ItemProperty -Path "$svc\Instances\$Name" -Name Altitude -Value "328000"
Set-ItemProperty -Path "$svc\Instances\$Name" -Name Flags -Value 0 -Type DWord
Set-ItemProperty -Path $svc -Name Group -Value "FSFilter Activity Monitor"
New-ItemProperty -Path $svc -Name DependOnService -PropertyType MultiString -Value @("FltMgr") -Force | Out-Null

& sc.exe start $Name
& fltmc.exe filters | Select-String $Name
New-Item -ItemType Directory -Force -Path "C:\AIDefender\protected" | Out-Null
