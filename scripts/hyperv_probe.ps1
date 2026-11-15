#requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$log = "C:\ProgramData\AIDefender\hyperv-probe.log"
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
Start-Transcript -Path $log -Force | Out-Null
try {
    Write-Output "whoami=$(whoami)"
    Get-VM | Select-Object Name,State | Format-Table
    Get-VMSwitch | Select-Object Name,SwitchType | Format-Table
    if (-not (Get-VMSwitch -Name "AIDF-Lab" -ErrorAction SilentlyContinue)) {
        New-VMSwitch -Name "AIDF-Lab" -SwitchType Internal
        Write-Output "created switch AIDF-Lab"
    }
    Get-VMSwitch -Name "AIDF-Lab" | Format-Table Name,SwitchType
} finally {
    Stop-Transcript | Out-Null
}
