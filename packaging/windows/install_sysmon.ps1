#requires -RunAsAdministrator
param(
    [string]$Sysmon = "$env:ProgramFiles\Sysmon\Sysmon64.exe",
    [string]$Config = (Join-Path $PSScriptRoot "sysmonconfig.xml")
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $Sysmon)) {
    throw "Sysmon64.exe not found. Download Sysinternals Sysmon and pass -Sysmon <path>."
}
$sig = Get-AuthenticodeSignature $Sysmon
if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "Microsoft") {
    throw "Sysmon binary is not validly signed by Microsoft: $($sig.Status)"
}
& $Sysmon -accepteula -i $Config
if ($LASTEXITCODE -ne 0) { throw "Sysmon install failed: $LASTEXITCODE" }
Get-Service Sysmon64 | Format-Table Name,Status,StartType
Write-Output "Sysmon installed. Restart AIDefender service with AIDF_SYSMON=1 to add win.sysmon source."
