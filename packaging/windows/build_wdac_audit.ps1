#requires -RunAsAdministrator
<#
.SYNOPSIS
  Generate an App Control for Business (WDAC) policy in AUDIT mode.
.DESCRIPTION
  Starts from the Microsoft DefaultWindows_Enforced template, enables Audit Mode,
  and writes a .cip. It does not deploy unless -Deploy is supplied. Test on a VM.
#>
param(
    [string]$OutDir = "C:\ProgramData\AIDefender\wdac",
    [switch]$Deploy
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$template = Join-Path $env:WINDIR "schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml"
if (-not (Test-Path $template)) { throw "WDAC template not found: $template" }
$xml = Join-Path $OutDir "AIDefender-Audit.xml"
Copy-Item $template $xml -Force
Set-RuleOption -FilePath $xml -Option 3          # Enabled:Audit Mode
Set-CIPolicyIdInfo -FilePath $xml -PolicyName "AIDefender Audit" -ResetPolicyID
$policyId = ([xml](Get-Content $xml)).SiPolicy.PolicyId
$cip = Join-Path $OutDir ("$policyId.cip")
ConvertFrom-CIPolicy $xml $cip
Write-Output "audit policy: $cip"
if (-not $Deploy) {
    Write-Output "Not deployed. Review in a VM, then rerun with -Deploy."
    return
}
if (-not (Get-Command CiTool.exe -ErrorAction SilentlyContinue)) {
    throw "CiTool.exe not found; deploy via MDM/GPO or copy to EFI manually."
}
& CiTool.exe --update-policy $cip -json
if ($LASTEXITCODE -ne 0) { throw "CiTool deploy failed: $LASTEXITCODE" }
Write-Output "deployed audit policy; reboot and review CodeIntegrity/Operational, then build an enforced policy."
