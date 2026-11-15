#requires -RunAsAdministrator
<#
.SYNOPSIS
  Build/deploy a WDAC ENFORCE policy that hash-allows the AIDefender onedir tree.
.DESCRIPTION
  Filepath rules are insufficient for PyInstaller DLLs. This scans every file in
  the service folder into SHA256 hash rules, merges them with the Microsoft
  DefaultWindows_Enforced template, removes Audit Mode, and optionally deploys.
#>
param(
    [string]$AppDir = "C:\Program Files\AIDefender\service",
    [string]$OutDir = "C:\ProgramData\AIDefender\wdac-enforce",
    [switch]$Deploy
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $AppDir)) { throw "missing $AppDir" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$base = Join-Path $OutDir "base.xml"
Copy-Item (Join-Path $env:WINDIR "schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml") $base -Force
$allow = Join-Path $OutDir "allow.xml"
New-CIPolicy -FilePath $allow -ScanPath $AppDir -Level Hash -Fallback FileName -UserPEs
$merged = Join-Path $OutDir "merged.xml"
Merge-CIPolicy -PolicyPaths $base, $allow -OutputFilePath $merged
Set-CIPolicyIdInfo -FilePath $merged -PolicyName "AIDefender Enforce HashAllow" -ResetPolicyID
Set-RuleOption -FilePath $merged -Option 3 -Delete   # remove Audit Mode
$cip = Join-Path $OutDir "merged.cip"
ConvertFrom-CIPolicy $merged $cip
Write-Output "enforce policy: $cip"
if (-not $Deploy) { Write-Output "Not deployed. Review, then -Deploy."; return }
& CiTool.exe --update-policy $cip
if ($LASTEXITCODE -ne 0) { throw "CiTool deploy failed: $LASTEXITCODE" }
& CiTool.exe --refresh
Write-Output "deployed; reboot required. To roll back: CiTool --remove-policy <PolicyID>."
