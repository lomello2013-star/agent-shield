#requires -RunAsAdministrator
<#
.SYNOPSIS
  Apply Microsoft Defender hardening (ASR, CFA, network protection) in audit or
  enforce mode. Does not disable Defender.
.DESCRIPTION
  Default is a dry run. Use -Apply to change settings. Use -Enforce to switch
  ASR/CFA/network protection from Audit to Block. Test in Audit first.
#>
param(
    [switch]$Apply,
    [switch]$Enforce,
    [switch]$SkipCfa
)
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run as administrator"
}

$mode = if ($Enforce) { 1 } else { 2 }   # 1=block, 2=audit
$asr = [ordered]@{
    "Block executable content from email and webmail" = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"
    "Block Office applications from creating child processes" = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"
    "Block Office applications from creating executable content" = "3B576869-A4EC-4529-8536-B80A7769E899"
    "Block Office applications from injecting code" = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"
    "Block Adobe Reader from creating child processes" = "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C"
    "Block WMI persistence" = "E6DB77E5-3DF2-4CF1-B95A-636979351E5B"
    "Block credential stealing from lsass" = "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2"
    "Block process creations from PSExec and WMI" = "D1E49AAC-8F56-4280-B9BA-993A6D77406C"
    "Block untrusted unsigned executables from USB" = "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4"
    "Block persistence through WMI event subscription" = "E6DB77E5-3DF2-4CF1-B95A-636979351E5B"
}
$ids = @($asr.Values)
$actions = @($ids | ForEach-Object { $mode })

$plan = [ordered]@{
    "ASR rules" = "$($ids.Count) rules in $(if ($Enforce) {'Block'} else {'Audit'})"
    "Controlled Folder Access" = if ($SkipCfa) { "skipped" } else { if ($Enforce) {"Block"} else {"Audit"} }
    "Network Protection" = if ($Enforce) {"Block"} else {"Audit"}
    "PUA Protection" = "Enabled"
    "Cloud protection" = "Enabled (level 2)"
}
if (-not $Apply) {
    Write-Output "DRY RUN. Planned changes:"
    $plan.GetEnumerator() | ForEach-Object { Write-Output ("  {0}: {1}" -f $_.Key, $_.Value) }
    Write-Output "Re-run with -Apply [-Enforce] to change Microsoft Defender."
    return
}

Set-MpPreference -AttackSurfaceReductionRules_Ids $ids `
    -AttackSurfaceReductionRules_Actions $actions
if (-not $SkipCfa) {
    Set-MpPreference -EnableControlledFolderAccess $mode
}
Set-MpPreference -EnableNetworkProtection $mode
Set-MpPreference -PUAProtection 1
Set-MpPreference -CloudBlockLevel 2
Set-MpPreference -MAPSReporting 2
Write-Output "Defender hardening applied in $(if ($Enforce) {'ENFORCE'} else {'AUDIT'}) mode."
Write-Output "Check: Get-MpPreference | Select AttackSurfaceReductionRules_Ids,EnableControlledFolderAccess,EnableNetworkProtection"
