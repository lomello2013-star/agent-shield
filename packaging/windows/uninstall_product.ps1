#requires -RunAsAdministrator
<#
.SYNOPSIS
  Unified AIDefender Windows uninstall / rollback.
.DESCRIPTION
  Removes the service, AppLocker policy, AIDefender WDAC policy, firewall rules,
  and returns Defender ASR/CFA/Network Protection to Disabled or Audit.
  Keeps ProgramData unless -PurgeData is supplied.
#>
param(
    [ValidateSet("Disable", "Audit")][string]$DefenderMode = "Audit",
    [switch]$PurgeData
)
$ErrorActionPreference = "Stop"

# 1. Service
$svc = Get-Service AIDefender -ErrorAction SilentlyContinue
if ($svc) {
    Stop-Service AIDefender -Force -ErrorAction SilentlyContinue
    sc.exe delete AIDefender | Out-Null
}
if (Test-Path "C:\Program Files\AIDefender") {
    Remove-Item "C:\Program Files\AIDefender" -Recurse -Force -ErrorAction SilentlyContinue
}

# 2. AppLocker: empty policy removes all AIDefender rules.
$empty = "C:\ProgramData\AIDefender\applocker-empty.xml"
New-Item -ItemType Directory -Force (Split-Path $empty) | Out-Null
Set-Content $empty '<AppLockerPolicy Version="1" />' -Encoding UTF8
Set-AppLockerPolicy -XmlPolicy $empty -ErrorAction SilentlyContinue

# 3. WDAC: remove AIDefender policies only.
try {
    $policies = (& CiTool.exe --list-policies -json 2>$null | ConvertFrom-Json).Policies
    foreach ($p in @($policies | Where-Object { $_.FriendlyName -like "AIDefender*" })) {
        & CiTool.exe --remove-policy $p.PolicyID | Out-Null
    }
    & CiTool.exe --refresh | Out-Null
} catch { Write-Warning "WDAC cleanup: $($_.Exception.Message)" }

# 4. Firewall rules created by response actions.
Get-NetFirewallRule -DisplayName "AIDF-block-*" -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

# 5. Defender: deterministic rollback to Disabled or Audit.
$action = if ($DefenderMode -eq "Audit") { "AuditMode" } else { "Disabled" }
$prefs = Get-MpPreference
$ids = @($prefs.AttackSurfaceReductionRules_Ids)
if ($ids.Count -gt 0 -and $ids[0]) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $ids `
        -AttackSurfaceReductionRules_Actions (@($action) * $ids.Count)
}
Set-MpPreference -EnableControlledFolderAccess $action
Set-MpPreference -EnableNetworkProtection $action

if ($PurgeData -and (Test-Path "C:\ProgramData\AIDefender")) {
    Remove-Item "C:\ProgramData\AIDefender" -Recurse -Force
}
Write-Output "AIDefender Windows rollback complete (Defender=$DefenderMode, purge=$PurgeData)."

