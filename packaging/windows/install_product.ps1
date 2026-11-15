#requires -RunAsAdministrator
<#
.SYNOPSIS
  Install the Windows pilot product: service + local agent.
  Optional: -SysmonPath to install Sysmon; -DefenderAudit to apply ASR audit.
#>
param(
    [string]$SysmonPath = "",
    [switch]$DefenderAudit
)
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
& (Join-Path $here "install_service.ps1")
& (Join-Path $here "install_aidf_agent.ps1")
if ($SysmonPath) {
    & (Join-Path $here "install_sysmon.ps1") -Sysmon $SysmonPath
}
if ($DefenderAudit) {
    & (Join-Path $here "harden_defender.ps1") -Apply
}
Write-Output "pilot product installed; panel: http://127.0.0.1:18080/ui/"
Write-Output "Next: install Sysmon, review Defender audit, then -Enforce."
