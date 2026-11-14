#requires -RunAsAdministrator
<#
.SYNOPSIS
    Verify the minifilter blocks writes under C:\AIDefender\protected and
    allows writes elsewhere.
#>
$ErrorActionPreference = "Stop"
$blocked = $false
$allowed = $false
try {
    Set-Content -Path "C:\AIDefender\protected\rt.txt" -Value "x" -ErrorAction Stop
} catch {
    $blocked = $true
}
try {
    Set-Content -Path "C:\AIDefender\allowed.txt" -Value "ok" -ErrorAction Stop
    $allowed = $true
} catch {
    $allowed = $false
}
Write-Host "blocked=$blocked allowed=$allowed"
if (-not $blocked -or -not $allowed) { exit 1 }
