#requires -RunAsAdministrator
<#
.SYNOPSIS
    Build the WHQL-ready package skeleton: INF + SYS + catalog, test-signed.
.DESCRIPTION
    Runs Inf2Cat (WDK) and signs the catalog with the local test certificate.
    Production still requires an EV certificate + HLK/WHQL submission.
.NOTES
    Run sign.ps1 first (it creates out\aidf-test.pfx).
#>
param(
    [string]$Pkg = "C:\ProgramData\AIDefender\driver-package",
    [string]$Pfx = (Join-Path $PSScriptRoot "out\aidf-test.pfx"),
    [string]$Password = "AidfTest!2026"
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $Pfx)) { throw "test PFX missing: $Pfx (run sign.ps1)" }
$sys = Join-Path $PSScriptRoot "out\AidfFilter.sys"
if (-not (Test-Path $sys)) { throw "driver missing: $sys (run build.ps1)" }

New-Item -ItemType Directory -Force -Path $Pkg | Out-Null
Copy-Item $sys, (Join-Path $PSScriptRoot "AidfFilter.inf"),
    (Join-Path $PSScriptRoot "out\aidf-test.cer") -Destination $Pkg -Force

$inf2cat = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter Inf2Cat.exe |
    Where-Object { $_.FullName -match '\\x86\\' } | Select-Object -First 1 -ExpandProperty FullName
if (-not $inf2cat) { throw "Inf2Cat.exe not found (install the WDK)" }
& $inf2cat "/driver:$Pkg" "/os:10_X64,10_GE_X64"
if ($LASTEXITCODE -ne 0) { throw "Inf2Cat failed: $LASTEXITCODE" }

$cat = Join-Path $Pkg "aidffilter.cat"
$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter signtool.exe |
    Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1 -ExpandProperty FullName
& $signtool sign /fd SHA256 /f $Pfx /p $Password $cat
if ($LASTEXITCODE -ne 0) { throw "signtool failed: $LASTEXITCODE" }

Copy-Item $cat (Join-Path $PSScriptRoot "out\AidfFilter.cat") -Force
Get-ChildItem $Pkg | Select-Object Name, Length | Format-Table -AutoSize
Write-Host "Package is TEST-SIGNED. Production requires EV + HLK (see docs/whql.md)."
