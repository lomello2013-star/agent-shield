#requires -RunAsAdministrator
<#
.SYNOPSIS
    Test-sign AidfFilter.sys with a local self-signed code-signing certificate.
.DESCRIPTION
    Lab only. Production requires an EV certificate and WHQL submission.
#>
param(
    [string]$SysPath = (Join-Path $PSScriptRoot "out\AidfFilter.sys"),
    [string]$OutDir = (Join-Path $PSScriptRoot "out"),
    [string]$Password = "AidfTest!2026"
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $SysPath)) { throw "driver not built: $SysPath" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$pfx = Join-Path $OutDir "aidf-test.pfx"
$cer = Join-Path $OutDir "aidf-test.cer"
$secure = ConvertTo-SecureString $Password -AsPlainText -Force
if (-not (Test-Path $pfx)) {
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject "CN=AIDefender Test Driver" `
        -CertStoreLocation Cert:\LocalMachine\My `
        -KeyExportPolicy Exportable `
        -NotAfter (Get-Date).AddYears(2)
    Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $secure | Out-Null
    Export-Certificate -Cert $cert -FilePath $cer | Out-Null
}

$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter signtool.exe |
    Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1 -ExpandProperty FullName
if (-not $signtool) { throw "signtool.exe not found in Windows Kits" }

& $signtool sign /fd SHA256 /f $pfx /p $Password $SysPath
if ($LASTEXITCODE -ne 0) { throw "signtool sign failed: $LASTEXITCODE" }
& $signtool verify /pa /v $SysPath

Get-Item $SysPath, $cer | Select-Object FullName, Length, LastWriteTime
