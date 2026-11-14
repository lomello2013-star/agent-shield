#requires -Version 5.1
<#
.SYNOPSIS
    Start the local STML server + demo connector + agent panel and open both UIs.
.DESCRIPTION
    Non-admin convenience launcher for a personal pilot. It starts only the
    processes whose ports are free. Logs go to C:\ProgramData\AIDefender\stml.
#>
$ErrorActionPreference = "Stop"
$Repo = Split-Path $PSScriptRoot -Parent
$Data = "C:\ProgramData\AIDefender"
$Stml = Join-Path $Data "stml"
$Demo = Join-Path $Data "agent-demo"
$Python = "C:\Users\lomel\AppData\Local\Programs\Python\Python312\python.exe"
if (-not (Test-Path $Python)) { $Python = "python" }
New-Item -ItemType Directory -Force -Path $Stml, $Demo | Out-Null

function Test-Port([int]$Port) {
    return [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}

function Start-Hidden([string]$File, [string[]]$Arguments) {
    Start-Process -FilePath $File -ArgumentList $Arguments -WindowStyle Hidden `
        -WorkingDirectory $Repo | Out-Null
}

if (-not (Test-Port 8080)) {
    $tokens = Join-Path $env:TEMP "stml-tokens.json"
    Copy-Item (Join-Path $Stml "tokens.json") $tokens -Force
    icacls $tokens /grant "$env:USERNAME:F" | Out-Null
    $env:STML_POLICY_PUBKEY_FILE = Join-Path $Stml "STML-policy.pub"
    Start-Hidden $Python @("-m", "stml.server", "run", "--host", "127.0.0.1",
        "--port", "8080", "--db", (Join-Path $Stml "server.sqlite3"),
        "--trust-dir", (Join-Path $Stml "trust"), "--tokens-file", $tokens)
    Start-Sleep -Seconds 2
}

if (-not (Test-Port 18080)) {
    Start-Hidden $Python @((Join-Path $Repo "scripts\aidf_agent.py"),
        "--config", (Join-Path $Demo "agent.toml"))
    Start-Sleep -Seconds 2
}

$connectorUp = $false
$lock = Join-Path $Demo "rpc.lock"
if (Test-Path $lock) {
    try {
        $info = Get-Content $lock -Raw | ConvertFrom-Json
        $connectorUp = [bool](Get-Process -Id ([int]$info.pid) -ErrorAction SilentlyContinue)
    } catch { $connectorUp = $false }
}
if (-not $connectorUp) {
    $tokens = Get-Content (Join-Path $Stml "tokens.json") -Raw | ConvertFrom-Json
    $env:STML_ENROL_TOKEN = $tokens.enrol_token
    Start-Hidden $Python @("-m", "stml.connector", "run", "--tenant", "default",
        "--data-root", $Demo, "--spool", (Join-Path $Demo "spool.sqlite3"),
        "--state", (Join-Path $Demo "state.json"), "--server-url", "http://127.0.0.1:8080",
        "--hostname", $env:COMPUTERNAME, "--os", "windows", "--arch", "x64",
        "--agent-version", "1.0.0",
        "--enrol-token", $env:STML_ENROL_TOKEN, "--console",
        "--rpc-lock", (Join-Path $Demo "rpc.lock"))
    Start-Sleep -Seconds 2
}

$urls = @("http://127.0.0.1:8080/ui/", "http://127.0.0.1:18080/ui/")
try {
    $tok = Get-Content (Join-Path $Stml "tokens.json") -Raw | ConvertFrom-Json
    $hash = "viewer=" + [uri]::EscapeDataString($tok.viewer_token) +
            "&admin=" + [uri]::EscapeDataString($tok.admin_token) +
            "&approver=" + [uri]::EscapeDataString($tok.approver_token)
    $urls[0] = "http://127.0.0.1:8080/ui/#$hash"
} catch { }
foreach ($url in $urls) {
    Start-Process $url | Out-Null
}
Write-Output "STML server:  http://127.0.0.1:8080/ui/"
Write-Output "Agent panel:  http://127.0.0.1:18080/ui/"
Write-Output "Tailscale:    http://desktop-jhqb492.tail7dcc3b.ts.net/ui/"
