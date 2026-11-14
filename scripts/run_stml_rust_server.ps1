param(
    [string]$Config = "C:\ProgramData\AIDefender\stml\rust.env.json"
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $Config)) { throw "config not found: $Config" }
$cfg = Get-Content $Config -Raw | ConvertFrom-Json
$env:DATABASE_URL = $cfg.DATABASE_URL
$env:STML_BIND = $cfg.STML_BIND
$env:STML_TENANT = $cfg.STML_TENANT
$env:STML_ADMIN_TOKEN = $cfg.STML_ADMIN_TOKEN
$env:STML_VIEWER_TOKEN = $cfg.STML_VIEWER_TOKEN
$env:STML_APPROVER_TOKEN = $cfg.STML_APPROVER_TOKEN
$env:STML_TRUST_DIR = $cfg.STML_TRUST_DIR
if ($cfg.STML_POLICY_PUBKEY_FILE) { $env:STML_POLICY_PUBKEY_FILE = $cfg.STML_POLICY_PUBKEY_FILE }
& "D:\-528D~1\rust\stml-server\target\debug\stml-server.exe"
