# Install Rust STML server as a SYSTEM scheduled task (port 8090).
$ErrorActionPreference = "Stop"
$ShortRepo = "D:\-528D~1"
$DataDir = "C:\ProgramData\AIDefender\stml"
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$tokens = Get-Content (Join-Path $DataDir "tokens.json") -Raw | ConvertFrom-Json
$policyPub = Get-ChildItem (Join-Path $DataDir "trust\policy-*.pub") -ErrorAction SilentlyContinue |
    Select-Object -First 1
$cfg = [ordered]@{
    DATABASE_URL = "postgres://stml:stml@127.0.0.1:5432/stml_p4"
    STML_BIND = "127.0.0.1:8090"
    STML_TENANT = "default"
    STML_ADMIN_TOKEN = $tokens.admin_token
    STML_VIEWER_TOKEN = $tokens.viewer_token
    STML_APPROVER_TOKEN = $tokens.approver_token
    STML_TRUST_DIR = (Join-Path $DataDir "trust")
    STML_POLICY_PUBKEY_FILE = if ($policyPub) { $policyPub.FullName } else { "" }
}
$cfgPath = Join-Path $DataDir "rust.env.json"
$cfg | ConvertTo-Json | Set-Content -Encoding utf8 $cfgPath
icacls $cfgPath /inheritance:r /grant:r "SYSTEM:F" "Administrators:F" | Out-Null
Copy-Item (Join-Path $ShortRepo "scripts\run_stml_rust_server.ps1") (Join-Path $DataDir "run_rust_server.ps1") -Force

$Action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$DataDir\run_rust_server.ps1`"" `
    -WorkingDirectory $ShortRepo
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
Register-ScheduledTask -TaskName "AIDefender-STML-Rust" -Action $Action -Trigger $Trigger `
    -Settings $Settings -User "SYSTEM" -RunLevel Highest -Force
Start-ScheduledTask -TaskName "AIDefender-STML-Rust"
