#requires -Version 5.1
param([string]$DataDir = "C:\ProgramData\AIDefender")
$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force $DataDir | Out-Null
$health = [ordered]@{ ts = (Get-Date).ToString("o"); services = @{}; actions = @() }
foreach ($name in @("AIDefender", "Sysmon64")) {
    $svc = Get-Service $name -ErrorAction SilentlyContinue
    if (-not $svc) { $health.services[$name] = "missing"; continue }
    $health.services[$name] = $svc.Status.ToString()
    if ($svc.Status -ne "Running") {
        try {
            Start-Service $name -ErrorAction Stop
            $health.actions += "started:$name"
        } catch {
            $health.actions += "failed:${name}:$($_.Exception.Message)"
        }
    }
}
$health | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $DataDir "health.json") -Encoding UTF8
