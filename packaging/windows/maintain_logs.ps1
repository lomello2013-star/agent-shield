#requires -Version 5.1
param(
    [string]$DataDir = "C:\ProgramData\AIDefender",
    [int]$RetentionDays = 30
)
$ErrorActionPreference = "Continue"
$cutoff = (Get-Date).AddDays(-$RetentionDays)
$removed = 0
foreach ($sub in @("reports", "raw")) {
    $root = Join-Path $DataDir $sub
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem $root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoff } |
        ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue; $removed++ }
}
$status = [ordered]@{
    ts = (Get-Date).ToString("o")
    retention_days = $RetentionDays
    removed_files = $removed
}
$status | ConvertTo-Json | Set-Content (Join-Path $DataDir "maintenance.json") -Encoding UTF8
