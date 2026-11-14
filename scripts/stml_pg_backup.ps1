# STML PostgreSQL backup (custom format + SHA256 sidecar).
param(
    [string]$Database = "stml",
    [string]$OutDir = "artifacts\pg-backups",
    [string]$DbUser = "stml",
    [string]$DbHost = "127.0.0.1",
    [int]$Port = 5432,
    [string]$Password = $env:PGPASSWORD
)
$ErrorActionPreference = "Stop"
$bin = "C:\Program Files\PostgreSQL\16\bin"
$pgDump = Join-Path $bin "pg_dump.exe"
if (-not (Test-Path $pgDump)) { throw "pg_dump not found: $pgDump" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$file = Join-Path $OutDir "$Database-$stamp.dump"
if ($Password) { $env:PGPASSWORD = $Password }
& $pgDump -h $DbHost -p $Port -U $DbUser -Fc -f $file $Database
if ($LASTEXITCODE -ne 0) { throw "pg_dump failed: $LASTEXITCODE" }
$hash = (Get-FileHash -Algorithm SHA256 $file).Hash.ToLower()
"$hash  $(Split-Path -Leaf $file)" | Set-Content -Encoding ascii "$file.sha256"
Write-Output "backup=$file"
Write-Output "sha256=$hash"
