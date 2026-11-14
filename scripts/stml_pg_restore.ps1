# STML PostgreSQL restore (custom format). Creates the target DB if needed.
param(
    [Parameter(Mandatory = $true)][string]$File,
    [string]$Database = "stml_restore",
    [string]$DbUser = "stml",
    [string]$DbHost = "127.0.0.1",
    [int]$Port = 5432,
    [string]$Password = $env:PGPASSWORD,
    [switch]$CreateDatabase
)
$ErrorActionPreference = "Stop"
$bin = "C:\Program Files\PostgreSQL\16\bin"
$pgRestore = Join-Path $bin "pg_restore.exe"
$createdb = Join-Path $bin "createdb.exe"
if (-not (Test-Path $File)) { throw "backup not found: $File" }
if ($Password) { $env:PGPASSWORD = $Password }
if ($CreateDatabase) {
    & $createdb -h $DbHost -p $Port -U $DbUser $Database
    if ($LASTEXITCODE -ne 0) { throw "createdb failed: $LASTEXITCODE" }
}
& $pgRestore -h $DbHost -p $Port -U $DbUser -d $Database --clean --if-exists --no-owner $File
if ($LASTEXITCODE -ne 0) { throw "pg_restore failed: $LASTEXITCODE" }
Write-Output "restored=$Database"
