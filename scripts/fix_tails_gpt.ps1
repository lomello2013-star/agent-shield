#requires -RunAsAdministrator
param([int]$DiskNumber = 3)
$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
Start-Transcript -Path (Join-Path $repo "artifacts\gpt-fix.log") -Force | Out-Null
$disk = Get-Disk -Number $DiskNumber
$lastLba = [int64]($disk.Size / 512) - 1
foreach ($part in Get-Partition -DiskNumber $DiskNumber) {
    foreach ($path in @($part.AccessPaths)) {
        if ($path) {
            Remove-PartitionAccessPath -DiskNumber $DiskNumber -PartitionNumber $part.PartitionNumber `
                -AccessPath $path -ErrorAction SilentlyContinue
        }
    }
}
Start-Sleep -Seconds 1
$python = (Get-Command python.exe).Source
& $python (Join-Path $repo "scripts\fix_gpt_backup.py") `
    --drive "\\.\PhysicalDrive$DiskNumber" --last-lba $lastLba
if ($LASTEXITCODE -ne 0) { throw "fix_gpt_backup failed: $LASTEXITCODE" }
Update-HostStorageCache
Write-Output "GPT repaired on Disk $DiskNumber (last LBA $lastLba)"
Stop-Transcript | Out-Null
