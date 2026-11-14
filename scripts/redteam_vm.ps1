#requires -RunAsAdministrator
<#
.SYNOPSIS
    Safe Windows red-team emulation, run INSIDE the AIDF-Win11 VM.
.DESCRIPTION
    Executes benign look-alike techniques, measures the running AIDefender
    service via aidfctl, and writes C:\AIDefender\redteam_result.json.
    No malware, no destructive actions.
#>
param(
    [Parameter(Mandatory = $true)][string]$Token,
    [Parameter(Mandatory = $true)][string]$AuthKey,
    [string]$Head = "unknown"
)

$ErrorActionPreference = "Continue"
$env:AIDF_AUTHKEY = $AuthKey
$env:AIDF_TOKEN = $Token
$py = "C:\Program Files\Python312\python.exe"
$ctl = "C:\AIDefender\scripts\aidfctl.py"

function Get-Stats {
    & $py $ctl stats 2>$null | ConvertFrom-Json
}
function Get-Pending {
    (& $py $ctl confirmations 2>$null | ConvertFrom-Json).pending
}
function RuleCount($stats, $name) {
    $p = $stats.pipeline.rule_counts.PSObject.Properties[$name]
    if ($p) { return [int]$p.Value }
    return 0
}
function Approve($cid) {
    $params = @{ confirmation_id = $cid; decision = "approved" } | ConvertTo-Json -Compress
    Set-Content -Path "C:\Temp\rt_params.json" -Value $params -Encoding ASCII
    $r = & $py $ctl confirm --params-file "C:\Temp\rt_params.json" 2>$null | ConvertFrom-Json
    return $r.status
}

$base = Get-Stats
$baseSvc = RuleCount $base "WIN-SERVICE-CREATE-007"
$baseTemp = RuleCount $base "WIN-EXEC-TEMP-001"
$basePs = RuleCount $base "WIN-PS-ENCODED-002"
$baseVerdicts = [int]$base.pipeline.verdicts
$scenarios = @()

# --- RT-WIN-01: persistence via service creation (T1543.003) -----------------
& sc.exe create AidfRtSvc binPath= "C:\Temp\rt.exe" start= demand 2>&1 | Out-Null
Start-Sleep -Seconds 7
$s = Get-Stats
$svcCount = RuleCount $s "WIN-SERVICE-CREATE-007"
$scenarios += [ordered]@{
    id = "RT-WIN-01"; technique = "T1543.003"; action = "sc create AidfRtSvc"
    rule = "WIN-SERVICE-CREATE-007"; detected = ($svcCount -gt $baseSvc)
    prevented = $false; note = "service install has no actor_pid; suspend is action_skipped"
}
& sc.exe delete AidfRtSvc 2>&1 | Out-Null

# --- RT-WIN-02: execution from temp + approval (T1204) -----------------------
$tick = "C:\Temp\tick.exe"
if (-not (Test-Path $tick)) {
    $code = @'
using System; using System.IO; using System.Threading;
public class T { public static void Main(){ using(var f=new FileStream(@"C:\Temp\tick.bin", FileMode.Append)){ while(true){ f.WriteByte(65); f.Flush(); Thread.Sleep(50); } } } }
'@
    Add-Type -TypeDefinition $code -OutputAssembly $tick -OutputType ConsoleApplication
}
Copy-Item $tick "C:\Temp\rt_tick.exe" -Force
Remove-Item "C:\Temp\tick.bin" -Force -ErrorAction SilentlyContinue
$p = Start-Process "C:\Temp\rt_tick.exe" -PassThru
Start-Sleep -Seconds 7
$s = Get-Stats
$tempCount = RuleCount $s "WIN-EXEC-TEMP-001"
$pend = Get-Pending
$item = $pend | Where-Object { "$($_.target)" -eq "$($p.Id)" } | Select-Object -First 1
$status = ""
if ($item) { $status = Approve $item.confirmation_id }
$before = 0; if (Test-Path "C:\Temp\tick.bin") { $before = (Get-Item "C:\Temp\tick.bin").Length }
Start-Sleep -Seconds 2
$after = 0; if (Test-Path "C:\Temp\tick.bin") { $after = (Get-Item "C:\Temp\tick.bin").Length }
$scenarios += [ordered]@{
    id = "RT-WIN-02"; technique = "T1204"; action = "exec C:\Temp\rt_tick.exe"
    rule = "WIN-EXEC-TEMP-001"; detected = (($tempCount -gt $baseTemp) -and ($null -ne $item))
    prevented = ($status -eq "executed"); pending = ($null -ne $item); confirm = $status
    frozen = ($before -eq $after)
}
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue

# --- RT-WIN-03: encoded PowerShell (T1059.001) ------------------------------
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Start-Sleep -Seconds 20"))
$p2 = Start-Process powershell -ArgumentList "-NoProfile", "-EncodedCommand", $enc -PassThru
Start-Sleep -Seconds 7
$s = Get-Stats
$psCount = RuleCount $s "WIN-PS-ENCODED-002"
$pend = Get-Pending
$item2 = $pend | Where-Object { "$($_.target)" -eq "$($p2.Id)" } | Select-Object -First 1
$status2 = ""
if ($item2) { $status2 = Approve $item2.confirmation_id }
$scenarios += [ordered]@{
    id = "RT-WIN-03"; technique = "T1059.001"; action = "powershell -EncodedCommand (sleep)"
    rule = "WIN-PS-ENCODED-002"; detected = ($psCount -gt $basePs)
    prevented = ($status2 -eq "executed"); pending = ($null -ne $item2); confirm = $status2
}
Stop-Process -Id $p2.Id -Force -ErrorAction SilentlyContinue

# --- RT-WIN-04: benign control + driver prevention (E6) ---------------------
$v0 = [int](Get-Stats).pipeline.verdicts
Start-Process cmd -ArgumentList "/c", "exit" -Wait
Start-Sleep -Seconds 7
$v1 = [int](Get-Stats).pipeline.verdicts
$filterLoaded = [bool](& fltmc.exe filters 2>$null | Select-String "AidfFilter")
$driverBlocked = $false
try { Set-Content -Path "C:\AIDefender\protected\rt.txt" -Value "x" -ErrorAction Stop }
catch { $driverBlocked = $true }
$scenarios += [ordered]@{
    id = "RT-WIN-04"; technique = "control+E6"; action = "benign cmd; protected write"
    rule = "none"; detected = $false; prevented = $driverBlocked
    fp_delta = ($v1 - $v0); driver_loaded = $filterLoaded
    note = "driver blocks protected write; benign cmd must not add verdicts"
}

$detected = @($scenarios | Where-Object { $_.detected }).Count
$prevented = @($scenarios | Where-Object { $_.prevented }).Count
$report = [ordered]@{
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    head = $Head
    vm = $env:COMPUTERNAME
    scenarios = $scenarios
    summary = [ordered]@{
        total = $scenarios.Count; detected = $detected; prevented = $prevented
        fp_delta = ($v1 - $v0); driver_blocked = $driverBlocked
    }
    limitations = "Safe technique emulation, not real malware; one VM, one run; E1-E6 still need a full 20-scenario/OS red-team."
}
$report | ConvertTo-Json -Depth 8 | Set-Content -Path "C:\AIDefender\redteam_result.json" -Encoding ASCII
Write-Host "redteam result written: C:\AIDefender\redteam_result.json"

