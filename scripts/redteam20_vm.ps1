#requires -RunAsAdministrator
<#
.SYNOPSIS
    20-scenario Windows red-team slice, run INSIDE AIDF-Win11.
.DESCRIPTION
    15 safe emulations are executed; 5 destructive ones are catalog-only
    (safe=$false). Detection is measured as a delta of service rule counts.
    Holdout scenarios are flagged and reported separately.
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
New-Item -ItemType Directory -Force -Path "C:\Temp", "C:\AIDefender\protected", "C:\AIDefender\secret" | Out-Null

function Get-Stats { & $py $ctl stats 2>$null | ConvertFrom-Json }
function Get-Rules {
    $s = Get-Stats
    $h = @{}
    foreach ($p in $s.pipeline.rule_counts.PSObject.Properties) { $h[$p.Name] = [int]$p.Value }
    return $h
}
function Get-RuleDelta($before, $after) {
    $new = @()
    foreach ($k in $after.Keys) {
        if (-not $before.ContainsKey($k) -or $after[$k] -gt $before[$k]) { $new += $k }
    }
    return $new
}
function Wait-Settled {
    # Let delayed verdicts from the previous scenario land before taking the baseline.
    $last = Get-Rules
    for ($i = 0; $i -lt 3; $i++) {
        Start-Sleep -Seconds 3
        $cur = Get-Rules
        if ((Get-RuleDelta $last $cur).Count -eq 0) { return }
        $last = $cur
    }
}
function Get-VerdictsSince([datetime]$since) {
    # Attribute by source-event time, not by processing window. A delayed RUNKEY
    # carries the event_ts of its own scenario and is excluded here.
    $h = @{}
    $path = "C:\ProgramData\AIDefender\audit\chain.jsonl"
    if (-not (Test-Path $path)) { return $h }
    Get-Content $path -Tail 500 -ErrorAction SilentlyContinue | ForEach-Object {
        try { $o = $_ | ConvertFrom-Json } catch { return }
        if ($o.type -ne "verdict" -or -not $o.payload.event_ts) { return }
        $ts = $null
        try { $ts = [datetime]::Parse([string]$o.payload.event_ts).ToUniversalTime() } catch { return }
        if ($ts -lt $since) { return }
        $r = [string]$o.payload.rule
        if ($r) { if (-not $h.ContainsKey($r)) { $h[$r] = 0 }; $h[$r]++ }
    }
    return $h
}

$rows = @(
    @{ id="WIN-01"; technique="T1543.003"; expected="WIN-SERVICE-CREATE-007"; safe=$true; holdout=$false; desc="service create";
       action={ & sc.exe create AidfRT01 binPath= "C:\Temp\rt.exe" start= demand 2>&1 | Out-Null }; cleanup={ & sc.exe delete AidfRT01 2>&1 | Out-Null } },
    @{ id="WIN-02"; technique="T1204"; expected="WIN-EXEC-TEMP-001"; safe=$true; holdout=$false; desc="temp exec";
       action={ if (Test-Path "C:\Temp\tick.exe") { $global:rtTick = Start-Process "C:\Temp\tick.exe" -PassThru } }; cleanup={ if ($global:rtTick) { Stop-Process -Id $global:rtTick.Id -Force -ErrorAction SilentlyContinue } } },
    @{ id="WIN-03"; technique="T1059.001"; expected="WIN-PS-ENCODED-002"; safe=$true; holdout=$false; desc="encoded PowerShell";
       action={ $e=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Start-Sleep -Seconds 15")); $global:rtPs = Start-Process powershell -ArgumentList "-NoProfile","-EncodedCommand",$e -PassThru }; cleanup={ if ($global:rtPs) { Stop-Process -Id $global:rtPs.Id -Force -ErrorAction SilentlyContinue } } },
    @{ id="WIN-04"; technique="T1059.003"; expected="WIN-EXEC-TEMP-001"; safe=$true; holdout=$true; desc="temp cmd";
       action={ Copy-Item "C:\Windows\System32\cmd.exe" "C:\Temp\rt_cmd.exe" -Force; Start-Process "C:\Temp\rt_cmd.exe" -ArgumentList "/c","exit" -Wait }; cleanup={ Remove-Item "C:\Temp\rt_cmd.exe" -Force -ErrorAction SilentlyContinue } },
    @{ id="WIN-05"; technique="T1053.005"; expected="WIN-SCHTASK-006"; safe=$true; holdout=$false; desc="scheduled task";
       action={ & schtasks.exe /create /tn AidfRT05 /tr "cmd /c exit" /sc once /st 23:59 /f 2>&1 | Out-Null }; cleanup={ & schtasks.exe /delete /tn AidfRT05 /f 2>&1 | Out-Null } },
    @{ id="WIN-06"; technique="T1547.001"; expected="WIN-RUNKEY-005"; safe=$true; holdout=$true; desc="Run key";
       action={ & reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v AidfRT06 /d "cmd.exe" /f 2>&1 | Out-Null }; cleanup={ & reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v AidfRT06 /f 2>&1 | Out-Null } },
    @{ id="WIN-07"; technique="T1136.001"; expected="none"; safe=$false; holdout=$false; desc="local user (destructive; catalog only)"; action={}; cleanup={} },
    @{ id="WIN-08"; technique="T1562.001"; expected="WIN-DEFENDER-TAMPER-009"; safe=$true; holdout=$true; desc="Defender exclusion";
       action={ Add-MpPreference -ExclusionPath "C:\Temp\AidfRT" -ErrorAction SilentlyContinue }; cleanup={ Remove-MpPreference -ExclusionPath "C:\Temp\AidfRT" -ErrorAction SilentlyContinue } },
    @{ id="WIN-09"; technique="T1546.003"; expected="WIN-WMI-SUBSCRIPTION-018"; safe=$true; holdout=$false; desc="WMI event subscription";
       action={
           $f = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments @{Name="AidfRT"; EventNamespace="root/cimv2"; QueryLanguage="WQL"; Query='SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA "Win32_Process"'} -ErrorAction Stop
           $c = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments @{Name="AidfRTC"; CommandLineTemplate="cmd.exe /c exit"} -ErrorAction Stop
           Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$f; Consumer=$c} -ErrorAction Stop | Out-Null
       };
       cleanup={
           Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { $_.Filter.Name -eq "AidfRT" } | Remove-CimInstance -ErrorAction SilentlyContinue
           Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -Filter "Name='AidfRT'" -ErrorAction SilentlyContinue | Remove-CimInstance -ErrorAction SilentlyContinue
           Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Filter "Name='AidfRTC'" -ErrorAction SilentlyContinue | Remove-CimInstance -ErrorAction SilentlyContinue
       } },
    @{ id="WIN-10"; technique="T1105"; expected="none"; safe=$true; holdout=$true; desc="certutil download";
       action={ & certutil.exe -urlcache -f "https://example.com/" "C:\Temp\rt_cert.txt" 2>&1 | Out-Null }; cleanup={ Remove-Item "C:\Temp\rt_cert.txt" -Force -ErrorAction SilentlyContinue } },
    @{ id="WIN-11"; technique="T1218"; expected="none"; safe=$true; holdout=$false; desc="rundll32";
       action={ $global:rtRundll = Start-Process rundll32.exe -ArgumentList "nonexistent.dll,Func" -PassThru }; cleanup={ if ($global:rtRundll) { Stop-Process -Id $global:rtRundll.Id -Force -ErrorAction SilentlyContinue } } },
    @{ id="WIN-12"; technique="T1055"; expected="WIN-INJECT-010"; safe=$false; holdout=$false; desc="injection (destructive; catalog only)"; action={}; cleanup={} },
    @{ id="WIN-13"; technique="T1003.001"; expected="WIN-LSASS-ACCESS-004"; safe=$false; holdout=$false; desc="LSASS dump (destructive; catalog only)"; action={}; cleanup={} },
    @{ id="WIN-14"; technique="T1070.001"; expected="WIN-LOG-CLEAR-008"; safe=$false; holdout=$false; desc="log clear (destructive; catalog only)"; action={}; cleanup={} },
    @{ id="WIN-15"; technique="T1490"; expected="none"; safe=$false; holdout=$false; desc="shadow copy deletion (destructive; catalog only)"; action={}; cleanup={} },
    @{ id="WIN-16"; technique="T1027"; expected="WIN-MASQUERADE-011"; safe=$true; holdout=$true; desc="masquerade svchost";
       action={ Copy-Item "C:\Windows\System32\notepad.exe" "C:\Temp\svchost.exe" -Force; $global:rtMasq = Start-Process "C:\Temp\svchost.exe" -PassThru }; cleanup={ if ($global:rtMasq) { Stop-Process -Id $global:rtMasq.Id -Force -ErrorAction SilentlyContinue }; Remove-Item "C:\Temp\svchost.exe" -Force -ErrorAction SilentlyContinue } },
    @{ id="WIN-17"; technique="T1204"; expected="WIN-DOWNLOADS-EXEC-016"; safe=$true; holdout=$true; desc="execute from Downloads";
       action={ Copy-Item "C:\Windows\System32\calc.exe" "C:\Users\aidf\Downloads\rt.exe" -Force; $global:rtDl = Start-Process "C:\Users\aidf\Downloads\rt.exe" -PassThru }; cleanup={ if ($global:rtDl) { Stop-Process -Id $global:rtDl.Id -Force -ErrorAction SilentlyContinue }; Remove-Item "C:\Users\aidf\Downloads\rt.exe" -Force -ErrorAction SilentlyContinue } },
    @{ id="WIN-18"; technique="T1569.002"; expected="WIN-SERVICE-CREATE-007"; safe=$true; holdout=$false; desc="service start";
       action={ & sc.exe start Sysmon64 2>&1 | Out-Null }; cleanup={} },
    @{ id="WIN-19"; technique="T1112"; expected="none"; safe=$true; holdout=$false; desc="registry modify";
       action={ & reg.exe add "HKCU\Software\AidfRT" /v x /d y /f 2>&1 | Out-Null }; cleanup={ & reg.exe delete "HKCU\Software\AidfRT" /f 2>&1 | Out-Null } },
    @{ id="WIN-20"; technique="control"; expected="none"; safe=$true; holdout=$false; desc="benign control";
       action={ Start-Process cmd -ArgumentList "/c","exit" -Wait }; cleanup={} }
)

# Let the collectors drain any backlog before measuring deltas.
$r1 = [int](Get-Stats).pipeline.ingest.received
Start-Sleep -Seconds 5
$r2 = [int](Get-Stats).pipeline.ingest.received
while ($r2 -gt $r1 + 20) {
    Start-Sleep -Seconds 5
    $r1 = $r2
    $r2 = [int](Get-Stats).pipeline.ingest.received
}

$results = @()
foreach ($row in $rows) {
    if (-not $row.safe) {
        $results += [ordered]@{ id=$row.id; technique=$row.technique; expected=$row.expected; detected=$false
            run=$false; skipped="destructive/catalog-only"; holdout=$row.holdout }
        continue
    }
    Wait-Settled
    $t0 = (Get-Date).ToUniversalTime()
    $err = ""
    try { & $row.action } catch { $err = $_.Exception.Message }
    $new = Get-VerdictsSince $t0
    $deadline = (Get-Date).AddSeconds(20)
    while ($new.Count -eq 0 -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
        $new = Get-VerdictsSince $t0
    }
    $detected = ($new.Count -gt 0)
    $results += [ordered]@{ id=$row.id; technique=$row.technique; expected=$row.expected; detected=$detected
        observed=(($new.Keys | Sort-Object) -join ","); run=$true; holdout=$row.holdout; error=$err }
    try { & $row.cleanup } catch {}
}

$attacks = @($results | Where-Object { $_.expected -ne "none" -and $_.run })
$controls = @($results | Where-Object { $_.expected -eq "none" -and $_.run })
$holdout = @($results | Where-Object { $_.holdout -and $_.run -and $_.expected -ne "none" })
$report = [ordered]@{
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    head = $Head
    vm = $env:COMPUTERNAME
    scenarios = $results
    summary = [ordered]@{
        catalog = $results.Count
        run = @($results | Where-Object { $_.run }).Count
        skipped = @($results | Where-Object { -not $_.run }).Count
        attacks_run = $attacks.Count
        attacks_detected = @($attacks | Where-Object { $_.detected }).Count
        controls_run = $controls.Count
        control_fp = @($controls | Where-Object { $_.detected }).Count
        holdout_total = $holdout.Count
        holdout_detected = @($holdout | Where-Object { $_.detected }).Count
    }
    limitations = "Safe emulation, 20/OS catalog with 5 destructive entries skipped; detection only for this run (prevention measured separately); E1-E6 still require real samples and a hidden holdout."
}
$report | ConvertTo-Json -Depth 8 | Set-Content -Path "C:\AIDefender\redteam20_result.json" -Encoding ASCII
Write-Host "redteam20 result written"

