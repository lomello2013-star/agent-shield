# Spike 2: app control (WDAC) capability + counterfactual false-block-rate on this host.
# Method: inventory real executables, classify Authenticode signer, then evaluate a candidate
# default-deny policy ("allow Microsoft-signed only") against (a) installed binaries and
# (b) a real launch trace produced by executing a representative console workload.
$ErrorActionPreference = 'Continue'
$out = [ordered]@{}
$out.measured_at = (Get-Date).ToString('o')
$out.host = $env:COMPUTERNAME

# ---------- 1. WDAC capability ----------
$out.capability = [ordered]@{}
$out.capability.os = (Get-CimInstance Win32_OperatingSystem).Caption
$out.capability.build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
$out.capability.sku = (Get-CimInstance Win32_OperatingSystem).OperatingSystemSKU
$ci = @("$env:SystemRoot\System32\CiTool.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
$out.capability.citool_path = if ($ci) { $ci } else { 'MISSING' }
try {
    $pol = Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName MSFT_CIPolicy -ErrorAction Stop
    $out.capability.ci_policies = @($pol).Count
} catch { $out.capability.ci_policies = "unavailable: $($_.Exception.Message)" }
$out.capability.ci_policy_registry = (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy')
try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    $out.capability.device_guard = "VBS=$($dg.VirtualizationBasedSecurityStatus) CI_enforcement=$($dg.CodeIntegrityPolicyEnforcementStatus)"
} catch { $out.capability.device_guard = 'unavailable' }

# ---------- 2. installed executable inventory + signer classification ----------
$roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, "$env:LOCALAPPDATA\Programs", "$env:SystemRoot\System32") | Where-Object { $_ -and (Test-Path $_) }
$exes = foreach ($r in $roots) {
    Get-ChildItem -Path $r -Filter *.exe -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -lt 40MB } | Select-Object -First 350
}
$exes = @($exes | Sort-Object FullName -Unique)
$sample = @($exes | Get-Random -Count ([Math]::Min(250, $exes.Count)) -SetSeed 1337)

function Get-Signer([string]$path) {
    try {
        $s = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
        $subj = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' }
        $cn = if ($subj -match 'CN=([^,]+)') { $Matches[1] } else { '' }
        [pscustomobject]@{ status = "$($s.Status)"; cn = $cn; subject = $subj; is_ms = [bool]($subj -match 'O=Microsoft Corporation|CN=Microsoft') }
    } catch {
        [pscustomobject]@{ status = 'ERROR'; cn = ''; subject = ''; is_ms = $false }
    }
}

$sigs = foreach ($e in $sample) {
    $s = Get-Signer $e.FullName
    [pscustomobject]@{ path = $e.FullName; size = $e.Length; status = $s.status; cn = $s.cn; ms_signed = $s.is_ms }
}
$out.inventory = [ordered]@{
    roots_scanned      = $roots.Count
    exe_files_found    = $exes.Count
    sampled            = @($sigs).Count
    valid_sig          = @($sigs | Where-Object status -eq 'Valid').Count
    not_signed         = @($sigs | Where-Object status -eq 'NotSigned').Count
    other_status       = @($sigs | Where-Object { $_.status -notin @('Valid', 'NotSigned') }).Count
    microsoft_signed   = @($sigs | Where-Object ms_signed).Count
    third_party_signed = @($sigs | Where-Object { $_.status -eq 'Valid' -and -not $_.ms_signed }).Count
    top_signers        = @($sigs | Where-Object { $_.cn -and -not $_.ms_signed } | Group-Object cn | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { "$($_.Count)x $($_.Name)" })
}

$blockedA = @($sigs | Where-Object { -not $_.ms_signed })
$blockedB = @($blockedA | Where-Object { $_.path -notlike "$env:ProgramFiles*" })
$out.policy_counterfactual = [ordered]@{
    policy_A                 = 'allow if Microsoft-signed only'
    A_false_block_pct        = [math]::Round(100.0 * $blockedA.Count / [Math]::Max(1, $sigs.Count), 2)
    A_blocked                = $blockedA.Count
    policy_B                 = 'policy A + Program Files path allowlist'
    B_false_block_pct        = [math]::Round(100.0 * $blockedB.Count / [Math]::Max(1, $sigs.Count), 2)
    B_blocked                = $blockedB.Count
    B_blocked_examples       = @($blockedB | Select-Object -First 8 | ForEach-Object { "$($_.status) :: $($_.cn) :: $(Split-Path $_.path -Leaf)" })
}

# ---------- 3. real launch trace ----------
$trace = New-Object System.Collections.Generic.List[object]
function Resolve-Exe([string]$name) {
    $c = Get-Command $name -ErrorAction SilentlyContinue
    if ($c) { $c.Source } else { $null }
}
$workload = @(
    @{ n = 'cmd.exe'; a = '/c echo spike2' },
    @{ n = 'powershell.exe'; a = '-NoProfile -Command "Get-Date" | Out-Null' },
    @{ n = 'pwsh.exe'; a = '-NoProfile -Command "1+1" | Out-Null' },
    @{ n = 'python.exe'; a = '-c "print(1)"' },
    @{ n = 'pip.exe'; a = '--version' },
    @{ n = 'curl.exe'; a = '--version' },
    @{ n = 'certutil.exe'; a = '-?' },
    @{ n = 'whoami.exe'; a = '/all' },
    @{ n = 'ipconfig.exe'; a = '/all' },
    @{ n = 'netstat.exe'; a = '-an' },
    @{ n = 'tasklist.exe'; a = '/fo csv' },
    @{ n = 'where.exe'; a = 'cmd' },
    @{ n = 'reg.exe'; a = 'query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName' },
    @{ n = 'schtasks.exe'; a = '/query /fo csv' },
    @{ n = 'tar.exe'; a = '--version' },
    @{ n = 'docker.exe'; a = '--version' },
    @{ n = 'wsl.exe'; a = '--version' },
    @{ n = 'msiexec.exe'; a = '/?' },
    @{ n = 'extrac32.exe'; a = '/?' }
)
foreach ($w in $workload) {
    $path = Resolve-Exe $w.n
    if (-not $path) {
        $trace.Add([pscustomobject]@{ name = $w.n; path = $null; status = 'MISSING'; cn = ''; ms_signed = $false; rc = 'NA'; launch_ms = 0 })
        continue
    }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $rc = 'NA'
    try {
        $p = Start-Process -FilePath $path -ArgumentList $w.a -NoNewWindow -Wait -PassThru -ErrorAction Stop
        $rc = [string]$p.ExitCode
    } catch { $rc = 'ERR' }
    $sw.Stop()
    $s = Get-Signer $path
    $trace.Add([pscustomobject]@{ name = $w.n; path = $path; status = $s.status; cn = $s.cn; ms_signed = $s.is_ms; rc = $rc; launch_ms = [int]$sw.ElapsedMilliseconds })
}
$launched = @($trace | Where-Object { $_.path })
$blockedA2 = @($launched | Where-Object { -not $_.ms_signed })
$blockedB2 = @($blockedA2 | Where-Object { $_.path -notlike "$env:ProgramFiles*" })
$out.launch_trace = [ordered]@{
    attempts                    = $trace.Count
    launched                    = $launched.Count
    missing                     = @($trace | Where-Object { -not $_.path }).Count
    distinct_images             = @($launched.path | Sort-Object -Unique).Count
    blocked_by_A                = $blockedA2.Count
    false_block_rate_A_pct      = [math]::Round(100.0 * $blockedA2.Count / [Math]::Max(1, $launched.Count), 2)
    blocked_by_B                = $blockedB2.Count
    false_block_rate_B_pct      = [math]::Round(100.0 * $blockedB2.Count / [Math]::Max(1, $launched.Count), 2)
    rows                        = @($trace | ForEach-Object { [pscustomobject]@{ name = $_.name; status = $_.status; ms_signed = $_.ms_signed; cn = $_.cn; rc = $_.rc; launch_ms = $_.launch_ms } })
}
$out | ConvertTo-Json -Depth 6 | Tee-Object -FilePath (Join-Path $PSScriptRoot 'wdac_probe.json')
