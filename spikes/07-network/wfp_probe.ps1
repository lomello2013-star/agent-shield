# Spike 7 (Windows): per-process network block availability without elevation.
# Tests: WFP engine open, firewall rule creation (PowerShell + netsh), WFP state dump.
$ErrorActionPreference = 'Continue'
$out = [ordered]@{}
$out.measured_at = (Get-Date).ToString('o')
$out.admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# P/Invoke WFP engine open (no elevation => should fail)
$src = @'
using System;
using System.Runtime.InteropServices;
public static class Wfp {
    [DllImport("fwpuclnt.dll")]
    public static extern uint FwpmEngineOpen0(string serverName, uint authnService, IntPtr authIdentity, IntPtr session, out IntPtr engineHandle);
    [DllImport("fwpuclnt.dll")]
    public static extern uint FwpmEngineClose0(IntPtr engineHandle);
}
'@
try { Add-Type -TypeDefinition $src -Language CSharp | Out-Null } catch { }
$h = [IntPtr]::Zero
$rc = [Wfp]::FwpmEngineOpen0($null, 0, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$h)
$out.wfp_engine_open_hresult = ('0x{0:X8}' -f $rc)
if ($rc -eq 0) { [void][Wfp]::FwpmEngineClose0($h) }

# firewall rule creation attempt (per-process block)
$tmpExe = Join-Path $env:TEMP 'aidf_spike7_probe.exe'
Copy-Item "$env:SystemRoot\System32\where.exe" $tmpExe -Force
$out.rule_create = [ordered]@{}
try {
    $r = New-NetFirewallRule -DisplayName 'aidf-spike7-probe' -Direction Outbound -Program $tmpExe -Action Block -ErrorAction Stop
    $out.rule_create.ps_method = "SUCCESS name=$($r.DisplayName)"
    Remove-NetFirewallRule -DisplayName 'aidf-spike7-probe' -ErrorAction SilentlyContinue
    $out.rule_create.cleanup = 'removed'
} catch {
    $out.rule_create.ps_method = "FAILED: $($_.Exception.Message)"
}
$netshOut = netsh advfirewall firewall add rule name="aidf-spike7-probe" dir=out program="$tmpExe" action=block 2>&1
$out.rule_create.netsh_exit = $LASTEXITCODE
$out.rule_create.netsh_output = ($netshOut | Out-String).Trim()
Remove-Item $tmpExe -Force -ErrorAction SilentlyContinue

# WFP state dump (requires elevation)
$wfpState = netsh wfp show state 2>&1
$out.wfp_show_state_exit = $LASTEXITCODE
$out.wfp_show_state = ($wfpState | Select-Object -First 3 | Out-String).Trim()

# readable firewall inventory
try {
    $rules = Get-NetFirewallRule -ErrorAction Stop
    $out.existing_rules_readable = @($rules).Count
    $out.program_scoped_rules = @($rules | Where-Object { $_.DisplayName -match 'aidf' }).Count
} catch { $out.existing_rules_readable = "ERR: $($_.Exception.Message)" }

$out | ConvertTo-Json -Depth 5 | Tee-Object -FilePath (Join-Path $PSScriptRoot 'wfp_probe.json')
