# Stage 2 (part 1): real inventory with Authenticode certs + live CodeIntegrity events.
# Read-only: no policy is deployed here (deployment needs elevation, blocker D).
$ErrorActionPreference = 'Continue'
$out = [ordered]@{}
$out.measured_at = (Get-Date).ToString('o')
$out.host = $env:COMPUTERNAME

$roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, "$env:LOCALAPPDATA\Programs",
           "$env:SystemRoot\System32") | Where-Object { $_ -and (Test-Path $_) }
$files = foreach ($r in $roots) {
    Get-ChildItem -Path $r -Filter *.exe -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -lt 40MB } | Select-Object -First 120
}
$files = @($files | Sort-Object FullName -Unique)
$sample = @($files | Get-Random -Count ([Math]::Min(150, $files.Count)) -SetSeed 424242)

$inv = foreach ($f in $sample) {
    $s = Get-AuthenticodeSignature -FilePath $f.FullName
    $cert = $s.SignerCertificate
    [pscustomobject]@{
        path      = $f.FullName
        status    = "$($s.Status)"
        subject   = if ($cert) { $cert.Subject } else { "" }
        cn        = if ($cert -and $cert.Subject -match 'CN=([^,]+)') { $Matches[1] } else { "" }
        der_b64   = if ($cert) { [Convert]::ToBase64String($cert.RawData) } else { $null }
        size      = $f.Length
    }
}
$out.inventory = @($inv)
$out.inventory_count = @($inv).Count
$out.signed = @($inv | Where-Object { $_.status -eq 'Valid' }).Count
$out.with_der = @($inv | Where-Object { $_.der_b64 }).Count

# live CodeIntegrity events (audit 3076 / block 3077) — read-only
try {
    $evts = Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 40 -ErrorAction Stop
    $xmls = @()
    foreach ($e in $evts) { $xmls += [pscustomobject]@{ id = $e.Id; xml = $e.ToXml() } }
    $out.ci_events = $xmls
    $out.ci_event_count = $xmls.Count
    $out.ci_ids = @($xmls | Group-Object id | ForEach-Object { "$($_.Name):$($_.Count)" })
} catch {
    $out.ci_events = @()
    $out.ci_error = $_.Exception.Message
}

$out | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $PSScriptRoot 'inventory_certs.json') -Encoding utf8
"inventory=$($out.inventory_count) signed=$($out.signed) der=$($out.with_der) ci_events=$(@($out.ci_events).Count) ids=$($out.ci_ids -join ',')"
