
param([string]$ListFile, [string]$OutFile)
$paths = Get-Content -LiteralPath $ListFile -Encoding UTF8 | Where-Object { $_ -and $_.Trim() }
$out = New-Object System.Collections.Generic.List[object]
foreach ($p in $paths) {
  try {
    $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
    $subject = ""
    if ($s.SignerCertificate) { $subject = $s.SignerCertificate.Subject }
    $out.Add([pscustomobject]@{ path = [string]$p; status = [string]$s.Status; signer = $subject })
  } catch {
    $out.Add([pscustomobject]@{ path = [string]$p; status = "Error"; signer = "" })
  }
}
$out | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $OutFile -Encoding UTF8
"done"
