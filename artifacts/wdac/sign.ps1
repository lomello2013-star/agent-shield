
param([string]$ListFile)
$Paths = Get-Content -LiteralPath $ListFile -Encoding UTF8 | Where-Object { $_ -and $_.Trim() }
$out = @()
foreach ($p in $Paths) {
  try {
    $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
    $out += [pscustomobject]@{ path = $p; status = "$($s.Status)";
      signer = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { "" } }
  } catch {
    $out += [pscustomobject]@{ path = $p; status = "Error"; signer = "" }
  }
}
$out | ConvertTo-Json -Depth 3
