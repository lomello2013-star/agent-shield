"""Full-host WDAC inventory: every `.exe` on the host, measured FBR, policy per root.

Runs over the four roots that hold user-mode binaries (System32, SysWOW64, Program Files,
Program Files (x86)): collects Authenticode status and publisher for every executable,
computes two FBR variants (signature-required and top-publisher allowlist), and asks
`New-CIPolicy` to build a publisher policy for each root (audit mode, unsigned allowed).

Writes `artifacts/wdac_inventory.json` and `artifacts/wdac_full/*.xml`. Runs for many
minutes, so it is meant to be started in the background.
"""

from __future__ import annotations

import glob
import json
import os
import subprocess
import sys
from collections import Counter

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(HERE, "artifacts", "wdac_inventory.json")
WORK = os.path.join(HERE, "artifacts", "wdac_full")
ROOTS = [r"C:\Windows\System32", r"C:\Windows\SysWOW64",
         r"C:\Program Files", r"C:\Program Files (x86)"]

PS = r"""
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
"""


def publisher_of(signer: str) -> str:
    if "O=" in signer:
        return signer.split("O=")[-1].split(",")[0].strip()
    return signer.strip()


def main() -> int:
    os.makedirs(WORK, exist_ok=True)
    paths: list[str] = []
    per_root: dict[str, int] = {}
    for root in ROOTS:
        found = [p for p in glob.glob(os.path.join(root, "**", "*.exe"), recursive=True)
                 if os.path.isfile(p)]
        per_root[root] = len(found)
        paths.extend(found)
    list_file = os.path.join(WORK, "paths.txt")
    with open(list_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(paths))
    result_file = os.path.join(WORK, "signatures.json")
    ps1 = os.path.join(WORK, "sign.ps1")
    with open(ps1, "w", encoding="utf-8-sig") as fh:
        fh.write(PS)
    proc = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                           "-File", ps1, "-ListFile", list_file, "-OutFile", result_file],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace")
    rows: list[dict] = []
    if os.path.exists(result_file):
        with open(result_file, encoding="utf-8-sig") as fh:
            data = json.load(fh)
        rows = [data] if isinstance(data, dict) else data
    rows = [row for row in rows if isinstance(row, dict) and row.get("path")]
    for row in rows:
        value = row.get("path")
        if isinstance(value, dict):
            row["path"] = str(value.get("value") or "")
        row["publisher"] = publisher_of(row.get("signer") or "")
    publishers = Counter(row["publisher"] for row in rows)
    unsigned = [row for row in rows if row.get("status") != "Valid"]
    top5 = [name for name, _ in publishers.most_common(8) if name][:5]
    blocked_top5 = [row for row in rows if row["publisher"] not in top5]
    fbr_sig = round(100.0 * len(unsigned) / max(1, len(rows)), 2)
    fbr_top5 = round(100.0 * len(blocked_top5) / max(1, len(rows)), 2)

    policies = []
    for index, root in enumerate(ROOTS):
        xml = os.path.join(WORK, f"policy_{index}.xml")
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
               "Import-Module ConfigCI -ErrorAction Stop; "
               f"New-CIPolicy -Level Publisher -Fallback Hash -UserPEs -FilePath '{xml}' "
               f"-ScanPath '{root}' -ErrorAction Stop"]
        res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                             errors="replace")
        policies.append({"root": root, "xml": xml if os.path.exists(xml) else None,
                         "returncode": res.returncode,
                         "bytes": os.path.getsize(xml) if os.path.exists(xml) else 0,
                         "stderr": (res.stderr or "").strip()[-200:]})

    report = {
        "roots": per_root,
        "executables": len(rows),
        "signed": len(rows) - len(unsigned),
        "unsigned": len(unsigned),
        "fbr_signature_required_pct": fbr_sig,
        "allowlist_top5_publishers": top5,
        "fbr_top5_allowlist_pct": fbr_top5,
        "publishers_top10": dict(publishers.most_common(10)),
        "blocked_examples": [row["path"] for row in blocked_top5[:10]],
        "policies": policies,
        "note": "FBR variants are computed on every .exe of the four roots; DLLs are not "
                "included (a full UMCI policy would also cover them)",
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps({k: report[k] for k in ("executables", "signed", "unsigned",
                                             "fbr_signature_required_pct",
                                             "fbr_top5_allowlist_pct")},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
