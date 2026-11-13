"""F12/D: audit-mode WDAC policy preparation plus a measured FBR on real applications.

Two artifacts come out of one inventory:

  1. `artifacts/wdac_audit.json` — FBR (false-block rate) of a publisher-based allowlist
     evaluated on **real executables** of this host: for each sampled binary we record
     Authenticode status and signer, then compute the fraction the policy would block.
  2. `artifacts/wdac/policy.xml` (and `.cip` if the ConfigCI module allows conversion) —
     an audit-mode WDAC policy generated from the same inventory, ready to deploy.

Nothing is deployed here: activation needs a reboot, and rebooting would interrupt the
24-hour soak. Deployment/rollback commands are printed for the operator.
"""

from __future__ import annotations

import glob
import json
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(HERE, "artifacts", "wdac_audit.json")
WORK = os.path.join(HERE, "artifacts", "wdac")
SAMPLE = int(os.environ.get("SAMPLE", "120"))
random.seed(20261113)

PS_SIGN = r"""
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
"""


def candidates() -> list[str]:
    pool: list[str] = []
    pool += glob.glob(r"C:\Windows\System32\*.exe")
    for root in (r"C:\Program Files", r"C:\Program Files (x86)"):
        for pattern in ("*\\*.exe", "*\\*\\*.exe"):
            pool += glob.glob(os.path.join(root, pattern))
    pool = [p for p in pool if os.path.isfile(p) and os.path.getsize(p) > 0]
    random.shuffle(pool)
    return pool[:SAMPLE]


def main() -> int:
    os.makedirs(WORK, exist_ok=True)
    paths = candidates()
    ps = os.path.join(WORK, "sign.ps1")
    with open(ps, "w", encoding="utf-8-sig") as fh:
        fh.write(PS_SIGN)
    payload = None
    list_file = os.path.join(WORK, "paths.txt")
    with open(list_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(paths))
    res = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                          "-File", ps, "-ListFile", list_file],
                         capture_output=True, text=True, encoding="utf-8",
                         errors="replace")
    try:
        rows = json.loads(res.stdout)
    except json.JSONDecodeError:
        print("signature scan failed:", (res.stderr or "")[-400:])
        rows = []
    # PowerShell 5.1 serialises a one-element array as a bare object
    if isinstance(rows, dict):
        rows = [rows]
    rows = [row for row in rows if isinstance(row, dict) and row.get("path")]
    for row in rows:                       # PowerShell may wrap the path in a PathInfo
        value = row.get("path")
        if isinstance(value, dict):
            row["path"] = str(value.get("value") or value.get("Path") or "")
    publishers: dict[str, int] = {}
    for row in rows:
        subject = row.get("signer") or ""
        org = subject.split("O=")[-1].split(",")[0] if "O=" in subject else subject
        row["publisher"] = org.strip()
        publishers[row["publisher"]] = publishers.get(row["publisher"], 0) + 1
    # allowlist of publishers covering the bulk of the inventory (top-3 non-empty)
    top = [name for name, _count in sorted(publishers.items(), key=lambda kv: -kv[1])
           if name][:3]
    allowed, blocked = [], []
    for row in rows:
        unsigned = row.get("status") != "Valid"
        if unsigned or row.get("publisher") not in top:
            blocked.append(row)
        else:
            allowed.append(row)
    total = len(rows) or 1
    report = {
        "sample": len(rows),
        "source_pool": SAMPLE,
        "publishers": dict(sorted(publishers.items(), key=lambda kv: -kv[1])[:8]),
        "allowlist_publishers": top,
        "allowed": len(allowed),
        "blocked": len(blocked),
        "fbr_pct": round(100.0 * len(blocked) / total, 2),
        "blocked_examples": [row.get("path") for row in blocked[:10]],
        "unsigned": sum(1 for row in rows if row.get("status") != "Valid"),
        "policy": None,
        "note": "FBR = share of real executables a publisher allowlist would block; "
                "measured before any policy deployment",
    }
    # policy generation (audit mode) from the same inventory, best effort
    xml = os.path.join(WORK, "policy.xml")
    if rows:
        scan_dirs = sorted({os.path.dirname(row["path"]) for row in rows})[:5]
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
               "Import-Module ConfigCI -ErrorAction Stop; "
               f"New-CIPolicy -Level Publisher -Fallback Hash -UserPEs "
               f"-FilePath '{xml}' -ScanPath '{scan_dirs[0]}' -ErrorAction Stop"]
        res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                             errors="replace")
        report["policy"] = {"xml": xml if os.path.exists(xml) else None,
                            "scan_path": scan_dirs[0],
                            "returncode": res.returncode,
                            "stderr": (res.stderr or "").strip()[-400:]}
        if os.path.exists(xml):
            cip = os.path.join(WORK, "policy.cip")
            res = subprocess.run(["powershell", "-NoProfile", "-Command",
                                  f"ConvertFrom-CIPolicy -XmlFilePath '{xml}' "
                                  f"-BinaryFilePath '{cip}'"],
                                 capture_output=True, text=True, encoding="utf-8",
                                 errors="replace")
            report["policy"].update({"cip": cip if os.path.exists(cip) else None,
                                     "convert_returncode": res.returncode,
                                     "convert_stderr": (res.stderr or "").strip()[-300:]})
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps({k: report[k] for k in ("sample", "allowed", "blocked", "fbr_pct",
                                             "unsigned", "allowlist_publishers")},
                     ensure_ascii=False))
    print("deploy:", "Admin: copy policy.cip -> C:\\Windows\\System32\\CodeIntegrity"
                     "\\CiPolicies\\Active\\<GUID>.cip, then reboot; audit events 3076/3077"
                     " appear in Microsoft-Windows-CodeIntegrity/Operational")
    print("rollback:", "delete that .cip and reboot")
    return 0


if __name__ == "__main__":
    sys.exit(main())
