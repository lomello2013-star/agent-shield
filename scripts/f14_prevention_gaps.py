"""F14: close the prevention gaps T1070 / T1562 / T1041.

The rules existed but were detect-only, so the coverage matrix reported three
prevention gaps. They are switched to prevention-capable (reversible containment:
suspend the acting process / stop the transfer), and the event-log rule is raised to
`high` so the policy gate actually acts on it (medium is observe-only).
"""

import io
import json

PATH = "rules/base.json"
data = json.loads(io.open(PATH, encoding="utf-8-sig").read())
changed = []
for rule in data["rules"]:
    if rule["id"] in ("WIN-LOG-CLEAR-008", "LINUX-AUDIT-TAMPER-103",
                      "WIN-DEFENDER-TAMPER-009", "NET-EXFIL-LARGE-017"):
        rule["prevention"] = True
        if rule["id"] == "WIN-LOG-CLEAR-008":
            rule["severity"] = "high"           # medium is observe-only in the gate
        changed.append(rule["id"])
io.open(PATH, "w", encoding="utf-8", newline="\n").write(
    json.dumps(data, indent=2, ensure_ascii=False) + "\n")
print("updated:", changed)
print("prevention rules:", sum(1 for r in data["rules"] if r["prevention"]))
