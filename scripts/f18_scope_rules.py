"""F18: every rule must be explicitly scoped to a platform or justified as global."""

import io
import json

PATH = "rules/base.json"
data = json.loads(io.open(PATH, encoding="utf-8-sig").read())
changed = []
for rule in data["rules"]:
    rid = rule["id"]
    if rid.startswith("LINUX-") and not rule.get("correlate"):
        if rule["match"].get("platform") != "linux":
            rule["match"]["platform"] = "linux"
            changed.append(rid)
io.open(PATH, "w", encoding="utf-8", newline="\n").write(
    json.dumps(data, indent=2, ensure_ascii=False) + "\n")
print("scoped:", changed)
globals_ = [r["id"] for r in data["rules"]
            if "platform" not in r["match"] and not r.get("correlate")]
print("global rules (justified):", globals_)
