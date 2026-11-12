import io
import json

PATH = "rules/base.json"
data = json.loads(io.open(PATH, encoding="utf-8-sig").read())
for rule in data["rules"]:
    if rule["id"] == "LINUX-EXEC-CORR-110":
        req = rule["correlate"]["require"][1]
        req["platform_data.provenance_known"] = True
io.open(PATH, "w", encoding="utf-8", newline="\n").write(
    json.dumps(data, indent=2, ensure_ascii=False) + "\n")
rule = next(r for r in data["rules"] if r["id"] == "LINUX-EXEC-CORR-110")
print("110 second requirement:", rule["correlate"]["require"][1])
