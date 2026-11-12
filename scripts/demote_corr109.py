import io
import json

PATH = "rules/base.json"
data = json.loads(io.open(PATH, encoding="utf-8-sig").read())
changed = []
for rule in data["rules"]:
    if rule["id"] == "LINUX-EXEC-CORR-109":
        rule["severity"] = "low"
        rule["title"] = ("PROT_EXEC after a cross-process write in the same process "
                         "tree (signal; alerting version is CORR-110)")
        changed.append(rule["id"])
io.open(PATH, "w", encoding="utf-8", newline="\n").write(
    json.dumps(data, indent=2, ensure_ascii=False) + "\n")
print("demoted:", changed, "total rules:", len(data["rules"]))
