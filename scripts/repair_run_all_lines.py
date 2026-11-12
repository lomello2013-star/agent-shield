"""Repair double-encoded Russian literals inside scripts/run_all.py (line-wise)."""

import io

PATH = "scripts/run_all.py"
lines = io.open(PATH, encoding="utf-8").read().split("\n")
fixed, repaired = [], 0
for line in lines:
    try:
        candidate = line.encode("cp1251").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        fixed.append(line)
        continue
    if candidate != line and sum(1 for ch in candidate if "\u0400" <= ch <= "\u04FF") > 2:
        fixed.append(candidate)
        repaired += 1
    else:
        fixed.append(line)

io.open(PATH, "w", encoding="utf-8", newline="\n").write("\n".join(fixed))
print("repaired lines:", repaired)
probe = "\u0421\u0442\u0430\u0442\u0443\u0441 \u043f\u0440\u043e\u0435\u043a\u0442\u0430"
print("has_correct_russian:", probe in "\n".join(fixed))
