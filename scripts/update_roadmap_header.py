"""Refresh the roadmap status header to the current state."""

import io
import re

PATH = "docs/fix-roadmap.md"
text = io.open(PATH, encoding="utf-8").read()
new_line = ("> **Статус выполнения:** F01–F10, F12–F18, F20 — ✅ сделано (F08 — потолок E7 "
            "измерен, F13 — гарнитура); F11 — 15 мин из суток; E6/E7 недостигнуты по "
            "измерению; F19 — контракт (код ждёт E).")
text = re.sub(r"^> \*\*Статус выполнения:\*\*.*$", new_line, text, count=1, flags=re.M)
io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("header ok:", new_line in text)
