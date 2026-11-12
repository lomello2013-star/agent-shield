"""Mark F12b as done in the roadmap and record the residual tradeoff."""

import io

PATH = "docs/fix-roadmap.md"
text = io.open(PATH, encoding="utf-8").read()

old = ("([f12_behavioral.json](../artifacts/f12_behavioral.json)); открыт **F12b**: "
       "критические вердикты должны обходить бюджет оповещений")
new = ("([f12_behavioral.json](../artifacts/f12_behavioral.json)); **F12b — сделано**: "
       "critical обходит бюджет, оповещено 3/8 вместо 1/8, high остаются в бюджете")
if old not in text:
    raise SystemExit("F12 row anchor not found")
text = text.replace(old, new, 1)

header_old = "> **Статус выполнения:** F01–F07, F09, F10, F12, F14–F18, F20 — ✅ сделано"
header_new = ("> **Статус выполнения:** F01–F07, F09, F10, F12 + F12b, F14–F18, F20 — "
              "✅ сделано")
if header_old in text:
    text = text.replace(header_old, header_new, 1)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("F12b noted:", "F12b — сделано" in text)
