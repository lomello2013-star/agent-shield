"""Update roadmap rows for F12 (and note F12b as open)."""

import io

PATH = "docs/fix-roadmap.md"
text = io.open(PATH, encoding="utf-8").read()

old = "| F12 | E8: нет 7-дневного поведенческого прогона → 0,85 @≤1 алерт/2 нед"
new = ("| F12 | ~~нет поведенческого прогона~~ → гарнитура 14 суток + 8 сценариев: "
       "**TPR 8/8 (1,0)**, benign-алертов **0**; но оповещён только **1 из 8** — "
       "бюджет 1/14 дней исчерпывается первым же алертом "
       "([f12_behavioral.json](../artifacts/f12_behavioral.json)); открыт **F12b**: "
       "критические вердикты должны обходить бюджет оповещений")
if old not in text:
    raise SystemExit("F12 anchor not found")
text = text.replace(old, new, 1)

header_old = "> **Статус выполнения:** F01–F07, F09, F10, F14–F18, F20 — ✅ сделано"
header_new = "> **Статус выполнения:** F01–F07, F09, F10, F12, F14–F18, F20 — ✅ сделано"
if header_old in text:
    text = text.replace(header_old, header_new, 1)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("F12 row:", "TPR 8/8" in text, "| header:", "F12, F14" in text)
