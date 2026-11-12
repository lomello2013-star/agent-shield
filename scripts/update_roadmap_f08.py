"""Update roadmap row F08 with the measured ceiling."""

import io

PATH = "docs/fix-roadmap.md"
text = io.open(PATH, encoding="utf-8").read()

old = "| F08 | E7: TPR **0,6724** @0,05 % FPR → 0,95"
new = ("| F08 | ~~E7: TPR 0,6724 @0,05 % FPR~~ → три приёма проверены на тех же данных: "
       "A 0,6724 (воспроизведение), B 0,6096 (глубже — хуже), C 0,6724 (hard-negative) "
       "→ **потолок статики подтверждён**, E7 недостижима без кросс-модальных данных "
       "([f08_tail.json](../artifacts/f08_tail.json))")
if old not in text:
    raise SystemExit("F08 anchor not found")
text = text.replace(old, new, 1)

header_old = ("> **Статус выполнения:** F01–F07, F09, F10, F12–F18, F20 — ✅ сделано "
              "(F13 — гарнитура, E6 открыт)")
header_new = ("> **Статус выполнения:** F01–F07, F08 (потолок измерен), F09, F10, "
              "F12–F18, F20 — ✅ сделано; E6/E7 остаются недостигнутыми по измерению")
if header_old in text:
    text = text.replace(header_old, header_new, 1)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("F08 row:", "потолок статики подтверждён" in text)
print("header:", "F08 (потолок измерен)" in text)
