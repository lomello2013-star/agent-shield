"""Update roadmap for F13 (harness for E1-E5, E6 unmeasurable)."""

import io

PATH = "docs/fix-roadmap.md"
text = io.open(PATH, encoding="utf-8").read()

old = ("| F13 | E1–E6 не измерялись (нет red-team наборов) | Промежуточно: размеченные "
       "сценарные гарнитуры на настоящих syscall/LSM-событиях (как T1055); полноценно — "
       "red-team 20 сценариев/ОС при VM | E3–E6 измерены на гарнитуре (с пометкой «не "
       "red-team»); цели пересчитаны честно | red-team — VM (B/C) |")
new = ("| F13 | ~~E1–E6 не измерялись~~ → гарнитура **10 сценариев**: E1/E2 2/2, "
       "E3/E4 5/5, E5 3/3 — **detect 10/10, prevent 10/10**; **E6 не измерима** без "
       "ядерной видимости ([f13_scenarios.json](../artifacts/f13_scenarios.json)) | "
       "Осталось: независимые сценарии (F13b) при VM — гарнитура авторская, это "
       "регрессия, не доказательство эффективности | detect/prevent на гарнитуре "
       "обязаны оставаться 100 % при изменениях правил | red-team — VM (B/C) |")
if old not in text:
    raise SystemExit("F13 anchor not found")
text = text.replace(old, new, 1)

header_old = ("> **Статус выполнения:** F01–F07, F09, F10, F12 + F12b, F14–F18, F20 — "
              "✅ сделано")
header_new = ("> **Статус выполнения:** F01–F07, F09, F10, F12–F18, F20 — ✅ сделано "
              "(F13 — гарнитура, E6 открыт)")
if header_old in text:
    text = text.replace(header_old, header_new, 1)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("F13 row:", "detect 10/10" in text, "| header:", "F12–F18" in text)
