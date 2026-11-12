"""Mark F10 as measured (not met) in the roadmap, with the real numbers."""

import io

PATH = "docs/fix-roadmap.md"
text = io.open(PATH, encoding="utf-8").read()

old = ("| F10 | E12: false block **46 %** (политика A) → <0,1 % "
       "([stage2_report.json](../artifacts/stage2_report.json))")
new = ("| F10 | ~~E12: false block **46 %** → <0,1 %~~ → измерено честно на отложенной "
       "выборке: **13,3 % FBR** у звучащей политики (цель 10 %), покрытие 86,7 %; "
       "0 % достижим только разрешением `AppData` — **отклонено** "
       "([stage2_report.json](../artifacts/stage2_report.json))")
if old not in text:
    raise SystemExit("F10 row anchor not found")
text = text.replace(old, new, 1)

header_old = "> **Статус выполнения:** F01–F07 и F14–F16 — ✅ сделано"
header_new = "> **Статус выполнения:** F01–F07, F10, F14–F16 — ✅ сделано"
if header_old in text:
    text = text.replace(header_old, header_new, 1)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("F10 row updated:", "13,3 % FBR" in text)
print("header updated:", "F10, F14" in text)
