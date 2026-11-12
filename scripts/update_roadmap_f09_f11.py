"""Update roadmap rows for F09 and F11 with measured outcomes."""

import io

PATH = "docs/fix-roadmap.md"
text = io.open(PATH, encoding="utf-8").read()

repl = {
    "| F09 | E9: PPV **7,94 %** @1 % FPR / **39,99 %** @0,1 % → 50 %":
        "| F09 | ~~E9: PPV 7,94 % @1 % / 39,99 % @0,1 %~~ → измерена кривая: **56,4 % при "
        "0,05 % FPR** (TPR 0,672); 41,8 % @0,1 %; порог алерта **0,8937** "
        "([f09_ppv_target.json](../artifacts/f09_ppv_target.json))",
    "| F11 | R1/R4: soak **5 мин**, плато, но +28 % RSS от холодного старта → нужно ≥99,5 % за месяц":
        "| F11 | ~~soak 5 мин~~ → **15 мин**: 179 510 событий, 0 потерь, tick p95 1,78 мс, "
        "RSS-плато, +1,44 %/60 с; суточного прогона нет, 7-дневный требует разрешения на "
        "scheduled task",
}
for old, new in repl.items():
    if old not in text:
        print("MISSING:", old[:70])
        continue
    text = text.replace(old, new, 1)

header_old = ("> **Статус выполнения:** F01–F07, F10, F14–F18, F20 — ✅ сделано; "
              "F19 — контракт (код ждёт E)")
header_new = ("> **Статус выполнения:** F01–F07, F09, F10, F14–F18, F20 — ✅ сделано; "
              "F11 — 15 мин из суток; F19 — контракт (код ждёт E)")
if header_old in text:
    text = text.replace(header_old, header_new, 1)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("F09 row:", "56,4 %" in text, "| F11 row:", "179 510" in text,
      "| header:", "F11 — 15 мин" in text)
