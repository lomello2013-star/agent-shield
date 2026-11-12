"""Refresh the compliance table with the post-fix measurements (2026-11-13)."""

import io

PATH = "docs/compliance-table.md"
text = io.open(PATH, encoding="utf-8").read()
before = text

replacements = [
    ("обнаружение **100 %** (18/18), предотвращение **83,33 %** (15/18)",
     "обнаружение **100 %** (18/18), предотвращение **100 %** (18/18)"),
    ("| R1 | доступность ≥99,5 % | ⚠️ soak 5 мин: 59 521 событие, RSS-плато, 0 потерь | Многочасового прогона нет — 99,5 % за месяц не доказаны |",
     "| R1 | доступность ≥99,5 % | ⛔ длинные прогоны падают нативно (**0xC0000005**); 900 с — ок, 1800 с и серии — падения | Дефект открыт (dev-report §14); R1 не подтверждена |"),
    ("| R4 | ≥99,9 % сессий без падений | ⚠️ 20/20 в proxy-модели | Реальных длинных сессий не было |",
     "| R4 | ≥99,9 % сессий без падений | ⛔ та же причина: нативный краш на длинных прогонах | Пока дефект открыт, метрику нельзя считать измеренной |"),
]

applied = 0
for old, new in replacements:
    if old in text:
        text = text.replace(old, new, 1)
        applied += 1

# E9 / E8 rows: replace whole lines by matching their prefix
lines = text.splitlines()
for index, line in enumerate(lines):
    if line.startswith("| E9 | PPV"):
        lines[index] = ("| E9 | PPV ≥50 % при prevalence 1/1000 | ✅ **56,4 %** при 0,05 % FPR "
                        "(TPR 0,672), порог алерта **0,8937**; при 1 % FPR PPV 8,3 % | "
                        "Цель достигается только на ужесточённом пороге; две трети "
                        "malicious при этом не алертят (только наблюдение) |")
        applied += 1
    elif line.startswith("| E8 |"):
        lines[index] = ("| E8 | ≥0,85 @≤1 алерт/2 нед | ⚠️ гарнитура 14 суток: TPR **8/8**, "
                        "benign-алертов **0**, оповещено 3/8 после F12b | Это размеченная "
                        "гарнитура, не пилот; 7-дневный прогон требует парка |")
        applied += 1
text = "\n".join(lines) + "\n"

text = text.replace(
    "- **Не достигнуто по существу:** E7 (0,6724 против 0,95), E12/E1 (46 % против <0,1 %), "
    "R1/R4 (минуты против суток), E9 (39,99 % против 50 %).",
    "- **Не достигнуто по существу:** E7 (0,6724 против 0,95 — потолок статики подтверждён), "
    "E12 (13,3 % FBR на held-out против <0,1 %), R1/R4 (нативный краш на длинных прогонах), "
    "E1/E2–E6 (нет red-team), E8 (гарнитура, не пилот).", 1)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("replacements applied:", applied)
print("changed:", text != before)
