"""Record the F11 statistical picture after the last campaign."""

import io

PATH = "docs/fix-roadmap.md"
text = io.open(PATH, encoding="utf-8").read()

start = text.find("| F11 |")
if start < 0:
    raise SystemExit("F11 row not found")
end = text.find("\n", start)
new_row = ("| F11 | длинные прогоны падали нативно (**0xC0000005**, t≈118–479 с). Две "
           "гипотезы (двойная валидация, пересчёт манифеста) проверены и **отклонены**; "
           "внедрены: одна валидация на событие, кеш манифеста 30 с, закрытый дескриптор, "
           "VEH-пробник модуля. После этого — **0 падений в 12 прогонах** (8×180 с, "
           "1×600 с, 3×600 с), но два падения сразу после правок были → дефект **открыт**, "
           "R1/R4 не подтверждены |")
text = text[:start] + new_row + text[end:]
io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("F11 row updated:", "0 падений в 12 прогонах" in text)
