"""Update F11 roadmap row: hypothesis falsified, statistics campaign running."""

import io

PATH = "docs/fix-roadmap.md"
text = io.open(PATH, encoding="utf-8").read()

start = text.find("| F11 |")
if start < 0:
    raise SystemExit("F11 row not found")
end = text.find("\n", start)
new_row = ("| F11 | длинные прогоны падают нативно (**0xC0000005**): 1 из 4 в кампании "
           "600 с; гипотеза о двойной валидации **опровергнута** (падение повторилось "
           "после исправления), pydantic-стресс 9,94 млн валидаций без сбоев, бисекция "
           "6×240 с чистая; исправлена двойная валидация и утечка дескриптора; идёт "
           "кампания 6×600 с для оценки частоты → **R1/R4 не подтверждены** |")
text = text[:start] + new_row + text[end:]
io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("F11 row replaced:", "опровергнута" in text)
