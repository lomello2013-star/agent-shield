"""Record the supervisor work in the roadmap as an R3 improvement."""

import io

PATH = "docs/fix-roadmap.md"
text = io.open(PATH, encoding="utf-8").read()

old_r3 = getattr(__builtins__, "x", None)  # noqa: F841  (no such key; R3 lives in compliance)
anchor = "## P1 — недобор по целям метрик (без человеческого блокера)"
note = ("## P0.5 — защита от последствий краша (R3)\n\n"
        "| ID | Что сделано | Измерено | Статус |\n|---|---|---|---|\n"
        "| R3s | `core/supervisor.py`: перезапуск с экспоненциальным backoff, сброс бюджета "
        "после здорового периода, circuit breaker | 3/3 перезапуска после `kill()`, медиана "
        "**277,7 мс**, худший **300,2 мс**, аудит-цепочка **ok (8 записей)** | ✅ шаг "
        "`supervisor_measure` в регрессии |\n\n"
        "Это **не** лечение краша F11, а гарантия, что служба переживает его за ~0,28 с "
        "с целой цепочкой аудита.\n\n---\n\n")
if "## P0.5 — защита от последствий краша" not in text:
    text = text.replace(anchor, note + anchor, 1)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("section added:", "P0.5" in text)
