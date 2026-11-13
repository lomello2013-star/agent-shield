"""Update the F11 roadmap row: 6 h clean on 3.12.9, 24 h run in a scheduled task."""

import io

PATH = "docs/fix-roadmap.md"
text = io.open(PATH, encoding="utf-8").read()

start = text.find("| F11 |")
if start < 0:
    raise SystemExit("F11 row not found")
end = text.find("\n", start)
new_row = ("| F11 | длинные прогоны падали нативно (**0xC0000005** из `python312.dll`, "
           "offset 0x278B44…0x278B57). Интерпретатор обновлён **3.12.8 → 3.12.9**; "
           "шестичасовое плечо на падающем профиле: **0 падений, доступность 100 %, "
           "92 418 записей аудита, chain ok** ([soak_6h_2026-11-13.json](../artifacts/soak_6h_2026-11-13.json)). "
           "Суточный прогон исполняется задачей планировщика `AIDF-Soak24` → **R1/R4** "
           "будут подтверждены только при `window_s ≈ 86400` |")
text = text[:start] + new_row + text[end:]
io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("F11 updated:", "3.12.9" in text and "AIDF-Soak24" in text)
