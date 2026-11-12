"""Record the F11 status (partial: 900 s ok, 1800 s hang under investigation)."""

import io

PATH = "docs/fix-roadmap.md"
text = io.open(PATH, encoding="utf-8").read()

old = ("| F11 | ~~soak 5 мин~~ → **15 мин**: 179 510 событий, 0 потерь, tick p95 1,78 мс, "
       "RSS-плато, +1,44 %/60 с; суточного прогона нет, 7-дневный требует разрешения на "
       "scheduled task")
new = ("| F11 | ~~soak 5 мин~~ → **900 с ok** (179 510 событий, 0 потерь, плато), но "
       "**1800 с завис на t≈1152 с** (222 231 событие, причина не установлена; в soak "
       "добавлен дамп стеков) → R1/R4 **не подтверждены**; 7-дневный прогон требует "
       "разрешения на scheduled task")
if old not in text:
    raise SystemExit("F11 anchor not found")
text = text.replace(old, new, 1)
io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("F11 updated:", "завис на t≈1152" in text)
