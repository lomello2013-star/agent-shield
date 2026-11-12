"""Record the native-crash finding for F11 in the roadmap (still open)."""

import io

PATH = "docs/fix-roadmap.md"
text = io.open(PATH, encoding="utf-8").read()

old = ("| F11 | ~~soak 5 мин~~ → **900 с ok** (179 510 событий, 0 потерь, плато), но "
       "**1800 с завис на t≈1152 с** (222 231 событие, причина не установлена; в soak "
       "добавлен дамп стеков) → R1/R4 **не подтверждены**; 7-дневный прогон требует "
       "разрешения на scheduled task")
new = ("| F11 | ~~soak 5 мин~~ → **900 с ok**, но длинные прогоны падают **нативным "
       "access violation (0xC0000005)**: t≈479 с в 1800-с прогоне, 180 с в smoke; "
       "health() и sampler как единственная причина исключены; добавлены faulthandler, "
       "дампы стеков и защита regex-пути → **R1/R4 не подтверждены**, дефект открыт; "
       "7-дневный прогон требует разрешения на scheduled task")
if old not in text:
    raise SystemExit("F11 anchor not found")
text = text.replace(old, new, 1)
io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("F11 updated:", "0xC0000005" in text)
