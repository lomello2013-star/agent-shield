"""Update the F11 roadmap row with the CPython-level conclusion."""

import io

PATH = "docs/fix-roadmap.md"
text = io.open(PATH, encoding="utf-8").read()

start = text.find("| F11 |")
if start < 0:
    raise SystemExit("F11 row not found")
end = text.find("\n", start)
new_row = ("| F11 | длинные прогоны падают нативно (**0xC0000005**). Нативный пробник показал: "
           "fault **в python312.dll**, стабильно в одной области (**offset 0x278B44 и "
           "0x278B57**, 19 байт разницы), битые адреса `0x4120`, `0x10000006F`. Контроли "
           "600 с: baseline / no_faulthandler / no_rules — чисто, **single_thread — упал** "
           "→ зависимость от диагностики, regex и sampler-потока не подтверждена. Меры: "
           "супервизор (перезапуск ~0,29 с) + lifecycle-записи в аудите. **R1/R4 не "
           "подтверждены** до смены интерпретатора; нужен апгрейд Python (вне прав агента) |")
text = text[:start] + new_row + text[end:]
io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("F11 updated:", "python312.dll" in text)
