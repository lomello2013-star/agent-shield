"""Mark F17–F20 in the roadmap with their measured outcome."""

import io

PATH = "docs/fix-roadmap.md"
text = io.open(PATH, encoding="utf-8").read()

repl = {
    "| F17 | 21/53 DEVLOG-записей неполные по полям §8 (раскрыто, но не закрыто)":
        "| F17 | ~~21/53 неполные~~ → аудит создан: **58 записей, 39 полных (67,2 %), "
        "19 legacy** раскрыты списком ([devlog-audit.md](devlog-audit.md))",
    "| F18 | Правила 28, но 10 платформо-независимых — риск кросс-платформенных срабатываний":
        "| F18 | ~~10 без платформы~~ → **5**, все в белом списке с обоснованием; "
        "2 Linux-правила привязаны к linux, есть регрессионный тест",
    "| F19 | Rust-порт (D2: Python 3.12 stdlib) отложен":
        "| F19 | ~~отложен~~ → контракт готов: 12 модулей → 12 типов, критерий приёмки — "
        "артефакты ±допуск ([rust-port-contract.md](rust-port-contract.md)); код ждёт блокер E",
    "| F20 | `coverage-matrix.md` / `t1055-coverage.md` генерируются, но не все — одним скриптом":
        "| F20 | ~~не одним скриптом~~ → `scripts/gen_docs.py` (4 шага) + шаг `gen_docs` в регрессии",
}
for old, new in repl.items():
    if old not in text:
        print("MISSING:", old[:60])
        continue
    text = text.replace(old, new, 1)

header_old = "> **Статус выполнения:** F01–F07, F10, F14–F16 — ✅ сделано"
header_new = "> **Статус выполнения:** F01–F07, F10, F14–F18, F20 — ✅ сделано; F19 — контракт (код ждёт E)"
if header_old in text:
    text = text.replace(header_old, header_new, 1)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("header:", header_new in text)
print("F17 updated:", "devlog-audit.md" in text)
