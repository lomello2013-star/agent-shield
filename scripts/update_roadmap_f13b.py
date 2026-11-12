"""Update the F13 roadmap row using its actual text (E1/E2/... form)."""

import io

PATH = "docs/fix-roadmap.md"
text = io.open(PATH, encoding="utf-8").read()

old = "| F13 | E1/E2/E3/E4/E5/E6 не измерялись (нет red-team наборов)"
new = ("| F13 | ~~E1–E6 не измерялись~~ → гарнитура **10 сценариев**: E1/E2 2/2, "
       "E3/E4 5/5, E5 3/3 — **detect 10/10, prevent 10/10**; **E6 не измерима** без "
       "ядерной видимости ([f13_scenarios.json](../artifacts/f13_scenarios.json))")
if old not in text:
    raise SystemExit("F13 anchor not found")
text = text.replace(old, new, 1)
io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("updated:", "detect 10/10" in text)
