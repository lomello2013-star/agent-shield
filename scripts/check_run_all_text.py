import io

text = io.open("scripts/run_all.py", encoding="utf-8").read()
lines = text.splitlines()
hits = [(i + 1, line) for i, line in enumerate(lines)
        if any("\u0400" <= ch <= "\u04FF" for ch in line)]
print("lines with cyrillic:", len(hits))
for i, line in hits[:6]:
    print(i, line.encode("unicode_escape").decode()[:150])
print("probe present:", "\u0421\u0442\u0430\u0442\u0443\u0441" in text)
