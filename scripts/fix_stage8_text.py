import io

PATH = "scripts/stage8_measure.py"
text = io.open(PATH, encoding="utf-8").read()
fixed = text.replace("\u0432\u0402\u201d", "-").replace("\u0432\u0402\u201c", "-")
io.open(PATH, "w", encoding="utf-8", newline="\n").write(fixed)
print("mojibake left:", "\u0432\u0402" in fixed)
print([l for l in fixed.splitlines() if "secrets/dev_keys" in l][:2])
