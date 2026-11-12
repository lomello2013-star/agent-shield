import io

PATH = "DEVLOG.md"
text = io.open(PATH, encoding="utf-8").read()

def is_cjk(ch: str) -> bool:
    return ("\u4e00" <= ch <= "\u9fff"
            or "\u3040" <= ch <= "\u30ff"
            or "\u3400" <= ch <= "\u4dbf")

lines = text.splitlines(keepends=True)
changed = []
out = []
for index, line in enumerate(lines, 1):
    if any(is_cjk(ch) for ch in line):
        cleaned = "".join(ch for ch in line if not is_cjk(ch))
        changed.append(index)
        out.append(cleaned)
    else:
        out.append(line)
io.open(PATH, "w", encoding="utf-8", newline="\n").write("".join(out))
print("lines cleaned:", changed)
print("cjk left:", sum(1 for ch in "".join(out) if is_cjk(ch)))
