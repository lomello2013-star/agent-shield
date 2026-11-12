import io
import re

text = io.open("artifacts/_stdout/soak_stacks.txt", encoding="utf-8", errors="replace").read()
marks = [m.start() for m in re.finditer("Windows fatal exception", text)]
print("fatal markers:", len(marks))
if marks:
    start = marks[-1]
    print(text[start:start + 1500])
