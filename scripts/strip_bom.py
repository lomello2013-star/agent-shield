import io
import sys

for path in sys.argv[1:]:
    text = io.open(path, encoding="utf-8-sig").read()
    io.open(path, "w", encoding="utf-8", newline="\n").write(text)
    print(f"{path}: BOM stripped, {len(text)} chars")
