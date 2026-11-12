"""Line-wise repair of double-encoded Cyrillic (handles cp1251 'undefined' bytes).

Usage: python scripts/repair_text.py <path> [<path> ...]

A line is repaired only when re-encoding+decoding yields *more* Cyrillic text, so
correct lines are left untouched.
"""

import io
import sys


def to_bytes(text: str) -> bytes:
    out = bytearray()
    for ch in text:
        code = ord(ch)
        if code < 0xA0:
            out.append(code)
        else:
            out.extend(ch.encode("cp1251"))
    return bytes(out)


def cyrillic_count(text: str) -> int:
    return sum(1 for ch in text if "\u0400" <= ch <= "\u04FF")


def repair(path: str) -> tuple[int, int]:
    lines = io.open(path, encoding="utf-8-sig").read().split("\n")
    fixed, repaired, failed = [], 0, 0
    for line in lines:
        try:
            candidate = to_bytes(line).decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            fixed.append(line)
            continue
        if candidate != line and len(candidate) < len(line) and cyrillic_count(candidate) > 0:
            fixed.append(candidate)
            repaired += 1
        else:
            fixed.append(line)
    io.open(path, "w", encoding="utf-8", newline="\n").write("\n".join(fixed))
    return repaired, failed


if __name__ == "__main__":
    for target in sys.argv[1:]:
        repaired, _ = repair(target)
        print(f"{target}: repaired_lines={repaired}")
