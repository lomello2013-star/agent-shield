"""Make step_immutable text ASCII-only and run the encoding guard line-wise."""

import io
import re

PATH = "scripts/run_all.py"
text = io.open(PATH, encoding="utf-8").read()
text = re.sub(r's\.detail = f"fingerprint=\{POLICY_FINGERPRINT\[:12\]\}[^"]*"',
              's.detail = f"fingerprint={POLICY_FINGERPRINT[:12]}"', text)
io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)

# rebuild the guard so one unencodable line cannot mask a corrupted file
GUARD = "tests/test_text_encoding.py"
guard = '''"""Guard against text corruption (double-encoded Cyrillic) in the repository.

PowerShell's ANSI round-trip double-encoded files repeatedly during this project.
A double-encoded Russian text is valid UTF-8, but re-encoding it to cp1251 and
decoding as UTF-8 recovers readable Russian. The check is per line, so a line with
a character cp1251 cannot represent (e.g. an arrow) cannot mask a corrupted file.
"""

import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

TEXT_GLOBS = (
    "*.md",
    "docs/*.md",
    "core/*.py",
    "schemas/**/*.py",
    "scripts/*.py",
    "tests/*.py",
    "rules/*.json",
    "pyproject.toml",
)


def _files():
    seen = set()
    for pattern in TEXT_GLOBS:
        for path in ROOT.glob(pattern):
            if (path.is_file() and path not in seen
                    and path.name != "test_text_encoding.py"):
                seen.add(path)
                yield path


def double_encoded_lines(text: str) -> list[int]:
    """Return 1-based line numbers that look double-encoded."""
    bad: list[int] = []
    for number, line in enumerate(text.splitlines(), start=1):
        try:
            candidate = line.encode("cp1251").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            continue
        if candidate != line and sum(1 for ch in candidate if "\\u0400" <= ch <= "\\u04FF") > 2:
            bad.append(number)
    return bad


@pytest.mark.parametrize("path", list(_files()), ids=lambda p: str(p.relative_to(ROOT)))
def test_text_file_is_not_double_encoded(path):
    text = path.read_text(encoding="utf-8")
    assert "\\ufffd" not in text, f"{path} contains replacement characters"
    bad = double_encoded_lines(text)
    assert not bad, f"{path}: double-encoded lines {bad[:5]}"


def test_detector_recognises_known_mojibake():
    sample = "\\u0421\\u0442\\u0430\\u0442\\u0443\\u0441".encode("utf-8").decode("cp1251")
    assert double_encoded_lines(sample) == [1]
    assert double_encoded_lines("correct text") == []
'''
io.open(GUARD, "w", encoding="utf-8", newline="\n").write(guard)
print("patched run_all and guard")
