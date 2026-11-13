"""Guard against text corruption (double-encoded Cyrillic) in the repository.

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
        if candidate != line and sum(1 for ch in candidate if "\u0400" <= ch <= "\u04FF") > 2:
            bad.append(number)
    return bad


def test_all_text_files_are_not_double_encoded():
    """One test for the whole tree: the test *count* must not drift with file count."""
    problems: list[str] = []
    checked = 0
    for path in _files():
        checked += 1
        raw = path.read_bytes()
        if path.suffix == ".py" and raw.startswith(b"\xef\xbb\xbf"):
            problems.append(f"{path.relative_to(ROOT)}: starts with a UTF-8 BOM")
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            problems.append(f"{path.relative_to(ROOT)}: not valid UTF-8 ({exc})")
            continue
        if "\ufffd" in text:
            problems.append(f"{path.relative_to(ROOT)}: contains replacement characters")
        bad = double_encoded_lines(text)
        if bad:
            problems.append(f"{path.relative_to(ROOT)}: double-encoded lines {bad[:5]}")
    assert checked > 50, "the glob set matched suspiciously few files"
    assert not problems, "text problems: " + "; ".join(problems[:8])


def test_detector_recognises_known_mojibake():
    sample = "\u0421\u0442\u0430\u0442\u0443\u0441".encode("utf-8").decode("cp1251")
    assert double_encoded_lines(sample) == [1]
    assert double_encoded_lines("correct text") == []
