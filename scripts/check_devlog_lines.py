import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
text = (ROOT / "DEVLOG.md").read_text(encoding="utf-8")
for number in (3, 14, 36):
    line = text.splitlines()[number - 1]
    print("LINE", number)
    print("  orig:", line.encode("unicode_escape").decode()[:120])
    try:
        cand = line.encode("cp1251").decode("utf-8")
        print("  cand:", cand.encode("unicode_escape").decode()[:120])
    except Exception as exc:
        print("  cand: error", type(exc).__name__)
