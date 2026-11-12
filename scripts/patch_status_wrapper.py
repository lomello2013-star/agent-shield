"""Replace write_status in run_all.py with a thin wrapper around scripts/status_text.py."""

import io

PATH = "scripts/run_all.py"
text = io.open(PATH, encoding="utf-8").read()

start = text.index("def write_status(")
end = text.index("def main()")
wrapper = (
    "def write_status(steps: list[Step], artifacts: dict[str, dict]) -> None:\n"
    "    sys.path.insert(0, os.path.join(HERE, \"scripts\"))\n"
    "    import status_text\n"
    "    content = status_text.render(steps, artifacts, datetime.now(timezone.utc), ART)\n"
    "    os.makedirs(os.path.dirname(STATUS_MD), exist_ok=True)\n"
    "    with open(STATUS_MD, \"w\", encoding=\"utf-8\") as fh:\n"
    "        fh.write(content)\n"
    "\n\n"
)
text = text[:start] + wrapper + text[end:]
io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("write_status replaced; bytes:", len(text))
