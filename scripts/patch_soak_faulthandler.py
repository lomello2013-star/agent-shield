"""Make a hung soak diagnosable: dump all thread stacks periodically to a file."""

import io

PATH = "scripts/soak_daemon.py"
text = io.open(PATH, encoding="utf-8").read()

if "import faulthandler" not in text:
    text = text.replace("import json\n", "import faulthandler\nimport json\n", 1)

if "dump_traceback_later" not in text:
    hook = '''def install_stack_dump() -> None:
    """If the run stalls, keep writing stack traces so the hang is diagnosable."""
    path = os.path.join(os.path.dirname(REPORT), "_stdout", "soak_stacks.txt")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fh = open(path, "a", encoding="utf-8", buffering=1)
    faulthandler.dump_traceback_later(120, repeat=True, file=fh)
    return None


def main() -> None:
    install_stack_dump()
'''
    text = text.replace("def main() -> None:\n", hook, 1)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("faulthandler:", "faulthandler" in text, "| hook:", "install_stack_dump" in text)
