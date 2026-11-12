"""Wire the native crash probe into the soak (opt-in via AIDF_NATIVE_PROBE=1)."""

import io

PATH = "scripts/soak_daemon.py"
text = io.open(PATH, encoding="utf-8").read()

anchor = '''def install_stack_dump() -> None:'''
helper = '''def install_native_probe() -> None:
    """Opt-in: resolve a faulting address to its module (see scripts/native_crash_probe.py)."""
    if os.environ.get("AIDF_NATIVE_PROBE") != "1":
        return
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import native_crash_probe
    native_crash_probe.install()


'''
if "install_native_probe" not in text:
    text = text.replace(anchor, helper + anchor, 1)
    text = text.replace("    install_stack_dump()\n",
                        "    install_stack_dump()\n    install_native_probe()\n", 1)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("probe wired:", "install_native_probe()" in text)
