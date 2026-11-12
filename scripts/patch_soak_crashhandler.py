"""Enable faulthandler on the soak process so the native crash leaves a C-level stack."""

import io

PATH = "scripts/soak_daemon.py"
text = io.open(PATH, encoding="utf-8").read()

if "faulthandler.enable" not in text:
    old = '''    fh = open(path, "a", encoding="utf-8", buffering=1)
    faulthandler.dump_traceback_later(120, repeat=True, file=fh)
    return None'''
    new = '''    fh = open(path, "a", encoding="utf-8", buffering=1)
    # enable() installs the fault handler: an access violation then prints the Python
    # stack at the moment of the crash, not only on timeouts.
    faulthandler.enable(file=fh, all_threads=True)
    faulthandler.dump_traceback_later(120, repeat=True, file=fh)
    return None'''
    if old not in text:
        raise SystemExit("anchor not found")
    text = text.replace(old, new, 1)
io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("enable():", "faulthandler.enable" in text)
