"""Diagnostic switch: skip manifest verification inside health().

The crash is time-correlated (~479.5 s in four different runs), which smells like an
accumulated-state threshold rather than a race. `Daemon.health()` re-hashes every file in
the data directory on *every* call (every 2 s), so by ~480 s it is hashing a ~100 MB audit
log repeatedly. This switch isolates that path.
"""

import io

PATH = "scripts/soak_daemon.py"
text = io.open(PATH, encoding="utf-8").read()

old = '''    d = Daemon(os.path.join(tmp, "daemon"), config=cfg, host=HOST,
               serve_http=False, log_fsync_every=64)'''
new = '''    d = Daemon(os.path.join(tmp, "daemon"), config=cfg, host=HOST,
               serve_http=False, log_fsync_every=64)
    if os.environ.get("AIDF_NO_MANIFEST") == "1":
        # diagnostic: health() no longer re-hashes the whole data directory
        d.manifest.verify = lambda *a, **k: {"ok": True, "files": {}, "checked": 0}'''
if old not in text:
    raise SystemExit("daemon anchor not found")
text = text.replace(old, new, 1)
io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("flag added:", "AIDF_NO_MANIFEST" in text)
