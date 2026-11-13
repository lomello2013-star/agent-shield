"""Lifecycle records in the audit chain: an unclean shutdown becomes visible.

After a native crash the process cannot write anything, so the *next* start has to tell
the story: every start records `daemon_start` (with pid and the chain position it
inherited) and every graceful stop records `daemon_stop`. A chain with a start and no
matching stop is therefore evidence of a crash — useful for forensics and for the
supervisor measurement.
"""

import io

PATH = "core/daemon.py"
text = io.open(PATH, encoding="utf-8").read()

old_start = '''    def start(self) -> None:
        if self._serve_http and self._httpd is None:'''
new_start = '''    def start(self) -> None:
        self._write_lifecycle("daemon_start")
        if self._serve_http and self._httpd is None:'''
if old_start not in text:
    raise SystemExit("start anchor not found")
text = text.replace(old_start, new_start, 1)

old_stop = '''    def stop(self) -> None:
        self._stop.set()'''
new_stop = '''    def _write_lifecycle(self, kind: str) -> None:
        """Record start/stop in the hash chain; failure here must not break startup."""
        try:
            inherited = getattr(self.log, "_verified_seq", 0)
            self.log.append(kind, {"pid": os.getpid(), "inherited_seq": inherited})
            self.log.flush()
        except Exception:            # audit is best-effort on lifecycle, not a blocker
            pass

    def stop(self) -> None:
        self._write_lifecycle("daemon_stop")
        self._stop.set()'''
if old_stop not in text:
    raise SystemExit("stop anchor not found")
text = text.replace(old_stop, new_stop, 1)

if "\nimport os\n" not in text:
    text = text.replace("\nimport time\n", "\nimport os\nimport time\n", 1)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("lifecycle:", text.count("_write_lifecycle"))
