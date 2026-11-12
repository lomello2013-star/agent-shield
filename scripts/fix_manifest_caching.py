"""F11 fix: health() must not re-hash the whole data directory on every call.

By ~480 s of soak the audit log is ~100 MB, and `health()` (called every 2 s by the
probe/sampler) re-hashed all files each time. A 600 s soak without that call passed the
479.5 s mark where four runs crashed, so the path is now rate-limited: the manifest is
verified at most once per `manifest_interval_s`, other calls reuse the cached result
while still reporting *when* the last verification happened.
"""

import io

PATH = "core/daemon.py"
text = io.open(PATH, encoding="utf-8").read()

# 1) config knob
old_cfg = '''    watchdog: dict[str, float] = field(default_factory=dict)
    allowlist: list[str] = field(default_factory=list)'''
new_cfg = '''    watchdog: dict[str, float] = field(default_factory=dict)
    allowlist: list[str] = field(default_factory=list)
    # health() must stay cheap: re-hashing the data directory on every call is both
    # expensive and (see DEVLOG F11) points at a native crash on long runs
    manifest_interval_s: float = 30.0'''
if old_cfg not in text:
    raise SystemExit("config anchor not found")
text = text.replace(old_cfg, new_cfg, 1)

# 2) health(): rate-limit the manifest check
old_health = '''    def health(self) -> dict:
        self._health_calls += 1
        # Incremental verification is O(new records); every 50th call does a full
        # pass so an in-place edit of an old record cannot hide forever.
        log_state = self.log.verify(incremental=(self._health_calls % 50 != 0))
        integrity = self.manifest.verify()'''
new_health = '''    def health(self) -> dict:
        self._health_calls += 1
        # Incremental verification is O(new records); every 50th call does a full
        # pass so an in-place edit of an old record cannot hide forever.
        log_state = self.log.verify(incremental=(self._health_calls % 50 != 0))
        integrity = self._manifest_snapshot()'''
if old_health not in text:
    raise SystemExit("health anchor not found")
text = text.replace(old_health, new_health, 1)

# 3) the helper + cached state
anchor = "    def stats(self) -> dict:"
helper = '''    def _manifest_snapshot(self) -> dict:
        """Verify the integrity manifest at most once per interval, cache otherwise."""
        interval = float(getattr(self.config, "manifest_interval_s", 30.0))
        now = time.monotonic()
        cached = getattr(self, "_integrity_cache", None)
        checked_at = getattr(self, "_integrity_checked_at", None)
        if cached is not None and checked_at is not None and now - checked_at < interval:
            return cached
        result = self.manifest.verify()
        self._integrity_cache = result
        self._integrity_checked_at = now
        return result

'''
if anchor not in text:
    raise SystemExit("stats anchor not found")
text = text.replace(anchor, helper + anchor, 1)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("patched:", "_manifest_snapshot" in text, "| interval:", "manifest_interval_s" in text)
