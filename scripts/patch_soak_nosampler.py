"""Allow running the soak without the health/rss sampler, to localise the crash."""

import io

PATH = "scripts/soak_daemon.py"
text = io.open(PATH, encoding="utf-8").read()

old = "    def sampler() -> None:\n        while not sample_stop.is_set():"
new = ("    def sampler() -> None:\n"
       "        if os.environ.get(\"AIDF_NO_SAMPLER\") == \"1\":\n"
       "            return          # diagnostic mode: no health()/rss from this thread\n"
       "        while not sample_stop.is_set():")
if old not in text:
    raise SystemExit("sampler anchor not found")
text = text.replace(old, new, 1)
io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("flag added:", "AIDF_NO_SAMPLER" in text)
