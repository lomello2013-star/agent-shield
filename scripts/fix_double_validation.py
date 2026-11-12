"""F11 fix candidate: avoid validating the same event twice.

`Pipeline.submit_raw` normalizes (validates) an event, dumps it to a dict for the queue,
and `Pipeline.run_once` validates the dict again. The crash-time stack sits exactly in
that second validation (`Event.model_validate` ← `run_once`), and the second validation is
also pure overhead. The validated Event is now carried through the in-memory queue; the
spill path still serializes the dict, so replayed records are validated as before.
"""

import io

INGEST = "core/ingest.py"
text = io.open(INGEST, encoding="utf-8").read()

old_record = '''class IngestRecord:
    category: str
    key: str
    payload: dict
    priority: int
    count: int = 1'''
new_record = '''class IngestRecord:
    category: str
    key: str
    payload: dict
    priority: int
    count: int = 1
    # runtime-only: the already validated Event (not serialized, not replayed)
    event: Any = None'''
if old_record not in text:
    raise SystemExit("IngestRecord anchor not found")
text = text.replace(old_record, new_record, 1)

old_submit = '''    def submit(self, category: str, key: str = "", payload: dict | None = None,
               priority: int = P2_NOISE) -> bool:
        """Submit one event. Returns False only when it was irrecoverably lost."""
        if priority not in (P0_PROCESS, P1_FILE, P2_NOISE):
            raise ValueError(f"bad priority: {priority}")
        rec = IngestRecord(category=category, key=key, payload=payload or {}, priority=priority)'''
new_submit = '''    def submit(self, category: str, key: str = "", payload: dict | None = None,
               priority: int = P2_NOISE, event: Any = None) -> bool:
        """Submit one event. Returns False only when it was irrecoverably lost.

        `event` is the already validated Event; it lets the pipeline skip a redundant
        second validation on the hot path (see DEVLOG F11).
        """
        if priority not in (P0_PROCESS, P1_FILE, P2_NOISE):
            raise ValueError(f"bad priority: {priority}")
        rec = IngestRecord(category=category, key=key, payload=payload or {},
                           priority=priority, event=event)'''
if old_submit not in text:
    raise SystemExit("submit anchor not found")
text = text.replace(old_submit, new_submit, 1)

if "from typing import Any" not in text:
    text = text.replace("from typing import Callable", "from typing import Any, Callable", 1)

io.open(INGEST, "w", encoding="utf-8", newline="\n").write(text)

PIPELINE = "core/pipeline.py"
pipe = io.open(PIPELINE, encoding="utf-8").read()

old_pass = '''        return self.ingest.submit(
            category=event.category,
            key=key,
            payload=event.model_dump(mode="json"),
            priority=priority_for(event.category),
        )'''
new_pass = '''        return self.ingest.submit(
            category=event.category,
            key=key,
            payload=event.model_dump(mode="json"),
            priority=priority_for(event.category),
            event=event,
        )'''
if old_pass not in pipe:
    raise SystemExit("submit_raw anchor not found")
pipe = pipe.replace(old_pass, new_pass, 1)

old_drain = '''        for record in self.ingest.drain(max_events):
            event = Event.model_validate(record.payload)'''
new_drain = '''        for record in self.ingest.drain(max_events):
            # Live records carry the validated Event; spills are replayed as dicts.
            event = record.event if record.event is not None else Event.model_validate(record.payload)'''
if old_drain not in pipe:
    raise SystemExit("run_once anchor not found")
pipe = pipe.replace(old_drain, new_drain, 1)

io.open(PIPELINE, "w", encoding="utf-8", newline="\n").write(pipe)
print("ingest patched:", "event: Any = None" in text, "| pipeline patched:",
      "record.event" in pipe)
