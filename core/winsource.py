"""Windows Event Log source that works **without elevation**.

Only logs a normal user can read are used (System, Defender/Operational). The
pipeline gets real OS records (e.g. 7045 service install) instead of synthetic
events. Querying goes through `wevtutil` (one process per poll) вЂ” acceptable for a
polling source; the measured cost is reported by the scripts that use it.

Security note: this source is *read-only*; nothing here changes the system.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Iterable

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
WEVTUTIL = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "wevtutil.exe")

# event_id -> (category, action, path field in EventData)
EVENT_SEMANTICS: dict[int, tuple[str, str, str]] = {
    7045: ("persistence.change", "service_create", "ImagePath"),
    7040: ("persistence.change", "service_change", "ImagePath"),
    7036: ("persistence.change", "service_state", "param1"),
    1102: ("log.tamper", "log_cleared", ""),
    104: ("log.tamper", "log_cleared", ""),
    # Defender/Operational: protection tampering vs plain detections are different
    5001: ("defender.tamper", "rtp_disabled", ""),
    5010: ("defender.tamper", "scan_disabled", ""),
    5012: ("defender.tamper", "rtp_disabled", ""),
    5007: ("defender.tamper", "config_change", ""),
    1116: ("malware.detected", "detected", ""),
    1117: ("malware.detected", "action_taken", ""),
    # Security log (opt-in win.security): scheduled task / user / process / log clear
    4698: ("persistence.change", "scheduled_task_create", ""),
    4720: ("persistence.change", "user_create", ""),
    4688: ("process.start", "start", "NewProcessName"),
    1102: ("log.tamper", "log_cleared", ""),
}

# Sysmon event_id -> (category, action, path field). Registered only for the
# sysmon provider so the same numeric IDs in System/Defender keep their meaning.
SYSMON_SEMANTICS: dict[int, tuple[str, str, str]] = {
    1: ("process.start", "start", "Image"),
    8: ("memory.access", "inject", "TargetImage"),
    10: ("process.access", "open_process", "TargetImage"),
    11: ("file.write", "create", "TargetFilename"),
    12: ("registry.change", "create", "TargetObject"),
    13: ("registry.change", "set", "TargetObject"),
    14: ("registry.change", "rename", "TargetObject"),
    19: ("persistence.change", "wmi_subscription", ""),
    20: ("persistence.change", "wmi_subscription", ""),
    21: ("persistence.change", "wmi_subscription", ""),
}


SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"


def channel_exists(log_name: str, wevtutil: str = WEVTUTIL) -> bool:
    """True when the event channel exists (Sysmon is an optional component)."""
    if not os.path.exists(wevtutil):
        return False
    try:
        completed = subprocess.run([wevtutil, "gl", log_name], capture_output=True,
                                   text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def _parse_pid(value: object) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def semantics_for(event_id: int, provider: str) -> tuple[str, str, str]:
    """Sysmon has its own event-ID namespace; other logs keep EVENT_SEMANTICS."""
    if provider == SYSMON_PROVIDER and event_id in SYSMON_SEMANTICS:
        return SYSMON_SEMANTICS[event_id]
    return EVENT_SEMANTICS.get(event_id, ("unknown", "event", ""))


@dataclass(frozen=True)
class EventLogRecord:
    record_id: int
    event_id: int
    time_created: str
    provider: str
    data: dict[str, str]

    def to_raw(self) -> dict:
        category, action, path_field = semantics_for(self.event_id, self.provider)
        data = dict(self.data)
        if self.event_id == 4688:
            process_id = _parse_pid(data.get("NewProcessId"))
            parent_id = _parse_pid(data.get("ProcessId"))
            image = data.get("NewProcessName", "")
        else:
            process_id = _parse_pid(data.get("SourceProcessId") or data.get("ProcessId")
                                    or data.get("ClientProcessId"))
            parent_id = _parse_pid(data.get("ParentProcessId"))
            image = data.get("SourceImage") or data.get("Image") or ""
        object_path = (data.get("TargetFilename") or data.get("TargetObject")
                       or data.get("TargetImage") or data.get("Destination") or "")
        if object_path.startswith("<"):
            object_path = ""               # e.g. Sysmon "<unknown process>"
        if self.event_id == 5007:
            # 5007 is mostly operational noise ("Diagnostics\..." etc.); classify it
            # against known tamper keys so benign churn does not become alerts.
            category, action, benign = classify_defender_change(
                data.get("Old Value", ""), data.get("New Value", ""))
            data["classification"] = "benign" if benign else "suspicious"
        path = data.get(path_field, "") if path_field else ""
        return {
            "category": category,
            "action": action,
            "path": path,
            "event_id": self.event_id,
            "provider": self.provider,
            "record_id": self.record_id,
            "ts": self.time_created,
            "process_id": process_id,
            "parent_id": parent_id,
            "image": image,
            "parent_image": data.get("ParentImage", ""),
            "object_path": object_path,
            "cmdline": data.get("CommandLine", ""),
            "data": data,
        }


# Defender configuration keys that mean "protection was weakened" (T1562).
DEFENDER_SUSPICIOUS_TOKENS: tuple[str, ...] = (
    "disablerealtimemonitoring", "disableioavprotection", "disablebehaviormonitoring",
    "disablescriptscanning", "disableantispyware", "disableantivirus",
    "exclusionpath", "exclusionextension", "exclusionprocess",
    "puaprotection", "tamperprotection", "disabletamperprotection",
    "enablecontrolledfolderaccess", "disablecoreservice",
)

# Cloud-telemetry policy keys: weakening them matters, but they oscillate on policy
# refresh (measured on this host), so they are recorded, not alerted.
DEFENDER_POLICY_TOKENS: tuple[str, ...] = (
    "spynetreporting", "submitsamplesconsent", "disableblockatfirstseen", "mapsreporting",
)

# Operational/diagnostic keys that change on every service start or platform update.
DEFENDER_BENIGN_PATTERNS: tuple[str, ...] = (
    "\\diagnostics\\", "isservicerunning", "initializingcomponentprogress",
    "platformrollbackmethod", "rolledbackplatformhealthdata", "lastconnected",
    "engineversion", "signatureversion", "productversion",
)


def classify_defender_change(old_value: str, new_value: str) -> tuple[str, str, bool]:
    """Return (category, action, benign) for a Defender 5007 config change."""
    text = f"{old_value} {new_value}".lower()
    if any(token in text for token in DEFENDER_SUSPICIOUS_TOKENS):
        return "defender.tamper", "config_tamper", False
    if any(token in text for token in DEFENDER_POLICY_TOKENS):
        return "config.change", "config_policy_weak", True
    if any(pattern in text for pattern in DEFENDER_BENIGN_PATTERNS):
        return "config.change", "config_benign", True
    # Unknown key: keep the FP budget safe, but make it visible in stats.
    return "config.change", "config_unclassified", True


def parse_events_xml(xml_text: str) -> list[EventLogRecord]:
    """Parse `wevtutil ... /f:xml` output into records.

    wevtutil emits a *sequence* of top-level ``<Event>`` elements (no ``<Events>``
    wrapper), so the payload is wrapped before parsing; an existing wrapper is kept.
    """
    import re
    text = xml_text.lstrip("\ufeff").strip()
    if not text:
        return []
    text = re.sub(r"<\?xml[^>]*\?>", "", text).strip()
    if not text.startswith("<Events"):
        text = f"<Events>{text}</Events>"
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"invalid event XML: {exc}") from exc
    records: list[EventLogRecord] = []
    for event in root.findall("e:Event", NS):
        system = event.find("e:System", NS)
        if system is None:
            continue
        event_id_text = system.findtext("e:EventID", default="", namespaces=NS)
        record_id_text = system.findtext("e:EventRecordID", default="", namespaces=NS)
        try:
            event_id = int(event_id_text)
            record_id = int(record_id_text)
        except ValueError:
            continue
        provider_el = system.find("e:Provider", NS)
        provider = provider_el.get("Name", "") if provider_el is not None else ""
        time_el = system.find("e:TimeCreated", NS)
        time_created = time_el.get("SystemTime", "") if time_el is not None else ""
        data: dict[str, str] = {}
        for node in event.findall(".//e:EventData/e:Data", NS):
            name = node.get("Name") or f"param{len(data) + 1}"
            data[name] = (node.text or "").strip()
        records.append(EventLogRecord(record_id=record_id, event_id=event_id,
                                      time_created=time_created, provider=provider,
                                      data=data))
    return records


@dataclass
class WindowsEventLogSource:
    log_name: str = "System"
    event_ids: tuple[int, ...] = (7045,)
    max_events: int = 50
    wevtutil: str = WEVTUTIL
    name: str = "win.eventlog"
    _last_record_id: int = 0
    calls: int = 0
    last_query_ms: float = 0.0

    def _xpath(self) -> str:
        ids = " or ".join(f"EventID={eid}" for eid in self.event_ids)
        return f"*[System[({ids})]]"

    def poll(self) -> list[EventLogRecord]:
        """Read events newer than the last seen record id."""
        import time
        if not os.path.exists(self.wevtutil):
            raise RuntimeError("wevtutil not available (not Windows?)")
        argv = [self.wevtutil, "qe", self.log_name, f"/q:{self._xpath()}",
                "/f:xml", f"/c:{self.max_events}", "/rd:true"]
        t0 = time.perf_counter()
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        self.last_query_ms = (time.perf_counter() - t0) * 1000
        self.calls += 1
        if completed.returncode not in (0, 1):      # 1 = no events
            raise RuntimeError(f"wevtutil failed: {completed.stderr.strip()[:200]}")
        records = parse_events_xml(completed.stdout)
        fresh = [r for r in records if r.record_id > self._last_record_id]
        if records:
            self._last_record_id = max(r.record_id for r in records)
        return sorted(fresh, key=lambda r: r.record_id)

    def stats(self) -> dict:
        return {"log": self.log_name, "event_ids": list(self.event_ids),
                "last_record_id": self._last_record_id, "calls": self.calls,
                "last_query_ms": round(self.last_query_ms, 3)}

