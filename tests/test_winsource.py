import pytest

from core.normalize import HostContext, Normalizer
from core.winsource import EVENT_SEMANTICS, EventLogRecord, parse_events_xml

XML = """<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Service Control Manager"/>
    <EventID>7045</EventID>
    <EventRecordID>12345</EventRecordID>
    <TimeCreated SystemTime="2026-11-12T10:00:00.0000000Z"/>
  </System>
  <EventData>
    <Data Name="ServiceName">evil</Data>
    <Data Name="ImagePath">C:\\Temp\\evil.exe</Data>
    <Data Name="ServiceType">user mode service</Data>
    <Data Name="StartType">auto start</Data>
    <Data Name="AccountName">LocalSystem</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Service Control Manager"/>
    <EventID>7036</EventID>
    <EventRecordID>12346</EventRecordID>
    <TimeCreated SystemTime="2026-11-12T10:01:00.0000000Z"/>
  </System>
  <EventData>
    <Data Name="param1">Windows Update</Data>
    <Data Name="param2">running</Data>
  </EventData>
</Event>
</Events>"""

HOST = HostContext(host_id="h", os="windows", version="10.0.19045", arch="x64")


def test_parse_events_xml():
    records = parse_events_xml(XML)
    assert len(records) == 2
    first = records[0]
    assert first.event_id == 7045 and first.record_id == 12345
    assert first.provider == "Service Control Manager"
    assert first.data["ServiceName"] == "evil"
    assert first.time_created.startswith("2026-11-12T10:00")


def test_parse_returns_empty_for_empty_output():
    assert parse_events_xml("") == []
    assert parse_events_xml("   ") == []


def test_parse_accepts_concatenated_event_documents():
    """wevtutil emits back-to-back <Event> documents without a wrapper."""
    inline = ('<?xml version="1.0" encoding="utf-8"?>\n'
              '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
              '<System><Provider Name="p"/><EventID>7045</EventID>'
              '<EventRecordID>7</EventRecordID>'
              '<TimeCreated SystemTime="2026-11-12T10:00:00Z"/></System>'
              '<EventData><Data Name="ImagePath">C:\\x.exe</Data></EventData></Event>\n'
              '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
              '<System><Provider Name="p"/><EventID>7045</EventID>'
              '<EventRecordID>8</EventRecordID>'
              '<TimeCreated SystemTime="2026-11-12T10:01:00Z"/></System>'
              '<EventData><Data Name="ImagePath">C:\\y.exe</Data></EventData></Event>')
    records = parse_events_xml(inline)
    assert [r.record_id for r in records] == [7, 8]


def test_parse_rejects_broken_xml():
    with pytest.raises(ValueError):
        parse_events_xml("<Events>")


def test_to_raw_maps_service_install():
    record = parse_events_xml(XML)[0]
    raw = record.to_raw()
    assert raw["category"] == "persistence.change"
    assert raw["action"] == "service_create"
    assert raw["path"].endswith("evil.exe")
    assert raw["record_id"] == 12345


def test_to_raw_maps_unknown_event_safely():
    record = EventLogRecord(record_id=1, event_id=9999, time_created="t",
                            provider="p", data={})
    raw = record.to_raw()
    assert raw["category"] == "unknown" and raw["action"] == "event"


def test_semantics_table_covers_service_events():
    assert 7045 in EVENT_SEMANTICS and 7040 in EVENT_SEMANTICS
    assert 1102 in EVENT_SEMANTICS


def test_defender_tamper_ids_map_to_tamper_category():
    for event_id, action in ((5001, "rtp_disabled"), (5010, "scan_disabled"),
                             (5012, "rtp_disabled")):
        record = EventLogRecord(record_id=1, event_id=event_id, time_created="t",
                                provider="Defender", data={})
        raw = record.to_raw()
        assert raw["category"] == "defender.tamper"
        assert raw["action"] == action


def test_defender_cloud_policy_change_is_recorded_not_alerted():
    record = EventLogRecord(
        record_id=9, event_id=5007, time_created="t", provider="Defender",
        data={"Old Value": "SpyNet\\SpyNetReporting = 0x0",
              "New Value": "Policies\\...\\SpyNetReporting = 0x0"})
    raw = record.to_raw()
    assert raw["category"] == "config.change"
    assert raw["action"] == "config_policy_weak"


def test_defender_detections_are_not_tamper():
    for event_id in (1116, 1117):
        record = EventLogRecord(record_id=1, event_id=event_id, time_created="t",
                                provider="Defender", data={})
        assert record.to_raw()["category"] == "malware.detected"


# ------------------------------------------------ 5007 classification (noise control)
def test_benign_defender_diagnostics_is_not_tamper():
    record = EventLogRecord(
        record_id=1, event_id=5007, time_created="t", provider="Defender",
        data={"Old Value": "HKLM\\...\\Diagnostics\\InitializingComponentProgress = LoadingEngine",
              "New Value": "HKLM\\...\\Diagnostics\\InitializingComponentProgress = ServiceStartedSuccessfully"})
    raw = record.to_raw()
    assert raw["category"] == "config.change"
    assert raw["action"] == "config_benign"
    assert raw["data"]["classification"] == "benign"


def test_disabled_protection_is_tamper():
    record = EventLogRecord(
        record_id=2, event_id=5007, time_created="t", provider="Defender",
        data={"Old Value": "DisableRealtimeMonitoring = 0x0",
              "New Value": "DisableRealtimeMonitoring = 0x1"})
    raw = record.to_raw()
    assert raw["category"] == "defender.tamper"
    assert raw["action"] == "config_tamper"
    assert raw["data"]["classification"] == "suspicious"


def test_added_exclusion_is_tamper():
    record = EventLogRecord(
        record_id=3, event_id=5007, time_created="t", provider="Defender",
        data={"Old Value": "", "New Value": "ExclusionPath = C:\\Temp"})
    assert record.to_raw()["category"] == "defender.tamper"


def test_unknown_config_change_is_visible_but_benign():
    record = EventLogRecord(
        record_id=4, event_id=5007, time_created="t", provider="Defender",
        data={"Old Value": "SomeNewKey = a", "New Value": "SomeNewKey = b"})
    raw = record.to_raw()
    assert raw["category"] == "config.change"
    assert raw["action"] == "config_unclassified"


def test_normalizer_accepts_eventlog_source():
    record = parse_events_xml(XML)[0]
    ev = Normalizer(host=HOST).normalize("win.eventlog", record.to_raw())
    assert ev.platform == "windows"
    assert ev.category == "persistence.change"
    assert ev.object.path.endswith("evil.exe")
    assert ev.platform_data["ServiceName"] == "evil"
    assert ev.platform_data["event_id"] == 7045
    assert ev.actor is None


# ---------------------------------------------------------------- poll() with a stub
class _Completed:
    def __init__(self, code=0, out="", err=""):
        self.returncode = code
        self.stdout = out
        self.stderr = err


def test_poll_reads_new_records_and_advances_bookmark(monkeypatch):
    from core.winsource import WindowsEventLogSource

    calls = {"n": 0}

    def fake_run(*args, **kwargs):
        calls["n"] += 1
        return _Completed(0, XML)

    monkeypatch.setattr("core.winsource.subprocess.run", fake_run)
    source = WindowsEventLogSource(log_name="System", event_ids=(7045,))
    first = source.poll()
    assert [r.record_id for r in first] == [12345, 12346]
    assert source.stats()["last_record_id"] == 12346
    second = source.poll()               # bookmark: nothing new
    assert second == []
    assert calls["n"] == 2
    assert source.stats()["last_query_ms"] >= 0


def test_poll_treats_exit_code_1_as_no_events(monkeypatch):
    from core.winsource import WindowsEventLogSource

    monkeypatch.setattr("core.winsource.subprocess.run",
                        lambda *a, **k: _Completed(1, "", "no events"))
    assert WindowsEventLogSource().poll() == []


def test_poll_raises_on_wevtutil_failure(monkeypatch):
    from core.winsource import WindowsEventLogSource

    monkeypatch.setattr("core.winsource.subprocess.run",
                        lambda *a, **k: _Completed(5, "", "access denied"))
    with pytest.raises(RuntimeError):
        WindowsEventLogSource().poll()


def test_poll_requires_wevtutil(monkeypatch):
    from core.winsource import WindowsEventLogSource

    source = WindowsEventLogSource(wevtutil="C:\\definitely\\missing.exe")
    with pytest.raises(RuntimeError):
        source.poll()


def test_channel_exists_reports_missing_and_present(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from core import winsource

    fake = tmp_path / "wevtutil.exe"
    fake.write_bytes(b"")
    monkeypatch.setattr(winsource.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(returncode=0))
    assert winsource.channel_exists("X", wevtutil=str(fake)) is True
    monkeypatch.setattr(winsource.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(returncode=1))
    assert winsource.channel_exists("X", wevtutil=str(fake)) is False
    assert winsource.channel_exists("X", wevtutil=str(tmp_path / "missing.exe")) is False


def test_sysmon_process_start_to_raw_carries_pid():
    from core.winsource import EventLogRecord

    record = EventLogRecord(
        record_id=1, event_id=1, time_created="2026-11-14T00:00:00Z",
        provider="Microsoft-Windows-Sysmon",
        data={"Image": r"C:\Temp\evil.exe", "ProcessId": "0x1092",
              "ParentProcessId": "0x4", "CommandLine": "evil.exe -x"})
    raw = record.to_raw()
    assert raw["category"] == "process.start"
    assert raw["process_id"] == 0x1092
    assert raw["parent_id"] == 4
    assert raw["image"] == r"C:\Temp\evil.exe"
