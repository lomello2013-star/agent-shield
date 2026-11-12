import json
import os
import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from schemas.v3 import (
    SCHEMA_VERSION,
    Action,
    CaseMemoryEntry,
    Event,
    Health,
    IncompatibleSchemaError,
    LearningUpdate,
    ModelPack,
    ModuleManifest,
    PlatformCapabilities,
    TaskSolution,
    Verdict,
    check_schema_version,
    export_json_schemas,
    parse_schema_version,
)

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)


def uid():
    return str(uuid.uuid4())


def event_payload(**overrides):
    payload = {
        "schema_version": SCHEMA_VERSION,
        "event_id": uid(),
        "trace_id": uid(),
        "ts_event": NOW.isoformat(),
        "ts_ingest": NOW.isoformat(),
        "platform": "windows",
        "source": "win.etw.ti",
        "layer": "kernel",
        "category": "process.access",
        "action": "open_process",
        "actor": {"pid": 512, "name": "malware.exe", "path": "%TEMP%/malware.exe",
                  "cmdline_hash": "ab" * 32},
        "object": {"type": "process", "path": "lsass.exe"},
        "host": {"host_id": "host-1", "os": "windows", "version": "10.0.19045",
                 "arch": "x64"},
        "raw_ref": "raw/2026/11/12/x.jsonl.zst#1",
        "platform_data": {"etw": {"opcode": 1}},
        "kernel_meta": {"callback_type": "post", "trust": "kernel"},
    }
    payload.update(overrides)
    return payload


# ---------------- versioning ----------------
def test_parse_schema_version():
    assert parse_schema_version("3.1") == (3, 1)
    assert parse_schema_version("4.0") == (4, 0)


@pytest.mark.parametrize("bad", ["3", "3.0.0", "v3.0", "", None, "3.x"])
def test_parse_schema_version_rejects_garbage(bad):
    with pytest.raises(IncompatibleSchemaError):
        parse_schema_version(bad)


def test_check_schema_version_accepts_3x():
    assert check_schema_version("3.0") == "3.0"
    assert check_schema_version("3.7") == "3.7"


def test_check_schema_version_rejects_4_0():
    with pytest.raises(IncompatibleSchemaError) as exc:
        check_schema_version("4.0")
    assert "incompatible_schema" in str(exc.value)


def test_event_accepts_forward_minor_version():
    ev = Event.model_validate(event_payload(schema_version="3.1"))
    assert ev.schema_version == "3.1"


def test_event_rejects_4_0_with_incompatible_schema():
    with pytest.raises(ValueError) as exc:
        Event.model_validate(event_payload(schema_version="4.0"))
    assert "incompatible_schema" in str(exc.value)


# ---------------- Event ----------------
def test_valid_event_roundtrip():
    ev = Event.model_validate(event_payload())
    again = Event.model_validate(json.loads(ev.model_dump_json()))
    assert again.event_id == ev.event_id
    assert again.platform_data["etw"]["opcode"] == 1


def test_pii_defaults_are_privacy_preserving():
    ev = Event.model_validate(event_payload())
    assert ev.pii.paths_hashed and ev.pii.cmdline_hashed and ev.pii.usernames_hashed
    assert ev.pii.ips_hashed is False      # IP needed for correlation, but flagged


def test_unknown_category_is_tolerated():
    ev = Event.model_validate(event_payload(category="future.new.category"))
    assert ev.category == "future.new.category"


def test_unknown_source_is_tolerated():
    ev = Event.model_validate(event_payload(source="win.future.provider"))
    assert ev.source == "win.future.provider"


def test_platform_data_is_extensible():
    ev = Event.model_validate(event_payload(platform_data={"a": 1, "unknown": {"b": 2}}))
    assert ev.platform_data["unknown"]["b"] == 2


def test_top_level_extra_field_rejected():
    with pytest.raises(ValidationError):
        Event.model_validate(event_payload(surprise="x"))


@pytest.mark.parametrize("field,value", [
    ("platform", "macos"),
    ("layer", "firmware"),
    ("event_id", "not-a-uuid"),
])
def test_event_rejects_bad_required_fields(field, value):
    with pytest.raises(ValidationError):
        Event.model_validate(event_payload(**{field: value}))


def test_actor_negative_pid_rejected():
    bad = event_payload()
    bad["actor"]["pid"] = -1
    with pytest.raises(ValidationError):
        Event.model_validate(bad)


def test_object_port_range():
    bad = event_payload()
    bad["object"] = {"type": "network", "path": "1.2.3.4:443", "port": 70000}
    with pytest.raises(ValidationError):
        Event.model_validate(bad)


# ---------------- Verdict / Action / Confirmation ----------------
def test_verdict_confidence_bounds():
    base = {"verdict_id": uid(), "trace_id": uid(), "event_id": uid(), "detector": "rule",
            "platform": "linux", "confidence": 1.0, "severity": "high",
            "reason_code": "r1", "reason_text": "test"}
    assert Verdict.model_validate(base).confidence == 1.0
    for bad in (-0.01, 1.01):
        with pytest.raises(ValidationError):
            Verdict.model_validate({**base, "confidence": bad})


def test_verdict_unknown_detector_rejected():
    base = {"verdict_id": uid(), "trace_id": uid(), "event_id": uid(),
            "detector": "oracle", "platform": "linux", "confidence": 0.5,
            "severity": "low", "reason_code": "r", "reason_text": "t"}
    with pytest.raises(ValidationError):
        Verdict.model_validate(base)


def test_action_defaults_and_reversibility():
    action = Action.model_validate({
        "action_id": uid(), "trace_id": uid(), "verdict_id": uid(),
        "type": "suspend", "target": "pid:1234", "reversible": True,
        "requires_confirmation": False, "platform_effect": "NtSuspendProcess",
        "rollback": {"kind": "resume", "payload": {"pid": 1234}},
    })
    assert action.status == "pending"
    assert action.rollback.kind == "resume"


def test_action_rejects_unknown_type():
    with pytest.raises(ValidationError):
        Action.model_validate({"action_id": uid(), "trace_id": uid(), "verdict_id": uid(),
                               "type": "format_disk", "target": "x",
                               "reversible": False, "requires_confirmation": True})


# ---------------- Health / Manifest / Capabilities ----------------
def test_health_rejects_negative_metrics():
    with pytest.raises(ValidationError):
        Health.model_validate({"module": "ingest", "version": "1.0.0", "status": "ok",
                               "ram_mb": -5})


def test_manifest_requires_platforms_and_schemas():
    with pytest.raises(ValidationError):
        ModuleManifest.model_validate({"name": "m", "version": "1.0.0", "platforms": [],
                                       "schemas": ["3.0"], "min_core_version": "0.1.0"})
    with pytest.raises(ValidationError):
        ModuleManifest.model_validate({"name": "m", "version": "1.0.0",
                                       "platforms": ["linux"], "schemas": [],
                                       "min_core_version": "0.1.0"})


def test_manifest_semver_validation():
    with pytest.raises(ValidationError):
        ModuleManifest.model_validate({"name": "m", "version": "1.0", "platforms": ["linux"],
                                       "schemas": ["3.0"], "min_core_version": "0.1.0"})


def test_platform_capabilities_defaults_are_false():
    caps = PlatformCapabilities.model_validate({"platform": "linux", "os_version": "24.04"})
    assert caps.has_ebpf is False and caps.has_btf is False and caps.secure_boot is False


# ---------------- Learning loop contracts ----------------
def test_case_memory_requires_trusted_confirmation_source():
    base = {"case_id": uid(), "created_at": NOW.isoformat(), "confirmed_by": "analyst",
            "features": {"a": 1.0}, "platform": "linux",
            "verdict": {"verdict_id": uid(), "trace_id": uid(), "event_id": uid(),
                        "detector": "rule", "platform": "linux", "confidence": 0.9,
                        "severity": "high", "reason_code": "r", "reason_text": "t"}}
    assert CaseMemoryEntry.model_validate(base).confirmed_by == "analyst"
    with pytest.raises(ValidationError):
        CaseMemoryEntry.model_validate({**base, "confirmed_by": "model"})   # self-confirmation banned


def test_model_pack_requires_signature_and_hash():
    base = {"model_id": "pe", "version": "1.0.0", "platform": "windows", "format": "onnx",
            "sha256": "a" * 64, "dataset_hash": "b" * 64, "metrics": {"tpr@fpr": 0.9},
            "limits": {}, "signature": "sig"}
    assert ModelPack.model_validate(base).sha256 == "a" * 64
    with pytest.raises(ValidationError):
        ModelPack.model_validate({**base, "signature": ""})
    with pytest.raises(ValidationError):
        ModelPack.model_validate({**base, "sha256": "not-a-hash"})


def test_learning_update_requires_signature():
    base = {"update_id": uid(), "version": "1.0.0", "signature": "sig"}
    assert LearningUpdate.model_validate(base).rules is None
    with pytest.raises(ValidationError):
        LearningUpdate.model_validate({**base, "signature": ""})


def test_task_solution_defaults_to_fewshot():
    ts = TaskSolution.model_validate({"task": "t", "solution": "s"})
    assert ts.used_as == "fewshot"


# ---------------- JSON Schema export ----------------
def test_export_writes_schemas_and_index(tmp_path):
    files = export_json_schemas(str(tmp_path))
    names = {p.split("\\")[-1].split("/")[-1] for p in files}
    assert "Event.schema.json" in names
    assert "index.json" in names
    event_schema = json.loads((tmp_path / "Event.schema.json").read_text(encoding="utf-8"))
    assert "required" in event_schema
    required = set(event_schema["required"])
    for field in ("event_id", "trace_id", "platform", "category", "host", "raw_ref"):
        assert field in required
    index = json.loads((tmp_path / "index.json").read_text(encoding="utf-8"))
    assert index["schema_version"] == SCHEMA_VERSION
    assert len(index["files"]) >= 20


def test_committed_json_schemas_match_models(tmp_path):
    """Guards against schema drift: committed artefacts must equal generated ones."""
    committed = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "schemas", "v3", "json_schema")
    export_json_schemas(str(tmp_path))
    for name in os.listdir(tmp_path):
        path = os.path.join(committed, name)
        assert os.path.exists(path), f"committed schema missing: {name}"
        with open(path, encoding="utf-8") as fh:
            expected = json.load(fh)
        with open(os.path.join(tmp_path, name), encoding="utf-8") as fh:
            actual = json.load(fh)
        assert expected == actual, f"schema drift in {name}"

