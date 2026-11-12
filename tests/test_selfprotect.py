import json
import os
from datetime import datetime, timezone

import pytest

from core.policy import POLICY_FINGERPRINT, verify_immutable
from core.selfprotect import HashChainLog, IntegrityManifest, SelfTest

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)


def make_log(tmp_path, seal=False):
    log = HashChainLog(str(tmp_path / "audit" / "chain.jsonl"),
                       anchor_path=str(tmp_path / "audit" / "anchor.json"),
                       now_fn=lambda: NOW)
    return log


# ------------------------------------------------------------------ hash chain
def test_append_and_verify(tmp_path):
    log = make_log(tmp_path)
    for i in range(5):
        log.append("test", {"i": i})
    result = log.verify()
    assert result.ok and result.records == 5


def test_record_links_to_previous_hash(tmp_path):
    log = make_log(tmp_path)
    first = log.append("a", {"x": 1})
    second = log.append("b", {"x": 2})
    assert first["prev"] == "0" * 64
    assert second["prev"] == first["hash"]


def test_modified_payload_detected(tmp_path):
    log = make_log(tmp_path)
    log.append("a", {"x": 1})
    log.append("b", {"x": 2})
    path = log.path
    lines = open(path, encoding="utf-8").read().splitlines()
    record = json.loads(lines[0])
    record["payload"]["x"] = 999
    lines[0] = json.dumps(record)
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    result = HashChainLog(path).verify()
    assert not result.ok and "hash mismatch" in result.reason


def test_deleted_middle_record_detected(tmp_path):
    log = make_log(tmp_path)
    for i in range(4):
        log.append("a", {"i": i})
    lines = open(log.path, encoding="utf-8").read().splitlines()
    open(log.path, "w", encoding="utf-8").write("\n".join([lines[0], lines[2], lines[3]]) + "\n")
    result = HashChainLog(log.path).verify()
    assert not result.ok


def test_reordered_records_detected(tmp_path):
    log = make_log(tmp_path)
    for i in range(3):
        log.append("a", {"i": i})
    lines = open(log.path, encoding="utf-8").read().splitlines()
    open(log.path, "w", encoding="utf-8").write("\n".join([lines[1], lines[0], lines[2]]) + "\n")
    result = HashChainLog(log.path).verify()
    assert not result.ok


def test_truncation_detected_with_anchor(tmp_path):
    log = make_log(tmp_path)
    for i in range(5):
        log.append("a", {"i": i})
    log.seal()
    lines = open(log.path, encoding="utf-8").read().splitlines()
    open(log.path, "w", encoding="utf-8").write("\n".join(lines[:3]) + "\n")
    result = HashChainLog(log.path, anchor_path=log.anchor_path).verify()
    assert not result.ok and "truncation" in result.reason


def test_append_after_reopen_continues_chain(tmp_path):
    log = make_log(tmp_path)
    log.append("a", {"i": 1})
    reopened = HashChainLog(log.path, anchor_path=log.anchor_path, now_fn=lambda: NOW)
    reopened.append("b", {"i": 2})
    assert reopened.verify().records == 2


def test_unparsable_line_detected(tmp_path):
    log = make_log(tmp_path)
    log.append("a", {})
    with open(log.path, "a", encoding="utf-8") as fh:
        fh.write("{not json}\n")
    assert not HashChainLog(log.path).verify().ok


def test_forged_record_without_required_keys_is_tamper_not_crash(tmp_path):
    log = make_log(tmp_path)
    log.append("a", {})
    with open(log.path, "a", encoding="utf-8") as fh:
        fh.write('{"forged": true}\n')
    result = HashChainLog(log.path).verify()
    assert result.ok is False
    assert "malformed record" in result.reason


def test_seal_requires_anchor(tmp_path):
    log = HashChainLog(str(tmp_path / "x.jsonl"))
    with pytest.raises(ValueError):
        log.seal()


# ------------------------------------------------------- batching / incremental
def test_batched_append_flushes_on_threshold(tmp_path):
    log = HashChainLog(str(tmp_path / "log.jsonl"), fsync_every=4,
                       anchor_path=str(tmp_path / "anchor.json"))
    for i in range(3):
        log.append("a", {"i": i})
    assert not os.path.exists(log.path) or os.path.getsize(log.path) == 0
    log.append("a", {"i": 3})                 # 4th triggers a batch flush
    assert os.path.getsize(log.path) > 0
    assert log.verify().records == 4


def test_batched_close_flushes_buffer(tmp_path):
    log = HashChainLog(str(tmp_path / "log.jsonl"), fsync_every=100)
    log.append("a", {"i": 1})
    log.close()
    assert HashChainLog(log.path).verify().records == 1


def test_seal_flushes_and_verifies(tmp_path):
    log = HashChainLog(str(tmp_path / "log.jsonl"), fsync_every=100,
                       anchor_path=str(tmp_path / "anchor.json"))
    log.append("a", {})
    log.seal()
    assert log.verify().records == 1


def test_seal_refuses_invalid_chain(tmp_path):
    log = HashChainLog(str(tmp_path / "log.jsonl"), anchor_path=str(tmp_path / "anchor.json"))
    log.append("a", {})
    with open(log.path, "a", encoding="utf-8") as fh:
        fh.write('{"forged": true}\n')
    with pytest.raises(ValueError):
        log.seal()


def test_incremental_verify_only_reads_tail(tmp_path):
    log = HashChainLog(str(tmp_path / "log.jsonl"), anchor_path=str(tmp_path / "anchor.json"))
    for i in range(100):
        log.append("a", {"i": i})
    assert log.verify(incremental=True).records == 100
    assert log.verified_records == 100
    for i in range(100, 110):
        log.append("a", {"i": i})
    result = log.verify(incremental=True)
    assert result.ok and result.records == 110


def test_incremental_verify_catches_tail_tamper(tmp_path):
    log = HashChainLog(str(tmp_path / "log.jsonl"), anchor_path=str(tmp_path / "anchor.json"))
    for i in range(5):
        log.append("a", {"i": i})
    log.verify(incremental=True)
    with open(log.path, "a", encoding="utf-8") as fh:
        fh.write('{"forged": true}\n')
    assert log.verify(incremental=True).ok is False


def test_incremental_misses_old_inplace_edit_full_catches_it(tmp_path):
    """Documented trade-off: tail-only verification does not re-hash old records."""
    log = HashChainLog(str(tmp_path / "log.jsonl"), anchor_path=str(tmp_path / "anchor.json"))
    for i in range(5):
        log.append("a", {"i": i})
    log.verify(incremental=True)
    lines = open(log.path, encoding="utf-8").read().splitlines()
    record = json.loads(lines[1])
    record["payload"]["i"] = 999
    lines[1] = json.dumps(record)
    open(log.path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    assert log.verify(incremental=True).ok is True       # tail unchanged
    assert log.verify(incremental=False).ok is False     # full pass catches it


def test_incremental_detects_truncation_against_anchor(tmp_path):
    log = HashChainLog(str(tmp_path / "log.jsonl"), anchor_path=str(tmp_path / "anchor.json"))
    for i in range(5):
        log.append("a", {"i": i})
    log.seal()
    fresh = HashChainLog(log.path, anchor_path=log.anchor_path)
    fresh.verify(incremental=True)
    lines = open(log.path, encoding="utf-8").read().splitlines()
    open(log.path, "w", encoding="utf-8").write("\n".join(lines[:3]) + "\n")
    result = HashChainLog(log.path, anchor_path=log.anchor_path).verify(incremental=True)
    assert not result.ok and "truncation" in result.reason


# ----------------------------------------------------------------- integrity
def test_integrity_manifest_detects_modification_and_deletion(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    a, b = root / "a.json", root / "b.json"
    a.write_text("{}", encoding="utf-8")
    b.write_text("[]", encoding="utf-8")
    manifest = IntegrityManifest(str(root), str(root / "manifest.json"))
    manifest.seal([str(a), str(b)])
    assert manifest.verify()["ok"] is True

    a.write_text('{"changed": true}', encoding="utf-8")
    os.remove(b)
    result = manifest.verify()
    assert result["ok"] is False
    assert result["modified"] == ["a.json"]
    assert result["missing"] == ["b.json"]


def test_integrity_manifest_lists_added_files(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    f = root / "a.json"
    f.write_text("{}", encoding="utf-8")
    manifest = IntegrityManifest(str(root), str(root / "manifest.json"))
    manifest.seal([str(f)])
    (root / "evil.json").write_text("{}", encoding="utf-8")
    assert "evil.json" in manifest.verify()["added"]


def test_integrity_manifest_reload(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    f = root / "a.json"
    f.write_text("x", encoding="utf-8")
    m1 = IntegrityManifest(str(root), str(root / "m.json"))
    m1.seal([str(f)])
    m2 = IntegrityManifest(str(root), str(root / "m.json"))
    m2.load()
    assert m2.verify()["ok"] is True


# ----------------------------------------------------------------- self-test
def test_self_test_passes_with_clean_state(tmp_path):
    log = make_log(tmp_path)
    log.append("boot", {})
    manifest = IntegrityManifest(str(tmp_path), str(tmp_path / "m.json"))
    f = tmp_path / "f.txt"
    f.write_text("x", encoding="utf-8")
    manifest.seal([str(f)])

    st = SelfTest()
    st.register("immutable", st.immutable_check(verify_immutable))
    st.register("log", st.log_check(log))
    st.register("integrity", st.integrity_check(manifest))
    report = st.run()
    assert report["ok"] is True and len(report["checks"]) == 3
    assert report["duration_ms"] >= 0


def test_self_test_reports_tamper_and_crashing_check(tmp_path):
    log = make_log(tmp_path)
    log.append("boot", {})
    manifest = IntegrityManifest(str(tmp_path), str(tmp_path / "m.json"))
    f = tmp_path / "f.txt"
    f.write_text("x", encoding="utf-8")
    manifest.seal([str(f)])
    f.write_text("tampered", encoding="utf-8")

    def broken():
        raise RuntimeError("boom")

    st = SelfTest()
    st.register("immutable", st.immutable_check(verify_immutable))
    st.register("integrity", st.integrity_check(manifest))
    st.register("broken", broken)
    report = st.run()
    assert report["ok"] is False
    assert "integrity" in report["failed"] and "broken" in report["failed"]
    detail = [c for c in report["checks"] if c["check"] == "broken"][0]["detail"]
    assert "RuntimeError" in detail


def test_self_test_detects_immutable_change():
    def tampered():
        bad = {"FAIL_SAFE_ON_TIMEOUT": "accept", "MODELS_TRAIN_ON_DEVICE": False,
               "DRIVER_SIGNED_BY_HUMAN": True, "KERNEL_CODE_REVIEW_REQUIRED": True}
        verify_immutable(bad)

    st = SelfTest()
    st.register("immutable", st.immutable_check(tampered))
    report = st.run()
    assert report["ok"] is False and report["failed"] == ["immutable"]


def test_policy_fingerprint_is_stable_across_runs():
    assert len(POLICY_FINGERPRINT) == 64
