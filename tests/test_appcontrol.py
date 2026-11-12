import hashlib
import xml.etree.ElementTree as ET

import pytest

from core.appcontrol import (
    AllowRule,
    MS_BASELINE_POLICY_ID,
    SIPOLICY_NS,
    AllowlistEvaluator,
    CiAuditEvent,
    InventoryEntry,
    WdacPolicy,
    parse_codeintegrity_any,
    parse_codeintegrity_event,
    tbs_certificate_sha256,
)


# ---------------- DER / TBS ----------------
def der_sequence(content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        return b"\x30" + bytes([n]) + content
    if n < 0x100:
        return b"\x30\x81" + bytes([n]) + content
    return b"\x30\x82" + n.to_bytes(2, "big") + content


def test_tbs_hash_of_minimal_certificate():
    tbs = der_sequence(b"\x02\x01\x01")                    # SEQUENCE { INTEGER 1 }
    sigalg = der_sequence(b"")
    sigval = b"\x03\x01\x00"
    cert = der_sequence(tbs + sigalg + sigval)
    assert tbs_certificate_sha256(cert) == hashlib.sha256(tbs).hexdigest()


def test_tbs_hash_with_long_form_length():
    tbs = der_sequence(b"\x04\x84" + b"x" * 0x84)          # 132-byte OCTET STRING
    cert = der_sequence(tbs + der_sequence(b"") + b"\x03\x01\x00")
    assert tbs_certificate_sha256(cert) == hashlib.sha256(tbs).hexdigest()


def test_tbs_hash_rejects_non_sequence():
    with pytest.raises(ValueError):
        tbs_certificate_sha256(b"\x02\x01\x01")


def test_tbs_hash_rejects_truncated_der():
    with pytest.raises(ValueError):
        tbs_certificate_sha256(b"\x30\x82\xff\xff\x00")


# ---------------- policy XML ----------------
def make_policy(**kwargs):
    pol = WdacPolicy(name="AIDefender-L0", **kwargs)
    pol.add_signer("a" * 64, "Microsoft Windows")
    pol.add_path("%OSDRIVE%\\Program Files\\AIDefender\\*")
    pol.add_hash("B" * 64)
    return pol


def test_policy_xml_is_well_formed_and_audit_by_default():
    xml = make_policy().to_xml()
    root = ET.fromstring(xml)
    assert root.tag == f"{{{SIPOLICY_NS}}}SiPolicy"
    options = [opt.text for opt in root.findall(f".//{{{SIPOLICY_NS}}}Option")]
    assert "Enabled:Audit Mode" in options
    assert "Enabled:Unsigned System Integrity Policy" in options


def test_policy_without_audit_is_enforce_candidate():
    xml = WdacPolicy(audit=False).to_xml()
    assert "Enabled:Audit Mode" not in xml


def test_policy_contains_signer_path_and_hash_rules():
    root = ET.fromstring(make_policy().to_xml())
    cert_roots = root.findall(f".//{{{SIPOLICY_NS}}}CertRoot")
    assert cert_roots and cert_roots[0].get("Value") == "a" * 64
    assert cert_roots[0].get("Type") == "TBS"
    allow_paths = [el.get("FilePath") for el in root.findall(f".//{{{SIPOLICY_NS}}}Allow")]
    assert any(p and "Program Files" in p for p in allow_paths)
    hashes = [el.get("Hash") for el in root.findall(f".//{{{SIPOLICY_NS}}}Allow")]
    assert "b" * 64 in hashes


def test_policy_rules_validate():
    pol = WdacPolicy()
    with pytest.raises(ValueError):
        pol.add_signer("short")
    with pytest.raises(ValueError):
        AllowRule(kind="wildcard", value="*")
    with pytest.raises(ValueError):
        AllowRule(kind="path", value="")


def test_baseline_policy_id_is_guid_like():
    assert MS_BASELINE_POLICY_ID.startswith("{") and MS_BASELINE_POLICY_ID.endswith("}")


# ---------------- allowlist evaluation ----------------
def entries():
    return [
        InventoryEntry(r"C:\Windows\System32\cmd.exe", True, "Microsoft Windows", "m" * 64, None, True),
        InventoryEntry(r"C:\Program Files\App\app.exe", True, "Vendor Inc", "v" * 64, None, False),
        InventoryEntry(r"C:\Users\u\AppData\Local\P\p.exe", False, "", None, "h" * 64, False),
        InventoryEntry(r"C:\Tools\unsigned.exe", False, "", None, "u" * 64, False),
    ]


def test_allowlist_signer_path_and_hash_rules():
    ev = AllowlistEvaluator(signers=["m" * 64], paths=["C:\\Program Files\\"],
                            hashes=["h" * 64])
    decisions = [ev.decide(e).reason for e in entries()]
    assert decisions == ["signer", "path", "hash", "no_rule"]


def test_false_block_rate_computation():
    ev = AllowlistEvaluator(signers=["m" * 64], paths=["C:\\Program Files\\", "C:\\Users\\"],
                            hashes=[])
    stats = ev.false_block_rate(entries())
    assert stats["total"] == 4 and stats["blocked"] == 1
    assert stats["false_block_rate"] == 0.25
    assert stats["within_target"] is False
    assert stats["blocked_examples"] == [r"C:\Tools\unsigned.exe"]


def test_full_coverage_passes_gate():
    ev = AllowlistEvaluator(signers=["m" * 64, "v" * 64],
                            paths=["C:\\Users\\"], hashes=["u" * 64])
    stats = ev.coverage(entries())
    assert stats["coverage"] == 1.0 and stats["passes_gate"] is True
    assert ev.false_block_rate(entries())["blocked"] == 0


def test_partial_coverage_fails_gate():
    ev = AllowlistEvaluator(signers=["m" * 64])
    stats = ev.coverage(entries())
    assert stats["coverage_pct"] == 25.0
    assert stats["passes_gate"] is False


def test_path_matching_is_case_insensitive():
    ev = AllowlistEvaluator(paths=["c:\\windows\\"])
    assert ev.decide(entries()[0]).allowed is True


# ---------------- CodeIntegrity 3076/3077 ----------------
EVENT_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>3076</EventID></System>
  <EventData>
    <Data Name="FileName">C:\\Temp\\evil.exe</Data>
    <Data Name="ProcessName">C:\\Windows\\explorer.exe</Data>
    <Data Name="PolicyID">{A244370E-44C9-4C06-B551-F30498B7F294}</Data>
    <Data Name="UserID">S-1-5-21-1</Data>
  </EventData>
</Event>"""


def test_parse_audit_event():
    ev = parse_codeintegrity_event(EVENT_XML)
    assert isinstance(ev, CiAuditEvent)
    assert ev.event_id == 3076
    assert ev.file_name.endswith("evil.exe")
    assert ev.process_name.endswith("explorer.exe")
    assert ev.policy_id.startswith("{A244370E")
    assert ev.user.startswith("S-1-5-21")


def test_parse_block_event_3077():
    ev = parse_codeintegrity_event(EVENT_XML.replace("<EventID>3076<", "<EventID>3077<"))
    assert ev.event_id == 3077


def test_parse_rejects_other_event_ids():
    with pytest.raises(ValueError):
        parse_codeintegrity_event(EVENT_XML.replace("<EventID>3076<", "<EventID>4688<"))


def test_parse_rejects_missing_filename():
    xml = EVENT_XML.replace('Name="FileName"', 'Name="Something"')
    with pytest.raises(ValueError):
        parse_codeintegrity_event(xml)


def test_parse_rejects_malformed_xml():
    with pytest.raises(ValueError):
        parse_codeintegrity_event("<Event><System>")


def test_generic_parser_reads_any_ci_event():
    xml = EVENT_XML.replace("<EventID>3076<", "<EventID>3089<")
    data = parse_codeintegrity_any(xml)
    assert data["event_id"] == "3089"
    assert data["FileName"].endswith("evil.exe")


def test_generic_parser_rejects_unusable_xml():
    with pytest.raises(ValueError):
        parse_codeintegrity_any("not xml")
    with pytest.raises(ValueError):
        parse_codeintegrity_any("<Event><NoSystem/></Event>")





def test_signed_any_allows_unknown_publisher_but_not_unsigned():
    """F10: 'any validly signed' is measurable as a tradeoff, unsigned still blocked."""
    from core.appcontrol import AllowlistEvaluator, InventoryEntry
    ev = AllowlistEvaluator(signed_any=True)
    signed_unknown = InventoryEntry(path=r"C:\x\a.exe", signed=True,
                                    signer_cn="Unknown Publisher", tbs_sha256="ab" * 32)
    unsigned = InventoryEntry(path=r"C:\x\b.exe", signed=False, signer_cn="",
                              sha256="cd" * 32)
    assert ev.decide(signed_unknown).allowed is True
    assert ev.decide(signed_unknown).reason == "signed_any"
    assert ev.decide(unsigned).allowed is False


def test_signed_any_off_keeps_publisher_strictness():
    from core.appcontrol import AllowlistEvaluator, InventoryEntry
    ev = AllowlistEvaluator(signers={"ff" * 32})
    other = InventoryEntry(path=r"C:\x\c.exe", signed=True, signer_cn="Other",
                           tbs_sha256="ab" * 32)
    assert ev.decide(other).allowed is False

