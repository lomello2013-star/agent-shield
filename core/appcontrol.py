"""Application control (L0) — the parts that do not require elevation.

Windows: build a WDAC policy in **audit** mode (never enforce by default),
compute signer TBS hashes for publisher rules, evaluate a candidate allowlist
against a real executable inventory, and parse CodeIntegrity audit events (3076).

Linux side (fapolicyd/IMA) is intentionally absent: it cannot be measured on the
current host (spike 2, Linux blocked) and must not be faked.
"""

from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Iterable

SIPOLICY_NS = "urn:schemas-microsoft-com:sipolicy"
MS_BASELINE_POLICY_ID = "{A244370E-44C9-4C06-B551-F30498B7F294}"


# --------------------------------------------------------------------------- DER
def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one DER TLV; returns (tag, value, next_offset)."""
    if offset + 2 > len(data):
        raise ValueError("truncated DER")
    tag = data[offset]
    length_byte = data[offset + 1]
    offset += 2
    if length_byte & 0x80:
        n = length_byte & 0x7F
        if n == 0 or offset + n > len(data):
            raise ValueError("bad DER length")
        length = int.from_bytes(data[offset:offset + n], "big")
        offset += n
    else:
        length = length_byte
    end = offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return tag, data[offset:end], end


def tbs_certificate_sha256(cert_der: bytes) -> str:
    """SHA-256 of the DER-encoded TBSCertificate (what WDAC signer rules use).

    Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    """
    tag, value, _ = _read_tlv(cert_der, 0)
    if tag != 0x30:
        raise ValueError("certificate is not a DER SEQUENCE")
    # Locate the first child (the TBS) inside the outer SEQUENCE value and hash
    # its full TLV (tag+length+value) — that is the TBS hash Microsoft uses.
    inner_offset = len(cert_der) - len(value)
    _, _, tbs_end = _read_tlv(cert_der, inner_offset)
    tbs_tlv = cert_der[inner_offset:tbs_end]
    return hashlib.sha256(tbs_tlv).hexdigest()


# ---------------------------------------------------------------------- policy
@dataclass
class AllowRule:
    kind: str                     # "signer" | "path" | "hash"
    value: str
    name: str = ""

    def __post_init__(self) -> None:
        if self.kind not in ("signer", "path", "hash"):
            raise ValueError(f"unknown rule kind: {self.kind}")
        if not self.value:
            raise ValueError("rule value must be non-empty")


@dataclass
class WdacPolicy:
    """Builds a WDAC policy XML document.

    Audit mode is the default on purpose: enforce requires the allowlist/SLA
    loop from roadmap §6.4 and a human-approved change window.
    """

    name: str = "AIDefender-L0"
    policy_id: str = "{11111111-2222-3333-4444-555555555555}"
    version: str = "1.0.0.0"
    audit: bool = True
    rules: list[AllowRule] = field(default_factory=list)

    def add_signer(self, tbs_sha256: str, name: str = "") -> None:
        if len(tbs_sha256) != 64:
            raise ValueError("TBS hash must be sha256 hex")
        self.rules.append(AllowRule("signer", tbs_sha256, name))

    def add_path(self, path: str) -> None:
        self.rules.append(AllowRule("path", path))

    def add_hash(self, sha256: str) -> None:
        self.rules.append(AllowRule("hash", sha256.lower()))

    def to_xml(self) -> str:
        ET.register_namespace("", SIPOLICY_NS)
        root = ET.Element(f"{{{SIPOLICY_NS}}}SiPolicy", {
            "PolicyType": "Base Policy",
            "VersionEx": self.version,
        })
        ET.SubElement(root, f"{{{SIPOLICY_NS}}}VersionEx").text = self.version
        ET.SubElement(root, f"{{{SIPOLICY_NS}}}PolicyID").text = self.policy_id
        ET.SubElement(root, f"{{{SIPOLICY_NS}}}BasePolicyID").text = self.policy_id
        ET.SubElement(root, f"{{{SIPOLICY_NS}}}PlatformID").text = "{2B7C8B7A-0B4B-4B8B-9B0E-1B4E2C6D8F01}"

        rules_el = ET.SubElement(root, f"{{{SIPOLICY_NS}}}Rules")
        if self.audit:
            ET.SubElement(ET.SubElement(rules_el, f"{{{SIPOLICY_NS}}}Rule"),
                          f"{{{SIPOLICY_NS}}}Option").text = "Enabled:Audit Mode"
        ET.SubElement(ET.SubElement(rules_el, f"{{{SIPOLICY_NS}}}Rule"),
                      f"{{{SIPOLICY_NS}}}Option").text = "Enabled:Unsigned System Integrity Policy"
        ET.SubElement(ET.SubElement(rules_el, f"{{{SIPOLICY_NS}}}Rule"),
                      f"{{{SIPOLICY_NS}}}Option").text = "Enabled:Update Policy No Reboot"

        file_rules = ET.SubElement(root, f"{{{SIPOLICY_NS}}}FileRules")
        signers = ET.SubElement(root, f"{{{SIPOLICY_NS}}}Signers")
        idx = 0
        for rule in self.rules:
            if rule.kind == "path":
                ET.SubElement(file_rules, f"{{{SIPOLICY_NS}}}Allow",
                              {"ID": f"Allow-{idx}", "FriendlyName": rule.name or f"path-{idx}",
                               "FilePath": rule.value})
            elif rule.kind == "hash":
                ET.SubElement(file_rules, f"{{{SIPOLICY_NS}}}Allow",
                              {"ID": f"Allow-{idx}", "FriendlyName": rule.name or f"hash-{idx}",
                               "Hash": rule.value})
            else:
                sid = f"Signer-{idx}"
                signer = ET.SubElement(signers, f"{{{SIPOLICY_NS}}}Signer", {
                    "ID": sid, "Name": rule.name or sid,
                })
                ET.SubElement(signer, f"{{{SIPOLICY_NS}}}CertRoot",
                              {"Type": "TBS", "Value": rule.value})
            idx += 1

        scenarios = ET.SubElement(root, f"{{{SIPOLICY_NS}}}SigningScenarios")
        scenario = ET.SubElement(scenarios, f"{{{SIPOLICY_NS}}}SigningScenario", {
            "Value": "131", "ID": "ID_SIGNINGSCENARIO_DRIVERS_1", "FriendlyName": "Driver",
        })
        ET.SubElement(scenario, f"{{{SIPOLICY_NS}}}ProductSigners")
        scenario2 = ET.SubElement(scenarios, f"{{{SIPOLICY_NS}}}SigningScenario", {
            "Value": "12", "ID": "ID_SIGNINGSCENARIO_WINDOWS", "FriendlyName": "User Mode",
        })
        prod = ET.SubElement(scenario2, f"{{{SIPOLICY_NS}}}ProductSigners")
        allowed = ET.SubElement(prod, f"{{{SIPOLICY_NS}}}AllowedSigners")
        for i, rule in enumerate(self.rules):
            if rule.kind == "signer":
                ET.SubElement(allowed, f"{{{SIPOLICY_NS}}}AllowedSigner", {"SignerId": f"Signer-{i}"})
            else:
                ET.SubElement(allowed, f"{{{SIPOLICY_NS}}}AllowedSigner", {"SignerId": f"Allow-{i}"})
        return ET.tostring(root, encoding="unicode", xml_declaration=True)


# -------------------------------------------------------------------- allowlist
@dataclass(frozen=True)
class InventoryEntry:
    path: str
    signed: bool
    signer_cn: str = ""
    tbs_sha256: str | None = None
    sha256: str | None = None
    ms_signed: bool = False


@dataclass
class AllowlistDecision:
    allowed: bool
    reason: str


class AllowlistEvaluator:
    """Evaluates a candidate default-deny allowlist against a real inventory."""

    def __init__(self, signers: Iterable[str] = (), paths: Iterable[str] = (),
                 hashes: Iterable[str] = (), signed_any: bool = False) -> None:
        self.signers = {s.lower() for s in signers}
        self.paths = tuple(paths)
        self.hashes = {h.lower() for h in hashes}
        # F10: "any validly signed binary" is a real (weak) WDAC option; measured as a
        # tradeoff against the publisher allowlist, not recommended as the default.
        self.signed_any = signed_any

    def decide(self, entry: InventoryEntry) -> AllowlistDecision:
        if self.signed_any and entry.signed:
            return AllowlistDecision(True, "signed_any")
        if entry.tbs_sha256 and entry.tbs_sha256.lower() in self.signers:
            return AllowlistDecision(True, "signer")
        if any(entry.path.lower().startswith(p.lower()) for p in self.paths):
            return AllowlistDecision(True, "path")
        if entry.sha256 and entry.sha256.lower() in self.hashes:
            return AllowlistDecision(True, "hash")
        return AllowlistDecision(False, "no_rule")

    def false_block_rate(self, entries: list[InventoryEntry]) -> dict[str, object]:
        """All entries are *legitimate* by construction (they come from the host inventory)."""
        blocked = [e for e in entries if not self.decide(e).allowed]
        total = len(entries)
        rate = (len(blocked) / total) if total else 0.0
        return {
            "total": total,
            "blocked": len(blocked),
            "false_block_rate": round(rate, 6),
            "false_block_rate_pct": round(100 * rate, 4),
            "target_pct": 0.1,
            "within_target": rate < 0.001,
            "blocked_examples": [e.path for e in blocked[:10]],
        }

    def coverage(self, entries: list[InventoryEntry]) -> dict[str, object]:
        """Share of observed legitimate inventory covered by the allowlist (>=99.5% gate)."""
        covered = sum(1 for e in entries if self.decide(e).allowed)
        total = len(entries)
        share = covered / total if total else 0.0
        return {"total": total, "covered": covered,
                "coverage": round(share, 6), "coverage_pct": round(100 * share, 4),
                "target_pct": 99.5, "passes_gate": share >= 0.995}


# ------------------------------------------------------------ audit event 3076
@dataclass(frozen=True)
class CiAuditEvent:
    event_id: int
    file_name: str
    process_name: str
    policy_id: str
    user: str = ""
    raw: dict[str, str] = field(default_factory=dict)


def parse_codeintegrity_any(xml_text: str) -> dict[str, str]:
    """Tolerant reader for any CodeIntegrity event (diagnostics, not enforcement).

    Returns ``{"event_id": "...", ...EventData...}``; raises ValueError only when
    the XML itself is unusable. Used to prove the parser works against real
    event-log data even when no 3076 audit policy is deployed.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"invalid event XML: {exc}") from exc
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    system = root.find("e:System", ns)
    if system is None:
        raise ValueError("event XML has no System")
    data: dict[str, str] = {"event_id": system.findtext("e:EventID", default="", namespaces=ns)}
    for node in root.findall(".//e:EventData/e:Data", ns):
        data[node.get("Name") or ""] = (node.text or "").strip()
    return data


def parse_codeintegrity_event(xml_text: str) -> CiAuditEvent:
    """Parse a CodeIntegrity/Operational 3076 (audit) or 3077 (block) event XML."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"invalid event XML: {exc}") from exc

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    system = root.find("e:System", ns)
    if system is None:
        raise ValueError("event XML has no System")
    event_id_text = system.findtext("e:EventID", default="", namespaces=ns)
    try:
        event_id = int(event_id_text)
    except ValueError as exc:
        raise ValueError(f"bad EventID: {event_id_text!r}") from exc
    if event_id not in (3076, 3077):
        raise ValueError(f"not a CodeIntegrity audit/block event: {event_id}")

    data: dict[str, str] = {}
    for node in root.findall(".//e:EventData/e:Data", ns):
        name = node.get("Name") or ""
        data[name] = (node.text or "").strip()

    file_name = data.get("FileName") or data.get("File Name") or ""
    process_name = data.get("ProcessName") or data.get("Process Name") or ""
    if not file_name:
        raise ValueError("CodeIntegrity event without FileName")
    return CiAuditEvent(event_id=event_id, file_name=file_name, process_name=process_name,
                        policy_id=data.get("PolicyID", ""), user=data.get("UserID", ""), raw=data)
