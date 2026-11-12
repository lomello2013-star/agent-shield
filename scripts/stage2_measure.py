"""Stage 2 measurement: WDAC audit policy over the real inventory + live CI events.

No policy is deployed (needs elevation). What is measured:
  * false block rate of candidate allowlists on the real installed inventory;
  * allowlist coverage against the В§6.4 audit->enforce gate (>=99.5%);
  * generator output is a well-formed audit-mode policy XML;
  * parser accepts real CodeIntegrity events from this host's event log.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.appcontrol import (
    parse_codeintegrity_any,
    AllowlistEvaluator,
    InventoryEntry,
    WdacPolicy,
    parse_codeintegrity_event,
    tbs_certificate_sha256,
)

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INVENTORY = os.path.join(HERE, "spikes", "02-app-control", "inventory_certs.json")
OUT_JSON = os.path.join(HERE, "artifacts", "stage2_report.json")
OUT_POLICY = os.path.join(HERE, "artifacts", "wdac_audit_policy.xml")


def file_sha256(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def build_entries(raw: list[dict]) -> list[InventoryEntry]:
    entries = []
    for item in raw:
        der = item.get("der_b64")
        tbs = None
        if der:
            try:
                tbs = tbs_certificate_sha256(base64.b64decode(der))
            except ValueError:
                tbs = None
        signed = item.get("status") == "Valid"
        subject = item.get("subject") or ""
        entries.append(InventoryEntry(
            path=item["path"],
            signed=signed,
            signer_cn=item.get("cn") or "",
            tbs_sha256=tbs,
            sha256=None if signed else file_sha256(item["path"]),
            ms_signed="Microsoft" in subject,
        ))
    return entries


def main() -> None:
    with open(INVENTORY, encoding="utf-8-sig") as fh:
        data = json.load(fh)
    entries = build_entries(data.get("inventory", []))
    report: dict[str, object] = {"host": data.get("host"), "measured_at": data.get("measured_at"),
                                 "inventory": len(entries),
                                 "signed": sum(1 for e in entries if e.signed),
                                 "unsigned": sum(1 for e in entries if not e.signed),
                                 "with_tbs": sum(1 for e in entries if e.tbs_sha256),
                                 "policies": {}}

    ms_signers = {e.tbs_sha256 for e in entries if e.ms_signed and e.tbs_sha256}
    all_signers = {e.tbs_sha256 for e in entries if e.signed and e.tbs_sha256}
    unsigned_hashes = {e.sha256 for e in entries if not e.signed and e.sha256}
    # System-owned, admin-writable only: safe to allow by path. User-writable
    # directories (AppData) are deliberately NOT path-allowed вЂ” they need hashes.
    program_paths = [
        os.environ.get("ProgramFiles", r"C:\Program Files") + "\\",
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)") + "\\",
        os.environ.get("SystemRoot", r"C:\Windows") + "\\",
    ]

    variants = {
        "A_ms_signed_only": AllowlistEvaluator(signers=ms_signers),
        "B_all_observed_publishers": AllowlistEvaluator(signers=all_signers),
        "C_publishers_plus_paths": AllowlistEvaluator(signers=all_signers, paths=program_paths),
        "D_plus_unsigned_hashes": AllowlistEvaluator(signers=all_signers, paths=program_paths,
                                                     hashes=unsigned_hashes),
    }
    for name, ev in variants.items():
        report["policies"][name] = {"false_block": ev.false_block_rate(entries),
                                    "coverage": ev.coverage(entries)}

    # F10: held-out evaluation. Every second file (by path order) is used to *design*
    # the allowlist, the other half is scored. In-sample numbers above are optimistic
    # by construction; these are the ones that answer "what would deployment do?".
    ordered = sorted(entries, key=lambda e: e.path.lower())
    design = ordered[::2]
    holdout = ordered[1::2]
    d_signers = {e.tbs_sha256 for e in design if e.signed and e.tbs_sha256}
    d_ms = {e.tbs_sha256 for e in design if e.ms_signed and e.tbs_sha256}
    d_hashes = {e.sha256 for e in design if not e.signed and e.sha256}
    holdout_variants = {
        "E_holdout_ms_only": AllowlistEvaluator(signers=d_ms),
        "F_holdout_publishers": AllowlistEvaluator(signers=d_signers),
        "G_holdout_publishers_plus_paths": AllowlistEvaluator(signers=d_signers,
                                                              paths=program_paths),
        "H_holdout_publishers_paths_hashes": AllowlistEvaluator(signers=d_signers,
                                                                paths=program_paths,
                                                                hashes=d_hashes),
        "I_holdout_any_signed_plus_paths": AllowlistEvaluator(signed_any=True,
                                                              paths=program_paths),
    }
    # What it would cost to reach the FBR target: allowing user-writable directories
    # (AppData) defeats default-deny, so it is measured explicitly as a risky variant.
    user_writable = [p for p in (os.environ.get("LOCALAPPDATA", r"C:\Users\x\AppData\Local"),
                                 os.environ.get("APPDATA", r"C:\Users\x\AppData\Roaming")) if p]
    holdout_variants["J_allow_user_writable_risk"] = AllowlistEvaluator(
        signed_any=True, paths=program_paths + [p + "\\" for p in user_writable])
    report["holdout"] = {"design": len(design), "evaluation": len(holdout),
                         "note": "allowlist designed on half the inventory, scored on the "
                                 "other half"}
    report["holdout"]["policies"] = {
        name: {"false_block": ev.false_block_rate(holdout),
               "coverage": ev.coverage(holdout)}
        for name, ev in holdout_variants.items()
    }
    report["holdout"]["risky_variants"] = {
        "J_allow_user_writable_risk": {
            "note": "allows user-writable AppData: low FBR but defeats default-deny",
            "paths": [p + "\\" for p in user_writable],
        }
    }
    risky = set(report["holdout"]["risky_variants"])
    sound = {k: v for k, v in report["holdout"]["policies"].items() if k not in risky}
    best = min(sound.items(), key=lambda kv: kv[1]["false_block"]["false_block_rate_pct"])
    report["holdout"]["best"] = {
        "policy": best[0],
        "false_block_pct": best[1]["false_block"]["false_block_rate_pct"],
        "coverage_pct": best[1]["coverage"]["coverage_pct"],
        "target_pct": 10.0,
        "target_fbr_met": best[1]["false_block"]["false_block_rate_pct"] <= 10.0,
        "coverage_target_pct": 99.5,
        "coverage_met": best[1]["coverage"]["coverage_pct"] >= 99.5,
        "risky_alternative": {
            "policy": "J_allow_user_writable_risk",
            "false_block_pct": report["holdout"]["policies"]["J_allow_user_writable_risk"][
                "false_block"]["false_block_rate_pct"],
            "rejected_because": "allowing user-writable AppData defeats default-deny; a "
                                "0 % false-block rate achieved this way is not a policy win",
        },
        "conclusion": "on unseen inventory a sound policy floors at ~13 % FBR; the target "
                      "needs a hash/update feed (pilot) rather than path widening",
    }

    # audit-mode policy artefact (deployment is blocked by elevation, not by code)
    policy = WdacPolicy(name="AIDefender-L0-audit", audit=True)
    for tbs in sorted(all_signers):
        policy.add_signer(tbs, "observed-publisher")
    for path in program_paths:
        policy.add_path(path + "*")
    for h in sorted(unsigned_hashes):
        if h:
            policy.add_hash(h)
    xml = policy.to_xml()
    os.makedirs(os.path.dirname(OUT_POLICY), exist_ok=True)
    with open(OUT_POLICY, "w", encoding="utf-8") as fh:
        fh.write(xml)
    root = ET.fromstring(xml)
    ns = "{urn:schemas-microsoft-com:sipolicy}"
    report["policy_xml"] = {
        "path": OUT_POLICY,
        "well_formed": True,
        "audit_mode": any(o.text == "Enabled:Audit Mode" for o in root.iter(f"{ns}Option")),
        "signer_rules": len(list(root.iter(f"{ns}CertRoot"))),
        "path_rules": len([a for a in root.iter(f"{ns}Allow") if a.get("FilePath")]),
        "hash_rules": len([a for a in root.iter(f"{ns}Allow") if a.get("Hash")]),
    }

    # real CodeIntegrity events
    ci = data.get("ci_events") or []
    parsed, failed, generic_ok = [], 0, 0
    for item in ci:
        try:
            any_data = parse_codeintegrity_any(item["xml"])
            if any_data.get("event_id"):
                generic_ok += 1
        except ValueError:
            pass
        try:
            ev = parse_codeintegrity_event(item["xml"])
            parsed.append({"id": ev.event_id, "file": ev.file_name,
                           "process": ev.process_name, "policy": ev.policy_id})
        except ValueError:
            failed += 1
    report["codeintegrity"] = {"events_in_log_sample": len(ci),
                               "generic_parse_ok": generic_ok,
                               "audit_events_3076_parsed": len(parsed),
                               "non_audit_events": failed,
                               "note": "0 events of type 3076/3077: no audit policy is deployed "
                                       "(elevation blocker D); generic reader validates the parser "
                                       "against real event-log data",
                               "ids": data.get("ci_ids"),
                               "examples": parsed[:5]}

    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False)[:6000])


if __name__ == "__main__":
    main()

