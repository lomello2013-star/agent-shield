"""Stage 11 measurement: tamper-evident log, integrity manifest, startup self-test.

Writes artifacts/stage11_report.json.
"""

from __future__ import annotations

import json
import os
import shutil
import statistics
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.policy import verify_immutable
from core.selfprotect import HashChainLog, IntegrityManifest, SelfTest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT = os.path.join(HERE, "artifacts", "stage11_report.json")


def p95(values):
    if not values:
        return None
    s = sorted(values)
    return round(s[min(len(s) - 1, int(len(s) * 0.95))], 3)


def measure_chain(n: int = 2000) -> dict:
    tmp = tempfile.mkdtemp(prefix="aidf_s11_")
    log = HashChainLog(os.path.join(tmp, "audit.jsonl"),
                       anchor_path=os.path.join(tmp, "anchor.json"))
    lat = []
    t0 = time.perf_counter()
    for i in range(n):
        t = time.perf_counter()
        log.append("probe", {"i": i})
        lat.append((time.perf_counter() - t) * 1000)
    total = time.perf_counter() - t0
    log.seal()
    t0 = time.perf_counter()
    verify = log.verify()
    verify_ms = (time.perf_counter() - t0) * 1000
    return {"records": n, "append_ms_p50": round(statistics.median(lat), 3),
            "append_ms_p95": p95(lat), "records_per_s": round(n / total, 0),
            "total_s": round(total, 2),
            "verify_ms": round(verify_ms, 3), "verify_ok": verify.ok,
            "verify_records": verify.records,
            "bytes": os.path.getsize(log.path)}


def measure_tamper_detection() -> dict:
    results = {}

    def fresh(n=5):
        tmp = tempfile.mkdtemp(prefix="aidf_t_")
        log = HashChainLog(os.path.join(tmp, "log.jsonl"),
                           anchor_path=os.path.join(tmp, "anchor.json"))
        for i in range(n):
            log.append("a", {"i": i})
        log.seal()
        return log

    # 1. edit payload
    log = fresh()
    lines = open(log.path, encoding="utf-8").read().splitlines()
    rec = json.loads(lines[1]); rec["payload"]["i"] = 999
    lines[1] = json.dumps(rec)
    open(log.path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    results["payload_edit"] = HashChainLog(log.path, anchor_path=log.anchor_path).verify().ok

    # 2. delete middle
    log = fresh()
    lines = open(log.path, encoding="utf-8").read().splitlines()
    open(log.path, "w", encoding="utf-8").write("\n".join(lines[:2] + lines[3:]) + "\n")
    results["delete_middle"] = HashChainLog(log.path, anchor_path=log.anchor_path).verify().ok

    # 3. reorder
    log = fresh()
    lines = open(log.path, encoding="utf-8").read().splitlines()
    open(log.path, "w", encoding="utf-8").write("\n".join([lines[1], lines[0]] + lines[2:]) + "\n")
    results["reorder"] = HashChainLog(log.path, anchor_path=log.anchor_path).verify().ok

    # 4. truncate tail (anchor catches it)
    log = fresh()
    lines = open(log.path, encoding="utf-8").read().splitlines()
    open(log.path, "w", encoding="utf-8").write("\n".join(lines[:3]) + "\n")
    results["truncate_tail"] = HashChainLog(log.path, anchor_path=log.anchor_path).verify().ok

    # 5. append forged record with wrong prev
    log = fresh()
    with open(log.path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"seq": 6, "ts": "x", "type": "a", "payload": {},
                             "prev": "0" * 64, "hash": "f" * 64}) + "\n")
    results["forged_append"] = HashChainLog(log.path, anchor_path=log.anchor_path).verify().ok

    detected = sum(1 for ok in results.values() if not ok)
    return {"modes": results, "tamper_modes": len(results), "detected": detected,
            "detection_rate": round(detected / len(results), 3), "target": 1.0}


def measure_integrity() -> dict:
    tmp = tempfile.mkdtemp(prefix="aidf_int_")
    root = os.path.join(tmp, "root")
    os.makedirs(root)
    sources = [os.path.join(HERE, "rules", "base.json"),
               os.path.join(HERE, "rules", "techniques.json")]
    schemas_dir = os.path.join(HERE, "schemas", "v3", "json_schema")
    if os.path.isdir(schemas_dir):
        sources += [os.path.join(schemas_dir, f) for f in os.listdir(schemas_dir)][:5]
    copies = []
    for src in sources:
        dst = os.path.join(root, os.path.basename(src))
        shutil.copyfile(src, dst)
        copies.append(dst)

    manifest = IntegrityManifest(root, os.path.join(root, "manifest.json"))
    t0 = time.perf_counter()
    manifest.seal(copies)
    seal_ms = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    clean = manifest.verify()
    verify_ms = (time.perf_counter() - t0) * 1000

    tampered = copies[0]
    with open(tampered, "a", encoding="utf-8") as fh:
        fh.write("\n// injected\n")
    dirty = manifest.verify()

    return {"files": len(copies), "seal_ms": round(seal_ms, 3),
            "verify_ms": round(verify_ms, 3), "clean_ok": clean["ok"],
            "tamper_detected": not dirty["ok"],
            "modified": dirty["modified"], "checked": clean["checked"]}


def measure_self_test() -> dict:
    tmp = tempfile.mkdtemp(prefix="aidf_st_")
    log = HashChainLog(os.path.join(tmp, "audit.jsonl"),
                       anchor_path=os.path.join(tmp, "anchor.json"))
    log.append("boot", {"version": "0.1.0"})
    manifest = IntegrityManifest(tmp, os.path.join(tmp, "manifest.json"))
    f = os.path.join(tmp, "config.json")
    with open(f, "w", encoding="utf-8") as fh:
        fh.write('{"schema_version": "1.0"}')
    manifest.seal([f])

    st = SelfTest()
    st.register("immutable_policy", st.immutable_check(verify_immutable))
    st.register("audit_chain", st.log_check(log))
    st.register("file_integrity", st.integrity_check(manifest))
    clean = st.run()

    with open(f, "a", encoding="utf-8") as fh:
        fh.write(" ")
    tampered = st.run()
    return {"clean_ok": clean["ok"], "clean_ms": clean["duration_ms"],
            "tampered_ok": tampered["ok"], "failed_after_tamper": tampered["failed"],
            "checks": [c["check"] for c in clean["checks"]]}


def main() -> None:
    report = {
        "environment": {"python": sys.version.split()[0]},
        "hash_chain": measure_chain(),
        "tamper_detection": measure_tamper_detection(),
        "integrity": measure_integrity(),
        "self_test": measure_self_test(),
        "note": "user-mode self-protection only: PPL/ELAM/fs-verity/IMA appraisal need "
                "signing and kernel components (blocked), so they are not claimed",
    }
    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    with open(REPORT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
