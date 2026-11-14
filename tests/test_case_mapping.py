import uuid

from stml.contracts.case_memory import case_to_memory_entry


def test_case_to_memory_entry():
    verdict = {"verdict_id": str(uuid.uuid4()), "trace_id": str(uuid.uuid4()),
               "event_id": str(uuid.uuid4()), "detector": "memory_model",
               "platform": "windows", "confidence": 0.9, "severity": "high",
               "reason_code": "case", "reason_text": "confirmed"}
    case = {"case_id": str(uuid.uuid4()), "report_id": "r1", "label": "TP",
            "features": {"f1": 1, "f2": 0.5}}
    entry = case_to_memory_entry(case, verdict, "windows")
    assert entry["case_id"] == case["case_id"]
    assert entry["confirmed_by"] == "analyst"
    assert entry["platform"] == "windows"
    assert entry["features"] == {"f1": 1.0, "f2": 0.5}
