import os

from core.coverage import (
    DETECTION_TARGET_PCT,
    PREVENTION_TARGET_PCT,
    build_matrix,
    load_techniques,
    render_markdown,
    summarize,
    write_matrix,
)
from core.rules import load_rules

RULES = load_rules(["rules/base.json"])
TECH = load_techniques("rules/techniques.json")
ROWS = build_matrix(TECH, RULES)
SUMMARY = summarize(ROWS)


def test_matrix_covers_every_in_scope_technique():
    assert len(ROWS) == len(TECH) == 18
    assert {r["technique"] for r in ROWS} == {t.id for t in TECH}


def test_every_rule_maps_to_a_matrix_technique():
    mapped = {r for row in ROWS for r in row["rules"]}
    assert {r.id for r in RULES} <= mapped


def test_detection_and_prevention_totals_are_measured():
    assert SUMMARY["detected"] == 18
    assert SUMMARY["techniques_in_scope"] == 18
    assert SUMMARY["detection_pct"] == 100.0
    assert SUMMARY["prevented"] == 18          # F14: T1070/T1562/T1041 closed
    assert SUMMARY["prevention_pct"] == 100.0


def test_gate_flags_reflect_targets():
    assert SUMMARY["passes_detection"] == (SUMMARY["detection_pct"] >= DETECTION_TARGET_PCT)
    assert SUMMARY["passes_prevention"] == (SUMMARY["prevention_pct"] >= PREVENTION_TARGET_PCT)
    assert SUMMARY["passes_detection"] is True
    assert SUMMARY["passes_prevention"] is True
    # detection is mapped for every technique; prevention gaps stay explicit
    assert SUMMARY["gaps_detection"] == []
    assert SUMMARY["gaps_prevention"] == []


def test_prevention_is_a_subset_of_detection():
    for row in ROWS:
        assert set(row["prevention_rules"]) <= set(row["rules"])


def test_markdown_renders_rows_and_gaps():
    md = render_markdown(ROWS, SUMMARY)
    assert "T1059" in md and "WIN-EXEC-TEMP-001" in md
    assert f"{SUMMARY['detection_pct']}%" in md
    # F14 closed the prevention gaps, so the gaps section is omitted entirely
    assert SUMMARY["gaps_prevention"] == []
    assert "Пробелы предотвращения" not in md


def test_write_matrix_creates_file(tmp_path):
    path = os.path.join(tmp_path, "coverage-matrix.md")
    content = write_matrix(path, ROWS, SUMMARY)
    assert os.path.exists(path)
    with open(path, encoding="utf-8") as fh:
        assert fh.read() == content
