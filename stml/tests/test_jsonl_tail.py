import json

from stml.connector.jsonl_tail import JsonlTailer


def test_reads_only_new_complete_lines(tmp_path):
    path = tmp_path / "events.jsonl"
    tailer = JsonlTailer(tmp_path / "state.json")
    path.write_text(json.dumps({"n": 1}) + "\n", encoding="utf-8")
    assert [r["n"] for r in tailer.read(path)] == [1]
    assert tailer.read(path) == []
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"n": 2}) + "\n")
    assert [r["n"] for r in tailer.read(path)] == [2]


def test_partial_line_is_not_consumed(tmp_path):
    path = tmp_path / "events.jsonl"
    tailer = JsonlTailer(tmp_path / "state.json")
    path.write_text('{"n": 1}\n{"n": 2', encoding="utf-8")
    assert [r["n"] for r in tailer.read(path)] == [1]
    with path.open("a", encoding="utf-8") as fh:
        fh.write("}\n")
    assert [r["n"] for r in tailer.read(path)] == [2]


def test_rotation_resets_offset(tmp_path):
    path = tmp_path / "events.jsonl"
    tailer = JsonlTailer(tmp_path / "state.json")
    path.write_text('{"n": 1}\n{"n": 2}\n', encoding="utf-8")
    assert len(tailer.read(path)) == 2
    path.write_text('{"n": 3}\n', encoding="utf-8")
    assert [r["n"] for r in tailer.read(path)] == [3]


def test_invalid_json_is_skipped(tmp_path):
    path = tmp_path / "events.jsonl"
    tailer = JsonlTailer(tmp_path / "state.json")
    path.write_text("not json\n" + json.dumps({"n": 1}) + "\n", encoding="utf-8")
    assert [r["n"] for r in tailer.read(path)] == [1]
    assert tailer.skipped == 1
