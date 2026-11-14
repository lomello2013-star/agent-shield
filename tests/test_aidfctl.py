"""CLI params loading: --params-file avoids native shell quoting of JSON."""

from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest


def _module():
    path = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "aidfctl.py"
    spec = importlib.util.spec_from_file_location("aidfctl_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_load_params_from_file(tmp_path):
    path = tmp_path / "confirm.json"
    path.write_text(json.dumps({"confirmation_id": "x", "decision": "approved"}),
                    encoding="utf-8")
    assert _module().load_params(None, str(path))["decision"] == "approved"


def test_load_params_rejects_non_object(tmp_path):
    path = tmp_path / "params.json"
    path.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(ValueError):
        _module().load_params(None, str(path))
