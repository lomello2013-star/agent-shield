import json

from stml import cli
from stml.server.app import ServerConfig, start_server
from stml.server.store import Store


def _server(tmp_path):
    store = Store(tmp_path / "db.sqlite3")
    server, _ = start_server(store, ServerConfig(
        tenant_id="t", admin_token="admin", viewer_token="viewer",
        approver_token="approver"), port=0)
    port = server.server_address[1]
    tokens = tmp_path / "tokens.json"
    tokens.write_text(json.dumps({"viewer_token": "viewer", "admin_token": "admin",
                                  "approver_token": "approver"}), encoding="utf-8")
    return store, server, f"http://127.0.0.1:{port}", str(tokens)


def test_cli_health_fleet_and_approvals(tmp_path, capsys):
    store, server, url, tokens = _server(tmp_path)
    try:
        assert cli.main(["--url", url, "--tokens-file", tokens, "--json", "health"]) == 0
        assert json.loads(capsys.readouterr().out)["ok"] is True
        assert cli.main(["--url", url, "--tokens-file", tokens, "fleet", "list"]) == 0
        assert "HOST" in capsys.readouterr().out
        assert cli.main(["--url", url, "--tokens-file", tokens, "approvals", "list"]) == 0
        assert "ID" in capsys.readouterr().out
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_cli_bad_token_and_bad_policy(tmp_path, capsys):
    store, server, url, tokens = _server(tmp_path)
    try:
        bad = json.loads(open(tokens, encoding="utf-8").read())
        bad["viewer_token"] = "wrong"
        bad_path = tmp_path / "bad.json"
        bad_path.write_text(json.dumps(bad), encoding="utf-8")
        assert cli.main(["--url", url, "--tokens-file", str(bad_path),
                         "fleet", "list"]) == 1
        assert "HTTP 401" in capsys.readouterr().err
        missing = tmp_path / "missing.json"
        assert cli.main(["--url", url, "--tokens-file", tokens,
                         "policy", "apply", str(missing)]) == 1
        assert "not found" in capsys.readouterr().err
    finally:
        server.shutdown()
        server.server_close()
        store.close()
