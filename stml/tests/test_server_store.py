from stml.server.store import Store


def test_enrolment_and_duplicate_token(tmp_path):
    store = Store(tmp_path / "db.sqlite3")
    token = store.create_enrol_token("t1")
    agent_id = store.enrol(token, "t1", "host1", "windows", "x64", "0.1.0", "pem")
    assert store.agent(agent_id).hostname == "host1"
    try:
        store.enrol(token, "t1", "host2", "linux", "x64", "0.1.0", "pem")
    except PermissionError:
        pass
    else:
        raise AssertionError("token must be single-use")


def test_heartbeat_inventory_isolate_and_audit(tmp_path):
    store = Store(tmp_path / "db.sqlite3")
    token = store.create_enrol_token("t")
    agent_id = store.enrol(token, "t", "h", "windows", "x64", "0.1.0", "pem")
    assert store.heartbeat(agent_id, "healthy", {}) is False
    store.inventory(agent_id, {"os": "windows", "agent_version": "0.2.0"})
    assert store.agent(agent_id).agent_version == "0.2.0"
    store.isolate(agent_id, True)
    assert store.heartbeat(agent_id, "healthy", {}) is True
    store.isolate(agent_id, False)
    assert store.heartbeat(agent_id, "healthy", {}) is False
    assert store.verify_audit() is True


def test_reports_idempotent_and_nonce_replay(tmp_path):
    store = Store(tmp_path / "db.sqlite3")
    report = {"report_id": "r1", "tenant_id": "t", "agent_id": "a",
              "priority": "P0", "kind": "incident", "payload": {}}
    assert store.ingest([report]) == ["r1"]
    assert store.ingest([report]) == ["r1"]  # duplicate still acked
    assert len(store.reports()) == 1
    assert store.seen_nonce("n1") is False
    assert store.seen_nonce("n1") is True
