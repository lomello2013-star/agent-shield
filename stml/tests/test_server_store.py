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


def test_tenant_isolation_policies_agents_approvals(tmp_path):
    store = Store(tmp_path / "db.sqlite3")
    for tenant in ("a", "b"):
        token = store.create_enrol_token(tenant)
        store.enrol(token, tenant, f"h-{tenant}", "windows", "x64", "0.1.0", "pem")
    for tenant in ("a", "b"):
        store.add_policy({"policy_id": "p", "version": "v1", "channel": "stable",
                          "content": {}, "key_id": "k", "signature": "s",
                          "tenant_id": tenant})
    assert len(store.policies("a")) == 1
    assert len(store.agents("a")) == 1
    assert store.agents("a")[0].hostname == "h-a"
    approval = store.propose_approval("policy", "p@v1", {}, "op", "a")
    assert store.is_approved("policy", "p@v1", "b") is False
    store.decide_approval(approval, "approved", "approver")
    assert store.is_approved("policy", "p@v1", "a") is True
    assert store.is_approved("policy", "p@v1", "b") is False


def test_staged_rollout_1_10_50_100(tmp_path):
    store = Store(tmp_path / "db.sqlite3")
    for i in range(20):
        token = store.create_enrol_token("t")
        store.enrol(token, "t", f"h{i:02d}", "windows", "x64", "0.1.0", "pem")
    store.add_policy({"policy_id": "p", "version": "v1", "channel": "stable",
                      "content": {}, "key_id": "k", "signature": "s", "tenant_id": "t"})
    rollout = store.start_rollout("p", "v1", 1, "t")
    assert rollout["percent"] == 1 and len(rollout["applied"]) == 1

    promoted = store.promote_rollout(rollout["rollout_id"])
    assert promoted["percent"] == 10
    promoted = store.promote_rollout(rollout["rollout_id"])
    assert promoted["percent"] == 50
    promoted = store.promote_rollout(rollout["rollout_id"])
    assert promoted["percent"] == 100 and promoted["status"] == "completed"
    assert len([a for a in store.agents("t") if a.policy_version == "v1"]) == 20
    try:
        store.promote_rollout(rollout["rollout_id"])
    except ValueError:
        pass
    else:
        raise AssertionError("completed rollout cannot be promoted")
