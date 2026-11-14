from stml.server.backup import backup, restore
from stml.server.store import Store
from stml.trust.service import TrustService


def test_backup_restore_db_and_trust(tmp_path):
    db = tmp_path / "db.sqlite3"
    trust_dir = tmp_path / "trust"
    store = Store(db)
    trust = TrustService(store, trust_dir)
    token = store.create_enrol_token("t")
    store.enrol(token, "t", "host1", "windows", "x64", "0.1.0", "pem")
    key = trust.create_key("policy")
    archive = tmp_path / "backup.zip"
    info = backup(db, trust_dir, archive)
    assert info["bytes"] > 0
    store.close()

    db2 = tmp_path / "restored" / "db.sqlite3"
    trust2 = tmp_path / "restored" / "trust"
    restore(archive, db2, trust2)
    store2 = Store(db2)
    try:
        assert [a.hostname for a in store2.agents()] == ["host1"]
        trust2_service = TrustService(store2, trust2)
        assert trust2_service.key(key["key_id"]) is not None
    finally:
        store2.close()
