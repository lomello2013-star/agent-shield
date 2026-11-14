import base64
import hashlib
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from core.daemon import Daemon
from core.ipc import (FORBIDDEN, INVALID_PARAMS, RpcClient, RpcError, RpcServer,
                      build_daemon_registry, free_pipe_name)
from core.policy_state import canonical_policy


def make_policy():
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    pub_pem = public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    key_id = hashlib.sha256(public.public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()[:16]
    policy = {"policy_id": "p1", "version": "v1", "channel": "stable",
              "key_id": key_id,
              "content": {"schema_version": "1.0", "sources": [],
                          "thresholds": {"min_confidence": 0.6}}}
    policy["signature"] = base64.b64encode(
        private.sign(canonical_policy(policy))).decode()
    return policy, pub_pem


def test_policy_state_apply_and_commands(tmp_path):
    daemon = Daemon(str(tmp_path), collectors=[])
    address = free_pipe_name("stml-phase-b")
    server = RpcServer(address, b"k" * 32,
                       {"admin": "admin", "operator": "operator", "viewer": "viewer"},
                       build_daemon_registry(daemon))
    server.start()
    time.sleep(0.05)
    policy, pub_pem = make_policy()
    try:
        viewer = RpcClient(address, b"k" * 32, "viewer")
        operator = RpcClient(address, b"k" * 32, "operator")
        admin = RpcClient(address, b"k" * 32, "admin")
        try:
            assert viewer.call("policy_state")["version"] is None
            with pytest.raises(RpcError) as exc:
                viewer.call("apply_policy", {"policy": policy, "pubkey": pub_pem,
                                             "dry_run": True})
            assert exc.value.code == FORBIDDEN

            dry = operator.call("apply_policy", {"policy": policy, "pubkey": pub_pem,
                                                 "dry_run": True})
            assert dry["accepted"] is True and dry["dry_run"] is True
            assert operator.call("policy_state")["version"] is None

            applied = operator.call("apply_policy", {"policy": policy, "pubkey": pub_pem,
                                                     "dry_run": False})
            assert applied["accepted"] is True
            assert operator.call("policy_state")["version"] == "v1"
            assert daemon.safe_mode.is_safe is False

            bad = dict(policy)
            bad["version"] = "v2"
            with pytest.raises(RpcError) as exc:
                operator.call("apply_policy", {"policy": bad, "pubkey": pub_pem,
                                               "dry_run": True})
            assert exc.value.code == INVALID_PARAMS

            cmd = admin.call("command_enqueue", {"kind": "isolate",
                                                 "payload": {"isolated": True}})
            pending = operator.call("command_poll")["commands"]
            assert [c["command_id"] for c in pending] == [cmd["command_id"]]
            ack = operator.call("command_ack", {"command_id": cmd["command_id"]})
            assert ack["isolated"] is True
            assert daemon.isolated is True
            assert operator.call("command_poll")["commands"] == []
        finally:
            viewer.close()
            operator.close()
            admin.close()
    finally:
        server.stop()
        daemon.stop()
