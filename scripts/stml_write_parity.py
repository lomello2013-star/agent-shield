"""P5 write-path parity: policy -> approval -> rollout on Python and Rust.

Starts a temporary Python reference server and a Rust server on PostgreSQL
(`stml_parity_write`), enrolls one agent in each, then runs the same signed
policy/approval/rollout sequence and compares the outcome.

Requires PostgreSQL localhost + psql + built Rust binary. Exit 1 on mismatch.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from stml.connector.signing import generate_keypair, key_id, load_private, sign
from stml.contracts.policy import canonical_policy
from stml.server.app import ServerConfig, start_server
from stml.server.store import Store

PSQL = r"C:\Program Files\PostgreSQL\16\bin\psql.exe"
DB = "stml_parity_write"
RUST_BIN = ROOT / "rust" / "stml-server" / "target" / "debug" / "stml-server.exe"


def http(base: str, method: str, path: str, payload=None, token: str = "") -> tuple[int, dict]:
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def psql(sql: str, db: str = "postgres") -> None:
    env = dict(os.environ, PGPASSWORD="postgres")
    subprocess.run([PSQL, "-h", "127.0.0.1", "-U", "postgres", "-d", db, "-c", sql],
                   check=True, env=env, capture_output=True)


def setup_rust_db() -> None:
    psql(f'DROP DATABASE IF EXISTS "{DB}" WITH (FORCE);')
    psql(f'CREATE DATABASE "{DB}" OWNER stml;')
    env = dict(os.environ, PGPASSWORD="stml")
    for name in ("0001_init.sql", "0002_enrol_nonces.sql", "0003_rollouts.sql",
                 "0004_trust_audit.sql", "0005_learning.sql", "0006_commands.sql"):
        subprocess.run([PSQL, "-h", "127.0.0.1", "-U", "stml", "-d", DB,
                        "-f", str(ROOT / "rust" / "stml-server" / "migrations" / name)],
                       check=True, env=env, capture_output=True)
    subprocess.run([PSQL, "-h", "127.0.0.1", "-U", "stml", "-d", DB, "-c",
                    "INSERT INTO enrol_tokens(token,tenant_id,created_at) VALUES ('parity','t',now());"],
                   check=True, env=env, capture_output=True)


def enroll(base: str, token: str, tmp: Path, name: str) -> str:
    priv, pub = tmp / f"{name}.pem", tmp / f"{name}.pub"
    generate_keypair(priv, pub)
    code, body = http(base, "POST", "/v0/enrol", {
        "tenant_id": "t", "enrolment_token": token, "hostname": name,
        "os": "windows", "arch": "x64", "agent_version": "10.0.19045",
        "pubkey": pub.read_text(encoding="utf-8")})
    if code not in (200, 201):
        raise RuntimeError(f"enrol {name}: {code} {body}")
    return body["agent_id"]


def run_flow(base: str, tmp: Path, roles: dict[str, str], policy: dict,
             agent_id: str) -> dict:
    out = {}
    code, body = http(base, "POST", "/v0/policies", policy, token=roles["admin"])
    out["policy"] = [code, body]
    if code not in (200, 201):
        return out
    approval_id = body.get("approval_id")
    code, body = http(base, "POST", "/v0/rollouts",
                      {"tenant_id": "t", "policy_id": policy["policy_id"],
                       "version": policy["version"], "percent": 1},
                      token=roles["admin"])
    out["rollout_before_approval"] = [code, body]
    code, body = http(base, "POST", f"/v0/approvals/{approval_id}/approve", {},
                      token=roles["approver"])
    out["approve"] = [code, body]
    code, body = http(base, "POST", "/v0/rollouts",
                      {"tenant_id": "t", "policy_id": policy["policy_id"],
                       "version": policy["version"], "percent": 1},
                      token=roles["admin"])
    out["rollout"] = [code, body]
    if code not in (200, 201):
        return out
    rollout_id = body["rollout_id"]
    promotes = []
    for _ in range(3):
        code, body = http(base, "POST", f"/v0/rollouts/{rollout_id}/promote", {},
                          token=roles["admin"])
        promotes.append([code, body.get("percent"), body.get("status")])
    out["promotes"] = promotes
    code, body = http(base, "GET", f"/v0/rollouts/{rollout_id}", token=roles["viewer"])
    out["final"] = [code, body.get("status"), body.get("percent")]
    return out


def main() -> int:
    if not RUST_BIN.exists():
        print(json.dumps({"ok": False, "error": "Rust binary missing", "path": str(RUST_BIN)}))
        return 1
    tmp = Path(tempfile.mkdtemp(prefix="stml-write-parity-"))
    rust = None
    py_server = None
    store = None
    try:
        setup_rust_db()
        policy_priv, policy_pub = tmp / "policy.pem", tmp / "policy.pub"
        generate_keypair(policy_priv, policy_pub)
        policy = {"policy_id": "parity-policy", "version": "v1", "channel": "stable",
                  "content": {"schema_version": "1.0", "sources": [],
                              "thresholds": {"min_confidence": 0.5}},
                  "tenant_id": "t",
                  "key_id": key_id(load_private(policy_priv).public_key())}
        policy["signature"] = sign(load_private(policy_priv), canonical_policy(
            policy["policy_id"], policy["version"], policy["channel"], policy["content"]))

        store = Store(tmp / "python.sqlite3")
        py_config = ServerConfig(tenant_id="t", admin_token="admin", viewer_token="viewer",
                                 approver_token="approver",
                                 policy_pubkey=policy_pub.read_text(encoding="utf-8"),
                                 require_approval=True)
        py_server, _ = start_server(store, py_config, port=0)
        py_port = py_server.server_address[1]
        py_token = store.create_enrol_token("t")
        py_agent = enroll(f"http://127.0.0.1:{py_port}", py_token, tmp, "py-agent")

        rust_env = dict(os.environ,
                        DATABASE_URL=f"postgres://stml:stml@127.0.0.1:5432/{DB}",
                        STML_BIND="127.0.0.1:18101", STML_ADMIN_TOKEN="admin",
                        STML_VIEWER_TOKEN="viewer", STML_APPROVER_TOKEN="approver",
                        STML_POLICY_PUBKEY_FILE=str(policy_pub),
                        STML_TRUST_DIR=str(tmp / "rust-trust"),
                        STML_REQUIRE_APPROVAL="1")
        rust = subprocess.Popen([str(RUST_BIN)], env=rust_env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        rust_base = "http://127.0.0.1:18101"
        for _ in range(50):
            try:
                if http(rust_base, "GET", "/health")[0] == 200:
                    break
            except Exception:
                pass
            time.sleep(0.2)
        else:
            raise RuntimeError("Rust server did not start")
        rust_agent = enroll(rust_base, "parity", tmp, "rust-agent")

        py = run_flow(f"http://127.0.0.1:{py_port}", tmp,
                      {"admin": "admin", "viewer": "viewer", "approver": "approver"},
                      policy, py_agent)
        ru = run_flow(rust_base, tmp,
                      {"admin": "admin", "viewer": "viewer", "approver": "approver"},
                      policy, rust_agent)
        ok = (py.get("rollout_before_approval", [0])[0] == 409
              and ru.get("rollout_before_approval", [0])[0] == 409
              and py.get("rollout", [0])[0] in (200, 201)
              and ru.get("rollout", [0])[0] in (200, 201)
              and py.get("final", [None, None])[1] == "completed"
              and ru.get("final", [None, None])[1] == "completed")
        print(json.dumps({"ok": ok, "python": py, "rust": ru}, ensure_ascii=False, indent=2))
        return 0 if ok else 1
    finally:
        if rust is not None:
            rust.terminate()
            try:
                rust.wait(timeout=5)
            except subprocess.TimeoutExpired:
                rust.kill()
        if py_server is not None:
            py_server.shutdown()
            py_server.server_close()
        if store is not None:
            store.close()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
