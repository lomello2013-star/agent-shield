"""STML Fleet Core HTTP API (S1 MVP) and read-only dashboard."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from stml.connector.signing import key_id, public_from_pem, verify
from stml.contracts.policy import canonical_policy
from stml.contracts.v0 import Heartbeat, Inventory
from stml.learning.service import LearningService
from stml.server.bus import build_bus
from stml.server.store import Store
from stml.server.tls import make_server_context
from stml.server.tracing import trace_id_from
from stml.trust.service import TrustError, TrustService

MAX_BODY = 2 * 1024 * 1024
SKEW_S = 300


@dataclass
class ServerConfig:
    tenant_id: str = "default"
    admin_token: str = ""
    viewer_token: str = ""
    db_path: str = "stml-server.sqlite3"
    policy_pubkey: str = ""
    approver_token: str = ""
    trust_dir: str = ""
    trust_backend: str = "file"
    require_approval: bool = True
    event_bus: str = "local"
    tls_cert: str = ""
    tls_key: str = ""
    tls_ca: str = ""
    require_client_cert: bool = True


class StmlServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr: tuple[str, int], store: Store, config: ServerConfig) -> None:
        super().__init__(addr, Handler)
        self.store = store
        self.config = config
        self.trust = TrustService(store, config.trust_dir or str(store.path) + ".trust",
                                  config.trust_backend)
        if not config.policy_pubkey:
            key = self.trust.active("policy") or self.trust.create_key("policy")
            config.policy_pubkey = key["public_pem"]
        self.learning = LearningService(store, self.trust)
        self.bus = build_bus(config.event_bus)
        self.started_at = time.time()
        if config.tls_cert:
            ctx = make_server_context(config.tls_cert, config.tls_key,
                                      config.tls_ca, config.require_client_cert)
            self.socket = ctx.wrap_socket(self.socket, server_side=True)


class Handler(BaseHTTPRequestHandler):
    server: StmlServer

    def log_message(self, fmt: str, *args: Any) -> None:  # keep test output quiet
        return

    # -- helpers ---------------------------------------------------------
    def _start_trace(self) -> None:
        self.trace_id = trace_id_from({k.lower(): v for k, v in self.headers.items()})

    def _client_revoked(self) -> bool:
        if not self.server.config.tls_cert:
            return False
        try:
            peer = self.connection.getpeercert()
        except (OSError, ValueError):
            return False
        serial = (peer or {}).get("serialNumber", "")
        return bool(serial) and self.server.store.is_cert_revoked(serial)

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_BODY:
            raise ValueError("body too large")
        return self.rfile.read(length) if length else b""

    def _send(self, code: int, payload: Any) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        if hasattr(self, "trace_id"):
            self.send_header("X-Trace-ID", self.trace_id)
        self.end_headers()
        self.wfile.write(raw)

    def _error(self, code: int, message: str) -> None:
        self._send(code, {"error": message})

    def _auth(self, role: str) -> bool:
        header = self.headers.get("Authorization", "")
        token = header.removeprefix("Bearer ").strip()
        cfg = self.server.config
        if role == "approver":
            if token != cfg.approver_token:
                self._error(403, "approver required")
                return False
            return True
        if role == "admin":
            if token != cfg.admin_token:
                self._error(403, "admin required")
                return False
            return True
        if token not in {cfg.admin_token, cfg.viewer_token, cfg.approver_token}:
            self._error(401, "unauthorized")
            return False
        return True

    def _agent(self, body: dict[str, Any]) -> Any:
        agent_id = body.get("agent_id")
        if not isinstance(agent_id, str):
            self._error(400, "agent_id required")
            return None
        agent = self.server.store.agent(agent_id)
        if agent is None:
            self._error(404, "unknown agent")
            return None
        return agent

    def _verify_signed(self, raw: bytes, body: dict[str, Any], agent: Any) -> bool:
        signature = self.headers.get("X-STML-Signature", "")
        if not signature or not verify(public_from_pem(agent.pubkey), raw, signature):
            self._error(403, "bad signature")
            return False
        nonce = body.get("nonce")
        if not isinstance(nonce, str) or self.server.store.seen_nonce(nonce):
            self._error(409, "replayed nonce")
            return False
        try:
            sent = datetime.fromisoformat(str(body.get("sent_at")).replace("Z", "+00:00"))
        except ValueError:
            self._error(400, "sent_at required")
            return False
        if abs((datetime.now(timezone.utc) - sent).total_seconds()) > SKEW_S:
            self._error(409, "timestamp outside skew")
            return False
        return True

    def _verify_policy(self, body: dict[str, Any]) -> bool:
        if not self.server.config.policy_pubkey:
            self._error(503, "policy signing not configured")
            return False
        try:
            pub = public_from_pem(self.server.config.policy_pubkey)
        except Exception:  # noqa: BLE001
            self._error(500, "bad server policy pubkey")
            return False
        if body.get("key_id") != key_id(pub):
            self._error(403, "policy key_id mismatch")
            return False
        canonical = canonical_policy(str(body.get("policy_id", "")),
                                     str(body.get("version", "")),
                                     str(body.get("channel", "stable")),
                                     body.get("content") or {})
        if not verify(pub, canonical, str(body.get("signature", ""))):
            self._error(403, "bad policy signature")
            return False
        return True

    # -- GET -------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        self._start_trace()
        if self._client_revoked():
            self._error(403, "client certificate revoked")
            return
        parsed = urlparse(self.path)
        parts = parsed.path.strip("/").split("/")
        query = parse_qs(parsed.query)
        if parts == ["health"]:
            self._send(200, {"ok": True, "service": "stml", "tenant": self.server.config.tenant_id})
            return
        if parts and parts[0] == "ui":
            gui_dir = Path(__file__).resolve().parent.parent / "gui"
            name = "index.html" if len(parts) == 1 else parts[1]
            target = (gui_dir / name).resolve()
            if gui_dir.resolve() not in target.parents or not target.is_file():
                self._error(404, "not found")
                return
            data = target.read_bytes()
            ctype = "text/html; charset=utf-8" if target.suffix == ".html" else (
                "text/css" if target.suffix == ".css" else "application/javascript")
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if parts == [""]:
            page = DASHBOARD.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
            return
        if parts[:2] == ["v0", "agents"]:
            if not self._auth("viewer"):
                return
            if len(parts) == 2:
                self._send(200, {"agents": [a.__dict__ for a in
                                            self.server.store.agents(self.server.config.tenant_id)]})
            elif len(parts) == 3:
                agent = self.server.store.agent(parts[2])
                if agent is None:
                    self._error(404, "unknown agent")
                else:
                    self._send(200, agent.__dict__)
            return
        if parts == ["metrics"]:
            if not self._auth("admin"):
                return
            stats = self.server.store.stats()
            lines = [
                "# HELP stml_agents Agents by status",
                "# TYPE stml_agents gauge",
                f'stml_agents{{status="healthy"}} {stats["healthy"]}',
                f'stml_agents{{status="degraded"}} {stats["degraded"]}',
                f'stml_agents{{status="offline"}} {stats["offline"]}',
                f'stml_agents{{status="isolated"}} {stats["isolated"]}',
                "# HELP stml_reports_total Reports ingested",
                "# TYPE stml_reports_total counter",
                f"stml_reports_total {stats['reports']}",
                f"stml_reports_p0_total {stats['p0_reports']}",
                "# HELP stml_approvals_pending Pending approvals",
                "# TYPE stml_approvals_pending gauge",
                f"stml_approvals_pending {stats['approvals_pending']}",
                "# HELP stml_models_total Registered models",
                "# TYPE stml_models_total gauge",
                f"stml_models_total {stats['models']}",
                "# HELP stml_uptime_seconds Server uptime",
                "# TYPE stml_uptime_seconds gauge",
                f"stml_uptime_seconds {time.time() - self.server.started_at:.1f}",
            ]
            data = ("\n".join(lines) + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if parts == ["v0", "slo"]:
            if not self._auth("admin"):
                return
            stats = self.server.store.stats()
            self._send(200, {
                "uptime_s": round(time.time() - self.server.started_at, 1),
                "stats": stats,
                "audit_ok": self.server.store.verify_audit(),
                "bus_events": len(getattr(self.server.bus, "events", [])),
                "targets": {"availability": 0.995, "heartbeat_p95_s": 2.0,
                            "report_p0_loss": 0, "approval_sla_h": 48},
            })
            return
        if parts == ["v0", "telemetry"]:
            if self._auth("viewer"):
                self._send(200, {"telemetry": self.server.store.telemetry()})
            return
        if parts == ["v0", "cases"]:
            if self._auth("viewer"):
                self._send(200, {"cases": self.server.store.cases()})
            return
        if parts == ["v0", "models"]:
            if self._auth("viewer"):
                self._send(200, {"models": self.server.store.models(),
                                 "active": self.server.store.active_model()})
            return
        if parts == ["v0", "reports"]:
            if self._auth("viewer"):
                self._send(200, {"reports": self.server.store.reports()})
            return
        if parts == ["v0", "incidents"]:
            if self._auth("viewer"):
                reports = [r for r in self.server.store.reports()
                           if r["priority"] in {"P0", "P1"}]
                self._send(200, {"incidents": reports})
            return
        if parts == ["v0", "modules"]:
            if self._auth("viewer"):
                self._send(200, {"modules": MODULES})
            return
        if parts == ["v0", "ops"]:
            if self._auth("viewer"):
                self._send(200, {"stats": self.server.store.stats(),
                                 "uptime_s": round(time.time() - self.server.started_at, 1),
                                 "bus_events": len(getattr(self.server.bus, "events", [])),
                                 "modules": len(MODULES)})
            return
        if parts == ["v0", "audit", "verify"]:
            if self._auth("admin"):
                self._send(200, {"ok": self.server.store.verify_audit()})
            return
        if parts == ["v0", "audit", "export"]:
            if not self._auth("admin"):
                return
            rows = self.server.store.audit_export()
            fmt = (query.get("format") or ["json"])[0]
            if fmt == "cef":
                lines = [
                    "CEF:0|AIDefender|STML|1.0|{action}|{action}|5|actor={actor} target={target} hash={hash}".format(
                        action=r["action"], actor=r["actor"], target=r["target"], hash=r["hash"])
                    for r in rows
                ]
                payload = ("\n".join(lines) + "\n").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            else:
                self._send(200, {"audit": rows})
            return
        if parts == ["v0", "tls", "revoked"]:
            if self._auth("admin"):
                self._send(200, {"revoked": self.server.store.revoked_certs()})
            return
        if parts == ["v0", "approvals"]:
            if self._auth("viewer"):
                self._send(200, {"approvals": self.server.store.approvals(
                    tenant_id=self.server.config.tenant_id)})
            return
        if parts == ["v0", "trust", "keys"]:
            if self._auth("viewer"):
                keys = [{k: v for k, v in key.items() if k != "private_path"}
                        for key in self.server.trust.keys()]
                self._send(200, {"keys": keys})
            return
        if parts == ["v0", "policies"]:
            if self._auth("viewer"):
                self._send(200, {"policies": self.server.store.policies(
                    self.server.config.tenant_id)})
            return
        if len(parts) == 3 and parts[:2] == ["v0", "rollouts"]:
            if self._auth("viewer"):
                rollout = self.server.store.rollout(int(parts[2]))
                if rollout is None:
                    self._error(404, "unknown rollout")
                else:
                    self._send(200, rollout)
            return
        self._error(404, "not found")

    # -- POST ------------------------------------------------------------
    def do_POST(self) -> None:  # noqa: N802
        self._start_trace()
        if self._client_revoked():
            self._error(403, "client certificate revoked")
            return
        parts = urlparse(self.path).path.strip("/").split("/")
        try:
            raw = self._body()
            body = json.loads(raw) if raw else {}
        except (ValueError, json.JSONDecodeError) as exc:
            self._error(400, str(exc))
            return

        if parts == ["v0", "enrol"]:
            try:
                public_from_pem(str(body.get("pubkey", "")))
                agent_id = self.server.store.enrol(
                    token=str(body.get("enrolment_token", "")),
                    tenant_id=str(body.get("tenant_id", self.server.config.tenant_id)),
                    hostname=str(body.get("hostname", "unknown")),
                    os_name=str(body.get("os", "unknown")),
                    arch=str(body.get("arch", "unknown")),
                    agent_version=str(body.get("agent_version", "unknown")),
                    pubkey=str(body.get("pubkey", "")),
                )
            except PermissionError as exc:
                self._error(403, str(exc))
                return
            except Exception as exc:  # noqa: BLE001
                self._error(400, f"bad enrolment: {exc}")
                return
            self._send(201, {"agent_id": agent_id, "tenant_id": body.get("tenant_id",
                                                                       self.server.config.tenant_id)})
            return

        if parts == ["v0", "tls", "revoke"]:
            if not self._auth("admin"):
                return
            serial = str(body.get("serial", ""))
            if not serial:
                self._error(400, "serial required")
                return
            self.server.store.revoke_cert(serial, str(body.get("reason", "operator")))
            self._send(200, {"ok": True, "serial": serial})
            return

        if parts == ["v0", "approvals"]:
            if not self._auth("admin"):
                return
            approval_id = self.server.trust.propose(
                str(body.get("kind", "policy")), str(body.get("target", "")),
                body.get("payload") or {}, "operator", self.server.config.tenant_id)
            self._send(201, {"approval_id": approval_id, "status": "pending"})
            return

        if len(parts) == 4 and parts[:2] == ["v0", "approvals"]:
            if not self._auth("approver"):
                return
            status = {"approve": "approved", "deny": "rejected"}.get(parts[3])
            if status is None:
                self._error(404, "not found")
                return
            try:
                self.server.trust.decide(int(parts[2]), status, "approver")
            except KeyError as exc:
                self._error(404, str(exc))
                return
            self._send(200, {"ok": True, "approval_id": int(parts[2]), "status": status})
            return

        if parts == ["v0", "trust", "keys"]:
            if not self._auth("admin"):
                return
            try:
                key = self.server.trust.create_key(str(body.get("key_class", "policy")))
            except (ValueError, TrustError) as exc:
                self._error(400, str(exc))
                return
            self._send(201, {k: v for k, v in key.items() if k != "private_path"})
            return

        if len(parts) == 5 and parts[:3] == ["v0", "trust", "keys"]:
            if not self._auth("admin"):
                return
            try:
                if parts[4] == "revoke":
                    self.server.trust.revoke(parts[3])
                    self._send(200, {"ok": True, "key_id": parts[3], "revoked": True})
                elif parts[4] == "rotate":
                    key = self.server.trust.rotate(parts[3])
                    self._send(201, {k: v for k, v in key.items() if k != "private_path"})
                else:
                    self._error(404, "not found")
            except (KeyError, TrustError) as exc:
                self._error(404, str(exc))
            return

        if parts == ["v0", "telemetry"]:
            if not self._auth("admin"):
                return
            events = body.get("events") if isinstance(body, dict) else []
            try:
                count = self.server.learning.ingest(
                    str(body.get("agent_id", "unknown")),
                    events if isinstance(events, list) else [],
                    bool(body.get("consent", False)))
            except PermissionError as exc:
                self._error(403, str(exc))
                return
            self._send(201, {"ok": True, "accepted": count})
            return

        if parts == ["v0", "cases"]:
            if not self._auth("admin"):
                return
            try:
                self.server.learning.add_case(
                    str(body.get("case_id", "")), str(body.get("report_id", "")),
                    str(body.get("label", "")), bool(body.get("holdout", False)),
                    body.get("features") or {})
            except ValueError as exc:
                self._error(409, str(exc))
                return
            self._send(201, {"ok": True, "case_id": body.get("case_id")})
            return

        if parts == ["v0", "models"]:
            if not self._auth("admin"):
                return
            try:
                result = self.server.learning.register_model(
                    str(body.get("name", "")), str(body.get("version", "")),
                    body.get("metrics") or {})
            except ValueError as exc:
                self._error(409, str(exc))
                return
            self._send(201, result)
            return

        if len(parts) == 4 and parts[:2] == ["v0", "models"]:
            if not self._auth("admin"):
                return
            try:
                model_id = int(parts[2])
                if parts[3] == "regress":
                    result = self.server.learning.regress(model_id)
                elif parts[3] == "activate":
                    result = self.server.learning.activate(model_id)
                else:
                    self._error(404, "not found")
                    return
            except (KeyError, ValueError) as exc:
                self._error(404, str(exc))
                return
            self._send(200, result)
            return

        if parts == ["v0", "models", "rollback"]:
            if not self._auth("admin"):
                return
            try:
                self._send(200, self.server.learning.rollback())
            except KeyError as exc:
                self._error(404, str(exc))
            return

        if parts == ["v0", "policies"]:
            if not self._auth("admin") or not self._verify_policy(body):
                return
            try:
                self.server.store.add_policy({
                    "policy_id": str(body.get("policy_id", "")),
                    "version": str(body.get("version", "")),
                    "channel": str(body.get("channel", "stable")),
                    "content": body.get("content") or {},
                    "key_id": str(body.get("key_id", "")),
                    "signature": str(body.get("signature", "")),
                    "tenant_id": self.server.config.tenant_id,
                })
            except ValueError as exc:
                self._error(409, str(exc))
                return
            target = f"{body.get('policy_id')}@{body.get('version')}"
            approval_id = self.server.trust.propose("policy", target, body, "operator",
                                                    self.server.config.tenant_id)
            self._send(201, {"ok": True, "policy_id": body.get("policy_id"),
                             "version": body.get("version"), "approval_id": approval_id})
            return

        if len(parts) == 5 and parts[:2] == ["v0", "policies"] and parts[4] == "dry-run":
            if not self._auth("viewer"):
                return
            try:
                result = self.server.store.dry_run(parts[2], parts[3],
                                                   body.get("agent_ids") if body else None,
                                                   self.server.config.tenant_id)
            except KeyError:
                self._error(404, "unknown policy")
                return
            self._send(200, result)
            return

        if parts == ["v0", "rollouts"]:
            if not self._auth("admin"):
                return
            target = f"{body.get('policy_id')}@{body.get('version')}"
            if self.server.config.require_approval and not self.server.trust.is_approved(
                    "policy", target, self.server.config.tenant_id):
                self._error(409, "policy approval required")
                return
            try:
                rollout = self.server.store.start_rollout(
                    str(body.get("policy_id", "")), str(body.get("version", "")),
                    int(body.get("percent", 0)), self.server.config.tenant_id)
            except KeyError:
                self._error(404, "unknown policy")
                return
            self._send(201, rollout)
            return

        if len(parts) == 4 and parts[:2] == ["v0", "rollouts"]:
            if not self._auth("admin"):
                return
            try:
                if parts[3] == "promote":
                    result = self.server.store.promote_rollout(int(parts[2]))
                    self._send(200, result)
                    return
                if parts[3] == "halt":
                    self.server.store.halt_rollout(int(parts[2]))
                elif parts[3] == "rollback":
                    self.server.store.rollback_rollout(int(parts[2]))
                else:
                    self._error(404, "not found")
                    return
            except KeyError as exc:
                self._error(404, str(exc))
                return
            except ValueError as exc:
                self._error(409, str(exc))
                return
            self._send(200, {"ok": True, "rollout_id": int(parts[2]), "action": parts[3]})
            return

        if parts == ["v0", "heartbeat"]:
            agent = self._agent(body)
            if agent is None or not self._verify_signed(raw, body, agent):
                return
            try:
                hb = Heartbeat.model_validate(body)
            except Exception as exc:  # noqa: BLE001
                self._error(400, f"bad heartbeat: {exc}")
                return
            isolated = self.server.store.heartbeat(agent.id, hb.status.value, hb.health)
            self._send(200, {"ok": True, "isolated": isolated})
            return

        if parts == ["v0", "inventory"]:
            agent = self._agent(body)
            if agent is None or not self._verify_signed(raw, body, agent):
                return
            try:
                inv = Inventory.model_validate(body)
            except Exception as exc:  # noqa: BLE001
                self._error(400, f"bad inventory: {exc}")
                return
            self.server.store.inventory(agent.id, {
                "os": inv.os, "arch": inv.arch, "agent_version": inv.agent_version,
                "policy_version": inv.rules_version,
            })
            self._send(200, {"ok": True})
            return

        if parts == ["v0", "reports"]:
            reports = body.get("reports") if isinstance(body, dict) else body
            if not isinstance(reports, list) or not reports:
                self._error(400, "reports[] required")
                return
            first = reports[0] if isinstance(reports[0], dict) else {}
            agent = self._agent(first)
            if agent is None or not self._verify_signed(raw, first, agent):
                return
            acked = self.server.store.ingest(reports)
            self.server.bus.publish("reports", {"acked": acked, "count": len(reports)})
            self._send(200, {"schema_version": "stml/v0", "acked": acked})
            return

        if len(parts) == 4 and parts[:2] == ["v0", "agents"] and parts[3] == "isolate":
            if not self._auth("admin"):
                return
            try:
                self.server.store.isolate(parts[2], bool(body.get("isolated", True)))
            except KeyError:
                self._error(404, "unknown agent")
                return
            self._send(200, {"ok": True, "agent_id": parts[2],
                             "isolated": bool(body.get("isolated", True))})
            return

        self._error(404, "not found")


MODULES = [
    {"name": "agent-connector", "kind": "T1", "status": "active",
     "note": "Python bridge, pickle->JSON"},
    {"name": "fleet-core", "kind": "T1", "status": "active",
     "note": "registry, enrolment, reports"},
    {"name": "trust-service", "kind": "T0", "status": "dev",
     "note": "SoftHSM file backend; prod HSM pending"},
    {"name": "learning", "kind": "T1", "status": "active",
     "note": "telemetry, cases, model registry"},
    {"name": "gui", "kind": "T2", "status": "active",
     "note": "web console /ui/"},
]


DASHBOARD = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>STML — Fleet</title>
<style>
body{background:#0b0f17;color:#e5e9f0;font:14px Inter,system-ui,sans-serif;margin:0}
header{background:#111827;border-bottom:1px solid #243044;padding:14px 20px;display:flex;gap:16px;align-items:center}
h1{font-size:16px;margin:0;color:#3b82f6}
input{background:#1a2234;border:1px solid #243044;color:#e5e9f0;padding:6px 10px;border-radius:6px}
button{background:#3b82f6;border:0;color:#fff;padding:6px 12px;border-radius:6px;cursor:pointer}
main{padding:20px}
table{width:100%;border-collapse:collapse;background:#111827;border:1px solid #243044;border-radius:8px;overflow:hidden}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #243044;font-size:13px}
th{color:#8b98a9;font-weight:500}
.ok{color:#22c55e}.warn{color:#f59e0b}.bad{color:#ef4444}
#msg{color:#8b98a9;font-size:12px}
</style></head><body>
<header><h1>STML Console</h1><span id="msg">read-only</span>
<input id="token" type="password" placeholder="viewer token"><button onclick="load()">Load</button></header>
<main><table><thead><tr><th>Host</th><th>OS</th><th>Version</th><th>Status</th><th>Last seen</th><th>Isolated</th></tr></thead>
<tbody id="rows"></tbody></table></main>
<script>
function esc(v){return String(v).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
async function load(){
 const t=document.getElementById('token').value;
 const r=await fetch('/v0/agents',{headers:{Authorization:'Bearer '+t}});
 if(!r.ok){document.getElementById('msg').textContent='auth error';return}
 const d=await r.json(); const rows=d.agents.map(a=>`<tr><td>${esc(a.hostname)}</td><td>${esc(a.os)}</td><td>${esc(a.agent_version)}</td><td class="${a.status==='healthy'?'ok':a.status==='degraded'?'warn':'bad'}">${esc(a.status)}</td><td>${new Date(a.last_seen*1000).toLocaleTimeString()}</td><td>${a.isolated?'yes':'no'}</td></tr>`).join('');
 document.getElementById('rows').innerHTML=rows; document.getElementById('msg').textContent=d.agents.length+' agents';
}
</script></body></html>"""


def start_server(store: Store, config: ServerConfig, port: int = 0) -> tuple[StmlServer, threading.Thread]:
    server = StmlServer(("127.0.0.1", port), store, config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread
