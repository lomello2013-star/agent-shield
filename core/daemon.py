"""`aidfd` user-mode daemon skeleton: wires reliability, telemetry, detection and gate.

This is the runnable spine, not a product binary: no kernel component, no
privileged operations. It exposes a localhost-only health endpoint so chaos
tests and operators can see the real state (R1/R2/R8), and it fails safe:
a bad config keeps the last-known-good state and enters safe mode.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from uuid import uuid4

from core.clock import MonotonicClock
from core.confirm import ConfirmationManager
from core.counters import LossCounters
from core.gate import AlertBudget, PolicyGate
from core.heartbeat import HeartbeatMonitor
from core.ingest import IngestPipeline
from core.normalize import HostContext, Normalizer
from core.pipeline import Pipeline
from core.rules import RuleEngine, load_rules
from core.safemode import SafeMode
from core.selfprotect import HashChainLog, IntegrityManifest, SelfTest


@dataclass
class DaemonConfig:
    schema_version: str = "1.0"
    sources: list[str] = field(default_factory=lambda: ["win.eventlog", "win.defender"])
    thresholds: dict[str, float] = field(default_factory=lambda: {
        "heartbeat_timeout_s": 60.0, "alert_budget": 1, "min_confidence": 0.5})
    queue: dict[str, float] = field(default_factory=lambda: {"capacity": 10_000})
    watchdog: dict[str, float] = field(default_factory=dict)
    allowlist: list[str] = field(default_factory=list)
    # health() must stay cheap: re-hashing the data directory on every call is both
    # expensive and (see DEVLOG F11) points at a native crash on long runs
    manifest_interval_s: float = 30.0

    def as_payload(self) -> dict:
        return {"schema_version": self.schema_version, "sources": list(self.sources),
                "thresholds": dict(self.thresholds), "queue": dict(self.queue),
                "watchdog": dict(self.watchdog), "allowlist": list(self.allowlist)}


def build_default_collectors(config: DaemonConfig) -> list[Any]:
    """Build real, non-admin collectors for the configured source names.

    Construction performs no I/O: ``wevtutil`` is only invoked by ``poll()``, so a
    daemon that never collects costs nothing. Unknown/unimplemented source names
    are skipped rather than faked.
    """
    if sys.platform != "win32":
        return []
    from core.winsource import WindowsEventLogSource
    built: list[Any] = []
    for source in config.sources:
        if source == "win.eventlog":
            built.append(WindowsEventLogSource(
                log_name="System", event_ids=(7045, 7040, 7036, 1102),
                name="win.eventlog"))
        elif source == "win.defender":
            built.append(WindowsEventLogSource(
                log_name="Microsoft-Windows-Windows Defender/Operational",
                event_ids=(5001, 5007, 5010, 5012, 1116, 1117),
                name="win.defender"))
    return built


class Daemon:
    def __init__(self, root: str, config: DaemonConfig | None = None,
                 rules_path: str | None = None, serve_http: bool = False,
                 host: HostContext | None = None, log_fsync_every: int = 1,
                 collectors: list[Any] | None = None, response: Any | None = None,
                 collect_interval_s: float = 0.0) -> None:
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)
        self.config = config or DaemonConfig()
        self.started_at = time.monotonic()
        self._stop = threading.Event()
        self._health_calls = 0
        self.safe_mode = SafeMode(self.root)
        apply_result = self.safe_mode.apply(self.config.as_payload(), dry_run=False)

        self.counters = LossCounters()
        self.clock = MonotonicClock(jump_threshold_s=5.0)
        self.host = host or HostContext(host_id="host-local", os="windows",
                                        version="10.0.19045", arch="x64")
        self.log = HashChainLog(os.path.join(self.root, "audit", "chain.jsonl"),
                                anchor_path=os.path.join(self.root, "audit", "anchor.json"),
                                fsync_every=log_fsync_every)
        self.manifest = IntegrityManifest(self.root, os.path.join(self.root, "manifest.json"))
        rules_path = rules_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "base.json")
        self.engine = RuleEngine(load_rules([rules_path]))
        self.heartbeat = HeartbeatMonitor(
            timeout_s=float(self.config.thresholds.get("heartbeat_timeout_s", 60.0)),
            on_incident=lambda inc: self.log.append("source_incident", {"source": inc.source,
                                                                       "kind": inc.kind}))
        for source in self.config.sources:
            self.heartbeat.register(source)
        self.pipeline = Pipeline(
            normalizer=Normalizer(host=self.host,
                                  quarantine_path=os.path.join(self.root, "quarantine.jsonl"),
                                  counters=self.counters),
            ingest=IngestPipeline(capacity=int(self.config.queue.get("capacity", 10_000)),
                                  spill_path=os.path.join(self.root, "spool", "events.jsonl"),
                                  counters=self.counters,
                                  on_incident=lambda reason: self.log.append("ingest_incident",
                                                                             {"reason": reason})),
            engine=self.engine)
        self.gate = PolicyGate(
            min_confidence=float(self.config.thresholds.get("min_confidence", 0.5)),
            budget=AlertBudget(per_window=int(self.config.thresholds.get("alert_budget", 1)),
                               window_s=14 * 24 * 3600))
        self.confirmations = ConfirmationManager()
        self.pending_actions: dict[str, Any] = {}
        self.response_quarantine = None          # set when the response layer is wired
        # Response layer (stage 7): without it the gate's actions were only counted.
        self.response = response
        if response is not None and getattr(response, "quarantine", None) is not None:
            self.response_quarantine = response.quarantine
        # Real sources (stage 1): collectors are polled here instead of by the harness.
        if collectors is None:
            collectors = build_default_collectors(self.config)
        self.collectors = list(collectors)
        for collector in self.collectors:
            cname = getattr(collector, "name", None)
            if cname and cname not in self.config.sources:
                self.heartbeat.register(cname)
        self.collect_interval_s = float(collect_interval_s)
        self.collected_count = 0
        self.response_executed = 0
        self.response_refused = 0
        self.response_failed = 0
        self.last_response_error = ""
        self.verdict_count = 0
        self.alert_count = 0
        self.containment_count = 0
        self._httpd: ThreadingHTTPServer | None = None
        self._http_thread: threading.Thread | None = None
        self._collector_thread: threading.Thread | None = None
        self._serve_http = serve_http
        if apply_result.accepted:
            self.log.append("config_applied", {"fingerprint": apply_result.fingerprint})
            self.manifest.seal([os.path.join(self.root, "lkg", "config.json")])
        else:
            self.log.append("safe_mode", {"reason": self.safe_mode.reason})

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> None:
        self._write_lifecycle("daemon_start")
        if self._serve_http and self._httpd is None:
            daemon = self

            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):                     # noqa: N802 - stdlib API
                    if self.path not in ("/health", "/stats"):
                        self.send_response(404)
                        self.end_headers()
                        return
                    body = json.dumps(daemon.health() if self.path == "/health"
                                      else daemon.stats()).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *args):         # keep test output clean
                    return

            self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            self._http_thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
            self._http_thread.start()
        self._start_collectors()

    def _start_collectors(self) -> None:
        """Poll configured collectors in the background (real sources, stage 1)."""
        if not self.collectors or self.collect_interval_s <= 0:
            return
        thread = threading.Thread(target=self._collector_loop, daemon=True)
        thread.start()
        self._collector_thread = thread

    def _collector_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.collect_once()
            except Exception as exc:      # a broken collector must not kill the daemon
                self.log.append("collector_incident", {"error": f"{type(exc).__name__}: {exc}"})
            self._stop.wait(self.collect_interval_s)

    def collect_once(self) -> int:
        """Pull one batch from every collector; returns how many records were submitted."""
        submitted = 0
        for collector in self.collectors:
            name = str(getattr(collector, "name", "collector"))
            records = collector.poll() or []
            for raw in records:
                payload = raw.to_raw() if hasattr(raw, "to_raw") else raw
                if self.submit(name, payload):
                    submitted += 1
        self.collected_count += submitted
        return submitted

    @property
    def port(self) -> int:
        return self._httpd.server_address[1] if self._httpd else 0

    def _write_lifecycle(self, kind: str) -> None:
        """Record start/stop in the hash chain; failure here must not break startup."""
        try:
            inherited = getattr(self.log, "_verified_seq", 0)
            self.log.append(kind, {"pid": os.getpid(), "inherited_seq": inherited})
            self.log.flush()
        except Exception:            # audit is best-effort on lifecycle, not a blocker
            pass

    def stop(self) -> None:
        self._write_lifecycle("daemon_stop")
        self._stop.set()
        if self._collector_thread is not None:
            self._collector_thread.join(timeout=5)
            self._collector_thread = None
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        self.pipeline.ingest.close()
        try:
            self.log.seal()
        except ValueError:
            pass

    # ------------------------------------------------------------------ events
    def submit(self, source: str, raw: dict) -> bool:
        self.heartbeat.beat(source)
        return self.pipeline.submit_raw(source, raw)

    def tick(self) -> dict:
        incidents = self.heartbeat.check()
        for conf in self.confirmations.expire():
            self.pending_actions.pop(conf.confirmation_id, None)
            self.log.append("confirmation_timeout", {"id": conf.confirmation_id})
        jump = self.clock.detect_jump()
        if jump is not None:
            self.log.append("clock_jump", {"skew_s": round(jump.skew_s, 3)})
        verdicts = self.pipeline.run_once(500)
        for verdict in verdicts:
            self.verdict_count += 1
            decision = self.gate.decide(verdict, self.host.host_id,
                                        target=f"{verdict.rule_id}")
            if decision.alert:
                self.alert_count += 1
            if decision.actions:
                self.containment_count += 1
                self._execute_actions(verdict, decision.actions)
            self.log.append("verdict", {"rule": verdict.rule_id, "severity": verdict.severity,
                                        "actions": list(decision.actions),
                                        "alert": decision.alert})
        return {"incidents": len(incidents), "verdicts": len(verdicts)}

    def _execute_actions(self, verdict, actions) -> None:
        """Create a confirmation per action; execute only after operator approval."""
        if self.response is None:
            return
        from schemas.v3 import Action
        for action_type in actions:
            destructive = action_type in {"terminate", "delete"}
            level = ("critical_system" if destructive
                     else "protected_dir" if action_type == "quarantine" else "normal")
            confirmation = self.confirmations.request(
                action_id=str(uuid4()), level=level, destructive=destructive)
            action = Action(
                action_id=uuid4(), trace_id=verdict.trace_id, verdict_id=verdict.verdict_id,
                type=action_type, target=str(verdict.rule_id or ""),
                reversible=not destructive, requires_confirmation=True,
                confirmation_id=confirmation.confirmation_id, status="pending",
                platform_effect="", rollback=None)
            self.pending_actions[confirmation.confirmation_id] = action
            try:
                result = self.response.execute(action)
            except Exception as exc:      # response must never break detection
                self.response_failed += 1
                self.last_response_error = f"{type(exc).__name__}: {exc}"
                self.log.append("response_error", {"action": action_type,
                                                   "confirmation_id": confirmation.confirmation_id,
                                                   "error": self.last_response_error})
                continue
            status = getattr(result, "status", "failed")
            if status == "executed":
                self.pending_actions.pop(confirmation.confirmation_id, None)
                self.response_executed += 1
            elif status == "refused":
                self.response_refused += 1
            else:
                self.response_failed += 1
            self.log.append("response", {"action": action_type, "status": status,
                                         "confirmation_id": confirmation.confirmation_id,
                                         "error": getattr(result, "error", "")})

    def confirm(self, confirmation_id: str, decision: str,
                decided_by: str = "operator") -> dict:
        """Resolve a pending confirmation; an approved action is executed exactly once."""
        try:
            conf = self.confirmations.resolve(confirmation_id, decision, decided_by)
        except KeyError:
            return {"confirmation_id": str(confirmation_id), "status": "unknown"}
        action = self.pending_actions.pop(confirmation_id, None)
        if conf.decision != "approved" or action is None:
            self.log.append("confirmation", {"id": confirmation_id,
                                             "decision": conf.decision})
            return {"confirmation_id": confirmation_id,
                    "status": conf.decision if action is not None else "approved_no_action"}
        try:
            result = self.response.execute(action)
        except Exception as exc:          # response must never break the daemon
            self.response_failed += 1
            self.last_response_error = f"{type(exc).__name__}: {exc}"
            self.log.append("response_error", {"action": action.type,
                                               "error": self.last_response_error})
            return {"confirmation_id": confirmation_id, "status": "failed"}
        status = getattr(result, "status", "failed")
        if status == "executed":
            self.response_executed += 1
        elif status == "refused":
            self.response_refused += 1
        else:
            self.response_failed += 1
        self.log.append("response", {"action": action.type, "status": status,
                                     "confirmation_id": confirmation_id,
                                     "error": getattr(result, "error", "")})
        return {"confirmation_id": confirmation_id, "status": status}

    def run_for(self, seconds: float, interval_s: float = 0.05) -> None:
        end = time.monotonic() + seconds
        while not self._stop.is_set() and time.monotonic() < end:
            self.tick()
            time.sleep(interval_s)

    # ------------------------------------------------------------------ health
    def health(self) -> dict:
        self._health_calls += 1
        # Incremental verification is O(new records); every 50th call does a full
        # pass so an in-place edit of an old record cannot hide forever.
        log_state = self.log.verify(incremental=(self._health_calls % 50 != 0))
        integrity = self._manifest_snapshot()
        sources = self.heartbeat.health()
        degraded = (not self.heartbeat.all_healthy() or not log_state.ok
                    or not integrity["ok"] or self.pipeline.ingest.lost > 0)
        status = "safe" if self.safe_mode.is_safe else ("degraded" if degraded else "ok")
        return {
            "status": status,
            "uptime_s": round(time.monotonic() - self.started_at, 3),
            "safe_mode": self.safe_mode.status(),
            "sources": sources,
            "ingest": self.pipeline.ingest.stats(),
            "ledger_ok": self.pipeline.ingest.ledger_ok(),
            "audit_chain_ok": log_state.ok,
            "integrity_ok": integrity["ok"],
            "quarantined_records": self.pipeline.normalizer.stats()["quarantined"],
            "verdicts": self.verdict_count,
            "alerts": self.alert_count,
            "containments": self.containment_count,
            "pending_confirmations": len(self.confirmations.pending()),
        }

    def _manifest_snapshot(self) -> dict:
        """Verify the integrity manifest at most once per interval, cache otherwise."""
        interval = float(getattr(self.config, "manifest_interval_s", 30.0))
        now = time.monotonic()
        cached = getattr(self, "_integrity_cache", None)
        checked_at = getattr(self, "_integrity_checked_at", None)
        if cached is not None and checked_at is not None and now - checked_at < interval:
            return cached
        result = self.manifest.verify()
        self._integrity_cache = result
        self._integrity_checked_at = now
        return result

    def stats(self) -> dict:
        return {"pipeline": self.pipeline.stats(), "gate": self.gate.stats(self.host.host_id),
                "audit": {"records": self.log.verify().records},
                "pending_confirmations": len(self.confirmations.pending())}

    # ------------------------------------------------------------------ checks
    def run_self_test(self) -> dict:
        st = SelfTest()
        from core.policy import verify_immutable
        st.register("immutable_policy", st.immutable_check(verify_immutable))
        st.register("audit_chain", st.log_check(self.log))
        st.register("file_integrity", st.integrity_check(self.manifest))
        return st.run()

