"""IPC benchmark: latency, concurrency, authorisation and oversized-request handling.

Writes artifacts/ipc_report.json. Uses a real daemon for `health`/`stats`.
"""

from __future__ import annotations

import json
import os
import statistics
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.daemon import Daemon, DaemonConfig
from core.ipc import (
    FORBIDDEN,
    UNAUTHORIZED,
    RpcClient,
    RpcError,
    RpcServer,
    build_daemon_registry,
    free_pipe_name,
    generate_token,
)
from core.normalize import HostContext

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT = os.path.join(HERE, "artifacts", "ipc_report.json")
HOST = HostContext(host_id="host-ipc", os="windows", version="10.0.19045", arch="x64")


def p95(values):
    s = sorted(values)
    return round(s[min(len(s) - 1, int(len(s) * 0.95))], 3)


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="aidf_ipc_")
    cfg = DaemonConfig(sources=["win.etw.ti"], thresholds={"heartbeat_timeout_s": 60,
                                                           "alert_budget": 10})
    daemon = Daemon(os.path.join(tmp, "daemon"), config=cfg, host=HOST)
    address = free_pipe_name()
    authkey = os.urandom(32)
    admin_token, viewer_token = generate_token(), generate_token()
    tokens = {admin_token: "admin", viewer_token: "viewer"}
    server = RpcServer(address=address, authkey=authkey, tokens=tokens,
                       registry=build_daemon_registry(daemon))
    server.start()
    time.sleep(0.05)

    try:
        client = RpcClient(address, authkey, admin_token)
        lat = []
        for _ in range(500):
            t = time.perf_counter()
            client.call("ping")
            lat.append((time.perf_counter() - t) * 1000)
        health_lat = []
        for _ in range(200):
            t = time.perf_counter()
            client.call("health")
            health_lat.append((time.perf_counter() - t) * 1000)
        stats_lat = []
        for _ in range(100):
            t = time.perf_counter()
            client.call("stats")
            stats_lat.append((time.perf_counter() - t) * 1000)
        client.close()

        # concurrency: 10 clients x 50 pings
        errors = []
        per_client = 50
        results = []

        def worker():
            try:
                c = RpcClient(address, authkey, admin_token)
                ok = 0
                for _ in range(per_client):
                    if c.call("ping") == {"pong": True}:
                        ok += 1
                results.append(ok)
                c.close()
            except Exception as exc:                    # recorded, not ignored
                errors.append(f"{type(exc).__name__}: {exc}")

        t0 = time.perf_counter()
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        concurrent_s = time.perf_counter() - t0

        # authorisation: viewer may not kill-switch
        viewer = RpcClient(address, authkey, viewer_token)
        forbidden = 0
        for _ in range(100):
            try:
                viewer.call("kill_switch", {"rule_id": "R-1"})
            except RpcError as exc:
                if exc.code == FORBIDDEN:
                    forbidden += 1
        viewer.close()

        # bad token
        bad_rejected = 0
        for _ in range(50):
            try:
                RpcClient(address, authkey, "bad-token")
            except RpcError as exc:
                if exc.code == UNAUTHORIZED:
                    bad_rejected += 1

        # oversized request (> 1 MiB)
        big = RpcClient(address, authkey, admin_token)
        oversized = None
        try:
            big.call("ping", {"pad": "x" * (2 * 1024 * 1024)})
            oversized = "accepted"
        except RpcError as exc:
            oversized = f"rejected:{exc.code}"
        except Exception as exc:
            oversized = f"connection_closed:{type(exc).__name__}"
        big.close()

        report = {
            "environment": {"python": sys.version.split()[0]},
            "ping": {"calls": 500, "ms_p50": round(statistics.median(lat), 3),
                     "ms_p95": p95(lat), "calls_per_s": round(500 / (sum(lat) / 1000), 0)
                     if lat else None},
            "health": {"calls": 200, "ms_p50": round(statistics.median(health_lat), 3),
                       "ms_p95": p95(health_lat)},
            "stats": {"calls": 100, "ms_p50": round(statistics.median(stats_lat), 3),
                      "ms_p95": p95(stats_lat)},
            "concurrency": {"clients": 10, "calls_per_client": per_client,
                            "ok_calls": sum(results), "errors": errors,
                            "elapsed_s": round(concurrent_s, 2),
                            "calls_per_s": round(sum(results) / concurrent_s, 0)},
            "authz": {"forbidden_attempts": 100, "forbidden": forbidden},
            "bad_tokens": {"attempts": 50, "rejected": bad_rejected},
            "oversized_request": oversized,
        }
    finally:
        server.stop()
        daemon.stop()

    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    with open(REPORT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
