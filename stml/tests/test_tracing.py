from urllib.request import Request, urlopen

from stml.server.app import ServerConfig, start_server
from stml.server.store import Store


def test_trace_id_propagation_and_generation(tmp_path):
    store = Store(tmp_path / "db.sqlite3")
    server, _ = start_server(store, ServerConfig(tenant_id="t"), port=0)
    port = server.server_address[1]
    try:
        trace = "a" * 32
        req = Request(f"http://127.0.0.1:{port}/health", headers={"X-Trace-ID": trace})
        with urlopen(req, timeout=5) as resp:
            assert resp.headers["X-Trace-ID"] == trace

        parent = "00-" + "b" * 32 + "-" + "c" * 16 + "-01"
        req = Request(f"http://127.0.0.1:{port}/health", headers={"traceparent": parent})
        with urlopen(req, timeout=5) as resp:
            assert resp.headers["X-Trace-ID"] == "b" * 32

        with urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as resp:
            generated = resp.headers["X-Trace-ID"]
        assert len(generated) == 32 and generated != trace
    finally:
        server.shutdown()
        server.server_close()
        store.close()
