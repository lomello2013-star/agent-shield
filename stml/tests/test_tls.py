import http.client
import ssl

import pytest

from stml.server.app import ServerConfig, start_server
from stml.server.store import Store
from stml.server.tls import generate_dev_certs, make_client_context


def test_mtls_required_and_client_cert_accepted(tmp_path):
    certs = generate_dev_certs(tmp_path / "certs")
    store = Store(tmp_path / "db.sqlite3")
    config = ServerConfig(tenant_id="t", admin_token="a", viewer_token="v",
                          tls_cert=certs["server_cert"], tls_key=certs["server_key"],
                          tls_ca=certs["ca"], require_client_cert=True)
    server, _ = start_server(store, config, port=0)
    port = server.server_address[1]
    try:
        ctx = make_client_context(certs["ca"], certs["client_cert"], certs["client_key"])
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=5)
        conn.request("GET", "/health")
        resp = conn.getresponse()
        assert resp.status == 200
        conn.close()

        no_cert = make_client_context(certs["ca"])
        bad = http.client.HTTPSConnection("127.0.0.1", port, context=no_cert, timeout=5)
        with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
            bad.request("GET", "/health")
            bad.getresponse()
        bad.close()
    finally:
        server.shutdown()
        server.server_close()
        store.close()
