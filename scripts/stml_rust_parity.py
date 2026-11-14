"""P5 parity smoke: compare Python reference and Rust server read APIs.

Usage:
  python scripts/stml_rust_parity.py \
    --python-url http://127.0.0.1:8080 --python-viewer <token> \
    --rust-url http://127.0.0.1:18096 --rust-viewer <token>

The script checks status codes and response shapes, not every value (IDs and
timestamps differ by design). Exit 1 on any mismatch.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request


def fetch(url: str, path: str, token: str = "") -> tuple[int, dict | str]:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url.rstrip("/") + path, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read()
            try:
                return resp.status, json.loads(body)
            except json.JSONDecodeError:
                return resp.status, body.decode(errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            return exc.code, json.loads(body)
        except json.JSONDecodeError:
            return exc.code, body.decode(errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--python-url", required=True)
    ap.add_argument("--python-viewer", required=True)
    ap.add_argument("--rust-url", required=True)
    ap.add_argument("--rust-viewer", required=True)
    ap.add_argument("--python-admin", required=True)
    ap.add_argument("--rust-admin", required=True)
    args = ap.parse_args()

    checks = []
    failures = []

    def check(name: str, py, rust, predicate) -> None:
        ok = predicate(py, rust)
        checks.append({"name": name, "ok": ok,
                       "python": py[0], "rust": rust[0]})
        if not ok:
            failures.append(name)

    py = fetch(args.python_url, "/health")
    ru = fetch(args.rust_url, "/health")
    check("health", py, ru,
          lambda a, b: a[0] == b[0] == 200 and {"ok", "service"} <= set(a[1]) & set(b[1]))

    py = fetch(args.python_url, "/ui/")
    ru = fetch(args.rust_url, "/ui/")
    check("ui", py, ru,
          lambda a, b: a[0] == b[0] == 200 and len(a[1]) > 1000 and len(b[1]) > 1000)

    py = fetch(args.python_url, "/v0/agents")
    ru = fetch(args.rust_url, "/v0/agents")
    check("agents_unauth", py, ru, lambda a, b: a[0] == b[0] == 401)

    py = fetch(args.python_url, "/v0/agents", args.python_viewer)
    ru = fetch(args.rust_url, "/v0/agents", args.rust_viewer)
    check("agents_viewer", py, ru,
          lambda a, b: a[0] == b[0] == 200 and isinstance(a[1].get("agents"), list)
          and isinstance(b[1].get("agents"), list)
          and (not a[1]["agents"] or not b[1]["agents"]
               or set(a[1]["agents"][0]) == set(b[1]["agents"][0])))

    py = fetch(args.python_url, "/v0/policies")
    ru = fetch(args.rust_url, "/v0/policies")
    check("policies_unauth", py, ru, lambda a, b: a[0] == b[0] == 401)

    py = fetch(args.python_url, "/v0/policies", args.python_viewer)
    ru = fetch(args.rust_url, "/v0/policies", args.rust_viewer)
    check("policies_viewer", py, ru,
          lambda a, b: a[0] == b[0] == 200 and isinstance(a[1].get("policies"), list)
          and isinstance(b[1].get("policies"), list))

    py = fetch(args.python_url, "/v0/approvals")
    ru = fetch(args.rust_url, "/v0/approvals")
    check("approvals_unauth", py, ru, lambda a, b: a[0] == b[0] == 401)
    py = fetch(args.python_url, "/v0/approvals", args.python_viewer)
    ru = fetch(args.rust_url, "/v0/approvals", args.rust_viewer)
    check("approvals_viewer", py, ru,
          lambda a, b: a[0] == b[0] == 200 and isinstance(a[1].get("approvals"), list)
          and isinstance(b[1].get("approvals"), list))

    py = fetch(args.python_url, "/v0/rollouts/999999", args.python_viewer)
    ru = fetch(args.rust_url, "/v0/rollouts/999999", args.rust_viewer)
    check("rollout_missing", py, ru, lambda a, b: a[0] == b[0] == 404)

    py = fetch(args.python_url, "/v0/models", args.python_viewer)
    ru = fetch(args.rust_url, "/v0/models", args.rust_viewer)
    check("models_viewer", py, ru,
          lambda a, b: a[0] == b[0] == 200 and isinstance(a[1].get("models"), list)
          and isinstance(b[1].get("models"), list))

    py = fetch(args.python_url, "/v0/cases", args.python_viewer)
    ru = fetch(args.rust_url, "/v0/cases", args.rust_viewer)
    check("cases_viewer", py, ru,
          lambda a, b: a[0] == b[0] == 200 and isinstance(a[1].get("cases"), list)
          and isinstance(b[1].get("cases"), list))

    py = fetch(args.python_url, "/v0/trust/keys", args.python_viewer)
    ru = fetch(args.rust_url, "/v0/trust/keys", args.rust_viewer)
    check("trust_keys_viewer", py, ru,
          lambda a, b: a[0] == b[0] == 200 and isinstance(a[1].get("keys"), list)
          and isinstance(b[1].get("keys"), list))

    py = fetch(args.python_url, "/v0/tls/revoked", args.python_viewer)
    ru = fetch(args.rust_url, "/v0/tls/revoked", args.rust_viewer)
    check("crl_viewer_forbidden", py, ru, lambda a, b: a[0] == b[0] == 403)

    py = fetch(args.python_url, "/v0/audit/verify", args.python_admin)
    ru = fetch(args.rust_url, "/v0/audit/verify", args.rust_admin)
    check("audit_admin", py, ru,
          lambda a, b: a[0] == b[0] == 200 and a[1].get("ok") is True
          and b[1].get("ok") is True)

    print(json.dumps({"ok": not failures, "checks": checks, "failures": failures},
                     ensure_ascii=False, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
