#!/usr/bin/env bash
# Offline Ed25519 policy signer for an air-gapped Ubuntu/Tails USB.
# Requires: openssl 3.x, python3, base64 (GNU).
set -euo pipefail
POLICY="${1:?policy.json}"
PRIVATE="${2:?policy.key}"
PUBLIC="${3:?policy.pub}"
OUT="${4:-policy.signed.json}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

python3 - "$POLICY" "$work/canonical.bin" <<'PY'
import json, sys
policy = json.load(open(sys.argv[1], encoding="utf-8"))
body = {k: policy[k] for k in ("policy_id", "version", "channel", "content") if k in policy}
open(sys.argv[2], "wb").write(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
PY

openssl pkeyutl -sign -inkey "$PRIVATE" -rawin -in "$work/canonical.bin" -out "$work/sig.bin"
openssl pkeyutl -verify -pubin -inkey "$PUBLIC" -rawin -in "$work/canonical.bin" -sigfile "$work/sig.bin"

python3 - "$POLICY" "$PUBLIC" "$work/sig.bin" "$OUT" <<'PY'
import base64, hashlib, json, subprocess, sys
policy = json.load(open(sys.argv[1], encoding="utf-8"))
der = subprocess.check_output(["openssl", "pkey", "-pubin", "-in", sys.argv[2], "-outform", "DER"])
key_id = hashlib.sha256(der[-32:]).hexdigest()[:16]
policy["key_id"] = key_id
policy["signature"] = base64.b64encode(open(sys.argv[3], "rb").read()).decode("ascii")
with open(sys.argv[4], "w", encoding="utf-8") as fh:
    json.dump(policy, fh, ensure_ascii=False, indent=2)
print(f"key_id={key_id}")
print(f"signed={sys.argv[4]}")
PY
