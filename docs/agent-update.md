# Signed agent updates and rollback

The agent uses A/B slots (`core/updater.py`): a new bundle is written to the
inactive slot, every file is checked against a signed manifest, then an atomic
pointer switches the active slot. A failed health check can switch back.

## 1. Keys

Generate an Ed25519 update key once:

```bash
openssl genpkey -algorithm ED25519 -out update.key.pem
openssl pkey -in update.key.pem -pubout -out update.pub.pem
```

Keep `update.key.pem` offline/HSM-backed in production. The agent only ships the
public key.

## 2. Build a bundle

```bash
python scripts/aidf_update.py sign \
  --root build/aidf-1.2.0 \
  --version 1.2.0 \
  --key update.key.pem \
  --out aidf-1.2.0.bundle.json

python scripts/aidf_update.py verify \
  --bundle aidf-1.2.0.bundle.json --pubkey update.pub.pem
```

A bundle contains base64 files, a canonical manifest and an Ed25519 signature.
The signature covers the manifest; each file hash is checked before staging.

## 3. Apply

```bash
sudo python scripts/aidf_update.py apply \
  --slots /var/lib/aidf/update \
  --bundle aidf-1.2.0.bundle.json \
  --pubkey update.pub.pem \
  --health-cmd "/opt/aidf/aidf_agent.py --config /etc/aidf/agent.toml --once"
```

Result:

- `updated` — new slot is active;
- `rolled_back` — health command failed, previous slot restored.

## 4. Rollback / status

```bash
python scripts/aidf_update.py status --slots /var/lib/aidf/update
python scripts/aidf_update.py rollback --slots /var/lib/aidf/update
```

`rollback` refuses if the previous slot fails verification. No silent fallback.

## 5. Fleet packages

The connector already has `stml-connector sign-package` / `verify-package` for a
fleet release manifest. Reuse the same key custody for both; the local bundle is
for an individual host.

## 6. Package install/remove

Linux:

```bash
sudo dpkg -i dist/aidf-auditd_0.1.0_amd64.deb
sudo systemctl status aidf-auditd
sudo apt remove aidf-auditd
```

The package installs `/opt/aidf`, `/etc/aidf/agent.toml` and the systemd unit.
It does **not** start the service automatically; review config first.

## 7. Limits

- No delta updates; the bundle carries full files.
- No automatic key rotation yet; rotate by shipping a new public key with the
  package and re-signing future bundles.
- Production requires HSM-backed signing and an independent update-channel
  penetration test.
