# Air-gapped USB key ceremony (no YubiHSM)

> **This is not an HSM.** The key is software, protected by an encrypted USB and
> an offline machine. It is acceptable for a personal pilot; it is not
> tamper-resistant and not a substitute for a production HSM.

## Hardware

- 1× 16 GB USB — bootable **Ubuntu LTS** (or Tails) with encrypted persistence.
- 1× 16 GB USB — transfer of `policy.signed.json` only.
- 1× old laptop/PC — dedicated, Wi-Fi/Bluetooth disabled, no production data.
- 3 paper envelopes — Shamir shares of the LUKS passphrase (2-of-3).

## 1. Prepare the USB (trusted network, once)

1. Write Ubuntu ISO with Rufus/Etcher; enable **LUKS-encrypted persistence**.
2. Boot it once, install `ssss` and `openssl` (Ubuntu has OpenSSL 3):
   ```bash
   sudo apt update && sudo apt install -y ssss openssl
   ```
3. Split a long random LUKS passphrase 2-of-3:
   ```bash
   ssss-split -t 2 -n 3 -w luks
   ```
   Put each share in a separate envelope; never store two together.
4. Shut down. From now on, boot this USB **offline** (disable radios).

## 2. Generate the policy key offline

```bash
cd /media/$USER/persistent/stml-keys
openssl genpkey -algorithm ED25519 -out policy.key
openssl pkey -in policy.key -pubout -out policy.pub
chmod 600 policy.key
sha256sum policy.key policy.pub > SHA256SUMS
```

- `policy.key` stays only on the encrypted USB.
- Copy `policy.pub` to the online server as `policy-hsm.pem`
  (`C:\ProgramData\AIDefender\stml\trust\policy-usb.pem`).
- Store a second encrypted copy of the USB in a different physical location.

## 3. Sign a policy

Canonical payload: `{policy_id,version,channel,content}`, sorted JSON.

```bash
./scripts/stml_offline_sign.sh policy.json policy.key policy.pub policy.signed.json
```

The script:
1. writes canonical JSON;
2. signs with `openssl pkeyutl -rawin`;
3. verifies immediately;
4. computes `key_id = sha256(raw pubkey)[:16]`;
5. writes base64 signature into `policy.signed.json`.

Move only `policy.signed.json` to the transfer USB. Unmount, wipe `canonical.bin`
and shell history, shut down.

## 4. Publish

On the online server:

```powershell
# policy_pubkey must be policy.pub
python -m stml.server ...
# POST /v0/policies with policy.signed.json (admin)
```

Server verifies `key_id` and Ed25519 signature; wrong signature → 403.

## 5. Quorum ceremony

1. Two custodians meet; a third may be remote/witness.
2. Reconstruct LUKS passphrase from two shares:
   ```bash
   ssss-combine -t 2
   ```
3. Boot the encrypted USB; verify `SHA256SUMS`.
4. Sign; record:
   - date/time, object/policy hash, who was present, which shares used;
   - `sha256sum policy.signed.json`;
   - photo/video of the ceremony (optional).
5. Change the LUKS passphrase after the ceremony? For a persistent USB, rotating
   the passphrase requires re-encrypting; at minimum rotate shares annually.

## 6. Limits

| Risk | Mitigation |
|---|---|
| USB lost/stolen | LUKS + 2-of-3 shares + second copy |
| Malware on signing host | dedicated offline machine, no network |
| Firmware/USB controller attack | buy reputable media, verify checksums, physical control |
| Key in RAM | power off after ceremony; no hibernation |
| No hardware attestation | accept; this is not an HSM |
| Share compromise | 2-of-3; rotate shares annually |

## 7. When to move to real HSM

- You start selling to third parties.
- You process other people's personal data.
- You need auditable key custody/attestation.
- Then: Nitrokey HSM 2 (check Ed25519 support), YubiHSM 2, or cloud KMS.
