# Tailscale web access (personal)

## Current setup

Tailscale is installed and logged in. STML is served **inside the tailnet**:

```text
http://desktop-jhqb492.tail7dcc3b.ts.net/
|-- proxy http://127.0.0.1:8080
```

GUI: `http://desktop-jhqb492.tail7dcc3b.ts.net/ui/`

## HTTPS

`tailscale cert` returned:

```text
your Tailscale account does not support getting TLS certs
```

Options:

1. **Enable HTTPS certificates** in Tailscale admin console
   (DNS → HTTPS Certificates), then:
   ```powershell
   tailscale serve --bg --https=443 8080
   ```
2. Keep **HTTP inside the tailnet**. Tailscale transport is WireGuard-encrypted;
   the browser will still mark `http://` as not secure.

Do **not** use `tailscale funnel` — that exposes the service to the public internet.

## Commands

```powershell
& 'C:\Program Files\Tailscale\tailscale.exe' status
& 'C:\Program Files\Tailscale\tailscale.exe' serve status
& 'C:\Program Files\Tailscale\tailscale.exe' serve --http=80 off
```

## Security notes

- Restrict tailnet with ACLs; only your devices.
- Use MFA/passkey on the Tailscale account.
- Keep `viewer`/`admin` tokens in `tokens.json` (ACL) or env.
- Prefer HTTPS once certificates are enabled.
- Do not expose port 8080 on the LAN/public interface.
