# Run STML and the agent locally

## One click

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_stml_demo.ps1
```

It starts (only if the port is free):

- STML server — `http://127.0.0.1:8080/ui/`
- Agent panel — `http://127.0.0.1:18080/ui/`
- demo connector — data under `C:\ProgramData\AIDefender\agent-demo`
- opens both pages

No admin required. Logs:

```text
C:\ProgramData\AIDefender\stml\server.run.log
C:\ProgramData\AIDefender\agent-demo\
```

## What you should see

Screenshots from this host:

- [server dashboard](../artifacts/stml-server-ru.png)
- [server reports](../artifacts/stml-reports-live.png)
- [agent panel](../artifacts/agent-panel-ru3.png)

### Server UI `/ui/`

- Fleet: at least `DESKTOP-JHQB492` (the existing agent) and a demo connector
  agent;
- Reports: `agent.record` and `event` entries;
- Policies/Approvals: empty or previous test data;
- Health: `ok`.

### Agent panel `/ui/`

- `PROTECTED`;
- Kernel/collector stack: `win.eventlog` loaded;
- Recent verdicts/events;
- Pending confirmations (if any);
- Pause/Scan buttons.

## Manual endpoints

```powershell
Invoke-RestMethod http://127.0.0.1:8080/health
Invoke-RestMethod http://127.0.0.1:18080/api/overview
```

## If a page is empty

1. Check `Get-NetTCPConnection -LocalPort 8080,18080 -State Listen`.
2. Check `Get-Content C:\ProgramData\AIDefender\stml\server.run.log -Tail 30`.
3. Check the connector process from `C:\ProgramData\AIDefender\agent-demo\rpc.lock`.
4. Re-run the launcher; it only starts missing components.

## Autostart after reboot

A per-user Startup shortcut `STML.lnk` is installed and runs the launcher with
`-NoBrowser`. It starts the server, demo connector and agent panel at logon; it
does not require admin.

For SYSTEM-level tasks:

```powershell
# elevated
.\scripts\install_stml_server_task.ps1
.\scripts\install_stml_connector_task.ps1
.\scripts\install_stml_rust_task.ps1
```

Those tasks are currently **not registered** on this host; the per-user startup
shortcut is the active autostart path.
