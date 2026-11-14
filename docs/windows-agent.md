# Windows agent package (EXE)

The Windows agent is a PyInstaller one-file executable around
`scripts/aidf_agent.py`. It uses the same daemon pipeline and local panel as the
Linux auditd runner.

## Build

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File packaging\windows\build_windows_exe.ps1
```

MSI (WiX 3 binaries are not committed; extract `wix314-binaries.zip` to
`.tools\wix3`):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File packaging\windows\build_windows_msi_wix3.ps1
```

Output:

- `dist\windows\aidf-agent.exe`
- `dist\windows\aidf-agent.msi`
- `dist\aidf-agent-windows.zip` (EXE + config + install/uninstall scripts)

The MSI is built with WiX 3 (no OSMF EULA) and installs the EXE and
`agent.toml`; it does not create the scheduled task. Use the post-install task
command from this document, or the PowerShell installer (which also creates the
task).

## Install (EXE/zip)

```powershell
# elevated
Expand-Archive dist\aidf-agent-windows.zip C:\Temp\aidf -Force
C:\Temp\aidf\install_aidf_agent.ps1
```

MSI-only install:

```powershell
msiexec /i dist\windows\aidf-agent.msi /qn
```

Then create the task manually (or rerun the installer after MSI):

```powershell
# elevated
$exe = "C:\Program Files\AIDefender\aidf-agent.exe"
$conf = "C:\ProgramData\AIDefender\agent.toml"
$action = New-ScheduledTaskAction -Execute $exe -Argument "--config `"$conf`"" -WorkingDirectory "C:\Program Files\AIDefender"
Register-ScheduledTask -TaskName "AIDefender-Agent" -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) -RunLevel Highest -Force
Start-ScheduledTask -TaskName "AIDefender-Agent"
```

Installs:

- `C:\Program Files\AIDefender\aidf-agent.exe`
- `C:\ProgramData\AIDefender\agent.toml`
- scheduled task `AIDefender-Agent` (only via the PowerShell installer)

Local panel: `http://127.0.0.1:18080/ui/`.

## Uninstall

```powershell
C:\Program Files\AIDefender\uninstall_aidf_agent.ps1
```

The config and data under `C:\ProgramData\AIDefender` are kept; remove manually
only after backup.

## One-shot check

```powershell
$env:TEMP = "D:\aidf-temp"       # PyInstaller one-file extraction directory
& "C:\Program Files\AIDefender\aidf-agent.exe" --config "C:\ProgramData\AIDefender\agent.toml" --once
```

If PyInstaller reports `Could not create temporary directory`, set `TEMP` to a
writable path as above. A future MSI will pass `--runtime-tmpdir`.

## Current limits

- The EXE is not code-signed; production needs an Authenticode certificate.
- MSI/WiX source is not built in this environment (WiX toolset absent).
- The scheduled task runs as the installing user; a true Windows service for
  SYSTEM-level telemetry is a separate packaging step.
- No Windows event-log kernel driver is included; the EXE uses the existing
  read-only `win.eventlog` source.
