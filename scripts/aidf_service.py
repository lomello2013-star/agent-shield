"""Windows service host for the AIDefender daemon (no pywin32, ctypes only).

SCM requires the process to call `StartServiceCtrlDispatcherW` and to report status via
`SetServiceStatus`; Python can do both through ctypes. The service keeps the daemon in
`C:\\ProgramData\\AIDefender` so its audit chain survives restarts and upgrades.

Install:  sc create AIDefender binPath= "<python.exe> <this file>" start= auto
Control:  sc start AIDefender / sc query AIDefender / sc stop AIDefender
Remove:   sc delete AIDefender
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import platform
import secrets
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

SERVICE_NAME = "AIDefender"
DATA_ROOT = os.environ.get("AIDF_SERVICE_ROOT", r"C:\ProgramData\AIDefender")

SERVICE_WIN32_OWN_PROCESS = 0x10
SERVICE_ACCEPT_STOP = 0x01
SERVICE_ACCEPT_SHUTDOWN = 0x04
SERVICE_RUNNING = 0x04
SERVICE_START_PENDING = 0x02
SERVICE_STOP_PENDING = 0x03
SERVICE_STOPPED = 0x01
NO_ERROR = 0
ERROR_SERVICE_SPECIFIC_ERROR = 1066

advapi = ctypes.WinDLL("advapi32", use_last_error=True)


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [("dwServiceType", wt.DWORD),
                ("dwCurrentState", wt.DWORD),
                ("dwControlsAccepted", wt.DWORD),
                ("dwWin32ExitCode", wt.DWORD),
                ("dwServiceSpecificExitCode", wt.DWORD),
                ("dwCheckPoint", wt.DWORD),
                ("dwWaitHint", wt.DWORD)]


class SERVICE_STATUS_HANDLE(ctypes.c_void_p):
    pass


HANDLER = ctypes.WINFUNCTYPE(wt.DWORD, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                             ctypes.c_void_p)
SERVICE_MAIN = ctypes.WINFUNCTYPE(None, wt.DWORD, ctypes.POINTER(wt.LPWSTR))


class SERVICE_TABLE_ENTRY(ctypes.Structure):
    _fields_ = [("lpServiceName", wt.LPWSTR), ("lpServiceProc", SERVICE_MAIN)]


advapi.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(SERVICE_TABLE_ENTRY)]
advapi.RegisterServiceCtrlHandlerExW.restype = SERVICE_STATUS_HANDLE
advapi.RegisterServiceCtrlHandlerExW.argtypes = [wt.LPCWSTR, HANDLER, ctypes.c_void_p]
advapi.SetServiceStatus.argtypes = [SERVICE_STATUS_HANDLE, ctypes.POINTER(SERVICE_STATUS)]

_status_handle: SERVICE_STATUS_HANDLE | None = None
_stop = threading.Event()
_checkpoint = 0


def _report(state: int, accepted: int = 0, hint_ms: int = 0, exit_code: int = NO_ERROR) -> None:
    global _checkpoint
    _checkpoint += 1
    status = SERVICE_STATUS(SERVICE_WIN32_OWN_PROCESS, state, accepted, exit_code, 0,
                            _checkpoint, hint_ms)
    if _status_handle:
        advapi.SetServiceStatus(_status_handle, ctypes.byref(status))


def _control(control: int, event_type: int, event_data: ctypes.c_void_p,
             context: ctypes.c_void_p) -> wt.DWORD:
    # SERVICE_CONTROL_STOP = 1, SERVICE_CONTROL_SHUTDOWN = 5
    if control in (1, 5):
        _stop.set()
        _report(SERVICE_STOP_PENDING, hint_ms=5000)
    return NO_ERROR


_HANDLER = HANDLER(_control)


def _restrict(path: str) -> None:
    """Best-effort ACL for a local secret file (Windows)."""
    user = os.environ.get("USERNAME", "")
    if user:
        subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", f"{user}:F"],
                       check=False, capture_output=True, timeout=10)


def _shared_secret(env_name: str, file_env: str, default_name: str,
                   *, token: bool = False) -> str:
    """Return a secret shared by the service and the STML connector.

    Precedence: env value → file → generate. The chosen value is persisted to the
    file so the connector can read the same value without its own random key.
    """
    path = os.environ.get(file_env) or os.path.join(DATA_ROOT, default_name)
    value = os.environ.get(env_name, "").strip()
    if not value and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            value = fh.read().strip()
    if not value:
        value = secrets.token_urlsafe(32) if token else secrets.token_hex(32)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(value)
            fh.flush()
            os.fsync(fh.fileno())
        _restrict(path)
    except OSError:
        pass
    return value


def _run_daemon() -> int:
    from core.daemon import Daemon, DaemonConfig
    from core.ipc import RpcServer, build_daemon_registry, default_address
    from core.normalize import HostContext
    from core.response import QuarantineStore, ResponseExecutor

    os.makedirs(DATA_ROOT, exist_ok=True)
    host = HostContext(host_id=os.environ.get("COMPUTERNAME", "host"),
                       os="windows", version=platform.version() or "unknown",
                       arch=platform.machine() or "x64")
    sources = ["win.eventlog", "win.defender"]
    sysmon_requested = os.environ.get("AIDF_SYSMON") == "1"
    sysmon_ok = False
    if sysmon_requested:
        from core.winsource import channel_exists
        sysmon_ok = channel_exists("Microsoft-Windows-Sysmon/Operational")
        if sysmon_ok:
            sources.append("win.sysmon")   # opt-in: process events with a PID
    if os.environ.get("AIDF_SECURITY") == "1":
        sources.append("win.security")     # opt-in: 4698/4720/4688/1102
    config = DaemonConfig(sources=sources,
                          thresholds={"heartbeat_timeout_s": 60})
    # Without a positive interval the collector thread never starts and the service
    # would detect nothing (P0-11). 5 s is the default poll cadence.
    collect_interval = float(os.environ.get("AIDF_COLLECT_INTERVAL_S", "5"))
    daemon = Daemon(DATA_ROOT, config=config, host=host, serve_http=False,
                    collect_interval_s=collect_interval)
    if sysmon_requested and not sysmon_ok:
        daemon.log.append("sysmon_missing",
                          {"channel": "Microsoft-Windows-Sysmon/Operational"})
    # Response layer: without this the gate could only count actions. The key is
    # provisioned in the data root (production: DPAPI/TPM, per docs/self-protection).
    key_path = os.path.join(DATA_ROOT, "quarantine.key")
    if not os.path.exists(key_path):
        with open(key_path, "wb") as fh:
            fh.write(os.urandom(32))
    quarantine = QuarantineStore(os.path.join(DATA_ROOT, "quarantine"), key_path=key_path)
    daemon.response = ResponseExecutor(daemon.confirmations, quarantine=quarantine)
    daemon.response_quarantine = quarantine
    # IPC is enabled by default; secrets are shared with the STML connector via
    # ACL-protected files in DATA_ROOT (production: DPAPI/TPM/secret store).
    rpc = None
    if os.environ.get("AIDF_ENABLE_IPC", "1") != "0":
        admin_token = _shared_secret("AIDF_ADMIN_TOKEN", "AIDF_ADMIN_TOKEN_FILE",
                                     "admin.token", token=True)
        operator_token = _shared_secret("AIDF_OPERATOR_TOKEN", "AIDF_OPERATOR_TOKEN_FILE",
                                        "operator.token", token=True)
        authkey_hex = _shared_secret("AIDF_AUTHKEY", "AIDF_AUTHKEY_FILE",
                                     "authkey.hex")
        try:
            authkey = bytes.fromhex(authkey_hex)
        except ValueError:
            authkey = os.urandom(32)
            authkey_hex = authkey.hex()
            path = os.environ.get("AIDF_AUTHKEY_FILE") or os.path.join(DATA_ROOT, "authkey.hex")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(authkey_hex)
            _restrict(path)
        tokens = {admin_token: "admin", operator_token: "operator"}
        rpc = RpcServer(default_address(), authkey, tokens, build_daemon_registry(daemon))
        rpc.start()
    daemon.start()
    _report(SERVICE_RUNNING, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN)
    try:
        while not _stop.is_set():
            daemon.tick()
            time.sleep(0.05)
    finally:
        if rpc is not None:
            rpc.stop()
        daemon.stop()
    return 0


def _service_main(argc: int, argv: ctypes.POINTER(wt.LPWSTR)) -> None:
    global _status_handle
    _status_handle = advapi.RegisterServiceCtrlHandlerExW(SERVICE_NAME, _HANDLER, None)
    if not _status_handle:
        return
    _report(SERVICE_START_PENDING, hint_ms=10000)
    try:
        code = _run_daemon()
    except Exception:                      # report failure, do not leave SCM hanging
        _report(SERVICE_STOPPED, exit_code=ERROR_SERVICE_SPECIFIC_ERROR)
        raise
    _report(SERVICE_STOPPED)
    sys.exit(code)


_SERVICE_MAIN = SERVICE_MAIN(_service_main)


def main() -> int:
    table = (SERVICE_TABLE_ENTRY * 2)()
    table[0].lpServiceName = SERVICE_NAME
    table[0].lpServiceProc = _SERVICE_MAIN
    table[1].lpServiceName = None
    table[1].lpServiceProc = SERVICE_MAIN()
    if not advapi.StartServiceCtrlDispatcherW(table):
        error = ctypes.get_last_error()
        print(f"StartServiceCtrlDispatcher failed: {error} (not started by SCM?)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
