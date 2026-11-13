"""E6/D: real Windows T1055 measurement through ETW-TI.

The project so far could not measure Windows memory-injection detection because the
provider was considered unavailable. Under admin the provider
`Microsoft-Windows-Threat-Intelligence` is present, so this script:

  1. starts an ETW trace on that provider with `logman`,
  2. performs a **safe, self-contained** T1055.002-shaped injection: it spawns its own
     dummy child (`cmd /c timeout`), opens it, allocates memory, writes a one-byte `ret`
     stub, flips the page to RWX and starts a remote thread that immediately returns,
  3. stops the trace, converts it with `tracerpt` and counts ETW-TI events by id,
  4. writes `artifacts/etwti_t1055.json` and prints a go/no-go.

Nothing is written into any process other than the dummy child this script starts.
Run elevated; the trace is stopped in a finally block.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import glob
import json
import os
import subprocess
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(HERE, "artifacts", "etwti_t1055.json")
WORK = os.path.join(HERE, "artifacts", "_etwti")
PROVIDER = "{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}"
SESSION = "AIDFTI"

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD, wt.DWORD]
k32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualProtectEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                 wt.DWORD, ctypes.POINTER(wt.DWORD)]
k32.CreateRemoteThread.restype = wt.HANDLE
k32.CreateRemoteThread.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                                   ctypes.POINTER(wt.DWORD)]
k32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
k32.CloseHandle.argtypes = [wt.HANDLE]

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT_RESERVE = 0x3000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace")


def start_trace() -> dict:
    os.makedirs(WORK, exist_ok=True)
    for stale in glob.glob(os.path.join(WORK, "*.etl")):
        os.remove(stale)
    etl = os.path.join(WORK, "etwti.etl")
    res = run(["logman", "create", "trace", SESSION, "-p", PROVIDER,
               "0xffffffffffffffff", "0xff", "-o", etl, "-ets"])
    return {"ok": res.returncode == 0, "returncode": res.returncode,
            "stderr": (res.stderr or "").strip()[-300:], "etl": etl}


def stop_trace() -> dict:
    res = run(["logman", "stop", SESSION, "-ets"])
    return {"ok": res.returncode == 0, "returncode": res.returncode,
            "stderr": (res.stderr or "").strip()[-300:]}


def inject_into_dummy() -> dict:
    child = subprocess.Popen(["cmd.exe", "/c", "timeout", "/t", "20", "/nobreak"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    result = {"child_pid": child.pid, "steps": {}}
    try:
        time.sleep(0.5)
        handle = k32.OpenProcess(PROCESS_ALL_ACCESS, False, child.pid)
        result["steps"]["open_process"] = bool(handle)
        if not handle:
            return result
        address = k32.VirtualAllocEx(handle, None, 0x1000, MEM_COMMIT_RESERVE,
                                     PAGE_READWRITE)
        result["steps"]["alloc"] = bool(address)
        if not address:
            return result
        stub = ctypes.create_string_buffer(b"\xC3", 1)          # ret: thread exits at once
        written = ctypes.c_size_t(0)
        ok = k32.WriteProcessMemory(handle, ctypes.c_void_p(address), stub, 1,
                                    ctypes.byref(written))
        result["steps"]["write"] = bool(ok)
        old = wt.DWORD(0)
        ok = k32.VirtualProtectEx(handle, ctypes.c_void_p(address), 0x1000,
                                  PAGE_EXECUTE_READWRITE, ctypes.byref(old))
        result["steps"]["protect"] = bool(ok)
        thread_id = wt.DWORD(0)
        thread = k32.CreateRemoteThread(handle, None, 0, ctypes.c_void_p(address), None,
                                        0, ctypes.byref(thread_id))
        result["steps"]["remote_thread"] = bool(thread)
        if thread:
            k32.WaitForSingleObject(thread, 5000)
            k32.CloseHandle(thread)
        k32.CloseHandle(handle)
    finally:
        child.kill()
        child.wait(timeout=10)
    return result


def parse(etl: str) -> dict:
    xml = os.path.join(WORK, "etwti.xml")
    res = run(["tracerpt", etl, "-of", "XML", "-o", xml, "-y"])
    if res.returncode != 0 or not os.path.exists(xml):
        return {"events": 0, "by_id": {}, "parse_error": (res.stderr or "")[-300:]}
    import re
    text = open(xml, encoding="utf-8", errors="replace").read()
    ids = re.findall(r"<EventID[^>]*>(\d+)</EventID>", text)
    counter = Counter(int(value) for value in ids)
    return {"events": len(ids), "by_id": dict(sorted(counter.items())),
            "xml_bytes": len(text)}


def main() -> int:
    admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    report: dict = {"admin": admin, "provider": PROVIDER}
    if not admin:
        report["error"] = "elevation required for logman ETW session"
    else:
        started = start_trace()
        report["start"] = started
        try:
            report["injection"] = inject_into_dummy()
            time.sleep(1.0)
        finally:
            report["stop"] = stop_trace()
        if started.get("ok"):
            report["trace"] = parse(started["etl"])
    trace = report.get("trace", {})
    steps = report.get("injection", {}).get("steps", {})
    report["verdict"] = {
        "injection_performed": all(steps.get(k) for k in
                                   ("open_process", "alloc", "write", "protect",
                                    "remote_thread")),
        "etw_ti_events": trace.get("events", 0),
        "detected": trace.get("events", 0) > 0,
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report["verdict"], ensure_ascii=False))
    print("by_id:", json.dumps(trace.get("by_id", {}), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
