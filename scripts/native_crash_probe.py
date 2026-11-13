"""F11: report *which native module* faults, not just the Python frame.

`faulthandler` prints Python stacks, which is useless once the crash is inside a C
extension. This installs a vectored exception handler with ctypes (no admin needed) that,
on an access violation, resolves the faulting address to the owning module (DLL/PD) and
writes the module name plus the Python traceback to a file before letting the process die.

Enable with AIDF_NATIVE_PROBE=1 (soak_daemon imports it on demand).
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import faulthandler
import os
from datetime import datetime, timezone

EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_CONTINUE_SEARCH = 1

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "artifacts", "_stdout", "soak_native.txt")


class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [
        ("ExceptionCode", wt.DWORD),
        ("ExceptionFlags", wt.DWORD),
        ("ExceptionRecord", ctypes.c_void_p),
        ("ExceptionAddress", ctypes.c_void_p),
        ("NumberParameters", wt.DWORD),
        ("ExceptionInformation", ctypes.c_void_p * 15),
    ]


class EXCEPTION_POINTERS(ctypes.Structure):
    _fields_ = [("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
                ("ContextRecord", ctypes.c_void_p)]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION),
                                  ctypes.c_size_t]
kernel32.VirtualQuery.restype = ctypes.c_size_t
kernel32.GetModuleFileNameW.argtypes = [wt.HMODULE, wt.LPWSTR, wt.DWORD]
kernel32.GetModuleFileNameW.restype = wt.DWORD

HANDLER = None          # keep a reference so it is not garbage collected


def _module_of(address: int) -> tuple[str, int, int]:
    """Return (module path, module base, offset within the module)."""
    info = MEMORY_BASIC_INFORMATION()
    if kernel32.VirtualQuery(ctypes.c_void_p(address), ctypes.byref(info),
                             ctypes.sizeof(info)) == 0:
        return "<unknown>", 0, 0
    base = info.AllocationBase or 0
    if not base:
        return "<no allocation base>", 0, 0
    buf = ctypes.create_unicode_buffer(512)
    got = kernel32.GetModuleFileNameW(wt.HMODULE(base), buf, len(buf))
    name = buf.value if got else f"<mapped at {hex(base)}>"
    return name, base, address - base


def _handler(exception_info):
    record = exception_info.contents.ExceptionRecord.contents
    if record.ExceptionCode in (EXCEPTION_ACCESS_VIOLATION,
                                0xC0000374,            # heap corruption
                                0xC0000409):           # stack buffer overrun
        address = record.ExceptionAddress or 0
        module, base, offset = _module_of(address)
        kind = {0: "read", 1: "write", 8: "execute"}.get(
            record.ExceptionInformation[0], "unknown") if record.NumberParameters else "unknown"
        bad_address = record.ExceptionInformation[1] if record.NumberParameters > 1 else 0
        lines = [
            f"native exception code=0x{record.ExceptionCode:08X}",
            f"exception address=0x{address:016X}",
            f"module={module}",
            f"module_base=0x{base:016X} offset=0x{offset:X}",
            f"access={kind} at=0x{bad_address:016X}",
            f"parameters={record.NumberParameters}",
            f"time={datetime.now(timezone.utc).isoformat()}",
        ]
        try:
            os.makedirs(os.path.dirname(OUT), exist_ok=True)
            with open(OUT, "a", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
                faulthandler.dump_traceback(file=fh, all_threads=True)
        except OSError:
            pass
    return EXCEPTION_CONTINUE_SEARCH


def install() -> None:
    global HANDLER
    proto = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.POINTER(EXCEPTION_POINTERS))
    HANDLER = proto(_handler)
    kernel32.AddVectoredExceptionHandler(1, HANDLER)
