"""Send a protection policy to AidfFilter over the Filter Manager port.

User-mode half of the driver contour: the kernel blocks create/write when the
file name contains the policy substring. Empty policy = no block.

Run on Windows (lab VM), as an account allowed to open the port:
    python scripts/aidf_driver_policy.py "\\protected\\"
    python scripts/aidf_driver_policy.py "\\secret\\"
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
import sys

PORT = r"\AidfFilterPort"


def send_policy(policy: str, port: str = PORT) -> None:
    if sys.platform != "win32":
        raise SystemExit("AidfFilter policy client is Windows-only")
    fltlib = ctypes.WinDLL("fltlib.dll")
    fltlib.FilterConnectCommunicationPort.argtypes = [
        wt.LPCWSTR, wt.DWORD, wt.LPVOID, wt.WORD, wt.LPVOID,
        ctypes.POINTER(wt.HANDLE),
    ]
    fltlib.FilterConnectCommunicationPort.restype = ctypes.c_long
    fltlib.FilterSendMessage.argtypes = [
        wt.HANDLE, wt.LPVOID, wt.DWORD, wt.LPVOID, wt.DWORD,
        ctypes.POINTER(wt.DWORD),
    ]
    fltlib.FilterSendMessage.restype = ctypes.c_long

    handle = wt.HANDLE()
    hr = fltlib.FilterConnectCommunicationPort(
        port, 0, None, 0, None, ctypes.byref(handle))
    if hr != 0:
        raise OSError(f"FilterConnectCommunicationPort failed: 0x{hr & 0xFFFFFFFF:08x}")

    try:
        data = policy.encode("utf-16-le")
        if len(data) > 255 * 2:
            raise ValueError("policy must be <= 255 UTF-16 code units")
        buf = struct.pack("<I", len(data)) + data
        returned = wt.DWORD(0)
        hr = fltlib.FilterSendMessage(
            handle, buf, len(buf), None, 0, ctypes.byref(returned))
        if hr != 0:
            raise OSError(f"FilterSendMessage failed: 0x{hr & 0xFFFFFFFF:08x}")
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)

    print(f"policy sent: {policy!r} ({len(policy)} chars)")


if __name__ == "__main__":
    send_policy(sys.argv[1] if len(sys.argv) > 1 else "\\protected\\")
