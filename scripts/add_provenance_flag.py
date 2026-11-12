"""F03: explicit provenance flag instead of silently treating an unresolved path as
untrusted (which produced noisy high-severity alerts).

Each memory adapter now reports `platform_data.provenance_known` = whether the actor
path came from the kernel (`exe`), and keeps `actor.path` empty when it did not.
"""

import io
import re

PATH = "core/normalize.py"
text = io.open(PATH, encoding="utf-8").read()

original = text

# 1) resolve the exe path once and record whether it is known
text = text.replace(
    '''    comm = str(raw.get("comm") or "")
    return {
        "category": "memory.access",
        "action": "process_vm_writev",''',
    '''    comm = str(raw.get("comm") or "")
    exe = str(raw.get("exe") or "")
    return {
        "category": "memory.access",
        "action": "process_vm_writev",''')
text = text.replace(
    '''    comm = str(raw.get("comm") or "")
    return {
        "category": "memory.access",
        "action": "ptrace_poke",''',
    '''    comm = str(raw.get("comm") or "")
    exe = str(raw.get("exe") or "")
    return {
        "category": "memory.access",
        "action": "ptrace_poke",''')
text = text.replace(
    '''    comm = str(raw.get("comm") or "")
    return {
        "category": "memory.access",
        "action": "proc_mem_write" if writable else "proc_mem_read",''',
    '''    comm = str(raw.get("comm") or "")
    exe = str(raw.get("exe") or "")
    return {
        "category": "memory.access",
        "action": "proc_mem_write" if writable else "proc_mem_read",''')

# 2) actor.path no longer falls back to comm
text = text.replace('"path": str(raw.get("exe") or comm),', '"path": exe,')

# 3) platform_data carries the flag
text = text.replace('"platform_data": {"target_pid": target, "riovcnt": raw.get("bytes")},',
                    '"platform_data": {"target_pid": target, "riovcnt": raw.get("bytes"),\n'
                    '                          "provenance_known": bool(exe)},')
text = text.replace('"platform_data": {"target_pid": target, "ptrace_request": request},',
                    '"platform_data": {"target_pid": target, "ptrace_request": request,\n'
                    '                          "provenance_known": bool(exe)},')
text = text.replace('"platform_data": {"proc_path": path, "writable": writable},',
                    '"platform_data": {"proc_path": path, "writable": writable,\n'
                    '                          "provenance_known": bool(exe)},')

# 4) mprotect adapter
text = text.replace(
    '''    comm = str(raw.get("comm") or "")
    anon = bool(raw.get("anon"))''',
    '''    comm = str(raw.get("comm") or "")
    exe = str(raw.get("exe") or "")
    anon = bool(raw.get("anon"))''')
text = text.replace('"platform_data": {"anon": anon, "length": raw.get("len")},',
                    '"platform_data": {"anon": anon, "length": raw.get("len"),\n'
                    '                          "provenance_known": bool(exe)},')

io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("exe locals:", len(re.findall(r'exe = str\(raw\.get\("exe"\) or ""\)', text)))
print("provenance flags:", text.count('"provenance_known": bool(exe)'))
print("comm fallbacks left:", text.count('str(raw.get("exe") or comm)'))
