"""Fixtures for every rule: one positive scenario per rule id.

Each case is a list of Event overrides fed to `make_event` (see conftest.py):
the rule must fire on at least one of them and stay silent on the benign control.
"""

RULE_CASES = {
    "WIN-EXEC-TEMP-001": {
        "events": [dict(category="process.start", action="start",
                        actor={"path": r"C:\Users\u\AppData\Local\Temp\dropper.exe",
                               "name": "dropper.exe"})],
    },
    "WIN-PS-ENCODED-002": {
        "events": [dict(category="process.start", action="start",
                        actor={"name": "powershell.exe",
                               "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"},
                        platform_data={"cmdline": "powershell.exe -EncodedCommand SQBFAFgA"})],
    },
    "WIN-OFFICE-SPAWN-003": {
        "events": [dict(category="process.start", action="start",
                        actor={"name": "cmd.exe", "path": r"C:\Windows\System32\cmd.exe"},
                        platform_data={"parent_name": "WINWORD.EXE"})],
    },
    "WIN-LSASS-ACCESS-004": {
        "events": [dict(category="process.access", action="open_process",
                        object={"type": "process", "path": r"C:\Windows\System32\lsass.exe"})],
    },
    "WIN-RUNKEY-005": {
        "events": [dict(category="registry.change", action="set_value",
                        object={"type": "registry",
                                "path": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater"})],
    },
    "WIN-SCHTASK-006": {
        "events": [dict(category="persistence.change", action="task_create")],
    },
    "WIN-SERVICE-CREATE-007": {
        "events": [dict(category="persistence.change", action="service_create")],
    },
    "WIN-LOG-CLEAR-008": {
        "events": [dict(category="log.tamper", action="clear")],
    },
    "WIN-DEFENDER-TAMPER-009": {
        "events": [dict(category="defender.tamper", action="disable_realtime")],
    },
    "WIN-INJECT-010": {
        "events": [dict(category="memory.access", action="write",
                        object={"type": "process", "path": r"C:\Temp\target.exe"})],
    },
    "WIN-MASQUERADE-011": {
        "events": [dict(category="process.start", action="start",
                        actor={"name": "svchost.exe",
                               "path": r"C:\Users\u\AppData\svchost.exe"})],
    },
    "NET-SMB-LATERAL-012": {
        "events": [dict(category="net.connect", action="connect",
                        object={"type": "network", "path": "10.0.0.5:445",
                                "port": 445, "proto": "tcp"})],
    },
    "NET-DNS-LONG-013": {
        "events": [dict(category="dns.query", action="query",
                        platform_data={"qname": "a" * 45 + ".example.com"})],
    },
    "FILE-MASS-WRITE-014": {
        "events": [dict(category="file.write", action="write") for _ in range(50)],
    },
    "FILE-CANARY-015": {
        "events": [dict(category="file.delete", action="delete",
                        object={"type": "file",
                                "path": r"C:\ProgramData\aidf\canary\canary_1.txt"})],
    },
    "WIN-DOWNLOADS-EXEC-016": {
        "events": [dict(category="process.start", action="start",
                        actor={"name": "setup.exe",
                               "path": r"C:\Users\u\Downloads\setup.exe"},
                        integrity={"level": "low", "verified": False})],
    },
    "NET-EXFIL-LARGE-017": {
        "events": [dict(category="net.connect", action="connect",
                        object={"type": "network", "path": "203.0.113.5:443",
                                "port": 443, "proto": "tcp"},
                        platform_data={"bytes_out": 25_000_000})],
    },
    "WIN-WMI-SUBSCRIPTION-018": {
        "events": [dict(category="persistence.change", action="wmi_subscription_create")],
    },
    "LINUX-EXEC-TMP-101": {
        "events": [dict(platform="linux",
                        actor={"name": "evil", "path": "/tmp/evil",
                               "cmdline_hash": "ab" * 32}),
                   ],
    },
    "LINUX-CRON-102": {
        "events": [dict(platform="linux", category="persistence.change",
                        action="cron_write")],
    },
    "LINUX-AUDIT-TAMPER-103": {
        "events": [dict(platform="linux", category="log.tamper", action="rotate")],
    },
    "LINUX-CRED-READ-104": {
        "events": [dict(platform="linux", category="file.read", action="open",
                        object={"type": "file", "path": "/etc/shadow"})],
    },
    "LINUX-C2-PORT-105": {
        "events": [dict(platform="linux", category="net.connect", action="connect",
                        object={"type": "network", "path": "10.0.0.9:4444",
                                "port": 4444, "proto": "tcp"})],
    },
    "LINUX-INJECT-106": {
        "events": [dict(platform="linux", category="memory.access",
                        action="process_vm_writev",
                        object={"type": "process", "path": "pid:4242"}),
                   dict(platform="linux", category="memory.access",
                        action="ptrace_poke",
                        object={"type": "process", "path": "pid:5252"})],
    },
    "LINUX-EXEC-MEM-107": {
        "events": [dict(platform="linux", category="memory.access",
                        action="mprotect_exec",
                        object={"type": "memory", "path": "pid:77:rwx"},
                        platform_data={"anon": True, "length": 4096})],
    },
    "LINUX-EXEC-CORR-108": {
        "events": [
            dict(platform="linux", category="memory.access", action="mprotect_exec",
                 object={"type": "memory", "path": "pid:4242:rwx"},
                 platform_data={"anon": True}),
            dict(platform="linux", category="memory.access", action="process_vm_writev",
                 object={"type": "process", "path": "pid:4242"}),
        ],
    },
    "LINUX-EXEC-CORR-109": {
        "events": [
            dict(platform="linux", category="memory.access", action="process_vm_writev",
                 object={"type": "process", "path": "pid:600"},
                 actor={"pid": 500, "ppid": 1}),
            dict(platform="linux", category="memory.access", action="mprotect_exec",
                 object={"type": "memory", "path": "pid:600:rwx"},
                 platform_data={"anon": True}, actor={"pid": 600, "ppid": 500}),
        ],
    },
    "LINUX-EXEC-CORR-110": {
        "events": [
            dict(platform="linux", category="memory.access", action="process_vm_writev",
                 object={"type": "process", "path": "pid:700"},
                 actor={"pid": 500, "ppid": 1, "path": "/tmp/injector"},
                 platform_data={"provenance_known": True}),
            dict(platform="linux", category="memory.access", action="mprotect_exec",
                 object={"type": "memory", "path": "pid:700:rwx"},
                 platform_data={"anon": True}, actor={"pid": 700, "ppid": 500}),
        ],
    },
}
