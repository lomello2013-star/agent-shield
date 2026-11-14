# Linux eBPF agent (prototype)

`scripts/linux_ebpf_agent.py` — единый коллектор: поднимает все loader-потоки,
прогоняет события через `linux.ebpf`-адаптер и product-правила, пишет audit JSONL.

## Потоки

| stream | loader mode | объект |
|---|---|---|
| exec | `stream` | `exec_path.bpf.o` |
| open | `stream_open` | `file_open_lsm.bpf.o` (cred/cron/audit/write) |
| mprotect | `stream_mprotect` | `mprotect_exec.bpf.o` |
| procmem | `stream_procmem` | `proc_mem.bpf.o` |
| ptrace | `stream_ptrace` | `ptrace_write.bpf.o` |
| mem | `stream_mem` | `mem_write.bpf.o` |
| net | `stream_net` | `net_connect_event.bpf.o` (root cgroup) |
| unlink | `stream_unlink` | `unlink_lsm.bpf.o` |
| sendto | `stream_sendto` | `sendto_monitor.bpf.o` |
| dns | `stream_dns` | `dns_monitor.bpf.o` |

## Запуск

```bash
sudo killall fapolicyd           # lab only: fapolicyd blocks the loader
sudo python3 /home/aidf/aidf/linux_ebpf_agent.py \
  --duration 60 --out /tmp/aidf_linux_audit.jsonl
sudo systemctl start fapolicyd
```

`--duration 0` — до SIGINT. Объекты/loader по умолчанию `/root/spike4`.

## Audit

Одна строка на вердикт:

```json
{"stream": "mem", "verdict": {"rule_id": "...", "severity": "..."},
 "event": {"...": "..."}}
```

## Проверено (2026-11-14)

10 потоков, сценарии `corr_helper` + `connect 4444` + DNS:
12 вердиктов — `LINUX-INJECT-106`×2, `LINUX-EXEC-MEM-107`×2,
`LINUX-EXEC-CORR-108/109/110`×2, `LINUX-C2-PORT-105`×1,
`NET-DNS-LONG-013`×1; `artifacts/linux_agent_audit.json`.

## systemd

```bash
sudo bash scripts/install_linux_agent.sh /root/spike4
sudo systemctl start aidf-agent
sudo journalctl -u aidf-agent -n 30 --no-pager
sudo systemctl stop aidf-agent
```

Юнит — `packaging/linux/aidf-agent.service`; install копирует `core/ schemas/
rules/`, `loader`, `*.bpf.o` в `/opt/aidf`, пишет audit в
`/var/log/aidf/linux_audit.jsonl`. Проверено: сервис стартует ~5 с, сценарии
`corr_helper` + connect 4444 + DNS дали **12 audit-строк**. Ротация —
`packaging/linux/aidf-agent.logrotate` (14 дней, `logrotate -d` OK).

## Очередь и целостность объектов

- audit-записи идут через bounded queue (`--queue-size`, по умолчанию 10 000);
  при переполнении считается `dropped`, readers не блокируются;
  проверено: `dropped=0`.
- `scripts/linux_object_manifest.py` пишет `packaging/linux/objects.sha256`
  (loader + `.bpf.o`); агент с `--manifest` падает fail-closed при mismatch.
- `scripts/sign_linux_manifest.py` подписывает манифест Ed25519 (lab dev-key);
  systemd передаёт `--manifest-sig`/`--manifest-pub`, проверка
  `manifest signature verified`. Production-ключ/HSM — внешний этап.

## Ограничения

- запуск только root; fapolicyd нужно останавливать в lab;
- объекты собираются `scripts/build_linux_ebpf.sh` и упаковываются в deb/rpm
  через `packaging/build_linux_packages.sh --objects`;
- без eBPF используй auditd-путь: [linux-auditd.md](linux-auditd.md);
- это прототип коллектора, не production-сервис.
