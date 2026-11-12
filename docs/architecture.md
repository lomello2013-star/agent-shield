# Архитектура ИИ-защитника

> **Статус:** норматив. Разворачивает v9.1 §3.
> **Назначение:** полное описание компонентов, слоёв, процессов, привилегий и потоков данных. Это источник истины для реализации и контрактных тестов.

## 1. Принципы проектирования

1. **Максимальная модульность.** Каждый компонент — модуль с контрактом; отказ одного не роняет остальные.
2. **Ядро не зависит от платформы.** Всё платформенное — за интерфейсами `platform/`.
3. **Возможности, а не предположения.** Модуль объявляет `requires_capabilities`; ядро отказывает несовместимому явно.
4. **Двухконтурность.** Быстрый детерминированный рефлекс отделён от медленного когнитивного ИИ.
5. **Fail-safe по умолчанию.** Таймаут подтверждения = отказ; без оператора разрушительное не выполняется.
6. **Наименьшие привилегии.** Разбор недоверенных файлов — в песочнице; LLM — отдельный uid.
7. **Расширяемость без breaking.** Плагины, версионируемые схемы, capability negotiation.

## 2. Процессная модель

```
ЯДРО (kernel)
├── драйвер/minifilter (Windows): callbacks — файлы/реестр/сеть/процессы
└── eBPF (Linux): tracepoints, kprobes, LSM-хуки, cgroup skb

ПОЛЬЗОВАТЕЛЬСКИЙ УРОВЕНЬ
aidfd (SYSTEM / root, минимальные caps)
├── core           оркестратор, реестр модулей, IPC-хаб, политика
├── platform/      windows | linux (адаптеры телеметрии и реакции)
├── telemetry      чтение → нормализация → приоритетная очередь
├── detectors      rules_engine, file_detector, behavior_detector, memory, net
├── response       suspend/quarantine/block/terminate + подтверждения
├── telemetry_self метрики, SLO, trace_id
├── watchdog       перезапуск, heartbeat, self-heal
├── diagnostics    outbox отчётов/телеметрии (opt-in)
└── llm (отдельный uid) — только объяснения, без авторитета

aidf-parse (sandbox)  парсер недоверенных PE/ELF/скриптов
aidf-session/agent    (user, per-session) подтверждения и уведомления
aidfctl / aidf-tui    (user) управление и диагностика
```

## 3. Слои L0–L8

| Слой | Роль | Windows | Linux | Отказ-режим |
|---|---|---|---|---|
| L0 | Предотвращение | WDAC, protected folders, Exploit Protection | fapolicyd+IMA, noexec | fallback на L1–L6 (детекция) |
| L1 | Ядро-видимость | minifilter, ELAM, ETW-TI | eBPF/LSM, auditd, fanotify | auditd-only (degraded) |
| L2 | Инспекция запуска | AMSI, script logging, CLR | LSM `bprm`, интерпретаторы | script-block отключён → L1+L6 |
| L3 | Память/эксплойты | LSASS protection, anti-injection, memory scan | kprobe, `/proc/pid/mem` | наблюдение без блокировки |
| L4 | Сеть | WFP callout (DPI, TLS-fp, DNS) | eBPF tc/XDP, nft, conntrack | nft 5-tuple (best-effort) |
| L5 | Реагирование | kernel suspend/quarantine/rollback | SIGSTOP/quarantine/rollback | очередь + notify |
| L6 | Детекция | правила + ML-ансамбль | правила + ML-ансамбль | только правила |
| L7 | Надёжность | heartbeat, проба, dual-slot, self-heal | ← те же | safe mode |
| L8 | Самозащита | тампер-доказательность, PPL, ELAM | IMA, fs-verity, SELinux | детекция + журнал |

## 4. Двухконтурный ИИ

```
КОГНИТИВНЫЙ контур (ИИ, 1–10 с)          РЕФЛЕКС (детерминированный, <5 мс)
  полное восприятие событий                ядро-компонент (driver/eBPF)
  корреляция, гипотезы, приоритеты         политика + правила
  предложение плана сдерживания            калиброванные ML-скоры (ONNX)
  объяснение, оценка                       обратимые действия: suspend/block/quarantine
          │                                        ▲
          └──► ПОЛИТИЧЕСКИЙ ГЕЙТ ──────────────────┘
               (allowlist действий, обратимые-первыми,
                порог уверенности, human-approval для необратимого)
```

- **Рефлекс** обязан: работать всегда (даже при падении ИИ), быть детерминированным, <5 мс, обратимые действия.
- **Когнитивный ИИ** имеет: полное восприятие, право предлагать и направлять; НЕ имеет: авторитета исполнения (его вывод — предложение, проходит гейт).

## 5. Платформенная абстракция

```python
class TelemetrySource(Protocol):
    def probe(self) -> PlatformCapabilities: ...
    def start(self, sink: EventSink) -> None: ...
    def stop(self) -> None: ...
    def health(self) -> SourceHealth: ...

class FileMonitor(Protocol): ...
class ProcessController(Protocol):   # terminate, suspend, resume, tree
class NetworkEnforcer(Protocol):     # block_process, block_flow, unblock, list
class QuarantineStore(Protocol):     # put, restore, purge, verify
class ServiceControl(Protocol):      # install, start, stop, status
class SecretStore(Protocol):         # get/set/delete (DPAPI / keyring/TPM)
class IntegrityVerifier(Protocol):   # binary, model pack, config manifest
class SessionResolver(Protocol):     # владелец процесса, активные сессии
class AuditSink(Protocol):           # Event Log / journald, tamper-evident
```

Выбор адаптера — entry point `aidefender.platform.windows` / `aidefender.platform.linux`. `probe()` пишет `capabilities.json`; отсутствие capability → `capability_missing`.

## 6. Привилегии и изоляция

| Процесс | Привилегия | Ограничения |
|---|---|---|
| `aidfd` | SYSTEM / root с минимальными caps | `CapabilityBoundingSet` (CAP_KILL, CAP_NET_ADMIN, CAP_SYS_ADMIN для fanotify, CAP_AUDIT_READ, CAP_DAC_READ_SEARCH) |
| драйвер/eBPF | ядро | только callbacks, никакого парсинга в ядре |
| `aidf-parse` | low-integrity/AppContainer; seccomp+Landlock+nobody | без сети, RLIMIT, таймауты |
| `aidf-llm` | отдельный uid | без доступа к управляющему IPC |
| `aidfctl`/`aidf-tui` | user | роли admin/operator/viewer, allowlist команд |

## 7. Матрица возможностей

| Возможность | Windows | Linux |
|---|---|---|
| Запуск/выход процесса | kernel callbacks, ETW-TI, Sysmon 1 | eBPF `sched_process_*`, auditd |
| Память | kernel-скан, anti-injection | kprobe, `/proc/pid/mem` |
| Скрипты | AMSI, script block logging | LSM `bprm`, интерпретаторы |
| Сеть | WFP callout (DPI, TLS-fp, DNS) | eBPF tc/XDP, nft, conntrack |
| Персистентность | реестр/задачи/службы/WMI | systemd/cron/authorized_keys/LD_PRELOAD |
| Блок процесса | TerminateProcess, NtSuspendProcess | SIGKILL/SIGSTOP |
| Блок сети процесса | WFP callout | nft cgroup + eBPF skb; fallback 5-tuple |
| Карантин | move+ACL+AES-GCM, `MoveFileEx` | rename+chmod+immutable+AES-GCM |
| Целостность | Authenticode, ELAM | GPG, fs-verity, IMA |

## 8. Жизненный цикл события (по trace_id)

```
ядро → чтение (ts_ingest) → парсинг → нормализация (Event v3.0)
  → приоритетная очередь → детекторы (rule/ML) → Verdict
  → политика → Action → подтверждение (если нужно) → исполнение
  → аудит + DEVLOG + (опционально) телеметрия наружу
```

Каждый хоп логируется меткой времени; MTTD меряется по хопам, а не одним числом (fast/slow — §метрики).

## 9. Точки расширения

- Плагин-интерфейс детекторов и реакций (динамическая загрузка по манифесту).
- Реестр моделей: shadow/canary-деплой, версии, подпись.
- Интеллект-коннекторы: hash reputation, Sigma-фиды, IoC.
- OTel-совместимая телеметрия; версионируемые схемы + capability negotiation.
- Конфиг-миграции и API-версионирование без breaking.

## 10. Бюджеты ресурсов

| Компонент | RAM | CPU (idle/пик) | Диск |
|---|---|---|---|
| core + IPC | 120 МБ | 0,5% / 3% | 50 МБ |
| telemetry | 200 МБ | 1% / 8% | 200 МБ |
| rules_engine | 150 МБ | 0,5% / 5% | 10 МБ |
| file_detector (+parser) | 400 МБ | 0,2% / 15% | 50 МБ |
| behavior_detector | 250 МБ | 0,5% / 10% | 50 МБ |
| response | 80 МБ | 0,1% / 2% | 20 МБ |
| self_telemetry/watchdog | 100 МБ | 0,3% / 2% | 100 МБ |
| diagnostics | 100 МБ | 0,2% / 2% | 500 МБ |
| llm (опц.) | 1 500 МБ | 0% / 20% | 1 ГБ |
| **Итого без LLM** | **≤ 1,4 ГБ** | **≤ 3% idle** | **≤ 2 ГБ** |

Продуктовый SLO: idle CPU ≤1% (среднее за час), пик ≤20% не дольше 30 с, рост RSS ≤1%/сутки.
