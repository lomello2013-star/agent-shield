# Модель данных и контракты v3.0

> **Статус:** нормативный контракт (спецификация, не реализация). Ссылается на v9.1 §4.
> **Назначение:** единые схемы обмена между ядром, модулями, платформенными адаптерами, TUI/CLI и циклом обучения. Все сообщения валидируются по этим схемам; расхождение = ошибка контракта, а не «best effort».

## 1. Политика версионирования

- Схемы: `schemas/v3/`. `3.x` — обратно совместимые дополнения (новые необязательные поля, новые значения в «открытых» enum-строках). `4.0` — ломающие (удаление/изменение обязательных полей, сужение типов).
- Ядро принимает `3.x`, отклоняет `4.0` с ошибкой `incompatible_schema`; модуль объявляет поддерживаемые версии в манифесте.
- `platform_data` и `source` версионируются **отдельно** от основного контракта (это расширяемый словарь с собственным schema-ключом).
- SemVer продукта и SemVer схем — независимы.

## 2. Перечисления

```python
EventCategory = Literal[
    "process.start", "process.exit", "process.access",
    "file.create", "file.write", "file.exec", "file.delete",
    "net.connect", "net.listen", "dns.query",
    "auth.success", "auth.failure", "priv.grant",
    "persistence.change", "module.load", "log.tamper",
    "registry.change", "memory.access", "defender.tamper",
    "script.execute", "config.change", "unknown"
]

Severity = Literal["info", "low", "medium", "high", "critical"]
Detector = Literal["rule", "file_model", "behavior_model", "memory_model", "net_model"]
ActionType = Literal["notify", "suspend", "resume", "block_network",
                     "unblock_network", "quarantine", "restore", "terminate"]
ActionStatus = Literal["pending", "approved", "rejected", "timeout", "executed", "failed"]
Decision = Literal["pending", "approved", "rejected", "timeout"]
ModuleStatus = Literal["ok", "degraded", "failed", "stopped"]
Platform = Literal["windows", "linux"]
Layer = Literal["kernel", "user", "script", "network", "memory"]
```

## 3. Ядро события — `Event`

```python
class Event(BaseModel):
    schema_version: Literal["3.0"]
    event_id: UUID
    trace_id: UUID
    ts_event: datetime            # время источника (момент события)
    ts_ingest: datetime           # время чтения нормализатором
    platform: Platform
    source: str                   # "win.etw.ti", "linux.ebpf", "win.amsi", ...
    layer: Layer
    category: EventCategory
    action: str                   # имя действия внутри категории
    actor: Actor | None
    object: ObjectRef | None
    user: UserRef | None
    host: HostInfo
    integrity: IntegrityInfo | None
    raw_ref: str                  # ссылка на сырое событие (JSONL+zstd)
    pii: PiiFlags
    platform_data: dict[str, Any] # расширяемый, со своим schema-ключом
    kernel_meta: KernelMeta | None
```

### Вложенные типы

```python
class Actor(BaseModel):
    pid: int
    ppid: int | None
    name: str                    # имя процесса/образа
    path: str                    # анонимизируется при выводе
    cmdline_hash: str            # хеш, не открытый текст
    cmdline_redacted: str        # ред актированная версия
    uid: str | None              # Linux uid
    sid: str | None              # Windows SID (хеш при экспорте)
    session: int | None
    container_id: str | None
    signature: str | None        # Authenticode / подпись
    sha256: str | None

class ObjectRef(BaseModel):
    type: str                    # "file" | "process" | "network" | "registry" | "module"
    path: str                    # анонимизируется
    sha256: str | None
    ip: str | None
    port: int | None
    proto: str | None

class UserRef(BaseModel):
    name: str                    # хеш при экспорте
    domain: str | None
    uid: str | None
    sid_hash: str | None

class HostInfo(BaseModel):
    host_id: str                 # стабильный анонимный id
    os: str
    version: str
    arch: str
    kernel: str | None

class IntegrityInfo(BaseModel):
    level: str                   # "low" | "medium" | "high" | "system"
    signature: str | None
    verified: bool

class PiiFlags(BaseModel):
    paths_hashed: bool = True
    cmdline_hashed: bool = True
    usernames_hashed: bool = True
    ips_hashed: bool = False     # IP нужен для корреляции, но помечается

class KernelMeta(BaseModel):
    irql: int | None             # Windows: уровень IRQL callback'а
    callback_type: str | None    # "pre" | "post"
    trust: str | None            # источник доверия в ядре
```

## 4. Вердикт и действие

```python
class Verdict(BaseModel):
    verdict_id: UUID
    trace_id: UUID
    event_id: UUID
    detector: Detector
    rule_id: str | None
    model_id: str | None
    model_version: str | None
    platform: Platform
    confidence: float            # калиброванная (isotonic/Platt), 0..1
    severity: Severity
    reason_code: str
    reason_text: str

class Action(BaseModel):
    action_id: UUID
    trace_id: UUID
    verdict_id: UUID
    type: ActionType
    target: str
    reversible: bool
    requires_confirmation: bool
    confirmation_id: UUID | None
    status: ActionStatus
    platform_effect: str         # чем выполнено (Firewall COM / nft / SIGSTOP ...)
    rollback: RollbackRef | None # как откатить, если reversible

class RollbackRef(BaseModel):
    kind: str                    # "resume" | "unblock" | "restore" | "none"
    payload: dict[str, Any]
```

## 5. Подтверждение, здоровье, манифест

```python
class Confirmation(BaseModel):
    confirmation_id: UUID
    action_id: UUID
    trace_id: UUID
    level: Literal["critical_system", "protected_dir", "normal"]
    timeout_sec: int = 30
    decision: Decision = "pending"
    decided_by: str | None
    decided_at: datetime | None

class Health(BaseModel):
    module: str
    version: str
    status: ModuleStatus
    platform: Platform | None
    ram_mb: float
    cpu_percent: float
    queue_depth: int
    last_error: str | None
    capabilities: list[str]      # активные возможности

class ModuleManifest(BaseModel):
    name: str
    version: str
    platforms: list[Platform]
    requires_capabilities: list[str]
    schemas: list[str]           # ["3.0", "3.1"]
    min_core_version: str

class PlatformCapabilities(BaseModel):
    platform: Platform
    os_version: str
    kernel: str | None
    has_etw: bool = False
    has_sysmon: bool = False
    has_wfp: bool = False
    has_auditd: bool = False
    has_ebpf: bool = False
    has_btf: bool = False
    has_bpf_lsm: bool = False
    has_fanotify: bool = False
    has_cgroup_v2: bool = False
    secure_boot: bool = False
    selinux: str | None
    apparmor: str | None
```

## 6. Контракты цикла обучения

```python
class CaseMemoryEntry(BaseModel):       # ярус 1 — память кейсов
    case_id: UUID
    created_at: datetime
    confirmed_by: Literal["rule", "analyst", "sandbox", "ensemble", "intel"]
    features: dict[str, float]          # вектор признаков
    verdict: Verdict
    context: dict[str, Any]             # анонимизированный
    platform: Platform
    signature: str | None               # подпись записи (целостность)

class ModelPack(BaseModel):             # подписанный артефакт модели
    model_id: str
    version: str
    platform: Platform
    format: str                         # "onnx" | "gguf"
    sha256: str
    dataset_hash: str
    metrics: dict[str, float]           # TPR@FPR и пр.
    limits: dict[str, Any]              # ограничения применения
    signature: str                      # Ed25519

class LearningUpdate(BaseModel):        # ярус 2 — обновление с сервера
    update_id: UUID
    version: str
    rules: list[str] | None             # новые/изменённые правила
    model_packs: list[ModelPack] | None
    qa_pairs: list[QAPair] | None       # «вопрос→ответ»
    task_solutions: list[TaskSolution] | None  # «задача→решение»
    kb_version: str | None
    signature: str

class QAPair(BaseModel):
    question: str
    answer: str
    source: str
    tags: list[str]

class TaskSolution(BaseModel):
    task: str                          # описание ситуации
    solution: str                      # ожидаемое действие + объяснение
    used_as: Literal["fewshot", "training"] = "fewshot"
```

## 7. Пример события (сжатый)

```json
{
  "schema_version": "3.0",
  "event_id": "…",
  "trace_id": "…",
  "ts_event": "2026-11-12T14:00:00.123Z",
  "ts_ingest": "2026-11-12T14:00:00.201Z",
  "platform": "windows",
  "source": "win.etw.ti",
  "layer": "kernel",
  "category": "process.access",
  "action": "open_process",
  "actor": {"pid": 512, "name": "malware.exe", "path": "%TEMP%/malware.exe", "cmdline_hash": "…"},
  "object": {"type": "process", "path": "lsass.exe"},
  "kernel_meta": {"callback_type": "post", "trust": "kernel"}
}
```

## 8. Правила эволюции и контрактные тесты

- Добавление поля: только необязательное → minor `3.(n+1)`.
- Изменение/удаление обязательного поля, сужение типа → `4.0`.
- Новое значение `EventCategory`/`Detector` — допустимо в `3.x` (обработчики обязаны игнорировать неизвестное, а не падать).
- Контрактные тесты: «старый модуль ↔ новое ядро», «новый модуль ↔ старое ядро» (должен отвергаться `incompatible_schema` при несовместимости), capability negotiation (`capability_missing`).
- `platform_data` каждого `source` имеет собственную JSON Schema, проверяется отдельно; неизвестные ключи в `platform_data` не считаются ошибкой.
