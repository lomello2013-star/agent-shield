# Совместимость агента и STML: аудит и план правок

> Дата: 2026-11-14. Изучены: `Дорожная_карта_ИИ-защитник_v9.1.md`,
> `DEVLOG.md` (последние записи), `core/ipc.py`, `core/daemon.py`,
> `core/policy.py`, `core/modelpack.py`, `core/model_registry.py`,
> `core/updater.py`, `core/selfprotect.py`, `core/negotiation.py`,
> `scripts/aidf_service.py`, `schemas/v3/` (ModelPack, LearningUpdate,
> CaseMemoryEntry), `docs/learning-loop.md`.

## 1. Вердикт

- **Транспортно** агент и STML совместимы: `core/ipc.py` даёт 10 RPC, pickle,
  authkey, роли; коннектор STML уже умеет читать `health/stats` и `*.jsonl`.
- **Флотски** агент **не готов**: нет policy/command-канала, контракта
  inventory/version, доставки `LearningUpdate`, бриджа confirm; authkey/token
  не провижены для sidecar.
- **Пилот** возможен после Phase A (без изменения поведения детектора).
- **Production** — после Phase B (control plane) + Phase C (learning) + Phase D
  (надёжность/поставка); плюс внешние HSM/Postgres/Tauri/EDR/юрист.

## 2. Что уже совместимо

| Возможность | Агент | STML | Статус |
|---|---|---|---|
| Локальный RPC | JSON-RPC/pickle, named pipe/AF_UNIX, authkey, роли | `AgentClient` | ✅ |
| health | `daemon.health()`: `ok/degraded/safe`, sources, counters | `Heartbeat` | ✅ (маппинг `ok→healthy`) |
| stats | вложенный `pipeline/gate/audit/response/collectors` | `Inventory` | ⚠️ нет platform-полей |
| immutable policy | `verify_immutable()` | `Inventory.immutable_ok` | ✅ |
| audit/spool/quarantine | `audit/chain.jsonl`, `spool/events.jsonl`, `quarantine.jsonl` | fallback tailer | ✅ |
| reconnect/offline | SQLite spool | SQLite outbox | ✅ |
| confirmations | `confirmations`/`confirm` | `Approvals` (отдельно) | ⚠️ нет бриджа |
| dual-slot updater | `core/updater.py` stage/activate/rollback | policy/model rollout | ⚠️ не связано |
| signed ModelPack | Ed25519 hex, `schemas.v3.ModelPack` | Ed25519 PEM, своя модель | ❌ формат/схема |
| learning update | `schemas.v3.LearningUpdate` | нет доставки | ❌ |
| case memory | `CaseMemoryEntry` | своя `cases` | ❌ схема |

## 3. Разрывы (критичные → средние)

| # | Разрыв | Сейчас | Нужно | Severity |
|---|---|---|---|---|
| G1 | **authkey/token провижн** | `aidf_service` генерирует random authkey, если нет `AIDF_AUTHKEY`; IPC включается только при `AIDF_ADMIN_TOKEN`; коннектор тоже генерирует свой random | общий authkey (файл/DPAPI) + operator token, ACL; коннектор читает тот же файл | **critical** |
| G2 | **Inventory/version** | `stats` не содержит `os/arch/version/capabilities` | `stats.platform` или read-only `inventory` RPC | high |
| G3 | **Policy state/apply** | нет чтения версии policy и применения; `safemode`/`rules` локальны | `policy_state` + `apply_policy` (signed, dry-run, rollback) | **critical** |
| G4 | **Command/isolate** | STML isolate — только серверный флаг; агент не знает | `command_poll/ack` или policy-флаг; KS-1..KS-5 | high |
| G5 | **Confirm bridge** | STML approval не вызывает `confirm`; destructive action | approval → `confirm` (operator token), audit | high |
| G6 | **ModelPack формат** | агент: hex-ключ, поля `model_id/version/platform/format/sha256/dataset_hash/metrics/limits`; STML: name/version/metrics/PEM | единый `ModelPack` + PEM↔hex конверт | **critical** |
| G7 | **LearningUpdate** | агент умеет реестр/верификацию, но нет доставки | pull `LearningUpdate`, verify signature, apply rules/packs/Q&A | **critical** |
| G8 | **CaseMemoryEntry** | STML `cases`: case_id/report_id/label/features; схема требует `created_at/confirmed_by/verdict/platform` | маппинг/валидация по v3 | high |
| G9 | **Telemetry** | агент не отправляет opt-in телеметрию; STML принимает admin-токеном | redaction на агенте/коннекторе, consent, signed upload | high |
| G10 | **Capability negotiation** | `core/negotiation.py` есть, но не вызывается | `capabilities` в inventory; проверка `3.x` | medium |
| G11 | **Update delivery** | STML rollout не передаёт payload в `DualSlot` | pull package, verify, stage/activate/rollback | high |
| G12 | **Sidecar install** | сервис только агент; коннектор — отдельный процесс | Windows service/systemd unit для коннектора | medium |
| G13 | **Audit anchor** | `HashChainLog` + anchor; STML свой audit | read-only tail + anchor export; не смешивать | medium |

## 4. План правок по фазам

### Phase A — Пилот без изменения детектора (сначала)

Цель: STML видит реальный агент, read-only, без управления.

1. **Провижн ключей/токенов**
   - `scripts/aidf_service.py`: `AIDF_AUTHKEY_FILE` (hex, ACL) + `AIDF_OPERATOR_TOKEN`; писать/читать файл, не random.
   - STML connector: читать тот же `AIDF_AUTHKEY_FILE`; token operator, не admin.
2. **Platform-инвентарь**
   - `core/daemon.py::stats`: добавить `"platform": {"os","arch","version","capabilities"}`.
   - `core/ipc.py`: read-only `inventory` (viewer) — опционально; достаточно `stats`.
3. **Data root**
   - коннектору явно передавать `DATA_ROOT` агента; fallback `spool/events.jsonl` и `audit/chain.jsonl`.
4. **Sidecar**
   - unit/скрипт запуска коннектора; lock/ACL; конфиг.
5. **Тесты**: контракт `inventory` из `stats`; authkey file; реальный агент → `heartbeat healthy`, `inventory os/arch/version`.
- **Выход:** пилотный scope работает; детектор не изменён.

### Phase B — Control plane (policy/command)

1. `core/ipc.py`: read-only `policy_state` (viewer); `apply_policy` (operator, signed, dry-run); `command_poll`/`command_ack` (operator).
2. `core/daemon.py`/`safemode`/`rules`: применение policy с проверкой подписи, dry-run, откат; policy version.
3. STML: command queue + policy delivery endpoint; `isolate` → command; approval → `confirm`.
4. Тесты: signed policy apply, wrong signature reject, dry-run no side effects, isolate/resume.
- **Выход:** STML управляет агентом, а не только читает.

**Статус (2026-11-14): agent-side готов, server-side нет.**

- Сделано: `policy_state`, `apply_policy` (Ed25519, `key_id`, dry-run, LKG), `command_poll`,
  `command_ack`, `command_enqueue` (admin), isolate на ack, файловая очередь.
- Сервер/коннектор: `isolate` ставит команду в SQLite; heartbeats возвращают
  `commands`; коннектор выполняет и подписанно ack-ает `/v0/commands/ack`.
- Тест: `tests/test_policy_commands.py` — dry-run не меняет state, wrong signature reject,
  viewer forbidden, isolate command.
- Тест: `stml/tests/test_server_http.py::test_command_delivery_and_ack` — isolate →
  command → signed ack → очередь пуста.
- Остаток: Rust parity для commands, policy live reload, approval → `confirm`.

### Phase C — Learning/ModelPack/LearningUpdate

1. `core/modelpack.py` + `schemas.v3.ModelPack`: поддержка PEM↔hex, поля STML; единый canonical.
2. STML `models` API: генерировать `ModelPack` (artifact, platform, dataset_hash, limits), подпись.
3. `LearningUpdate`: pull endpoint, verify signature, apply rules/model packs/Q&A; replay/regression.
4. `CaseMemoryEntry`: STML cases → v3 схема (`confirmed_by`, `verdict`, `platform`).
5. Тесты: pack verify, wrong key, LearningUpdate apply/rollback, case schema.
- **Выход:** флотское обучение действительно доставляет подписанные обновления.

### Phase D — Надёжность/поставка

1. F11/R1/R4: закрыть 24-часовой soak; не считать закрытым по 6-часовому плечу.
2. `core/updater.py` + STML rollout: package fetch/verify/stage/activate/rollback.
3. Self-protect/audit: anchor export, tamper → incident; STML audit read-only.
4. mTLS уже на STML; коннектор — client cert.
5. Тесты: kill/restore, tamper, upgrade/rollback, 24h soak.

### Phase E — Агент Rust/стек

- v9.1 D2: Rust daemon target; текущий агент Python. **Не портировать STML и агент одновременно.**
- Решение: оставить `stml/v0` стабильным; агент может быть Python (v9-min) или Rust позже, коннектор скрывает разницу.
- Если агент переезжает на Rust — менять только `AgentClient`/`afl` adapter, не STML API.

## 5. Что менять в STML

| Область | Изменение |
|---|---|
| Connector | `AIDF_AUTHKEY_FILE`, operator token, `DATA_ROOT`, `policy_state`, `command_poll`, `confirm` bridge |
| Server | command queue, policy delivery, LearningUpdate endpoint, ModelPack schema |
| Learning | v3 `ModelPack`/`CaseMemoryEntry`/`LearningUpdate` |
| GUI | показывать policy version/commands/update status |
| Deploy | sidecar service + mTLS client cert |

## 6. Что важно из DEVLOG/дорожной карты

- **F11/R1/R4 не закрыты**: 6-часовое плечо на 3.12.9 без падений, 24-часовой прогон ещё
  не завершён; `run_all` 29/29, 472 теста (на 14:20). Не считать надёжность доказанной.
- **v9-min**: user-mode, драйвер/ELAM не подписаны; `DRIVER_SIGNED_BY_HUMAN=True`
  остаётся immutable, но фактической подписи нет.
- **D10**: JSON-RPC named pipe/AF_UNIX — совпадает.
- **D11**: dual-slot/канарейка/откат — есть в `updater.py`, не связано с STML.
- **D12**: телеметрия opt-in/анонимная — STML уже требует consent, но агент не отправляет.
- **D2**: Rust — целевой, но текущий агент Python; не смешивать с Rust/axum STML.
- **Learning loop**: ярусы 0/1/2; `MODELS_TRAIN_ON_DEVICE=False`; STML сейчас не доставляет
  `LearningUpdate`.

## 7. Решения, которые нужны до Phase B

| # | Вопрос | Варианты | Рекомендация |
|---|---|---|---|
| A1 | authkey | env / файл ACL / DPAPI | файл ACL + DPAPI в prod |
| A2 | policy apply | `safemode` / `rules` / новый канал | `safemode` + signed policy |
| A3 | isolate | серверный флаг / команда агенту | команда + ack |
| A4 | LearningUpdate | pull / push | pull |
| A5 | агент Rust | сейчас / позже | позже; стабильный `stml/v0` |

## 8. Ближайшие шаги (Phase A)

1. `aidf_service`: authkey file + operator token.
2. `daemon.stats`: platform block.
3. STML connector: authkey file/operator token/data_root.
4. Sidecar unit + smoke на реальном агенте.
5. Записать результат в `docs/agent-stml-compatibility.md` и `artifacts/agent-stml-compatibility.json`.

**Пилот не начинать, пока Phase A не зелёная.** Production — после B+C+D.

## 9. Phase A — статус (2026-11-14)

**done-readonly.**

- `scripts/aidf_service.py`: `AIDF_AUTHKEY_FILE`, `admin.token`, `operator.token`,
  ACL; IPC включён по умолчанию (`AIDF_ENABLE_IPC=0` — выключить).
- `core/daemon.py::stats`: добавлен `platform` (`os/arch/version/kernel/capabilities`).
- `stml/connector/service.py`: platform-маппинг; исправлен `safe_mode` (dict, не
  truthiness); `status="ok"` → healthy.
- `stml/connector/__main__.py`: `--authkey-file`, `--token-file`.
- Sidecar: `scripts/run_stml_connector.cmd`,
  `scripts/install_stml_connector_task.ps1`,
  `deploy/systemd/stml-connector.service`.
- Smoke: `scripts/stml_phase_a_smoke.py` → `ok:true`, healthy/rpc, os/arch/version,
  capabilities, immutable_ok. Артефакт: `artifacts/stml_phase_a.json`.
- Тесты: 54 STML + 16 IPC + 13 daemon_wiring.

**Остаток:** реальный запуск службы на этом хосте (нужен admin/SCM) и запись
результата оператором. Phase B (policy/command) не начата.

### 9a. Проверка операторской установки (2026-11-14, выполнена)

- `AIDefender` — Running; named pipe `\\.\pipe\aidf` есть.
- `AIDefender-STML-Server` — Running; `/health` 200, `/ui/` 200.
- `AIDefender-STML-Connector` — Running; последний heartbeat `healthy`,
  `last_error` пуст.
- Агент в `/v0/agents`: `DESKTOP-JHQB492`, `windows/AMD64`, `10.0.19045`,
  `healthy`, `last_seen` свежий.
- Найдено и исправлено: `server.boot.log` содержал plaintext-токены (удалён,
  токены перевыпущены); дубли серверных процессов; stale-сокет коннектора после
  рестарта сервера (перезапуск задачи); `agent_version` был `10` (рестарт службы
  → `10.0.19045`).
- Остаток: `server.run.log`/`connector.log` не должны содержать секретов;
  `tokens.json` — ACL; production: DPAPI/secret store.

