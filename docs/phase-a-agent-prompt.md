# Phase A — промпт для ИИ-агента (copy-paste)

> Вставь этот текст в нового агента вместе с доступом к репозиторию
> `D:\ИИ защитник Вектор-защитник`. Не давай production-ключей/секретов.

---

## Роль и задача

Ты — инженер интеграции STML ↔ агент «ИИ-защитник». Выполни **только Phase A**
(пилот, read-only) из `docs/agent-stml-compatibility.md`. Не реализуй Phase B/C/D
и не меняй логику детектора.

## Сначала прочитай

1. `docs/agent-stml-compatibility.md` — разрывы G1–G13.
2. `docs/stml-dev-plan.md`, `docs/agent-stml-compatibility.md`.
3. `Дорожная_карта_ИИ-защитник_v9.1.md` §4, §8, §10.2, §10.6.
4. `DEVLOG.md` — последние 10 записей (F11/R1/R4 **не закрыты**).
5. `core/ipc.py`, `core/daemon.py` (`stats`, `health`), `scripts/aidf_service.py`,
   `stml/connector/{agent_client,service,__main__}.py`.

## Ограничения

- Не трогай `core/` кроме `core/daemon.py::stats` (только блок `platform`).
- Не меняй `core/policy.py`, `rules/`, детекторы, response, F11-код.
- Не коммить секреты; токены/ключи — только в `%ProgramData%\AIDefender` с ACL.
- Не заявляй production; Phase A — read-only пилот.
- Бюджет/сроки не фиксируй; работай по факту.

## Изменения

### 1. `scripts/aidf_service.py`

- Добавь `_restrict(path)` (icacls текущему пользователю).
- Добавь `_shared_secret(env_name, file_env, default_name, token=False)`:
  env → файл → сгенерировать; всегда сохранить в файл с ACL.
- Замени блок IPC:
  - `AIDF_ENABLE_IPC` (default `1`; `0` — выключить).
  - `AIDF_ADMIN_TOKEN` / `AIDF_ADMIN_TOKEN_FILE` → `DATA_ROOT/admin.token`.
  - `AIDF_OPERATOR_TOKEN` / `AIDF_OPERATOR_TOKEN_FILE` → `DATA_ROOT/operator.token`.
  - `AIDF_AUTHKEY` / `AIDF_AUTHKEY_FILE` → `DATA_ROOT/authkey.hex` (hex).
  - tokens: `{admin: "admin", operator: "operator"}`.
- Не логируй секреты.

### 2. `core/daemon.py::stats`

Добавь только:
```python
"platform": {
    "os": self.host.os, "arch": self.host.arch, "version": self.host.version,
    "kernel": self.host.kernel,
    "capabilities": ["ipc", "rules", "response", "selfprotect", "audit", "confirm"],
},
```
Остальной `stats` не меняй.

### 3. `stml/connector/service.py`

- `inventory()`: читать `stats["platform"]`, fallback на top-level.
- `_status_from_health()`: `safe_mode` — dict; проверять `safe_mode["safe_mode"]`,
  не truthiness. `status="ok"` → healthy; `status="safe"` → degraded/safe_mode.
- Не менять outbox/flush.

### 4. `stml/connector/__main__.py`

- `--authkey-file`, `--token-file`; fallback env `AIDF_AUTHKEY_FILE` /
  `AIDF_OPERATOR_TOKEN_FILE`.
- Токен: `--token` → `--token-file` → env; не использовать admin по умолчанию.

### 5. Sidecar

- `scripts/run_stml_connector.cmd` — уже есть; проверь.
- `scripts/install_stml_connector_task.ps1` — scheduled task SYSTEM; проверь.
- `deploy/systemd/stml-connector.service` — Linux unit.

### 6. Тесты и smoke

- Добавь/обнови `stml/tests/test_service.py`:
  - platform block → inventory os/arch/version/capabilities;
  - `safe_mode` dict false → healthy, true → safe_mode.
- `scripts/stml_phase_a_smoke.py` — реальный `core.daemon.Daemon` → RpcServer →
  AgentClient → Connector; должен печатать `ok: true`.
- Запусти:
```powershell
python -m pytest stml/tests tests/test_ipc.py -q
python scripts\stml_phase_a_smoke.py
```
- Ожидаемо: все тесты зелёные; smoke `health_status=healthy`, os не `unknown`.

## Критерий готовности Phase A

- [ ] `AIDF_AUTHKEY_FILE`/токены создаются и читаются коннектором.
- [ ] `daemon.stats()["platform"]` есть; inventory не `unknown`.
- [ ] `safe_mode` dict корректно маппится.
- [ ] sidecar-скрипт запускает коннектор.
- [ ] tests + smoke зелёные.
- [ ] Отчёт: что изменено, что проверено, что осталось (Phase B).

## Не делать

- Не реализовывать policy apply/command/confirm bridge (Phase B).
- Не менять `LearningUpdate`/`ModelPack` (Phase C).
- Не трогать F11/soak/детекторы.
- Не выдавать Phase A за production.

---

## Ответ агента (формат)

1. Список изменённых файлов.
2. Команды и результаты тестов/smoke.
3. Остаточные риски/блокеры.
4. Явно: `Phase A: done|blocked`.
