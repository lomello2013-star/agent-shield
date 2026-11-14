# `stmlctl` — проектный терминал

`stmlctl` — **allowlisted CLI**, не shell. Он умеет только операции STML и
ходит в `/v0/*`; произвольные команды ОС выполнить нельзя.

## Запуск

Без установки:

```powershell
python -m stml.cli --tokens-file C:\ProgramData\AIDefender\stml\tokens.json health
.\stmlctl.cmd --tokens-file C:\ProgramData\AIDefender\stml\tokens.json fleet list
```

С установкой entrypoint:

```powershell
pip install -e .
stmlctl health
```

## Токены

Приоритет:

1. `STML_VIEWER_TOKEN`, `STML_ADMIN_TOKEN`, `STML_APPROVER_TOKEN`;
2. `--tokens-file` / `STML_TOKENS_FILE` — JSON с ключами
   `viewer_token`, `admin_token`, `approver_token`.

Токены не печатаются и не логируются.

## Команды

```text
stmlctl health
stmlctl fleet list
stmlctl policy list
stmlctl policy apply policy.signed.json
stmlctl approvals list
stmlctl approve 12
stmlctl deny 12
stmlctl isolate <agent-id>
stmlctl isolate <agent-id> --resume
stmlctl commands <agent-id>
stmlctl rollout start <policy-id> <version> --percent 1
stmlctl rollout promote <rollout-id>
stmlctl rollout halt <rollout-id>
stmlctl rollout rollback <rollout-id>
stmlctl audit verify
```

`--json` — машинный вывод.

## Роли

| Команда | Токен |
|---|---|
| `health` | — |
| `fleet list`, `policy list`, `approvals list`, `commands` | viewer |
| `policy apply`, `isolate`, `rollout *` | admin |
| `approve`, `deny` | approver |

Admin **не может** approve; approver **не может** isolate/rollout (SoD).

## Пример с Tailscale

```powershell
$env:STML_URL = "https://desktop-jhqb492.tail7dcc3b.ts.net"
stmlctl --tokens-file C:\ProgramData\AIDefender\stml\tokens.json fleet list
```

## Коды возврата

- `0` — успех.
- `1` — ошибка API/токена/файла.

## Дальше

Тот же CLI можно вызвать из Tauri (sidecar) или обернуть в GUI command palette.
Он не зависит от браузера и не даёт shell-доступа.
