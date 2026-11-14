# STML deployment (S7)

## 1. Docker Compose (малый парк)

```powershell
$env:STML_ADMIN_TOKEN="..."
$env:STML_VIEWER_TOKEN="..."
$env:STML_APPROVER_TOKEN="..."
docker compose -f deploy/docker-compose.yml up -d --build
# UI: http://127.0.0.1:8080/ui/  health: /health
```

- Образ: `deploy/Dockerfile` (python:3.12-slim, `stml/`, pydantic+cryptography).
- Данные: volume `stml-data` → `/data` (SQLite + trust).
- `restart: unless-stopped`; healthcheck `/health`.
- **Статус:** Dockerfile/compose созданы; на этой машине Docker daemon не запущен,
  сборка не проверена. Это внешний gate.

## 2. K8s / Helm (средний/большой)

```bash
helm install stml deploy/helm/stml \
  --set env.STML_ADMIN_TOKEN=... \
  --set env.STML_VIEWER_TOKEN=... \
  --set env.STML_APPROVER_TOKEN=...
```

- `replicaCount: 2`; PVC `ReadWriteOnce` (SQLite — один writer; для HA нужен
  PostgreSQL-адаптер, S1.5).
- readiness/liveness `/health`.
- **Статус:** chart создан; `helm`/кластер недоступны — lint/install не проверены.

## 3. systemd (локальный сервер)

`deploy/systemd/stml.service`: пользователь `stml`, `/opt/stml`, `/var/lib/stml`,
`ProtectSystem=strict`, `NoNewPrivileges`.

## 4. Air-gapped

1. Собрать образ/пакет на подключённом хосте; подписать Ed25519.
2. Перенести на USB; журнал: кто/когда/пакет/хеш.
3. Проверить подпись и **anti-rollback** (версия ≥ текущей).
4. Dual-slot обновление; health-check; при провале — last-known-good.
5. План B: restore из backup (RTO ≤1 ч обычный; полный DR ≤4 ч, ceremony отдельно).
6. Watchdog: локальный независимый пробер (другая ВМ) + ручной чек-лист оператора.

## 5. DR-тест

| Стенд | Тест | RTO |
|---|---|---|
| Compose | backup → restore (SQLite+trust) | ≤1 ч |
| K8s | полный DR (кластер+HSM) | ≤4 ч |

Уже проверено: `python -m stml.server backup|restore` + тест
`stml/tests/test_backup.py`. Полный K8s DR — после появления кластера.

## 6. Ограничения S7

- Docker/Helm не запускались на этом хосте.
- SQLite не HA; для `replicaCount>1` нужен PostgreSQL (S1.5).
- Air-gapped обновление STML — процедура описана, не автоматизирована.
