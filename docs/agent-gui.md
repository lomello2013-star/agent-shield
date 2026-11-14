# Agent GUI (local web panel) — design demo

Локальная панель агента в стиле серверного STML: статус устройства, стек защиты,
вердикты, подтверждения, карантин и связь с сервером.

## Посмотреть

```powershell
python -m http.server 18081 --bind 127.0.0.1 --directory agent/gui
```

Открыть: **http://127.0.0.1:18081/**

Сейчас это **статические демо-данные** для оценки дизайна, а не live-данные
агента.

## Что на экране

- верхняя строка: host, версия, policy, tenant, связь с сервером;
- hero: «This device is protected», пауза/скан/переход в серверную консоль;
- KPI: protection, heartbeat, verdicts 24h, pending, quarantine;
- стек защиты: minifilter, reflex rules, ML, network, self-protection;
- recent verdicts: severity, rule id, событие, действие;
- «Needs your decision»: approve/deny с деталями;
- quarantine и server link;
- footer: audit chain, latency, drops.

## Что нужно для live-версии

1. Локальный HTTP-сервер внутри агента на `127.0.0.1`, только loopback.
2. Токен/сессия (не URL hash, как в демо).
3. API:
   - `GET /api/status`, `/api/verdicts`, `/api/approvals`, `/api/quarantine`;
   - `POST /api/approvals/{id}/approve|deny`, `/api/protection/pause|resume`.
4. Обновление через SSE/WS или polling 1–2 с.
5. Подпись/упаковка — отдельный этап; для lab достаточно loopback + токен.

## Отличие от серверного GUI

- **Серверный** `/ui/` — флот, policy, rollout, approvals, audit.
- **Агентский** `/` — один хост, реальное состояние защиты и локальные решения.
- Стиль общий: тёмная SOC-тема, те же design tokens.
