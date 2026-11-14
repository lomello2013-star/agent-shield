# STML demo UI (visual review)

Локальный демо-сервер с заполненным флотом — чтобы посмотреть дизайн без реального пилота.

```powershell
python scripts/stml_demo.py
```

Открыть:

```text
http://127.0.0.1:18080/ui/#viewer=demo-viewer&admin=demo-admin&approver=demo-approver
```

## Что внутри

- 5 агентов: healthy / degraded / offline / tamper;
- 3 версии policy (stable, canary);
- 2 pending approval;
- dashboard, fleet, policies, approvals, reports, incidents, modules, ops, audit, settings;
- правая панель агента (drawer), isolate/resume, approve/deny.

## Важно

- Это **демо**: токены в URL hash только для локального просмотра, в прод так нельзя.
- `stml/gui/index.html` — рабочий web-GUI; Tauri-обёртки нет.
- Демо-БД пересоздаётся в `artifacts/demo/stml-demo.sqlite3`.
- Сервер слушает только `127.0.0.1:18080`.
