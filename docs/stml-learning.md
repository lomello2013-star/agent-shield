# STML Learning Pipeline (S4 MVP)

> Реализация: `stml/learning/service.py`; API — `/v0/telemetry`, `/v0/cases`,
> `/v0/models`. DPIA — в финале (решение владельца); до неё — opt-in + PII-фильтр.

## 1. Приём телеметрии

- `POST /v0/telemetry` (admin для MVP): `{agent_id, consent, events[]}`.
- **consent=false → 403**; без явного opt-in данные не принимаются.
- PII-фильтр (`filter_event`):
  - **удаляет** `path/file/cmdline/raw/username/hostname/ip/domain/url`;
  - **хеширует** `sha256/md5/hash/file_hash/process_hash/signer` с солью;
  - рекурсивно по dict/list.
- Retention: `purge_telemetry(max_age_s)`; по умолчанию — 30 дней (политика в S4.0/DPIA).

## 2. Кейсы

- `POST /v0/cases` `{case_id, report_id, label: TP|FP, holdout, features}`.
- `case_id` уникален; `holdout=true` — не участвует в обучении, только регрессия.
- `GET /v0/cases` — список.

## 3. Модели

- `POST /v0/models` `{name, version, metrics}`:
  - подпись Ed25519 ключом `model` (Trust Service), `key_id` в записи;
  - статус `staged`.
- `POST /v0/models/<id>/regress`:
  - сравнение с **active** моделью: `tpr_at_fpr` не ниже, `fp_budget` не выше;
  - pass → `regressed`, fail → `rejected`.
- `POST /v0/models/<id>/activate` — active/previous; `POST /v0/models/rollback` — вернуть previous.
- `GET /v0/models` — список + active.

## 4. Ограничения S4 MVP

- Нет реального обучения/песочницы: реестр и регрессия — да, тренировка — внешний офлайн-скрипт.
- Нет dual-slot на агенте: активация модели — серверная запись; доставка/откат на агенте — S4.2+.
- Нет k-anonymity агрегатов; PII-фильтр — baseline.
- Телеметрия принимается admin-токеном; подпись агента для телеметрии — следующий шаг.
