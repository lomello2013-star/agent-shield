# STML transport & scale (S5)

## 1. Event bus abstraction

`stml/server/bus.py`:

| Реализация | Статус | Назначение |
|---|---|---|
| `LocalBus` | ✅ | MVP, in-process; публикует `reports` после ingest |
| `NatsBus` | ⚠️ заглушка | включается при наличии `nats-py` и NATS-сервера; сейчас `BusUnavailable` |
| Kafka | ⏳ | по критерию ADR D16 |

`ServerConfig.event_bus = "local" | "nats"`. При `nats` и отсутствии клиента сервер
падает с явной ошибкой, а не тихо переключается.

## 2. 1000 агентов — измерение

`python scripts/stml_load.py` (in-process server, SQLite):

| Метрика | Значение |
|---|---|
| Агентов | 1000 |
| Enrolment (1000) | 9,67 с |
| Heartbeat p50 | 87,7 мс |
| Heartbeat p95 | **111,6 мс** |
| p95 < 2 с | ✅ |

Артефакт: `artifacts/stml_s5_load.json`.

## 3. Offline / durability

- Connector SQLite outbox: P0 **не вытесняется**; P1–P3 purge через 7 дней.
- Retry с backoff 1→2→4→…→300 с.
- Report idempotency по `report_id`.
- Replay: `nonce` + `sent_at` ±300 с на сервере.

## 4. Триггеры

- 800 агентов при работающем S1 → подготовка S5.
- p95 >2 с на 500 → **инцидент S1**, эскалация; не маскировать триггером S5.
- При нестабильности NATS: Kafka только если есть кластер/нужна партиционная
  модель; иначе остановка масштабирования.

## 5. Остаток

- Реальный NATS/Kafka и push (gRPC stream) — внешняя инфраструктура.
- 10k+ и multi-region — после появления нагрузки.
