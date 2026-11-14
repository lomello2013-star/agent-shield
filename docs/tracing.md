# Трассировка (S6)

- Каждый HTTP-запрос STML получает `trace_id`:
  - входящий `X-Trace-ID` (32 hex) или `traceparent` (`00-<32hex>-<16hex>-<flags>`) — переиспользуется;
  - иначе генерируется UUID4 hex.
- Ответ содержит `X-Trace-ID`; коннектор отправляет свой `X-Trace-ID` в каждом запросе.
- Покрытие: JSON-ответы (`_send`), health/metrics/slo; HTML/CEF — без заголовка (TODO).
- OTel SDK/collector не подключён: это минимальная совместимая передача id, не полный OTel.

Ограничения: нет span/экспорта, нет записи `trace_id` в audit; для production —
OpenTelemetry SDK + collector.
