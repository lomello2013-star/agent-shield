# Отзыв клиентских сертификатов (CRL-lite)

## Реализация

- `Store.revoke_cert(serial, reason)` → таблица `revoked_certs`; нормализация serial
  (hex, upper, без `:`/пробелов).
- При TLS-запросе сервер читает `getpeercert()["serialNumber"]`; если serial
  отозван — `403 client certificate revoked` (TLS handshake уже прошёл).
- API:
  - `POST /v0/tls/revoke` (admin) `{serial, reason}`;
  - `GET /v0/tls/revoked` (admin).
- Audit: `cert_revoke`.

## Проверка

`stml/tests/test_tls.py`: client cert → 200; revoke → тот же cert → 403;
без client cert → TLS handshake error.

## Ограничения

- Это **не полноценный CRL/OCSP**: нет подписанного CRL, нет OCSP responder,
  нет проверки на стороне клиента. Отзыв действует только на этом сервере.
- Production: внешний CA + CRL/OCSP (S15), SLA ≤24 ч.
- Serial хранится как hex-строка; при смене CA — пересоздать список.
