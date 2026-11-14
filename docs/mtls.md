# mTLS (S2 prod slice)

## 1. Что реализовано

- Сервер: `ServerConfig.tls_cert/tls_key/tls_ca/require_client_cert`; TLS 1.2+,
  проверка клиентского сертификата (mTLS).
- Коннектор: `ServerClient`/`HttpTransport` принимают `ssl.SSLContext`
  (`--server-ca/--server-cert/--server-key`).
- Dev-сертификаты: `stml.server.tls.generate_dev_certs()` (ECC P-256, CA + server
  + client, SAN `127.0.0.1`/`localhost`).
- Тест: клиент с сертификатом → 200; без сертификата → TLS handshake error.

## 2. Запуск

```powershell
python -c "from stml.server.tls import generate_dev_certs; print(generate_dev_certs('certs'))"
python -m stml.server run --tls-cert certs/server.pem --tls-key certs/server.key --tls-ca certs/ca.pem
# connector:
python -m stml.connector run --server-url https://127.0.0.1:8080 \
  --server-ca certs/ca.pem --server-cert certs/client.pem --server-key certs/client.key ...
```

## 3. Production

- CA — корпоративный/внешний; сертификаты агентов/операторов выпускаются CA.
- Отзыв: CRL/OCSP (S15), срок ≤24 ч.
- Приватные ключи — OS keychain/TPM для GUI (Tauri), файл с ACL для dev.
- **Не использовать dev-CA в production.**

## 4. Ограничения

- Tauri-клиент пока не использует mTLS (web GUI — same-origin HTTP).
- CRL/OCSP не автоматизированы.
- HSM + quorum всё ещё не сделаны.
