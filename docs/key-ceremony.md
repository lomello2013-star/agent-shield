# Key ceremony (STML Trust Service)

> Статус: процедура для SoftHSM-dev (S2) и production-HSM (S2 prod).
> Ключи не покидают HSM; в БД — только `key_id`, публичная часть и путь.

## 1. Роли

| Роль | Кто | Обязанность |
|---|---|---|
| Ведущий | security engineer | генерация, запись, проверка |
| Свидетель | PM | подтверждает шаги и запись |
| Свидетель | владелец проекта | финальная подпись протокола |

## 2. Классы ключей

`root` → `policy` → `model` / `driver` / `connector`. Root — offline, только
подписывает промежуточные; в STML не используется для рутинных операций.

## 3. Процедура (SoftHSM-dev)

1. Выбрать `key_class`; `TrustService.create_key(class)`.
2. Записать `key_id`, публичный PEM, дату, класс в `docs/key-ceremony-record.md`.
3. Свидетели проверяют `key_id = sha256(pubkey)[:16]`.
4. Приватный файл — ACL 0600; в git не попадает.
5. Backup: `python -m stml.server backup --db ... --trust-dir ... --out ...`.
6. Протокол подписывается свидетелями (пока — отметка в DEVLOG).

## 4. Production (HSM)

- Quorum: **2 из 3** (рекомендация) или 2 из 2 (риск).
- Backend `hsm` (PKCS#11) реализуется отдельным адаптером; в S2-dev `TrustService`
  возвращает `TrustError`, пока HSM не настроен.
- Root — offline; policy/model/driver — в HSM; публичные части — в БД.
- При недоступности quorum раскатка блокируется; **KS-4 (freeze fleet) доступен
  без quorum** (это отключение, не подпись).

## 5. Ротация и отзыв

- Ротация: `POST /v0/trust/keys/<id>/rotate` → новый ключ `rotated_from=<old>`;
  старый остаётся для проверки старых подписей (overlap).
- Отзыв: `POST /v0/trust/keys/<id>/revoke`; после — `sign` запрещён, `verify`
  возвращает false.
- SLA отзыва: ≤24 ч (S15); запись в audit.
