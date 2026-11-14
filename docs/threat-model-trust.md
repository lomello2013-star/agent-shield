# Threat model — Trust Service (S2)

> Статус: принята делегированно (AI под human-approval); финальная подпись — приёмка.

## Активы

- Приватные ключи policy/model/driver/connector.
- Очередь human-approval и audit-цепочка.
- Подписанные policy/model-пакеты.

## STRIDE

| Угроза | Вектор | Митигация |
|---|---|---|
| Spoofing | поддельный approver/admin | отдельные токены, SoD, audit |
| Tampering | подмена policy после подписи | Ed25519 + canonical JSON + проверка `policy_pubkey` |
| Repudiation | отрицание approve | `decided_by`, audit hash-chain |
| Information disclosure | приватный ключ в БД/git | в БД только путь; ACL 0600; `secrets/` в `.gitignore` |
| DoS | нет quorum | раскатка блокируется, KS-4 без quorum |
| Elevation | Admin approve / Approver kill-switch | RBAC + тесты SoD |
| Replay | повтор policy/approval | nonce/`report_id`; approvals одноразовые |
| Key compromise | отзыв | `revoke`, SLA ≤24 ч, ротация с overlap |

## Остаточные риски

- SoftHSM-dev = файл на диске; production — HSM/quorum (не сделано).
- mTLS/CA и отзыв сертификатов — S2 prod (не сделано).
- Root-ключ offline — процедура, не код.
