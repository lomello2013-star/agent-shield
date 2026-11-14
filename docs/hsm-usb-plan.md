# HSM на USB: lab-план (не production HSM)

> EV-сертификат требует сертифицированного HSM/токена и юрлица. То, что описано
> здесь, — **offline USB для lab-ключей**, а не замена EV-токену.

## Что храним на USB

- Ed25519-ключ подписи манифеста Linux-агента (`objects.sha256`);
- ключ policy/ModelPack (если используется);
- публичные ключи и `SHA256SUMS`.

## Процедура

1. **Отдельный offline-хост**: Ubuntu LTS live USB с LUKS-persistence, Wi-Fi/BT off.
2. **Shamir 2-of-3** на LUKS-пароль:
   ```bash
   ssss-split -t 2 -n 3 -w luks
   ```
   Три конверта в разных местах; никогда два вместе.
3. **Генерация ключа только на offline-хосте**:
   ```bash
   openssl genpkey -algorithm ED25519 -out objects.key
   openssl pkey -in objects.key -pubout -out objects.pub
   chmod 600 objects.key
   sha256sum objects.key objects.pub > SHA256SUMS
   ```
4. **Подпись**:
   ```bash
   python scripts/sign_linux_manifest.py   # lab-вариант; ключ передаётся offline
   ```
   Для строгого варианта — `openssl pkeyutl -sign -rawin` по canonical manifest;
   публичный ключ копируется на хост.
5. **Перенос только подписи/публичного ключа** на втором USB; private key
   никогда не покидает offline-хост.
6. **Проверка на онлайн-хосте**:
   ```bash
   journalctl -u aidf-agent | grep 'manifest signature verified'
   ```
7. **Ротация**: ежегодно или при компрометации; старые подписи хранить для аудита.

## Ограничения

| Риск | Митигация |
|---|---|
| USB потерян | LUKS + 2-of-3 + вторая копия |
| Malware на signing host | отдельный offline-хост, без сети |
| Нет tamper resistance | принять для lab; production — сертифицированный HSM |
| Ключ в RAM | power off после церемонии |

## Когда переходить на настоящий HSM

- продажа третьим лицам / чужие ПДн;
- EV/HLK/Partner Center;
- требуется attestation/key custody.

До этого production-подпись заморожена (D-016).
