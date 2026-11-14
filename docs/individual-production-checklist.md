# STML для физлица: практический чек-лист

> Цель: **self-hosted pilot / personal production**, без организации, без
> коммерческих EDR-лицензий и без code-signing сертификата.
> Это не «сертифицированный production»: независимый аудит, юридическая подпись
> и vendor-сертификация остаются недоступны.

## 0. Что покупаем / ставим

| Компонент | Вариант | Ориентир по цене |
|---|---|---|
| HSM | **air-gapped encrypted USB** (см. [offline-usb-key-ceremony.md](offline-usb-key-ceremony.md)) | ~$0–20 |
| HSM (позже) | Nitrokey HSM 2 / YubiHSM 2 — опционально | от ~€110 |
| Ключи-доли | 3 paper shares + 2 USB copies | $0 |
| Доступ | Tailscale (private) + Caddy/Let's Encrypt | free–$10/год |
| Backup | Backblaze B2 + restic | ~$6/TB/мес |
| EDR-стенд | Defender + Sysmon + Wazuh | free |
| Wazuh manager | Hyper-V Ubuntu VM 4 GB | free |
| Security | Semgrep/Bandit/Trivy/ZAP/Nuclei | free |

---

## 1. Неделя 1 — HSM-замена: air-gapped USB

> YubiHSM 2 не обязателен. Для личного пилота делаем **offline USB + LUKS +
> 2-of-3 shares**. Это не HSM, но ключ не лежит на онлайн-хосте.
> Полная процедура: [offline-usb-key-ceremony.md](offline-usb-key-ceremony.md).

### 1.1 Подготовка

- Ubuntu LTS live USB с LUKS persistence.
- `sudo apt install -y ssss openssl`.
- `ssss-split -t 2 -n 3 -w luks` → три конверта.
- Выключить Wi-Fi/Bluetooth; подписывать только офлайн.

### 1.2 Ключ

```bash
openssl genpkey -algorithm ED25519 -out policy.key
openssl pkey -in policy.key -pubout -out policy.pub
chmod 600 policy.key
```

`policy.key` — только на зашифрованном USB; `policy.pub` копируется на сервер.

### 1.3 Подпись policy

```bash
./scripts/stml_offline_sign.sh policy.json policy.key policy.pub policy.signed.json
```

Скрипт делает canonical JSON, `openssl pkeyutl -sign -rawin`, проверяет подпись,
считает `key_id` и пишет base64 в JSON.

### 1.4 Проверка

- `policy.signed.json` проверяется сервером (`policy_pubkey` = `policy.pub`).
- Неверная подпись → 403.
- Ключ никогда не попадает на онлайн-ОС.

### 1.5 Ограничения

- Это **не HSM**: нет tamper resistance/attestation.
- Защита: LUKS + 2-of-3 + офлайн + второй USB в другом месте.
- При продаже/чужих ПДн — переходить на Nitrokey HSM 2/YubiHSM/cloud KMS.

---

## 2. Неделя 2 — web GUI без Tauri

Tauri не обязателен: используй существующий `/ui/`.

### Вариант A — Tailscale (рекомендую)

```powershell
winget install Tailscale.Tailscale
tailscale up
tailscale serve --bg 8080
tailscale status
```

Доступ: `https://<machine>.<tailnet>.ts.net/` — TLS от Tailscale, наружу порт
не открывается.

### Вариант B — Caddy + домен

```powershell
winget install CaddyServer.Caddy
# Caddyfile:
# stml.example.com { reverse_proxy 127.0.0.1:8080 }
caddy run --config Caddyfile
```

Let's Encrypt выдаст сертификат автоматически; нужен домен и 80/443.

### Проверка

- `/ui/` 200.
- В Settings введён viewer token; `/v0/agents` 200.
- Старый token после ротации → 401.

---

## 3. Неделя 3 — backup + PITR

### 3.1 Backblaze B2

1. Создай bucket `stml-backup` (private).
2. Application key с доступом только к bucket.
3. Установи `rclone` и `restic`.

```powershell
winget install Rclone.Rclone
winget install restic.restic

rclone config create b2 b2 account <keyID> key <appKey>
restic init --repo rclone:b2:stml-backup
```

### 3.2 Ежедневный backup

```powershell
$stamp = Get-Date -Format yyyyMMdd-HHmmss
pg_dump -h 127.0.0.1 -U stml -Fc -f "$env:TEMP\stml-$stamp.dump" stml_p4
restic backup --repo rclone:b2:stml-backup `
  "$env:TEMP\stml-$stamp.dump" `
  "C:\ProgramData\AIDefender\stml\server.sqlite3" `
  "C:\ProgramData\AIDefender\stml\trust"
restic forget --repo rclone:b2:stml-backup --keep-daily 7 --keep-weekly 4 --prune
```

- `restic` шифрует backup; B2 видит только шифротекст.
- Токены/ключи не клади в plaintext backup.

### 3.3 PITR (опционально)

Для PITR нужен WAL-archiving (`pgBackRest`/WAL-G) в B2. Это отдельная настройка;
для личного пилота достаточно ежедневного dump + weekly restore drill.

### 3.4 Проверка restore

```powershell
# создать пустую БД stml_restore (роль stml не имеет CREATEDB)
.\scripts\stml_pg_restore.ps1 -File <dump> -Database stml_restore -Password <pw>
psql -d stml_restore -c "select count(*) from agents;"
```

---

## 4. Неделя 4 — Defender + Sysmon + Wazuh

### 4.1 Wazuh manager в Hyper-V

- Ubuntu 22.04 VM, 4 GB RAM, 2 vCPU.
- Установка all-in-one:
  ```bash
  curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
  sudo bash wazuh-install.sh -a
  ```
- Сохрани admin password; dashboard в private network.

### 4.2 Windows agent

```powershell
msiexec /i wazuh-agent-4.x.msi /qn `
  WAZUH_MANAGER="<wazuh-ip>" WAZUH_AGENT_NAME="stml-host"
Start-Service WazuhSvc
```

### 4.3 Sysmon

```powershell
Sysmon64.exe -accepteula -i sysmonconfig.xml
```

### 4.4 Матрица совместимости

| Сценарий | Ожидание |
|---|---|
| Defender only | STML работает |
| Defender + Sysmon | события идут, нет конфликта |
| Defender + Wazuh | Wazuh видит события |
| Все три | STML не ломает защиту, нет BSOD/потери событий |

Это lab-матрица, не vendor-сертификация.

---

## 5. Неделя 5 — security + legal

### 5.1 SAST/DAST/fuzz

```powershell
pip install semgrep bandit
semgrep --config auto stml core scripts
bandit -r stml core scripts
python scripts\stml_pentest.py
python scripts\stml_sast.py
```

- `pickle.loads` в `core/ipc.py` — известный finding; вход только named pipe с
  authkey, не сеть. Зафиксируй accepted risk.
- Для web: OWASP ZAP baseline, Nuclei по localhost.

### 5.2 DPIA/legal

- Если обрабатываешь **только свои** данные — напиши self-assessment:
  какие данные, зачем, сроки, кто имеет доступ.
- Если чужие ПДн (сотрудники/клиенты) — нужен юрист/DPO; это не обойти.
- `docs/dpia-draft.md` — стартовая техническая версия.

### 5.3 Acceptance

- Ты — owner/acceptance authority.
- Второй человек (друг/коллега) — peer review, не аффилированный с кодом.
- Подпиши `docs/individual-acceptance.md` (создай по шаблону ниже).

---

## 6. Неделя 6 — пилот

1. Включи 24h soak; дождись 0 рестартов/0 падений.
2. Прогони parity CI:
   ```powershell
   python scripts\stml_parity_ci.py ...
   ```
3. Прогони restore drill.
4. Проверь GUI token и `/ui/`.
5. Зафиксируй known risks и подпиши acceptance.

---

## 7. Что останется недоступным

| Пункт | Почему |
|---|---|
| Настоящий 2-of-3 threshold HSM | YubiHSM не умеет; нужен MPC/HSM cluster |
| Vendor EDR-сертификация | нет лицензий/вендора |
| Independent pen-test | нужен независимый человек/компания |
| Юридическая DPIA | подпись юриста/DPO |
| Code-signing certificate | для личного web GUI не нужен; для Tauri — внешний cert |
| HA | нет второго узла |

## 8. Итоговый статус, который честно писать

> **Self-hosted pilot / personal production.**  
> Контроли: HSM-backed policy key, 2-of-3 custodians, TLS, encrypted offsite
> backup, Defender/Sysmon/Wazuh, SAST/DAST/fuzz, owner acceptance.  
> Не является сертифицированным commercial production; independent audit,
> vendor EDR certification и legal DPIA отсутствуют.
