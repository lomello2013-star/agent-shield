# STML для одного человека: полная инструкция

> Это **personal pilot**, не коммерческий production.  
> Цель: STML видит агента, оператор управляет политиками, ключ подписи
> хранится офлайн, без Tails Persistent Storage.

---

## 1. Что где лежит

| Компонент | Где | Зачем |
|---|---|---|
| Python STML server | `127.0.0.1:8080` | API + GUI + approvals + rollouts |
| Rust STML server | `127.0.0.1:8090` | второй сервер/parity, не обязателен |
| Tailscale | `http://desktop-jhqb492.tail7dcc3b.ts.net/` | приватный доступ к GUI |
| PostgreSQL | локальная служба | БД Rust/RLS |
| AIDefender | служба Windows | агент |
| Connector | задача Windows | агент ↔ STML |
| **64-GB Tails USB** | офлайн | Tails + LUKS-раздел `STMLKEY` + приватный ключ |
| **4-GB USB** | transfer | `STML-SIGN.sh`, `policy.json`, `policy.pub`, подпись |
| `STML-LUKS-PASSWORD.txt` | рабочий стол Windows | пароль LUKS, **удалить после переноса** |
| `STML-policy.pub` | рабочий стол + `C:\ProgramData\AIDefender\stml` | публичный ключ для сервера |
| `stmlctl` | `python -m stml.cli` | проектный терминал |

### Почему две флэшки

- **64-GB** — ключ. Её нельзя монтировать на онлайн-ОС; только Tails офлайн.
- **4-GB** — transfer. Приватного ключа там нет, только публичные артефакты.
- Если 4-GB была онлайн — скрипт `STML-SIGN.sh` мог быть подменён. Проверяй
  его hash или держи отдельную копию.

---

## 2. Сначала — сохранить пароль и удалить plaintext

1. Открой `C:\Users\lomel\OneDrive\Рабочий стол\STML-LUKS-PASSWORD.txt`.
2. Напечатай/запиши пароль в менеджер паролей.
3. Удали файл:
   ```powershell
   Remove-Item "C:\Users\lomel\OneDrive\Рабочий стол\STML-LUKS-PASSWORD.txt" -Force
   ```
4. Проверь, что в корзине его нет.

**Почему:** пока файл существует, любой доступ к Windows = доступ к LUKS.

### 2-of-3 (рекомендуется)

На Tails/Ubuntu (офлайн) раздели пароль LUKS:

```bash
ssss-split -t 2 -n 3 -w luks
```

Три shares — на три бумажных конверта, в разные места.  
Восстановление: `ssss-combine -t 2`.

Это **операционный кворум**, не threshold HSM. Без двух shares LUKS не
открывается.

---

## 3. Подпись policy в Tails

### 3.1 Загрузка

1. Вставь 64-GB Tails USB.
2. Boot Menu → USB → Tails.
3. На Welcome Screen задай **Administration Password** (нужен для `sudo`).
4. Подключи **4-GB USB**.

### 3.2 Запуск

Открой Terminal:

```bash
lsblk -o NAME,SIZE,TYPE,LABEL
```

Найди 4-GB флэшку (FAT, ~3.7G). Перейди в неё:

```bash
cd /media/amnesia/<метка-4GB>
sudo bash STML-SIGN.sh
```

Скрипт:

1. найдёт `/dev/disk/by-partlabel/STMLKEY` (fallback — раздел 57.3G);
2. попросит пароль LUKS;
3. смонтирует ключ;
4. подпишет `policy.json`;
5. положит `policy.signed.json` рядом;
6. отмонтирует LUKS.

### 3.3 Проверка

```bash
ls -l policy.signed.json
python3 - <<'PY'
import json
p=json.load(open('policy.signed.json'))
print(p['policy_id'], p['version'], p['key_id'], len(p['signature']))
PY
```

Выключи Tails. 64-GB флэшку храни офлайн.

---

## 4. Сервер: public key

Python-сервер должен доверять **твоему** `STML-policy.pub`, иначе подпись
будет отклонена.

### 4.1 Файл

```powershell
Copy-Item "C:\Users\lomel\OneDrive\Рабочий стол\STML-policy.pub" `
  "C:\ProgramData\AIDefender\stml\STML-policy.pub" -Force
```

### 4.2 Автозапуск

`run_stml_server.cmd` должен содержать:

```bat
if exist "%DATA%\STML-policy.pub" set "STML_POLICY_PUBKEY_FILE=%DATA%\STML-policy.pub"
```

В репозитории это уже есть в `scripts/run_stml_server.cmd`.  
Скопировать в ProgramData и перезапустить задачу:

```powershell
# elevated
Copy-Item "D:\ИИ защитник Вектор-защитник\scripts\run_stml_server.cmd" `
  "C:\ProgramData\AIDefender\stml\run_server.cmd" -Force
Restart-ScheduledTask -TaskName "AIDefender-STML-Server"
```

Если задачи нет — создай:

```powershell
.\scripts\install_stml_server_task.ps1
```

**Почему:** сервер иначе использует свой автоматически созданный policy-ключ,
и твоя USB-подпись не пройдёт.

### 4.3 Контроль

```powershell
Invoke-RestMethod http://127.0.0.1:8080/health
Get-Content "C:\ProgramData\AIDefender\stml\server.run.log" -Tail 20
```

---

## 5. Применить policy

### 5.1 CLI

```powershell
python -m stml.cli --tokens-file C:\ProgramData\AIDefender\stml\tokens.json `
  policy apply policy.signed.json
```

Ожидаемо: `201` + `approval_id`.

### 5.2 Approve (SoD)

```powershell
python -m stml.cli --tokens-file C:\ProgramData\AIDefender\stml\tokens.json `
  approvals list
python -m stml.cli --tokens-file C:\ProgramData\AIDefender\stml\tokens.json `
  approve <approval_id>
```

Admin не может approve; approver не может rollout.

### 5.3 Rollout

```powershell
python -m stml.cli --tokens-file C:\ProgramData\AIDefender\stml\tokens.json `
  rollout start personal-1 1 --percent 1
python -m stml.cli --tokens-file C:\ProgramData\AIDefender\stml\tokens.json `
  rollout promote <rollout_id>
```

Проверка:

```powershell
python -m stml.cli --tokens-file C:\ProgramData\AIDefender\stml\tokens.json `
  fleet list
```

### 5.4 GUI

Открой `http://desktop-jhqb492.tail7dcc3b.ts.net/ui/`, Settings → viewer token,
Fleet/Policies/Approvals.

---

## 6. Tailscale

Сейчас сервер доступен только внутри tailnet:

```text
http://desktop-jhqb492.tail7dcc3b.ts.net/
```

HTTPS-сертификат Tailscale аккаунт не выдал; HTTP внутри WireGuard.  
Чтобы включить HTTPS: Tailscale admin → DNS → HTTPS Certificates, затем:

```powershell
tailscale serve --bg --https=443 8080
```

Не включай Funnel — это публичный интернет.

---

## 7. Автозапуск: проверить/восстановить

Задачи могли исчезнуть после перезагрузки. Проверь:

```powershell
Get-ScheduledTask -TaskName "AIDefender-STML-*"
```

Если пусто:

```powershell
# elevated
.\scripts\install_stml_server_task.ps1
.\scripts\install_stml_connector_task.ps1
.\scripts\install_stml_rust_task.ps1
```

Проверка:

```powershell
Get-Service AIDefender
Invoke-RestMethod http://127.0.0.1:8080/health
Invoke-RestMethod http://127.0.0.1:8090/health
```

---

## 8. Backup/restore

### PostgreSQL

```powershell
.\scripts\stml_pg_backup.ps1 -Database stml_p4 -Password <pw>
```

Восстановление — в **заранее созданную** пустую БД:

```powershell
.\scripts\stml_pg_restore.ps1 -File <dump> -Database stml_p4_restore -Password <pw>
```

`-CreateDatabase` требует права CREATEDB; у роли `stml` его нет.

### Offsite

Используй `restic` + Backblaze B2; шифрование на клиенте:

```powershell
winget install Rclone.Rclone
winget install restic.restic
rclone config create b2 b2 account <keyID> key <appKey>
restic init --repo rclone:b2:stml-backup
restic backup --repo rclone:b2:stml-backup <dump> <sqlite> <trust>
```

---

## 9. Если что-то сломалось

### Tails не грузится

- Boot Menu → UEFI USB.
- Secure Boot off, Fast Boot off.
- Другой USB-порт.

### `STML-SIGN.sh` не находит ключ

```bash
lsblk -o NAME,SIZE,TYPE,PARTLABEL
sudo cryptsetup open /dev/disk/by-partlabel/STMLKEY stmlkey
```

Если метки нет — используй раздел 57.3G вручную.

### Сервер отклоняет policy

- `STML-policy.pub` не тот;
- сервер не перезапущен с `STML_POLICY_PUBKEY_FILE`;
- policy подписана другим ключом;
- `key_id` не совпадает.

Проверь `server.run.log`, `policy.signed.json`.

### Connector `10055`

Перезапусти задачу коннектора; проверь `connector.log`; при повторе —
`Get-NetTCPConnection` на TIME_WAIT.

### Задачи STML исчезли

См. раздел 7, переустанови задачи.

---

## 10. Что нельзя делать

- Не монтировать 64-GB Tails USB на онлайн-Windows для расшифровки ключа.
- Не хранить LUKS-пароль в plaintext после настройки.
- Не запускать `STML-SIGN.sh` с 4-GB, если она была на подозрительной машине,
  без проверки hash.
- Не выключать Secure Boot и не менять BIOS без понимания.
- Не считать это commercial production: нет независимого pen-test, DPIA,
  vendor EDR certification, HA.

---

## 11. Минимальный чек-лист

- [ ] Пароль LUKS перенесён, plaintext удалён.
- [ ] 2-of-3 shares на бумаге (рекомендуется).
- [ ] `policy.signed.json` создан в Tails.
- [ ] `STML-policy.pub` лежит в ProgramData.
- [ ] Сервер перезапущен с `STML_POLICY_PUBKEY_FILE`.
- [ ] `policy apply` → `approval` → `rollout`.
- [ ] GUI/Tailscale работает.
- [ ] Задачи автозапуска на месте.
- [ ] Backup/restore проверен.

---

## 12. Терминал

`stmlctl`:

```powershell
python -m stml.cli --tokens-file C:\ProgramData\AIDefender\stml\tokens.json health
python -m stml.cli --tokens-file C:\ProgramData\AIDefender\stml\tokens.json fleet list
```

Только allowlisted команды, без shell. Полный список — [docs/stmlctl.md](stmlctl.md).
