# Драйверный контур (minifilter, lab)

> **Статус: тестовый контур, не production.** Драйвер собран WDK 10.0.26100 +
> MSVC, подписан self-signed сертификатом и загружен в Windows 11 VM с
> `testsigning on`. Это доказывает контракт «kernel callback → реальная
> блокировка», но **не** заменяет EV-подпись и WHQL.

## Что делает

`AidfFilter` — минимальный minifilter (altitude `328000`, 4 инстанса: C:, D:, Mup,
ещё один volume). На `IRP_MJ_CREATE` с write-доступом проверяет путь: если он
содержит `\protected\`, возвращает `STATUS_ACCESS_DENIED`. Дополнительно
зарегистрирован `IRP_MJ_WRITE` с тем же префиксом.

Проверено в `AIDF-Win11`:

| Проверка | Результат |
|---|---|
| `fltmc filters` | `AidfFilter 4 328000` |
| запись в `C:\AIDefender\protected\rt.txt` | **Access denied** |
| запись в `C:\AIDefender\allowed.txt` | OK |

## Канал политики (агент → драйвер)

Драйвер создаёт port `\AidfFilterPort`; по умолчанию политика **пустая**, то есть
блокировки нет. User-mode клиент отправляет подстроку:

```powershell
python scripts\aidf_driver_policy.py "\\protected\\"
```

Проверено в VM:

| Политика | `C:\AIDefender\protected` | `C:\AIDefender\secret` |
|---|---|---|
| пустая | allowed | allowed |
| `\protected\` | **denied** | allowed |
| `\secret\` | allowed | **denied** |

Порт защищён DACL (SYSTEM + Administrators); это прообраз канала, по которому
агент будет отправлять путь при подтверждённом вердикте. Сейчас policy client
запускается вручную.

## Сборка (host)

```powershell
powershell -ExecutionPolicy Bypass -File driver\minifilter\build.ps1
powershell -ExecutionPolicy Bypass -File driver\minifilter\sign.ps1
```

`build.ps1` собирает в `C:\ProgramData\AIDefender\driver-build` (ASCII-путь,
иначе `cmd.exe` ломает кириллицу) и копирует `out\AidfFilter.sys`.
`sig.ps1` использует/создаёт `out\aidf-test.pfx` + `aidf-test.cer`; `verify /pa`
на хосте падает на недоверенном корне — это ожидаемо, в VM сертификат
импортируется в Root/TrustedPublisher.

## Установка (VM)

1. Скопировать `out\AidfFilter.sys` и `out\aidf-test.cer` в `C:\AIDefender\driver`.
2. В VM: `powershell -File C:\AIDefender\driver\install.ps1`.
3. Проверка: `powershell -File C:\AIDefender\driver\test.ps1` → `blocked=True allowed=True`.
4. Удаление: `install.ps1 -Uninstall` (или `fltmc unload AidfFilter` + `sc delete`).

## Ограничения (честно)

- **Test-signing**: только для лаборатории; production требует EV-сертификат и
  WHQL-подпись, иначе Secure Boot/CI не пропустят драйвер.
- **Нет ELAM/ETW-TI/WFP**: это только файловый minifilter, не полный
  kernel-контур; ETW-TI по-прежнему требует подписанного PPL-компонента.
- **Нет связи с user-mode политикой**: блокировка по фиксированному пути, не по
  вердикту агента; следующий шаг — канал `FltSendMessage`/IOCTL и policy engine.
- **Altitude 328000** — лабораторный; в продукте нужен согласованный диапазон и
  совместимость с EDR (см. `docs/operations.md`).
- **Риск BSOD**: драйвер минимальный, но checkpoint в VM был отключён; при
  падении VM восстанавливается перезагрузкой (драйвер demand-start).
