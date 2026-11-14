# EV-подпись и WHQL: что закрыто, что блокирует

> **Честный статус: EV/WHQL не закрыты и не могут быть закрыты в этой сессии.**
> Нужны покупка EV-сертификата и прогон HLK на отдельном стенде. Ниже —
> подготовленный пакет и точный список внешних действий.

## 1. Что уже готово (пакет)

| Артефакт | Где | Статус |
|---|---|---|
| Исходник minifilter | `driver/minifilter/AidfFilter.c` | собран, загружен, блокировка проверена |
| Сборка | `build.ps1` (WDK 10.0.26100 + MSVC) | воспроизводима |
| INF | `driver/minifilter/AidfFilter.inf` | черновик пакета |
| Тестовая подпись | `sign.ps1` (self-signed) | только `testsigning` |
| Каталог | `package.ps1` → `Inf2Cat` + `signtool` | **собран: RC=0, cat 1078 → 2366 B (test-signed)** |
| Установка/тест | `install.ps1`, `test.ps1` | проверены в Win11 VM |
| Политика агента | `scripts/aidf_driver_policy.py` | communication port, policy switch проверен |

## 2. Почему нельзя закрыть сейчас

| Требование | Блокер |
|---|---|
| EV code-signing certificate | покупка у CA (DigiCert/Sectigo/GlobalSign), юрлицо, HSM/токен |
| HLK (Hardware Lab Kit) | HLK Controller + HLK Studio, тестовая машина/VM, прогон playlists |
| WHQL submission | Partner Center / Hardware Dev Center, EV-подпись пакета, каталог |
| Secure Boot / CI | подписанный `AidfFilter.cat` + EV-цепочка; текущая подпись test-only |
| ELAM/PPL | отдельный подписанный компонент, не этот minifilter |

## 3. Порядок закрытия (когда появится EV)

1. Получить EV-сертификат; установить в HSM/токен на сборочной машине.
2. Собрать `AidfFilter.sys` + `AidfFilter.inf`; сгенерировать каталог:
   `powershell -File driver\minifilter\package.ps1` (Inf2Cat + test-sign).
   Проверено: `Inf2Cat` RC=0, каталог создан; подпись пока test-only.
3. Подписать `AidfFilter.sys` и `AidfFilter.cat` EV-сертификатом (`signtool sign /fd SHA256 /tr ... /td SHA256`).
4. Прогнать HLK: `DriverVerifier`, minifilter playlists, stress/PNP/IO, fuzz; сохранить `.hlkx`.
5. Отправить пакет в Partner Center → получить WHQL-подпись.
6. Проверить загрузку на чистой Win11 с Secure Boot On; без `testsigning`.
7. Только после этого убрать `testsigning` из лабораторной инструкции.

## 4. Что нельзя выдавать за «закрыто»

- `signtool verify /pa` на self-signed сертификате — **не** WHQL.
- Загрузка с `testsigning on` — **не** production.
- Отсутствие EV — **не** «почти готово»: без него драйвер не пройдёт Secure Boot/CI.

## 5. Следующий инженерный шаг (без покупки)

Связать политику драйвера с вердиктом агента: сейчас `scripts/aidf_driver_policy.py`
шлёт подстроку вручную; следующий шаг — IPC-метод агента, который вызывает
`FilterSendMessage` при подтверждённом вердикте (quarantine/protect path).
