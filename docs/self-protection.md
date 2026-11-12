# Самозащита и безопасность поставки

> **Статус:** норматив. Раскрывает v9.1 §10.1 и §10.10.

## 1. Самозащита

| Механизм | Windows | Linux |
|---|---|---|
| Тампер-доказательность | ETW+Event Log, подпись, ACL | append-only журнал, auditd, fs-verity |
| Защита процесса | PPL (через драйвер), ELAM | systemd hardening, IMA, AppArmor/SELinux |
| Целостность | Authenticode+каталог, Ed25519-манифест | GPG+fs-verity+IMA |
| Ключи | HSM/CI-secret вне агента | HSM/TPM вне агента |
| Обновление | dual-slot, canary, откат | dual-slot, canary, откат |

**Принцип:** самозащита — это **детекция и восстановление**, не «неубиваемость». Против администратора/root не выживаем (threat-model.md); детектируем тамперинг и логируем.

## 2. Сценарии тамперинга и реакция

| Сценарий | Реакция |
|---|---|
| Остановка службы не через TUI/CLI | `tamper` + `incident` |
| Изменение правил/бинарей/моделей | несовпадение хеша → `failed` + `tamper` |
| Подмена пакета модели | `model_pack_verify` → `failed` + `tamper` |
| Выключение критичного модуля без подтверждения | отказ |
| Патч AMSI/ETW (Windows) / tamper auditd (Linux) | L8 + ETW-TI/ELAM / auditd+fs-verity |
| Откат системного времени | монотонные часы + `incident` |

Каждый сценарий — обязательный security-тест (§test-strategy).

## 3. Безопасность поставки (trust boundary)

- **Гейты вне периметра агента:** protected branch, CODEOWNERS, human-review через API платформы; `human_acceptance` — подписанный коммит человека из allowlist.
- **Ключи:** подпись драйвера/моделей/обновлений — HSM/CI-secret, недоступны агенту.
- **Драйвер:** отдельный репозиторий, строжайшее ревью, любое изменение — human-подпись (M10=100%).
- **SBOM:** lock-файлы с хешами, `cargo audit`/`pip-audit`, воспроизводимые сборки.
- **Политика раскрытия уязвимостей + bug bounty.**

## 4. Уровни автономии разработки

| Уровень | Что можно | Контроль |
|---|---|---|
| A | код модулей, тесты, документация, конфиги | CI + авто-ревьюер |
| B | core/rules/response/watchdog/адаптеры/схемы | second-agent review + CI |
| C | **драйвер, модель угроз, политика fail-safe, метрики, обновление моделей** | **только human-подпись** |

## 5. Immutable guards (`core/policy.py`)

```python
# IMMUTABLE: requires human_acceptance
FAIL_SAFE_ON_TIMEOUT = "reject"      # НИКОГДА не "accept"
MODELS_TRAIN_ON_DEVICE = False       # НИКОГДА не True
DRIVER_SIGNED_BY_HUMAN = True        # НИКОГДА не False
KERNEL_CODE_REVIEW_REQUIRED = True   # НИКОГДА не False
```

`ci_immutable_check.py` блокирует merge, если файл изменён без подписанного `human_acceptance`. Агент не может обойти сам.

## 6. Полная спецификация контура агента

См. `docs/auto-reviewer-spec.md` (second-agent review, M7–M10, сев-дефекты, чек-листы драйвера).
