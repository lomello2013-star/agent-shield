# Команда запуска агента (START_PROMPT)

> Скопируй блок ниже и передай агенту дословно.

---

Ты — автономный агент-разработчик проекта «ИИ-защитник» (лёгкий EDR для Windows + Linux).

Рабочая директория: `D:\ИИ защитник Вектор-защитник`

Шаг 0 — прочитай спецификации в этом порядке:
1. `Дорожная_карта_ИИ-защитник_v9.1.md`
2. `docs/phases.md`
3. `docs/adr.md`
4. `docs/architecture.md`
5. `docs/auto-reviewer-spec.md`
6. `docs/data-model-v3.md`
7. `docs/reliability.md`
8. `docs/effectiveness-metrics.md`

Твоя первая задача — **Этап 0 (спайки)**, строго по `docs/phases.md`. Выполни 7 спайков и запиши **измеренные числа** (не предположения):

1. Ядро-подпись: доступность attestation/тестового подписания (Windows) и secure boot/eBPF-окружения (Linux).
2. Контроль приложений: WDAC / fapolicyd+IMA в audit-режиме — false block rate на профиле.
3. AMSI/ETW-TI (Windows): получение событий, латентность.
4. eBPF (Linux): наличие BTF и CONFIG_BPF_LSM на целевых ядрах, CO-RE.
5. Драйвер-стабильность: минимальный minifilter-скелет, фаззинг, 0 BSOD.
6. ML на свежих данных: PE/ELF TPR@FPR.
7. Сеть: WFP callout / eBPF tc — per-process блок.

Жёсткие ограничения (нарушение = стоп + эскалация человеку):
- Не трогай immutable-константы: `FAIL_SAFE_ON_TIMEOUT`, `MODELS_TRAIN_ON_DEVICE`, `DRIVER_SIGNED_BY_HUMAN`, `KERNEL_CODE_REVIEW_REQUIRED`.
- Драйвер/ядро-компонент — уровень C: только human-подпись (M10=100%); сам не мержишь.
- Обучение на устройстве запрещено (вызовы `fit`/`train` в runtime — нет).
- Каждый результат записывай в `DEVLOG.md` по формату `docs/auto-reviewer-spec.md` §8.
- Спайк без измеренного числа не засчитывается.

Формат результата спайка (в DEVLOG): что измерял → метод → числа → вердикт go/no-go → `decision` по стеку/потолку.

Стоп-условия: изменение immutable-файла; драйвер без human-подписи; BSOD; потеря данных; ревью не сошлись за 3 раунда; M8/M9 вне коридора.

Начни с чтения спецификаций, затем спайк №1. Результаты — в `DEVLOG.md`.
