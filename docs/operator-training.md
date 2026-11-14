# Обучение оператора STML

> Допуск к production GUI — только после этого чек-листа. Тренинг не блокирует
> технический гейт S3, но без подписи оператор не получает production-доступ.

## 1. Роли

| Роль | Что может |
|---|---|
| Viewer | читать флот, политики, отчёты |
| Operator | dry-run, isolate/resume (в рамках политики) |
| Admin | rollout/promote/halt/rollback, ключи, revoke cert |
| Approver | approve/deny (SoD, отдельный токен) |

## 2. Модули тренинга

1. **Dashboard/Fleet** — статусы, last_seen, drawer агента.
2. **Policies** — подпись, dry-run, diff, rollout 1→10→50→100.
3. **Rollback** — halt vs rollback, что происходит с агентами.
4. **Isolate** — KS-5, heartbeat продолжается, reports буферизуются.
5. **Approvals** — SoD: Admin не approve, Approver не kill-switch.
6. **Trust** — ключи, отзыв, CRL-lite, backup/restore.
7. **Audit** — verify, JSON/CEF export.
8. **Инцидент** — runbook `docs/runbook-stml.md`.

## 3. Сценарии (обязательные)

- [ ] Dry-run policy на 20 агентах → прочитать `would_change`.
- [ ] Запустить rollout 1 %, promote до 10 %, halt.
- [ ] Rollback → проверить, что policy_version вернулся.
- [ ] Isolate агент → heartbeat идёт, reports не уходят; resume → досылка.
- [ ] Approve policy под approver-токеном; попытка approve под admin → 403.
- [ ] Отозвать client cert → запрос 403; restore cert.
- [ ] Backup → restore → audit verify ok.
- [ ] Найти инцидент P0 в GUI, открыть drawer, объяснить действия.

## 4. Допуск

| Проверка | Подпись |
|---|---|
| Все сценарии пройдены | оператор |
| SoD и rollback поняты | security engineer |
| Runbook прочитан | оператор |
| Дата/версия STML | — |

## 5. Метрики после допуска

- **S18** — доля действий оператора, отменённых/откаченных; цель ≤15 % (S3) → ≤5 % (S6).
- **S19** — доля инцидентов от оператора; цель ≤5 % → ≤1 %.
- Минимум **50 действий/неделю** для метрики; иначе «недостаточно данных».
- S18/S19 видны в **Ops** GUI и `/v0/ops`.

## 6. Запрещено

- Передавать admin/approver токены другому человеку.
- Обходить dry-run и approval для production-policy.
- Использовать dev-CA/SoftHSM в production.
