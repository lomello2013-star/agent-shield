# Individual acceptance (self-hosted pilot)

> Заполняется владельцем. Это не заменяет независимый аудит/DPIA.

## 1. Область

- Версия/коммит:
- Дата:
- Хост/ОС:
- Кто принимает:
- Второй ревьюер (не автор кода):

## 2. Проверено

- [ ] 24h soak: 0 рестартов, 0 падений, availability ≥ 99.9%.
- [ ] Python/Rust parity CI: `ok:true`.
- [ ] Backup создан и restore проверен.
- [ ] GUI `/ui/` открывается; viewer token работает; старый токен 401.
- [ ] Policy key в HSM; 2-of-3 custodians; протокол церемонии подписан.
- [ ] mTLS/CRL (если включены): без cert / revoked → отказ.
- [ ] Defender + Sysmon + Wazuh: матрица пройдена.
- [ ] SAST/DAST/fuzz: отчёты приложены; known findings приняты.
- [ ] DPIA/self-assessment: заполнен; юрист не требуется / требуется.

## 3. Known risks

| Риск | Принят? | Комментарий |
|---|---|---|
| Нет threshold HSM | | YubiHSM + 2-of-3 operational |
| Нет vendor EDR certification | | lab-матрица |
| Нет independent pen-test | | OSS + peer review |
| Нет HA | | backup + restore |
| `pickle.loads` в IPC | | named pipe + authkey |
| Tauri не подписан | | web GUI only |

## 4. Решение

- [ ] Принято для личного/пилотного использования.
- [ ] Не принято; причины:

Подпись владельца: ____________________  
Подпись ревьюера: ____________________
