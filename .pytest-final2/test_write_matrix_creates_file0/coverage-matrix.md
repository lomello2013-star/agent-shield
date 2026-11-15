# Матрица покрытия ATT&CK (in-scope)

> Генерируется `scripts/stage5_measure.py` из `rules/base.json` и `rules/techniques.json`.
> Покрытие = полнота отображения «техника → слой → правило → тест», а не доказанная
> эффективность: реальная проверка — red-team (этап 12).

**Обнаружение**: 18/18 = 100.0% (цель ≥90.0%) — в цели.
**Предотвращение**: 18/18 = 100.0% (цель ≥70.0%) — в цели.

| Техника | Название | Слой | Правила обнаружения | Правила предотвращения |
|---|---|---|---|---|
| T1059 | Command and Scripting Interpreter | L2 | WIN-EXEC-TEMP-001, LINUX-EXEC-TMP-101 | WIN-EXEC-TEMP-001, LINUX-EXEC-TMP-101 |
| T1027 | Obfuscated Files or Information | L2 | WIN-PS-ENCODED-002 | WIN-PS-ENCODED-002 |
| T1566 | Phishing | L1 | WIN-OFFICE-SPAWN-003 | WIN-OFFICE-SPAWN-003 |
| T1003 | OS Credential Dumping | L3 | WIN-LSASS-ACCESS-004, LINUX-CRED-READ-104 | WIN-LSASS-ACCESS-004, LINUX-CRED-READ-104 |
| T1547 | Boot or Logon Autostart Execution | L1 | WIN-RUNKEY-005 | WIN-RUNKEY-005 |
| T1053 | Scheduled Task/Job | L1 | WIN-SCHTASK-006, LINUX-CRON-102 | WIN-SCHTASK-006, LINUX-CRON-102 |
| T1543 | Create or Modify System Process | L1 | WIN-SERVICE-CREATE-007, WIN-SERVICE-CREATE-007A | WIN-SERVICE-CREATE-007 |
| T1070 | Indicator Removal | L1 | WIN-LOG-CLEAR-008, LINUX-AUDIT-TAMPER-103 | WIN-LOG-CLEAR-008, LINUX-AUDIT-TAMPER-103 |
| T1562 | Impair Defenses | L8 | WIN-DEFENDER-TAMPER-009 | WIN-DEFENDER-TAMPER-009 |
| T1055 | Process Injection | L3 | WIN-INJECT-010, LINUX-INJECT-106, LINUX-EXEC-MEM-107, LINUX-EXEC-CORR-108, LINUX-EXEC-CORR-109, LINUX-EXEC-CORR-110 | WIN-INJECT-010 |
| T1036 | Masquerading | L1 | WIN-MASQUERADE-011 | WIN-MASQUERADE-011 |
| T1021 | Remote Services | L4 | NET-SMB-LATERAL-012 | NET-SMB-LATERAL-012 |
| T1071 | Application Layer Protocol | L4 | NET-DNS-LONG-013, LINUX-C2-PORT-105 | LINUX-C2-PORT-105 |
| T1486 | Data Encrypted for Impact | L6 | FILE-MASS-WRITE-014 | FILE-MASS-WRITE-014 |
| T1485 | Data Destruction | L5 | FILE-CANARY-015 | FILE-CANARY-015 |
| T1204 | User Execution | L0 | WIN-DOWNLOADS-EXEC-016, WIN-DOWNLOADS-EXEC-016A | WIN-DOWNLOADS-EXEC-016 |
| T1041 | Exfiltration Over C2 Channel | L4 | NET-EXFIL-LARGE-017 | NET-EXFIL-LARGE-017 |
| T1546 | Event Triggered Execution | L1 | WIN-WMI-SUBSCRIPTION-018 | WIN-WMI-SUBSCRIPTION-018 |
