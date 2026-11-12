# Реестр окон взлома

> **Статус:** рабочий документ, ссылается на дорожную карту v9.1 (§9).
> **Назначение:** исчерпывающая карта «окно атаки → слой защиты → механизм закрытия → способ проверки → метрика». Каждое окно обязано иметь владельца-слой, механизм и проверочную метрику; не допускаются «пустые» ячейки.
> **Правило пересмотра:** реестр пересматривается ежеквартально и после каждого red-team/инцидента. Закрытое окно остаётся в реестре с пометкой `verified`; новое окно добавляется через `decision`.

## 1. Легенда

- **Слой** — уровень архитектуры L0–L8 (см. v9.1 §3).
- **Обнаружение** — чем и как фиксируем (детекция).
- **Предотвращение** — чем и как не даём случиться / сдерживаем.
- **Верификация** — тест или red-team-сценарий, доказывающий закрытие.
- **Метрика** — R/E-метрика из v9.1, которой контролируется окно.
- **Остаточный риск** — что остаётся незакрытым честно.

## 2. Сводная матрица

| Стадия | Окно (Windows) | Окно (Linux) | Слои | Метрика |
|---|---|---|---|---|
| Initial Access | макро/HTA/ISO/LNK/MSI | веб-шелл, публичный сервис | L0, L1, L2, L6 | E5 |
| Execution | LOLBin, обход WDAC | интерпретатор, /tmp | L0, L1, L2 | E1, E5 |
| Persistence | Run-ключи, службы, задачи, WMI, DLL-hijack | cron, systemd, authorized_keys, LD_PRELOAD | L1, L8 | E11 |
| Privilege Escalation | UAC-bypass, kernel exploit | sudo/suid, kernel exploit | L0, L3 | E4 |
| Defense Evasion | patch AMSI/ETW, kill Defender | tamper auditd, rm журналов | L8, L1 | R10 |
| Credential Access | LSASS dump, SAM, DPAPI | /etc/shadow, SSH-ключи | L3, L5 | E3 |
| Discovery / Lateral | WMI, SMB, WinRM | SSH, API-вызовы | L1, L6 | E3 |
| C2 / Exfiltration | DNS/HTTPS-туннель | DNS/HTTPS | L4 | E4 |
| Impact | ransomware, wiper | miner, rm -rf | L0, L5 | E1 |

## 3. Детально по стадиям

### 3.1. Initial Access

| Поле | Windows | Linux |
|---|---|---|
| Вектор | фишинг → макро (docm), HTA, ISO+LNK, MSI, js; USB | веб-шелл через уязвимость, дефолтные креды, supply chain |
| Обнаружение | AMSI (макро/скрипт), L1 файл-события, L6 file-модель на загруженном | L1 eBPF exec нового процесса из www-data, L6 ELF/скрипт-модель |
| Предотвращение | L0 WDAC (неподписанный не запускается), макро-политика, protected folders | L0 fapolicyd/IMA (неподписанный бинарь не исполняется), noexec /tmp |
| Верификация | прогон фишингового набора (макро/HTA/ISO) → 0 исполнений | web-shell-сценарий → блок на exec |
| Метрика | E5 ≥85% | E5 ≥85% |
| Остаточный риск | подписанный вредонос (stolen cert), 0-day | 0-day в веб-приложение, легитимный подписанный бинарь |

### 3.2. Execution

| Поле | Windows | Linux |
|---|---|---|
| Вектор | LOLBin (rundll32, mshta, regsvr32, wmic, powershell -enc), обход WDAC | bash/sh/python/perl из /tmp, интерпретатор |
| Обнаружение | L1 kernel callback запуска + командная строка, L2 AMSI+script logging | L1 `sched_process_exec`, L2 LSM `bprm_check_security` |
| Предотвращение | L0 WDAC (deny по пути/хэшу), L2 AMSI блок скрипта | L0 fapolicyd, L2 LSM-deny, noexec |
| Верификация | набор LOLBin-техник → блок/алерт | интерпретатор-сценарии → блок |
| Метрика | E1 ≥92%, E5 ≥85% | E1 ≥92%, E5 ≥85% |
| Остаточный риск | интерпретатор с подписанным бинарём, обход WDAC-политики | подписанный/доверенный интерпретатор, /dev/shm |

### 3.3. Persistence

| Поле | Windows | Linux |
|---|---|---|
| Вектор | Run/RunOnce, службы, Scheduled Tasks, WMI subscription, DLL search-order hijack, AppInit | cron, systemd unit/timer, authorized_keys, LD_PRELOAD, init-скрипты, /etc/profile |
| Обнаружение | L1 реестр/файл callbacks, L8 целостность | L1 файл-события, L8 IMA/fs-verity |
| Предотвращение | L0 protected folders (Startup), L1 блок записи в автозапуск | L0 IMA-enforce (неизменяемые критичные пути), L8 |
| Верификация | сценарий каждой техники персистентности → детекция/блок | cron/authorized_keys/LD_PRELOAD сценарии |
| Метрика | E11 покрытие ≥90% | E11 покрытие ≥90% |
| Остаточный риск | легитимный механизм (служба с подписью), kernel-persist | root-скрытый unit, initramfs |

### 3.4. Privilege Escalation

| Поле | Windows | Linux |
|---|---|---|
| Вектор | UAC-bypass, token-манипуляции, kernel exploit, vulnerable driver | sudo злоупотребление, setuid-бинарь, kernel exploit, container escape |
| Обнаружение | L1 (integrity-переход 4688), L3 (anti-injection) | L1 auditd `setuid`/`capset`, L3 kprobe |
| Предотвращение | L0 Exploit Protection, kernel-целостность (PatchGuard) | L0 noexec, LSM, live-patch, seccomp |
| Верификация | UAC-bypass/токен-набор | suid/sudo/escape сценарии |
| Метрика | E4 ≥70% | E4 ≥70% |
| Остаточный риск | 0-day в ядре, подписанный уязвимый драйвер | 0-day в ядре, misconfig вне контроля |

### 3.5. Defense Evasion

| Поле | Windows | Linux |
|---|---|---|
| Вектор | patch AMSI/ETW, unhook ntdll, отключить/убить Defender, очистка логов (1102), тайм-стоппинг | tamper auditd, rm wtmp/btmp, выгрузка eBPF, LD_PRELOAD на наш демон |
| Обнаружение | L8 (tamper-доказательность), L1 ETW-TI (patch-детекция), ELAM | L8 (append-only журнал, auditd, fs-verity), L1 |
| Предотвращение | L8 PPL/ELAM, защита конфигов | L8 IMA/fs-verity, systemd hardening |
| Верификация | сценарий «убить/пропатчить защиту» → `tamper` | tamper auditd → `tamper` |
| Метрика | R10 = 100% | R10 = 100% |
| Остаточный риск | администратор с полным доступом, руткит ниже нас | root с полным доступом, kernel-руткит |

### 3.6. Credential Access

| Поле | Windows | Linux |
|---|---|---|
| Вектор | LSASS dump (mimikatz, comsvcs minidump), SAM/SYSTEM, DPAPI, креды в памяти | /etc/shadow, SSH-ключи, креды в env/файлах, ptrace на процессы |
| Обнаружение | L3 (LSASS protection, anti-injection, handle-access блок), canary-креды | L3 kprobe/ptrace-детекция, L5 canary SSH-ключи |
| Предотвращение | L3 Credential Guard, LSA protection, блок handle | L0 IMA на /etc/shadow, L3, honeytoken |
| Верификация | LSASS-dump набор (T1003.001) → блок+алерт | dump/ptrace сценарий → детекция |
| Метрика | E3 ≥80% | E3 ≥80% |
| Остаточный риск | direct syscalls, kernel-level dump | root-доступ = всё читается; детекция, не предотвращение |

### 3.7. Discovery / Lateral Movement

| Поле | Windows | Linux |
|---|---|---|
| Вектор | WMI/WinRM/SMB, PSExec, RDP-переброс | SSH-переброс, API-вызовы, redis/mysql-клиенты |
| Обнаружение | L1 процесс/сеть, L6 поведение (аномальный lateral) | L1 net-события, L6 поведение |
| Предотвращение | L5 блок сети процесса, L4 WFP | L4 eBPF/nft, L5 блок |
| Верификация | lateral-сценарий (WMI/WinRM) → блок | SSH-переброс → блок |
| Метрика | E3 ≥80% | E3 ≥80% |
| Остаточный риск | легитимный канал (подписанный WinRM) | легитимный SSH, шифрованный трафик |

### 3.8. C2 / Exfiltration

| Поле | Windows | Linux |
|---|---|---|
| Вектор | DNS/HTTPS-туннель, DoH, beaconing | DNS/HTTPS, SSH-туннель |
| Обнаружение | L4 WFP callout (TLS-fp, DNS, beacon-анализ) | L4 eBPF tc/XDP, conntrack, DNS |
| Предотвращение | L4 блок по flow/домену, L5 изоляция | L4 блок, nft |
| Верификация | C2-эмуляция (Sliver/Cobalt-стиль) → блок | туннель-сценарий → блок |
| Метрика | E4 ≥70% | E4 ≥70% |
| Остаточный риск | зашифрованный C2 с легитимным доменом, DoH | шифрованный трафик без MITM, VPN |

### 3.9. Impact

| Поле | Windows | Linux |
|---|---|---|
| Вектор | ransomware (шифрование), wiper, удаление теней (VSS) | crypto-miner, rm -rf, шифрование |
| Обнаружение | L5 canary-файлы, L6 поведение (bulk write) | L5 canary, L6 (CPU/сеть аномалии) |
| Предотвращение | L5 auto-suspend по canary, L0 protected folders, VSS-защита | L5 auto-suspend/kill, снапшоты |
| Верификация | ransomware-эмуляция → сдерживание ≤5 с | miner/wiper сценарий → сдерживание |
| Метрика | E1 ≥92%, E10 ≤5 с | E1 ≥92%, E10 ≤5 с |
| Остаточный риск | шифрование до срабатывания (файлы уже зашиты), восстановление = бэкап | восстановление = снапшот/бэкап |

## 4. Приоритизация закрытия

Закрывать в порядке, приносящем максимум пользы при минимальной сложности:

1. **Impact (canary + auto-suspend)** — дёшево, спасает от ransomware.
2. **Execution (L0 default-deny)** — главный рычаг 90%+.
3. **Credential Access (L3 + canary-креды)** — блокирует мимик-атаки.
4. **Defense Evasion (L8 tamper)** — условие доверия ко всему остальному.
5. **C2/Exfil (L4)** — перекрывает пост-эксплуатацию.
6. Persistence / Privilege Escalation / Lateral / Initial Access — по мере.

## 5. Процесс пересмотра

- Ежеквартально: ревью каждого окна, актуализация MITRE-техник, добавление новых окон из инцидентов/red-team.
- После каждого red-team: необнаруженное → новое окно + приоритет + владелец.
- Закрытие окна фиксируется `decision` с указанием верификации; окно остаётся с `verified`.
