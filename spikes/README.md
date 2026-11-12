# Этап 0 — спайки: артефакты и воспроизведение

> Все числа в `DEVLOG.md` получены прогонами из этой папки на хосте `DESKTOP-JHQB492`
> (Windows 10 Pro 19045, 4C/8T i7-6700K, 16 ГБ) 2026-11-12. Никакие значения не «оценены».

## Что где лежит

| Спайк | Папка / файл | Что внутри |
|---|---|---|
| 1. Ядро-подпись | записи DEVLOG + выводы в этой папке | Secure Boot, cert store, WDK, EFI/lockdown, IMA, BTF |
| 2. Контроль приложений | `02-app-control/wdac_probe.ps1` → `wdac_probe.json` | инвентарь 843 exe, 250 подписей, 2 политики, trace 18 запусков |
| 3. AMSI/ETW-TI | `03-amsi-etw/amsi_latency.ps1` → `amsi_latency.json` | 600 сканов AMSI, ETW-TI провайдер/сессия |
| 4. eBPF | `04-ebpf/*.bpf.c`, `loader.c`, `run_spike4.sh` | CO-RE сборка, tracepoint, LSM, cgroup_skb |
| 5. Драйвер | выводы в DEVLOG | 19 minifilter, 19 BugCheck/90д, WDK/admin = 0 |
| 6. ML | `06-ml/ml_pe.py`, `ml_elf.py` → `ml_*_result.json` | PE 50k holdout, ELF 12k holdout, латентность |
| 7. Сеть | `07-network/wfp_probe.ps1` → `wfp_probe.json`, `04-ebpf/run_spike7_net*.sh` | Windows WFP/firewall denied; Linux connect4/EPERM 8 мкс |

## Воспроизведение

```powershell
# Спайк 2 (инвентарь + контрфактическая политика + trace)
powershell -NoProfile -ExecutionPolicy Bypass -File spikes\02-app-control\wdac_probe.ps1

# Спайк 3 (AMSI-латентность)
powershell -NoProfile -ExecutionPolicy Bypass -File spikes\03-amsi-etw\amsi_latency.ps1

# Спайк 7 (Windows WFP/firewall, без elevation)
powershell -NoProfile -ExecutionPolicy Bypass -File spikes\07-network\wfp_probe.ps1

# Спайк 6 (данные скачиваются в spikes\artifacts\data)
python spikes\06-ml\ml_pe.py
python spikes\06-ml\ml_elf.py
```

```powershell
# Спайки 4 и 7 (Linux, WSL2 root)
$d = (Resolve-Path 'spikes\04-ebpf').Path
$wd = (wsl.exe -d Ubuntu -u root -- wslpath -a "$d").Trim()
wsl.exe -d Ubuntu -u root -- bash "$wd/run_spike4.sh" "$wd"
wsl.exe -d Ubuntu -u root -- bash "$wd/run_spike7_net4.sh" "$wd"
wsl.exe -d Ubuntu -u root -- bash "$wd/run_spike7_net.sh" "$wd"
```

## Данные

`spikes/artifacts/data/` (не коммитить в git — 3,5 ГБ):

* EMBER2018 (только векторизованные признаки, без исполняемых образцов): 4 benign-шарда + 5 mixed-шардов train, 5 holdout-шардов test.
* EMBER2024 ELF: 52 train-шарда, 12 test-шардов (сентябрь–ноябрь 2024).

Источники: `https://huggingface.co/datasets/cw1521/ember2018`, `https://huggingface.co/datasets/joyce8/EMBER2024`.

## Важные ограничения (не прятать)

1. Реальная WDAC/fapolicyd-политика **не разворачивалась** — только контрфактическая оценка на реальном инвентаре и trace; развёртывание требует elevation.
2. AMSI измерен при выключенном Defender RTP — это стоимость API, а не полного скана.
3. ETW-TI-потребитель требует PPL/подписи; сессия без elevation не создаётся.
4. WSL2 — прокси, не целевой дистрибутив; tc/XDP в WSL не проверены (нет модулей), Secure Boot/lockdown в WSL отсутствуют.
5. Спайк 5 (драйвер) **не закрыт**: нет WDK, admin, тест-VM; на хосте 19 BugCheck за 90 дней — база для canary непригодна.
6. PE-данные 2018 года; «свежими» являются только ELF-данные (2024).
