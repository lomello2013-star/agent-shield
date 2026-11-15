# Р§РµРє-Р»РёСЃС‚ РїРёР»РѕС‚РЅРѕРіРѕ СЂРµР»РёР·Р° AIDefender/STML

РЎС‚Р°С‚СѓСЃ: **pilot / lab-only**. РќРµ production. EV/WHQL/HDC Рё СЋСЂС‡Р°СЃС‚СЊ Р·Р°РјРѕСЂРѕР¶РµРЅС‹.

## Linux вЂ” РїСЂРѕРІРµСЂРµРЅРѕ

- [x] Ubuntu 24.04 VM, СЃС‚Р°С‚РёС‡РµСЃРєРёР№ IP `172.23.213.50/20`.
- [x] Р’С…РѕРґ РїРѕ SSH-РєР»СЋС‡Сѓ.
- [x] BPF LSM: `lsm=lockdown,capability,landlock,yama,apparmor,bpf`.
- [x] `aidf-ebpf-guard.service` Р°РєС‚РёРІРµРЅ РїРѕСЃР»Рµ reboot.
- [x] eBPF exec deny: `/tmp/t2` в†’ `Permission denied` (RC 126).
- [x] eBPF write deny: `write=/tmp/wtest`.
- [x] `apt-get update` РїРѕРґ enforce: `APT_RC=0`.
- [x] `.deb` Рё `.rpm` СЃРѕР±СЂР°РЅС‹.
- [x] Pydantic 2.14.3 РІ `/opt/aidf/venv`.
- [x] auditd fallback Р°РєС‚РёРІРµРЅ Р±РµР· eBPF.
- [x] logrotate reports/audit/raw вЂ” 14 РґРЅРµР№.

## Windows вЂ” РїСЂРѕРІРµСЂРµРЅРѕ

- [x] Onedir-СЃР»СѓР¶Р±Р° РІ `C:\Program Files\AIDefender\service`.
- [x] `AIDefender` Running РїРѕСЃР»Рµ reboot.
- [x] `Sysmon64` Running, СЃРѕР±С‹С‚РёСЏ `win.sysmon`.
- [x] Defender ASR/CFA/NP audit в†’ enforce.
- [x] WDAC enforce + SHA256 hash-allowlist.
- [x] AppLocker Exe + Dll + Script enforce.
- [x] Firewall block/unblock.
- [x] Quarantine/restore.
- [x] Suspend/resume.
- [x] Uninstall/rollback Рё reinstall/upgrade.
- [x] Watchdog: РѕСЃС‚Р°РЅРѕРІР»РµРЅРЅР°СЏ СЃР»СѓР¶Р±Р° РїРѕРґРЅРёРјР°РµС‚СЃСЏ.
- [x] Log maintenance 30 РґРЅРµР№.

## STML

- [x] Live Linux в†’ connector в†’ STML (1 guard report).
- [x] Live Windows в†’ connector в†’ STML (50 reports).
- [x] HTTPS self-signed.
- [x] mTLS: Р±РµР· cert reject, СЃ cert OK.
- [x] non-loopback bind С‚СЂРµР±СѓРµС‚ `--allow-remote`.
- [x] Р СѓСЃСЃРєРёР№ STML UI Рё РґРёРЅР°РјРёС‡РµСЃРєРёРµ СЃС‚Р°С‚СѓСЃС‹.
- [x] Р СѓСЃСЃРєРёР№ agent panel РІ РїРµСЂРµСЃРѕР±СЂР°РЅРЅРѕРј EXE/MSI.

## Р“РµР№С‚С‹ СЂРµР»РёР·Р°

- [x] РџР°РєРµС‚С‹ РїРµСЂРµСЃРѕР±СЂР°РЅС‹.
- [x] `objects.sha256` + РїРѕРґРїРёСЃСЊ.
- [x] Release manifest / SBOM.
- [x] CI workflow РґРѕР±Р°РІР»РµРЅ.
- [ ] CI СЂРµР°Р»СЊРЅРѕ РїСЂРѕРіРЅР°РЅ РЅР° GitHub.
- [ ] Clean-VM acceptance РЅР° С‡РёСЃС‚РѕРј Ubuntu/Windows.
- [ ] RPM live РЅР° Fedora/RHEL.

## РР·РІРµСЃС‚РЅС‹Рµ РѕРіСЂР°РЅРёС‡РµРЅРёСЏ

- AppLocker DLL enforcement РјРѕР¶РµС‚ РІР»РёСЏС‚СЊ РЅР° РїСЂРѕРёР·РІРѕРґРёС‚РµР»СЊРЅРѕСЃС‚СЊ.
- WDAC hashes РЅСѓР¶РЅРѕ РїРµСЂРµСЃС‡РёС‚С‹РІР°С‚СЊ РїРѕСЃР»Рµ РєР°Р¶РґРѕР№ СЃР±РѕСЂРєРё СЃРµСЂРІРёСЃР°.
- РќРµС‚ СЃРѕР±СЃС‚РІРµРЅРЅРѕРіРѕ Windows-РґСЂР°Р№РІРµСЂР°/PPL/ELAM.
- EV/WHQL/HDC Рё СЋСЂРёРґРёС‡РµСЃРєР°СЏ СЃРµСЂС‚РёС„РёРєР°С†РёСЏ вЂ” РІРЅРµ scope.

## Testing notes

- [x] pytest tests — pass.
- [x] pytest stml/tests — pass.
- [ ] Single-process full pytest after long session — Windows socket exhaustion (10048/10055); run after host reboot/cleanup.


## Build reproducibility

- [ ] Two builds of the same .deb are byte-identical: **NO** (2c5... vs db0b...). Timestamps/venv paths vary; not yet reproducible.

