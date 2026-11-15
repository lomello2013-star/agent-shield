# Р§РµРє-Р»РёСЃС‚ РїРёР»РѕС‚РЅРѕРіРѕ СЂРµР»РёР·Р° AIDefender/STML

РЎС‚Р°С‚СѓСЃ: **pilot / lab-only**. РќРµ production. EV/WHQL/HDC Рё СЋСЂС‡Р°СЃС‚СЊ Р·Р°РјРѕСЂРѕР¶РµРЅС‹.

## Linux вЂ” РїСЂРѕРІРµСЂРµРЅРѕ

- [x] Ubuntu 24.04 VM, СЃС‚Р°С‚РёС‡РµСЃРєРёР№ IP `172.23.213.50/20`.
- [x] Р’С…РѕРґ РїРѕ SSH-РєР»СЋС‡Сѓ.
- [x] BPF LSM РІРєР»СЋС‡С‘РЅ: `lsm=lockdown,capability,landlock,yama,apparmor,bpf`.
- [x] `aidf-ebpf-guard.service` Р°РєС‚РёРІРµРЅ РїСЂРё Р·Р°РіСЂСѓР·РєРµ.
- [x] eBPF exec deny: `/tmp/t2` в†’ `Permission denied` (RC 126), РїРµСЂРµР¶РёРІР°РµС‚ reboot.
- [x] `apt-get update` РїРѕРґ enforce: `APT_RC=0`.
- [x] `.deb` Рё `.rpm` СЃРѕР±СЂР°РЅС‹ Рё СѓСЃС‚Р°РЅРѕРІР»РµРЅС‹.
- [x] РџРѕРґРїРёСЃР°РЅРЅС‹Р№ РјР°РЅРёС„РµСЃС‚ РѕР±СЉРµРєС‚РѕРІ (`objects.sha256` + `.sig`).
- [ ] eBPF write-deny РїРµСЂРµРїСЂРѕРІРµСЂРёС‚СЊ РЅР° С„РёРЅР°Р»СЊРЅРѕР№ VM.
- [ ] fanotify СѓРґР°Р»С‘РЅ; fallback вЂ” С‚РѕР»СЊРєРѕ auditd.

## Windows вЂ” РїСЂРѕРІРµСЂРµРЅРѕ

- [x] Onedir-СЃР»СѓР¶Р±Р° РІ `C:\Program Files\AIDefender\service`.
- [x] РЎР»СѓР¶Р±Р° `AIDefender` Running РїРѕСЃР»Рµ reboot.
- [x] Sysmon64 Running; СЃРѕР±С‹С‚РёСЏ `win.sysmon` РїРёС€СѓС‚СЃСЏ.
- [x] Defender ASR/CFA/NP: audit в†’ enforce.
- [x] WDAC enforce СЃ SHA256 hash-allowlist (`AIDefender Enforce HashAllow`, IsEnforced=True).
- [x] AppLocker enforce РґР»СЏ **Exe + Dll + Script**; allow-РїСЂР°РІРёР»Р°:
  - `%WINDIR%\*`
  - `%PROGRAMFILES%\*`
  - `C:\Program Files\AIDefender\*`
- [x] Firewall block/unblock, quarantine/restore, suspend/resume РїСЂРѕРІРµСЂРµРЅС‹ РЅР° benign-РѕР±СЉРµРєС‚Р°С….
- [x] Service recovery + ACL hardening РїСЂРёРјРµРЅРµРЅС‹.
- [ ] РџРѕСЃР»Рµ Р»СЋР±РѕРіРѕ РёР·РјРµРЅРµРЅРёСЏ Р±РёРЅР°СЂРЅРёРєРѕРІ РїРµСЂРµСЃРѕР±СЂР°С‚СЊ WDAC hash-allowlist.

## STML

- [x] guard event в†’ connector в†’ STML report (`kind=guard`) РІ WSL.
- [x] РџРѕР»РЅС‹Р№ `pytest` вЂ” pass.
- [ ] Live end-to-end РЅР° С„РёРЅР°Р»СЊРЅРѕР№ Linux VM.

## Р“РµР№С‚С‹ СЂРµР»РёР·Р°

- [ ] РџРµСЂРµСЃРѕР±СЂР°С‚СЊ РїР°РєРµС‚С‹ СЃ С„РёРЅР°Р»СЊРЅРѕРіРѕ РєРѕРјРјРёС‚Р°.
- [ ] РџРµСЂРµСЃС‡РёС‚Р°С‚СЊ `objects.sha256` + РїРѕРґРїРёСЃСЊ.
- [ ] РџРµСЂРµСЃС‡РёС‚Р°С‚СЊ WDAC hash-allowlist РїРѕСЃР»Рµ РїРµСЂРµСЃР±РѕСЂРєРё СЃРµСЂРІРёСЃР°.
- [ ] РџСЂРёС‘РјРѕС‡РЅС‹Р№ РїСЂРѕРіРѕРЅ РЅР° С‡РёСЃС‚С‹С… Linux + Windows VM.
- [ ] РќРµ Р·Р°СЏРІР»СЏС‚СЊ production; РїСЂРёР»РѕР¶РёС‚СЊ СЌС‚РѕС‚ С‡РµРє-Р»РёСЃС‚ Рє РїРёР»РѕС‚Сѓ.

## РР·РІРµСЃС‚РЅС‹Рµ РѕРіСЂР°РЅРёС‡РµРЅРёСЏ

- AppLocker DLL enforcement РјРѕР¶РµС‚ РІР»РёСЏС‚СЊ РЅР° РїСЂРѕРёР·РІРѕРґРёС‚РµР»СЊРЅРѕСЃС‚СЊ; РїСЂРѕРІРµСЂСЏС‚СЊ РЅР° С†РµР»РµРІРѕРј РџРљ.
- WDAC-С…РµС€Рё РїСЂРёРІСЏР·Р°РЅС‹ Рє РєРѕРЅРєСЂРµС‚РЅРѕР№ СЃР±РѕСЂРєРµ.
- РќР° Windows РЅРµС‚ СЃРѕР±СЃС‚РІРµРЅРЅРѕРіРѕ РґСЂР°Р№РІРµСЂР°; РЅРµС‚ PPL/ELAM.
- EV/WHQL/HDC Рё СЋСЂРёРґРёС‡РµСЃРєР°СЏ СЃРµСЂС‚РёС„РёРєР°С†РёСЏ вЂ” РІРЅРµ scope.




- [x] Approval -> ResponseExecutor -> QuarantineStore test (real quarantine).

