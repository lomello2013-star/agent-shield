# Windows kernel trust: CKS, WHCP, preproduction, test signing

Status: research note. This does not change the production scope.

## Executive summary

**Custom Kernel Signers (CKS)** is a real, Microsoft-supported mechanism. It lets an
organization trust its own kernel signers without a WHCP signature for every
driver. It is **not** a general bypass for consumer PCs and **not** a path to a
market product.

For the current host:

- OS is **Windows 10 Pro 19045**; CKS's documented platform requirement is
  Windows 11 24H2+ (AMD64) with the April 2026 non-security update (or later).
- CKS requires a **clean install/reset** and control of UEFI **PK/KEK**.
- We do not have a production kernel driver; only a lab minifilter.
- Therefore CKS is **not applicable to this working PC in its current state**.

## Options matrix

| Option | What it gives | Requirements | Applicability |
|---|---|---|---|
| **Custom Kernel Signers (CKS)** | Own kernel signers trusted without per-driver WHCP, via App Control policy anchored in Secure Boot PK/KEK | Windows 11 24H2+ non-Home, April 2026+ update, clean install/reset, UEFI 2.3+, physical PK/KEK control, own PKI/HSM, policy management, HVCI compatibility | Controlled/air-gapped devices only; not arbitrary user PCs; not this Windows 10 host |
| **WHCP + Hardware Dev Center** | Production WHQL signature, distributable driver | EV certificate, HLK, HDC account, legal agreements, fees | Market product; unavailable to an individual in Russia |
| **Preproduction signing** | Load test drivers with Secure Boot enabled on prepared test devices | EV certificate + HDC; `EnableUefiSbTest.exe`; test Secure Boot policy; test device only | Development/testing only; still blocked by EV/HDC |
| **TESTSIGNING** | Self-signed driver loads | Secure Boot disabled, test mode; no production trust | Lab only; weakens the whole OS |
| **Cross-signed CA** | Old driver trust path | — | Removed by April 2026 Windows updates; dead |
| **Sysmon** | Kernel telemetry with Microsoft-signed driver | Admin install | Available; no own driver |
| **Defender ASR/CFA/WDAC/AppLocker** | Prevention/blocking without own driver | Windows policy/admin | Available |
| **Linux eBPF LSM** | Real kernel enforcement on Linux | Linux kernel with BPF LSM; root | Available for Linux, not Windows |

## What CKS actually does

Official docs: [Custom kernel signers for App Control for Business](https://learn.microsoft.com/en-ca/windows/security/application-security/application-control/app-control-for-business/design/custom-kernel-signers).

Trust chain:

1. Secure Boot **PK/KEK** — root of trust, controlled by platform owner/OEM.
2. An App Control policy signed by a PK/KEK authority.
3. The policy lists trusted kernel signers (your PKI; optionally Microsoft/WHCP).
4. Windows Code Integrity checks every driver against that policy.

Important consequences:

- It **does not** make an unsigned driver trusted on normal PCs.
- It **does not** remove the need to build and sign the driver with your PKI.
- It **does not** solve HVCI incompatibilities; a driver can be policy-trusted
  but still rejected by HVCI.
- The signed policy is sticky: removing it without a valid replacement can make
  Windows unbootable; recovery requires UEFI access.
- A mistake in UEFI keys can brick the device.
- It is intended for **classified/sensitive/air-gapped/internal** environments,
  not public distribution.

## Preproduction signing

Official docs: [How to test preproduction drivers with Secure Boot enabled](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/preproduction-driver-signing-and-install).

- Requires a **Hardware Dev Center** submission and **EV**.
- Produces a **preproduction WHQL/WHCP signature**.
- Requires provisioning the test device with `EnableUefiSbTest.exe` and a
  Secure Boot policy.
- Not for retail/production systems; not a WHCP replacement.
- For us: blocked by the same EV/HDC gate.

## Current host check

```text
Windows 10 Pro 10.0.19045 (64-bit)
```

CKS is documented for **Windows 11 24H2+** (AMD64) with the April 2026 update.
This host is not eligible without an OS upgrade/clean install. Even then, the
UEFI firmware must allow PK/KEK changes; many OEM devices do not.

## Recommendation

### For this working PC

**Do not attempt CKS.** It requires an unsupported OS change, clean install,
UEFI key replacement and a production driver. The risk/benefit is bad.

Use:

- Windows Defender (prevention);
- Defender ASR / Controlled Folder Access (prevention);
- WDAC/AppLocker (execution control);
- Sysmon (signed driver telemetry);
- our user-mode agent for detection/response/STML.

### For a dedicated lab PC (optional)

Only if you have a spare machine and can afford to lose/reset it:

1. Clean install Windows 11 24H2+ non-Home.
2. Confirm UEFI 2.3+, Secure Boot, and PK/KEK control.
3. Build a minimal test driver.
4. Create CKS App Control policy in **Audit** mode first.
5. Test HVCI compatibility.
6. Only then Enforce, with recovery media.

This is a lab experiment, not a product.

### For a product

- No legal path as an individual in Russia.
- Need an organization with EV/HDC/WHCP, or license/partner with an existing
  signed-driver vendor.
- Otherwise: no own Windows kernel driver; use Defender/Sysmon/WDAC and Linux
  eBPF where applicable.

## Bottom line

CKS is the **only official non-WHCP trust path**, but it is for
**controlled/air-gapped devices**, requires a clean install and firmware key
control, and still leaves you with driver engineering, HVCI and recovery risk.
It does not turn this project into a marketable Windows EDR.
