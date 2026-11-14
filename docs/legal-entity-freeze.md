# Freeze register: legal-entity / external gates

Status: **frozen until an organization, budget or external specialist exists**.  
This file separates true legal-entity gates from tasks that only *look* blocked.

## A. Hard freeze — cannot be completed as an individual

| Item | Why it is blocked | What we can still do |
|---|---|---|
| **EV code-signing certificate** | EV is organization-validated; the Hardware Developer Program explicitly requires an organization, an Entra ID global admin, a legal contact authorized to sign agreements, and an EV certificate. | OV/individual code-signing may be available from some CAs (not EV); it does not enable driver submission. Test-signing for the lab remains possible. |
| **Partner Center / Hardware Dev Center** | Hardware program registration requires company details/D-U-N-S, legal contact and EV certificate. An individual Store developer account is a different program and does not grant driver-signing rights. | Use Microsoft Store individual account only for a user-mode app, not for a kernel driver. |
| **HLK / WHQL submission** | Submission and WHQL signing happen through Hardware Dev Center and the Windows Hardware Compatibility agreements. | Install HLK locally, run the tests, keep the report. This is useful evidence but not WHQL. |
| **Production driver signature** | Kernel drivers accepted by Secure Boot/CI require Microsoft attestation/WHQL signing tied to the Hardware Dev Center account. | Test-sign `AidfFilter.sys`, install in a VM with `testsigning on`, keep the lab contract. |
| **Legal contracts / liability / signed DPIA** | A legal opinion, DPA, terms of service and liability need a legal person/entity and a lawyer. | Technical DPIA draft, data map, retention schedule, privacy notice draft, incident runbook. |
| **Independent accredited pen-test / human review** | Independence and liability usually require an external specialist/firm and a contract. This is **not strictly a legal-entity requirement**: a sole-trader pentester can be hired. | Internal SAST/fuzz/chaos tests, threat models, bug-bounty-style self-review. Freeze only the *independent, contracted* version. |

## B. Not a legal-entity gate — we can do it ourselves

| Item | Why it is self-doable | Concrete path |
|---|---|---|
| **Production HSM/key custody** | Hardware HSMs are sold to individuals; no company registration is needed to buy/use one. | YubiHSM 2 / Nitrokey HSM + PKCS#11, offline ceremony, dual control, paper shares, audit log. SoftHSM remains dev-only. |
| **HLK test execution** | The HLK kit can be installed and run locally; only *submission* needs the program. | Install HLK, create a controller/studio, run the driver tests, archive the report. |
| **Test-signed driver** | Self-signed certificate + test-signing is a lab operation. | `driver/minifilter/build.ps1`, `sign.ps1`, `install.ps1` in a VM. |
| **User-mode agent packages** | EXE/MSI/deb/rpm do not require a legal entity to build. | Existing PyInstaller EXE, WiX MSI, deb/rpm; sign only if a certificate is available. |
| **Linux package signing** | GPG keys can be generated and used by an individual. | Sign deb/rpm metadata with a local GPG key; publish fingerprint. |
| **DPIA technical work** | GDPR DPIA can be drafted by a natural person; it is the legal sign-off that is external. | `docs/dpia-draft.md`: data map, risks, retention, mitigations. |
| **Internal security review** | SAST/fuzzing/chaos/pentest can be run by the developer; independence is the only missing property. | Existing SAST/fuzz/soak artifacts + threat models; keep results. |
| **OV code signing (if eligible)** | Some CAs issue OV certificates to individuals/sole traders with identity verification. | Ask CA for individual OV eligibility; it reduces SmartScreen warnings but is not EV and does not unlock WHQL. |

## C. Engineering-only freeze (not legal)

These are not legal-entity gates; they are infrastructure/tooling gates:

- Tauri signed desktop shell (WebView2 + Node/Tauri toolchain; signing cert separate).
- NATS/Kafka broker + auth/TLS/monitoring.
- PostgreSQL HA/quorum, off-site immutable backup.
- Rust/axum parity endpoints.
- Independent production monitoring/on-call.

## D. What “unfreeze” requires

1. **EV + Hardware Dev Center**: legal entity, D-U-N-S/company record, Entra global admin, legal contact, EV certificate.
2. **WHQL**: HLK report + Hardware Dev Center submission + signed agreements.
3. **Legal**: lawyer/DPO sign-off, DPA/terms, liability insurance.
4. **Independent review**: a contracted external tester with a defined scope and report.
5. **HSM**: purchase YubiHSM/Nitrokey, define dual-control ceremony, test restore/rotation.

## E. What we can do now without unfreezing

- [x] Linux auditd agent + STML reports + tests.
- [x] Local agent panel and confirmations.
- [x] Signed A/B updates.
- [x] Linux deb/rpm build; Windows EXE/MSI.
- [x] HLK-ready test plan (run locally, do not submit).
- [x] Test-signed driver lab.
- [x] Technical DPIA draft, threat models, SAST/fuzz/soak evidence.
- [x] HSM purchase/ceremony design (YubiHSM/Nitrokey) — hardware not yet bought.
- [ ] Buy HSM and execute the ceremony (self, no legal entity).
- [ ] Run HLK locally and archive the report (self).
- [ ] Contract an individual pentester, if independence is required (budget/contract, not legal entity).

## F. Verification of the “legal entity only” claim

Microsoft’s Hardware Developer Program registration page requires:

- an organization Dev Center account or Microsoft Entra ID company directory;
- a legal contact authorized to sign agreements on behalf of the organization;
- an EV code-signing certificate.

Source: [Register for the Microsoft Windows Hardware Developer Program](https://learn.microsoft.com/en-au/windows-hardware/drivers/dashboard/hardware-program-register).

That is the concrete basis for freezing EV, Hardware Dev Center, HLK/WHQL submission
and production driver signing. The other items in section A are legal/contractual,
not technical.
