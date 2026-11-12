# Changelog

All notable changes are recorded here. The project does not yet have a public
release; versions are development snapshots.

## [0.1.0] — 2026-11-13

### Added

- User-mode EDR prototype: ingest, normalization, 28 rules, policy gate,
  reversible response, self-protection, JSON-RPC IPC, signed ModelPack and
  shadow ML.
- Contract v3.0 JSON schemas (21 files).
- Reliability/chaos harnesses, ATT&CK coverage harness, measurement artifacts.
- Rust port of 12 modules with Python-wire IPC (TCP/named pipe/AF_UNIX),
  full 50k ML holdout, gate and release benchmark.
- Release engineering baseline: README, license placeholder, security policy,
  `.gitignore`, build metadata, CI workflow, release checklist.

### Known limitations

- No Windows kernel driver / ETW-TI / WFP; blockers A/B/D.
- R1/R4 not proven: native `0xC0000005` in long soak.
- E7 (0.6724 @0.05 % FPR) and E12 (13.3 % FBR audit) not met.
- No independent auto-review or human acceptance.
- Rules/models not fully packaged for installation outside the checkout.
