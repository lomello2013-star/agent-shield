# Security policy

## Scope

This repository is a **research prototype** of a user-mode EDR. It is not
approved for production endpoints and has known open gates (see
[release-checklist.md](docs/release-checklist.md)).

## Reporting a vulnerability

Do not open a public issue with exploit details. Contact the project owner
through the private channel agreed for the pilot and include:

- affected component and version/commit;
- reproduction steps or a minimal proof of concept;
- impact assessment (local privilege, data loss, bypass, etc.);
- whether the issue is already public.

Target acknowledgement: 48 hours; triage: 5 business days.

## Secrets

- `secrets/` is excluded from git.
- The current `secrets/dev_keys.json` is a **development** Ed25519 key and must
  never sign production ModelPacks.
- Production signing keys belong in an HSM/CI secret store, not on the host.
- `AIDF_AUTHKEY` / `AIDF_TOKEN` are runtime secrets; do not pass them on the
  command line in shared shells.

## Supported versions

Only the current `main` snapshot is supported during development. There are no
backported security releases yet.
