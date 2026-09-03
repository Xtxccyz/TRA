# Round 9 Release Acceptance

## Current decision

**BLOCKED (2026-08-27).** Code-level checks and the out-of-tree plugin/runtime
acceptance pass. The Docker Desktop Linux engine is unavailable on this host,
so clean Compose startup, real Resume/ComHost browser E2E, and worker failure
injection cannot be signed off. Docker Desktop's host log reports an
Inference-manager startup failure on the reparse-point path
`%LOCALAPPDATA%\\Docker\\run\\dockerInference`, then shuts down every Linux
engine. The machine-independent gate writes its exact result to
`.scratch/round9-release-gate.json`.

## Verified without Docker

- DSH upstream is pinned to `47f943859bef60e4160492346772ded9b24f765a` and is clean.
- Backend source manifest and API/event/report contracts are present.
- Workbench TypeScript, static tests, runtime pluginability, manifests,
  security profile, legacy guard, and DSH core diff guard pass.
- The event bridge rejects initial sequence gaps, out-of-order pages, and
  backwards `next_seq`; successful appends persist the cursor.
- The threat-static model-facing profile exposes zero arbitrary shell,
  filesystem, web, subprocess, workflow, or subagent tools.

## Docker-required gates (not signed off)

- Compose clean start and one-command startup transcript.
- PostgreSQL/MinIO/Temporal/Worker recovery drills.
- Real browser upload and refresh/restart recovery.
- Resume and ComHost benchmark reports, negative-gold checks, and report-size
  measurements from a freshly built image.

## Historical artifact warning

`.scratch/round8-resume-comhost-docker-report-v3.md` is 620,574 bytes and is
therefore a failed historical Report V2 anti-bloat artifact. It is retained as
audit evidence only; it is not a release report. A fresh run must be generated
after the current 40 KiB report gate is deployed.

## Release blockers

Open P0/P1 defects must be zero. The release is blocked by sample execution,
sample-directed networking, unsupported critical claims, lost/duplicate event
sequences, DSH core threat patches, model-gateway bypass, policy bypass,
legacy WebUI in the production profile, unavailable clean-start evidence, or
failed Resume/ComHost critical gates.

## Reproducible commands

```powershell
python scripts/round9_release_gate.py
cd threat-dsh-workbench
npm run typecheck
npm test
npm run test:runtime
npm run manifest
npm run security
npm run legacy-guard
npm run core-guard
npm run smoke:dsh
```

The command exits non-zero while Docker or either real-sample benchmark is
blocked. This is intentional and is the release gate's fail-closed behavior.
