# Round 9 Architecture Final

Round 9 adopts DeepSeek Harness (DSH) as the supported analyst product shell and
keeps the Python service as the only Threat Domain Truth. DSH owns conversation,
trajectory, session persistence, and presentation. The backend owns Case,
Artifact, ToolRun, Evidence, Claim, Mechanism, Investigation, policy, Temporal
execution, reports, and audit.

Threat-specific code is out-of-tree under `threat-dsh-workbench`. The upstream
Harness checkout is pinned and is never patched with threat business logic. DSH
talks to the versioned `/api/v1/workbench/*` contract only; it does not access
PostgreSQL, MinIO, or Temporal directly.

The security boundary is static-only. Model proposals are untrusted input,
must cite backend evidence, and are checked by the backend Action Catalog and
Policy before any read-only static worker action. Sample execution, arbitrary
subprocesses, web fetches, and sample-directed networking are unavailable in
the `threat-static` profile.

## Migration decisions

- DSH upstream: `47f943859bef60e4160492346772ded9b24f765a` (`v24.14.0`).
- Backend source lock: `.scratch/backend-source-manifest.sha256`.
- Backend has no Git repository in this workspace, so the source manifest is
  the reproducible lock and is recorded as such in `dsh-upstream-lock.md`.
- Existing `/api/v1/tasks/*` APIs remain compatibility/headless APIs. New DSH
  integrations use `/api/v1/workbench/*`.
- A task has at most one primary DSH session mapping. DSH session events carry
  bounded identifiers and summaries; complete Evidence remains backend data.

## Extension rule

New tools, views, event projectors, context providers, and report sections are
implemented as plugins or backend capabilities plus a manifest. No DSH core
change is required. The acceptance fixture under
`threat-dsh-workbench/examples/threat-plugin-template` demonstrates this rule.

The supported Windows launcher is `Start-ThreatReportAgent.bat`; it starts the
backend Compose stack and DSH `threat-static` on fixed ports (`8000` and
`3080`). `Stop-ThreatReportAgent.bat` stops services without deleting volumes.
