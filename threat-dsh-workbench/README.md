# Threat Analysis Workbench

Independent Threat Analysis Workbench UI and integration layer for the DSH
runtime. The backend is the only domain authority; this workspace contains
adapters, typed tools, event projections, profile composition, and UI extension
points. The runtime is an implementation dependency, not the product identity.

The workspace targets DSH commit
`47f943859bef60e4160492346772ded9b24f765a`. It is intentionally separate from
the upstream checkout. Install it into a DSH profile using the profile tooling
from the pinned Harness checkout; do not copy these files into `packages/` in
that checkout.

## Product isolation

The Windows launcher sets `DSH_HOME` to
`D:\\threat report agent\\.data\\dsh-threat-static`. This directory is created
on demand and contains only the Threat Workbench profile and its own sessions.
The user's existing `%USERPROFILE%\\.dsh` is never copied, modified, or deleted.
The `@threat-dsh/brand` plugin replaces the browser title, favicon, logo, and
legacy visible product labels with the Threat Workbench identity.

On the first launch after this migration, the launcher removes only pre-existing
sessions, workspace records, credentials, anonymous identifiers, and settings
inside the product-owned `.data\\dsh-threat-static` directory, then writes the
`.threat-workbench-home-v1` marker. Later launches retain Threat Workbench
sessions. The pinned DSH package names remain internal loader identifiers needed
by the runtime and are not product-facing labels, URLs, or stored user data.

## Security

The `threat-static` profile exposes only bounded, read-only backend tools. No
shell, terminal, arbitrary code, web fetch, sample execution, or sample-directed
networking is registered. Tool calls are proposals to the backend, which
enforces Policy, Action Catalog, Temporal, and Worker boundaries.

## Packages

- `threat-plugin-sdk`: versioned manifest and role contracts.
- `threat-api-client`: task-scoped backend client with bounded responses.
- `threat-tool-provider`: DSH `defineTool` registrations for capabilities and
  evidence queries.
- `threat-model-gateway`: single-route model request adapter contract.
- `threat-session-events`: backend-event to durable DSH event projection.
- `threat-context-provider`: bounded context assembly for agent turns.
- `threat-ui-*`: extension-point UI contributions.

Run `node scripts/validate-manifests.mjs` and the Python pluginability contract
tests from the parent project before release.

The supported Windows product launcher is the parent project's
`Start-ThreatReportAgent.bat`; it starts the backend and DSH `threat-static`
profile on fixed ports. This workspace also provides the machine-independent
checks below:

```powershell
npm run typecheck
npm test
npm run test:runtime
npm run manifest
npm run security
npm run legacy-guard
npm run core-guard
npm run smoke:dsh
```
