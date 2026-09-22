# Threat Report Agent

Evidence-backed static malware analysis and report generation for the first project phase.
Unknown samples are never executed. Human reference reports are not accepted by the analysis
API and remain isolated for post-analysis evaluation.

## Current vertical slice

- Case and immutable Analysis Task input snapshot
- Content-addressed blobs and provenance-preserving Artifacts
- Bounded folder-equivalent ZIP intake with nested archive layering
- Deterministic file identity, PE structure/import parsing, strings and entropy
- Static decryption, loader, C2/network and anti-analysis indicators
- ToolRun to anchored Evidence to Claim/Relation to Analysis Snapshot trace
- Structured, redacted analysis-process view at
  `/api/v1/tasks/{task_id}/analysis-trace` and in the Web UI; it exposes
  observable steps and provenance links, never private model chain-of-thought
- Full JSON analysis package and selectable Markdown/DOCX/PDF report revisions
- Manual report edits as immutable MANUAL_EDIT revisions
- Input Gate for unsafe, encrypted or over-budget archives
- Model-driven, policy-gated action planning with dependency-aware scheduling and
  evidence-driven replanning; deterministic coverage remains the fallback
- Versioned FastAPI and a minimal replaceable Web client
- Local folder submission through the CLI with relative-path preservation

Ghidra Headless is active when `GHIDRA_HOME` and `JAVA_HOME` are configured. It imports a
temporary copy of a PE, exports functions/Xrefs/CFG, and never executes the sample. A missing
or failed Ghidra runtime still produces an explicit failed ToolRun and a PARTIAL outcome instead
of a false success. Temporal and the model gateway retain their configuration boundaries for the
next platform iteration.

## Local development

Use a dedicated virtual environment because the workstation may contain unrelated Python
applications with incompatible dependency pins.

    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install -e '.[dev]'
    $env:DATABASE_URL='sqlite:///./.data/threat-agent.db'
    $env:CONTENT_STORE_PATH='.data/content'
    python -m uvicorn threat_report_agent.main:app --reload

Open http://127.0.0.1:8000. API documentation is available at
http://127.0.0.1:8000/docs.

Submit one sample or a local sample folder through the same analysis chain:

    threat-report-agent analyze "D:\path\to\sample-folder" --title "Folder analysis"

The Web UI accepts multiple files in one submission. They are wrapped in a
read-only ZIP package and analyzed as one breadth-first task, preserving each
file as a separate Artifact under the batch root. Script imports and calls are
promoted into evidence-backed behavior Claims; a file with no behavior rule
hit receives an explicit static profile Claim instead of an empty report.

The Semantica design reference assessment is in
`docs/semantica-reference-evaluation-20260823.md`. Semantica is not installed
as a runtime dependency; its system-level provenance ideas are applied while
PostgreSQL and the append-only audit chain remain authoritative.

The generic investigation loop and the structured scheduler contract are described in
`docs/dynamic-investigation-planning.md`.

## Container deployment

Copy .env.example to .env, set deployment credentials outside source control, and set `CONTAINER_REGISTRY_PREFIX` to a reachable registry mirror when Docker Hub is unavailable. Start Docker
Desktop, then run:

    docker compose up --detach

On Windows, double-click `Start-ThreatReportAgent.bat`. That is the normal start
path: it starts Docker Desktop when needed, rebuilds the API and `emu-worker`
images when backend Python or Compose files changed, starts Compose (including
the isolated emulator worker), starts the pinned DSH `threat-static` profile,
checks health, and opens `http://127.0.0.1:3080/`. Use
`Start-ThreatReportAgent.bat -BuildApi` to force those image rebuilds. It never
removes containers, images, or data volumes. The desktop shortcuts **Threat
Report Agent** and the migrated **DSH Desktop** shortcut both point to this same
product launcher; do not start the upstream `DSH Desktop.exe` directly, because
it does not load the Threat Workbench profile. The
launcher starts ordinary services from existing images and never rebuilds the Ghidra
worker during a normal launch. To intentionally rebuild that worker after changing its
Dockerfile or replacing the trusted local archive, use
`Start-ThreatReportAgent.bat -BuildGhidra`. It verifies the local archive SHA-256,
serves only that file on a temporary loopback listener, and stops the listener when the
build completes. To stop the services without deleting data, double-click
`Stop-ThreatReportAgent.bat` (it runs `docker compose stop`).

The first-stage default is a deterministic static agent. The product does not
ship a backend analysis model. Use the authenticated **模型配置** panel to
save the single provider, endpoint, model name, and API key that analysis,
planning, and DSH `model/complete` will share. Keys are sent over the same-origin
API, encrypted at rest with `MODEL_CONFIG_SECRET_KEY` (or the deployment
`GATE_SECRET_KEY` fallback), and never returned to the browser. Optional `.env`
`MODEL_PRIMARY_*` / `MODEL_FALLBACK_*` values are only a user-owned bootstrap;
leave them empty unless you are recovering a deployment without the UI.

    MODEL_CONFIG_SECRET_KEY=replace-with-a-long-random-server-secret
    MODEL_CALLS_ENABLED=true

The UI shows the active mode and whether credentials are configured. Provider credentials
stay on the API server and are not copied into browser storage, task evidence, or reports.

The Ghidra worker is part of the default worker topology. Runtime startup requires its
already verified image. For a deliberate local rebuild, keep the versioned release ZIP in
`.tools`, configure its exact version and SHA-256 in `.env`, then run:

    powershell -ExecutionPolicy Bypass -File scripts\build-ghidra-worker.ps1

The build helper overrides `GHIDRA_ZIP_URL` only for the child Docker build with a temporary
`host.docker.internal` loopback URL. It does not use a stale server from a previous session.

The worker runs without elevated capabilities, without network access, with a read-only root
filesystem and an ephemeral output directory. GHIDRA_HOME is only an explicit local
development override.

## Verification

The fail-closed Round 9 release gate records its result in
`.scratch/round9-release-gate.json`:

    python scripts/round9_release_gate.py

It exits non-zero until Docker E2E and fresh Resume/ComHost benchmarks are
available. The individual machine-independent checks are:

    python -m pytest -q
    python -m ruff check src tests
    node --check src\threat_report_agent\static\app.js
    docker compose config --quiet
