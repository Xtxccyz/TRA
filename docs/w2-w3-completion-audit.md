# W2/W3 Completion Audit

Date: 2026-08-03

This audit is the current implementation record for rows W2 and W3 of the
`多智能体的深度逆向应用` worksheet. It supersedes the earlier provisional
statements in `implementation-status.md` for these two work packages.

## W2 Input And Platform

| Requirement | Implementation and verification |
|---|---|
| Frozen preset catalog and four input channels | Strict Pydantic `FourChannelInput`, frozen `first-phase-full-static@1.0.0` catalog, and catalog SHA-256. Extra channels are rejected. Tested in `test_platform_contracts.py`. |
| Case, Analysis Task, Artifact, and status codes | SQLAlchemy domain records plus separate task lifecycle, analysis outcome, ToolRun, Claim, and Report state enums with guarded transitions. |
| FastAPI, PostgreSQL, object storage, LangGraph | Versioned FastAPI control plane; PostgreSQL/MinIO/Temporal Compose services; selectable local or S3/MinIO content-store adapters; compiled LangGraph investigation graph. The production-shaped Compose stack and persistence path were exercised successfully. |
| Hash, Magic/MIME, read-only intake, audit | SHA-256/SHA-1/MD5 identity, magic/MIME result and source, content-addressed write-once storage with re-read hash verification, bounded ZIP/folder intake, and task audit API at `GET /api/v1/tasks/{task_id}/audit`. |
| Prompt, tool and resource controls | Versioned prompt manifest and hashes, untrusted-context separation, hard sample-execution/network denial, CPU/memory budgets, and five queue-specific Worker allowlists: `static-intake`, `static-parser`, `static-script`, `static-document`, and `static-ghidra`. |

## W3 Deterministic Static Extraction

| Requirement | Implementation and verification |
|---|---|
| Ghidra Headless | `GhidraHeadlessRunner` imports only a temporary copy of a PE and runs `ExportStaticFacts.java`. A real run against `C:\Windows\System32\notepad.exe` succeeded with 519 functions, 2,600 Xrefs, 6,512 CFG blocks, symbols, and 519 per-function SimHash values. |
| PE parsing | Sections, imports, exports, entry RVA, strings and entropy. Export tests assert names, ordinals, function RVA, and anchors. |
| Script parsing | Python AST and conservative PowerShell/JS/VBS/BAT lexical extraction; functions, imports, calls, indicators, and script-line anchors are preserved without loading or executing scripts. |
| Document carriers | PDF metadata/pages/URLs/JavaScript/embedded-object markers; OOXML relationships, VBA markers, and embedded paths; OLE detection with explicit limitations where a stream cannot be parsed. Anchors use PDF object or OOXML internal path. |
| Function fuzzy fingerprint | Finished 64-bit Charikar SimHash contract: normalized mnemonic 4-grams, MD5-prefix 64-bit feature hashes, and Hamming distance. Ghidra output and `function_simhash` Evidence carry version-identifying metadata; exact-output and distance behavior are tested. Future robustness work is retained in `docs/function-simhash-evolution.md` and is not part of phase one. |
| Triage and static agents | Formal `TriageAgent` and `StaticAnalysisAgent` use versioned prompt metadata and deterministic fallbacks. The static Agent consumes persisted function/Xref/CFG Evidence and creates at most ten conservative function-review Candidate Claims with categorical confidence. |
| Persistence and trace | Type-specific ToolRuns (`pe-parser`, `script-parser`, `document-carrier-parser`, `ghidra-headless`) feed anchored Evidence, ClaimEvidence links, and audit events. Real Temporal results were persisted by content reference in MinIO and materialized as PostgreSQL ToolRun/Evidence records. |

## Production-Shaped Integration Evidence

- Running services: FastAPI, PostgreSQL 16 with pgvector, MinIO, Temporal 1.27.2,
  and five isolated intake/parser/script/document/Ghidra Workers.
- Worker runtime: Python 3.12.13, Temurin JDK 21.0.11, and Ghidra 12.1.2.
- Worker isolation: read-only root filesystems, capability drop, no-new-privileges,
  internal-only network, PID/CPU/memory limits, queue-specific tool allowlists,
  and ephemeral tmpfs work areas.
- Real input: `C:\Windows\System32\notepad.exe`, SHA-256
  `db1131b5060bcfad80fc21d7bd333d9a7de3eee5190c5586d0a3a096fd563b87`.
- API task: `ef801c96-8a3d-4749-aeda-ae0689e115fa`; intake, `pe-parser`, and
  `ghidra-headless` are `SUCCEEDED` on their distinct queues.
- Temporal workflows: intake
  `toolrun-af828cfb2d35acf21e9d70579a8d1fe940718795be5800c871367baa4041ba3f`,
  parser `toolrun-304074d5d974fa7482d908c666a4fc1e8493596754a4e9987234a8c7ce3a0311`,
  and Ghidra `toolrun-8dad5a5fea6ced7e3c6780da77d37993ee77e50ef599a4ba6583df3d9ca70d3a`
  all closed as `WORKFLOW_EXECUTION_STATUS_COMPLETED`.
- MinIO output:
  `sha256/c8/c4/c8c47dd62e79ec7973e0adcfe73fda42d4d68778cc39aee0ed0adc5081bcbedb`,
  2,589,734 bytes. Its payload reports 519 functions, 2,600 Xrefs, 6,512 CFG
  blocks, and 519 fuzzy fingerprints.
- PostgreSQL records 13 Evidence objects for `pe-parser` and 15,562 for
  `ghidra-headless` (15,575 total), plus 14 Candidate Claims. Ghidra's
  2,589,734-byte raw result remains in MinIO while its PostgreSQL ToolRun output
  is a 117-byte count summary with an immutable object reference.
- Audit integrity is valid across all 38 current task events. The HMAC-SHA256
  task-terminal seal covers sequence 36; sequences 37-38 record report
  generation/recomposition from the same immutable Analysis Snapshot, and the
  extended chain verifies with no errors.
- Synthetic archive task `8cf5f29a-52c8-4f1c-802a-7a9ab23bb410` expanded a
  ZIP containing a script and DOCX into 20 referenced Artifacts. All 21 ToolRuns
  succeeded across `static-intake`, `static-parser`, `static-script`, and
  `static-document`. Its MinIO intake manifest contains object hashes/keys and
  no inline sample payload. A real cross-queue `pe-parser` request sent to
  `static-script` returned `TOOL_NOT_ALLOWED_ON_WORKER` before object access.
- Full-module report revision `baf5a405-8a19-464f-ae5b-e6b4703b1992` retains
  all 15,575 Evidence IDs in its machine trace while grouping human-facing
  evidence rows. Markdown is 29,252 bytes and downloaded in 0.017 seconds;
  DOCX is 46,097 bytes, downloaded in 0.295 seconds, and reopened successfully
  with `python-docx`.
- The task analysis outcome is `PARTIAL` only because no primary model is
  configured and deterministic report wording was used. This is outside the
  W2/W3 deterministic extraction acceptance criteria; neither static ToolRun
  failed.

## Cancellation, Recovery, And Rebuild Evidence

- The rebuilt API image is
  `sha256:dbb934cf50542638ae2cff857520b71528c9ff3d6c7f4be7e9a7c4c30beb72ce`.
  The clean Ghidra Worker image is
  `sha256:7f7d7dbbd5047c2726f3e7a154025206339152c45566618b461a4eb098fe8e26`.
  The Worker build completed in 385.6 seconds through the Tsinghua Debian
  mirror and the HTTPS `ghfast.top` GitHub accelerator. The downloaded Ghidra
  archive still passed the pinned official SHA-256, single-top-level-directory,
  and `ghidra_12.1.2*` version checks.
- Cancellation task `5e98c1f3-a496-431d-82bd-73b6a932b0fa` was cancelled
  while `ghidra-headless` was `RUNNING`. The public cancel API returned 200
  in 23.979 seconds (24.341 seconds client-observed). PostgreSQL records the
  Task as `CANCELLED` and the Ghidra ToolRun as
  `CANCELLED/GHIDRA_CANCELLED`. Temporal Workflow
  `toolrun-3447fcd64cb22957ce1e9ad34e0f005ef74054eb7d655b63aefb446f445b9186`
  closed with `EVENT_TYPE_WORKFLOW_EXECUTION_CANCELED`. The Worker process
  tree retained only its Python poller after cancellation. Its 5,021-event
  audit chain is valid and has an HMAC-SHA256
  `analysis_task.cancelled` terminal seal.
- Recovery task `6e9feb66-774f-43e4-9304-611e0cd18dc2` restarted the only
  Ghidra Worker while `execute_static_tool` was active. Temporal retried the
  same scheduled Activity as attempt 2, Workflow
  `toolrun-67d9ca9c953a1fb88f004b342bdc8f359a5dee3aa2a2ab013f75272ab2a30df5`
  closed as `WORKFLOW_EXECUTION_STATUS_COMPLETED`, and all three ToolRuns
  succeeded. The Task finished `SUCCEEDED/PARTIAL`, persisted 308,695
  Evidence rows, and produced a valid 5,030-event audit chain with a signed
  `analysis_task.succeeded` terminal seal. No Ghidra or Java process remained
  after completion.

## Verification Record

- `python -m pytest -q`: 64 passed.
- Regression coverage includes Temporal payload/idempotency, referenced
  content, retry/heartbeat/cancellation, per-Worker allowlists, failed ToolRun
  persistence, Ghidra delegation, nested function/Xref/CFG Evidence, categorical
  Claim confidence, and bounded editable report rendering.
- `python -m ruff check src tests scripts/verify_ghidra.py`: passed.
- `python -m ruff format --check src tests scripts/verify_ghidra.py`: passed
  for all 33 controlled Python files. Sample corpora, review snapshots, and
  third-party skill scripts are intentionally outside the application lint
  boundary.
- `python -m py_compile` for service, tool execution, Ghidra adapter, config,
  and CLI: passed.
- `python -m compileall -q src tests scripts/verify_ghidra.py`: passed.
- `node --check src\threat_report_agent\static\app.js`: passed.
- `docker compose -f docker-compose.yml --profile tooling config --quiet`: passed.
- Ghidra installation: `Ghidra 12.1.2`, local ZIP SHA-256
  `b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d`.
- Container JDK installation: Temurin `21.0.11`.

## Runtime Status

The verified stack remains running for inspection. The FastAPI demonstration
surface is available at `http://localhost:8000`. The Ghidra build uses HTTPS
only for remote artifacts and validates the official digest; no host file server
or build-only service is a runtime dependency.

Workers still use bucket-level MinIO credentials rather than per-ToolRun
temporary object authorization. Analysis Package export exists, but a package
import/replay entry point is not implemented. Worker execution has trace
metadata but is not yet represented by complete OpenTelemetry spans.
Independent Audit Sealer/WORM, real model execution, and adversarial consensus
remain the explicitly deferred phase-one hardening/future work described in the
project traceability documents; none is claimed complete here.

## Post-Migration Validation (2026-08-05)

This snapshot was revalidated after Docker Desktop WSL data migration. Compose now supports a
configurable `CONTAINER_REGISTRY_PREFIX`, and the DaoCloud mirror was used because direct Docker
Hub access was unavailable. The API and Ghidra Worker images were rebuilt, all ten services
started, and BuildKit cache was removed after the run.

A new real API acceptance task (`c7fd264b-9c4d-4316-a97c-538e58495bd4`) processed Windows
`notepad.exe` through intake, PE parsing and the isolated Ghidra Worker. All three ToolRuns
succeeded; 19,183 Evidence records, 14 Candidate Claims and a report revision were persisted.
The 3,644-event task audit chain and HMAC terminal seal verified successfully. The result is
`SUCCEEDED/PARTIAL` solely because the primary model is not configured.

The final code gate is 80 pytest tests passed, compileall and Ruff passed, and Compose config
passed. See `docs/w2-w3-final-validation-20260805.md` for the complete record and deferred
first-phase hardening boundary.
