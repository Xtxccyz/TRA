# W2S/W3/W4 Current Status and Remediation Plan

Date: 2026-08-23

## Scope and evidence

This review covers the W2S/W3/W4 rows in the project plan, the requirement and
design documents under `resource and plan`, the ADRs in `docs/adr`, and the
current source and tests. The repository is not a Git checkout, so the review
uses the current working tree, public service interfaces, deterministic test
fixtures, and runtime probes. No malware payload is executed; all sample work
is read-only static analysis.

Baseline before this remediation: 124 tests passed, Ruff passed, Python
compileall passed, JavaScript syntax check passed, and Compose syntax passed.
Docker Desktop was stopped, so live PostgreSQL/MinIO/Temporal acceptance was
not claimed.

## Requirement status before this remediation

| Workstream | Status | Evidence | Gap |
|---|---|---|---|
| Input and base platform | Partial | Frozen four-channel contract, Case/Task/Artifact states, FastAPI/SQLAlchemy/object-store/LangGraph/Temporal seams, hashes/MIME/read-only intake/audit | No repeatable live dependency acceptance record; background context was only in the request snapshot |
| Deterministic static extraction | Partial | PE/script/PDF/OOXML/OLE parsers, Ghidra adapter, function SimHash and catalog search, triage and priority claims | Ghidra real-PE coverage is environment-sensitive; output validation and behavior aggregation needed strengthening |
| Evidence and result model | Partial | Artifact/ToolRun/Evidence/Claim/Relation/Snapshot/ReportRevision, evidence anchors, nature enums, validation hook | Background evidence was not a first-class Evidence row; claim-to-component automation was incomplete |
| Single-sample B0xD3 | Partial | Single-file preset, granularity calculation, function/RVA/Xref/CFG evidence schema, IOC/interface evidence | D3 requires a successful Ghidra function result; behavior claims needed function-level references |
| Granularity and component relations | Partial | Atomic Claim fields, artifact tree, relation constraints, report confirmed/inferred/unknown rendering | Only extraction relations were automatic; behavioral relations were mostly manual |
| Model adaptation baseline | Partial | ModelGateway supports OpenAI-compatible and Anthropic requests, primary/fallback, structured output, timeout/failure audit | GPT/Claude/Qwen/Kimi/GLM contract coverage was not explicit; protocol compatibility was not separated from production integration |

## Remediation checklist

1. Persist non-empty background context as `BACKGROUND_REPORTED` Evidence with
   source, observation time, confidence, human confirmation, trust zone, and a
   dedicated ingestion ToolRun. Keep it isolated from sample Evidence and do
   not allow it to satisfy sample completion gates.
2. Convert Ghidra function calls into atomic static behavior Claims. Every such
   Claim must reference function-entry and, when present, call/Xref/CFG Evidence.
   Keep claims inferred and never label them as direct observations.
3. Infer `LOADS`, `DECRYPTS`, and `INJECTS` component relations only when a
   parent has an extracted child Artifact and a supporting Claim. Keep the
   relation status `INFERRED`; otherwise the report must expose `unknown`.
4. Define an explicit five-family model contract (GPT, Claude, Qwen, Kimi,
   GLM) over the single ModelGateway. Add protocol fixtures for endpoint,
   authentication headers, structured response, timeout, and fallback. These
   are offline compatibility tests, not production credentials or claims of
   live vendor access.
5. Version and validate Ghidra export JSON. Add deterministic success,
   timeout, failed-process, malformed-output, and zero-function acceptance
   tests. Real Ghidra success is reported only when the configured runtime
   produces non-zero function evidence.
6. Run the complete local quality gate and record live dependency status. Do
   not report Docker/Temporal/PostgreSQL/MinIO as passed when Docker is off.

## Execution plan

The plan is intentionally vertical: each item gets a public-behavior test,
the smallest implementation, and a focused regression run before the next
item. After all items, run the full suite, Ruff, compileall, JavaScript check,
and Compose validation, then update the audit with completed versus
environment-blocked requirements.

## Acceptance definition

The W2S/W3/W4 local deliverable is complete when every checklist item has a
passing deterministic test and the service emits a trace from input, through
ToolRun and Evidence, to Claim/Relation, snapshot, and editable report. Live
infrastructure remains a separately labelled acceptance result and cannot be
inferred from SQLite or mocks.

## Post-remediation disposition

All six checklist items were implemented. The final local gate is 144 passing
tests plus Ruff, compileall, JavaScript syntax, and Compose configuration
checks. A real configured Ghidra run reached `B0 x D3` with 25 functions. The
live PostgreSQL/MinIO/Temporal/Worker path has now been exercised through the
repeatable `scripts/live_acceptance.py` probe, and the real Ghidra Worker path
also returned `B0 x D3` with non-zero function evidence. Vendor production
model calls remain intentionally unconfigured; protocol compatibility and
fallback are tested without credentials.

The post-audit production-database correction is also complete: PostgreSQL now
accepts the ORM/API structural relation set including `EXTRACTED_FROM`, and
embedded OOXML/PDF/OLE children receive both `CONTAINS` and `EXTRACTED_FROM`.
Deterministic Claims and function-priority Claims use the same Evidence
validation hook as model Claims, and static execution indicators project
`EXECUTES` when a child component is available. The live carrier acceptance
probe verifies these paths through PostgreSQL rather than SQLite.

The final acceptance pass also validates the Ghidra export at the API boundary.
The current API image was rebuilt and a DLL replay through the existing signed
Ghidra Worker completed successfully. The Ghidra Worker image itself was not
rebuilt because its historical local archive server was unavailable; the
versioned API validator makes this rolling-image state explicit and rejects
malformed output rather than materializing partial evidence.
