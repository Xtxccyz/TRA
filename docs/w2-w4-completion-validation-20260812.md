# W2-W4 Completion and Validation Report

Date: 2026-08-12
Scope: Excel worksheet `多智能体的深度逆向应用`, W2, W3, and W4 only.

## Result

W2, W3, and the W4 development tasks listed in the worksheet are implemented in the current workspace and pass the local validation gate. W5-W7 are not claimed complete.

The implementation remains static-only. Samples, scripts, macros, and generated code are never executed. Reference reports and evaluation baselines remain outside the analysis input channels.

## Acceptance Matrix

| Work package | Status | Evidence |
| --- | --- | --- |
| W2 input schema, Case/Task/Artifact/state model | Complete | `contracts.py`, `models.py`, `status.py`, API tests |
| W2 FastAPI/PostgreSQL/object store/LangGraph skeleton | Complete | `main.py`, `database.py`, `content_store.py`, `orchestration.py`, Compose validation |
| W2 hashes, Magic/MIME, read-only intake, audit | Complete | `intake.py`, `static_analysis.py`, content-addressed stores, audit integrity tests |
| W2 Prompt, tool allowlist, resource limits and production Worker enforcement | Complete for development scope | `prompts.py`, `policy.py`, Compose Worker restrictions, production rejects local tool execution |
| W3 Ghidra Headless, PE/script/document parsing | Complete | `ghidra_adapter.py`, `ExportStaticFacts.java`, `static_analysis.py` |
| W3 function/Xref/CFG/fuzzy fingerprint persistence | Complete | `service.py` Ghidra persistence and `function_simhash.py` |
| W3 fuzzy similarity retrieval | Complete | `function_similarity.py`, packaged eight-entry catalog, similarity ToolRun and Evidence |
| W3 deterministic triage/static Agent baseline | Complete | `agents.py`, Evidence-backed Claims and priority Claims |
| W4 B0xD3 single-sample closure | Complete when required tool Evidence succeeds | actual granularity, function RVA/interface/call/mechanism/IOC Evidence |
| W4 atomic behavior and component relations | Complete | atomic Claim fields, relation API, support checks, six relation types |
| W4 object tree and embedded carrier extraction | Complete for supported OOXML carriers | bounded embedded child Artifact materialization and `CONTAINS` Relation |
| W4 confirmed/inferred/unknown static attack chain | Complete | report `behavior_attack` module derives state from Relation support |
| W4 unified model adapter baseline | Complete as an explicit optional capability | OpenAI-compatible `ModelGateway`, primary/fallback, structured schema, timeout/failure audit |

## Implementation Details

### Fuzzy similarity

The finished mnemonic 4-gram Charikar SimHash contract is preserved: normalized mnemonics, consecutive four-mnemonic features, first 64 MD5 bits in little-endian order, Charikar accumulation, and Hamming distance comparison.

The application path searches the packaged `known-functions.yaml` catalog and bounded same-task function Evidence. It records a separate deterministic `function-similarity-index` ToolRun and `STATIC_OBSERVED` `function_similarity` Evidence. A hit never creates attribution or family Claims automatically.

### Model Gateway

`model_gateway.py` is the only model-call seam. It accepts a versioned Prompt, bounded Evidence context, and a Pydantic response schema. It sends an OpenAI-compatible `/chat/completions` request, validates `AtomicClaimEnvelope`, records provider/model/attempt/latency/token/hash metadata, and falls back from primary to fallback. Secrets never enter audit views.

When enabled with `MODEL_CALLS_ENABLED=true`, raw request and raw provider response bytes are stored in the content store by SHA-256. `ModelCall` rows link generated Claims. Model output can only create `STATIC_INFERRED` Claims referencing Evidence IDs from the bounded context. If all providers fail, deterministic Claims remain and the task records an explicit limitation.

### W4 deep static evidence

Ghidra output is persisted as function, `function_simhash`, `xref`, `cfg_block`, `function_interface`, `function_call`, `function_mechanism`, and `function_ioc` Evidence with function/RVA anchors. Script facts retain line anchors. OOXML embedded objects are extracted into child Artifacts with content hashes, parent links, roles, and observed `CONTAINS` Relations.

Single-file submissions select `single-sample-static-deep` and freeze `B0xD3`. Actual depth is D3 only after the applicable parser succeeds and, for PE, Ghidra function Evidence is present. Otherwise the task records D2 and an explicit limitation.

### Audit and evidence lifecycle

Relations require Evidence or Claim support at the database level. Structural relations (`CONTAINS`, `DROPS`) require observed Evidence; behavioral relations (`LOADS`, `DECRYPTS`, `EXECUTES`, `INJECTS`) require Claims. Daily UTC audit sealing is idempotent and stores a signed, content-addressed seal payload. Evidence purge requires an archived Case, independent requester/reviewer/admin identities, and real-time shared Blob reference checks.

## Validation

Passed on 2026-08-12:

```text
python -m pytest -q                 96 passed
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m compileall -q src tests scripts
python -m py_compile simhash.py fuzzy_hash.py register_crypto_simhashes.py
docker compose config --quiet
```

W4-specific acceptance tests cover model-call persistence, atomic Claim linkage, daily seal idempotency, relation type enforcement, and the B0xD3 path.

`docker compose build api` was not executed because Docker Desktop's Linux Engine was not running (`dockerDesktopLinuxEngine` named pipe unavailable). Compose syntax validation passed. No malware sample was executed.

## Not Complete

W5 ATT&CK STIX/RAG, W6 benchmark/automated quality evaluation/adversarial consensus, W7 release hardening/auth/WORM/disaster recovery/package replay, and semantic/CFG fuzzy-hash upgrade benchmarks remain incomplete.

## Review Addendum (2026-08-12)

This addendum records the corrective review performed after the initial W2-W4 validation.

### Corrective changes completed

- Added public Case archive, UTC daily audit sealing, evidence purge request, independent review,
  and independent execution endpoints. The CLI also exposes `seal-audit-day` for scheduled
  operations.
- Enforced terminal-task preconditions before Case archival and preserved the three-person
  retention separation: requester, reviewer, and administrator must be distinct.
- Corrected ContentBlob disposal. Physical bytes may be removed only after live Artifact reference
  checks; the ContentBlob metadata row is retained so historical Artifact foreign keys and report
  provenance remain valid. A later identical submission can restore the backing bytes.
- Added database migration coverage for `content_blobs.disposed_at` and database-level relation
  support constraints. Structural relations require Evidence; behavioral relations require Claim.
- Corrected daily audit sealing to seal the last event within the requested UTC day, rather than
  the current chain tip. Integrity validation now checks the signed content-addressed daily seal
  payload and its terminal event.
- Added immutable snapshot schema migration support for schema `1.0` to `2.0` reads. New snapshots
  continue to use schema `2.0`.
- Fixed OOXML embedded carrier handling when ZIP intake had already materialized the member:
  the existing child Artifact is upgraded to `EMBEDDED_OBJECT`, receives the carrier metadata,
  and remains linked by observed `CONTAINS` Evidence/Relation.
- Added native Anthropic Messages protocol support behind an explicit `api_style` provider setting.
  OpenAI-compatible providers remain the default. Unconfigured primary and fallback providers now
  produce explicit failed ModelCall audit rows instead of disappearing from the trace.
- The packaged `knowledge/known-functions.yaml` is preferred in installed deployments; repository
  copies are development fallbacks only.

### Review evidence

The corrective review added end-to-end tests for retention routes, embedded child Artifacts,
packaged known-function data, snapshot migration, native Anthropic calls, unconfigured model
failure auditing, and daily seal terminal-event selection. The complete local gate is now:

```text
python -m pytest -q                 105 passed
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m compileall -q src tests scripts
python -m py_compile simhash.py fuzzy_hash.py register_crypto_simhashes.py
docker compose config --quiet
```

Docker image construction remains environment-dependent: it requires Docker Desktop's Linux Engine
to be running. No malware sample, macro, script, or generated code was executed during this review.

### Scope boundary

The completed W4 model adapter is an auditable optional baseline, not the W5-W7 production quality
layer. ATT&CK STIX/RAG, benchmark scoring, adversarial consensus, independent WORM sealing, RBAC,
disaster recovery, and analysis-package replay remain explicitly open work.
