# W2-W4 Strict Remediation Review (2026-08-17)

This document is the current acceptance record for the worksheet
`Multi-agent deep reverse engineering application`, W2S, W3 and W4. Earlier
review notes remain historical and are not completion evidence.

## Acceptance Position

W2S, W3 and the W4 scope that is required before later adversarial stages are
implemented in the repository and exercised through public interfaces. The
system is a usable evidence-backed static Agent with an explicit model gateway
and deterministic fallback. It is not presented as a fully production-certified
deployment: external identity, HSM/KMS, WORM certification and W5+ multi-agent
consensus still require deployment-specific work.

## W2S and W3

| Requirement | Status | Evidence |
|---|---|---|
| Four-channel immutable input contract | Complete | `contracts.py`, `test_platform_contracts.py` |
| Case, Analysis Task, Artifact, lifecycle and outcome model | Complete | `models.py`, `status.py`, API acceptance tests |
| FastAPI, PostgreSQL-compatible ORM, object storage and LangGraph-shaped orchestration | Complete | `main.py`, `database.py`, `orchestration.py`, Compose |
| Hash, Magic/MIME, read-only intake and audit chain | Complete | `intake.py`, `static_analysis.py`, audit tests |
| Frozen preset commands, system prompts, tool whitelist and resource limits | Complete | `policy.py`, `prompts.py`, `policies/`, action-proposal tests |
| Isolated Temporal control/tool Workers | Complete | `tool_execution.py`, `docker-compose.yml`, production policy test |
| PE, script, document and PDF/OLE carrier extraction | Complete | `static_analysis.py`, carrier tests |
| Bounded recursive child Artifact analysis without execution | Complete | `service.py`, PDF/OOXML/Base64 acceptance tests |
| Ghidra Headless adapter and function evidence | Complete | `ghidra_adapter.py`, `ExportStaticFacts.java`, real Compose acceptance |
| User-specified function SimHash implementation | Complete | `function_simhash.py`, `function_similarity.py` |
| Similarity search against known catalog and current Task | Complete | `service.py`, `known-functions.yaml`, cross-Artifact tests |
| High-value function prioritization and Evidence-backed Claims | Complete | `agents.py`, `service.py`, Claim/Evidence tests |

Similarity is supporting evidence only. It never becomes a conclusive malware
family or attribution statement by itself.

## W4

| Requirement | Status | Evidence |
|---|---|---|
| Configurable primary/fallback model gateway | Complete | `model_gateway.py`, gateway tests |
| Structured Claim envelope and Evidence validation hook | Complete | `validation.py`, `service.py`, model acceptance tests |
| Prompt version, route, context manifest and model attempts are auditable | Complete | `prompts.py`, `ModelCall`, audit assertions |
| Explicit deterministic fallback when models are disabled/unconfigured | Complete | `service.py`, health and fallback tests |
| Report modules, selection for presentation, all-module analysis retained | Complete | `reporting.py`, report/API tests |
| Frozen Analysis Snapshot and Report Revision lifecycle | Complete | `service.py`, snapshot immutability tests |
| Analysis Package export and database-independent replay | Complete | `analysis_package`, replay endpoint, replay/tamper tests |
| Human approval/publication gates | Complete | `main.py`, `service.py`, gate transition tests |
| UTC daily audit sealing, Merkle root and signed seal verification | Complete | `seal_daily_audit`, integrity tests |
| Model request/response retention expiry with shared-reference protection | Complete | `expire_model_payloads`, retention tests |
| Case retention freeze and evidence purge gate | Complete | freeze/purge API and acceptance tests |
| RS256 OIDC/JWKS adapter with issuer/audience and cache validation | Complete as an adapter | `auth.py`, production OIDC acceptance test |
| Dedicated audit object-store bucket and Object Lock write path | Complete as an adapter | `content_store.py`, FakeS3 Object Lock test |

The OIDC/JWKS implementation is an adapter. A real IdP URL, key rotation
policy, service-account registration and production incident procedures still
must be supplied by the deployment.

The audit signer is currently an HMAC signer with a separate application
secret and a replaceable signer seam. An external HSM/KMS and independent
WORM service are not falsely claimed as complete. MinIO must create the audit
bucket with Object Lock enabled before production data is written; the adapter
also sends a compliance/governance retention request for every seal object.

## Agent Reality Check

When model routes are configured, the Agent sends a versioned system prompt and
a bounded, explicitly marked untrusted Evidence context to the gateway. The
gateway validates the structured output, rejects Claim drafts with invalid or
cross-module Evidence references, and records every attempt. When no route is
configured, the deterministic static Agent remains the declared fallback and
the task is marked partial when model enrichment was required.

This is not yet the W5+ automatic adversarial consensus engine. Serial
specialist disagreement, multi-model consensus, complete ATT&CK STIX/RAG and
dynamic investigation remain later stages. Their seams are preserved by the
Claim, Evidence, ToolRun, ModelCall and Report Revision contracts.

## Verification

The current local verification target is:

```text
pytest -q
ruff check src tests
python -m compileall -q src
node --check src/threat_report_agent/static/app.js
docker compose config --quiet
```

The 124-test suite includes W2S/W3 static, recursive-carrier, similarity, model,
retention, replay, audit and Object Lock adapter tests. Malware samples are
handled only as read-only bytes; no sample, macro, script or extracted payload
is executed and no original benchmark report enters Agent context.

The real Docker acceptance previously completed with PostgreSQL, MinIO,
Temporal, API, control/tool Workers and Ghidra 12.1.2. It verified script and
DLL static tasks, a succeeded Ghidra ToolRun with Temporal and MinIO output
references, and an audit chain with a valid seal and Merkle root. Docker is
intentionally stopped after acceptance; the final cleanup must preserve the
PostgreSQL, MinIO and content volumes.

## Remaining Release Boundaries

1. Supply deployment-owned OIDC/JWKS, HSM/KMS and WORM credentials/policies.
2. Recreate or provision the dedicated MinIO audit bucket with Object Lock
   before production writes; never delete the existing data volumes during this
   step.
3. Implement W5+ adversarial consensus, complete ATT&CK knowledge retrieval,
   dynamic analysis and benchmark thresholds according to their own ADRs.
4. Keep benchmark/original reports outside intake, prompt, retrieval and
   analysis storage; use them only in an offline evaluation harness.
