# Round 7 P0/P1 Final Code Audit

Date: 2026-08-26

## Scope

This audit covers the Evidence Recovery and Investigation Control Plane changes
through P1. Samples remain read-only. No sample, macro, script, network target,
Qiling, Speakeasy, or flare-emu runtime was executed.

## Defects fixed in this round

1. `EvidenceDeliveryTrace` is append-only for both update and delete on SQLite
   and PostgreSQL. The PostgreSQL branch no longer executes SQLite trigger SQL,
   and blind-run snapshot protection is a separate valid PostgreSQL trigger.
2. `EvidenceSearchKey` migration now backfills selector keys for historical
   Evidence rows, so existing installations can use question-centric retrieval.
3. `ClaimGate` rejects `STATIC_DERIVED` Evidence without evaluator, input IDs,
   input digest, and output digest provenance.
4. Investigation hypotheses are selected from the matching mechanism playbook.
   Dynamic API, XOR/config recovery, PPID/process creation, entrypoint timeline,
   and generic fallback receive different questions, dimensions, and evidence
   requirements. PPID requirements are no longer applied to every Artifact.
5. Model actions accept the legacy `expected_evidence` field by normalizing it
   to `expected_evidence_kinds`. Incomplete actions are rejected or skipped
   without aborting the task; deterministic playbooks remain authoritative.
6. Evidence delivery traces infer `artifact_id` from the cited Evidence when a
   caller does not provide one, preserving cross-Artifact traceability.

## Requirement and ADR status

| Area | Status | Verification |
|---|---|---|
| Evidence funnel and append-only delivery ledger | Complete | SQLite mutation tests and service persistence path |
| Historical selector-index migration | Complete | Migration regression retrieves pre-index Evidence |
| Typed RetrievalRequest and bounded retriever | Complete | Evidence-recovery and service tests |
| Question-centric context, roles, and exclusion rationale | Complete | Retrieval/context test matrix |
| Nature and provenance gate | Complete | Missing-provenance rejection and valid-derived paths |
| Target-aware 17-action catalog and queue | Complete | Catalog, dedupe, dependency, and budget tests |
| Mechanism playbooks and targeted static executor | Complete for static boundary | PPID service vertical slice plus strategy tests |
| Recursive investigation state machine | Complete for static boundary | Loop, persistence, verifier, and claim-gate tests |
| Model planner compatibility and policy gate | Complete | Mock OpenAI-compatible planning tests |
| Blind-run isolation and evaluator-only reference data | Preserved | Existing blind-v2/evaluator isolation tests |
| P1 semantic differential plumbing | Complete as evaluator-only tooling | Resume evaluator/scorecard modules and isolation tests |

## Verification results

```text
pytest -q
250 passed, 1 warning

ruff check src benchmarks scripts tests
All checks passed

python -m compileall -q src benchmarks scripts tests
passed
```

The new regression coverage includes delivery-trace update/delete rejection,
historical selector backfill, derived-provenance enforcement including malformed
digest rejection, cross-Artifact trace inference, playbook-specific PPID
hypothesis creation, and legacy model planning field normalization.

## Honest boundary

The implementation is a static evidence-driven investigation Agent. It can
schedule bounded read-only actions, derive and persist evidence with
provenance, update hypotheses recursively, and emit a Claim only after the
verifier gate passes. It does not claim runtime behavior from static evidence.

Dynamic emulator adapters remain detection/safety seams only. Actual dynamic
execution requires a separately authorized isolated worker and is outside this
P0/P1 static completion gate. A complete Resume-equivalent result for every
sample is also not guaranteed; unsupported child types and runtime-only facts
remain explicit `UNKNOWN` or `STATIC_BOUNDARY` outcomes.

## Final judgement

The P0/P1 code-level defects identified by the Round 7 audit are fixed and
covered by executable tests. The system is materially usable as a static,
evidence-driven Agent rather than a field-listing pipeline. Remaining dynamic
execution and universal sample-depth claims are intentionally not marked
complete.
