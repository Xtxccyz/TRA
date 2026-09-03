# Round 8 Control-Plane Audit

Date: 2026-08-27

## Scope

This audit covers the Round 8 Evidence Recovery and Investigation Control Plane
changes. Samples remain read-only; no sample, macro, script, network target,
Qiling, Speakeasy, or flare-emu runtime is executed.

## Implemented changes

1. Model `DynamicPlanAction.action_type` is normalized to a typed
   `ActionSpec`, validated by both the closed Action Catalog and the tool Policy
   Registry, and executed by the static evidence-query executor. Model actions
   cannot bypass artifact compatibility, selector anchoring, unsafe-tool
   restrictions, or the evidence gate. `BACKGROUND_REPORTED` Evidence may be
   visible as explicitly isolated background context in an ordinary task, but
   it is excluded from `allowed_evidence_ids` and can never authorize an Action
   or support a Claim; reference-isolated blind runs omit it entirely.
   `source_evidence_ids` are checked against the target Artifact before the
   executor reads them; a selector cannot redirect an Action to another
   Artifact. When a provider emits only `action_type`, the compatible static
   tool is selected from the Action Catalog instead of silently downgrading the
   turn.
2. Initial and replanned model actions enter the Investigation Loop immediately
   after baseline extraction. The executor produces provenance-bearing
   Evidence, and the next planner turn receives that new evidence. Repeated
   actions are deduplicated by target-sensitive action keys. Failed or rejected
   Actions are excluded from the completed-action history; successful entries
   retain `action_type`, selector, parameters, source Evidence, and
   `planner_turn_id` for replay and audit.
3. `ModelCall` now records `turn_id` and `phase`. Planner and enrichment turns
   persist immutable manifests for success, failure, and empty-context paths;
   raw request/response bodies remain encrypted and are never exposed through
   the analysis trace. `context_bytes` is the serialized request/manifest byte
   count, rather than an estimate, and each turn's result contains only that
   turn's Actions and Evidence (no cumulative cross-turn duplication).
4. Retrieval allocation is performed before selection. The manifest, packet,
   model-call context count, and delivery ledger no longer disagree because of
   post-hoc truncation. Blind v2 first-turn retrieval is restricted to the
   minimal identity/PE/import/TLS evidence kinds and remains reference-isolated.
5. `analysis_trace` exposes an auditable Evidence Funnel view containing stage
   counts, per-turn counts, and append-only records without private model
   reasoning. The trace exposes a context manifest and delivery ledger, but
   never model private chain-of-thought or unencrypted payloads. Static
   investigation ToolRuns explicitly record `sample_execution: false`,
   `network_access: false`, and the `database_only_no_sample_execution`
   isolation boundary.
6. Evaluator-only Evidence Funnel scoring now reports retrieval/delivery recall,
   model utilization, verified-support conversion, thread discovery recall,
   action productivity, silent evidence loss, refuted-from-absence errors, and
   a deterministic Round 8 Gate result. Gold components may span multiple
   Evidence rows and Gold thread matching supports semantic labels, seed kinds,
   question text, and Artifact path selectors. Gold/reference data remains in
   evaluator-only code and is not available to the runtime planner.

7. SQLite relation guards now cover both INSERT and UPDATE. Every Relation must
   have Evidence or Claim support; structural relations require Evidence and
   behavioral relations require Claim. This prevents unsupported or
   post-creation relation mutations from entering the database.

## Verification

```text
pytest -q
265 passed, 1 warning

ruff check src benchmarks tests
All checks passed

python -m compileall -q src benchmarks tests
passed
```

The added vertical tests prove model Action Catalog actions are replayed by the
static executor, use only cited Evidence from the target Artifact, produce
investigation Evidence, are retained in Turn audit, and do not duplicate Claims.
Regression tests cover rejected/failed Actions, selector and planner-turn
metadata, action-type-only tool compatibility, and INSERT/UPDATE Relation
support guards. Trace tests prove Funnel exposure without model payload
leakage. Evaluator tests cover multi-row Gold components, semantic thread
recall, silent loss, refutation-from-absence detection, and the productivity and
thread-recall Gate thresholds.

## Acceptance boundary

The code-level control-plane requirements are complete for the static Agent
boundary. This does not claim that the Round 8 effectiveness Gate has passed:
the fresh provider-backed Resume run below is an operational validation, not a
claim that the Resume report was fully reproduced. Raw provider output remains
in the existing restricted encrypted payload store and is scored outside the
Agent with evaluator-only Gold data. Dynamic simulators remain
detection/extension points; this Round 8 path performs database-backed static
evidence queries and never executes a sample, macro, script, network target,
Qiling, Speakeasy, or flare-emu runtime.

## Docker validation runs

The API image was rebuilt and restarted before the third run. `/healthz`
returned `200` and reported the model gateway configured. The same read-only
sample was submitted in all runs: `D:\\test\\Resume\\ComHost.exe.VIR`.

### Run 1: quota baseline

- Task `f230f93a-69b3-45a7-8715-3c577af12009` completed `SUCCEEDED/PARTIAL`.
- Ghidra emitted 3,455 functions while the intended processing budget was 512;
  170,391 Evidence rows and 68,456 audit events exposed a function-quota
  bypass.
- The root cause was iteration over the raw Ghidra list after computing the
  bounded list, plus an unbounded similarity-index query.

### Run 2: quota fix and context-budget discovery

- Task `ee95ab90-f3ab-4081-8e5c-2df90218d3b3` completed `SUCCEEDED/PARTIAL`.
- Processing was bounded to 512 functions and produced 40,780 Evidence rows;
  the similarity index produced 3,626 rows.
- Three model planner calls succeeded, but a later turn hit
  `AGENT_CONTEXT_BUDGET_EXCEEDED` because completed-action Evidence IDs were
  accumulated without a bounded history.

### Run 3: current image after both fixes

- Task `1281ba94-1988-4274-b7ae-f72a9cb8f658` completed
  `SUCCEEDED/PARTIAL`; report revision is
  `bd488c23-6937-480e-8383-4a4a003c9a9b`.
- Four provider calls succeeded, all routed to `ali/qwen3.7-max`; no
  `AGENT_CONTEXT_BUDGET_EXCEEDED` string occurs in the task, trace, or report.
- Four analysis turns were persisted (initial planning, two replans, and
  enrichment). The trace contains 8799 audit events and the audit integrity
  endpoint returned `valid=true` with a terminal HMAC seal.
- Ghidra `12.1.2` completed through Temporal task queue `static-ghidra`.
  The run persisted 512 `function`, 512 `function_context`, 512
  `function_simhash`, and 512 `abstract_execution_trace` rows. The final
  Evidence set contains 40,779 rows, including 3,624
  `function_similarity` rows, 453 `function_mechanism` rows, 66
  `cross_function_chain` rows, and 129 Relations.
- The Evidence Funnel records 386 items through `ELIGIBLE`, 66 delivered to
  model turns, and 19 referenced by the model. All funnel records are exposed
  with turn IDs and no private chain-of-thought or raw payload.
- The provider returned valid responses, but some proposed Actions were
  rejected by the policy layer (`uncited_investigation_action` and
  `unknown_artifact`); the deterministic scheduler retained the safe baseline
  order. This is an auditable safety outcome, not evidence that every proposed
  model action executed.
- The generated Markdown contains mechanism hypotheses, function/call-chain
  observations, ATT&CK candidates (for example `T1129`, `T1059`, `T1497`, and
  `T1071`), evidence references, and explicit static-only limitations. The
  outcome remains `PARTIAL`: runtime behavior is unverified and the report is
  not asserted to be Resume-level `COMPLETE`.

Saved raw validation artifacts:

- `.scratch/round8-resume-comhost-docker-submission-v3.json`
- `.scratch/round8-resume-comhost-docker-task-v3.json`
- `.scratch/round8-resume-comhost-docker-report-v3.json`
- `.scratch/round8-resume-comhost-docker-trace-v3.json`
- `.scratch/round8-resume-comhost-docker-audit-integrity-v3.json`

## Strict review result

The implementation and tests were re-read after the final control-plane edits.
The reviewed paths enforce the provenance and isolation invariants listed
above, and the repository passes the full test, lint, and bytecode compilation
checks. Remaining work is effectiveness validation with an approved provider
and evaluator-only Gold fixtures, not an unverified claim of Resume-level
coverage.
