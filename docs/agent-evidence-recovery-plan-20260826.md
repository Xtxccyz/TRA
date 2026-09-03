# Agent Evidence Recovery Plan (2026-08-26)

## Purpose and safety boundary

This plan addresses the gap between an auditable static-analysis pipeline and
an Agent that recovers evidence-backed mechanisms. It is based on the ComHost
blind-test records, the Resume reference-gap review, and direct source/artifact
verification.

Samples remain read-only. No sample, macro, payload, C2 address, or recovered
URL may be executed or contacted. Static parsing, Ghidra, bounded byte reads,
P-code-based abstract execution, and deterministic decoding are allowed.
Dynamic emulation is not a P0 requirement: an emulation result is admissible
only after a separately authorized, isolated worker has actually produced it.
Exact, reproducible bounded evaluation over preserved byte/instruction inputs
may be `STATIC_DERIVED`; abstract, path-merged, range, or symbolic
approximation remains `STATIC_INFERRED`. A derived result must retain the
evaluator version, input Evidence IDs, input digest, and output digest.

## Review reconciliation

The first external review correctly identifies an evidence-delivery failure in
the prompt-controlled blind harness: its packet had one `file_identity` item
and 127 `import_symbol` items, and it explicitly closed tool execution. It is
therefore invalid for measuring recursive Agent performance, but valid for
measuring evidence discipline.

That exact `evidence[:128]` implementation is not present in the current
production static-analysis selector. The preserved production enrichment
request instead contains 96 items: one `pe_structure` and 95 generic
`function` rows. This disproves the literal implementation diagnosis while
confirming the underlying failure: the selected context contains no
function-context, Xref, CFG, P-code, data-reference, decode, or targeted trace
evidence.

The planner has an independent production fault. It queries Evidence ordered by
creation time and applies `limit(120)` before context construction. The current
`QuestionCentricContextBuilder` then accepts rows in supplied order until its
byte budget is full. It performs no relevance ranking, diversity budgeting, or
graph expansion. Consequently, re-planning can still be starved by early import
rows.

The second external review is also directionally correct that the action loop
is under-specialized. `Investigator.propose()` presently follows a small,
PPID-oriented heuristic. The catalog contains 17 action types, but the default
strategy does not turn a resolver, crypto, or entrypoint clue into a targeted
multi-step chain. A large number of Claims or a `SUCCEEDED` task is therefore
not evidence of Resume-level mechanism recovery.

`PARTIAL` in the recorded Resume run alone cannot prove that PPID or XOR
recovery failed: the documented outcome is also caused by unsupported decoded
child artifact types. A semantic differential test is required before making a
mechanism-completeness claim.

## Required terminology

- **Produced**: a tool emitted a raw fact.
- **Normalized**: the raw fact was converted to the canonical Evidence schema
  with its ToolRun and source provenance intact.
- **Persisted**: the normalized fact has an immutable Evidence record.
- **Eligible**: policy and evidence nature permit it to support the active
  question.
- **Candidate**: a structured retrieval plan returned it as relevant to the
  active question before budgeted ranking and packing.
- **Selected**: retriever chose it for a concrete model turn.
- **Delivered**: its ID and compact representation are in that turn's request.
- **Referenced by model**: a structured model output names the Evidence ID.
- **Accepted as support**: the deterministic verifier/Claim Gate accepts the
  Evidence ID for a concrete Claim or mechanism step. A model reference alone
  is not accepted support.
- **REFUTED**: an explicitly scoped hypothesis has affirmative contradictory
  evidence or passes an exhaustive proof gate. Missing evidence never means
  `REFUTED`; it means `UNKNOWN` or `STATIC_BOUNDARY`.

An Evidence item's knowledge `nature` remains immutable. Its `PRIMARY`,
`DERIVED`, or `NAVIGATION` role is context-specific and belongs to the
retrieval/delivery record, not to the Evidence row: the same function summary
may help navigation in one question and be directly relevant in another.

## Implementation order

### P0.1 Evidence funnel and delivery trace

1. Add an immutable per-turn manifest recording the counts and IDs at every
   stage: `PRODUCED -> NORMALIZED -> PERSISTED -> ELIGIBLE -> CANDIDATE ->
   SELECTED -> DELIVERED -> REFERENCED_BY_MODEL -> ACCEPTED_AS_SUPPORT`.
2. Record per-item exclusion reasons (`wrong_artifact`, `budget`,
   `low_relevance`, `duplicate`, `unsupported_nature`, or policy exclusion).
3. Persist an append-only `EvidenceDeliveryTrace` separate from immutable
   Evidence, because eligibility, role, and selection are turn-specific.
4. Display the funnel and context manifest in the existing auditable trace;
   do not display private reasoning or secrets.
5. Add tests that require Ghidra function-context, Xref, CFG/P-code, and
   targeted action output to be delivered to a relevant model turn when they
   exist.

Acceptance: a failed mechanism investigation can be attributed to a precise
funnel stage; no evidence silently disappears between a successful tool run and
the model request.

### P0.2 Structured RetrievalRequest

1. Replace the global, creation-time database `limit(120)`. Do not remove all
   bounds: issue bounded, indexed candidate queries before loading values into
   memory.
2. Compile a question and typed hypothesis into a versioned
   `RetrievalRequest`: target anchors, required evidence kinds, graph-expansion
   depths, artifact scope, and a mechanism/playbook profile. Natural-language
   semantic search is neither required nor a source of truth.
3. Version the request compiler and record its source thread, hypothesis,
   Playbook, target anchors, required evidence kinds, graph-expansion depths,
   artifact scope, and candidate-query limits in `EvidenceDeliveryTrace`.

### P0.3 Question-centric retriever and Context Builder v2

1. Retrieve candidates through exact anchors, structured API names, RVA/data
   references, call/data graph edges, and prior-action outputs; then apply
   relevance ranking and budgeted packing.
2. Use a two-part packet: mandatory Core Context plus Expansion Context.
   Apply diversity floors and adaptive maxima by Playbook profile, rather than
   fixed equal quotas. Generic function summaries are `NAVIGATION` context and
   cannot satisfy a mechanism Claim Gate alone.
3. Assign context-specific roles from the closed set `CORE_SUPPORT`,
   `CORROBORATING`, `NAVIGATION`, and `EXPANSION`. Do not use `DERIVED` as a
   context role, because it is reserved for Evidence nature.
4. Treat every sample-derived string, script body, resource, document,
   decompiler/P-code rendering, and decoded value as `UNTRUSTED_DATA`. Serialize
   it only inside a data envelope; it cannot alter system/developer policy,
   tool allow-lists, action parameters, or Claim Gate rules.
5. Make evidence IDs, retrieval features, rank, context role, quota group, and
   selection/exclusion reason part of the delivered manifest.
6. Add adversarial regression fixtures containing instructions in strings,
   resources, scripts, and decompiler output. Every planner and analysis route
   must preserve the text solely as Evidence and ignore it as an instruction.

Acceptance: for a dynamic-resolver question the context contains the
`GetProcAddress`/`LoadLibrary` anchors, their callers/Xrefs, nearby data and
decompile/P-code evidence before unrelated import rows. For an XOR question it
contains the decode loop, bytes/table candidates, call sites, and any decoder
output.

### P0.4 Epistemic and verifier gates

1. Formalize and validate the Evidence-nature vocabulary across contracts,
   persistence, reports, and migrations: `STATIC_OBSERVED` for direct tool
   observations, `STATIC_DERIVED` for exact reproducible computation, and
   `STATIC_INFERRED` for over-approximated or interpretive static results.
   `STATIC_DERIVED` requires preserved evaluator/input provenance; a
   decompiler rendering alone is not sufficient.
2. Replace free-form rejection semantics with a typed hypothesis predicate:
   subject, predicate, object, scope, and required counter-evidence rule.
3. Permit `REFUTED` only through a verifier gate with affirmative
   counter-evidence or an explicit exhaustive scope such as "direct IAT import
   of WinHTTP".
4. Enforce that absence of a direct import cannot refute runtime use when a
   dynamic resolver, wrapper, hash resolver, or indirect call remains viable.
5. Render `UNKNOWN`, `STATIC_BOUNDARY`, `CONTRADICTED`, and `REFUTED`
   separately in reports and benchmark metrics.

Acceptance: regression tests reject the invalid inference "WinHTTP absent from
IAT => no network capability" and accept the narrower, correctly scoped
"direct WinHTTP IAT import absent" result.

### P0.5 Targeted action semantics and playbook framework

The current static action executor flattens all source Evidence and performs
generic matching. It must be replaced by targeted, read-only queries over
artifact-scoped indexes. `GET_XREFS_TO(GetProcAddress)` and
`GET_XREFS_TO(LoadLibrary)` are distinct experiments, not one globally
deduplicated action type.

1. Extend `ActionSpec`/`ActionProposal` with a validated target selector,
   expected evidence kinds, success criterion, failure interpretation,
   deterministic cost profile, and canonical dedupe key.
2. Deduplicate by action type plus canonical target/parameters, not action type
   alone. Permit bounded retries only when their target or evidence frontier
   differs.
3. Build artifact-scoped indexes for function/RVA, API Xrefs, call graph, data
   references, P-code/instruction slices, bounded file bytes, and derived
   decoder outputs. Every executor result must retain source Evidence IDs and
   exact anchors.
4. Introduce versioned `MechanismPlaybook` profiles. A playbook declares
   triggers, structured retrieval requirements, preferred actions, evidence
   thresholds, failure semantics, and potential spawned threads. It is not a
   separate hard-coded Agent.
5. Add an information-gain gate based on deterministic novelty, graph frontier
   expansion, hypothesis-state delta, and cost. It ends a thread as
   `NO_NEW_EVIDENCE` only after a bounded consecutive no-gain policy, never as
   a covert refutation.

Acceptance: an action executed with a target returns only evidence reachable
from that target or explicitly reports no result. Changing the target changes
the canonical dedupe key and can produce independently auditable results.

### P0.6 Mechanism-specific static strategies

Implement deterministic, policy-approved strategies that can be proposed by a
model but are independently validated and executed by the static executor:

1. Dynamic API resolution: import/API seed -> Xrefs/callers -> decompile or
   P-code slice -> referenced strings/hashes -> resolved API candidate -> call
   site/argument anchor.
2. Decode/config recovery: encoded-data seed -> data Xrefs -> loop/function ->
   abstract execution and bounded bytes -> deterministic decode candidate ->
   output validation and provenance.
3. Process/PPID chain: process enumeration -> target comparison -> OpenProcess
   rights -> UpdateProcThreadAttribute constant/argument -> CreateProcess flags
   and ordered chain.
4. Entrypoint timeline: entrypoint -> bounded call graph -> phase candidates ->
   ordered function/RVA anchors and branch limitations.

Every emitted mechanism Claim must cite exact function/RVA/argument/data anchors
and distinguish direct observations from inferences.

Acceptance: focused fixtures validate every strategy with success, unknown, and
contradiction paths. The strategies must produce new targeted Evidence, not
only action records or text matches over the complete ledger.

### P0.7 Valid ComHost blind harness v2

1. Preserve the existing closed-tool run as `INVALID_FOR_AGENTIC_GENERALIZATION`.
2. Start a fresh run with the exact blind-prompt constraints, no reference
   report or family context, and only minimal PE baseline evidence at turn one.
3. Allow the candidate model to issue structured action proposals. The policy
   gate validates them, the static executor runs them, new evidence is
   retrieved question-centrically, then the model replans until a budget, proof
   threshold, or static boundary.
4. Store immutable raw first response, all subsequent responses, action
   arguments/results, per-turn manifests, and verifier decisions.
5. Use the same Qwen route and same sample for an A/B comparison. Score evidence
   discipline separately from retrieval recall, action quality, mechanism
   completeness, and unsupported-claim rate.
6. Freeze and hash a BlindRun snapshot containing the model and parameters,
   system Prompt ID/version/hash, policy and Action Catalog versions, Playbook,
   retrieval, Context Builder and Evidence-schema versions, tool versions,
   initial Evidence snapshot, and scorecard version. Historical scores are
   comparable only when this manifest, or its declared comparison policy,
   matches.

The public test prompt and all Agent-delivered context must exclude ComHost
ground-truth details such as expected API names, ETW behavior, protocol
semantics, or shell-chain conclusions. Those details belong only to the
post-run evaluator and its versioned scorecard.

Acceptance: the valid run is reproducible, traceable, reference-isolated, and
can show whether evidence recovery was blocked by tool output, retrieval,
action choice, verifier policy, or the sample's static boundary.

### P0.8 Resume critical-mechanism regression

Maintain a compact, reference-isolated regression scorecard for Resume-XOR,
Resume-PPID, Resume-Entry, and Resume-DynamicAPI. Each test evaluates the
minimum anchored mechanism components appropriate to that case, with positive,
unknown, and anti-overclaim assertions. Gold labels, required anchors, and
expected decoded values remain evaluator-only and cannot be queried by an
Agent, RetrievalRequest, or Playbook.

Acceptance: every P0 retrieval/action/playbook change is evaluated against both
the valid ComHost Blind v2 run and this Resume regression suite. An improvement
on ComHost that regresses a Resume critical mechanism fails P0.

### P1. Full Resume semantic differential

1. Execute the completed static pipeline only, then compare its output with the
   reference report outside the Agent input path.
2. Score loading chain, decoder/config recovery, PPID/process chain, dynamic
   resolver, network/protocol, anti-analysis, and entrypoint timeline
   individually.
3. For each discrepancy, classify it as missing static evidence, retrieval
   failure, action-planning failure, analysis/verifier failure, unsupported
   child type, or a conclusion that requires an authorized dynamic phase.
4. Publish a mechanism scorecard rather than using Claim/Relation totals or
   `PARTIAL`/`COMPLETE` as proxies for report quality.

Use a versioned mechanism-completeness rubric per test case, with independently
scored entry, input, transformation, condition, output/side effect, consumer,
and anchors. This is an offline benchmark metric. It must never become a
runtime Claim Gate, and a high completeness score cannot compensate for an
unsupported conclusion.

Acceptance: every reference mechanism has a traceable supported, unsupported,
or static-boundary outcome with evidence IDs and a reason; the reference report
never enters the Agent's context.

### P2. Future isolated emulation

Only after a separate authorization and deployment review: build a network-off,
filesystem-scoped, instruction/time-bounded worker for one emulator. Model
output remains advisory; it cannot enable emulation. Any result must be stored
as `DYNAMIC_OBSERVED` with tool version, sandbox policy, resource limits, and
raw trace provenance. This work is intentionally outside the current static
completion gate.

## Test matrix and definition of done

The next release is not complete because the suite passes. It is complete only
when all of the following hold:

1. Unit tests cover `RetrievalRequest` compilation, candidate-query bounds,
retrieval diversity, selection rationale, context-specific evidence roles,
false-negative evidence handling, target-aware action deduplication, and each
strategy's positive/unknown/contradiction path.
2. Integration tests prove tool-output-to-model delivery for the planner and
the static-analysis agent, using evidence IDs asserted from the actual request.
3. A fresh ComHost v2 run is valid under the stated protocol, preserves every
   turn, freezes its BlindRun snapshot, and reaches conclusions no stronger
   than its accepted support.
4. The Resume critical regression passes without exposing Gold data to the
   runtime Agent path.
5. A full Resume differential scorecard demonstrates exactly which requested
   mechanisms are recovered by static analysis and which remain at a static
   boundary.
6. The final report front page leads with mechanisms, rationale, confidence,
   anchors, and limitations rather than raw field enumeration.
