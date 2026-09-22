# Final Completion Stage - Reviewed Execution Plan

Date: 2026-09-02  
Canonical status: reviewed amendment to `F:/迅雷下载/final-completion-stage-plan.md`

This document preserves the original seven waves and final gate, while making evidence,
security, attribution and environment prerequisites executable. The original plan remains
unchanged as the source proposal; this file is the implementation and acceptance authority.

Task amendment, 2026-09-07: see
[Behavior-driven investigation review and task plan](behavior-driven-investigation-plan-reviewed-20260907.md).
It prioritizes evidence-relation correctness, first-request investigation and unified behavior
reports, and specifies a separately gated controlled-emulation profile. It does not mark the
remaining release gates complete or enable execution in the existing static-only profile.

## 1. Product objective

The release must support the complete static-only user path:

```text
DSH session -> sample upload -> user asks for analysis
-> Agent discovers the attached Artifact
-> Agent asks a falsifiable question
-> Agent selects a bounded static action
-> action yields useful Evidence
-> mechanism fields are updated
-> Verifier and Claim Gate classify the result
-> static behavior flow and analyst-grade report are produced
-> user can navigate Report <-> Mechanism <-> Evidence <-> Chat
```

No task id, SQL, curl or manual tool orchestration is required from the user. The product may
show an observable trace but never private model chain-of-thought.

## 2. Non-negotiable boundaries

- Static-only: never execute samples, scripts, macros, shell commands or dynamic emulators.
- Never access sample-specified network targets.
- Never use reference reports, Gold, known sample hashes, RVAs or IPs as analysis input.
- Model text, imports and strings are leads; they are not runtime facts.
- Derived Evidence remains `STATIC_DERIVED` and carries evaluator, input Evidence IDs and
  input/output digests.
- Product fixes require a failing gate, a documented root cause, a red test and a negative
  control. Sample-specific production logic is prohibited.

## 3. Evidence levels and artifact requirements

Every acceptance claim is tagged with one of these levels:

| Level | Required artifact | Allowed use |
|---|---|---|
| L0 | source/test/static audit | implementation confidence |
| L1 | deterministic fixture or stub-model run | regression and CI |
| L2 | fresh real-sample run; real provider when the gate concerns model contribution | sample/semantic certification and model certification respectively |
| L3 | captured real DSH/browser path | product acceptance |
| L4 | recovery, replay, load, soak and hardening records | production certification |

For semantic C1-C4 and report-depth gates, L2 requires a fresh real sample through the static
pipeline but no model provider. For model-effectiveness gates, L2 additionally requires a fresh
real-provider call with an attributable response.

Each artifact records commit/tree identity, timestamp, configuration fingerprint, sample hash,
session/task ids, event cursor range and redaction status. A lower level never closes a higher
level gate.

## 4. Wave A - Agentic mechanism effectiveness

### A1. Instrumentation

Persist one `MechanismEffectivenessTrace` per investigated mechanism:

```json
{
  "seed": {},
  "question": {},
  "competing_hypotheses": [],
  "action_proposals": [],
  "tool_runs": [],
  "new_evidence_ids": [],
  "evidence_delta": {},
  "hypothesis_delta": {},
  "mechanism_delta": {},
  "verifier_result": {},
  "claim_gate": {},
  "report_projection": {}
}
```

Every model proposal carries `origin=model|deterministic_fallback`, a prompt/profile digest,
action validation result and target selector. Only `origin=model` can receive model-contribution
credit.

### A2. Productivity and autopsy

```text
useful action = new useful Evidence
              OR competing hypothesis eliminated
              OR missing mechanism field completed
productivity = useful_model_actions / accepted_model_actions
```

Certification requires >= 6 accepted model actions/sample, productivity >= 50%, one model
Evidence delta consumed by a mechanism, and >= 3 useful model actions for ComHost. Every
`NO_NEW_EVIDENCE` is classified as one of the seven autopsy causes from the source plan and
includes selector, target, dedup key, boundary and next-action data.

### A3. Seeded and blind gates

For C1-C4 seeded fixtures, require 4/4 question quality, applicable competing hypotheses,
useful action, new Evidence, >=80% mechanism completeness, verifier pass and zero unsupported
critical claims. Repeat the complete suite three times with fresh run ids. Then run blind
ComHost discovery with only “analyze this sample”. Seeded fixtures are L1; real ComHost is L2.

## 5. Wave B - static semantic recovery

C1-C4 are static semantic mechanisms, not runtime execution claims:

- **C1**: hash resolver loop, PE export directory fields, hash input, matched exports and
  consumer/global table; explicitly distinguish export resolver, PE validator and manual mapper.
- **C2**: resolved WinHTTP APIs, configured host/port/secure flag, request path/method, response
  consumer and retry/check-in relation; use configured/possible wording only.
- **C3**: CreatePipe/CreateProcessW, command-line source, creation flags, stdout/stderr read,
  timeout, cleanup and output consumer.
- **C4**: EtwEventWrite resolution, VirtualProtect, target address, exact `33 C0 C3` bytes,
  protection restore and FlushInstructionCache.

For each mechanism require Input, Transformation, Condition, Output and Consumer, plus
function/RVA and critical argument provenance. Missing fields remain `UNKNOWN` or
`STATIC_BOUNDARY`. The C1-C4 gate is closed only when each is `SUPPORTED` or `VERIFIED` by an
L2 static run, with critical unsupported count zero. Runtime behavior remains explicitly
unverified.

Secondary mechanisms are explored only when they are selected by a failing seed/coverage gate;
they do not justify adding new playbooks or report sections.

Wave B acceptance thresholds are explicit: high-value seed closure >=90%, visible unresolved
candidates <=8, candidate noise <=20%, critical mechanism completeness >=80%, recoverable API
argument coverage >=80%, and at least one ordered behavior flow with >=4 nodes and >=3 anchored
relations. A decoder candidate must identify input/output buffers, loop, state or key, formula,
consumer and deterministic replay. A register-zeroing XOR sequence is a required negative
control and must produce zero decoder positives. PE classification must keep validator,
export/import resolver, manual mapper and resource parser distinct; MZ/PE bytes alone must not
classify as manual mapping.

## 6. Wave C - analyst-grade report

The report must contain the existing core sections: executive assessment, artifact/static
profile, high-value findings, configuration/deobfuscation, orchestration, mechanism deep dives,
static behavior flow, IOC/hunting, ATT&CK, unknown/rejected and coverage.

For five sampled core findings, require all HOW fields, evidence ids, alternative hypothesis,
static boundary and function/RVA. A finding supported only by an import or string is rejected.

Score the report with the defined 100-point rubric and require >=80. New deep Evidence must
create a new immutable snapshot and report revision. Resume regression must include the required
positive mechanisms and the stated negative Gold; no active C2, theft, family attribution or
durable persistence may be overclaimed.

The report comparison records mechanism depth, function/argument detail, recovered configuration,
flow, IOC/hunting usefulness, Unknown discipline and overclaim count for both Resume and ComHost.
Decoded-only plaintext is not emitted as a raw YARA plaintext rule; rules use raw bytes, encoded
patterns or stable raw strings only.

## 7. Wave D - DSH/browser product E2E

### D0 environment gate

Require Docker/DSH availability, pinned `threat-static` profile, API and workbench health,
same-origin session binding, a clean capture directory and redacted logging. Failure is
`BLOCKED`, not a skipped pass.

### D1-D15 user path

Capture a fresh run proving New Session -> Upload -> “analyze this sample” -> Agent trace ->
action -> Evidence -> Mechanism -> report/export. The capture must show event cursors and ids,
not task-id instructions. Verify session A/B isolation, same-workspace reset, A->B->A stale-data
absence, refresh/restart recovery, failure stage/code/retryability, transient auto-retry and no
blind retry loop for deterministic failures. Include a >=20 minute long analysis with a
responsive chat and bounded event-driven waits. Exercise browser refresh, browser restart,
mechanism-to-evidence deep links, report revision after follow-up analysis and session switching.

## 8. Wave E - generalization

Create a manifest before running:

```text
development: 15 malware + 5 benign
held-out:     5 malware + 5 benign
```

Each item has SHA-256, class, provenance/license, archive-password policy and Gold location.
Gold is evaluator-only. If the corpus is smaller, the result is `NOT_CERTIFIED` and the claim
is narrowed to the observed corpus; no synthetic or historical item silently fills the gap.

Held-out gates: critical mechanism recall >=80%, precision >=95%, critical relation recall
>=75%, precision >=95%, Unknown F1 >=85%, critical unsupported=0, report pass >=80%, traceability
100%, benign critical-malicious false positives=0. Any P0/P1 invalidates the held-out run and
requires a new release candidate and a full rerun.

## 9. Wave F - reliability

Run fresh, timestamped scenarios for DSH/backend/PostgreSQL/MinIO/Temporal/worker/model-gateway
restart and browser reconnect. Verify event replay with >=10,000 events, 3 concurrent full
analyses plus 5 smoke analyses, context stress at >=500 events/100 ToolRuns/20k Evidence, and a
fresh 24-hour soak. No lost/duplicate/ordered events, cross-case contamination, unrecovered
crash, corruption or manual repair is allowed.

## 10. Wave G - production hardening

Before freeze, obtain a trusted Git commit SHA. Record container digest, DSH commit, plugin
digest, prompt/profile hash, model version, benchmark hash and Gold hash. Complete secret
rotation, dedicated worker identity, non-root/minimal ports, health/readiness, SBOM, CVE scan,
backup/restore and RBAC or an explicit single-user deployment declaration.

Record the existing Ruff format-debt baseline (63 files) and fail CI when new debt exceeds that
baseline. A later format-only change may reduce the debt, but formatting churn must not be mixed
with semantic fixes.

Run independent malware-analyst, architecture, security, reliability and product reviews.
Architecture review must verify DSH core diff=0, one analysis context, one gateway, one policy
gate and zero sample-specific production hits. Security review must verify no execution, no
sample network, no IDOR/path escape/prompt-injection bypass and Gold isolation. Every reviewer
records `APPROVED` or a blocking finding; a missing reviewer is not an implicit approval.

## 11. Release gate and stop rules

The only releasable result is:

```json
{
  "status": "PASS",
  "production_ready": true,
  "open_p0": 0,
  "open_p1": 0,
  "agentic_mechanism_effectiveness": "PASS",
  "comhost_c1_c4": "PASS",
  "analysis_depth_gate": "PASS",
  "report_depth_gate": "PASS",
  "browser_e2e": "PASS",
  "generalization": "PASS",
  "recovery": "PASS",
  "concurrency": "PASS",
  "soak_24h": "PASS",
  "production_hardening": "PASS",
  "independent_reviews": "APPROVED"
}
```

Otherwise status remains `BLOCKED` with named missing evidence. Feature work is allowed only
after a failing gate has a root cause, red test, general fix and negative control. The project
must not create another planning round to hide residual P0/P1.

The release dashboard must publish, for the same release identity: unit/integration results,
model action productivity and useful-Evidence count, critical mechanism and high-value seed
closure, candidate noise, report depth, ComHost C1-C4, Resume regression, browser E2E,
context/recovery/concurrency/soak status and open P0/P1 counts.

## 12. Execution order

1. Freeze evidence schema and action-origin instrumentation.
2. Run seeded C1-C4 and NO_NEW_EVIDENCE autopsy.
3. Repeat seeded suite three times and run blind ComHost.
4. Run Resume/ComHost report-depth regression.
5. Execute DSH/browser E2E and session-isolation matrix.
6. Build and validate corpus manifest; run development then held-out.
7. Run recovery, replay, concurrency, context stress and 24-hour soak.
8. Freeze release identity, complete hardening and independent reviews.
9. Publish one final gate artifact; otherwise publish `BLOCKED` with evidence gaps.
