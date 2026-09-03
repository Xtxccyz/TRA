# Final Completion Stage Plan Review

Date: 2026-09-02  
Scope: `F:/迅雷下载/final-completion-stage-plan.md` and the current repository state  
Review mode: specification, feasibility, evidence, security and release-gate review

## Decision

The plan is directionally correct and can reach the stated product goal, but it is not
acceptance-ready as written. It mixes four different evidence levels and therefore allows a
code-level implementation or a synthetic fixture to look like a production certification.

Decision: **CONDITIONALLY FEASIBLE after the amendments in the companion reviewed plan.**

The final product goal remains valid:

```text
Upload -> Chat -> Agent plan -> useful static action -> new Evidence
-> mechanism closure -> verifier/claim gate -> analyst-grade report
```

The repository is not at that final gate today. The latest local gate is
`BLOCKED`/`production_ready=false`; ComHost C1-C4, model evidence contribution, browser E2E,
long-turn/context stress, restart/recovery, concurrency, soak and generalization remain
unproven.

## What the original plan gets right

- The dependency order (agent effectiveness, semantic depth, report, product E2E, corpus,
  reliability, hardening) is technically sound.
- The static-only boundary is compatible with mechanism recovery when every result is phrased
  as configured, possible, inferred or unknown rather than observed at runtime.
- Seed -> question -> competing hypotheses -> action -> evidence -> verifier -> report is the
  correct control-plane contract.
- Resume and ComHost are appropriate regression references, provided their reports remain
  evaluator-only and are never sent into the analysis context.
- A final `PASS` must require `production_ready=true`, zero open P0/P1 and independent review.

## Blocking ambiguities corrected by the amendment

### 1. Evidence levels were not separated

The plan now uses five explicit levels:

| Level | Meaning | Counts toward release? |
|---|---|---|
| L0 | Source-code/static contract and unit tests | Code confidence only |
| L1 | Deterministic fixture or stub-model integration | Regression only |
| L2 | Fresh real-sample run; real provider when the gate concerns model contribution | Sample/semantic gates and model gates respectively |
| L3 | Fresh browser/DSH user-path capture | Product E2E gates |
| L4 | Failure, recovery, concurrency, soak and hardening evidence | Production gate |

L0/L1 evidence cannot close an L2-L4 gate. Historical artifacts are context only and cannot
replace a fresh run.

For semantic C1-C4 and report-depth gates, L2 means a fresh real sample through the static
pipeline and does not require a model provider. For model-effectiveness gates, L2 additionally
requires a fresh real-provider call with an attributable response.

### 2. C1-C4 conflicted with static-only wording

C1-C4 are renamed **static semantic recovery mechanisms**. They may recover resolver logic,
configured transport, shell-output plumbing and ETW patch bytes from static evidence. They do
not execute a sample, call a simulator, contact a C2 or assert runtime success. Any requirement
for runtime observation is out of scope for this static-only release and must remain a separate
blocked gate.

### 3. Model action productivity was underspecified

The denominator and attribution are now fixed:

```text
productivity = useful_model_actions / accepted_model_actions
```

An action counts only when its proposal came from the real model, passed policy and target
validation, executed through the closed static catalog, and produced either new useful Evidence,
an elimination of a competing hypothesis, or a completed mechanism field. Deterministic
fallback actions, rejected actions and duplicate-suppressed actions are reported separately and
cannot inflate the numerator.

Required minimums: at least six accepted model actions per certification sample, productivity
>= 50%, and at least one model-attributed Evidence delta consumed by a mechanism. ComHost
requires at least three useful model actions.

### 4. Sample corpus prerequisites were implicit

The repository currently exposes only a small local corpus under `D:\test`; it does not prove
the required 15/5 development split and 5/5 held-out split. The amended plan requires a signed
corpus manifest containing path, SHA-256, class, license/source, archive password handling and
analysis status. Missing samples result in `NOT_CERTIFIED`, never fabricated positives or a
silently reduced universal claim. Synthetic fixtures may validate control flow but do not count
as malware/benign certification.

### 5. Browser and DSH prerequisites were not a gate

The browser wave now begins with an environment check for Docker/DSH, the pinned workbench
profile, API health, same-origin session binding and a capture directory. If any prerequisite is
missing, the wave is `BLOCKED` and no “browser passed” claim is allowed. The required capture
contains session id, event cursor, action/evidence/mechanism ids and report revision, with secrets
redacted.

### 6. No-Git repositories could not satisfy the release identity requirement

The final release must have a Git commit SHA. Before release-candidate freeze, the repository
must be initialized or restored with a trusted commit. A deterministic tree hash is an audit
aid only; it is not an acceptable substitute for the final production gate.

### 7. Private model chain-of-thought was not explicitly bounded

The product may display an observable investigation trace (questions, hypotheses, actions,
state transitions, evidence deltas and verifier results). It must never display or persist
private chain-of-thought. “Thinking chain” in product requirements is therefore implemented as
an auditable reasoning summary, not hidden token-level reasoning.

### 8. Stop rules needed to prevent scope expansion

Feature work is permitted only when a failing gate has a documented root cause and a red test.
No new provider, playbook, report section, dynamic executor or DSH-core patch may be added to
make a metric look better.

## Current repository cross-check

| Area | Current evidence | Review result |
|---|---|---|
| Static investigation control plane | `src/threat_report_agent/investigation.py`, service integration, tests | PASS at L0/L1 |
| Semantic recovery and provenance | deep-analysis reports and focused tests | PASS at L0/L1; real-sample depth pending |
| Model gateway | implemented and mocked in tests | PASS at L0/L1; L2 contribution not proven |
| Report structure | V3 sections, seed map, static-only wording | PASS at L0/L1; analyst-grade score pending |
| ComHost C1-C4 | `release-artifacts/comhost-runtime-regression.json` | BLOCKED (`NOT_VERIFIED`) |
| Model useful Evidence | `release-artifacts/agent-participation.json` | BLOCKED (`NOT_PROVEN`) |
| Browser path | `release-artifacts/browser-runtime-e2e.md` | BLOCKED (`NOT PROVEN`) |
| Reliability | final runtime gate artifact | BLOCKED |
| Source identity | repository has no `.git` directory | BLOCKED for final release |

## Review conclusion

The amended plan can serve as the final completion plan. It is feasible only as a gated
certification program, not as a promise that all external evidence can be generated by code
changes alone. The correct end state is either:

1. `PASS` with all L2-L4 evidence and independent approvals, or
2. `BLOCKED` with named missing evidence and no production-ready claim.

## Original-plan coverage matrix

| Original sections | Covered by reviewed plan | Result |
|---|---|---|
| 0-4 objective, product definition, stop scope and priorities | 1-2, 11 | Preserved and made explicit |
| 5-16 Agentic effectiveness, trace, productivity, autopsy, seeded/blind gates | 4 | Preserved with evidence levels and attribution |
| 17-30 C1-C4, semantic recovery, thresholds and behavior flow | 5 | Preserved; static-only terminology clarified |
| 31-40 report sections, depth score, Resume/ComHost, YARA and revisions | 6 | Preserved with reject rules |
| 41-56 browser E2E, isolation, long turn, refresh/restart and retry | 7 | Preserved as D0-D15 |
| 57-63 corpus, Gold, held-out and benign metrics | 8 | Preserved with manifest prerequisite |
| 64-68 recovery, replay, concurrency, context and soak | 9 | Preserved with fresh evidence requirement |
| 69-77 hardening, source identity and independent reviewers | 10 | Preserved with no-Git blocking rule |
| 78-93 final P0/P1, dashboard, order, stop rules and success standard | 11-12 | Preserved; one final gate artifact required |
