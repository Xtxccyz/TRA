# Capability Re-audit: Evidence-Driven Investigation

Date: 2026-08-26

## Verdict

The prior `capability-audit-20260826.md` was materially correct for the code
state it examined. Its P0 findings are now implemented and exercised through
the service path. The system is no longer only a deterministic field listing:
it runs a bounded, evidence-driven investigation loop after static extraction.

This is a capability correction, not a claim that dynamic execution or
universal Resume-level conclusions are complete.

## Findings Rechecked

| Finding | Current status | Evidence |
|---|---|---|
| Recursive investigation loop | Implemented | `InvestigationLoopDriver.run()` performs Hypothesis -> Action -> Evidence -> verification -> state update. |
| Investigation queue | Implemented | `InvestigationQueue` provides priority ordering, dependency blocking, de-duplication and a step budget. |
| Action catalog | Implemented | `ActionCatalog.default()` exposes 17 typed static actions; unknown action types are rejected. |
| Thread state machine | Implemented | `ThreadStateMachine` rejects illegal transitions and the service persists the resulting state. |
| Hypothesis persistence | Implemented | `investigation_threads`, `investigation_hypotheses`, and `investigation_actions` are SQLAlchemy records created by the service. |
| Hypothesis -> Claim gate | Implemented for investigation upgrades | `Verifier` delegates to `ClaimGate`; investigation-generated behavior Claims are created only after required evidence predicates pass. Legacy parser claims remain conservative `CANDIDATE` outputs with ordinary Evidence-reference validation. |
| Investigator/Verifier split | Implemented | `Investigator.propose()` and `Verifier.evaluate()` are separate seams used by the loop driver. |
| Dynamic simulator execution | Deliberately bounded | `IsolatedSimulationRunner` has an adapter seam, but denies execution unless explicit policy and isolated-worker flags are both present. No dynamic observation is fabricated. |

## What Is Actually Executable

For every non-container Artifact, the service now:

1. Reads only already-recorded static Evidence.
2. Creates or resumes a durable investigation thread and hypothesis.
3. Enqueues typed actions and records each action as an investigation ToolRun
   when it produces observations.
4. Derives new `STATIC_INFERRED` Evidence with action and Artifact anchors.
5. Re-evaluates the hypothesis through an AND-style Claim Gate with nature and
   contradiction checks.
6. Persists `SUPPORTED` or `UNKNOWN`, and emits a behavior Claim only for a
   passing gate.
7. Adds runtime investigation events to the strategy snapshot, redacted trace,
   task view, and report timeline.

The PPID vertical slice is covered end to end: seed/API observations can drive
`GET_FUNCTION`, `GET_STRINGS_REFERENCED`, `GET_CALLEES`,
`TRACE_API_ARGUMENT`, and `EVALUATE_CONSTANT`; the verifier requires
`OpenProcess`, `UpdateProcThreadAttribute`, and
`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` before producing the candidate
Parent-PID-Spoofing Claim. Missing evidence produces `UNKNOWN` instead.

The generic verifier also requires two independent static observation classes,
so unrelated strings cannot become a behavior Claim by themselves.

## Boundaries and Remaining Work

- The investigation actions currently query the static evidence graph. They do
  not execute the sample, invoke macros, contact a network, or emulate runtime.
- Ghidra, Qiling, Speakeasy, and flare-emu remain behind isolated worker seams;
  availability is reported truthfully, and unavailable adapters are not
  represented as dynamic observations.
- The model gateway may propose typed actions, but catalog and policy checks
  remain authoritative. Model failure falls back to deterministic investigation.
- Resume-level coverage for every decoded child still depends on expanding child
  type detection and additional bounded static action executors.

## Verification

The following checks pass after this change:

```text
pytest -q                 250 passed
ruff check src tests      All checks passed
python -m compileall -q src
```

The new tests cover catalog size and policy, queue dependency and budget
behavior, illegal state transitions, Claim Gate thresholds and contradictions,
recursive PPID investigation, service persistence, and dynamic simulation
denials. Existing API, worker, audit, reporting, Ghidra, similarity, and static
analysis tests continue to pass.

## Review Conclusion

The previous 42.5% assessment should be updated for the P0 Agentic
Investigation items: those items are now real, persisted, and tested. The
system should be described as a static evidence-driven investigation Agent
with a bounded action loop and explicit dynamic-execution boundary. It should
not yet be described as a fully dynamic reverse-engineering platform or as
guaranteeing a complete Resume-equivalent report for every sample.
