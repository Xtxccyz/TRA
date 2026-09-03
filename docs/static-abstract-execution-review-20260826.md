# Static Abstract Execution Review

## Scope

This review re-checks the previous capability audit and closes one concrete
gap: static analysis previously exposed parser fields and a safe emulator
capability probe, but did not produce a bounded execution-like prediction that
could participate in investigation and reporting.

The implementation deliberately does not execute a sample, script, macro,
network request, or optional emulator. The term "simulation" in this document
means static abstract execution over already-produced Ghidra/static evidence.

## Previous Audit Reconciliation

The previous audit was correct about the following boundaries:

- the investigation loop, queue, state machine, persisted hypotheses, verifier,
  and Claim Gate are present;
- Qiling, Speakeasy, and flare-emu are capability seams only and are not run;
- a Resume-level result still requires a real sample regression and must not be
  inferred from unit tests alone.

The remaining material gap was that the investigation loop mostly queried
static rows. It did not carry an abstract register/memory/path state or an
ordered predicted mechanism trace.

## Implemented Closure

### Static abstract executor

`src/threat_report_agent/static_simulation.py` adds:

- bounded abstract register and memory state;
- constant assignments and simple arithmetic tracking;
- branch and path-condition recording;
- address-aware merging of instruction and call-reference order;
- API semantic classes for allocation, memory writes, protection changes,
  thread/injection, process discovery/creation, network, and dynamic symbol
  resolution;
- mechanism candidates for memory loading, memory execution, PPID spoofing,
  network staging, and dynamic loading;
- explicit unknowns, confidence, budget, and limitations.

Every result contains:

```json
{
  "simulation_kind": "static_abstract_execution",
  "runtime_observed": false,
  "predicted": true,
  "steps": [],
  "path_conditions": [],
  "mechanism_candidates": [],
  "unknowns": [],
  "limitations": []
}
```

### Evidence and investigation integration

The Ghidra persistence path emits an `abstract_execution_trace` Evidence row
for every function. Its anchors retain function entry/RVA and source Evidence
IDs. Investigation actions that require deeper context (`GET_CFG_SLICE`,
`GET_PCODE_SLICE`, `TRACE_API_ARGUMENT`, `TRACE_RETURN_VALUE`,
`TRACE_GLOBAL_USAGE`, `READ_BYTES`, and `GET_DECOMPILE`) invoke the same safe
executor over the current static rows. This keeps the hypothesis/action/evidence
loop connected to a real analysis result rather than a generic observation.

The static Agent promotes only explicit mechanism candidates to candidate
Claims. The trace remains linked Evidence, and all statements retain the
condition that runtime execution is unverified.

### Report integration

The static triage report now includes a `static_simulation_prediction` row with:

- function and RVA;
- predicted operation/API sequence;
- inputs and abstract outputs;
- path conditions;
- mechanism candidates and ATT&CK candidate IDs;
- unknowns and limitations;
- `runtime_observed: false`.

The report and analysis trace continue to expose structured investigation
events, actions, evidence IDs, and gate outcomes. Private model chain of
thought is not exposed.

## Verification

The following checks pass:

- `pytest -q`: **210 passed**;
- `ruff check src tests`: **All checks passed**;
- `python -m compileall -q src tests`: **passed**.

Coverage includes:

- `VirtualAlloc -> WriteProcessMemory -> VirtualProtect -> CreateThread`;
- `CreateToolhelp32Snapshot -> Process32First -> OpenProcess ->
  UpdateProcThreadAttribute -> CreateProcessW`;
- register constants and unresolved branch conditions;
- budget exhaustion and unknown API semantics;
- end-to-end Ghidra evidence persistence containing
  `abstract_execution_trace`.

## Remaining Honest Boundaries

This change does not claim:

- runtime observation or actual Qiling/Speakeasy/flare-emu execution;
- complete symbolic execution, alias analysis, or opaque predicate solving;
- universal recovery of every malware mechanism;
- a completed Resume sample comparison.

The next validation gate is a read-only Resume sample run and a structured
comparison of phase ordering, XOR recovery, PPID evidence, mechanism chains,
and final outcome. Any unsupported or contradictory path must remain UNKNOWN
or CANDIDATE rather than being upgraded by the abstract trace alone.
