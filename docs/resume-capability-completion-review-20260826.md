# Resume Capability Completion Review (2026-08-26)

## Scope and safety

This review covers the evidence-driven static analysis path requested by the Resume
reference report and `sample-analysis-workflow.md`. The reference report remained an
evaluation-only artifact and was not submitted to the service, model gateway, scheduler,
or evidence store. The two Resume PE files were read by Ghidra Headless only; no sample,
macro, shell, network request, or dynamic emulator was executed.

## Implemented vertical slices

### Investigation language and scheduling

- `InvestigationThread`, `Hypothesis`, and `Mechanism` are frozen structured contracts.
- Thread states are explicit: `DISCOVERED`, `PRIORITIZED`, `CONTEXT_READY`,
  `HYPOTHESIZING`, `INVESTIGATING`, `VERIFYING`, `MECHANISM_READY`, `CLAIM_READY`,
  `UNKNOWN`, and `CLOSED`.
- Every preset creates a stable thread/question/hypothesis before a model call.
- `DeterministicSeedRanker` produces a reproducible priority and expected-tool seed for
  every Artifact. Model failure therefore cannot remove mandatory coverage.
- `QuestionCentricContextBuilder` bounds model context and records omitted evidence count.
- Model actions retain artifact, question, expected evidence, focus, dependency, and policy
  checks. They are proposals, never authorization.
- Strategy snapshots and the redacted analysis trace expose state transitions and structured
  actions, while `private_chain_of_thought` remains withheld.

### Mechanism and evidence chain

- Ordered per-function API/instruction mechanisms are emitted as anchored Evidence and
  promoted to `STATIC_INFERRED` Claims.
- Bounded cross-function call paths are emitted as Evidence and Claims; inferred
  `LOADS`/`EXECUTES`/`INJECTS`/`DECRYPTS` Relations now preserve the chain in the relation model.
- Function context includes entry/RVA, xrefs, CFG blocks, instruction windows, interfaces,
  and fuzzy fingerprints.
- XOR verification supports both the existing rolling single-key form and
  `key_table[i % N] ^ counter` replay against file bytes. Replay is static-only and bounded.
- Windows process-creation constants are decoded into set flags. Unknown runtime effects are
  not asserted; in particular, absent bits are explicitly represented for
  `CREATE_SUSPENDED` and `CREATE_NEW_CONSOLE`.

### Report and trace

- The report front page contains analyst assessment before raw evidence.
- A structured investigation timeline contains questions, priorities, claims, relations, and
  evidence references. It does not contain model prompts, raw responses, or private reasoning.
- ATT&CK mappings remain candidate mappings with snapshot/version/hash and evidence IDs.
- Static-only limitations and unavailable simulation capabilities remain visible.

## Acceptance evidence

Focused and full test results after the implementation:

```text
pytest -q                         199 passed
ruff check src tests              All checks passed
python -m compileall -q src tests passed
```

Additional direct acceptance checks:

- Ghidra Headless on `Resume.pdf ... .exe.VIR`: `SUCCEEDED`, 704 functions.
- Ghidra Headless on `ComHost.exe.VIR`: `SUCCEEDED`, 3,455 functions.
- End-to-end service run on `Resume.pdf ... .exe.VIR`:
  - lifecycle `SUCCEEDED`, outcome `PARTIAL`;
  - 14 Artifacts, 61,173 Evidence rows, 200 Claims, 658 Relations;
  - 135 mechanism/cross-function Claims and 17 candidate ATT&CK mappings;
  - report length 528,754 characters and includes the investigation timeline;
  - audit integrity `valid=true`, 11,079 events, HMAC seal present.
- End-to-end service run on `ComHost.exe.VIR`:
  - lifecycle `SUCCEEDED`, outcome `COMPLETE`;
  - 1 Artifact, 216,183 Evidence rows, 152 Claims, 182 Relations;
  - 108 mechanism/cross-function Claims and 16 candidate ATT&CK mappings;
  - audit integrity `valid=true`.

`PARTIAL` is expected for this run because bounded resource/decoded children are not all
recognized as PE/script/document types. The root PE and Ghidra D3 path succeeded; unsupported
children are recorded as limitations rather than silently treated as analyzed.

## Residual boundaries

- Dynamic emulation adapters are capability probes only. Qiling, Speakeasy, and flare-emu are
  not claimed as executed unless an isolated future worker actually runs them.
- Static strings/API references remain hypotheses. They do not prove C2 connectivity,
  persistence, injection, or payload execution.
- The model gateway remains optional; deterministic planning and static mechanism synthesis are
  the guaranteed first-stage path.
- Full Resume-level semantic conclusions for every decoded resource still require a bounded
  child-type detector/decoder expansion and, where authorized, a later isolated dynamic phase.

## Review conclusion

The investigation framework is now a usable evidence-driven Agent path rather than a field
listing: it asks a bounded question, prioritizes and schedules tools, records hypotheses and
verification state, constructs mechanism Claims from ordered evidence, preserves Relations, and
renders an auditable report. The remaining `PARTIAL` state is explicit and attributable to
unsupported child artifacts, not an unreported failure or fabricated runtime conclusion.

## Post-review P0 completion update

After the initial review, the missing execution pieces were implemented in
`investigation.py` and integrated into the service:

- 17 typed static action kinds, priority/dependency queue, and bounded loop;
- durable thread, hypothesis, and action records;
- separate Investigator and Verifier seams with AND/OR Claim Gate support;
- persisted action/evidence/verification events in task views and reports;
- explicit `BLOCKED`, `REJECTED`, and `CONTRADICTED` state paths;
- context fields for call graph, P-code slice, contradictions, open unknowns,
  and action history;
- isolated simulation runner that truthfully denies execution without an
  explicit isolated-worker policy.

The post-review regression suite is `207 passed`; Ruff and compile checks also
pass. Dynamic emulation remains intentionally unavailable until a separately
authorized isolated worker adapter is deployed.
