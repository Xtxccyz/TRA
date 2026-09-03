# Round 11 Implementation Status

## Implemented in this increment

- Public `AnalysisResultClass` contract with strict aggregation of `FULL_STATIC_ANALYSIS`, `BOUNDED_STATIC_ANALYSIS`, `UNSUPPORTED_ARTIFACT`, and `FAILED_ANALYSIS`.
- Artifact result classification that distinguishes an unavailable analyzer from an explicit static boundary.
- Public Supported Artifact Matrix and corpus split validator.
- Generic `GENERIC_MECHANISM_INVESTIGATION` playbook and fallback questions/actions for unfamiliar mechanisms.
- Report V3 metadata: report version, analysis class, static coverage, and the required reconstructed static behavior-flow disclaimer.
- Static-only wording gate for unqualified runtime assertions.
- Static-only wording gate handles multi-word negative/conditional clauses and
  evaluates every match in a line, preventing both false rejection and
  same-line bypasses.
- Static acceptance entrypoints wait for API health after Compose restarts,
  making the documented verification commands deterministic.
- Persisted task `analysis_class` and `coverage`, exposed through `task_view` and snapshots.
- Deterministic coverage score and offline release metric/gate helpers.

## Tests

The full Python suite is green (`304 passed`, one dependency deprecation warning).
Round 11 behavior tests cover result classification, aggregation, wording safety,
coverage bounds, corpus validation, and a non-forgeable blocked release gate.
`ruff check src benchmarks scripts tests`, Python compilation, Compose config
validation, and the DSH typecheck/manifest/security/core-diff checks also pass.

The rebuilt Compose stack passed `/healthz` and the live static acceptance probe
(`05549a24-f76a-4f29-97d7-20fbdbcf5d3c`). A fresh OOXML carrier probe
(`4c60b3ef-5f0c-471e-ba12-3721fc799d12`) passed after the wording-gate fix and
verified child Artifact provenance.
The carrier probe verified child Artifacts plus `CONTAINS` and `EXTRACTED_FROM`
relations; with a configured remote model its runtime exceeded the old short
probe timeout, so the probe now uses a configurable 600-second default and
accepts truthful `COMPLETE`/`PARTIAL` result classes.

The Round 11 release-gate entrypoints are runnable directly from a fresh
checkout (`python scripts/round11_release_gate.py --help` and
`python scripts/build_round11_corpus.py --help`); they no longer depend on an
editable install merely to resolve repository-local evaluator modules.

## Development pre-cert baseline

On 2026-08-29 the current release candidate was run against four real samples
using only the static API/Temporal path. The run record is
`.scratch/round11-development-precert-baseline-20260829.json` and is not a
certification result. All four tasks reached `SUCCEEDED` with truthful
`PARTIAL` outcomes and `BOUNDED_STATIC_ANALYSIS` classes; audit integrity was
valid for every task and no sample-execution or sample-network event was
observed. Evidence/Claim counts were 36,807/146, 41,420/113, 40,487/190 and
9,297/45 respectively. The first three tasks took approximately 8, 10 and 16
minutes; the initial batch driver timed out while polling the third task, which
prompted the bounded `/status` polling endpoint and incremental result writes.

## Not yet certifiable

The release plan requires 20 held-out malware samples, 10 benign controls, fresh certification runs, browser E2E, restart/recovery, concurrency, soak, and independent reviewers. Those are external verification gates and must remain `BLOCKED` until real environments and isolated corpora are available. No fixture or historical report is used to claim those gates.
