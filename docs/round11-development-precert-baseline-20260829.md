# Round 11 Development Pre-Cert Baseline

Generated on 2026-08-29 from four real artifacts submitted to the running
Compose product. This record is a development/generalization observation, not
the evaluator-owned Round 11 certification corpus.

## Scope and safety

- Runtime path: HTTP intake -> Temporal static workers -> evidence-driven
  investigation -> report synthesis.
- Sample execution: not performed.
- Sample network access: not performed.
- Gold answers, reference reports, and evaluator labels: not supplied to the
  runtime, planner, retriever, model context, or RAG.
- Every task reached `SUCCEEDED`; every audit integrity check was valid.

## Results

| Sample | Task | Lifecycle | Outcome | Analysis class | Artifacts | Evidence | Claims | Audit events |
|---|---|---|---|---|---:|---:|---:|---:|
| `dcdc3457...14b306` | `d941ac80...ce0b1e` | `SUCCEEDED` | `PARTIAL` | `BOUNDED_STATIC_ANALYSIS` | 2 | 36,807 | 146 | 8,449 |
| `ComHost.exe.VIR` | `a870a248...2a1555` | `SUCCEEDED` | `PARTIAL` | `BOUNDED_STATIC_ANALYSIS` | 1 | 41,420 | 113 | 8,807 |
| `Resume.pdf ... .exe.VIR` | `49313e96...074190` | `SUCCEEDED` | `PARTIAL` | `BOUNDED_STATIC_ANALYSIS` | 3 | 40,487 | 190 | 5,464 |
| `Darkpulsar-1.1.0.exe` | `c5943b6e...7b3b84` | `SUCCEEDED` | `PARTIAL` | `BOUNDED_STATIC_ANALYSIS` | 1 | 9,297 | 45 | 3,903 |

The complete machine-readable record, including immutable sample paths and
task identifiers, is `.scratch/round11-development-precert-baseline-20260829.json`.

## Interpretation

The run proves that the current product can complete real static analyses,
persist large evidence ledgers, produce claims and reports, and preserve an
auditable static-only boundary. It does **not** prove mechanism precision,
unknown calibration, benign false-positive rates, report usefulness, or
production readiness. All four `BOUNDED_STATIC_ANALYSIS` results are treated
as observations requiring evaluator-owned expectations; no claim is made that
the boundary was correct without Gold.

The initial batch driver used the full task projection on every poll. On the
third sample that caused a client timeout and excessive API serialization,
although the server task later completed. The driver now polls the bounded
`GET /api/v1/tasks/{task_id}/status` projection, fetches the full task once at
termination, writes results incrementally, and can continue after an
individual timeout without discarding prior samples.

## Failure taxonomy

There were no terminal task failures in this baseline. Model planner/action
rejections and static limitations are recorded in each task's immutable
limitations and are not promoted to a primary product root cause without a
Gold expectation. The companion taxonomy record therefore reports zero
classified failures and lists the evidence needed to classify future failures:
artifact, seed/question, retrieval/delivery, action/tool, mechanism/verifier,
claim gate, report, and boundary classification.

## Certification status

Round 11 remains `BLOCKED`: the required 15 development malware + 5
development benign and 5 certification malware + 5 certification benign
corpus, evaluator-owned Gold, fresh certification metrics, browser E2E,
restart/recovery, concurrency, soak, and independent review are not present.
