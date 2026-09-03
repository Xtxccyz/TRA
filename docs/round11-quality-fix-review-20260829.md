# Round 11 Quality Fix Review

**Review date:** 2026-08-30  
**Scope:** Reporting fixes and the four-sample development/generalization run  
**Decision:** Code-level fix review passed; external certification gate remains BLOCKED.

## 1. Review Basis

This review uses the implementation currently running in Docker, the latest
task/report revisions retrieved from the API, the machine-readable result at
`.scratch/round11-postfix-20260830-latest.json`, and a fresh full test run. The
historical files under `reports/round11-dtest-*.md` were generated before the
latest report-revision fix and are retained as historical artifacts; they are
not used as the latest-report evidence below.

The repository has no Git metadata, so a commit-diff review against `HEAD`
could not be performed. The substitute review is source-level and runtime
based: implementation inspection, focused assertions over the generated
revisions, API/Compose health checks, and the complete automated test suite.

## 2. Problems Found Before This Fix

The previous report renderer had three auditability/usability gaps:

1. The static-only safety boundary was present in task metadata but was not
   always explicit in the human-readable report.
2. Semantic coverage and pipeline completion were not clearly separated,
   making a completed report pipeline easy to confuse with complete behavioral
   analysis.
3. A report with no model-generated candidates could omit the model section,
   which made it unclear whether the model was called, rejected, or had no
   admissible output.

These were reporting-contract defects, not evidence-generation failures.

## 3. Source-Level Fixes

### `src/threat_report_agent/reporting.py`

- The report header now explicitly emits `Sample execution: **false**` for
  the static phase.
- Analysis Coverage is rendered as two separate values: semantic coverage and
  pipeline completion, including their dimensions and gaps.
- `Model-Synthesized Candidates` is always rendered. An empty candidate list is
  represented explicitly instead of being silently omitted.
- Mechanism output keeps the required fields: Input,
  Transformation/Control, Condition, Output, Consumer, Side Effect, and
  supporting Evidence IDs.
- Evidence Explorer remains the traceability path for full tool output and
  detailed function/string records; the report does not dump complete raw
  Strings or Imports inventories into the narrative.

### `tests/test_reporting.py`

Focused regression assertions now require the execution boundary, model
section, semantic score, pipeline score, mechanism fields, and Evidence
Explorer marker in the rendered Markdown.

## 4. Four-Sample Runtime Verification

All four samples were submitted through the running HTTP intake and Temporal
static-analysis path. No sample was executed and no sample network access was
allowed.

| Sample | Size | Lifecycle | Outcome | Analysis class | Artifacts | Evidence | Trace steps | Audit | Sample execution |
|---|---:|---|---|---|---:|---:|---:|---|---|
| `Architouch-1.0.0.exe` | 112,128 | `SUCCEEDED` | `PARTIAL` | `BOUNDED_STATIC_ANALYSIS` | 1 | 22,117 | 3,275 | valid | false |
| `Doublepulsar-1.3.1.exe` | 45,568 | `SUCCEEDED` | `PARTIAL` | `BOUNDED_STATIC_ANALYSIS` | 1 | 8,952 | 4,584 | valid | false |
| `Eternalblue-2.2.0.exe` | 129,024 | `SUCCEEDED` | `PARTIAL` | `FULL_STATIC_ANALYSIS` | 1 | 28,933 | 3,761 | valid | false |
| `Pcdlllauncher-2.3.1.exe` | 337,408 | `SUCCEEDED` | `PARTIAL` | `BOUNDED_STATIC_ANALYSIS` | 1 | 11,755 | 6,714 | valid | false |

The machine-readable record reports `status=PASS` and `sample_count=4`. The
four latest report revisions were fetched directly from the API and checked
for the following contract markers:

- explicit static-only execution boundary;
- `Model-Synthesized Candidates` section, including the no-candidate case;
- semantic and pipeline coverage values;
- six mechanism fields and Evidence Explorer traceability;
- absence of standalone `## Strings` or `## Imports` raw-dump sections.

All four latest revisions passed those assertions. Their revision IDs are:

- Architouch: `25c5d22f-1560-4f8d-b53e-a4e3a9d455c2`
- Doublepulsar: `4f8372ae-d331-4a0c-82e4-f20fefdf2770`
- Eternalblue: `46417adc-a5c8-4c10-a722-bb1b38d5f098`
- Pcdlllauncher: `76fc1ed9-0cc8-4db0-933d-3bca78811aba`

The observed `PARTIAL` outcomes are intentional. For bounded samples the
task records missing custom components, unresolved imports/ordinals,
obfuscation limits, and the absence of runtime evidence instead of upgrading
an inference to a confirmed behavior.

## 5. Automated Verification

Fresh verification on 2026-08-30:

- `python -m pytest -q`: **311 passed, 1 warning, 27.71s**
- Focused reporting/runtime checks: **37 passed**
- `ruff check src tests`: passed
- `python -m compileall -q src`: passed
- Docker Compose: all 10 services running; PostgreSQL and MinIO healthy.

The only test warning is an upstream `RequestsDependencyWarning` caused by
the installed `urllib3`/`chardet` version combination; it does not fail the
suite or change analysis behavior.

## 6. Honest Boundaries and Certification Status

This run proves a usable static evidence pipeline and auditable report
generation. It does **not** prove that the malware executed, that network or
file-system behavior occurred, or that every inferred mechanism is correct.
The optional flare-emu, Qiling, and Speakeasy adapters remain disabled in the
static phase. Model planning/replanning and deterministic fallback are
recorded in the task trace; private chain-of-thought is not persisted.

`release-artifacts/round11-release-gate.json` remains intentionally
`BLOCKED` with 37 blockers. The gate has no evaluator-owned Gold corpus and
therefore its zero-sample metrics are not certification evidence. Still
outstanding external gates include the labeled malware/benign development and
held-out corpora, evaluator Gold answers, retrieval/quality metrics, browser
E2E, restart/recovery, concurrency, soak, independent review, and security
boundary proofs.

No database volume, MinIO volume, historical report, or user sample was
deleted during this review.

## 7. Final Disposition

The reporting defect fix is accepted at code and runtime level. The four real
sample runs are valid development observations and the full automated suite
is green. Round 11 must remain a pre-certification build until the external
certification inputs and operational gates listed above are supplied and
measured; changing the release gate to PASS would be an unsupported claim.
