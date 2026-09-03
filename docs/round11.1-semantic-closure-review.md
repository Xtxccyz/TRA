# Round 11.1 Semantic Closure Review

**Review date:** 2026-08-30  
**Decision:** Round 11.1 **PASS**; external Round 11 certification remains **BLOCKED**.

## Scope and method

This review follows `F:/迅雷下载/round11.1-semantic-analysis-closure-plan.md`.
The source, tests, Docker runtime, fresh HTTP submissions, task projections,
audit integrity endpoints, and the four latest report revisions were checked.
The repository has no Git metadata, so a commit-based diff review was not
possible; the substitute was file-level source review plus runtime assertions.

The static safety boundary was preserved throughout: samples were parsed and
analyzed only through the product's static pipeline. No sample was executed,
no sample-derived network request was sent, and no flare-emu, Qiling, or
Speakeasy execution was enabled.

## Implemented closure

- Explicit semantic API predicates prevent timing, environment-query, memory,
  and generic runtime APIs from becoming execution claims without an exact
  execution predicate.
- `mechanism_completeness.py` is the single semantic scoring implementation.
  UNKNOWN, navigation, xref prominence, API density, and `prioritizes` values
  do not receive semantic points; mandatory-field hard caps are applied.
- Mechanism projection preserves verifier-owned semantic fields. A bounded
  closure loop records targeted static actions and terminates with an explicit
  `Static boundary` / `missing evidence` limitation when closure is impossible.
- Core Findings are projected only from evidence-backed verified mechanisms or
  qualified security findings. Navigation and raw reference observations stay
  in the investigation/evidence trace.
- Security Meaning, IOC, and hunting text is mechanism-specific and remains
  explicitly static. Reconstructed behavior flow uses semantic nodes and does
  not promote low-level instruction paths to security findings.
- `docs/adr/ADR-static-analysis-result-class.md` defines FULL, BOUNDED, FAILED,
  and UNSUPPORTED result classes. Lack of dynamic evidence alone is not a
  bounded reason.

## Fresh four-sample evidence

The fresh run created new Cases and Tasks after the final image rebuild:

| Sample | Task | Lifecycle | Class | Evidence | Claims | Verified coverage | Behavior flow |
|---|---|---|---|---:|---:|---:|---|
| Architouch-1.0.0.exe | `720975c6-7130-4838-89b0-7096d93580f8` | SUCCEEDED | FULL_STATIC_ANALYSIS | 22,111 | 39 | 1.0 | present |
| Doublepulsar-1.3.1.exe | `92cf64fa-f01d-4427-8b7e-04aa408b4d69` | SUCCEEDED | BOUNDED_STATIC_ANALYSIS | 8,949 | 20 | 0.0 | bounded |
| Eternalblue-2.2.0.exe | `75767ed2-335d-4598-877b-8b397c742f96` | SUCCEEDED | BOUNDED_STATIC_ANALYSIS | 28,922 | 64 | 0.0 | bounded |
| Pcdlllauncher-2.3.1.exe | `2059dff9-e123-4308-a96b-525279a1d4c3` | SUCCEEDED | FULL_STATIC_ANALYSIS | 11,755 | 84 | 1.0 | present |

The FULL reports contain a verified dynamic-API-resolution mechanism with
module-name and entry-point data, resolved address, downstream consumer, and
supporting Evidence IDs. The bounded samples contain explicit structural
limits (`missing evidence: cipher/data`) rather than unsupported certainty.

## Gate results

The release gate is recorded in
`release-artifacts/round11.1-gate.json`. All Round 11.1 checks pass:

- four-sample rerun and task success;
- zero timing/system API execution misclassification;
- zero navigation-only Core Findings;
- zero high-completeness UNKNOWN mechanisms;
- zero generic Security Meaning placeholders;
- valid audit integrity for every task;
- static-only execution boundary remains false.

The full automated suite reports `342 passed, 1 warning`; `ruff check src
tests` and `python -m compileall -q src` pass. Docker Compose has all ten
services running, with PostgreSQL and MinIO healthy.

The DSH workbench checks also pass: typecheck, 5 unit tests, 7 runtime tests,
17 manifest validations, profile security validation (`dangerous_tools=0`),
legacy-webui guard, and the upstream core-diff guard (`upstream_core_diff=0`
at the pinned revision `47f943859bef60e4160492346772ded9b24f765a`). The DSH
smoke test served the Chinese product title and found no legacy text or
favicon.

## Product acceptance disposition

Round 11.1 is acceptable as a **static mechanism-analysis release candidate**,
not as the final product certification. The remaining blockers are external
to this semantic-closure round: the evaluator-owned 20-malware/10-benign
corpus and Gold labels, held-out certification metrics, browser E2E, restart
and recovery drills, concurrency and soak measurements, and independent
analyst/product review. These are intentionally recorded as BLOCKED and are
not claimed complete here.

Model calls are auditable (the fresh tasks recorded model-call attempts), but
the configured provider failed in this environment and deterministic fallback
was used. The report records that gap; it is not presented as successful model
reasoning.
