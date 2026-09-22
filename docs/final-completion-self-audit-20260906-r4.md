# Final Completion Self-Audit - 2026-09-06 (Core Analysis and Performance)

## Scope

This audit covers the core static-analysis, bounded investigation, report
projection, and local performance paths. The sample path used for the smoke
run was handled read-only. No sample, script, macro, dynamic emulator, or
network action was executed.

## Changes verified

- Static indicator matching reuses module-level compiled regular expressions;
  import matching remains exact and string matching remains boundary-aware.
- Static Evidence source recovery uses an anchor/locator inverted index while
  retaining strict anchor validation and the unanchored compatibility fallback.
- `TRACE_API_ARGUMENT` treats explicit API selectors as normalized exact API
  identities. Function/RVA selectors are treated as function scope and are
  never compared as API names. This preserves DLL-qualified API matching and
  function-local argument recovery.
- `GET_DECOMPILE` emits a provenance-bearing `function_semantic_summary`
  containing ordered API calls, static argument producers, branch conditions,
  consumers, and an explicit runtime-unobserved boundary.
- Semantic summaries admit only explicit call references or explicit
  `is_call`/`call` flags. DATA/READ/WRITE/JUMP references and `LAB_`/`DAT_`
  labels cannot enter the ordered call sequence.
- The primary Markdown projection shows the highest-priority 12 function
  summaries and reports the omitted count; lower-priority summaries remain
  available through the immutable Evidence ledger. This keeps IOC, ATT&CK,
  unknown-boundary, and coverage sections inside the 40 KiB presentation
  budget.
- Duplicate Ghidra call projections are removed by `(API, callsite, target)`;
  distinct callsites remain separate.
- Unresolved internal dispatch labels (`FUN_*`, `PTR_FUN_*`, `PTR_PTR_*`) are
  excluded from the primary ordered-call narrative when no semantic target is
  recovered. Their count and concrete constant/string argument clues remain
  visible, and the source `function_semantic_summary` Evidence ID remains the
  drill-down anchor.
- Same-callsite API aliases (case/import-pointer variants) are collapsed in the
  analyst projection using normalized API identity plus callsite; calls at
  distinct callsites remain separate and their argument provenance is merged.

## Verification

- Full regression: `665 passed, 2 skipped, 1 warning` (`pytest -q`).
- Core targeted regression: `115 passed` across investigation, deep mining,
  service, and Ghidra performance suites.
- Report/deep-mining/performance targeted regression: `86 passed`.
- `ruff check src tests scripts`: PASS.
- `python -m compileall -q src/threat_report_agent tests`: PASS.
- `git diff --check`: PASS.

The local final-stage gate was rerun as
`release-artifacts/final-round/final-completion-stage-gate-20260906-r3.json`.
It correctly remains `BLOCKED`: the local seeded C1-C4 fixture is `PASS`, but
real-provider attribution, fresh ComHost C1-C4 closure, browser/DSH E2E,
recovery/concurrency/soak, corpus Gold, CVE scan, production hardening and
independent reviews are not proven in this environment. No blocked gate was
promoted by the local fixture.

## Real sample smoke acceptance

Input: `D:\\test\\Resume\\ComHost.exe.VIR`.

- Task lifecycle: `SUCCEEDED`.
- Outcome: `PARTIAL`, with analysis class `BOUNDED_STATIC_ANALYSIS`.
- Materialized: 1 artifact, 15,675 Evidence rows, 104 Claims, 44 Relations,
  85 ToolRuns, and 93 investigation actions in the static CLI run.
- Output artifact:
  `release-artifacts/final-round/resume-static-cli-20260906.json`.
- Analyst-facing Markdown projection:
  `release-artifacts/final-round/resume-static-cli-20260906-rerendered.md`.
- The rerendered report contains function/RVA evidence, ordered call and
  argument summaries, loader/decode indicators, similarity rows, static
  boundaries, and ATT&CK candidate mappings. A post-render scan found no
  `LAB_`/`DAT_` navigation labels in the visible call summaries.
- The rerendered report retains the required IOC, Detection/Hunting, ATT&CK,
  Unknowns/Static Boundaries, and Analysis Coverage sections.
- Final rerender: `release-artifacts/final-round/resume-static-cli-20260906-rerendered-v3.md`;
  39,007 UTF-8 bytes, no visible `LAB_`/`DAT_` labels and no unresolved
  internal `FUN_`/`PTR_FUN_`/`PTR_PTR_` call rows. Nine unresolved targets are
  represented by bounded count/parameter-clue summaries instead; duplicate
  API aliases at the same callsite are rendered once.
- The same result was verified through the product `recompose_report` path as
  revision `30670641-a044-4849-8864-c59f1516fa62`, recorded in
  `release-artifacts/final-round/resume-static-cli-20260906-product-rerender.md`
  and its JSON check artifact.
- `PARTIAL` is intentional: runtime behavior is not observable in a
  static-only run, and unresolved mechanisms remain explicitly bounded.

## Performance result

- The string-heavy triage benchmark remains approximately `0.23-0.28s` for
  the capped 5,000-string workload in the regression environment.
- Anchor-index source recovery is covered by a bounded 2,000-row regression
  and remains below its two-second test budget.

## Explicitly not proven

Docker/Temporal/DSH browser acceptance, real-provider model contribution,
dynamic emulator execution, restart recovery, concurrency, soak testing, and
held-out corpus certification were not run in this session. Docker was not
available in the current environment, so those gates remain `BLOCKED` rather
than being claimed complete.
