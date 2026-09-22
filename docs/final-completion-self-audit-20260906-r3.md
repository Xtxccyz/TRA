# Final Completion Self-Audit - 2026-09-06 (Core Analysis and Performance)

## Scope

This audit covers the core static-analysis and bounded investigation path. The
sample was handled read-only. No sample, script, macro, dynamic emulator, or
network action was executed.

## Changes verified

- Static indicator matching now reuses module-level compiled regular
  expressions. Import matching remains exact and string matching remains
  boundary-aware.
- Static Evidence source recovery in `_record_static_result` now uses an
  anchor/locator inverted index while retaining the existing strict anchor
  validation and unanchored compatibility fallback.
- `GET_DECOMPILE` investigation actions now emit a provenance-bearing
  `function_semantic_summary` containing ordered API calls, static argument
  producers, branch conditions, consumers, and an explicit runtime-unobserved
  boundary.
- Duplicate Ghidra call projections are removed by `(API, callsite, target)`;
  distinct callsites remain separate.

## Verification

- Full regression: `655 passed, 2 skipped, 1 warning` (`pytest -q`).
- Core targeted regression: `85 passed`.
- Deep-mining and semantic regression: `69 passed`.
- `ruff check src tests`: PASS.
- `python -m compileall -q src tests`: PASS.
- `git diff --check`: PASS.

## Real sample smoke acceptance

Input: `D:\\test\\Resume\\ComHost.exe.VIR`.

- Task lifecycle: `SUCCEEDED`.
- Outcome: `PARTIAL`, with analysis class `BOUNDED_STATIC_ANALYSIS`.
- Materialized: 1 artifact, 15,675 Evidence rows, 104 Claims, 44 Relations,
  and 85 ToolRuns.
- Investigation materialized 93 actions and persisted semantic summaries for
  the admitted function targets.
- Output artifact:
  `release-artifacts/final-round/resume-static-cli-20260906.json`.
- Analyst-facing Markdown projection:
  `release-artifacts/final-round/resume-static-cli-20260906.md`.
- The output includes function/RVA evidence, ordered call/argument summaries,
  loader/decode indicators, similarity rows, static boundaries, and ATT&CK
  candidate mappings. `PARTIAL` is intentional because runtime behavior is
  not observable in a static-only run.

## Performance result

The string-heavy triage benchmark remains below one second in the regression
environment; the measured optimized profile is approximately `0.23-0.28s` for
the capped 5,000-string workload. Anchor-index recovery is covered by a
bounded 2,000-row regression and remains below its two-second test budget.

## Explicitly not proven

Docker/Temporal/DSH browser acceptance, real-provider model contribution,
dynamic emulator execution, restart recovery, concurrency, soak testing, and
held-out corpus certification were not run in this session. They remain
blocked by external runtime or certification prerequisites and are not claimed
as complete.
