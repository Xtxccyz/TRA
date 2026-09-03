# Round 9 Benchmark Results

This is an evidence ledger, not a forecast. Real Resume and ComHost runs must
be recorded with task ID, report revision, critical mechanism recall,
negative-gold violations, evidence delivery recall, and report size.

## Status: NOT SIGNED OFF

No fresh Round 9 benchmark is claimed in this checkout because Docker Desktop's
Linux engine is unavailable. The prior Round 8 artifact is retained for
comparison only:

| artifact | result | reason |
|---|---|---|
| `.scratch/round8-resume-comhost-docker-report-v3.md` | FAIL anti-bloat | 620,574 bytes, outside the 40 KiB Report V2 budget |
| `.scratch/round8-resume-comhost-docker-task-v3.json` | operational only | `SUCCEEDED/PARTIAL`; not a Resume-level completion claim |

The static evaluator and Gold files remain evaluator-only. Static abstract
execution predictions are hypotheses, never runtime observations. A release
benchmark must be generated from a freshly built image and pass all critical
Resume and ComHost gates before this table can be changed to PASS.
