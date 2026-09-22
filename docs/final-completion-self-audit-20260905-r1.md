# Final Completion Self-Audit (2026-09-05, lockfix)

## Scope

This addendum covers the cross-invocation `NO_NEW_EVIDENCE` action dedupe fix
and the fresh short-budget static Resume run. It does not promote any blocked
release gate and does not claim Resume-level report completion.

## Code change

`AnalysisService._run_investigation_loop()` now loads durable action rows for
the artifact and treats a `FAILED` action with `error=NO_NEW_EVIDENCE` as
terminal for its current evidence frontier. The same action key is admitted
again only when an Evidence row for the same task and artifact was created
after the failed action's `finished_at`. Successful actions remain terminal;
other failures retain their existing retry behavior.

## Regression evidence

- Test: `test_no_new_evidence_action_is_deduped_until_new_evidence_arrives`
- First invocation: no duplicate action row is created.
- New target Evidence is then inserted.
- Second invocation: the same action key is admitted once and produces a
  successful derived observation.
- Focused service suite: `17 passed`.
- Full suite after the baseline-script fix: `517 passed, 2 skipped`.

The baseline utility now refreshes `/status` after a successful cancellation
and preserves scalar `artifact_count`, `evidence_count`, and `claim_count`
returned by that endpoint. This prevents a timeout artifact from claiming a
stale `RUNNING` lifecycle or zero counts.

## Fresh Resume run

Sample: `Resume.pdf                                                               .exe.VIR`

- SHA-256: `6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145`
- Task: `f3ab57d3-6a0d-435b-bf54-a270ec9eeb33`
- Budget: 180 seconds client-side, static-only
- Final lifecycle: `CANCELLED` after the budget; report was not available
- Persisted result before cancellation: 1 artifact, 41,973 Evidence, 219
  Claims, 5 ToolRuns
- Model calls: 0 in this run (the task was cancelled before model planning)
- Audit: 2 `orchestration.action_dequeued` events and 0
  `investigation.action_no_new_evidence` events; no duplicate action storm
- Sample execution/network/dynamic emulator invocation: all `false`
- Audit integrity: valid

Artifact: `release-artifacts/final-round/resume-static-baseline-lockfix-20260905.json`

## Gate decision

The final release Gate remains `BLOCKED`. This fix proves finite retry
behavior, but it does not close C1-C4, real model contribution, Resume report
completion, browser E2E, recovery, concurrency, soak, or production-hardening
evidence gaps.

The regenerated Gate is recorded at
`release-artifacts/final-round/final-completion-stage-gate-current-20260905-r2.json`:

- `status=BLOCKED`, `production_ready=false`, `blocker_count=23`
- local suite: `517 passed, 2 skipped`
- source worktree remains dirty; no clean-release claim is made
