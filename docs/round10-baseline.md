# Round 10 Baseline Freeze

Date: 2026-08-28

This document freezes the pre-Round-10 state without changing DSH upstream or
the legacy user data directories.

## Verified baseline

- Backend test baseline: `282 passed, 1 warning` (`pytest -q`).
- Existing Round 9 workbench checks were previously recorded as passing:
  typecheck, unit tests, manifest, security, legacy guard, and core guard.
- The repository is not a Git checkout, so no Git tag is created. File hashes
  and this document are the immutable local baseline instead.
- Docker Linux engine is currently unavailable in this environment. Compose,
  browser E2E, and restart/failure drills remain explicitly BLOCKED until the
  engine is available; no fixture is accepted as a substitute.

## Round 10 gaps frozen for remediation

At freeze time the following gaps were recorded and are the scope of this
round. Items 1-6 now have code or evaluator assets; fresh product validation
remains a separate release blocker.

1. Mechanism Playbook Registry had only four legacy profiles.
2. `Mechanism` lacked typed recovery fields and verifier checks.
3. Case goals went directly to broad seed questions.
4. Funnel metrics used legacy thresholds and counted explained loss as silent.
5. ComHost Gold and evaluator-only autopsy assets were missing.
6. Reports had no hard VERIFIED-Mechanism analytical gate.

## Safety and isolation

Round 10 remains static-only. Samples, scripts, macros, dynamic emulators, and
sample-specified network destinations must not be executed or contacted.
Evaluator Gold and reference reports remain outside `src/threat_report_agent`.
