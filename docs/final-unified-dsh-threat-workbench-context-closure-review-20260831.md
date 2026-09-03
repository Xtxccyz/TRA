# Unified DSH Threat Workbench Context Closure Review

**Review date:** 2026-08-31  
**Scope:** final unified DSH context-closure workstream, with emphasis on the
same-workspace blank-session reuse defect.  
**Decision:** code and runtime fix PASS; full product certification remains
BLOCKED.

## Executive verdict

The reported cross-session contamination defect is fixed and reproduced as a
real browser failure before the fix.  After the fix, the same DSH blank Session
can be reused without retaining a terminal Analysis Task binding.  A running
analysis remains attached and is not detached by the New Session action.

This is a verified product fix, not a declaration that every closure-plan
acceptance gate is complete.  The accurate release status is:

```text
Unified context code path: PASS
Session reuse isolation fix: PASS
Static-only security boundary: PASS
External certification / full product closure: BLOCKED
```

## Boundary and safety

- Only the existing static analysis pipeline was used.
- No sample was executed.
- No sample-derived network destination was contacted.
- Qiling, Speakeasy and flare-emu were not invoked.
- No PostgreSQL or MinIO data volume was removed.
- The DSH process was restarted only after the local regression analysis had
  finished; backend services and their data volumes were kept running.

## Defect and root cause

DSH intentionally reuses a blank Session for the New Session action.  A Session
can be blank from DSH's conversation perspective while the server still holds
a terminal Threat Analysis binding.  The first guard implementation replaced
`startSession` with ordinary assignment on a Cordis traceable service Proxy.
That assignment could target a transient shadow receiver, so the UI's later
method lookup still reached the native `WorkspaceRuntime.startSession`.

The product-side fix uses `Object.defineProperty` to install the wrapper on the
actual service target and uses the same operation during disposal.  The wrapper
then:

1. mirrors DSH's exact blank-session reuse predicate;
2. reads the server-authoritative analysis context;
3. unbinds only terminal/history states;
4. leaves `ANALYSIS_RUNNING` attached; and
5. fails closed when the context or unbind request fails.

Implementation locations:

- `threat-dsh-workbench/packages/threat-session-events/src/session-scope.ts:132`
- `threat-dsh-workbench/packages/threat-context-store/client.js:161`
- `threat-dsh-workbench/packages/threat-session-events/client.js:1`

## Browser evidence

The supported DSH profile was loaded from `http://127.0.0.1:3080/` while the
Threat backend was running at `http://127.0.0.1:8000/`.

### Reproduction before the fix

For Session `session-869c88c4-31af-4663-9f51-5cf29c08ac1f`, a harmless README
artifact was attached and a static task was allowed to reach
`ANALYSIS_READY`.  Clicking the native `新建会话` button kept the same Session
ID and left the server context at `ANALYSIS_READY` with the old task attached.

### Verification after the fix

After rebuilding/restarting DSH and reloading the page, the same native button
was clicked against the same terminal blank Session.  The observed result was:

```text
Session before: session-869c88c4-31af-4663-9f51-5cf29c08ac1f
Session after:  session-869c88c4-31af-4663-9f51-5cf29c08ac1f
State before:   ANALYSIS_READY
State after:    ARTIFACT_READY
Active task:    null
Attached artifact: retained by the existing upload/unbind contract
```

The retained artifact is intentional: `analysis/unbind` clears the active
task binding while preserving explicitly attached artifacts for a subsequent
explicit start.  It is not a historical Task, Evidence or Report binding.

### Running-analysis safety

A second task `e017797b-0f90-4c36-b790-540995cd5c7a` was started in the same
blank DSH Session.  Clicking `新建会话` while it was running produced:

```text
State after click: ANALYSIS_RUNNING
Active task:      e017797b-0f90-4c36-b790-540995cd5c7a
Lifecycle:        RUNNING
```

The task subsequently reached `ANALYSIS_READY` normally.  This confirms the
guard does not detach in-flight work.

## Automated verification

### Backend

```text
python -m pytest -q
359 passed, 1 warning, 49.80s
```

The warning is an upstream Python dependency deprecation/version warning; it
did not fail a test.

### Threat Workbench frontend/runtime

All commands were run in `D:\threat report agent\threat-dsh-workbench`:

| Check | Result |
|---|---|
| `pnpm typecheck` | PASS |
| `pnpm test:runtime` | PASS, 13/13 |
| `pnpm test` | PASS, 20/20 |
| `pnpm manifest` | PASS, 18 manifests + profile |
| `pnpm security` | PASS, `dangerous_tools=0`, 141 rows checked |
| `pnpm core-guard` | PASS, pinned commit unchanged, upstream core diff 0 |

The complete regression suite was rerun after the final session-guard fix on
2026-08-31:

```text
python -m pytest -q                 359 passed, 1 warning
pnpm typecheck                      PASS
pnpm test                            20 passed
pnpm test:runtime                    13 passed
pnpm manifest                        18 manifests + profile
pnpm security                        dangerous_tools=0, 141 rows checked
pnpm smoke:dsh                       PASS, product title and 7 required plugins
pnpm legacy-guard                    PASS, legacy_mounts=0
pnpm core-guard                      PASS, upstream_core_diff=0
```

The regression tests include:

- `tests/session-scope-client.test.mjs:52` terminal binding is unbound before
  native reuse;
- `tests/session-scope-client.test.mjs:65` running analysis stays attached;
- `tests/session-scope-guard.test.ts:13` and `:36` the typed guard behavior;
- a Proxy double whose `set` trap rejects ordinary assignment, locking in the
  Cordis receiver failure mode.

The temporary browser diagnostic global used during reproduction was removed;
the final bundle serves cleanly and `window.__THREAT_SESSION_GUARD__` is absent
after reload.

## Runtime infrastructure

`docker compose ps` showed all ten services running. PostgreSQL and MinIO were
healthy; API, Temporal, Ghidra and the five workers were up. `docker system df`
initially reported 5 active images (4.598 GB), 10 active containers, 3 active
volumes (9.465 GB), and 601 MB BuildKit cache with 124 MB reclaimable. The
reclaimable BuildKit cache was pruned without touching images, containers,
networks or volumes. The final state is 5 active images (4.598 GB), 10 active
containers, 3 active volumes (9.448 GB), and 477 MB BuildKit cache with 0 B
reclaimable. No data volume or active service was removed.

## Closure-plan status matrix

### Implemented and realistically tested

- Server-authoritative Session Analysis Context and versioned protocol.
- Explicit artifact intake versus explicit analysis start.
- Session-scoped Threat UI context store with stale-response guards.
- v4 Threat tool contract and static-only policy checks.
- DSH session event bridge and shared Threat projections.
- Native Threat views for overview, investigation, mechanisms, flow, evidence
  and report.
- Same-workspace terminal blank-session reuse isolation, including the Proxy
  receiver regression fixed in this review.
- Static security boundary, manifest checks and upstream-core immutability.

### Code exists but is not a complete production proof

- The full 20-malware/10-benign evaluator corpus and evaluator-owned Gold set.
- Independent analyst scoring of held-out reports.
- Full browser matrix (batch upload, password-gated archive, historical bind,
  deep links, all restart/reconnect permutations).
- PostgreSQL/MinIO/Temporal failure drills, concurrency, and 24-hour soak.
- Production identity/secrets, independent audit-sealer credentials and
  deployment hardening.

### Not completed and still explicitly out of scope

- Dynamic sample execution or dynamic emulator results.  The product remains a
  static evidence-driven analysis workbench.
- Final external certification and the claim `Product Ready`.

## Remaining work to close the product

1. Run the evaluator-owned malware/benign corpus with held-out labels and
   publish precision, recall, mechanism closure and report-quality metrics.
2. Execute the remaining DSH browser E2E matrix from the final closure plan,
   preserving request/event traces and exported reports.
3. Complete restart, dependency-outage, concurrency and soak evidence.
4. Obtain an independent analyst/product/security review.
5. Replace development secrets and enforce production worker/audit controls.

Until those external proofs pass, this document records a verified code/runtime
closure for the Session context defect while keeping final certification
honestly blocked.
