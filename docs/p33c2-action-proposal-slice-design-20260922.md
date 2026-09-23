# P3.3c(2): the action-proposal members move once both layer items have landed

- **Date**: 2026-09-22
- **Status**: implemented, gated; the two-axis review runs after this document and its outcome is recorded in the step
  record in `.scratch/structure-status.json` (rendered into `docs/structure-execution-status-20260922.md`)
- **Governing plan**: `docs/code-structure-optimization-execution-plan-reviewed-20260922.md` (§7.1 algorithm, §3.2 matrix)
- **Slice record**: `docs/p33-investigation-coordinator-design-20260922.md` §13.1 (why these members stayed)

## 1. Why this slice could only move now

`STAYED_FROM_P3_3C` was the group that could not move when P3.3c ran. Both recorded blockers are layer work, and both
landed in the two preceding steps:

| member | what blocked it | removed by |
| --- | --- | --- |
| `_action_is_model_or_human` | called `action_is_model_or_human`, which lived in `task/analysis_task_orchestration.py`; importing that from `investigation/` is the cycle | **layer item 1**: the predicate moved into `investigation/loop_path.py` |
| `_model_action_plan` | needs `DynamicPlanAction` at run time (`isinstance`) | **layer item 4**: the canonical class moved into `contracts.py` and the model port exposes it |
| `_has_complete_model_action_plan` | annotation + calls `_model_action_plan` | same as above |
| `_merge_planned_actions` | annotation; reads `target_artifact_id` / `priority` at run time | same as above |

The whole group is moved in one step rather than leaving the 3-line wrapper behind: it was one stayed group with one
reason, and the slice is only "complete" when the group is empty.

MEASURED (`.scratch/p32-measure-cluster.py ... --from ed363a5`): **4 members / 74 lines** -
`_model_action_plan` 42 (a `@staticmethod`), `_merge_planned_actions` 20, `_has_complete_model_action_plan` 9 (a
`@classmethod`), `_action_is_model_or_human` 3 (a `@classmethod` wrapper).

## 2. What moved, and what it cost

- `investigation/coordinator.py`: **1270 → 1367 lines** (the four bodies, appended as module-level functions).
- `service.py`: **28,032 → 27,968 lines** (four delegations replace 74 lines; the import the move made dead is gone).
- **The port did NOT grow.** The extractor reports `host need: NONE` for all four members: the cluster's only
  receiver-shaped reference was `cls._model_action_plan(action)` inside `_has_complete_model_action_plan`, and
  `_model_action_plan` travels with the cluster, so the intra-cluster call became a direct module call. The
  host-member pin therefore stays at SIX.
- **Two imports were added to the coordinator DELIBERATELY, because the extractor's guard refused to add them
  silently** - and both are products of the two layer items:
  `from threat_report_agent.contracts import DynamicPlanAction` (plan matrix line 132 allows `investigation/` to import
  contracts; the model *implementation* is what is forbidden) and
  `from threat_report_agent.investigation.loop_path import action_is_model_or_human` (same package, so no cycle). The
  guard's message - "Add them deliberately (and say why in the step record)" - is quoted in the step record.
- The four delegations keep their original call shapes: `@staticmethod` stays static, both `@classmethod`s stay
  classmethods (neither forwards a receiver, because the moved bodies need none), and `_merge_planned_actions` stays an
  instance method that forwards only its three arguments.
- **Call sites, corrected after review**: three `self._model_action_plan(...)` sites and
  `self._has_complete_model_action_plan(...)` are unchanged in production. `_merge_planned_actions` has **no production
  caller** - its only caller is `tests/test_w4_acceptance.py:660` - which the first draft of this document claimed
  otherwise; plan section 3.3 line 154 makes a private member kept alive only by a test Phase-4 debt, and that is
  recorded rather than fixed here.
- **One behaviour-adjacent difference, recorded under P1.4**: `_has_complete_model_action_plan` used to reach its
  sibling as `cls._model_action_plan(action)`, i.e. through the class, so a SUBCLASS overriding `_model_action_plan`
  would have been dispatched to. After the move the call is a direct module call, so that dispatch point is gone.
  MEASURED: no subclass of `AnalysisService` exists in the repository, so nothing observable changes - but it is a
  real, if currently unreachable, semantic difference and it belongs in P1.4's comparison rather than in a footnote.

## 3. A tool defect found before the move, and the process gap it exposes

`p33-extract.py` - the instrument every P3.3 slice uses - **did not compile**: line 351 had two statements merged onto
one line (`delegate_def = ...`)        args = fn.args.args`), which is the signature of the PowerShell text-writing
mangling this project has hit repeatedly. It was repaired before any extraction ran, and the repair is recorded here
because of what it implies:

- the slice tooling lives in `.scratch/`, which is **gitignored**, so a corrupted instrument produces no `git status`
  signal and no diff to review; the only detector is running it;
- the previous step's records that name `p33-extract.py` were written when the tool worked (they produced the
  coordinator content those records measure), so nothing in those records is invalidated - but a successor cannot
  assume the tool is intact. The durable fix (moving the slice instruments into tracked `scripts/`) is recorded as a
  follow-up rather than done inside a structural step.

## 4. Verification performed

1. **AST identity** (`.scratch/p33-verify.py`): all four moved bodies are identical to `HEAD:service.py` with the
   receiver normalised away - digests `6d17c325b37fc1fe`, `cd0a569d219fe66d`, `cf0b3290425d9ac4`, `c0f515c11f2b2cfd`.
   The verifier also prints 4 items as **NOT VERIFIED** (functions that earlier slices had already moved out of
   service.py) rather than passing them silently.
2. **Value-level identity** (`.scratch/p33c-textdiff.py`): string VALUES character-for-character and body code lines
   identical for all four - `ast.unparse` cannot see string content, which is why this check exists separately.
3. **Arity** (`.scratch/p33-arity.py`): no call to any of the 10 host-taking module functions omits the host.
4. **Reference check** (`.scratch/p33-reference-check.py --moved-in-coordinator`): all 26 coordinator-owned members are
   delegations and all 32 call sites route through those delegations; for this slice, 4 members / 4 call sites.
5. **Can-fail proofs**: the identity verifier was tampered (a body symbol changed) and exited 1 naming the tampered
   member; the arity pin was tampered with a host-omitting call and caught it. Both files were restored with
   before/after hash equality (`.scratch/p33-canfail.py`, `.scratch/p33d-arity-canfail.py`).
6. **The contract test now pins the NEW state** rather than the old one:
   `test_the_action_proposal_slice_moved_once_both_layer_items_landed` asserts the four members are delegations, that
   their bodies are module-level functions in the coordinator, and - the part that matters for the future - that the
   coordinator imports `DynamicPlanAction` from **contracts** (not the model implementation) and the predicate from
   **this package's** `loop_path` (not `task`), and that the module imports `task` nowhere at all.
   `STAYED_FROM_P3_3C` is now an explicitly EMPTY tuple with the history in its comment, so the retirement is recorded
   rather than the constant just disappearing.
   It also restores the RUNTIME-use assertions the replaced test carried (both branches of `_model_action_plan` -
   Mapping and model action - both verdicts of the completeness predicate, and the wrapper returning the predicate's
   own verdict for three inputs, two of which the predicate separates), and scans import sources as a MULTI-source map
   rather than last-write-wins.
7. **The generic delegation test gained an ARGUMENT-IDENTITY check** after a review showed the hole: every previous
   assertion constrained the *receiver*, so a hostless member's delegation - this slice adds four - could drop or
   reorder an argument and pass, and the arity pin cannot see it either because it only inspects calls whose target
   takes a host. The forwarded arguments must now equal the module function's parameters in order. It proved
   non-vacuous immediately: its first version mis-modelled host-taking members (a host-taking delegation's first
   forwarded argument IS the host) and failed on `_unattempted_seed_thread_ids`, which is exactly the kind of failure
   the check exists to produce.
8. **Lint and format**: `ruff check` reports no error this step created (the 5 remaining in `service.py` are
   pre-existing). Format debt was ATTRIBUTED rather than counted, because reflowing shifts line numbers and splits
   hunks: `.scratch/format-debt-attribution.py` reports **0 format hunks touching lines this step added** in the test
   file and 14 pre-existing. The two hunks it flagged in `coordinator.py` are the **verbatim moved bodies**, which are
   byte-identical to their old text by design - reformatting them would break the move's identity invariant, so they
   are recorded, not reformatted. `test_ports.py` and `service.py` show 0 added.
9. **Gates**: import graph PASS (110 modules, **215** runtime same-package edges - two more: the coordinator now imports
   contracts and loop_path - cycles 0, the known `persist_how -> reporting` reverse edge unchanged); structure diff
   PASS; behaviour probe UNCHANGED.
10. **Focused battery**: 127 passed (`test_investigation_coordinator_contract` 12, `test_investigation_service` 58,
    `test_w4_acceptance` 33, `test_ports` 12, `test_oversized_lists_are_truncated_not_rejected` 12).
11. Full suite, rebuild and the deployment gate: recorded in the step record.

## 5. What this completes, and what is next

- **P3.3c(2) is complete.** The `STAYED_FROM_P3_3C` group is empty; the action-proposal slice's members are all in
  `coordinator.py` behind delegations.
- `service.py` is down to **27,971 lines** (from 29,640 at the Phase-3 start).
- The next structural step is **layer item 2** - expose the 7 `simulation_adapters` policy names as an allowed
  emulation interface - because it is the only thing that unblocks **P3.3e**
  (`_derive_investigation_observations`, 2,795 lines; 3,041 wholesale), the largest remaining slice. The other
  recorded layer items (3 and 5) unblock P3.3b(2) and P3.3d(2).

## 6. Not done, recorded

- The slice tooling is still in `.scratch/` and therefore untracked (§3); moving it to `scripts/` is a follow-up step,
  not something to smuggle into a structural move.
- `_action_is_model_or_human` is now a 3-line pass-through in both places (a delegation in service.py and a wrapper
  function in the coordinator). Removing the double indirection would be a behaviour-surface change (the private name
  is pinned by the contract test and by `service.` call sites), so it is recorded rather than done.
- No port members were added or removed by this slice (measured: `host need: NONE` for all four), so the
  `INVESTIGATION_HOST_MEMBERS` pin is unchanged at six and the port's "smaller than the implementation" property is
  unaffected.

## 7. The two-axis review: findings and dispositions

Both axes ran as independent subagents against the last verified code commit `ed363a5`. **Neither reported a hard
violation**, and both independently verified the substantive claims: the four bodies are AST- and value-identical to
their pre-move text (including the intra-cluster rewrite), there is no half-moved state (one definition per name per
module), every call site still resolves, the port did not grow and its pin still matches the protocol, the two new
imports are allowed by the matrix with no `task`/model-implementation edge, and removing `action_is_model_or_human`
from `service.py` is safe (nothing else imported it).

| finding | disposition |
| --- | --- |
| The replacement test proves *provenance* but dropped the old test's RUNTIME-use assertions; and its import map was last-write-wins, so a shadowing import could hide a forbidden one | **Accepted and fixed**: the runtime assertions are back (both `_model_action_plan` branches, both completeness verdicts, the wrapper matching the predicate for three inputs) and the scan collects ALL sources per name and requires exactly the allowed one. |
| The arity pin only inspects calls whose target takes a `host`, so a hostless member's delegation could drop or shift an argument invisibly | **Accepted and fixed**: the generic delegation test now checks argument identity for every moved member. Its first version failed immediately on a host-taking member, which is the evidence that it is not vacuous. |
| The design doc listed `self._merge_planned_actions(...)` as an existing call site; there is none (its only caller is a test) | **Accepted and fixed** in §2, with the Phase-4 debt recorded. |
| The doc's line count (27,971) was 3 lines off | **Accepted and fixed**: measured 27,968. |
| `cls._model_action_plan` → direct module call drops subclass dispatch | **Accepted and recorded** in §2 under P1.4, with the measurement that no subclass exists in the repository. |
| The new test partially re-pins what the generic delegation test pins (the file's own "second home for one pin" anti-pattern) | **Partially disputed, recorded**: the generic pin owns SHAPE; the new one owns PROVENANCE and runtime use, which the generic pin cannot express. The delegation-substring assertion inside it is the overlap, and it is deliberate because the generic pin iterates a list this test also documents. |
| Replacing the obsolete "stayed whole" test could be read as weakening a test to go green | **Accepted as a judgement call, and recorded as legitimate by the Standards axis itself**: the plan forbids loosening for green, but the state that test pinned ("these members have not moved") retired BY DESIGN as this step's success criterion, and the successor asserts strictly more (provenance, runtime use, an empty-tuple pin) while the four names joined `MOVED_MEMBERS`, so the generic shape/decorator/arity test now covers them too. |
| The status record and the parent slice table still describe P3.3c(2) as blocked/next | **Accepted and fixed**: the status doc is regenerated with this step's record, and `docs/p33-investigation-coordinator-design-20260922.md`'s slice table now marks P3.3c(2) moved. |
