# P3.3 layer item 4: the model-authored plan action gets a home in the pure contract layer

- **Date**: 2026-09-22
- **Status**: implemented, gated; the two-axis review's findings and my dispositions are in §7
- **Governing plan**: `docs/code-structure-optimization-execution-plan-reviewed-20260922.md` (§3.2 matrix, §7.1 algorithm)
- **Decision it executes**: `docs/p33ef-giants-decision-20260922.md` §3 item 4

## 1. The problem, and the route the measurements selected

P3.3c(2)'s three members (`_model_action_plan`, `_has_complete_model_action_plan`, `_merge_planned_actions`, 71 lines)
need `DynamicPlanAction`:

| member | how it needs the type |
| --- | --- |
| `_model_action_plan` | **at run time**: `isinstance(action, DynamicPlanAction)` chooses `model_dump(mode="json")` over `dict(action)` |
| `_has_complete_model_action_plan` | annotation only |
| `_merge_planned_actions` | annotation only; reads `target_artifact_id` / `priority` off the objects |

`investigation/` may not import the model **implementation**: `model/model_gateway.py` imports `httpx`. Item 4's action
is "往 ports.py 加一个名字，不动任何行为" - add a name to the port module, changing no behaviour.

**THE ROUTE (and a correction the review forced)**: the first draft of this step re-routed item 4 to "the pure contract
layer" and left `ports.py` untouched, justifying that with a route table that only ever measured *`ports.py` importing
the GATEWAY*. That comparison was unfair, and the Spec axis said so: once the class lives in `contracts.py` - which
imports pydantic but not httpx - `ports.py` can re-export it **purely**, which is exactly what the item asks for and is
permitted by plan line 142 ("重新导出不是第二个实现"). The step therefore does BOTH:

1. the canonical class moves to `contracts.py` (a) because the plan's matrix line 132 already lets `investigation/`
   import contracts, (b) because line 118 prefers extending an existing contract module over creating one, and (c) so
   that the port can expose it **without** importing the gateway; and
2. `ports.py` re-exports it, so the model port exposes the type, per the item as written.

| route | verdict |
| --- | --- |
| port re-exports the class **from the gateway** | **rejected**: the gateway imports httpx; `ports.py` documents itself as free of transport/SDK imports, so this would pull httpx into every importer of the port module. (The banned-import test checks only substrings of `ports.py`'s own statements, so it would NOT have caught it - the rule is enforced by reading, not by that list.) |
| port declares a structural `*View` Protocol | **rejected**: it would force the later move to rewrite `isinstance(action, DynamicPlanAction)` into a STRUCTURAL check - a behaviour change inside a step whose point is to move the same implementation. |
| class stays in the gateway, `investigation/` uses a type-only import | **rejected**: `_model_action_plan` needs the type at RUNTIME, and a runtime edge to an unlisted layer is exactly what P3.3c's record refused to smuggle into a move. |
| **class moves to `contracts.py`, gateway AND port both re-export the same object** | **chosen** |

`runtime_contracts.py` was weighed and not chosen: it is pure standard library today (`hashlib`, `json`, `dataclass`),
and a pydantic model there would add a dependency to a module that has none.

The class stays a MUTABLE `BaseModel` (its siblings in `contracts.py` are `FrozenContract`s). That is deliberate:
`service.py` assigns control-plane provenance fields after validation (`planner_turn_id`, the digests) and the
`model_validator` rewrites the payload; making it frozen would be a behaviour change, not a structural one.

## 2. What moved (measured)

MEASURED with `.scratch/layer4-measure.py`:

- `DynamicPlanAction`: **107 lines** in `model/model_gateway.py` (lines 386-492), a **closed** cluster - its only free
  names are `Any`, `BaseModel`, `ClassVar`, `Field`, `Literal`, `field_validator`, `model_validator`.
- `contracts.py`: **138 → 247 lines** (+107 class, +2 derived import lines).
- `model/model_gateway.py`: **1554 → 1451 lines** (class out; explicit re-export with its reason in; the dead
  `field_validator` import removed).
- `ports.py`: **+8 lines** - the pure re-export and the comment explaining why it comes from contracts.
- **Callers migrated (plan §7.1 step 5)**: `service.py` (production first) and the three test files that imported the
  symbol, by AST (`.scratch/layer4-callers.py`). Every `DynamicPlanAction` import now points at `contracts`; the only
  imports left on the model path are the two explicit re-exports. `tests/test_model_package_contract.py` is exempt
  because it exists to pin the re-export.

The class text is **byte-identical** to its pre-move text, comment block included.

## 3. A latent defect the move's own guard found, and the move fixes

The extraction guard derives the imports the new home needs from the moved body's free names and refuses to write a
module whose free names are unresolvable. It stopped on **`ClassVar`**: the class annotates
`_TRUNCATION_BOUNDS: ClassVar[dict[str, int]]`, and `model_gateway.py` **never imported `ClassVar`**. It works only
because `from __future__ import annotations` makes every annotation a lazy string that nothing resolves; anything that
evaluated that annotation (`typing.get_type_hints`, a pydantic rebuild) would have raised `NameError`.

This was already visible to the linter: **`ruff check` reported it as `F821 undefined name 'ClassVar'` at HEAD**. The
move resolves it because `contracts.py` imports `ClassVar` properly. Measured both ways with
`.scratch/layer4-ruff-diff.py`:

```
ruff at HEAD: 4 error INSTANCES / 3 unique messages   (F821 ClassVar, F841 reason_control_note, F821 reason_control_note x2)
ruff now:     3 error INSTANCES / 2 unique messages   (F841 reason_control_note, F821 reason_control_note x2)
CREATED by this move: none
removed by this move: F821 ClassVar
```

The two `reason_control_note` errors are **pre-existing and deliberately NOT fixed**: the variable is assigned inside one
branch and read 400 lines later outside its scope, which is a behaviour-adjacent repair that does not belong in a
structural step. It is recorded here and in the step record instead.

## 4. Verification performed

1. **Text**: the class is byte-identical to `HEAD:src/threat_report_agent/model/model_gateway.py`, comment block
   included (`.scratch/layer4-verify.py` property 1).
2. **One object, four paths**: `contracts`, `model.model_gateway`, the root shim `model_gateway`, and the model port
   `ports` all expose the same object (property 2).
3. **Exactly one definition in `src/`**, at `contracts.py:141` (property 3) - plan 3.2 line 142's "re-export is not a
   second implementation" made checkable.
4. **The behaviour the class exists for** (property 4): an oversized list is TRUNCATED AND RECORDED, never rejected -
   12 `alternatives` in, 8 kept, `truncated_fields == ["alternatives:8/4"]` - and an explicit JSON `null` for
   `depends_on` still normalises to `[]`.
5. **Three product-suite pins** in `tests/test_ports.py`: the contract layer is importable WITHOUT importing the model
   implementation (fresh interpreter); exactly one definition exists in all of `src/`, with the model path and the port
   both re-exporting that one object; and a **tracked self-check** proving the duplicate-definition checker detects a
   synthetic duplicate (plan §4.3/§4.4: verification reproducible from tracked files, not only from a gitignored
   script - the checker was extracted into `_definitions_of` for exactly that reason).
6. **Can-fail proof, four tampers** (`.scratch/layer4-canfail.py`): a second definition under `model/`; the contract
   layer importing the gateway; a widened truncation bound; and the port dropping its re-export. All four fail the
   matching pin; the restored tree passes; every file is restored byte-for-byte with hash verification.
7. **Lint**: `ruff check` reports **no error this step created** (measured set difference, §3). The repository has
   27 pre-existing ruff errors in untouched files, unchanged by this step. `ruff format --check` debt was also measured
   before/after per file (`.scratch/layer4-format-diff.py`): `test_ports.py` 7 → 7 hunks, the coordinator contract test
   14 → 14, `contracts.py`/`ports.py`/`model_gateway.py` unchanged - the two hunks this step initially added were
   reformatted away.
8. **Gates**: import graph PASS (110 modules, **213** runtime same-package edges - two more than before this step: the
   gateway's re-export edge and the port's - cycles 0, empty cycle allowlist, the known `persist_how -> reporting`
   reverse edge unchanged); structure diff PASS; behaviour probe UNCHANGED.
9. **Focused battery**: **86 passed** across the five files this step's change is about (`test_ports` 12 - 9 before this
   step - `test_oversized_lists_are_truncated_not_rejected` 12, `test_w4_acceptance` 33,
   `test_investigation_coordinator_contract` 12, `test_analysis_task_orchestration` 17); **144 passed** when
   `test_investigation_service` (58) is added, because the caller migration touched its import.
10. Full suite, rebuild and the deployment gate: recorded in the step record in `.scratch/structure-status.json`,
    rendered into `docs/structure-execution-status-20260922.md`.

## 5. What this unblocks

**P3.3c(2) now has no layer blocker left.** Both recorded blockers are gone: `action_is_model_or_human`'s (removed by
layer item 1) and `DynamicPlanAction`'s (removed here - `investigation/` may import the type from `contracts`, and the
model port also exposes it). The three members can be moved with their `isinstance` intact, because the canonical class
is still the nominal type.

## 6. Not done, and blind spots recorded rather than hidden

- The two pre-existing `reason_control_note` lint errors in `model_gateway.py` are **not fixed** (§3).
- **The gate cannot check the matrix.** `docs/import-policy.json` encodes forbidden edges, cycles and known violations -
  not the allowed-dependency matrix - so the new `model.model_gateway -> contracts` edge is invisible to `--strict`,
  exactly as `investigation -> simulation_adapters` was (and that one was REJECTED one step earlier for being unlisted).
  The decision is therefore recorded where this repository records such decisions:
  `docs/plan-conflict-resolutions-20260922.md` decision (d), plus a `recorded_allowed_edges` key in the policy file whose
  note says plainly that the gate does not read it and how to machine-check it (encode the matrix as an allow-list).
- `ports.py` now imports `contracts` and therefore pydantic transitively. pydantic is a validation library, not
  persistence/transport/SDK/ORM, so the file's own rule is satisfied; recorded because it is a real change in what
  importing the port module costs.

## 7. The two-axis review: findings and dispositions

Both axes ran as independent subagents against the last verified code commit `a48e902`.

**Independently confirmed by both axes**: the class is byte-identical (107 lines); there is exactly one definition in
`src/`; `contracts` / `model.model_gateway` / the root shim are one object; importing `contracts` leaks no
`model_gateway`; the truncation and `None`-normalisation behaviour is preserved; the `ClassVar` F821 really is fixed and
the two `reason_control_note` errors really are untouched.

| finding | disposition |
| --- | --- |
| **Item 4's action was dodged**: `ports.py` was untouched, and the reason recorded for skipping it was based on an unfair comparison (only "port imports the gateway" was measured) | **Accepted and fixed**: `ports.py` now re-exports the class from `contracts`, which is the item's action, and §1 states the corrected comparison. The reviewer was right that "purpose satisfied, action dodged" was the honest description of the first draft. |
| The new `model.model_gateway -> contracts` edge is unlisted by the matrix, and the step justified it by "the gate accepts it" while rejecting an unlisted edge one step earlier | **Accepted and fixed**: recorded as decision (d) with its measurements, plus a `recorded_allowed_edges` entry in the policy file that states the gate blind spot and the way to close it. |
| Doc §4.6 claimed "ruff check on every touched file passes" while the touched module has two remaining errors | **Accepted and fixed**: the claim is now "no error this step CREATED", with the set difference and the instance/message counts measured (4/3 → 3/2). |
| Doc §4.3 claimed "exactly one definition in `src/`" while the pin only scanned `model/*.py` | **Accepted and fixed**: the pin now scans all of `src/`, and a tracked self-check proves the checker catches a synthetic duplicate. |
| The can-fail proof lived only in a gitignored `.scratch` script | **Accepted and fixed** for the central pin (the tracked self-check in item 5 of §4); the four-tamper script remains in `.scratch` like the previous step's. |
| The pins were placed in `test_ports.py` while `ports.py` was untouched, and `tests/test_model_package_contract.py` already owns the model-path pin | **Resolved by the fix rather than waived**: `ports.py` IS touched now, so `test_ports.py` is the right jurisdiction for the exposure pin. The model package's own contract test was left alone deliberately - its `MOVED` table covers MODULE moves, and this is a symbol move inside a module; adding an entry there would claim a module move that did not happen. |
| `tests/test_investigation_coordinator_contract.py:118-124` still described the old blockers | **Claim checked and REFUTED**: this step updated that comment before the review ran (the reviewer read the pre-edit file). Recorded here because a review's wrong findings must be recorded too, not quietly dropped. |
| `investigation/coordinator.py:21` still said only ONE blocker was removed | **Accepted and fixed** (comment only). |
| `ruff format --check` debt added by the new hunks | **Accepted and fixed**, then measured: parity restored (7 → 7 hunks in `test_ports.py`). |
| Moving a 107-line class instead of adding one name | **Partially disputed, recorded**: the move is what makes a *pure* port re-export possible at all; the reviewer's own suggested one-line change is only available after it. |
| The `ClassVar` F821 repair is a lint fix inside a structural step | **Partially disputed, recorded**: the guard refuses to emit a module with unresolvable free names, so the fix is a precondition of the move, not a detour - and it removes a defect `ruff` had been reporting all along. |
| `contracts.py` holds a mutable `BaseModel` among `FrozenContract`s; `runtime_contracts.py` was never weighed | **Accepted as a documentation gap and fixed** in §1 (both weighed; the mutable choice is deliberate and explained). |
| §7.1 step 5 was not done for the moved symbol | **Accepted and fixed**: production caller first, then the three test callers, by AST. |
