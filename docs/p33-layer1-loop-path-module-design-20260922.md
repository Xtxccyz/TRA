# P3.3 layer item 1: move the investigation loop-path policy into `investigation/loop_path.py`

- **Date**: 2026-09-22
- **Status**: implemented, gated, two-axis reviewed; the review's findings are dispositioned in §8
- **Governing plan**: `docs/code-structure-optimization-execution-plan-reviewed-20260922.md` (§7.1 nine-step algorithm)
- **Parent step**: P3.3 (`docs/p33-investigation-coordinator-design-20260922.md`)
- **Decision it executes**: `docs/p33ef-giants-decision-20260922.md` §3 item 1

## 1. Why this is a layer move and not a refactor

`threat_report_agent.task.analysis_task_orchestration` imports `threat_report_agent.investigation`. Any policy that
`investigation/` itself needs therefore cannot live in `task/`, because the import back would be a cycle.

Two slices were blocked on exactly this:

- **P3.3f** `_run_investigation_loop` (3,523 lines): the loop body must move into `investigation/`, and it calls
  `next_investigation_loop_path` and `resolve_persist_how_skip`, which lived in `task/`. **This blocker is now gone**
  (verified: no `investigation -> task` import exists, and importing `investigation.loop_path` does not load `task`).
- **P3.3c(2)** (3 members, 71 lines): one of them calls `action_is_model_or_human`, which is in this cluster. That slice
  has a **second, independent** blocker - the model port does not expose `DynamicPlanAction` (decision doc §3 item 4) -
  so this step removes ONE of its two blockers, not both. **P3.3c(2) is not executable from this change alone.**

**One ADR note, because the names look like budget semantics**: `LOOP_PATH_BUDGET_DEFER` (and the READY/BOUNDARY order
the loop path encodes) moved into `investigation/`. ADR-0002 keeps budget ownership and termination with the
orchestrator; what moved is the *policy encoding* of "persist-HOW skip beats budget, budget beats the planner", not the
budget itself. `service.py` still owns every budget decision.

## 2. What moved (measured, not estimated)

MEASURED with `.scratch/layer1-measure.py`:

| item | kind | item lines |
| --- | --- | --- |
| `SUPPORTING_SKIP_CATEGORIES` (plus its 2-line rationale comment) | assignment | 11 |
| `SLOT_DEAD_LETTER_ATTEMPTS` | assignment | 1 |
| `PERSIST_HOW_READY` / `_BOUNDARY` / `_MINE` | assignment | 3 |
| `PersistHowSeedFn`, `PersistHowBoundaryFn` | assignment (type aliases) | 2 |
| `PersistHowDecision` | **decorated class** (`@dataclass(frozen=True)`) | 7 |
| `unique_os_thread_playbook` | function | 2 |
| `resolve_persist_how_skip` | function | 103 |
| `LOOP_PATH_PERSIST_READY` / `_BOUNDARY` / `_BUDGET_DEFER` / `_PLANNER` | assignment | 4 |
| `next_investigation_loop_path` | function | 18 |
| `action_is_model_or_human` | function | 18 |
| **total** | 16 items | **169 lines** (of which 2 are the carried comment) |

Result: `task/analysis_task_orchestration.py` **460 → 298 lines**; `investigation/loop_path.py` **213 lines**
(23-line header + 190 lines of moved content and separators, of which 6 are the PEP 8 double-blank separations).

The free names the new module needs are exactly `Callable`, `Iterable`, `Mapping`, `SimpleNamespace`, `dataclass`,
`recovery_actions_for_gap`, and the import block is **derived** from them (§3, D2).

**A measurement correction this step forced**: the cluster was first measured at 166 lines and its spans are 167
(excluding the carried comment). The missing line was `@dataclass(frozen=True)` - the measurement had the extractor's
blind spot (§3, D1).

## 3. The five defects, and who found each one

### Found by the pytest battery, not by a gate

**D1 - the span started at `node.lineno`, so decorators were left behind.** `ast` gives a decorated definition a
`lineno` pointing at the `def`/`class` keyword, so a span starting there excludes the decorator line. Both halves of the
move were wrong at once: the moved copy **lost** `@dataclass(frozen=True)` (so `PersistHowDecision` became a plain class
and every construction raised `TypeError: PersistHowDecision() takes no arguments`), and the original decorator
**stayed** in the task module, where it re-bound to the next statement - MEASURED: onto
`class AnalysisTaskRuntime(Protocol)`, silently turning a Protocol into a frozen dataclass.

What stayed **green** on that defective tree: the import-graph gate, the structure-diff gate (all nine behaviour-surface
digests unchanged), the behaviour probe (UNCHANGED), `compileall` (0), the `is`-identity check across both import paths,
and **the identity verifier written for this move** - which computed its spans the same way and therefore reported
BYTE-IDENTICAL for all 16 items. `tests/test_analysis_task_orchestration.py` caught it: **9 failed, 36 passed**.

`p33-extract.py` had already learned this for METHOD delegations (it carries the comment and uses
`min([fn.lineno, *(d.lineno for d in fn.decorator_list)])`); the module-level path and the new verifier had not.

**D2 - the imports were a hand-written header plus a whitelist that could not discover a miss.** The dry run
"confirmed" the import set by intersecting the moved text's names with a hard-coded four-name set, so it could only
print the names it had already been told about. The corrected derivation found **two** imports the first attempt had
omitted: `dataclass` and `SimpleNamespace`. The second would have been a `NameError` inside `unique_os_thread_playbook` -
a defect that could have shipped and failed later in a path no test exercises. The mover now derives the block and
**refuses to write code** whose free names are neither builtins nor imports in the source module.

### Found by the two-axis review

**D3 - a comment block directly above a moved definition was left behind.** `SUPPORTING_SKIP_CATEGORIES`' two-line
rationale ("Keyword supporting seeds still get durable UNKNOWN threads...") stayed in the task module, where it orphaned
above `class AnalysisTaskRuntime`. Contiguous comment lines above a span now travel with it.

**D4 - the derived import went through a re-export facade, and the re-export block failed the pinned linter.**
`from threat_report_agent.investigation import recovery_actions_for_gap` resolved through the target package's own
PEP-562 facade - a dynamic edge the import gate counts as zero cycles and cannot see. The mover now prefers the
**defining submodule** (which is what the other nine `investigation/*.py` modules do). Separately, a plain re-export
block made `ruff check` fail with **16 F401** errors; the repo pins `ruff>=0.8` and its default rules include F401. The
block now uses the explicit-re-export idiom `NAME as NAME`, and the five imports the move made dead were removed
(`dataclass`, `SimpleNamespace`, `Callable`, `Mapping`, `recovery_actions_for_gap` - each measured at zero references).

**D5 - the joining whitespace was restyled without being declared, and not to the package's own convention.** Items
were joined with a single blank line, so the new module had **zero** PEP 8 double-blank separations while every other
module in the package has them (measured: `behavior_catalog` 42, `coordinator` 31, `investigation` 110,
`investigation_ledger` 17, `persist_how` 8, `mechanism_ready` 3). No gate checks this and `ruff`'s default rule set does
not include E302. MEASURED after the fix: 6 double-blank separations and zero runs of three-or-more blank lines.

### What is and is not byte-identical (stated precisely, because the first draft overclaimed)

- **Every one of the 16 items is byte-identical to its pre-move text, comment block and decorator included.** A
  module-to-module move has no receiver rewrite, so exact equality is required; there is no intended difference.
- **The separators between items were normalised** (12 of them, measured): the old file used 0 blank lines between
  adjacent constants, 2 around definitions, and 20 in the one place where two moved items were far apart. The new module
  uses 1 blank line between adjacent assignments and 2 around definitions.

## 4. Verification actually performed

1. **Moved text, decoration and comments, byte for byte**: all 16 items identical to
   `HEAD:src/threat_report_agent/task/analysis_task_orchestration.py` (`.scratch/layer1-verify.py` property 1).
2. **No unbound references** in the new module (property 2) - the check that would have caught D2's `SimpleNamespace`.
3. **The source module's unrelated statements keep their names and their decoration**: `lost=none gained=none
   dragged=none` (property 3).
4. **Identity through both import paths**: `task.analysis_task_orchestration.<name> is investigation.loop_path.<name>`
   for all 16 names (property 4, and pinned in the product suite).
5. **Plan §7.1 step 5 - callers migrated**: production first (`service.py` now imports the six moved names it uses from
   `investigation.loop_path`), then the test callers one by one (10 sites in
   `tests/test_analysis_task_orchestration.py`, by AST, not by hand). The only remaining importer of the old path is
   `tests/test_task_package_contract.py`, which exists to pin the re-export.
6. **Two regression pins in the PRODUCT suite** (not only in gitignored `.scratch`): the cluster is defined in
   `investigation/loop_path.py` and re-exported (all 16 names, one object per name, plus the frozen-dataclass behaviour
   asserted through public API - `is_dataclass`, construction, `FrozenInstanceError`), and the task module has **no
   top-level decorated statement** - the general form of D1, which catches a decorator dragged onto *any* surviving
   statement rather than the single landing site the first version checked. Both were **can-fail proven** by
   reproducing each half of the defect on the real files and restoring them byte-for-byte
   (`.scratch/layer1-canfail.py`; tamper 2 deliberately decorates a different statement than the one that actually got
   hit).
7. **Lint**: `ruff check` clean on every file this step touched. The repository has 27 pre-existing ruff errors in
   untouched files (measured before and after; unchanged).
8. **Gates**: import graph PASS (110 modules, 211 runtime same-package edges, cycles 0, empty allowlist, the one known
   `persist_how -> reporting` reverse edge unchanged); structure diff PASS (no new violation, no behaviour-surface
   change); behaviour probe UNCHANGED.
9. **Focused battery**: 47 passed (MEASURED per file: `test_analysis_task_orchestration` 17 - 15 before this step's two
   new pins - `test_task_package_contract` 7, `test_investigation_coordinator_contract` 12, `test_task_runner_contract`
   11).
10. Full suite, rebuild and the deployment gate: recorded in the step record in
    `.scratch/structure-status.json`, rendered into `docs/structure-execution-status-20260922.md`.

## 5. What this unblocks

- **P3.3f**: the `investigation -> task` cycle is gone for this cluster, so the loop can import its own loop-path policy
  from inside the package. P3.3f still needs its ~34 shared helpers sunk and one `getsource` assertion migrated.
- **P3.3c(2)**: one of its two blockers is gone; the other (model port / `DynamicPlanAction`, decision-doc item 4)
  remains, so it is **still not executable**.

Layer items 2-5 of the decision doc are untouched. Item 4 is the smallest and is next; item 2 is the one that unblocks
P3.3e, the largest remaining slice.

## 6. Deferred on purpose, and recorded rather than silently skipped

- **`tests/test_analysis_task_orchestration.py:404`'s `inspect.getsource(AnalysisService._run_investigation_loop)`
  assertion was NOT migrated.** The status document's instruction for this step named it, and the plan (line 154)
  forbids `getsource` as a long-term test interface - but the member it inspects (`_run_investigation_loop`) has NOT
  moved, so the assertion still measures the real body and would only become a delegation-reader when P3.3f moves it.
  It is therefore part of P3.3f's work (and P3.7's test-surface item), not this step's. This deviation is recorded in
  the step record rather than left implicit.
- **`investigation/persist_how.py:26` still imports through the package facade** (`from threat_report_agent.investigation
  import ...`), unlike the nine other modules. It is a different step's artifact and may be deliberate; D4's fix applies
  to the new module only. Recorded as an observed inconsistency.
- `legacy_path_imports` (the old flattened paths) is P4.1's allowlist; this step adds nothing to it.

## 7. The standing lesson (sixth instance of one tool family)

This is the **sixth** time in this phase that an instrument produced a confident wrong answer because its scan was too
narrow, and the **second** time a verifier inherited the very blind spot it existed to detect:

| # | instrument | what it could not see |
| --- | --- | --- |
| 1 | port measurement | `cls.` receiver (only `self.`) |
| 2 | port measurement | reads of the working tree while measuring a move |
| 3 | call-shape probe | arity (only shape) |
| 4 | can-fail proof | a tampered docstring made the proof vacuous |
| 5 | three AST scans | annotated assignments (`AnnAssign`) |
| 6 | mover + verifier | decorators (`decorator_list`), comment blocks above a span, and imports listed by hand |

The generalisable rule, now applied here: **when a tool and its verifier are written together, test the verifier against
a deliberately damaged subject**, or it agrees with the tool by construction. Properties 2 and 3 of §4 exist purely
because of this - they are what would have failed loudly on the defective tree.

## 8. The two-axis review: findings and dispositions

The review ran as two independent subagents against the last verified code commit `72fa4c8`.

**Confirmed true by the Spec axis** (independently re-measured): the 16 spans are decorator-aware byte-identical, the
cluster is 169 lines, the task module lost exactly the moved names and gained none, no unbound free names, the
investigation-to-task cycle is gone, and both gates pass.

| finding | disposition |
| --- | --- |
| Zero callers migrated (plan §7.1 step 5) | **Accepted and fixed**: production caller then test callers, by AST (§4.5). |
| The `getsource` assertion the status doc named was not migrated | **Accepted as a deviation, recorded** and assigned to P3.3f with the reason (§6). |
| The design doc cited a step record that did not exist yet | **Accepted**: the record is written and rendered in the same commit as this document, and the wording now names `.scratch/structure-status.json` as the source and the rendered doc as its output. |
| Structural properties pinned only in gitignored `.scratch` | **Accepted and fixed**: two product-suite pins, can-fail proven (§4.6). |
| Five dead imports left in the shim | **Accepted and fixed** (D4). |
| `ruff` F401 on the changed file; the doc's gate list omitted lint | **Accepted and fixed** (D4); lint is now in the gate list (§4.7). |
| "Byte-identical / MOVED VERBATIM" overclaims because blank lines were redistributed | **Accepted and fixed**: the claim is now split into what is byte-identical (the items) and what was normalised (the separators), with the measurement (§3). |
| Orphaned comment and a now-false module docstring | **Accepted and fixed** (D3). |
| The derived import resolved through a PEP-562 facade, an edge the gate cannot see | **Accepted and fixed** (D4). |
| Whitespace restyled without being declared and not to the package convention | **Accepted and fixed** (D5). |
| `_is_protocol` / `__dataclass_params__.frozen` pin private internals against plan §3.3 line 154 | **Accepted and fixed**: the pins now use public behaviour only. |
| The dragged-decorator pin covered one landing site | **Accepted and fixed**: it now asserts the whole decorated set, and the can-fail proof tampers with a different statement. |
| Stale rationale in `coordinator.py` and in the coordinator contract test ("action_is_model_or_human would be a cycle") | **Accepted and fixed** in both places, marked as a historical reason. |
| Scope creep: the giants decision doc was edited beyond marking item 1 done | **Partially disputed, recorded**: the step's whitelist includes `docs/**`, and the user's own round-100 instruction requires stale next-step guidance to be fixed rather than left standing. The edit is limited to marking item 1 done and re-pointing the next executable step; the re-ranking within it is a judgement call flagged here. |
| The task module's remaining statements must not be touched | **Upheld**: measured `lost=none gained=none dragged=none`, and `AnalysisTaskRuntime` is an undecorated Protocol in the product suite's pin. |

## 9. Cost

The D1 defect was found by the focused pytest battery - the same instrument that catches most policy breaks here. Had it
not been caught, a Protocol would have silently become a frozen dataclass and the moved policy class could not be
constructed at all. The rest of the review's findings cost one extra verification cycle each (rebuild + full suite +
deployment gate), which is why the fixes were batched before re-running them.
