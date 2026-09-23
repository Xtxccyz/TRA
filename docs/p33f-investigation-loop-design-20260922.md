# P3.3f design: moving `_run_investigation_loop` (the orchestration giant)

- **Date**: 2026-09-23 (round 119)
- **Status**: measured and designed; the move itself is NOT executed
- **Governing plan**: `docs/code-structure-optimization-execution-plan-reviewed-20260922.md` (§7.1 algorithm, §3.2 matrix)
- **Predecessors**: `docs/p33ef-giants-decision-20260922.md` (the two-giants decision, whose P3.3f blocker was the
  loop-path names in `task/analysis_task_orchestration.py`), `docs/p33e-derivation-slice-design-20260922.md` (P3.3e,
  COMPLETE - it produced this module, and the loop's move reuses its instruments and its three lessons)
- **Everything below is MEASURED against `HEAD` (3c53869) with the probes named in each section.** The phase has
  published three different port numbers for the giant by quoting estimates; this document quotes components.

## 1. What the slice is, measured

| component | measured | how |
| --- | --- | --- |
| the loop | **3,523 lines** (`service.py` 5215-8737), no decorators | `.scratch/p33e-giant-prep.py _run_investigation_loop`, `.scratch/p32-measure-cluster.py` |
| references to `AnalysisService.` / `service.` inside its body | **0** | same probe, section 2 |
| nested closures | **7, of which 1** (`execute`) reaches a receiver (6 host members) | same probe, section 5 |
| free names it closes over | **63** | same probe, section 4 |
| module-level names it closes over that `service.py` DEFINES | **13 -> 1** | `.scratch/p33f-travellers.py`; P3.3f-1 moved twelve of them, leaving `_investigation_scheduled_keys` to travel with the loop |
| distinct receiver references | **45** | `.scratch/p33f-member-homes.py` |
| production call sites | 4 in `service.py` (3413, 3574, 17731, 23255) | `git grep` |
| test surface | 2 `getsource` sites, 1 monkeypatch site, 9 test files that call it | `.scratch/p33e-giant-prep.py`, section 6 |

**The decision doc's blocker is gone.** It recorded P3.3f as blocked on five names from
`task/analysis_task_orchestration.py` (`LOOP_PATH_PERSIST_READY`, `LOOP_PATH_PERSIST_BOUNDARY`,
`LOOP_PATH_BUDGET_DEFER`, `next_investigation_loop_path`, `resolve_persist_how_skip`). Layer item 1 moved them into
`investigation/loop_path.py`, and the measurement confirms the loop now reaches them there.

## 2. Layer verdicts for all 63 free names (`.scratch/p33f-layer-scan.py`)

| verdict | count | detail |
| --- | --- | --- |
| allowed layers | **45** | `models` (18), `investigation`/siblings (22: `loop_path`, `investigation_ledger`, `mechanism_ready`, `mechanism_completeness`, `investigation_protocol`), `static.evidence_recovery`, `static.static_analysis` |
| stdlib / third-party | **4** | `hashlib`, `typing.Mapping`, `dataclasses.replace`, `sqlalchemy.select` |
| defined in `service.py` (not imported) | **13 -> 1** | section 4 below; P3.3f-1 moved twelve |
| **FORBIDDEN (unlisted layer)** | **1 -> 0** | `no_new_evidence_autopsy` from `threat_report_agent.deep_analysis_quality`. P3.3f-1 sank its DEFINITION into `investigation/evidence_autopsy.py`; `service.py` still imports it through the old path, but as a re-export, so the loop's new home can import it from an allowed layer. THE VERDICT IS ABOUT THE DEFINITION, which is why the scan had to be taught to resolve names to their defining module rather than to `service.py`'s import path - its first form still printed FORBIDDEN immediately after the sink |

**A SECOND FORBIDDEN NAME APPEARED IN CLUSTER B'S CLOSURE AND THE DESIGN DID NOT PREDICT IT.**
`_HOW_SEED_CATEGORIES = HOW_SEED_CATEGORIES` needs `HOW_SEED_CATEGORIES`, which `task/analysis_task_orchestration.py`
defines; section 3.2 does not admit `task/` into `investigation/`, so the VALUE was sunk into `investigation/seed_support.py`
with a re-export left behind in the task module. This is the same class of blocker as the five loop-path names layer item 1
moved, and it was invisible to the extractor's import guard because that guard checked functions but not constants
(P3.3f-1 extended it). It also adds an edge this design did not list:
`task.analysis_task_orchestration -> investigation.seed_support`.

**THE ONE FORBIDDEN NAME IS THE WHOLE BLOCKING CONDITION, and it is cheap to remove.** MEASURED with
`.scratch/p33e-giant-prep.py`'s closure logic: `no_new_evidence_autopsy` is 73 lines whose entire closure is
`Mapping`, two module constants (`NO_NEW_EVIDENCE_CATEGORIES`, `_AUTOPSY_NEXT_ACTIONS`) and two tiny private helpers
(`_first_selector_value` 6 lines, `_has_nonempty` 8) - **87 lines plus two constants**. Its readers are `service.py`
(5 sites), `deep_analysis_quality.py` itself (4 sites) and `tests/test_deep_analysis_quality.py`.

The two names that LOOK like an existing `investigation -> deep_analysis_quality` edge in
`investigation/investigation.py:7977,8294` are **string literals**, not imports: `git grep` shows them in quotes and the
module has no import of that module. So adding an import in the loop's new home would be a genuinely NEW forbidden edge,
and the phase's own ruling applies (the `emulation.controlled_emulation` precedent: a pre-existing use is not a licence,
and here there is not even a pre-existing use).

**DECISION: sink the autopsy cluster into `investigation/`** (the PURE-sink pattern P3.3e used for its seven helpers),
rather than routing it through the port. The module it comes from already imports ONLY
`investigation.investigation_protocol` / `investigation.mechanism_completeness` / `investigation.mechanism_ready` and
stdlib, so the direction is consistent, and the sink keeps the port smaller than a wrapper would.

## 3. The partition, from the cluster-wide fixed point (`.scratch/p33e-cluster-fixed-point.py --member _run_investigation_loop`)

| partition | count | note |
| --- | --- | --- |
| **PURE** | 20 | helpers with readers outside the loop, e.g. `_audit` (76 outside readers!), `_link_claim_evidence` (10), `_canonical_json` (8), and the eight `_is_*_seed_row` / `_is_*_row` predicates |
| **TRAVELS** | 38 | no reader outside the loop, dependencies pure or travelling |
| **HOST (port)** | 9 | each with a printed reason: `_investigation_value_text` (calls a non-pure sibling), `_is_task_cancelled` (reads `database`), `_load_investigation_execution_rows` and `_select_investigation_execution_rows` (read `_INVESTIGATION_EXECUTION_EVIDENCE_LIMIT`, `_MODEL_EVIDENCE_PRIORITY`), `_persist_how_function_entries` (`_PERSIST_HOW_PLAYBOOKS`), `_persist_pma_static_analysis_plan` (calls `_pma_plan_facts_from_session`), `_persist_ready_emulation_actions` (calls `_persist_how_function_entries`), `_persist_time_static_boundary` (`_HOW_PLAYBOOK_IDS`), `_pma_plan_facts_from_session` (`_PMA_PLAN_FACT_KINDS`, `_PMA_PLAN_FACT_LIMIT`) |

**The pure/travelling verdict is NOT the whole answer**, because a name's verdict depends on where it lives TODAY - and
Phase 3 has already moved four slices. `.scratch/p33f-member-homes.py` adds that axis for the 45 receiver references:

| home today | count | port cost |
| --- | --- | --- |
| one-statement delegation to `_coordinator` / `_derivation` (allowed siblings) | **6** | **none** - the new home imports the sibling module |
| one-statement delegation to `_limitations` (`task.limitations`) | **2** | **PORT** - `task/` is not in §3.2, so the new home cannot import it (`_is_task_cancelled`, `_static_decode_recovery_from_limitations`) |
| real body, no reader outside the loop | **25** | none (they travel), EXCEPT the 8 the fixed point pins to the host for host-state reasons |
| real body WITH readers outside the loop | **4** | **PORT**: `_audit` (86 lines, 76 readers), `_link_claim_evidence` (32, 10), `_canonical_json` (4, 8), `_persist_pma_static_analysis_plan` (26, 3) |
| class attributes | **5** | **PORT** (read through the receiver; 4 have outside readers, `_PERSIST_HOW_CLAIM_MODULES` has none but is still class state) |
| instance attributes | **3** | **PORT**: `settings` (178 outside readers), `database` (97), `content_store` (29) |

**PORT, component by component: 4 + 7 + 2 + 5 + 3 = 21 members** (4 real bodies with outside readers; 7 further
host-state-pinned bodies from the fixed point's list of 9, less the two counted above; the 2 `task.limitations`
delegations; 5 class attributes; 3 instance attributes). For comparison, P3.3e's module ended with **7**. The move must
re-measure and record the number it gets, because a port this size is exactly where an estimate has been wrong before.

## 4. The 13 module-level travellers and who else reads them (`.scratch/p33f-travellers.py`)

**EXECUTED in P3.3f-1, with one correction to this design's own list.** Exactly ONE travelled with no other reader -
`_investigation_scheduled_keys` - and it is the only one still in `service.py`. The other twelve were sunk. The design's
list understated the FOOTPRINT of that sink: the twelve bring EIGHT module constants in their closure
(`_SEED_CATEGORY_PLAYBOOKS`, `_ARTIFACT_WIDE_SCHEDULER_DIMENSIONS`, `_HOW_SLOT_RANK`, `_PLACEHOLDER_EMU_BUDGET_STATUSES`,
`_PER_SLOT_TRACE_CAP`, `_PROVENANCE_STRIP_KEYS`, `_HOW_SEED_CATEGORIES` and `_strip_provenance`), so P3.3f-1 moved **19
definitions out of `service.py` plus `HOW_SEED_CATEGORIES` out of `task/`**, and a Standards-axis review measured that
six private names and one public constant had lost their `service.` reachability until every moved name was re-exported.
TEN of the thirteen are read by test files:

| name | readers in `service.py` outside the loop | test files |
| --- | --- | --- |
| `_evidence_anchor_keys` | 4 | - |
| `_scoped_investigation_action_key` | 4 | `test_pe_entry_function_budget` |
| `_evidence_api_symbols` | 2 | - |
| `_HOW_SEED_CATEGORIES` | 1 | `test_pe_entry_function_budget` |
| `_provenance_free_digest` | 1 | `test_semantic_evidence_key` |
| `coalesce_investigation_seed_clusters` | 1 | `test_investigation_service` |
| `_seed_context_rows` | - | `test_investigation_service`, `test_pe_entry_function_budget` |
| `investigation_seed_step_budget` | - | `test_investigation_service`, `test_investigation_step_budget` |
| `_seed_playbook` | - | `test_pe_entry_function_budget` |
| `admit_investigation_seed_clusters` | - | `test_investigation_service` |
| `how_seed_slot_rank` | - | `test_investigation_service` |
| `investigation_budget_charged_action_count` | - | `test_investigation_service` |

The seed/evidence-key cluster is cohesive (seed-row selection, slot ranking, step budget, action keys) and is read by
BOTH `service.py` and the tests, so §7.1's rule applies: SINK it to a layer both may import, and keep the names
reachable from `service.py` until P4 migrates every reader. Sinking also removes 12 of the 13 travellers from the move.

## 5. Test surface - and the lesson P3.3e paid for

| site | what it does | migration |
| --- | --- | --- |
| `tests/test_analysis_task_orchestration.py:428` | `inspect.getsource(AnalysisService._run_investigation_loop)` | point at the implementation's new home (as P3.3e did for two sites) |
| `tests/test_investigation_recovery_loop.py:274` | the SAME assertion, in a second file | the decision doc predicted one site; this is the second |
| `tests/test_controlled_emulation.py:1304` | `monkeypatch.setattr(service, "_run_investigation_loop", ...)` | instance-level: unaffected while `service.py` keeps a delegation, but it must be RE-CHECKED at move time |
| 9 test files call `service._run_investigation_loop(...)` | through the delegation | unchanged |

**P3.3e's measured lesson is not "check for getsource":** moving a body moves where its names RESOLVE, so
`getsource` targets, `monkeypatch` targets and any test that patches a module-level name the moved body reads all have to
be found by RUNNING the suite, not by grepping for `getsource`. P3.3e predicted none and found three; this slice has
already found three before moving.

## 6. The split this design prescribes - P3.3f-1 is DONE, P3.3f-2 remains

**P3.3f-1 (preparation) - EXECUTED in round 120, with two corrections this design did not foresee:**
1. sank the autopsy cluster into `investigation/evidence_autopsy.py` with re-exports from `deep_analysis_quality.py`,
   removing the ONLY forbidden IMPORT. The re-export is for ALL FIVE names, not only the two that module still reads: a
   review measured that six private names and one PUBLIC constant (`NO_NEW_EVIDENCE_CATEGORIES`, listed in `__all__`) had
   become unreachable, and §7.1 step 4 keeps the old path reachable until P4;
2. sank the seed/evidence-key cluster into `investigation/seed_support.py` - TWELVE functions plus the EIGHT constants
   their closures need (the design listed twelve names and no constants), keeping every name reachable from `service.py`
   as `X as X`;
3. left `_investigation_scheduled_keys` to travel with the loop - the one name of the thirteen with no other reader;
4. AND moved `HOW_SEED_CATEGORIES` out of `task/analysis_task_orchestration.py` into the same module, because the twelfth
   name's closure needed a value defined in a layer §3.2 forbids. This is the one deviation from the prescription, it is
   forced by the design's own §3.2 reading, and it adds the edge `task -> investigation.seed_support`.

**P3.3f-2 (the move, one step):** move the loop plus its port, its 7 nested closures (1 of which carries receiver
references), `_investigation_scheduled_keys`, and migrate the two `getsource` sites and re-check the monkeypatch site.
**THE PORT MUST BE RE-MEASURED FIRST**: P3.3f-1 changed both of its inputs - the twelve seed names and the autopsy name now
live in allowed layers and cost no port entry at all, while whatever else the loop reads through the receiver still does.
The 21 components in section 3 are the PRE-SINK measurement and are not a promise.

**Where the loop lands is a decision for the move, with a preference:** `investigation/derivation.py` already holds the
giant and the cluster; landing the loop there makes `self._derive_investigation_observations(...)` and the whole
travelling cluster BARE calls (no alias, no port entry), which is why 6 of the 8 delegations cost nothing in section 3.
If the move instead creates `investigation/loop_runner.py`, those six become `_derivation.<name>(...)` calls through the
sibling import - also admissible, slightly noisier. The move must state which it did and why.

## 7. Risks, stated before the work

- **This is the phase's largest slice** (3,523 lines, a 21-member port, 13 module-level names, 7 closures) and its two
  predecessors both needed a preparation step. The split in section 6 exists because a single step of this size cannot
  be verified with the phase's gates in one round.
- **The port is where an estimate has failed three times.** The components are measured; the total is not a promise.
- **The seed/evidence-key sink touches tests** (ten files read those names), so P3.3f-1 carries a test-surface risk of
  its own - mitigated by keeping every name reachable from `service.py` (the P4 migration then has one list to work
  through instead of a scatter of edits).
- **The one forbidden name is the only LAYER fact that blocks the move**, and it is removable in 87 lines. If the sink
  turns out to drag in more of `deep_analysis_quality` than its closure shows, the fallback is a host wrapper (the
  `_emulation_entry_key` precedent) and the port grows by one.
