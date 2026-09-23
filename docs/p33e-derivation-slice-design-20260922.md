# P3.3e design: moving `_derive_investigation_observations` (the derivation giant)

- **Date**: 2026-09-22
- **Status**: designed and measured; the move itself is the next step
- **Governing plan**: `docs/code-structure-optimization-execution-plan-reviewed-20260922.md` (§7.1 algorithm)
- **Relationship to the giants decision**: it estimated this slice's port as "6 → 12" (six shared helpers, 90 lines on
  the host). §2 re-measures the helper split and §4 lands the port between **10 and 15**, decided by a fixed point at
  move time: the estimate's ORDER was right, its count was low (eleven helpers have outside readers, 142 lines). This
  document's own first version claimed "6 → 8" on the strength of a scan that could not see `self.`-qualified calls;
  that claim is withdrawn in §2 with the reason.

## 1. What the slice is, measured

`.scratch/p32-measure-cluster.py _derive_investigation_observations --from HEAD`:

| component | measured |
| --- | --- |
| the giant itself | **2,795 lines** (`service.py` 4133-6927) |
| in-class helpers it calls | **15** |
| module-level names it closes over | **4** |
| nested closures inside the giant | **16** |
| host references already on the port | `settings` (1) |
| implementation references (`simulation_adapters`) | **2** |
| test files that reference it | **12** (9 CALL it, 2 only mention it, **0 call `getsource` ON IT** - see the correction directly below) |
| production call sites | 1 (`service.py:9752`) |

**A CLAIM THIS TABLE GOT WRONG, CORRECTED BY THE SPEC-AXIS REVIEW OF THE MOVE ITSELF (round 116), AND THEN CORRECTED
AGAIN BY THE MOVE (round 118) BECAUSE THE FIRST CORRECTION UNDERCOUNTED.** "0 use `getsource`/`getattr`" is literally
true and materially misleading. `tests/test_mechanism_chains.py:199` does
`source = inspect.getsource(AnalysisService)` and then asserts
`"plausible_traced_creation_flags(parsed_flags)" in source`. Nothing calls `getsource` on the GIANT, but the assertion
depends on the giant's BODY: the call site it looks for is inside `_derive_investigation_observations`. It passed only
while the giant was in `AnalysisService`, and when the giant moved the text left the class and the assertion broke. The
site is already listed as NEGATIVE in `docs/p37-getsource-conversion-plan-20260922.md:49`.

**THE MOVE FOUND TWO MORE SITES, SO THE COUNT WAS THREE, NOT ONE.** A second `getsource` loop over
`AnalysisService._derive_investigation_observations` (`tests/test_static_simulation_budget.py`) began reading a
one-statement delegation instead of the body, and - a family this design never considered - a
`monkeypatch.setattr(service_module, "controlled_emulation_windows", ...)` stopped intercepting anything, because the
moved body resolves that name from its NEW module. All three were migrated to the implementation's new home with their
strength preserved. The lesson is the phase's recurring one: a scope-limited scan ("getsource on the giant") answered a
question nobody asked ("which tests depend on where this code and its names live").

## 2. Per-helper verdict: TRAVEL, SINK or HOST - and a wrong answer this step caught before publishing

`.scratch/p33e-design-measure.py` counts each helper's readers among the class's other methods and
`.scratch/p33e-design-checks.py` checks the whole tree from outside `service.py`.

**A CLAIM THIS DOCUMENT MADE AND THEN WITHDREW, recorded because it is the seventh narrow-scan defect of the phase:**
the first version of `readers()` matched only `ast.Name`, so a call written `self._helper(...)` (an `ast.Attribute`) was
**invisible** and all 15 helpers appeared unused - from which the draft concluded "they all travel, so the port grows
only to 8" and prepared to "correct" the decision doc's arithmetic downwards. A whole-file AST check counted the
`Attribute` references too and showed the opposite. Had it been published, the design would have been wrong in the
direction that breaks the move: eleven helpers would have had no home.

| helper | lines | readers outside the giant | verdict |
| --- | --- | --- | --- |
| `_follow_local_tail_jmp` | 72 | 0 | **travels** |
| `_global_accesses_from_rows` | 70 | 0 | **travels** |
| `_row_own_function_matches` | 13 | 0 | **travels** |
| `_matching_simulation_results` | 10 | 0 | **travels** (tests call it; `service.py` keeps a delegation) |
| `_emulation_entry_key` | 2 | 6 | **sink** - no receiver reads, free names portable |
| `_locator_key` | 8 | 12 | **sink** |
| `_parse_static_address` | 12 | 16 | **sink** |
| `_row_own_function_payload` | 9 | 2 | **sink** |
| `_code_locator_integers` | 11 | 5 | host member today - but its only receiver read is `self._parse_static_address`, which SINKS, so a fixed point may sink it too |
| `_function_entry_integers` | 10 | 6 | same shape as above |
| `_pe_entry_integers` | 12 | 1 | same shape as above |
| `_instruction_access_kind` | 9 | 1 | reads the CLASS constants `_DATA_LOAD_INSTRUCTION` / `_DATA_STORE_INSTRUCTION`; if those are pure data they can sink with it |
| `_reference_access_kind` | 11 | 2 | reads `self._instruction_access_kind` - follows it |
| `_overlay_pe_parser_thread_start` | 40 | 1 | reads `self._locator_key` - follows it |
| `_investigation_value_text` | 18 | 3 | reads the `AnalysisService` class itself; needs a hand measurement |

**Measured totals**: 4 travel (165 lines - the decision doc's figure, confirmed), 4 sink (31 lines), 7 keep a receiver
read of which at most two are genuinely host-bound once the call graph is re-closed. `.scratch/p33e-helper-purity.py`
does this classification and **will be run as a fixed point during the move** - exactly the discipline the extractor
already applies to host needs, and the numbers in §4 follow from it rather than from a guess.

## 2b. The cluster-wide fixed point (added by the preparation rounds, measured)

Per-helper verdicts kept flipping while the preparation slices ran, because each helper's verdict depends on the verdicts
of the helpers it calls, so `.scratch/p33e-cluster-fixed-point.py` now computes the whole partition at once and prints the
reason for every host member. Against `8059cfc`, with the two class constants checked separately by
`.scratch/constant-readers.py`:

| partition | names | lines |
| --- | --- | --- |
| **PURE** - readers outside the giant, no host state → `investigation/derivation_support.py` | `_parse_static_address`, `_locator_key`, `_row_own_function_payload`, `_code_locator_integers`, `_function_entry_integers`, `_pe_entry_integers`, `_overlay_pe_parser_thread_start` | 102 |
| **TRAVELS** - no reader outside the giant, dependencies met | `_bind_recovered_xor_verification` 40, `_decode_output_buffer` 18, `_row_own_function_matches` 13, `plausible_traced_creation_flags` 16, **plus `_instruction_access_kind` 9, `_reference_access_kind` 11 and `_global_accesses_from_rows` 70 once the constants below travel** | 177 |
| **HOST** - must become port members | `_emulation_entry_key` 2 (needs an emulation implementation module), `_follow_local_tail_jmp` 72 (reads `_MAX_GHIDRA_INSTRUCTIONS_PER_FUNCTION`, which TWO methods outside the cluster also read), `_investigation_value_text` 18 (its recursive call goes through the class name, so moving it would import `service`), `_matching_simulation_results` 10 (needs the same emulation module) | 102 |
| **MODULE-LEVEL, travels** | `_DECODE_PRODUCER_KINDS` 7, `_bind_recovered_xor_verification` 40, `_decode_output_buffer` 18, `plausible_traced_creation_flags` 16 | 81 |

**THE CONSTANTS DECIDE THREE MEMBERS, measured**: `_DATA_LOAD_INSTRUCTION` and `_DATA_STORE_INSTRUCTION` have exactly
ONE reader each (`_instruction_access_kind`), so they can travel as module constants - which makes that helper, and then
`_reference_access_kind` (which calls it) and `_global_accesses_from_rows` (which calls that), travel too.
`_MAX_GHIDRA_INSTRUCTIONS_PER_FUNCTION` is read by `_record_builtin_code_signal_evidence` and `_record_ghidra_evidence`
as well, so it must stay a class attribute and `_follow_local_tail_jmp` must stay a host member.

**THE "12" IN SECTION 2b IS REFUTED BY THE MOVE, AND THE ERROR WAS OURS.** §2b ends with "Port for the giant's move,
measured: 6 existing + 4 host members + 2 execution members = 12 - the figure the giants decision doc estimated". After
the move, the two pins can be counted directly: `coordinator.py`'s `INVESTIGATION_HOST_MEMBERS` has **6** members
(`database`, `_audit`, `_MAX_COMPLETED_ACTION_EVIDENCE_IDS`, `_CONVERGENCE_ALTERNATES`,
`_CONVERGENCE_EXPECTED_KINDS`, `_canonical_json`) and this module's has **7** (`settings`,
`_run_simulation_window`, `_qiling_unavailable_observation`, `_emulation_entry_key`, `_follow_local_tail_jmp`,
`_investigation_value_text`, `_matching_simulation_results`). The two sets are DISJOINT, so the giant's path carries
**7** declared members, not 12 - the "6 existing" were the COORDINATOR slice's members, which the giant never reads, and
adding them to this slice's need produced a total that no single port ever had. The correct decomposition of this
module's 7 is `settings` + the 2 execution members + the 4 host helpers. Recorded here rather than quietly renumbered:
this is the third figure for the same quantity to appear in the phase (6→8, then 12, now 7), and each wrong one came
from counting the wrong set rather than from the code.

## 3. Module-level names that must travel

| name | lines | kind | note |
| --- | --- | --- | --- |
| `_DECODE_PRODUCER_KINDS` | 7 | **module-level** assign (verified: `module-level: True, class-level: False`) | module state read by the giant, so it travels |
| `_bind_recovered_xor_verification` | 40 | module function | |
| `_decode_output_buffer` | 18 | module function | |
| `plausible_traced_creation_flags` | 16 | module function | **`tests/test_mechanism_chains.py` uses it** → `service.py` re-exports it after the move |

## 4. Port arithmetic, corrected twice

The decision doc estimated "port 6 → 12" (six shared helpers, 90 lines staying on the host). MEASURED: **eleven**
helpers have outside readers (142 lines), not six - the doc appears to have counted only the helpers reached from the
four travelling ones. Of those eleven, four sink to a pure module and the rest shrink under a fixed-point re-closure
(§2). The move will therefore add:

| addition | count | note |
| --- | --- | --- |
| helpers that must stay host members | **2-7**, decided by the fixed point | each used by the moved code AND by un-moved code, which is what pins them |
| pure helpers sunk to a shared module (like layer item 2's policy) | **4+** | keeps the port small; `service.py` imports them back |
| execution seam | **2** | `_run_simulation_window` and `_qiling_unavailable_observation` (§5) |

**So the port lands between 6+2+2 = 10 and 6+7+2 = 15, and the move must state the number it measured.** The honest
statement now is: *the decision doc's 12 was closer to right than this document's withdrawn 8*; the exact figure is a
fixed-point measurement, not an estimate, and it will be recorded by the move.

The execution members' shapes, which are decided (they are not affected by the fixed point):

| new member | shape | why this shape |
| --- | --- | --- |
| `_run_simulation_window(policy, window)` | returns a small outcome Protocol (`status`, `stop_reason`, `output_bytes`, `as_dict()`), declared in the coordinator | keeps the RUNNER inside the host: the moved code never touches an implementation object, and the deletion test's "narrower than the implementation" holds |
| `_qiling_unavailable_observation(policy)` | `dict | None` | mirrors the existing function exactly, so the payload is unchanged |

## 5. Import canonicalisation the move must perform

The giant imports **`threat_report_agent.dataflow`** - the LEGACY shim path for `facts.dataflow` (it is the single
recorded `legacy_path_imports` entry) - for SEVENTEEN names, the largest canonicalisation of the phase (the cluster slice needed two of them; the giant closed over the other fifteen). A new module in `investigation/` must import the canonical
`threat_report_agent.facts.dataflow` instead: plan §7.1 step 4 says a new implementation must not import the old path,
and `docs/import-policy.json` already records that entry as debt to be repaid rather than copied. Everything else it
imports is either stdlib, an allowed layer (`facts`/`static`/`emulation` interfaces/`models`), or already moved into the
pure policy seam by layer item 2 - which is the visible payoff of that step.

## 6. Recipe for the move (one step, §7.1)

1. Measure again against the current HEAD (the numbers above are from `d6262f9`).
2. Extract the giant + the 15 helpers + the 4 module-level names with `.scratch/p33-extract.py`, which already carries
   the fixes this phase cost six defects to learn: spans start at the first decorator and carry the comment block, the
   import guard refuses to add imports silently, travelling constants are derived, host needs are a fixed point, and the
   arity stop refuses to write a call that omits a host.
3. Declare the two new host members and implement them on `AnalysisService` **by relocating the execution code**, not by
   rewriting it: the runner construction, the window loop and the qiling call move into the host methods with their
   bodies byte-identical, and the moved giant calls them.
4. Add the `SimulationWindowOutcome` view to the coordinator, and extend the host pin from six to eight members.
5. Canonicalise `dataflow` → `facts.dataflow` (the only import rewrite; record it).
6. Verify: AST + value identity for the moved bodies, `p33-reference-check.py --moved-in-coordinator`, the arity pin,
   three can-fail tampers, focused emulation tests, full suite with node-set comparison, rebuild + deployment gate.
7. Then P3.7's test-surface item can retire any remaining `service.<member>` test references deliberately, and P4 can
   delete the re-exports.

## 7. Risks, stated before the move

- **A ~2,900-line single step is the largest of the phase**, and its port growth is the largest too (up to nine new
  members). The mitigations are that every verdict above is measured, that the 16 nested closures need no handling
  (they travel inside the method), and that **no test calls `getsource` ON the giant**. THAT LAST MITIGATION IS
  WEAKER THAN IT READS, corrected in round 116: `tests/test_mechanism_chains.py:199` calls
  `getsource(AnalysisService)` and asserts the class's text contains `plausible_traced_creation_flags(parsed_flags)`,
  a call site inside the giant. The assertion survives only while the giant is in the class, so the giant's move must
  migrate it (already recorded as NEGATIVE in `docs/p37-getsource-conversion-plan-20260922.md:49`). The `getsource`
  failure mode that made P3.3d delicate therefore DOES apply, one indirection away.
- **THE SCAN THAT MEASURES THE SPLIT IS ITSELF THE RISK**, and this step demonstrates it twice: the first `readers()`
  could not see `self.`-qualified calls (withdrawn claim, §2), and the helper-purity classifier's first version treated
  stdlib imports (`typing`, `re`) as "leaving the allowed layers", which would have turned two sinkable helpers into
  port members. Both are fixed, and the move must re-run the classifier as a **fixed point** - sink a helper, then
  re-close its callers - rather than trusting one pass.
- **The two execution members are the only behaviour-adjacent part**: they relocate execution code, so their bodies must
  be byte-identical moves and the emulation tests (`test_controlled_emulation`, `test_t4_isolation_matrix`,
  `test_in_process_execution_rule`, `test_static_simulation_budget`) are the pins that would catch a slip.
- **Three test files call moved helpers** (`test_controlled_emulation`, `test_t3_callback_fixture`,
  `test_mechanism_chains`); they must keep working through delegations, and if a delegation's shape is wrong they fail
  loudly, which is the designed failure mode.

## 8. Execution state: the first half has landed (measured 2026-09-23, round 116)

The move was executed in two halves, because a ~2,900-line body plus a 12-member port in one step cannot be verified
with the phase's gates. **This section is the state, not a plan.**

**LANDED** (`investigation/derivation.py`, NEW, 260 lines; `service.py` 27,889 -> 27,714 lines):

| moved | shape now |
| --- | --- |
| `_bind_recovered_xor_verification` (40), `_decode_output_buffer` (18), `plausible_traced_creation_flags` (16) | module functions in `derivation.py`; `service.py` RE-EXPORTS all three as `X as X` until P4.3 removes that surface, so `service.<name>` and every existing caller are unchanged |
| `_DATA_LOAD_INSTRUCTION`, `_DATA_STORE_INSTRUCTION` (4 each) | module constants in `derivation.py`, REMOVED from the class (each had exactly one reader, `_instruction_access_kind`); the old path is asserted absent |
| `_row_own_function_matches` (13), `_instruction_access_kind` (9), `_reference_access_kind` (11), `_global_accesses_from_rows` (70) | module functions; `service.py` keeps `@classmethod` one-statement delegations, so `_ghidra_data_reference_rows` and the tests that call them are unchanged |

The pure helpers these four call (`_locator_key`, `_code_locator_integers`, `_function_entry_integers`,
`_row_own_function_payload`) already live in `derivation_support.py`, so the moved bodies reach them through that
module's alias - the import canonicalisation of section 5 was performed at the same time (`service.py` keeps the legacy
`threat_report_agent.dataflow` path for its own un-moved code, and this is the ONLY import rewrite the move made).

**THE EXECUTION SEAM HAS ALSO LANDED** (P3.3e-move-2a, round 117), and it is recorded here because it changes this
document's own state table. Section 4's two execution members now exist on `AnalysisService`:
`_run_simulation_window(policy, window)` and `_qiling_unavailable_observation(policy)`, with the runner construction and
the `runner.run(...)` call RELOCATED from the giant's `CONTROLLED_EMULATE` branch, and the giant calls them through
`self`. The branch therefore no longer names `simulation_adapters` at all, which is what lets the giant move into
`investigation/` next.

Three things about that seam are decisions this document did not make, and they are recorded here rather than left to be
rediscovered:

  * **The seam was executed as its OWN step, before the giant's move, although section 6 step 3 prescribes it inside
    that move.** Reason: it is the ONLY behaviour-adjacent part (§7), and isolating it means the behaviour gates
    (`test_controlled_emulation` calls the giant at four sites, plus the isolation/budget tests, the behaviour probe and
    the full suite) prove "no behaviour change" in a step where nothing else moved. The plan's nine-step algorithm is
    therefore satisfied at the granularity of the giant's migration, not of this half-step.
  * **One behaviour delta exists and is deliberate:** the runner is built PER WINDOW (0 times when no window was
    granted, up to 2 per action) instead of once per action before the empty-window check. MEASURED as unobservable:
    every `self.<x>` store in `IsolatedSimulationRunner` is in `__init__`, `run` stores nothing on it, the module holds
    no mutable global, `may_execute_in_process` is pure and `SimulationExecutionPolicy` is frozen. It is now PROBED, not
    argued: `tests/test_investigation_derivation_seam.py` asserts policy-driven outcomes (`WORKER_REQUIRED` under the
    isolated policy, `POLICY_DENIED` for a simulator the policy does not allow), which a member building the runner from
    a default policy cannot produce - proven by `.scratch/p33e-seam-test-canfail.py`.
  * **`SimulationWindowOutcome` was declared in `derivation.py`, not "in the coordinator" as section 4 says.** The
    coordinator cannot take it: `tests/test_investigation_coordinator_contract.py` asserts that the coordinator's pin
    equals EXACTLY the receiver references its own bodies make, so widening that pin for a member the coordinator never
    calls would fail a gate whose purpose is keeping pins honest. Declaring it beside its consumer is the layer-correct
    alternative, and the deviation is recorded here.

THE PIN WAS NOT DECLARED IN THAT STEP, on purpose: a pin must name exactly what THIS module's bodies read, and after the
seam none of them was here yet. Declaring seven host members for a module that read none of them would have been the
aspirational-pin defect this phase has already recorded once. The step that moved the giant declared it in the same
change, and the measurement is now an assertion in `tests/test_investigation_derivation_contract.py`.

**THE GIANT HAS MOVED** (P3.3e-move-2b, round 118), so this section is now a record of the whole slice rather than of a
half. Measured outcome: `investigation/derivation.py` is 3,240 lines and holds the giant's 2,787-line body as a
module-level function whose first parameter is `host: DerivationHost`; `_DECODE_PRODUCER_KINDS` travelled with it;
`service.py` went from 27,889 lines (the start of P3.3e) to **24,948**, keeping a one-statement delegation so every
existing caller and test that reaches `service.<name>` still resolves.

THE PORT IS DECLARED, AND ITS ARITHMETIC IS NOW A MEASUREMENT RATHER THAN AN ESTIMATE:

| what | value | how it was fixed |
| --- | --- | --- |
| this module's own pin | **7 members** | `settings`, `_run_simulation_window`, `_qiling_unavailable_observation`, `_emulation_entry_key`, `_follow_local_tail_jmp`, `_investigation_value_text`, `_matching_simulation_results` |
| the coordinator's pin | 6 members | unchanged; the design's "6 + 4 + 2 = 12" total was counting BOTH pins' members and the two execution members together, and the two pins are declared in their own modules because each must equal exactly what its own bodies read |
| how the 7 were derived | not guessed | `.scratch/p33e-giant-prep.py` printed every receiver reference the giant makes, and `tests/test_investigation_derivation_contract.py` asserts `pin == the references the module's bodies actually make` (can-failed by removing one member) |

FIVE NEW IMPORT STATEMENTS CAME WITH THE MOVE, and the gate's counter moved by four (227 -> 231 runtime same-package
edges, cycles still 0). MEASURED by diffing this module's `threat_report_agent.*` imports against `HEAD`'s version of
it: `emulation.emulation_plan`, `emulation.policy`, `investigation.investigation`, `investigation.semantic_predicates`,
`static.static_simulation`. The two numbers differ because the gate resolves imports against its own module table and
drops self-edges, and an earlier revision of this paragraph asserted a mechanism for the difference that was not
measured - so both numbers are recorded and the raw five-name list is the evidence. Each is a direction §3.2 admits for
`investigation/` (emulation interfaces, sibling investigation modules, a static interface) and the strict gate passes;
they are recorded because "N new edges" is exactly the kind of number that should not appear silently. A related GAP the
Standards axis raised and this step does not close: the gate encodes only the directions it has been taught, so §3.2's
"unlisted edges are forbidden by default" is not mechanically enforced for a future `investigation/` -> implementation
edge.

THE MOVE ALSO FORCED THREE TEST MIGRATIONS, and the reason is worth stating once because the design's section 1 claim
about `getsource` understated it: **moving a body moves where its names resolve.** `getsource(AnalysisService)` stopped
seeing the add-site (`tests/test_mechanism_chains.py`), a loop over `AnalysisService._derive_investigation_observations`
started reading a delegation instead of a body (`tests/test_static_simulation_budget.py`), and a
`monkeypatch.setattr(service_module, "controlled_emulation_windows", ...)` stopped intercepting anything because the
moved body resolves that name from `derivation.py` (`tests/test_controlled_emulation.py`). All three were migrated to
the implementation's new home with their strength unchanged; a can-fail proof on the port contract shows the new pin
assertion can go red.

**WHAT REMAINS ON THE HOST BY DESIGN** (not "not landed"): the four HOST members above, each for the measured reason
recorded in `derivation.py` beside the pin, plus the class attribute `_MAX_GHIDRA_INSTRUCTIONS_PER_FUNCTION` that two
un-moved methods also read.

**SIX INSTRUMENT DEFECTS THIS HALF COST**, all of the phase's recurring family (narrow scope or hard-coded
configuration producing a confident wrong answer):

1. **The class-constant de-indent doubled every newline** (`"\n".join(...splitlines(keepends=True))`), turning 8 lines
   into 16. `ast.unparse` comparison, string-VALUE comparison, the byte-diff tool, the behaviour probe and the full
   suite were ALL green; the Spec-axis review read the file. Fixed, and the byte-diff tool now compares raw lines for
   constants as well as values.
2. **The alias-stripping blind spot, proven by the Standards axis**: both identity tools deleted every `--external`
   alias from BOTH sides, so a call rewritten to the WRONG MODULE (`_derivation_support.x` -> `_derivation.x`, a latent
   `AttributeError`) still compared IDENTICAL with exit 0. Normalisation is now mapping-aware (a receiver becomes the
   alias that really defines the name; alias references are left verbatim) and both tools audit every
   `<alias>.<name>` against the module's symbol table. `.scratch/p33e-alias-canfail.py` tampers exactly that base and
   requires both tools to reject it.
3. **A second `--apply` appended a SECOND banner** (the target already carried one): valid Python, invisible to every
   gate. The banner now has the same dedup guard the import block got after P3.3a.
4. **Option values were treated as member names** in the extractor, both verifiers and the can-fail proof (`--target`
   in one place, `--external` in the others), producing `KeyError` / `not found` / `substring not found` failures that
   read like broken moves. Members are now classified by AST (method / module function / constant) instead of assumed.
5. **`p33-verify.py` could not verify a module-level member at all** (`statements_of(..., "AnalysisService")`); it now
   classifies by what the revision actually holds, and the hard-coded tuples are only the default slice.
6. **`.scratch/p33e-arithmetic.py` still prints the WITHDRAWN partition** (the one that could not see `self.`-qualified
   calls). It is marked superseded in its own header; section 2b's fixed point is the authority.

**And one document claim this half disproved**, corrected in sections 1 and 7 above: "no test uses `getsource`" is not
the same question as "no test depends on the giant's text".

## 9. What the successor step must do first (rewritten after the move landed)

Sections 9.1-9.3 of the previous revision are DONE: the `getsource(AnalysisService)` assertion was migrated in the same
step (plus two more sites the design had not predicted), `_DECODE_PRODUCER_KINDS` travelled with the giant, and this
module's 7-member pin is declared and contract-tested. What is left:

1. **P3.3f: `_run_investigation_loop` (3,523 lines)**, which needs ~34 shared helpers sunk to a layer `investigation/`
   may import plus the `getsource` assertion at `tests/test_analysis_task_orchestration.py:404` migrated. THE GIANT'S
   MOVE JUST ADDED TWO LESSONS FOR IT, both measured: expect MORE `getsource`/`monkeypatch` sites than any scan
   predicted (three here, while section 1 said zero), and expect the move to take four new import edges whose
   admissibility has to be checked against §3.2 rather than assumed.
2. **P3.3b(2) and P3.3d(2)** remain layer-blocked on `report/` and `methodology` helpers being sunk first.
3. **P4.3** can now delete the `service.py` re-export surface this slice left behind, but only after every test that
   reads `service.<moved name>` has been migrated - and the three migrations in this step show that list is discovered
   by RUNNING the suite, not by grepping for `getsource`.
