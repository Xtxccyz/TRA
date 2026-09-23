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
| test files that reference it | **12** (9 CALL it, 2 only mention it, **0 use `getsource`/`getattr`**) |
| production call sites | 1 (`service.py:9752`) |

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
recorded `legacy_path_imports` entry) - for 16 names. A new module in `investigation/` must import the canonical
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
  (they travel inside the method), and that **no test uses `getsource` on it** - the failure mode that made P3.3d
  delicate does not apply.
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
