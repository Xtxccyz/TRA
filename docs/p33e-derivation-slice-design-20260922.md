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

**A CLAIM THIS TABLE GOT WRONG, CORRECTED BY THE SPEC-AXIS REVIEW OF THE MOVE ITSELF (round 116).** "0 use
`getsource`/`getattr`" is literally true and materially misleading. `tests/test_mechanism_chains.py:199` does
`source = inspect.getsource(AnalysisService)` and then asserts
`"plausible_traced_creation_flags(parsed_flags)" in source`. Nothing calls `getsource` on the GIANT, but the assertion
depends on the giant's BODY: the call site it looks for is inside `_derive_investigation_observations`. It passes today
only because the giant is still in `AnalysisService`; when the giant moves, the text leaves the class and the assertion
breaks. The site is already listed as NEGATIVE in `docs/p37-getsource-conversion-plan-20260922.md:49`, so the giant's
move must migrate it - the same class of work P3.3f needs for
`tests/test_analysis_task_orchestration.py:404`. The lesson is the phase's recurring one: a scope-limited scan
("getsource on the giant") answered a question nobody asked ("does any test depend on the giant's text").

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

**Port for the giant's move, measured: 6 existing + 4 host members + 2 execution members = 12** - the figure the giants
decision doc estimated, and the same one the preparation step reached from the other direction.

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
| `_bind_recovered_xor_verification` (40), `_decode_output_buffer` (18), `plausible_traced_creation_flags` (16) | module functions in `derivation.py`; `service.py` imports all three back by name, so `service.<name>` and every existing caller are unchanged |
| `_DATA_LOAD_INSTRUCTION`, `_DATA_STORE_INSTRUCTION` (4 each) | module constants in `derivation.py`, REMOVED from the class (each had exactly one reader, `_instruction_access_kind`); the old path is asserted absent |
| `_row_own_function_matches` (13), `_instruction_access_kind` (9), `_reference_access_kind` (11), `_global_accesses_from_rows` (70) | module functions; `service.py` keeps `@classmethod` one-statement delegations, so `_ghidra_data_reference_rows` and the tests that call them are unchanged |

The pure helpers these four call (`_locator_key`, `_code_locator_integers`, `_function_entry_integers`,
`_row_own_function_payload`) already live in `derivation_support.py`, so the moved bodies reach them through that
module's alias - the import canonicalisation of section 5 was performed at the same time (`service.py` keeps the legacy
`threat_report_agent.dataflow` path for its own un-moved code, and this is the ONLY import rewrite the move made).

**NOT LANDED, with the reason each waits:** the giant itself, `_DECODE_PRODUCER_KINDS` (its only reader is the giant -
one bare read - so it travels WITH the giant, not before it), the four HOST members, and the two execution members
(`_run_simulation_window`, `_qiling_unavailable_observation`) with the host pin. Bringing the constant here now would
leave this module holding a constant nothing here reads while `service.py` still reads it.

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

## 9. What the successor step must do first

1. **Treat the giant as one step with its own port growth**, per section 6, now with the corrected `getsource`
   constraint: migrate `tests/test_mechanism_chains.py:199` (or park the assertion) in the SAME step, because the
   assertion reads the class the giant is leaving.
2. **Bring `_DECODE_PRODUCER_KINDS` with the giant** (one bare read) and declare the host pin at that point - this
   module has no port today, which the extractor enforces by refusing to write any body that still refers to a
   receiver.
3. Re-run the identity battery with `--external _derivation_support=...` (without it the tools correctly report
   DIFFERS, which is a configuration error, not a finding) and keep the wrong-base can-fail proof in the gate list.
