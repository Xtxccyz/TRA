# P3.3e preparation: the pure derivation helpers move into `investigation/derivation_support.py`

- **Date**: 2026-09-22
- **Status**: implemented, gated; the two-axis review runs after this document and its outcome is recorded in the step
  record in `.scratch/structure-status.json`
- **Governing plan**: `docs/code-structure-optimization-execution-plan-reviewed-20260922.md` (§3.2 matrix, §7.1 algorithm)
- **Design it executes**: `docs/p33e-derivation-slice-design-20260922.md` §2 and §4

## 1. Why this slice exists

The next step is the largest of the phase: moving `_derive_investigation_observations` (2,795 lines) out of
`AnalysisService`. Its design measured fifteen in-class helpers and split them by the coordinator's own rule - a helper
with no reader outside the giant **travels** with it; a helper with another reader **stays** and must then be reachable
by the moved code. Four travel (165 lines). Eleven have outside readers, so the naive answer was eleven new HOST
members, which is what the giants decision doc had guessed at ("6 → 12").

This slice removes most of that need: eight of the eleven are **pure** - after the intra-cluster rewrite none of them
reads receiver state, and every free name they mention is stdlib or from an allowed layer - so they can live in a leaf
that BOTH `service.py` (for its un-moved callers) and the moved derivation import. `.scratch/p33e-sink-set.py` computes
this as a **fixed point** (sink a helper, then re-close its callers), because three helpers' only receiver read is a
call to a helper that itself sinks.

The three that stay are the ones that genuinely read service state: `_instruction_access_kind` (class constants
`_DATA_LOAD_INSTRUCTION` / `_DATA_STORE_INSTRUCTION`), `_reference_access_kind` (calls it) and `_investigation_value_text`
(references the `AnalysisService` class).

## 2. What moved (measured)

- `investigation/derivation_support.py`: **NEW** - **seven** functions, all `@classmethod`s except `_locator_key`
  (`@staticmethod`), with the receiver parameter dropped and intra-cluster `cls._x(...)` calls rewritten to module-level
  calls (`_parse_static_address`, `_locator_key`, `_function_entry_integers` and `_overlay_pe_parser_thread_start` each
  called a sinking sibling). 102 lines of bodies.
- `service.py`: **27,972 → 27,888 lines** (102 moved lines out, seven delegations in, one dead import removed and one
  restored - see the eighth item below).
- The imports the guard demanded, and they are the **evidence that the leaf is legal**: `facts.thread_start`
  (`recovered_thread_start_address`), `investigation.semantic_predicates` (`normalize_api_symbol`), `typing.Mapping`,
  `re`. Nothing here imports `service` or an implementation module.
- The seven delegations preserve the original decorator and forward **no receiver** (the new functions take none), so
  every existing call - including the tests that call these helpers through the service object - is unchanged.
- **EIGHT helpers were moved and SEVEN stayed moved**: `_emulation_entry_key` went back to the host. A review found that
  the leaf imported `emulation.controlled_emulation` to reach `emulation_entry_key`, and plan section 3.2 admits only
  emulation INTERFACES into `investigation/`. The module is defensible as an interface (stdlib-only imports, no adapters,
  and `investigation/investigation.py` has imported it for `is_real_simulation_row` all along), so the reviewer's
  "hard violation" is **partially refuted** - but this slice would have been the one introducing a NEW occurrence, the
  cheapest correct fix is not to create the edge at all, and the giants decision doc's port estimate of 12 then holds
  exactly (`6 + 4 + 2`). The original body was restored byte-for-byte from `8059cfc` and `service.py` re-imports
  `emulation_entry_key` for it. `.scratch/p33e-sink-set.py` now carries the layer rule as an explicit blocked set with
  its reason, so the classifier cannot call that helper sinkable again.

## 3. Instrument defects this step found and fixed (eight of the family, in one round)

The phase's recurring failure - an instrument whose scope is too narrow or whose configuration is hard-coded, producing
a confident wrong answer - appeared **six times** while making this one small move, and every one was fixed rather than
worked around:

1. **The extractor's delegation was hard-coded to `_coordinator`.** With `--target` added, the generated delegations
   would have called `_coordinator._parse_static_address(...)` for a function that lives in the new leaf - a move that
   compiles only because nothing evaluates the name until the call. The alias is now derived from the target
   (`_derivation_support`), and the tool's own summary line, which printed "coordinator.py" regardless of the target,
   now names the real file.
2. **The verifier had no `--target`,** so it compared the coordinator and reported `_parse_static_address not found` - a
   configuration error that reads exactly like a failed identity check.
3. **That flag's first version resolved against `src/` instead of the package**, so it looked for
   `src/investigation/derivation_support.py`.
4. **A patcher produced mismatched indentation** inside `main()` of the verifier; `py_compile` caught it before the tool
   was used, which is precisely why the hard-gate checklist compiles the instruments first.
5. **The value-diff tool re-hard-coded the coordinator** below the new flag, so the flag had no effect (`KeyError`).
6. **The reference check reported four members as "service.py still holds a REAL implementation"** - a fabricated
   correctness failure - because it looked for `_coordinator.`; a direct AST check showed all eight are one-statement
   delegations, and the tool now follows `--target` for both the alias and the members it enumerates.
7. **The can-fail proof tampered the wrong file** (the coordinator) after the verifier was fixed, so it died with
   `ValueError` instead of proving anything; its tamper subject now follows `--target` too.
8. **The sink-set fixed point left stale `host` entries**, reporting `_code_locator_integers` and
   `_function_entry_integers` as BOTH sinkable and host members. The loop now drops a helper from `host` when it sinks
   and asserts the two sets are disjoint - an instrument that answers one question with two opposite answers is worse
   than one that answers nothing.

## 4. Verification performed

1. **AST identity**: all eight bodies are identical to `HEAD:src/threat_report_agent/service.py` with the receiver
   normalised away (`.scratch/p33-verify.py ... --target investigation/derivation_support.py`);
   the four names belonging to earlier slices are reported **NOT VERIFIED** rather than passing silently.
2. **Value identity**: string values character-for-character and body code lines identical
   (`.scratch/p33c-textdiff.py ... --target ...`).
3. **Destination shape**: exactly eight functions defined, and **zero** receiver leftovers
   (`self.`/`cls.`) in the new module.
4. **Reference check**: eight members are one-statement delegations and 46 call sites route through them
   (`.scratch/p33-reference-check.py ... --target ...`).
5. **Can-fail proven**: tampering a body symbol in the new leaf makes the verifier exit 1 and name the tampered
   function; the file is restored with matching before/after hashes.
6. **Gates**: import graph PASS - **112 modules** (one more: the new leaf), 222 runtime same-package edges, cycles 0,
   the known `persist_how -> reporting` reverse edge unchanged; structure diff PASS; behaviour probe UNCHANGED.
7. **Focused battery**: 195 passed with the four `test_t3_callback_fixture` failures that are **baseline-known** (they
   are four of the six pre-existing failures), i.e. no new failing node.
8. Full suite, rebuild and the deployment gate: recorded in the step record.

## 5. What this unblocks, measured rather than asserted

For the giant's move, the helper part of the port need drops from **seven prospective host members to four** -
`_instruction_access_kind` (class constants), `_reference_access_kind` (calls it), `_investigation_value_text` (its
recursive call is written through the class name, so moving it would make the leaf import `service` and create a cycle)
and `_emulation_entry_key` (needs an emulation implementation module) - so with the two execution members the port lands
at **6 + 4 + 2 = 12**, which is exactly the giants decision doc's estimate. This design's own earlier "6 → 8" and the
first version of this slice's "6 + 3 + 2 = 11" were both artifacts: the first of a scan blind to `self.`-qualified
calls, the second of a review that correctly objected to an emulation implementation edge.

## 6. Not done, recorded

- The three host-bound helpers stay in `service.py` until the giant moves, because their bodies read class state; the
  move will turn them into port members, and the design records that.
- `_parse_static_address` being reachable from the new leaf means the three helpers that call it through `cls.` still
  resolve - they call the delegation - which is why they did not need editing here.
