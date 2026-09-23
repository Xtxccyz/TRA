# P3.3 layer item 2: the pure simulation policy moves into `emulation/policy.py`

- **Date**: 2026-09-22
- **Status**: implemented, gated; the two-axis review runs after this document and its outcome is recorded in the step
  record in `.scratch/structure-status.json`
- **Governing plan**: `docs/code-structure-optimization-execution-plan-reviewed-20260922.md` (§3.2 matrix, §7.1 algorithm)
- **Decision it executes**: `docs/p33ef-giants-decision-20260922.md` §3 item 2

## 1. Why, and which of the two offered routes the measurement selected

P3.3e (`_derive_investigation_observations`, 2,795 lines) needs seven names from `simulation_adapters.py`, and plan
section 3.2 does not let `investigation/` import that module: it is an **implementation** module (it owns the qiling
adapter, the isolated runner and the builtin adapter table), so the edge is unlisted and therefore forbidden by default.
Item 2 offered two routes - "expose the 7 as an allowed emulation interface" or "sink the pure policy functions" - and
this is what decided between them.

MEASURED with `.scratch/layer2-closure.py`, expanding each of the seven through the module's own definitions:

| name | closure | reaches implementation? |
| --- | --- | --- |
| `default_simulation_runner` | 8 | **yes** - `BUILTIN_ADAPTERS`, `IsolatedSimulationRunner`, `_qiling_adapter` |
| `qiling_unavailable_observation` | 6 | **yes** - `_qiling_adapter` |
| `evidence_nature_for_simulation_status` | 3 | no |
| `may_execute_in_process` | 5 | no |
| `request_for_granted_window` | 4 | no |
| `simulation_policy_from_settings` | 6 | no |
| `worker_defers_simulation` | 4 | no |

So exposing all seven as an "interface" would have been a pass-through that leaves the implementation edge in place
transitively - the shape the plan's deletion test exists to reject. Instead the **five clean names and their 12-name
closure** moved into a pure module, and the two that reach implementation stayed behind. That also sharpens what blocks
P3.3e (§5).

## 2. What moved (measured)

- `emulation/policy.py`: **NEW, 311 lines** - 12 module-level names: the five policy functions, the types they mention
  (`SimulationRequest` 30 lines, `SimulationExecutionPolicy` 58), `resolve_qiling_rootfs` (8) and four constants
  (`CERTIFIED_PROFILES`, `PINNED_QILING_ROOTFS`, `_POLICY_OR_PLACEHOLDER_STATUSES`, `_NON_WORKER_STOP_REASONS`).
- `simulation_adapters.py`: **2088 → 1824 lines** (264 lines out; the twelve re-exports and their comment in).
- Every moved item is **byte-identical** to its pre-move text, comment block and decorators included.
- Production callers migrated per §7.1 step 5 by an AST script: `service.py` (5 moved, 3 kept) and
  `tools/tool_execution.py` (2 moved, 3 kept); test callers followed (`test_simulation_policy`,
  `test_in_process_execution_rule`, `test_controlled_emulation`, `test_t4_isolation_matrix`). **The first version of that
  migration listed `src/` and `tests/` BY HAND and MISSED `scripts/`, so `scripts/structure_behavior_probe.py` kept
  importing a moved name from the implementation module while this document asserted no such import existed** - the
  Standards review caught it, and the claim was false when written. The migration now discovers its targets by TREE, and
  `.scratch/layer2-sweep.py` re-checks src+tests+scripts (plus `.scratch` with `--all`): as of this step, 360 files
  scanned, no tracked module imports a moved name from the implementation module. The two further test files the sweep
  found (`tests/test_investigation.py`, `tests/test_unique_thread_emulation.py`) were migrated in the same pass.
- **Declared explicitly, because the ruling named only the dataclasses**: the cluster is 12 names, and the four
  constants it travels with - `CERTIFIED_PROFILES`, `PINNED_QILING_ROOTFS`, `_POLICY_OR_PLACEHOLDER_STATUSES`,
  `_NON_WORKER_STOP_REASONS` - are the *transitive closure* of the five functions, computed by
  `.scratch/layer2-closure.py` rather than chosen. They had to travel: `simulation_policy_from_settings` reads the first
  two and `evidence_nature_for_simulation_status` classifies by the other two, so leaving them behind would have made the
  seam either incomplete or a second copy of the classification rule.
- The seam's **module-level** imports are stdlib only (`hashlib`, `dataclasses`, `pathlib`, `typing`), which is what
  makes importing it free of the implementation. One moved BODY imports a sibling lazily
  (`emulation.emulation_plan`, inside `request_for_granted_window`); that import travels verbatim, targets a module made
  of facts/static - both allowed layers for `investigation/` - and is pinned as NOT being the implementation module.
- **Two private names cross the boundary in each direction**, recorded rather than hidden: `simulation_adapters`
  imports `_NON_WORKER_STOP_REASONS` / `_POLICY_OR_PLACEHOLDER_STATUSES` from the seam (it uses them), and a moved body
  imports `emulation_plan._as_int_address`. Both existed before the move in some form (the second unchanged), and
  neither is covered by the structure rules, which gate `getsource`/`getattr` only.

## 3. Three tool defects the move's own guards found (the narrow-instrument family, again)

1. **The free-name scan ignored function-local imports.** It reported `_as_int_address` as unresolvable, when
   `request_for_granted_window` imports it *inside its own body* (`from ...emulation_plan import _as_int_address`) and
   that statement travels with the body. The scan now counts `Import`/`ImportFrom` inside a body as bindings - and,
   because such an import is invisible to the import-graph gate, the mover additionally **resolves every in-body import
   module** so a move cannot carry an import that only worked from the old location. This is the fourth instrument in
   this phase whose scan was too narrow in a way that produced a confident wrong answer.
2. **The import-block assembly mangled a plain `import`**: `import hashlib` was fed through the `from … import …` string
   surgery and came out as `import import hashlib`. Plain imports and `from` imports are now assembled structurally.
3. **The re-export was inserted at the first textual match of an import anchor**, which in this module is an *indented*
   import inside `request_for_granted_window` - producing an `IndentationError` inside a `try:` block. The insertion
   point is now found through the AST (after the last **top-level** import).

## 4. Verification performed

1. **Byte identity**: all 12 items are byte-identical to `HEAD:src/threat_report_agent/simulation_adapters.py`
   (`.scratch/layer2-verify.py` property 1).
2. **One object through both paths**: `emulation.policy.<name> is simulation_adapters.<name>` for all twelve.
3. **One implementation**: every definition of the twelve lives in `emulation/policy.py`; the implementation module
   defines none of them again.
4. **The moved policy still RUNS** (a fresh interpreter): a policy builds from settings;
   `worker_defers_simulation` → False and `may_execute_in_process` → True for a test-environment policy;
   `evidence_nature_for_simulation_status("SUCCEEDED")` → `EMULATION_OBSERVED` while `("DEFERRED_TO_WORKER")` →
   `STATIC_INFERRED` - i.e. the classifier still separates a real observation from a deferral.
5. **Can-fail proof, three tampers** (`.scratch/layer2-canfail.py`): a changed body symbol, a dropped re-export, and a
   second definition each fail the matching property; all files restored byte-for-byte with hash verification.
6. **A new product-suite pin** in `tests/test_simulation_policy.py`: the seam is pure at module level, importing it
   drags in no `simulation_adapters`, the twelve names are one object behind both paths, and the implementation module
   does not define the two types again. Its first version failed for the right reason (it scanned ALL imports including
   the lazy in-body one) and the assertion was corrected to the property that actually matters, with the lazy import
   recorded rather than papered over.
7. **Lint**: `.scratch/ruff-set-diff.py` shows the implementation module's error SET is unchanged (`F821 Any`, ×3 -
   pre-existing) and the new module is clean; no error was created.
8. **Gates**: import graph PASS - **111 modules** (one more: the new module), 218 runtime same-package edges, cycles 0,
   the known `persist_how -> reporting` reverse edge unchanged; structure diff PASS; behaviour probe UNCHANGED.
9. **Focused battery**: 104 passed, 1 skipped.
10. Full suite, rebuild and the deployment gate: recorded in the step record.

## 5. Does this unblock P3.3e? Partly - and the remainder is now measured precisely

The giant method references the seven names **only in its final ~130 lines** (6648-6780), nine references total, and
`_run_investigation_loop` (P3.3f) references **none** of them. Of those nine, the ones that sank now come from the pure
seam. What is left is the block that **executes** a simulation:

- `default_simulation_runner(policy, execute_in_process=…)` (line 6725) builds the isolated runner, and
  `runner.run(request_for_granted_window(policy, window))` (6756) **runs** it in-process - that is adapter work, and
  the runner's closure reaches the qiling adapter and the builtin adapter table;
- `qiling_unavailable_observation(policy)` (6769) needs the qiling adapter to decide what to report.

So the honest statement of item 2's result is: **the POLICY half of P3.3e's blocker is gone, and the remaining blocker is
a single- responsibility question - who runs the simulation** - which the plan already answers with a declared seam:
`ports.EmulationPort` (P1.2), whose note today says it has "no producer yet". The next step for P3.3e is therefore to
route that execution through the emulation port (or a host method), not to move more policy.

## 6. Not done, recorded

- The two implementation-coupled names stay in `simulation_adapters.py` by design; they are not re-exported through the
  seam, because a seam that forwards implementation is what the deletion test rejects.
- Nothing in `emulation/` was renamed or re-packaged: `policy.py` is a new sibling of `emulation_plan.py` and
  `controlled_emulation.py`, whose own docstrings and imports were left untouched.
- The `_as_int_address` private name crosses from `emulation_plan` into a body of the policy seam by a function-local
  import. That is pre-existing (it was the same edge before the move) and is recorded here rather than "cleaned up" in a
  structural step; the mover's new resolver proves the import still works from the new home.

## 7. The two-axis review: findings and dispositions

Both axes ran as independent subagents against the last verified code commit `a11c2c7`. **Neither found the move itself
wrong** - both independently confirmed all 12 items byte-identical, one definition per name, the re-export complete and
faithful, the seam's module-level imports stdlib-only, and the pre-existing `F821 Any` not introduced here. What they
found was in the step's *reach* and its *records*, and every finding is fixed:

| finding | disposition |
| --- | --- |
| **The caller migration missed `scripts/`** and this document asserted the opposite | **Accepted and fixed**: the migration now discovers targets by tree, a sweep over all three tracked trees is green (360 files), and the two further test files it found were migrated. The false sentence is replaced by the account of how it was wrong (§2). |
| Stale module citation in `ports.py` (and in the status doc's current-state text) | **Accepted and fixed**: `ports.py` now cites `emulation.policy` with the move recorded, and the status file's current-state field was corrected - while the **30 historical occurrences** in superseded objects and step records were deliberately restored to the original wording, because at that time the old location WAS correct (§8 of this step's record). |
| The re-export block had no blank line before the next definition (E302), invisible because the repo's ruff selects only E4/E7/E9/F | **Accepted and fixed**, and the gate blind spot recorded: "no error was created" was true only by omission. |
| `emulation/__init__.py` still described the package as holding only moved implementations | **Accepted and fixed**: the docstring now describes the pure seam, why it was sunk rather than moved whole, and re-states the qiling-path refusal that keeps the rest of the module in place. |
| The pin identity-checked 10 of 12 names | **Accepted and fixed**: all 12, including the two private constants. |
| "Scope creep": 12 names moved where the ruling named the dataclasses | **Accepted as a recording gap and fixed**: the four constants are the measured transitive closure, now declared in §2 with what each is read by, rather than left implicit. |
| The design doc "did not exist" at review time | **Refuted by timing, and recorded as such**: the Spec axis read the tree while the document was still being written (its prompt said so); the document exists in the same commit as the code. A review's stale claim is recorded too, not quietly dropped. |
| P3.3e is still blocked | **Upheld, independently**: both axes reached this conclusion from the code, and it is what §5 says. The Spec axis names the same two names (`default_simulation_runner`, `qiling_unavailable_observation`) and the same route (an emulation port / runner seam), which is now the recorded next step rather than a guess. |
