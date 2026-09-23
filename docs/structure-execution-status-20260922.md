# 结构优化执行状态（方案 `code-structure-optimization-execution-plan-reviewed-20260922.md`）

> 本文件由 `.scratch/structure-status.json` **程序化生成**（`.scratch/render-structure-status.py`）。`.scratch/` 被 gitignore，因此把最终状态在此留一份被跟踪的记录。逐步骤的完整字段（allowed_files / commands / focused_result / full_result / new_failures / import_graph / module_identity / deployment_smoke / behavior_probe_diff / rollback_point / decision）在 `step_records`，共 53 条，本文件只汇总。

- 本文档描述的树经核验于 HEAD `93d2dbe8374785695ab6fee01b67e417dd89a3ff`（本轮改动在该提交之上，与本文件一并提交）
- **structure_status：`IN_PROGRESS`**
- **capability_status：`UNVERIFIED`**

## 一、为什么不是 READY / ACCEPTED

Plan section P5 grants `structure_status=READY` only after P2-P4 are complete. Phase 0, Phase 1 and Phase 2 are COMPLETE (nine packages, 34 moved paths, report/ finished, all seven investigation siblings moved, all three task modules moved, duplicate list empty, cycle allowlist empty). PHASE 3 IS IN PROGRESS: P3.1 (facade contract stated and pinned), P3.2-design (the `TaskHost` port declared with its contract test), P3.2a/P3.2b (the failure/limitation projection seam extracted) P3.2c (the `creation` cluster moved behind the port - `create_submission_task`, `prepare_blind_run` and the `SubmissionResult` dataclass) P3.2d (the `lifecycle` cluster - `archive_case`) P3.2e (the `budget` cluster - `_deferred_budget_thread_ids` and `_actual_depth`, the latter a static method that needed no host at all) P3.2f (the `cancellation` cluster - `cancel_task` and `cancel_tool_run`) and P3.2g (the workbench-binding cluster, which deliberately WIDENED the port from 6 to 9 members - the only widening in P3.2) are COMPLETE, so **P3.2 IS COMPLETE**: service.py 29,640 lines at the Phase-3 start -> 28,898, with every moved cluster a one-statement delegation, leaving one-statement delegations in service.py. P3.3 has been MEASURED and its boundary DECIDED (`docs/p33-investigation-coordinator-design-20260922.md`): the plan's one-line scope is actually 53 candidate members / 8,881 lines behind a 20-member spine, with two methods at 71% of it, so it is split into six slices and 495 lines are excluded to P3.4/P3.6 by name. NO P3.3 SLICE HAS MOVED YET. Also NOT STARTED: P3.4 (ReportRevisionWriter), P3.5 (EmulationCoordinator), P3.6 (WorkbenchQueryReader), P3.7 (test surface off private/`getsource`), and Phases 4 and 5, P3.3 (InvestigationCoordinator), P3.4 (ReportRevisionWriter), P3.5 (EmulationCoordinator), P3.6 (WorkbenchQueryReader), P3.7 (test surface off private/`getsource`), and Phases 4 and 5. The deployed images DO equal the tree - 121 files x 8 services, missing=0 differing=0 container-only=0, with 49 enumerated smoke imports per container - which satisfies P5.1's mechanical condition, but the plan's own wording makes that necessary and not sufficient. See `docs/p32-task-runner-design-20260922.md` for the measured P3.2 scale, the port and the per-cluster order.

`capability_status` is a different axis: the Ghidra B3/C3 capability items (T4 route B2, T8, T3, T6, T7, the diagnostic channel, undeclared truncation) were not touched by this plan's execution. `structure_status=READY` must never imply `capability_status=ACCEPTED`.

## 二、阶段状态

| 阶段 | 状态 |
|---|---|
| phase_0 | COMPLETE (P0.1-P0.6, plus repairs P0.3-r2/r3 and P0.5-r2/r3) |
| phase_1 | COMPLETE (P1.1-P1.4, plus repairs P1.1-r2 and P1.3-r3) |
| phase_2 | COMPLETE - 9 packages, 34 moved paths, report/ complete, 7 investigation siblings moved, 3 task modules moved, duplicate list empty, cycle allowlist empty |
| phase_3 | IN PROGRESS - P3.1 and P3.2 are COMPLETE (port `TaskHost` with 9 members, all used; eleven functions moved; service.py 29,640 -> 28,898 lines). P3.3 is DESIGNED and MEASURED but nothing has moved: the surface is 53 candidates / 8,881 lines, split into six slices (ledger 156, frontier/thread 409, action proposal 327, methodology+convergence 514, observations 2,795, the loop 3,523) with 495 lines excluded to P3.4/P3.6. Remaining: P3.3a-P3.3f, P3.4, P3.5, P3.6, P3.7. |
| phase_4 | NOT STARTED (remove shims, one checkpoint each, then converge the root package's exports) |
| phase_5 | NOT STARTED (re-verification; the DSH suite has never been run in this session) |

## 三、机械条件（P5.1）

121 files x 8 services, missing=0 differing=0 container-only=0, and the import smoke imports 49 enumerated modules in every container (48 before P3.2c added `task/task_runner.py`, 47 before P3.2a), with all 11 containers running

四道门禁在 HEAD 上全部通过：结构 diff、导入图 `--strict`、行为探针（含 item 8「移动模块同一性」）、部署 `--strict --import-smoke`。全量 pytest 的失败**节点集合**与 P0.2 基线一致。

## 四、已完成的步骤

- DECISIONS-a-b-c
- P0.1
- P0.2
- P0.3
- P0.3-r3
- P0.4
- P0.5
- P0.5-r3
- P0.6
- P1.1
- P1.2
- P1.3
- P1.3-r3
- P1.4
- P2-E
- P2-F
- P2-I
- P2-M
- P2-R.1
- P2-R.2-5
- P2-R.5
- P2-R.reporting
- P2-R.small-modules
- P2-S.1
- P2-S.2-5
- P2-S.6-8
- P2-T
- P2-T.0
- P2-TK
- P2-V
- P2-V.0
- P2-V.1
- P2-V.2
- P2-V.3
- P2-V.4
- P2-V.5
- P2-V.6
- P2-V.7
- P2-V.8
- P3.1
- P3.2a
- P3.2b
- P3.7-audit
- P3.2-design
- P3.2c
- P3.2d
- P3.2e
- P3.2f
- P3.2g
- P3.2 (complete)
- P3.3-design

## 五、审计历史

- round 64/65: P0.3-P1.1 instrument audit -> 3 critical findings, all repaired with can-fail proofs
- round 66: three-axis audit of P1.3/P1.4 (standards, spec, adversarial) -> 6 confirmed escapes, all closed; the standards axis found the gate could not pass on a clean checkout, verified fixed in a clean worktree
- round 69: adversarial audit of the report move -> move trustworthy, enforcement not; 5 findings fixed, 2 recorded
- Round 97, P3.2-design + P3.2c - denial-stance self-review inside the `improve-codebase-architecture` framework (`.scratch/p32design-adversarial-review.md`, `.scratch/p32c-adversarial-review.md`): 12 charges raised across the two steps, 0 retracted, 0 conclusions withdrawn. Two findings were new FACTS rather than restatements and both were recorded: the design step's port was a HYPOTHETICAL SEAM until P3.2c gave it a production adapter, and moving a PUBLIC dataclass changed `SubmissionResult.__module__` (measured blast radius: no pickling, no repr or module assertions, `is`-identity preserved through the re-export). The review's own process lesson - a PowerShell `Set-Content` without `-Encoding utf8` corrupted a can-fail tamper into a UnicodeDecodeError - is recorded with the step.

## 六、后继者必须先做的事

1. Read `docs/code-structure-optimization-execution-plan-reviewed-20260922.md`, `docs/p32-task-runner-design-20260922.md` and `tests/test_task_runner_contract.py` before touching P3.2 again: the port, the measured cluster order and the verification recipe are recorded there.
2. Read `docs/p33-investigation-coordinator-design-20260922.md` BEFORE touching P3.3: it records the measured surface, the boundary decision (which members belong to P3.4/P3.6 and must NOT be swallowed), the per-slice port needs, and the 15 unassigned members / 660 lines that must not be left unclaimed.
3. Start with a slice that needs NO port widening - P3.3b (frontier/thread, 8 members / 409 lines) or P3.3c (action proposal, 9 / 327), both with `database` as their only host need - by creating `src/threat_report_agent/investigation/coordinator.py` with an `InvestigationHost` Protocol, the two-sided contract test, and the P3.2 recipe (measure -> extract -> verify against the pre-move revision -> PROVE THE CAN-FAIL -> battery -> rebuild -> deployment gate). Leave the two giant methods (P3.3e, P3.3f) for last.
4. Keep re-running `.scratch/p32-verify-cluster.py --from <pre-move revision>` and the can-fail proof whenever the verifier's normalisation changes: in P3.2g a verifier change made every earlier cluster's digest differ, and the only way to show the change did not weaken the check was to re-verify all eleven bodies against their own pre-move commits.
5. Use the same recipe per cluster: extract with the generator, prove file identity with `.scratch/p32c-verify-bodies.py` (statements unparsed, receiver normalised away), PROVE THE VERIFIER CAN FAIL before trusting it, run the focused battery plus `tests/test_service_facade_contract.py` and `tests/test_task_runner_contract.py`, then rebuild and pass the deployment gate, then compare the full suite's failure NODE SET (never the count alone).
6. WRITING THE STATUS RECORD HAS A TRAP that was measured in round 97: `render-structure-status.py` selects the newest `final_state_*` object that carries `why_not_READY`, so a new round object without that key is skipped and the tracked document silently keeps the PREVIOUS round's prose (it described 120 files / 48 smoke modules while the tree had 121/49). Give the new object the full field set, then run `py .scratch/render-structure-status.py` and `--check`.
7. `structure_status=READY` must never imply `capability_status=ACCEPTED`: the Ghidra B3/C3 capability items (T4 route B2, T8, T3, T6, T7, the diagnostic channel, undeclared truncation) are untouched by this plan.

## 七、已记录、但**不得**在结构步骤里修的行为缺陷

- the compose gate accepts a draft that keeps the operational-limitation HEADING and drops every bullet (analyst_report.py:6123 is a heading substring test) - recorded in the P0.5 probe and pinned by a test
- `is_real_simulation_row` returns True for DISABLED_BY_POLICY and NO_GRANTED_WINDOW while `simulation_adapters._POLICY_OR_PLACEHOLDER_STATUSES` treats both as non-observed
- `_mechanism_catalog_id` is called with a Mapping at two sites while the live definition takes a scalar, so the 'recovered' branch of `_topic_status` can never fire and mechanism labels lose the catalog title
- LINE-ENDING DRIFT (MEASURED in round 79/80, pre-existing and repo-wide): `core.autocrlf=true` with no `.gitattributes`, so `git ls-files --eol src` reports 74 tracked files `i/lf w/lf` and 23 `i/lf w/crlf`. A fresh checkout materialises the first group as CRLF, therefore git status is BLIND to line-ending differences between the worktree and HEAD, and `scripts/check-deployed-code-hashes.py`'s clean-tree note ("src/ clean, so the tree IS HEAD") is not byte-true; plan 5.1's condition is byte-oriented. The gate's EVIDENCE stays valid because `host_hashes()` reads the working tree and the images are built from that same tree, but a byte-exact HEAD comparison does not exist today. Fixing it rewrites ~74 files and needs a rebuild plus re-verification, so it is a work item of its own - measured, not silently normalised inside a structural step. RE-MEASURED in round 97: `git ls-files --eol src` now reports 101 files `i/lf w/lf`, 19 `i/lf w/crlf` and 1 `i/none w/none` (121 tracked src files in total, matching the deployment gate's file count), because the tree has grown by package `__init__`/facade files since round 79/80. The defect is unchanged in kind: the gate reads the WORKING TREE, so its evidence stays valid, but a byte-exact HEAD comparison still does not exist.

## 八、方案级冲突（及其裁决）

- **static-name-collision**（blocked P2-S）：**RESOLVED (round 71, commit 65b86ac)** — The ASSET directory was renamed `static/` -> `assets/` and the mount URL was kept as `/static`, so every browser-visible URL is unchanged. The package name the plan wants is left free.
- **investigation-and-intake-self-shadow**（blocked P2-V and P2-I）：**RESOLVED AND IMPLEMENTED (P2-I for intake, P2-V.0 + P2-V for investigation)** — A module -> package move needs a LAZY facade (PEP 562 `__getattr__`) - implemented ONCE as the shared mechanism in `src/threat_report_agent/package_facade.py` - and `investigation` additionally needed one shared predicate group moved down into `facts/thread_start.py` first. Both halves are now in the tree and verified on the DEPLOYED images, not only in the copy simulation that chose the recipe.
