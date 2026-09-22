# 结构优化执行状态（方案 `code-structure-optimization-execution-plan-reviewed-20260922.md`）

> 本文件由 `.scratch/structure-status.json` **程序化生成**（`.scratch/render-structure-status.py`）。`.scratch/` 被 gitignore，因此把最终状态在此留一份被跟踪的记录。逐步骤的完整字段（allowed_files / commands / focused_result / full_result / new_failures / import_graph / module_identity / deployment_smoke / behavior_probe_diff / rollback_point / decision）在 `step_records`，共 37 条，本文件只汇总。

- 本文档描述的树经核验于 HEAD `431e187f27730baf8cd5a67fbcac69a44655da09`（本轮改动在该提交之上，与本文件一并提交）
- **structure_status：`IN_PROGRESS`**
- **capability_status：`UNVERIFIED`**

## 一、为什么不是 READY / ACCEPTED

Plan section P5 grants `structure_status=READY` only after P2-P4 are complete. Phase 0 and Phase 1 are complete. Phase 2 has EIGHT packages in place with 28 moved paths, report/ is COMPLETE, the ONE recorded duplicate implementation is resolved, four investigation siblings have moved, and BOTH recorded import cycles are retired with an empty allowlist. Phase 2 is still NOT complete: 3 investigation siblings remain (`persist_how.py`, `mechanism_ready.py`, `semantic_predicates.py`) and so does P2-TK (`task/`). Phases 3-5 have not started. The deployed images DO equal the tree - 112 files x 8 services, missing=0 differing=0 container-only=0, with 40 enumerated smoke imports per container - which satisfies P5.1's mechanical condition, but the plan's own wording makes that necessary and not sufficient.

`capability_status` is a different axis: the Ghidra B3/C3 capability items (T4 route B2, T8, T3, T6, T7, the diagnostic channel, undeclared truncation) were not touched by this plan's execution. `structure_status=READY` must never imply `capability_status=ACCEPTED`.

## 二、阶段状态

| 阶段 | 状态 |
|---|---|
| phase_0 | COMPLETE (P0.1-P0.6, plus repairs P0.3-r2/r3 and P0.5-r2/r3) |
| phase_1 | COMPLETE (P1.1-P1.4, plus repairs P1.1-r2 and P1.3-r3) |
| phase_2 | IN PROGRESS - 8 packages in place; report/ COMPLETE; duplicates NONE recorded and NONE measured; 4 of the 7 investigation siblings moved and 3 remain (`persist_how`, `mechanism_ready`, `semantic_predicates`); P2-TK task still to do |
| phase_3 | NOT STARTED (split AnalysisService) |
| phase_4 | NOT STARTED (remove shims) |
| phase_5 | NOT STARTED (re-verification; the DSH suite has never been run in this session) |

## 三、机械条件（P5.1）

112 files x 8 services, missing=0 differing=0 container-only=0, and the import smoke imports 40 enumerated modules in every container (39 before P2-V.5), with all 11 containers running

四道门禁在 HEAD 上全部通过：结构 diff、导入图 `--strict`、行为探针（含 item 8「移动模块同一性」）、部署 `--strict --import-smoke`。全量 pytest 的失败**节点集合**与 P0.2 基线一致。

## 四、已完成的步骤

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
- P2-V
- P2-V.0
- P2-V.1
- P2-V.2
- P2-V.3
- P2-V.4
- P2-V.5

## 五、审计历史

- round 64/65: P0.3-P1.1 instrument audit -> 3 critical findings, all repaired with can-fail proofs
- round 66: three-axis audit of P1.3/P1.4 (standards, spec, adversarial) -> 6 confirmed escapes, all closed; the standards axis found the gate could not pass on a clean checkout, verified fixed in a clean worktree
- round 69: adversarial audit of the report move -> move trustworthy, enforcement not; 5 findings fixed, 2 recorded

## 六、后继者必须先做的事

1. BOTH plan conflicts are RESOLVED and recorded, BOTH import cycles are retired with `known_cycles` EMPTY, the duplicate list is EMPTY, and P2-R is COMPLETE. Nothing is blocked on the user.
2. next: `mechanism_ready.py` is ALREADY MEASURED SAFE by the simulation run at P2-V.5 (it is not imported by the implementation, so it should not need the submodule-only shim - let the gate confirm). Then `persist_how.py`, the only sibling with package imports and the subject of the recorded `persist_how -> reporting` violation, and `semantic_predicates.py` LAST because `facts/dataflow.py` and `facts/thread_start.py` import it, so moving it creates upward edges that need their own analysis.
3. then P2-TK (`task/`)
4. DECIDE `tool_authoring`: it has no production importer today (only `tests/test_tool_authoring.py`).
5. then P3-P5, and run the DSH suite separately - pytest passing must not be used to offset it

## 七、已记录、但**不得**在结构步骤里修的行为缺陷

- the compose gate accepts a draft that keeps the operational-limitation HEADING and drops every bullet (analyst_report.py:6123 is a heading substring test) - recorded in the P0.5 probe and pinned by a test
- `is_real_simulation_row` returns True for DISABLED_BY_POLICY and NO_GRANTED_WINDOW while `simulation_adapters._POLICY_OR_PLACEHOLDER_STATUSES` treats both as non-observed
- `_mechanism_catalog_id` is called with a Mapping at two sites while the live definition takes a scalar, so the 'recovered' branch of `_topic_status` can never fire and mechanism labels lose the catalog title
- LINE-ENDING DRIFT (MEASURED in round 79/80, pre-existing and repo-wide): `core.autocrlf=true` with no `.gitattributes`, so `git ls-files --eol src` reports 74 tracked files `i/lf w/lf` and 23 `i/lf w/crlf`. A fresh checkout materialises the first group as CRLF, therefore git status is BLIND to line-ending differences between the worktree and HEAD, and `scripts/check-deployed-code-hashes.py`'s clean-tree note ("src/ clean, so the tree IS HEAD") is not byte-true; plan 5.1's condition is byte-oriented. The gate's EVIDENCE stays valid because `host_hashes()` reads the working tree and the images are built from that same tree, but a byte-exact HEAD comparison does not exist today. Fixing it rewrites ~74 files and needs a rebuild plus re-verification, so it is a work item of its own - measured, not silently normalised inside a structural step.

## 八、方案级冲突（及其裁决）

- **static-name-collision**（blocked P2-S）：**RESOLVED (round 71, commit 65b86ac)** — The ASSET directory was renamed `static/` -> `assets/` and the mount URL was kept as `/static`, so every browser-visible URL is unchanged. The package name the plan wants is left free.
- **investigation-and-intake-self-shadow**（blocked P2-V and P2-I）：**RESOLVED AND IMPLEMENTED (P2-I for intake, P2-V.0 + P2-V for investigation)** — A module -> package move needs a LAZY facade (PEP 562 `__getattr__`) - implemented ONCE as the shared mechanism in `src/threat_report_agent/package_facade.py` - and `investigation` additionally needed one shared predicate group moved down into `facts/thread_start.py` first. Both halves are now in the tree and verified on the DEPLOYED images, not only in the copy simulation that chose the recipe.
