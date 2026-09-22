# 结构优化执行状态（方案 `code-structure-optimization-execution-plan-reviewed-20260922.md`）

> 本文件由 `.scratch/structure-status.json` **程序化生成**（round 70）。`.scratch/` 被 gitignore，
> 因此把最终状态在此留一份被跟踪的记录。逐步骤的完整字段（allowed_files / commands / focused_result /
> full_result / new_failures / import_graph / module_identity / deployment_smoke / behavior_probe_diff /
> rollback_point / decision）在 `step_records`，共 19 条，本文件只汇总。

- HEAD：`01f93c43eef4eaad8bee45b1c6b3a0a14928a1d3`（与 `origin/main` 同步）
- **structure_status：`IN_PROGRESS`**
- **capability_status：`UNVERIFIED`**

## 一、为什么不是 READY / ACCEPTED

Plan section P5 grants `structure_status=READY` only after P2-P4 are complete. Phase 0 and Phase 1 are complete, Phase 2 has ONE package partly done (report/), and Phases 3-5 have not started. The deployed images DO equal the tree, which is P5.1's mechanical condition, but the plan's own wording makes that necessary and not sufficient.

`capability_status` is a different axis: the Ghidra B3/C3 capability items (T4 route B2, T8, T3, T6, T7, the diagnostic channel, undeclared truncation) were not touched by this plan's execution. `structure_status=READY` must never imply `capability_status=ACCEPTED`.

## 二、阶段状态

| 阶段 | 状态 |
|---|---|
| phase_0 | COMPLETE (P0.1-P0.6, plus repairs P0.3-r2/r3 and P0.5-r2/r3) |
| phase_1 | COMPLETE (P1.1-P1.4, plus repairs P1.1-r2 and P1.3-r3) |
| phase_2 | IN PROGRESS - report/ has 3 of 4 modules moved; P2-M/T/I/S/E/V/K not started |
| phase_3 | NOT STARTED (split AnalysisService) |
| phase_4 | NOT STARTED (remove shims) |
| phase_5 | NOT STARTED (re-verification; the DSH suite has never been run in this session) |

## 三、机械条件（P5.1）

81 files x 8 services, missing=0 differing=0 container-only=0, and the import smoke exercises 4 modules in every container

四道门禁在 HEAD 上全部通过：结构 diff、导入图 `--strict`、行为探针（含 item 8「移动模块同一性」）、
部署 `--strict --import-smoke`。全量 pytest 的失败**节点集合**与 P0.2 基线一致。

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
- P2-F
- P2-R.1
- P2-R.2-5
- P2-R.small-modules

## 五、审计历史

- round 64/65: P0.3-P1.1 instrument audit -> 3 critical findings, all repaired with can-fail proofs
- round 66: three-axis audit of P1.3/P1.4 (standards, spec, adversarial) -> 6 confirmed escapes, all closed; the standards axis found the gate could not pass on a clean checkout, verified fixed in a clean worktree
- round 69: adversarial audit of the report move -> move trustworthy, enforcement not; 5 findings fixed, 2 recorded

## 六、后继者必须先做的事

1. decide the two plan conflicts: (a) `static/` collides with the existing asset directory and `pyproject.toml`'s package-data lists `static/*` for the root package, so adding an `__init__.py` changes published artefacts; (b) `investigation/` and `intake/` would shadow same-named modules (measured: 145 ImportErrors)
2. finish P2-R (move reporting.py; retire the tests-only `document_to_markdown` exit, measured at 9 test files / 78 references, which is a test-surface behaviour change and must be its own step)
3. then P2-M, P2-T, P2-I, P2-S, P2-E, P2-V, P2-K, each through the 9-step algorithm in plan 7.1
4. then P3-P5, and run the DSH suite separately - pytest passing must not be used to offset it

## 七、已记录、但**不得**在结构步骤里修的行为缺陷

- the compose gate accepts a draft that keeps the operational-limitation HEADING and drops every bullet (analyst_report.py:6123 is a heading substring test) - recorded in the P0.5 probe and pinned by a test
- `is_real_simulation_row` returns True for DISABLED_BY_POLICY and NO_GRANTED_WINDOW while `simulation_adapters._POLICY_OR_PLACEHOLDER_STATUSES` treats both as non-observed
- `_mechanism_catalog_id` is called with a Mapping at two sites while the live definition takes a scalar, so the 'recovered' branch of `_topic_status` can never fire and mechanism labels lose the catalog title

## 八、方案级冲突（等用户决定，阻塞对应阶段）

- **static-name-collision**（blocks P2-S）：src/threat_report_agent/static/ ALREADY EXISTS as a served-asset directory (app.js, index.html, styles.css) and has no __init__.py. Plan section 3.1 lists static/ as the package for static recovery and section 7.7 puts static_analysis.py, literal_table.py, ghidra_adapter.py and others there. A package directory cannot be adopted at a path that already holds served assets without either moving the assets or renaming the package. Additionally pyproject.toml packages.find has no excludes, so an __init__.py added there would newly publish the asset directory as a Python package.
- **investigation-and-intake-self-shadow**（blocks P2-V and P2-I）：Plan sections 7.6 and 7.9 put intake.py inside intake/ and investigation.py inside investigation/. A package SHADOWS a same-named module, so `from threat_report_agent.investigation import f` would resolve to the package and lose the module's exports. MEASURED: an earlier attempt produced 145 ImportErrors (144 investigation, 1 intake), each naming the new __init__.py. CPython probes __init__ before the file suffix.
