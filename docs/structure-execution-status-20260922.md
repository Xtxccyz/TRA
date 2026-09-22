# 结构优化执行状态（方案 `code-structure-optimization-execution-plan-reviewed-20260922.md`）

> 本文件由 `.scratch/structure-status.json` **程序化生成**（`.scratch/render-structure-status.py`）。`.scratch/` 被 gitignore，因此把最终状态在此留一份被跟踪的记录。逐步骤的完整字段（allowed_files / commands / focused_result / full_result / new_failures / import_graph / module_identity / deployment_smoke / behavior_probe_diff / rollback_point / decision）在 `step_records`，共 41 条，本文件只汇总。

- 本文档描述的树经核验于 HEAD `b75f188b20c1efc3d24a6812cf0a1cf076d05eaa`（本轮改动在该提交之上，与本文件一并提交）
- **structure_status：`IN_PROGRESS`**
- **capability_status：`UNVERIFIED`**

## 一、为什么不是 READY / ACCEPTED

Plan section P5 grants `structure_status=READY` only after P2-P4 are complete. PHASE 2 IS NOW COMPLETE: nine packages are in place (facts, report, model, tools, intake, static, emulation, investigation, task) with 34 moved paths; report/ is complete including plan 7.3 step 5; plan 7.9's seven investigation siblings are all moved; plan 7.10's three task modules are moved; the ONE recorded duplicate implementation is resolved; BOTH recorded import cycles are retired with an empty allowlist; and one of the two recorded legacy-path imports is gone. PHASES 3, 4 AND 5 HAVE NOT STARTED - splitting `AnalysisService` (P3.1-P3.7) is the next work and it is the high-risk phase, then removing the shims (P4.1-P4.4) and the final re-verification including the DSH suite (P5.1-P5.5). The deployed images DO equal the tree - 119 files x 8 services, missing=0 differing=0 container-only=0, with 47 enumerated smoke imports per container - which satisfies P5.1's mechanical condition, but the plan's own wording makes that necessary and not sufficient.

`capability_status` is a different axis: the Ghidra B3/C3 capability items (T4 route B2, T8, T3, T6, T7, the diagnostic channel, undeclared truncation) were not touched by this plan's execution. `structure_status=READY` must never imply `capability_status=ACCEPTED`.

## 二、阶段状态

| 阶段 | 状态 |
|---|---|
| phase_0 | COMPLETE (P0.1-P0.6, plus repairs P0.3-r2/r3 and P0.5-r2/r3) |
| phase_1 | COMPLETE (P1.1-P1.4, plus repairs P1.1-r2 and P1.3-r3) |
| phase_2 | COMPLETE - 9 packages, 34 moved paths, report/ complete, 7 investigation siblings moved, 3 task modules moved, duplicate list empty, cycle allowlist empty |
| phase_3 | NOT STARTED (split AnalysisService: P3.1 facade contract, P3.2 TaskRunner, P3.3 InvestigationCoordinator, P3.4 ReportRevisionWriter, P3.5 EmulationCoordinator, P3.6 WorkbenchQueryReader, P3.7 move the test surface off private/`getsource` onto behaviour) |
| phase_4 | NOT STARTED (remove shims, one checkpoint each, then converge the root package's exports) |
| phase_5 | NOT STARTED (re-verification; the DSH suite has never been run in this session) |

## 三、机械条件（P5.1）

119 files x 8 services, missing=0 differing=0 container-only=0, and the import smoke imports 47 enumerated modules in every container (43 before P2-TK), with all 11 containers running

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

## 五、审计历史

- round 64/65: P0.3-P1.1 instrument audit -> 3 critical findings, all repaired with can-fail proofs
- round 66: three-axis audit of P1.3/P1.4 (standards, spec, adversarial) -> 6 confirmed escapes, all closed; the standards axis found the gate could not pass on a clean checkout, verified fixed in a clean worktree
- round 69: adversarial audit of the report move -> move trustworthy, enforcement not; 5 findings fixed, 2 recorded

## 六、后继者必须先做的事

1. PHASE 2 IS COMPLETE and nothing is blocked on the user. Three recorded items await DECISIONS rather than work: (a) the `facts -> investigation` edge created by P2-V.8 (either forbid it and move the pure helper down into `facts/`, or accept it); (b) `tool_authoring` has no production importer; (c) `turn_lifecycle` has no production importer. Each is frozen by a test so it fails loudly rather than drifting.
2. next: PHASE 3, starting with P3.1 - define the facade's PUBLIC contract before splitting anything, per plan section 8. `AnalysisService` is ~29,000 lines with a live HTTP path; plan 8's principle is 'split by responsibility and seam, not by line count', and P3.2-P3.6 each end with `AnalysisService` still constructible by the existing HTTP path.
3. then P4 (delete the shims one checkpoint at a time) and P5 (re-verification: the images must equal HEAD, the DSH suite must be run SEPARATELY, and `structure_status` / `capability_status` must stay separate axes).
4. the `service.py` old-path `dataflow` import is the last recorded `legacy_path_imports` entry; it belongs to whichever step touches `service.py` deliberately, not to a move step.

## 七、已记录、但**不得**在结构步骤里修的行为缺陷

- the compose gate accepts a draft that keeps the operational-limitation HEADING and drops every bullet (analyst_report.py:6123 is a heading substring test) - recorded in the P0.5 probe and pinned by a test
- `is_real_simulation_row` returns True for DISABLED_BY_POLICY and NO_GRANTED_WINDOW while `simulation_adapters._POLICY_OR_PLACEHOLDER_STATUSES` treats both as non-observed
- `_mechanism_catalog_id` is called with a Mapping at two sites while the live definition takes a scalar, so the 'recovered' branch of `_topic_status` can never fire and mechanism labels lose the catalog title
- LINE-ENDING DRIFT (MEASURED in round 79/80, pre-existing and repo-wide): `core.autocrlf=true` with no `.gitattributes`, so `git ls-files --eol src` reports 74 tracked files `i/lf w/lf` and 23 `i/lf w/crlf`. A fresh checkout materialises the first group as CRLF, therefore git status is BLIND to line-ending differences between the worktree and HEAD, and `scripts/check-deployed-code-hashes.py`'s clean-tree note ("src/ clean, so the tree IS HEAD") is not byte-true; plan 5.1's condition is byte-oriented. The gate's EVIDENCE stays valid because `host_hashes()` reads the working tree and the images are built from that same tree, but a byte-exact HEAD comparison does not exist today. Fixing it rewrites ~74 files and needs a rebuild plus re-verification, so it is a work item of its own - measured, not silently normalised inside a structural step.

## 八、方案级冲突（及其裁决）

- **static-name-collision**（blocked P2-S）：**RESOLVED (round 71, commit 65b86ac)** — The ASSET directory was renamed `static/` -> `assets/` and the mount URL was kept as `/static`, so every browser-visible URL is unchanged. The package name the plan wants is left free.
- **investigation-and-intake-self-shadow**（blocked P2-V and P2-I）：**RESOLVED AND IMPLEMENTED (P2-I for intake, P2-V.0 + P2-V for investigation)** — A module -> package move needs a LAZY facade (PEP 562 `__getattr__`) - implemented ONCE as the shared mechanism in `src/threat_report_agent/package_facade.py` - and `investigation` additionally needed one shared predicate group moved down into `facts/thread_start.py` first. Both halves are now in the tree and verified on the DEPLOYED images, not only in the copy simulation that chose the recipe.
