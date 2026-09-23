# 结构优化执行状态（方案 `code-structure-optimization-execution-plan-reviewed-20260922.md`）

> 本文件由 `.scratch/structure-status.json` **程序化生成**（`.scratch/render-structure-status.py`）。`.scratch/` 被 gitignore，因此把最终状态在此留一份被跟踪的记录。逐步骤的完整字段（allowed_files / commands / focused_result / full_result / new_failures / import_graph / module_identity / deployment_smoke / behavior_probe_diff / rollback_point / decision）在 `step_records`，共 60 条，本文件只汇总。

- **被核验的树 = 提交 `ed363a564c8537bc714b82b0f804fa2c3f13f126`**（该提交的 tree 上跑过四道门禁与全量套件）
- `head_sha` 的语义：**`head_sha` 是被门禁核验的代码提交 `ed363a564c85`，不是「当前 HEAD」。** 四道门禁、focused 套件与全量套件都在它的 tree 上运行过。**本轮实测到的两处漂移正是这个字段造成的**：先前它记的是提交前的 HEAD，于是文档声称在一个不含本步改动的提交上完成核验；改成「当前 HEAD」后又发现，写下该值的提交本身就会移动 HEAD——**任何文件都无法正确写出「包含自己的那个提交」**。因此这里固定记代码提交，并在每次复验时核对 `src/` 与 `tests/` 是否仍与它一致（本轮实测：`git diff --name-only ed363a564c85..HEAD -- src tests` 为空，即逐字节相同）。每一步的回滚点是该步 `rollback_point` 记录的上一个提交。
- **structure_status：`IN_PROGRESS`**
- **capability_status：`UNVERIFIED`**

### 读取指引：本文件的哪一部分代表**当前**状态

- **权威内容＝`step_records` + 最新的 `final_state_*` 对象（当前是 `final_state_round_106_layer4`，由 `authoritative_final_state` 指定）。**
- 渲染器改写于 round 100：它过去按**字符串**排序挑最新对象，于是 `round_100` 排在 `round_97` **之前**，文档因此写着「还没有任何 P3.3 切片搬迁」而实际已搬两个。现在改为：显式指针 `authoritative_final_state` → （其次）`head_sha` 与被核验提交一致的对象 → （最后）**按数字**排序。
- 其余一切 `final_state_round_*` 都是**历史**（每个都带 `superseded_by` 指向最新对象）；它们的 `what_a_successor_must_do_first` 可能点名早已完成的工作，**不要照它执行**。
- 已经刷新为当前值的段落：`import_graph`、`deployment`、`worktree`（各自带 `measured_at_commit`）。
- **保留但属于历史**的段落（不删除，以免丢失 Phase 0/1 的证据链）：`p0_6_progress`、`ghidra_worker_blocker`（已标注 `_resolved`）、`behavior_probe`、`baseline`、`legacy_import_callers`、`phase_0`/`phase_1`/`phase_2` 的细节、`audit_findings_round_*`、`reverted_steps`。
- 结构状态与能力状态是两个轴：`structure_status` 反映本方案，`capability_status` 反映 Ghidra B3/C3 能力项；**结构 READY 不得推出能力 ACCEPTED**。

## 一、为什么不是 READY / ACCEPTED

Plan section P5 grants `structure_status=READY` only after P2-P4 are complete. Phases 0, 1 and 2 are COMPLETE (nine packages, 34 moved paths, all seven investigation siblings and all three task modules moved, duplicate list empty, cycle allowlist empty). PHASE 3 IS IN PROGRESS. P3.1 (facade contract) and the whole of P3.2 are COMPLETE (the `TaskHost` port has 9 members, all used, with eleven functions behind it). P3.3 is DESIGNED (53 candidates / 8,881 lines / 20-member spine, six slices, 495 lines excluded to P3.4/P3.6 by name) and SIX PIECES OF IT HAVE MOVED: four slices into `investigation/coordinator.py`, whose port is SIX members (`database`, `_audit`, `_MAX_COMPLETED_ACTION_EVIDENCE_IDS`, `_CONVERGENCE_ALTERNATES`, `_CONVERGENCE_EXPECTED_KINDS`, `_canonical_json`) - P3.3b, P3.3a, P3.3c and P3.3d - plus TWO LAYER ITEMS: item 1, the new module `investigation/loop_path.py` (16 names / 169 lines) which REMOVED the `investigation -> task` cycle, and item 4, which moved `DynamicPlanAction` (107 lines) into the pure contract module `contracts.py` so `investigation/` can import it. `service.py` is down from 29,640 lines at the Phase-3 start to 28,028. P3.3c(2)'s three members / 71 lines are now UNBLOCKED and are the next slice; the remaining giants are still layer-blocked: P3.3e (2,795 lines; 3,041 wholesale) needs the 7 `simulation_adapters` policy names exposed as an allowed emulation interface, and P3.3f (3,523 lines) needs ~34 shared helpers sunk plus the `getsource` assertion migrated (`tests/test_analysis_task_orchestration.py:404`). Still layer-blocked sub-slices: P3.3b(2) (a helper must move below `report/`), P3.3d(2) (`methodology` must become a declared shared module). NOT STARTED: P3.4 (ReportRevisionWriter), P3.5 (EmulationCoordinator), P3.6 (WorkbenchQueryReader), P3.7 (test surface off private/`getsource`), and Phases 4 and 5. Per-slice detail and every measured blocker: `docs/p33-investigation-coordinator-design-20260922.md`, `docs/p33ef-giants-decision-20260922.md`, `docs/p33-layer1-loop-path-module-design-20260922.md` and `docs/p33-layer4-model-action-contract-design-20260922.md`.

UNCHANGED and untouched by this plan: capability acceptance is measured on the analyst-facing behaviours, not on structure. The Ghidra B3/C3 capability items (T4 route B2, T8, T3, T6, T7, the diagnostic channel, undeclared truncation) are still open, and `structure_status=READY` must never be read as implying `capability_status=ACCEPTED`.

## 二、阶段状态

| 阶段 | 状态 |
|---|---|
| phase_0 | COMPLETE (P0.1-P0.6, plus repairs P0.3-r2/r3 and P0.5-r2/r3) |
| phase_1 | COMPLETE (P1.1-P1.4, plus repairs P1.1-r2 and P1.3-r3) |
| phase_2 | COMPLETE - 9 packages, 34 moved paths, report/ complete, 7 investigation siblings moved, 3 task modules moved, duplicate list empty, cycle allowlist empty |
| phase_3 | IN PROGRESS - P3.1 and P3.2 COMPLETE (TaskHost; service.py 29,640 -> 28,898). P3.3 DESIGNED with FOUR SLICES MOVED (P3.3b/a/c/d; coordinator port = six members; service.py 28,898 -> 28,028) AND TWO LAYER ITEMS DONE: item 1 (`investigation/loop_path.py`; the `investigation -> task` cycle is gone) and item 4 (`DynamicPlanAction` now lives in the pure contract module `contracts.py`, re-exported by the model gateway). P3.3c(2) is UNBLOCKED and is the next slice. Remaining giants both need layer work first: P3.3e (3,041 lines wholesale; needs the `simulation_adapters` interface) and P3.3f (3,523 lines; needs ~34 helpers sunk plus one `getsource` migration). P3.3b(2) and P3.3d(2) stay blocked on layers. |
| phase_4 | NOT STARTED (remove shims, one checkpoint each, then converge the root package's exports) |
| phase_5 | NOT STARTED (re-verification; the DSH suite has never been run in this session) |

## 三、机械条件（P5.1）

123 files x 8 services, missing=0 differing=0 container-only=0, and the import smoke imports 51 enumerated modules in every container, with all 11 containers running

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
- P3.3b
- P3.3a
- P3.3c
- P3.3d
- P3.3e/f-decision

## 五、审计历史

- round 64/65: P0.3-P1.1 instrument audit -> 3 critical findings, all repaired with can-fail proofs
- round 66: three-axis audit of P1.3/P1.4 (standards, spec, adversarial) -> 6 confirmed escapes, all closed; the standards axis found the gate could not pass on a clean checkout, verified fixed in a clean worktree
- round 69: adversarial audit of the report move -> move trustworthy, enforcement not; 5 findings fixed, 2 recorded
- Round 97, P3.2-design + P3.2c - denial-stance self-review inside the `improve-codebase-architecture` framework (`.scratch/p32design-adversarial-review.md`, `.scratch/p32c-adversarial-review.md`): 12 charges raised across the two steps, 0 retracted, 0 conclusions withdrawn. Two findings were new FACTS rather than restatements and both were recorded: the design step's port was a HYPOTHETICAL SEAM until P3.2c gave it a production adapter, and moving a PUBLIC dataclass changed `SubmissionResult.__module__` (measured blast radius: no pickling, no repr or module assertions, `is`-identity preserved through the re-export). The review's own process lesson - a PowerShell `Set-Content` without `-Encoding utf8` corrupted a can-fail tamper into a UnicodeDecodeError - is recorded with the step.
- Round 105, P3.3 layer item 1 - two-axis eview skill against 72fa4c8: 4 hard violations + 4 judgement calls (Standards) and 7 findings (Spec); 10 accepted and fixed in the step, 1 accepted as a recorded deviation (the getsource assertion, assigned to P3.3f), 1 partially disputed and recorded (a decision-doc edit), 1 upheld as a check. The worst finding was self-inflicted and found by pytest, not by any gate: the moved class lost @dataclass(frozen=True) while the decorator re-bound onto AnalysisTaskRuntime(Protocol).
- Round 106, P3.3 layer item 4 - two-axis review against a48e902: 2 hard violations + 6 judgement calls (Standards) and 3 findings (Spec); 8 accepted and fixed (including the item's own action, which the first draft dodged), 2 partially disputed and recorded, 1 refuted by the tree, 1 accepted as a documentation gap. The worst finding was self-inflicted: the step left the model port untouched while claiming the item was satisfied.

## 六、后继者必须先做的事

1. Read `step_records` plus the object named by `authoritative_final_state`; they are the only current content.
2. DONE and not to be re-opened: P3.3b/a/c/d, layer item 1 and layer item 4. THE NEXT SLICE IS P3.3c(2) - its three members `_model_action_plan`, `_has_complete_model_action_plan` and `_merge_planned_actions` (71 lines) - because BOTH of its recorded blockers are now removed (`action_is_model_or_human` by item 1, `DynamicPlanAction` by item 4). Move them with their `isinstance` intact: the canonical class is still the nominal type in `contracts.py`.
3. After that, the two giants still need LAYER work, in this order: LAYER ITEM 2 (expose the 7 `simulation_adapters` policy names as an allowed emulation interface) unblocks P3.3e, the largest remaining slice; P3.3f needs ~34 shared helpers sunk and `tests/test_analysis_task_orchestration.py:404`'s `getsource` assertion migrated. Items 3 and 5 are recorded with their measurements in the giants decision doc.
4. MEASURE THE ROUTE, NOT JUST THE ITEM WORDING. Item 4's text said "let the model PORT expose the type"; the measurement showed that re-exporting a pydantic model through `ports.py` would drag httpx into every port importer (its own docstring forbids transport/SDK imports) and that a structural `*View` would have forced a SEMANTIC rewrite (`isinstance`) inside a move that must be byte-identical. The class went to `contracts.py` instead, which the plan's matrix already allows `investigation/` to import. Record such re-routes explicitly.
5. ANY MOVE MUST DERIVE THE IMPORTS ITS NEW HOME NEEDS from the moved body's free names and REFUSE to write unresolvable ones. That guard found a latent defect in this step (the moved class annotated `ClassVar` while its old module never imported it - `ruff` had flagged it as F821 all along) and found a shipped defect in layer item 1 (`SimpleNamespace` missing). Spans must also start at the FIRST DECORATOR and carry the comment block directly above a definition, or a decorator re-binds onto the next statement and a rationale orphans.
6. WHEN A TOOL AND ITS VERIFIER ARE WRITTEN TOGETHER, TEST THE VERIFIER AGAINST A DELIBERATELY DAMAGED SUBJECT, or it agrees with the tool by construction. Two can-fail scripts now do this for these steps (`.scratch/layer1-canfail.py`, `.scratch/layer4-canfail.py`) and they restore every file byte-for-byte.
7. `structure_status=READY` must never imply `capability_status=ACCEPTED`: the Ghidra B3/C3 capability items are untouched by this plan.

## 七、已记录、但**不得**在结构步骤里修的行为缺陷

- the compose gate accepts a draft that keeps the operational-limitation HEADING and drops every bullet (analyst_report.py:6123 is a heading substring test) - recorded in the P0.5 probe and pinned by a test
- `is_real_simulation_row` returns True for DISABLED_BY_POLICY and NO_GRANTED_WINDOW while `simulation_adapters._POLICY_OR_PLACEHOLDER_STATUSES` treats both as non-observed
- `_mechanism_catalog_id` is called with a Mapping at two sites while the live definition takes a scalar, so the 'recovered' branch of `_topic_status` can never fire and mechanism labels lose the catalog title
- LINE-ENDING DRIFT (MEASURED in round 79/80, pre-existing and repo-wide): `core.autocrlf=true` with no `.gitattributes`, so `git ls-files --eol src` reports 74 tracked files `i/lf w/lf` and 23 `i/lf w/crlf`. A fresh checkout materialises the first group as CRLF, therefore git status is BLIND to line-ending differences between the worktree and HEAD, and `scripts/check-deployed-code-hashes.py`'s clean-tree note ("src/ clean, so the tree IS HEAD") is not byte-true; plan 5.1's condition is byte-oriented. The gate's EVIDENCE stays valid because `host_hashes()` reads the working tree and the images are built from that same tree, but a byte-exact HEAD comparison does not exist today. Fixing it rewrites ~74 files and needs a rebuild plus re-verification, so it is a work item of its own - measured, not silently normalised inside a structural step. RE-MEASURED in round 97: `git ls-files --eol src` now reports 101 files `i/lf w/lf`, 19 `i/lf w/crlf` and 1 `i/none w/none` (121 tracked src files in total, matching the deployment gate's file count), because the tree has grown by package `__init__`/facade files since round 79/80. The defect is unchanged in kind: the gate reads the WORKING TREE, so its evidence stays valid, but a byte-exact HEAD comparison still does not exist.

## 八、方案级冲突（及其裁决）

- **static-name-collision**（blocked P2-S）：**RESOLVED (round 71, commit 65b86ac)** — The ASSET directory was renamed `static/` -> `assets/` and the mount URL was kept as `/static`, so every browser-visible URL is unchanged. The package name the plan wants is left free.
- **investigation-and-intake-self-shadow**（blocked P2-V and P2-I）：**RESOLVED AND IMPLEMENTED (P2-I for intake, P2-V.0 + P2-V for investigation)** — A module -> package move needs a LAZY facade (PEP 562 `__getattr__`) - implemented ONCE as the shared mechanism in `src/threat_report_agent/package_facade.py` - and `investigation` additionally needed one shared predicate group moved down into `facts/thread_start.py` first. Both halves are now in the tree and verified on the DEPLOYED images, not only in the copy simulation that chose the recipe.
