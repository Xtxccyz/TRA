# 结构优化执行状态（方案 `code-structure-optimization-execution-plan-reviewed-20260922.md`）

> 本文件由 `.scratch/structure-status.json` **程序化生成**（`.scratch/render-structure-status.py`）。`.scratch/` 被 gitignore，因此把最终状态在此留一份被跟踪的记录。逐步骤的完整字段（allowed_files / commands / focused_result / full_result / new_failures / import_graph / module_identity / deployment_smoke / behavior_probe_diff / rollback_point / decision）在 `step_records`，共 84 条，本文件只汇总。

- **被核验的树 = 提交 `cb42d7bb488d5c9cc0cebf5db6707585e16c4c44`**（该提交的 tree 上跑过四道门禁与全量套件）
- `head_sha` 的语义：`head_sha` 是**被门禁核验的代码提交**，不是「当前 HEAD」：当前为 `30c2adcf258c`（P3.3f-2 的循环迁移）。每一步的回滚点是该步 `rollback_point` 记录的上一个提交。**本 phase 实测过的两次漂移**都出在这个字段上：它曾记「提交前的 HEAD」，于是文档声称在一个不含本步改动的提交上完成核验；改成「当前 HEAD」后，写下该值的提交本身又会移动 HEAD——任何文件都无法正确写出「包含自己的那个提交」。因此这里固定记代码提交，并在每次复验时核对 `src/` 与 `tests/` 是否仍与它一致。**P3.4 设计步（records commit a83126b6680f）实测为**`git diff --name-only 30c2adcf258c..a83126b6680f -- src tests` 为空，即本步只动 `docs/`。ROUND 121 AMEND NOTE: P3.3f-2 的代码提交先写成 `d1cda62d8488`，两轴审查的修复（模块 docstring 的成员数、`_investigation_scheduled_keys` 的再导出、注释与两个加强后的测试）落盘后被 `git commit --amend` 折进同一提交，并在改写后的树上**重跑**了全量套件与部署门禁——被 amend 的提交不可达，写它等于让读者无法检出。
- **structure_status：`IN_PROGRESS`**
- **capability_status：`UNCHANGED in substance and now backed by this round's separate-toolchain evidence: the capability items (T4 route B2, T8, T3, T6, T7, the diagnostic channel, undeclared truncation) remain OPEN, and the DSH suite that gates the product side reports 4 pass / 4 fail (typecheck, test, test:runtime, smoke:dsh) - recorded in the P5.1 step record and NOT offset by any pytest result. `structure_status=READY` must never be read as implying `capability_status=ACCEPTED`.`**

### 读取指引：本文件的哪一部分代表**当前**状态

- **权威内容＝`step_records` + 最新的 `final_state_*` 对象（当前是 `final_state_round_121_p33f2`，由 `authoritative_final_state` 指定）。**
- 渲染器改写于 round 100：它过去按**字符串**排序挑最新对象，于是 `round_100` 排在 `round_97` **之前**，文档因此写着「还没有任何 P3.3 切片搬迁」而实际已搬两个。现在改为：显式指针 `authoritative_final_state` → （其次）`head_sha` 与被核验提交一致的对象 → （最后）**按数字**排序。
- 其余一切 `final_state_round_*` 都是**历史**（每个都带 `superseded_by` 指向最新对象）；它们的 `what_a_successor_must_do_first` 可能点名早已完成的工作，**不要照它执行**。
- 已经刷新为当前值的段落：`import_graph`、`deployment`、`worktree`（各自带 `measured_at_commit`）。
- **保留但属于历史**的段落（不删除，以免丢失 Phase 0/1 的证据链）：`p0_6_progress`、`ghidra_worker_blocker`（已标注 `_resolved`）、`behavior_probe`、`baseline`、`legacy_import_callers`、`phase_0`/`phase_1`/`phase_2` 的细节、`audit_findings_round_*`、`reverted_steps`。
- 结构状态与能力状态是两个轴：`structure_status` 反映本方案，`capability_status` 反映 Ghidra B3/C3 能力项；**结构 READY 不得推出能力 ACCEPTED**。

## 一、为什么不是 READY / ACCEPTED

Plan section P5 grants `structure_status=READY` only after P2-P4 are complete. Phases 0, 1 and 2 are COMPLETE. **P3.1-P3.4 COMPLETE; P3.6-1 COMPLETE; P3.7 COMPLETE FOR THE `getsource` HALF AND PARTIAL FOR THE DIRECT-CALL HALF** (39 -> 2 `getsource` calls; 9 direct private calls were ADDED, and one of the plan's 18 sites survives at `tests/test_investigation_recovery_loop.py:68`); **P3.5 IS BLOCKED** (plan conflict 3, with an exact P3.5-0 worklist measured); **P4.0 IS COMPLETE** (`legacy_path_imports` EMPTY). REMAINING: (1) the P3.7 direct-call half (concept-level public functions or an HTTP facade); (2) the shared preparation step P3.5/P3.6-0 or a plan decision for conflict 3; (3) P3.6-2 (`workbench_capabilities`); (4) the Phase 4 shim deletions, each rewriting its pinning assertion in the same commit; (5) Phase 5: the deployment gate and the two Docker-blocked nodes owe a re-run, the DSH suite already ran separately (4 pass / 4 fail, recorded), and the capability matrix is written and says NOT ACCEPTED (8 OPEN / 2 PARTIAL).

UNCHANGED and untouched by this plan: capability acceptance is measured on the analyst-facing behaviours, not on structure. The Ghidra B3/C3 capability items (T4 route B2, T8, T3, T6, T7, the diagnostic channel, undeclared truncation) are still open, and `structure_status=READY` must never be read as implying `capability_status=ACCEPTED`.

## 二、阶段状态

| 阶段 | 状态 |
|---|---|
| phase_0 | COMPLETE (P0.1-P0.6, plus repairs P0.3-r2/r3 and P0.5-r2/r3) |
| phase_1 | COMPLETE (P1.1-P1.4, plus repairs P1.1-r2 and P1.3-r3) |
| phase_2 | COMPLETE - 9 packages, 34 moved paths, report/ complete, 7 investigation siblings moved, 3 task modules moved, duplicate list empty, cycle allowlist empty |
| phase_3 | IN PROGRESS - P3.1-P3.4 and P3.6-1 COMPLETE; P3.5 BLOCKED (plan conflict 3); P3.7 MEASURED (17 sites, count reconciled against the surface's 39). REMAINING: the shared prep step (with a scope note), P3.6-2/P3.5-2, P3.7's sites, then Phases 4-5. service.py 29,640 -> 18,831 since Phase 3 began. |
| phase_4 | NOT STARTED (remove shims, one checkpoint each, then converge the root package's exports) |
| phase_5 | NOT STARTED (re-verification; the DSH suite has never been run in this session) |

## 三、机械条件（P5.1）

PASS - 130 files per service across 8 services, missing=0 differing=0 container-only=0, import smoke 57 modules per service

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
- P3.3-layer4
- P3.3c2
- PROC-tooling-gate
- P3.3-layer2
- P3.3e-design

## 五、审计历史

- round 64/65: P0.3-P1.1 instrument audit -> 3 critical findings, all repaired with can-fail proofs
- round 66: three-axis audit of P1.3/P1.4 (standards, spec, adversarial) -> 6 confirmed escapes, all closed; the standards axis found the gate could not pass on a clean checkout, verified fixed in a clean worktree
- round 69: adversarial audit of the report move -> move trustworthy, enforcement not; 5 findings fixed, 2 recorded
- Round 97, P3.2-design + P3.2c - denial-stance self-review inside the `improve-codebase-architecture` framework (`.scratch/p32design-adversarial-review.md`, `.scratch/p32c-adversarial-review.md`): 12 charges raised across the two steps, 0 retracted, 0 conclusions withdrawn. Two findings were new FACTS rather than restatements and both were recorded: the design step's port was a HYPOTHETICAL SEAM until P3.2c gave it a production adapter, and moving a PUBLIC dataclass changed `SubmissionResult.__module__` (measured blast radius: no pickling, no repr or module assertions, `is`-identity preserved through the re-export). The review's own process lesson - a PowerShell `Set-Content` without `-Encoding utf8` corrupted a can-fail tamper into a UnicodeDecodeError - is recorded with the step.
- Round 105, P3.3 layer item 1 - two-axis 
eview skill against 72fa4c8: 4 hard violations + 4 judgement calls (Standards) and 7 findings (Spec); 10 accepted and fixed in the step, 1 accepted as a recorded deviation (the getsource assertion, assigned to P3.3f), 1 partially disputed and recorded (a decision-doc edit), 1 upheld as a check. The worst finding was self-inflicted and found by pytest, not by any gate: the moved class lost @dataclass(frozen=True) while the decorator re-bound onto AnalysisTaskRuntime(Protocol).
- Round 106, P3.3 layer item 4 - two-axis review against a48e902: 2 hard violations + 6 judgement calls (Standards) and 3 findings (Spec); 8 accepted and fixed (including the item's own action, which the first draft dodged), 2 partially disputed and recorded, 1 refuted by the tree, 1 accepted as a documentation gap. The worst finding was self-inflicted: the step left the model port untouched while claiming the item was satisfied.
- Round 107, P3.3c(2) - two-axis `review` skill against ed363a5: 0 hard violations (Standards) and 2 findings (Spec, one about the record rather than the code); 6 accepted and fixed, 2 accepted and recorded, 2 partially disputed. The worst finding was about the pins, not the move: the delegation test checked only receivers and the replacement test dropped the retired pin's runtime-use assertions.
- Round 111, P3.3 layer item 2 (part 1) - two-axis `review` skill against a11c2c7: 3 hard violations + 3 judgement calls (Standards) and 3 findings (Spec); 5 accepted and fixed, 1 recording gap accepted, 1 refuted by timing, and 1 upheld independently (P3.3e still blocked, with the same two names). The worst finding was the hand-listed caller migration that missed `scripts/` while the step's own document claimed otherwise.
- Round 113, P3.3e preparation - two-axis `review` skill against 8059cfc: 3 hard violations + 3 judgement calls (Standards) and 2 findings (Spec); 5 accepted and fixed, 1 partially refuted with evidence, 1 upheld as the phase's own pattern. The worst finding was a NEW matrix edge this slice introduced; the fix removed the edge instead of justifying it.
- Round 116, P3.3e first half (the travelling cluster) - two-axis `review` skill against HEAD, one subagent per axis: ONE HARD tooling violation (both identity verifiers stripped every external alias from both sides, so a call rewritten to the wrong module compared identical - proven by tampering a base) plus the double-newline constant defect, the missing `_DECODE_PRODUCER_KINDS`, the class-constant removal and the `getsource` claim correction. Every finding was accepted and fixed except one: the review's '4 relocated HOST members' came from an imprecise sentence in the review brief, not from the code - no HOST member moved.
- Round 117, P3.3e execution seam - two-axis `review` skill against HEAD: STANDARDS found NO hard violations (the first clean standards axis of the phase's recent steps) and four judgement calls, all actioned; SPEC found the missing contract test (now added and can-failed), the same behaviour delta, one docstring overclaim and stale records, and had TWO claims refuted by measurement (runner construction count 3 vs the measured 2; 'two new import edges' vs the measured 227-edge graph unchanged).
- Round 118, P3.3e giant move (2,787 lines) - two-axis `review` skill against HEAD: STANDARDS found ONE hard violation (the re-export surface deleted; restored) plus false docstrings and a regression in a test guard it caught being WIDENED (now stricter than before), and a real blind spot in the identity tools for which it supplied the compensating control; SPEC refuted the design's port arithmetic ('12' vs the measured disjoint pins 6 and 7), found six stale sentences and the `getsource` family under-counted (one predicted, three found). One review claim (a four-name edge list) was itself refuted by measurement: the true list is five.
- Round 120, P3.3f-1 (the sink preparation) - two-axis `review` skill against the pre-commit HEAD: STANDARDS found one hard violation that was a mid-rebuild artefact of the deployment gate (now green, naming commit 169bca2) and three judgement calls, ALL FIXED (old-path reachability restored for every moved name, a docstring count corrected, two orphaned comments moved with their code); SPEC confirmed byte-identity independently and found the same reachability gap plus four stale record claims, all corrected. Both axes independently re-derived the core measurements and neither could falsify the byte-identity, the runtime identity or the edge admissibility.
- Round 121, P3.3f-2 (the loop's move, the phase's largest slice) - two-axis `review` skill against 1f9a686: STANDARDS found one documentation-only hard violation (the pin docstring said 7 members where 42 exist; fixed) plus four judgement calls - three actioned (a lost re-export restored, a stale comment corrected, a vacuous contract branch strengthened) and one REFUTED by measurement (three functions were said to name `self` where they name `host`); it also falsified three claims in this step's own record script before it ran, all corrected. SPEC found the port number unrecorded, the same vacuous branch, and a DEAD negative guard whose literal has never existed in this repo (replaced by a check on the call site's code, shown to fire on the old shape). Both axes independently confirmed byte identity, the pin/Protocol/reference equality and the layer admissibility.

## 六、后继者必须先做的事

1. **CLOSE THE OPEN RED-LINE VIOLATION FIRST** (it is proven, named and small): `tests/test_speakeasy_reachability.py::test_granted_window_planning_asks_for_speakeasy` no longer fails when the granted-window plan is forced to `allow_speakeasy=False`. The fix must pin the DECISION'S EFFECT (the request the worker receives given the operator's setting), NOT the plan call's argument - that argument is a ternary (`False if granted_windows else speakeasy`) and asserting it is True made the test fail, which is why the first attempt was reverted. Require a can-fail: forcing the plan's argument to False MUST make the new assertion fail.
2. **Two smaller P3.7 gaps the same review measured**: (a) `tests/test_static_simulation_budget.py` lost one of its two call-site guards (`_derive_investigation_observations` is no longer pinned by any test); (b) two added tests have zero discriminating power (`test_analysis_task_orchestration.py:460-471`, `test_function_similarity_cost.py:208-210`). And the P1.4 `reaching_a_private_member` metric should be widened to count BARE private imports, or the plan's 18-site list must be tracked separately - today it reports 0 while a plan site survives.
3. **WHEN DOCKER RETURNS, CLOSE THE OWED EVIDENCE FIRST** - it is now owed by a step that changed `src/`: re-run the two blocked nodes, re-compare the failure NODE SET, rebuild BOTH image routes and run the deployment gate. Until then the honest state is `STRUCTURE_READY_LOCAL / DEPLOYMENT_BLOCKED` at best, never READY.
4. **APPEND THE STANDARDS-AXIS FINDINGS for the P3.7 diff** (fixed point 9ae5f609); the Spec axis has already run and its four gaps are recorded in the round's step record.
5. **P3.7'S REMAINING HALF (direct private calls -> concept-level public functions or an HTTP facade)**: nine were ADDED by the conversion, at `test_controlled_emulation.py:1240,2058`, `test_investigation_recovery_loop.py:374`, `test_investigation_service.py`, `test_analysis_task_orchestration.py:600`, `test_function_similarity_cost.py:126`, `test_speakeasy_reachability.py:148`, `test_pe_entry_function_budget.py:1776`, `test_static_simulation_budget.py`. Also convert the one surviving plan site (`test_investigation_recovery_loop.py:68`, PRESENCE) and decide whether the P1.4 `reaching_a_private_member` metric should count moved-module targets too, since today it keys only on `AnalysisService._` and therefore reports 0 while a plan site survives.
6. **THEN the owed two-axis review of the P3.7 diff** (fixed point: the commit before this round's records commit; the diff spans 15 test files, +6 tests and the `docs/structure-surface.json` re-record of `test_getsource_count` 39/17 -> 2/0).
7. **THE OBJECTIVE IS NOT COMPLETE AND THE ROUNDS ARE EXHAUSTED.** Five workstreams remain (listed in `why_not_READY`); the two largest - the shared preparation step and P3.7's 17 sites - each need multiple rounds with the full gate battery. Do NOT start either unless it can be finished and verified in the round; a half-moved slice leaves the tree in a state the next author cannot tell apart from a regression.
8. **P3.6-2's ONE REMAINING DEBT (measured obstacle, round 130)**: the design's section 5.4 dict-key-set assertion cannot be derived statically - `workbench_domain_view` builds its payload incrementally, so an AST extraction yields no key list. Do it at runtime: run `tests/test_investigation_service.py::test_workbench_domain_view_exposes_snapshot_mechanisms` (line 1724) with its existing `test_settings` fixture, print `sorted(view)` once, and assert `REQUIRED_VIEW_KEYS <= set(view)` so additive changes do not break it. This is a TEST-ONLY step: no image rebuild, so the focused battery, the full suite and the node-set comparison suffice.
9. **IF EXACTLY ONE MORE ROUND IS AVAILABLE, THE BEST-VALUE VERIFIABLE STEP IS P3.6-2's TEST DEBT**: add the design's section 5.4 dict-key-set assertion to a query test that already has a session fixture (it is the one remaining review finding with no measurement attached). It is test-only, so it needs no image rebuild - only the focused battery, the full suite and the node-set comparison.
10. **THE PREPARATION STEP'S SHAPE IS PRESCRIBED IN THE P3.5 DESIGN'S SECTION 5** and its scope note must name `contracts.py`, `ports.py` and `investigation/**` as out-of-whitelist files it touches deliberately.
11. **HARD GATES FOR EVERY SLICE**: slice-tooling; the data-driven can-fail proof (never concurrent with the suite); compileall; the scope gate; the strict import graph; `docker compose config`/`ps` with BLOCKED classification and no skipped `ghidra-worker`; focused -> full suite -> behaviour probe; failure sets by NODE SET; the deployment gate after rebuilding BOTH image routes, then `HEAD == origin/main`; the tracked contract test's bidirectional pin assertion; the delegation-shape gate (parameters AND `__doc__`); the read-only AST assertion for read-only slices. **AND: never amend an already-pushed commit** (round 127 did; the push refused and the fix was a backup branch plus a re-applied commit - recorded in `git_sync.reason`).
12. **BEFORE MOVING ANY CLASS ATTRIBUTE, GREP EVERY `*_HOST_MEMBERS` TUPLE**: a constant read through another module's host pin is invisible to a `self.`/`cls.` scan of `service.py` and cost 37 broken tests in P3.6-1.
13. **WHAT STILL OWES A RE-RUN WHEN THE ENVIRONMENT RECOVERS** (both were blocked this round and neither is presented as a pass): (1) the two Docker-blocked nodes (`test_detection_rule_indicator_correctness::test_the_verifier_flags_a_self_referential_and_resource_digest_indicator`, `::test_the_verifier_is_quiet_on_a_correct_rule`) plus the node-set re-comparison; (2) the deployment gate, once the Docker engine is back and BOTH image routes are rebuilt. And (3) the push, which is failing on both routes (`ls-remote failed`), so the last two rounds' commits are LOCAL ONLY - the remote is behind and the repository is not in sync until that succeeds.

## 七、已记录、但**不得**在结构步骤里修的行为缺陷

- the compose gate accepts a draft that keeps the operational-limitation HEADING and drops every bullet (analyst_report.py:6123 is a heading substring test) - recorded in the P0.5 probe and pinned by a test
- `is_real_simulation_row` returns True for DISABLED_BY_POLICY and NO_GRANTED_WINDOW while `emulation.policy._POLICY_OR_PLACEHOLDER_STATUSES` (moved there by P3.3 layer item 2; `simulation_adapters` re-exports it) treats both as non-observed
- `_mechanism_catalog_id` is called with a Mapping at two sites while the live definition takes a scalar, so the 'recovered' branch of `_topic_status` can never fire and mechanism labels lose the catalog title
- LINE-ENDING DRIFT (MEASURED in round 79/80, pre-existing and repo-wide): `core.autocrlf=true` with no `.gitattributes`, so `git ls-files --eol src` reports 74 tracked files `i/lf w/lf` and 23 `i/lf w/crlf`. A fresh checkout materialises the first group as CRLF, therefore git status is BLIND to line-ending differences between the worktree and HEAD, and `scripts/check-deployed-code-hashes.py`'s clean-tree note ("src/ clean, so the tree IS HEAD") is not byte-true; plan 5.1's condition is byte-oriented. The gate's EVIDENCE stays valid because `host_hashes()` reads the working tree and the images are built from that same tree, but a byte-exact HEAD comparison does not exist today. Fixing it rewrites ~74 files and needs a rebuild plus re-verification, so it is a work item of its own - measured, not silently normalised inside a structural step. RE-MEASURED in round 97: `git ls-files --eol src` now reports 101 files `i/lf w/lf`, 19 `i/lf w/crlf` and 1 `i/none w/none` (121 tracked src files in total, matching the deployment gate's file count), because the tree has grown by package `__init__`/facade files since round 79/80. The defect is unchanged in kind: the gate reads the WORKING TREE, so its evidence stays valid, but a byte-exact HEAD comparison still does not exist.

## 八、方案级冲突（及其裁决）

- **static-name-collision**（blocked P2-S）：**RESOLVED (round 71, commit 65b86ac)** — The ASSET directory was renamed `static/` -> `assets/` and the mount URL was kept as `/static`, so every browser-visible URL is unchanged. The package name the plan wants is left free.
- **investigation-and-intake-self-shadow**（blocked P2-V and P2-I）：**RESOLVED AND IMPLEMENTED (P2-I for intake, P2-V.0 + P2-V for investigation)** — A module -> package move needs a LAZY facade (PEP 562 `__getattr__`) - implemented ONCE as the shared mechanism in `src/threat_report_agent/package_facade.py` - and `investigation` additionally needed one shared predicate group moved down into `facts/thread_start.py` first. Both halves are now in the tree and verified on the DEPLOYED images, not only in the copy simulation that chose the recipe.
- **conflict-3-emulation-row-cannot-carry-the-coordinator**（blocking）：**OPEN - blocks P3.5; P3.5 may only be reported BLOCKED until it is resolved** — (a) RECOMMENDED - hoist those contracts into `contracts.py` (or expose them through `ports.py`) with `X as X` re-exports at every old path, take tool execution through `ToolExecutionPort` with the concrete `TemporalToolExecutor` INJECTED, sink `TaskLifecycle`/`PackageEntry` into `contracts.py`, and record the `emulation.coordinator -> models` edge as a decision (the decision-(e) mechanism). Every row of section 3.2 admits `contracts`, and this completes the types P1.1/P1.2 left behind. (b) Alternatively, widen the `emulation/` row by an explicit plan decision and say so in the plan file.
