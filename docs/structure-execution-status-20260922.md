# 结构优化执行状态（方案 `code-structure-optimization-execution-plan-reviewed-20260922.md`）

> 本文件由 `.scratch/structure-status.json` **程序化生成**（`.scratch/render-structure-status.py`）。`.scratch/` 被 gitignore，因此把最终状态在此留一份被跟踪的记录。逐步骤的完整字段（allowed_files / commands / focused_result / full_result / new_failures / import_graph / module_identity / deployment_smoke / behavior_probe_diff / rollback_point / decision）在 `step_records`，共 123 条，本文件只汇总。

- **被核验的代码树 = 提交 `58e9323bd9e0`**（四道门禁与全量套件在它的 tree 上通过）；当前 `head_sha` `4226e64b1fee` 只改了 `docs/`，实测 `git diff --name-only 58e9323bd9e0..4226e64b1fee -- src tests` 为空，所以 `src/` 与 `tests/` 仍等于被核验的那棵树。**部署门禁例外**：Docker Desktop 当前不可达，`check-deployed-code-hashes.py --strict` 无法运行。
- `head_sha` 的语义：`head_sha` = **被核验的代码提交**，不是「当前 HEAD」。ROUND 161: 值从 `7ecb6b4` 修正为 `4226e64b1fee`——它此前落后了三个提交，且被指向的 final state 还在描述一个已不存在的树。**该提交只改了 `docs/`**；真正跑过四道门禁与全量套件的代码提交是 `58e9323bd9e0`（P3.7 facade batch 8），实测 `git diff --name-only 58e9323bd9e0..4226e64b1fee -- src tests` 为空，即两者的 `src/` 与 `tests/` 逐字节相同。任何 `src/` 改动都会重新欠一次门禁；Docker 当前不可用，因此 `deployment.gate_state = BLOCKED`，最后一次 PASS 停留在 `58e9323bd9e0`。
- **structure_status：`STRUCTURE_READY_LOCAL at 4226e64 / DEPLOYMENT_BLOCKED (Docker Desktop unreachable on this host, measured 2026-09-26) - P3.7 is FROZEN as REQUIRES_REDESIGN, and phases 3 (P3.5), 4 and 5 remain incomplete`**
- **capability_status：`UNVERIFIED`**

### 读取指引：本文件的哪一部分代表**当前**状态

- **当前主计划是 `.scratch/plan-ghidra-b3-c3-execution-plan-reviewed-20260922.md`**（状态见 `main_plan_state` 与 `docs/ghidra-c3-execution-status-20260926.md`）。本结构计划是**子计划**：P3.7 已冻结为 `REQUIRES_REDESIGN`，结构步骤不再阻塞功能开发。
- **权威内容 = `step_records` + `authoritative_final_state` 指定的那一个 `final_state_*` 对象（当前是 `final_state_round_161_governance`）。** 顶层 `head_sha` / `current_step` / `structure_status` / `p37_status` / `behavior_plan_state` 与它一致。
- **Round 161 修复过一次失真**：此前顶层 `head_sha` 仍是 `7ecb6b4`、`current_step` 仍是 `P3.7-recount`，被指向的 final state 仍写着 P3.5 准备未完成、DSH 4/8。凡与 `authoritative_final_state` 冲突的散文一律以该对象为准。
- 其余 `final_state_round_*` 都是**历史**（带 `superseded_by`）；它们的 `what_a_successor_must_do_first` 可能点名早已完成的工作，**不要照它执行**。
- **P3.7 已冻结为 `REQUIRES_REDESIGN`**：`.scratch/p37-batch*.py` 与 `.scratch/p37-make-batch*.py` 不得再运行；58 个facade 不回滚，随调用它们的测试迁到所属模块的真实 Interface 时逐个删除。
- **Docker 当前不可用**，因此 `deployment.gate_state = BLOCKED`；最后一次 PASS 在 `58e9323`。任何 `src/` 改动都重新欠一次部署门禁，且**不得**用本机 pytest 顶替。
- **活动计划已切换**为 `docs/behavior-driven-investigation-plan-reviewed-20260907.md`（见 `behavior_plan_state`）；结构方案不再是功能开发的前置条件。
- 结构状态与能力状态是两个轴：`structure_status` 反映结构方案，`capability_status` 反映 Ghidra B3/C3 能力项；**结构 READY 不得推出能力 ACCEPTED**。

## 一、为什么不是 READY / ACCEPTED

Plan P5 grants `structure_status=READY` only after P2-P4 are complete, and the deployment half of P5 cannot be re-run at all right now. MEASURED AT 4226e64: **Phases 0/1/2 COMPLETE**; **P3.1-P3.4, P3.6-1, P3.6-2 and P3.5-0 COMPLETE** (M-1..M-5, D-1, D-2, D-3, R2 all landed); **P3.7 FROZEN**: the `getsource` half is complete (39 -> 2 calls) but the direct-call half was executed in the wrong direction and is now `REQUIRES_REDESIGN` - 58 one-to-one public wrappers exist with ZERO production callers and 310 test call sites, and 53 private members (80 sites) are still called on service receivers plus 9 members (20 sites) on OTHER receivers; **P3.5 (`EmulationCoordinator`) NOT STARTED** and is now an ON-DEMAND prerequisite, owed only before work that touches the controlled-emulation main chain; **P4** shim deletion is gated and does NOT block behaviour work (`legacy_path_imports` is EMPTY); **P5** deployment was last VERIFIED at 58e9323 and is now BLOCKED by an unreachable Docker daemon, while the DSH half is 8/8 and must never be offset by a pytest result. STRUCTURAL DEBT RECORDED, NOT FIXED: `investigation/derivation.py` imports `sqlalchemy`, `sqlalchemy.orm` and `threat_report_agent.models`, and `DerivationHost` declares 42 members (34 functions + 8 class attributes); `investigation/seed_support.py` imports `models`; the import gate passes those edges because 263 edges are grandfathered in `known_edges`, not because they satisfy the layer matrix; 7 of the 33 `service.py:<line>` citations in `ports.py` point past EOF (service.py is 19,372 lines, the citations date from ~28k).

UNCHANGED and untouched by this plan: capability acceptance is measured on the analyst-facing behaviours, not on structure. The Ghidra B3/C3 capability items (T4 route B2, T8, T3, T6, T7, the diagnostic channel, undeclared truncation) are still open, and `structure_status=READY` must never be read as implying `capability_status=ACCEPTED`.

## 二、阶段状态

| 阶段 | 状态 |
|---|---|
| phase_0 | COMPLETE (P0.1-P0.6, plus repairs P0.3-r2/r3 and P0.5-r2/r3) |
| phase_1 | COMPLETE (P1.1-P1.4, plus repairs P1.1-r2 and P1.3-r3) |
| phase_2 | COMPLETE - 9 packages, 34 moved paths, report/ complete, 7 investigation siblings moved, 3 task modules moved, duplicate list empty, cycle allowlist empty |
| phase_3 | PARTIAL AND FROZEN WHERE IT WAS WRONG - P3.1-P3.4, P3.6-1, P3.6-2 and the whole P3.5-0 worklist are COMPLETE; **P3.7's direct-call half is FROZEN as REQUIRES_REDESIGN** (58 test-only facades, 53 members / 80 sites on service receivers, 9 members / 20 sites on other receivers, no production caller); **P3.5 (`EmulationCoordinator`) NOT STARTED** and no longer a prerequisite for the whole plan - it is owed only before B06-B10/T4-class work that touches the controlled-emulation main chain. service.py 29,640 -> 19,372 lines since Phase 3 began. |
| phase_4 | NOT STARTED AND NOT BLOCKING - `legacy_path_imports` is EMPTY, i.e. no production module imports a legacy path. The remaining shims are deleted as their callers migrate, one checkpoint each. |
| phase_5 | HALF VERIFIED, HALF BLOCKED - the DSH half PASSES 8/8 (core-guard, legacy-guard, manifest, security, smoke:dsh, test, test:runtime, typecheck) at the isolated `DSH_HOME=<repo>/.data/dsh-threat-static`; the deployment half is BLOCKED on the Docker daemon (see above). |

## 三、机械条件（P5.1）

BLOCKED at 4226e64: Docker Desktop is unreachable (`docker version` exit 1, `npipe:////./pipe/dockerDesktopLinuxEngine` not found), so `scripts/check-deployed-code-hashes.py --strict --import-smoke` CANNOT RUN and no deployment claim is made for this commit. The LAST PASS was at 58e9323 (131 files x 8 services, `ALL DEPLOYED MODULES MATCH src/`, import smoke OK, both image routes rebuilt). Any `src/` change after that commit re-owes the gate; the gate stays BLOCKED until the daemon returns.

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
- GOVERNANCE-P37-FREEZE
- MAIN-PLAN-P0-REFERENCE

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
- Round 161, the 2026-09-26 two-axis review of 4226e64 (Standards + Spec) - 3 hard Standards findings and 5 Spec findings, of which 6 reproduced EXACTLY when re-measured and 2 did not: the review's 'DerivationHost has 42 members' holds only when class attributes are counted (34 functions + 8 attributes), and its implied doubled-decorator debt does NOT exist at this commit (measured 0 methods with two decorators on `AnalysisService`, and the four named methods carry exactly one `@staticmethod` each). The one finding that matters most - that P3.7's direct-call half publishes private implementations instead of behaviour entry points, leaving a test-only surface - was CONFIRMED by the deletion test (0 production call sites, 310 test call sites for 58 facades). This step records the verdict and freezes the generator; it fixes nothing else, because a structural step must not silently become a behaviour step.

## 六、后继者必须先做的事

1. **DO NOT RUN `.scratch/p37-batch*.py` OR ANY `p37-make-batch*.py` GENERATOR.** They are frozen. The P3.7 direct-call half is `REQUIRES_REDESIGN`: a public entry point must be a CONCEPTUAL operation that a production caller would use, not a renamed private implementation. The 58 existing wrappers are NOT to be mass-reverted either - they are deleted one at a time, as the tests that call them migrate onto the real interface of the module that owns the behaviour.
2. **THIS STATE FILE IS NOW THE ONLY AUTHORITATIVE SOURCE; the top-level `head_sha`, `current_step`, `structure_status` and the object named by `authoritative_final_state` were all re-pointed at 4226e64 by this step.** A successor must re-measure rather than trust prose: `.scratch/verify-review-charges.py` re-measures every claim this record makes.
3. **THE ACTIVE PLAN IS NOW `docs/behavior-driven-investigation-plan-reviewed-20260907.md`** (the user's 2026-09-26 instruction), not the structure plan. Order: `behavior_contracts` B02/B03, `behavior_reporting` B05, `dsh_depth_control` B00/B04, and root (`service.py`, decoder/child dataflow, emulation isolation and integration). Ownership and file boundaries are in `.scratch/behavior-implementation-assignments.md` and `AGENTS.md`.
4. **P3.5 (`EmulationCoordinator`) IS AN ON-DEMAND PREREQUISITE, NOT A BLOCKER FOR EVERYTHING.** Re-measure and complete it before the first step that touches the controlled-emulation main chain (B06-B10, T4, emulation scheduling). Its success criterion is that the four responsibilities (authorisation window, worker dispatch, result archival, failure classification) genuinely live in that module and that Temporal's concrete types do not leak - not a line-count reduction.
5. **DO NOT REFACTOR `DerivationHost` AT THE SAME TIME AS B02/B03.** They would edit the same investigation code. Its 42-member interface and its `sqlalchemy` / `models` imports are registered as debt in `structural_debt_register`; narrow it after the behaviour-contract batches settle, by the same owner.
6. **PHASE 4 SHIM DELETION DOES NOT BLOCK BEHAVIOUR WORK.** Production legacy-path imports are already 0; delete each shim when its caller migrates.

## 七、已记录、但**不得**在结构步骤里修的行为缺陷

- the compose gate accepts a draft that keeps the operational-limitation HEADING and drops every bullet (analyst_report.py:6123 is a heading substring test) - recorded in the P0.5 probe and pinned by a test
- `is_real_simulation_row` returns True for DISABLED_BY_POLICY and NO_GRANTED_WINDOW while `emulation.policy._POLICY_OR_PLACEHOLDER_STATUSES` (moved there by P3.3 layer item 2; `simulation_adapters` re-exports it) treats both as non-observed
- `_mechanism_catalog_id` is called with a Mapping at two sites while the live definition takes a scalar, so the 'recovered' branch of `_topic_status` can never fire and mechanism labels lose the catalog title
- LINE-ENDING DRIFT (MEASURED in round 79/80, pre-existing and repo-wide): `core.autocrlf=true` with no `.gitattributes`, so `git ls-files --eol src` reports 74 tracked files `i/lf w/lf` and 23 `i/lf w/crlf`. A fresh checkout materialises the first group as CRLF, therefore git status is BLIND to line-ending differences between the worktree and HEAD, and `scripts/check-deployed-code-hashes.py`'s clean-tree note ("src/ clean, so the tree IS HEAD") is not byte-true; plan 5.1's condition is byte-oriented. The gate's EVIDENCE stays valid because `host_hashes()` reads the working tree and the images are built from that same tree, but a byte-exact HEAD comparison does not exist today. Fixing it rewrites ~74 files and needs a rebuild plus re-verification, so it is a work item of its own - measured, not silently normalised inside a structural step. RE-MEASURED in round 97: `git ls-files --eol src` now reports 101 files `i/lf w/lf`, 19 `i/lf w/crlf` and 1 `i/none w/none` (121 tracked src files in total, matching the deployment gate's file count), because the tree has grown by package `__init__`/facade files since round 79/80. The defect is unchanged in kind: the gate reads the WORKING TREE, so its evidence stays valid, but a byte-exact HEAD comparison still does not exist.
- the P3.7 direct-call half converted 53 private members into a test-only public surface - recorded as a REQUIRES_REDESIGN, not repaired in place, because repairing it is behaviour work (it changes which operation a caller expresses, not just where the code lives)

## 八、方案级冲突（及其裁决）

- **static-name-collision**（blocked P2-S）：**RESOLVED (round 71, commit 65b86ac)** — The ASSET directory was renamed `static/` -> `assets/` and the mount URL was kept as `/static`, so every browser-visible URL is unchanged. The package name the plan wants is left free.
- **investigation-and-intake-self-shadow**（blocked P2-V and P2-I）：**RESOLVED AND IMPLEMENTED (P2-I for intake, P2-V.0 + P2-V for investigation)** — A module -> package move needs a LAZY facade (PEP 562 `__getattr__`) - implemented ONCE as the shared mechanism in `src/threat_report_agent/package_facade.py` - and `investigation` additionally needed one shared predicate group moved down into `facts/thread_start.py` first. Both halves are now in the tree and verified on the DEPLOYED images, not only in the copy simulation that chose the recipe.
- **conflict-3-emulation-row-cannot-carry-the-coordinator**（blocking）：**OPEN - blocks P3.5; P3.5 may only be reported BLOCKED until it is resolved** — (a) RECOMMENDED - hoist those contracts into `contracts.py` (or expose them through `ports.py`) with `X as X` re-exports at every old path, take tool execution through `ToolExecutionPort` with the concrete `TemporalToolExecutor` INJECTED, sink `TaskLifecycle`/`PackageEntry` into `contracts.py`, and record the `emulation.coordinator -> models` edge as a decision (the decision-(e) mechanism). Every row of section 3.2 admits `contracts`, and this completes the types P1.1/P1.2 left behind. (b) Alternatively, widen the `emulation/` row by an explicit plan decision and say so in the plan file.
