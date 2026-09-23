# 结构优化执行状态（方案 `code-structure-optimization-execution-plan-reviewed-20260922.md`）

> 本文件由 `.scratch/structure-status.json` **程序化生成**（`.scratch/render-structure-status.py`）。`.scratch/` 被 gitignore，因此把最终状态在此留一份被跟踪的记录。逐步骤的完整字段（allowed_files / commands / focused_result / full_result / new_failures / import_graph / module_identity / deployment_smoke / behavior_probe_diff / rollback_point / decision）在 `step_records`，共 72 条，本文件只汇总。

- **被核验的树 = 提交 `30c2adcf258c678743d1df4c0e3fdef0e83f6714`**（该提交的 tree 上跑过四道门禁与全量套件）
- `head_sha` 的语义：**`head_sha` 是被门禁核验的代码提交 `30c2adcf258c`，不是「当前 HEAD」。** 四道门禁、focused 套件与全量套件都在它的 tree 上运行过。**本轮实测到的两处漂移正是这个字段造成的**：先前它记的是提交前的 HEAD，于是文档声称在一个不含本步改动的提交上完成核验；改成「当前 HEAD」后又发现，写下该值的提交本身就会移动 HEAD——**任何文件都无法正确写出「包含自己的那个提交」**。因此这里固定记代码提交，并在每次复验时核对 `src/` 与 `tests/` 是否仍与它一致（本轮实测：`git diff --name-only 30c2adcf258c..HEAD -- src tests` 为空，即逐字节相同）。每一步的回滚点是该步 `rollback_point` 记录的上一个提交。 ROUND 116 UPDATE: the verified code commit is now `30c2adcf258c`; the measured check above was re-run for it - `git diff --name-only 30c2adcf258c..HEAD -- src tests` is empty (HEAD == 30c2adcf258c at the moment the records were written), and the deployment gate's own output names that commit: `checked 126 file(s) across 8 service(s) against HEAD 30c2adcf258c`. UPDATE for 30c2adcf258c: the verified code commit is now `30c2adcf258c`; the measured check above was re-run - `git diff --name-only 30c2adcf258c..HEAD -- src tests` is empty (HEAD == 30c2adcf258c when the records were written), and the deployment gate's own output names that commit. UPDATE for 30c2adcf258c: the verified code commit is now `30c2adcf258c`; the measured check above was re-run - `git diff --name-only 30c2adcf258c..HEAD -- src tests` is empty (HEAD == 30c2adcf258c when the records were written), and the deployment gate's own output names that commit. UPDATE: the verified CODE commit is STILL `30c2adcf258c` - the commits after it are documentation and records only, and that is proven rather than asserted: `git diff --name-only 30c2adcf258c..1f82e634b4ed -- src tests` is EMPTY, so the gates and the suites that ran on 30c2adcf258c apply to this tree unchanged. HEAD is 1f82e634b4ed.
- **structure_status：`IN_PROGRESS`**
- **capability_status：`UNVERIFIED`**

### 读取指引：本文件的哪一部分代表**当前**状态

- **权威内容＝`step_records` + 最新的 `final_state_*` 对象（当前是 `final_state_round_121_p33f2`，由 `authoritative_final_state` 指定）。**
- 渲染器改写于 round 100：它过去按**字符串**排序挑最新对象，于是 `round_100` 排在 `round_97` **之前**，文档因此写着「还没有任何 P3.3 切片搬迁」而实际已搬两个。现在改为：显式指针 `authoritative_final_state` → （其次）`head_sha` 与被核验提交一致的对象 → （最后）**按数字**排序。
- 其余一切 `final_state_round_*` 都是**历史**（每个都带 `superseded_by` 指向最新对象）；它们的 `what_a_successor_must_do_first` 可能点名早已完成的工作，**不要照它执行**。
- 已经刷新为当前值的段落：`import_graph`、`deployment`、`worktree`（各自带 `measured_at_commit`）。
- **保留但属于历史**的段落（不删除，以免丢失 Phase 0/1 的证据链）：`p0_6_progress`、`ghidra_worker_blocker`（已标注 `_resolved`）、`behavior_probe`、`baseline`、`legacy_import_callers`、`phase_0`/`phase_1`/`phase_2` 的细节、`audit_findings_round_*`、`reverted_steps`。
- 结构状态与能力状态是两个轴：`structure_status` 反映本方案，`capability_status` 反映 Ghidra B3/C3 能力项；**结构 READY 不得推出能力 ACCEPTED**。

## 一、为什么不是 READY / ACCEPTED

Plan section P5 grants `structure_status=READY` only after P2-P4 are complete. Phases 0, 1 and 2 are COMPLETE; PHASE 3 IS IN PROGRESS. P3.1/P3.2 COMPLETE; P3.3 has four slices (b/a/c/d), P3.3c(2), three layer items, **P3.3e COMPLETE**, the P3.3f DESIGN, **P3.3f-1 COMPLETE** (the sink) and now **P3.3f-2 COMPLETE: THE LOOP MOVED** (3,523 lines with its 20 helpers behind a 42-member measured host pin). `service.py` is at 20,478 lines, down from 29,640 when Phase 3 began. NEXT: P3.3c(2)-style leftovers are gone, so the remaining structural work is **P3.4-P3.7** (the facade, the remaining coordinators and the test-surface migration) and then Phases 4 and 5. P3.3b(2) and P3.3d(2) remain layer-blocked on `report/` and `methodology` helpers being sunk first.

UNCHANGED and untouched by this plan: capability acceptance is measured on the analyst-facing behaviours, not on structure. The Ghidra B3/C3 capability items (T4 route B2, T8, T3, T6, T7, the diagnostic channel, undeclared truncation) are still open, and `structure_status=READY` must never be read as implying `capability_status=ACCEPTED`.

## 二、阶段状态

| 阶段 | 状态 |
|---|---|
| phase_0 | COMPLETE (P0.1-P0.6, plus repairs P0.3-r2/r3 and P0.5-r2/r3) |
| phase_1 | COMPLETE (P1.1-P1.4, plus repairs P1.1-r2 and P1.3-r3) |
| phase_2 | COMPLETE - 9 packages, 34 moved paths, report/ complete, 7 investigation siblings moved, 3 task modules moved, duplicate list empty, cycle allowlist empty |
| phase_3 | IN PROGRESS - P3.1/P3.2 COMPLETE. P3.3: four slices (P3.3b/a/c/d) + P3.3c(2) + three layer items + P3.3e COMPLETE (the 2,787-line giant) + P3.3f COMPLETE (the 3,523-line loop, its 20 helpers, a 42-member measured host pin). service.py 29,640 -> 20,478. NEXT: P3.4-P3.7 (the facade, the remaining coordinators, the test-surface migration), then P4 and P5; P3.3b(2)/P3.3d(2) remain layer-blocked. |
| phase_4 | NOT STARTED (remove shims, one checkpoint each, then converge the root package's exports) |
| phase_5 | NOT STARTED (re-verification; the DSH suite has never been run in this session) |

## 三、机械条件（P5.1）

PASS - 128 files per service across 8 services, missing=0 differing=0 container-only=0, import smoke 56 enumerated modules per service, 11 containers running

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

1. **P3.4-P3.7 are the remaining STRUCTURAL steps** (the plan's list: P3.4 `ReportRevisionWriter`, P3.5 `EmulationCoordinator`, P3.6 `WorkbenchQueryReader`, P3.7 the test surface from private/`getsource` to behavioural assertions), then P4.1-P4.4 (migrate the remaining callers, delete the shims one checkpoint at a time, converge the root package's exports) and P5.1-P5.5 (re-verification, with the image hash equal to HEAD or an explicit `STRUCTURE_READY_LOCAL / DEPLOYMENT_BLOCKED`, the DSH suite run separately, and the capability matrix reported separately).
2. **BEFORE THE NEXT MOVE, ADD THE DELEGATION-SHAPE CHECK THE TOOLING STILL LACKS.** Two rounds have now been bitten by generated delegations (a wrong receiver name in P3.2e, dropped `*args, **kwargs` here), because the import guard and the arity stop inspect moved bodies and the target, not the wrapper left in `service.py`. The check is small: every delegation must forward every parameter of its own signature.
3. **HARD GATES FOR EVERY SLICE - a slice missing any of these is NOT complete: 1. `py scripts/check-slice-tooling.py` (+ `--self-check`); 2. the tool's own can-fail proof against a deliberately damaged subject, whose tamper must be ASSERTED TO HAVE LANDED, restoring every file byte-for-byte; 3. focused tests on the slice's own contract files; 4. the FULL suite; 5. `py scripts/check-deployed-code-hashes.py --strict --import-smoke` after a rebuild if `src/` changed; 6. failure-set comparison by NODE SET, never by count; 7. commit, then confirm `git rev-parse HEAD` == `git rev-parse origin/main`.**

## 七、已记录、但**不得**在结构步骤里修的行为缺陷

- the compose gate accepts a draft that keeps the operational-limitation HEADING and drops every bullet (analyst_report.py:6123 is a heading substring test) - recorded in the P0.5 probe and pinned by a test
- `is_real_simulation_row` returns True for DISABLED_BY_POLICY and NO_GRANTED_WINDOW while `emulation.policy._POLICY_OR_PLACEHOLDER_STATUSES` (moved there by P3.3 layer item 2; `simulation_adapters` re-exports it) treats both as non-observed
- `_mechanism_catalog_id` is called with a Mapping at two sites while the live definition takes a scalar, so the 'recovered' branch of `_topic_status` can never fire and mechanism labels lose the catalog title
- LINE-ENDING DRIFT (MEASURED in round 79/80, pre-existing and repo-wide): `core.autocrlf=true` with no `.gitattributes`, so `git ls-files --eol src` reports 74 tracked files `i/lf w/lf` and 23 `i/lf w/crlf`. A fresh checkout materialises the first group as CRLF, therefore git status is BLIND to line-ending differences between the worktree and HEAD, and `scripts/check-deployed-code-hashes.py`'s clean-tree note ("src/ clean, so the tree IS HEAD") is not byte-true; plan 5.1's condition is byte-oriented. The gate's EVIDENCE stays valid because `host_hashes()` reads the working tree and the images are built from that same tree, but a byte-exact HEAD comparison does not exist today. Fixing it rewrites ~74 files and needs a rebuild plus re-verification, so it is a work item of its own - measured, not silently normalised inside a structural step. RE-MEASURED in round 97: `git ls-files --eol src` now reports 101 files `i/lf w/lf`, 19 `i/lf w/crlf` and 1 `i/none w/none` (121 tracked src files in total, matching the deployment gate's file count), because the tree has grown by package `__init__`/facade files since round 79/80. The defect is unchanged in kind: the gate reads the WORKING TREE, so its evidence stays valid, but a byte-exact HEAD comparison still does not exist.

## 八、方案级冲突（及其裁决）

- **static-name-collision**（blocked P2-S）：**RESOLVED (round 71, commit 65b86ac)** — The ASSET directory was renamed `static/` -> `assets/` and the mount URL was kept as `/static`, so every browser-visible URL is unchanged. The package name the plan wants is left free.
- **investigation-and-intake-self-shadow**（blocked P2-V and P2-I）：**RESOLVED AND IMPLEMENTED (P2-I for intake, P2-V.0 + P2-V for investigation)** — A module -> package move needs a LAZY facade (PEP 562 `__getattr__`) - implemented ONCE as the shared mechanism in `src/threat_report_agent/package_facade.py` - and `investigation` additionally needed one shared predicate group moved down into `facts/thread_start.py` first. Both halves are now in the tree and verified on the DEPLOYED images, not only in the copy simulation that chose the recipe.
