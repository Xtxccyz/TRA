# 结构优化执行状态（方案 `code-structure-optimization-execution-plan-reviewed-20260922.md`）

> 本文件由 `.scratch/structure-status.json` **程序化生成**（`.scratch/render-structure-status.py`）。`.scratch/` 被 gitignore，因此把最终状态在此留一份被跟踪的记录。逐步骤的完整字段（allowed_files / commands / focused_result / full_result / new_failures / import_graph / module_identity / deployment_smoke / behavior_probe_diff / rollback_point / decision）在 `step_records`，共 118 条，本文件只汇总。

- **被核验的树 = 提交 `7ecb6b49d3c598cf82a5a6e4d746187f94eb1813`**（该提交的 tree 上跑过四道门禁与全量套件）
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

Plan P5 grants `structure_status=READY` only after P2-P4 are complete. MEASURED STATE: **Phases 0/1/2 COMPLETE**; **P3.1-P3.4 COMPLETE**; **P3.5-0 COMPLETE except D-3's MOVE** (M-1, M-2, M-3, M-4, M-5 all landed; D-1 decided and registered; D-2 landed with the executor injected through the port and the R2 decision implemented; D-3 renamed publicly and aliased in place, but the worklist row also required the MOVE to the contract layer, which M-1 has now made feasible and which remains OWED); **P3.5 BLOCKED** by plan conflict 3; **P3.6-1 and P3.6-2 COMPLETE** (P3.6-2 landed with the payload byte-identical and a 5/5 can-fail; its two OPTIONAL leftovers remain: the `task_view` key-set assertion was added by this session, the capability-key-set assertion was NOT); **P3.7 COMPLETE for the `getsource` half (39 -> 2 calls) and BLOCKED-ON-FACADE for the direct-call half** (nine direct private calls were ADDED by the conversion, one plan site survives at `tests/test_investigation_recovery_loop.py:68`, and the six phase drivers the added sites call have NO public entry point); **P4.0 COMPLETE** (`legacy_path_imports` EMPTY) and the Phase 4 shim deletions are GATED on Phase 2/3 completion plus synced images; **P5** has the deployment half VERIFIED and the DSH half MEASURED (4/8 scripts pass, causes recorded) but NOT PASSING. OPEN DEFECTS THAT ARE NOT PLAN STEPS: the import gate cannot police an unregistered EDGE (measured twice, on an addition and on a removal); the P1.4 private-reach metric under-counts by ~40x (1 vs 41); several `ports.py` docstring line citations predate a 29k-line `service.py` and point past EOF.

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

PASS at f5d62fa243a6: 131 files x 8 services, `ALL DEPLOYED MODULES MATCH src/`, and `import smoke OK` for every service. Both image routes rebuilt from this commit. Re-owed by any later `src/` change.

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

1. **M-1 IS LANDED AND VERIFIED** (the 10-name investigation-action contract cluster, plus 7 closure-forced definitions, now in `contracts.py` with `X as X` re-exports; the two `test_ports.py` line pins moved 142 -> 146 with the measured cause). Its move is the precedent to follow for M-3/M-4: the mover must anchor the re-export at the END OF THE LEADING IMPORT BLOCK, not at the file's last import - M-1's record measured that anchoring on the last import would have left a class-level default (`CATALOG_SELECTOR_KEYS`) unresolved ~600 lines above it and raised NameError at import time.
2. **M-3 IS LANDED AND VERIFIED** (`TaskLifecycle`/`InvalidStateTransition`/`TASK_TRANSITIONS`/`transition_task` in `contracts.py`, re-exported; `AnalysisClass` and the five other StrEnums stayed). Next sinks from the P3.5-0 worklist: **M-4** (`fill_protocol` -> `contracts.py` or `facts/`) and **D-2** (`ToolExecutionPort` + an injected executor). Follow the two precedents: anchor the re-export at the END OF THE LEADING IMPORT BLOCK, and assert the negative half (nothing beyond the named cluster moved).
3. **M-4 IS LANDED AND VERIFIED** (the `fill_protocol` cluster, 12 definitions / 244 lines, now in the NEW pure `facts/investigation_protocol.py` with six public names re-exported from the old path and the `function_call_names` home pin updated deliberately). P3.5-0's remaining items are **D-2** (`ToolExecutionPort` + an injected executor) and **D-3** (make `_scoped_investigation_action_key` public); M-1 through M-5 are all done. Two measured lessons to reuse: the closure is always bigger than the prep doc's estimate (241 not ~130; 17 definitions not 10 in M-1), and a private helper shared with a definition that stays forces either a bigger move or a cross-module private reach.
4. **D-3 IS LANDED AND VERIFIED** (`scoped_investigation_action_key` public, private alias in place, three callers migrated; 2 cross-module private reaches removed, 0 introduced). **P3.5-0 is now complete except D-2** (`ToolExecutionPort` + an injected executor). WHILE DOING D-2, do not trust `private_reach_total`: it reports 1 while the measured count is 39 (`py .scratch/p35-d3-private-reach.py`), so a D-2 that removes private reaches will move it by zero, and a D-2 that ADDS one would be invisible to it too.
5. **P3.6-2 IS LANDED AND VERIFIED** (`workbench_capabilities` in `workbench_query.py` behind a delegation, pin 14, payload byte-identical, can-fail 5/5). Its optional leftovers are real debts: the `task_view` key-set assertion and the capability-key-set assertion were NOT added, and the deployment gate is re-owed because this step changed `src/`.
6. **D-2 IS LANDED AND VERIFIED** (tool execution through `ToolExecutionPort`, `cancel(workflow_id)` per R2, host-pin replaced not widened, new tracked contract file with 7 tests, can-fail 5/5; the executing agent DIED mid-step and the parent finished the verification). **P3.5-0 is now complete except D-3's MOVE** (the rename landed, the move to the contract layer did not) - and the deployment gate is RE-OWED by this step: rebuild both image routes, then `check-deployed-code-hashes.py --strict --import-smoke`.
7. **P3.7'S FACADE IS STARTED: the six PHASE DRIVERS now have public entry points and their 46 test call sites use them** (contract file `tests/test_p37_behaviour_entry_points.py`, can-fail 6/6). The direct-call half is NOT complete: ~335 sites over ~102 other private members remain, and the way to continue is the same shape - pick the next member cluster, give it a public behaviour entry point, migrate its call sites, and let the completeness assertion in that file hold the line. Re-measure with `py .scratch/p37-driver-sites.py`.
8. **P3.7's FACADE COVERS FOURTEEN MEMBERS NOW** (six phase drivers + eight plain methods; contract file at 29 tests). MEASURED REMAINDER: 130 distinct private members and 353 call sites, of which only 38 are plain methods - so the next step for this half is a DESIGN one: public entry points for the class/static methods (`_persist_time_seed_result`, `_select_report_evidence_rows`, `_persist_how_claim_specs`, `_select_ghidra_function_rows`, `_simulation_covers_request`, `_stamp_persist_how_snapshot`, `_failed_tool_run_limitations`, `_gate_for_seed_playbook` - 85 sites) and for the members that belong to other classes (21 sites on `_execute` alone). Re-measure with `py .scratch/p37-next-batch.py`.
9. **P3.7 BATCH 4 FAILED AND WAS REVERTED; RETRY IT WITH A FIXED SPLICER.** The receiver-aware rule is VALIDATED (`.scratch/p37-batch4.py` dry run: 13 service-receiver sites migrated, 5 foreign receivers correctly skipped), but its text-splicing helper mixed `ast` LINE numbers with COLUMN offsets, so it garbled three test files; `ast.parse` stopped it and `.scratch/p37-restore.py` restored them byte-exact. Re-do it the safe way: build EVERY file's new text, validate all of them, and only then write anything - and prefer replacing whole LINE ranges (the batch-2 generator's approach, which worked) over column arithmetic.
10. **P3.7 BATCH 4 SUCCEEDED ON RETRY** (four class/static members, 13 service-receiver sites, contract file at 53 tests, can-fail coverage intact). The generator that works is `.scratch/p37-batch4b.py`: build every file in memory, validate all, write last, and migrate with a receiver-aware regex cross-checked against an AST count. MEASURED REMAINDER: 120 members / 265 call sites, mostly class/static members and members of other objects.
11. **M-2 IS LANDED AND VERIFIED** (`PackageEntry` -> `contracts.py`, both `test_ports.py` line pins updated 141 -> 142 with the measured reason): node set back to baseline 6 + 2 Docker-blocked. Continue P3.5-0 with the remaining sinks (M-1's 10 definitions, M-3's `TaskLifecycle` cluster, M-4's `fill_protocol`, D-1, D-2).
12. **THE §5.4 VIEW KEY-SET DEBT IS DISCHARGED AND NOW HAS A CAN-FAIL - do not rewrite it.** `REQUIRED_VIEW_KEYS` (13 keys, superset check) already existed in `tests/test_investigation_service.py`; this round proved its power with nine branches (`.scratch/p36-viewkeys-canfail.py`), closed the coverage hole it structurally cannot see (the `sample_timeline` projection is now content-pinned), and added the key set for the OTHER view the slice owns (`REQUIRED_TASK_VIEW_KEYS`, 33 keys, runtime-measured). Nothing to redo here.
13. **P3.6-2 IS ONE STEP with a measured shape and a gate blind spot** (`docs/p36-capability-slice-design-20260922.md`): `workbench_capabilities` = `service.py:17264-17368` (105 lines, closure 195, ZERO write calls in 47 calls); host pin 11 -> 14 (`THREAT_CONTEXT_PROTOCOL`, `THREAT_TOOL_CONTRACT_VERSION`, `_analysis_planner_payload`); 1 production call site (`main.py:789`) that must keep working through a HOST DELEGATION, not a facade. BEFORE CODING, decide how the catalog arrives: importing `ActionCatalog` from `investigation/investigation.py` lands a reverse edge that the import gate CANNOT see (`forbidden_edges` is a flat-name deny-list with no `workbench_query` source entry and node-only registration), so prefer passing the catalog in from the delegation, or add `recorded_allowed_edges` plus a tracked negative assertion and prove it with the tamper the design specifies.
14. **Two smaller P3.7 gaps the same review measured**: (a) `tests/test_static_simulation_budget.py` lost one of its two call-site guards (`_derive_investigation_observations` is no longer pinned by any test); (b) two added tests have zero discriminating power (`test_analysis_task_orchestration.py:460-471`, `test_function_similarity_cost.py:208-210`). And the P1.4 `reaching_a_private_member` metric should be widened to count BARE private imports, or the plan's 18-site list must be tracked separately - today it reports 0 while a plan site survives.
15. **THE IMPORT GATE'S BLIND SPOT IS NOW REPRODUCED ON A REAL MOVE** (P3.6-2's can-fail T4): adding and USING `from threat_report_agent.investigation.investigation import ActionCatalog` in `workbench_query.py` leaves `check-import-graph.py --strict` at exit 0 with `STRICT: no new cycles and no new reverse edges`. Two steps have now measured this independently (D-1 from the registration side, P3.6-2 from the deny-list side) and P3.6-2 had to route around it. Fix it as its own step: encode section 3.2 as an allow-list so `--strict` fails on ANY unregistered edge, with the can-fail the design specifies.
16. **THE P1.4 METRIC NEEDS FIXING, WITH THE COUNTER THAT ALREADY EXISTS**: `.scratch/p35-d3-private-reach.py` counts every `from <other module> import _private_name` edge inside the package (41 at M-4/HEAD, 39 after D-3) while `check-structure-diff.py`'s `private_reach_total` reports 1. Either widen the gate to this definition of a private reach or record the metric's limitation where the gate prints it - a metric that moves by zero when the defect is fixed is worse than no metric, because it reads as evidence.
17. **THE DEPLOYMENT GATE IS NOW OWED BY FOUR STEPS THAT CHANGED `src/`** (M-2, M-1, M-3, M-4) and it is the only thing between the current state and `STRUCTURE_READY`: `.scratch/rebuild-and-deploy-gate.py` runs the strict gate BEFORE and AFTER rebuilding both image routes (`docker compose build api emu-worker`, then `scripts/build-ghidra-worker.ps1` with `DEBIAN_MIRROR`, then `docker compose up -d`, then `--strict`). Never report a local pytest pass as deployment evidence - the gate's own docstring says a missing or mismatched file is a MISMATCH and unavailable Docker is BLOCKED.
18. **ADD `ruff` TO THE GATE BATTERY, OR THE RECORDED BASELINE STAYS A LIE**: M-1 introduced a genuine ruff F402 into `contracts.py` and every recorded gate passed with it present; it was found only because M-3 happened to lint the files it touched. The measured baseline is now 5 in `service.py` plus 10 elsewhere, all in files the round never touched (`simulation_adapters.py` 3, `model/model_gateway.py` 3, `static/static_analysis.py` 1, `static/literal_table.py` 1, `report/analyst_report.py` 1, `investigation/investigation.py` 1 deliberate E402). A future step should record that set as the baseline and run `ruff check src/threat_report_agent/` as a gate so a new error fails the step instead of accumulating.
19. **WHEN DOCKER RETURNS, CLOSE THE OWED EVIDENCE FIRST** - it is now owed by a step that changed `src/`: re-run the two blocked nodes, re-compare the failure NODE SET, rebuild BOTH image routes and run the deployment gate. Until then the honest state is `STRUCTURE_READY_LOCAL / DEPLOYMENT_BLOCKED` at best, never READY.
20. **APPEND THE STANDARDS-AXIS FINDINGS for the P3.7 diff** (fixed point 9ae5f609); the Spec axis has already run and its four gaps are recorded in the round's step record.
21. **EDGE REGISTRATION IS NOT ENFORCED, and two steps have now measured it** (`scripts/check-import-graph.py:281` reads `recorded_allowed_edges` only to register NODES; 258 runtime edges vs 4 recorded entries, `--strict` green either way). Measured independently by D-1 (`docs/decision-d1-emulation-imports-models-20260922.md` section 4) and by P3.6-2's design (`docs/p36-capability-slice-design-20260922.md` section 6.3/8.1). The fix is ONE step: encode section 3.2's matrix as an allow-list so `--strict` fails on any unregistered edge, with the can-fail that adds `from threat_report_agent.investigation.investigation import ActionCatalog` to `workbench_query.py` and requires rejection. Until it exists, an unlisted edge is invisible to every gate.
22. **P3.7'S REMAINING HALF (direct private calls -> concept-level public functions or an HTTP facade)**: nine were ADDED by the conversion, at `test_controlled_emulation.py:1240,2058`, `test_investigation_recovery_loop.py:374`, `test_investigation_service.py`, `test_analysis_task_orchestration.py:600`, `test_function_similarity_cost.py:126`, `test_speakeasy_reachability.py:148`, `test_pe_entry_function_budget.py:1776`, `test_static_simulation_budget.py`. Also convert the one surviving plan site (`test_investigation_recovery_loop.py:68`, PRESENCE) and decide whether the P1.4 `reaching_a_private_member` metric should count moved-module targets too, since today it keys only on `AnalysisService._` and therefore reports 0 while a plan site survives.
23. **THEN the owed two-axis review of the P3.7 diff** (fixed point: the commit before this round's records commit; the diff spans 15 test files, +6 tests and the `docs/structure-surface.json` re-record of `test_getsource_count` 39/17 -> 2/0).
24. **THE OBJECTIVE IS NOT COMPLETE AND THE ROUNDS ARE EXHAUSTED.** Five workstreams remain (listed in `why_not_READY`); the two largest - the shared preparation step and P3.7's 17 sites - each need multiple rounds with the full gate battery. Do NOT start either unless it can be finished and verified in the round; a half-moved slice leaves the tree in a state the next author cannot tell apart from a regression.
25. **THE PREPARATION STEP'S SHAPE IS PRESCRIBED IN THE P3.5 DESIGN'S SECTION 5** and its scope note must name `contracts.py`, `ports.py` and `investigation/**` as out-of-whitelist files it touches deliberately.
26. **HARD GATES FOR EVERY SLICE**: slice-tooling; the data-driven can-fail proof (never concurrent with the suite); compileall; the scope gate; the strict import graph; `docker compose config`/`ps` with BLOCKED classification and no skipped `ghidra-worker`; focused -> full suite -> behaviour probe; failure sets by NODE SET; the deployment gate after rebuilding BOTH image routes, then `HEAD == origin/main`; the tracked contract test's bidirectional pin assertion; the delegation-shape gate (parameters AND `__doc__`); the read-only AST assertion for read-only slices. **AND: never amend an already-pushed commit** (round 127 did; the push refused and the fix was a backup branch plus a re-applied commit - recorded in `git_sync.reason`).
27. **BEFORE MOVING ANY CLASS ATTRIBUTE, GREP EVERY `*_HOST_MEMBERS` TUPLE**: a constant read through another module's host pin is invisible to a `self.`/`cls.` scan of `service.py` and cost 37 broken tests in P3.6-1.
28. **WHAT STILL OWES A RE-RUN WHEN THE ENVIRONMENT RECOVERS** (both were blocked this round and neither is presented as a pass): (1) the two Docker-blocked nodes (`test_detection_rule_indicator_correctness::test_the_verifier_flags_a_self_referential_and_resource_digest_indicator`, `::test_the_verifier_is_quiet_on_a_correct_rule`) plus the node-set re-comparison; (2) the deployment gate, once the Docker engine is back and BOTH image routes are rebuilt. And (3) the push, which is failing on both routes (`ls-remote failed`), so the last two rounds' commits are LOCAL ONLY - the remote is behind and the repository is not in sync until that succeeds.
29. **THE SPEAKEASY VIOLATION IS CLOSED** (recorded in the round's step record, with the measurement and the two-branch can-fail). Do not reopen it; if the assertion is ever touched, keep the module-object import (`svc`) - patching `service` in that test body targets the wrong name and silently measures nothing, which is what cost two attempts.
30. **P3.7'S DIRECT-CALL HALF IS MEASURED AND IS BLOCKED ON THE FACADE**: 372 direct private call sites at the P3.7 base -> 381 at HEAD (108 distinct members; the largest is `_derive_investigation_observations` with 62). The nine ADDED ones call phase drivers/recorders (`_run_investigation_loop`, `_run_post_static_emulation`, `_run_gap_driven_model_rounds`, `_run_controlled_emulator`, `_record_ghidra_evidence`, `_record_function_similarity`) for which NO public entry point exists - so the work is 'design facade methods, then migrate', or it is reported BLOCKED ON THE FACADE. Do not present a partial migration as completing this half. Re-measure with `py .scratch/p37-direct-call-delta.py`.
31. **PHASE 4 IS GATED, NOT JUST PENDING**: the plan allows shim deletion only after Phase 2/3 all pass AND the images are synced. Until then, do NOT delete shims - verified-but-deferred candidates are `mechanism_ready.py` (8 lines, zero importers) and `mechanism_completeness.py` (16 lines, zero importers), and the executor of that step must rewrite any same-commit pin, keep `moved_paths` (it is a normalisation map), and re-run the deployment gate after rebuilding BOTH image routes.
32. **A SUBAGENT CAN DIE MID-STEP, and the artefacts it leaves are not obviously incomplete**: D-2's agent left the source edits, a NEW tracked test file (invisible to `git diff`) and a gitignored can-fail instrument (invisible to `git status`) before failing during the decisive suite, with only a 1,182-byte truncated capture to show for it. When a delegated step's agent does not report, do NOT assume it did nothing and do NOT assume it finished: list the untracked files (`git status --porcelain --untracked-files=all`), check for the gitignored instruments under `.scratch/`, and have `compare-failure-nodes.py` adjudicate the capture (it REFUSES a truncated one).

## 七、已记录、但**不得**在结构步骤里修的行为缺陷

- the compose gate accepts a draft that keeps the operational-limitation HEADING and drops every bullet (analyst_report.py:6123 is a heading substring test) - recorded in the P0.5 probe and pinned by a test
- `is_real_simulation_row` returns True for DISABLED_BY_POLICY and NO_GRANTED_WINDOW while `emulation.policy._POLICY_OR_PLACEHOLDER_STATUSES` (moved there by P3.3 layer item 2; `simulation_adapters` re-exports it) treats both as non-observed
- `_mechanism_catalog_id` is called with a Mapping at two sites while the live definition takes a scalar, so the 'recovered' branch of `_topic_status` can never fire and mechanism labels lose the catalog title
- LINE-ENDING DRIFT (MEASURED in round 79/80, pre-existing and repo-wide): `core.autocrlf=true` with no `.gitattributes`, so `git ls-files --eol src` reports 74 tracked files `i/lf w/lf` and 23 `i/lf w/crlf`. A fresh checkout materialises the first group as CRLF, therefore git status is BLIND to line-ending differences between the worktree and HEAD, and `scripts/check-deployed-code-hashes.py`'s clean-tree note ("src/ clean, so the tree IS HEAD") is not byte-true; plan 5.1's condition is byte-oriented. The gate's EVIDENCE stays valid because `host_hashes()` reads the working tree and the images are built from that same tree, but a byte-exact HEAD comparison does not exist today. Fixing it rewrites ~74 files and needs a rebuild plus re-verification, so it is a work item of its own - measured, not silently normalised inside a structural step. RE-MEASURED in round 97: `git ls-files --eol src` now reports 101 files `i/lf w/lf`, 19 `i/lf w/crlf` and 1 `i/none w/none` (121 tracked src files in total, matching the deployment gate's file count), because the tree has grown by package `__init__`/facade files since round 79/80. The defect is unchanged in kind: the gate reads the WORKING TREE, so its evidence stays valid, but a byte-exact HEAD comparison still does not exist.

## 八、方案级冲突（及其裁决）

- **static-name-collision**（blocked P2-S）：**RESOLVED (round 71, commit 65b86ac)** — The ASSET directory was renamed `static/` -> `assets/` and the mount URL was kept as `/static`, so every browser-visible URL is unchanged. The package name the plan wants is left free.
- **investigation-and-intake-self-shadow**（blocked P2-V and P2-I）：**RESOLVED AND IMPLEMENTED (P2-I for intake, P2-V.0 + P2-V for investigation)** — A module -> package move needs a LAZY facade (PEP 562 `__getattr__`) - implemented ONCE as the shared mechanism in `src/threat_report_agent/package_facade.py` - and `investigation` additionally needed one shared predicate group moved down into `facts/thread_start.py` first. Both halves are now in the tree and verified on the DEPLOYED images, not only in the copy simulation that chose the recipe.
- **conflict-3-emulation-row-cannot-carry-the-coordinator**（blocking）：**OPEN - blocks P3.5; P3.5 may only be reported BLOCKED until it is resolved** — (a) RECOMMENDED - hoist those contracts into `contracts.py` (or expose them through `ports.py`) with `X as X` re-exports at every old path, take tool execution through `ToolExecutionPort` with the concrete `TemporalToolExecutor` INJECTED, sink `TaskLifecycle`/`PackageEntry` into `contracts.py`, and record the `emulation.coordinator -> models` edge as a decision (the decision-(e) mechanism). Every row of section 3.2 admits `contracts`, and this completes the types P1.1/P1.2 left behind. (b) Alternatively, widen the `emulation/` row by an explicit plan decision and say so in the plan file.
