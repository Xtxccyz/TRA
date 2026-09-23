# P3.3 `InvestigationCoordinator` 设计记录（round 97，实测先行）

> 本文件记录计划 §8「P3.3 抽出 `InvestigationCoordinator`」的**实测边界**、**端口策略**、**切片顺序**与**验证方案**。
> 计划 P3.3 的定义是：「迁移：调查循环、Action Proposal 验证、账本更新、饱和和尾扫；编排器仍掌握图」。
> 与 P3.2 一样，**先测量再设计**：P3.2 的测量（6 成员端口、`SubmissionResult` 返回类型、必须拆出的一个簇）
> 直接改变了那一步的范围；P3.3 的测量同样改变结论——**它不是一个簇**。
>
> 可复现：`py .scratch/p33-inventory.py`（全片段扫描，输出存 `.scratch/p33-inventory.txt`）与
> `py .scratch/p33-slices.py`（逐切片实测行数、端口需求与**逐条对账**，输出存 `.scratch/p33-slices.txt`）。
> 本文件里**每一个数字**都来自这两个脚本；我第一版曾凭印象写下 ~236 / ~260 两个估计值，实测是 409 / 327，
> 已按实测改正——设计记录里的估计值就是下一步的错误来源。

## 1. 实测：P3.3 的表面比 P3.2 大 14 倍，而且不是单个簇

| 事实 | P3.2（已完成） | P3.3（本步实测） |
|---|---|---|
| 候选成员 | 19 | **53** |
| 候选行数 | 585 | **8,881** |
| 直接端口面 | 6 | **20** |
| helper 闭包 | 18 成员 / 1,040 行 | **71 成员 / 3,059 行** |
| 随簇搬迁的 exclusive helper | 1 / 90 行 | **27 / 746 行** |
| 搬迁上限 | 675 行 | **≈9,600 行** |

**两个方法占了候选集的 71%**：

| 方法 | 行数 |
|---|---|
| `_run_investigation_loop` | **3,523** |
| `_derive_investigation_observations` | **2,795** |
| 其余 51 个成员合计 | 2,563 |

其余较大的成员：`_run_methodology_action` 271、`workbench_submit_action` 258、`_build_investigation_frontier` 213、
`_collect_model_action_results` 151、`_grounded_planner_action_candidates` 136、`_build_convergence_alternate` 111、
`_semantic_action_result` 103、`_persist_evidence_delivery_ledger` 97。

## 2. 边界决定（实测驱动，**不是**把 53 个成员一次搬走）

用 P3.3 的片段扫出来的 53 个成员里，有 7 个**不属于 P3.3**，把它们并进来会吞掉后面两步的接缝：

| 成员 | 行数 | 归属 | 实测理由 |
|---|---|---|---|
| `workbench_submit_action` | 258 | **P3.6** `WorkbenchQueryReader` | 名字与职责都是 workbench 的公开动作/查询面 |
| `workbench_dispatch_analysis_intent` | 81 | **P3.6** | 同上；其 spine 是 5 个 `workbench_*` 操作 |
| `workbench_thread` | 46 | **P3.6** | 只读线程视图 |
| `workbench_action` | 40 | **P3.6** | 只读动作视图 |
| `workbench_submit_session_action` | 18 | **P3.6** | 会话级动作，走 `workbench_analysis_context_v3` |
| `workbench_action_for_task` | 9 | **P3.6** | 只读 |
| `_refresh_report_after_investigation` | 43 | **P3.4** `ReportRevisionWriter` | 其 spine 是 `_create_report_revision` / `_freeze_snapshot` / `_materialize_mechanism_snapshot`，正是 P3.4 的三个核心动作 |

**因此 P3.3 的范围是 46 个成员 / 8,386 行**（8,881 − 495），并把上面 7 个**显式排除并记录**，避免「按名字扫出来的都属于我」
这种跨步吞并。这条边界是设计记录存在的首要理由：不做这一步决定，P3.3 会把 P3.4/P3.6 一起吃掉。

**逐条对账（实测，`py .scratch/p33-slices.py`）**：片段扫出 53 个成员 / 8,881 行 =
已分配到切片的 30 个 / **7,724** 行 + 排除给 P3.4/P3.6 的 7 个 / **495** 行 + **未分配的 15 个 / 660 行** +
已搬迁的 1 个（`_deferred_budget_thread_ids`）/ 2 行。和恰好等于 8,881，没有对不上的成员。

**未分配的 15 个 / 660 行必须显式处理**（最大的几个）：`_collect_model_action_results` 151、
`_semantic_action_result` 103、`_follow_local_tail_jmp` 72、`_workbench_action_provenance` 72、
`_persist_time_unique_thread_result` 66、`_load_investigation_execution_rows` 48、
`_persist_ready_emulation_actions` 47、`_overlay_pe_parser_thread_start` 40，其余 7 个合计 61 行。
它们要么在某切片搬迁时被实测证明是 **exclusive helper**（随之搬迁），要么自成一个切片，要么按上面的边界规则
划给别的步骤——**不允许在 P3.3 收尾时无人认领**。`_follow_local_tail_jmp` 与 `_overlay_pe_parser_thread_start`
名字上属于「尾扫/线程」面（P3.3b 的近亲），`_workbench_action_provenance` 名字上属于 P3.6，但这只是线索，
**归属要在对应切片实测之后再定**，不在此刻猜。

## 3. 端口策略：**按切片扩端口**，不预先声明 20 个成员

P3.2-design 一次把 6 个成员全声明出来，是因为测量显示那 6 个就是全集且整个 P3.2 只用到它们。
P3.3 **不能**照做：20 个直接端口面里包含上面那些**属于 P3.4/P3.6 的**成员，预先声明等于把边界决定写反。

所以 P3.3 采用 **P3.2g 已证明可行的「按切片扩大」** 模式：

* 新模块 `src/threat_report_agent/investigation/coordinator.py`，协议名 `InvestigationHost`；
* 每个切片只把**该切片实测需要的**成员加入 `INVESTIGATION_HOST_MEMBERS` 并同步声明到协议；
* 契约测试沿用 P3.2 的**双向断言**（`remaining ⊆ port` 且 `remaining ∪ used_by_moved_code == port`），
  因此「端口里有没人用的成员」与「切片用了端口外的东西」都会先失败。

`database`（74 个外部使用者）、`_audit`（47）、`settings`（32）、`content_store`（23）几乎必然出现在每个切片里；
`methodology_library`、`_canonical_json`、`_link_claim_evidence` 等是方法级依赖，逐切片加入。

## 4. 切片顺序（由小到大；**两个巨方法排最后**）

| 顺序 | 切片 | 成员 | 行数（实测） | 实测端口需求（相对 P3.3 其余部分） |
|---|---|---|---|---|
| **P3.3a** | 账本（ledger） | `_persist_evidence_delivery_ledger`, `_finalize_tail_ledger`, `_park_open_ledger`, `_work_ledger`, `_ledger_ids` | **156** | `_audit`（+ 全局的 `database`） |
| P3.3b | 前端/线程辅助 | `_build_investigation_frontier`, `_convergence_frontier_fingerprint`, `_frontier_value_present`, `_unattempted_seed_thread_ids`, `_is_unique_thread_seed_row`, `_select_unique_thread_seed_rows`, `_unique_thread_start_keys`, `_unique_execution_threads_for_view` | **409** | **无**（切片内自洽，只需 `database`） |
| P3.3c | Action Proposal 验证与选择 | `_grounded_planner_action_candidates`, `_action_payload`, `_model_action_plan`, `_has_complete_model_action_plan`, `_merge_planned_actions`, `_deterministic_action_plan`, `_action_is_model_or_human`, `_planner_user_action`, `_bound_completed_actions` | **327** | **无**（只需 `database`） |
| P3.3d | 方法论动作与收敛合同 | `_run_methodology_action`, `_convergence_failure_contract`, `_build_convergence_alternate`, `_convergence_completed_fields`, `_convergence_alternate_type`, `_convergence_method_id` | **514** | `_audit`, `_is_reference_isolated_blind`, `_link_claim_evidence`（+ `database`, `methodology_library`） |
| P3.3e | 观测派生 | `_derive_investigation_observations` | **2,795** | `_emulation_entry_key`, `_function_entry_integers`, `_investigation_value_text`, `_overlay_pe_parser_thread_start`（+ `settings`） |
| P3.3f | 调查循环本体 | `_run_investigation_loop` | **3,523** | `_audit`, `_canonical_json`, `_investigation_value_text`, `_is_task_cancelled`, `_link_claim_evidence`, `_persist_pma_static_analysis_plan`（+ `content_store`, `database`, `settings`） |

P3.3b 与 P3.3c 的端口需求实测为**空**，这是本设计里最有用的两个数字：它们是完全自洽的切片，
可以独立搬迁而不扩大端口，因此应当先做——这也是 P3.2 的顺序原则（先搬不需要扩端口的簇）。

**为什么两个巨方法必须最后**：它们不是「大一点的簇」，而是**单个 3,523 / 2,795 行的方法**。
一次搬迁的失败面是整段调查循环；而 P3.2 的成功恰恰来自「每步只搬几十到几百行、每步都能逐字节证明」。
先把周围 5 个切片搬干净，会让两个巨方法**剩下的依赖面变小、变明确**，届时再决定是整体搬迁还是先切内部接缝。

## 5. 每切片的验证（与 P3.2 同标准，另加 P3.3 特有的行为断言）

复用 P3.2 已脚本化的流程：`.scratch/p32-measure-cluster.py`（簇前测量，注意它当前只认 `AnalysisService`）、
`p32-extract-cluster.py`、`p32-verify-cluster.py --from <搬迁前 revision>`、`p32-canfail-cluster.py`；
外加四道门禁（导入图 `--strict`、结构 diff `--all --strict`、行为探针、部署 `--strict --import-smoke`）与全量失败**节点集合**比对。

P3.3 特有的**行为**成功标准（计划原文，必须由 contract test 覆盖，不能只靠「体逐字节相同」）：

1. **模型不能直接改变预算/权限**——模型只能提出 Action Proposal，预算与权限由编排器裁决；
2. **terminal 之后不能再 dispatch**（STOP_DISPATCH）；
3. 结构迁移**不改变**现有预算与 limitation 投影；硬预算耗尽是否补齐具体 limitation 属于**独立行为任务**，
   不得在结构步骤里被隐藏（继续留在 `known_behavior_gaps`）。

这三条要在切片搬完后用**输入/输出行为断言**钉住（P3.7 的目标形态），而不是 `inspect.getsource`。

## 6. 本步明确不做（记录，而非顺手改）

- **不**把 `workbench_*`（P3.6）与 `_refresh_report_after_investigation`（P3.4）并入 P3.3；
- **不**在一次检查点里搬两个巨方法；
- **不**为 P3.3 预先声明 20 个端口成员；
- **不**在结构步骤里修「硬预算耗尽时的 limitation 缺口」（独立行为任务）；
- **不**动 `investigation/` 现有 9 个模块的公开面（P3.3 只新增 `coordinator.py`）。
