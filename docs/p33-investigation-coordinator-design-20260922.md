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
| **P3.3a** ✅ | 账本（ledger） | `_persist_evidence_delivery_ledger`, `_finalize_tail_ledger`, `_park_open_ledger`, `_work_ledger`, `_ledger_ids` | **156** | `database` + `_audit`（**已完成**，见第 12 节） |
| **P3.3b** ✅ | 前端辅助 | `_build_investigation_frontier`, `_convergence_frontier_fingerprint`, `_frontier_value_present`, `_unattempted_seed_thread_ids`, `_mechanism_missing_fields`（+ 两个模块级谓词与其 frozenset） | **312 + 15** | `database`（**1 个**，实测；见第 11 节） |
| ~~P3.3b 原范围~~ → **P3.3b(2)** | 唯一线程族（**受阻**） | `_is_unique_thread_seed_row`, `_unique_thread_start_keys`, `_unique_execution_threads_for_view`, `_select_unique_thread_seed_rows` | **97** | 需要 `report.reporting` → **违反方案 §3.2 允许依赖矩阵**，须先把 `_address_lookup_keys` / `build_unique_execution_threads` 下移到 facts/ 或 static/ 才能搬（第 11 节） |
| **P3.3c** ✅ | Action Proposal 验证与选择 | `_grounded_planner_action_candidates`, `_action_payload`, `_deterministic_action_plan`, `_planner_user_action`, `_bound_completed_actions` | **253** | `_MAX_COMPLETED_ACTION_EVIDENCE_IDS`（**已完成**，见第 13 节） |
| **P3.3c(2)** | 受阻：模型动作计划 | `_model_action_plan`, `_has_complete_model_action_plan`, `_merge_planned_actions`, `_action_is_model_or_human` | **74** | 需要 `DynamicPlanAction`（`model/model_gateway.py`）与 `action_is_model_or_human`（`task/`）——**均为 §3.2 未允许的层**，且后者会成环（见第 13.1 节） |
| **P3.3d** ✅ | 收敛合同 | `_convergence_failure_contract`, `_build_convergence_alternate`, `_convergence_completed_fields`, `_convergence_alternate_type`, `_convergence_method_id` | **243** | `_canonical_json` + 两个**类常量**（**已完成**，见第 14 节） |
| **P3.3d(2)** | 受阻：方法论动作 | `_run_methodology_action` | **271** | **两个阻塞**：`investigation -> methodology` 无先例的未列层边；模块级 `REFERENCE_ISOLATED_FACT_LIBRARY` 与未搬方法共享（见第 14.2 节） |
| **P3.3e** | 观测派生 | `_derive_investigation_observations` | **2,795** | **判定：整体搬迁（3,124 行总账）**；端口 6 → 12；见 `docs/p33ef-giants-decision-20260922.md` |
| **P3.3f** | 调查循环本体 | `_run_investigation_loop` | **3,523** | **判定：受阻于环**（`investigation -> task`）＋ 34 个共享 helper ＋ 13 个被测试导入的模块级项；见同一决策文件 |

P3.3b 与 P3.3c 的端口需求：**P3.3b 实测为「只需 `database`」**（已按此执行）；**P3.3c 起初被同一个工具报成「无」，
但那是工具缺陷**——`_bound_completed_actions` 是通过 `cls.` 读类常量 `_MAX_COMPLETED_ACTION_EVIDENCE_IDS`，
而当时的测量只扫 `self.`。**抓住它的是契约测试**，端口因此有意扩到第 3 个成员（第 13 节）。

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

## 11. P3.3b 执行结果（首个切片；**方案的依赖矩阵否决了三分之一的范围**）

**实际搬迁**：`_build_investigation_frontier`（213）、`_unattempted_seed_thread_ids`（35）、
`_convergence_frontier_fingerprint`（27）、`_frontier_value_present`（25）、`_mechanism_missing_fields`（12）
= **312 行 / 5 个成员**，加两个模块级谓词（`frontier_status_is_open`、`deferred_keeps_planner_open`，15 行）
与其闭合的两个 frozenset。`service.py` 28,898 → 28,568 行；`coordinator.py` 466 行。
9 个搬迁项用 `p33-verify.py` 逐一比对 **IDENTICAL**，can-fail 已证明（见下）。

### 11.1 方案 §3.2 的依赖矩阵否决了 4 个成员的搬迁（这是本步最重要的发现）

片段扫描把 8 个「前端/线程」成员算作同一簇，但实测显示其中 **4 个必须留在宿主**：

| 成员 | 行数 | 实测原因 |
|---|---|---|
| `_is_unique_thread_seed_row` | 29 | 读 `_address_lookup_keys` |
| `_unique_thread_start_keys` | 11 | 读 `_address_lookup_keys` |
| `_unique_execution_threads_for_view` | 47 | 读 `build_unique_execution_threads` |
| `_select_unique_thread_seed_rows` | 22 | 调用上面两个成员 |

这三个 helper 来自 `report/reporting.py`，而方案 §3.2（第 132 行）只允许 `investigation/` 导入
contracts、facts、static/emulation/tools 的接口与 model port，并明确「**未列出的边默认禁止**」。
搬这 4 个成员会**新建一条 `investigation -> report` 的禁止边**——正是 P1.2 端口化要消除的那类耦合。
因此它们**不搬**，成为 **P3.3b(2)**：要搬迁必须先按方案的口径把
`_address_lookup_keys` / `build_unique_execution_threads` **下移**到 `investigation/` 允许导入的层
（`facts/` 或 `static/`），这与 `docs/plan-conflict-resolutions-20260922.md` 里 `facts -> investigation` 的裁决
是同一形状：**先把东西挪下去，再声明边，绝不只做一半**。

> 测量工具的教训：`p33b-edge.py` 第一次跑在**工作树**上，于是报告「没有任何成员需要 report.reporting」——
> 因为那时成员体已经被替换成单行委托。**对着错误的 revision 测量，会让工具给出自信的错误答案**；
> 改成读 `git show HEAD:service.py` 才得到正确结论。这与 P3.3 设计里「先测量」是同一条纪律的另一面。

### 11.2 双轴自审（`review` skill：Standards + Spec 两个独立子代理）发现并**已修**的问题

| 轴 | 发现 | 处置 |
|---|---|---|
| Standards（HARD） | `investigation -> report.reporting` 违反方案 §3.2 矩阵（`--strict` 看不见，因为 `forbidden_edges` 是扁平模块名且 `investigation.coordinator` 无 `moved_paths` 条目） | **缩范围**：4 个成员不搬（11.1），新契约测试增加一条 pin，断言该模块**不导入** `threat_report_agent.report.*` |
| Standards（HARD） | 端口在**错误声明**上被扩大：docstring 称两个类常量都被 `structure-surface.json` 按符号记录，实测只有 `_CATALOG_HOW_SEED_SCAN_LIMIT` 是；`_UNIQUE_THREAD_VIEW_KINDS` 的唯一读者也已留下 | 端口从 3 个成员缩到 **1 个**（`database`），与设计第 4 节的实测一致；docstring 与契约测试同步 |
| Standards（judgement） | 新测试重复了 `test_pe_entry_function_budget.py` 的数值 pin（`>= 2048`） | 删除重复 pin，只保留「常量仍在 `AnalysisService` 上」这一条，并注明数值 pin 的唯一位置 |
| Standards（judgement） | 委托生成出 135 字符单行 | 抽取器改为按**整行宽度**（>110）换行，而不是只看实参串长度 |
| Standards（judgement） | 删除模块级常量留下 8 个空行 | 抽取器增加「3+ 连续空行折叠为 2」；**先实测** HEAD 的 `service.py` 有 **0** 处这样的连续空行，所以该规范化不可能产生无关改动 |
| Spec | `tests/test_investigation_service.py` 用 `getsource(AnalysisService._build_investigation_frontier)` 断言源码里出现谓词名——搬迁后该断言读的是单行委托 | 迁移为**经导入系统解析规范实现**再读 AST（shim 无法满足），保留同一主题；行为级替换按方案归 P3.7 |
| Standards（delta） | 上述迁移使记录的 surface `test_getsource_count.reaching_a_private_member` 由 21 降到 20，P1.4 门因此变红 | **有意重新记录** surface，并核对 diff 只改这一个数字（`21 -> 20`），随后 `--all --strict` 通过；这正是 P3.7 的期望方向 |

### 11.3 本步的工具教训：can-fail 证明**两次**是空洞的

1. 第一次：篡改搜索从函数起点找到**文件末尾**，改到了后面另一个函数里的符号，验证器（只被问了被点名的方法）
   正确地报告无差异——于是脚本报「CAN-FAIL PROOF FAILED」，但那是**证明**的问题。
2. 第二次：篡改字符串字面量时插到了**文档字符串**的前两个引号之间（`""-tampered"Doc…`），产生 `SyntaxError`；
   验证器在比较之前就崩了，退出码 1 被脚本误读为「检测成功」。
3. 现在的证明**要求三件事同时成立**：未篡改时验证器 exit 0（基线）、篡改后 exit 1、且输出里**点名被篡改的函数并给出
   `DIFFERS`**。缺一即报 `VACUOUS`。这两次都说明：**「证明会失败」本身也需要被证明**。

## 12. P3.3a 执行结果（`ledger` 簇；端口**有意**从 1 个扩到 2 个）

**实测（搬迁前）**：5 个成员 / 156 行（`_ledger_ids` 是 `staticmethod`，其余为实例方法）；宿主引用只有
`database`（3 个使用者）与 `_audit`（1 个）；闭包里的 `_audit_event_hash` 是**经由 `_audit` 到达**的（`_audit`
留在宿主，所以它不是端口成员）；**没有** `report/` 依赖 → 不触犯 §3.2 矩阵；**没有** service 内定义的类型要随迁。

因此本步按设计第 4 节的预测，**只把 `_audit` 加进端口**（1 → 2 个成员），并把理由写在
`INVESTIGATION_HOST_MEMBERS` 旁。`service.py` 28,568 → 28,442 行；`coordinator.py` 466 → 669 行；
5 个搬迁体逐一比对 **IDENTICAL**；can-fail 已证明（见 12.2）。

**与 P3.3b 的关键差别**：这次是**纯机械**步骤——不需要缩范围、不需要迁移测试、不需要重新记录 surface。
原因是 P3.3b 的教训被**前移**成了一条检查：搬迁前先按 §3.2 矩阵核对切片的自由名（本轮用
`.scratch/p32-measure-cluster.py` 的自由名段），而不是等门禁或审查来发现。

### 12.1 工具通用化（本步的真正副产物）

P3.2/P3.3b 的抽取器、验证器与 can-fail 都是**按切片硬编码**的，于是 P3.3b 修好的「装饰器区间」缺陷**没有**自动
传递到第二个切片——本步把三者都改成**从 argv 取切片成员**，并显式处理「模块级函数/常量在后续切片里已不存在」
（`already moved (not in service.py)`），而不是断言失败。**每修一次工具就要问：这个修法在下一个切片还成立吗。**

### 12.2 can-fail 的**第三**次教训：篡改点必须落在**被比对的范围**内

1. can-fail 起初没把切片成员传给验证器，于是**基线**跑的是默认（P3.3b）名单、对 HEAD 全是委托 → 基线失败 →
   加固后的证明**拒绝**给出结论（这是它该做的）。
2. 传对成员后，自动挑选的篡改符号是 `AnalysisTask`——它只出现在**类型注解**里，而验证器**有意**不比对签名，
   于是「篡改后仍然 IDENTICAL」是**正确**结果，证明据此报 `FAILED`，也是对的。
3. 现在篡改符号从**被调用的名字**（`ast.Call` 的 `func`）中选，保证落在被比对的方法体内。三次都说明：
   **can-fail 的价值全在于它拒绝在证据不足时说「已证明」**。

### 12.3 状态文件的两处缺陷（用户在本轮指出，已修）

1. **`head_sha` 落后于真实 HEAD**：旧约定把它写成**提交前**的 HEAD，于是受跟踪文档声称「在一个不含本步改动的提交上
   完成核验」（写的是 `854d9e5`，而被核验的树成了 `fa4fe5d`）。现在 `head_sha` **就是被核验的那个提交**，
   语义写进 `head_sha_semantics` 并渲染到文档里；每步的回滚点仍由该步 `rollback_point` 指向上一个提交。
2. **历史段落可能误导后继者**：顶层仍有 Phase 0/1 的旧快照（例如 `import_graph` 还写着 64 模块 / 150 边），
   以及约 20 个更早的 `final_state_round_*`，它们的 `what_a_successor_must_do_first` 点名的是早已完成的工作。
   处置：**刷新**可廉价测量的段落（`import_graph` / `deployment` / `worktree`，各自带 `measured_at_commit`）；
   给每个被取代的 `final_state_*` 加 `superseded_by` 与 `_historical`；给 `ghidra_worker_blocker` 加 `_resolved`；
   并在文件顶部加**读取指引**（权威＝`step_records` + 最新 `final_state_*`）。历史**不删除**——那会丢掉 Phase 0/1
   的证据链。

## 13. P3.3c 执行结果（Action Proposal 验证切片；**四种工具缺陷，各被不同的安全网抓住**）

**实测（搬迁前，`--from 6027665`）**：5 个成员 / 253 行；唯一的接收者引用是**类常量**
`_MAX_COMPLETED_ACTION_EVIDENCE_IDS`（由 `tests/test_ghidra_performance.py:116,118` 钉在 `AnalysisService` 上，
因此必须留在宿主 → 端口有意扩到第 3 个成员）。`service.py` 28,435 → 28,219 行；5 个搬迁体逐一 **IDENTICAL**；
can-fail 已证明。

### 13.1 同一切片里有 4 个成员**不能**搬（逐成员实测）

| 成员 | 行数 | 实测阻塞原因 | 性质 |
|---|---|---|---|
| `_model_action_plan` | 42 | 需要 `DynamicPlanAction`（`model/model_gateway.py`）的**运行时**使用（`isinstance`） | §3.2 未允许 `investigation -> model` |
| `_action_is_model_or_human` | 3 | 需要 `task/analysis_task_orchestration.action_is_model_or_human` 的**运行时**调用 | 且该模块**自己 import investigation** → 会成**环** |
| `_has_complete_model_action_plan` | 9 | `DynamicPlanAction` **仅出现在注解** | 类型边；未取用 |
| `_merge_planned_actions` | 20 | 同上 | 类型边；未取用 |

后两者本可用 `TYPE_CHECKING` 导入搬走（类型边不是运行时依赖），**故意不做**：干净的修法是让 **model port**
暴露 `DynamicPlanAction`（P1.2 的 `ports.py` 今天没有），而「向未列出的层引入类型边」这个决定应当与那个修法
一起做，而不是夹带在一次搬家里面。它们成为 **P3.3c(2)**，与 P3.3b(2) 同形：**先把东西挪到允许的层，再声明边**。

### 13.2 四种工具缺陷——注意它们各自是被**不同的**安全网抓住的

1. **测量工具只扫 `self.`**（`p32-measure-cluster.py`）：`_bound_completed_actions` 是通过 `cls.` 读类常量的
   classmethod，于是该切片被报成「宿主需求：无」。**抓住它的是契约测试**（`host_refs == port` 断言），不是工具。
   工具现已同时扫 `self.` 与 `cls.`。
2. **测量工具只会读工作树**：搬家之后再量，量到的是**单行委托**（`_bound_completed_actions` 报 5 行而非 26 行）。
   Spec 轴在 P3.2 的评审里就点过这个 caveat（「被引用的工具无法重读某个 revision」），而它到本轮才真正咬人。
   工具现支持 `--from <rev>` 并会打印它在量哪个 revision。
3. **抽取器根本没有 import 守卫**——**最严重的一条**。P3.2 的抽取器有守卫，我为 P3.3 重写时把它漏掉了，
   而 P3.3b 的记录里还**声称**存在（「抽取器拒绝自行放宽导入」）。后果：`_grounded_planner_action_candidates`
   用到 `DeepMiningPlanner`，搬家照常应用、`compileall` 通过（未解析的全局名不是语法错误），直到测试套件报出
   **7 个错误**才暴露。守卫已移植过来（并跳过已搬成员，否则会对委托报出 `self` 这种无意义的缺失），
   can-fail 用真实的未来切片 `_run_methodology_action` 验证（它缺 4 个名字，守卫如实停下）。
   **教训：一个「以为存在」的安全网比没有更糟，因为周围的文字在宣称它提供保护。**
4. **委托把接收者硬编码成 `self`**：`@classmethod` 的委托因此生成
   `return _coordinator._bound_completed_actions(self, actions)`，而 classmethod 里没有 `self` →
   `NameError: name 'self' is not defined`（又一批 6 个测试错误）。现在转发的是**成员自己的**接收者名；
   契约测试也从「断言出现 `self`」改为「按模块函数的签名判断是否需要 host，并核对转发的是该成员自己的接收者」。
5. 附带修正：孤儿导入检查改为**只报本次搬家造成的增量**（此前会把既存的 F401 与 `from __future__` 一起报出来）。

### 13.3 surface 变更的证明（`threshold_comparisons`）

搬迁后 P1.4 门报 `threshold_comparisons CHANGED`：该读数记录比较表达式的**源文本**，而接收者改名
（`cls.` → `host.`）会改变文本。**先证明再重录**：probe 显示记录 140 条、当前 140 条，差值恰好一条
（`len(evidence_ids) > cls._MAX_COMPLETED_ACTION_EVIDENCE_IDS` → 同式 `host.` 版），运算符与两个操作数均未变——
即纯接收者改名；随后有意识重录，diff 也只有这一行，`--all --strict` 通过。
（probe 自身也有过一个缺陷：它只把 `host.` 归一化回 `self.`，而该条目原本用的是 `cls.`，于是误报「需要调查」——
已修成两种接收者都试，并且改为与 **git 中的基线**比较，否则重录之后 probe 就永远说「无差异」。）

### 13.4 「逐字节相同」这句话曾经**不准确**，现在有了正确的证明

Standards 轴指出：`_grounded_planner_action_candidates` 的搬迁文本与旧家**并非逐字节相同**——文档字符串与 6 处多行
字符串的续行缩进不同；而 `p33-verify.py` 比对的是 `ast.unparse` 之后的语句，**看不到这类差异**。

按正确的判据重新测量（`.scratch/p33c-textdiff.py`），结论是**两者都对**：

* **字符串常量的值逐字符相同**（5 个成员全部 `string values identical: True`）。搬迁体**故意**保留多行字符串续行的
  原始缩进——因为那些空格是**字符串内容**的一部分；把整段代码从类里减掉 4 个空格时，若连字符串内部一起减，
  改变的就是 `__doc__` 与可能的输出文本，那才是真正禁止的行为变更。所以「按行比较（整体减 4 空格）」这个判据本身
  对多行字符串是错的——reviewer 的发现因此是**安全的误报**（其自己也写明「Semantics unchanged」）。
* **函数体的代码行**在归一化接收者（`self.`/`cls.`/`host.` → 同一占位符）后逐行相同；签名行被**有意排除**，
  因为「接收者变成 `host` 形参」正是这一步的设计本身。

因此本记录此后不再使用含糊的「逐字节相同」，而是写：**字符串值逐字符相同 + 函数体代码行相同（模接收者改名与类缩进）**，
两者都有脚本证据。这是「宣称的强度必须与测过的强度一致」的又一例。

## 14. P3.3d 执行结果（收敛合同切片；方法论半片受阻）

**实测（`--from 044a2ef`）**：5 个成员 / **243 行**，全部是 classmethod；唯一接收者引用是共享 helper
`_canonical_json`（8 个使用者，其中 7 个在簇外 → 必须留在宿主）与**两个类常量**。端口因此从 3 有意扩到 **6**。
`service.py` 28,219 → **28,028 行**；5 个搬迁体的**字符串值与函数体代码行**都相同（模接收者改名与类缩进），
can-fail 已证明（基线通过 + 篡改后 exit 1 且点名 DIFFERS + 逐字节还原）。

### 14.0 一次**真正的行为变更**：簇内调用漏传 host（由 Standards 轴发现，任何门禁都没看见）

`_convergence_failure_contract`（本步搬迁，自身不需要 host）调用同簇的 `_convergence_alternate_type`，而后者**需要
host**。抽取器的簇内重写把 `cls._convergence_alternate_type(...)` 改成 `_convergence_alternate_type(...)` 时
**没有补上 host**，于是每个实参整体位移一位：`host` 收到 `ActionType.TRACE_API_ARGUMENT`，`action_type` 收到
`existing_method_ids`……结果 `_CONVERGENCE_ALTERNATES` 回退分支**静默失效**（不抛异常）。

**没有门禁能看见它**：`compileall` 只编译不检查调用元数；行为探针报 UNCHANGED（这条路径未被探针覆盖）；
契约测试当时只 pin 委托的形状、不看调用元数。三处修复：

1. **代码**：`_convergence_failure_contract` 现在接收 `host`（因为它要传给同簇函数），调用改为
   `_convergence_alternate_type(host, action.action_type, existing_method_ids)`；其 classmethod 委托转发 `cls`。
   实测复核：`_convergence_alternate_type(host, TRACE_API_ARGUMENT, set())` → `ActionType.GET_DECOMPILE`。
2. **新增门禁（测试）**：`test_no_call_omits_the_host_a_sibling_requires` 遍历整个模块，凡首参为 `host` 的函数，
   其任何调用都必须把 host 传在第一位；另有 `test_every_host_taking_function_is_delegated_with_its_own_receiver`
   检查委托侧。can-fail 已证明（把 host 去掉 → 该测试以正确理由失败 → 逐字节还原）。
3. **工具**：抽取器先**迭代求不动点**算出「谁需要 host」（自身触碰接收者 **或** 调用了需要 host 的兄弟），
   重写簇内调用时补上 host；并在产出前跑一次**元数硬停**，不合规就拒绝写文件。

这一条同时**反证了上一节的措辞纪律**：§13 末尾刚写下「宣称的强度必须与测过的强度一致」，而 §14 初稿又写了
「AST 与值层面都相同」——**值层面的探针看不见调用点少一个实参**（它只归一化接收者与字符串）。因此本节的正确表述是：
*字符串值与函数体代码行相同*，**另加**一条独立的**调用元数**检查；三者合起来才覆盖这个切片。

### 14.1 第五次同类工具缺陷：**只认 `ast.Assign`，看不到带注解的赋值**

一个探针把 `_CONVERGENCE_ALTERNATES` / `_CONVERGENCE_EXPECTED_KINDS` 报成 `class-level=no`，于是它们被当成
**模块级**状态（按规则应当**随函数搬迁**）。真相是两者都是**带注解的类属性**（`X: dict[ActionType, ...] = {...}`）。
若照那条读数执行，会有**两个后果**，而且都不会被现有门禁发现：

* 把**类属性搬出类**（改变 `AnalysisService` 的可观察表面）；
* 反过来，一条真正的**带注解模块级常量**永远找不到，于是搬迁后的函数引用未定义名——**又一个 NameError**，
  与上一轮「没有 import 守卫」是同一族。

修法：抽出 `assigned_names()`，同时处理 `ast.Assign` 与 `ast.AnnAssign`，并用于**三处**：端口读取、类/模块归属判定、
随迁常量查找。（`_canonical_json` 是 staticmethod，签名 `(value) -> str`。）

**这一轮把同一族缺陷数到了第 5 个**（只扫 `self.`；只读工作树；缺 import 守卫；委托硬编码 `self`；只认 `Assign`）。
共同点是**扫描范围写得太窄**，而后果总是「工具给出自信的错误结论」。因此本轮之后，测量类工具的每条读数都要先问
一句：**它扫的范围是否覆盖了这类节点/接收者的所有形态？**

### 14.2 方法论半片（`_run_methodology_action`，271 行）有**两个独立阻塞**，逐条实测

1. **`threat_report_agent.methodology` 是没有先例的未列层边。** 实测各 root 模块被多少个「层」导入：
   `models` 5（root/investigation/static/task/tools）、`config` 5、`runtime_contracts` 3、`contracts` 2，
   而 **`methodology` 只有 1（service.py）**。因此它不是既有的共享原语，把需要 `DIMENSIONS`/`build_profile` 的
   代码搬进 `investigation/` 会**新建**一条 §3.2 未列出的边——与 P3.3b 的 `report`、P3.3c 的 `model.model_gateway`
   同一处理方式：**不搬**。
2. **模块级 `REFERENCE_ISOLATED_FACT_LIBRARY` 不能随迁。** 它（service.py:1150 由 `FactLibrary(...)` 构造）同时被
   `_freeze_blind_run_snapshot`（**未搬迁**）与 `_run_methodology_action` 读取，所以既不能搬走、也不能被本模块导入。

此外它还会再要 **5 个端口成员**（3 个共享 helper `_canonical_json`/`_is_reference_isolated_blind`/
`_link_claim_evidence`、类常量 `_METHODOLOGY_EVIDENCE_LIMIT`、实例属性 `methodology_library`——后者被测试钉住）。
**解除路径**与 P3.3b(2)/P3.3c(2) 同形，但更大：要么把 `methodology.py` 提升为**被多层的共享纯模块**
（它只 import 标准库与 yaml，具备条件）并按记录声明该层关系，要么把 `FactLibrary` 构造下沉到一个允许的层并把
`REFERENCE_ISOLATED_FACT_LIBRARY` 一并下移。**两件都在本步白名单之外，故本步只记录，不动手。**

### 14.3 过程失误（记下来以免复发）

1. 本轮在用 PowerShell 改脚本内容时又踩了 `Set-Content -Encoding utf8` 的 **BOM** 坑（Python 报
   `SyntaxError: invalid non-printable character U+FEFF`，且把一行注释挤到了代码行尾）。这是本会话**第三次**同类事件。
   结论写死：**脚本内容改动只用编辑器工具，不用 PowerShell 文本命令**；不得不处理时先用 `.scratch/strip-bom.py` 清 BOM 并验证可解析。
2. **记录脚本自身有语法错误，于是「步骤记录」没有写入，而代码与文档照常提交了。** 这正是上一轮 reviewer 指出的
   同一类缺口（「P3.3c 没有 step_records」），只是成因不同：那次是时序，这次是脚本报错没被看见。教训：
   **写完记录后必须核对输出里的计数**（本轮 `step_records 57`）并确认渲染出的文档真的提到该步骤；
   记录脚本的失败必须与代码提交一样被当作阻塞，而不是被 `2>&1 | Select-Object -Last` 吞掉。

