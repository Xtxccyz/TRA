# P3.6 设计：抽出 `WorkbenchQueryReader`（20260922）

> **本步性质：只测量 + 只设计，不动 `src/`、不动 `tests/`。** 记录里有机器证明：
> `git diff --name-only <verified>..HEAD -- src tests` 必须为空。

计划出处：`docs/code-structure-optimization-execution-plan-reviewed-20260922.md` §P3.6。
允许修改 `workbench_query.py`、`main.py`、`service.py`、query tests。要迁移：**Evidence、timeline、report revision
等只读查询，不进入分析循环**。成功标准：**查询不会改变 snapshot/revision**；HTTP adapter 不被 investigation 导入。
测试：`tests/test_workbench_report_file.py`、evidence query tests、API read-only tests。

**结论：P3.6 比 P3.5 可行得多——实测只有 2 个自由名不在允许层内，而且其中一个与 P3.5 是同一个准备步。**
但它**不能按名字关键词扫出来的 32 个候选执行**：那里面混着写操作，见 §1。

---

## 1. 实测分区：只读 6 个成员 / 1,040 行；写操作**排除**

按 `workbench|evidence|timeline|query|view|list_|get_` 关键词扫出 **32 个候选 / 2,539 行**，但计划的 P3.6 要的是
**只读查询**，因此按"是否真正只读"逐个判定，结果分三类：

| 类别 | 成员 | 处置 |
|---|---|---|
| **只读投影（搬）** | `task_view`(395)、`workbench_domain_view`(374)、`workbench_capabilities`(105)、`workbench_query_evidence`(62)、`model_configuration_view`(58)、`workbench_thread`(46) | **本切片**，合计 **1,040 行** |
| **写/驱动（不搬）** | `workbench_submit_action`(258)、`workbench_model_complete`(163)、`workbench_start_static_analysis`(113)、`workbench_write_report_file`(92)、`workbench_dispatch_analysis_intent`(81)、`workbench_link_session`(96)、`request_evidence_purge`(56)、`execute_evidence_purge`(58)、`workbench_unbind_analysis`(45)、`workbench_wait_for_analysis_update`(96) 等 | **留在 `service.py`**：它们会改状态或驱动分析循环 |
| **已搬** | `get_report_revision` | P3.4-2 已在 `report/revision_writer.py` |

**"只读"不是形容词，是实测的**：六个成员体内 `session.add` / `delete` / `flush` / `commit` / `merge`
**全部为 0 次**；出现的 `scalars`/`scalar` 是 SELECT 读取（`workbench_query_evidence`、`workbench_domain_view`、
`workbench_thread`、`task_view`）。（判定方法：AST 里按 `session.`/`self.database.` 的方法名匹配，
把"读"与"写"分开——第一版把 `scalars?` 混进"写"里，是错的，已修正。）

**一个必须记录的相邻风险**：`workbench_wait_for_analysis_update`(96) 名字像查询，实际是**等待/驱动**（会推进分析
状态），所以不搬；否则 P3.6 会在结构步里引入行为变化。

## 2. 层判定：24 个自由名，只有 2 个不在允许层内

仪器（home 取 `report/` 的规则作为"只读投影"这一档的最宽松近似）：
`py .scratch/p33f-layer-scan.py --members task_view,workbench_domain_view,workbench_capabilities,workbench_query_evidence,model_configuration_view,workbench_thread --home-module threat_report_agent.report.reporting`
→ 5 stdlib、17 allowed、**2 禁止**：

| 名字 | 来源 | 处置 |
|---|---|---|
| `ActionCatalog` | `investigation`（re-export 自 `investigation.investigation`） | **与 P3.5-0 的同一件事**：下沉到 `contracts.py`，旧路径 `X as X` 再导出 |
| `simulation_policy_from_settings` | `emulation.policy`（272 行纯策略模块） | 记录一条**小决定**：查询模块允许读 `emulation.policy`（它是纯函数策略，不含实现、不 import service/report），或同样下沉 |

**home 的行问题**：`workbench_query.py` 是**根包模块**，§3.2 的矩阵里没有它的行。本设计的建议：**沿用 `report/`
行的规则**（contracts、facts、investigation 只读投影、models；禁止 `service`、`main.py`、HTTP、DSH、
investigation/model 的实现），理由是 P3.6 的成功标准"HTTP adapter 不被 investigation 导入"正是这条规则的另一面。
若方案owner选择新增一行，本设计给出的允许/禁止集合即该行的内容。

## 3. pin：原始 14 → 按实测读者收敛到 **12**

对 14 个原始 pin 成员逐个实测"搬迁之外的读者"：

* **随行（无外部读者，2 个）**：`_config_route_view`(1 个读者，全在片内)、`_unique_execution_threads_for_view`(1，全在片内)。
* **留作 pin（12 个）**：`THREAT_CONTEXT_PROTOCOL`、`THREAT_TOOL_CONTRACT_VERSION`（各有 `_context_payload_v3` 这个外部读者）、
  `_action_payload`(`workbench_submit_action`、`workbench_action`)、`_analysis_planner_payload`(2 个外部)、
  `_audit_timestamp`(2)、`_elapsed_ms`(3)、`_failure_payload`(2)、`_model_calls_env_enabled`(`__init__` 等 3 个)、
  `_model_status_payload`(`_analysis_planner_payload`)、`_report_inputs`(2)、`database`(75)、`settings`(33)。

**这是 P3.5 那条教训的同型应用**：pin 必须等于"搬迁之外仍被读"的集合，多一个就是死接口、少一个就是运行期
`NameError`；而 mover 默认把类常量当 host 状态，所以真正随行的常量要在搬迁时**显式点名**。

## 4. 一个准备步同时解锁 P3.5 与 P3.6（本设计的综合结论）

P3.5 与 P3.6 的阻塞名有**同一个根因**：`investigation/` 拥有的一批契约没有下沉到 `contracts.py`。
* P3.5 需要 13 个（`ActionSpec`、`ActionType`、`InvestigationEvent`、`InvestigationResult`、
  `InvestigationThreadState`、`MechanismPlaybookRegistry`、`PersistHow`、`SimulationWindowOutcome` 等）；
* P3.6 需要其中 1 个（`ActionCatalog`）+ `emulation.policy` 的一条小决定。

因此建议把准备步命名为 **P3.5/P3.6-0「契约下沉 + 端口化 + 两条决定」**，一次做完：
1. 下沉上述契约到 `contracts.py`（每个旧路径 `X as X` 再导出，零行为变化）；
2. 工具执行改走 `ports.ToolExecutionPort`（具体 executor 注入、进 pin）；
3. 记录决定：`emulation.coordinator -> models`、`workbench_query -> emulation.policy`（若选择不下沉该名字）。
这样 P3.5-2 与 P3.6-2 都能在**不新增禁止边**的前提下执行。

## 5. 成功标准与"怎么检查"

1. **查询不改变 snapshot/revision**：把"六个体内 0 次 `add`/`delete`/`flush`/`commit`/`merge`"写成**受跟踪的负向
   断言**（AST 级别，移动后仍必须为 0），并保留 `tests/test_workbench_report_file.py` 的全部 revision identity 断言。
2. **HTTP adapter 不被 investigation 导入**：`check-import-graph.py --strict` 实测（`main -> workbench_query`
   是向下；反向边由 gate 拒绝）。
3. **63 个语法调用点继续工作**：实测 63 处（`task_view` 59、`workbench_domain_view` 4）分布在 15 个测试文件里
   （`test_analysis_api.py`、`test_attack_mapping.py`、`test_c10_t5_benign_contract.py`、`test_evidence_recovery.py`、
   `test_injects_self_loop.py`、`test_investigation.py`、`test_investigation_ledger.py`、`test_investigation_service.py` 等）
   ——同名 delegation 必须逐个保住调用形状（`task_view` 是主入口，59 处）。
4. **只读语义不变**：`workbench_domain_view` 的返回结构、`task_view` 的字段集合在移动前后逐字段相同（用现有
   API 测试 + 一条直接比较 dict 键集的断言）。

## 6. 执行顺序

`P3.5/P3.6-0`（准备，解锁两者）→ `P3.6-2`（搬 6 个成员 + 2 个随行视图助手，pin 12）→ 记录。
若方案owner选择先放宽 `emulation/` 行（冲突 3 的选项 b），P3.5-2 可与之并行，但 P3.6-2 仍需要
`ActionCatalog` 的下沉或等价决定。

## 命令

```
py .scratch/p34-pin.py --members task_view,workbench_domain_view,workbench_capabilities,workbench_query_evidence,model_configuration_view,workbench_thread --declared 12
py .scratch/p33f-layer-scan.py --members task_view,workbench_domain_view,workbench_capabilities,workbench_query_evidence,model_configuration_view,workbench_thread --home-module threat_report_agent.report.reporting
```
