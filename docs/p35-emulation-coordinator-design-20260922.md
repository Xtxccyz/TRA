# P3.5 设计：抽出 `EmulationCoordinator`（20260922）

> **本步性质：只测量 + 只设计，不动 `src/`、不动 `tests/`。** 记录里对此有机器证明：
> `git diff --name-only <verified>..HEAD -- src tests` 必须为空。

计划出处：`docs/code-structure-optimization-execution-plan-reviewed-20260922.md` §P3.5。
允许修改 `emulation/coordinator.py`、`service.py`、emulation tests。要迁移四件事：**授予窗口、worker dispatch、
结果归档、失败分类**。硬约束：**不得在 coordinator 内执行宿主样本**；成功标准：真实 simulation result 与占位记录
分离，`STATIC_BOUNDARY` 只在真实 `CONTROLLED_EMULATE` 之后使用。

**本设计的结论是一句话：P3.5 目前被层规则挡住，不能作为单个切片执行。** 下面给出测量依据、可立即执行的部分、
以及必须先做的准备步。

---

## 1. 实测候选面（15 个成员 / 1,011 行）

`py .scratch/p34-pin.py --members <15 names> --declared N`（本步把 pin 仪器通用化为可传 `--members`/`--declared`/
`--reasons`）：

| 成员 | 行数 | 接收者 | 角色 |
|---|---|---|---|
| `_run_controlled_emulator` | 263 | `self` | 授权窗口驱动 + worker 派发 |
| `_emit_controlled_emulation` | 135 | `self` | 生成授予/拒绝记录 |
| `_persist_emulation_result` | 134 | `self` | **结果归档** |
| `_collect_emulation_inputs` | 90 | `self` | 输入收集 |
| `_run_post_static_emulation` | 88 | `self` | 静态后模拟编排 |
| `_persist_time_static_boundary` | 81 | `cls` | `STATIC_BOUNDARY` 落库 |
| `_persist_how_function_entries` | 62 | — | HOW 函数条目（唯一"干净"成员之一） |
| `_persist_ready_emulation_actions` | 47 | `cls` | 就绪 action 落库 |
| `_emulation_fallback_payload` | 34 | — | 占位/回退载荷 |
| `_reverify_how_after_emulation` | 33 | `self` | 模拟后 HOW 复验 |
| `_run_simulation_window` | 25 | `self` | **授予窗口** |
| `_real_simulation_result_count` | 15 | `self` | 真实结果计数（占位分离的判据） |
| `_supporting_seed_static_boundary` | 14 | — | `STATIC_BOUNDARY` 辅助 |
| `_emulation_entry_key` | 2 | `self` | entry key |
| `_gate_for_seed_playbook` | 2 | `cls` | playbook gate |

**不搬、也不进 pin：`workbench_dispatch_analysis_intent`（81 行）** —— 它是 workbench 侧派发，不属于四件事中的任何一件。

## 2. 搬迁与 pin 的划分（按实测读者，而不是按名字）

对每个 host 候选成员实测"除本次搬迁之外还有没有读者"（`self.`/`cls.` 引用所属方法）：

| 名字 | 总读者 | 搬迁之外的读者 | 判定 |
|---|---|---|---|
| `_emulation_entry_key` | 2 | **无** | 随切片搬走 |
| `_persist_how_function_entries` | 1 | **无** | 随切片搬走 |
| `_gate_for_seed_playbook` | 1 | **无** | 随切片搬走 |
| `_HOW_PLAYBOOK_IDS`（类常量） | 1 | **无** | 随切片搬走 |
| `_materialize_recovered_bytes_child` | 3 | `_record_ghidra_evidence` | **留作 pin** |
| `_upsert_tool_run` | 4 | `_register_archive_relations`、`_analyze_artifact`、`_persist_ghidra_result` | **留作 pin** |

加上四个宿主属性 `content_store`、`database`、`policy`、`settings`，即 **pin = 6 个成员**
（`_materialize_recovered_bytes_child`、`_upsert_tool_run`、`content_store`、`database`、`policy`、`settings`）。
这是 P3.4-1 那条教训的直接应用：**只被本切片读的类常量/成员必须随行，否则 pin 会长出一个"其实模块自己拥有"的成员**
（P3.4-2 的 `host._snapshot_report_context` 就是这样被抓出来的）。

**实测补正（本设计的第二版，第一版只跑了 12 个成员）**：把三个随行 helper 计入搬迁集合后，pin 推导又多出
**四个类级名字**——`_HOW_PLAYBOOK_IDS`、`_PERSIST_HOW_PLAYBOOKS`（常量）、`_investigation_row_mapping`、
`_persist_how_rows_for_playbook`（方法）。逐个实测读者后确认它们**在搬迁之外没有任何读者**，因此：
* 两个常量**显式随行**（mover 默认把类属性当 host 状态，必须点名，同 P3.4-1 的
  `_REPORT_PROJECTION_EVIDENCE_LIMIT`）；
* 两个方法**并入搬迁集合**（各 2 行）。

于是搬迁集合 = **17 个方法 + 2 个常量（1,011 + 6 = 1,017 行）**，pin 仍是 **6**。若照第一版把 15 个成员搬走而把
这四个留在 host，pin 会变成 10，且新模块会通过 host 调用它自己该拥有的四个名字——正是 P3.4-2 抓到的那个缺陷形状。

## 3. 层判定：**12 个成员被挡，只有 2 个今天可搬**

仪器：`py .scratch/p33f-layer-scan.py --members <15> --home-module threat_report_agent.emulation.controlled_emulation
--allow-modules threat_report_agent.emulation.controlled_emulation,threat_report_agent.simulation_adapters`
（`--allow-modules` 是本步新加的**home-aware**开关，理由见 §7）。

§3.2 对 `emulation/` 的允许列：**contracts、facts、worker/模拟入口**；禁止列：`service`、`report`、HTTP、DSH；
**未列出的边默认禁止**。53 个自由名的实测分布：allowed 15、stdlib 9、**按层禁止 28、实现模块 1**。

按成员统计（`py .scratch/p35-admissibility.py`）：

* **CLEAN（2）**：`_emulation_entry_key`、`_persist_how_function_entries`。
* **BLOCKED（12）**，阻塞名按来源层归类（去重后）：

| 阻塞来源 | 名字 | 影响成员数 |
|---|---|---|
| `tools.tool_execution`（实现模块） | `TemporalToolExecutor`、`ToolRunRequest`、`ToolRunResult` | 1（`_run_controlled_emulator`） |
| `task.status` | `TaskLifecycle` | 2 |
| `intake` | `PackageEntry` | 2 |
| `investigation/`（含其 re-export 与 `persist_how`、`derivation`、`seed_support`、`investigation_protocol`） | `ActionSpec`、`ActionType`、`InvestigationEvent`、`InvestigationResult`、`InvestigationThreadState`、`MechanismPlaybookRegistry`、`PersistHow`、`SimulationWindowOutcome`、`apply_emulation_reverification`、`fill_protocol`、`recovery_actions_for_gap`、`_derivation`、`_scoped_investigation_action_key` | 8 |
| `models`（**未列出**，不是"禁止"） | `AnalysisTask`、`Artifact`、`ContentBlob`、`Evidence`、`InvestigationActionRecord`、`ToolRun`、`new_id`、`utcnow` | 9 |
| `service`（模块级函数） | `_qiling_worker_deferred_observation` | 1 |

**这解释了为什么 P3.5 不能作为单切片**：`_run_controlled_emulator`（263 行，本切片的核心）要 `tools` 的具体
`TemporalToolExecutor` 与 `task.status.TaskLifecycle`；`_persist_time_static_boundary` 要 6 个 `investigation/`
名字；9 个成员要 `models`。全部照搬进来会产生**新的禁止边**，`check-import-graph.py --strict` 会直接拒绝。

## 4. 可用的既有接口（实测，不是假设）

`src/threat_report_agent/ports.py`（438 行）**已经**声明/引用了 `ToolExecutionPort`、`EmulationPort`、
`ToolRunRequest`（6 处）、`ToolRunResult`（3 处）、`Evidence`（8 处）——即"经端口拿工具执行能力"这条路是通的。
但以下名字**不在** ports/contracts 里：`TemporalToolExecutor`、`TaskLifecycle`、`PackageEntry`、`ActionSpec`、
`ActionType`、`InvestigationActionRecord`、`PersistHow`、`MechanismPlaybookRegistry`、`SimulationWindowOutcome`。

## 5. 执行划分（本设计的处方）

* **P3.5-0（准备步，必须先做）**
  1. **把 13 个 `investigation/` 契约名下沉**到 `contracts.py`（或经 `ports.py` 暴露），保持每个旧路径
     `X as X` 再导出——这是 P3.3f-1 "sink" 的同型操作，且顺带修正 §3.2 里 `investigation → emulation` 单向可import
     而反向不可的结构事实。
  2. **工具执行改走端口**：coordinator 不得 import `tools.tool_execution`，而是接收
     `ToolExecutionPort`（`TemporalToolExecutor` 由宿主注入，pin 里加一项 `tool_executor` 之类的宿主状态）。
     `ToolRunRequest`/`ToolRunResult` 已在 `ports.py`，从那里取。
  3. **`models` 记录为决定**（同 decision (e) 的做法：`recorded_allowed_edges` + 决议文档），理由是数据层被每一层共享，
     而 `emulation/` 今天一次都没 import 过 `models`（实测），所以这是**新边**，必须显式登记。
  4. `TaskLifecycle`/`PackageEntry` 一并下沉到 `contracts.py`（它们分别是状态枚举与存储实体，属于契约）。
* **P3.5-1**：搬 CLEAN 的两个成员（`_emulation_entry_key`、`_persist_how_function_entries`）+ 随行常量。
  **但这两个只有 64 行，单独立步不值得**——因此它们并入 P3.5-2。
* **P3.5-2**：在 P3.5-0 落地后搬其余 10 个成员（1,011 − 64 行），pin = 6。

## 6. 成功标准与"怎么检查"（不是复述）

1. *真实结果与占位分离*：`_real_simulation_result_count` 与 `PLACEHOLDER_STATUSES`（`emulation.controlled_emulation`）
   的配合必须在移动后**逐字不变**；`tests/test_controlled_emulation.py` 的 worker 用例与
   `test_worker_emulates_granted_snippet_without_opening_sample_path` 必须继续通过。
2. *`STATIC_BOUNDARY` 只在真实 `CONTROLLED_EMULATE` 之后*：把 `STATIC_BOUNDARY` 的**全部赋值点**列出（移动前后各一次），
   断言"仅当存在真实模拟结果才写"的判据代码逐字相同；这是本切片最容易被"结构迁移"破坏的行为，按 P3.4 的
   draft-gate 先例，**为它单独写一条受跟踪的负向断言**（无真实结果时不得出现 `STATIC_BOUNDARY`）。
3. *不在宿主执行样本*：coordinator 内不得出现 `open(sample…)`/`subprocess`/宿主导入样本路径；用
   `tests/test_controlled_emulation.py` 的既有隔离断言 + 一条新的静态断言（模块内不得引用样本路径构造器）兜住。

## 7. 本步发现并修掉的仪器缺陷（必须记录）

**层扫描把同包兄弟与 worker 入口当成"禁止"。** `p33f-layer-scan.py` 里 `IMPLEMENTATION_MODULES` 是 P3.3 裁决的
硬编码集合（`simulation_adapters`、`emulation.controlled_emulation`、`service`）。当 home 是 `investigation/` 时它
是对的；当 home 是 `emulation/` 时，`emulation.controlled_emulation` 是**同包兄弟**、`simulation_adapters` 正是
§3.2 点名允许的"worker/模拟入口"。第一版扫描因此把 **6 个允许名**列进了阻塞清单（`PLACEHOLDER_STATUSES`、
`emulation_entry_key`、`post_static_emulation_needed`、`default_simulation_runner`、
`qiling_unavailable_observation`、`_qiling_worker_deferred_observation` 中的前五个）——若照抄，本设计会声称
`_run_controlled_emulator` 有 12 个阻塞名而不是 12 个里的一部分。修法：新增 `--allow-modules`（默认空，
investigation 判定不变），并把 home 的允许集从"该包实测 import 的模块"扩展为"该包实测 import 的模块 + 显式声明的
同包/端口模块"。修完后 allowed 12 → **15**，阻塞数随之更正。

**第二条仪器缺陷**：`p34-pin.py` 的成员表与 11 条理由是硬编码的。已通用化为 `--members`/`--declared`/`--reasons`，
P3.4 的调用方式与数字不变（默认值保持原样）。

## 8. 方案级冲突（登记，需要裁决）

**冲突 3：`emulation/` 行的允许列不足以承载"emulation coordinator"这一职责。** 四件事里"worker dispatch"必须
知道工具执行类型、"结果归档"必须知道 investigation 的 action/result 契约、"失败分类"要 `TaskLifecycle`。
今天这些名字只在 `tools/`、`task/`、`intake/`、`investigation/` 里，照搬即产生禁止边。二选一：
(a) 按 §5 的 P3.5-0 把契约下沉到 `contracts.py`/`ports.py`（**本设计推荐**，方向与 §3.2 每一条"可以导入 contracts"
一致，且顺带完成 P1.1/P1.2 未覆盖的剩余类型）；(b) 在方案里显式放宽 `emulation/` 的允许列并写明理由。
**在裁决之前，P3.5 只能报 `BLOCKED`，不得用"部分搬迁"声称完成。**

## 命令

```
py .scratch/p34-pin.py --members _run_controlled_emulator,_emit_controlled_emulation,_persist_emulation_result,_collect_emulation_inputs,_run_post_static_emulation,_run_simulation_window,_real_simulation_result_count,_emulation_fallback_payload,_persist_ready_emulation_actions,_persist_time_static_boundary,_supporting_seed_static_boundary,_reverify_how_after_emulation,_emulation_entry_key,_persist_how_function_entries,_gate_for_seed_playbook --declared 6 --reasons .scratch/p35-reasons.json
py .scratch/p33f-layer-scan.py --members <同上> --home-module threat_report_agent.emulation.controlled_emulation --allow-modules threat_report_agent.emulation.controlled_emulation,threat_report_agent.simulation_adapters
py .scratch/p35-admissibility.py
```
