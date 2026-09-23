# P3.4 设计：抽出 `ReportRevisionWriter`（20260922）

> **本步性质：只测量 + 只设计，不动 `src/`、不动 `tests/`。** 记录里对此有机器证明：
> `git diff --name-only 30c2adcf258c..HEAD -- src tests` 必须为空。下面每一个数字都可由本节末尾
> **命令**栏的仪器重新推导，不接受"估计值"——本 phase 已经因为估计值发布过三个互不相同的端口数字。
>
> **English abstract.** This step designs P3.4 (extracting `ReportRevisionWriter` into
> `report/revision_writer.py`). It moves no code. Measured: 11 members / 795 lines (`def` spans; 798 with the three
> `@classmethod` decorator lines) plus one constant, behind a **host pin of exactly 11 members, each with a recorded
> reason**, machine-asserted by `.scratch/p34-pin.py --assert` and — at execution time — by a TRACKED contract test.
> Layer verdict: the new module imports only `report/*` siblings plus `models`; the `models` edge is unlisted in plan
> §3.2's matrix, so it is taken as a **recorded decision** (precedent: `model.model_gateway -> contracts`) rather than
> justified by the deny-list's silence. Test surface: 36 syntactic call sites in 12 files, **0 `inspect.getsource`**,
> and the draft-gate behaviour guarded by three named assertions in `tests/test_workbench_report_file.py`. Two
> instrument defects were found and fixed before the numbers were published; two review findings are recorded as
> refuted, with the measurement that refutes them.

计划出处：`docs/code-structure-optimization-execution-plan-reviewed-20260922.md` §P3.4。
允许修改 `report/revision_writer.py`、`service.py`、report tests。要迁移的三件事：
**从不可变 Analysis Snapshot 组装 Report Document、执行 compose gate、写入 Report Revision**。
成功标准三句：官方正文/聊天/页面/导出仍读同一个 revision；draft 未过 gate 不能成为官方结论；
父 revision identity 不变。

---

## 1. 实测分区（`py .scratch/p34-pin.py --assert`）

搬走 **11 个成员 / 795 行**（`def` 跨度；含 3 行 `@classmethod` 装饰器为 **798 行**），外加 1 个常量：

| 成员 | 行数 | 接收者形态 | 在类内读者 | 角色 |
|---|---|---|---|---|
| `_snapshot_report_context` | 138 | `self` | 3 | 从不可变 Snapshot 组装上下文（冻结） |
| `_select_report_evidence_rows` | 171（+1 装饰器） | 无 | 1 | Evidence 窗口选择（纯函数） |
| `_migrate_snapshot_payload` | 47（+1） | `cls` | 1 | snapshot payload schema 迁移 |
| `_canonical_sha256` | 6（+1） | `cls` | 2 | 正文 sha256（不物化整串） |
| `_create_report_revision` | 156 | `self` | 3 | **compose gate + 写 revision**（构造函数 #1） |
| `edit_report` | 52 | `self` | 0（`main.py` 2） | 直接写 `status="DRAFT"` 的第二个 revision 写入口（构造函数 #2） |
| `get_report_revision` | 28 | `self` | 6 | 读回 revision |
| `recompose_report` | 44 | `self` | 0（`main.py` 1） | 重编排 |
| `publish_report` | 25 | `self` | 0（`main.py` 1） | 发布（官方化的唯一出口） |
| `submit_analyst_draft` | 96 | `self` | 1（`main.py` 1） | draft gate（构造函数 #3） |
| `workbench_submit_analyst_draft` | 32 | `self` | 1（`main.py` 1） | DSH 侧 draft 入口 |
| `_REPORT_PROJECTION_EVIDENCE_LIMIT` | 常量 | — | — | 组装用的 Evidence 窗口上限 |

**`edit_report` 是审查后补进来的，理由记录在此而不是悄悄改掉。** `service.py` 里一共只有三个
`ReportRevision(` 构造点：`_create_report_revision:15505`、`edit_report:20242`、`submit_analyst_draft:20336`——
后两个之外的那个如果不搬，"写入 Report Revision"就分裂在两个家里；而且 `edit_report` 写的正是
`status="DRAFT"` 且**不过 compose gate**，恰是成功标准 2（draft 不得成为官方结论）所指的路径，它
必须和新模块处在同一个可审计的位置。代价实测：52 行、**0 个新增 pin 成员**（它的接收者
`_audit`/`_postgres_safe_text`/`_postgres_safe_value`/`database` 本来就在 pin 里，
`get_report_revision` 随切片搬走）。

## 2. 留在原地的 11 个 host pin 成员（每个都有实测理由）

| pin 成员 | 为什么不搬 |
|---|---|
| `_audit` | 服务级审计写入，所有步骤共用 |
| `_postgres_safe_text` / `_postgres_safe_value` | 通用持久化净化器，多处在用 |
| `database` | session 工厂，宿主状态 |
| `audit_integrity` | 服务自有的完整性助手 |
| `workbench_task_for_session` | workbench 会话查找，与 revision 无关 |
| `_overlay_analyst_report_plan` | 需要 `model_gateway`/`prompts`/`settings`——§3.2 明确把模型网关实现排除在 `report/` 之外 |
| `_apply_honest_analysis_outcome` | `@staticmethod`，写 `AnalysisOutcome.PARTIAL`（来自 `task.status`），且 `test_task_runner_contract.py` 直接读它；它属于"分析结论诚实性"，不属于 revision 写入 |
| `_t6_revision_diff_payload` | `@staticmethod`，内部按**类名**调用 `AnalysisService._t6_trace_gains`；搬走会把类本身拉进新模块的自由名 |
| `_canonical_json_chunks` | `@classmethod`，通用 canonical-JSON 原语；搬走的成员里只有 `_canonical_sha256` 读它，搬它会连带拖走序列化簇 |
| `SNAPSHOT_SCHEMA_VERSION` | snapshot seal 的 schema 常量，writer 之外的成员也通过 `self.`/`cls.` 读它 |

**不搬、也不进 pin：`_leftover_official_report_dump`（33 行）。** 它是"残留官方正文 dump"的运维/诊断出口，
pin 需要 `workbench_domain_view`（374 行视图），与 §P3.4 的三项职责无关；它继续留在 `service.py`，
并且 `test_final_runtime_closure.py` 用 `service._leftover_official_report_dump = lambda ...` 打补丁——
**一旦误搬，这个 monkeypatch 会静默失效**。这是本设计里唯一"刻意不动"的相邻成员，理由记录在此。

## 3. 层判定（不是抄矩阵，是从 `report/` 包实测出来的）

`py .scratch/p33f-layer-scan.py --members <10 个成员> --home-module threat_report_agent.report.reporting`
把 §3.2 那一行变成了实测导入集（仪器本步被通用化：支持多成员、支持任意 home 包）：

* **13 个自由名来自 `report/*`**（`reporting.py` / `analyst_report.py` / `report_verification.py`）——
  这正是新模块的同包兄弟，全部允许：`build_report_document`、`compose_official_markdown`、
  `stamp_official_report_chrome`、`report_analytical_violations`、`report_bloat_violations`、
  `report_v3_quality_violations`、`verify_report_correctness`、`corrections_summary`、`correctness_summary`、
  `official_revision_semantic_gains`、`normalize_modules`、`string_fact_class`、
  `instruction_window_carries_process_creation_flags`。
* **6 个自由名来自 `models` / `task.status`**：`AnalysisSnapshot`、`AnalysisTask`、`Artifact`、`CaseRecord`、
  `ReportRevision`、`AnalysisOutcome`。
  * `AnalysisOutcome`（来自 `task.status`）**不进新模块**：唯一读它的 `_apply_honest_analysis_outcome`
    留在 `service.py` 当 pin，于是 `report/` 不新增到 `task` 的边。
  * **`report.revision_writer -> models` 是一条 §3.2 矩阵里没有列出的边，因此按"未列出的边默认禁止"
    处理：它不是"因为不在 deny-list 里所以合法"。** 审查在这里驳回了我原来的论证，且驳回成立：
    实测 `forbidden_edges` 的源集合是 25 个具体模块名、目标只有 `service`/`reporting`/`emulation`，
    但 `docs/import-policy.json` 自己写明 "an unlisted edge cannot be machine-checked at all - that blind
    spot is stated here rather than hidden"，且 `report/reporting.py` 今天**从不** import `models`
    （它的 `Artifact` 只出现在文案字符串里），所以这确实是一条新边。
    处理办法沿用既有机制而不是新发明：执行步**记录一条 decision**，加进
    `recorded_allowed_edges` 与 `docs/plan-conflict-resolutions-20260922.md`（先例是 decision (d)
    的 `[model.model_gateway, contracts]`）。理由是可测的：新模块必须**构造** `ReportRevision` 行，
    所以这个 import 是结构性的；另一条路（把行构造留给 host）等于把"写入 revision"又搬回 `service.py`，
    正好废掉 P3.4 的目的。
* **2 个 service 自有名字**：
  * `AnalysisService`（类名引用）——同上，靠"不搬 `_t6_revision_diff_payload`"消除；
  * `ReportComposeGateRejected`（定义在 `service.py:467`，由 `submit_analyst_draft` 抛出）——**迁到
    `report/revision_writer.py`，并在 `service.py` 里 `X as X` 再导出**，保持 exception identity
    （已有的 `except`/`isinstance` 与 import 该名字的调用方都不受影响）。**这是一个 shim，且有主**：
    按计划 §P4.1 迁移生产调用方、§P4.2 每个旧出口单独一步删除；本设计把
    "`ReportComposeGateRejected` 的 service 侧再导出"登记为 P4 的删除项，不留无主的 shim。
* 新模块 **永不 import `service`**；方向是 `service -> report.revision_writer`（向下），
  不会新增反向边或环——这一点由 `check-import-graph.py --strict` 实测，而不是由本节声明。

## 4. 本步发现的仪器缺陷（必须记录，且已修）

**缺陷 1（会造成运行期炸）**：pin 推导的第一版只匹配 `self.`。而成员里有 **3 个是 `@classmethod`**，
`cls._canonical_json_chunks` 与 `cls.SNAPSHOT_SCHEMA_VERSION` 因此**不可见**：pin 打印 9，
两个接收者到新模块会变成裸名——这是**运行期 NameError**（报告生成时才炸），而不是 import 期错误。
修正后 pin = **11**，与声明的 11 逐个相等（脚本用 `--assert` 断言 pin 集合 == 声明集合，
且每个 pin 成员必须有理由）。

**缺陷 2（会给出假阳性）**：同一脚本当时用**源码片段正则**收接收者，于是注释/docstring 里的
`self.`/`cls.` 也会进 pin——正是本设计在第 6 节批评 `p34-tests.py` 的那个假阳性类别。今天实测影响为
**零**，而"零影响"正是必须在它变得有影响之前修掉的理由；现改为 AST 遍历（只看 `Attribute` 节点）。

值得记下的是：**mover 本身一直是对的**（`p33-extract.py` 第 611 行把 `cls.` 与 `self.` 一起改写成 `host.`，
它对 `@classmethod`/`@staticmethod` 装饰器有断言保护）。落后的是测量仪器。这与本 phase 反复出现的
"仪器比工具弱，于是缺陷从仪器漏过去"是同一类，故记录在案。

**同一节里的第二个仪器缺陷（也修了）**：本设计的测试面数字最初是**手数**的，四个数错了
（`test_c10_t5_benign_contract.py` 8→11、`test_report_synthesis_performance.py` 4→6、`get_report_revision`
7→9、"1 处 monkeypatch"→2）；更早的那版 grep 还把 **docstring/注释里的词**算成读者——正是 P3.3f 审查里
被实测驳回的同一个假阳性。修法不是改数字而是加仪器：`p34-tests.py` 用 AST 只数语法调用点，
本文件第 6 节的表格是它的输出。**"按名字数出来的覆盖"与"真实行为覆盖"是两件事**，所以第 6 节同时给出
按名字为 0、但经路由有行为覆盖的 draft gate 三条护栏。

## 5. 接口与不变量

* 形态沿用 P3.3 的先例（`InvestigationCoordinator` = `investigation/coordinator.py` 的**模块级函数 + 实测 host pin**）：
  `report/revision_writer.py` 提供模块级函数（首参 `host: ReportRevisionWriterHost`），
  Protocol 成员 **等于** 第 2 节的 11 个，二者由 contract test 双向断言 + can-fail 证明。
* `service.py` 保留同名 **one-statement delegation**：`@classmethod`/`@staticmethod` 装饰器保真
  （`AnalysisService._select_report_evidence_rows(...)` 这类**按类名调用**的写法必须继续工作），
  签名逐个参数转发（含 `*args, **kwargs`），旧出口不删。
* 三条成功标准各自**怎么被检查**（不是复述）：
  1. *同一 revision*：`test_workbench_report_file.py`、`test_analyst_draft_submission.py`、
     `test_phase_acceptance.py` 在移动后必须仍然全绿，且 `publish_report`/`get_report_revision` 的返回
     identity 与移动前逐字段相同（用同一 session 的字节级对比）。
  2. *draft 未过 gate 不能官方化*：`submit_analyst_draft` 的负向用例（gate 拒绝 → `ReportComposeGateRejected`
     → 官方 revision 不变）必须继续失败得**一样**；这是本步最容易被"结构迁移"破坏的行为，故列为独立
     focused 断言。
  3. *父 revision identity 不变*：`_t6_revision_diff_payload` 的 `parent_present` 语义与
     `parent_revision_id` 取值在移动前后相同；`test_c10_t5_benign_contract.py` 的 3 处静态调用是现成护栏。

## 6. 测试面（实测，`py .scratch/p34-tests.py` 的输出逐行照抄）

按**语法调用点**计（AST `Call` 节点，不算 docstring/注释里的词）：**36 处 / 12 个文件**。
另有**属性/字符串读取各计一类**、不计入 36：`__doc__` 读取 **1** 处、`hasattr(..., "…")` **1** 处、
`monkeypatch-by-assignment` **2** 处、docstring 提及 **1** 处。`getsource` **0** 处。
（审查独立复算：36 与逐成员分布**全部复现**；审查另报 `test_c10_t5_benign_contract.py` 为 13 处、
总数 37 —— **这两条被逐行实测驳回**：该文件 AST `Call` 恰好 11 处，`hasattr`/`__doc__` 两处不是
`Call` 节点，本设计已把它们单列，故 36 是"调用点"而不是"所有提及"。）

| 文件 | 处数 | 成员 |
|---|---|---|
| `test_c10_t5_benign_contract.py` | 11 | `get_report_revision`×4、`_t6_revision_diff_payload`×3（留下）、`_apply_honest_analysis_outcome`×2（留下）、`_leftover_official_report_dump`×2（留下） |
| `test_report_evidence_window.py` | 6 | `_select_report_evidence_rows`×6 |
| `test_report_synthesis_performance.py` | 6 | `_snapshot_report_context`×3、`_create_report_revision`×2、`_canonical_sha256`×1 |
| `test_ghidra_performance.py` | 4 | `_select_report_evidence_rows`×4 |
| `test_w4_acceptance.py` | 2 | `get_report_revision`×2 |
| `test_attack_mapping.py` / `test_investigation.py` / `test_service_facade_contract.py` | 各 1 | `get_report_revision` |
| `test_database_regressions.py` | 1 | `_create_report_revision` |
| `test_phase_acceptance.py` | 1 | `publish_report` |
| `test_platform_contracts.py` | 1 | `_migrate_snapshot_payload` |
| `test_report_no_false_negative_facts.py` | 1 | `_select_report_evidence_rows` |

三个搬走的成员**按名字 0 处直接调用**：`recompose_report`、`submit_analyst_draft`、
`workbench_submit_analyst_draft`（它们经 `main.py` 的 HTTP 路由到达）。另有 1 处
`hasattr(AnalysisService, "submit_analyst_draft")`、1 处 docstring 提及、2 处
`service._leftover_official_report_dump = lambda ...`（`test_final_runtime_closure.py:547,586`）。

**"按名字 0 处"不等于"没有行为覆盖"**——这正是本 phase 反复踩的"用名字/字符串代替行为"。
draft gate 的**行为**覆盖在 `test_workbench_report_file.py` 里，经 workbench 路由而非按名字；审查已逐条
打开该文件核实存在且确实在断言这三件事：
* `test_the_write_publishes_the_official_revision`（`:226`）`assert "gate_violations" not in result`；
* `test_rejected_draft_keeps_the_file_and_publishes_nothing`（`:270-274`）`len(revisions) == 1`、
  `revisions[0].id == bound_report.base_revision_id`、`FABRICATED_DRAFT not in revisions[0].markdown`；
* `test_file_route_returns_a_rejection_as_data_not_an_error`（`:431`）`draft_route.status_code == 422`。

这三条就是成功标准 2 的护栏，移动前后必须**同样失败/同样通过**；`__doc__` 读取处
（`test_analyst_draft_submission.py:96`）在 delegation 保留 docstring 的前提下继续工作。

**上面 36 个调用点在本步都不需要改**（同名 delegation 保真，含 `@classmethod`/`@staticmethod`
装饰器与逐参数转发）——这是本步的硬要求。但**"本步不需要改"不等于"永远不用改"**：见第 8 节的归属说明，
测试面改造是 P3.7/P4 的交付物。

## 7. 风险与缓解

| 风险 | 缓解（可检查） |
|---|---|
| classmethod 的 delegation 丢了装饰器 → 按类名调用炸 | 移动后立刻跑 `AnalysisService._select_report_evidence_rows(...)` 的 10 个调用点；delegation 形状门禁（每个 delegation 必须转发每个签名参数） |
| pin 漏成员 → 裸名 NameError | `p34-pin.py --assert` + contract test 双向断言 + **can-fail**：故意去掉一个 pin 成员，断言 contract test 失败 |
| `ReportComposeGateRejected` 迁移改变 identity | service 侧 `X as X` 再导出；加一条 `is` 同一性断言（`service.ReportComposeGateRejected is revision_writer.ReportComposeGateRejected`） |
| draft gate 被"顺手"放宽 | `test_workbench_report_file.py` 的三条行为护栏（通过态无 `gate_violations`、被拒 draft 不改官方 revision、路由 422）移动前后逐条同样通过；本步不改任何 gate 逻辑（只搬位置） |
| `report/` 首次 import `models` 触发新边（**审查确认的硬问题**） | 不靠 deny-list 的沉默：执行步在 `recorded_allowed_edges` + `docs/plan-conflict-resolutions-20260922.md` 记一条 decision（先例 decision (d)），并实测 `report/reporting.py` 今天不 import `models`，即这确实是新边 |
| 大切片（11 个成员 / 795 行） | 分两步：P3.4-1 先搬 4 个纯函数（`_select_report_evidence_rows`/`_migrate_snapshot_payload`/`_canonical_sha256`/`_snapshot_report_context`，pin 仅 2 个 `cls` 成员），P3.4-2 再搬 revision 生命周期（含 `edit_report`）与 exception；每步各自跑满下面 9 道门禁 |
| `.scratch/` 仪器是 gitignored，pin 断言不可从 clone 复现（**审查确认**） | pin 的**权威**断言放在**受跟踪的** contract test（`tests/test_report_revision_writer_contract.py`）里，仪器只是设计期的便利；计划 §4 明确禁止把门禁建立在 `.scratch/` 上 |

## 8. 执行顺序与硬门禁

P3.4-1（纯组装/选择函数）→ P3.4-2（gate + 写入 + 读回 + 发布 + draft + `edit_report` + exception）→ 记录。
每个切片必须过计划 §4 的通用门禁，外加本设计新增的三条：

1. `py scripts/check-slice-tooling.py`（+ `--self-check`）；
2. **can-fail 证明**：篡改必须被断言"已落地"，且逐字节还原；
3. `python -m compileall`（计划 §4.2）；
4. 范围门禁：本步只改 `allowed_files` 列出的文件（计划 §4.1）；
5. `py scripts/check-import-graph.py --strict --policy docs/import-policy.json`（计划 §4.3；新模块到 `models` 的边按上面的 decision 处理，且不得新增反向边或环）；
6. `docker compose config`/`ps` 检查、`--strict --services`、BLOCKED 分类、**禁止跳过 `ghidra-worker`**（计划 §4.4）；
7. focused 测试 → 全量套件 → 行为冻结探针 `structure_behavior_probe.py --check`（计划 §4.5）；
8. 失败集合按**节点集**比较（`.scratch/compare-failure-nodes.py`，绝不用数量）；
9. 提交后 `check-deployed-code-hashes.py --strict --import-smoke`（重建镜像后）并确认 `HEAD == origin/main`。
10. **本设计新增**：受跟踪的 contract test 双向断言 pin（`==` 仪器结果，且仪器结果本身有 can-fail）；
11. **本设计新增**：delegation 形状门禁——每个 delegation 必须转发**每个**签名参数（本 phase 已被咬过两次：
    P3.2e 丢接收者参数、P3.3f-2 丢 `*args, **kwargs`）。

**测试点归属**：这 36 个调用点在本步**继续可用**（同名 delegation 保真），但**不是"永不需要改"**——
计划 §3.3/§P3.7 要求把测试对 private method 的依赖改成输入/输出行为断言、把 private 直接调用改成
概念公开函数或 HTTP facade，那由 **P3.7（测试面改造）与 P4（迁移调用方、删除 shim）** 拥有。
本步只负责"移动后旧出口仍然给出正确值"，不负责"让测试改用新出口"。

## 命令

```
py .scratch/p34-measure.py
py .scratch/p34-measure2.py
py .scratch/p34-pin.py --assert
py .scratch/p34-tests.py
py .scratch/p33f-layer-scan.py --members _create_report_revision,_snapshot_report_context,_t6_revision_diff_payload,get_report_revision,recompose_report,publish_report,submit_analyst_draft,workbench_submit_analyst_draft,_apply_honest_analysis_outcome,_select_report_evidence_rows,_canonical_sha256,_migrate_snapshot_payload --home-module threat_report_agent.report.reporting
```
