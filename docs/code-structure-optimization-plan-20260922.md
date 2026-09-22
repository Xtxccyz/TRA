# 代码结构优化方案（2026-09-22）

日期：2026-09-22  
状态：**方案已写。未收到「按本文开工」之前，禁止按本文搬目录、改产品代码、改测试调用点。**  
读者：按节执行的编码者。一次只做当前阶段里的一步。一步未绿，不开下一步。

本文只优化代码结构。它不替代、也不推进：

- `docs/behavior-driven-investigation-plan-reviewed-20260907.md`（B00–B11、M、T）
- `docs/first-usable-static-analysis-plan-20260916.md`（G0–G5；用户成功只认 3080 路径）

结构改完之后，T1–T8 与 G5 仍是能力缺口。本文完成不等于分析报告已经达到人工样例的能力深度。

配套（开工前读）：

1. 本文第 0–3 节和第 8 节。
2. `CONTEXT.md`（领域词以它为准）。
3. ADR-0002、0014、0024、0025、0035、0036。

**本文件落盘后不自动改产品代码。** 工作区保持 dirty。不 commit，除非另一次明确要求提交。不在宿主执行样本，不访问样本网络端点，不改 API key，不用 `docker compose down -v`。

---

## 0. 开工规则

### 0.1 每次会话

1. 读本文第 0–3 节和第 8 节。
2. 读 `.scratch/code-structure-status.json`。没有就按第 9 节创建，`current_step` 为 `S0`。
3. 只做 `current_step` 这一步。做完再改状态文件。
4. 先有能失败的测试，再改结构，再跑该步点名的 pytest。
5. 结构提交与行为提交分开。同一提交里只有搬家、为搬家而留的重新导出、以及因此必须改的测试调用点。
6. 与行为轨并行时，不要两个人同时改同一文件。行为轨的所有权仍以 `docs/first-usable-static-analysis-plan-20260916.md` 第 0.2 节为准。本文开工期间，`service.py`、`reporting.py`、`analyst_report.py`、`investigation.py` 只允许结构轨一个人写。

### 0.2 行为冻结

每一步的完成定义是：**对外能观察到的分析结果与开工基线一致。** 包括：

- 官方 GET 的分析报告正文仍由 `compose_official_markdown` 生成。
- 创建标志仍须通过 `credible_windows_process_creation_flags`。`0x000f4240` 仍不能当创建标志。
- 解码消费者 Join 仍是对象别名（ADR-0035）。同函数里 API 名共现仍不能记成已链接。
- 验证器仍拒绝把关键词阈值当成证明。不得为了搬家而放宽 `mechanism_is_critical_ready` 或 `static_wording_violations`。
- `STATIC_BOUNDARY` 仍只在真实 `CONTROLLED_EMULATE` 之后。`DEFERRED_TO_WORKER` 仍不算模拟。

### 0.3 基线

2026-09-22 测量：`python -m pytest -q` 为 **6 failed, 2338 passed, 3 skipped**。当时失败为：

- `tests/test_analysis_api.py::test_end_to_end_static_analysis_and_report_revisions`
- `tests/test_deep_static_recovery.py::test_seed_clustering_opens_unique_os_thread_from_recovered_start`
- `tests/test_t3_callback_fixture.py` 中 4 个失败

S0 必须重跑全量，把当时的失败集合写入状态文件。之后每步的全量失败集合不得比该基线多出新失败。既有失败变绿可以保留。

### 0.4 搬家手法

大文件不按行数切开。每一步用同一种手法：

1. 把函数移到它所属的 module。
2. 旧路径留下同名重新导出，调用方先不用改。
3. 该步测试改到新位置，确认绿。
4. 生产调用方改完、测试不再引用旧路径之后，另一步删掉重新导出。

删除与搬家分属不同提交。

---

## 1. 当前测量（2026-09-22）

`src/threat_report_agent` 为扁平包：**58 个 module，92,844 行。**

| 行数 | 文件 | 结构上的问题 |
|---:|---|---|
| 29,588 | `service.py` | `AnalysisService`（约 1201 行起）有 **76 个 public、275 个 private**。编排、规划、调查调度、受控模拟、报告组装叠在同一个 class 里 |
| 11,811 | `reporting.py` | 含 `document_to_markdown`（9677 行）与 `creation_flags_from_callsite`（7106 行） |
| 8,525 | `investigation.py` | 调查循环、账本动作、验证器在同一文件 |
| 7,298 | `static_analysis.py` | 静态恢复，并持有创建标志判定（175、195 行） |
| 6,365 | `analyst_report.py` | 官方正文 `compose_official_markdown`（6217 行）。`_mechanism_catalog_id` 定义了两次（1147 行、2247 行） |
| 2,343 | `persist_how.py` | HOW 的实际写入 |
| 2,088 | `simulation_adapters.py` | Unicorn / Speakeasy / Qiling / flare-emu 适配器 |
| 1,888 | `main.py` | HTTP |
| 1,554 | `model_gateway.py` | 模型网关与截断界 |
| 1,455 | `tool_execution.py` | 工具执行与白名单 |
| 1,236 | `behavior_catalog.py` | 行为目录 1.0.0 |
| 1,131 | `dataflow.py` | `decoded_output_consumer`（331 行） |

已核对的重复出口：

- 生产代码里，官方正文只在 `service.py` 调用 `compose_official_markdown`（24107、29418、29431 行附近）。`document_to_markdown` 的定义在 `reporting.py`，`src/` 内没有其他调用。测试仍大量调用它，集中在 `tests/test_reporting.py`，另有 `tests/test_analyst_report_acceptance.py`、`tests/test_report_bloat_gate.py`、`tests/test_deep_static_semantics.py`、`tests/test_round11_2_pre_cert.py`。
- `analyst_report.py` 的两个 `_mechanism_catalog_id`：1147 行按行内的 `catalog_id` / `mechanism_type` / `verifier_id` 查找；2247 行把字符串交给 `registry.resolve_or_unknown`。Python 在模块加载完成后，同名函数以后者为准。1147 行那份在加载完成后不可达。
- 附录标题：`ANALYST_APPENDIX_HEADING` 为 `## 调查附录（内部账本，非分析结论）`（`analyst_report.py` 41 行）。DSH `threat-tool-provider` 的 `analystPrimaryMarkdown` 用较短的 `## 调查附录` 做切分（`packages/threat-tool-provider/src/index.ts` 453 行）。短前缀碰巧能切中长标题，但是第二份规则。
- 至少 **29 个**测试文件直接点名 `AnalysisService` 的 private 方法，或对其使用 `inspect.getsource`。最大的几份是 `tests/test_investigation_service.py`、`tests/test_reporting.py`、`tests/test_behavior_reporting.py`、`tests/test_pe_entry_function_budget.py`、`tests/test_analyst_report_acceptance.py`。

DSH 有 17 个 package。本方案只动报告切分与停止原因的重复句子。UI 的 `client.ts` 槽位与 `client.js` 实现留在原处。

---

## 2. 目标结构

扁平包改成按领域概念分的子包。旧 import 路径在对应阶段结束前保持可用。

```text
src/threat_report_agent/
  task/            Analysis Task：启动、预算、循环、修订写入
  report/          Analysis Snapshot → 一份分析报告
  investigation/   行为目录、调查循环、验证器、HOW
  facts/           创建标志、解码 Join、数据流谓词
  static/          静态恢复与 Ghidra 适配
  emulation/       受控模拟的计划、隔离、适配器
  model/           模型网关与规划回合
  tools/           工具白名单与 worker 执行
  intake/          样本包进入 Artifact / Content Blob
  http 入口仍是 main.py
```

各包最终收哪些现有文件：

| 包 | 收进的现有文件 | 留在包外、本方案不搬 |
|---|---|---|
| `report/` | `analyst_report.py` 的官方合成、`reporting.py` 的 Document 与评估、`report_verification.py`、`gold_output_bar.py` | — |
| `investigation/` | `investigation.py`、`investigation_protocol.py`、`investigation_ledger.py`、`behavior_catalog.py`、`persist_how.py`、`mechanism_completeness.py`、`mechanism_ready.py`、`semantic_predicates.py` | — |
| `facts/` | `dataflow.py`、`decode_primitives.py`，以及从 `static_analysis.py` 抽出的创建标志判定 | 静态恢复本体留在 `static/` |
| `static/` | `static_analysis.py`、`ghidra_adapter.py`、`literal_table.py`、`function_similarity.py`、`function_simhash.py`、`evidence_recovery.py`、`evidence_index.py`、`static_simulation.py`、`pma_static_plan.py` | — |
| `emulation/` | `simulation_adapters.py`、`emulation_plan.py`、`controlled_emulation.py`、`vb6_runtime_shim.py` | — |
| `model/` | `model_gateway.py`、`agents.py`、`agent_runtime.py`、`prompts.py` | — |
| `tools/` | `tool_execution.py`、`tool_authoring.py` | — |
| `intake/` | `intake.py`、`content_store.py` | — |
| 平台（暂留根包） | `main.py`、`config.py`、`auth.py`、`database.py`、`models.py`、`contracts.py`、`runtime_contracts.py`、`policy.py`、`validation.py`、`observability.py`、`secret_store.py`、`cli.py`、`analysis_trace.py`、`attack_mapping.py`、`methodology.py`、`product_certification.py`、`deep_analysis_quality.py` | 某个阶段碰到它们时再决定是否随该概念搬家。不单独为它们开阶段 |

`task/` 不新写一个调查引擎。它是 `AnalysisService` 拆开之后剩下的编排器，加上已经存在的 `analysis_task_orchestration.py`、`turn_lifecycle.py`、`status.py`。

完成后，调用者要知道的 Analysis Task 表面只有两件事：启动一次 Analysis Task，读取它的 Report Revision。275 个 private 方法不再是测试或 HTTP 要依赖的表面。

---

## 3. 保持不动的架构决定

| 决定 | 约束 |
|---|---|
| ADR-0002 | 调查图仍由编排器掌握。模型只提交带目标、理由、预期证据、成本与风险的 Action Proposal |
| ADR-0014 | 工具产 ToolRun / Evidence。Agent 只产 Claim |
| ADR-0024 | 报告只读一份 Analysis Snapshot。迟到结果不得改写既有 Report Revision |
| ADR-0025 | 一份 Report Document。Markdown 是可编辑正文。HTML、DOCX、PDF 从同一 Document 渲染 |
| ADR-0035 | 解码消费者是对象别名：`api_argument_trace` 或 `value_flow`，已解析，有 API 名、producer、callsite、`argument_index` |
| ADR-0036 | 报告在合成门通过之前是草稿 |

领域词用 `CONTEXT.md`：Artifact、Evidence、ToolRun、Claim、Analysis Task、Analysis Snapshot、Report Document、Report Revision、分析报告、受控模拟、样本保真。

---

## 4. 阶段与步骤

状态文件里的 `current_step` 使用下表的编号。编号顺序就是执行顺序。

### S0 — 钉住基线

不搬代码。

1. 跑 `python -m pytest -q`。把失败节点名写入 `.scratch/code-structure-status.json` 的 `baseline_failures`。
2. 写一条测试，锁定章节解析目录 id 的行为与 2247 行那份一致：`HTTP_DOWNLOAD` 一类 token 经 `resolve_or_unknown` 落到目录 id。这条测试在删除 1147 行定义之前就必须绿，并且在删除之后仍绿。
3. 列出仍调用 `document_to_markdown` 的测试文件，写入状态文件的 `legacy_markdown_callers`。生产路径确认仍只有 `compose_official_markdown`。

完成：状态文件有基线失败集合与旧 Markdown 调用方清单。产品代码无 diff。

### S1 — 删掉被覆盖的目录 id 函数

只动 `analyst_report.py` 1147 行起的第一份 `_mechanism_catalog_id`。

1. S0 的锁定测试已绿。
2. 删除第一份定义。
3. 跑 `tests/test_analyst_report_acceptance.py` 与 `tests/test_behavior_reporting.py`。

完成：模块内只剩 2247 行那一份。章节目录 id 的锁定测试仍绿。全量失败集合不超出基线。

### S2 — 建立 `report/`，官方正文留在原名

1. 新建 `src/threat_report_agent/report/`。
2. 把 `compose_official_markdown`、`ANALYST_APPENDIX_HEADING`、章节渲染所依赖的函数移入该包。
3. `analyst_report.py` 重新导出这些名字，`service.py` 的三处调用先不改。
4. 跑官方 GET 与报告验收相关测试：`tests/test_analyst_report_acceptance.py`、`tests/test_workbench_report_file.py`。

完成：`service.py` 仍 `import` 原路径并得到同一函数对象。正文快照与搬家前一致。

### S3 — 创建标志只留一处判定

判定函数已经在 `static_analysis.py`：`plausible_windows_process_creation_flags`（175 行）、`credible_windows_process_creation_flags`（195 行）。

1. 新建 `facts/`，把这两个函数与 `dataflow.decoded_output_consumer` 的调用关系理清。创建标志函数先迁入 `facts/`，`static_analysis.py` 重新导出。
2. `reporting.creation_flags_from_callsite` 改为调用 `credible_windows_process_creation_flags`，不再自算可信性。
3. `service.py` 与 `analyst_report.py` 里另写的立即数挑选，改为调用同一函数。
4. 跑现有创建标志反例（含 `0x000f4240` 不得当作创建标志的测试）以及 `tests/test_reporting.py` 中覆盖 `creation_flags_from_callsite` 的用例。

完成：可信创建标志只有 `facts/` 里一个实现。三个调用方的重新导出可以暂留，到 S9 再删。

### S4 — 测试改到官方正文，再停用旧 Markdown 出口

`document_to_markdown` 今天只被测试调用。

1. 按 S0 的 `legacy_markdown_callers`，逐个测试文件改成调用 `compose_official_markdown`，或调用它在 `report/` 中的新位置。一个测试文件一步。
2. 每改一个文件就跑该文件。
3. 全部改完且 `src/` 与 `tests/` 都不再调用 `document_to_markdown` 之后，删除该函数。

完成：仓库内搜索 `document_to_markdown` 只剩删除说明或零命中。官方正文测试仍绿。

不要在这一步重写断言去「放宽」报告内容。断言对不上时，先查是测试锁了旧账本格式，还是搬家改变了正文。改变了正文就回退这一步。

### S5 — 删掉 Analysis Task 上的纯转发

只删已经把工作交给别人的方法。

1. 点名 `PersistHow` 的种子判断与 Claim 规格：调用方改为直接用 `persist_how`。删掉 `AnalysisService` 上的同名转发。同一提交改掉调用这些名字的测试。
2. 点名 `analysis_task_orchestration` 的受控模拟续跑：调用方改为直接用该 module。删掉 class 上的转发。
3. 报告修订组装改为调用 `report/`。`AnalysisService` 上留一行调用，HTTP 路径不变。

每组转发单独一步。跑 `tests/test_persist_how.py`、`tests/test_analysis_task_orchestration.py`、`tests/test_investigation_service.py` 里点名被删方法的用例。

完成：`AnalysisService` 不再保存第二份 HOW 写入、第二份模拟调度、第二份正文组装。

### S6 — 把实现从 class 体搬到包内，class 先留委托

循环、规划、预算仍由编排器调用。一次只搬一组方法。class 上留一行委托，测试先不用改。委托的删除放到 S9。

顺序固定：

1. **S6a** 模型规划回合（`_run_model_planning` 及它专用的上下文组装）→ `model/`。跑 `tests/test_truncation_notice_reaches_planning_limitations.py` 与点名 `_run_model_planning` 的测试。
2. **S6b** 调查循环的调度（饱和调查、缺口动作、账本更新）→ `investigation/`，与现有 `investigation.py` 放在一起。不新写第二个循环。跑 `tests/test_investigation_service.py`、`tests/test_investigation_protocol.py`。
3. **S6c** 受控模拟的授予窗口与 worker 派发 → `emulation/`，与 `simulation_adapters.py`、`emulation_plan.py` 放在一起。跑 `tests/test_controlled_emulation.py`。
4. **S6d** 工作台只读查询与修订读取留在 HTTP 旁边的只读 module，不进分析循环。跑 `tests/test_workbench_report_file.py`。

完成：`service.py` 里这四组只剩委托。行为与基线一致。

### S7 — 解码 Join 与验证器各留一个口

1. `decoded_output_consumer` 只留在 `facts/`（自 `dataflow.py` 迁入）。`persist_how` 负责写成 HOW。`investigation` 负责接受或拒绝。
2. `reporting.py` 与 `analyst_report.py` 里用证据文本子串决定章节 HOW 的路径，改为读验证器结果。
3. `analyst_report.verify_model_slot_proposals` 的子串命中改为只问验证器的接受或拒绝。

每条路径一步。ADR-0035 的反例（同函数共现不能算 Join）必须在每一步保持绿色。

完成：关键词或子串不能单独把一条 Claim 标成已链接或已验证。

### S8 — DSH 使用同一附录标题

1. `threat-tool-provider` 的 `analystPrimaryMarkdown` 改为切 `## 调查附录（内部账本，非分析结论）`。标题字符串与 `ANALYST_APPENDIX_HEADING` 保持逐字相同。Python 侧导出该常量；TypeScript 侧复制同一字面量并在 `packages/threat-tool-provider` 的测试里锁定它。不要为这一行引入跨语言生成。
2. 更新 `threat-dsh-workbench/tests/tool-provider-runtime.test.ts`。该测试已经使用长标题。
3. `threat-context-provider` 里复述停止原因、CANDIDATE 不得升格的句子，改为引用后端已经发布的字段。这一步只改文案指向，不改停止条件本身。

完成：切分点与 Python 标题逐字相同。短前缀 `## 调查附录` 不再是第二套规则。

### S9 — 去掉重新导出与 class 委托

按 S2–S8 留下的重新导出和一行委托，逐个删除。每删一个，同一提交更新仍引用旧路径的测试。

`inspect.getsource(AnalysisService._…)` 这类锁源码文本的测试，在对应方法不再是 class 方法时，改成锁行为：给定输入，断言接受、拒绝或正文片段。

新测试只走两种面：

- HTTP：启动 Analysis Task，读取 Report Revision。
- 该概念自己的公开函数：Join、验证器、`compose_official_markdown`。

完成：测试不再把 `AnalysisService` 的 private 方法当作稳定 interface。

### S10 — 其余包的机械搬家

S2–S9 绿了之后，按第 2 节的表把尚未搬家的文件移入 `static/`、`emulation/`、`model/`、`tools/`、`intake/`、`investigation/`。每个包一步。旧路径重新导出，下一步再删。

这一阶段不改函数体。

完成：第 2 节的表与目录一致。根包只剩平台文件与 `main.py`。

---

## 5. 每一步的检查

该步点名的测试文件：

```bash
python -m pytest -q <该步点名的文件>
```

阶段最后一步额外跑：

```bash
python -m pytest -q
```

把失败集合与 `baseline_failures` 比较。多出来的失败先修，再进入下一步。

DSH 的 S8 另跑该包已有的测试（`tool-provider-runtime.test.ts` 所在的 package 脚本）。不把 DSH 测试失败当成 Python 全量的替代。

---

## 6. 怎样算整份方案做完

同时满足：

1. 一个 Report Revision 只有 `compose_official_markdown` 这一条 Markdown 出口。
2. 目录 id 解析在 `analyst_report` 模块内只有一个函数。
3. 可信创建标志只有 `facts/` 里一个实现。
4. 解码消费者 Join 的接受条件只有 `facts/` 里一个实现，验证器是唯一接受口。
5. `AnalysisService` 的调用者只依赖「启动 Analysis Task」和「读取 Report Revision」。private 方法可以仍存在于实现里，测试不再依赖它们。
6. DSH 切分附录使用与 `ANALYST_APPENDIX_HEADING` 逐字相同的标题。
7. 全量 pytest 的失败集合不超出 S0 基线。

行数下降不是完成条件。`service.py` 变短只是 S5、S6、S9 的副作用。

---

## 7. 明确不做

- 按行数把 `service.py` 切成多个无概念边界的文件。
- 在一个分支里重写 `AnalysisService`。
- 让模型直接改调查图、Case 范围、预算或工具权限。
- 为 HTML、DOCX、PDF 再写一套正文。
- 新建第二套 planner、第二套行为目录或第二套验证器。
- 放宽验证器、合成门或静态措辞检查来让测试变绿。
- 把 `tests/test_investigation_service.py` 整文件拆开当作独立目标。它只在被搬家的方法碰到时修改。
- 改 `client.ts` / `client.js` 的界面实现。
- 用本方案去关闭 T1（Speakeasy 整模块窗口）、T2（运行时依赖）、T3（VB6）、T4（常驻 Ghidra）、T6/T7、T8，或 G5 的 3080 用户路径。
- 在宿主执行样本，访问样本 C2，修改 API key，或 `docker compose down -v`。

---

## 8. 与进行中工作的关系

当前工作区有大量未提交的行为改动。结构轨开始时：

- 不还原这些改动。
- 不把结构 diff 与行为 diff 打进同一次提交。
- 行为轨仍在改 `service.py` 时，结构轨停在 S0，不进入 S1。

能力工作（模拟器语义、Ghidra 常驻服务、VB 运行时、用户路径验收）继续走各自的计划。那些计划改到的函数，若已按本文迁走，行为轨改新位置，并在同一提交更新重新导出。

---

## 9. 状态文件

路径：`.scratch/code-structure-status.json`。S0 创建。不提交进 git。

```json
{
  "plan": "docs/code-structure-optimization-plan-20260922.md",
  "current_step": "S0",
  "baseline_command": "python -m pytest -q",
  "baseline_failures": [],
  "legacy_markdown_callers": [],
  "completed_steps": [],
  "notes": ""
}
```

每步结束：把该步编号追加到 `completed_steps`，`current_step` 改为下一步。失败时 `current_step` 不变，`notes` 写失败节点与是否超出基线。
