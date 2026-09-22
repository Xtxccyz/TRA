# 代码结构优化执行方案（Reviewed）

日期：2026-09-22  
状态：**执行手册已写，默认不执行。** 只有用户明确授权“按本方案开工”后，DeepSeek 才能按当前步骤修改代码。  
适用对象：需要低上下文、逐步照做的编码 Agent。  
目标：降低耦合、缩小稳定接口、让每一步都可验证、可回滚、可解释。  
非目标：本方案不直接完成 T1-T8、G5、3080 最终验收，也不把结构完成伪装成能力完成。

本方案由 `request-refactor-plan`、`improve-codebase-architecture` 和 `grill-me` 的方法合并而成：小提交、深接口、以行为为测试面，并在文末进行对抗式审查。这里的“模块”“接口”“实现”“深度”“接缝”“适配器”“局部性”“杠杆”按架构 skill 和 `CONTEXT.md` 的定义使用。

---

## 1. 当前状态和结论

### 1.1 已知基线

本次审查观察到：

- `HEAD = 5165a8681221d1e65c3265c857148bc561c0c980`，提交主题为 `structure: first package move (facts/) + a published-layer instrument that can actually fail`。
- 当前工作树在审查时是干净的；DeepSeek 开始执行前必须重新测量，不能把这一事实当作未来状态。
- 最新一次全量测试基线为 `6 failed, 2358 passed, 3 skipped, 2 warnings`。失败集合必须由执行者重新运行并保存，不能手抄旧文档的 `2338 passed`。
- `py -m compileall -q src/threat_report_agent` 已通过。
- `src/threat_report_agent/facts/` 已经存在，`dataflow.py` 和 `decode_primitives.py` 已迁入；旧路径保留 compatibility shim。这个迁移是既有事实，不得再按“从零创建 facts”执行。
- 运行中的 API/emu 容器曾无法导入 `threat_report_agent.facts`，仍只有旧的 `threat_report_agent/dataflow.py`；ghidra-worker 也曾是旧镜像。**源码和镜像不一致是当前硬风险。**

### 1.2 当前结构性风险

- `service.py` 约 1.4 MB、约 29,000 行，`AnalysisService` 同时承担任务编排、调查循环、模型规划、受控模拟、报告修订、HTTP/workbench 查询和失败投影。
- `reporting.py`、`investigation.py`、`analyst_report.py`、`static_analysis.py` 也各自包含多个概念，调用者大量依赖 `AnalysisService` private method 或 `inspect.getsource`。
- `document_to_markdown`、创建标志判定、解码消费者 Join、验证器等存在重复出口或历史兼容出口。
- 目前报告限制传播、compose gate 对具体 limitation bullet 的保留、外部 IOC 阻断、DSH persona 与后端硬预算之间仍有已知行为问题。这些问题不能由结构提交偷偷修复或放宽。

### 1.3 结论

旧方案的领域分包方向可以保留，但直接从 `S0` 搬目录不安全。新的执行顺序必须是：

```text
恢复可观测性 -> 固定依赖方向 -> 建立公开接口和契约测试
-> 小步搬迁并保持 shim -> 最后拆 AnalysisService
-> 清理 shim -> 部署/DSH/行为复验
```

没有 Phase 0 的证据，禁止搬目录。没有部署源码一致性证据，禁止把测试绿报成可运行。

### 1.4 相对旧方案的必要修订

- 旧方案的领域分包表保留，但 `facts/` 已经提前迁移，改为 P0.6 审计和收尾，不重复搬家。
- 原来的直接 `S0-S10` 顺序前增加 P0/P1：先记录基线、镜像 hash、导入图和行为 probe，再建立接缝。
- `AnalysisService` 延后到 Phase 3；先移动纯事实、报告、模型、工具和静态/模拟适配器。
- 兼容 shim、生产调用方、测试调用方、shim 删除拆成不同步骤，防止“只改出口、不改使用者”。
- 将 DSH、API、emu-worker、ghidra-worker 的镜像源码一致性列为硬门，不再只看本机 pytest。
- 把结构状态和能力状态分开，避免结构目录完成被误报成 G5/3080 或人工报告深度完成。

---

## 2. 执行总规约

### 2.1 DeepSeek 每次只做一个步骤

每次开始必须：

1. 读取本文、`CONTEXT.md`、相关 ADR 和 `.scratch/structure-status.json`。
2. 读取 `current_step` 对应的小步骤，不得自行跳步或并行改下一步。
3. 在修改前记录工作树状态和目标文件清单。
4. 只修改该步骤的文件白名单；发现需要越界时停下，写入 `notes`，不要自行扩展范围。
5. 先加入一个会失败的契约测试或门禁，再移动实现。
6. 跑该步骤的 focused tests、静态检查和导入检查。
7. 在阶段末跑全量 pytest，并把失败集合与基线做集合比较。
8. 通过所有门禁后才更新状态文件的 `completed_steps` 和 `current_step`。

每次回复必须包含：`step`、修改文件、未修改文件、命令、结果、失败集合变化、部署检查、下一步。不能只说“已完成”。

### 2.2 当前轮次的安全限制

- 本次只写方案，不改产品代码，不提交。
- 执行阶段不得恢复、覆盖或删除用户已有改动；不得使用 `git reset --hard`、`git checkout --`、`git clean`。
- 不在宿主执行样本，不访问样本网络端点，不修改 API key。
- 不执行 `docker compose down -v`。重建只能按服务进行，保留 PostgreSQL、MinIO、content-data 等既有数据卷。
- 不用 mock、pytest、离线重渲染冒充 3080/C2/C3 或真实 emu-worker 验收。
- 结构步骤不得修改报告语义、验证器门槛、`UNKNOWN/CANDIDATE/PARTIAL/STATIC_BOUNDARY` 的含义；这些变化必须另开行为步骤并有单独验收。
- 未得到单独提交授权时不 commit。后续若获授权，每个小步骤最多一个结构提交，禁止把行为修复混入其中。

### 2.3 结构完成的最小不变量

所有结构步骤都必须保持：

1. ADR-0002：编排器掌握调查图；Agent 只能提交带目标、理由、预期证据、成本和风险的 Action Proposal。
2. ADR-0014：工具产生 ToolRun/Evidence，Agent 产生 Claim；模型文字不是 Evidence。
3. ADR-0024：Report 只读 immutable Analysis Snapshot；迟到结果不能改写既有 Report Revision。
4. ADR-0025：所有 Markdown/HTML/DOCX/PDF 来自一个 Report Document。
5. ADR-0035：解码消费者必须是对象级 alias/join；API 名称共现不是 Join。
6. ADR-0036：Agent draft 在 compose gate 通过前只能是草稿。
7. ADR-0037：样本只能在隔离 worker 中受控处理，不能在宿主执行。
8. 已知的 `0x000f4240` 立即数反例仍不能变成可信创建标志。
9. `DEFERRED_TO_WORKER`、`WORKER_REQUIRED`、`SUPERSEDED_BY_WORKER` 不能伪装成真实模拟结果。
10. 结构重构后，官方正文仍只有一个可追溯的合成出口。

---

## 3. 目标结构和依赖方向

### 3.1 目标目录

```text
src/threat_report_agent/
  task/            Analysis Task 的启动、预算、循环、修订写入
  report/          Analysis Snapshot -> 一个 Report Document
  investigation/  行为目录、调查循环、账本、验证器、HOW
  facts/          创建标志、解码 Join、数据流谓词
  static/         静态恢复和 Ghidra 适配
  emulation/      受控模拟计划、隔离和适配器
  model/          模型网关、规划回合、prompt 装载
  tools/          工具白名单、authoring、worker 执行
  intake/         Artifact/Content Blob 接入
  main.py         HTTP 入口，暂留根包
```

不要为了“看起来分层”复制类型或建立第二个 planner、第二个行为目录、第二个验证器。若循环分析证明需要轻量纯类型模块，优先扩充已有 `contracts.py`/`runtime_contracts.py`；只有在记录 ADR 后才新增 `domain/`。

### 3.2 允许依赖矩阵

箭头表示“可以导入”。未列出的边默认禁止。

| 模块 | 可以导入 | 禁止导入 |
|---|---|---|
| `contracts.py`、纯领域类型 | Python 标准库 | `service`、HTTP、DSH、数据库、模型实现 |
| `facts/` | contracts、标准库 | `service`、`report`、DSH、HTTP |
| `static/` | contracts、facts、静态适配器 | `service`、`report`、DSH |
| `emulation/` | contracts、facts、worker/模拟端口 | `service`、`report`、HTTP、DSH |
| `tools/` | contracts、worker 端口、策略 | `service` 的具体实例、`report`、DSH |
| `intake/` | contracts、存储端口 | `service`、`report`、DSH |
| `investigation/` | contracts、facts、static/emulation/tools 的接口、model port | HTTP、DSH、`main.py`、`AnalysisService` private method |
| `report/` | contracts、facts、investigation 的只读投影 | `service`、HTTP、DSH、模型网关实现 |
| `task/` | contracts、facts、static、emulation、investigation、report、model ports | DSH 具体实现、HTTP request 对象 |
| `main.py` / DSH adapters | task、report、intake、认证和传输适配器 | 反向进入 facts/investigation 的实现细节 |

规则：

- 反向依赖不是“暂时可以”；需要新接缝或适配器。
- 动态 import 也算依赖，必须登记在 allowlist，并有 import smoke test。
- compatibility shim 只能位于旧模块入口；新模块不得反向 import 旧模块。
- 一个概念只能有一个 canonical implementation。重新导出不是第二个实现。

### 3.3 稳定接口

最终对外只承诺：

- Analysis Task：启动、读取状态、读取 Report Revision、受限查询。
- `facts`：对象级 decode consumer join、可信创建标志判定和相关纯谓词。
- `investigation`：调查问题/账本/验证器的结构化输入输出。
- `report`：`Report Document` 和 `compose_official_markdown`。
- worker/tool/emulation：结构化请求、ToolRun、simulation result；不暴露 `AnalysisService` private method。

测试禁止把 private method 或 `inspect.getsource` 当长期接口。迁移期间可暂留测试，但必须在 Phase 4 删除。

---

## 4. 每一步的共同门禁

以下门禁适用于每一个步骤；步骤表只列额外命令。

### 4.1 修改范围门

执行前保存：

```powershell
git status --short
git diff --name-only
```

只允许步骤白名单和 `.scratch/structure-status.json`。出现其他文件变化时停止，记录来源，不还原。

### 4.2 测试门

```powershell
py -m pytest -q <focused tests>
py -m compileall -q src/threat_report_agent
py -m pytest -q
```

全量结果必须与 `baseline_failures` 做集合比较：

- 既有失败变绿：允许，记录为 `baseline_fixed`，不能因此扩大范围。
- 新增任何失败：该步失败，`current_step` 不变。
- 为了绿而删断言、放宽 gate、跳过测试、增加无条件 fallback：立即失败。

### 4.3 导入图门

维护一个可复现的 AST 导入检查脚本（建议放在 `scripts/check-import-graph.py`，不依赖 `.scratch`）：

```powershell
py scripts/check-import-graph.py --root src/threat_report_agent --policy docs/import-policy.json
```

检查：

- 无强连通分量大于 1，除明确登记的标准库循环外；
- 禁止边为空；
- 新包可在干净 Python 进程中 import；
- 旧路径和新路径若是 shim，`sys.modules[old] is sys.modules[new]`，公开函数对象 identity 也一致；
- 不存在两个相同概念的函数实现。

### 4.4 部署一致性门

必须把生产源码 manifest 做成 tracked、可从 fresh clone 运行的脚本，不能依赖被 gitignore 的 `.scratch/check-deployed-code-hashes.py`。manifest 至少覆盖：

- `src/threat_report_agent/**/*.py`；
- API、intake-worker、document-worker、parser-worker、script-worker、control-worker、emu-worker、ghidra-worker 中实际 import 后端代码的服务；
- 变更到 DSH 时，覆盖对应 package 的 lockfile、源码和测试入口。

每个被结构步骤影响的服务都要执行：

```powershell
docker compose config --quiet
docker compose ps
py scripts/check-deployed-code-hashes.py --strict --services <affected services>
docker compose exec <service> python -c "import threat_report_agent.facts, threat_report_agent.report, threat_report_agent.task"
```

镜像不存在、Docker 不可用、源码 hash 不等于当前 HEAD、容器 import 失败，都算 `BLOCKED`，不是“本机 pytest 已绿”。禁止跳过 ghidra-worker 或用旧镜像继续下一阶段。

### 4.5 行为冻结门

每一步都要比较：

- 官方 Report Revision 的正文 SHA（或等价结构化 canonical JSON）；
- Report/HTML/DOCX/PDF 是否仍来自同一 Report Document；
- compose gate 的拒绝/接受反例；
- `decoded_output_consumer` 的正例和“同函数 API 共现”反例；
- `credible_windows_process_creation_flags(0x000f4240)` 反例；
- limitation、UNKNOWN、CANDIDATE、PARTIAL、STATIC_BOUNDARY 的状态投影。

结构步骤不得要求正文“更好看”或“更完整”。正文发生变化时，先判定是搬家导致的回归，还是另一个行为变更；后者必须退出本方案。

---

## 5. Phase 0：冻结现状并恢复可观测性

Phase 0 不搬目录；所有步骤失败都停在原地。它解决旧方案最危险的假设：状态文件缺失、镜像落后、manifest 不完整、导入图不可测。

### P0.1 重新测量工作树和版本

**做什么**：记录 HEAD、分支、工作树、当前包列表、Python/Node/Docker 版本。  
**允许修改**：`.scratch/structure-status.json`、`.scratch/structure-baseline/`。  
**禁止修改**：`src/`、`tests/`、DSH 产品代码。  
**前置条件**：能读取仓库和 Docker 状态。  
**命令**：

```powershell
git rev-parse HEAD
git status --short
py --version
node --version
docker compose config --quiet
rg --files src/threat_report_agent | Sort-Object
```

**成功标准**：status 文件保存 `head_sha`、`dirty_files`、版本、包列表；若仓库已脏，逐项注明“既有/本轮不可碰”。  
**失败处理**：无法识别既有改动就停下；不使用 reset/clean 猜测清理。

### P0.2 生成真实 pytest 基线

**做什么**：重新跑全量和关键 focused tests，保存完整输出及失败节点集合。  
**允许修改**：`.scratch/structure-baseline/pytest-full.txt`、JSON 失败清单。  
**命令**：

```powershell
py -m pytest -q | Tee-Object .scratch/structure-baseline/pytest-full.txt
py -m pytest -q tests/test_dataflow.py tests/test_decode_primitives.py tests/test_primitive_decode_wiring.py tests/test_persist_how.py
```

**成功标准**：`baseline_failures` 是测试节点的稳定集合，不只是一行数字；保存通过数、跳过数、警告数。  
**失败处理**：全量本身失败不阻止 Phase 0，但必须把失败标为 baseline；不得为了基线先修行为。

### P0.3 建立部署源码 manifest 和 strict gate

**做什么**：把所有生产 Python 文件和受影响 DSH package 纳入可复现 manifest；修复现有 gate 对固定 14 个文件和 ignored `.scratch` 的依赖。  
**允许修改**：`scripts/check-deployed-code-hashes.py`、`scripts/migrate-packages.py`、必要的 `docs/dsh-upstream-lock.md`、对应测试；不改业务实现。  
**前置条件**：P0.1 完成。  
**命令**：

```powershell
py scripts/check-deployed-code-hashes.py --self-check
py scripts/check-deployed-code-hashes.py --strict --services api,emu-worker,ghidra-worker
```

**成功标准**：fresh clone 不依赖 `.scratch` 也能生成/校验 manifest；新增 `facts/`、`report/` 等任何生产路径会自动纳入；旧镜像被明确报为 mismatch。  
**失败处理**：Docker 不可用或服务仍旧时写 `deployment_blocked`，不把本机测试当替代。

### P0.4 建立导入图和循环依赖门禁

**做什么**：实现或补强 AST import graph 检查，输出边、反向依赖和循环分量。  
**允许修改**：`scripts/check-import-graph.py`、`docs/import-policy.json`、该脚本的测试。  
**成功标准**：当前 HEAD 有一份可审阅的 graph；旧扁平结构的已知边可被登记，但新增反向边会失败；动态 import 有显式 allowlist。  
**失败处理**：发现现有循环先记录，不借搬家机会顺手重写业务；进入 Phase 1 之前必须至少阻断新增循环。

### P0.5 建立行为冻结探针

**做什么**：生成 deterministic probe，保存纯函数输出、报告 canonical body、Join/flag/gate 反例。  
**允许修改**：`scripts/structure_behavior_probe.py`、`.scratch/structure-baseline/behavior.json`、focused tests。  
**必须覆盖**：

- `compose_official_markdown` 的最小报告；
- heading 存在但 limitation bullet 被丢失时必须被探针识别；
- 外部/未证明 IOC 的当前 gate 状态必须被记录，不能默默变成通过；
- 解码后对象级 alias/join 正例；
- 同函数仅 API 名共现的反例；
- `0x000f4240` 创建标志反例；
- `DEFERRED_TO_WORKER` 不是真实模拟的反例。

**成功标准**：探针结果可在每一步重复，结构迁移前后差异可比较。  
**失败处理**：若探针暴露已知行为 bug，记录为 `known_behavior_gap`，不得在结构提交里修复或放宽。

### P0.6 对齐现有 `facts/` 迁移

**做什么**：审计当前 `facts/`、旧路径 shim、调用方和容器，不重复迁移。  
**允许修改**：只允许补测试、状态和部署 gate；若发现已有迁移缺少证据，不删除代码。  
**成功标准**：

- `threat_report_agent.facts.dataflow` 和旧路径指向同一 module object；
- `dataflow.py`、`decode_primitives.py` 只有一个实际实现；
- API/emu-worker/ghidra-worker import smoke 通过；
- 迁移差异已经写入 status 的 `preexisting_migrations`。

**失败处理**：identity 不一致或容器缺包时，`current_step` 留在 `P0.6`，先修部署/alias 证据，不进入 P1。

---

## 6. Phase 1：建立接缝、接口和结构测试

这一阶段仍不拆 `AnalysisService` 大实现，先让后续搬家有稳定接缝。

### P1.1 发布只读领域投影

**允许修改**：`contracts.py`、`runtime_contracts.py`、必要的新纯类型模块、对应 contract tests。  
**做什么**：定义/确认 `Analysis Snapshot`、`Report Document`、`Report Revision`、`ToolRun`、`Evidence`、`Claim`、`Action Proposal` 的最小结构和不变量。  
**成功标准**：这些类型不 import `service`、数据库连接、HTTP request、DSH 或具体模型 SDK；Report 可以从 immutable snapshot 生成，迟到结果不能改变 revision。  
**失败处理**：若类型需要大量业务逻辑，先建立 protocol/adapter，不把 `AnalysisService` 复制到类型模块。

### P1.2 固定端口和适配器

**允许修改**：`investigation/`、`report/`、`task/` 相关新接口文件和 contract tests。  
**做什么**：定义 `ModelPlanningPort`、`ToolExecutionPort`、`EmulationPort`、`StaticEvidencePort`、`ReportRevisionWriter`、`WorkbenchQueryReader`；接口写明输入、输出、错误、预算和 ordering。  
**成功标准**：至少有一个现有 adapter 和一个 deterministic test adapter；接口比实现小，调用者不需要知道 `AnalysisService` private method。  
**失败处理**：如果端口只是逐字复制大类的 20 个方法，应用 deletion test，缩小接口后再继续。

### P1.3 固化 import policy 和结构差异检查

**允许修改**：`docs/import-policy.json`、`scripts/check-import-graph.py`、`scripts/check-structure-diff.py`、测试。  
**做什么**：结构检查必须拒绝：新反向依赖、重复 canonical implementation、生产文件中的 `inspect.getsource(AnalysisService._...)`、未经登记的旧路径 import。  
**成功标准**：纯搬家 diff 通过；加入一个故意违规的 fixture 时 gate 失败，移除 fixture 后恢复。  
**失败处理**：不要把规则改松来适应当前实现；补 allowlist 只允许已解释的兼容 shim。

### P1.4 建立“结构变更不能混入行为变更”检查

**允许修改**：`scripts/check-structure-diff.py`、测试和文档。  
**做什么**：检查结构步骤是否改动报告 schema、验证器阈值、状态枚举、prompt 语义、预算常量、样本执行策略。  
**成功标准**：纯重命名/移动通过；故意改 `UNKNOWN` 为 `CANDIDATE`、删除 limitation、放宽 compose gate 的 fixture 被拒绝。  
**失败处理**：需要行为修复时分叉为独立 work item，不在当前 step 继续。

---

## 7. Phase 2：按低风险到高风险迁移领域包

### 7.1 共同迁移算法

每个包都严格执行下列 9 步：

1. 列出旧模块中的符号、生产调用方、测试调用方和动态 import。
2. 在新包先建立最小公开接口和 contract test。
3. 移动**同一份实现**，不复制函数体。
4. 旧路径留下 `sys.modules`/re-export shim；新实现不得 import 旧路径。
5. 先改生产调用方到新路径，再逐个改测试调用方。
6. 做 module identity、函数 identity 和 JSON/byte-for-byte 输出比较。
7. 跑 focused tests、compileall、import graph、deployment import smoke。
8. 跑全量 pytest，比较 failure set。
9. 写 checkpoint；只有下一步授权后才删 shim。

失败时保留旧 shim，`current_step` 不变；不把失败测试改成更宽松的断言。

### 7.2 P2-F facts（当前迁移的审计/收尾）

**范围**：`facts/dataflow.py`、`facts/decode_primitives.py`、`static_analysis.py` 中创建标志判定、`reporting.py`/`persist_how.py`/`service.py` 的调用点。  
**允许修改**：`src/threat_report_agent/facts/**`、旧路径 shim、focused tests、scripts；不得修改报告语义。  
**测试**：

```powershell
py -m pytest -q tests/test_dataflow.py tests/test_decode_primitives.py tests/test_primitive_decode_wiring.py tests/test_persist_how.py
```

**额外成功标准**：可信创建标志只有一个实现；`decoded_output_consumer` 只有一个接受口；API 名共现反例仍拒绝；旧/新 import identity 一致。  
**失败处理**：若当前 HEAD 已满足，记录为 `already_present`，只补证据，不再次移动。

### 7.3 P2-R report

**范围**：`analyst_report.py` 的官方合成、`reporting.py` 的 Document/评估、`report_verification.py`、`gold_output_bar.py`。  
**允许修改**：`src/threat_report_agent/report/**`、旧模块 shim、报告 contract tests；不得修改 `service.py` 行为。  
**顺序**：

1. 先删除 `analyst_report.py` 中被后定义覆盖的重复 `_mechanism_catalog_id`，用锁定测试证明解析结果不变。
2. 移动 `compose_official_markdown` 和必要的纯渲染函数。
3. 保留旧路径 re-export，确认 `service.py` 旧 import 得到同一函数对象。
4. 将测试逐个切到新接口。
5. 最后在独立步骤删除 `document_to_markdown` 的旧测试出口；不能把它变成第二个正文出口。

**测试**：`tests/test_analyst_report_acceptance.py`、`tests/test_behavior_reporting.py`、`tests/test_workbench_report_file.py`、`tests/test_draft_cannot_drop_pipeline_limitations.py`。  
**成功标准**：一个 Report Revision 只有 `compose_official_markdown` 产出官方 Markdown；HTML/DOCX/PDF 仍来自同一个 Document；限制 bullet、外部 IOC gate 的冻结探针不变。  
**失败处理**：正文 SHA 改变时先回滚本步结构变更，比较 canonical document，不允许通过删断言解决。

### 7.4 P2-M model

**范围**：`model_gateway.py`、`agents.py`、`agent_runtime.py`、`prompts.py`。  
**允许修改**：`src/threat_report_agent/model/**`、model port/adapter、模型相关 focused tests。  
**成功标准**：model package 只返回结构化 planning/action proposal；不直接改调查图、Case 范围、预算或工具权限；截断和 limitation 字段与 baseline 相同。  
**测试**：`tests/test_truncation_notice_reaches_planning_limitations.py` 及点名 model gateway 的测试。  
**失败处理**：任何 prompt 文义变化、模型 provider 路由变化或 token budget 变化都拆成行为变更，不在本步继续。

### 7.5 P2-T tools

**范围**：`tool_execution.py`、`tool_authoring.py`。  
**允许修改**：`src/threat_report_agent/tools/**`、worker port、tool policy tests；不得让 tools import `AnalysisService`。  
**成功标准**：tool 只产生结构化 ToolRun/Evidence；样本执行仍只能走隔离 worker；工具白名单和失败状态不变。  
**测试**：现有 tool policy、worker isolation、tool execution focused tests。  
**失败处理**：若旧模块为了循环动态 import `service`，先通过 port/adapter 解环，不把循环搬到新包。

### 7.6 P2-I intake

**范围**：`intake.py`、`content_store.py`。  
**允许修改**：`src/threat_report_agent/intake/**`、接入 contract tests。  
**成功标准**：Artifact、Content Blob、样本来源和 hash 的语义不变；intake 不知道 report/investigation。  
**测试**：intake/content store/数据库回归测试。  
**失败处理**：存储 schema 或 hash 变化属于独立数据库/行为变更。

### 7.7 P2-S static

**范围**：`static_analysis.py`、`ghidra_adapter.py`、`literal_table.py`、`function_similarity.py`、`function_simhash.py`、`evidence_recovery.py`、`evidence_index.py`、`static_simulation.py`、`pma_static_plan.py`。  
**允许修改**：`src/threat_report_agent/static/**`、旧 re-export、静态 contract tests。  
**成功标准**：静态恢复只产静态 Evidence/候选，不把 `DEFERRED_TO_WORKER` 写成运行时观察；创建标志判定仍来自 facts。  
**测试**：`tests/test_deep_static_recovery.py`、`tests/test_deep_static_semantics.py`、Ghidra adapter/recovery tests。  
**失败处理**：任何恢复排序、预算、证据等级变化都停止并单独登记。

### 7.8 P2-E emulation

**范围**：`simulation_adapters.py`、`emulation_plan.py`、`controlled_emulation.py`、`vb6_runtime_shim.py`。  
**允许修改**：`src/threat_report_agent/emulation/**`、worker adapter tests。  
**成功标准**：受控模拟请求明确目标、窗口、CPU/墙钟/指令预算和隔离环境；失败区分 `FAILED`、`TIMED_OUT`、`DEFERRED_TO_WORKER`；不把 stub/无网响应写成活 C2。  
**测试**：`tests/test_controlled_emulation.py`、isolation matrix、worker result tests。  
**失败处理**：不能在本机直接运行样本；只能用已有安全 fixture 和隔离 worker contract。

### 7.9 P2-V investigation

**范围**：`investigation.py`、`investigation_protocol.py`、`investigation_ledger.py`、`behavior_catalog.py`、`persist_how.py`、`mechanism_completeness.py`、`mechanism_ready.py`、`semantic_predicates.py`。  
**允许修改**：`src/threat_report_agent/investigation/**`、investigation contract tests；不得直接依赖 HTTP 或 DSH。  
**成功标准**：调查循环由编排器控制；账本明确 OPEN/DEFERRED/CLOSED/UNKNOWN；镜像内可恢复槽位不能因 CANDIDATE 行自动关闭；验证器是接受/拒绝唯一入口。  
**测试**：`tests/test_investigation_service.py`、`tests/test_investigation_protocol.py`、`tests/test_behavior_reporting.py` 中对应纯行为测试。  
**失败处理**：不要为减少行数新写第二个循环；发现循环逻辑重复时先合并 canonical implementation。

### 7.10 P2-TK task

**范围**：`analysis_task_orchestration.py`、`turn_lifecycle.py`、`status.py`，以及后续从 `service.py` 抽出的最小 task facade。  
**允许修改**：`src/threat_report_agent/task/**`、task contract tests；`main.py` 只做必要 import 更新。  
**成功标准**：Task 生命周期、预算和取消语义保持；Task 对外只暴露启动和读取 Report Revision 等稳定操作；HTTP request 对象不进入 task core。  
**测试**：`tests/test_analysis_task_orchestration.py`、analysis API/database regression tests。  
**失败处理**：不要按行数机械切 `service.py`；若没有可命名接缝，先回到 P1 设计接口。

---

## 8. Phase 3：拆 `AnalysisService`，但保留兼容 facade

这一阶段是高风险区。原则是“按职责和接缝拆”，不是“把 29,000 行平均分成几个文件”。每个子步骤结束时 `AnalysisService` 仍可被现有 HTTP 路径构造。

### P3.1 建立 facade 的公开契约

**允许修改**：`service.py`、`task/`、API contract tests。  
**做什么**：明确 facade 只负责依赖组装和稳定操作：启动 Analysis Task、读取状态、读取 Report Revision、授权的 workbench query。  
**成功标准**：新增 contract test 不需要调用 private method；现有 private tests 暂时仍能通过委托。  
**失败处理**：无法定义最小 facade 时停止，不先删除方法。

### P3.2 抽出 `TaskRunner`

**允许修改**：`task/task_runner.py`、`service.py`、task tests。  
**迁移**：任务创建、生命周期、预算、取消、失败/限制投影；保留一行委托。  
**成功标准**：TaskRunner 不 import HTTP/DSH；旧 facade 调用和新公开接口返回同一状态；结构迁移不新增限制丢失。当前已知的模型禁用/失败分支限制缺口必须继续在 `known_behavior_gaps` 中显式记录，修复它属于独立行为任务。  
**测试**：analysis API、task lifecycle、database regressions、limitation propagation focused tests。

### P3.3 抽出 `InvestigationCoordinator`

**允许修改**：`investigation/coordinator.py`、`service.py`、investigation tests。  
**迁移**：调查循环、Action Proposal 验证、账本更新、饱和和尾扫；编排器仍掌握图。  
**成功标准**：模型不能直接改变预算/权限；terminal 后不能继续 dispatch；结构迁移不改变现有预算和 limitation 投影。硬预算耗尽时是否补齐具体 limitation 属于独立行为任务，但不得在结构步骤中被隐藏。  
**测试**：investigation protocol/service、budget、terminal/STOP_DISPATCH tests。

### P3.4 抽出 `ReportRevisionWriter`

**允许修改**：`report/revision_writer.py`、`service.py`、report tests。  
**迁移**：从 immutable Analysis Snapshot 组装 Report Document、执行 compose gate、写入 Report Revision。  
**成功标准**：所有官方正文、聊天、页面和导出仍读取同一个 revision；draft 未过 gate 不能成为官方结论；父 revision identity 不变。  
**测试**：report acceptance、revision identity、workbench report file、draft gate tests。

### P3.5 抽出 `EmulationCoordinator`

**允许修改**：`emulation/coordinator.py`、`service.py`、emulation tests。  
**迁移**：授予窗口、worker dispatch、结果归档、失败分类；不得在 coordinator 内执行宿主样本。  
**成功标准**：真实 simulation result 与占位记录分离；`STATIC_BOUNDARY` 只在真实 `CONTROLLED_EMULATE` 后使用。  
**测试**：controlled emulation/isolation/worker coverage tests。

### P3.6 抽出 `WorkbenchQueryReader`

**允许修改**：`workbench_query.py`、`main.py`、`service.py`、query tests。  
**迁移**：Evidence、timeline、report revision 等只读查询，不进入分析循环。  
**成功标准**：查询不会改变 snapshot/revision；HTTP adapter 不被 investigation 导入。  
**测试**：`tests/test_workbench_report_file.py`、evidence query tests、API read-only tests。

### P3.7 改造测试面

**允许修改**：受影响测试文件和新 contract tests。  
**做什么**：逐个把 `inspect.getsource(AnalysisService._...)` 改成输入/输出行为断言；把对 private method 的直接调用改成概念公开函数或 HTTP facade。  
**成功标准**：生产代码和测试不再把 private method 当稳定 API；测试仍覆盖边界、错误和 ordering。  
**失败处理**：不能通过删除测试“解决耦合”；缺少行为面时先补 contract test。

---

## 9. Phase 4：清理 compatibility shim

只有在 Phase 2/3 全部通过且部署镜像已同步后执行。每个旧出口单独一步。

### P4.1 生产调用方迁移

搜索并清零生产代码中的旧路径 import：

```powershell
rg -n "from threat_report_agent\.(dataflow|static_analysis|reporting|investigation|service) import" src
```

允许 `main.py`/兼容模块暂留 shim，但 canonical implementation 不得再依赖旧路径。成功标准是 import graph 只剩登记的 adapter 边。

### P4.2 测试调用方迁移

逐文件迁移测试；每个文件单独跑。不能把所有测试一次性替换后再猜是哪一步改变了行为。`document_to_markdown` 只剩零命中或迁移说明。

### P4.3 删除旧 shim

一次只删一个 shim 文件或一个 re-export；先运行 identity 反例，确认没有动态 import、插件入口或容器旧路径依赖。失败则恢复 shim（保留可回滚 patch），不要删除调用方。

### P4.4 根包出口收敛

根包只保留平台/HTTP 入口和明确的公开 facade。成功标准：

- `AnalysisService` 的调用者只依赖稳定 facade；
- report/facts/investigation 不 import `service`；
- 根包没有同名第二实现；
- 旧路径在文档中标记为 removed 或 compatibility-only。

---

## 10. Phase 5：结构完成后的复验

“目录完成”不是“最终目标完成”。本阶段必须单独记录结构结果和能力结果。

### P5.1 Python/镜像复验

```powershell
py -m pytest -q
py -m compileall -q src/threat_report_agent
py scripts/check-import-graph.py --strict
docker compose config --quiet
py scripts/check-deployed-code-hashes.py --strict --services api,intake-worker,document-worker,parser-worker,script-worker,control-worker,emu-worker,ghidra-worker
```

任何服务源码 hash 不等于当前 HEAD，结果只能是 `STRUCTURE_READY_LOCAL / DEPLOYMENT_BLOCKED`。

### P5.2 DSH 复验

在 `threat-dsh-workbench` 根目录执行仓库已有脚本：

```powershell
pnpm typecheck
pnpm test
pnpm test:runtime
pnpm manifest
pnpm security
pnpm legacy-guard
pnpm core-guard
pnpm smoke:dsh
```

若环境使用 npm 而不是 pnpm，必须使用等价的现有 package-script 命令并在状态记录中写明。测试至少覆盖：

- `analystPrimaryMarkdown` 使用与 Python `ANALYST_APPENDIX_HEADING` 完全相同的长标题；
- terminal/STOP_DISPATCH 后不继续调度；
- 用户无需手动催促，但后端硬预算仍有效；
- 失败/限制字段来自后端发布字段，不由 UI 文案猜测。

DSH 测试失败不能用 Python pytest 通过来抵消。

### P5.3 真实用户路径验收的前置条件

只有镜像 parity、worker 健康、无运行中任务且得到单独授权后，才按既有 G5 计划执行 benign C1 和 3080 C2/C3。结构方案本身不启动样本分析，不访问样本网络，不把 mock 或旧报告当验收。

### P5.4 能力复验矩阵

必须单独报告：

| 能力 | 证据要求 | 结构完成是否足够 |
|---|---|---|
| report/chat/revision 同源 | 同一 Report Revision identity 和正文 hash | 否 |
| decode -> WinHTTP/CreateProcess object-level join | 新旧正反例、真实报告 evidence | 否 |
| emulation failure distinction | worker result、隔离日志、报告限制 | 否 |
| T3/T4/T7/T8 | 对应行为计划的真实证据 | 否 |
| G5 3080 用户路径 | 新建会话、单句请求、完整报告和限制 | 否 |

### P5.5 最终状态

最终状态必须拆成两个字段：

- `structure_status`: `NOT_STARTED / IN_PROGRESS / READY / BLOCKED`
- `capability_status`: `UNVERIFIED / PARTIAL / BLOCKED / ACCEPTED`

不能因为 `structure_status=READY` 就写 `capability_status=ACCEPTED`。

---

## 11. 状态文件和证据包

路径：`.scratch/structure-status.json`，不提交。执行者不得只写一句“完成”。建议 schema：

```json
{
  "plan": "docs/code-structure-optimization-execution-plan-reviewed-20260922.md",
  "plan_revision": "20260922-reviewed-r1",
  "head_sha": "",
  "current_step": "P0.1",
  "structure_status": "IN_PROGRESS",
  "capability_status": "UNVERIFIED",
  "baseline": {
    "pytest_command": "py -m pytest -q",
    "failures": [],
    "passed": null,
    "skipped": null,
    "warnings": null,
    "captured_at": ""
  },
  "preexisting_migrations": [],
  "legacy_import_callers": [],
  "deployment": {
    "manifest_sha256": "",
    "services": {},
    "blocked_reason": ""
  },
  "completed_steps": [],
  "step_records": [],
  "known_behavior_gaps": [
    "limitation propagation on model disabled/failed paths",
    "compose gate does not yet prove every limitation bullet",
    "unprovenanced IOC detection is currently audit-only",
    "DSH persona wording and backend hard budget need reconciliation"
  ],
  "notes": ""
}
```

每个 `step_records` 项至少包含：

```json
{
  "step": "P2-R.2",
  "started_at": "",
  "finished_at": "",
  "allowed_files": [],
  "changed_files": [],
  "commands": [],
  "focused_result": "",
  "full_result": "",
  "new_failures": [],
  "import_graph": "pass/fail",
  "module_identity": "pass/fail/not_applicable",
  "deployment_smoke": "pass/fail/blocked",
  "behavior_probe_diff": "none/expected/behavior_change",
  "rollback_point": "",
  "decision": "complete/blocked/needs_review"
}
```

若 `decision != complete`，不得推进 `current_step`。

---

## 12. 回滚和失败处理

### 12.1 一般规则

- 失败首先分类：既有 baseline、结构引入、部署漂移、测试假绿、外部环境阻塞。
- 结构引入失败：保留失败证据，撤销**本步自己新增的 patch**；不能用 broad checkout 覆盖他人的改动。
- 部署失败：停在当前 step，重建受影响服务；不删除数据卷、不切换旧镜像继续。
- 发现行为变化：不“修正”正文或降低门槛；回到最后一个 behavior probe 一致的 checkpoint。
- 同一阻塞连续三次仍无法解决时，状态置 `BLOCKED` 并写清需要的外部条件；不能继续空转。

### 12.2 允许的兼容期

shim 可存在，但必须：

1. 指向 canonical module object；
2. 有删除日期/所属 step；
3. 不被新代码依赖；
4. 有 identity smoke test；
5. 不把旧行为复制成第二实现。

### 12.3 不允许的“修复”

以下操作即使能让测试变绿也算失败：

- 删除失败测试或扩大 skip；
- 把精确断言改成只检查标题存在；
- 把 CANDIDATE/UNKNOWN 强升格为 VERIFIED；
- 把 limitation 从失败分支删掉；
- 把 unprovenanced IOC 从阻断改成无条件 warning；
- 将旧镜像、mock、离线 markdown 当作部署/3080 验收；
- 为绕开循环把 `service` 动态 import 塞进 facts/report/investigation；
- 通过复制函数体制造“新模块已完成”的假象。

---

## 13. 提交/PR 切片规则（后续获授权后）

当前不提交。若后续授权提交，按下面切片：

1. `P0`：观测和 gate 工具，不改业务行为。
2. `P1`：接口、导入图、结构 diff gate 和 contract tests。
3. 每个 `P2-*` 包一个独立结构提交。
4. `P3` 每个 coordinator 一个提交，facade 委托和调用方更新同提交。
5. `P4` 每个 shim 删除一个提交。
6. `P5` 只提交文档/验收证据，不把运行时样本结果伪装成结构提交。

每个提交都必须能独立回退并通过当时的 focused tests；禁止一个大提交同时移动 10 个包和修改报告行为。

---

## 14. 对抗式审核：在执行前先攻击这份方案

下面不是“建议”，而是 DeepSeek 每一步都要回答的质疑。任何一项回答不清，步骤保持 blocked。

### 14.1 假绿风险

**质疑**：测试只检查模块能 import 或 heading 存在，是否可能正文已经丢掉具体 limitation、IOC 或 evidence？  
**防线**：P0.5 保存 canonical body 和逐条 limitation/IOC probe；P2-R、P3.4 必须做 byte/JSON-equivalent 比较；只检查标题的测试不算完成。

**质疑**：把 `inspect.getsource` 测试删掉后，是否把行为覆盖一起删掉？  
**防线**：每个删除前先有 public seam contract test；输入、拒绝原因、状态和输出片段必须被断言。

**质疑**：全量 pytest 仍有 6 个 baseline failure，是否会被一句“不是本步造成”掩盖新增失败？  
**防线**：保存节点集合而不是计数；新失败集合非空即 blocked。

### 14.2 循环依赖风险

**质疑**：把 `service.py` 搬进 `task/` 后，facts/report 是否通过动态 import 反向取 service？  
**防线**：P0.4 AST + 动态 smoke；新模块禁止反向 import；需要运行时协作时使用 port/adapter，登记动态 import allowlist。

**质疑**：re-export 是否只是把循环藏起来？  
**防线**：旧模块只能把 `sys.modules[old]` 指向 canonical module；canonical module 不得 import old；identity test 和 graph test 同时通过。

### 14.3 只迁移 shim、没有迁移调用方

**质疑**：目录看起来变了，但 95% 调用者仍 import 旧路径，是否只是换了名字？  
**防线**：每个包有 production caller 和 test caller 清单；P4.1/P4.2 必须用 `rg` 清零未登记旧 import；shim 删除是独立步骤，不能与搬家混写。

### 14.4 部署漂移风险

**质疑**：本机新包可 import，但 API/emu/ghidra-worker 运行的是旧镜像，是否会在用户路径才爆炸？  
**防线**：manifest 覆盖所有生产路径和服务；strict hash 必须等于当前 HEAD；容器 import smoke 是硬门；Docker 不可用只能报告 BLOCKED。

**质疑**：`ghidra-worker` 没有默认 build，是否会被无意跳过？  
**防线**：服务清单显式列出 ghidra-worker；若它无法同步，任何影响静态恢复的包迁移不得进入下一阶段。

### 14.5 行为回归和范围漂移

**质疑**：DeepSeek 为了“重构后更合理”，是否会同时修 limitation、IOC gate、预算或 UNKNOWN 语义？  
**防线**：P1.4 结构 diff gate；已知行为 gap 明确列出；行为修复必须另开计划、另测、另验收。

**质疑**：拆 `AnalysisService` 是否会改变异常/取消/超时投影？  
**防线**：P3.2、P3.3 contract tests 覆盖成功、失败、超时、取消、模型禁用和空响应；每条分支比较状态、限制和 revision identity。

### 14.6 ADR 违规风险

**质疑**：把 investigation coordinator 变成模型直接控制调查图，是否违反 ADR-0002？  
**防线**：Action Proposal 仍由编排器验证和 dispatch；模型 port 不拥有 ledger、budget、tool permission。

**质疑**：把报告渲染放到 DSH 或每种格式各自生成，是否违反 ADR-0025/0036？  
**防线**：ReportRevisionWriter 是唯一官方 Document -> Markdown 出口；DSH 只读取发布字段/正文，不重写结论。

**质疑**：把静态占位记录写成 `STATIC_BOUNDARY` 或 emulation observed，是否违反 ADR-0037？  
**防线**：emulation result schema 区分真实 worker result、失败、超时和 deferred；P2-E/P3.5 负例测试强制保留。

### 14.7 目标偷换风险

**质疑**：结构计划完成后，是否会声称已经达到人工报告深度或 G5？  
**防线**：P5 将 `structure_status` 与 `capability_status` 分开；T1-T8、3080、C2/C3 仍需真实证据；结构测试不算用户验收。

### 14.8 深度和局部性风险

**质疑**：新增的 coordinator 是否只是把 `AnalysisService` 的 30 个参数原样转发，接口仍然浅？  
**防线**：对每个新模块应用 deletion test；接口必须隐藏预算、ordering、错误投影和不变量；若调用者需要知道实现细节，回到 P1 缩小接缝。

---

## 15. 本方案的最终验收清单

只有全部满足才可把 `structure_status` 置为 `READY`：

- [ ] Phase 0 基线、导入图、manifest、行为 probe 均有可审计证据。
- [ ] 新包没有未登记反向依赖或重复实现。
- [ ] `facts`、`report`、`investigation`、`task` 不依赖 `AnalysisService` private method。
- [ ] 官方 Report Revision 只有一个 Document/Markdown 出口。
- [ ] 解码 Join、创建标志、验证器各只有一个 canonical implementation。
- [ ] 所有 shim 的生产调用方和测试调用方已经迁移，shim 删除有独立 checkpoint。
- [ ] 每阶段 focused tests 通过，全量失败集合未增加。
- [ ] 所有受影响容器的源码 hash 等于当前 HEAD，import smoke 通过。
- [ ] DSH package 测试通过，附录标题和停止字段与后端一致。
- [ ] 没有通过放宽断言、删除失败、旧镜像或 mock 获得“通过”。
- [ ] `capability_status` 仍诚实反映 T1-T8/G5/3080 的未验收状态。

最终输出必须说明“完成了哪些结构接缝、还剩哪些能力缺口、哪些证据因部署或外部环境而 blocked”，不能只报目录树或行数下降。
