# W2S/W3/W4 严格完成度审查

审查日期：2026-08-21  
审查范围：输入与基础平台、确定性静态提取、证据与结果模型、单样本深度分析、颗粒度与组件关系、模型适配基线。  
对照资料：`resource and plan/多智能体的深度逆向应用.docx`、`resource and plan/多智能体深度逆向系统.docx`、`resource and plan/多智能体深度逆向系统_补充2.docx`、`resource and plan/ZTW项目进展跟踪.xlsx`（仅工作表“多智能体的深度逆向应用”）、相关 ADR 和 `CONTEXT.md`。

## 1. 审查边界与方法

本目录不是 Git 仓库，无法按 `review` 技能要求提供 commit 固定点和 diff 审查。因此本次固定点为 2026-08-21 当前工作树，采用“需求/ADR 对照 + 代码路径 + 自动化测试 + 真实运行探针”的替代审查方法。没有把历史完成文档当作证据。

安全边界：只做静态分析和可控测试，不执行恶意样本、宏、脚本、嵌入载荷或样本中提取的代码，不把人工参考报告送入 Agent、Prompt、RAG 或分析数据库。

本轮验证结果：

- `python -m pytest -q`：124 passed，1 warning。
- `ruff check src tests`：通过。
- `python -m compileall -q src`：通过。
- `node --check src/threat_report_agent/static/app.js`：通过。
- `docker compose config --quiet`：通过。
- Docker Desktop 当前未运行，因此没有把 Compose、PostgreSQL、MinIO、Temporal 和 Worker 的实时可用性宣称为已验收。
- Ghidra 配置解析为可用；对构造的最小 PE Headless 运行返回 `SUCCEEDED`，但函数数为 0；对真实 Windows PE 的直接运行在 180 秒内 `TIMED_OUT`。代码中存在历史成功输出 `.data/ghidra-actual.json`，但不能替代本轮实时验收。

## 2. 总结结论

| 工作组 | 结论 | 可否宣称“全部完成” |
|---|---|---|
| 输入与基础平台 | 部分完成 | 否，生产依赖和实时部署未验收 |
| 确定性静态提取 | 部分完成 | 否，Ghidra/函数级链路对真实 PE 未稳定闭环 |
| 证据与结果模型 | 部分完成 | 否，背景证据性质未完整落为 Evidence，Validation 仍是预留/候选层 |
| 单样本深度分析 | 部分完成 | 否，B0×D3 对真实 PE 未达到，行为输出不完整 |
| 颗粒度与组件关系 | 部分完成 | 否，关系接口存在但大多数攻击链关系不自动生成 |
| 模型适配基线 | 部分完成 | 否，只有协议级适配和 Mock 测试，没有五类模型的实连验证 |

当前可以如实宣称的是：**静态 MVP 的安全输入、对象模型、确定性解析基础、证据存储、报告快照和模型网关骨架已形成，并有 124 个自动化测试覆盖。不能如实宣称 W2S/W3/W4 的六组任务全部完成或已经达到生产可用。**

## 3. 逐项审查

### 3.1 输入与基础平台

#### 已完成

- 四通道输入已在 `src/threat_report_agent/contracts.py:13-47` 定义：任务请求、样本包、背景上下文、版本化知识快照；`FrozenContract` 使用 `frozen=True` 和 `extra="forbid"`。
- 预设命令和工具白名单在 `src/threat_report_agent/policies/preset-commands.json`、`tool-policy.json` 中冻结，`PolicyRegistry` 计算目录摘要并校验资源上限。
- `CaseRecord`、`AnalysisTask`、`Artifact` 和生命周期状态在 `models.py`、`status.py` 中存在；任务快照、报告快照和审计链路已落库。
- FastAPI API、PostgreSQL 配置、对象存储接口、LangGraph `StateGraph` 和 Temporal Worker 骨架均存在。
- SHA-256 内容寻址、Magic/MIME 识别、只读 Artifact、归档/嵌入对象父子关系和审计事件已实现。
- Prompt Registry、Prompt 版本/摘要、工具策略、样本执行关闭和网络关闭边界已实现。
- 测试覆盖了四通道闭合性、不可变性、策略拒绝、状态迁移、审计不可变和 API 入口。

#### 不足与证据

- 本轮 Docker Desktop 未运行，`docker compose config` 只证明 Compose 语法正确，不证明 PostgreSQL、MinIO、Temporal、API 和各 Worker 的集成可用。
- 业务测试主要使用 SQLite 和本地 Content Store；没有本轮 PostgreSQL + S3/MinIO + Temporal 的完整实时验收记录。
- `Settings` 仍允许开发/测试环境 `tool_execution_mode=local`，虽然生产环境强制 Temporal；这满足开发需要，但不能作为生产隔离已验收的证据。

#### 结论

**部分完成。** W2 的契约、骨架和本地安全链路完成；“平台已经可部署并真实运行”的部分没有在本轮得到证据。

### 3.2 确定性静态提取

#### 已完成

- `static_analysis.py` 实现 PE 头、节区、导入、导出、字符串、熵、脚本 AST/词法、PDF、OOXML、OLE 的静态提取，并为文件偏移、脚本行、PDF 对象和 OOXML 路径生成锚点。
- 载体嵌入对象通过 `extract_embedded_bytes()` 提取为新的只读 Artifact；子 Artifact 会重新进入静态分析队列，宏、JavaScript 和提取载荷不会执行。
- `function_simhash.py` 实现既定的 `charikar-simhash-64`、`mnemonic-4gram`、`md5-prefix-64-le` 成品算法。
- `function_similarity.py` 已加载打包的 `known-functions.yaml`，支持已知函数库和当前任务 Evidence 的有界汉明距离检索；`service.py:_record_function_similarity()` 已接入并写入 `function_similarity` Evidence。
- `TriageAgent` 和 `StaticAnalysisAgent` 已存在；函数优先级排序在 `service.py:2460-2501` 被调用并写入 `FUNCTION_REVIEW_PRIORITY` Claim。

#### 不足与证据

- Ghidra 真实路径不是稳定的本轮闭环：构造的最小 PE 运行成功但未产生函数；真实 PE 运行在 180 秒内超时。因而不能把“存在适配器”写成“函数/Xref/CFG 对真实样本已稳定完成”。
- PE 内建解析器覆盖结构和导入导出，但函数、Xref、CFG 依赖 Ghidra；当 Ghidra 失败时任务正确降为 `PARTIAL/D2`，这同时证明 B0×D3 尚未稳定可用。
- 对脚本的 `StaticAnalysisAgent` 是基于 fact.kind 的确定性规则，不是 LLM 推理。一个实际脚本探针可以产生 7 条 Evidence，但没有行为 Claim；不能把“Agent 类存在”写成“静态语义 Agent 已完成深度解释”。
- 当前自动关系只由归档/嵌入/解码路径产生 `CONTAINS`、`EXTRACTED_FROM`；函数相似性是 Evidence，不会自动形成跨 Artifact 家族结论。

#### 结论

**部分完成。** 静态解析基础和模糊哈希检索代码已完成，但 Ghidra 真实稳定性、函数级证据和 Agent 语义解释尚未达到 Excel 中 W3 的完整要求。

### 3.3 证据与结果模型

#### 已完成

- `models.py` 定义 `Artifact`、`ToolRun`、`Evidence`、`Claim`、`ClaimEvidence`、`Relation`、`AnalysisSnapshot` 和 `ReportRevision`。
- `Evidence.anchor` 保存文件偏移、脚本行、函数入口、RVA、CFG 块、载体内部路径等信息；Evidence 绑定 Artifact 和 ToolRun。
- `Evidence.nature` 默认 `STATIC_OBSERVED`，Claim 使用 `STATIC_INFERRED`；报告和 API 区分 Evidence、Claim、Relation、ModelCall。
- `validation.py` 对模型 Claim 的 Evidence ID、模块和允许范围进行校验；无效引用会被拒绝并形成限制项。
- 报告模块、分析包、快照、重放和篡改检测均有结构化 Schema 和测试。

#### 不足与证据

- `EvidenceNature.BACKGROUND_REPORTED` 在 `status.py` 中定义，但提交的背景上下文主要保存在 `AnalysisTask.request_snapshot` 和报告的 `input_manifest`，没有形成统一的、带来源/时间/可信度锚点的 Background Evidence 行。因此不能宣称四种证据性质已完整落地。
- 第一阶段的 Validation Hook 仍主要是人工 Gate/模型输出验证；独立工具复核和对抗验证属于后续阶段，不能将预留接口称为已完成验证能力。
- 结构化结果正确区分“观察”和“推断”，但确定性 `StaticAnalysisAgent` 直接依据 facts 创建 Claim，缺少单独的“工具观察后再由 Agent 推断”的运行边界说明；当前实现是受控的规则回退，不是完整多智能体语义链。

#### 结论

**部分完成。** 数据模型和引用链较完整，背景证据标准化及真正独立验证尚未完成。

### 3.4 单样本深度分析

#### 已完成

- 单文件任务会冻结 `B0×D3` 目标，载体/目录任务会冻结 `B1×D2` 目标。
- 任务收尾会计算 `actual_granularity`，当必需 Artifact 或 Ghidra 失败时返回限制并降级为 `PARTIAL`，不会伪造 `COMPLETE`。
- Ghidra 输出持久化函数、入口、RVA、Xref、CFG、调用、签名、模糊哈希、函数接口和 IOC Evidence；函数高价值排序 Claim 已写库。
- 脚本行级证据、PDF/OOXML/OLE 嵌入对象和递归静态分析已接入。

#### 不足与证据

- 对真实 PE 的本轮运行得到 `PARTIAL`，`actual_granularity.depth=D2`，限制为 `Ghidra function, Xref, CFG evidence unavailable ... GHIDRA_HEADLESS_FAILED/TIMEOUT`。因此 B0×D3 不能宣称完成。
- 代码输出调用和机制 Evidence，但没有把完整调用关系、输入/输出数据流和行为机制统一聚合为可直接使用的原子 Behavior Claim；当前主要是函数优先级 Claim 和规则型候选 Claim。
- 对脚本，AST/词法事实可有行锚点，但调用关系、输入输出、机制和 IOC 的深度恢复不是普遍能力，取决于简单规则命中。
- IOC 提取主要是 URL、域名、IP 和函数名启发式，不能等同于完整样本级 IOC 恢复。

#### 结论

**部分完成。** 任务状态降级机制是真实可用的，但目标深度本身尚未稳定达标。

### 3.5 颗粒度与组件关系

#### 已完成

- `Claim` 具备 Subject/Action/Object/Mechanism/Condition/Statement/Evidence 引用/Status/Nature/Confidence 字段。
- Artifact 的 `parent_artifact_id`、`role`、`obligation` 和 `logical_path` 支持对象树与组件角色的基本表达。
- `Relation` 和 `add_component_relation()` 支持 `CONTAINS`、`DROPS`、`EXTRACTED_FROM`、`LOADS`、`DECRYPTS`、`EXECUTES`、`INJECTS`，并强制结构关系使用 Evidence、行为关系使用 Claim。
- 报告会把关系状态映射为 `confirmed`、`inferred` 或无关系时的 `unknown`。

#### 不足与证据

- 自动分析链只稳定生成 `CONTAINS` 和 `EXTRACTED_FROM`；`DROPS`、`LOADS`、`DECRYPTS`、`EXECUTES`、`INJECTS` 没有从静态事实/Claim 自动推导的完整管线。
- `confirmed/inferred/unknown` 是报告渲染层对已有 Relation 的映射，不是完整的静态攻击链构建器；没有关系时只能输出 unknown。
- 组件角色来自有限的入库/分诊规则，尚未形成“控制端、植入物、载荷、配置、支持库”等可审计的集合级角色恢复。

#### 结论

**部分完成。** 关系模型和安全约束完成，关系发现与攻击链构建未完成。

### 3.6 模型适配基线

#### 已完成

- `model_gateway.py` 提供统一 `ModelRequest/ModelResponse/ModelAttempt`，记录 provider、model、Prompt 版本、请求/响应摘要、延迟、Token、失败原因和回退原因。
- 支持 OpenAI-compatible `/chat/completions` 和显式 `api_style=anthropic` 的 `/messages`。
- Pydantic `AtomicClaimEnvelope` 强制结构化输出；超时、失败、主模型失败后回退、双模型不可用时保留确定性结果并返回 `PARTIAL` 均有测试。
- 默认配置为 DeepSeek 主模型、GLM 备选模型；具体 URL、模型名和密钥来自运行环境，不进入代码库。

#### 不足与证据

- Excel 要求 GPT、Claude、Qwen、Kimi、GLM 的统一调用基线；当前代码只有协议级通用适配，测试只覆盖 OpenAI-compatible 假提供方和 Anthropic 假接口，未对 GPT、Qwen、Kimi、GLM 的实际 endpoint、鉴权、结构化输出和错误语义分别验收。
- 当前默认 `MODEL_CALLS_ENABLED=false` 时，系统运行的是 `deterministic_static_agent`；这不是实际 LLM Agent。启用开关且未配置凭据时，测试验证为失败尝试并 `PARTIAL`，这是正确降级，但仍不是模型能力验收。
- 没有真实模型凭据和可重复的离线录制响应时，不能宣称“主模型和备选模型已联调完成”。

#### 结论

**部分完成。** 网关边界和降级策略完成，五类模型的实际统一调用基线未完成验收。

## 4. 不能忽略的判定

1. `124 passed` 证明现有测试契约通过，不证明需求中的所有能力已经具备。现有测试大量使用合成输入、Mock Transport、SQLite 和本地执行模式。
2. Ghidra 适配器“可启动”不等于 Ghidra 对真实 PE 的函数/Xref/CFG 管线稳定；本轮真实运行已经观察到超时和零函数结果。
3. `FunctionSimilarityIndex` 已经不是 write-only：它有 catalog + current-task 查询路径和单元测试。但真实样本是否得到可检索函数，仍依赖 Ghidra 成功，故端到端能力只能判定为部分完成。
4. 当前 Agent 是“受控规则 Agent + 可选模型网关”，不是默认启用的多智能体 LLM 系统。这个差异必须在阶段状态和对外文档中保留。
5. 参考报告仍被隔离：报告模块明确记录 `evaluation_baseline_in_context=False` / `not_present`，没有进入模型上下文；这一点符合需求。

## 5. 完成前必须补的工作

### P0：使 W3/W4 真实可用

- 建立可重复的 Ghidra Headless 验收夹具：固定小型、合法、可分析的 PE；固定超时、Java/Ghidra 版本和输出 Schema；对真实 PE 必须得到非零函数、RVA、Xref、CFG，失败时只能 `PARTIAL`。
- 将 Ghidra 运行结果纳入端到端验收，而不是只测适配器和历史 JSON；记录成功/超时/失败三类证据。
- 为函数调用、输入输出、机制、IOC 建立统一的原子 Claim 生成器，并强制每条 Claim 至少引用一个函数/RVA/Xref/CFG Evidence。
- 为 `DROPS/LOADS/DECRYPTS/EXECUTES/INJECTS` 建立确定性关系推导规则；不能只保留手工 API。
- 为脚本和载体建立至少一个真实多组件夹具，验证子 Artifact 重新进入分析、关系和报告闭环。

### P1：补齐 W2S/证据标准

- 将背景上下文规范化为 `BACKGROUND_REPORTED` Evidence，保存来源、时间、可信度、人工确认和冲突关系；仍禁止其覆盖样本 Evidence。
- 在 PostgreSQL、MinIO、Temporal、Worker 实例运行时执行一次端到端测试，记录数据库、对象存储、队列、Worker 和 API 结果。
- 增加“测试是否合成/是否实时/是否 Mock”的验收标签，避免测试通过被误读为生产能力。

### P2：完成模型基线

- 用录制的、去密钥的协议夹具分别覆盖 GPT、Claude、Qwen、Kimi、GLM；至少验证鉴权头、请求路径、结构化响应、超时、限流、错误和回退。
- 明确主/备模型部署配置、模型调用开关和无模型时的对外状态；默认关闭时必须在任务和报告中显示 deterministic fallback。
- 在有授权凭据的环境做一次真实主模型/备模型联调；没有凭据时只能标注“协议兼容已测，生产联调未测”。

## 6. 最终状态

当前工程是一个有安全边界、证据链和可扩展接口的静态分析 MVP 基础，不是六组任务全部完成的 W4 交付版本。对外最准确的阶段描述是：

> W2S/W3/W4 的数据契约、存储、审计、静态解析基础、模糊哈希检索代码、报告快照和模型网关骨架已实现并通过本地自动化测试；真实 Ghidra 函数级闭环、完整 B0×D3、自动攻击链关系、背景 Evidence 标准化和五类模型生产联调仍未完成。

