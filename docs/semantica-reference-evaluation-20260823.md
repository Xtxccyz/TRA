# Semantica 参考评估

日期：2026-08-23

## 结论

Semantica 可以作为本项目“可解释、可追溯 Agent 基础设施”的设计参考，但不应在当前阶段直接作为运行时依赖。它的核心价值是把上下文、事实、关系、决策、因果链和 provenance 作为可查询对象；这与本项目现有的 `Artifact -> ToolRun -> Evidence -> Claim -> Relation -> Snapshot` 链路方向一致。

本项目已吸收其中的系统级可解释性思想，新增 `analysis-trace` 视图。该视图说明系统做了哪些可观察步骤、用了哪些工具、读取了哪些 Evidence、形成了哪些 Claim、经过了哪些校验，以及当前的限制和降级状态。它不声称也不尝试恢复模型内部逐字 Chain-of-Thought。

## 实际查阅范围

- 项目主页与 README：<https://github.com/semantica-agi/semantica>
- `pyproject.toml`：版本 `0.6.6`，MIT License，Python `>=3.8`
- README 的 Architecture、Decision Intelligence、Context Graphs、Recipe: Audit Trail 章节
- README 宣布的 `ContextGraph.record_decision()`、`trace_decision_chain()`、`add_causal_relationship()`、`ProvenanceManager` 与 W3C PROV-O 导出模式

## 可借鉴部分

### 1. 决策是一等对象

Semantica 将决策作为可查询对象，并记录场景、结果、置信度和因果关系。本项目对应地将 Agent 结论存为带 `nature`、`status`、`confidence` 和 `model_call_id` 的 `Claim`，并通过 `ClaimEvidence` 强制引用 Evidence。

### 2. 上下文图而不是孤立日志

Semantica 用图结构连接实体和关系。本项目已经有 `Relation`，新增 trace 的 `links` 字段，将 `AnalysisTask`、`Artifact`、`ToolRun`、`Evidence`、`ModelCall`、`Claim` 和 `AgentRun` 连接成可回溯的过程视图。当前实现从 PostgreSQL/SQLite 权威记录实时投影，不引入第二套事实存储。

### 3. Provenance 和审计导出

Semantica 强调来源、版本和可回放。本项目继续以不可变 Analysis Snapshot、哈希链和审计封存作为权威；trace 只读投影审计链，不修改事实，也不把参考报告放入样本分析上下文。

### 4. 确定性规则在模型之外

Semantica 明确“system-level explainability, not foundation-model explainability”。这正是本项目的安全边界：模型可选，确定性静态提取和证据校验始终是主链路；模型失败时保留确定性 Claim 并记录降级事件。

## 不直接引入的部分

- Semantica 核心依赖包含科学计算、NLP、向量、图数据库和可视化等大量组件，会显著扩大恶意样本分析服务的攻击面和镜像体积。
- 当前 W2-W4 的 PostgreSQL 权威模型已经满足证据链要求，引入第二个知识图谱存储会产生双写、版本一致性和证据销毁协调问题。
- RDF/OWL/SHACL、向量检索、通用文档抽取和企业数据连接器不属于当前静态样本交付目标，留待后续阶段按真实需求增加。

## 与“思维链展示”的边界

允许展示：

- 分析阶段和事件顺序
- ToolRun、Evidence、Claim、ModelCall、AgentRun 的标识
- 证据引用关系、验证决定、置信度、限制、失败和降级原因
- 审计链完整性和封存状态

不展示：

- 模型私有逐字思维链或隐藏推理 token
- API Key、原始 Prompt、原始模型请求/响应和加密载荷
- 未经过 Evidence 校验的自由文本推断

这样既能回答“系统为什么形成这个结论”，又不会把不可验证的内部生成文本误当成证据。

## 当前实现

- API：`GET /api/v1/tasks/{task_id}/analysis-trace`
- 数据来源：不可变 `AuditEvent`、`ToolRun`、`Evidence`、`ClaimEvidence`、`Claim`、`ModelCall` 和任务限制
- 输出：阶段化 `steps`、类型化 `links`、`disclosure` 边界说明和审计完整性摘要
- Web UI：结果页新增 `Analysis trace` 视图，可在任务轮询期间持续刷新
- 验证：trace 专项测试、全量测试、Ruff、compileall 和前端语法检查均通过

## 后续演进

1. 需要跨 Case 的家族聚类和相似决策检索时，再评估将 `Relation` 投影到专用图查询索引。
2. 需要合规交换时，增加受控 JSON-LD/PROV-O 导出适配器，仍以 PostgreSQL 和审计封存为权威。
3. 需要多 Agent 对抗时，为每个 AgentRun 增加角色、输入 Evidence 集合、输出 Claim 集合和裁决关系；仍然只展示结构化过程，不展示私有 CoT。
