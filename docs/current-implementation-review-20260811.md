# 当前实现汇总与审查说明

更新时间：2026-08-11  
审查范围：`ZTW项目进展跟踪.xlsx` 工作表“多智能体的深度逆向应用”中的 W2、W3，及其在当前工作区的实现。  
审查依据：项目需求/设计文档、`CONTEXT.md`、W2/W3 验收记录、源代码、测试和本轮独立验证。

## 1. 结论摘要

当前项目已经完成并验证了 Excel 中 W2 和 W3 的核心交付：输入与基础平台、确定性静态提取、证据入库、初版分诊 Agent 和初版静态 Agent。第一阶段的主体框架已经搭建，可以沿着“样本包 → 静态工具 → Evidence → Claim → 报告”的链路继续扩展。

这不等于第一阶段全部发布验收已经完成。W4-W7 中的生产模型网关、完整模块化报告闭环、3-5 个基准样例自动评测、ATT&CK/RAG 完整链路、对抗式 Agent 共识和发布前审计硬化仍属于后续工作，本文单独列出，不将其标记为已完成。

当前第一期仍坚持以下边界：

- 样本只做静态分析，不执行样本、不连接样本指定的外部网络。
- 评测基准报告与分析主链路隔离，只在分析报告生成后用于人工或自动对比。
- 模糊哈希是 `STATIC_OBSERVED` 支撑事实和相似性线索，不单独构成家族归因或攻击者归因。
- 所有分析模块可以持续计算；用户选择模块只影响报告呈现，不会让被隐藏模块停止分析。

## 2. 对照 Excel 的完成状态

| Excel 工作项 | 当前状态 | 实现与审查依据 |
|---|---|---|
| W2：冻结预设命令目录和四通道输入 Schema | 已完成并测试 | Pydantic `FourChannelInput`、冻结的第一期命令目录、版本和摘要校验；额外输入通道会被拒绝。 |
| W2：Case、Analysis Task、Artifact 和状态码 | 已完成并测试 | SQLAlchemy 领域对象、任务生命周期、ToolRun、Claim、Report 状态以及受控状态迁移。 |
| W2：FastAPI、PostgreSQL、对象存储、LangGraph 骨架 | 已完成并验证 | FastAPI 控制面、PostgreSQL 真值层、本地/S3/MinIO Content Store、LangGraph 调查图，以及 Temporal 长工具任务承载。 |
| W2：哈希、Magic/MIME、只读入库和审计 | 已完成并测试 | SHA-256/SHA-1/MD5、Magic/MIME 来源、内容寻址只读存储、ZIP/目录边界检查、审计查询和完整性复核。 |
| W2：系统 Prompt、工具白名单和资源限制 | 已完成并测试 | Prompt 版本/摘要、五类 Worker 队列白名单、只读文件系统、无公网、CPU/内存/PID/超时和临时目录约束。 |
| W3：Ghidra Headless | 已完成并验证 | `GhidraHeadlessRunner` 调用固定版本的 `ExportStaticFacts.java`，在隔离 Worker 中处理临时只读副本。 |
| W3：PE、脚本和文档载体静态解析 | 已完成并测试 | PE 节区/导入/导出/字符串/熵，Python AST 和脚本词法解析，PDF/OOXML/OLE/ZIP 载体识别与嵌入对象线索。 |
| W3：函数、Xref、CFG 提取 | 已完成并测试 | Ghidra 输出函数入口、RVA、助记符、Xref 和 CFG block；Evidence 带有函数、RVA、偏移或载体内部路径锚点。 |
| W3：函数模糊哈希指纹 | 已完成并重新校准 | 已切换到现有成品的 mnemonic 4-gram SimHash 契约，见第 4 节。 |
| W3：入库、分诊 Agent、静态 Agent 初版 | 已完成并验证 | ToolRun 输出写入对象存储，摘要和证据写入 PostgreSQL；分诊与静态 Agent 使用版本化 Prompt 和确定性回退。 |
| W4-W7：一期最终发布验收 | 未完成 | 生产模型、完整评测、ATT&CK/RAG、对抗共识、发布前审计硬化等仍需按第 7 节推进。 |

Excel 中“项目目标”部分仍混有 AI 代码风格和 LLM 归因的模板内容。当前实现没有把模型风格、模型指纹或单一模糊哈希当作确定性归因结论；这部分必须等证据基准、反例和人工 Gate 完成后再作为后续研究能力引入。

## 3. 当前系统是如何实现的

### 3.1 输入、存储和任务边界

1. 用户提交样本包、任务请求、背景上下文和知识快照后，系统创建 `Case` 与不可变的 `Analysis Task`。
2. 输入字节写入按 SHA-256 寻址的 `Content Blob`，原始输入和派生内容形成有来源关系的 `Artifact`。相同字节可以复用 Content Blob，但不同路径的 Artifact 不会被合并。
3. 输入识别先执行 Magic/MIME 和哈希计算，再按 ZIP、目录、PE、脚本或文档载体进入适用的静态工具。解压数量、深度、字节数、路径和加密条目均有硬限制。
4. ToolRun 保存工具版本、参数、资源限制、状态和原始输出引用；大输出保存在对象存储，PostgreSQL 保存摘要、来源和 Evidence 索引。
5. 每个工具只允许在对应 Worker 队列中运行。Worker 使用只读挂载、内部网络、无新权限、能力裁剪和临时工作区；样本内容不会被执行。

### 3.2 确定性静态提取

- Ghidra Headless 通过 `src/threat_report_agent/ghidra_adapter.py` 调度，`src/threat_report_agent/ghidra_scripts/ExportStaticFacts.java` 导出函数、助记符、Xref 和 CFG。
- `src/threat_report_agent/static_analysis.py` 负责格式识别、PE/脚本/文档载体分析、字符串和网络指标提取以及确定性摘要。
- `src/threat_report_agent/service.py` 将工具输出转换为带锚点的 `function`、`function_simhash`、`xref`、`cfg_block` 等 Evidence，并建立 Claim-Evidence 关系。
- Agent 只能根据结构化 Evidence 生成解释性 Claim；Claim 的 Nature 是 `STATIC_INFERRED`，不能伪装成工具观察事实。

### 3.3 报告和评测隔离

报告生成使用冻结的 `Analysis Snapshot`，快照包括 Artifact、ToolRun、Evidence、Claim、Relation 和状态版本。Markdown、DOCX 等 Report Revision 都引用明确的快照，不回写或覆盖原始事实。

评测基准报告不会进入四通道输入、Prompt、知识快照、RAG 或 Agent 上下文。分析完成后，才可以将当前 Report Revision 与人工基准做差异评估。白象样本包可作为多个基准样例之一，但不作为唯一基准。

## 4. 当前模糊哈希的实现方式

### 4.1 采用的成品算法

根目录的 `simhash.py`、`fuzzy_hash.py` 和 `register_crypto_simhashes.py` 是当前算法来源。为了让 Docker/安装包中的主链路不依赖根目录文件，核心逻辑以同一算法契约落在 `src/threat_report_agent/function_simhash.py`；这不是新增算法，而是对现有成品逻辑的正式包内接入。

当前契约如下：

1. 从 Ghidra 得到函数助记符，并统一去空白、转小写。
2. 按连续 4 条助记符生成 4-gram；不足 4 条时使用整个序列作为单个特征。
3. 对每个特征计算 MD5，取前 8 字节并按 little-endian 解释为 64 位整数。
4. 对 64 个 bit 做均匀权重的 Charikar SimHash 累加，正向量位置置 1，负向量位置置 0。
5. 指纹以 16 位十六进制字符串写入 `function_simhash` Evidence；两个指纹通过 64 位汉明距离比较。

Evidence 同时记录：

```json
{
  "algorithm": "charikar-simhash-64",
  "feature": "mnemonic-4gram",
  "hash": "md5-prefix-64-le",
  "value": "..."
}
```

### 4.2 已知函数库

`known-functions.yaml` 收录了 `register_crypto_simhashes.py` 中 8 个静态字节序列的 SimHash 和 ssdeep 参考值。注册脚本已经移除不可移植的硬编码路径，并通过本地库验证了批量注册、距离矩阵和精确检索。

该库只用于静态相似性检索，不是评测基准报告，也不向 Agent 提供未经标注的归因结论。当前库规模有限，不能替代后续的同源/非同源扰动基准集。

### 4.3 使用边界

模糊哈希只能表达“函数指纹与某参考函数的距离较近”这一线索。正式报告必须同时列出函数入口、RVA、调用 API、Xref/CFG、字符串或其他独立静态证据；不能依据“汉明距离小”直接写成“确定属于某病毒家族”。多个视图即使来自同一个 Ghidra ToolRun，也不能被误算为独立证据来源。

## 5. 已完成的审查和测验

截至 2026-08-11，本轮验证结果如下：

- `python -m pytest -q`：88 passed。
- `python -m ruff check src tests scripts`：通过。
- `python -m ruff format --check src tests scripts`：通过。
- `python -m compileall -q src tests scripts`：通过。
- `python -m py_compile simhash.py fuzzy_hash.py register_crypto_simhashes.py ...`：通过。
- `python -m pip install --no-deps .`：wheel 构建和安装通过。
- `docker compose config --quiet`：通过。
- `simhash.py`：相同指纹汉明距离为 0，已知函数检索通过。
- `fuzzy_hash.py`：SimHash 比较和 ssdeep 引擎可执行。
- `register_crypto_simhashes.py`：8 个函数批量注册和距离矩阵可执行。
- 静态链路测试覆盖 Ghidra 委托、函数/Xref/CFG Evidence、ToolRun 引用、重试、取消、Worker 白名单、报告渲染和审计链。

此前的真实容器验收使用 Windows `notepad.exe` 和合成 ZIP 载体进行静态验证；没有执行恶意样本。真实 Ghidra 记录曾成功产出 519 个函数、2,600 个 Xref、6,512 个 CFG block 和 519 个函数指纹。该记录证明链路可运行，不代表所有类型样本都已经完成基准评测。

## 6. 当前尚未完成或不能宣称完成的内容

| 内容 | 当前状态和原因 |
|---|---|
| 生产 Model Gateway、真实模型调用和受限上下文正文留存 | 尚未完成；当前没有主模型凭证时使用确定性回退，因此任务可能是 `SUCCEEDED/PARTIAL`。 |
| W4 单样本 B0×D3 深度分析闭环 | 框架已有，但完整的高价值函数排序、机制、输入输出、IOC 和全链路验收仍需补齐。 |
| 解密、加载器、C2/网络、反分析、证据聚合/归因的完整一期覆盖 | 已有部分静态规则和模块边界，但需按完整样本包和组件关系进行闭环验证。 |
| ATT&CK 本地快照、Behavior Claim 到 Technique 的证据映射 | 计划已定义，完整版本化 RAG 和映射验收尚未完成。 |
| 3-5 个基准样例和自动评测脚本 | 尚未完成；白象只是候选样例之一，不能替代多类型基准。 |
| Agent 对抗式共识 | 尚未执行；SentinelOne 风格的对抗审查需要在证据分歧、成本和人工 Gate 明确后接入。 |
| 独立 Audit Sealer/WORM、完整性封存、分析包导入/重放 | 属于一期发布前硬化，当前不宣称完成。 |
| 模糊哈希鲁棒性基准 | 当前只有成品算法和 8 个参考函数，尚无编译器、优化、混淆、加壳和函数边界误差的标注数据集。 |

## 7. 后续工作计划

### 阶段 A：先完成第一阶段交付闭环

1. 固化 W4 单样本深度分析的输入输出：高价值函数排序、RVA 级锚点、调用关系、输入输出、机制、IOC、脚本行和嵌入对象。
2. 将解密、加载器、C2/网络、反分析和证据聚合统一为静态模块；所有模块都运行，但报告呈现由用户选择模块控制。
3. 完成 Behavior Claim 的原子结构和 `contains/drops/loads/decrypts/executes/injects` 等组件关系，明确 `confirmed/inferred/unknown` 的证据要求。
4. 建立 3-5 个不同类型样例和良性干扰样例，标准答案至少包含 Artifact、关键行为、函数/脚本证据、组件关系、IOC、ATT&CK 候选和未知项。
5. 以 Artifact 提取率、关键行为召回率、精确率、证据覆盖率和虚假 `COMPLETE` 为验收指标，并保存每一版评测结果。

### 阶段 B：接入模型和报告能力

1. 通过 Model Gateway 统一 GPT、Claude、Qwen、Kimi、GLM 等调用，固化模型、Prompt、参数、上下文清单、裁剪、重试、延迟和失败策略。
2. 保持不可信样本数据与系统 Prompt 分区；Agent 只能提交结构化 `Action Proposal`，模型外策略层决定是否执行。
3. Report Document 以结构化事实为共同来源，生成 Markdown、DOCX 等可编辑版本。用户可以隐藏模块呈现，但不能删除依赖模块的分析事实。
4. 报告生成、人工修改、批准和发布都创建独立 Report Revision，并从报告结论追溯到 Claim、Evidence、ToolRun 和输入哈希。

### 阶段 C：升级模糊哈希和对抗验证

这一阶段不改变第一期指纹历史，所有新算法必须独立版本化并保留旧算法结果。

1. 增加语义归一化视图：寄存器类别、立即数类别、相对/绝对地址等操作数抽象。
2. 增加 CFG 结构视图：基本块、边、出度、循环和支配关系；控制流平坦化应作为专门扰动场景测试，不能假设结构天然保持不变。
3. 建立同源/非同源扰动基准库，测试编译器、优化、简单混淆、加壳和函数边界误差，依据距离分布校准阈值。
4. 将多视图结果作为独立的支撑观察写入证据链，只有在证据独立性、冲突处理和人工 Gate 规则明确后，才接入 Agent 对抗共识。
5. 对抗式 Agent 采用“提出主张 → 独立反驳 → 证据裁决 → 冲突 Gate”的串行流程，不能用简单多数票替代证据审查。

### 阶段 D：发布前硬化

完成独立审计封存/WORM、受限审计载荷访问授权、Case 证据销毁 Gate、共享 Content Blob 回收、分析包导入/重放、灾备恢复和完整性回放测试后，才将一期标记为正式发布版本。

## 8. 主要代码和文档入口

- 输入、领域对象和状态：`src/threat_report_agent/contracts.py`、`models.py`、`status.py`
- 静态分析：`src/threat_report_agent/static_analysis.py`
- Ghidra 调度和导出：`src/threat_report_agent/ghidra_adapter.py`、`src/threat_report_agent/ghidra_scripts/ExportStaticFacts.java`
- 证据入库和报告编排：`src/threat_report_agent/service.py`、`reporting.py`
- 成品模糊哈希：`simhash.py`、`fuzzy_hash.py`、`register_crypto_simhashes.py`
- 包内模糊哈希契约：`src/threat_report_agent/function_simhash.py`
- 已知函数库：`known-functions.yaml`
- W2/W3 验收：`docs/w2-w3-completion-audit.md`、`docs/w2-w3-final-validation-20260805.md`
- 模糊哈希后续演进：`docs/function-simhash-evolution.md`

## 2026-08-12 superseding correction

The authoritative current result is `docs/w2-w4-completion-validation-20260812.md` plus
`docs/w2-w4-review-addendum-20260812.md`. Statements below that describe similarity retrieval,
the model adapter, W4 B0xD3 evidence, daily sealing, or evidence purge as absent are historical and
no longer current. W5-W7 production hardening and evaluation remain incomplete.

## 9. 审查结论

当前可以审查和演示的是“第一期静态分析主体框架 + W2/W3 确定性工具闭环”，而不是已经完成所有 W4-W7 的正式发布产品。W2/W3 的核心任务已经有代码、证据链、测试和运行记录支撑；后续开发应优先围绕完整样本包、标准答案、报告可编辑输出、模型网关和评测闭环推进，再进入多视图模糊哈希与 Agent 对抗共识升级。

## 2026-08-14 strict remediation supersession

The current implementation also contains server-side Principal authorization,
production Worker enforcement, task-wide similarity retrieval, REQUIRED
Artifact completion checks, bounded static decoding, Action Proposal policy
auditing, Claim validation, encrypted model payload storage, and report approval
and publication gates. The authoritative status and remaining release blockers
are recorded in `docs/w2-w4-strict-remediation-20260814.md`; this historical
review must not be read as claiming production WORM, OIDC, full recursive
carrier extraction, benchmark certification, or disaster recovery.
