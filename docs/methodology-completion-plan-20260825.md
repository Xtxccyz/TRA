# 方法论接入补全计划与执行记录

日期：2026-08-25

## 目标

将 `sample-analysis-workflow.md` 的分析链真正接入样本处理流程：

`Survey -> 六维信号 -> Analysis Profile -> Facts 匹配 -> 上下文消歧 -> 可追溯结论`

重点不是增加字段数量，而是让每个结论都能回溯到静态 Evidence，并在报告中解释证据、机制和限制。

## 执行计划

| 编号 | 工作项 | 验收标准 | 状态 |
|---|---|---|---|
| 1 | 方法论中间模型 | Signal、AnalysisProfile、FactMatch、AttributionAssessment 可序列化并带证据 ID | 已完成 |
| 2 | 知识快照 | 内置 `loading-chain-facts.yaml`，记录 SHA-256，分析期间只读 | 已完成 |
| 3 | 六维信号提取 | 从字符串、PE 结构/导入、RVA API、机制 Evidence、脚本/载体 Evidence 提取六维信号 | 已完成 |
| 4 | Facts 匹配与消歧 | 支持 HIT/MISMATCH/PARTIAL，命中只形成 Supporting Evidence | 已完成 |
| 5 | 调度接入 | 模型可提出专项静态动作；策略层保留强制基线与安全边界 | 已完成 |
| 6 | 幂等性 | 容器不进入行为 Profile；Profile/FactMatch 不作为下一轮原始观察；重复动作不新增结果 | 已完成 |
| 7 | 报告/Trace | 报告显示 Profile、命中/排除、机制链、ATT&CK、Evidence ID；Trace 只显示结构化事件 | 已完成 |
| 8 | 真实样本验证 | 密码 ZIP 只内存解压，样本不执行，生成报告并校验审计链 | 已完成 |

## 实现说明

- `src/threat_report_agent/methodology.py` 是方法论模块的唯一入口。
- `AnalysisService._run_methodology_action()` 在静态解析完成后为每个非容器 Artifact 生成 Profile。
- 容器 Artifact 只承担 intake/contains 关系，不直接参与行为信号提取，避免 ZIP 头、文件名和压缩字节造成误报。
- Profile 输入排除 `analysis_profile` 和 `fact_match` 两类派生 Evidence，保证重试不会自我放大。
- 网络识别要求 URL、IP 或保守域名后缀，并排除 Windows 路径、DLL 名称等常见字符串。
- PE 静态结果补充 DLL Characteristics、Rich Header 摘要、CodeView/PDB 路径（如存在）和 RC4 S-box 结构候选，均保留文件锚点并标注为候选证据。
- 模型规划器只能从冻结白名单中选择工具；模型不能跳过基线、执行样本或访问网络。
- 调度器会自动为所有方法论专项动作补上对应 Artifact 的基线解析依赖，即使模型遗漏 `depends_on` 也不能在 Survey 之前运行专项分析。
- 不保存或展示模型私有思维链，仅保存结构化 Agent/调度/方法论 Trace。

## 自审证据

自动化测试：

- `pytest -q`：185 passed
- `python -m ruff check src tests scripts`：通过
- `python -m compileall -q src tests scripts`：通过

新增/修正的关键测试：

- PE 导入和 RVA API 会进入 loading/crypto/C2/anti-analysis 维度。
- 知识库代号只有在原始静态 Evidence 中出现才会命中。
- Windows 路径和 `KERNEL32.dll` 不会被识别为 C2。
- Worker ToolRun 视图正确暴露 `tool` 与 `version`。
- 重复运行方法论动作不会新增 ToolRun、Profile、FactMatch 或 Claim。

真实样本探针：

- 输入：白象密码 ZIP，密码由 Gate 单独提交。
- 处理：内存解压、只读静态解析，未执行样本、宏、脚本或网络访问。
- 结果：3 个 Artifact，其中 2 个可分析 Artifact 生成 Profile；容器 Profile 数量为 0。
- 使用本地 Ghidra 12.1.2/JDK 21 重跑 PE：`ghidra-headless=SUCCEEDED`，报告中存在 function、RVA/Xref、CFG 和 function-similarity Evidence。
- 报告：包含机制链、ATT&CK 映射、Analysis Profile、Evidence ID 和静态限制。
- 审计：方法论事件写入审计链，任务完成后完整性校验通过。

## 能力边界

本轮完成的是可用的确定性静态方法论基线，不应表述为完整逆向或组织归因系统。Rich Header/PDB 当前只做安全的元数据提取，编译器/库版本映射、反编译数据流、跨函数语义证明、动态行为验证、ATT&CK 完整 STIX/RAG、对抗式多 Agent 共识，以及经真实样本标注集验证的阈值校准仍需后续阶段建设。

任何 Fact 命中都只能作为支撑证据；`EXCLUDE_NSA` 只表示当前静态证据未命中该知识快照，不表示样本安全。
