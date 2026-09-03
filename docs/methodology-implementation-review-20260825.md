# 方法论闭环实现审查（2026-08-25）

本轮把 `loading-chain-facts.yaml` 与 `sample-analysis-workflow.md` 的要求落入正式分析链。方法论要求的核心不是“列出字段”，而是：

`Survey -> 六维信号 -> 结构化 Profile -> 知识库匹配 -> 上下文消歧 -> 可追溯结论`

## 已实现

- `methodology.py` 定义 `Signal`、`AnalysisProfile`、`FactMatch` 和 `AttributionAssessment`。
- Signal 包含 `type/value/label/context_tags/context_mismatch_keywords/context_note/evidence_ids/anchors`。
- 内置加载并版本化 `knowledge/loading-chain-facts.yaml`，当前包含 26 条事实；知识库 SHA-256 随 Profile 保存。
- 支持 `HIT`、`MISMATCH`、`PARTIAL` 匹配；匹配结果绑定原始 Evidence ID。
- 支持 `EXCLUDE_NSA`、`POSSIBLE_MATCH`、`INCONCLUSIVE`，并同时保存 `expected_verdict` 与 `actual_verdict`。
- 六维信号提取覆盖 loading-chain、cryptography、c2-design、anti-analysis、build-system、codenames；没有证据的维度保留为 0，不伪造信号。
- Profile 和 FactMatch 作为 `Evidence` 持久化，归因 Claim 通过 `ClaimEvidence` 回溯到信号和原始工具观察。
- 报告 attribution 模块显示 Profile、命中事实、上下文排除、匹配率和证据 ID。
- Analysis Trace 增加 `methodology.profile_generated` 与 `methodology.fact_matched` 事件，显示维度、知识库版本、结论和证据引用；不保存私有思维链。
- 模型规划器新增受策略约束的专项动作：`signal-extractor`、`knowledge-fact-matcher`、`rva-xref-query`、`crypto-pattern-scanner`、`c2-protocol-scanner`、`build-metadata-scanner`、`codename-scanner`。这些动作只能追加调查，不能移除强制静态覆盖，也不能执行样本或访问网络。

## 真实样本探针

对 `resource and plan/白象_revers_AGENT/236762036dc5fc664c27bc52760c269539f9418ee2eff25deacda520e8a15d05.zip` 使用密码 `threatbook` 进行内存解压，随后只调用静态解析：

| 指标 | 结果 |
|---|---:|
| Artifact | 3（1 个容器、1 个 PE、1 个解码二进制） |
| Evidence | 1,013 |
| Claim | 5 |
| Analysis Profile | 2（容器不生成 Profile） |
| 知识库命中 | 0 |
| Profile 实际结论 | `EXCLUDE_NSA` |
| 报告/ATT&CK/机制链 | 均已生成 |
| 审计完整性 | `valid=true` |

同一密码 ZIP 在本地 Ghidra 12.1.2/JDK 21 环境再次执行只读 Headless 静态分析：`ghidra-headless=SUCCEEDED`，任务中可见 `function`、`xref`、`cfg_block` 和 `function_similarity` Evidence，审计完整性仍为 `valid=true`。样本本身未被执行。

该结果表示当前静态证据没有形成知识库事实匹配，不代表样本安全，也不代表动态行为不存在；报告会同时保留 `static-only` 限制和未覆盖维度。

## 本轮修正

- 修正方法论幂等性：派生的 `analysis_profile`/`fact_match` 不再作为下一轮原始观察。
- 容器 Artifact 不再直接生成行为 Profile；只对解压/递归得到的可分析 Artifact 建立 Profile。
- 扩展结构化 PE 导入、RVA API、机制 Evidence 和知识库指标的六维信号提取。
- 收紧网络指标识别，避免 Windows 路径、DLL 名称和 `.txt` 文件名误报为 C2。
- 增加服务级重复动作回归测试和真实密码 ZIP 端到端探针。

## 验收

- `pytest -q`：185 passed。
- `python -m ruff check src tests scripts`：通过。
- `python -m compileall -q src tests scripts`：通过。
- 新增方法论单元测试覆盖六维 Profile、Evidence 追溯、HIT、MISMATCH、结论分级。
- 新增 API 集成断言，确认报告包含 Profile 和六维覆盖统计。
- 新增调度测试，确认模型可以在基线动作之外追加专项动作，并按依赖排序。

## 明确边界

- 当前事实库是 `loading-chain-facts.yaml` 的只读版本，不自动把新发现写入知识库；新事实入库仍需人工审核。
- 当前匹配是确定性文本/指标匹配，不等同于组织归因；任何命中都只能作为 Supporting Evidence。
- 当前分析仍是静态分析，不证明运行时执行、C2 实际通信、意图或归因。
- Ghidra 反编译、数据流和动态验证仍由现有 W4/W5 边界控制；方法论 Profile 会引用已有函数/RVA Evidence，但不会把导入存在误写成运行时行为。
