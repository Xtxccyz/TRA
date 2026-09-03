# Deep Static Analysis 实施报告

日期：2026-09-02  
范围：`analyst-grade-static-malware-report-standard.md`、`universal-static-malware-investigator-agent-prompt.md`、`deep-static-analysis-capability-upgrade-plan.md`  
本轮性质：代码层收口、证据链修复、报告可审查性补全

## 1. 裁决摘要

当前代码已经形成一条可测试的静态证据驱动调查链：

```text
Artifact
  -> static observations
  -> bounded seed map
  -> question/hypothesis
  -> typed static action
  -> derived/observed Evidence
  -> Claim Gate / Verifier
  -> mechanism projection
  -> static behavior flow
  -> critic and sufficiency metrics
  -> report revision
```

本轮确认的代码层结果：

- Seed Map 已持久化并出现在报告中，保留问题、竞争假设、优先级和 Evidence ID。
- `STATIC_DERIVED` Evidence 具有 evaluator、输入 Evidence、输入摘要和输出摘要，可被 Claim Gate 复核。
- 递归 Investigation Loop、优先级队列、Action Catalog、Verifier/Claim Gate 和静态抽象执行均有实现与单测。
- 报告以机制和行为流为主，不把完整 Import/String/Evidence 账本展开成正文。
- 静态报告明确声明不会执行样本、不会进行动态模拟、不会访问样本网络目标。

本轮不能宣称的内容：

- ComHost C1-C4 真实机制尚未通过。
- 真实模型供应商尚未证明产生有效新 Evidence 并贡献 Mechanism。
- 浏览器真实 Upload -> Chat -> Agent -> Action -> Evidence -> Mechanism -> Report 闭环尚未形成可复核记录。
- 长轮次、真实上下文压力、故障注入/重启恢复、生产并发和 24 小时 Soak 尚未完成。
- 因此最终产品 Gate 仍为 `BLOCKED`，不能称为 Production Ready。

本轮还修复了一个回归：语义闭合限制曾被追加到 legacy `task.outcome` 的判断字段，
导致工具链成功但存在静态边界的任务被错误显示为 `PARTIAL`。现在 `outcome` 使用语义
限制追加前的 operational limitation 快照；语义边界仍保留在 `task.limitations`、
`analysis_class`、coverage 和报告中。

## 2. 本轮实现与代码入口

### 2.1 Seed/Question 层

`src/threat_report_agent/static_analysis.py` 的
`build_investigation_seed_map()` 将导入、动态解析、编码数据、网络原语、进程创建、
内存保护、注册表、载荷/插件、环境门和 PE 解析等平面事实聚类为有限数量的高价值问题。
它输出：

- `seed_id`、类别、目标和优先级；
- 具体的可证伪 `question`；
- 竞争 `hypotheses`；
- 来源 `evidence_ids`；
- 面向调度器的 `reason`。

`src/threat_report_agent/service.py` 将 Seed Map 以 `STATIC_DERIVED` Evidence 写入任务，
同时把队列快照和 `SEED_CLUSTER_QUEUED` 事件写入 Investigation 状态。
`src/threat_report_agent/reporting.py` 的 Markdown 投影只展示有限的 Seed Map 摘要，
完整账本仍通过 Evidence Explorer 访问。

### 2.2 Action/Investigation 层

`src/threat_report_agent/investigation.py` 提供：

- `ActionCatalog`：17 种有边界的静态动作，包含 selector、成本、预期 Evidence 和成功条件；
- `InvestigationQueue`：优先级、依赖、去重和步数预算；
- `MultiSeedInvestigationScheduler`：限制活跃线程和 admitted seed 数；
- `ThreadStateMachine`：调查状态合法迁移；
- `Investigator`：按 Playbook 从具体 Evidence 生成后续动作；
- `InvestigationLoopDriver`：执行 `Hypothesis -> Action -> Evidence -> Verification` 循环；
- `Verifier` 与 `ClaimGate`：按机制契约判断支持、未知、矛盾和反驳。

关键约束：

- 未锚定的动作会被拒绝；
- 动作参数必须与 target selector 完全一致；
- `STATIC_DERIVED` 必须携带完整派生 provenance；
- `NO_NEW_EVIDENCE` 只表示有界动作没有产生新证据，不表示假设被反驳；
- 静态 API/import/string 不能单独升级为强行为结论。

### 2.3 语义恢复层

当前包内实现覆盖以下可泛化能力：

- 字符串质量分类及代码字节误识别抑制；
- bounded decoder candidate、公式/状态/消费者校验；
- PE 语义分类，区分 PE Validator、Export/Hash Resolver、Import Resolver、
  Manual Mapper 和 Resource Parser；
- hash resolver 识别与导出表匹配；
- x64/x86 API 参数恢复；
- P-code/CFG 窗口和跨函数 producer -> consumer 关联；
- 静态抽象执行预测（预测不是运行时观察）；
- ComHost 语义关联器及 HTTP/Shell/ETW 专项 verifier。

这些能力的共同原则是：只有输入、变换/控制、条件、输出和消费者形成可追溯链路时，
才提升机制完整度；缺失字段保留为 `UNKNOWN`，不会用导航关系或 API 密度填充。

### 2.4 报告和质量层

`src/threat_report_agent/deep_analysis_quality.py` 提供三类确定性门禁：

1. `report_depth_score()`：按 HOW、流程、解码、函数/参数、安全意义、IOC/Hunting、
   Unknown/Precision 七个维度评分，总分 100，阈值 80。
2. `critic_pass()`：检查未经验证的强标签、缺失竞争假设、闭合机制缺字段、
   静态-only 用词违规以及未记录的 Unknown。
3. `deep_analysis_metrics()`：计算高价值 Seed 闭合率、候选噪声率、机制完整度、
   关键机制闭合率、动作生产率和 Unknown 记录率，并输出
   `READY_FOR_REPORT` 或 `BOUNDED_WITH_LIMITATIONS`。

`reporting.py` 的报告渲染顺序遵循：

```text
Triage -> Deep Investigation -> Mechanism Closure -> Critic/Sufficiency
-> Frozen Snapshot -> Report Revision
```

报告保留 Executive Assessment、Profile、Findings、Obfuscation/Config、Orchestration、
Mechanism Deep Dives、Static Flow、IOC、Hunting、ATT&CK、Unknown/Rejected 和 Coverage。

### 2.5 本轮 provenance 修复

派生观察现在至少保存：

```json
{
  "source_evidence_ids": ["..."],
  "derivation": {
    "evaluator": "static-investigation-v1",
    "input_evidence_ids": ["..."],
    "input_digest": "<sha256>",
    "output_digest": "<sha256>",
    "exact": true
  }
}
```

优先使用同一函数/RVA 的观察证据作为输入；没有同 anchor 证据时，才使用有界的
artifact-local observed Evidence。没有 provenance 的派生证据会被 Claim Gate 降级为
`UNKNOWN`，不会通过放宽门限来“修复”。

## 3. 规范逐项核对

| 规范要求 | 当前判定 | 证据 |
|---|---|---|
| 不停留在 Import/String 列表 | PASS（代码/测试） | 机制投影、参数恢复、静态流、Seed Map、报告反膨胀测试 |
| HOW：输入、变换、条件、输出、消费者 | PASS（代码/测试） | `mechanism_completeness.py`、`test_round11_1_semantic_closure.py` |
| 程序入口到主要能力的静态时序 | PASS（能力/测试） | Investigation timeline、CFG/P-code、静态行为流测试 |
| 竞争假设与主动证据获取 | PASS（控制面/测试） | Playbook、Investigator、Action Catalog、Loop 测试 |
| 解码/混淆优先 | PASS（实现/测试） | decoder 语义门、输出/消费者校验、误检回归 |
| 动态 API/hash resolver | PASS（实现/测试） | PE 语义分类、hash 匹配、间接调用/全局关联测试 |
| 关键 API 参数与 RVA | PASS（实现/测试） | `trace_static_api_arguments()`、x86/x64 参数测试 |
| 机制级 ATT&CK/IOC/Hunting | PARTIAL | 结构和静态约束已存在；真实样本覆盖和外部认证尚未完成 |
| Unknown/Rejected Hypotheses | PASS（代码/测试） | Critic、静态边界、Refutation Gate |
| 报告生成在深度调查之后 | PASS（代码路径/测试） | 深度语义与报告 revision 测试 |
| 静态-only 安全边界 | PASS（代码/测试/既有产物） | Tool Policy、Simulation Adapter、静态用词 Gate |
| 任意支持样本达到人工报告深度 | BLOCKED | 需要真实样本基线、浏览器链路和独立评测证明 |

## 4. 验证计划与已覆盖测试

聚焦回归覆盖：

- `tests/test_deep_static_recovery.py`
- `tests/test_deep_static_semantics.py`
- `tests/test_static_semantics_gap_closure.py`
- `tests/test_static_simulation.py`
- `tests/test_investigation.py`
- `tests/test_investigation_service.py`
- `tests/test_deep_analysis_quality.py`
- `tests/test_reporting.py`
- `tests/test_round11_1_semantic_closure.py`
- `tests/test_round11_product_certification.py`

测试验证的行为包括：Seed 聚类边界、代码噪声抑制、DJB2/hash resolver、PE 语义分类、
解码误检拒绝、参数追踪、Evidence provenance、递归调查、队列预算、Claim Gate、
静态抽象执行、报告深度评分、反膨胀和静态用词。

本轮执行的回归验证覆盖批量上传、ZIP 报告 revision 和本地目录分析，确认三类
“工具链成功但语义存在边界”的任务仍返回 legacy `outcome=COMPLETE`，同时保留
`analysis_class` 与覆盖率中的 bounded 事实。

最终门禁结果（2026-09-02）：

- `python -m pytest -q`：`410 passed, 1 warning`
- `python -m ruff check src tests`：通过
- `python -m compileall -q src tests`：通过
- `release-artifacts/final-runtime-agentic-e2e-gate.json`：`BLOCKED`

## 5. 安全与运行边界

本轮未执行：

- 真实恶意样本；
- flare-emu、Qiling、Speakeasy；
- 样本宏、脚本或 shell；
- 样本指定的 URL、域名、IP 或 C2；
- 未经隔离和策略授权的任意工具。

静态抽象执行只生成确定性的“可能路径/预测”，不冒充动态观察。

## 6. 发布判定

代码层：`PASS`（以测试和静态审查为依据）。  
开发级静态分析能力：`PASS/PARTIAL`（能力存在，真实样本广度和报告深度仍需认证）。  
最终产品：`BLOCKED`。

生产 Gate 只有在以下证据全部形成后才能关闭：真实模型动作产生新 Evidence 并进入
Mechanism、ComHost C1-C4 通过且连续三次成功、真实浏览器闭环、长轮次/上下文压力、
故障注入与恢复、生产并发/Soak、Workspace 浏览器链路和真实恶意/良性基线。
