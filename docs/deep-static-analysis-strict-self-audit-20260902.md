# Deep Static Analysis 严格自审报告

审查日期：2026-09-02  
审查依据：

- `F:\迅雷下载\analyst-grade-static-malware-report-standard.md`
- `F:\迅雷下载\universal-static-malware-investigator-agent-prompt.md`
- `F:\迅雷下载\deep-static-analysis-capability-upgrade-plan.md`
- 当前 `src/`、`tests/`、`docs/` 和 `release-artifacts/`

审查方法：源代码逐项核对、测试覆盖核对、既有验收产物核对。仓库没有 Git 元数据，
因此无法执行基于固定 commit 的 diff review；本报告明确采用文件级和运行产物级替代审查。
本次不执行样本、不执行动态模拟器、不访问样本网络。

## 1. 判定规则

- `PASS`：代码路径存在，行为有针对性测试或可复核产物。
- `PARTIAL`：代码能力存在，但样本级/产品级证据不足，或只完成一部分要求。
- `BLOCKED`：存在明确缺口，或外部前提未满足，不能宣称验收通过。

## 2. 逐项矩阵

| 维度 | 判定 | 审查结论 |
|---|---|---|
| Candidate / Seed | PASS | Seed Map 聚类、优先级、问题、竞争假设和 Evidence ID 已生成、持久化、报告可见；有 Seed Map 集成回归。 |
| String quality | PASS | 有 section/xref/可打印性语义分类和代码字节误报抑制；测试覆盖语义字符串与噪声。 |
| Decoder recovery | PASS | 候选必须具备输入读取、输出写入、循环/状态、变换和消费者；直线寄存器清零 XOR 不再被当作 decoder。 |
| PE semantic classifier | PASS | 已区分 validator、export/hash resolver、import resolver、manual mapper 和 resource parser；MZ/PE 检查不会单独升级为 mapper。 |
| Hash resolver | PASS | 可识别受支持的 hash loop 并与导出表匹配；结果标记为静态派生并保存输入 provenance。 |
| Argument recovery | PASS | 支持 API、callsite 和参数索引，覆盖 x64/x86 常量、字符串、全局和未知值；报告输出参数来源。 |
| Cross-function flow | PASS | 支持 caller/callee、xref、producer/consumer、全局指针和静态行为流；关系有 Evidence 锚点。 |
| Investigation loop | PASS | `InvestigationLoopDriver` 实现有界递归；Queue/Action/Verifier/Claim Gate 均有测试。 |
| Sufficiency gate | PASS | `deep_analysis_metrics` 输出 Seed 闭合率、动作生产率、关键机制闭合率、候选噪声、报告深度和阻塞原因。 |
| Self-critic | PASS | `critic_pass` 会拦截未经验证强结论、缺竞争假设、缺字段、静态措辞违规和未记录 Unknown。 |
| Report structure | PASS | 报告有 Executive/Profile/Findings/Config/Orchestration/Mechanism/Flow/IOC/Hunting/ATT&CK/Unknown/Coverage；Seed Map 明确可见。 |
| Evidence provenance | PASS | `STATIC_DERIVED` 需要 evaluator、输入 Evidence ID、input/output digest；Claim Gate 对缺 provenance 拒绝升级。 |
| Static-only safety | PASS | 工具白名单、静态动作策略、Simulation Adapter 和静态用词 Gate 保持 fail-closed；本轮未执行样本。 |
| Agent autonomy | PARTIAL | 控制面支持问题驱动、动作调度和递归；真实模型供应商尚未产生可归因的新 Evidence，不能证明模型主导规划。 |
| Mechanism depth on real samples | PARTIAL | 四样本/历史样本证明了静态管线可运行，但尚无足够的开发集和 Gold 对照证明普遍达到 80 分。 |
| ATT&CK quality | PARTIAL | 有版本化快照和结构映射约束；真实机制覆盖和独立评测尚未完成。 |
| ComHost C1-C4 | BLOCKED | 当前产物仍为 `NOT_VERIFIED`，不能把平面 API 事实升级成四个关键机制。 |
| Model useful-evidence gate | BLOCKED | 最新参与记录中 3 个模型动作均为 `NO_NEW_EVIDENCE`，未证明模型贡献 Mechanism。 |
| Browser product E2E | BLOCKED | 未形成可复核的 Upload -> Chat -> Agent -> Action -> Evidence -> Mechanism -> Report 记录。 |
| Long-turn/context stress | BLOCKED | 没有真实长轮次、跟进消息、切换会话、刷新和上下文压力验收产物。 |
| Fault/restart/recovery | BLOCKED | 没有 Docker/Worker/Temporal/PostgreSQL/MinIO 故障注入和恢复证据。 |
| Concurrency/Soak | BLOCKED | 合成控制面测试不等价于生产并发和 24 小时 Soak。 |
| Workspace browser chain | BLOCKED | API 相对路径和 symlink 防逃逸已测，浏览器导入链路未证明。 |
| Universal malware claim | BLOCKED | “任意样本达到 Resume 深度”需要真实多类型开发集、良性集、Gold 和盲测，当前证据不足。 |

## 3. 关键反证检查

### 3.1 是否把平面事实写成机制？

当前门禁会拒绝以下升级：

- `CreateProcess` import 单独升级为命令执行；
- `VirtualProtect` 单独升级为注入；
- MZ/PE 解析单独升级为手动映射；
- `GetTickCount` 单独升级为反分析；
- 任意 XOR 指令单独升级为解码器；
- 网络 API 或 URL 单独升级为 active C2。

### 3.2 是否把派生证据伪装成观察？

没有。派生证据保留 `STATIC_DERIVED` nature，并要求可复算 provenance。无法满足时
Claim Gate 返回 `UNKNOWN`，不会修改 nature 或放宽门槛。

### 3.3 是否把报告流程完成误认为语义完成？

没有。报告同时记录 semantic coverage、pipeline completion、quality score、
readiness blockers 和 static-only boundary。`SUCCEEDED` 任务仍可为 `PARTIAL` 或
`BOUNDED_STATIC_ANALYSIS`。

### 3.4 是否泄露模型私有思维链？

没有。分析轨迹展示问题、动作、状态转移、结果 Evidence 和验证状态，不展示私有
Chain-of-Thought。该设计符合可追溯性要求，也避免把不可审计的内部推理当作证据。

### 3.5 Task Outcome 与 Analysis Class 是否混淆？

已修复并通过回归。`outcome` 表示输入/工具链是否完成，`analysis_class` 表示静态
语义结果是 FULL、BOUNDED、FAILED 或 UNSUPPORTED。语义闭合不足不会伪装成工具失败，
但仍会在限制、Coverage、Readiness 和报告中显式呈现。

## 4. 当前可接受的产品表述

可以表述为：

> 具备问题中心、证据驱动、静态-only 的递归调查控制面；能够在有足够静态证据时
> 恢复候选解码器、动态 API/hash resolver、关键 API 参数、跨函数关系和机制级报告，
> 并对未知和静态边界保持保守标注。

不能表述为：

- 已完成 Runtime Agentic Product；
- 已通过 ComHost C1-C4；
- 模型已经对样本完成有效自主分析；
- 任意恶意样本都能稳定输出 Resume 级完整报告；
- 已完成生产故障恢复、并发和 24 小时 Soak 验收。

## 5. 自审结论

代码和自动化测试层面：`PASS`。  
静态分析方法论落地层面：`PASS/PARTIAL`。  
真实产品验收层面：`BLOCKED`。

工程备注：`ruff check src tests` 和 `compileall` 通过；`ruff format --check`
当前仓库报告 63 个既有文件需要重排。本轮没有对无关文件做机械格式化，避免产生
与语义修复无关的大范围变更；该项属于代码风格债务，不改变本轮功能测试结论。

该结论与 `docs/final-runtime-agentic-e2e-audit-20260902.md` 一致。除非补齐外部运行
证据和真实样本质量评测，否则不应把发布状态改成 `PASS`。
