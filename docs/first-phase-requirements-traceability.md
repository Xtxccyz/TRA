# 第一期需求追踪矩阵

本矩阵把第一期静态分析交付范围映射到需求、设计、计划和验收证据。所有条目当前仅表示需求或设计已经确认，代码实现状态必须在开发过程中另行更新。

## 来源与优先级

1. [项目需求文档](<../resource and plan/多智能体的深度逆向应用.docx>)定义最终成果与业务目标。
2. [总体设计 V0.2](<../resource and plan/多智能体深度逆向系统.docx>)和[静态方案 V0.5](<../resource and plan/多智能体深度逆向系统_补充2.docx>)定义架构与第一阶段能力。
3. [项目进度表](<../resource and plan/ZTW项目进展跟踪.xlsx>)只读取“多智能体的深度逆向应用”工作表，用于任务与排期映射。
4. 已接受的 ADR 记录访谈中确认的新决定；发生冲突时，新决定优先，并在本矩阵中标记计划调整。

## 需求矩阵

| ID | 第一期要求 | 来源 | 已确认设计 | 验收证据 | 计划状态 |
|---|---|---|---|---|---|
| FR-01 | 四通道输入并绑定 Case 与 Analysis Task | V0.5、Excel W2 | 任务请求、样本包、背景上下文、知识快照严格隔离且一期可见 | UI/API 输入清单；报告审计页；基准报告未进入分析上下文 | 已决定 |
| FR-02 | Case 可演进，单次任务可重放与审计 | V0.5、Excel W2 | Analysis Task 启动后输入快照不可变；新增输入创建新任务 | 补充密码后生成 Task 2，Task 1 状态与报告不被覆盖 | 已决定 |
| FR-03 | 样本只读入库并安全识别 | V0.5、Excel W2、访谈决定 | 哈希、Magic/MIME、来源、完整性和敏感输入分离；当前主路径接受本地文件夹和ZIP样本包；密码包、未知格式及其他压缩格式进入Gate 0 | 哈希复算；扩展名伪装测试；文件夹与ZIP保留相同父子路径；加密包和未知格式测试 | 当前关键路径 |
| FR-04 | 第一期交付完整静态分析模块 | 需求 Step 0-6；ADR-0001 | 接入分层、分诊、解密、加载器、C2/网络、反分析、证据聚合/归因全部落地 | 每个模块有真实输入输出、失败状态和端到端样例，不允许空壳 | 需要扩展 W3-W5 |
| FR-05 | 确定性静态提取 | V0.2、V0.5、Excel W3 | Ghidra Headless及PE、脚本、PDF/Office/压缩载体工具通过统一契约运行 | 节区、导入导出、字符串、函数、Xref、CFG、嵌入对象和工具状态 | 已列入计划 |
| FR-06 | 加密加载链递归拆解 | 需求文档、V0.2 | 新产物成为新 Artifact 并重新进入适用模块；按哈希去重并限制递归 | 多层样本产生完整父子关系；未完成 REQUIRED 子项使 Case 降级 | 需要扩展 W3-W4 |
| FR-07 | 动态调查图由受控编排器管理 | V0.2、V0.5、ADR-0002 | Agent只提交下一步提议；策略引擎裁决；编排器调度；人工覆盖 | 越权提议被拒绝；重试、去重、预算、暂停与恢复均可审计 | 已决定 |
| FR-08 | 统一证据与结论对象 | V0.5、Excel W3 | Artifact、ToolRun、Evidence、Claim、Relation形成完整追溯链 | 从报告结论可点击到Claim、工具输出及RVA/偏移/脚本行 | 已决定，需补UI任务 |
| FR-09 | 二维分析颗粒度 | V0.5、Excel W4 | 单样本B0×D3；样本包B1×D2且关键组件D3；事件B2×D2；策略可版本化 | 任务记录目标值、实际值及未达到原因 | 已列入计划 |
| FR-10 | 原子行为和组件关系 | V0.5、Excel W4 | Subject/Action/Object/Mechanism/Condition/Evidence/Status；关系支持包含、解密、加载、执行和注入 | 高价值行为具有机制、条件、证据锚点和组件路径 | 已列入计划 |
| FR-11 | ATT&CK基于行为映射 | V0.5、Excel W5 | Behavior Claim到Technique/Sub-technique；禁止按API或关键词直接映射 | 映射包含理由、用途、版本、Evidence IDs和candidate状态 | 已列入计划 |
| FR-12 | 全模块报告和机器分析包 | 需求文档、V0.5、Excel W6 | 一期实现全部报告模块并默认全选；用户选择只影响呈现 | 同一任务无需重跑即可重组报告；结构化包保留全部分析 | 需调整W6的固定章节表述 |
| FR-13 | 明确任务与发布状态 | V0.5、Excel W6 | COMPLETE/PARTIAL/BLOCKED/UNSUPPORTED与DRAFT/APPROVED/PUBLISHED分离 | 工具失败和证据不足不会产生虚假COMPLETE；报告审批可追踪 | 已决定 |
| FR-14 | 风险分级人工Gate | V0.5、Excel W6、ADR-0004、访谈决定 | 一期启用输入、冲突、资源、报告审批和Case证据销毁Gate；动态执行硬拒绝；知识候选隔离 | Gate 0/2/3/5及Case证据销毁Gate端到端测试；被拒绝动作无副作用 | 输入/冲突/资源/报告进入当前关键路径；Case证据销毁置于一期发布前硬化 |
| FR-15 | 模型与Prompt可替换且可审计 | Excel W4-W6、ADR-0010、访谈决定 | 统一Model Gateway；模块级主/备模型；一期使用OpenAI兼容协议，DeepSeek为主提供方、GLM为回退提供方；实际模型、参数、Prompt和回退事件入链 | 模型切换可见；超时、限流、降级和结构化输出测试；双模型不可用时不静默切换未知服务且任务正确降级 | 当前关键路径 |
| FR-16 | 对抗验证可扩展 | 需求文档、V0.2、V0.5、ADR-0009 | 一期落地Validation Hook、共识Schema、拒绝记录和人工裁决；后续接入IDA/Unicorn串行Gauntlet | 高价值Claim可完成同源挑战；不得伪装为多工具独立验证 | 需扩展W6并保留后续阶段 |
| FR-17 | 候选知识与已验证知识隔离 | 需求文档、V0.2、V0.5 | 案件证据可积累；候选知识不进入RAG；后续经Gate 4晋升且可撤销 | 候选污染测试；知识版本和撤销依赖测试 | 需补充一期契约任务 |
| FR-18 | 参考报告与分析流程隔离 | V0.5、访谈决定 | 评测基准报告只供离线评估，不进入输入、Prompt、RAG或生成上下文 | 分析运行审计中不存在基准报告哈希或内容 | 需补充评测隔离任务 |
| FR-19 | 第一期禁止未知代码执行和外联 | V0.5、Excel W5-W7 | 不运行样本、宏、脚本、Unicorn或沙箱，不访问C2和开放互联网 | 安全回归、Prompt Injection和越权工具调用测试全部被拒绝 | 已列入计划 |
| FR-20 | 后续能力无需推翻主链路 | 需求文档、V0.2/V0.5、ADR-0003/0005 | 工具、证据性质、验证节点、动态权限、知识和发布契约可增量扩展 | IDA/Unicorn契约测试；历史Task无需迁移即可引用新来源 | 已决定 |
| FR-21 | Artifact角色与分析义务分离 | V0.5、ADR-0011 | Role描述载体、加载器、载荷、配置等作用；Obligation使用REQUIRED/SUPPORTING/EXCLUDED | 未达标REQUIRED阻止COMPLETE；未知对象不能静默排除；排除理由可审计 | 已决定 |
| FR-22 | 内容去重但来源链不丢失 | V0.5、ADR-0012 | Content Blob按SHA-256去重；Artifact保留Task、路径、父载体和发现关系 | 相同哈希多路径只存一份字节，但报告可分别还原每次出现及角色 | 已决定 |
| FR-23 | Relation具有证据和状态 | V0.5、ADR-0013 | 结构与行为关系均为有向版本化对象，使用受控类型并绑定Evidence或Claim | 组件图、加载链和攻击链可由Relation重建；rejected关系保留 | 已决定 |
| FR-24 | ToolRun、Evidence与Claim严格分层 | V0.2/V0.5、ADR-0014 | 工具输出不可变；Evidence必须有锚点；Agent只能产生引用Evidence的Claim | 无锚点Evidence被拒绝；工具失败使依赖Claim降级；模型文本不能进入事实层 | 已决定 |
| FR-25 | 高价值行为使用原子Claim | V0.5、Excel W4、ADR-0015 | 每个Behavior Claim只表达一个Subject/Action/Object/Mechanism/Condition组合 | 多行为能力拆分；ATT&CK逐Claim映射；报告聚合不产生新事实 | 已决定 |
| FR-26 | Evidence与推断性质分离 | V0.5、ADR-0016 | Evidence使用STATIC_OBSERVED/BACKGROUND_REPORTED/DYNAMIC_OBSERVED；STATIC_INFERRED属于Claim Nature | 报告保持四类显示标签；内部不能把Agent推断存为工具观察 | 已决定，可版本化调整 |
| FR-27 | 运行状态与分析结果分域 | V0.2/V0.5、Excel W2/W6、ADR-0017 | Task Lifecycle、ToolRun Status、Analysis Outcome、Claim Status和Report Status分别管理 | 等待Gate不误报BLOCKED；工具重试不提前降级；SUCCEEDED可对应PARTIAL | 已决定 |
| FR-28 | Temporal真实承载长ToolRun | V0.2/V0.5、ADR-0018 | 一期以生产形态受控切片接入Temporal，LangGraph/PostgreSQL仍为调查决策与业务真值层 | Ghidra任务支持幂等、超时、重试、心跳、取消及服务重启恢复 | 需补入Excel W2-W3 |
| FR-29 | 静态工具处理不可信输入时隔离执行 | V0.2/V0.5、ADR-0019 | ToolRun在非管理员、无公网、只读样本和受限资源的隔离Worker中执行 | 逃逸面、网络、存储权限、资源限制和临时目录销毁通过安全测试 | 已决定，需补隔离任务 |
| FR-30 | Prompt Injection不能跨越模型外权限边界 | V0.5、Excel W5、ADR-0020 | 样本、背景、RAG和工具输出均视为不可信数据；Agent只提交结构化提议 | 人工注入样例被保留为Evidence但无法改Prompt、预算、工具、Case或报告要求 | 已决定 |
| FR-31 | PostgreSQL与对象存储职责明确 | V0.2/V0.5、Excel W2、ADR-0021 | PostgreSQL+JSONB保存业务对象与关系；MinIO/S3保存大对象；pgvector仅作召回 | COMPLETE报告可追溯存储索引；相似度不能自动形成Claim或归因 | 已决定 |
| FR-32 | API核心可迁移且一期展示最小化 | Excel W6、ADR-0022 | Versioned FastAPI与模块化单体控制面为主，Web UI只覆盖必要演示路径 | 其他平台可替换UI；一期可展示四通道、任务/Gate、报告和证据跳转 | 已决定 |
| FR-33 | 性能以单Case端到端时延为首要指标 | 需求文档、Excel W6、ADR-0023 | 固定环境测量B0/B1完成时延，吞吐、资源与成本作为次级指标 | W4建立基线后版本化门槛；人工等待独立统计；质量与安全指标不回退 | 已决定 |
| FR-34 | 分析并行流水化且报告读取一致快照 | 需求文档、V0.2/V0.5、ADR-0024 | 独立Artifact和模块并行，依赖与Gauntlet保持有序；最终报告绑定Analysis Snapshot | 并发结果增量可见；同一报告无跨版本Claim；终态Task不被迟到结果改写 | 已决定 |
| FR-35 | 报告同时支持机器交换、编辑和归档 | V0.5、ADR-0025 | JSON分析包；Markdown主编辑格式；HTML/DOCX/PDF由同一Report Document渲染 | 用户编辑生成新Revision；Claim引用保留；MANUAL_EDIT不反向污染Evidence | 已决定 |
| FR-36 | 身份与Gate权限可移植 | V0.5、ADR-0026、访谈决定 | OIDC/JWT Auth Adapter、RBAC和Service Account；Analyst、Reviewer、Operator、Auditor和Admin职责分离；演示模式显式隔离 | API服务端校验权限；Gate与Revision记录真实Principal；受限审计载荷默认拒绝；应急审计访问须由不同Principal的Admin批准、范围受限、最长24小时并逐次审计；Case证据销毁须申请、Reviewer复核和另一名Admin执行授权三方分离；保留冻结创建与解除职责分离 | 当前实现Principal与基础服务授权；细粒度角色、应急审计与职责分离置于一期发布前硬化 |
| FR-37 | 审计、运维日志与性能Trace全程可追溯 | V0.2/V0.5、Excel W2/W6、ADR-0027/0029 | Audit Event、结构化日志和OpenTelemetry分离；Task、Case、System审计流使用链式摘要，日终与关键终态生成独立签名封存；统一ID贯穿全链路 | Case可回放工具、模型、缓存、Gate和报告版本；篡改事件、对象替换、越权读取和未封存快照均被检测或拒绝 | 当前实现统一ID、基础Audit Event和Trace关联；签名封存、WORM和完整性核验置于一期发布前硬化 |
| FR-38 | 模型实际上下文与响应可复现、受限留存 | 访谈决定、ADR-0028 | 每次调用固化上下文清单、真实模型与参数、Prompt版本、裁剪、完整请求与原始响应、解析、Token、延迟、重试和缓存关系；正文作为加密受限审计载荷保存，默认在Case归档后保留180天，可经保留冻结延长 | 可从任一Claim定位到对应Model Call并重建其脱敏后实际消息；普通日志、RAG和无权用户无法读取载荷；仅Auditor或已获应急审计访问者可读正文；到期后正文不可读但元数据、来源链和销毁审计仍可查；冻结创建不提升读取权限 | 当前实现Model Call来源和版本元数据；全量受限载荷、保留策略和访问控制置于一期发布前硬化 |
| FR-39 | Case事实基础长期可复核 | 访谈决定、ADR-0012/0029 | 原始样本、派生Artifact、ToolRun原始输出和Evidence所依赖内容一期不自动清理；处置须在Case归档后经申请、Reviewer复核和另一名Admin执行授权，并保留快照和报告影响；共享Content Blob先撤销单Case引用，全部有效引用消失后才物理回收 | Case归档不会删除事实基础；未经Gate或职责分离不满足的处置被拒绝；合法处置后原报告状态不变、Snapshot为HISTORICAL_VALID；共享Blob不会因单Case处置损坏其他Case | 当前实现不自动清理与来源关系；销毁Gate、共享引用回收和灾备一致性置于一期发布前硬化 |

## 基准验收

- 使用3-5个事先选定且具有人工作业标准答案的样例，覆盖PE、脚本、含嵌入对象载体、样本包关系和良性干扰样本。
- 白象样本包可作为其中一个多组件样例，但不作为主要或唯一基准；其他样例按能力覆盖选择。
- 标准答案至少包含Artifact清单、关键Behavior Claim、函数或脚本证据、组件关系、IOC、ATT&CK候选和明确未知项，不能只有自然语言报告。
- Artifact提取率建议不低于95%。
- 高价值能力召回率建议不低于75%。
- 高价值行为精确率建议不低于85%。
- 函数或脚本证据覆盖率建议不低于90%。
- 虚假COMPLETE必须为0。
- 所有阈值在基准样例完成标注后版本化，调整阈值不得覆盖历史评测结果。

## 第一期实施顺序

以下顺序只调整开发关键路径，不削减已确认范围或最终验收责任。

1. 当前关键路径：四通道与Case/Task、只读入库、以本地文件夹和ZIP为主路径的样本包接入、Artifact/Content Blob、确定性静态工具、全部静态分析模块、Evidence/Claim/Relation、报告与机器分析包、最小展示和性能基线。基础Audit Event、稳定对象ID、实际工具/模型版本及Trace关联随主链路一起落地。
2. 静态闭环完善：递归加载链、验证Hook、报告模块重组、基准样例评测、并行流水化和性能调优，直到能够对提交的样本包稳定输出带证据报告。
3. 一期发布前硬化：完整模型请求/响应留存、Auditor与应急审计访问、保留冻结、Case证据销毁Gate、签名审计封存、WORM、完整性核验以及灾备恢复回放。它们不阻塞当前静态闭环开发，但必须在一期正式对外部署前完成验收。

## 2026-08-14 strict remediation correction

The older W4 baseline statement is superseded by
`docs/w2-w4-strict-remediation-20260814.md`. The current code has closed the
principal W2-W4 correctness gaps and passes 114 tests, but production OIDC,
independent WORM/Merkle sealing, full payload lifecycle, real dependency
certification, benchmark/replay and disaster-recovery gates remain explicitly
open. Those items must not be reported as complete.

## 2026-08-12 W2-W4 traceability correction

W2-W4 implementation evidence and the corrected standards/specification boundary are recorded in
`docs/w2-w4-completion-validation-20260812.md` and
`docs/w2-w4-review-addendum-20260812.md`. W4 is complete as a development baseline: B0xD3 static
analysis, function evidence and similarity leads, component relations, embedded objects, model
adapter baseline, and auditable failure/degradation paths are available. W5-W7 production controls
and evaluation work remain open and must not be interpreted as completed by this correction.

## 当前计划缺口

1. Excel“项目目标”仍是AI代码风格/反向模型归因内容，与本项目需求不一致，应作为模板残留清理。
2. W3只列入库与分诊Agent、静态Agent初版，需要加入解密、加载器、C2/网络、反分析、证据聚合/归因模块。
3. W7把“简单脱层计划”放到第二阶段，与首期完整静态模块冲突；静态脱层和解密需要前移。
4. Excel尚未明确四通道可视化、点击式证据追溯、候选知识隔离和共识上下文Schema，需要补充任务。
5. 一期范围扩大后，原W1-W7排期需要重新估算，不能沿用三Agent原型的工作量假设。
6. Excel W2-W3未明确列出Temporal，但一期需要真实验证Ghidra等长ToolRun的耐久执行，应补入平台与工具接入任务。
7. Excel只笼统列出工具白名单和资源限制，需要补充静态Worker隔离、只读挂载、无公网、临时目录销毁和对象存储最小权限任务。
8. Excel尚未列出模型上下文清单、完整调用载荷、独立访问权限、保留与销毁策略及调用复现测试，需要补入Model Gateway和审计任务。
9. Excel尚未列出审计流、规范事件编码、独立签名封存、对象存储权限分区、完整性核验、受限正文销毁及备份保留一致性任务，需要补入平台与验收计划。
10. Excel尚未列出Case证据长期保留、证据销毁影响分析、共享Content Blob引用处置与物理回收验证，需要补入数据生命周期任务。
