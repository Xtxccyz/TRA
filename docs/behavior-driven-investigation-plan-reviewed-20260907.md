# 行为驱动调查任务修订与方案复核

日期：2026-09-07

状态：方案复核及任务修订完成；方法论 v1 已纳入增补项。以下开发项尚未因本文而完成，也未开展新的样本验收。

> 方法论增补来源：`F:/迅雷下载/behavior-driven-malware-investigator-methodology.md`。
> 本文只吸收可审计的行为目录、行为证据契约、静态升级阶梯、问题驱动停止条件和报告就绪门；目录不是能力清单，80% 不是自动放行阈值，模拟结果仍不等于真实运行观察。

本文针对用户最新的行为分析、首轮深挖和受控模拟要求，补充现有 Final Completion Stage，不另起一套调查架构，不清零旧验收缺口。运行中的 static-only 策略不因本文自动放开。

> 术语：静态分析包括反汇编/数据流恢复，以及隔离 worker 上的 Unicorn、Speakeasy、Qiling。动态分析仅指构建沙箱并完整跑样本；当前产品不做动态分析，模拟器输出不得写成 `DYNAMIC_OBSERVED` 或宿主/沙箱执行观察。

## 1. 审查依据与结论

已读取：

- 用户本次方案：`C:/Users/王宪韬/.codex/attachments/66ce73c4-9a21-488e-9842-1cde0465c118/pasted-text.txt`。
- 当前新样本报告：`C:/Users/王宪韬/Desktop/报告.md`，声明任务 `7cdd3cc5-b81c-4d5e-9305-fda1d85a44b2`。
- 对标报告实际存在于 `D:/test/20260730_Resume_恶意样本分析报告.md`。本次给出的 `D:/test/20260730/_Resume/_恶意样本分析报告.md` 不存在，按文件检索定位到前者；没有修改原报告。
- `docs/final-completion-stage-plan-reviewed-20260902.md`、`CONTEXT.md`、现有 Prompt、Playbook、Verifier、解码关联、报告投影及模拟适配代码。

附件中的 `sandbox:/mnt/data/behavior-driven-malware-investigator-methodology.md` 无本地文件，未声称读取该链接背后的文档。

结论：采纳“以安全相关行为为调查与报告对象”的方向，但不是从 Evidence-Driven 改成不受证据约束的 Behavior-Driven。应为：**行为问题驱动，证据关系裁决，机理闭环产出**。

当前缺陷包含三层，不能只修 Prompt：

1. 调查没有稳定恢复关键参数、共享对象、输出去向和失败分支。
2. 存在把 API 共现升级为数据流关系、把文字门槛当验证的代码路径。
3. 对话报告可比正式报告的权威状态更乐观，出现“正文已坐实、后端仍候选”的双重结论。

## 2. 新报告与对标报告的具体问题

### 2.1 当前新报告

| 位置 | 核查发现 | 应要求的证据/修正 |
|---|---|---|
| 第 10、20、156 行及行为链 | 声明 93 个候选机制、1 个已验证，却称“资源解密到执行的完整管线已坐实” | 分别恢复 resource buffer -> decrypt input -> decrypt output -> executable region -> entry/APC routine，逐条绑定对象与路径；未连接的环节不得用实线或肯定语气拼接 |
| 第 145-156 行 | CryptImportKey/CryptDecrypt 被直接解释为内嵌密钥、对称解密资源 payload | 明确 key blob 来源、类型、算法/模式、输入长度及资源归属；CryptoAPI 符号本身不足以证明这些属性 |
| 第 21、115 行 | 动态解析被称为规避检测，memset 被称为清痕 | 分别确认动态解析事实、被清零对象及使用生命周期；用途判断需另有证据并考虑普通初始化/释放 |
| 环境对抗/单例章节 | Sleep、系统查询、OpenMutexW 被赋予反沙箱或单例用途 | 恢复查询结果控制的分支、阈值、返回处理与受影响路径 |
| 第 224 行 | 资源提取被映射到 T1105/T1564 | 没有外部传输不能支持 T1105；资源保存方式不自动支持隐藏制品 |
| 第 212-214、302 行 | 使用未引出处的组织关联背景，又建议按 APT 级处置 | 有来源的情报放入 BACKGROUND_REPORTED 并分离；无来源的模型记忆不能进入归因或结论强度 |
| 第 293 行 | 对话产物自称与正式修订“互补” | 聊天展示、报告页、Markdown/DOCX 必须共享同一行为事实集合和 revision；新增观点先走 Claim/Verifier，而非聊天直接补写 |

这次是报告与代码复核，不是重新分析该 DLL。上表指出的是报告尚未给出足够支持的判断，不等于已证明该样本没有这些能力。

### 2.2 对标 Resume 报告

应学习：参数、阈值、配置恢复、上下游消费者、失败回退与模块级解释，而不是复制它的全部结论。

- PPID Spoofing 是父进程属性伪装，不自动等于进程注入。
- 报告给出的 `0x09080008` 与 `CREATE_SUSPENDED=0x4`、`CREATE_NEW_CONSOLE=0x10` 按位与均为 0；因此“挂起+新控制台”的解释不成立。参数应从权威常量表解码。
- 创建/运行/删除一次性计划任务可以是备用执行路径，不直接证明长期驻留。
- 修改 Defender 云报告、样本提交、排除路径不等于关闭整个 Defender 服务，更不能保证“永不扫描”。
- 重复 HTTP 下载不自动证明命令接收、心跳或 C2 tasking；静态配置地址不证明服务器当时活跃。
- Rust 运行库、TLS、异常处理器、文件导入不能仅凭存在就判为反分析或窃密。

这份报告是深度与可用性的参考，不是不可质疑的 Gold。验收只采用经证据校准的预期项，参考报告与其答案不得注入产品分析上下文。

### 2.3 代码对应缺口

以下位置对应本次读取的工作区版本；后续修改后行号可能变化。

| 位置 | 已观察到的实现 | 对应任务 |
|---|---|---|
| `service.py:4938`，解码 consumer 选择 | 双方函数锚点都存在且不同时才过滤；同函数共现和无锚点全局引用仍可成为 LINKED_STATIC | B01：验证具体输出到具体参数/缓冲区的关联 |
| `tests/test_evidence_recovery.py:584` | 正例仅给同函数 LoadLibraryW，没有解码输出到该参数的值流 | B01/T1：升级正例并加入近似但不关联的反例 |
| `investigation.py:3154`，`verify_mechanism` | 注册 6 种专用验证器，其余类型返回 specialized_verifier_not_available | B03：区分通用结构验证与用途专用验证，不按 Playbook 数量声称覆盖 |
| `investigation.py:3728`，`Verifier._evaluate_playbook` | 将 Evidence 的 kind/value/anchor 整体转成字符串进行关键词阈值匹配 | B03：将事实存在、值确定、对象关系与否定状态分别校验 |
| `reporting.py:1513`，`_build_assessment` | 非 static_triage 的 Claim 按模块去重，3 个模块即可生成 HIGH 风险值；未先排除候选 | B05：分别计算严重性与证据置信度，禁止数量驱动肯定式恶意判断 |
| `prompts/static-analysis-system-v1.md` 与 DSH `agent.cordis.yml` | 后端已有 HOW 提示；DSH persona 主要强调静态安全、会话和启动授权 | B00/B04：核对实际加载和控制循环，不只是新增提示词文件 |
| `simulation_adapters.py` | 可注入 callable，但无实际内置模拟执行器，且 isolation 使用请求布尔值 | B06-B09：服务端可信策略与真实 worker 适配验收 |

这不是对全部代码的重新验收；已完成的队列、状态机、索引和启动器改动保留，不因新缺口被重复重写。

## 3. 对附件方案的调整

| 提议 | 处理 | 修订理由 |
|---|---|---|
| 行为目录填空 | 采纳，但改为可扩展的安全相关行为目录 | 行为存在、用途、恶意性分开；允许未知类别，不能只匹配预设标签 |
| 没发现的不展示 | 部分采纳 | 未触发类别不铺满正文；高价值未闭合、未覆盖或不支持必须出现在限制中 |
| 强制十问 | 采纳为结构化调查义务 | 每项保存证据或明确 UNKNOWN/N/A 与理由，不能用任意非空文本满足门槛 |
| 30% 通用、70% 独特线程 | 改为自适应预算 | 保底覆盖、信息增益、风险、依赖和等待时长共同排序；不能饿死通用关键机制 |
| Static -> Unicorn -> Speakeasy -> Qiling | 改为按问题选择工具 | 并非能力逐级包含；兼容性、输入可恢复性、API 模型与成本决定可用工具 |
| Hook CryptDecrypt 自动恢复 payload | 改为有前提的恢复路径 | Hook 记录不等于算法实现；必须区分真实模拟结果、完整语义模型、stub 和人工/合成输入 |
| 高价值线程闭环后才允许报告 | 改为可见阶段报告与严格完成门槛 | 始终能交付已知结果和阻塞项，不能无限等待；报告可完成导出但任务仍 PARTIAL |
| 默认首轮 Deep Analysis | 采纳 | 一次用户请求触发多步自动调查，非一次 LLM completion；受硬预算约束，续轮不需用户重复催促 |

“调查线程”与“执行线程”必须分开：前者是问题工作单元；后者才是 CreateThread/APC 等对应的程序执行对象。命令分发器、解码器和主线程也可能是最独特的部分，不能只深挖新建 OS 线程。

## 4. 内部行为目录 v1 的覆盖面

此表是调查地图，**不是当前已经具备的检出能力清单**。每项最终需声明 `discovery / executable_contract / executor / verifier / real_validation` 的支持状态。下表未闭合能力不能因写入目录而记为完成。

| 类别 | 应覆盖的操作与机制 | 必须追问的关键语义 |
|---|---|---|
| 文件与目录 | 创建、打开、读取、写入、追加、复制、自复制、移动、重命名、替换、删除、延迟删除、自删除、枚举、搜索、临时文件、落地、配置文件 | 路径如何生成、访问方式、缓冲区来源、成功/失败处理、谁消费文件 |
| 文件元数据/访问 | 隐藏属性、时间戳、ACL、ADS、文件链接、系统文件修改 | 目标对象、精确修改值、触发条件；普通维护不自动是隐藏/规避 |
| 注册表 | 开/读/写/创建/删除/枚举、策略、安全产品、防火墙、代理、文件关联 | hive/key/value/type/data、权限与返回处理；用途单独推导 |
| 进程与命令 | 创建/枚举/打开/终止、命令解释器、命令行、工作目录、环境、重定向、进程树、Job | 输入来源、标志位、目标身份、句柄、等待/清理与失败回退 |
| 身份与权限 | PPID、Token 获取/复制/模拟、权限调整、登录会话、提权相关路径 | token/parent 的来源与消费者；尝试与成功分开，合法父进程不等于注入 |
| 执行线程与回调 | 创建/远程线程、入口参数、APC、挂起/恢复、上下文、TLS、VEH、线程池、Timer/Callback | 谁注册/启动、入口解析、共享状态、事件条件、结束和失败路径 |
| 进程操纵/注入 | 远程写入/线程、APC、映射、空洞化、上下文劫持、DLL 注入 | 源/目标地址空间、代码来源、载入区间、执行转移；必须有跨进程关系证据 |
| 内存与映射 | 分配/释放、权限变化、复制、Section/View、手工映射、重定位、代码修改 | buffer/region identity、大小、权限、生命周期、实际消费者 |
| 加载/API 解析 | LoadLibrary/GetProcAddress、导出遍历、API hash、IAT/全局指针、反射加载、旁加载 | 模块/函数身份、解析算法、表槽写入及间接调用；解析不等于加载完整 PE |
| 配置/编码/密码学 | XOR/标准算法、自定义变换、密钥导入/派生、字符串/API/配置解码、压缩 | 算法参数、输入输出长度/字节、有效性、引用/使用点、失败条件 |
| 多阶段与插件 | 资源、内嵌、解码、解压、下载、内存子载荷、插件、更新 | child 内容哈希、父来源、变换链、验证结果、下一阶段入口与任务归属 |
| 网络传输 | DNS、连接、Bind/Listen/Accept、HTTP/WinHTTP/WinINet、Socket、TLS、代理、WebSocket、SMB/RPC、隧道 | 客户端/服务端角色、端点、端口、方法/路径、请求体、响应消费、错误/重试 |
| 通信循环/协议 | 注册/check-in、polling、心跳、重试退避、jitter、消息格式、会话状态 | 网络调用是否位于该循环、时间来源、消息意义；重试/更新检查不能自动叫 C2 |
| 命令分发 | opcode/消息路由、命令表、文件/进程/插件命令、配置更新、卸载、结果回传 | 输入解析、分发条件、每个 handler 的副作用、输出及异常分支 |
| 持久化触发 | Run/RunOnce、任务、服务、启动目录、WMI、COM、Winlogon、IFEO、AppInit、LSA、BITS、驱动、加载项、快捷方式、登录/启动脚本 | 持续触发条件、载荷、权限、生命周期；单次执行与清理后驻留区分 |
| 服务/驱动 | 创建/启动/停止/删除服务、驱动加载、DeviceIoControl、内核交互 | 服务/设备身份、参数/IOCTL、输入输出；用户态模拟不证明内核利用成功 |
| 主机/环境侦察 | 用户/主机/域、OS/架构、CPU/RAM/uptime、接口、进程/模块、服务、软件、安全产品、区域/环境变量 | 采集目标、数据去向、是否控制执行分支，运行库初始化排除 |
| 反分析/防御干扰 | 调试/VM/沙箱检查、时间比较、异常流、不透明条件、自修改、ETW/AMSI、unhook、syscall、安全配置和日志修改 | 比较常量、条件影响、patch 目标/字节及恢复；API 或异常处理存在不代表规避 |
| 凭据/敏感数据 | LSASS/SAM/LSA/DPAPI、浏览器凭据/cookie、SSH/云 token/证书/密钥、会话凭据 | 数据源、访问条件、提取/解密方法与消费者；不将普通 DPAPI 使用判为窃密 |
| 收集/暂存/外传 | 文件/文档/数据库、剪贴板、按键、截屏、音视频、邮件、压缩暂存、网络上传 | 收集对象 -> 缓冲/归档 -> 传输载荷的同一来源关系，收集不等于外传 |
| IPC/协作 | 管道、共享内存、事件、互斥量、信号量、ALPC、COM、窗口消息、本地 socket | 两端角色、命名、共享消息、同步条件；命名管道不自动为 C2 |
| 横向移动/远程操作 | 共享、远程服务/任务、WMI、WinRM、RDP、DCOM、远程注册表 | 远端身份、认证来源、远端副作用和执行路径，协议存在不等于横移 |
| 破坏/资源滥用 | 文件加密/覆盖/删除、备份/恢复修改、服务终止、锁定、篡改、挖矿、DoS | 目标范围、循环、变换、恢复影响、资源消费，不能按算法名判勒索 |
| 独特/未知机制 | 自定义状态机、watchdog、自恢复、虚拟机解释器、自定义协议、未归类逻辑 | 不强塞目录；从入口、状态转移、输入变换和终端副作用建立新调查问题 |

目录条目按稳定行为 ID 去重，多个类别只作为视图；同一进程/文件/缓冲区关联不得因多标签重复计分。

## 5. 复用现有模型，不重建平行系统

复用 `Artifact -> ToolRun -> Evidence -> Claim/Mechanism -> Relation -> Snapshot/Revision`，以及现有 InvestigationQueue、LoopDriver、Playbook、Verifier。

新增的是行为级契约及投影，而非第二套 Case、线程引擎、数据库或“写报告 Agent”事实库：

```text
BehaviorCatalogEntry
  id/version, applicability, discovery_seeds, executor_support
  required_facts, relation_predicates, alternatives, forbidden_inferences
  preferred_actions, verifier_id/version, ATT&CK candidates

BehaviorFinding (由 Claim/Mechanism 投影，绑定快照)
  id/catalog_id, artifact_id, claim_ids, mechanism_ids
  what/how/target/condition/output/consumer
  finding_status, evidence_natures, supporting/refuting evidence_ids
  semantic_interpretation, maliciousness_assessment, unknowns
  investigation_thread_ids, execution_context, relation_ids

BehaviorRelation
  source/target finding + source/target object + typed relation
  evidence_ids + condition + provenance + validation_status
```

关键约束：

- `UNKNOWN`、`NOT_IDENTIFIED`、否定文本、字段名和 API 字符串不能通过门槛。
- 不能以同一函数、同一 Artifact 或 API 共现代替对象数据流。
- 缓冲区须记录 Artifact/地址空间/偏移或 VA/长度、别名与重分配；句柄须记录产生点、传参/复制和使用点。
- 调用关系说明可达性的一部分，不直接说明 A 输出被 B 消费或 A 总在 B 之前。
- 同步调用、异步触发、条件先后和数据依赖分别建模；未知关系保留，不编成唯一完整时间线。
- 通用验证器只验证结构事实；专有用途由专用契约裁决。风险严重性与结论置信度分开，候选模块数量不决定 HIGH。

## 6. 首轮分析与默认提示词

当前 `prompts/static-analysis-system-v1.md` 已要求 Input/Transformation/Condition/Output/Consumer/HOW，说明“没有任何深挖提示词”不是准确诊断。DSH persona 则主要约束静态安全和会话绑定，首轮自动继续调查与正式报告一致性仍需落实。

使用同一版本化 policy/profile 生成 DSH 调查指令和后端角色提示，保留各角色的结构化输出 schema。记录实际启用的 prompt/profile digest，不只修改未加载的文件。模型网关适配类存在，不等于 DSH 对话已使用后端同一路由，应核查真实注入点与调用记录。

以下是待实现的主调查指令骨架，不直接替换安全策略：

```text
用户要求分析已绑定样本时，默认启动一次多步骤深度调查。
上传本身不代表授权开始分析，不猜测或跨会话读取 task/artifact。

目标是恢复样本的安全相关行为及 HOW，而非罗列 API、函数或线程。
用版本化行为目录检查覆盖盲区；允许发现目录外机制。
从线索提出可证伪问题及良性/替代解释，不预设每个样本恶意。

每个高价值问题恢复：启动者、输入、状态/配置、变换、条件、
副作用、输出、消费者、循环、失败/回退。
每项需事实和关系锚点；不可恢复则标明具体缺失项，不用空话填满。

优先选择能够补齐关键关系或排除解释的动作。
静态证据适用时追踪参数、返回、全局、回调、间接调用、数据与控制流。
不机械地对每个函数跑全工具，不将工具失败或一次无新增当静态边界。
工具/模型故障、预算结束、缺输入、不支持和真实技术阻塞分别记录。

请求模拟必须给出问题、范围、输入及不确定性、预期观察和停止条件，
只能使用服务端授予的受控能力；模型不能授权自己运行工具。
模拟假设、stub 和真实输入严格区分，结果不表述为真实宿主执行成功。

行为、用途、恶意性分别裁决。没有对应关系证据，不拼接攻击链。
APC 不等于远程注入；PPID 不等于注入；Sleep+HTTP 不等于心跳；
配置端点不等于活跃 C2；注册表修改不等于持久化；收集不等于外传。

第一轮自动形成执行摘要、证据支持的行为 HOW、独特机制、
已确认的链路、恢复配置、IOC/检测机会、ATT&CK 和关键未知。
聊天和导出引用同一权威 revision，不在聊天中提升验证状态。
有缺口时交付明确 PARTIAL 的阶段报告及已执行/剩余动作，
不得声称完成，也不要求用户重复说“再深入”才继续预算内调查。
只展示问题、动作、证据变化和验证理由摘要，不展示原始思维链。
```

首次请求先进行必要覆盖，再按信息增益、影响、成本、可恢复性与等待时长调度。独特问题获得增量预算，但保留入口、配置、输出、退出/清理等覆盖下限。预算耗尽保存未完成 frontier，可续跑；不能静默丢失线索或通过降低覆盖提高速度。

## 7. 首批必须落地的证据契约

| 行为/机制 | 必需语义 | 最小反例 |
|---|---|---|
| 资源提取 | 资源 ID/type/module、实际字节区间、长度、复制输出及用途 | 只看到资源 API 导入 |
| 解密/解码 | 输入来源、算法/状态/密钥、输出、复现/验证、消费者单独验证 | 解出可打印字符串但无使用点；hook 只返回成功 |
| 内存权限/执行转移 | 同一 region 的来源、范围、权限参数、入口去向 | VirtualAlloc 和 VirtualProtect 处理不同区域 |
| 线程/回调逻辑 | 创建点、入口/间接目标、参数、共享状态、核心循环及清理 | 只有 CreateThread；入口是普通 runtime worker |
| APC/远程注入 | 目标线程/进程、routine、代码来源、跨地址空间关系；触发条件单列 | 同进程 APC、普通异步 I/O、未解决的线程句柄 |
| 文件读写/落地 | path、access、buffer/size、返回分支、落地结果消费者 | 字符串中出现文件名但未传入文件 sink |
| 注册表/安全修改 | 完整 key/value/type/data、句柄来源、返回分支；安全含义按精确值解释 | 普通设置项写入；失败路径被写成成功 |
| 进程/PPID/输出捕获 | 命令来源、flags、parent/启动参数、句柄与管道匹配、回退 | 只 OpenProcess；flags 按位解释错误 |
| HTTP 下载/服务监听 | 请求/监听角色、端点、内容来源/去向、响应消费和失败处理 | 配置 URL 或 socket import，没有调用链 |
| 周期通信/命令分发 | back-edge/触发、网络路径、时间状态、协议解析、handler 副作用 | 普通重试/健康检查被称心跳 C2 |
| 任务/服务/其他持久化 | trigger、payload、存续条件、权限、清理；单次执行单独命名 | once+run+delete 自动称长驻 |
| 环境分支/安全补丁 | 检测输入、比较与分支效果；补丁目标、字节、权限恢复 | Rust CRT/异常处理或系统查询自动称反分析 |

剩余目录类别复用对象、数据流和控制流谓词，登记缺失专用能力；不能为赶进度把关键词匹配包装成已验证行为。

## 8. 受控模拟与子对象递归

### 8.1 当前边界

`simulation_adapters.py` 目前是探测及注入回调接口，没有内置的三种实际执行适配器；`static_simulation.py` 是静态抽象状态推演，不是运行 Unicorn。当前 `SIMULATOR_IMPORTS` 也未列 Unicorn。

`worker_isolated`、`allow_execution` 等请求布尔字段不是隔离的证明。新设计必须由服务端检查真实 worker 身份、固定配置、运行能力和预算，忽略模型自报授权。

现有计划禁止模拟。本文建议新增版本化 `static-first-controlled-emulation` 能力画像，保留旧 `static-only` 及旧任务重放语义。新画像通过安全验收后才可在平台启用；不是对旧画像全局解除限制。

### 8.2 工具选择与输入完整性

| 工具 | 合适问题 | 不作出的保证 |
|---|---|---|
| Unicorn | 局部 decoder/hash、小型分发、计算跳转；入口/寄存器/内存/退出点可约束 | 不自带 Windows API、加载器和系统语义；缺输入不能任意补零后冒充真实输出 |
| Speakeasy | Windows API 密集的 loader、资源、线程/回调与内存路径 | 不保证所有 CryptoAPI/系统行为完整；必须逐项确认模型与返回语义 |
| Qiling | 需要文件系统/用户态 OS 模型的路径，且架构、rootfs、API 支持适合 | 不保证比 Speakeasy 覆盖更全；rootfs 来源、许可及哈希需固定 |

先实现共用执行/证据契约和最小 Unicorn worker，再以当前 loader 问题接 Speakeasy，Qiling 复用相同接口作为匹配的备选。可并行实现适配器，但不能用同一未知输入的三次失败替代输入恢复。能由已验证的确定性解码器完成时，无需强制模拟。

### 8.3 隔离与可追溯

- 独立低权限 worker，样本只读挂载，输出限额，临时文件系统，固定工具镜像与配置；不在 Windows 宿主运行目标代码。
- 禁止真实网络/DNS、宿主文件/注册表/进程交互、Docker socket、特权容器和生产凭证挂载。需要服务数据时只能使用显式合成响应，单独标注为假设。
- CPU/墙钟/指令/内存/输出字节/子对象数量/递归深度硬限额，超时与取消能终止完整工作进程树，异常不触发宿主 fallback。
- 记录样本和输入哈希、入口、地址映射、输入来源、工具版本、镜像摘要、API hook/stub 清单、返回值、访问日志、输出差异和停止原因。
- `EMULATION_OBSERVED` 必须贯穿 Evidence、序列化、索引、Claim Gate、Snapshot、报告和审计。静态抽象结果继续为派生事实；模拟器输出不是 `DYNAMIC_OBSERVED`。
- 环境值替换、分支强制或 API stub 影响结果时，标记依赖范围；该路径的输出不能直接证明样本正常运行会产生同样结果。
- 无网络样本执行不是无风险：模拟器本身处理不可信输入，容器仍共享内核；客户环境是否需要 VM 级隔离须记录，不宣称绝对安全。

### 8.4 子 Artifact

只有确实恢复的字节才能创建 child，不凭 MZ 文本、返回码或模型描述创建 payload。

保留父 Artifact、原始字节区间/模拟内存区间、变换参数及输入输出哈希，写入只读内容存储；结构完整的 PE/脚本/文档进入已有静态管线，未知 blob/shellcode 保留为待分类对象。MZ 不是完整 PE 验证，任意非 PE 字节也不自动是 shellcode。

去重按内容处理，但保留每条来源；限制总展开量、循环与深度。子对象未分析完成不能被父报告宣称闭环。后续恢复遵循现有 Task/Snapshot 生命周期契约，不改写历史已冻结 revision；现有续跑行为与 CONTEXT 的终态任务约定需要在接入时校准。

## 9. 更新后的执行清单与并行安排

以下均为待实施或待验证，不使用百分比代替验收证据。

| ID | 优先级/负责线 | 工作与代码落点 | 完成条件/依赖 |
|---|---|---|---|
| B00 | P0，集成 | 固定当前输入报告/代码身份；核对 DSH 与后端实际模型路由、402/超时/空回复、Prompt 生效点 | 工作台清晰区分模型故障与静态边界；不能把 Codex 代写记成产品效果 |
| B01 | P0，证据线 | 修复 `service.py` decoder consumer；同函数、跨函数、无锚点都要求真实对象/参数关系 | 两缓冲区正例及错误关联反例通过；替换 `test_decode_result_links_same_function_static_consumer` 的弱标准 |
| B02 | P0，契约线 | 将现有 Playbook 整理为版本化行为目录；声明发现/执行/验证支持级别，不另建平行架构 | 目录覆盖、未知类别入口、稳定 ID、旧机制 ID alias 与版本化兼容 |
| B03 | P0，契约线 | 把 token 字符串门槛改为类型化事实/关系谓词；补齐第 7 节契约；评估 `verify_mechanism` 注册与调用路径 | 否定/UNKNOWN/共现不能过门槛；名称有 verifier 但主路径未调用视为未完成；依赖 B01/B02 |
| B04 | P0，调查线 | 首轮自动深挖：统一版本化指令、十问缺口、回调/线程入口、共享状态/间接调用、失败分支和持久化 frontier | 一次“分析”后自主追踪到新证据或具体阻塞，不靠第二次用户催促；依赖 B00/B02，使用 B03 结果 |
| B05 | P0，报告线 | BehaviorFinding/Relation 投影；摘要先答做什么/怎么做/关键未知；不按模块数评 HIGH；聊天/报告/导出同一 revision | 候选状态不提升，图边有依据，无来源组织关联不进入摘要；依赖 B01/B03，可先按契约并行开发 |
| B06 | P0，工具线 | 专用 worker、服务端授权、模拟请求/结果契约、Evidence Nature 贯通、预算/取消/安全策略 | 未授权/无隔离拒绝；真实出口和宿主写入为零，stub 假设传播；开发可与静态线并行 |
| B07 | P1，工具线 | Unicorn 局部执行适配；实际执行良性已知变换并记录字节/寄存器结果 | 不是 probe 或 mock adapter；输入缺失、映射错误、无限循环受控；依赖 B06 |
| B08 | P1，工具线 | Speakeasy Windows 路径适配；确认资源与密码 API 的真实支持情况并测试 | 包版本固定、hook/stub 能力矩阵、受控输出可复现；依赖 B06，不能虚报解密 |
| B09 | P1，工具线 | Qiling 按架构/系统模型适配，固定 rootfs，选择/失败策略 | 至少一条适用路径真实可用；不适用显式 UNSUPPORTED；依赖 B06 |
| B10 | P1，集成 | 模拟/解码 child 回流静态管线、去重/来源、父子报告更新、不可变历史 | 回流不是只写 blob；真实子对象获得静态结果并影响父行为，异常保留；依赖 B06 及可用适配器 |
| B11 | P0，集成验收 | 通过实际 3080 平台验证首轮完整路径和第 10 节测试；独立检查证据越级/漏深挖 | 不用手工改报告、SQL/CLI 代替用户路径；依赖 B01-B05，模拟增量验收依赖 B07-B10 |
| K01 | P1，调查/服务集成 | 失败或 `NO_NEW_EVIDENCE` 后持久化失败假设、有效性、替代方法和 frontier 指纹；自动选择一个不同动作族或给出具体边界 | 真实 service 路径执行替代方法；不把失败当阴性；同语义动作不因改写文本而重放；依赖 B04/M03 |
| K02 | P1，调查/服务集成 | 跨轮次持久化信息增益与停滞状态，检测 `STALLED/BACKTRACK_REQUIRED` 并执行一次有界干预 | 两次以上受限调用无增益时有审计事件、干预/边界和报告限制；不无限循环、不绕过必需静态面；依赖 K01 |

### 9.1 方法论增补任务

这些任务不是新增平行架构，而是对 B02-B05/B11 的验收约束。若实现只增加枚举、提示词或报告段落而没有可追溯的事实变化，不得计为完成。

| ID | 归属 | 增补内容 | 可证明的完成条件 |
|---|---|---|---|
| M01 | B02/B03 | 将方法论行为目录、每类必需事实与最小反例登记为版本化目录数据 | 目录可查询 applicability/discovery/executor/verifier/validation 状态；未知类别可进入调查；旧 ID 可兼容；至少一组反例实际阻止越级 |
| M02 | B03 | 采用行为证据契约和静态升级阶梯 S0-S4 | API/字符串/单次 NO_NEW_EVIDENCE 不能关闭线程；达到 STATIC_BOUNDARY 前可审计地完成相关 S1-S3 尝试，或记录具体不支持/缺输入 |
| M03 | B04 | 首轮调查协议覆盖十问、竞争假设、失败/回退和独特线程预算 | 单次用户请求后自动产生问题、动作、证据增量和下一步/阻塞；调查线程与 OS 执行线程分开；无新增时换方法或给出具体边界 |
| M04 | B05/B11 | 报告就绪门与行为模板 | 每个核心 Finding 有 What/How/Target/Condition/Output/Consumer/Evidence/Unknown；候选不提升；摘要、聊天、导出引用同一 revision；未满足时明确 PARTIAL/BOUND-ED |
| M05 | B06-B10 | 模拟器结果规范化和子 Artifact 回流 | 只接受真实受控 worker 结果；输出含输入/版本/停止原因/假设；EMULATION_OBSERVED 全链路贯通；确实恢复的 child 才进入静态管线 |
| M06 | B04/B05 | S4 编排闭合与对抗式报告自检 | 每个高价值线程在进入 `STATIC_BOUNDARY` 或报告 revision 前均记录 S4 为已闭合、明确不适用或具体阻塞；保存一次结构化越级推断检查，覆盖 API/字符串即行为、网络即 C2、任务/注册表即持久化、PPID/APC 即注入、收集即外传等反例。检查失败的结论降级或保留为 UNKNOWN/CANDIDATE，不能仅靠提示词文本放行 |

工作批次：

1. 第一批并行：证据/契约、首轮调查、报告一致性。集成负责人核对真实路由与固定数据契约。
2. 第二批：集中跑一组核心回归，再通过平台跑当前 DLL 的首轮分析，检查 HOW 与未知。模拟安全契约可先并行，尚未通过安全门槛不得承接恶意样本。
3. 第三批：验证各模拟器适用路径与子对象回流，在确有增益的问题上补跑，不反复重跑所有样本。
4. 原有泛化、恢复、上下文、并发、Soak 与发布硬化任务仍保留，按用户要求排在核心效果之后，不因本轮功能通过而变成已验收。

方法论中的行为类别（文件、注册表、进程/线程、内存、加载器、网络/C2、持久化、身份权限、凭据、发现、规避、命令分发、收集外传、IPC、横向、影响、配置密码学及未知机制）作为 M01 的目录输入；最终报告只显示样本实际有证据支撑的类别，未闭合的高价值类别进入限制和未解决问题。

不现在承诺“任意样本都达到相同恢复深度”。不可获得的密钥、服务器输入、环境依赖、未知指令和保护机制可能构成真实边界；可承诺的是系统性调查、适用能力执行、证据充分才下结论，以及对未解决项给出具体解释。

## 10. 精简但有效的验收

每个大板块完成后集中验证，不为每个目录词条独立跑真实样本。用最少用例覆盖最高风险，不把少测试理解成少验证。

| 组 | 核心用例 | 通过标准 |
|---|---|---|
| T1，关系与门槛 | 正确 producer/consumer；两个不同 buffer；无锚点 import；同/异函数无数据流；UNKNOWN/否定字段 | 只有正确对象关系成立；不存在错误已验证链 |
| T2，语义负例 | 同进程 APC、普通配置写、HTTP 重试、运行库线程/异常处理、0x09080008、候选模块计分 | 不误判远程注入/持久化/C2/反分析；常量正确；模块数量不能升级置信 |
| T3，自动深挖 | 一个带回调/全局状态和缺失消费者的普通编译 fixture，一次用户请求，多次 action，重入续跑 | 新关系被发现并用于行为解释；无结果会换有根据的动作或真实阻塞，不重放无效工具 |
| T4，模拟隔离/真实性 | 每种适配器一个适用的良性真实输入；stub、缺输入、超时、取消、禁网/禁宿主访问；恢复 child | 输出/假设/停止原因准确；不以 mock 测试代替实际适配验收；不触达样本域名 |
| T5，真实平台首轮 | 当前新 DLL、Resume、一个不同机制样本及一个良性样本；只说“分析这个样本” | 默认摘要和行为 HOW；高价值线索有追踪记录；对话/导出同源；错误恶意结论为零 |
| T6，差分审查 | 对照本轮前后报告和工具记录，按证据审读核心 Finding 与缺口 | 有实际新增参数/关系/字节/反证，不按字数、动作数、状态名或报告得分独自验收 |

T5 可先跑新 DLL 检查演示收益，再跑其余三项做本次能力回归；这四项不是原计划全语料泛化认证的替代品。原目标中的 ComHost C1-C4 保留单独验收状态。

每次验收保留：输入哈希、代码/镜像/配置/Prompt 标识、实际模型和调用状态、第一请求原始回答、动作及 Evidence 增量、行为字段变化、验证结果、报告 revision、用时/峰值资源和未完成项。

具体的门槛：

- 首轮关键结果都有 What/How/Target/Condition/Output/Consumer/Evidence/Unknown；不适用项解释 N/A，不编造。
- 每条高价值线索均有已解答、反证排除、保留并说明阻塞三者之一；“看过函数”不算闭环。
- 核心行为/图边 unsupported 为 0；模拟假设不能被写成实际外联/执行/持久化成功。
- 若完整 payload 不能恢复，必须记录已试方法、缺少输入/支持和可执行的下一步。不能仅写“超出静态能力”。
- 有新证据、排除关键解释或补齐关系才记为有效动作；文本换写和重复同一输出不记增益。
- 性能同输入、同覆盖、同环境比较，分别记提取/检索/模型/验证/渲染时间；不靠降低必要覆盖换加速。
- 对每个进入静态边界或正式报告的高价值线程，保留 S4 编排状态：已恢复的前后置行为关系、明确不适用理由，或具体缺失输入/能力。S1-S3 的动作记录不能替代 S4 的闭合或阻塞说明。
- 报告生成前运行可追溯的对抗式自检；至少检测 API/字符串被当成行为、网络被当成 C2、任务或注册表被当成持久化、PPID/APC 被当成注入、收集被当成外传、模拟或 stub 被写成真实运行观察。自检是门禁，不是模型的私有思维链。

## 11. 本次自审与边界

- 已对照新报告、对标报告、已有任务与代码，定位具体缺陷并规划修复，而非认定附件所有判断都正确。
- `grill-with-docs` 用于领域术语与现有契约校准；独立只读子任务复核现有行为验证缺口，并提出模拟证据边界建议。未将本次方案复核等同于新代码的独立验收。
- 本文及 `CONTEXT.md` 是本次修改范围；未修改原始报告，未把参考答案装入 Agent，未运行恶意样本，未变更现有运行画像。
- 尚未宣称 B00-B11 实现或测试通过。第一交付目标是首轮可信行为报告与可追溯深挖，不是把候选数调低或将 PARTIAL 改成 COMPLETE。

## 12. 外部方法论复核与计划增补（2026-09-07）

本节记录对 `F:/迅雷下载/behavior-driven-malware-investigator-methodology.md` 的独立复核结果。该文档提供了可复用的方法论约束，但不是当前实现已经满足的能力清单。纳入本计划的内容必须仍然通过代码、测试和真实运行证据验收。

### 12.1 采纳项

以下内容与现有 `Artifact -> ToolRun -> Evidence -> Claim/Mechanism -> Relation -> Snapshot/Revision` 主链兼容，直接作为 B02-B05、B06-B11 的验收约束：

1. **行为目录是调查地图而非检测真值表**：每个条目必须有稳定 ID、版本、适用载体、发现线索、必需事实、关系谓词、禁止推断、执行器/验证器/真实验收状态。目录外机制进入 `unique-or-unknown`，不能被目录覆盖率自动放行。
2. **十问调查协议**：高价值调查线程逐项保存 initiator、input、state/config、transformation/control、condition、side effect、output、consumer、loop 和 failure/fallback；缺失项必须是结构化 `UNKNOWN/N/A` 并带理由，不能用任意非空文本填槽。
3. **S0-S4 静态升级阶梯**：在标记 `STATIC_BOUNDARY` 前记录相关 S1-S3 动作、结果和缺口。工具失败、模型失败或一次 `NO_NEW_EVIDENCE` 不是边界；相同动作重放只有在输入或问题发生变化时才算新的尝试。
4. **行为证据契约**：API/字符串/同函数共现只能产生 seed 或 candidate；对象身份、参数/缓冲区、控制条件、输出消费者和反例排除必须由类型化 Evidence/Relation 支持。
5. **报告就绪门**：报告先回答 What/How/Target/Condition/Output/Consumer/Unknown，再给安全含义、ATT&CK 和限制；候选不得在渲染阶段提升为已验证，聊天、报告页和导出必须引用同一个不可变 `Report Revision`。
6. **受控模拟结果规范化**：所有模拟结果至少记录输入哈希、入口/地址空间、工具版本、镜像/worker 身份、hook/stub、观察、输出哈希、停止原因和假设，并以 `EMULATION_OBSERVED` 贯穿 Evidence、Claim Gate、Snapshot、报告和审计。
7. **子 Artifact 回流**：只有确实恢复并通过内容完整性检查的字节才创建 child Artifact；child 必须进入现有静态分析主链，父子关系、变换来源和未完成状态均保留在不可变历史中。

> 术语校准：本产品的静态分析包括反汇编/数据流恢复以及隔离 worker 上的 Unicorn、Speakeasy、Qiling。完整沙箱跑样本才称为动态分析，当前不做。外部方法论的 `DYNAMIC_OBSERVED` 不作为新的证据性质；受控模拟统一使用 `EMULATION_OBSERVED`，不得写成宿主/沙箱执行观察。

### 12.2 调整后采纳项

外部文档中的下列建议不能原样落地，按以下方式纳入：

| 外部建议 | 当前计划的可执行版本 | 不变的限制 |
|---|---|---|
| 固定 30% 通用、70% 独特线程预算 | 使用信息增益、风险、依赖、成本和等待时间的自适应调度；保留入口/配置/输出/失败回退的最低覆盖 | 不得用独特线程预算饿死必要通用检查 |
| `Static -> Unicorn -> Speakeasy -> Qiling` 固定顺序 | 按问题选择工具：Unicorn 处理局部字节/解码，Speakeasy 处理 Windows API 路径，Qiling 处理适合其 OS 模型的用户态路径 | 工具不适用或输入不足时必须是 `UNSUPPORTED/BLOCKED`，不能用失败次数替代证据 |
| Hook API 自动恢复 payload | 仅把 hook 作为观察来源；算法、输入、输出、消费者和 child 完整性仍需独立确认 | hook 成功、stub 返回或模型描述不能冒充真实解密/执行 |
| 高价值线程闭环后才导出报告 | 允许导出带明确 `PARTIAL/BOUNDED_WITH_LIMITATIONS` 的阶段报告；未闭合问题必须列出已尝试动作、缺失证据和下一步 | 任务不得因“生成了报告”而自动成为 `COMPLETE` |
| 用模型/提示词补齐分析链 | 模型只提交结构化 Action Proposal 和假设，由目录、队列、验证器和服务端策略裁决 | 不展示或保存模型私有思维链，不让模型自授权工具 |

### 12.3 明确不纳入当前验收的内容

- 方法论的类别数量、条目数量或“覆盖率”不能作为能力完成度指标。
- 参考样本报告、外部项目报告或模型记忆不能进入当前样本的分析上下文，也不能作为证据。
- 当前环境未安装或未完成隔离验收的 Speakeasy、Qiling、Unicorn 适配保持 `BLOCKED/UNSUPPORTED`；只能报告能力探测结果。
- 静态抽象执行、合成 fixture、mock worker 和测试桩不产生 `EMULATION_OBSERVED`。
- 真实恶意样本不得在 Windows 宿主执行；平台验收只能使用静态解析或经过独立安全门禁的受控良性输入。

### 12.4 增补后的验收映射

| 方法论要求 | 计划落点 | 证明材料 |
|---|---|---|
| 行为目录与未知入口 | B02 / M01 | 版本化 catalog 序列化、digest、alias、支持级别和未知类别测试 |
| 类型化契约与反例 | B03 / M02 | producer-consumer、同/异对象、UNKNOWN/否定值、API 共现反例测试 |
| 十问、竞争假设和 S0-S4 | B04 / M03 | 一次用户请求的动作序列、证据增量、假设变化、具体阻塞或边界记录 |
| 行为报告和共同 revision | B05 / M04 | What/How 等字段、候选不升级、聊天/导出 revision 一致性和报告就绪门结果 |
| 模拟安全与 child 回流 | B06-B10 / M05 | 受控 worker 记录、结果规范化、输入/输出哈希、child 静态再分析和父报告更新 |
| 平台首轮可用性 | B00、B11 / T5、T6 | 实际路由/Prompt/模型调用记录、一次“分析”触发完整调查、差分报告和未完成项 |
| S4 编排闭合与对抗式自检 | B04/B05 / M06 | 每条高价值线程的 S4 状态、结构化自检结果、降级/UNKNOWN 记录；不能只以提示词或报告字数放行 |

本次复核结论：外部方法论的可行部分已并入现有计划，但没有改变系统的 static-only 默认策略，也没有降低证据门槛。以上内容全部完成前，不能宣称达到 analyst-grade 或任意样本的完整深度。

### 12.5 进一步纳入的三个可执行细化项

对照外部方法论的证据状态、模拟结果和行为报告模板，当前计划再补充以下三个实现约束。它们是现有主链上的序列化/验收细化，不新增 Case、调查引擎或报告事实库：

1. **证据性质与结论状态分离**：序列化和报告投影必须明确区分 Evidence Nature（`STATIC_OBSERVED`、`STATIC_DERIVED`、`EMULATION_OBSERVED`、`BACKGROUND_REPORTED`）、Claim Nature（例如 `STATIC_INFERRED`）以及 Claim/验证状态（`CANDIDATE`、`SUPPORTED`、`VERIFIED`、`UNKNOWN`、`REJECTED` 等）。同一字符串不得因为字段名相同而跨层晋升；`VERIFIED_STATIC` 只能表示验证结果，不得伪装成工具直接观察。
2. **模拟结果固定字段集**：受控 worker 的规范化结果除输入/输出摘要、工具/worker 身份和停止原因外，还必须按类型记录 attempted APIs、文件操作、注册表操作、网络意图、进程/线程操作、内存操作、解码缓冲区、分支/控制流观察、unsupported API 以及假设和影响范围。没有某类观察时写空集合或 `NOT_OBSERVED`，不能由模型补写。
3. **行为报告完整十问投影**：行为章节至少可追溯展示 initiator、inputs、state/config、transformation/control、conditions、side effects、outputs、consumer、loop/repetition、failure/fallback，并同时列出关键函数/RVA、参数/常量、Evidence、竞争假设、静态/模拟观察和 remaining unknowns。摘要可以压缩展示，但不能丢失这些字段的来源和未知状态；报告就绪门仍按证据闭合与阻塞项裁决，不按字段数量或字数放行。

这三项的验收映射为：第一项并入 M01/M02 的反越级测试，第二项并入 M05 的结果契约和审计字段测试，第三项并入 M04/T5 的同一 revision 报告投影测试。它们不会把尚未完成的 B00、B06-B11 变成已完成，也不会将 mock、静态抽象或历史报告变成真实运行证据。

### 12.6 Kunglao 收敛控制复核与新增计划项（2026-09-08）

对照本地 Kunglao 参考资料（`.scratch/kunglao-agent-reference/`）和现有
`InvestigationLoopDriver`、`InvestigationQueue`、service 模型动作路径后，确认现有实现
已经具备局部去重、单轮 `NO_NEW_EVIDENCE` 记录和有限 frontier，但还缺少两项跨轮次的
收敛控制。它们是方法论中“失败不是结论、信息增益必须可证明”的可行补强，纳入本计划，
但在代码、测试和真实运行证据完成前不得标记为已完成：

1. **失败驱动的替代方法（K01，P1）**：对每次 `NO_NEW_EVIDENCE` 或执行失败保存
   `method_assumption`、`assumption_validity`、`next_method`、目标选择器、方法 ID、前后
   frontier 指纹和结果。相同目标最多自动尝试一个不同动作族；替代方法也失败时，记录
   具体 `STATIC_BOUNDARY`/`UNSUPPORTED` 或保留未决，不生成阴性行为结论。替代方法必须
   改变动作族或实际输入/选择器，不能用换一段理由文本绕过去重。
2. **跨轮次停滞/自旋检测（K02，P1）**：持久化每个调查线程的 frontier 签名、有效证据
   增量、被排除假设、已完成十问字段和方法 ID。连续多个不同方法没有有效增益时，生成
   `STALLED/BACKTRACK_REQUIRED`，并强制一次有界的升级、改写问题、拆分、延后或具体
   边界裁决。相同语义方法不能因新的 action ID 或自然语言重述而重复派发；不得用停滞
   分数绕过必需静态面，也不得把零增益当成样本阴性。

这两项是对 B04/M03 的补充，不新增 Case、Evidence 或第二套调查引擎。它们的完成条件是：

- 失败或无增益的模型动作在真实 service 路径上自动留下三问失败契约，并执行一次不同方法，
  或留下有依据的边界；不得停在“失败=静态无结果”。
- 跨两次受限调用仍无增益时，系统能持久化停滞事件、避免无限循环并把干预/边界带入
  investigation snapshot、报告限制和审计流。
- 同一目标、同一选择器、同一 frontier 下仅更换动作 ID/理由文本不会产生新尝试。

当前复核结论：K01/K02 在现有计划中属于**新增待实施项**；已有的局部 autopsy、queue
排序和单轮 no-gain 计数只能算部分满足，不能替代跨轮次控制的验收。

## 13. Grok 修改对账与目标修订（2026-09-09）

本节根据 `C:/Users/王宪韬/Desktop/记录.md` 及仓库中的实现记录补充。历史记录中的
“完成”只表示当时某个代码切片或某次测试结束；除非本节明确列出活体证据，否则不把它
提升为平台或真实样本验收通过。对账的完整记录见
`.scratch/grok-reconciliation-20260909.md`；独立复跑与变更审计见
`.scratch/grok-log-extract-20260909.md` 和 `.scratch/record-change-audit-20260909.md`。

### 13.1 已落地且可复用的修改

以下修改已经进入工作树，并有对应的聚焦测试或受控 worker 证据；它们是后续验收的
基础，不是对全部 B/T 项的自动放行：

1. **证据关联与反越级**：解码输出带 `output_buffer` 身份；不同缓冲区、仅同函数共现、
   无锚点引用不会产生消费关系。`TRACE_API_ARGUMENT`、`DECODE_CANDIDATE` 和 child
   回流都保留来源。`INJECTS` 同 Artifact 自环在报告门禁中降级/隐藏，新任务不再铸造
   该关系。
2. **深挖与收敛**：TLS 回调、PE32 `CreateThread` stdcall `PUSH`、Ghidra 未命名 DATA
   写入、`TRACE_GLOBAL_USAGE` producer/consumer 缺口、函数语义摘要和有界替代动作已经
   接入调查前沿；同语义失败方法不因换 action id/理由文本重放；跨轮次停滞可投影为
   `STALLED/BACKTRACK_REQUIRED`。
3. **报告语义**：HOW 优先使用有函数/RVA 和参数的语义证据；报告保留
   `CANDIDATE/UNKNOWN/PARTIAL`，不以模块数量把结论升为 HIGH；报告摘要、工具结果和
   DSH persona 已要求引用权威 GET revision。
4. **模型接入容错**：模型请求的 enrichment/planning 强制非流式、禁 reasoning 解析
   歧义；近合法 DeepSeek envelope 做字段别名和缺省归一化，但 evidence id 仍必须绑定，
   真正的 402/传输/Schema 失败仍可见且不能伪装成静态边界。
5. **受控模拟边界**：宿主不执行样本；Windows PE 的 Speakeasy 只走隔离 worker；
   Qiling 使用独立 Unicorn 2 环境和固定 Linux rootfs。活体 Qiling 成功路径只证明
   适用的 Linux ELF，不证明 Windows PE 可由 Qiling 执行。

### 13.2 目前可以确认的活体结果

截至 2026-09-09 的最新记录：

- DLL 的一次 3080「分析这个样本」已得到官方 GET revision、100/100 gold、Speakeasy
  成功、同源 chat/revision 一致；日志中另有模型 enrichment 成功记录，但同批次也出现
  `ValueError`/`ValidationError`/`402`，因此模型健康路径必须按**具体 task、镜像版本和
  调用记录**逐条复核，不能用一次成功概括全批。Unicorn 对该 PE 是真实 `EMULATOR_ERROR`，
  不能写成成功。
- 日志声称 Qiling worker 对固定 Linux ELF 返回过
  `SUCCEEDED/END_ADDRESS/EMULATION_OBSERVED`，并记录了 rootfs digest；该记录尚未在本次
  审查中用 worker 日志、输入哈希、镜像 digest 和 rootfs digest 独立重放，暂记为
  **C1 声称/待复核**。Windows PE 返回 `UNSUPPORTED/NOT_LINUX_ELF` 是正确边界。
- ComHost 的旧一次 T5 也有 100/100 和同 revision，但其 enrichment 失败记录属于
  历史任务，不能代表修复后的健康路径。
- K02 的 `STALLED/BACKTRACK_REQUIRED` 已在真实任务限制中出现；这证明停滞投影，
  尚不等于 K01 三问失败契约在活体服务路径闭合。

### 13.3 修订后的总目标

本阶段目标修订为：

> **让一个用户在 3080 中只提交一次“分析这个样本”，系统就能自主建立问题驱动的
> 调查前沿，按证据增量选择下一动作，恢复参数/对象/控制流/输出消费者，必要时进入
> 隔离模拟，并产出同一 immutable revision 的分析报告；每个结论都能回到 Evidence、
> ToolRun、Action、Hypothesis 和限制记录。不能闭合的内容必须明确为 UNKNOWN、CANDIDATE、
> UNSUPPORTED 或 PARTIAL。**

不再把“有 17 个动作”“生成了 Markdown”“模型被调用”或“gold 分数一次通过”单独当作
深度能力。深度能力的最小可见表现是：一轮中存在至少一个有证据增量的追踪，或存在一条
带三问失败契约、替代方法和具体边界的可审计阻塞链。

### 13.4 四层完成判定

任何编号项必须按其要求的层级验收：

| 层级 | 允许证明的内容 | 不能替代的证据 |
|---|---|---|
| C0 代码契约 | 类型化谓词、状态机、序列化、去重、报告门禁 | 不能替代 worker 或 3080 |
| C1 受控良性 worker | 模拟器真实调用、停止原因、输入/输出/版本/隔离 | 不能替代恶意样本分析结论 |
| C2 3080 用户路径 | 真实 DSH 会话、一次请求、多动作、同 revision、失败可见 | 不能用 `analysis/start`、CLI 或手工 SQL 代替 |
| C3 样本报告 | 指定样本的 HOW/IOC/机制/ATT&CK/Unknown 与证据链 | 不能用重组报告隐藏历史关系来替代 |

T5/B11/M04 需要 C2+C3；B07-B10/M05 需要 C1，若计划明确要求平台路径还必须补 C2；
T1/T2/T3/T6 按各自表格逐项取证。缺少层级证据时状态只能是 `PARTIAL` 或 `NOT_PROVEN`。

## 14. 剩余任务计划（修订版）

### 14.1 P0：先闭合真实分析链和平台一致性

1. **P0-A：完成当前 post-rebuild T5 批次**。先查询并记录现有任务是否已终态；已终态的
   任务直接复用其原始请求、事件和 revision，不因“等待”重复发送。只有缺少 required
   artifact 的样本才在同一批次对 Resume、notepad 和 ComHost（必要时 DLL）各发送一次
   3080「分析这个样本」，并收集官方 GET Markdown、DSH chat transcript、model-call
   状态、simulator rows、stored relations 和 gold bar。禁止中途重启 API 或逐小改动重打
   模型。
2. **P0-B：模型健康路径与错误分层**。对修复后的同一模型路由验证 DLL/Resume/ComHost/
   notepad 至少一条成功 enrichment；402、Schema mismatch、超时和静态停滞在 UI、
   analysis-context、报告限制中分别可辨识。不要改 API key，不要增加隐含第二模型。
3. **P0-C：S4 与历史关系清理策略**。对 Resume 等历史任务重新生成一份不可变 revision，
   确认报告不含同 Artifact `INJECTS`，同时保留旧 revision 和修正原因；新任务仍必须为
   0。每个高价值线程的 S4 只能是 `CLOSED`（有非空尝试）、`NOT_APPLICABLE`（有理由）
   或 `BLOCKED`（有具体缺口），禁止 CLOSED+空 attempts。
4. **P0-D：T1/T2 3080 证据**。用隔离的良性双缓冲/反例 fixture 走一次平台路径，验证
   错误输出缓冲区不会被链接；用包含 `0x09080008` 的良性 fixture 验证
   `CREATE_SUSPENDED` 不被臆造。pytest 仅作为 C0 回归，不能替代 C2。
5. **P0-E：T6 差分**。冻结本批次之前的同一任务/同一样本官方 Markdown 和 ToolRun 摘要，
   复测后生成 scored before/after；禁止拿 workbench-start 的旧 Resume1/Resume3 对代替
   3080 T5 差分。

### 14.2 P1：补齐深挖、模拟和故障路径

1. **P1-A（T3）**：用编译的 benign TLS/global-state fixture 走一次 3080；验证一轮请求
   产生多个动作，第二轮不重放同语义 no-gain 动作，并把 producer/consumer UNKNOWN 理由
   写入正式报告。仍不在宿主执行 PE。
2. **P1-B（K01）**：在真实 service 任务上抓取 append-only failure record，至少含
   `method_id`、`method_assumption`、`assumption_validity`、`next_method`、前后 frontier
   fingerprint、`gain_class` 和 outcome；第二个方法失败后必须给具体 boundary，不能只留
   `STALLED` 文案。
3. **P1-C（B07/M05）**：为 benign transform 取得 worker Unicorn 字节/寄存器 ledger，
   记录输入/输出 hash、stop reason、tool/worker digest、hook/stub 和假设范围；T5 PE 的
   `EMULATOR_ERROR` 只作为失败证据。
4. **P1-D（T4）**：在 worker/Temporal 路径验证 missing-input、cancel、timeout、deny-
   network、deny-host、no-isolation；结果必须是拒绝/取消/超时等真实状态，不能用 host
   pytest 矩阵替代。
5. **P1-E（B10）**：让一个真实恢复的 child bytes 重新进入静态主链并成功得到结构化 facts；
   若 child 非 PE/script/document 或 Ghidra 不适用，保留 `UNSUPPORTED` 并在报告中说明，
   不能把只创建 blob 当作回流完成。
6. **P1-F（T5 benign bar）**：notepad 的 90/100 `decoded_constants` 阻塞要么通过合法
   静态证据补齐，要么将“良性样本允许未解常量”的豁免固化为明确的 gold policy，不能静默
   当作完整 PASS。

### 14.3 并行编排与所有权

| 轨道 | 所有者 | 允许修改 | 交付物 |
|---|---|---|---|
| 证据/契约 | `behavior_contracts`（已有分工） | `investigation.py`、`behavior_catalog.py`、契约测试 | C0 B02/B03/M01/M02/T1 证明包 |
| 报告/门禁 | `behavior_reporting`（已有分工） | `reporting.py`、报告测试 | C0 B05/M04/M06 报告投影与 S4 门禁 |
| DSH 深挖控制 | `dsh_depth_control`（已有分工） | `threat-dsh-workbench`、Prompt、运行时测试 | C2 B00/B04/B11 同 revision/citation |
| 服务集成 | root | `service.py`、decoder/child dataflow、模拟调度、整合测试 | K01、B01、B06-B10、T2/T3 集成 |
| 运行验收 | root + 一次性批次 | 仅测试脚本、`.scratch` 证据、镜像 | T4/T5/T6 活体包 |

轨道之间共享现有主链，不创建第二套调查引擎、第二个 Evidence 模型或隐藏模型路由。
每个轨道可以先跑 C0；所有代码合并到一批后，才执行一次昂贵的 Docker/3080 验收。

### 14.4 统一验收顺序

1. **静态检查**：`py_compile`、受影响聚焦 pytest、DSH runtime/npm tests；记录失败而不改写
   旧证据。
2. **受控 worker 批次**：只使用 benign ELF/PE fixture 和现有隔离 worker；确认 Qiling
   Linux 成功、Windows PE OS mismatch、Unicorn ledger、取消/拒绝路径。
3. **重建镜像**：按启动脚本重建受影响服务，核对运行镜像源码 hash；不使用 `compose
   down -v`，不删除 PostgreSQL/MinIO/Temporal 数据卷。
4. **一次 3080 批次**：按固定样本顺序跑 DLL、Resume、ComHost、notepad 和必要 benign
   fixtures；每个任务保存请求、工具/会话事件、GET report、chat citation、model calls、
   relations 和 gold 分数。
5. **逐条矩阵复核**：用 `live-proven/partial/pytest-only/not-proven/blocked` 五态更新
   表格；没有 C2/C3 证据的项不提升。最终报告必须列出剩余限制和未完成项。

### 14.5 明确不做的事情

- 不在 Windows 宿主运行恶意样本，不访问样本中的网络端点。
- 不展示或保存模型私有思维链；只记录结构化问题、Action、Evidence 增量、验证理由和限制。
- 不把固定 rootfs、镜像 digest 字符串、mock、pytest、手工构造 snapshot 当成 live success。
- 不为每个小修复单独发送一次 DSH 分析；代码批次稳定后再做一次平台验收。
- 不新建“规划模型”旁路；当前 DSH 对话模型负责规划，后端保持确定性静态底座和可追溯的
  受控 Action 执行。

### 14.6 本轮结束条件

本轮不能以“代码已写”结束。结束时必须同时提供：

1. 修订后的计划和状态矩阵；
2. C0/C1 测试与 worker 证据；
3. C2 3080 批次的原始请求、工具/会话记录和报告 revision；
4. C3 样本报告 gold 结果及 before/after 差分；
5. 自审报告：逐条解释 B00-B11、M01-M06、K01-K02、T1-T6 哪些已证明、哪些仍为
   `PARTIAL/NOT_PROVEN/BLOCKED`，以及下一步具体边界。

在这些材料齐全前，计划状态保持“执行中”，不调用目标完成。
