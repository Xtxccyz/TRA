# 完整静态分析执行方案（Lite 之后）

> **用户验收已 superseded。** `complete_c10_passed` 与本文「HOW 或显式 UNKNOWN」不得再当作用户要的效果已达到。现行执行合同是 `docs/first-usable-static-analysis-plan-20260916.md`（ADR-0034）。本文仍保留 T4 隔离、emu-worker 安全与模块对照，供实施时吸收，不作为停工条件。

日期：2026-09-15

前置：`docs/static-how-lite-execution-plan-20260915.md` 的**增量 1**已完成（S0 结论门 + XOR 下限 + 消费者可 UNKNOWN）。未完成增量 1 不得开工本文。

目的：交付 **首期完整静态逆向**，使一次 3080「分析这个样本」达到 Resume 级能力类型（HOW 或显式 UNKNOWN），然后才能进入下一阶段（Full 专长模型并行、隔离沙箱动态分析）。本文吃掉 Lite 方案里未写全的增量 2–5，以及行为方案中仍属静态、尚未作为 Lite 交付的全部项。

不替代 `docs/behavior-driven-investigation-plan-reviewed-20260907.md`。配套：`CONTEXT.md`，ADR-0001/0002/0014/0019/0020/0031/0032/0033。

**本文不改产品代码。** 开工须另授权。dirty worktree、不 commit、不在宿主跑样本、不打样本 C2、不改 API key、不用 `docker compose down -v`。

---

## 0. 和 Lite、下一阶段的边界

| 阶段 | 有什么 | 没有什么 |
|---|---|---|
| Lite（已另文） | 结论门、XOR 下限不回退、无消费者则 UNKNOWN | 进程/PPID/线程 HOW、Join、受控模拟主路径、十问/S4/K01、3080 正例 |
| **本文 = 完整静态** | 上表右侧全部 + 目录命中模块的 HOW/UNKNOWN + B11 | DSH subagent、多路专长模型并发达套、沙箱完整跑样本、第二份评测基准报告 |
| 下一阶段（禁止混进本文验收） | Full：Task 内并行专长模型调用；动态分析：沙箱 Worker + `DYNAMIC_OBSERVED` | — |

ADR-0001 曾把 Unicorn 和沙箱一并后置。后续 `CONTEXT.md` 已把隔离 worker 上的 Unicorn/Speakeasy/Qiling 算进**静态分析**（`EMULATION_OBSERVED`）。本文采用后者：受控模拟是完整静态的一部分；完整跑样本不是。

---

## 1. 完整静态的退出标准（做完才能进下一阶段）

一次用户路径必须同时成立。缺任何一条都不得宣称「静态已完成」。

1. **环路**：放入样本 →「分析」→ PMA 蒸馏计划 + 行为目录调查线程 → Action Proposal → 策略 → ToolRun（含授权窗口模拟）→ 官方 Report Revision = 聊天结论 → STOP。
2. **深度**：Resume 上，目录命中的高价值行为达到能力类型：关键函数/RVA、参数或 flags、阈值、输入/输出、消费者、失败回退；缺的写 `UNKNOWN(<槽>)` 并给出已试动作与边界。不套 Resume 章节、不抄 IOC、不喂评测基准报告。
3. **诚实**：无证据不升级；Gold JSON 全绿 ≠ 完成；不削弱 verifier；`FUN_` 账本不进「分析结论」；未命中类目不开空章。
4. **十问与 S4**：每条高价值**调查线程**有 initiator…failure/fallback 的结构化槽或 N/A；进入报告前 S4 为已闭合、明确不适用、或具体阻塞。一次 `NO_NEW_EVIDENCE` 不是边界。
5. **K01/K02**：失败换动作族；跨轮零增益则 STALLED 并有界停，不重放同语义动作。
6. **受控模拟**：静态停住后可 `CONTROLLED_EMULATE`；结果规范化且 `EMULATION_OBSERVED`；hook/stub 不冒充解密成功；真实恢复的 child 才回流静态管线；不适用写 `UNSUPPORTED`，禁止用探测当验收。
7. **一份 revision**：聊天、报告页、导出同源；候选不在渲染期变已验证；M06 对抗自检过门（API≠行为、HTTP≠活 C2、PPID≠注入、模拟≠已运行）。
8. **T 组**：T1–T4 契约/适配绿；T5 Resume 正例 + 无基准样本反幻觉 + 良性样本零误报；T6 差分证明有新 HOW/关系/UNKNOWN，不是字数。
9. **Analysis Outcome**：深度不够则 `PARTIAL`/`BOUNDED`；不得因「出了报告」标 `COMPLETE`。

正例场仍只有 Resume 评测基准报告。无第二份人工报告的样本只做反幻觉，不声称同等深度。这不阻止完整静态过关。

---

## 2. 已有、Lite 会有、本文才做

**视为已有（不要重做脚手架）**：Case/Artifact/ToolRun/Evidence/Claim、Ghidra 队列、DSH threat-static、Action Catalog、部分 verifier 函数、`pma_static_plan.py`、persona PMA cheatsheet、stop_dispatch、Report Revision 模型、emu-worker Compose 画像。

**Lite 增量 1 交付后才有**：官方结论门、XOR 下限、无对象消费者不得 LINKED。

**本文必须做完**：

| 缺口 | 行为方案 | 为何卡住静态 |
|---|---|---|
| 进程 flags / 线程入口 / PPID 链接到主路径并进结论 | B03 轨 B | Resume 最像「不是导入表」的 HOW |
| 解码明文 → 进程镜像/URL/任务名 Join | B01 Join | 否则两轨各说各话 |
| 环境阈值、网络请求重建、schtasks vs 持久化、Relation 时序 | 目录其余命中项 | 否则仍是表面 |
| 首轮自动深挖、十问、S0–S4 | B04 / M02 / M03 | 用户不能再说「再深入」 |
| 失败换方法、停滞检测 | K01 / K02 | 否则空转烧额度 |
| 报告十问投影、就绪门、同一 revision、M06 | B05 / M04 / M06 | 否则 HOW 写不进用户看见的结论 |
| 受控模拟隔离、Unicorn/Speakeasy/Qiling 适用路径、child 回流 | B06–B10 / M05 / T4 | 静态停住后没有下一刀 |
| 工作台路由/Prompt/STOP 与结论同源 | B00 / B11 / T5 | 否则契约绿、产品仍停 |
| DSH 增量（Lite 空闲） | B04 产品侧 | 提议契约、STOP、不写桌面 |

---

## 3. 明确不做（本文验收为失败）

- 打开 DSH bash/web/skill/subagent。
- Task 内并发达套专长模型（Full）。
- 沙箱完整跑样本、`DYNAMIC_OBSERVED`、样本联网。
- 把模拟成功写成已感染/已外联/已持久化。
- 无 flags 写 `CREATE_SUSPENDED`；无匹配链写 `explorer.exe`；沿用金标准对 `0x9080008` 的可疑解读。
- 第二份评测基准报告未写就宣布 DLL/ComHost 正例深度达标。
- 削弱 verifier、用 Gold 100、字数、动作数代替 HOW。
- 新调查引擎、把 Resume 报告或 Sikorski 全书灌进模型。

---

## 4. 并行所有权（全程）

| Agent | 可改 | 禁止 |
|---|---|---|
| `behavior_contracts` | `investigation.py`、`behavior_catalog.py`、investigation/catalog/pma 测试 | `service.py`、`reporting.py`、`analyst_report.py`、DSH、Prompts |
| `behavior_reporting` | `reporting.py`、`analyst_report.py`、报告测试 | `service.py`、`investigation.py`、DSH |
| `dsh_depth_control` | `threat-dsh-workbench/`、`src/threat_report_agent/prompts/` | `service.py`、`investigation.py`、`reporting.py` |
| root | `service.py`、`dataflow.py`、`persist_how.py`、`static_analysis.py`、`simulation_adapters.py`、`controlled_emulation.py`、`analysis_task_orchestration.py`、emu-worker 集成、gold JSON 增补、B11 | 不拆第二人改 `service.py` |

冲突时 `service.py` 归 root。笔记 `.scratch/<task-name>-implementation.md`。

---

## 5. 增量总表（必须按依赖，允许组内并行）

```
C2 轨 B 进程/线程/PPID     ∥  (contracts + root TRACE + reporting 章)
        ↓
C3 Join 明文→消费者
        ↓
C4 其余命中槽（环境/网络/驻留/时序）  ∥  C5 调查协议 B04/K01/K02/S4
        ↓                                    ↓
C6 受控模拟 B06–B10（可与 C5 后半并行，不得先于 C2 语义）
        ↓
C7 报告十问 + M06 就绪门（依赖 C2–C5 的对象）
        ↓
C8 B00/DSH 控制环核对
        ↓
C9 T1–T4 集中契约
        ↓
C10 T5/T6/B11  3080 完整静态验收  →  才能开下一阶段
```

C2 与 C5 的「写测试」可同时红；C5 的主路径接线不要在 C2 verifier 主路径红着时宣称深挖完成。C6 不得在进程/解码槽位仍靠共现升级时扩大模拟（会把假 HOW 写成 `EMULATION_OBSERVED`）。

---

## 6. C2 — 进程创建 / 线程 / PPID

**语义**

- `PROCESS_EXECUTION`：CreateProcess(W) 类**调用** + 恢复的 `creation_flags`。缺 flags → UNKNOWN，禁止写具体创建方式。
- `THREAD_CALLBACK`：线程 API 调用 + `start_routine`（RVA/入口）。列出 CreateThread 不是闭环；入口体至少有关键调用/循环/退出或 UNKNOWN。
- `PPID_SPOOFING`：`InitializeProcThreadAttributeList` / `UpdateProcThreadAttribute` + 父进程身份来源（快照枚举 + 名称匹配证据）。无链不得写 `explorer.exe`。PPID ≠ 注入。
- flags 用常量表解码；`0x9080008` 不得直接抄金标准「挂起+新控制台」——与运算为 0 的位必须标未知或否证。
- 失败回退：CreateProcess 失败 → schtasks 仅当控制流/字符串使用链支持，否则 UNKNOWN(fallback)。

**文件**

| 轨 | 文件 |
|---|---|
| contracts | `investigation.py`：`verify_process_execution_mechanism`、`verify_thread_callback_mechanism`、`verify_ppid_mechanism` **必须被 persist/主循环调用**；缺槽不得 VERIFIED |
| root | `service.py` / `static_analysis.py`：`TRACE_API_ARGUMENT`、`process_creation_flags`、线程 start 从 R8/参数恢复；Evidence 回流 |
| reporting | `analyst_report.py`：只开本样本命中的 process-creation / thread-and-callback / parent-process-spoofing |

**测试**：`tests/test_pma_static_plan.py` 已有骨架则收紧；补「导入存在但无 flags → 结论 UNKNOWN」；T2 负例：APC≠远程注入、0x09080008 不误解码。

**过关**：契约绿 + Resume 只读产物或后续 C10 正例中这三类不再靠 API 清单。

**Gold**：仅证成后增补 flags/start_routine 组件；不删严。

---

## 7. C3 — Join：解码产物的消费者

**语义**

Lite 允许 `UNKNOWN(consumer)`。完整静态要求：若明文/缓冲在样本里确有消费者，必须连上；若静态+模拟都连不上，保留 UNKNOWN 并记录已试 `GET_DECOMPILE` / `TRACE_*` / `CONTROLLED_EMULATE`。

Resume 强制边（有证据才写死，没有则两边 UNKNOWN）：

- XOR 明文任务名/路径 → CreateProcess / schtasks 参数
- XOR 明文 URL → WinHTTP 构造（动态解析链的 consumer）
- CryptoAPI 输出缓冲 → 后续 VirtualAlloc/入口/APC（无边不得写「载荷已执行」）

**文件**：root `dataflow.py` `catalog_output_consumer_relation`、`service.py` 建 Relation；contracts 契约谓词；reporting 结论里消费者槽可见。

**测试**：T1 全组（正确边、两缓冲、无锚点 import、同/异函数无流、UNKNOWN/否定）。`tests/test_evidence_recovery.py`、`tests/test_dataflow.py`。

**过关**：错误已验证链为 0；Resume 正例要么连上明文→用途，要么双 UNKNOWN，禁止进程轨「自己发现」`Resume.pdf` 字符串当任务名却不引用解码槽。

---

## 8. C4 — 其余目录命中槽

只填**本样本有种子+证据**的类目。Resume 预期（仍按证据，不按章节抄）：

| 槽 | HOW 或 UNKNOWN |
|---|---|
| 环境门控 | `GetTickCount64` / 内存阈值常量、失败则退出的控制流 |
| 网络传输 | 动态解析的 WinHTTP 顺序、硬编码头、重建的 URL/Host；**不是**服务器当时存活 |
| 通信循环 | Sleep/延时常量 + 回跳；不是 C2 tasking |
| 防御规避 | Defender 键与 DWORD **值**；排除路径；不得写「永不扫描/关闭整个 Defender」除非证据 |
| 文件落地 | `.tmp`、MZ 校验、大小阈值 `0x1000` |
| 时序 | 由 Relation 串起来的阶段，禁止发明 Phase 1–8 空壳 |

其他样本：有则写，无则整章关闭。横向移动/命令分发/DoS 等无证据不得因 strcmp/CRT 打开。

**文件**：`behavior_catalog.py` 契约；`investigation.py` 已有 `verify_http_download_mechanism`、`verify_etw_mechanism` 等接主路径；`analyst_report.py` 选题；root 常量/字符串引用恢复。

**测试**：T2 语义负例全组。

---

## 9. C5 — 调查协议（B04 / M03 / K01 / K02 / S4）

**语义**

- 一次「分析」必须自动：开线程、提动作、吃证据、换方法或写边界。禁止要用户说「再深入」。
- 十问槽位持久化，空文本不算填槽。
- S0–S4：标 `STATIC_BOUNDARY` 前有 S1–S3 尝试记录。工具/模型失败 ≠ 边界。
- K01：`NO_NEW_EVIDENCE` 保存 method_assumption、next_method、frontier 指纹；最多自动换**一个**不同动作族。
- K02：连续多方法零增益 → `STALLED`/`BACKTRACK_REQUIRED`，一次有界升级或停，不无限循环。
- 调查线程 ≠ OS 线程。

**文件**

| 轨 | 文件 |
|---|---|
| contracts | `investigation.py` `InvestigationLoopDriver`、ledger 状态 |
| root | `service.py` `_run_investigation_loop`、`analysis_task_orchestration.py` |
| dsh | persona 已有收敛指令则**核对生效**，不靠加长 prompt 代替 ledger；`threat_propose_static_action` 在 CONVERGED 后仍 STOP |

**测试**：T3 fixture：回调 + 全局状态 + 缺消费者；一次请求多次 action；失败换族；不重放同选择器。

**过关**：T3 绿。C10 再看 Resume 动作史。

---

## 10. C6 — 受控模拟作为静态补充（B06–B10 / M05 / T4）

**何时**：目标槽静态停住（反编译/参数追踪 `NO_NEW_EVIDENCE` 或明确缺运行时值），且策略授予窗口。禁止模型自授权。

**按问题选工具**（不是固定 Unicorn→Speakeasy→Qiling 阶梯）：

| 问题 | 工具 | 失败 |
|---|---|---|
| 局部 xor/解码、短块 | Unicorn | 缺输入、循环 → 受控停 |
| Windows API 路径（Crypt*/部分进程） | Speakeasy | hook/stub 矩阵；stub 返回 ≠ 解密成功 |
| 适合其 OS 模型的用户态 | Qiling | 无 rootfs/架构 → `UNSUPPORTED`，Windows PE 不得假装成功 |

**规范化字段**（空则 `NOT_OBSERVED`，模型不得补）：输入哈希、入口、工具版本、worker 身份、hook/stub、attempted APIs、文件/注册表/网络**意图**、进程/线程/内存、解码缓冲、停止原因、输出哈希、假设范围。全程 `EMULATION_OBSERVED`。

**Child**：仅真实恢复字节；完整性检查后进既有静态管线；父报告不得在 child 未分析完时宣称载荷闭环。

**安全**：emu-worker 只读、丢权、无样本网、无宿主执行。T4 用**良性已知变换**，禁止用恶意样本打 T4。

**文件**：root `simulation_adapters.py`、`controlled_emulation.py`、`tool_execution.py`、emu Dockerfile/compose 已有则验收而非重写；contracts 不把 placeholder `DEFERRED_TO_WORKER` 当 `simulation_result`。

**测试**：T4 每适配器一条适用良性输入 + 禁网/超时/取消 + placeholder 不是观察。

**过关**：至少 Unicorn 一条真实解码/变换路径；Speakeasy/Qiling 要么真实适用路径，要么显式 UNSUPPORTED。禁止 mock 冒充 EMULATION_OBSERVED。

---

## 11. C7 — 报告就绪（B05 / M04 / M06）

**语义**

- 「分析结论」按十问投影：What/How/Target/Condition/Output/Consumer/Unknown 可追溯。摘要可短，不能丢未知状态。
- 候选不提升；HIGH 风险不按模块数量。
- 无来源组织/APT 不进结论。
- M06 自检门：API/字符串当行为、网络当活 C2、注册表/任务当持久化、PPID/APC 当注入、收集当外传、模拟当已运行 → 降级或 UNKNOWN。
- 聊天必须 `threat_get_report_summary` 且引用 `authoritative_revision_id`。

**文件**：`analyst_report.py`、`reporting.py`、报告测试；DSH 工具描述保持 STOP（C8 核对）。

**测试**：扩展 `test_analyst_report_acceptance.py`；M06 反例夹具；同一 revision 导出。

---

## 12. C8 — DSH / 模型路由（B00）

**语义**：工作台能区分模型 402/超时、策略拒绝、静态边界。STOP 后不再 `GET_DECOMPILE`。不写桌面。不引用旧 SUCCEEDED 当本轮结论。

**文件**：仅 `dsh_depth_control`：`agent.cordis.yml`、context-provider `stop_dispatch`、`threat-tool-provider` 摘要指令。

**过关**：现有 workbench 单测/persona 契约绿；C10 浏览器路径再证一次。不做 DSH core patch。

---

## 13. C9 — T1–T4 集中契约验收

在 C2–C8 代码合并后跑，不为每个目录词条单独跑毒。

| 组 | 命令（实施时按实际测试文件收紧） | 通过 |
|---|---|---|
| T1 | `pytest -q tests/test_dataflow.py tests/test_evidence_recovery.py -k decode` | 无错误已验证链 |
| T2 | investigation/reporting 负例（APC、HTTP 重试、CRT、0x09080008、模块数） | 零越级 |
| T3 | investigation recovery / deep mining 一次请求多 action | 换方法或真边界 |
| T4 | `tests/test_controlled_emulation.py` 及 isolation matrix 中**非恶意**用例 | 真实适配或 UNSUPPORTED |

禁止用 T1–T4 绿代替 C10。

---

## 14. C10 — 完整静态平台验收（B11 / T5 / T6）

**T5 用户路径（只说「分析这个样本」）**

| 样本 | 角色 | 通过 |
|---|---|---|
| Resume | 唯一正例 | 官方结论达到第 1 节能力类型或显式 UNKNOWN；revision 同源；无假深度 |
| 无评测基准报告的 PE（如 DoubleFeatureDll） | 反幻觉 | 不出现 Resume IOC；无消费者不写管线；无空类目 |
| 另一机制样本（若本地有、仍无人工报告） | 反幻觉 + 目录选题 | 同上 |
| 良性样本 | 误报 | 错误恶意结论为零 |

**T6**：对照本轮前后报告/ToolRun，必须有新参数、关系、字节或反证。字数、Gold、动作数单独不算过。

**记录**：输入哈希、代码/镜像/Prompt、模型状态、第一轮回答、Evidence 增量、revision、用时、未完成项。

**不得**：SQL 改报告、CLI 渲染冒充 3080、Codex 代写当产品效果。

C10 通过 = **完整静态阶段结束**，可以开下一阶段立项（Full 调度、沙箱动态）。C10 未过 = 仍停在静态，继续修缺口，不开下一阶段。

---

## 15. 分析模块对照（ADR-0001 首期模块）

每个模块在 C10 上必须是「HOW 或 UNKNOWN」，不是「章节存在」。

| 模块 | 完整静态要求 | 典型 UNKNOWN |
|---|---|---|
| 接入与分层 | Artifact 身份、父子、角色 | 加密包密码缺失 → BLOCKED |
| 静态分诊 | PE/节/IAT 假说、加壳门闩 | 壳 stub 当载荷功能 |
| 解密 | 算法/密钥/输入/明文/消费者 | 无消费者 |
| 加载器 | 动态解析链、入口 | 仅 LoadLibrary 导入 |
| C2 与网络 | 重建请求与配置 | 写成活 C2 |
| 反分析 | 阈值与控制流 | Sleep=反沙箱 |
| 行为与攻击链 | Relation 时序、失败回退 | 发明 Phase 空壳 |
| 归因 | 仅 candidate + 知识快照 | APT 标签 |

---

## 16. 建议日历（并行，不是再拖一条长队）

| 批次 | 增量 | 并行 |
|---|---|---|
| 1 | C2 | contracts ∥ root TRACE ∥ reporting 章 |
| 2 | C3 | root 主写，contracts 契约测试并行红 |
| 3 | C4 + C5 | 目录槽 ∥ 调查协议（service 仍 root 单写，先合 C5 测试再接线） |
| 4 | C6 | root emu；T4 良性输入 |
| 5 | C7 + C8 | reporting ∥ DSH |
| 6 | C9 然后 C10 | 单集成窗口，禁止边改边宣称 T5 |

每批结束写 `.scratch/` 缺口：已绿测试、未做 3080、仍 UNKNOWN 的槽。禁止用「代码已写」标完成。

---

## 17. 完成定义

**本文完成 = C10 通过。** 这就是完整静态版本。其后才能进入多智能体 Full 与动态沙箱。

**不在完成定义内：** 任意样本同等深度、第二份评测基准报告、Gold 100、Qiling 全 PE 通、独立解密/加载器/C2 进程、IDA 三源 diff。

Lite 增量 1 未完成时，本文零进度。
