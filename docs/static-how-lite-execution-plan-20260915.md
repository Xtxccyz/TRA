# 静态 HOW Lite 执行方案（2026-09-15）

> **用户验收已 superseded。** 2026-09-16 起，用户可见成功与 C10 以 `docs/first-usable-static-analysis-plan-20260916.md` 和 ADR-0034 为准。本文仍保留 Lite 契约与诚实门说明，不得再把「UNKNOWN 也算完成」当作 3080 过关。

本文是可执行合同，不是新调查引擎。它把用户要的产品环路落到当前代码上，并给出并行分工、增量和验收。不替代 `docs/behavior-driven-investigation-plan-reviewed-20260907.md`；是把它的 B01/B03/B05/B11 排成 Lite 顺序。

配套：`CONTEXT.md`，ADR-0031 / 0032 / 0033，`.scratch/static-how-sequence-20260915.md`，以及 canvases 目录下的 `static-how-sequence-20260915.canvas.tsx`。

**Lite 的代码范围是增量 1。** 增量 2 起的完整静态路径由 `docs/static-how-complete-execution-plan-20260915.md` 承接；本文第 7 节增量 2–5 仅为当时草稿，以完整静态方案为准。

**本文件写完后不自动改产品代码。** 开工须另一次明确授权。工作区保持 dirty，不 commit，不在宿主跑样本，不访问样本 C2，不改 API key，不用 `docker compose down -v`。

---

## 1. 产品要跑成什么样

用户放入样本并说「分析」之后：

1. 系统接入样本包，形成 Case / Artifact / Analysis Task。
2. 用蒸馏后的 PMA 规则（persona cheatsheet + `pma_static_plan.py`）和**行为目录**核对样本，生成可并行的**调查线程**（编码/配置、进程/线程等）。不是把《恶意代码分析实战》全书灌进 DSH，也不是打开 DSH skill/bash。
3. 模型只提交 **Action Proposal**；策略批准后才变成 **ToolRun**（Ghidra、解析器、授权窗口上的 Unicorn/Speakeasy/Qiling）。
4. 遇新问题：在目录动作里换方法（`GET_DECOMPILE` → `TRACE_API_ARGUMENT` → `CONTROLLED_EMULATE`）。映射不上就 `UNKNOWN`。一条 DSH 会话串行提议；无依赖的 ToolRun 后端可并行。
5. 终态引用一份官方 **Report Revision**。「分析结论」只写本样本已取证行为的 HOW，其余 `UNKNOWN`。聊天不得另写更强结论。

深度对齐 `D:\test\20260730_Resume_恶意样本分析报告.md` 所展示的**能力类型**：模块 HOW、解码配置、参数/阈值、失败回退、可落地 IOC。不对齐其章节、不抄其 IOC、不把该文件写入分析上下文。

---

## 2. 已冻结决策

| 决策 | 位置 |
|---|---|
| 首期不挂 DSH bash/web/skill/subagent；执行语义只走 `CONTROLLED_EMULATE` | ADR-0031 |
| 人工样例定能力深度，不定内容/输入 | ADR-0032 |
| 调查线程可并行，Join 在解码消费者；不是 DSH subagent | ADR-0033 |
| 当前阶段只做 Lite：契约 + 无依赖 ToolRun 并行；一条 DSH 会话；不上多路专长模型调度 | ADR-0033 续段 |
| Gold JSON 是回归下限，不是穷举；全绿 ≠ 达标 | ADR-0032 续段 |
| 正例对照只有 Resume 评测基准报告；其他样本只做反幻觉 | 第 5 节 |
| 动态分析以后用新沙箱 ToolRun，不在本阶段做 | ADR-0003 / 0019；执行器讨论已搁置 |
| 不削弱 verifier 刷覆盖率 / Gold 分数 | `test_analyst_report_acceptance.py` 前言 |

---

## 3. 明确不做

- 打开 DSH 宿主工具，或把「以后多智能体」当作现在挂 shell 的理由。
- 把 Sikorski 全书或 Resume 报告当 few-shot。
- 新建第二套 planner / claim-register / 空的多 agent 运行时。
- 把 Unicorn/Speakeasy/Qiling 写成动态分析或 `DYNAMIC_OBSERVED`。
- 无 `creation_flags` 写 `CREATE_SUSPENDED`；无 Process32 匹配链写 `explorer.exe`。
- 无消费者把 `CryptDecrypt` / XOR 写成「解密管线已坐实」。
- 把 Resume 的 C2 URL 写进其他样本。
- 用 CLI/SQL/手工改报告代替 3080 用户路径声称 B11 通过。
- 增量 1 改轨 B（进程/PPID/线程主路径），或改 DSH/Prompt。

---

## 4. Lite 运行时形状

```
一条 DSH 会话
  → threat_start_static_analysis
  → 后端确定性队列 + PMA 计划
  → 调查线程 A（编码/配置）∥ 调查线程 B（进程/线程）
  → 无依赖 ToolRun 可并行
  → Join：decode 明文/缓冲 → 消费者（API 参数或进程镜像）
  → persist HOW → Analysis Snapshot → 官方 GET「分析结论」
  → threat_get_report_summary，STOP
```

- **调查线程**：可证伪问题，不是 OS 线程，不是 DSH subagent。
- **专长 Agent**：同运行时上的逻辑角色；首期不并发达套模型调用。
- **Join**：Resume 上任务名/载荷路径来自 XOR，进程轨不得凭空写出。无这条边时两轨独立。

PMA 在产品里的位置：`agent.cordis.yml` cheatsheet + `pma_static_plan.py` 确定性计划。桌面 `sikorski-practical-malware-analysis` 只给写代码的人读。

---

## 5. 核验模型

| 材料 | 角色 |
|---|---|
| Resume 评测基准报告 | 事后对照能力类型。不进主链路。自身有待补充和可质疑 flags 解读，不是神谕。 |
| `benchmarks/gold/resume-critical-v1.json`、`resume-mechanisms-v2.json` | evaluator 回归下限。未列入 ≠ 系统无此能力。全绿 ≠ 深度达标。证成后只增补槽位。 |
| ComHost gold JSON | 同样是下限夹具，不是人工 HOW 报告。 |
| 无评测基准报告的样本 | 只验反幻觉：无证据不得闭环，不得出现 Resume IOC。 |

能力类型清单（下限可增补，不是穷举）：编码还原（算法/密钥/输入/明文/消费者）、动态 API 解析链、进程创建 flags、PPID 对象链、线程 start_routine 体、环境门控阈值、失败回退、由 Relation 支撑的时序。样本没有的类目保持关闭。

---

## 6. 并行所有权（实现 A）

沿用 `.scratch/behavior-implementation-assignments.md` / `AGENTS.md`。增量 1 把 S0 明确扩到 `analyst_report.py`。

| 轨 | 实现 agent | 可改 | 禁止 |
|---|---|---|---|
| S0 结论门 | `behavior_reporting` | `analyst_report.py`，`tests/test_analyst_report_acceptance.py`，必要时 `reporting.py` 中与官方 GET 衔接的最小面 | `service.py`、`investigation.py`、`persist_how.py`、DSH、Prompts |
| XOR 下限 | `behavior_contracts` | `investigation.py` 中 DECODE/XOR 契约与调用路径，`behavior_catalog.py` 编码类契约，`tests/test_pma_static_plan.py` / 相关 investigation 测试 | `service.py`、`reporting.py`、`analyst_report.py`、DSH |
| 消费者 UNKNOWN | root | `service.py` 解码关联，`dataflow.py`，`persist_how.py`，`tests/test_evidence_recovery.py`，`tests/test_dataflow.py`；证成后增补 gold JSON 槽 | 不改 DSH；不抢 reporting 正在改的 `analyst_report.py` 结论门 |
| 未授权 | `dsh_depth_control` | 增量 1 空闲 | — |

`service.py` 单写者 = root。状态笔记：`.scratch/<task-name>-implementation.md`。

---

## 7. 增量路线

终态仍是「4」（S0 + 轨 A + 轨 B + Join）。开工不是 4。

### 增量 1（当前授权范围，尚未开工）

S0 + 轨 A 的 XOR 下限 + 消费者可 UNKNOWN。轨 B 冻结。

**语义**

1. 官方 GET「分析结论」不得出现 `FUN_…@…:` 账本行、覆盖率字典、Evidence UUID、未命中类目空章。V3 台账留在「调查附录」。
2. XOR/DECODE：有 cipher、key/算法、明文证据时，下限槽位不得回退。`verify_xor_mechanism` 不得靠样本文件名 token 过关。
3. 没有对象级消费者（同一输出缓冲进入具体 API 参数/调用）时：保持 `UNKNOWN(consumer)`，不得升 `LINKED_STATIC`，不得写「管线已坐实」。共现、同函数混用、无锚点全局引用不能当消费者。
4. CryptoAPI（`CryptDecrypt`）走单独槽，不与 XOR 混成一条已验证解密链。
5. 静态停住才允许提议 `CONTROLLED_EMULATE`；模拟成功是 `EMULATION_OBSERVED`，不是样本已运行。

**S0 测试（reporting）**

- 保持并收紧 `tests/test_analyst_report_acceptance.py`：DLL 失败模式（假阳性章节、`FUN_` 倾倒）必须失败；有证据的 HOW 不得被结论门藏掉。
- 验收命令：`pytest -q tests/test_analyst_report_acceptance.py`

**XOR 下限测试（contracts）**

- `verify_xor_mechanism`：缺消费者 → 不得 VERIFIED 整条机制；有 cipher/key/plaintext → 变换事实可保留，missing 含 `consumer`。
- 禁止用 `Resume.pdf` 等文件名当 proof token（代码已有注释，测试钉死）。
- 验收命令：针对 `tests/test_pma_static_plan.py`、`tests/test_investigation.py` 中 DECODE/XOR 用例的聚焦 pytest。

**消费者 UNKNOWN 测试（root）**

- 强化 `tests/test_evidence_recovery.py`：`test_decode_result_does_not_link_api_cooccurrence` 及不同缓冲反例必须保持。
- 正例只接受 `catalog_output_consumer_relation` 所需的同一 `output_buffer` 身份。
- persist HOW：无消费者时 Claim/报告槽为 UNKNOWN，不编造 downstream API。
- 验收命令：`pytest -q tests/test_evidence_recovery.py tests/test_dataflow.py -k decode`

**Gold**

- 不把现有 JSON 当完整答案。
- 仅当某槽在 Resume 路径上被类型化证成后，才往 `resume-mechanisms-v2.json` **增加**下限项（例如显式 `consumer` 组件）。不得为了让分数变绿而删严槽位。

**增量 1 过关（契约，不是完整 B11）**

- 上述 pytest 绿。
- 不削弱 verifier。
- 无 3080 T5 冒充完成。若有已有 Resume 任务产物，只做只读对照：结论无 `FUN_` 倾倒；无消费者则文中可见 UNKNOWN；不得出现编造管线。
- DoubleFeatureDll 等无基准样本：若碰巧跑到，只检查反幻觉，不声称 Resume 深度。

### 增量 2 — 轨 B 进程/线程（增量 1 合并之后）

- `PROCESS_EXECUTION`：要有 CreateProcess 类调用 **和** 恢复的 `creation_flags`；否则 UNKNOWN，不写具体创建方式。
- `THREAD_CALLBACK`：要有线程 API **和** `start_routine`；列出 CreateThread 不是闭环。
- `PPID_SPOOFING`：要有属性链 + 父进程身份证据；禁止无 Process32 链写 `explorer.exe`。
- 不把 PPID 写成注入。不把金标准对 `0x9080008` 的解读当标准答案；flags 按常量表解码。
- 正例：Resume 3080 一次「分析」，不喂评测基准报告。
- 实现：contracts 接 verifier 主路径；root 接 `TRACE_API_ARGUMENT` 回流；reporting 只开命中的 process/thread/PPID 章。

### 增量 3 — Join

- 解码输出缓冲 → 进程镜像 / 计划任务名 / WinHTTP URL 的 Relation。
- Resume：载荷路径、任务名必须能追溯到 XOR 明文槽，或两边都标 UNKNOWN。
- 无 Join 边时轨 A/B 仍可独立闭环各自槽位。

### 增量 4 — S3 其余命中槽

环境门控阈值、网络请求重建（不是活 C2）、持久化 vs 一次性 schtasks、由 Relation 支撑的时序。未命中类目保持关闭。

### 增量 5 — Lite 正例验收（B11 静态部分）

- 3080：放入 Resume →「分析这个样本」→ 官方 revision = 聊天结论。
- 对照评测基准报告的能力类型，不对照章节复制。
- Gold JSON 下限不回退，且不作为「已完成」。
- 无基准样本只报反幻觉结果。
- 仍不做 Full 多路专长调度、不做动态沙箱。

### 增量 6 以后（本阶段不排期）

- Full：一次 Task 内并行专长模型调用（仍共享 Evidence，仍无 DSH subagent）。
- 动态分析：隔离沙箱 Worker + `DYNAMIC_OBSERVED`。
- 第二份评测基准报告：若要对 DLL/ComHost 做正例深度验收，必须另写人工报告。

---

## 8. 增量 1 文件级清单

### reporting 轨

| 文件 | 动作 |
|---|---|
| `src/threat_report_agent/analyst_report.py` | `primary_analyst_violations`、选题：仅本样本证据/PMA 高价值假说；无消费者的编码章必须能写 UNKNOWN |
| `tests/test_analyst_report_acceptance.py` | 保持 DLL 复盘用例；增加「有 XOR 明文、无消费者 → 结论含 UNKNOWN(consumer)、无管线已坐实」 |
| `src/threat_report_agent/reporting.py` | 仅当官方 GET 仍拼接 V3 正文时做最小衔接；不改评分刷 HIGH |

### contracts 轨

| 文件 | 动作 |
|---|---|
| `src/threat_report_agent/investigation.py` | `verify_xor_mechanism` / `verify_mechanism("DECODE_CONFIG")` 主路径确实被调用；缺消费者 → 非整链 VERIFIED |
| `src/threat_report_agent/behavior_catalog.py` | 编码类契约：消费者是独立槽，不是 API 共现 |
| `tests/test_pma_static_plan.py` 等 | 钉死：无消费者不得 VERIFIED；文件名不是 plaintext 证明 |

### root 轨

| 文件 | 动作 |
|---|---|
| `src/threat_report_agent/dataflow.py` | `catalog_output_consumer_relation` 保持同一缓冲身份 |
| `src/threat_report_agent/service.py` | 解码关联调用处：无关系就不写 LINKED；不要为过 verifier 填假 consumer |
| `src/threat_report_agent/persist_how.py` | 投射 DECODE HOW 时保留 UNKNOWN(consumer) |
| `tests/test_evidence_recovery.py`、`tests/test_dataflow.py` | 共现反例 + 同缓冲正例 |
| `benchmarks/gold/resume-mechanisms-v2.json` | 仅证成后增补；禁止删严 |

### 所有人不动（增量 1）

`threat-dsh-workbench/`、`prompts/`、进程/PPID/线程 verifier 扩 scope、emu-worker 新能力、DSH 预设回挂 bash/skill。

---

## 9. 建议实施顺序（并行时的汇合）

1. **T0 同步（短）**：三轨各自先写失败测试（红），不改生产语义。reporting 用 DLL 结论门；contracts 用无 consumer 的 XOR；root 用共现反例。
2. **T1 并行改**：按第 8 节文件改到测试绿。
3. **T2 root 集成**：确认 `verify_mechanism` 在 persist HOW 路径吃到的是真实 Evidence，不是关键词汤。
4. **T3 只读抽查**：若环境已有 Resume 任务产物，对照「分析结论」；不跑完整 T5，除非用户另授 B11。

冲突时 root 的 `service.py` 优先；reporting 不得为排版改 Evidence。

---

## 10. 与现有 B 任务的映射

| 本方案 | 行为方案 |
|---|---|
| 增量 1 消费者 | B01 |
| 增量 1 XOR 契约 | B03 的 DECODE 切片（非整本目录重写） |
| 增量 1 结论门 | B05 / M04 的官方正文部分 |
| 增量 2 | B03 进程/线程/PPID 主路径 |
| 增量 3 | B01 Join + Relation |
| 增量 5 | B11 静态用户路径 |
| 受控模拟 | 仅当增量 1/2 静态停住；B06–B10 不在增量 1 扩大范围 |
| Full 多智能体 | 增量 6 以后 |

---

## 11. 完成定义

**增量 1 完成：** 第 7 节契约测试绿；无 verifier 削弱；无把 mock/CLI 报成 3080 验收。

**Lite 阶段完成：** 增量 5。Resume 一次「分析」的官方结论达到能力类型深度或显式 UNKNOWN；gold 下限不回退；无 DSH 宿主工具；无第二套调度器。

**产品愿景完成：** Lite + 以后的 Full 专长并行 + 以后的沙箱动态分析。后两项不在本文开工范围。
