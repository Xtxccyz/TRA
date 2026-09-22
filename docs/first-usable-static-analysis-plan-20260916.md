# 第一版可用静态分析 — 逐步实施手册

日期：2026-09-16  
状态：**计划已锁。未收到用户「按本文开工」之前，禁止改产品代码、钩子、Docker 镜像、`.scratch/static-how-lite-status.json` 的完成标记。**  
读者：能力一般的编码 Agent。按节执行，不要跳步，不要发明第二种完成定义。

配套（先读，读完再改代码）：

1. 本文  
2. `CONTEXT.md`（只用这里的词）  
3. ADR-0002、0031、0032、0033、**0034、0035、0036**  
4. `docs/behavior-driven-investigation-plan-reviewed-20260907.md` 第 7 节契约、第 10 节 T 组（验收形状，不是「HOW 或 UNKNOWN 过关」）  
5. 评测基准报告只允许你（写代码的人）对照能力类型：`D:\test\20260730_Resume_恶意样本分析报告.md`。**禁止**把该文件写入分析上下文、Prompt、few-shot、知识快照。

旧计划 `docs/static-how-lite-execution-plan-20260915.md` 与 `docs/static-how-complete-execution-plan-20260915.md` 仅吸收 T4 隔离 / emu-worker 安全。它们的 C10「HOW 或 UNKNOWN」**已作废**（ADR-0034）。`.scratch/static-how-lite-status.json` 里 `complete_c10_passed=true` **不是**用户需求已完成。

---

## 0. 你是谁、先做什么、何时停

### 0.1 每次会话开始（复制执行）

1. 读本文第 0–2 节和第 8 节禁令。  
2. 读 `.scratch/first-usable-status.json`（没有就按第 12 节创建，`current_gate` 为 `G0`）。  
3. 只做 `current_gate` 这一组。做完更新状态文件。未绿不得开下一组。  
4. 用 TDD：先写失败测试，再改产品代码，再跑指定 pytest。  
5. 不要 commit。不要改 API key。不要 `docker compose down -v`。不要在 Windows 宿主执行样本。不要访问样本里的 URL/IP。不要打开 DSH 的 bash/web/skill/subagent。

### 0.2 文件所有权（并行时必须遵守）

| Agent 名字含 | 可改 | 禁止 |
|---|---|---|
| `behavior_contracts` | `src/threat_report_agent/investigation.py`、`behavior_catalog.py`、对应 tests | `service.py`、`reporting.py`、`analyst_report.py`、DSH |
| `behavior_reporting` | `reporting.py`、`analyst_report.py`、报告 tests | `service.py`、`investigation.py`、DSH |
| `dsh_depth_control` | `threat-dsh-workbench/`、`src/threat_report_agent/prompts/` | `service.py`、`investigation.py`、`reporting.py` |
| root / 无轨名 | `service.py`、`dataflow.py`、`persist_how.py`、`static_analysis.py`、`analysis_task_orchestration.py`、`controlled_emulation.py`、`simulation_adapters.py`、emu-worker、钩子、gold JSON **只增不删严**、G5 集成 | 不要两个人同时改 `service.py` |

冲突时 `service.py` 只允许一个人写。状态笔记：`.scratch/<task-name>-implementation.md`。

### 0.3 用户要的一句话

用户在 3080 提交样本并说「分析这个样本」后，得到一篇**分析员能用的分析报告**：该样本真实存在的行为被挖到 HOW（参数、配置、消费者、回退），没有的类目写「已核对未发现」，没有编造，没有把 Resume 的 IOC 抄到别的样本上。系统自己调查、静态停住就真实进隔离模拟器。**不是** 1/28 闭合率，不是账本，不是「再深入」才能继续。

### 0.4 本文完成 = 仅 G5

G0–G4 全绿也不许对用户说「已经能用」。只有 G5 的 3080 用户路径过了，才许说第一版可用。

---

## 1. 必须使用的术语（禁止自造同义词）

以 `CONTEXT.md` 为准。弱 Agent 容易写错的对应：

| 禁止说 | 必须说 |
|---|---|
| 动态分析（指 Unicorn/Speakeasy/Qiling） | **受控模拟**，证据性质 `EMULATION_OBSERVED` |
| 闭合率 / 机制闭合当用户成功 | **机制就绪**（内部诚实门）；用户成功是 **分析报告** 能力类型 |
| HOW 或 UNKNOWN 即完成 | **镜像内可恢复** 槽未恢复不得 COMPLETE |
| 同一缓冲 length 全等才算消费者 | **解码消费者 Join**（对象别名，ADR-0035） |
| 看不懂就沙箱跑样本 | 隔离 **emu-worker**；禁止宿主执行；禁止完整沙箱 **动态分析** |
| 润色稿直接给用户 | 通顺稿是内部 DRAFT；过 **报告合成门** 才是官方分析结论 |
| 调查线程 = CreateThread | **调查线程** ≠ **执行线程** |

---

## 2. 全局禁令（违反即本闸失败）

1. 削弱 `verify_*_mechanism`、`mechanism_is_critical_ready`、`static_wording_violations` 来增加 VERIFIED 条数。  
2. 把 `D:\test\20260730_Resume_恶意样本分析报告.md` 或其中 C2 URL、任务名、IOC 写入 Prompt / 分析上下文 / 其他样本报告。  
3. 无 `EXTENDED_STARTUPINFO_PRESENT` / `CREATE_NO_WINDOW` 的立即数写成 `creation_flags`（例如 `0x000f4240`）。  
4. 把 `0x09080008` 写成 `CREATE_SUSPENDED` + `CREATE_NEW_CONSOLE`（与运算为 0）。  
5. 单独进程名字符串写成父进程身份；PPID 写成注入。  
6. `DEFERRED_TO_WORKER` 当成已模拟或 `STATIC_BOUNDARY`。  
7. stub 的 WinHTTP/CreateProcess 写成活 C2、本次 PID、宿主已创建进程。  
8. 聊天一份更强结论、页面一份更弱。必须同一 `Report Revision`。  
9. 用 SQL/CLI/`render_official_markdown` 冒充 3080 用户路径宣称 G5 通过。  
10. 宣称 G5 通过却没有新的 Join / 说得通的 flags / 入口体（只加字数或 Verified 从 1 变 2 但 HOW 仍空）。

---

## 3. 当前代码里已经确认的根因（改之前先打开这些行）

按这个表改，不要另起一套调查引擎。

| 根因 | 位置 | 错误行为 |
|---|---|---|
| 旧 C10 完成定义 | `docs/static-how-complete-execution-plan-20260915.md`；`.scratch/static-how-lite-status.json`；`.cursor/hooks/static-how-lite-continue.py` | HOW 或 UNKNOWN 就算过 |
| persist skip 优先于规划器 | `analysis_task_orchestration.py`：`next_investigation_loop_path`、`resolve_persist_how_skip` | CANDIDATE 可写就停挖 |
| consumer 不跑参数追踪 | `investigation.py` `_MISSING_FIELD_ACTIONS["consumer"]` 约 1269–1274 行 | 只有 GET_CALLEES / TRACE_RETURN_VALUE / GET_DECOMPILE / CONTROLLED_EMULATE |
| Join 过严 | `dataflow.py` `decoded_output_consumer` 要求 address **和** length 全等；`catalog_output_consumer_relation` 无 `artifact_id` 返回 None；`output_buffer_identity` 不带 artifact_id | Resume 切片引用永远 UNKNOWN(join) |
| 假 flags | `service.py` TRACE_API_ARGUMENT 写 `process_creation_flags` 时只排除 `0xFFFFFFFF`，**没调用** `plausible_windows_process_creation_flags` | `0x000f4240` 进 HOW |
| 页脚撒谎 | `analyst_report.py` `_recovered_creation_flags` 用正则 `creation_flags\s*=`；章节可能写成 `creation_flags0x000f4240;` | 正文有值、页脚 UNKNOWN(creation_flags) |
| 模拟占位 | `service.py` CONTROLLED_EMULATE 在 docker 隔离下 `add("simulation_result", status=DEFERRED_TO_WORKER)` | 占位当已尝试 |
| 报告套话 | `analyst_report.py` 加载器/线程章节模板；`_verification_note` 固定 28 条口径 | 主文像账本 |

评测基准报告展示的能力类型（只对照，不抄内容）：模块 HOW、XOR/配置明文与用途、进程 flags、PPID 对象链、线程入口体、失败回退、可落地 IOC。

---

## 4. G0 — 停掉旧完成定义

**目标：** 任何 Agent 都不能再靠 UNKNOWN 或 `complete_c10_passed` 宣布用户需求完成。命中线程缺 consumer/flags/start_routine 时必须继续 TRACE_API_ARGUMENT / GET_DECOMPILE / 真实 CONTROLLED_EMULATE。

### 4.1 可改 / 禁止

可改：`.cursor/hooks/static-how-lite-continue.py`、`.cursor/hooks.json`（若改 command 路径）、`.scratch/first-usable-status.json`（新建）、`analysis_task_orchestration.py`、`investigation.py`（只改 `_MISSING_FIELD_ACTIONS` 与 `recovery_actions_for_gap` 相关）、`analyst_report.py` 中 `_recovered_creation_flags` / `_verification_note`、对应 tests。  
禁止：这一组不要改 Join 算法、不要改 emu-worker、不要改 DSH。

### 4.2 钩子（必须先做）

把 `.cursor/hooks/static-how-lite-continue.py` 的 `PROMPT` 改成只认本文：

- 读 `.scratch/first-usable-status.json`  
- `complete_c10_passed` **不再**作为停工条件  
- 未完成 G5 时 followup 必须是：「继续 `docs/first-usable-static-analysis-plan-20260916.md` 的当前 gate，禁止用 HOW 或 UNKNOWN 宣称完成。」  
- `first_usable_g5_passed is true` 才允许空 followup  

保留 `loop_limit`。不要删 stop hook。

### 4.3 persist skip 语义（必须改）

文件：`src/threat_report_agent/analysis_task_orchestration.py`

当前：`persist_ready` 且 `recovery_actions_for_gap` 为空 → `PERSIST_HOW_READY`，leftover TRACE 被取消。

改为：

- `gate.missing` 含 `consumer`、`creation_flags`、`start_routine`、`plaintext`、`join`、`parent identity` 任一（大小写不敏感，含 `unknown(consumer)` 这类）→ **必须** `PERSIST_HOW_MINE` 或至少 keep `TRACE_API_ARGUMENT` + `GET_DECOMPILE` + `CONTROLLED_EMULATE`。  
- 不得因「已经写出 CANDIDATE HOW 句子」而 skip。  
- leftover `GET_CALLEES` / 无缺口的 TRACE 仍可取消，避免聊天要求「再深入」刷无关动作。

现有测试 `tests/test_analysis_task_orchestration.py`：`test_persist_how_ready_skips_mining_when_playbook_is_present` 在 missing 为空时仍可 READY。你必须**新增**测试：`missing=("consumer",)` 时 disposition 不是 READY，或 keep 列表含 `TRACE_API_ARGUMENT`。

同类：`tests/test_investigation_recovery_loop.py` 的 `test_persist_skip_keeps_argument_trace_and_emulate` 必须继续绿，并覆盖 consumer 缺口。

### 4.4 `_MISSING_FIELD_ACTIONS["consumer"]`

文件：`src/threat_report_agent/investigation.py` 约 1269 行。

**必须**把 `ActionType.TRACE_API_ARGUMENT.value` 放在该元组**第一位**，保留 GET_DECOMPILE 与 CONTROLLED_EMULATE。不要删 DECODE 相关动作。

新增测试（放 `tests/test_investigation.py` 或 `tests/test_investigation_recovery_loop.py`）：

```text
recovery_actions_for_gap("DECODE_CONFIG", ("consumer",))
  必须包含 TRACE_API_ARGUMENT
  在尚未 attempted 时，TRACE_API_ARGUMENT 出现在 GET_CALLEES 之前或至少存在
```

### 4.5 页脚 flags 正则

文件：`src/threat_report_agent/analyst_report.py` `_recovered_creation_flags`

正则必须同时匹配：

- `creation_flags=0x...`  
- `creation_flags = 0x...`  
- `creation_flags0x...`  
- `creation_flags \`0x...\``  

若已恢复且 `plausible`，`_verification_note` 的 PROCESS_EXECUTION 分支必须走「已恢复 creation_flags」那句，禁止再写 `UNKNOWN(creation_flags)`。

测试：`tests/test_behavior_reporting.py` / `tests/test_analyst_report_acceptance.py` 增加：blob 为 `creation_flags0x00080000;` 时不得输出「flags 未恢复」。**注意：** `0x000f4240` 不是合法 flags，不得被当成已恢复成功 HOW。

### 4.6 G0 验收命令（必须全部绿）

在仓库根目录：

```text
pytest -q tests/test_analysis_task_orchestration.py tests/test_investigation_recovery_loop.py tests/test_investigation.py -k "persist or recovery_actions or consumer"
pytest -q tests/test_analyst_report_acceptance.py tests/test_behavior_reporting.py -k "creation_flags or verification_note or recovered_creation"
```

若 `-k` 太窄导致 0 tests，去掉 `-k` 跑整个文件。

### 4.7 G0 完成清单（全部勾上才能改 status）

- [ ] 钩子 followup 指向本文，不以 `complete_c10_passed` 停  
- [ ] consumer 缺口会 TRACE_API_ARGUMENT  
- [ ] missing consumer 时 persist 不是 READY  
- [ ] 页脚不再在已有 flags 文本时撒谎  
- [ ] 未削弱 verifier  
- [ ] `.scratch/first-usable-status.json` 中 `G0.status=passed`，`current_gate=G1`

---

## 5. G1 — 解码消费者 Join 与合法 flags

**目标：** XOR/解密输出的切片若被 WinHTTP 或 CreateProcess 当参数用，必须 Join；硬编码共现不得 Join。调用点立即数只有说得通的进程 flags 才能进 HOW。

### 5.1 可改文件

root：`dataflow.py`、`service.py`（TRACE_API_ARGUMENT 写 flags 的那段，约 6098–6120 行）、`persist_how.py`（decode HOW 的 consumer 字段）、`static_analysis.py`（只复用 `plausible_windows_process_creation_flags`，不要改常量表语义）。  
contracts：`investigation.py` 的 `verify_xor_mechanism` 在有明文+对象别名消费者时不得因缺「全等 length」失败。  
tests：`tests/test_dataflow.py`、`tests/test_evidence_recovery.py`、`tests/test_static_xor_config_recovery.py`、`tests/test_deep_static_semantics.py`、`tests/test_mechanism_chains.py`。

禁止：削弱 `test_decode_result_does_not_link_api_cooccurrence`。

### 5.2 Join 算法（ADR-0035）

改 `decoded_output_consumer`（`dataflow.py` 约 275 行）：

保留：`resolved is True`、命名 API、`source_role == decoded_output`、producer id、callsite、argument_index ≥ 0、同一 `address_space`。

**删除**「address 与 length 都必须相等」。

**改为对象别名：**

- 将 address 用已有 `addresses_alias(..., image_base)` 比较。  
- consumed 的 address 落在 `[output.address, output.address + output.length)` 内（切片）也算 Join。  
- length 可以不等。length 缺失时，若 address 别名成功且 API 是字符串类参数（WinHttp* URL、CreateProcess lpCommandLine/lpApplicationName），允许 Join。  
- `catalog_output_consumer_relation`：不要仅因缺少 `artifact_id` 返回 None。若 producer Evidence 有 `artifact_id`，用 `with_artifact_identity` 补上。  
- `decoded_va_reference` 仍**不是** Join（`is_object_level_decode_consumer` 已排除）。

### 5.3 必须先写的测试（红）

在 `tests/test_dataflow.py`：

1. **正例切片：** output 缓冲 VA=`0x14004A000` length=`0x200`；WinHttpOpenRequest 参数指向 `0x14004A040` resolved。必须 Join。  
2. **正例别名：** RVA vs image_base+RVA，`addresses_alias` 为真。必须 Join。  
3. **反例共现：** 同函数有 CreateProcess 与 decode，参数是另一个 VA 或未 resolved。不得 Join。  
4. **反例硬编码：** 参数字符串 `FoxitPDFReader.exe` 与明文相同但没有地址关系。不得 Join。  
5. **反例 FUN_：** consumer API 为 `FUN_140012345` 不得算命名消费者。

`tests/test_evidence_recovery.py` 保持 `test_decode_result_does_not_link_api_cooccurrence` 绿。

### 5.4 flags plausibility

`service.py` 在 `add("process_creation_flags", ...)` **之前**调用 `plausible_windows_process_creation_flags(parsed_flags)`。假则：

- 不写 process_creation_flags Evidence，或  
- 写明 `rejected_as_creation_flags` 且 persist HOW 用 `UNKNOWN(creation_flags)` 并记录 raw 值仅在附录。

`0x00080000`（EXTENDED_STARTUPINFO_PRESENT）应通过。`0x000f4240`、`0xFFFFFFFF` 不得通过。

`tests/test_mechanism_chains.py` 的 `test_process_creation_flags_do_not_overclaim_suspended_or_console_modes` 必须保持绿。新增：TRACE 路径不把 `0xF4240` 当成 flags。

### 5.5 G1 验收命令

```text
pytest -q tests/test_dataflow.py tests/test_evidence_recovery.py tests/test_static_xor_config_recovery.py tests/test_deep_static_semantics.py tests/test_mechanism_chains.py tests/test_persist_how.py
```

### 5.6 G1 完成清单

- [ ] 切片 Join 测试绿  
- [ ] 共现/硬编码反例绿  
- [ ] 0xF4240 不进 HOW  
- [ ] 未把 Resume IOC 写进测试以外的产品 Prompt  
- [ ] status `G1.passed`，`current_gate=G2`

---

## 6. G2 — 真实受控模拟

**目标：** 镜像内槽静态停住后，必须出现 emu-worker 的真实 `simulation_result`（SUCCEEDED / FAILED / UNSUPPORTED / 超时均可）。占位不能结束调查线程。

### 6.1 可改文件

`service.py`（CONTROLLED_EMULATE 分支约 6743–6809 行、`_attempted_recovery_names` 丢弃占位的逻辑约 1318、`_run_post_static_emulation`）、`controlled_emulation.py`、`simulation_adapters.py`、`gold_output_bar.py` 中 DEFERRED 集合、tests：`test_controlled_emulation.py`、`test_t4_isolation_matrix.py`、`test_simulation_policy.py`、`test_unique_thread_emulation.py`、`test_pe_entry_function_budget.py` 里占位相关。

禁止：改 T4 隔离让 API 进程本地跑恶意 PE；禁止 `SIMULATION_ALLOW_LOCAL_PROCESS=true` 在 Compose 里对真实样本。

### 6.2 占位规则（已有 CONTEXT「受控模拟占位」）

`DEFERRED_TO_WORKER` / `WORKER_REQUIRED` / `SUPERSEDED_BY_WORKER`：

- 不是 attempted CONTROLLED_EMULATE  
- 不能 `STATIC_BOUNDARY`  
- 调查循环必须继续等到 worker 回写，或显式 FAILED/UNSUPPORTED  

实现：`investigation.py` `_attempted_recovery_names` 已有「CONTROLLED_EMULATE 在 names 但不在 completed 则 discard」。把 Evidence 行 status 为上述占位的也视为未完成。

`service.py` 在 persist skip 之后 `_keep_emulation_after_persist_skip` 必须留下 CONTROLLED_EMULATE，且 **dispatch 到 Temporal `static-emu` queue**，不要只 add 一行占位就 CONVERGED。

### 6.3 模拟窗口（第一版，不怕贵）

对每个仍缺的镜像内槽，按问题选工具（不是固定 Unicorn→Speakeasy→Qiling 阶梯）：

| 缺口 | 工具 | 失败时 |
|---|---|---|
| XOR/明文字节 | Unicorn 授权窗口 | 缺输入 → 记录缺输入，不得补零冒充明文 |
| start_routine 入口体 | Unicorn 或 Speakeasy | 无入口 VA → UNKNOWN(start_routine) 且记已试 |
| WinHTTP / CreateProcess 参数 | Speakeasy（若政策允许该窗口） | stub 返回记意图，不写活 C2 |
| Qiling Windows PE | 无 rootfs → `UNSUPPORTED` | 禁止假装成功 |

Compose 已有 `emu-worker`，`SIMULATION_PROFILE=static-first-controlled-emulation`。G2 不要重写 Dockerfile，要验收 worker 结果回流 `EMULATION_OBSERVED`。

### 6.4 必须先写的测试

1. 占位行不能让 `recovery_actions_for_gap` 认为 CONTROLLED_EMULATE 已 attempted。  
2. 真实 Unicorn XOR 变换（良性短字节，已有 `test_controlled_emulation.py`）必须仍绿。  
3. stub 成功不得把 Claim status 打成「运行时已外联」。  
4. T4 隔离矩阵 58 条继续绿：`pytest -q tests/test_t4_isolation_matrix.py`

### 6.5 G2 验收命令

```text
pytest -q tests/test_controlled_emulation.py tests/test_t4_isolation_matrix.py tests/test_simulation_policy.py tests/test_unique_thread_emulation.py
```

Docker 若未起，T4 里依赖 compose 的测试失败则记录 BLOCKED，**不得**把跳过写成 passed。G5 前必须能起 `emu-worker`。

### 6.6 G2 完成清单

- [ ] 占位 ≠ attempted 的测试绿  
- [ ] T4 绿或明确 BLOCKED（缺 Docker）且未标 G2 passed  
- [ ] 无「模拟成功 = 样本已运行」措辞进入 reporting  
- [ ] status `G2.passed`，`current_gate=G3`

---

## 7. G3 — 进程 / PPID / 线程 HOW

**目标：** 主文可以写进程/PPID/线程，但必须达到第 1 节最低 HOW；导入表不够。

### 7.1 可改

contracts：`investigation.py` 中 `verify_process_execution_mechanism`（约 5045）、`verify_ppid_mechanism`（约 4589）、`verify_thread_callback_mechanism`（约 5112）。确认它们被 persist / 主循环调用；只注册未调用 = 未完成。  
root：`persist_how.py` `_recovered_process_how_fields`、线程 start_routine 文本（文件内已有 `UNKNOWN(start_routine)` 注释约 1593 行）。  
reporting：`analyst_report.py` 进程/PPID/线程章节生成函数（约 1080–1190、进程创建段）。

### 7.2 最低 HOW（写进测试断言）

**进程创建**

- 有 CreateProcess(W) **调用**（不是仅 IAT）  
- `creation_flags` 通过 `plausible_windows_process_creation_flags`，或明确 `UNKNOWN(creation_flags)` 且附录写 raw + 拒绝原因  
- 命令对象来自 Join 或调用点立即数，不是无来源字符串  
- fallback：仅当控制流/使用链接到 schtasks 等才写；否则 `UNKNOWN(fallback)`  
- 禁止：导入即「已创建进程」；禁止抄金标准挂起+新控制台

**PPID**

- `UpdateProcThreadAttribute` 或等价 + 镜像内 Process32 枚举或名称使用链  
- 禁止：单独 `explorer.exe` 字符串 = 父进程身份  
- 模拟观察到枚举链 = 镜像内可恢复，仍不得写「本次运行父进程 PID=…」

**线程**

- `start_routine` VA  
- 入口体至少：关键调用或循环或退出，或三者都 UNKNOWN 且已反编译/局部模拟  
- 列出 CreateThread ≠ 闭环；同进程 ≠ 远程注入

### 7.3 测试

`tests/test_pma_static_plan.py`、`tests/test_persist_how.py`、`tests/test_mechanism_chains.py`、`tests/test_analyst_report_acceptance.py`：

- 仅 IAT CreateProcess → 主文不得「已过验证器门限」当进程 HOW 完成  
- 无 Process32 链 → 不得写 explorer 伪装成功  
- CreateThread 无入口 → 必须出现 `UNKNOWN(start_routine)` 且不得章节标 recovered（`_blocking_unknown_demotes_threshold` 对 thread 已有 demote，保持并测网络章节同类）

### 7.4 G3 验收命令

```text
pytest -q tests/test_persist_how.py tests/test_pma_static_plan.py tests/test_mechanism_chains.py tests/test_analyst_report_acceptance.py -k "process or ppid or thread or creation_flags or start_routine"
```

### 7.5 G3 完成清单

- [ ] 三个 verifier 在 persist 路径被调用（加测试或 grep 断言测试）  
- [ ] IAT 负例绿  
- [ ] status `G3.passed`，`current_gate=G4`

---

## 8. G4 — 完整报告：分段、通顺 DRAFT、合成门

**目标：** 用户打开官方 GET「分析结论」是一篇完整分析员报告：适用目录类目每类一段；命中写 HOW，未命中写「已核对未发现」；通顺可以，编造不行。

### 8.1 可改

`analyst_report.py`、`reporting.py`（官方 GET 衔接最小面）、`tests/test_analyst_report_acceptance.py`、`tests/test_behavior_reporting.py`、`tests/test_report_bloat_gate.py`、`product_certification.py` 的 `static_wording_violations`（只加检查，不放宽）。  
DSH：仅当官方 GET 与 leftover 不一致时由 `dsh_depth_control` 改摘要指令，使 leftover = 官方 GET。

### 8.2 主文必须有的结构

1. 报告核心维度：任务状态、样本与组件、静态事实（PE/哈希/节，导入不当功能清单）、命中行为 HOW、IOC（仅本样本 Evidence）、ATT&CK **candidate**、分析限制。  
2. `CATALOG_TITLES_ZH` 里**对本文件类型适用**的类目各有一节（见 `analyst_report.py` 41–71 行）。PE 适用 Windows 那些类；不要对 PE 省略 C2/持久化/注入/编码/进程/PPID/线程。  
3. 未命中模板（固定，禁止发挥）：  
   `已核对：<类目>。静态导入/字符串/调用序列与受控模拟均未提供对象级使用链。不是「样本没有恶意能力」的证明。`  
4. 命中模板必须含：做什么、怎么做（函数/RVA 可进附录）、关键参数、输出/消费者（Join 或 UNKNOWN）、失败回退或 UNKNOWN、Evidence 可追溯（主文可用稳定短锚，UUID 进附录）。  
5. `## 调查附录（内部账本，非分析结论）`：十问槽、机制就绪计数、FUN_、覆盖率字典。主文不得出现 `FUN_`、Evidence UUID、`Seed Map`、`closure` 百分比作为结论。

### 8.3 合成流水线（ADR-0036）

1. 每类目从 Claim/Finding **确定性**生成片段，写入 Snapshot / Document 行（暂存）。  
2. 可选模型通顺：输入=片段+禁止清单；输出=DRAFT 正文。  
3. **报告合成门**（代码，不是人审）：  
   - `static_wording_violations` 失败 → 丢弃 DRAFT，发布拼接稿  
   - 新 URL/IP/父进程名/flags 不在片段 Evidence 中 → 失败  
   - 把 CANDIDATE/UNKNOWN 写成「已验证/已执行/活 C2」→ 失败  
   - Resume IOC 出现在非 Resume 样本 → 失败  
4. 过门正文成为官方分析结论。聊天 `threat_get_report_summary` 必须引用同一 `authoritative_revision_id`。  
5. 禁止再让模型生成 HTML/DOCX 专用稿（ADR-0025）。

### 8.4 必须先写的测试（`tests/test_analyst_report_acceptance.py`）

1. DoubleFeatureDll 失败模式继续：主文无 FUN_ 倾倒、无横向移动空章编造（未命中只允许「已核对」句，不允许编 IOC）。  
2. 润色稿加入片段没有的 `http://evil.example` → 官方正文不得出现。  
3. 润色把 CANDIDATE 写成 VERIFIED → 门失败。  
4. 拼接稿含全部适用类目标题。  
5. 主文可以没有「机制闭合率」；若出现只能在附录。  
6. 聊天/导出同源：已有 leftover=GET 测试保持绿。

### 8.5 G4 验收命令

```text
pytest -q tests/test_analyst_report_acceptance.py tests/test_behavior_reporting.py tests/test_report_bloat_gate.py tests/test_c10_t5_benign_contract.py
```

### 8.6 G4 完成清单

- [ ] 适用类目全覆盖测试绿  
- [ ] 合成门负例绿  
- [ ] 良性 PE 测试不编造 C2（`test_c10_t5_benign_contract.py`）  
- [ ] status `G4.passed`，`current_gate=G5`

---

## 9. G5 — 3080 用户路径（唯一用户验收）

**禁止：** CLI 渲染、SQL 改报告、只跑 pytest、用旧任务 `0d8d73a4` / revision `7969ba96` / `f117af1c` 冒充本轮 G5。那些是 T6 对照基线，不是本轮通过证明。

### 9.1 启动（用户环境）

1. 用户用 `Start-ThreatReportAgent.bat` 起工作台（DSH :3080，API :8000）。  
2. 你改完 G0–G4 后必须重建 **api** 与 **emu-worker** 镜像（代码在镜像里才算数）：  
   `docker compose build api emu-worker`  
   然后 `docker compose up -d --no-deps --force-recreate api emu-worker`  
   **禁止** `-v`。  
3. `GET http://127.0.0.1:8000/healthz` 成功。  
4. `docker compose ps` 中 emu-worker 在跑。

### 9.2 浏览器操作（必须像用户）

1. 打开 http://127.0.0.1:3080 （或工作台实际入口）。  
2. **新建会话**（不要续旧会话当本轮 G5）。  
3. 附加用户指定的样本包（Resume 正例用用户提供的 Resume 样本，不要用仓库里的 `workspace/Resume.pdf.exe.VIR` 除非用户指定）。  
4. 只输入：`分析这个样本`  
5. 等到 CONVERGED / 给出分析结论 / STOP。此后不得再自动 `GET_DECOMPILE`。  
6. 记录：`case_id`、`task_id`、`authoritative_revision_id`、镜像 digest、模型路由是否用户配置模型。

### 9.3 Resume 正例清单（人读 + 自动抽官方 GET markdown）

从 `GET /api/v1/reports/{revision_id}` 的 markdown 检查 **分析结论**（附录可忽略）：

必须（镜像内可恢复，缺一则 G5 失败）：

- [ ] 编码/配置：算法或公式、明文或明确已试解码；若明文在镜像里被 WinHTTP/CreateProcess 引用则必须有 Join 叙述（URL 或命令来自该解码），不得只写 `UNKNOWN(consumer)` 还宣称成功  
- [ ] 进程：CreateProcess 调用 + 说得通的 flags 或诚实拒绝 raw 立即数；命令有来源  
- [ ] 线程：有 CreateThread 则必须有 start_routine VA 或已试反编译/模拟的 UNKNOWN  
- [ ] PPID：有 UpdateProcThreadAttribute 则必须有枚举/名称链或「已核对无 Process32 链」；不得把单独进程名写成伪装成功  
- [ ] 网络：WinHTTP 序列或解码 URL 作为配置；必须写清 **不是活 C2**  
- [ ] 适用目录其他类：HOW 或「已核对未发现」  
- [ ] 主文像分析员文章，不是十问列表  
- [ ] 无 `FUN_1400` 倾倒  
- [ ] 聊天引用同一 revision_id  
- [ ] 至少一条真实 `EMULATION_OBSERVED` 或规范化 UNSUPPORTED（XOR 或入口窗口）；不得只有 DEFERRED_TO_WORKER  
- [ ] Outcome 不是用「已出报告」伪装 COMPLETE；槽未齐则 PARTIAL

禁止：

- [ ] `CREATE_SUSPENDED` 来自错误位运算  
- [ ] `0x000f4240` 当作 creation_flags 成功 HOW  
- [ ] 服务器当时存活、本次父进程 PID、宿主已执行  

对照评测基准报告时只问：这些**能力类型**有没有。不要复制其 C2 列表进产品。若产品 Join 出的 URL 与样例不同，以**本样本 Evidence** 为准。

### 9.4 无基准 PE（如用户再交的 DLL）

- [ ] 不得出现 Resume 样例里的特定 IOC（人工报告中的具体 URL/任务名）  
- [ ] 未命中类目只有已核对句  
- [ ] 命中类目有 HOW 或已试方法  
- [ ] 人读：没有编造的横向移动/C2 任务

### 9.5 良性 PE（可用 `benign_pe32_ret` 或 notepad 类，用户授权的良性文件）

- [ ] 零「已确认恶意/APT/活 C2」  
- [ ] 不得因导入 CreateProcess 写已创建恶意子进程  

### 9.6 T6 差分

对照旧官方稿 `f117af1c` / `7969ba96`（`.scratch/resume-0d8d73a4-official.md` 若仍在）：

必须出现至少一项**新事实**：Join 边、合法 flags、start_routine 体、真实 emu 行。  
字数变长、Verified 计数、动作次数 **单独不算** 过。

### 9.7 G5 记录（写入 `.scratch/first-usable-g5-evidence.md`）

输入哈希、`docker images` digest、Prompt 版本、模型名（用户配置）、第一句用户原话、task/revision id、官方 GET 全文路径、emu ToolRun id、未完成槽列表。

### 9.8 G5 完成清单

- [ ] 新建会话 + 一句话分析  
- [ ] Resume 第 9.3 节全过  
- [ ] 第二样本保真过（若用户提供；否则 BLOCKED 并写明缺样本，**不得**用合成 DLL 冒充 Resume 深度）  
- [ ] 良性零误报  
- [ ] T6 有实质 HOW 增量  
- [ ] `first_usable_g5_passed=true`  
- [ ] 此时才允许钩子停止催更

合成 DLL / `print1` 只能当反幻觉，不能当 G5 Resume 正例。

---

## 10. 状态文件格式

路径：`.scratch/first-usable-status.json`

```json
{
  "plan": "docs/first-usable-static-analysis-plan-20260916.md",
  "current_gate": "G0",
  "first_usable_g5_passed": false,
  "gates": {
    "G0": { "status": "pending", "pytest": "", "notes": "" },
    "G1": { "status": "pending", "pytest": "", "notes": "" },
    "G2": { "status": "pending", "pytest": "", "notes": "" },
    "G3": { "status": "pending", "pytest": "", "notes": "" },
    "G4": { "status": "pending", "pytest": "", "notes": "" },
    "G5": { "status": "pending", "task_id": "", "revision_id": "", "notes": "" }
  }
}
```

每闸结束后把 `pytest` 字段写成实际命令和 passed 数量。禁止把 failed 写成 passed。

---

## 11. 卡住时怎么做（禁止发明新架构）

1. 先读本节对应「当前代码根因表」。  
2. 参考 `kunglao-agent` **仅当**同一缺口（skip、占位、消费者）已有实现可移植；禁止移植成第二套 Case/报告库。  
3. 参考 Lite/Complete 的 T4 与 emu Compose，禁止参考其 C10 完成定义。  
4. 仍卡住：在 `.scratch/first-usable-status.json` 的 notes 写 BLOCKED 原因，保持 `first_usable_g5_passed=false`，不要改完成定义来「过关」。

---

## 12. 授权口令

用户必须说类似：

`按 docs/first-usable-static-analysis-plan-20260916.md 开工`

然后从 G0 开始。未说这句话：只许改文档/测试设计讨论，不许改 `src/`、钩子、compose、状态里的 passed 标记。

写本文本身不等于开工。
