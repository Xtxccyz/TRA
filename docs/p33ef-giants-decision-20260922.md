# P3.3e / P3.3f 决策记录：两个巨方法（round 103，实测；**经对抗式复核后重写**）

> 设计记录把两个巨方法排在最后，并写明「只有到那时才值得决定是整体搬迁还是先切内部接缝」。本文件给出决定，
> **并在一次对抗式复核之后整篇重写**：初稿有几处数字与判断是错的，重写版逐条标注了「初稿错在哪、如何实测改正」。
>
> 复核者的三条指控**我独立复现后确认成立**（数字、测试引用、层判定），一条**不成立**（工具文件不存在——
> 实测 `.scratch/p32-measure-cluster.py` 存在且正在使用）。复核者对**中心论点**的反驳同样成立，见第 1.3 节。
>
> 可复现（**精确命令**，初稿写的调用方式有误）：
> ```powershell
> py .scratch/p33e-decision.py      # 规模、helper 使用者数、内部结构、层证据（REV 在脚本内固定为 32a7921）
> py .scratch/p33e-arithmetic.py    # 搬迁总账的逐项加总（本文件第 1.1 节就是它的输出）
> py .scratch/p32-measure-cluster.py <member> --from <rev>   # 单个成员的宿主/自由名测量
> ```

## 0. 结论（先说结果，理由在后面）

**P3.3e `_derive_investigation_observations`（2,795 行）与 P3.3f `_run_investigation_loop`（3,523 行）都无法在
当前层次上搬迁。** 初稿判定 P3.3e「可以整体搬迁」，那是在**层判定用错标准**的情况下得出的：把
`simulation_adapters` 当成「接口」放行。按方案 §3.2 的**原则性判据**（`investigation/` 只能导入
static/emulation/tools 的**接口**，未列出的边默认禁止）重判，它是**实现模块**（第 2.3 节）。因此：

**P3.3 剩下的全部工作，卡点都是「层」，不是切片。** 关键路径从此变成**层的搬迁**：把几个纯策略名/模块移到
`investigation/` 允许导入的位置，一次能解开多个子切片（第 3 节给出五条层工作及其分别解锁的东西）。

## 1. P3.3e：规模、可证明性、以及初稿错在哪

### 1.1 精确总账（`.scratch/p33e-arithmetic.py` 的原始输出）

| 组成部分 | 行数 |
|---|---|
| 巨方法本体 | **2,795** |
| 4 个簇内专有 helper（随迁）：`_follow_local_tail_jmp` 72、`_global_accesses_from_rows` 70、`_row_own_function_matches` 13、`_matching_simulation_results` 10 | **165** |
| 3 个模块级函数（随迁）：`_bind_recovered_xor_verification` 40、`_decode_output_buffer` 18、`plausible_traced_creation_flags` 16 | **74** |
| 1 个模块级常量（随迁）：`_DECODE_PRODUCER_KINDS`（service.py:886，字典字面量） | **7** |
| **整体搬迁总账** | **3,041** |

另需端口从 6 扩到 **12**（新增 6 个共享 helper，共 90 行**留在宿主**）。

**初稿的两处数字错误，均已实测改正**：
* 初稿写总账 **3,124** —— 它把「十个被调 helper 的 255 行」换成「四个专有 helper 的 165 行」却**没有重算总和**。
  复核者指出该矛盾后独立复measure，得出的 3,127 同样对不上：`2795 + 165 + 74 = 3,034`。真正的差额是
  **`_DECODE_PRODUCER_KINDS` 的 7 行**——它是**模块级常量**（不是类属性），而测量脚本的「接收者引用」扫描
  只找方法，**结构上看不见它**，所以两版都漏了。加上它才是 **3,041**，与本文件表格逐项对齐。
* 初稿把 `_DECODE_PRODUCER_KINDS` 写成「很可能是类常量」——实测在 `service.py:886` 定义、在 6051 行（巨方法内）
  使用，是**模块级常量**。

### 1.2 测试引用：初稿的「只有它用」是**生产侧**的事实，不是**搬迁成本**的事实

| 成员/函数 | 生产侧其他使用者 | 测试引用次数 | 测试如何用它 |
|---|---|---|---|
| `_follow_local_tail_jmp` / `_global_accesses_from_rows` / `_row_own_function_matches` / `_decode_output_buffer` / `_bind_recovered_xor_verification` | 无 | **0** | — |
| `_matching_simulation_results` | 无 | **5** | `AnalysisService._matching_simulation_results(rows, {...})`（按类调用 → 它是 `staticmethod`） |
| `plausible_traced_creation_flags` | 无 | **6** | `from threat_report_agent.service import plausible_traced_creation_flags`（模块级函数） |
| `_overlay_pe_parser_thread_start`（进端口、留宿主） | 另有 `_record_ghidra_evidence` | 2 | `AnalysisService._overlay_pe_parser_thread_start(...)`（`staticmethod`） |

**这些测试引用为什么不构成阻塞**（初稿完全没写，复核者也因此读成「搬走就断测试」）——两条既有机制即可覆盖，
且都已有测试钉住：
1. **被搬的方法在 service.py 留下单行委托**，且**保留原装饰器**（`p33-extract.py` 有 `ORIGINAL_DECORATORS` 检查）。
   因此 `AnalysisService._matching_simulation_results(...)` 这类**按类调用**继续成立——委托仍是 `staticmethod`。
2. **被搬的模块级函数会被 service.py 反向导入**（P3.3b 的 `frontier_status_is_open` / `deferred_keeps_planner_open`
   就是这么做的），因此 `from threat_report_agent.service import plausible_traced_creation_flags` 继续成立；
   `tests/test_investigation_coordinator_contract.py` 还专门断言**两个命名空间里是同一个对象**。
   把测试**迁到新家**是 P4 的收尾（§7.1 第 5 步），不是本步的前置条件。

**但初稿的表述方式确实错了**，现已固定为纪律：**「随迁」清单必须同时给生产使用者数与测试引用数**，
并说明它们靠哪条机制继续成立。

### 1.3 中心论点被复核者驳倒的部分：**「可证明」是「在重写之外可证明」**

初稿写「整体搬迁可被逐字节证明，切分没有等价性证明，所以整体更优」。复核者指出这是**不成立的**，
我复现确认：三件套**恰好把这次搬迁真正改变的东西归一化掉了**。

| 工具 | 实际能证明 | **不能**证明 |
|---|---|---|
| `p33-verify.py` | 逐语句 `ast.unparse` 后（去接收者前缀、去首个接收者实参）相同 | 归一化删掉的正是「换家」这一步：**端口成员接错、兄弟调用接到错的接收者、方法被误留在端口内，都会照样打印 IDENTICAL**；且它不比对签名、不检查方法是否被删/重复、不检查「搬走的成员是否还有外部调用者」 |
| `p33c-textdiff.py` | 字符串常量**值**逐字符 + 函数体代码行（模接收者改名与类缩进） | 只比对**模块级函数**，且初稿时**写死读 `HEAD`**（现已支持 `--from`） |
| `p33-arity.py` | 名字调用若目标函数首参是 `host` 却漏传 → 报错 | 宿主侧成员是否存在、属性调用的元数、任何运行期行为 |

**因此正确的说法不是「整体可证明」，而是**：
* 整体搬迁的风险是「**解析（resolution）未被证明**」——即搬过去的字节一致，但接线可能错；
* 切分的风险是「**行为等价未被证明**」——拆出来的等价性只能靠测试主张。
两者都不可证明，但**可核查的手段数量不同**：解析风险可以用**四类**手段核查（委托 pin、元数检查、
宿主引用 pin、以及**新增的引用检查**：搬走的成员在 service.py 里除委托外不得再有调用者），
而行为等价只能靠测试。**结论仍是整体搬迁**，但理由从「可证明 vs 不可证明」修正为
「**可核查手段更多**」，并且必须把「引用检查」补进搬迁前门禁（见 1.4）。

**同时记录一条对整体搬迁有利、初稿漏写的事实**：`_derive_investigation_observations` **只有一个调用者**
（`execute`，service.py:9748），所以「整体 vs 切分」不影响调用图——这使整体搬迁不会同时改变多个调用路径。

### 1.4 三件套之外，搬迁前必须补的门禁

1. **引用检查（新增，必须）**：对每个将被搬走的成员，统计 `service.py` 里除「自身的委托」之外的调用者——
   必须为 0，否则说明还有调用方没被考虑。这条补的正是 1.3 表里 `p33-verify.py` 的盲区。
2. 元数检查（已有 `p33-arity.py`）+ 契约测试的 arity pin（P3.3d 加入）。
3. 宿主引用 pin（`host_refs == port`，P3.3g/P3.3c 已有）。
4. **全量失败节点集合**比对。基线 6 个节点**具名**如下（初稿只写「6 个节点」，不可执行）：
   `tests/test_analysis_api.py::test_end_to_end_static_analysis_and_report_revisions`、
   `tests/test_deep_static_recovery.py::test_seed_clustering_opens_unique_os_thread_from_recovered_start`、
   `tests/test_t3_callback_fixture.py::` 的四个（`test_t3_protocol_answers_callback_global_and_keeps_missing_consumer`、
   `test_t3_one_start_discovers_global_relation_for_behavior_explanation`、
   `test_t3_service_does_not_replay_no_gain_when_unrelated_evidence_arrives`、
   `test_t3_service_one_start_enqueues_multiple_distinct_actions`）。
5. **回滚计划**（初稿缺失）：搬迁前记录 `service.py` 与 `coordinator.py` 的 sha256；失败时用
   `git show <pre-move-commit>:<path>` **复制式**恢复并校验哈希（禁止 `git checkout --`），
   文件级范围仅这两个 + 契约测试。

### 1.5 那么 P3.3e **为什么仍然不能搬**：`simulation_adapters` 不是接口

巨方法需要 `simulation_adapters` 的 7 个名字（`default_simulation_runner`、
`evidence_nature_for_simulation_status`、`may_execute_in_process`、`qiling_unavailable_observation`、
`request_for_granted_window`、`simulation_policy_from_settings`、`worker_defers_simulation`）。实测：

* 该模块里有 `SimulationCapability`、`detect_simulation_capabilities`、`speakeasy_capability_matrix`、
  `SimulationRequest`、`SimulationExecutionPolicy`、`default_simulation_runner` 等——**适配器与能力探测的实现**；
* 7 个名字里**没有一个定义在 `emulation/`**，只有 `evidence_nature_for_simulation_status` 在
  `ports.py`/`projection_protocols.py` 里出现过 1 次（且不是接口定义）。

方案 §3.2（第 122/132 行）只允许 `investigation/` 导入 **static/emulation/tools 的接口**，未列出的边默认禁止。
**一个装满适配器实现的 root 模块不是接口**，所以这条边与 P3.3d 被否掉的 `methodology` **同族**：
**P3.3e 判为受阻**，解除路径见第 3 节第 2 条。

> 初稿在这里用了「2 层先例 + 接口性质」的双重理由放行。复核者指出「2 层先例」这个阈值**在方案里不存在**，
> 是为了放行而事后设定的；我复现后同意，**改用方案自己写明的判据（是不是接口）**，并把该判据同样施加于
> `methodology`（结论不变：两者都不是接口，都禁止）。

## 2. P3.3f `_run_investigation_loop`（3,523 行）

### 2.1 实测事实

* 它需要 `task/analysis_task_orchestration.py` 的 `LOOP_PATH_PERSIST_READY`(198)、`LOOP_PATH_PERSIST_BOUNDARY`(199)、
  `LOOP_PATH_BUDGET_DEFER`(200)、`next_investigation_loop_path`(204)、`resolve_persist_how_skip`(93)；
  这些名字**都定义在 task 层内**（不是从 investigation 再导出），而该模块第 25 行
  `from threat_report_agent.investigation import ActionSpec, ActionType, recovery_actions_for_gap`
  ——`investigation -> task` 会成环。
* 端口面：**34 个**直接共享 helper（另有 5 个类常量）。把它们逐个加进端口等于把宿主重新变成一堵墙。
* 13 个模块级函数/常量要随迁，其中大者 `coalesce_investigation_seed_clusters`(138)、`_seed_context_rows`(105)；
  **且被测试直接导入**（如 `tests/test_investigation_service.py` 导入 `admit_investigation_seed_clusters`、
  `coalesce_investigation_seed_clusters`、`investigation_seed_step_budget`）——按 1.2 节的两条机制，它们**仍可导入**，
  真正要改的是**测试从新家导入**（P4 收尾）。

### 2.2 修正：**不是「受阻于设计」，而是「需要先做一个层步骤」**

初稿写「P3.3f 判为受阻」，同时在 §2.2 第 1 条给出了解除办法——**自相矛盾**：把已经写明的下一步说成阻塞。
准确表述：**P3.3f 目前不可直接搬迁，因为它依赖一个尚未执行的层步骤**，而那一步是可做的（第 3 节第 1 条）。

真正的环只有一处：`task/analysis_task_orchestration.py` 里的 `runtime._run_investigation_loop` 重新进入
（该文件 356/368/394/400/413/441 行）。把 5 个**纯策略名**下移即可消除它。

**复核者补出的、初稿漏写的成本**：`tests/test_analysis_task_orchestration.py:402` 用
`inspect.getsource(AnalysisService._run_investigation_loop)` 做断言——搬迁后它读的是单行委托，
属于 P3.7 的测试面改造项，必须具名记录（与 P3.3b 迁移 `test_investigation_service.py` 的那条同形）。

## 3. 关键路径：**层工作**（按依赖顺序；每条都解锁不止一个子切片）

| 序 | 层工作 | 解锁 | 实测依据 |
|---|---|---|---|
| 1 | ~~把**循环路径策略** `LOOP_PATH_*` / `next_investigation_loop_path` / `resolve_persist_how_skip` 从 `task/analysis_task_orchestration.py` 下移到 `investigation/`（或 contracts），task 侧改为导入~~ **已完成**：落到 `investigation/loop_path.py`（16 个模块级名字 / 167 行，task 侧 re-export） | ~~**P3.3f**（消除环）与 **P3.3c(2)** 的 `action_is_model_or_human`~~ 环已消除；P3.3c(2) 仍受第 4 条阻塞 | 名字定义位置实测（第 2.1 节）；方案第 133 行本就允许 `task/ -> investigation`。完成记录见 `docs/p33-layer1-loop-path-module-design-20260922.md` |
| 2 | 把 7 个模拟策略名从 `simulation_adapters` 暴露成**允许的 emulation 接口**（或把纯策略函数下移） | ~~**P3.3e**~~ **部分完成**：**策略那一半已解锁**（5 个纯策略名 + 实测闭包共 12 个名字下移到 `emulation/policy.py`），**但 P3.3e 仍未解锁**——见下方修正 | 第 1.5 节的判定；实测见 `docs/p33-layer2-emulation-policy-design-20260922.md` |
| 3 | 把 `_address_lookup_keys` / `build_unique_execution_threads` 从 `report/reporting.py` 下移到 `facts/` 或 `static/` | **P3.3b(2)**（97 行） | P3.3b 的实测 |
| 4 | ~~让 **model port** 暴露 `DynamicPlanAction`（`ports.py` 目前没有；它只 `ModelPlanningPort` 等 Protocol）~~ **已完成**：类本体（107 行）先移入纯契约层 `contracts.py`，再由 `ports.py` 与 `model/model_gateway.py` 各自 re-export 同一对象 | **P3.3c(2)** 的 3 个成员（71 行）——两个阻塞（本条与第 1 条）均已消除 | P3.3c 的实测；路线与实测见 `docs/p33-layer4-model-action-contract-design-20260922.md`，新边 `model -> contracts` 的登记见 `docs/plan-conflict-resolutions-20260922.md` 决策 (d) |
| 5 | 把 `methodology` 提升为**被多层共享的纯模块**（它只 import 标准库与 yaml）或下移其 `FactLibrary` 构造 | **P3.3d(2)** 的 `_run_methodology_action`（271 行） | P3.3d 的实测 |

这五条都属于 P1.2（端口与适配器）那条线的工作，各自应是一个独立步骤（自己白名单、自己验证）。
**第 1 条、第 4 条已全部完成，第 2 条的「策略那一半」已完成**（第 1 条：`investigation/loop_path.py`，消除
`investigation -> task` 的环；第 4 条：`DynamicPlanAction` 落入 `contracts.py` 并由 model port 暴露；第 2 条：
5 个纯策略名与其 12 个名字的实测闭包下移到 `emulation/policy.py`）。

### 第 2 条的实测修正：**P3.3e 仍然不能搬，但卡点从「7 个名字」缩小到「运行模拟这件事」**

逐名展开闭包后（`.scratch/layer2-closure.py`）：7 个名字里 **5 个完全不触及实现**，另 2 个触及——
`default_simulation_runner`（闭包含 isolated runner + qiling adapter + builtin adapter 表）与
`qiling_unavailable_observation`（qiling adapter）。因此「把 7 个都当接口放行」会是一层转发、实现边依然存在
（正是删除测试要拒绝的形状）；于是只下移纯的那 5 个。**下移后巨方法的实现依赖只剩两处，且都是"执行"**：
`default_simulation_runner(policy, …)`（`service.py:6725`，紧接着 `runner.run(...)` 在进程内跑模拟）与
`qiling_unavailable_observation(policy)`（`:6769`）。所以 P3.3e 的下一个前置不是继续搬策略，而是**给已声明的
`ports.EmulationPort` 一个生产者**并把这两处执行走它——这与方案 §3.3「emulation 暴露结构化请求与 simulation
result」一致。两个评审轴独立复算后给出同一结论。

**当前可执行的下一个结构步骤是「runner / simulation-result 端口」**，它同时服务 P3.3e 与 §3.3 的接口要求；
之后再做 P3.3c(2) 式的常规切片。
之后应做**第 2 条**（把 7 个模拟策略名暴露成允许的 emulation 接口），因为它是唯一解开 P3.3e
（2,795 行的 `_derive_investigation_observations`）的前提——那是本阶段剩余价值最大的一步。第 3 条与第 5 条
分别解开 P3.3b(2)（97 行）与 P3.3d(2)（271 行），实测依据均在表中。

## 4. 本步明确不做

- 不搬任何巨方法（两者都缺各自需要的层前提）；
- 不为「看起来有进展」而切 `_derive_investigation_observations` 的内部接缝（16 个内层闭包捕获局部变量，
  且没有等价性证明）；
- 不把 34 个共享 helper 加进端口来绕过层问题；
- 不改 `service.py` 的旧 `dataflow` 导入（`legacy_path_imports` 是 P4.1 的白名单；新模块写 `facts.dataflow`）。

## 5. 本文件自身的修正清单（供复核者核对）

| 初稿 | 实测改正 |
|---|---|
| 总账 3,124 | **3,041**（逐项：2795 + 165 + 74 + 7），并给出计算脚本 |
| 漏 `_DECODE_PRODUCER_KINDS` | 补为**模块级常量** 7 行、service.py:886；说明测量脚本为何看不见它 |
| 「随迁无成本」的暗示 | 补**测试引用次数表**与两条「为什么测试不会断」的机制 |
| 「整体搬迁可被逐字节证明」 | 改为「在**重写之外**可证明」，并列出三件套各自的盲区 + 新增引用检查 |
| 「P3.3f 受阻」 | 改为「**需要一个尚未执行的层步骤**」，并补 getsource 测试项与真实环的位置 |
| `simulation_adapters` 放行 | 按方案**接口判据**重判为**禁止** → P3.3e 受阻 |
| 未具名基线失败 | 6 个节点**逐个具名** |
| 无回滚计划 | 补复制式回滚（`git show <commit>:<path>` + 哈希校验） |
| 未写调用者数量 | 补「巨方法只有一个调用者：service.py:9748」 |

**复核者的一条指控不成立**：初稿引用的 `.scratch/p32-measure-cluster.py` **确实存在**（9130 字节，
本轮多次运行），复核者称「`p32-measure-cluster.py` 不存在」与其自己的工具目录状态不符；
不过初稿给的复现命令**确实不够精确**（未说明 `p33e-decision.py` 内部固定 REV），已在文件头改正。
