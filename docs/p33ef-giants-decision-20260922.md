# P3.3e / P3.3f 决策记录：两个巨方法（round 103，实测）

> 设计记录 `docs/p33-investigation-coordinator-design-20260922.md` 把两个巨方法排在最后，并写明「只有到那时才值得
> 决定是整体搬迁还是先切内部接缝」。**现在就是那个时候**，本文件用实测把两个巨方法分别判定到「可搬」与「受阻」。
>
> 可复现：`py .scratch/p32-measure-cluster.py <member> --from 32a7921`；
> 规模与结构：`py .scratch/p33e-decision.py`。

## 1. P3.3e `_derive_investigation_observations`（2,795 行）：**可以整体搬迁，且整体搬迁才是可证明的做法**

### 1.1 规模实测（整体搬迁的总账）

| 项 | 值 |
|---|---|
| 巨方法本体 | **2,795 行** |
| 它直接调用的 4 个**簇内专有** helper（可随迁） | `_follow_local_tail_jmp` 72、`_global_accesses_from_rows` 70、`_row_own_function_matches` 13、`_matching_simulation_results` 10 = **165 行** |
| 它直接调用的 6 个**共享** helper（必须留宿主 → 端口成员） | `_function_entry_integers` 5 个使用者、`_locator_key` 5、`_emulation_entry_key` 3、`_overlay_pe_parser_thread_start` 2、`_pe_entry_integers` 2、`_investigation_value_text` 2 |
| 3 个**模块级函数**（生产侧仅它使用 → 随迁） | `_decode_output_buffer` 18、`_bind_recovered_xor_verification` 40、`plausible_traced_creation_flags` 16 = **74 行** |
| **整体搬迁总规模** | **3,124 行** |

**测试面的引用（实测，且它改变了随迁的成本）**：`_follow_local_tail_jmp`、`_global_accesses_from_rows`、
`_row_own_function_matches`、`_decode_output_buffer`、`_bind_recovered_xor_verification` 在测试里 **0 次引用**；
但 **`_matching_simulation_results` 被测试引用 5 次**、**`plausible_traced_creation_flags` 被引用 6 次**。
「生产侧只有它使用」**不等于**「随迁无成本」：这两个必须按 §7.1 第 5 步**逐个迁移测试调用方**，
或者在旧位置留一层可导入的转发（而转发会与新家形成第二份访问路径，属于 P4 的 shim 话题）。
这一点是本文件初稿的**不准确之处**，已按实测改正——凡「随迁」清单都必须同时给**生产使用者数**与**测试引用数**。

另需：端口从 6 扩到 **12**（+6 个共享 helper）；`_DECODE_PRODUCER_KINDS` 待测归属（很可能是类常量 → 第 13 个成员）。

### 1.2 两个导入层问题，各自有实测判定

1. **`threat_report_agent.dataflow` 是旧 shim 路径**。它在 `docs/import-policy.json` 的 `legacy_path_imports`
   里有案（唯一一条，属 P4.1 待迁清单）。新模块**必须**写 `facts.dataflow`（canonical 路径，§3.2 允许
   `facts/`），service.py 的旧写法留给 P4.1 统一处理。这一条不是阻塞，只是不能照抄。
2. **`simulation_adapters` 是被两层导入的 root 模块**（`(root)` 与 `tools`）。用与
   `methodology` 相同的判据（P3.3d 的记录）：`methodology` 只有 1 层、故判为未列边；`simulation_adapters` 有 **2 层**
   先例，且它承载的正是模拟执行/策略接口，落在 §3.2 允许 `investigation/` 导入的
   「static/emulation/tools 的**接口**」范围内。**判定：允许**，理由是实测先例 + 接口性质，两者都写在记录里。

### 1.3 决定：**整体搬迁**，而不是先切内部接缝

实测它的内部结构：**34 个顶层语句、16 个嵌套函数、77 个循环、220 个 if、9 个 try**。也就是说它并非「没有接缝」，
但那些接缝是**捕获局部变量的内层闭包**（`selectors`、`symbols_match`、`add`、`collect_caller_edges` …），
把闭包提升为方法**必然改写数据流**。

关键判据是**可证明性**，不是规模：

* **整体搬迁可以被逐字节级别地证明**：`p33-verify.py`（AST 身份）+ `p33c-textdiff.py`（字符串值逐字符 + 函数体代码行）
  + `p33-arity.py`（调用元数）三件套对「整函数搬家」是完全适用的，和前面每一个切片同一标准。
* **内部切分没有等价性证明**：把 2,795 行拆成接缝，行为等价只能靠测试覆盖来主张；而这个项目已知的基线里就有
  6 个失败节点、且行为探针只覆盖 8 项。**用一个没有证明的操作去换一个规模更小的操作，是负交换。**

因此：**P3.3e 走整体搬迁**，风险是**单次检查点的失败面**（3,124 行）而不是不可验证；缓解手段是
(a) 搬迁后**先**跑三件套再跑任何测试，(b) 全量失败**节点集合**比对（不是计数），(c) 部署门照旧，
(d) `_matching_simulation_results` 与 `plausible_traced_creation_flags` 的**测试调用方**必须同一步迁移
（这是实测出来的额外交付项，不是可选项）。

### 1.4 三件套**证明不了**什么（写给下一位执行者）

它们证明的是「搬过去的字节与结构与原来一致」。它们**不**证明：
* 新端口成员在宿主侧的行为与原来相同（端口只是把调用改道，若宿主方法被同时改动，三件套看不见）；
* 被搬迁的 helper 之间**接线正确**——尤其当一个 helper 变成端口调用、另一个随迁时的组合；
* 任何**运行期**性质（顺序、事务、审计链封口），这些只有 focused 套件与行为探针覆盖。

因此 1.3 节里 (b)(c) 两步不是形式：**搬迁本身可证明，搬迁的接线不可证明**，两者必须分开报告。

## 2. P3.3f `_run_investigation_loop`（3,523 行）：**受阻于环，且规模远大于 P3.3e**

### 2.1 实测：三个独立阻塞

1. **环**。它需要 `threat_report_agent.task.analysis_task_orchestration` 的
   `LOOP_PATH_BUDGET_DEFER` / `LOOP_PATH_PERSIST_BOUNDARY` / `LOOP_PATH_PERSIST_READY` /
   `next_investigation_loop_path` / `resolve_persist_how_skip`，而该模块**自己 import investigation**
   （`from threat_report_agent.investigation import ActionSpec, ActionType, recovery_actions_for_gap`）。
   `investigation -> task` 会**成环**——端口化解决不了它，因为环的另一端就是调用方本身。
   这与 P3.3c(2) 里 `action_is_model_or_human` 的阻塞**同一形状**，但规模大得多。

   **实测这些名字的定义位置**（防止「也许它们只是从别处再导出」这种可能）：
   `resolve_persist_how_skip` 定义在 `task/analysis_task_orchestration.py:93`，
   `LOOP_PATH_PERSIST_READY`/`LOOP_PATH_PERSIST_BOUNDARY`/`LOOP_PATH_BUDGET_DEFER` 在该文件 198–200 行，
   `next_investigation_loop_path` 在 204 行——**都定义在 task 层内**，不是从 investigation 再导出的。
   因此环是真实的：循环路径决策被放在了调用方那一层。
2. **端口面 34 个**直接共享 helper（另有 5 个类常量、4 个已在端口的成员）。把端口从 6 扩到 40 左右，
   等于把「宿主」重新变成一堵墙——这与 P3.3 的目的（把任务/调查路径从 `AnalysisService` 里分离出来）相悖。
   必须**先**把这些 helper 下沉到允许的层（它们是纯逻辑，多数只依赖 models/database），而不是逐个加进端口。
3. **13 个模块级函数/常量**要随迁，其中两个很大（`coalesce_investigation_seed_clusters` 138 行、
   `_seed_context_rows` 105 行），**而且它们被测试直接导入**
   （`tests/test_investigation_service.py` 导入 `admit_investigation_seed_clusters`、
   `coalesce_investigation_seed_clusters`、`investigation_seed_step_budget`、`frontier_status_is_open` 等）。
   这属于 §7.1 第 5 步「先改生产调用方，再逐个改测试调用方」的工作，**不是一次搬家能附带的**。

### 2.2 判定与解除路径（记录，不在本步动手）

**P3.3f 判为受阻**，受阻原因与 P3.3b(2)/P3.3c(2)/P3.3d(2) 同族但更深：**它需要先做「层」的工作，而不是端口的
工作**。可执行的解除顺序（每一步都是一个独立步骤，各自有白名单与验证）：

1. 把 `next_investigation_loop_path` / `resolve_persist_how_skip` / `LOOP_PATH_*` 这些**循环路径决策**从
   `task/analysis_task_orchestration.py` 下移到一个**允许被 investigation 导入**的层（它们本质是
   investigation 的循环策略常量与纯决策，放在 task/ 里才是反常的）——这同时会解掉
   `_action_is_model_or_human`（P3.3c(2)）的环。
2. 把 34 个 helper 里**纯逻辑的那批**下沉（例如 `_select_*_seed_rows` / `_is_*_seed_row` 系列只依赖 models），
   让端口不必膨胀到 40。
3. 最后才搬 `_run_investigation_loop`，并按 §7.1 第 5 步迁移那 13 个模块级函数的测试调用方。

## 3. 本步明确不做

- **不**整体搬 `_run_investigation_loop`（受阻，且端口会膨胀到约 40 个成员，与 P3.3 的目的相悖）；
- **不**为了「看起来有进展」而先去切 `_derive_investigation_observations` 的内部接缝（没有等价性证明）；
- **不**把 34 个共享 helper 逐个加进端口来绕过层问题；
- **不**在本步改动 `service.py` 的旧 `dataflow` 导入（那是 P4.1 的白名单）。

## 4. 对设计记录里「15 个未分配成员」的处置更新

设计第 2 节列的 660 行未分配残留，经本轮实测已经明确归属的有：
`_follow_local_tail_jmp`（72）与 `_overlay_pe_parser_thread_start`（40）是 P3.3e 的依赖（前者簇内专有、随迁；
后者共享、进端口）；`_investigation_value_text`（18）同时被 P3.3e 与 P3.3f 使用（共享 → 端口）；
`_persist_time_unique_thread_result`、`_load_investigation_execution_rows`、`_select_investigation_execution_rows`、
`_persist_ready_emulation_actions`、`_run_emulation_informed_investigation`、`_run_saturated_investigation` 等
出现在 P3.3f 的闭包里，属于**第 2.2 节第 2 步要下沉的那批**。剩余未认领的以
`_collect_model_action_results`（151）与 `_semantic_action_result`（103）为首，仍待 P3.3c(2)/P3.3f 的后续步骤定性。
