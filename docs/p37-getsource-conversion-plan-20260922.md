# P3.7 测试面改造：`getsource` 耦合的逐点转换方案（round 94 实测）

> 本文件由 round 94 的**实测**产出，不是设想。方案 §P3.7 的要求是：
> 「逐个把 `inspect.getsource(AnalysisService._...)` 改成输入/输出行为断言；把对 private method 的直接调用改成概念公开函数或 HTTP facade」，
> 成功标准是「生产代码和测试不再把 private method 当稳定 API；测试仍覆盖边界、错误和 ordering」，
> 失败处理是「**不能通过删除测试『解决』耦合；缺少行为面时先补 contract test**」。

## 1. 为什么现在给出「方案」而不是直接改完

实测（`.scratch/p37-getsource-audit.py`、`.scratch/p37-classify.py`）表明：**18 个 `getsource` 站点分布在 10 个测试文件**，
按断言性质分三类，而其中 6 个**负向**守卫（`X not in source`）与 3 个 ordering/其他守卫**目前没有现成的行为面**——
它们存在的理由恰恰是「当时没有可观测的行为出口」。

要把它们转成行为断言，需要**先建集成夹具**（例如：用会设置该 flag 的策略真正跑一遍 post-static emulation 路径，断言
flag 没有被关掉；或用 P1 的端口做一个记录型协作者来断言调用顺序）。

在一次结构步骤里仓促转换只有两种结局，**两种都违反红线**：

* 把精确断言改成只查标题（红线明文禁止）；或
* 删掉没有行为替代的守卫（红线明文禁止「删失败测试/削断言」）。

所以本轮交出的是一份**逐点方案**：每个站点都写清「需要什么夹具才能转换」，让后继者按点执行、每点独立验证。

## 2. 实测清单（18 站点 / 10 文件）

| 断言性质 | 站点数 | 含义 |
|---|---|---|
| PRESENCE（`X in source`） | 9 | 断言某调用/字段**存在** |
| NEGATIVE（`X not in source`） | 6 | 断言某危险写法**不存在**——**这类最需要先补行为面** |
| OTHER（`index(...) <`、切片等） | 3 | ordering / 结构性断言 |

逐站点清单（file:line → 目标成员 → 性质）由 `.scratch/p37-classify.py` 生成到 `.scratch/p37-sites.json`，要点：

| 文件 | 行 | 目标 | 性质 |
|---|---|---|---|
| `test_analysis_task_orchestration.py` | 402 | `_run_investigation_loop` | NEGATIVE |
| `test_controlled_emulation.py` | 1180 | `_run_post_static_emulation` | NEGATIVE |
| `test_controlled_emulation.py` | 1246 | `_run_analysis` | PRESENCE |
| `test_controlled_emulation.py` | 1247 | `workbench_submit_action` | PRESENCE |
| `test_controlled_emulation.py` | 1732 | `_run_post_static_emulation` | PRESENCE |
| `test_controlled_emulation.py` | 1922 | `StaticToolActivities._execute_controlled_emulator` | NEGATIVE |
| `test_function_similarity_cost.py` | 34 | `_record_function_similarity` | OTHER |
| `test_investigation_protocol.py` | 97 | `_persist_time_seed_result` | PRESENCE |
| `test_investigation_recovery_loop.py` | 271 | `_run_gap_driven_model_rounds` | NEGATIVE |
| `test_investigation_recovery_loop.py` | 274 | `_run_investigation_loop` | PRESENCE |
| `test_investigation_recovery_loop.py` | 278 | `_reverify_how_after_emulation` | OTHER |
| `test_investigation_service.py` | 2743 | `_run_investigation_loop` | PRESENCE |
| `test_investigation_service.py` | 2745 | `_build_investigation_frontier` | PRESENCE |
| `test_mechanism_chains.py` | 199 | `AnalysisService`（整类） | NEGATIVE |
| `test_pe_entry_function_budget.py` | 1734 | `_record_ghidra_evidence` | NEGATIVE |
| `test_pe_entry_function_budget.py` | 2040 | `_record_ghidra_evidence` | PRESENCE |
| `test_persist_how.py` | 45 | `_reverify_how_after_emulation` | PRESENCE |
| `test_speakeasy_reachability.py` | 37 | `_run_controlled_emulator` | OTHER |

## 3. 已记录的「耦合读数」必须**刻意**重录

`docs/structure-surface.json` 记录着 `test_getsource_count = {"reaching_a_private_member": 21, "total": 39}`。
**每转换一个站点，这个读数就会变化，结构 diff 门禁会因此失败**——这是设计如此，不是故障。
转换点的提交**必须**：先测量变化量、写明它下降的原因，再 `--record-surface` 重录；**不允许**为了让门禁变绿而跳过。

## 4. 建议的执行顺序（每点一步、独立验证）

1. **先易后难，先 PRESENCE 后 NEGATIVE**：PRESENCE 站点通常只差一个「调用产出什么」的断言；
2. **每个点先写行为断言、再删 `getsource`**（红线的顺序要求：先补 contract test，后改测试面）；
3. 对 6 个 NEGATIVE 站点，先建**一个**可复用的记录型夹具（例如 P1 端口上的 spy），再逐点替换——
   先建夹具而不是先删守卫，正是 P3.7 失败条款的字面意思；
4. 每点之后运行：`tests/test_service_facade_contract.py`（P3.1 契约，P3 每个子步都要跑）、该点所在文件、
   受影响文件的聚焦批次，然后**全量**比较失败**节点集合**；
5. 全部转换完成后：`test_getsource_count` 应降到 0，届时该表面不再需要，**按门禁的「拒录空表面」规则**
   处理（记录并说明，而不是让它空着）。

## 5. 与其他步骤的关系

* P3.1 的 facade 契约（`tests/test_service_facade_contract.py`）已经**禁止本契约测试自身**碰私有成员，是这一工作的样板；
* P3.2a 把 5 个纯限制投影函数搬进 `task/limitations.py` 时，**刻意保留了同名私有委托**，正是为了让 P3.7 与搬动解耦——
  两者互不阻塞；
* P3.3–P3.6 每次搬动都会让若干 `getsource` 目标**消失或改址**；因此本方案的第 2 节清单要在每个 P3 子步后**重新生成**
  （一条命令：`py .scratch/p37-classify.py`），而不是照抄本文件。

---

## 附录 A：计数对账（round 128 实测，`py .scratch/p37-recount.py`）

**两个数字测的不是同一件事，先把它们对齐再动手：**

| 指标 | 值 | 含义 |
|---|---|---|
| 本方案第 2 节的站点数 | **18** | round 94 实测的**私有可达**站点（`getsource(AnalysisService._…)` 这一类） |
| P1.4 表面 `test_getsource_count.total` | **39** | 测试里**全部** `inspect.getsource(...)` **调用**（AST 计数，15 个文件） |
| 本次实测的私有可达站点 | **17** | 与方案的 18 相差 1 —— round 94 之后有一个站点已转换/改形 |
| P1.4 表面 `reaching_a_private_member` | **17** | 与本次实测的 17 一致 |

**结论**：方案第 2 节的逐点表对**私有可达**子集仍然有效，但它的 18 已过时（今天 17）；而表面记的 39 是**全部**调用，
其中 22 个的目标是公开/非 service 符号（`analyst_report.render_official_markdown`、`PersistHow.*`、
`simulation_adapters._speakeasy_adapter`、`auth_module` 等）。**两条计数都不错，但它们不能互换使用**——
用 39 去核对方案的 18 会得出"方案漏了 21 个点"，用 18 去核对表面会得出"表面多算了 21 个"，两者都是错的。

**逐文件分布（全部 39 个调用）**：`test_controlled_emulation.py` 9、`test_pe_entry_function_budget.py` 6、
`test_investigation_recovery_loop.py` 4、`test_vb6_shim_evidence_reaches_the_body.py` 4、
`test_analysis_task_orchestration.py` 3、`test_investigation_service.py` 2、`test_persist_how.py` 2、
`test_static_wording_repair_on_publish_path.py` 2、其余 7 个文件各 1。

**对后续执行的约束**：P3.7 的转换按**私有可达子集（17）**逐点做；每转换一个站点，`test_getsource_count.total`
**必然下降**，因此每次都要**重录表面**并用"该站点已改为行为断言"作为依据（先例：P3.4-1 的
`threshold_comparisons` 重录带值断言）。**不得**为了把总数降到某个数字而删掉负向守卫——方案的失败处理写明：
不能通过删除测试"解决"耦合，缺少行为面时先补 contract test。
