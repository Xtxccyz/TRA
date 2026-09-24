# P3.6-2 设计：把 `workbench_capabilities` 移出 `service.py`（实测，20260924）

> **本步性质：只测量 + 只设计。** 本 agent 未修改任何 `src/` 或 `tests/` 文件，未提交、未推送、未 amend
> （本次唯一新增的受跟踪文件就是本文；其余新增都在 gitignored 的 `.scratch/`）。
> 测量基线：**HEAD = `a299869ca7e89b68a117f00b3e816c75973be5d9`**，且**测量开始时工作树是干净的**
> （`git status --short` 输出为空，与 `git rev-parse HEAD` 一致）。
>
> **并发写入警告（实测，写本文时已发生）**：另一个 agent 正在同一工作树上执行 P3.5-0/M-1，
> `git status --short` 在本文完成时是
> ` M src/threat_report_agent/contracts.py`（+321）、` M src/threat_report_agent/investigation/investigation.py`（−233）、
> ` M src/threat_report_agent/static/evidence_recovery.py`（−92）、` M src/threat_report_agent/workbench_query.py`（2 行），
> `git diff --stat` 合计 `4 files changed, 345 insertions(+), 303 deletions(-)`。**这 4 个文件不是本文改的。**
> 后果：本文里**所有 `service.py` 的行号仍然等同于 HEAD**（`service.py` 不在这次并发 diff 里，实测），
> 但 `investigation/investigation.py` 的行号**已经漂移**——`class ActionCatalog` 在 HEAD 上是 `:3598`，
> 在写本文时的工作树上是 **`:3446`**（M-1 正在把定义下沉到 `contracts.py`；`ActionCatalog` 本身尚未下沉）。
> **引用该文件的任何行号前，先重跑一次 `git grep -n "class ActionCatalog" -- src`。**

本文与 `docs/p36-workbench-query-design-20260922.md`（P3.6-1 的设计）是同一系列：那一篇决定了**只读切片**
哪些成员搬走；本文决定 `workbench_capabilities`（当时被明确留在原地的那一个）怎么搬。

**对任务前提的三处实测修正（先写在最前面，因为它们改变下一步该做什么）：**

| 任务前提 | 实测结果 |
|---|---|
| "P3.6-2 = 移动 `workbench_capabilities` + **两个已知债务**" | **只剩一个债务。** §5.4 dict-key 债务已在提交 `1bc2e80`（2026-09-24 09:25，HEAD 之前第 14 个提交）清偿，见 §4。 |
| "the plan 的 §5.4 dict-key debt" | **计划里没有这一节讲 dict key。** 计划 §5.4 是「能力复验矩阵」（`docs/code-structure-optimization-execution-plan-reviewed-20260922.md:600`），全文没有 `dict`/键集的字样（实测：该文件对 `dict|键|key` 的搜索只命中第 77、263 行，两处都与键集无关）。真正的出处是 **P3.6-1 设计文档的 §5 第 4 条**（`docs/p36-workbench-query-design-20260922.md:87-88`："一条直接比较 dict 键集的断言"）。 |
| "preceding slices pinned 10 host members; something required an 11th" | 实测不是 10→11。`WORKBENCH_QUERY_HOST_MEMBERS` 的设计值是 **12**（`p36-workbench-query-design:57-59`），首次实施时**判错两个类常量随迁**，第一个应用断了 **37 个测试**，于是 pin 变成 **11**；复查后按规则应为 **10**。偏差成员是 `_UNIQUE_THREAD_VIEW_KINDS`，见 §5。 |

> 同理，"the deployment gate is currently blocked by the same outage"也不准确：**Docker 引擎是活的**
> （`docker info --format '{{.ServerVersion}}'` → `29.7.2`，exit 0），是 **8 个容器全部没在跑**，见 §7.7。

---

## 0. 仪器（全部 read-only，脚本位于 gitignored 的 `.scratch/`）

| 脚本 | 作用 | 关键输出 |
|---|---|---|
| `.scratch/p36-2-measure.py` | AST 求 `workbench_capabilities` 的 def 跨度、`self.`/`cls.` 引用、传递闭包、写动词、模块级自由名 | §1、§3 |
| `.scratch/p36-2-calls.py` | 把闭包内**每一个** `Call` 表达式列出并按 write/read/pure 分类（不靠关键词筛） | §3 |
| `.scratch/p36-2-callsites.py` | 对 `src`、`tests`、`scripts`、`blind-tests`、`benchmarks` 做 AST 扫描，找 capability 成员的每一个外部引用及调用形状；并算 pin 候选的 `self.` 读者所属成员 | §2 |
| `.scratch/p36-2-hostpins.py` | **仓库内每一处 `*_HOST_MEMBERS` 元组的 AST 清单**（成员名逐个列出） | §5 |
| `.scratch/p36-2-payload-keys.py` | 运行期真正调用一次 `workbench_capabilities()`，打印顶层/嵌套键集与 `ActionCatalog` 大小 | §4 |
| `.scratch/p36-2-debts-measure.py`（既有） | 仓库级 host-pin 扫描（正则版） | §5 的"仪器缺陷" |
| `.scratch/p36-2-dump-record.py` / `p36-2-status-tail.py` / `p36-2-baseline.py` | 只读读取 `.scratch/structure-status.json`（`encoding='utf-8-sig'`） | §4、§5、§7 |
| `.scratch/compare-failure-nodes.py`（既有） | 按**节点集合**比较失败 | §7.5 |

**一个必须记录的仪器缺陷（实测）**：既有的 `.scratch/p36-2-debts-measure.py` 用正则
`([A-Z_]*HOST_MEMBERS)[^=]*?=\s*\(([^)]*)\)` 抓元组，因为 `[^)]*` 会在**元组内注释里的 `)`** 处截断，
它对 `coordinator.py` 报 **1** 个成员（真值 6）、对 `task_runner.py` 报 **6** 个（真值 9）。
本轮改用 AST（`p36-2-hostpins.py`），下表以 AST 为准。**任何 pin 成员数都不要引用那个正则的输出。**

---

## 1. `workbench_capabilities` 今天是什么

### 1.1 切片本体

`src/threat_report_agent/service.py:17264-17368`，**105 行**（`def` 行到最后一个 `}`，含注释；无装饰器）。
行数与 P3.6-1 设计记录的 `workbench_capabilities`(105) 完全一致（`docs/p36-workbench-query-design-20260922.md:23`）。

它是一个 `AnalysisService` 的**实例方法**，无参数，返回 `dict[str, object]`。

### 1.2 传递闭包：切片之外它还要读 3 个 `self.` 成员，共 195 行

`p36-2-measure.py` 对切片成员做 BFS（按 `self.`/`cls.` 属性名继续展开）：

| depth | 成员 | `file:line` | 行数 |
|---|---|---|---|
| 0 | `workbench_capabilities` | `service.py:17264-17368` | **105** |
| 1 | `_analysis_planner_payload` | `service.py:1025-1043` | 19 |
| 2 | `_model_status_payload` | `service.py:969-1023` | 55 |
| 3 | `_planner_user_action` | `service.py:952-967` | 16 |
| | **闭包合计** | | **195** |

### 1.3 闭包读到的 `self.` 名字 = **3 个**，这就是必须成为 host-pin 成员的集合

| 名字 | 种类 | 声明处 | 闭包内读者 | 切片外读者（证明不是死接口） |
|---|---|---|---|---|
| `THREAT_CONTEXT_PROTOCOL` | 类常量（`= "v3"`） | `service.py:556` | `workbench_capabilities`(17325) | `_context_payload_v3`(15806) |
| `THREAT_TOOL_CONTRACT_VERSION` | 类常量（`= "threat-tools-v4"`） | `service.py:557` | `workbench_capabilities`(17324) | `_context_payload_v3`(15805) |
| `_analysis_planner_payload` | 方法 | `service.py:1025` | `workbench_capabilities`(17364) | `_context_payload_v3`(15870)、`workbench_analysis_planner_model_view`(1046) |

**必须新增的 pin 成员 = 3。** `settings` 也是闭包读的（`_model_status_payload:997`、`workbench_capabilities:17296/17316/17319`），
但**它已经在 pin 里**（`workbench_query.py:104`）。所以 pin 从 **11 → 14**。

（实测口径：`p36-2-callsites.py` 报 `settings` 在 `service.py` 里共有 150 处 `self.settings` 读者，
其中切片内 2 处、切片外 30 个成员——所以它是"有外部读者"的 pin，不是为切片而加的。）

### 1.4 模块级自由名：闭包还要 3 个非 stdlib 名字，全部来自别的层

`p36-2-measure.py` §6（自由名解析到 `service.py` 的 import 处）：

| 自由名 | 使用处 | `service.py` 的 import | 目标层 |
|---|---|---|---|
| `ActionCatalog` | 17266 | `from threat_report_agent.investigation import (...)`（`service.py:118-119`） | `investigation`（实现模块 `investigation/investigation.py`，`class ActionCatalog` 在 HEAD 上 `:3598`；并发 M-1 已把它漂到 `:3446`，见文件头警告） |
| `simulation_policy_from_settings` | 17296 | `service.py:224` | `emulation.policy`（`emulation/policy.py:190`） |
| `Path` | 17340, 17347 | `pathlib`（stdlib） | stdlib |
| `AnalysisFailureRecord`, `ModelCall` | 971, 972, 1027, 1028 | `service.py` 的 `models` import 块 | `models` |

**闭包真正触达的其它模块 = `investigation`、`investigation.coordinator`、`emulation.policy`、`models`。**
其中 `investigation.coordinator` 的触达路径是 `_analysis_planner_payload → _model_status_payload →
_planner_user_action → _coordinator._planner_user_action`（`service.py:370` 的
`from threat_report_agent.investigation import coordinator as _coordinator`，调用在 `service.py:961`）。

**这条链决定了切片的边界**：只要 `_analysis_planner_payload` 留在宿主（作为 pin 成员），
`_model_status_payload` / `_planner_user_action` / `_coordinator` **都不需要进入新模块**。
反过来，如果把它当"顺手一起搬"的簇（195 行全搬），新模块就必须自己 import
`threat_report_agent.investigation.coordinator`——这正是 §8 要防的那类新边。**建议只搬 105 行。**

### 1.5 与 `workbench_query.py` 现状的接口

`src/threat_report_agent/workbench_query.py` 今天共 **1152 行**，其中：

* `WORKBENCH_QUERY_HOST_MEMBERS`（`workbench_query.py:93-105`）= **11** 个成员；
* `WorkbenchQueryReaderHost`（`workbench_query.py:108-125`）声明与 pin 完全相同的 11 个；
* 7 个已搬函数（`workbench_query.py:137, 534, 910, 974, 1034, 1082, 1106`）+ 2 个纯 helper；
* 模块 docstring 第 19-20 行**今天仍然写着**"not yet moved: `workbench_capabilities`"，
  第 89-92 行写着"`THREAT_CONTEXT_PROTOCOL`、`THREAT_TOOL_CONTRACT_VERSION` 和 `_analysis_planner_payload`
  只被 `workbench_capabilities`/`_context_payload_v3` 读……搬 `workbench_capabilities` 的那一步会把它们加进来"。
  **这两段 prose 是 P3.6-2 必须同步改掉的**（本 phase 已因 prose 与实测不符被 review 抓过多次）。

---

## 2. 每一个跨模块调用点

`p36-2-callsites.py` 扫了 **377 个 py 文件**（`src`、`tests`、`scripts`、`blind-tests`、`benchmarks`；
跳过 `blind-tests/comhost-20260826/_noop.py`：UTF-8 BOM + `U+FEFF` 非打印字符导致 `ast.parse` 失败）。
对 `workbench_capabilities` 的引用统计：

```
COUNTS: {'workbench_capabilities': {'ATTRIBUTE': 1, 'BARE': 0, 'GETATTR': 0, 'STRING': 0}}
```

### 2.1 生产调用点：**1 个**

| `file:line` | 形状 | 说明 |
|---|---|---|
| `src/threat_report_agent/main.py:789` | `_service(request).workbench_capabilities()` | 服务对象上的属性访问，位于路由函数 `create_app.workbench_capabilities` 内，路由 `@app.get("/api/v1/workbench/capabilities/static-actions")`（`main.py:786-787`），前面有 `require_permission(request, "task:read")`（`main.py:788`） |

### 2.2 测试调用点：**4 个，全部走 HTTP**（不是 `service.` 属性访问，所以上面的 ATTRIBUTE 计数看不到它们）

| `file:line` | 形状 |
|---|---|
| `tests/test_runtime_agentic_contracts.py:44` | `TestClient(create_app(test_settings)).get("/api/v1/workbench/capabilities/static-actions")`，函数 `test_workbench_capabilities_distinguish_model_tools_from_backend_actions`（`:42`），断言 15 行（`:45-62`） |
| `tests/test_workbench_api.py:28` | 同一个路由，包在端到端用例里（断言 `api_version == 1`、`"GET_XREFS_TO" in actions`） |
| `tests/test_workbench_security.py:7` | 同一个路由（安全/权限用例） |
| `tests/test_model_config_api.py:153` | 同一个路由 |

### 2.3 非 Python 调用点：**1 个**

| `file:line` | 形状 |
|---|---|
| `threat-dsh-workbench/packages/threat-api-client/src/index.ts:140` | `this.request('/api/v1/workbench/capabilities/static-actions')`，纯 HTTP，不 import Python |

文档里还记录了路由（`docs/backend-workbench-api.md:7`、`docs/migration-runbook.md:9`），不是调用点。
`.understand-anything/fingerprints.json:13183` 里也有这个名字，见 §5.4。

### 2.4 结论：**不需要 facade，需要 host**

* **没有任何调用方可以"改写到新模块"**：唯一的 Python 生产调用方是 HTTP 路由，它手里只有
  `AnalysisService`（`_service(request)` 是请求级依赖注入的结果，`main.py` 不持有 `workbench_query`）。
* 因此**必须保持"通过 service 对象工作"**：与 P3.6-1 完全同形——在 `service.py` 保留一个
  `def workbench_capabilities(self)` 委托到 `_workbench_query.workbench_capabilities(self)`。
* 支持这个判断的既有先例：`service.py:377` 的别名 import
  `from threat_report_agent import workbench_query as _workbench_query`，以及 7 个 `_workbench_query.*`
  委托（`service.py:1133, 1136, 17419, 17445, 17455, 18014, 18260`）。
* 要注意 `docs/p4-shim-migration-measurement-20260922.md:180` 已记录的坑：
  `git grep "threat_report_agent.workbench_query"` **会漏掉**这个别名 import。
* **`main.py` 不需要改**（P3.6 计划的"允许修改 `main.py`"在这一步用不上）。

---

## 3. 写侧风险清单

### 3.1 闭包里的写操作：**0**

`p36-2-calls.py` 不靠关键词筛，而是把闭包内**全部 47 个 `Call` 表达式**列出来逐个分类：

```
WRITE: 0 call(s)
READ: 11 call(s)          # dict.get / getattr / Path.is_dir
PURE/OTHER: 36 call(s)
TOTAL calls in the closure: 47
```

`p36-2-measure.py` §5 的写动词扫描（`session.add`/`add_all`/`flush`/`commit`/`delete`/`merge`/`refresh`/
`expire`/`execute`/`exec_driver_sql`/`begin`/`begin_nested`/`rollback`/`bulk_save_objects`，以及
`open`/`text`/`insert`/`update`/`delete` 裸名调用）**结果为 0**。

### 3.2 非写入但有外部副作用的调用：**2 类，都不是写**

| `file:line` | 调用 | 性质 |
|---|---|---|
| `service.py:17340`、`service.py:17347` | `Path(policy.qiling_rootfs).is_dir()` | 文件系统 **stat（读）**，无写。间接来源：`emulation/policy.py:213-215` 调 `resolve_qiling_rootfs()`，后者在 `emulation/policy.py:39,41` 也做 `is_dir()` |
| `service.py:17266` | `ActionCatalog.default()` | 构造行为目录（`investigation/investigation.py:3598` 起）。**实测无 I/O**：运行期调用返回 18 个动作名，见 §4.3 |

`simulation_policy_from_settings(self.settings)`（`service.py:17296`）实测是**纯函数**：只做
`getattr(settings, ...)` + `resolve_qiling_rootfs()`（`emulation/policy.py:190-220`），不读库、不写盘、不发网络。

**闭包内没有**：`session.*` 任何调用、`open()`、容器/socket 调用（`exec_run`/`create_container`/`sendall`
零出现）、`getattr(self, ...)` 字符串式私有读取。

### 3.3 这对 P3.6-2 的安全断言意味着什么

* `tests/test_workbench_query_contract.py:116-138` 的 `test_the_slice_is_read_only` **遍历模块里的每一个
  顶层函数**（`_module_functions()`，`:47-52`），`WRITES = ("add", "delete", "flush", "commit", "merge",
  "execute", "text")`（`:44`），接收者匹配 `session`/`host`/`*.database`（`:134-137`）。
  **一旦 `workbench_capabilities` 落进 `workbench_query.py`，它自动被这条断言覆盖**，不需要新增断言。
* 而且**不会误报**：§3.1 已实测闭包 0 次写、0 次 `execute`/`text`。
* **P3.6-2 因此可以、也必须把"只读"这条负向断言从 7 个函数扩到 8 个函数**，并把
  `MOVED_MEMBERS`（`tests/test_workbench_query_contract.py:34-42`）加上 `"workbench_capabilities"`——
  这是 P3.6-1 那条 `read-only AST 断言`的自然延伸，代价为零。
* **不能做的断言**：不能断言"该切片无副作用"。它确实会 `stat` 文件系统（§3.2），
  也会构造 `ActionCatalog`。断言必须精确到"不写 session / 不调 `execute`/`text`"。
* **已知逃逸口（P3.6-1 review 已记录，`:43`）**：接收者匹配只认 `session`/`host`/`*.database`，
  派生句柄（`handle = session.connection(); handle.add(...)`）仍可逃逸。P3.6-2 不新开这个口，
  但也**不要**声称它已关闭。

---

## 4. §5.4 dict-key 债务，实测

### 4.1 债务的原文与实际出处

* 计划 §5.4（`docs/code-structure-optimization-execution-plan-reviewed-20260922.md:600-610`）是
  **「能力复验矩阵」**，5 行表格，讲 report/chat/revision 同源、decode→WinHTTP join、emulation failure
  distinction、T3/T4/T7/T8、G5 3080 路径。**它与 dict key 无关**（对 `dict|键|key` 的全文搜索零命中）。
* 真正的出处是 P3.6-1 设计 §5 第 4 条（`docs/p36-workbench-query-design-20260922.md:87-88`）：
  > "**只读语义不变**：`workbench_domain_view` 的返回结构、`task_view` 的字段集合在移动前后逐字段相同
  > （用现有 API 测试 + **一条直接比较 dict 键集的断言**）。"
* 状态文档把它压成 "design's section 5.4"（`docs/structure-execution-status-20260922.md:133`）。

### 4.2 **实测：这个债务已经清偿了**（这是本文最重要的一条状态修正）

| 证据 | 实测 |
|---|---|
| 断言在树里 | `tests/test_investigation_service.py:1788-1792`：`missing = REQUIRED_VIEW_KEYS - set(view)` + 失败时打印缺失键集 |
| key 集本体 | `tests/test_investigation_service.py:1730-1744`，**13 个键**：`actions, artifacts, claims, hypotheses, mechanisms, relations, report, sample_timeline, schema_version, task, threads, unique_execution_threads, work_ledger` |
| 语义 | **超集断言（`<=`）**：新增键不失败，删/改键硬失败（`:1786-1787` 的注释写明了这个选择及其理由） |
| 为什么不能静态求 | `:1724-1729` 记录：`workbench_domain_view` 增量拼装 payload，AST 取不到 dict 字面量，键集是**运行期测出来的**（round 137，`pytest -q -s` 打印 `sorted(view)`） |
| 引入提交 | `1bc2e80`（2026-09-24 09:25:10 +0800，"P3.7 complete ... plus the P3.6 key-set debt closed"），**是 HEAD 的祖先**（`git merge-base --is-ancestor 1bc2e80 HEAD` → exit 0，`git rev-list --count 1bc2e80..HEAD` = **14**） |
| HEAD 里在不在 | `git show HEAD:tests/test_investigation_service.py` 命中 5 行 `REQUIRED_VIEW_KEYS`；工作树干净 |
| step record | `.scratch/structure-status.json` 的 `step_records` 第 81 条（`P3.7 COMPLETE ... + the P3.6 section-5.4 debt closed`），findings 第 3 条明说该债务已关闭 |

**因此 `docs/structure-execution-status-20260922.md:133-134` 是过期的**：它由 `.scratch/structure-status.json`
的 `authoritative_final_state`（`final_state_round_129_p36_2debts`，`head_sha=7ecb6b4...`，即 HEAD~2 那一代）
程序化渲染，而清偿发生在它之后 14 个提交。第 134 条"IF EXACTLY ONE MORE ROUND IS AVAILABLE, THE
BEST-VALUE VERIFIABLE STEP IS P3.6-2's TEST DEBT"**已经被执行过了**，不要照它再做一遍。

### 4.3 债务的**残留一半**：`task_view` 的"字段集合"没有对应断言（实测）

* 设计的 §5 第 4 条要求**两个**视图：`workbench_domain_view` 的返回结构 **和** `task_view` 的字段集合。
* 实测：`tests/` 中对 `task_view` 的 dict 键集比较为 **0 处**
  （`git grep -n "task_view" -- tests | Select-String "keys\(\)|set\(|<=|sorted\("` 无命中）。
* 但 `task_view` 的调用面很大：**`task_view(` 在 tests 里 65 处、19 个文件**（本次实测；P3.6-1 设计当时记的是
  59 处，`:83-86`）；生产侧 `main.py:1589, 1672`，`service.py:2003, 2099`，`task/task_runner.py:402, 489`。
* 所以**"§5.4 债务"应拆成两半报**：`workbench_domain_view` 那一半 **CLOSED**；
  `task_view` 那一半是 **OPEN 但无任何记录**——它是 P3.6-1 review 留下的、至今没有测量附着的唯一一条。

### 4.4 对 P3.6-2 的含义：debt 的处置 + capability 自己的键集

用同一手法（运行期测键集）对 capability payload 做了一次实测（`.scratch/p36-2-payload-keys.py`，
用 `tests/conftest.py:11-35` 的 `test_settings` 配方构造 `Settings` + `Database("sqlite://")` + `LocalContentStore`）：

```
TOP-LEVEL KEYS (16): action_submission_tool, actions, analysis_planner_model, api_version,
  backend_static_action_catalog, capability_profile, isolated_emulation, model_callable_tools,
  network_access, profiles, sample_execution, session_context_protocol, static_only,
  tool_contract_version, unavailable_capabilities, workspace
```

嵌套结构（实测）：
* `actions` = **18** 个 dict，键 `['description','estimated_cost','input_schema','name','output_schema','security_class']`
  （`ActionCatalog.default().names()` 实测 18 个：`GET_FUNCTION, GET_CALLERS, GET_CALLEES, GET_XREFS_TO,
  GET_XREFS_FROM, GET_STRINGS_REFERENCED, GET_DATA_REFERENCES, READ_BYTES, CONTROLLED_EMULATE, GET_DECOMPILE,
  GET_PCODE_SLICE, GET_CFG_SLICE, TRACE_API_ARGUMENT, TRACE_RETURN_VALUE, TRACE_GLOBAL_USAGE, DECODE_CANDIDATE,
  EVALUATE_CONSTANT, COMPARE_FUNCTION`）；
* `backend_static_action_catalog` = 同 18 个（**同一份 `actions` 列表被两个键引用**，`service.py:17301-17302`）；
* `model_callable_tools` = **16** 个（`service.py:17278-17295` 的硬编码名字表）× 键 `['name','security_class']`；
* `analysis_planner_model` = 12 键（`_analysis_planner_payload` 的 7 键 + `_model_status_payload` 的 `status.get(...)`
  投影 + `owned_by`/`configure_in`）；
* `isolated_emulation` = 6 键（含嵌套 `qiling` = 5 键）；`workspace` = 3 键；`unavailable_capabilities` = 4 项；`profiles` = 1 项。

**要清偿债务必须改什么**（精确）：
1. `task_view` 那一半：在已有 session fixture 的测试里加一条 `REQUIRED_TASK_VIEW_KEYS <= set(view)`，
   键集**运行期测出**（不能静态推）。**TEST-ONLY，不动 `src/`。**
2. capability 那一半（可选、但同一步顺手）：加 `REQUIRED_CAPABILITY_KEYS <= set(payload)`（16 键）。
   注意必须在**没有 DB 行**的路径上跑，否则 `model_configuration_view` 不存在、`isolated_emulation.qiling`
   的 `status` 会随 `qiling_rootfs` 是否存在而变——本文实测的 16 键是在 `Settings` 默认值 + 空库下得到的。

**能否放进 P3.6-2**：**能**，而且是**应该**——两条都是 test-only、都只需现有 fixture，
而 P3.6-2 无论如何都要改 `tests/test_workbench_query_contract.py`。不需要独立的 2b 步（见 §6）。

### 4.5 生产/消费方（实测）

产出这些键集的模块只有一个：`src/threat_report_agent/service.py`（`workbench_capabilities`）。
消费方：
* `src/threat_report_agent/main.py:787-789`（HTTP adapter，原样透传）；
* `threat-dsh-workbench/packages/threat-api-client/src/index.ts:140`（TS 客户端）；
* 4 个 Python 测试文件（§2.2）。
**没有任何 Python 模块 import 这些 dict 的键名**（grep `backend_static_action_catalog` 在 `src/` 只有 1 处，
即 `service.py:17302` 自己的产出），所以键集是**纯 JSON 契约**，只能靠运行期断言和 DSH 侧测试守。

---

## 5. 第 11 个 pin 成员偏差，实测

### 5.1 偏差是什么（数字全部来自 step record 与树）

`WORKBENCH_QUERY_HOST_MEMBERS` 的三个数字：

| 数字 | 来源 | 内容 |
|---|---|---|
| **12** | 设计值，`docs/p36-workbench-query-design-20260922.md:51-59`："原始 14 → 按实测读者收敛到 12" | 12 个成员，其中 **`_CATALOG_HOW_SEED_SCAN_LIMIT` 和 `_UNIQUE_THREAD_VIEW_KINDS` 都判为"随迁"** |
| **11** | 树里今天的值，`workbench_query.py:93-105` | 两个类常量**都改判为 pin 成员**（原文："Both constants are now PIN members (**11, not 9**)"） |
| **10** | 复查后的规则值，`workbench_query.py:80-87` | `_UNIQUE_THREAD_VIEW_KINDS` **没有任何其它 pin 读它**，按设计规则应随迁 |

**偏差成员 = `_UNIQUE_THREAD_VIEW_KINDS`（pin 里多出来的第 11 个）。**

### 5.2 造成偏差的两件事必须分开说，否则会误读

**事件 A（`_CATALOG_HOW_SEED_SCAN_LIMIT`，真·意外，代价 37 个测试）**：
pin 最初由"扫 `service.py` 里切片之外的 `self.`/`cls.` 读者"得出，两个类常量被判为随迁。
第一次应用后 **37 个测试**失败，异常是
`AttributeError: 'AnalysisService' object has no attribute '_CATALOG_HOW_SEED_SCAN_LIMIT'`，
**从 `investigation/derivation.py` 抛出**——一个已经搬走的模块，通过**它自己的 host pin** 读这个常量。
`service.py` 的 `self.`/`cls.` 扫描看不见 `host.<name>`。
（来源：`.scratch/structure-status.json` `step_records` 第 77 条的 findings 第 1 条；
`docs/structure-execution-status-20260922.md:137` 把它记为"BEFORE MOVING ANY CLASS ATTRIBUTE,
GREP EVERY `*_HOST_MEMBERS` TUPLE"。）

**事件 B（`_UNIQUE_THREAD_VIEW_KINDS`，保守误判，代价 0）**：
它为防同类意外而被一并 pin。复查测了**全仓库每一个 `*_HOST_MEMBERS` 元组**，
结论是**没有任何 pin 读它，只有本模块自己的 pin 读它**，所以它应该随迁（pin 应为 10）。
它留在 pin 里是因为"为一个成员重跑整次搬迁（恢复、重做、全部门禁、重建镜像）"是独立的重步，
被显式记为 **recorded deviation**，写在该常量旁边（`workbench_query.py:80-87`）。
（来源：`step_records` 第 79 条 findings 第 2 条。）

### 5.3 教训的可执行形式：仓库内**每一个** `*_HOST_MEMBERS` 元组（AST 实测）

`p36-2-hostpins.py` 的完整清单，共 **5 个元组、79 个被 pin 成员**：

| # | 文件:行 | 常量 | 成员数 | 成员 |
|---|---|---|---|---|
| 1 | `src/threat_report_agent/investigation/coordinator.py:144` | `INVESTIGATION_HOST_MEMBERS` | **6** | `database`, `_audit`, `_MAX_COMPLETED_ACTION_EVIDENCE_IDS`, `_CONVERGENCE_ALTERNATES`, `_CONVERGENCE_EXPECTED_KINDS`, `_canonical_json` |
| 2 | `src/threat_report_agent/investigation/derivation.py:234` | `INVESTIGATION_HOST_MEMBERS` | **42** | `_CATALOG_HOW_SEED_SCAN_LIMIT`, `_CONFIG_CONSUMER_SEED_KIND_LIMITS`, `_HOW_PLAYBOOK_IDS`, `_INVESTIGATION_EXECUTION_EVIDENCE_LIMIT`, `_PERSIST_HOW_CLAIM_MODULES`, `_audit`, `_canonical_json`, `_emulation_entry_key`, `_follow_local_tail_jmp`, `_gate_for_seed_playbook`, `_investigation_row_mapping`, `_investigation_value_text`, `_is_config_consumer_seed_row`, `_is_dynamic_api_seed_row`, `_is_explorer_parent_string_row`, `_is_http_transport_seed_row`, `_is_parent_attribute_seed_row`, `_is_process_creation_seed_row`, `_is_process_enumeration_row`, `_is_task_cancelled`, `_is_unique_thread_seed_row`, `_keep_emulation_after_persist_skip`, `_link_claim_evidence`, `_load_investigation_execution_rows`, `_matching_simulation_results`, `_persist_partial_how_ready`, `_persist_pma_static_analysis_plan`, `_persist_ready_emulation_actions`, `_persist_time_seed_result`, `_persist_time_static_boundary`, `_persist_time_unique_thread_result`, `_persist_unique_thread_claim_specs`, `_qiling_unavailable_observation`, `_run_simulation_window`, `_select_investigation_execution_rows`, `_static_decode_recovery_from_limitations`, `_supersede_queued_trace_after_persist_skip`, `_supporting_seed_static_boundary`, `_unique_thread_start_keys`, `content_store`, `database`, `settings` |
| 3 | `src/threat_report_agent/report/revision_writer.py:77` | `REVISION_WRITER_HOST_MEMBERS` | **11** | `SNAPSHOT_SCHEMA_VERSION`, `_apply_honest_analysis_outcome`, `_audit`, `_canonical_json_chunks`, `_overlay_analyst_report_plan`, `_postgres_safe_text`, `_postgres_safe_value`, `_t6_revision_diff_payload`, `audit_integrity`, `database`, `workbench_task_for_session` |
| 4 | `src/threat_report_agent/task/task_runner.py:100` | `TASK_HOST_MEMBERS` | **9** | `_audit`, `_seal_task_audit_chain`, `content_store`, `database`, `settings`, `task_view`, `_context_payload_v3`, `_context_state_for_task_v3`, `_require_session_id` |
| 5 | `src/threat_report_agent/workbench_query.py:93` | `WORKBENCH_QUERY_HOST_MEMBERS` | **11** | `_CATALOG_HOW_SEED_SCAN_LIMIT`, `_UNIQUE_THREAD_VIEW_KINDS`, `_action_payload`, `_audit_timestamp`, `_elapsed_ms`, `_failure_payload`, `_model_calls_env_enabled`, `_model_status_payload`, `_report_inputs`, `database`, `settings` |

对两个被 watch 的名字做交叉验证：

```
_CATALOG_HOW_SEED_SCAN_LIMIT: pinned by 2 tuple(s):
    investigation/derivation.py:INVESTIGATION_HOST_MEMBERS, workbench_query.py:WORKBENCH_QUERY_HOST_MEMBERS
_UNIQUE_THREAD_VIEW_KINDS:   pinned by 1 tuple(s):
    workbench_query.py:WORKBENCH_QUERY_HOST_MEMBERS
```

**这独立复现了事件 B 的结论**：`_UNIQUE_THREAD_VIEW_KINDS` 只有本模块的 pin 读它。

### 5.4 读者检查清单（P3.6-2 的作者必须逐条做，否则同一个意外会重演）

P3.6-2 要新增的 3 个 pin 成员里，**两个是类常量**（`THREAT_CONTEXT_PROTOCOL`、`THREAT_TOOL_CONTRACT_VERSION`），
正是事件 A 的受害类型。开工前必须：

1. `py .scratch/p36-2-hostpins.py`——列出全部 5 个元组的成员（**不要**用正则版仪器，见 §0）。
2. 对每个要动/要 pin 的类常量，检查**它是否出现在别处的 pin 里**：
   本例实测 `_CATALOG_HOW_SEED_SCAN_LIMIT` 在 `derivation.py` 的 pin 里（同型风险），
   `THREAT_CONTEXT_PROTOCOL`/`THREAT_TOOL_CONTRACT_VERSION` **不在任何 pin 里**（本次实测，`p36-2-hostpins.py` 的
   watch 集合可扩展后复查）。
3. **`self.`/`cls.` 扫描永远不够**：`git grep -n "THREAT_CONTEXT_PROTOCOL\|THREAT_TOOL_CONTRACT_VERSION" -- src tests`
   实测命中 **7 处**：`service.py:556`、`:557`（两处声明）、`:15805`、`:15806`（`_context_payload_v3` 读）、
   `:17324`、`:17325`（`workbench_capabilities` 读），加 `workbench_query.py:90` 的一句注释。
   **没有一处是 pin 读取**——所以这两个**可以安全地只 pin 不搬**。
4. 额外的一个"看起来像读者但不是读者"的地方（实测已排除）：**`.understand-anything/fingerprints.json:13183`
   是 tracked 文件**，里面有一份 `AnalysisService` 成员名快照，包含 `workbench_capabilities`、`workbench_domain_view`、
   `_unique_execution_threads_for_view` 等**已经搬走的成员**。`git grep -ln "understand-anything" -- src tests scripts docs`
   **零命中**：没有任何代码或门禁读它。它是 `understand` 技能在 2026-09-16 生成的陈旧产物，
   **P3.6-2 不需要更新它，也不要用它做读者分析。**

---

## 6. 步骤拆分与规模

### 6.1 结论：**P3.6-2 是一步，不是两步**

理由（全部实测）：

1. **原定的 2b（dict-key 债务）已经不存在**（§4.2，`1bc2e80` 已清偿）。
2. 搬迁本体只有 **105 行 / 3 个新 pin 成员 / 0 个写操作**——是 Phase 3 至今最小的切片
   （对比：P3.4-1 搬 4 个纯函数、P3.6-1 搬 1,040 行、P3.3f-2 搬 2,787 行）。
3. 剩下的两件事都是**同一批文件里的 test/prose 修改**，拆出去只会多一次镜像重建：
   (a) `task_view` 键集断言；(b) capability payload 键集断言；外加 (c) `workbench_query.py`
   的 docstring 与 pin prose 更新、(d) `_UNIQUE_THREAD_VIEW_KINDS` 偏差的处置决定。
4. **不建议把 `_UNIQUE_THREAD_VIEW_KINDS` 的"重跑搬迁"折进这一步**：那需要"恢复 → 重做 → 全部门禁 →
   重建两个镜像路由"，而部署门现在是 BLOCKED（§7.7），做了也无法证明。**应当继续记为 deviation**，
   并在同一处把"若要重跑，必须先有可运行的 8 个服务"写清楚。

### 6.2 建议的步骤定义

**P3.6-2（一步）**：把 `workbench_capabilities`（105 行）搬进 `workbench_query.py`，
pin 11 → 14，委托留在 `service.py`，并把两条 dict-key 断言补上。

| 项 | 值 |
|---|---|
| 搬移行数 | **105**（`service.py:17264-17368` → `workbench_query.py`，`self` → `host: WorkbenchQueryReaderHost`） |
| 闭包行数（留在宿主） | 195 − 105 = **90**（`_analysis_planner_payload` 19 + `_model_status_payload` 55 + `_planner_user_action` 16） |
| pin 变化 | 11 → **14**（+`THREAT_CONTEXT_PROTOCOL`、+`THREAT_TOOL_CONTRACT_VERSION`、+`_analysis_planner_payload`；`settings` 已在） |
| Protocol 变化 | `WorkbenchQueryReaderHost` 增加同 3 个声明（`workbench_query.py:108-125`） |
| 新增模块级 import | `ActionCatalog`（来源见 §6.3）、`simulation_policy_from_settings`（`emulation.policy`）、`Path`（`pathlib`）；`AnalysisFailureRecord`/`ModelCall` **不需要**（它们只在留下来的两个成员里用） |
| 新增委托 | `service.py` 增加 `def workbench_capabilities(self)` → `_workbench_query.workbench_capabilities(self)`，返回类型与 docstring 与实现一致（`test_delegations_keep_the_implementations_docstring`，`tests/test_workbench_query_contract.py:184-188`） |
| 删除 | `service.py:17264-17368` 原体（**零行为变化**：AST 层面只有接收者重命名与类去缩进） |
| 生产调用方改动 | **无**（`main.py` 不改；`service.py` 的委托是同名同签名） |
| 预计 `service.py` 行数 | 18831 → **约 18730**（删 105 行 + 新增约 4 行委托；`splitlines()` 口径，含空行，实测 HEAD = 18831） |

### 6.3 唯一需要方案级决定的点：`ActionCatalog` 的来源

| 选项 | 后果（实测） |
|---|---|
| (a) 先做 P3.5-0 的 `ActionCatalog` 下沉到 `contracts.py`，再搬 | 0 条新边。但这依赖 P3.5-0 的剩余 sink（M-1 的 10 个定义、M-3 的 `TaskLifecycle`、M-4 的 `fill_payload`、D-1、D-2，见 `docs/structure-execution-status-20260922.md:126`），**P3.6-2 会被 P3.5-0 卡住**。 |
| (b) 直接从 `threat_report_agent.investigation` 导入（今天的做法，`service.py:118-119`） | 新增一条 `workbench_query -> investigation` 模块级边。**`--strict` 不会报**（§8）。按 P3.6-1 设计给 `workbench_query` 指定的行（沿用 `report/` 行："contracts、facts、investigation 的**只读投影**，禁止 investigation/model 的实现"，`docs/p36-workbench-query-design-20260922.md:46-49`），从实现模块 `investigation/investigation.py` 的 `class ActionCatalog`（HEAD `:3598`）导入**属于被禁的一类**。 |
| (c) 把 catalog 作为参数从委托传进来（`workbench_capabilities(self, ActionCatalog)`） | 0 条新边、不依赖 P3.5-0。代价是模块函数多一个参数，且调用形状与 P3.6-1 的"host-only"惯例不同。 |
| (d) 记一条 `recorded_allowed_edges`（像 `["workbench_query","models"]` 那样）并加一条 tracked 负向断言 | 0 条新边被"合理化"，但需要显式决定 + 断言；`docs/import-policy.json:375-389` 的 note 明说门禁**不读**这个键。 |

**测量给出的建议**：先问 `ActionCatalog` 的下沉是否在本轮可达。不可达时**取 (c)**——它是唯一
"不需要方案级决定、也不需要新增被禁边、也不需要门禁配合"的选项，且与 `_coordinator._planner_user_action`
留在宿主是同一手法（宿主把跨层对象交给纯投影函数）。

### 6.4 各步允许触碰的文件

**P3.6-2（代码 + 测试 + prose）**
* `src/threat_report_agent/workbench_query.py`（新增函数、pin 11→14、Protocol、docstring/prose）
* `src/threat_report_agent/service.py`（删除原体、新增委托；`service.py:377` 的别名 import 已存在）
* `tests/test_workbench_query_contract.py`（`MOVED_MEMBERS` +1；pin 断言自动跟随；can-fail 计划 `--plan` 指向它）
* `tests/test_investigation_service.py`（**只**为 `task_view` 键集断言；若本轮不做则不动）
* `docs/p36-capability-slice-design-20260922.md`（本文件）、`docs/structure-execution-status-20260922.md`（刷新）
* `.scratch/structure-status.json`（gitignored，唯一允许的 `.scratch` 写）

**明确不允许触碰**：`docs/import-policy.json`（除非选 (d)）、`docs/structure-surface.json`（实测这道门禁的 8 个键
`compose_gate_fixture_verdicts / prompt_semantics / report_schema / sample_execution_strategy / state_enums /
test_getsource_count / threshold_comparisons / validator_thresholds` **没有一个与 capability 有关**，
新增测试不会改变它们）、`tests/test_runtime_agentic_contracts.py`（它的断言全部走 HTTP，搬家后应**原样通过**——
这正是"零行为变化"的证据，不要为了让新代码好看而改它）。

---

## 7. P3.6-2 必须通过的门禁

计划 §7.1（`docs/code-structure-optimization-execution-plan-reviewed-20260922.md:365-379`）规定每个迁移严格执行 **9 步**：

> 1. 列出旧模块中的符号、生产调用方、测试调用方和动态 import。
> 2. 在新包先建立最小公开接口和 contract test。
> 3. 移动**同一份实现**，不复制函数体。
> 4. 旧路径留下 `sys.modules`/re-export shim；新实现不得 import 旧路径。
> 5. 先改生产调用方到新路径，再逐个改测试调用方。
> 6. 做 module identity、函数 identity 和 JSON/byte-for-byte 输出比较。
> 7. 跑 focused tests、compileall、import graph、deployment import smoke。
> 8. 跑全量 pytest，比较 failure set。
> 9. 写 checkpoint；只有下一步授权后才删 shim。

各步的共同门禁见计划 §4.1-4.5（`:158-233`）。**对应本仓库的真实命令与今日实测状态**：

### 7.1 语法门

```
python -m compileall -q src
```
**今日实测 EXIT=0。**

### 7.2 导入图门（计划 §4.3）

```
py scripts/check-import-graph.py --strict
```
**今日实测 EXIT=0：**
```
modules : 117
edges   : 258 (runtime, same-package)
type-only edges (not runtime): 0
cycles  : 0 total, 0 not in the allowlist
forbidden edges present: 1 (0 not registered)
  [known] persist_how -> reporting
STRICT: no new cycles and no new reverse edges
```
（`docs/import-policy.json` 的 `_known_violations_note` 记录的正是这条 `persist_how -> reporting`。）
注意 `step_records` 第 82 条记的是 **257** 条边、`docs/structure-execution-status-20260922.md` 也写 257；
**今天实测 258**——引用时以本轮为准。`known_modules`（`docs/import-policy.json:390-421`）是 30 个名字，
`workbench_query` **不在其中**，它靠 `recorded_allowed_edges` 的 `["workbench_query","models"]` 条目注册
（registry 是各条目的并集，`scripts/check-import-graph.py:272-289`）。

### 7.3 结构 diff 门（计划 §4.1/§4.5/§4.6 的实现）

```
py scripts/check-structure-diff.py --all --strict
```
**今日实测 EXIT=0**，末行 `STRUCTURE DIFF: no new structural violation, no behaviour-surface change`，
四个负向 fixture 3 REJECTED / 1 `accepted (recorded gap)`（`narrow_case_heading_kept_bullets_dropped`）。
**不要加 `--record-surface`**，除非确实改了被记录的 surface（本步不应改）。

### 7.4 切片工具门

```
py scripts/check-slice-tooling.py
```
**今日实测 EXIT=0**：`compiling 1257 python file(s) from: scripts, .scratch` / `OK: 1257 file(s) parse`。
（该门只覆盖 `scripts` 与 `.scratch`，**不覆盖 `src`/`tests`**；两个 registered-unrunnable：
`_head_check.py`、`_rev32a7921_service.py`。）

### 7.5 focused 电池

```
python -m pytest -q tests/test_workbench_query_contract.py tests/test_workbench_api.py tests/test_runtime_agentic_contracts.py tests/test_model_config_api.py tests/test_workbench_security.py
```
**今日实测 34 passed**（其中 `tests/test_workbench_query_contract.py` 单跑 **8 passed**，exit 0）。
搬家后这 5 个文件必须**原样全绿**——它们是"HTTP 契约未变"的正面证据。

### 7.6 全量套件 + **按节点集合**比较（计划 §4.2）

```
py -m pytest -q
py .scratch/compare-failure-nodes.py <captured run file>
```
`compare-failure-nodes.py` 的用法是把**本次捕获的运行文件**作为唯一参数（`sys.argv[1]`，见该脚本
`__doc__` 与 `main()`）；它按节点集合而不是失败计数比较，并与 pytest 自己的 `N failed` 交叉校验
（脚本 docstring 记录了初版按数量比较时的假绿事故）。

**当前基线（实测自 `.scratch/structure-status.json` 的 `baseline`）**：
* 6 个 P0.2 失败节点，全部在 `tests/test_analysis_api.py`、`tests/test_deep_static_recovery.py`、
  `tests/test_t3_callback_fixture.py`（4 个）；
* **`baseline.environment_blocked` 记 2 个节点**（`tests/test_detection_rule_indicator_correctness.py::
  test_the_verifier_flags_a_self_referential_and_resource_digest_indicator` 与
  `::test_the_verifier_is_quiet_on_a_correct_rule`）；
* 最近一次全量（`.scratch/m2-verify-pytest.txt`，2026-09-24 10:41:55，HEAD 同代）：
  **8 failed / 2557 passed / 3 skipped** = 6 基线 + 2 环境阻塞。

**"环境阻塞"的真实原因是实测出来的、且与状态文档的措辞不同**：本轮跑那两个节点得到
`2 failed, 6 passed in 0.99s`，失败文本是
`psql failed: Error response from daemon: container c4eb069f7439... is not running`。
即 **Docker 引擎是活的（`docker info` → `29.7.2`，exit 0），是 Postgres 容器没在跑**。
`.scratch/structure-status.json` 的 `environment_blocked_note` 写的是"docker engine ... is down ...
`com.docker.service` Stopped"，**这句话今天已不成立**，但节点的阻塞结论不变。

### 7.7 部署一致性门（计划 §4.4）——**今日 BLOCKED**

```
docker compose config --quiet
docker compose ps
py scripts/check-deployed-code-hashes.py --strict --services api,intake-worker,document-worker,parser-worker,script-worker,control-worker,emu-worker,ghidra-worker
python -c "import threat_report_agent.facts, threat_report_agent.report, threat_report_agent.task"   # compose exec
```
本轮**只重跑了 hash 门**（下列输出）；`docker compose config --quiet` 与 `docker compose ps` 本轮未重跑
（`NOT MEASURED this round`；`.scratch/structure-status.json` 的 `environment.docker_compose_config`
记的是早前一轮的 `exit 0`，容器 import smoke 同理属于上一轮证据）。

**hash 门今日实测（EXIT=1，如实记为 BLOCKED，不当作通过）：**
```
manifest    : 130 file(s), enumerated from disk (not a fixed list)
head        : a299869ca7e8 (src/ clean, so the tree IS HEAD)
docker      : available ()
  api / intake-worker / document-worker / parser-worker / script-worker / control-worker / emu-worker / ghidra-worker
              NOT RUNNING - not compared
checked 130 file(s) across 8 service(s) against HEAD a299869ca7e8
DIFFERING (8): <每个服务> NOT RUNNING - no file could be compared
STRICT: deployment does NOT match the tree
```
**含义与计划 §4.4/§5.1 的规定一致**（`:220`："镜像不存在、Docker 不可用、源码 hash 不等于当前 HEAD、
容器 import 失败，都算 `BLOCKED`"）：P3.6-2 **改了 `src/`**，所以它**只能**被记为
`STRUCTURE_READY_LOCAL / DEPLOYMENT_BLOCKED`，除非先重建**两个镜像路由**并让 8 个服务跑起来。
`docs/structure-execution-status-20260922.md` 的第 3、13 条已把这个欠账记为"owed by a step that changed `src/`"。
**禁止跳过 `ghidra-worker`**（计划 `:220`）。

*（另注：`baseline.failures` 的 6 个节点是 P0.2、HEAD `5165a86` 上测的 `2358 passed`；
`.scratch/structure-status.json` 的 `deployment` 段记的是 **128** files / commit `30c2adcf`，
与今日实测的 **130** files / `a299869` 不一致——引用部署数字时必须用本轮实测值。）*

---

## 8. can-fail 要求（新受跟踪断言必须被证明"会失败"）

本 phase 的规则是"没见过失败的 gate 不是证据"。既有先例的写法（本设计照抄）：
* `.scratch/p34-canfail.py`：`tamper()` 先存 `path.read_bytes()` 与 sha256，**断言篡改真的落盘**
  （`digest(path) != before`），跑 contract test，`finally` 里按字节写回，**断言 sha256 回到原值**，
  最后断言 `not passed`（"tamper 后测试必须失败"）。全程**不用** `git checkout --`/`git reset --hard`。
* `.scratch/gate-hole-canfail.py`：先断言 gate 在干净树上 rc==0 → 造探针 → 断言探针落盘 →
  跑 gate → 删除探针 → 断言 gate 回到 rc==0；并且**断言失败信息里出现探针名与正确的失败类别**
  （"the gate failed but not because of the probe"）。
* 数据驱动版：`.scratch/canfail.py --plan .scratch/p36-canfail.json`（3 个 tamper，P3.6-1 用过并复用）。

### 8.1 P3.6-2 必须展示的篡改（每个都要：落盘 → 被拒 → 按字节还原）

> **编号说明**：下表 T1-T4 是**本设计新增**的篡改编号；它们与既有的
> `.scratch/p36-canfail.json` 里那一套 T1/T2/T3 **不是同一套编号**（那一套见本节末段的"还原要求"）。

| # | 篡改 | 目标文件 | 期望被哪条断言拒绝 |
|---|---|---|---|
| **T1** | 从 pin 里删掉 `"THREAT_CONTEXT_PROTOCOL",` | `workbench_query.py` | `tests/test_workbench_query_contract.py::test_pin_equals_the_receivers_the_moved_bodies_actually_read`（`:81-87`，pin≠bodies 双向断言）——这是新增 pin 成员的**唯一**证明 |
| **T2** | 把委托改写成调兄弟函数：`_workbench_query.workbench_capabilities(` → `_workbench_query.workbench_thread(` | `service.py` | `test_every_delegation_forwards_every_parameter`（`:141-181`，行为式 sentinel 门，**不用 `getsource`**）；这个篡改 import 得干干净净、能过所有结构门 |
| **T3** | 把 `workbench_capabilities` 的名字从 `MOVED_MEMBERS` 里删掉 | `tests/test_workbench_query_contract.py` | 该篡改会让 T1/T2 类的门**静默失去覆盖**，所以必须有一条断言直接守 `MOVED_MEMBERS` 与模块/宿主的**双向存在性**（`:110-113` `test_moved_names_exist_in_both_homes`）——即"新成员进了场，就必须进 `MOVED_MEMBERS`" |
| **T4（最有价值的一条，因 §8.2 而必须新增）** | 在 `workbench_query.py` 里加入 `from threat_report_agent.investigation.investigation import ActionCatalog`（选 §6.3 的选项 (b)） | `workbench_query.py` | **今天没有任何门会拒绝它**（§8.2 实测）。所以 P3.6-2 必须新加一条 tracked 负向断言——与 `test_module_never_imports_service`（`:94-107`）同形：断言模块的 import 名集合里不出现 `investigation.investigation`/`investigation.coordinator`/`emulation.*` 实现模块——并证明它在 T4 下失败 |

**还原要求**：每个篡改后用 sha256 断言逐字节回到原值；`p36-canfail.json` 里已有 3 条（T1 pin 成员移除、
T2 委托指错兄弟、T3 只读切片加入 `host.database.add(None)`），**T3 那条（只读篡改）在搬家后必须仍然咬得住**——
它现在会自动覆盖新函数（§3.3），这是"拓宽的 gate 仍然能抓到原来抓的东西"的证明。

### 8.2 为什么 T4 是必须的：**门禁看不见新边**（实测）

* `scripts/check-import-graph.py` 的 `forbidden_edges` 是**扁平名 deny-list**（`docs/import-policy.json:11-212`），
  且 `workbench_query` **不作为源**出现在任何一条里。
* 该脚本的"必须登记"检查是对**节点**做的（`scripts/check-import-graph.py:272-289`：
  `unregistered = [node for node in nodes if short(node) not in registered ...]`），**不是对边**。
  所以"两个端点都登记了"就通过。
* `docs/import-policy.json:389`（`_recorded_allowed_edges_note`）自认这一点：
  "the gate does **NOT** read this key today: `forbidden_edges` is a deny-list and the matrix is not
  machine-encoded, so **an unlisted edge cannot be machine-checked at all** - that blind spot is stated
  here rather than hidden."
* `step_records` 第 82 条（GATE HOLE CLOSED）关掉的是"**新模块**不可见"，
  并**没有**把 §3.2 矩阵编码成 allow-list；该条 findings 最后一句自己写着：
  "To machine-check this class of decision, encode the matrix as an allow-list and make
  `check-import-graph.py --strict` fail on any unregistered edge."

**结论**：P3.6-2 若走选项 (b)，`--strict`、`check-structure-diff --all --strict`、`check-slice-tooling`、
focused、全量**六道门全绿**，而 `workbench_query -> investigation`（P3.6-1 设计所判的禁止类）已经落地。
**这就是本文认为 P3.6-2 最大、且计划未提的风险。**

---

## 9. NOT MEASURED

* **NOT MEASURED: DSH 侧对该 payload 的运行时消费。** 只测到 TS 客户端的一个 HTTP 调用点
  （`threat-dsh-workbench/packages/threat-api-client/src/index.ts:140`）。要判断"capability 数据是否真的
  被 UI 读取/呈现"，需要跑 DSH 侧工具链（`pnpm typecheck/test/test:runtime/smoke:dsh`）并给出证据；
  本轮未运行，故不作任何断言（记录：DSH 套件上一次独立运行是 4 pass / 4 fail）。
* **NOT MEASURED: 搬家后的字节级/函数级 identity。** 需要真的执行搬迁并用
  `check-structure-diff` 的 `--all`（含 old-path 规则）比对；本轮是设计步，未改 `src/`。
* **NOT MEASURED: `ActionCatalog` 下沉到 `contracts.py` 的成本。** 需要 P3.5-0 的 M-1 sink 测量
  （`docs/p35-prep-measurement-20260922.md` 已测 15 个被阻塞名字，但 `ActionCatalog` 是否在其中、
  其 import 者范围是否影响该步，本轮未复核）。已测到的只有范围：`git grep -l "ActionCatalog" -- src`
  命中 **5 个文件**（`investigation/coordinator.py`、`investigation/derivation.py`、
  `investigation/investigation.py`（定义处 `:3598`）、`service.py`，以及 `workbench_query.py`——
  最后一个今天只在 docstring 里提到它）。
* **NOT MEASURED: 部署门在"两个镜像路由重建"后能否通过。** 本轮只有 BLOCKED 证据（§7.7）。

---

## 10. 一句话结论

`workbench_capabilities` 是 **105 行、0 次写、闭包 195 行、只需 3 个新 pin 成员、只有 1 个生产调用点
（HTTP 路由，必须继续走 service 对象）** 的小切片——机械上它是 Phase 3 最便宜的一步；
真正的风险不在搬迁，而在**它必须跨层读 `ActionCatalog`，而这一层边今天的门禁完全看不见**（§8.2）。
先决定 §6.3 的 (a)/(c)/(d)，再开工；`--strict` 绿**不能**作为那条决定的证据。
