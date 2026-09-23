# P3.2 `TaskRunner` 设计记录（round 96）

> 本文件记录计划 §8 中 **P3.2** 的**接口设计**与**实测依据**。计划 §7.1 的九步算法把「先在新包建立最小公开接口
> 和 contract test」放在第 2 步、把「移动同一份实现」放在第 3 步，所以本轮的产物是两件：
> `src/threat_report_agent/task/task_runner.py`（端口）与 `tests/test_task_runner_contract.py`（契约）。
> 真正的搬迁从 **P3.2c** 起，按本文件第 3 节的顺序逐簇进行。
>
> 可复现命令（HEAD `90aedec` + 本轮，两个脚本都在 `.scratch/`，未纳入版本控制）：
>
> ```powershell
> py .scratch/p32design-candidates.py   # 逐个候选的直接端口面
> py .scratch/p32design-scale.py        # 搬迁规模：候选 / 闭包 / 端口 / 随迁 / 留在宿主
> ```

## 1. 实测：P3.2 到底要搬多少

| 事实 | 值 |
|---|---|
| 候选成员（任务创建 / 生命周期 / 预算 / 取消 / 限制与结果投影） | **19 个方法 / 585 行** |
| 其完整 helper 闭包 | 18 个成员 / 1,040 行 |
| **直接端口面**（候选直接触碰、且候选集**之外**也有使用者的成员） | **6 个** |
| 随簇搬迁的 exclusive 成员（只有候选在用） | 1 个 / 90 行（`workbench_bind_existing_analysis`） |
| 通过端口间接调用、**留在宿主**的共享成员 | 17 个 / 950 行 |
| 整个 P3.2 的搬迁上限 | **675 行 / 20 个成员** |

**一个被更正的旧读数**：早前记录过「163 成员闭包 / 31 个共享成员」，据此认为任务路径无法有界拆分。
那个数字统计的是**传递闭包**——闭包里绝大多数成员是经由端口成员**间接**到达的，它们留在宿主，
不进入端口。真正决定端口大小的是**直接**触碰面，实测是 6 个。这是本轮把 P3.2 从「先设计接口、暂不动」
推进到「接口已定、可以逐簇搬」的唯一依据，因此记录在此以免再次误读。

## 2. 端口：`TaskHost`（6 个成员）

| 成员 | 端口外使用者数 | 形态 |
|---|---|---|
| `database` | 86 | 宿主状态（`__init__` 赋值） |
| `_audit` | 52 | 宿主操作（审计写入） |
| `settings` | 34 | 宿主状态（`__init__` 赋值） |
| `content_store` | 24 | 宿主状态（`__init__` 赋值） |
| `_seal_task_audit_chain` | 6 | 宿主操作（终态审计链封口，仅取消簇需要） |
| `task_view` | 1 | **公开**门面操作（P3.1「读状态」组） |

两个设计决定：

1. **端口里出现两个私有名不是疏忽。** 宿主是 `AnalysisService`，它的**公开面本身是一份契约**：P3.1 把它固定为
   四组稳定操作，`tests/test_service_facade_contract.py` 与本轮契约测试都在钉住它，计划 §7.10 也要求 HTTP
   边界只走公开成员。为了让端口「看起来整洁」而新增公开的 `audit` / `seal_task_audit_chain`，会为一次**纯内部
   协作**扩大对外发布面。因此端口照实写出宿主已有的名字；将来若确有对外审计入口的需要，应在**同一次**改动里
   改私有名 + 端口 + 两处 pin，而不是先放宽端口。
2. **`task_view` 进端口是为了单一来源。** 预算簇需要读任务状态，端口让它去问宿主的公开读操作，而不是自己去读
   任务行；这样「任务视图怎么算」仍然只有一份实现。

端口的**增长规则**：新增第 7 个成员意味着某个任务簇开始依赖端口之外的东西。契约测试会先失败
（它每次都从 `service.py` 重新推导直接端口面并与 pin 比对），因此扩大端口必须是一次**有意识的、带理由的**改动。

## 3. 迁移顺序（由小到大，每簇一次检查点）

| 顺序 | 簇 | 成员 | 行数 | 需要的端口成员 | 备注 |
|---|---|---|---|---|---|
| **P3.2c** ✅ | `creation` | `create_submission_task`, `prepare_blind_run` + `SubmissionResult`（两者返回类型） | 152 + 8 | `_audit`, `content_store`, `database` | **已完成**：实测端口无需扩大（见第 6 节） |
| P3.2d | `lifecycle` | `archive_case` | 31 | `_audit`, `database` | **已完成**：实测无端口外依赖、无 service 内定义类型，纯机械搬迁（见第 7 节） |
| P3.2e | `budget` | `_deferred_budget_thread_ids`, `_actual_depth` | 68 | `task_view` | **已完成**：`_actual_depth` 是 `@staticmethod`（无接收者），搬迁不引入 `host`；另需**有意识地**加 3 个 models 导入（见第 8 节） |
| P3.2f | `cancellation` | `cancel_task`, `cancel_tool_run` | 206 | 全部 6 个 | **已完成**：首个用满**全部 6 个**端口成员的簇；需要一次有意识的导入放宽（含 `task -> tools.tool_execution`，实测无环）（见第 9 节） |
| P3.2g | workbench binding | `bind_historical_analysis`, `workbench_bind_existing_analysis` | 94 | 6 个 + `_context_payload_v3`, `_context_state_for_task_v3`, `_require_session_id` | **已完成**：唯一一次**有意扩大端口**（6 → 9），全部有记录（见第 10 节） |

P3.2a / P3.2b 已完成的投影面（`task/limitations.py`）不在上表内：它们的 service.py 主体已是单行委托。

## 4. 每簇的验证（不得省略，与 P3.2a / P3.2b 同标准）

1. **同一份实现**：从 `service.py` 剪切方法体到新模块，`self.` → `host.` 重写；用 `ast.unparse` 归一化比对
   证明除接收者重写外**逐节点一致**（P3.2b 的 `p32b-verify-bodies.py` 已证明该工具能抓到真实差异，包括
   `@staticmethod` 与缩进导致的伪差异）。
2. **单行委托**：`service.py` 里原方法体替换为 `return _task_runner.<fn>(self, ...)`，公有/私有/静态三种形态
   必须按实际语义选择（P3.2b 曾在这一点上犯过 3 次错）。
3. **回滚路径**：任何失败都用 `git show HEAD:<path>` 取回 + 哈希校验，不使用 `git checkout --` / `reset --hard`。
4. focused 测试 + 新契约测试；
5. `py scripts/check-import-graph.py --strict --policy docs/import-policy.json`；
6. `py scripts/check-structure-diff.py --all --strict`；
7. `py scripts/structure_behavior_probe.py --check .scratch/structure-baseline/behavior.json`（必须 UNCHANGED）；
8. 重建镜像后 `py scripts/check-deployed-code-hashes.py --strict --import-smoke`（新模块必须随镜像分发）；
9. 全量 pytest 与基线**失败节点集合**比对（基线 6 节点，用 `.scratch/compare-failure-nodes.py`）。

失败时保留 shim、`current_step` 不动、**不把失败测试改宽松**。

## 5. 本步明确不做（记录，而非顺手改）

- 不把 `_audit` / `_seal_task_audit_chain` 改名为公开成员（理由见第 2 节）；
- 不动 P3.2a / P3.2b 已迁的 5 个投影函数；
- 不动 17 个共享 helper：它们经由 6 个端口成员被间接调用，属于宿主的实现细节；
- 不在本步引入 `TaskRunner` 类骨架：计划 §7.1 第 2 步只要求**最小**接口，空的类骨架是投机结构。
  `TaskHost` 是本步唯一的结构声明，`missing_task_host_members()` 是它的可执行形式。

## 6. P3.2c 实测结果（`creation` 簇已搬迁）

**实测改变了本步范围，而不是让结论去迁就范围**（`.scratch/p32c-creation-analysis.py`，搬迁前运行）：

| 发现 | 实测 | 处置 |
|---|---|---|
| 返回类型 `SubmissionResult` **定义在 service.py 内**（第 360-367 行，无依赖的 frozen dataclass） | `create_submission_task` 的返回类型 | **随簇搬迁**，service.py 改为 `from threat_report_agent.task.task_runner import SubmissionResult` 再导出；公开路径与全部既有调用点不变，`service.SubmissionResult is task_runner.SubmissionResult` 实测为 True |
| `bind_historical_analysis` 只是**2 行转发** | 真正实现是 `workbench_bind_existing_analysis`（90 行） | 二者一起**留待 P3.2g**：搬一个转发器不产生任何收益（deletion test 不通过） |
| `workbench_bind_existing_analysis` 需要端口外的 **3 个**宿主 helper | `_context_payload_v3`（classmethod）、`_context_state_for_task_v3`（classmethod）、`_require_session_id`（staticmethod） | 它是**唯一**需要扩大端口的簇，因此单独一步、单独一次有理由的端口放宽 |
| creation 簇的 `host.X` 只有 3 个 | `_audit`、`content_store`、`database`，全部已在端口内 | **无需扩大端口**，这一步因此是纯机械的 |

搬迁结果：`create_submission_task`（114 行）、`prepare_blind_run`（38 行）、`SubmissionResult`（8 行，含
`@dataclass(frozen=True)`）→ `task/task_runner.py`（298 行）；service.py 29,389 → 29,268 行；两个方法在
service.py 内各只剩**一条** `return _task_runner.<fn>(self, ...)` 委托，签名保持原有的多行排版。

搬迁过程中**由工具而非肉眼**发现的两个问题，都记在这里以免后人重犯：

1. **`ClassDef.lineno` 指向 `class` 行而不是装饰器行**（第一次 dry run 的 `compile()` 抓到的 `SyntaxError`）。
   以 `data_class.lineno` 为起点会同时造成两件事：service.py 里 `@dataclass(frozen=True)` 变成悬空行，以及
   **搬走的类丢掉装饰器**——把 frozen dataclass 悄悄变成普通类，即「披着搬家外衣的行为变更」。生成器现在从
   `decorator_list[0].lineno` 起算，并断言搬走的源码以装饰器开头。
2. **委托的排版**：由 AST 拼出的单行委托给 `create_submission_task` 生成了 411 字符的一行（文件内最长行只有
   186 且与本步无关）。生成器改为复用**原始的多行签名块** + 逐参数换行的调用，使 diff 只体现方法体。

验证：`p32c-verify-bodies.py` 用「逐语句 `ast.unparse` + 归一化掉接收者」比对，三个搬迁体全部 IDENTICAL
（含装饰器）；并且**先证明它能失败**——把 `host.database` 改名为 `host.database_renamed` 后验证器以
exit 1 报 `DIFFERS`，随后逐字节还原（`p32c-canfail.py`）。

> 顺带记一条工具教训：第一次 can-fail 用 PowerShell 的 `Set-Content` **未带 `-Encoding utf8`** 改写文件，
> 结果写成了本机 ANSI 代码页，验证器直接以 `UnicodeDecodeError` 崩掉。这是「响亮地失败」而不是「悄悄通过」，
> 但它证明不了比对本身，所以 can-fail 改用 Python 明确按 UTF-8 往返重做。

## 7. P3.2d 实测结果（`lifecycle` 簇已搬迁）

P3.2c 之后把「测量 → 抽取 → 证同 → can-fail → 门禁」这套流程**脚本化复用**（这是 P3.2c 之后的效率改进，
不是新方法）：`.scratch/p32-measure-cluster.py`（搬迁前测量，第 1-4 节全部问题）、
`.scratch/p32-extract-cluster.py`（抽取 + 委托生成）、`.scratch/p32-verify-cluster.py`（逐语句比对）、
`.scratch/p32-canfail-cluster.py`（先证明验证器会失败）。三者都接受簇名作为参数，P3.2e/f 直接复用。

`archive_case` 实测（31 行，无装饰器）：宿主引用只有 `_audit` 与 `database`（均在端口内）；
自由名 `select` / `AnalysisTask` / `CaseRecord` **已在新模块里导入**；**没有** service 内定义的类型要一起搬。
因此这是纯机械搬迁：service.py 29,268 → 29,239 行，方法只剩一条委托
（`return _task_runner.archive_case(self, case_id, actor=actor)`），搬迁体比对 IDENTICAL（`c52a9eb037bfe535`）。

抽取器新增的一条**由实测逼出来的处理**：`archive_case` 的签名在**同一行**内写完
（`def archive_case(self, case_id: str, *, actor: str = ...) -> dict[str, object]:`），
而 P3.2c 的两个方法签名都是多行的，所以「`self` 独占一行」的分支匹配不到——抽取器现在先处理
`def <name>(self` 的单行形态，再走逐行分支。生成器为此停止而不是产出错误结果，这是设计使然。

抽取器还加了一条**防止搬家顺手改导入**的硬约束：搬迁代码需要的每个自由名，必须**已经**在
`task/task_runner.py` 里导入；否则脚本**直接停止**并列出缺的导入。理由写在脚本 docstring 里：
对活模块做导入手术，正是把「搬家」变成「重写」的那类副作用。

## 8. P3.2e 实测结果（`budget` 簇已搬迁）

实测（`.scratch/p32-measure-cluster.py _deferred_budget_thread_ids _actual_depth`）：两个成员共 68 行；
宿主引用只有 `task_view`（在端口内）；**没有** service 内定义的类型；自由名 `select` / `Session` /
`Artifact` / `Evidence` / `ToolRun`。service.py 29,239 → 29,175 行；两个搬迁体比对 IDENTICAL
（`fe62ef3d4b1a43be` / `8b21adb882b7ec63`）。

本步新增的两条处理，都是**实测逼出来**的，不是预先设计的：

1. **`@staticmethod` 形态**：`_actual_depth` 是静态方法，**没有 `self` 参数**，也就没有「接收者」可重写。
   对一个静态方法硬塞一个 `host: TaskHost` 参数等于**发明一个不存在的协作者**，正是方案 P3.2 要求接口设计
   避免的做法。因此它作为普通模块函数搬走（签名原样），service.py 的委托保留 `@staticmethod` 且不传 `self`。
   抽取器据此分成两条路径：有 `self` → `host`；静态 → 完全不动接收者。契约测试也据此分别断言
   （静态委托**不得**出现 `self`，实例委托**必须**转发宿主）。
2. **抽取器第一次跑出的双重装饰器 bug**（`@staticmethod` 出现两次）。根因：`FunctionDef.lineno` 指向 **`def`
   行**，所以替换区间从 `def` 行开始时，**原来的装饰器被留在原地**，而生成器又输出了一行。
   **这个 bug 不会被测试抓到**，因为我的验证器只比对**函数体**，装饰器不在其中——它是靠**肉眼检查生成结果**
   发现的。修法：替换区间从第一个装饰器行开始，委托恰好带一行装饰器。（注意这与 P3.2c 的 `ClassDef` 情形
   方向相反：那边 `lineno` 指向 `class` 行、装饰器在区间外——两次都得实测，不能类推。）
3. **一次有意识的导入放宽**：budget 簇需要 `Artifact` / `Evidence` / `ToolRun`。抽取器的硬约束因此**先报错并
   停止**，由我在 `task/task_runner.py` 里显式加上这三个名字并写明理由（注释就在 import 旁），再重新运行
   抽取器。这正是那条约束想要的效果：导入面的扩大是被记录的动作，而不是搬家的副作用。

## 9. P3.2f 实测结果（`cancellation` 簇已搬迁）

实测：`cancel_task`（115 行）+ `cancel_tool_run`（91 行），**用满全部 6 个端口成员**——其中
`_seal_task_audit_chain` 至今只有这一个簇需要它。service.py 29,175 → 28,984 行；两个搬迁体比对 IDENTICAL
（`cb268d755757cb4d` / `235a5cb1c5e87ad1`），can-fail 对两者分别证明。

搬迁前实测又抓到两条**工具自身的缺陷**，都影响正确性，不只是效率：

1. **假阳性**：`except ... as exc` 里 `exc` 的绑定是 `ExceptHandler.name`（**字符串**），不是 `ast.Name` 的
   Store 节点。只收集 Name-Store 的遍历器会把 `exc` 当成自由名，进而报出「service 内定义的类型」这种不存在
   的结论，**直接挡住搬迁**。修法：把 `ExceptHandler` / `Global` / `Nonlocal` / `MatchAs` / `MatchStar` /
   `MatchMapping` 这些「引入名字」的节点形态全部计入局部名。测量工具的错误结论会伪装成方案结论，这条记在此。
2. **`self.` 文本重写会改到散文**（潜在的行为变更，且验证器看不见）：重写是
   `moved.replace("self.", "host.")`，如果某方法的文档字符串里出现 `itself.`，就会被改成 `ithost.`——
   而验证器把两侧的 `self.`/`host.` 都归一化掉，两侧都化成 `ithost` 前的前缀，**因此不会报差异**。
   现在加了两道断言：文本 `self.` 出现次数必须等于 AST 里 `self` 属性访问次数；且任何字符串常量都不得包含
   `self.`，否则脚本停止、要求人工处理。
   同时「残余 `self`」检查从**子串扫描**改为 **AST 名称检查**——原来的子串扫描把某文档字符串里的英文单词
   `itself` 当成了残余 `self` 并中止了一次合法搬迁。

**端口覆盖率里程碑**：P3.2f 之后，「已搬迁代码实际用到的 `host.X`」恰好等于**全部 6 个**端口成员，
即端口不再有任何「留给将来用」的成员；而**尚未搬迁**的候选（`bind_historical_analysis` 等）直接端口面是
全集的子集。契约测试据此把原来「端口 == 候选集直接 spine」的单向等式改成**双向断言**
（`remaining ⊆ port` 且 `remaining ∪ used_by_moved_code == port`）：候选搬走后变成单行委托、其直接 spine 收缩，
原等式会因**正当原因**变假，而把它放宽成子集则是弱化；现在两个方向各自都有真实主体——
「没有端口外需求」与「没有无人使用的成员」。

## 10. P3.2g 实测结果（workbench binding 已搬迁；唯一一次端口扩大）

实测：`bind_historical_analysis`（4 行，2 行转发）+ `workbench_bind_existing_analysis`（90 行）= 94 行；
宿主引用为 `_audit`、`database` 加**端口外的 3 个 DSH 上下文 helper**。service.py 28,984 → 28,898 行；
两个搬迁体比对 IDENTICAL（`e8a0267b451af66a` / `059c12c99c3ef012`）。**P3.2 至此全部完成**：
`creation` / `lifecycle` / `budget` / `cancellation` / workbench binding 五簇全部在端口之后，
service.py 从 Phase-3 起点的 29,640 行降到 28,898 行。

**端口扩大（6 → 9）是有意为之，并且是被测试看见的**：三个新成员按宿主的真实形态声明
（`_context_payload_v3` 是实例方法，`_context_state_for_task_v3` 是 classmethod，`_require_session_id` 是
staticmethod；三者都以 `host.<name>(...)` 访问，对三种形态都成立）。它们作为**宿主操作留在 service.py**，
不随簇搬迁——契约测试新增一条 pin 就是钉这一点：三个 helper 必须仍在 `AnalysisService` 上、且仍在端口里。

本步又抓到四个**工具自身**的问题，前三个都会让结论失真：

1. **簇内调用被误写成走宿主**：`bind_historical_analysis` 调用同簇的 `workbench_bind_existing_analysis`，
   而抽取器把 `self.` 一律改写成 `host.`，于是变成 `host.workbench_bind_existing_analysis(...)`——
   **绕回宿主的委托**，并依赖一个**不在端口里**的成员（契约测试的 `host_refs ⊆ port` 会失败）。
   现在抽取器先处理**簇内调用**：同簇目标直接调模块函数（有 `host` 形参就传 `host`，静态则不传）。
2. **验证器的归一化必须对称地覆盖「接收者变成实参」**：原始代码写 `self.f(...)`，搬迁后写 `f(host, ...)`，
   若只做文本层的 `self.`/`host.` 剥离，就会把**这个有意的变化**报成函数体差异。现在两侧都先按 AST 去掉
   调用里的第一个 `self`/`host` 位置实参再比对。**这条改动必须自证没有削弱验证**，所以用
   `--from <rev>` 对**全部 11 个已搬迁体**逐个回到它们各自的搬迁前提交重新比对，结果全部 IDENTICAL；
   并对 7 种形态重新做 can-fail。
   > 记录一处**口径变化**：归一化改变后，部分体的**摘要值**与第 6–9 节记录的不同（例如
   > `prepare_blind_run` 由 `cafe49e74bba6d04` 变为 `286e7dc287c444a8`）。函数体没有变，变的是规范化形式；
   > 摘要只是同一比对下的副产物，跨口径不可直接比较，这一条写在这里以免后人误读为「体被改过」。
3. **测量工具里留了端口的第二份副本**：`p32-measure-cluster.py` 自己硬编码了 6 个成员，端口扩大后它仍把三个
   新 helper 报成「不在端口上」——一个与被测代码意见相左的测量工具比没有工具更糟。现在它从
   `task.task_runner.TASK_HOST_MEMBERS` **导入**唯一事实来源。
4. **can-fail 证明一度是空洞的**：篡改搜索从函数起点一直找到**文件末尾**，于是改到了**后面另一个函数**里的
   `host.`，而验证器只被问了被点名的那个方法，正确地报告「无差异」——证明脚本据此报出
   「CAN-FAIL PROOF FAILED」，但那是**证明的问题**，不是验证器的问题。现在篡改被**限定在该函数自身的区间**内，
   且对「没有 `host.` 属性、也没有字符串字面量」的单行转发器改为篡改 `return` 后**被调用的名字**
   （字符串回退会落到**签名**上，而签名正是验证器有意忽略的部分）。修好后 7 种形态的 can-fail 全部通过。

