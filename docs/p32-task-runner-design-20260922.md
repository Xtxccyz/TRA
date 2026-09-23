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
| P3.2d | `lifecycle` | `archive_case` | 31 | `_audit`, `database` | |
| P3.2e | `budget` | `_deferred_budget_thread_ids`, `_actual_depth` | 68 | `task_view` | 唯一**不需要**审计写入的簇 |
| P3.2f | `cancellation` | `cancel_task`, `cancel_tool_run` | 206 | 全部 6 个 | 唯一需要 `_seal_task_audit_chain` |
| P3.2g | workbench binding | `bind_historical_analysis`, `workbench_bind_existing_analysis` | 94 | 6 个 + `_context_payload_v3`, `_context_state_for_task_v3`, `_require_session_id` | 唯一需要**扩大端口**的簇；P3.2c 实测后从 creation 拆出 |

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

