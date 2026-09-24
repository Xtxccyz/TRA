# 决议 D-1：`emulation -> models` 这条边是否接受

**状态**：已决议并登记（P3.5-0 / D-1）。**登记是记录，不是机器强制**——原因见 §4，且这一点是实测的，不是推测的。
**日期**：2026-09-24
**相关**：`docs/code-structure-optimization-execution-plan-reviewed-20260922.md` §3.2（层矩阵）、§P3.5（抽 `EmulationCoordinator`）；`docs/p35-prep-measurement-20260922.md` §4 的 D-1 行；`docs/import-policy.json` 的 `recorded_allowed_edges`；`docs/plan-conflict-resolutions-20260922.md` 决议 (d)。

---

## 1. 问题

P3.5 要抽出 `EmulationCoordinator`（`emulation/coordinator.py`）。按测量，它需要 8 个名字：`AnalysisTask`、`Artifact`、`ContentBlob`、`Evidence`、`InvestigationActionRecord`、`ToolRun`、`new_id`、`utcnow`。

这 8 个名字都在 `threat_report_agent.models`（ORM 模块）里。而方案 §3.2 的层矩阵给 `emulation/` 写的是：

> | `emulation/` | contracts、facts、worker/模拟端口 | `service`、`report`、HTTP、DSH |

**`models` 既不在"可以导入"里，也不在"禁止导入"里**——它是一条**未列出的边**，所以需要一份决议，而不是一个假设。

## 2. 实测（决议的依据，不是口味）

### 2.1 `models` 被矩阵的**每一行**都漏掉了，不只是 `emulation/` 这一行

矩阵列的层是：`contracts.py`/纯领域类型、`facts/`、`static/`、`emulation/`、`tools/`、`intake/`、`investigation/`、`report/`、`task/`、`main.py`/DSH。**`models` 不是其中任何一行**，因此"某层可以导入 `models`"在矩阵里**根本没有表达方式**。

### 2.2 实测：11 个模块已经在导入 `models`，跨 4 个包

| 导入者 | 层 | 导入的名字 |
|---|---|---|
| `database.py` | 基础设施 | 10 个（含 `Base`、`new_id`） |
| `service.py` | 门面 | 32 个 |
| `investigation/coordinator.py` | investigation | 8 个 |
| `investigation/derivation.py` | investigation | 13 个 |
| `investigation/persist_how.py` | investigation | `Claim`、`new_id` |
| `investigation/seed_support.py` | investigation | `Evidence` |
| `static/evidence_recovery.py` | **static** | `Evidence`、`EvidenceSearchKey` |
| `task/analysis_task_orchestration.py` | **task** | `utcnow` |
| `task/limitations.py` | **task** | 5 个 |
| `task/task_runner.py` | **task** | 10 个 |
| `tools/tool_execution.py` | **tools** | 4 个 |

**结论**：导入 `models` 是**既成实践**，跨 `static/`、`investigation/`、`task/`、`tools/` 四个包，共 11 个模块。单独拒绝 `emulation/` 会是矩阵里唯一一条没有依据的例外。

### 2.3 已登记的同类边只有 2 条，而不是 11 条

`docs/import-policy.json` 的 `recorded_allowed_edges` 里，指向 `models` 的只有：

```
["report.revision_writer", "models"]
["workbench_query", "models"]
```

也就是说 11 条 `-> models` 的边里，**只有 2 条被登记过**。这次登记会把 `emulation -> models` 变成第 3 条被登记的边。

### 2.4 `emulation/` 今天**没有**导入 `models`

实测：`emulation/` 四个模块的包外 import 全集是 `facts.{dataflow,thread_start}` 与 `static.static_analysis`（`policy.py` 只导入标准库）。所以这条边是**为 P3.5 的 coordinator 预备的**，不是今天已经存在的边。

## 3. 决议

**接受 `emulation -> models`，并登记在 `recorded_allowed_edges`。** 依据是 §2.2 的实测：`models` 是横切的基础设施模块，已被 4 个包、11 个模块导入，而矩阵对**任何**层都没有给它留位置；拒绝 `emulation/` 会是没有依据的单独例外。

**附带条件（写下来是为了让后来者能判断"这条边是否还在被正当使用"）：**

1. 这条边**只为 `emulation/coordinator.py` 的持久化与身份生成**而开：读/写行（`AnalysisTask`、`Artifact`、`ContentBlob`、`Evidence`、`InvestigationActionRecord`、`ToolRun`）与 `new_id`/`utcnow`。
2. 它**不**放宽 `emulation/` 的其余禁令：`service`、`report`、HTTP、DSH 仍然禁止。
3. `emulation/` 中**不承担持久化职责**的模块（`policy.py`、`vb6_runtime_shim.py`、`emulation_plan.py`）保持今天的纯净度：**只有标准库 + `facts`/`static`**。这条边的存在不能成为"顺手把 ORM 引进 `policy.py`"的理由。
4. 一旦该边真正落地，**同一次提交**必须：把它写进 `recorded_allowed_edges`（若尚未写入）、在 `check-import-graph.py` 的 node registry 里确认两个端点都已登记，并跑 `--strict`。

**为什么不是"加端口"**：那会把 `ToolRun`/`Evidence` 这类 ORM 行对象抽象成新的端口类型，而 `report.revision_writer` 与 `workbench_query` 已经用"直接导入 `models`"的方式解决同一个问题；为 `emulation/` 单独引入端口会让三处同类接缝出现两套写法。若 P1.1 的端口工作日后把持久化收敛成端口，这条边应当**随之撤销**，而不是继续共存——这点记在 §5。

**为什么不是"禁止"**：见 §2.2，禁止需要先把 11 个模块一起改掉，那是一次跨包重构，不是 P3.5-0 的一步（方案纪律：不得自行扩大范围）。

## 4. 这次登记**不是机器强制**的（实测）

必须写清楚，否则读者会把"登记了"当成"被检查了"：

- `scripts/check-import-graph.py` **确实读** `recorded_allowed_edges`，但只用来**登记节点**：`registered.update(...)`，见该脚本的 node-registry 段（`for pair in policy.get("recorded_allowed_edges", [])`）。
- 它**从不把一条实际边与这个键做比较**：`--strict` 的失败条件只有两条——新循环、以及命中 `forbidden_edges` 扁平名 deny-list 的新违规。
- `docs/import-policy.json` 自己的 `_recorded_allowed_edges_note` 已经承认这点："The gate does NOT read this key today ... an unlisted edge cannot be machine-checked at all"。
- 实测的非强制证据：树上今天有 **258** 条运行时边，而 `recorded_allowed_edges` 只有 **3**（登记后 4）条，`--strict` 依然绿。若登记被强制，另外 254 条边都该被报出来。

**因此**：本决议的价值在于**把决定和依据写下来**，让后来者不必重新推导；它**不**提供机器保护。

## 5. 仍然未解决的（不塞进 D-1）

1. **边登记没有被强制**（§4）。真正的修法是给门禁加**边注册表**（或把 §3.2 矩阵机器编码），使"未登记的边"像"未登记的模块"一样被拒。**这是独立一步**，需要它自己的 can-fail（篡改：在 `workbench_query.py` 里加 `from threat_report_agent.investigation.investigation import ActionCatalog`，要求新断言拒绝它）。P3.6-2 的设计（`docs/p36-capability-slice-design-20260922.md` §6.3/§8.1）独立地撞到同一个盲区并给了同样的修法，两处应合并成一步。
2. **11 条 `-> models` 的边里只有 3 条被登记**。把其余 8 条补齐是同一件"边注册表"工作的一部分；在门禁会读之前，补齐只是文档整理。
3. **P1.1 的端口工作若把持久化收敛成端口**，本决议应被撤销（§3 末段），而不是保留成"历史例外"。
