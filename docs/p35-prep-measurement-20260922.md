# P3.5-0 准备步实测：把 15 个阻塞名送到 `emulation/` 可达的地方（20260922）

> **本步性质：只测量 + 只写这一份文档。** 未改 `src/`、`tests/`，未改任何其他文档。
> 本文件是 `docs/p35-emulation-coordinator-design-20260922.md` §5 的 P3.5-0 的**准备步实测**，不是 P3.5 本身。
> 结论先行：**15 个名字里 10 个可以便宜下沉，5 个沉不下去**（它们不是类型，是实现代码/模块别名），
> 而这 5 个恰好是"结果归档"和"失败分类"两件事的核心。

---

## 0. 测量方法与复现

所有数字来自本步直接读源码的 AST 扫描（`ast.parse` 遍历 `src/threat_report_agent` 全部 117 个模块），
不是引用旧文档：

* **定义点**：模块顶层 `ClassDef` / `FunctionDef` / `Assign` 的 `lineno`，并对 re-export 追到真实定义。
* **kind**：直接引用定义处的 `class X(...)` 源码行，不按名字猜。
* **drags in**：定义所在模块（或搬迁簇）**模块级** import 的包内模块 + 第三方库。用 `ast.walk` 采全（含函数级 import）。
* **importers**：在代码里（`ast.Name`，排除定义模块自身）引用该名字的模块数。字符串/文档串里的出现**不计**
  —— 这条规则本步抓到了 §4 的一个错误，见 §6。
* **closure**：从给定根名出发、在同文件内按模块级定义做传递闭包，再记录跨模块的外部依赖。

复现命令（只读，不改工作树）：

```
py - <<'EOF'
# 见本文件 §0 描述：ast 遍历 src/threat_report_agent，输出 def/kind/importers/drags-in/closure
EOF
py scripts/check-import-graph.py            # 报告
py scripts/check-import-graph.py --strict   # 门禁
```

---

## 1. 基线事实（全部实测，供后续引用）

| 事实 | 实测值 |
|---|---|
| `emulation/` 是否 import `models` | **0 处**。`emulation/` 四个模块的包内 import 只有：`emulation.emulation_plan`、`emulation.policy`、`emulation.vb6_runtime_shim`、`facts.dataflow`、`facts.thread_start`、`static.static_analysis`。所以 `emulation -> models` 是**新边**，必须登记（与设计 §5.3 一致）。 |
| `investigation/` 是否 import `tools.tool_execution` | **0 处**。`tools` 这条边**没有先例**，不能用"已有先例"辩护，只能登记。 |
| `emulation/` 已有的、3.2 未列出的边 | **`emulation.emulation_plan -> static.static_analysis`**（3 个名字：`pe_slice_at_rva`、`recover_static_xor_configs`、`unique_thread_function_starts`）。emulation 行允许列写的是 contracts/facts/worker 端口，**static 不在里面**。真正存在的先例是 `static`，不是 `tools`。 |
| `investigation -> emulation` 是否已存在 | **是，两条**：`investigation.investigation -> emulation.controlled_emulation`（取 `is_real_simulation_row`）、`investigation.derivation -> emulation.emulation_plan` + `emulation.policy`。另有 `report.reporting -> emulation.controlled_emulation`、`tools.tool_execution -> emulation.{controlled_emulation,emulation_plan,policy}`、`simulation_adapters -> emulation.{policy,vb6_runtime_shim}`。3.2 line 132 允许 investigation 导入 emulation 接口，所以这个方向**合法且已落地**。 |
| `emulation/coordinator.py` 是否存在 | **不存在**（P3.5 要新建）。`emulation/__init__.py` 的 `__all__` 是空元组，无 re-export、无 facade。 |
| **15 个候选成员今天住在哪** | 全部 15 个真实实现都在 **`service.py`**（`AnalysisService`）：`_run_controlled_emulator`(:10032)、`_persist_emulation_result`(:10296)、`_emit_controlled_emulation`(:9637)、`_collect_emulation_inputs`(:9773)、`_run_post_static_emulation`(:9943)、`_run_simulation_window`(:9894)、`_persist_time_static_boundary`(:3593)、`_supporting_seed_static_boundary`(:3676)、`_persist_how_function_entries`(:3862)、`_persist_ready_emulation_actions`(:3926)、`_real_simulation_result_count`(:4144)、`_reverify_how_after_emulation`(:4169)、`_emulation_entry_key`(:9867)、`_gate_for_seed_playbook`(:3568)、`_emulation_fallback_payload`(:14614)。`investigation/derivation.py`、`investigation/persist_how.py`、`task/analysis_task_orchestration.py` 里的是同名 **Protocol 桩**，不是实现。 |
| `contracts.py` 的真实约束 | **不是"仅标准库"**。它 247 行，模块级 import 是 `__future__`、`datetime`、`typing`、**`pydantic`**（`BaseModel`/`Field`/`AwareDatetime`/`ConfigDict`/validators）。所以 operative 的线是"**不许 ORM、不许 service、不许 report**"，而不是字面上的 stdlib-only。ORM 类（`models.py` 那 8 个）绝对不能进 `contracts.py` —— 这一点与任务简报的结论一致，理由需要更正为"pydantic 已在，ORM 才是禁区"。 |
| `ports.py` 的真实约束 | 438 行，模块级 import 只有 `__future__`、`typing`、`contracts.DynamicPlanAction`、`projection_protocols`；`projection_protocols` 只有 stdlib。**零 ORM、零 transport、零 SDK**，与它自己的 docstring 一致。 |
| `emulation/policy.py` 是"纯契约下沉进 emulation"的既有先例 | 311 行，包内 import 只有 `emulation.emulation_plan`。其 docstring 写明它是"从 `simulation_adapters` 里**下沉**出来的纯策略，好让 `investigation/` 不必 import 实现模块就能拿到"。**这是 `SimulationWindowOutcome` 的首选归宿依据。** |

---

## 2. 主表：15 个名字

**目的地代号**（只用这六个）：

* **D1 `contracts.py`** —— 纯类型层。实测门槛：无 ORM / 无 service / 无 report（pydantic 已在此，可接受）。
* **D2 `facts/`** —— 可 import contracts + stdlib。
* **D3 `ports.py`** —— emulation 行明写的"worker/模拟**端口**"，实测零 ORM 零 transport。
* **D4 `emulation/` 自身**（`emulation/policy.py` 或新建模块）—— 同包，**零新边**，有 `policy.py` 先例。
* **D5 `models.py` 原地不动 + 一条登记决定** —— 覆盖全部 8 个 ORM 名。
* **D6 沉不下去**：必须 MOVE 它的定义、或干脆不 import（宿主注入/端口）。**不能靠 re-export 解决。**

### 2.1 便宜可沉的纯类型（5 个）

| 名字 | 定义在 | kind（引用定义行） | drags in | importers（模块数） | 推荐目的地 | 为什么 |
|---|---|---|---|---|---|---|
| `ActionType` | `investigation/investigation.py:922` | 纯枚举 `class ActionType(str, Enum):`（19 个 str 成员） | 定义模块拖 `facts.dataflow`、`facts.thread_start`、`investigation.{behavior_catalog,investigation_protocol,mechanism_completeness,semantic_predicates}`（8,446 行）→ re-export 即 `emulation -> investigation`，禁止 | **5**：`investigation.coordinator`、`investigation.derivation`、`investigation.seed_support`、`service`、`task.analysis_task_orchestration` | **D1**（MOVE 定义 + 原地 `X as X` re-export） | 定义体 19 行、闭包 = 自身、外部依赖 = 只有 `enum.Enum`。全表最便宜的一个。 |
| `InvestigationThreadState` | `investigation/investigation.py:3897` | 纯枚举 `class InvestigationThreadState(str, Enum):`（13 个成员） | 同上 | **4**：`investigation.coordinator`、`investigation.derivation`、`investigation.persist_how`、`service` | **D1** | 同上：闭包 = 自身，外部只有 `enum.Enum`。 |
| `InvestigationEvent` | `investigation/investigation.py:6798` | `@dataclass(frozen=True)`，5 个字段全 `str`/`str \| None`/`tuple[str, ...]` | 同上 | **2**：`investigation.derivation`、`service` | **D1** | 闭包 = 自身，外部只有 `dataclasses.dataclass`。 |
| `PackageEntry` | `intake/intake.py:25` | `@dataclass(frozen=True)`，12 个字段全 stdlib + `size` property | 定义模块拖第三方 **`py7zr`** 与 `zipfile`/`zlib`（7z 解包）→ 不是纯层 | **2**：`service`、`tools.tool_execution` | **D1** | 闭包 = 自身（只 `dataclasses.dataclass`）。`py7zr` 是模块的，不是这个类的，所以 MOVE 而不是 re-export 即可脱开。 |
| `TaskLifecycle` | `task/status.py:15` | 纯枚举 `class TaskLifecycle(StrEnum):`（8 个成员） | 定义模块拖 **`product_certification`**（仅为 `AnalysisClass = AnalysisResultClass` 别名），而它又拖 `investigation.mechanism_completeness` + `mechanism_ready` → re-export 会把 investigation 拖进 emulation | **3**：`service`、`task.limitations`、`task.task_runner` | **D1**（MOVE `TaskLifecycle` + `TASK_TRANSITIONS` + `transition_task` + `InvalidStateTransition`，共 3 个同文件名字、§1 实测闭包 = 3） | 闭包 3 个名字、外部只有 `enum.StrEnum`。**注意 `task/status.py` 的 `AnalysisClass` 别名留在原地**，不要把 `product_certification` 一起带走。 |

### 2.2 纯，但要连闭包一起搬（2 个，互为一体）

| 名字 | 定义在 | kind | drags in | importers | 推荐目的地 | 为什么 |
|---|---|---|---|---|---|---|
| `ActionSpec` | `investigation/investigation.py:954` | **带行为的** `@dataclass(frozen=True)`：`__post_init__` 调 `normalize_target_selector` + `SELECTOR_ALIASES`；`dedupe_key` property 调 `action_scope_from_plan` + `canonical_action_key` | 实测闭包 8 个同文件名字 + 外部 `static.evidence_recovery.{FailureInterpretation, canonical_action_key}`。而 `static/evidence_recovery.py` 自己 import **`sqlalchemy`**、`sqlalchemy.orm.Session`、`models.{Evidence,EvidenceSearchKey}`、`static.evidence_index` | **4**：`investigation.coordinator`、`investigation.derivation`、`service`、`task.analysis_task_orchestration` | **D1**，作为**一个 10 名簇**整体 MOVE | 不是"纯数据类型"而是"纯数据类型 + 两个纯 helper"：簇 = `{ActionSpec, ActionType, InvestigationEvent, InvestigationResult, InvestigationThreadState, GateDecision, action_scope_from_plan, normalize_target_selector}`（8 个 in-module）+ 从 `static/evidence_recovery.py` 搬出 `{FailureInterpretation, canonical_action_key}`（2 个）。**10 个名字一起走才能闭合**；漏掉 `canonical_action_key` 就会把 sqlalchemy 拖进 contracts。 |
| `InvestigationResult` | `investigation/investigation.py:6807` | `@dataclass(frozen=True)`，字段含 `InvestigationThreadState`、`tuple[InvestigationEvent, ...]`、`tuple[ActionSpec, ...]`、`GateDecision` | 同簇；`GateDecision` 在 `investigation.py:3939`（7 行纯 frozen dataclass，闭包 = 自身） | **3**：`investigation.derivation`、`investigation.persist_how`、`service` | **D1**，同簇 | 它的"drags in"完全等于 `ActionSpec` 的簇，所以**和 `ActionSpec` 同一步走，边际成本 ≈ 0**。 |

### 2.3 同包下沉：零新边（1 个，全表最优）

| 名字 | 定义在 | kind | drags in | importers | 推荐目的地 | 为什么 |
|---|---|---|---|---|---|---|
| `SimulationWindowOutcome` | `investigation/derivation.py:206` | `class SimulationWindowOutcome(Protocol):`，4 个成员（`status: str`、`stop_reason: str \| None`、`output_bytes: bytes`、`as_dict()`） | 定义模块 `derivation.py` 拖 **`sqlalchemy`**、`sqlalchemy.orm`、`models` 和 10 个 investigation 模块 → re-export 是全表最贵的非法边之一 | **1**：`service`（`service.py:353`） | **D4**：MOVE 进 **`emulation/policy.py`**（或新建 `emulation/result.py`） | 三重理由：(a) 它是**emulation 自己的** `_run_simulation_window` 的返回形状；(b) `investigation.derivation` **已经** import `emulation.policy` 和 `emulation.emulation_plan`，所以搬过去**不新增任何边**，只是换了个名字的既有边；(c) `emulation/policy.py` 正是"纯契约下沉进 emulation 供上层使用"的既有先例。`derivation.py` 原地留 `X as X` re-export 即可。 |

### 2.4 沉不下去的（6 个）—— P3.5-0 的真实工作量在这里

| 名字 | 定义在 | kind | drags in | importers | 推荐目的地 | 为什么 |
|---|---|---|---|---|---|---|
| `fill_protocol` | `investigation/investigation_protocol.py:259` | 普通函数（`evidence` + `existing` → `dict[str, dict[str, object]]`） | **整个模块是纯的**：496 行，模块级 import 只有 `__future__` 和 `collections.abc`。实测闭包 10 个同文件名字（`empty_protocol`、`empty_slot`、`_slots_from_row`(114 行)、`is_empty_marker`、`function_call_names`、`_EMPTY_MARKERS`、`_THREAD_EXIT_APIS`、`_THREAD_LOOP_HINTS`、`_api_tail`），外部依赖 = 只有 `Iterable`/`Mapping` | **4**：`investigation.derivation`、`investigation.investigation`、`report.reporting`、`service` | **D1 或 D2**：把纯函数簇（~130 行）MOVE 到 `contracts.py`，或把**整个 496 行纯模块**MOVE 到 `facts/` 并留 re-export | 它本身便宜（无外部包内依赖），**但它住在 `investigation/` 这个名字下**，而 emulation 行不认 `investigation`。所以"re-export 就行"是错的；必须把定义搬出 investigation 的名字空间。这是 §5 处方里"13 个 investigation 契约名下沉"中**唯一一个真正配得上"下沉"**的。 |
| `_scoped_investigation_action_key` | `investigation/seed_support.py:204` | **私有**函数（11 行），签名 `(action_type: str, selector: Mapping, plan: Mapping \| None) -> str` | 实测闭包 = 自身；外部只有 2 个：`investigation.investigation.action_scope_from_plan`、`static.evidence_recovery.canonical_action_key`。但它所在模块 `seed_support.py` 拖 `investigation.investigation` + `semantic_predicates` + **`models`** | **2**：`investigation.derivation`、`service`（`service.py:326`） | **D1，但必须先 MOVE 那两个依赖，且必须改名公开** | 好消息：`action_scope_from_plan` 和 `canonical_action_key` **正好都在 §2.2 那个 10 名簇里**。所以 10 名簇一落地，这个名字就变成"3 个 stdlib 依赖的纯函数"，边际成本 ≈ 0。坏消息：它是 `_` 私有名，跨模块 import 私有名正是仓库自己记录的缺陷形状（`import-policy.json.known_private_reach`）。要跨模块用就必须**改名公开**（如 `scoped_investigation_action_key`）+ 原地留旧名 alias——这是一条**独立的小决定**，不是纯搬迁。 |
| `recovery_actions_for_gap` | `investigation/investigation.py:1525` | 普通函数（~65 行） | 实测闭包 **17 个**同文件名字：`_attempted_recovery_names`、`_normalize_gap_key`、`_process_seed_has_recoverable_target`、`_dynamic_api_seed_has_recoverable_target`、`_evidence_text_blob`、`_typed_call_api`、`_has_cryptoapi_decode_evidence`、`_has_named_resolved_api`、`completed_investigation_methods` + 6 个常量组（`_PROCESS_EXECUTION_APIS`、`_PROCESS_SEED_TERMS`、`_CRYPTOAPI_DECODE_APIS`、`_DYNAMIC_API_SEED_TERMS`、`_HTTP_TRANSPORT_SEED_TERMS`）+ `ActionType`。外部：`semantic_predicates.normalize_api_symbol`、`emulation.controlled_emulation.is_real_simulation_row`、`types.SimpleNamespace` | **3**：`investigation.derivation`、`investigation.loop_path`、`service` | **D6**：不能靠 re-export；要么整簇 17 名 MOVE，要么让 coordinator 不调用它 | 17 个名字里含 6 个"种子词表"常量组，MOVE 出去等于把 investigation 的种子判定面切一块下来——**这已经超出"契约下沉"的范围，是行为边界重划**。注意它今天**已经**引用 `emulation.controlled_emulation.is_real_simulation_row`，说明这条边双向都活了。 |
| `apply_emulation_reverification` | `investigation/investigation.py:1593` | 普通函数（~35 行） | 实测闭包 **87 个**同文件名字（本文件最长的闭包之一）：`verify_mechanism` + `verify_*_mechanism` 9 个 specialist + `MechanismVerification` + `completed_investigation_methods` + `recovery_actions_for_gap` + 一整组 `_ENVIRONMENT_GUARD_*`/`_PROCESS_SEED_*`/`_xor_*` 判定 helper | **1**：`service` | **D6**：**沉不下去**。coordinator 必须通过宿主注入/端口拿到这个行为，不能 import 它 | 87 个名字的闭包 = 整个 specialist 验证器层。**"把 13 个 investigation 契约名下沉到 contracts.py"这条处方对它完全不适用**——它不是契约，是验证器编排。这是 §5 处方与实际形状偏差最大的一个。 |
| `MechanismPlaybookRegistry` | `investigation/investigation.py:3096` | **普通类**（不是数据类型）：500 行 / 9 个成员，`default_playbooks()`（3109→3458，~350 行）逐字构造 playbook 表，另有 `matching`/`fallback`/`best_match`/`by_id`/`behavior_entry`/`digest` | in-module 闭包只有 3 个名字（`ActionType`、`MechanismPlaybook`(20 行 frozen dataclass，3074)），但外部需要 `investigation.behavior_catalog.BehaviorCatalog`（**1,236 行，实测纯 stdlib**）+ `static.evidence_recovery.FailureInterpretation` | **4**：`investigation.derivation`、`investigation.persist_how`、`investigation.seed_support`、`service` | **D6**：不能便宜沉。若一定要沉，是 `{MechanismPlaybook, MechanismPlaybookRegistry, BehaviorCatalog}` ≈ **1,756 行纯代码**整体 MOVE 到 `contracts.py` | 概念上它是 investigation 的，搬到 contracts 是"契约层"扩容；搬到 `emulation/` 则是概念倒置（emulation 拥有 investigation 的 playbook 注册表）。**两个方向都不是"便宜"。** 规模（1,756 行）已经超过 P3.5 本身（1,017 行）。 |
| `PersistHow` | `investigation/persist_how.py:44` | **普通类**：**2,214 行 / 61 个成员**（全 `@classmethod`） | 定义模块 `persist_how.py` 模块级 import：`facts.dataflow`、`facts.thread_start`、**`models`（`Claim`, `new_id`）**、**`report.reporting`（私有名 `_address_lookup_keys`, `_thread_body_from_evidence`，line 36）**、`investigation.semantic_predicates`、`static.static_analysis` | **2**：`investigation.derivation`（line 155）、`service`（line 146） | **D6，且必须避免 import**：coordinator 不得 import `PersistHow`。需要的 2–3 个成员必须**单独提取**成纯函数下沉 | **`import-policy.json.known_violations` 里唯一一条违规就是 `persist_how -> reporting`。** 因此任何 `emulation -> persist_how` 都会把 report 层**传递性**拖进 emulation，而 emulation 行明写禁止 report。**这是全表最贵的一个名字**，且它的模块还在跨模块 import `report.reporting` 的私有名。 |
| `_derivation` | **不是定义** —— 是模块别名：`service.py:364` `from threat_report_agent.investigation import derivation as _derivation` | **模块对象**，不是类/函数/常量 | `investigation.derivation` 本身拖 **`sqlalchemy` + `sqlalchemy.orm` + `models`**、10 个 investigation 模块、`emulation.{emulation_plan,policy}` | **1 个 import 点**（service.py:364），但 service.py 里有 **13 处 `_derivation.<私有名>` 调用**：`:3231 _instruction_access_kind`、`:3237 _reference_access_kind`、`:3295 _global_accesses_from_rows`、`:3305 _derive_investigation_observations`、`:3394/:3403/:3456/:3479/:3500/:3520/:3529 _select_*_seed_rows`、`:3565 _pin_config_consumer_seed_rows`、`:3573 _apply_seed_playbook_gate`、`:3584 _persist_time_seed_result`、`:3684 _supporting_seed_static_boundary`、`:4210 _run_investigation_loop`、`:4555 _static_decode_recovery_from_evidence`、`:8709 _row_own_function_matches` | **D6，且不是"下沉"能解决的** | **它不是一个可以搬的名字。** 它是一个模块对象，用法是 13 次跨模块**私有**调用。前置问题的正确提法是"把这 13 个被调用的行为改成端口/宿主注入"，是**接口设计**，不是"把契约名沉到 contracts"。把它列进"13 个 investigation 契约名"会让人误以为一次 sink 就能解决——实际不能。 |

### 2.5 另案处理：models（8 个）与 tools（3 个）

| 名字 | 定义在 | kind（引用定义行） | drags in | importers（引用模块数） | 推荐目的地 | 为什么 |
|---|---|---|---|---|---|---|
| `AnalysisTask` | `models.py:53` | ORM `class AnalysisTask(Base):` | `sqlalchemy` / `sqlalchemy.orm` | 9 | **D5**：原地不动 + 一条决定 | 这 8 个名字**已经在**共享数据层，问题不是"搬去哪"，而是"`emulation/` 能不能 import `models`"。实测 emulation 今天 **0 次** import models ⇒ 这是**新边**，需要一条**登记决定**。一条决定覆盖全部 8 个。 |
| `Artifact` | `models.py:182` | ORM `class Artifact(Base):` | 同上 | 7 | **D5** | 同上 |
| `ContentBlob` | `models.py:171` | ORM `class ContentBlob(Base):` | 同上 | 3 | **D5** | 同上 |
| `Evidence` | `models.py:227` | ORM `class Evidence(Base):` | 同上 | 8 | **D5** | 同上。**注意**：`ports.py` 里 `Evidence` 的"8 处出现"**全是 docstring 散文**（见 §6），ports 并没有 re-export 它。 |
| `InvestigationActionRecord` | `models.py:690` | ORM `class InvestigationActionRecord(Base):` | 同上 | 4 | **D5** | 同上 |
| `ToolRun` | `models.py:206` | ORM `class ToolRun(Base):` | 同上 | 5 | **D5** | 同上 |
| `new_id` | `models.py:26` | 普通函数（uuid） | 同上（同模块） | 5 | **D5** | 纯 stdlib helper，但把 `new_id`/`utcnow` 单独搬到 contracts 会产生**第二条新边** `models -> contracts`（今天不存在），换不来任何收益。同属那一条决定。 |
| `utcnow` | `models.py:30` | 普通函数（datetime） | 同上（同模块） | 6 | **D5** | 同上 |
| `ToolRunRequest` | `tools/tool_execution.py:86` | pydantic `class ToolRunRequest(BaseModel):`（`frozen=True, extra="forbid"`），依赖同文件 `ToolRunStorageAccess`(:68) | 定义模块拖 **`temporalio`**（activity/workflow/client/common/exceptions）、`pydantic`、`models`、`intake` | **1**：`service`（line 295） | **D3，且不搬**：用 `ports.py` 已有的 `ToolExecutionPort` + `ToolRunRequestView` | 不要从 `tools.tool_execution` 取（拖 temporalio + models）。`ports.py:217` 的 `ToolRunRequestView`（19 字段）是同一形状的地址-only 视图，`ToolExecutionPort.execute/cancel`（`:283`/`:287`）就是这条缝。**唯一缺口见 §5 风险 R2。** |
| `ToolRunResult` | `tools/tool_execution.py:133` | pydantic `class ToolRunResult(BaseModel):` | 同上 | **1**：`service`（line 295） | **D3**：用 `ports.py:242` 的 `ToolRunResultView` | 同上。备选（若确实需要完整 pydantic 模型）：把这 3 个纯 pydantic 类 MOVE 到 `contracts.py`——它们只需 pydantic + stdlib；但这会与端口视图形成**第二个接口面**，违反"一个概念一个 canonical implementation"，所以**不推荐**。 |
| `TemporalToolExecutor` | `tools/tool_execution.py:1195` | 普通类（Temporal 客户端适配器），`execute()`/`cancel()`/`cancel_workflow()` | 同模块：`temporalio` | **2**：`service`、`task.task_runner` | **D6**：**沉不下去**，由宿主注入（设计 §5.2 的 `tool_executor` pin），emulation 只认 `ToolExecutionPort` | 它内部 `Client.connect(...)` + `start_workflow`，是彻头彻尾的 transport 适配器。emulation 行不允许任何 transport。宿主注入是唯一合法形态。 |

---

## 3. 汇总计数

| 分类 | 数量 | 名字 |
|---|---|---|
| **便宜可沉（D1/D2，纯类型/纯枚举）** | 5 | `ActionType`、`InvestigationThreadState`、`InvestigationEvent`、`PackageEntry`、`TaskLifecycle` |
| **纯但要连闭包搬（D1，10 名簇）** | 2 | `ActionSpec`、`InvestigationResult`（+ `GateDecision`、4 个 helper、`static` 侧 2 个） |
| **同包下沉、零新边（D4）** | 1 | `SimulationWindowOutcome` |
| **需要"搬定义"而不是 re-export，但边界清楚（D1/D2）** | 1 | `fill_protocol` |
| **必须先搬依赖、再改名公开（D1）** | 1 | `_scoped_investigation_action_key` |
| **沉不下去（D6）** | 5 | `PersistHow`、`MechanismPlaybookRegistry`、`apply_emulation_reverification`、`recovery_actions_for_gap`、`_derivation` |
| **不是名字、是模块别名（属于上一条）** | （1） | `_derivation` |
| **一条决定覆盖（D5）** | 8 | `AnalysisTask`、`Artifact`、`ContentBlob`、`Evidence`、`InvestigationActionRecord`、`ToolRun`、`new_id`、`utcnow` |
| **端口替代（D3，零搬动）** | 2 | `ToolRunRequest`、`ToolRunResult` |
| **宿主注入（D6，零搬动）** | 1 | `TemporalToolExecutor` |

**Q6 的答案（"只住在 investigation/ 且已被 emulation_plan/controlled_emulation/policy import 的名字"）：零个。**
实测 `emulation/` 四个模块的包内 import 全集是 `emulation.{emulation_plan,policy,vb6_runtime_shim}` + `facts.{dataflow,thread_start}` + `static.static_analysis`。
**没有任何一个 investigation 名字今天已经通过合法边进入 emulation。** 所以不存在"已经合法的同层边"可以利用——每一个名字都是新边。

---

## 4. 对 P3.5-0 意味着什么（最小工作清单）

P3.5-0 的**最小**形态是 **5 个搬动项 + 2 条决定 + 1 次改名**，不是设计 §5 写的"把 13 个名字下沉"：

| # | 项 | 内容 | 覆盖的名字 | 新增边 |
|---|---|---|---|---|
| **M-1** | 10 名纯簇 → `contracts.py` | `{ActionSpec, ActionType, InvestigationEvent, InvestigationResult, InvestigationThreadState, GateDecision, action_scope_from_plan, normalize_target_selector}` 从 `investigation/investigation.py` 搬出；`{FailureInterpretation, canonical_action_key}` 从 `static/evidence_recovery.py` 搬出。旧路径全部 `X as X` re-export | `ActionSpec`、`ActionType`、`InvestigationEvent`、`InvestigationResult`、`InvestigationThreadState`（5 个） | 无（contracts 面向所有人） |
| ~~**M-2**~~ ✅ | `PackageEntry` → `contracts.py` | 1 个 17 行纯 dataclass，`intake/intake.py` 留 re-export | `PackageEntry` | 无 |
| **M-3** | `TaskLifecycle` 簇 → `contracts.py` | `{TaskLifecycle, TASK_TRANSITIONS, transition_task, InvalidStateTransition}`；**`AnalysisClass` 别名与 `product_certification` 留在原地** | `TaskLifecycle` | 无 |
| **M-4** | `fill_protocol` → `contracts.py` 或 `facts/` | 纯函数簇（~130 行）或整个 496 行纯模块；`investigation/investigation_protocol.py` 留 re-export | `fill_protocol` | 无 |
| ~~**M-5**~~ ✅ | `SimulationWindowOutcome` → `emulation/policy.py` | 同包 MOVE，4 成员 Protocol；`investigation/derivation.py` 留 re-export | `SimulationWindowOutcome` | **零新边**（`derivation -> emulation.policy` 已存在） |
| **D-1** | 登记 `emulation -> models` 决定 | `docs/import-policy.json` 的 `recorded_allowed_edges` 已有该机制（现有 3 条：`model.model_gateway->contracts`、`report.revision_writer->models`、`workbench_query->models`）。**注意 `_recorded_allowed_edges_note` 自己写明：门禁今天不读这个键。** 所以这条决定还需要一份决议文档（同 decision (d) 做法） | `AnalysisTask`、`Artifact`、`ContentBlob`、`Evidence`、`InvestigationActionRecord`、`ToolRun`、`new_id`、`utcnow`（8 个） | **1 条新边** |
| **D-2** | 工具执行走端口 + 宿主注入 | coordinator 接收 `ToolExecutionPort`（`ports.py:261`），用 `ToolRunRequestView`/`ToolRunResultView`；`TemporalToolExecutor` 由宿主 pin（设计 §5.2 的 `tool_executor`）；**不 import `tools.tool_execution`** | `ToolRunRequest`、`ToolRunResult`、`TemporalToolExecutor`（3 个） | 无（端口在允许列"worker/模拟端口"里） |
| **D-3** | `_scoped_investigation_action_key` 改名公开 | M-1 落地后它是 3 依赖纯函数，但跨模块用私有名违反仓库自己的 canonical 规则；改名（如 `scoped_investigation_action_key`）+ 原地保留旧私有名 alias | 1 个 | 无 |

**这 5 搬 + 2 决定 + 1 改名 = 清掉 15 个里的 10 个，外加全部 8 个 models 名与 3 个 tools 名（共 21 个名字）。**

### 落地状态（实测，不是计划）

| 项 | 状态 | 实测证据 |
|---|---|---|
| M-5 `SimulationWindowOutcome` | ✅ **已落地** | 同包 MOVE 到 `emulation/policy.py`；`derivation.SimulationWindowOutcome is policy.SimulationWindowOutcome`；全量套件节点集 = 基线 + 环境阻断，无新增。 |
| M-2 `PackageEntry` | ✅ **已落地** | 定义搬到 `contracts.py:251-267`，`intake/intake.py` 用 `X as X` re-export；三条 import 路径同一对象。**这一步动了 2 个"新失败"节点，两个都是 `tests/test_ports.py` 里对 `contracts.py` 的"行号 pin"（`DynamicPlanAction` 141 → 142，因为模块新增了 `from dataclasses import dataclass`）** —— pin 的存在意义就是逼人做这次显式更新，所以按 §7.1 更新 pin 并在 pin 处写下实测原因，全量套件随即回到基线。 |
| **M-1** | ✅ **已落地** | 10 名簇 + 闭包强制的 7 个定义（共 17 个）搬入 `contracts.py`，旧路径全部 `X as X`；13 个 public 名在三条路径上同一对象；新增 2 条合法 `-> contracts` 边、0 环。 |
| **M-3** | ✅ **已落地** | `TaskLifecycle`/`InvalidStateTransition`/`TASK_TRANSITIONS`/`transition_task` 搬入 `contracts.py`，`AnalysisClass` 与另外五个 StrEnum 留原地；`test_ports.py` 的行号 pin 未受影响（集群追加在文件末尾）。 |
| **M-4** | ✅ **已落地** | `fill_protocol` 簇 12 个定义 / 244 行搬入**新**模块 `facts/investigation_protocol.py`。实测：闭包是 241 行而非本节估计的 ~130 行，且留在原地的 `_slot_from_row` 会读被搬走的私有 helper，故整簇搬；6 个 public 名在旧路径 `X as X`。 |
| **D-1** | ✅ **已落地** | 决议文档 + `recorded_allowed_edges` 登记。实测依据：`models` 被矩阵**每一行**漏掉，而 11 个模块已在导入它。**登记不等于强制**——见决议文档 §4。 |
| **D-3** | ⚠️ **部分落地** | 改名公开 + 原地 alias 已做，两个跨模块私有引用已消除（41 → 39，新增 0）。但本行原本要求「先 MOVE 那两个依赖，再改名公开」；M-1 已把 `action_scope_from_plan` 与 `canonical_action_key` 搬进 `contracts.py`，**因此把该函数本身搬进 `contracts.py` 这一步仍然欠着**。 |
| **D-2** | ⏳ **未落地** | `ToolExecutionPort` + 宿主注入未做；**并且 R2 决策（见下节：`ToolRunRequestView` 带 `workflow_id`，还是 `cancel` 直接收 workflow id）尚未做出、也未记录为欠账**——本节要求这条决定「必须在 P3.5-0 里做」。 |

**方法论留痕（M-2 这一轮最重要的产出）：** 新失败**只报数量**时，2 个未知节点差点被当成"能力回归"并把一个结构上干净、行为不变的搬动回滚掉；把失败段落落盘、用 `compare-failure-nodes.py` 按**节点集合**求差之后，两个节点当场有了名字（`test_ports.py` 的两个行号 pin）。基线现在另外记 `environment_blocked`（Docker 引擎停机的 2 个 `test_detection_rule_indicator_correctness` 节点，报错是 `container ... is not running`），使"引擎没起"不再被打印成某一步的回归。

**剩下的 5 个名字沉不下去，必须另立一步（P3.5-0b / P3.5-1）：**
`PersistHow`(2,214 行 + `-> reporting` 违规)、`MechanismPlaybookRegistry`(+`BehaviorCatalog` 1,236 行 + `MechanismPlaybook` 20 行 ≈ 1,756 行)、`apply_emulation_reverification`(87 名闭包)、`recovery_actions_for_gap`(17 名闭包)、`_derivation`(模块别名 + 13 处私有跨模块调用)。

### 让 P3.5-0 大于一轮的名字

按"体积 × 边风险"排序，**任何一个单独出现都足以让 P3.5-0 不能作为一步做完**：

1. **`PersistHow`** —— 2,214 行 / 61 成员；其模块是 `import-policy.json.known_violations` 里**唯一**一条已记录违规（`persist_how -> reporting`）的当事方，还跨模块 import `report.reporting` 的两个**私有**名。不可能搬迁，只能"提取需要的 2–3 个成员 + coordinator 不 import 它"。
2. **`MechanismPlaybookRegistry`** —— 1,756 行纯代码必须整体走，**规模超过 P3.5 本身（1,017 行）**；且两个候选归宿（contracts 或 emulation）在概念上都不干净。
3. **`_derivation`** —— 不是名字，是模块别名 + **13 处 `_derivation.<私有名>` 跨模块调用**。它把"下沉契约"变成"设计端口"，是**另一类工作**。
4. **`apply_emulation_reverification`（87 名闭包）** —— 整层 specialist 验证器的编排，坐实了"不是契约名"。
5. **`ActionSpec`（10 名簇且尾部踩到 sqlalchemy）** —— 边界清楚但**必须一次做对**：漏掉 `canonical_action_key` 就会把 `sqlalchemy` 拖进 `contracts.py`。

---

## 5. 本步发现的三处事实/仪器偏差（必须记录）

**R1（门禁盲区，最高优先级）：`emulation/coordinator.py` 这个名字对 `--strict` 完全不可见。**
`scripts/check-import-graph.py` 的 `--strict` 只对两类失败退出 1（实测 line 290）：**新循环** 与
**`forbidden_edges` 里逐条列出的直接边**（`resolved` 是直接边，line 257-262；`short()` 在 line 108）。
而 `forbidden_edges` 写的是**扁平名**（`controlled_emulation`、`emulation_plan`），靠 `moved_paths` 的
rename 表把 `emulation.controlled_emulation` 归一回扁平名（line 221-242）。
**新建的 `emulation/coordinator.py` 在 `moved_paths` 里没有条目，于是它的 `short()` 是 `emulation.coordinator`，
永远不匹配任何一条 `forbidden_edges`。** 后果：
* `("emulation.coordinator", "reporting")`、`("emulation.coordinator", "service")`、`("emulation.coordinator", "persist_how")`
  **都不在 forbidden 里** ⇒ 一条**直接的** `coordinator -> report.reporting` import 也能让 `--strict` 通过；
* 门禁不做传递闭包 ⇒ `coordinator -> persist_how -> reporting` 同样通过；
* `import-policy.json` 的 `_recorded_allowed_edges_note` 自己承认："`forbidden_edges` 是 deny-list、矩阵没有机器编码，
  所以未列出的边**根本无法被机器检查**"。

**这意味着：P3.5 拿到一个绿色的 `--strict` 不构成任何"层规则未被违反"的证据。** 要么本步给
`forbidden_edges` 补 `("emulation.coordinator", "service"|"reporting"|"models"|"investigation")`，
要么明确在 P3.5 的证据包里写明"门禁对目标模块不可见"。

**R2 决议（P3.5-0 已做，2026-09-24）：选 (b) —— `cancel` 直接收 `workflow_id: str`。** 实测依据（`.scratch/d2-r2-measure.py`）：
* **真正的取消调用点根本不经过端口**：`task/task_runner.py:531` 与 `:640` 都是 `executor.cancel_workflow(workflow_id)`，直接调用实现类，且 id 取自**持久化行**的 `run.environment["workflow_id"]`（`ToolRun` 14 个字段里没有 workflow 列，id 在 `environment` JSON 里）——也就是说调用者手里**从来就是**一个 id 字符串，不是一个 view。
* `tools/tool_execution.py:1234` 的实现是 `await self.cancel_workflow(request.workflow_id)`，即**今天**的 `cancel(request)` 要求 view 上有 `workflow_id`，而 `ToolRunRequestView` 的 18 个字段里没有它 → 端口在取消方向**确实不闭合**（传 view 过去会 AttributeError）。
* `ToolRunRequestView` **含全部 10 个 idempotency 输入**（`task_id`/`artifact_id`/`content_sha256`/`tool_name`/`tool_version`/`parameters`/`max_cpu_seconds`/`max_memory_mb`/`task_queue`/`environment_version` 一个不缺），所以 (a) 在技术上可行；**但选 (a) 会让端口自己承担"canonical JSON + sha256 + `toolrun-` 前缀"这套派生**（`tool_execution.py:112-130`），把实现细节变成接口的第二份真相来源。
* (b) 只改一个方法签名，`execute(view)` 不变，且与端口 docstring 里"cancellation is issued by a DIFFERENT caller ... cancel by workflow id"的既有描述一致 —— 该 docstring 本来就写着取消是按 workflow id 做的。

**以下为决议前的原文（保留为论证记录）：**

`ports.py:283` `execute(request: ToolRunRequestView)`、`:287` `cancel(request: ToolRunRequestView)`，
但 `ToolRunRequestView`（`:217-238`，19 字段）**没有 `workflow_id`**，也没有 `control_task_queue`；
而真实取消路径用的是 workflow id（`service.py` 的取消点"cancel by workflow id"写在 `ports.py:278-280` 的说明里，
真实实现在 `tool_execution.py:1234 cancel_workflow`）。
`workflow_id`/`idempotency_key` 是 `ToolRunRequest` 的 **property**（`tool_execution.py:112`/`:128`），视图里没有。
所以"工具执行改走端口"这条在**执行**方向成立、在**取消**方向今天不闭合。
P3.5-0 必须显式选一个：(a) 给 `ToolRunRequestView` 加 `workflow_id`（改 `ports.py`，P1.2 接口面 +1 字段），
或 (b) `cancel` 直接收 workflow id（改端口签名）。**这是一条必须在 P3.5-0 里做的决定，不是可以顺手带过的实现细节。**

**R3（对既有设计文档的两处更正）：**
* `docs/p35-emulation-coordinator-design-20260922.md` §4 说 `ports.py`"**已经**声明/引用了 `ToolRunRequest`（6 处）、
  `ToolRunResult`（3 处）、`Evidence`（8 处）"，并据此在 §5.2 写"从那里取"。**实测：`ports.py` 里这三个名字的
  代码级出现次数是 0 / 0 / 0** —— 全部出现在 docstring 散文里（如 `:116`、`:219` 的说明文字）。
  `ports.py` 真正提供的是**自己的** `ToolRequestView`/`ToolRunResultView`（`:217`/`:242`，代码级引用在 `:283`/`:287`）。
  §5.2 的处方需要改为"用端口视图"，否则执行者会去找一个不存在的可 import 名字。
* 任务简报与本步都引用"`contracts.py` 只允许标准库"。**实测它已经 import `pydantic`**（247 行 / `BaseModel`、`Field`、
  `AwareDatetime`、validators）。所以"ORM 不能进 contracts"的结论**成立**，但理由要写成
  "contracts 是纯类型层、不许 ORM/service/report"，而不是"只许标准库"——后者是已经被现实突破的措辞。

---

## 6. 最大的风险（一句话）

**最大的风险不是"搬不动"，而是"搬错了却拿到绿灯"**：`emulation/coordinator.py` 这个新模块在
`scripts/check-import-graph.py --strict` 的 deny-list 里没有任何条目，而 `investigation/persist_how.py`
是仓库唯一已记录的层级违规（`-> reporting`，还带两个 `report.reporting` 私有名导入）。
两者叠加的结果是：**P3.5 只要 import 一次 `PersistHow`，就能把 report 层合法地"绿着"拖进 emulation，
而门禁、`known_violations` 和 `recorded_allowed_edges` 三者都不会报警。**
所以 P3.5-0 的验收判据必须包含"门禁对该模块**不可见**"这条显式声明，并在 P3.5 里用**直接边清单**
（而不是 `--strict` 的退出码）来证明没有 `coordinator -> {report, service, investigation, persist_how, tools.tool_execution}`。
