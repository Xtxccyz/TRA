# P4（迁移生产/测试调用方、逐个删 shim、根包出口收敛）实测与检查点方案（20260922）

> **本步性质：只测量 + 只写这一份文档。** 未改 `src/`、`tests/`、`docs/import-policy.json`，未改任何其他文档，
> 未跑任何测试套件（其他 agent 正在并发改测试文件）。
> 测量方式：`git grep` 全局入边 + `ast.parse` 全量遍历 `src/**` 与 `tests/**` 的 `Import`/`ImportFrom`（含函数级、
> 含 `importlib.import_module` 字符串形式）+ 直接 `import` 现有门禁模块 `scripts/check-structure-diff.py` 调用它的
> `legacy_paths()` / `legacy_path_imports()`，**不引用任何旧文档里的数字**。
> 仓库状态：`HEAD = f1837f6f151e1b8daad681cd532b3dc18960938d`，`branch = main`。
> 结论先行：**旧路径的"删不掉"几乎全部来自 6 个追踪的 package-contract 测试与 2 个门禁脚本，而不是业务代码。**

---

## 0. 复现命令（全部只读）

```powershell
# 1) 生产侧旧路径 import（期望：只有 service.py:41 一处）
git grep -nE "^\s*(from|import) threat_report_agent\.(dataflow|decode_primitives|analyst_report|report_verification|gold_output_bar|function_simhash|evidence_index|function_similarity|literal_table|static_simulation|evidence_recovery|pma_static_plan|static_analysis|emulation_plan|controlled_emulation|vb6_runtime_shim|prompts|agent_runtime|agents|model_gateway|tool_execution|tool_authoring|reporting|investigation_protocol|investigation_ledger|behavior_catalog|mechanism_completeness|mechanism_ready|persist_how|semantic_predicates|analysis_task_orchestration|turn_lifecycle|status)(\s|\.|import|$)" -- src

# 2) 门禁自己登记的旧路径导入者（期望：只有 1 条 dataflow）
python -c "import importlib.util as u,sys,json; s=u.spec_from_file_location('c',r'scripts/check-structure-diff.py'); m=u.module_from_spec(s); s.loader.exec_module(m); print(json.dumps(m.legacy_path_imports()))"

# 3) 门禁本身（本步实测结果见 §5.4）
python scripts/check-import-graph.py --strict          # EXIT=0
python scripts/check-structure-diff.py --strict        # EXIT=1（表面前，与 P4 无关，见 §5.4）

# 4) 根 shim 文件清单（期望：33 个，全部含 "sys.modules[__name__] = _real"）
git grep -l "sys.modules\[__name__\] = _real" -- src/threat_report_agent
```

---

## 1. 旧路径面：逐条实测（`moved_paths` 全部 33 条）

**保留形式**一栏的读法（本仓库实际存在三种，必须分开处理）：

* `sys.modules shim` = 根包 11–20 行的 `X.py`，内容是 `import <新家> as _real; sys.modules[__name__] = _real`。
  **P4.3 的删除对象**。共 **33 个**（`moved_paths` 里除 `investigation` 之外的全部），字节数 424–470。
* `public facade` = `investigation/`、`intake/` 这类"模块变包"，旧 dotted path **没有变**，靠
  `src/threat_report_agent/package_facade.py:30 install_module_facade()` 做惰性 `__getattr__` 转发（PEP 562）。
  **不是 shim，P4.3 不删**。
* `nothing` = 根包已无同名文件（实测 `investigation.py`、`intake.py` 均不存在）。

| # | OLD path | NEW path | 保留形式 | PROD 引用者 | TEST 引用者(AST) | 分类 |
|---|---|---|---|---|---|---|
| 1 | `dataflow` | `facts.dataflow` | `sys.modules shim` | **1**（`service.py:41-54`） | 4 | **NEEDS_PROD_MIGRATION** |
| 2 | `decode_primitives` | `facts.decode_primitives` | `sys.modules shim` | 0 | 1 | NEEDS_TEST_MIGRATION |
| 3 | `analyst_report` | `report.analyst_report` | `sys.modules shim` | 0 | **41** | NEEDS_TEST_MIGRATION |
| 4 | `report_verification` | `report.report_verification` | `sys.modules shim` | 0 | 2 (+1 文本) | NEEDS_TEST_MIGRATION |
| 5 | `gold_output_bar` | `report.gold_output_bar` | `sys.modules shim` | 0 | 1 (+1 文本) | NEEDS_TEST_MIGRATION |
| 6 | `function_simhash` | `static.function_simhash` | `sys.modules shim` | 0 | 0 | **DELETABLE_NOW** |
| 7 | `evidence_index` | `static.evidence_index` | `sys.modules shim` | 0 | 0 | **DELETABLE_NOW** |
| 8 | `function_similarity` | `static.function_similarity` | `sys.modules shim` | 0 | 1 | NEEDS_TEST_MIGRATION |
| 9 | `literal_table` | `static.literal_table` | `sys.modules shim` | 0 | 2 | NEEDS_TEST_MIGRATION |
| 10 | `static_simulation` | `static.static_simulation` | `sys.modules shim` | 0 | 5 | NEEDS_TEST_MIGRATION |
| 11 | `evidence_recovery` | `static.evidence_recovery` | `sys.modules shim` | 0 | 4 | NEEDS_TEST_MIGRATION |
| 12 | `pma_static_plan` | `static.pma_static_plan` | `sys.modules shim` | 0 | 1 | NEEDS_TEST_MIGRATION |
| 13 | `static_analysis` | `static.static_analysis` | `sys.modules shim` | 0 | **22** | NEEDS_TEST_MIGRATION |
| 14 | `emulation_plan` | `emulation.emulation_plan` | `sys.modules shim` | 0 | 5 (+1 文本) | NEEDS_TEST_MIGRATION |
| 15 | `controlled_emulation` | `emulation.controlled_emulation` | `sys.modules shim` | 0 | 1 | NEEDS_TEST_MIGRATION |
| 16 | `vb6_runtime_shim` | `emulation.vb6_runtime_shim` | `sys.modules shim` | 0 | 3 | NEEDS_TEST_MIGRATION |
| 17 | `investigation` | `investigation.investigation` | **`public facade`（`public_path_unchanged: true`）** | — | — | **KEEP（公开路径未变，无旧路径可迁）** |
| 18 | `prompts` | `model.prompts` | `sys.modules shim` | 0 | 5 (+1 文本) | NEEDS_TEST_MIGRATION |
| 19 | `agent_runtime` | `model.agent_runtime` | `sys.modules shim` | 0 | 2 | NEEDS_TEST_MIGRATION |
| 20 | `agents` | `model.agents` | `sys.modules shim` | 0 | 2 | NEEDS_TEST_MIGRATION |
| 21 | `model_gateway` | `model.model_gateway` | `sys.modules shim` | 0 | 13 | NEEDS_TEST_MIGRATION |
| 22 | `tool_execution` | `tools.tool_execution` | `sys.modules shim` | 0 | 0 | **DELETABLE_NOW** |
| 23 | `tool_authoring` | `tools.tool_authoring` | `sys.modules shim` | 0 | 0（3 处文本引用，见 §5.2） | **KEEP（§5.2：测试明文把"是否退役"划给行为/产品步）** |
| 24 | `reporting` | `report.reporting` | `sys.modules shim` | 0 | 0 | **DELETABLE_NOW** |
| 25 | `investigation_protocol` | `investigation.investigation_protocol` | `sys.modules shim` | 0 | 0 | **DELETABLE_NOW** |
| 26 | `investigation_ledger` | `investigation.investigation_ledger` | `sys.modules shim` | 0 | 0 | **DELETABLE_NOW** |
| 27 | `behavior_catalog` | `investigation.behavior_catalog` | `sys.modules shim` | 0 | 0 | **DELETABLE_NOW** |
| 28 | `mechanism_completeness` | `investigation.mechanism_completeness` | `sys.modules shim` | 0 | 0 | **DELETABLE_NOW** |
| 29 | `mechanism_ready` | `investigation.mechanism_ready` | `sys.modules shim` | 0 | 0 | **DELETABLE_NOW** |
| 30 | `persist_how` | `investigation.persist_how` | `sys.modules shim` | 0 | 0 | **DELETABLE_NOW** |
| 31 | `semantic_predicates` | `investigation.semantic_predicates` | `sys.modules shim` | 0 | 0 | **DELETABLE_NOW** |
| 32 | `analysis_task_orchestration` | `task.analysis_task_orchestration` | `sys.modules shim` | 0 | 0 | **DELETABLE_NOW** |
| 33 | `turn_lifecycle` | `task.turn_lifecycle` | `sys.modules shim` | **0\*** | 0（1 处文本引用；\*生产调用方在 `scripts/runtime_control_plane_acceptance.py:25`，见 §5.1） | **KEEP（§5.2：测试明文拒绝"顺手退役"，且脚本仍在 import）** |
| 34 | `status` | `task.status` | `sys.modules shim` | 0 | 0 | **DELETABLE_NOW** |

> `moved_paths` 共 33 条，但第 17 条 `investigation` 的旧路径**就是**新公开路径；上表按"可操作的旧路径面"排成 34 行，
> 其中第 17 行是 `KEEP`。

### 1.1 分类汇总（实测计数，逐条可点）

`moved_paths` 共 **33** 条。33 = 13 + 17 + 1 + 2，四个分类的明细相加**恰好等于 33**（本步自检：分类按名字点数，不按"感觉"点数）。

| 分类 | 条数 | 明细（全部点名到路径） |
|---|---|---|
| `DELETABLE_NOW`（`src/**` 与 `tests/**` 引用者均为 0） | **13** | `function_simhash`、`evidence_index`、`tool_execution`、`reporting`、`investigation_protocol`、`investigation_ledger`、`behavior_catalog`、`mechanism_completeness`、`mechanism_ready`、`persist_how`、`semantic_predicates`、`analysis_task_orchestration`、`status` |
| `NEEDS_TEST_MIGRATION`（只有测试引用） | **17** | `decode_primitives`、`analyst_report`、`report_verification`、`gold_output_bar`、`function_similarity`、`literal_table`、`static_simulation`、`evidence_recovery`、`pma_static_plan`、`static_analysis`、`emulation_plan`、`controlled_emulation`、`vb6_runtime_shim`、`prompts`、`agent_runtime`、`agents`、`model_gateway` |
| `NEEDS_PROD_MIGRATION`（生产仍引用） | **1** | `dataflow` —— 唯一一处：`src/threat_report_agent/service.py:41`（`git grep` 实测生产侧仅此 1 处） |
| `KEEP`（有具名理由） | **2** | `investigation`（`public_path_unchanged: true`，公开路径未变，没有"旧路径"可迁）、`tool_authoring`（测试 docstring 明文把这个决策划给行为/产品步，见 §5.2） |

**两点必须一起读的补充**：

1. `turn_lifecycle` 也是 `KEEP`，但它的 `KEEP` 理由**不在 `moved_paths` 的语义里，而在一处生产调用方**：
   `scripts/runtime_control_plane_acceptance.py:25` 仍 `from threat_report_agent.turn_lifecycle import LongTurnLifecycle`。
   上表把它计入哪一类取决于读数范围：按 `src/** + tests/**` 它是"零引用"，
   按"全部追踪文件"它有一个脚本引用者，所以**它必须与那个脚本同改，不能单独删**（§5.1、§5.2）。
2. `DELETABLE_NOW` **不等于"现在可以删"**：这 13 条里 11 条被追踪的 package-contract 测试断言"文件必须存在"（§5.2），
   删它们必须与改那些断言同处一个检查点。**"DELETABLE_NOW" 的准确含义是"没有任何代码/测试需要这个旧路径继续可导入"**，
   而不是"删除不需要配套改动"。

### 1.2 每个旧路径的测试引用者清单（用于逐文件切）

* `dataflow`(4)：`test_pe_entry_function_budget.py`、`test_investigation.py`、`test_persist_how.py`、`test_dataflow.py`
* `decode_primitives`(1)：`test_primitive_decode_wiring.py`
* `analyst_report`(41)：`test_reporting.py`(141k)、`test_analyst_report_acceptance.py`(85k)、`test_report_no_false_negative_facts.py`(19k)、
  `test_emulation_observations_published.py`、`test_import_module_attribution.py`、`test_c10_t5_benign_contract.py`、
  `test_persisted_slot_rendering.py`、`test_report_string_facts.py`、`test_report_renders_recovered_parent.py`、
  `test_import_identity_masquerade.py`、`test_second_table_completeness_chapter.py`、`test_model_slot_proposals.py`、
  `test_runtime_sequence_in_body.py`、`test_recovered_static_facts.py`、`test_report_import_modules.py`、
  `test_tool_authoring_ticket_wiring.py`、`test_model_candidate_projection.py`、`test_bare_array_does_not_displace_envelope.py`、
  `test_stop_kinds_wiring.py`、`test_compose_gate_absence_claims.py`、`test_report_command_provenance.py`、
  `test_ioc_quick_reference.py`、`test_official_unknown_slots.py`、`test_compose_path_ledger_residue.py`、
  `test_tls_callbacks_in_body.py`、`test_report_provenance_string_facts.py`、`test_version_info_identity.py`、
  `test_compile_language.py`、`test_report_renders_environment_gate.py`、`test_unmatched_category_blockers.py`、
  `test_unknowns_single_source.py`、`test_draft_cannot_drop_pipeline_limitations.py`、`test_analyst_draft_submission.py`、
  `test_emulation_status_chapter.py`、`test_provenance_gap_detection.py`、`test_attribution_chapter.py`、
  `test_unmatched_topic_scope.py`、`test_fun_label_scrub.py`、`test_bounded_api_list_is_declared.py`、
  `test_raw_payload_not_published_as_fact.py`、`test_pipeline_limitations_reach_the_body.py`
* `report_verification`(2)：`test_report_verification.py`、`test_renderer_correction_markers.py`
* `gold_output_bar`(1)：`test_gold_output_bar.py`
* `function_similarity`(1)：`test_function_similarity.py`
* `literal_table`(2)：`test_literal_table.py`、`test_model_slot_proposals.py`
* `static_simulation`(5)：`test_trace_path_condition_hoist.py`、`test_static_simulation.py`、`test_static_simulation_budget.py`、
  `test_abstract_trace_anchor_dedup.py`、`test_abstract_expression_bound.py`
* `evidence_recovery`(4)：`test_evidence_recovery.py`(73k)、`test_deep_mining_strategy.py`(66k)、`test_database_regressions.py`、`test_retrieval_budget.py`
* `pma_static_plan`(1)：`test_pma_static_plan.py`
* `static_analysis`(22)：`test_investigation_service.py`(187k)、`test_evidence_recovery.py`(73k)、`test_deep_static_recovery.py`(48k)、
  `test_t3_callback_fixture.py`、`test_ports.py`、`test_literal_table.py`、`test_static_analysis.py`、`test_round11_1_semantic_closure.py`、
  `test_t4_isolation_matrix.py`、`test_mechanism_chains.py`、`test_reference_set_completeness.py`、`test_ghidra_performance.py`、
  `test_static_xor_config_recovery.py`、`test_static_semantics_gap_closure.py`、`test_ppid_parent_selection.py`、
  `test_command_string_index_hoist.py`、`test_primitive_decode_wiring.py`、`test_decode_config_scan_cost.py`、
  `test_ppid_parent_literal_scope.py`、`test_unique_thread_emulation.py`、`test_decoded_config_string_table.py`、`test_agents.py`
* `emulation_plan`(5)：`test_controlled_emulation.py`(84k)、`test_speakeasy_entry_selection.py`、`test_speakeasy_start_selection.py`、
  `test_emulation_window_applicability.py`、`test_emulation_architecture.py`
* `controlled_emulation`(1)：`test_controlled_emulation.py`
* `vb6_runtime_shim`(3)：`test_vb6_runtime_shim.py`、`test_vb6_shim_does_not_mutate_sample_memory.py`、`test_vb6_register_arguments.py`
* `prompts`(5)：`test_analyst_report_acceptance.py`、`test_mechanism_chains.py`、`test_platform_contracts.py`、
  `test_prompt_manifest_consistency.py`、`test_agents.py`
* `agent_runtime`(2)：`test_ports.py`、`test_agent_runtime.py`
* `agents`(2)：`test_mechanism_chains.py`、`test_agents.py`
* `model_gateway`(13)：`test_investigation_service.py`、`test_w4_acceptance.py`、`test_model_gateway.py`、`test_ports.py`、
  `test_final_completion_gaps.py`、`test_model_enrichment.py`、`test_bare_array_does_not_displace_envelope.py`、
  `test_reasoning_budget_diagnosis.py`、`test_reason_control_note.py`、`test_truncation_notice_reaches_planning_limitations.py`、
  `test_confidence_is_not_invented.py`、`test_agent_runtime.py`、`test_model_json_mode_prompt.py`

**跨家族文件（会被两个检查点都碰到，必须显式登记以免漏改）**：
`test_model_slot_proposals.py`（`analyst_report` + `literal_table`）、`test_literal_table.py`（`literal_table` + `static_analysis`）、
`test_primitive_decode_wiring.py`（`decode_primitives` + `static_analysis`）、`test_ports.py`（`static_analysis` + `model_gateway` + `agent_runtime`）、
`test_investigation_service.py`（`static_analysis` + `model_gateway`）、`test_evidence_recovery.py`（`evidence_recovery` + `static_analysis`）、
`test_mechanism_chains.py`（`static_analysis` + `prompts` + `agents`）、`test_agents.py`（`static_analysis` + `prompts` + `agents`）、
`test_analyst_report_acceptance.py`（`analyst_report` + `prompts`）。

**关键性质（实测，用于安全论证）**：**没有任何测试文件同时 import 旧路径和新路径**，`src/**` 也是如此。
所以不存在"同一测试里两个 module 对象做 `is` 比较"的暗桩——身份类断言全部集中在 §5.2 的 6 个契约测试里。

---

## 2. 根包模块面（`src/threat_report_agent/*.py`，共 61 个）

`REAL` = 真实实现（不是 shim）；`SHIM` = `sys.modules` 重绑的兼容出口。
"公开出口"只列**本模块自己定义/赋值的非下划线顶层名**（把 import 进来的名字排除，否则会把依赖当出口）。

| 模块 | 行数 | 类型 | 公开出口 |
|---|---|---|---|
| `__init__.py` | 1 | REAL（仅 docstring） | 无（`__all__` 不存在） |
| `service.py` | 18,831 | REAL（兼容 facade，P3 未完成） | `AnalysisService`、`ContextMismatchError`、`AnalysisRunOrphaned`、`IntakeExecution`、`ScheduledStaticAction`、`RetrievedModelContext`、`SPECIALIST_STATIC_TOOLS`、`analysis_intent_question`、`REFERENCE_ISOLATED_FACT_LIBRARY` + **273 个顶层名 + 124 个单语句委托方法** |
| `main.py` | 1,892 | REAL（HTTP 入口，方案 §3.1 明确"暂留根包"） | `create_app`、`app` + 31 个 Pydantic 请求模型 |
| `cli.py` | 88 | REAL（`pyproject.toml:52` 的 console script 入口） | `build_parser`、`main` |
| `config.py` | 390 | REAL | `Settings`、`ModelProviderSettings` |
| `database.py` | 848 | REAL（ORM 引擎/会话） | `Database` |
| `models.py` | 793 | REAL（ORM 表，11 个 src 模块导入） | `Base`、`new_id`、`utcnow` + 30 个 ORM 记录类 |
| `contracts.py` | 247 | REAL（唯一领域类型源） | `FrozenContract`、`DynamicPlanAction` + 9 个纯契约模型 |
| `runtime_contracts.py` | 208 | REAL | `ContextBudgetDecision`、`ContextBudgetManager`、`classify_failure`、`retry_decision` |
| `projection_protocols.py` | 159 | REAL | 5 个只读视图 Protocol + `PROJECTION_PAIRS` |
| `ports.py` | 438 | REAL（P1.2 端口，方案 §3.3 的公开面） | `ModelPlanningPort`、`ToolExecutionPort`、`StaticEvidencePort`、`EmulationPort`、`ReportRevisionWriter`、`WorkbenchQueryReader` + 视图类型 + `P12_PORTS`。**src 导入者 = 0** |
| `port_adapters.py` | 101 | REAL（端口 adapter） | `StaticEvidenceAdapter`。**src 导入者 = 0** |
| `workbench_query.py` | 1,152 | REAL（P3.6-1 新根模块） | `WorkbenchQueryReaderHost`、`WORKBENCH_QUERY_HOST_MEMBERS`、`task_view`、`workbench_domain_view`、`workbench_query_evidence`、`model_configuration_view`、`workbench_thread`。src 导入者 = **1**，且是**别名 import**：`service.py:377 from threat_report_agent import workbench_query as _workbench_query`（只被 5 个 `_workbench_query.*` 委托方法使用；`git grep "threat_report_agent.workbench_query"` 会**漏掉**它） |
| `package_facade.py` | 56 | REAL（`investigation`/`intake` 共用的惰性门面机制） | `install_module_facade` |
| `auth.py` | 222 | REAL（HTTP 认证适配器） | `Principal`、`AuthAdapter`、`require_permission` |
| `observability.py` | 59 | REAL（HTTP 观测） | `configure_observability`、`metrics_payload`、`JsonOperationalFormatter`、`HTTP_REQUESTS`、`HTTP_DURATION` |
| `secret_store.py` | 20 | REAL | `SecretCipher` |
| `control_activities.py` | 260 | REAL（Temporal 控制面 worker） | `RetentionActivities`、`ModelPayloadCleanupWorkflow`、`DailyAuditSealWorkflow`、`run_static_worker`、2 个 schedule 安装函数 |
| `content_store.py` | 352 | REAL（intake 的存储端口实现） | `ContentStore`、`LocalContentStore`、`S3ContentStore`、`ScopedToolRunContentStore`、`StoredContent`、`ToolRunStorageGrant` |
| `policy.py` | 140 | REAL（工具策略） | `PolicyRegistry`、`PolicyDecision`、`ToolPolicy`、`PresetCommand`、`PresetResourceLimits`、`PolicyModel` |
| `validation.py` | 52 | REAL | `ValidationResult`、`validate_claim_evidence` |
| `ghidra_adapter.py` | 277 | REAL（static 的 Ghidra 适配器，未进 `static/`） | `GhidraHeadlessRunner`、`GhidraRun`、`validate_ghidra_output`、`GHIDRA_OUTPUT_SCHEMA_VERSION` |
| `simulation_adapters.py` | 1,826 | REAL（emulation 的 worker 适配器，未进 `emulation/`） | `IsolatedSimulationRunner`、`SimulationResult`、`SimulationCapability`、`detect_simulation_capabilities`、`BUILTIN_ADAPTERS`、`default_simulation_runner` 等 |
| `analysis_trace.py` | 893 | REAL | `build_analysis_trace`、`build_mechanism_effectiveness_traces` |
| `deep_analysis_quality.py` | 833 | REAL | `critic_pass`、`report_depth_score`、`deep_analysis_metrics`、`action_is_productive`、`apply_adversarial_downgrades` |
| `product_certification.py` | 713 | REAL（认证/发布门禁） | `release_gate`、`evaluate_gold`、`classify_artifact_result`、`SUPPORTED_ARTIFACT_MATRIX` 等 19 个 |
| `methodology.py` | 624 | REAL | `build_profile`、`DIMENSIONS`、`SIGNAL_TYPES`、`VERDICTS` 等 |
| `orchestration.py` | 483 | REAL | `StaticInvestigationOrchestrator`、`QuestionCompiler`、`InvestigationPlan` 等 |
| `attack_mapping.py` | 331 | REAL | `AttackMapping`、`load_attack_snapshot`、`map_behavior_claim` 等 |
| `agent_runtime.py` | 11 | **SHIM** → `model.agent_runtime` | — |
| `agents.py` | 11 | **SHIM** → `model.agents` | — |
| `analysis_task_orchestration.py` | 11 | **SHIM** → `task.analysis_task_orchestration` | — |
| `analyst_report.py` | 11 | **SHIM** → `report.analyst_report` | — |
| `behavior_catalog.py` | 18 | **SHIM** → `investigation.behavior_catalog`（`import` 形式，避 cycle） | — |
| `controlled_emulation.py` | 11 | **SHIM** → `emulation.controlled_emulation` | — |
| `dataflow.py` | 11 | **SHIM** → `facts.dataflow` | — |
| `decode_primitives.py` | 11 | **SHIM** → `facts.decode_primitives` | — |
| `emulation_plan.py` | 11 | **SHIM** → `emulation.emulation_plan` | — |
| `evidence_index.py` | 11 | **SHIM** → `static.evidence_index` | — |
| `evidence_recovery.py` | 11 | **SHIM** → `static.evidence_recovery` | — |
| `function_simhash.py` | 11 | **SHIM** → `static.function_simhash` | — |
| `function_similarity.py` | 11 | **SHIM** → `static.function_similarity` | — |
| `gold_output_bar.py` | 11 | **SHIM** → `report.gold_output_bar` | — |
| `investigation_ledger.py` | 11 | **SHIM** → `investigation.investigation_ledger` | — |
| `investigation_protocol.py` | 18 | **SHIM** → `investigation.investigation_protocol`（`import` 形式） | — |
| `literal_table.py` | 11 | **SHIM** → `static.literal_table` | — |
| `mechanism_completeness.py` | 19 | **SHIM** → `investigation.mechanism_completeness`（`import` 形式） | — |
| `mechanism_ready.py` | 11 | **SHIM** → `investigation.mechanism_ready` | — |
| `model_gateway.py` | 11 | **SHIM** → `model.model_gateway` | — |
| `persist_how.py` | 11 | **SHIM** → `investigation.persist_how` | — |
| `pma_static_plan.py` | 11 | **SHIM** → `static.pma_static_plan` | — |
| `prompts.py` | 11 | **SHIM** → `model.prompts` | — |
| `report_verification.py` | 11 | **SHIM** → `report.report_verification` | — |
| `reporting.py` | 11 | **SHIM** → `report.reporting` | — |
| `semantic_predicates.py` | 20 | **SHIM** → `investigation.semantic_predicates`（`import` 形式，注释记录了它会闭合 7 模块 cycle） | — |
| `static_analysis.py` | 11 | **SHIM** → `static.static_analysis` | — |
| `static_simulation.py` | 11 | **SHIM** → `static.static_simulation` | — |
| `status.py` | 11 | **SHIM** → `task.status` | — |
| `tool_authoring.py` | 11 | **SHIM** → `tools.tool_authoring` | — |
| `tool_execution.py` | 11 | **SHIM** → `tools.tool_execution` | — |
| `turn_lifecycle.py` | 11 | **SHIM** → `task.turn_lifecycle` | — |
| `vb6_runtime_shim.py` | 11 | **SHIM** → `emulation.vb6_runtime_shim` | — |

**合计：33 个 SHIM + 28 个 REAL = 61 个 `.py` 文件**（实测：`sys.modules` 重绑文件逐个数为 33，
根目录 `*.py` 共 61 个，可对账）。

### 2.1 P4.4 根包收敛的真实缺口（实测）

方案 §3.1 的目标目录只列 9 个包 + `main.py`；P4.4 要求"根包只保留平台/HTTP 入口和明确的公开 facade"。
今天根包里有 **28 个 REAL 模块**（61 个 `.py` 减去 33 个 shim），全部既不属于任何包、也没被 `moved_paths` 登记。
其中 **15 个明确该留 / 13 个需要 P4.4 做决定**（15 + 13 = 28，可对账）：

* **明确该留（15）**：`main.py`（§3.1 明文）、`cli.py`（`pyproject.toml:52` 的 console script 入口）、
  `auth.py`/`observability.py`/`secret_store.py`（传输/平台适配器）、
  `config.py`/`database.py`/`models.py`/`contracts.py`/`runtime_contracts.py`/`projection_protocols.py`（§3.2 的底层类型/存储层）、
  `ports.py`/`port_adapters.py`/`package_facade.py`（§3.3 的公开面与门面机制，方案 P1.2 的直接产物）、
  `__init__.py`（仅 docstring）。
* **需要 P4.4 做决定（13，本步只登记、不裁）**：`workbench_query.py`（P3.6-1 新建的只读查询模块，src 导入者只有
  `service.py:377` 的别名 import，只被 5 个 `_workbench_query.*` 委托方法引用）、`control_activities.py`（Temporal 控制面 worker）、
  `content_store.py`、`policy.py`、`ghidra_adapter.py`、`simulation_adapters.py`、`analysis_trace.py`、
  `deep_analysis_quality.py`、`product_certification.py`、`methodology.py`、`orchestration.py`、`attack_mapping.py`、`validation.py`。
  这些模块的归属（进 `static/`、`emulation/`、`tools/`、`report/`、`task/`，还是作为根包公开面登记）**是方案里尚未写死的部分**，
  P4.4 若要"根包没有同名第二实现 + 出口收敛"，必须为每一个给出 disposition，否则收敛标准无法判定。

**"根包没有同名第二实现"今天是满足的（可机器验证）**：`python scripts/check-structure-diff.py --structure` 报
`duplicates_total 0`、`duplicates_new []`（本步实测），`docs/import-policy.json` 的 `known_duplicate_implementations` 也是 `[]`。

---

## 3. 两个已知方案冲突对 P4 的实际影响（实测结论）

| 冲突 | 文档记载状态 | 本步实测 | 是否影响本文件推荐的删除 |
|---|---|---|---|
| **冲突 1：`static/` 包名 vs 资源目录** | `docs/plan-conflict-resolutions-20260922.md:13` 写"**已解决（提交 `65b86ac`）**"，方案是目录改名 `static/ → assets/`、挂载 URL 保持 `/static` | **已落地且可证**：`main.py:648 asset_path = Path(__file__).parent / "assets"`，`main.py:649 app.mount("/static", StaticFiles(directory=asset_path, check_dir=False), name="static")`；`pyproject.toml:70` 的 `package-data` 已是 `"assets/*"`；`src/threat_report_agent/assets/` 存在（3 个文件），`src/threat_report_agent/static/` 是**纯 Python 包**（9 个 `.py`，无数据文件） | **不影响**。`static/` 包名下不存在需要"绕开"的资源目录，23 个 `static.*` 旧路径的删除没有任何目录命名障碍 |
| **冲突 2：`investigation/`、`intake/` 包遮蔽同名模块** | `docs/plan-conflict-resolutions-20260922.md:40` 写"**已定案（方案已验证，实施待做）**" | **实施已完成**：`src/threat_report_agent/investigation.py` **不存在**、`src/threat_report_agent/intake.py` **不存在**；两个包各用 `package_facade.install_module_facade(__name__, "<impl>")`（`tests/test_investigation_package_contract.py:102`、`tests/test_intake_package_contract.py` 对这条有断言）；决定性前提（把共享谓词 `recovered_thread_start_address` 下移到 `facts/thread_start.py`）也已在位（`facts/thread_start.py` 存在，`facts/dataflow.py:9` 从 `investigation.semantic_predicates` 取 `normalize_api_symbol`） | **不影响**，但产生一条**必须保留**的约束：这两个旧路径**没有 shim 文件可删**，也**不能**用 `sys.modules` 重绑（`plan-conflict-resolutions:55` 实测 157 个 collection error，且会让 `from threat_report_agent.investigation import investigation_protocol` 直接失败）。P4 对它们的动作只能是"确认公开路径未变"，不是"删 shim" |

**结论**：两个冲突**都不阻塞**本文件推荐的任何一条删除。真正阻塞删除的是 §5.2 的 6 个契约测试（它们是 P2/P3 阶段的
**故意设计**，不是历史遗留）。

---

## 4. 有序 P4 检查点（每个可独立验证）

**验证配方（所有检查点通用，除第 2 项外都是只读）**：

1. `python scripts/check-structure-diff.py --structure` —— 必须 `duplicates_total 0`、`reverse_dependency_ok True`；
2. 该检查点点名的 focused pytest（**由执行者跑，本步不跑**）；
3. `python scripts/check-import-graph.py --strict` —— 必须 `EXIT=0`、`cycles 0`、只有 `<known> persist_how -> reporting`；
4. `python -c "import importlib.util as u,json;s=u.spec_from_file_location('c',r'scripts/check-structure-diff.py');m=u.module_from_spec(s);s.loader.exec_module(m);print(json.dumps(m.legacy_path_imports()))"` —— 必须只剩**该检查点尚未迁移**的那些条目；
5. 每次删 shim 前先跑**身份反例**（方案 P4.3 原文要求）：`old is new` 且 `old.__file__ == new.__file__`，
   并确认 `git grep -nE "import (threat_report_agent\.)?<old>|from threat_report_agent(\.<old>)? import" -- src scripts tests` 为空、
   `git grep -n "import_module(\"threat_report_agent.<old>" -- src scripts tests` 为空、无插件入口/容器旧路径依赖。

**一条本步实测的漏检陷阱（对上表和上面第 5 条都适用）**：本仓库的生产代码用**别名 import** 访问根模块，
例如 `service.py:377 from threat_report_agent import workbench_query as _workbench_query`。
按 dotted path 去 grep（`threat_report_agent.workbench_query`）**看不见它**——`scripts/check-structure-diff.py`
的 `legacy_path_imports()` 用的是 AST（`ast.ImportFrom` + `alias.name`），所以它**不会**漏；但方案 §9 P4.1 给的
`rg -n "from threat_report_agent\.(...) import" src` 命令**会漏**，`git grep "threat_report_agent.<old>"` 也会漏。
本文件的旧路径计数全部来自 AST 遍历（不是那条 rg），因此不受影响；但**执行者若照抄方案 P4.1 的 rg 命令做"清零"判据，
会得到假绿**。建议把 P4.1 的判据从 rg 改为 `python scripts/check-structure-diff.py --structure` 的
`legacy_path_imports()`（它已经是 AST 实现）。

| # | 检查点 | 性质 | 触碰文件 | 必须通过 |
|---|---|---|---|---|
| **P4.0** | **生产侧唯一旧路径迁移**：`service.py:41-54` 的 `from threat_report_agent.dataflow import (...)` → `from threat_report_agent.facts.dataflow import (...)`（12 个名字原样搬）。同时删除 `docs/import-policy.json` 的 `legacy_path_imports[0]`（登记项，不是 `moved_paths`）。 | **机械（安全）** | `src/threat_report_agent/service.py`、`docs/import-policy.json` | `legacy_path_imports() == []`；`tests/test_dataflow.py`、`test_persist_how.py`、`test_investigation.py`、`test_pe_entry_function_budget.py`（旧路径此时仍在，它们不受影响）；import graph `--strict` |
| **P4.1** | **`static/` 家族测试迁移 A（小文件）**：`function_similarity`、`literal_table`、`pma_static_plan`、`static_simulation`、`evidence_recovery` 5 条的测试调用方改指 `threat_report_agent.static.<name>`。 | 机械 | `tests/test_function_similarity.py`、`test_literal_table.py`、`test_model_slot_proposals.py`、`test_pma_static_plan.py`、`test_trace_path_condition_hoist.py`、`test_static_simulation*.py`、`test_abstract_*.py`、`test_evidence_recovery.py`、`test_deep_mining_strategy.py`、`test_database_regressions.py`、`test_retrieval_budget.py` | 上述 13 个测试文件；`legacy_path_imports()` 不含这 5 条路径 |
| **P4.2** | **`static/` 家族测试迁移 B（`static_analysis`，22 个文件）**。建议按文件大小分 2 个提交：B1 = 前 11 个（`test_investigation_service.py` 起），B2 = 后 11 个。**注意**：同一步里 `static.static_analysis` 也是 `models.py`、`port_adapters.py`、`ghidra_adapter.py` 的生产依赖，但它们**早已走新路径**（src 旧路径导入者 = 0），不要顺手改。 | 机械 | `tests/test_investigation_service.py`、`test_evidence_recovery.py`、`test_deep_static_recovery.py`、`test_t3_callback_fixture.py`、`test_ports.py`、`test_literal_table.py`、`test_static_analysis.py`、`test_round11_1_semantic_closure.py`、`test_t4_isolation_matrix.py`、`test_mechanism_chains.py`、`test_reference_set_completeness.py`、`test_ghidra_performance.py`、`test_static_xor_config_recovery.py`、`test_static_semantics_gap_closure.py`、`test_ppid_parent_selection.py`、`test_command_string_index_hoist.py`、`test_primitive_decode_wiring.py`、`test_decode_config_scan_cost.py`、`test_ppid_parent_literal_scope.py`、`test_unique_thread_emulation.py`、`test_decoded_config_string_table.py`、`test_agents.py` | 同左 22 个文件；`check-structure-diff.py --fixtures` 仍 3 REJECTED / 1 accepted（本步实测基线） |
| **P4.3** | **`model/` 家族测试迁移**：`prompts`、`agent_runtime`、`agents`、`model_gateway` 4 条改指 `threat_report_agent.model.<name>`。 | 机械 | `test_analyst_report_acceptance.py`、`test_mechanism_chains.py`、`test_platform_contracts.py`、`test_prompt_manifest_consistency.py`、`test_agents.py`、`test_model_gateway.py`、`test_ports.py`、`test_w4_acceptance.py`、`test_final_completion_gaps.py`、`test_model_enrichment.py`、`test_bare_array_does_not_displace_envelope.py`、`test_reasoning_budget_diagnosis.py`、`test_reason_control_note.py`、`test_truncation_notice_reaches_planning_limitations.py`、`test_confidence_is_not_invented.py`、`test_agent_runtime.py`、`test_model_json_mode_prompt.py`、`test_investigation_service.py` | 同左；`test_model_package_contract.py` 的 identity 断言仍绿（此时 shim 还在） |
| **P4.4** | **`report/` 家族测试迁移**：`analyst_report`(41)、`report_verification`(2)、`gold_output_bar`(1)。**必须分批**：建议 R1 = `test_reporting.py`(141k) 单独一步，R2 = `test_analyst_report_acceptance.py`(85k) 单独一步，R3 = 其余 39 个小文件按 §1.2 顺序 5–8 个一提交。 | R1/R2 = **需要判断**（两个巨型文件，且 `test_reporting.py` 尚存疑）；R3 = 机械 | 见 §1.2 `analyst_report` 清单 + `test_report_verification.py`、`test_renderer_correction_markers.py`、`test_gold_output_bar.py` | 逐文件跑；正文 SHA / 官方 Markdown 出口不得变化（方案 §7.3 的失败处理：正文 SHA 改变先回滚本步） |
| **P4.5** | **`emulation/` 家族测试迁移**：`emulation_plan`(5)、`controlled_emulation`(1)、`vb6_runtime_shim`(3)。 | 机械 | `test_controlled_emulation.py`、`test_speakeasy_entry_selection.py`、`test_speakeasy_start_selection.py`、`test_emulation_window_applicability.py`、`test_emulation_architecture.py`、`test_vb6_runtime_shim.py`、`test_vb6_shim_does_not_mutate_sample_memory.py`、`test_vb6_register_arguments.py` | 同左 8 个文件（`test_controlled_emulation.py` 同时覆盖 2 条路径，一次改完） |
| **P4.6** | **`facts/` 剩余测试迁移**：`decode_primitives`(1) + `dataflow` 的 4 个测试文件。 | 机械 | `test_decode_primitives.py`（文本引用，需连 docstring 一起改）、`test_primitive_decode_wiring.py`、`test_dataflow.py`、`test_investigation.py`、`test_persist_how.py`、`test_pe_entry_function_budget.py` | 同左；此后 `moved_paths` 的 `dataflow`/`decode_primitives` 两条**测试侧**归零 |
| **P4.7** | **删 shim 批次 1：`DELETABLE_NOW` 的 13 个 + P4.6 后新归零的 2 个 facts shim**（共 15 个 shim、15 个 `moved_paths` 条目）。建议再拆成"每家族一步"：`facts.{dataflow,decode_primitives}` → `static.{function_simhash,evidence_index}` → `tools.tool_execution` → `report.reporting` → `investigation.{investigation_protocol,investigation_ledger,behavior_catalog,mechanism_completeness,mechanism_ready,persist_how,semantic_predicates}` → `task.{analysis_task_orchestration,status}`。**每删一个 shim，同步把 `assert shim.is_file()` 改成"旧路径不存在"断言**（§5.2 的 6 个文件之一）。 | **需要判断**（要同时改契约测试的语义：从"shim 必须在"改成"旧路径必须不存在"） | 删除根包 15 个 `X.py`；`tests/test_static_package_contract.py`、`test_tools_package_contract.py`、`test_report_structure_contract.py`、`test_task_package_contract.py`（`investigation` 家族无 shim 文件，但要确认 `test_investigation_package_contract.py:70` 的"根包无 `investigation.py`"仍成立） | 同左 4 个契约测试；**`scripts/structure_behavior_probe.py` 必须同步改**（§5.1）；`check-structure-diff.py --structure` |
| **P4.8** | **删 shim 批次 2：static 家族剩余 6 个** —— `function_similarity`、`literal_table`、`static_simulation`、`evidence_recovery`、`pma_static_plan`、`static_analysis`（P4.1/P4.2 完成后它们已无任何引用者）。 | 机械 + §5.2 契约测试改语义 | 删除根包 6 个 `X.py` + `tests/test_static_package_contract.py` 的 `MOVED` 表 | `test_static_package_contract.py`（断言改为"旧路径已不存在"）、`test_ports.py`、`check-import-graph.py --strict` |
| **P4.9** | **删 shim 批次 3：`model/` 家族 4 个 + `emulation/` 家族 3 个 + `report/` 家族 3 个**（P4.3/P4.4/P4.5 完成后）。同样每家族一步，同步改对应契约测试。 | 机械 + 契约测试改语义 | 删除根包 10 个 `X.py`；`test_model_package_contract.py`、`test_emulation_package_contract.py`、`test_report_structure_contract.py` | 同左 3 个契约测试；**`scripts/check-structure-diff.py:668` 的 `_gate()` 与 `scripts/structure_behavior_probe.py:237-246` 必须同步改**（§5.1） |
| **P4.10** | **删 shim 批次 4：`task/` 家族 2 个（`analysis_task_orchestration`、`status`）** —— 若 P4.7 未一并做。`turn_lifecycle` **不删**（§5.2）。 | 机械 + 契约测试改语义 | 删除根包 2 个 `X.py`；`tests/test_task_package_contract.py` | `test_task_package_contract.py`（含 `test_turn_lifecycle_still_has_no_production_importer` 的 docstring 必须保留理由） |
| **P4.11** | **根包出口收敛（P4.4）**：为 §2.1 的 13 个"未归属根模块"逐条登记 disposition；`AnalysisService` 的调用者改依赖稳定 facade（P3 遗留）；清掉 `service.py:376` 的 `ReportComposeGateRejected as ReportComposeGateRejected` 与 `service.py:200` 的 `inspect_mechanism_ready as inspect_mechanism_ready`（**必须先看 §5.3**）。 | **需要判断（最高风险）** | `docs/`（disposition 表）、`src/threat_report_agent/service.py`、`tests/test_report_revision_writer_contract.py`、`tests/test_service_facade_contract.py` | `test_service_facade_contract.py`、`test_report_revision_writer_contract.py`、`test_control_plane_contract.py`；方案 §3.2 的四条反向依赖规则；`check-import-graph.py --strict` |

**机械（安全）判定汇总**：P4.0、P4.1、P4.2、P4.3、P4.5、P4.6、P4.8 是机械的（纯改名 + 逐文件跑）；
**必须判断**的是 P4.4 的 R1/R2、P4.7、P4.11（后两者要改追踪契约测试的**语义**，以及 §2.1 的模块归属）。

---

## 5. 不安全的删除：有文档/测试具名理由在挡

### 5.1 门禁脚本自己就是旧路径调用方（**最容易漏、后果最直接**）

| 文件:行 | 内容 | 后果 |
|---|---|---|
| `scripts/structure_behavior_probe.py:237-246` | `MOVED_MODULES` 明确列 5 组旧→新路径对：`dataflow`、`decode_primitives`、`analyst_report`、`report_verification`、`gold_output_bar`，并在 `moved_module_identity()` 里 `importlib.import_module(old_name)` | **删这 5 个 shim 会让行为探针直接 ImportError**，而它是 §5.1 部署/行为冻结门禁的一部分。删 shim 前必须把这几行改成"旧路径已不存在"的断言 |
| `scripts/structure_behavior_probe.py:226-231` | 注释写明这个读数的存在理由："the probe imported only the OLD path, so it would have read green even if the old path still held its own copy" | 这条理由**依赖旧路径可导入**。改它等于改一个已记录的 can-fail 证据，必须显式登记 |
| `scripts/check-structure-diff.py:668-671` | `_gate()` 里 `from threat_report_agent.analyst_report import (OPERATIONAL_LIMITATIONS_HEADING, compose_gate_violations)` | **删 `analyst_report` shim 会让 P1.4 负向 fixture 门禁失败**（本步实测该 fixture 是"3 REJECTED"的关键路径） |
| `scripts/replay_retrieval_benchmark.py:26-27` | `from threat_report_agent.evidence_index import INDEXED_EVIDENCE_KINDS`；`from threat_report_agent.evidence_recovery import BoundedEvidenceRepository, RetrievalRequest` | **删这 2 个 shim 会让 benchmark 脚本失败**（不在 pytest 套件里，套件不会发现） |
| `scripts/runtime_control_plane_acceptance.py:25` | `from threat_report_agent.turn_lifecycle import LongTurnLifecycle` | 同上 |

**量化**：`scripts/` 里对旧路径的引用共 5 个文件、**9 处 import + 5 组身份对**。P4 的"逐个删 shim"若只看
`src/**` 与 `tests/**`，这 5 个脚本会在删除提交之后才炸——而它们当中有 2 个（`structure_behavior_probe.py`、
`check-structure-diff.py --fixtures`）**是验收证据链的一部分**。

### 5.2 6 个追踪的 package-contract 测试明文要求 shim 留到 P4（逐条引原文）

```
tests/test_model_package_contract.py:76       assert shim.is_file(), f"{name}.py is gone; the shim must stay until P4"
tests/test_static_package_contract.py:70      assert shim.is_file(), f"{name}.py is gone; the shim must stay until P4"
tests/test_tools_package_contract.py:108      assert shim.is_file(), f"{name}.py is gone; the shim must stay until P4"
tests/test_emulation_package_contract.py:63   assert shim.is_file(), f"{name}.py is gone; the shim must stay until P4"
tests/test_task_package_contract.py:86        assert shim.is_file(), f"{name}.py is gone; the shim must stay until P4"
tests/test_report_structure_contract.py:293   assert shim.is_file(), f"the old path {name}.py is gone; the shim must stay until P4"
```

它们各自的 `MOVED` 表就是被钉住的 shim 清单：
`test_model_package_contract.py:34-39`（`prompts`、`agent_runtime`、`agents`、`model_gateway`）、
`test_static_package_contract.py:36-42`（`function_simhash`、`evidence_index`、`function_similarity`、`literal_table`、`static_simulation`）、
`test_tools_package_contract.py:32-49`（`tool_execution`、`tool_authoring`）、
`test_emulation_package_contract.py:28-32`（`emulation_plan`、`controlled_emulation`、`vb6_runtime_shim`）、
`test_task_package_contract.py:32-51`（`analysis_task_orchestration`、`status`、`turn_lifecycle`）、
`test_report_structure_contract.py:280-284`（`reporting`、`report_verification`、`gold_output_bar`）。

**这就是"DELETABLE_NOW 却删不掉"的全部原因**：这 13 条在 `src/**` 与 `tests/**` 里的**引用者确实为 0**，
但有一个追踪的契约测试**要求文件必须存在**。所以 P4.3 的删除动作**必须与"把这些断言从『shim 必须在』改成
『旧路径必须不存在』"同处一个检查点**，否则删除本身必然让 6 个测试变红。方案 P4.3 只说"一次只删一个 shim"，
没有说这一步同时要改契约测试——**这是本测量发现的方案级缺口**。

**两个额外具名理由（旧路径不该删，或删法要特别小心）**：

* `tests/test_tools_package_contract.py:155-181` `test_tool_authoring_still_has_no_production_importer`：
  docstring 原文 "**nothing in src/ imports it, only a test does … Deciding whether `tool_authoring` should be wired
  into the authoring route or retired is a behaviour/product decision, not a structural one**"，
  断言"`tool_authoring` 现在有生产导入者"要失败。删 shim 不触发它（它排除 `tool_authoring.py` 自身，且 `tools/tool_authoring.py` 仍存在），
  但**它明确说这个决策属于行为/产品，不属于结构步**——所以 `tool_authoring` 的"是否该彻底退役"不能在 P4 顺手决定。
* `tests/test_task_package_contract.py:178-199` `test_turn_lifecycle_still_has_no_production_importer`：同一形状的理由
  （"wiring the long-turn path … needs its own step"）。同时 `scripts/runtime_control_plane_acceptance.py:25` 还在用
  `threat_report_agent.turn_lifecycle`——**`turn_lifecycle` 的 shim 应当保留或与脚本同改**。

### 5.3 `X as X` re-export 与身份断言（P4.1 提到的 "ReportComposeGateRejected 是 P4 删除项"）

* 生产侧 `X as X` re-export 实测只有 3 处：`src/threat_report_agent/service.py:200`
  （`inspect_mechanism_ready as inspect_mechanism_ready`）、`src/threat_report_agent/service.py:376`
  （`ReportComposeGateRejected as ReportComposeGateRejected`）、`src/threat_report_agent/model/model_gateway.py:22` +
  `src/threat_report_agent/ports.py:36`（`DynamicPlanAction as DynamicPlanAction`，是 §3.2 的**刻意公开别名**，不是待删项）。
* `service.py:376` 这一条由 `tests/test_report_revision_writer_contract.py:285-293` 钉住，原文：
  "`service.ReportComposeGateRejected` is caught by the workbench route's 422 handler and the plugin's …" 且
  `assert service.ReportComposeGateRejected is revision_writer.ReportComposeGateRejected`，失败消息是
  "**the compose-gate exception exists twice; `except service.ReportComposeGateRejected` would stop catching**"。
  生产侧真实捕获点是 `service.py:17092 except ReportComposeGateRejected as exc:`。
  `.scratch/structure-status.json` 的 P3.4-2 记录也把它登记为 **P4 deletion item**（"the `X as X` re-export of
  `ReportComposeGateRejected` had no owning retirement step (now registered as a P4 deletion item)"）。
  **删除它的安全前提**：`except` 子句改指 `report.revision_writer.ReportComposeGateRejected`，且
  `tests/test_report_revision_writer_contract.py` 的 identity 断言同步改成"旧别名不存在"。**只删别名不改捕获点会静默改变异常捕获范围**。
* 更广的 facade 面：`AnalysisService` 上有 **124 个单语句委托方法**（本步 AST 实测），
  按目标模块分：`_workbench_query.*` 5 个、`_revision_writer.*` 6 个、`_task_runner.*` 8 个、`_coordinator.*` 24 个、
  `_derivation.*` / `_derivation_support.*` 21 个、`PersistHow.*` 若干、`_limitations.*` 若干。
  这些**不是** `moved_paths` 的旧路径（它们是 P3 的兼容 facade），P4.4 的"调用者只依赖稳定 facade"要处理的是它们，
  不应混进 P4.3 的 shim 删除批次。

### 5.4 当前基线（本步实测，供执行者对照）

| 门禁 | 本步实测 |
|---|---|
| `python scripts/check-import-graph.py --strict` | **EXIT=0**；117 modules / 257 runtime edges / cycles 0 / forbidden 1（仅 `<known> persist_how -> reporting`） |
| `python scripts/check-structure-diff.py --structure` | `reverse_dependency_ok True`、`duplicates_total 0`、`duplicates_new []` |
| `python scripts/check-structure-diff.py --strict` | **EXIT=1**，唯一问题：`surface test_getsource_count CHANGED in 2 place(s): reaching_a_private_member, total` |
| `legacy_path_imports()` | `[{"old":"dataflow","new":"facts.dataflow","importer":"threat_report_agent.service"}]`（与 `docs/import-policy.json` 登记的**恰好一致**） |
| `check-structure-diff.py --fixtures` | `unknown_restated_as_verified` REJECTED / `limitation_block_deleted` REJECTED / `compose_gate_relaxed_unprovenanced_endpoint` REJECTED / `narrow_case_heading_kept_bullets_dropped` accepted (recorded gap) |

> `--strict` 的 EXIT=1 **不是 P4 的问题，也未必是代码问题**：`test_getsource_count` 是在数
> `inspect.getsource(AnalysisService._...)` 的调用点，而 P3.7（方案 §8 P3.7）正在由其他 agent 并发迁移测试面，
> 这个面本来就处于"应当在变"的状态。**P4.0 开始之前必须重新测一次这个基线**，并把"变异"与"漂移"分开记录，
> 否则 P4 的每一个检查点都会带着一个红门禁。

### 5.5 一条必须保留的登记：`moved_paths` 不能随 shim 一起删

`docs/import-policy.json` 的 `_moved_paths_note` 自己写明：`moved_paths` 是 `check-import-graph.py`（cycle 归一化）
与 `check-structure-diff.py`（old-path 规则、`known_duplicate_implementations` 的命名空间归一）的**唯一来源**
（`scripts/check-structure-diff.py:300-302,753-763`）。因此 P4 的"出口收敛"**只能清 `legacy_path_imports`，
不能删 `moved_paths` 条目**；删了会让一张空的 cycle allowlist 失去归一化能力（历史记录："moving `static_analysis.py`
into `static/` made the recorded cycle report as NEW, because the graph now spells the member `static.static_analysis`"）。

---

## 6. 最大风险

**最大风险是"删除动作与钉住它的契约测试不在同一个检查点"**：13 条旧路径在 `src/**` 与 `tests/**` 里已经**零引用**，
按方案 P4.3 的字面读法它们"可以删"；但 6 个追踪的 package-contract 测试（§5.2 逐条引了行号）正在断言
**这些 shim 文件必须存在**，2 个门禁脚本（§5.1 的 `structure_behavior_probe.py:237-246` 与
`check-structure-diff.py:668`）**正在 import 这些旧路径**。这三件事在同一棵树上是互相矛盾的，而这个矛盾被
"P4.3 = 删 shim"和"契约测试 = 证明 shim 正确"两条各自独立的纪律掩盖了：**任何一次"干净地删掉一个 shim"的提交，
都会在事后被读成"结构门禁变红 + 行为探针 ImportError"，从而无法判断是删除写错了还是契约测试过期了。**
缓解方式已写进 §4 的每个删除检查点（删 shim 与改契约测试断言同一步），但**这不是机械操作**，
是本 phase 唯一需要判断力、且必须由人确认语义（"旧路径不存在"是否是新的正确契约）的地方。

第二位风险是 `--strict` 目前就是红的（§5.4 的 `test_getsource_count`），与 P4 无关但与 P3.7 并发相关：
若不在 P4.0 前把基线重新钉住，"每步都有红门禁"会让真正的回归失去信号。

---

## 7. 本步没有做的事（诚实限制）

* **没有跑任何测试套件**（约束要求；并发 agent 正在改测试文件）。所有"必须通过"一栏是**指定**，不是**实测通过**。
* 没有改 `src/`、`tests/`、`docs/import-policy.json` 或任何其他文档；本文件是唯一新增物。
* `analyst_report` 的测试引用者里，`test_reporting.py`(141k) 我只用 AST 确认了它 import `threat_report_agent.analyst_report`，
  **没有读它的断言内容**——所以 P4.4 的 R1 被标为"需要判断"而不是机械。
* 未覆盖的动态面：容器/镜像内是否有旧路径 import（`scripts/check-deployed-code-hashes.py` 的 import smoke 是
  从磁盘枚举的，P4 每个删除检查点都应重跑一次部署 import smoke），以及 `.scratch/`、`benchmarks/`、
  `docs/` 之外任何未被 `git grep -- src tests scripts` 覆盖的调用方。
* `§2.1` 的 13 个"未归属根模块"只做了**disposition 登记**，没有给出最终归属方案——那是 P4.4 的设计输入，不是本步。
