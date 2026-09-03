# Final Runtime Agentic E2E 计划严格审查

审查日期：2026-09-01  
依据：`F:\迅雷下载\final-runtime-agentic-e2e-defect-closure-plan.md`  
审查方式：代码核验、现有验收产物核验、Docker/API 状态核验、Python/DSH 测试复跑。未执行样本，不调用动态模拟器，不访问样本网络。

## 最终裁决

**状态：BLOCKED，不能判定为生产就绪。**

当前证据足以证明控制面和静态安全边界的大部分实现存在，但不足以证明计划要求的真实用户闭环：

```text
上传 -> Chat 意图 -> Agent 规划 -> ActionProposal -> 静态工具 -> Evidence
-> Mechanism/Verifier -> 事件回传 -> Report
```

尤其是 ComHost 的 C1-C4 关键机制、模型动作产生有效新证据、三次连续成功、浏览器真实链路、长轮次/上下文压力、故障注入和恢复演练均未通过或未证明。

## 已通过或已有充分实现证据

| 计划项 | 判定 | 证据 |
|---|---|---|
| static-only 边界 | PASS | `release-artifacts/final-runtime-agentic-e2e-gate.json`；`sample_execution=false`、`sample_network_access=false`、`dynamic_emulators_invoked=false`；Compose worker 为只读、丢弃能力、无网络执行工具 |
| API/数据库/对象存储/Temporal/静态 worker 可用 | PASS（运行时健康） | `docker compose ps`：10 个服务运行；`GET http://127.0.0.1:8000/healthz` 返回 200 |
| Failure Contract | PASS（代码+单测） | `release-artifacts/analysis-failure-contract.json` 为 `IMPLEMENTED_AND_TESTED`；`runtime_contracts.py:128-188`；相关 Python 测试通过 |
| 失败根因记录 | PASS（历史故障） | `release-artifacts/comhost-runtime-failure.json` 和 `comhost-runtime-failure-autopsy.md` 将两次历史失败归因到 `DB_FAILURE/evidence_search_keys` LZ4 损坏；fresh run 已不再必然失败 |
| 事件等待协议 | PASS（代码+单测） | `service.py:11267-11345` 的 `workbench_wait_for_analysis_update`；`session-analysis-event-contract.json`；DSH runtime 13/13 通过 |
| 服务器权威 elapsed 字段 | PASS（代码） | `service.py` 状态/进度投影包含 `created_at/started_at/finished_at/elapsed_ms/server_time`；`runtime_contracts.py:188` |
| Context Budget Manager | PASS（代码+单测） | `runtime_contracts.py:18-108`；`context-budget-contract.json` 为 `IMPLEMENTED_UNIT_VERIFIED`；Python 377/377 通过 |
| Capability taxonomy | PASS（代码+单测） | `service.py:11834-11888` 同时返回 `model_callable_tools`、`backend_static_action_catalog`、`action_submission_tool` 和 unavailable 能力；`tool-contract-vNext.json` |
| 受控静态 ActionProposal 路径 | PASS（实现存在） | DSH `threat_propose_static_action`（`threat-tool-provider/src/index.ts:141-170`）和后端校验/持久化/执行路径（`service.py:12198-12320`）存在；只允许闭合静态目录 |
| Session 绑定与跨任务防护 | PASS（代码+单测） | `workbench_query_current_evidence` 从 session 解析 active task；`test_workbench_context_protocol.py` 和 `test_final_runtime_closure.py` 覆盖 foreign bind/IDOR；DSH runtime session isolation 测试通过 |
| Workspace 路径安全 | PASS（API/单测） | `service.py:11348-11420` 拒绝绝对路径、UNC、`..`、symlink escape；`workspace-integration.json` 记录 root-scoped 和 symlink rejection |
| 上传不自动启动、显式启动 | PASS（API/单测） | `service.py:10986-11175`；`test_upload_only_context_then_explicit_static_start` 通过 |
| Retry lineage / duplicate fingerprint suppression | PASS（代码+单测） | `runtime_contracts.py:192-200`；`service.py:435-473`；`retry-policy.json`；对应测试通过 |
| DSH 包、manifest、安全、legacy/core guard | PASS（静态检查） | `npm test` 20/20、`npm run test:runtime` 13/13、`typecheck`、`manifest`、`security`、`legacy-guard`、`core-guard` 均通过 |

## 部分完成或只能算代码级通过

| 计划项 | 判定 | 严格理由 |
|---|---|---|
| Agent ↔ Investigation 集成 | PARTIAL/FAIL | `agent-participation.json` 只有 2 threads、3 accepted model actions；`comhost-c1-c4-agent-evidence-review-20260901.json` 显示 3 个 action 全部失败 `NO_NEW_EVIDENCE`，`successful_actions=0`，因此没有证明模型动作产生有用证据或贡献 Mechanism |
| ComHost 运行时稳定性 | PARTIAL | fresh task 能 `SUCCEEDED`，但 outcome 仅 `PARTIAL`；`comhost-runtime-regression.json` 为 1 verified、197 candidate，C1-C4 全部 `NOT_VERIFIED` |
| 模型路径 | PARTIAL | `model-path-health.json` 的 3 个校准任务模型调用成功，但这是“模型可调用”证据，不等于模型驱动 Investigation 有效；当前 ComHost action 结果仍无有效新证据 |
| Workspace 正式集成 | PARTIAL | API root 已配置（Compose 将 `D:\test` 挂载到 `/workspace:ro`），但 `workspace-integration.json` 明确 `browser_e2e=NOT_PROVEN`；没有证明用户在工作台通过路径完成 import -> attach -> start |
| 上传/附件事务 | PARTIAL | API 在同一事务内持久化 Blob、Artifact、Session context 和审计事件；但没有真实浏览器 ACK -> persisted link -> context revision 的验收产物 |
| 普通工具 task 绑定 | PARTIAL | 模型-facing `threat_query_current_analysis_evidence` 已移除 task_id；但 DSH 前端证据视图仍在 `threat-ui-evidence/client.js:22` 发送 `{task_id: id}`，API client 的 legacy `evidence(taskId, ...)` 仍在 `threat-api-client/src/index.ts:130-135` 发送 task_id。后端与最终工作台契约尚未完全统一 |
| polling 收敛 | PARTIAL/风险未关闭 | wait/event bridge 已有，但 Overview/Evidence/Investigation/Mechanisms/Report 仍分别使用 `setInterval`（Overview 3s，Evidence/Report 4s，Investigation/Mechanisms 3s）。计划要求消除 polling storm；当前只证明了后端 wait，不证明前端真实路径不会重复轮询 |
| Context compaction | PARTIAL | Manager 会截断工具结果和消息窗口，但 `context-window-stress.json` 为 `NOT_PROVEN`；现有 `runtime_control_plane_acceptance.py` 只做 synthetic control-plane stress，不触碰真实 500 events/100 ToolRuns/20k Evidence 链路 |
| Retry policy | PARTIAL | retry 分类、lineage 和重复 fingerprint 抑制已单测验证；`retry-policy.json` 明确 `injection_e2e=NOT_PROVEN`，没有 Docker/Temporal Worker 瞬态故障的真实自动恢复证据 |
| Failure UX | PARTIAL | Report 视图能显示“静态分析失败，暂无报告”（`threat-ui-report/client.js:49`），但没有在浏览器中证明 stage/code/retryability/attempt/last-successful-stage 全部可见，也没有真实失败 UX 产物 |
| Elapsed time truthfulness | PARTIAL | 服务端字段实现正确，但计划要求真实 UI/Agent 使用 server-authoritative elapsed；没有浏览器/长任务证据验证不存在估算耗时 |

## 未完成、失败或未证明的 Gate

### P0/P1 运行时阻塞

1. **ComHost C1-C4 Gate FAIL**：动态/hash API resolution、secure WinHTTP transport、shell output capture、ETW patch 均 `NOT_VERIFIED`。现有平面 API 计数只能是候选证据，不能升级为机制。
2. **模型动作有效性未证明**：模型有调用和 accepted proposal，但 3 个 ComHost action 全部 `NO_NEW_EVIDENCE`；`model_action_useful_evidence` 与 `model_thread_mechanism_contribution` 均 `NOT_PROVEN`。
3. **三次连续成功未证明**：现有 fresh terminal runs 只有两次，且均 `PARTIAL`；计划要求 3 次 fresh ComHost 成功并保持关键机制一致性。
4. **真实浏览器 E2E 未证明**：`release-artifacts/browser-runtime-e2e.md` 明确 `NOT PROVEN`。工作台页面能加载和单测通过，不等于 Upload -> Chat -> Agent -> Action -> Evidence -> Report 通过。
5. **长轮次/分支生命周期未证明**：`dsh-long-turn-branch-autopsy.md` 明确 `NOT PROVEN`；没有 >=20 分钟分析、跟进消息、切换会话、刷新、完成和分支无错误的证据。
6. **上下文窗口压力未证明**：`context-window-stress.json` 的 `context_overflow` 为 null，要求的 500 events/100 ToolRuns/20k Evidence 未在真实链路执行。
7. **故障注入/恢复未证明**：retryable、non-retryable、same-fingerprint 第二次抑制目前只有合成/单元证据；真实 Worker/Temporal/DB 故障注入和重启恢复均缺失。
8. **并发与 Soak 未证明**：`release-artifacts/round11.2/{concurrency.json,soak-24h.json,restart-recovery.json}` 均 BLOCKED；计划要求的并发、重启和 24h soak 没有证据。

### 证据和环境一致性问题

- `final-runtime-agentic-e2e-gate.json` 记录工作台 URL 为 `http://127.0.0.1:8787`、`legacy_3080_url=NOT_CONFIGURED`；当前实际监听端口是 `3080`，`8787` 关闭。这份 Gate 产物已过期，不能作为当前浏览器运行证据。
- 计划要求的 release artifacts 虽然大多存在，但关键文件仍是 `BLOCKED`/`PARTIAL`/`NOT_PROVEN`，文件存在不代表 Gate 通过。
- 当前 `/health` 返回 404，权威端点是 `/healthz`。启动/运维文档若仍使用 `/health`，属于运维契约不一致，但不改变静态分析 Gate 结论。

## 测试复跑结果

```text
Python pytest: 377 passed, 1 warning, 52.45s
DSH npm test: 20 passed
DSH npm run test:runtime: 13 passed
DSH typecheck/manifest/security/legacy-guard/core-guard: passed
Docker Compose: 10 services running; PostgreSQL/MinIO healthy
API /healthz: HTTP 200
DSH / on 3080: HTTP 200
```

这些结果证明工程/单元/集成控制面的一部分，**不**证明最终计划的真实 Agentic E2E Gate。

## 审查结论与下一步门槛

当前不能声称“文档内所有内容已经完成”或“满足最终需求”。应继续保持：

```json
{"status":"BLOCKED","production_ready":false}
```

在下次复审前，至少必须补齐并保存以下可独立复核证据：

1. 修正 DSH 前端 legacy evidence task_id 调用，并重新通过 session-bound 浏览器链路。
2. fresh ComHost 连续 3 次 `SUCCEEDED`，C1-C4 逐条达到 `SUPPORTED/VERIFIED`，且 critical unsupported=0。
3. 至少一个成功的模型 ActionProposal 产生新 Evidence，并被 Verifier/Mechanism 引用。
4. 浏览器真实 Upload -> Chat -> Agent -> Investigation -> Report 记录（包含 session/task/action/evidence/report IDs）。
5. 真实长轮次、context stress、retryable/non-retryable/same-fingerprint、重启、并发、soak 产物。
6. 更新过期 Gate 的端口和时间戳，所有 release artifact 与实际运行保持一致。

本报告是审查产物，不修改既有 Gate，不把未证明项降级为通过。
