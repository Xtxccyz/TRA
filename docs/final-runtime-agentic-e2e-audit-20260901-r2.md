# Final Runtime Agentic E2E 复核报告（Round 7 收口复审）

审查日期：2026-09-01  
依据：`F:\迅雷下载\final-runtime-agentic-e2e-defect-closure-plan.md`  
方法：读取计划、代码路径、最新验收产物，并重新执行 Python/DSH 核心测试与静态安全检查。未执行样本、未访问样本网络、未调用 flare-emu/Qiling/Speakeasy。

## 最终判定

```json
{"status":"BLOCKED","production_ready":false}
```

当前是“控制面和静态安全边界基本可用、真实产品 Agentic E2E 仍未闭环”。不能因为单元测试或容器健康而宣布计划全部完成。

## 本次复核已确认

| 领域 | 判定 | 证据 |
|---|---|---|
| Static-only 安全边界 | PASS | 当前 Gate 与 runtime acceptance 均保持 `sample_execution=false`、`sample_network_access=false`、未调用动态模拟器 |
| API/数据库/对象存储/Temporal/Worker 健康 | PASS（环境级） | `docker compose ps` 显示 10 个服务运行；`GET http://127.0.0.1:8000/healthz` 返回 200 |
| 失败契约、脱敏、重试 lineage | PASS（代码+单测） | `runtime_contracts.py`、`analysis-failure-contract.json`、`retry-policy.json`；相关回归通过 |
| Session-bound wait、事件游标、跨会话隔离 | PASS（代码+单测） | `analysis/wait` 路径、DSH runtime 13/13、Python runtime contract tests |
| Context Budget Manager | PASS（代码+单测） | `ContextBudgetManager` 具备压缩和 completion reserve；未等同真实长轮次证明 |
| Capability taxonomy | PASS（代码+单测） | API 返回 `model_callable_tools`、`backend_static_action_catalog`、`action_submission_tool`、不可用能力 |
| 受控 ActionProposal 后端路径 | PASS（实现+模拟网关测试） | `threat_propose_static_action` -> session task -> policy/catalog -> static executor -> Evidence；`test_investigation_service.py` 覆盖成功派生证据 |
| ComHost 语义关联器 | PASS（单测） | `derive_static_mechanism_links` 只在同函数/RVA事实共存时生成带 `source_evidence_ids` 的 STATIC_INFERRED 链；HTTP/Shell/ETW verifier 已注册 |
| DSH 前端事件契约 | PASS（静态契约+测试） | 6 个视图移除数据 `setInterval`，统一使用 Context Store 的 session `analysis/wait` 与 `onEvent`；Evidence 查询不再携带 `task_id` |
| 上传与显式启动基本入口 | PASS（真实浏览器记录） | `.scratch/browser-real-e2e-20260901.md` 证明页面加载、批量入口、上传、显式开始分析 |
| 应用级轻量运行时控制面 | PASS（合成验收） | `runtime-control-plane-acceptance-20260901.json`：8/8，包括事件等待、上下文压力、重试分类、应用重启模拟、5 会话并发、短 Soak |

## 仍未满足或未证明

### P0/P1 阻塞项

1. **ComHost C1-C4 真实机制仍未验证**  
   `comhost-runtime-regression.json` 和 `final-runtime-agentic-e2e-gate.json` 仍为：C1/C2/C3/C4=`NOT_VERIFIED`。真实样本目前只观察到 `GetProcAddress`、`CreatePipe`、`CreateProcessW`、`VirtualProtect` 等平面事实，没有足够的 WinHTTP、ETW、精确 patch 或函数指针消费者链。新关联器会拒绝把这些计数升级为机制，这是正确的保守行为，但也意味着 Gate 仍失败。

2. **真实模型动作的有效证据未证明**  
   最近一次真实工作台记录中，自定义模型 `ali/qwen3.7-max` 返回 HTTP 402，系统使用 deterministic fallback；模型规划轮次存在，但模型动作没有产生可归因的新 Evidence，也没有模型驱动 Mechanism 贡献。`agent-participation.json` 仍为 `PARTIAL/NOT_PROVEN`。模拟 HTTP gateway 的单测不能替代真实模型供应商成功调用。

3. **三次连续 ComHost 完整成功未满足**  
   已有 fresh run 为 `SUCCEEDED/PARTIAL`，且只有 1 个已验证机制；计划要求 3 次 fresh run、C1-C4 全部 `SUPPORTED/VERIFIED`、critical unsupported=0。

4. **浏览器完整闭环未满足**  
   浏览器记录只证明页面上传和显式启动；没有证明真实 Chat 意图 -> 模型规划 -> ActionProposal -> 新 Evidence -> Mechanism -> final Report 的完整链路。现有报告为 DRAFT/PARTIAL，模型失败信息也明确出现在限制中。

5. **长轮次/分支、真实 context stress、故障注入、Docker 重启、生产并发和 24h Soak 未满足**  
   `runtime-control-plane-acceptance-20260901.json` 的 8/8 是 synthetic control-plane evidence，明确注明 Docker/Worker 故障、真实样本并发和 24 小时 Soak 未执行。`browser-runtime-e2e.md` 与 `dsh-long-turn-branch-autopsy.md` 仍是 `NOT PROVEN`。

6. **Workspace 浏览器链路未满足**  
   API 的 root-scoped 相对路径解析和 symlink 防逃逸已有代码与单测，但没有浏览器中“workspace list -> import -> attach -> explicit start”的独立通过记录。当前应视为 API 已配置、产品 E2E 未证明。

7. **真实模型供应商配置/余额是外部前提**  
   当前 `.env` 为 `MODEL_CALLS_ENABLED=false`，历史工作台运行的自定义供应商曾返回 402。没有有效供应商响应时，不能把 fallback 的成功动作当模型 Agent 成功。

## 前端旧模式复核结论

- `threat-ui-overview`、`threat-ui-investigation`、`threat-ui-mechanisms`、`threat-ui-sample-timeline`、`threat-ui-evidence`、`threat-ui-report` 均已改为 `onEvent` 驱动。
- `threat-context-store` 使用有界 `analysis/wait`、游标和 AbortController；没有视图级定时器。
- `threat-ui-evidence` 与 `ThreatApiClient.currentEvidence/evidence` 使用 session-bound URL，普通 Evidence 查询 body 不含 `task_id`。
- `threat-brand/client.js` 仍有 500ms scrub 定时器，但它是产品控件清理，不是分析数据轮询；不应误判为业务 polling storm。
- `bindAnalysis(sessionId, taskId)` 仍保留用于“显式绑定历史任务”，这是与普通 current-session Evidence 查询不同的管理操作。

## 测试复跑

```text
Python pytest: 378 passed, 1 warning
ComHost/Investigation focused: 62 passed, 1 warning
DSH npm test: 24 passed
DSH npm run typecheck: passed
DSH npm run test:runtime: 13 passed
DSH manifest/security/legacy-guard/core-guard: passed
Runtime control-plane acceptance: 8/8 PASS (synthetic scope)
Docker Compose: 10 services running; PostgreSQL/MinIO healthy
API /healthz: HTTP 200
Workbench /: HTTP 200 on 127.0.0.1:3080
```

## 结论

本次修改真实关闭了前端事件契约和 ComHost 语义关联代码缺口，也增加了可复核的控制面验收；但计划的最终产品门禁仍不能关闭。必须继续保持 `BLOCKED`，直到有真实模型成功调用、模型动作产生新 Evidence 并进入 Mechanism、ComHost C1-C4 通过、浏览器全链路、三次连续样本成功，以及真实故障/重启/并发/Soak 证据。

本报告不把 fixture、mock gateway、deterministic fallback、合成压力测试或“文件存在”当作真实产品能力证明。
