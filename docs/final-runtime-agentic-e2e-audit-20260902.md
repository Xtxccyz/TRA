# Final Runtime Agentic E2E 严格核查（2026-09-02）

依据：`F:\迅雷下载\final-runtime-agentic-e2e-defect-closure-plan.md`。本次核查只使用仓库代码、测试和已有本地验收产物；没有执行样本、动态模拟器或样本网络。

## 裁决

```json
{"status":"BLOCKED","production_ready":false}
```

代码回归已通过，但最终 Runtime/产品门禁仍未通过。合成控制面测试不能替代真实模型、真实工作台链路和真实故障演练。

## 本轮实际验证

| 范围 | 结果 | 证据 |
|---|---|---|
| Python 全量回归 | PASS | `pytest -q`: 391 passed, 1 warning |
| 深度静态参数追踪 | PASS | `tests/test_deep_static_semantics.py` 等聚焦测试 11 passed |
| DSH 工作台单测 | PASS | `npm test`: 24/24 |
| DSH runtime 测试 | PASS | `npm run test:runtime`: 13/13 |
| DSH 类型检查 | PASS | `npm run typecheck` |
| API/Docker 健康 | PASS（环境级） | API `/healthz` 200；Compose 服务运行；实际工作台端口为 3080 |
| Static-only 边界 | PASS（代码/产物） | 未执行样本、动态模拟器或样本网络 |

本轮修复了 `TRACE_API_ARGUMENT` 派生证据的可追溯性：结果锚点现在包含顶层 `function_entry`，并保留规划器显式引用的全部 Evidence ID。该修复不改变静态-only 边界。

## 已有充分证据的能力

- Session-bound 上下文、事件游标等待、跨会话访问防护。
- Failure Contract、脱敏、失败指纹和 retry lineage 的代码与单测。
- Context Budget Manager 的单测级压缩和 completion reserve。
- Capability taxonomy 与受控 `threat_propose_static_action` 后端路径。
- DSH 视图的数据刷新已使用共享事件/有界等待；主 Evidence 查询不带 `task_id`。
- 上传与显式启动的 API 语义、静态安全边界和报告构建回归。

## 仍未完成或未证明的计划门禁

1. **ComHost C1-C4 失败**：`release-artifacts/comhost-runtime-regression.json` 中 C1、C2、C3、C4 均为 `NOT_VERIFIED`；critical mechanism gate 为 `FAIL`。
2. **模型动作未产生有效新证据**：`agent-participation.json` 为 `PARTIAL/FAIL`，3 个动作均 `NO_NEW_EVIDENCE`，没有模型驱动 Mechanism 贡献的有效证据。
3. **三次连续 ComHost 完整成功未满足**：现有运行是 `SUCCEEDED/PARTIAL`，且不满足 C1-C4 及 critical unsupported=0。
4. **真实浏览器闭环未证明**：`release-artifacts/browser-runtime-e2e.md` 与 `round11.2/browser-e2e.json` 为 `NOT PROVEN/BLOCKED`，没有 Upload -> Chat -> Agent -> Action -> Evidence -> Mechanism -> Report 记录。
5. **真实长轮次/分支未证明**：`dsh-long-turn-branch-autopsy.md` 为 `NOT PROVEN`；没有 >=20 分钟任务、跟进消息、切会话、刷新及完成的证据。
6. **真实上下文压力未证明**：`context-window-stress.json` 为 `NOT_PROVEN`；现有 500 事件测试属于 synthetic control-plane，不是模型真实长轮次。
7. **故障注入和恢复未证明**：`round11.2/restart-recovery.json`、`concurrency.json`、`soak-24h.json` 均为 `BLOCKED`；没有 Docker/Worker/Temporal 故障注入、真实重启、生产并发或 24 小时 Soak 证据。
8. **Workspace 浏览器链路未证明**：API root-scoped 解析和 symlink 防逃逸已有，但 `workspace-integration.json` 仅为 `CONFIGURED_API_ONLY`，浏览器链路仍 `NOT_PROVEN`。
9. **最终 Gate 产物过期/阻塞**：`final-runtime-agentic-e2e-gate.json` 为 `BLOCKED`，并记录过期的 `8787` 工作台地址；当前实际监听的是 `3080`。

## 结论

当前可称为“静态证据驱动调查控制面 + 已通过工程回归”，不能称为已完成的 Runtime Agentic 产品。只有在真实模型成功调用并产生可追溯新 Evidence、ComHost C1-C4 通过、三次连续成功、浏览器全链路、长轮次/上下文/故障/重启/并发/Soak 验收全部形成可复核产物后，才能将状态改为 `PASS`。
