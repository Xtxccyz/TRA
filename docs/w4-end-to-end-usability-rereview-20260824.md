# W4 端到端可用性复核

复核日期：2026-08-24

## 结论

原始 `.scratch/w4-end-to-end-usability-audit-20260824.md` 中关于 PDF/OLE 递归、前端 UI 和 Kimi 适配的缺失判断已经过时。当前代码已有文档载体提取后重新进入 `_run_analysis()` 的递归队列、批量上传与 Analysis Trace UI，并通过对应自动化测试；Kimi、Qwen、GLM 等 OpenAI-compatible 供应商复用统一网关协议，不需要单独实现协议分支。

本轮复核实际完成并验证了两项真实缺口：模型 Payload 的自动清理调度、真实样本静态基线。Worker 容灾演练也已执行。样本只经过输入 Gate、解密和静态工具，未执行 PE、脚本、宏、Shell 或动态分析。

## 已完成项

### 自动 Payload 清理

- `ModelPayloadCleanupWorkflow` 通过 Temporal Schedule 注册。
- Schedule ID：`threat-report-agent-model-payload-cleanup`。
- 每日 UTC 03:17 执行，`SKIP` 重叠策略，2 小时 catch-up，Activity 最多重试 3 次。
- Worker 重启后 Schedule 仍存在、未暂停，下一次触发时间可由 Temporal 客户端查询。
- 复核中发现 control-worker 漏注册 `ModelPayloadCleanupWorkflow`，已修复并重建镜像；真实手动触发 Schedule 后 Workflow `COMPLETED`，返回 `{"actor":"retention-worker","disposed":0}`。
- 保留期逻辑继续使用 180 天、Retention Freeze、共享 Blob 引用计数和审计事件；只清除 Payload 引用，不清除 ModelCall 元数据。

### 真实样本基线

新增 `scripts/real_sample_baseline.py`。脚本只调用 HTTP API，输出元数据，不输出样本内容或压缩包密码，并验证任务终态、Evidence/Claim、Trace、审计完整性以及无执行类事件。

对 `D:\\test\\白象_revers_AGENT` 下 6 个加密 ZIP（密码由用户提供）运行结果：

| 指标 | 结果 |
| --- | ---: |
| 样本数 | 6 |
| `SUCCEEDED` | 6 |
| 审计完整性为真 | 6 |
| 未执行样本 | 6 |
| 结果 | 全部 `PARTIAL`，限制已记录 |

所有任务都生成了递归 Artifact、静态 Evidence、行为 Claim、Analysis Trace 和 Markdown 报告。首个样本包含 58 个函数 SimHash 证据；全部样本均经过 Ghidra/静态工具链（适用时）和相似性索引。`PARTIAL` 只表示真实载荷中存在无法识别或未达到目标深度的对象，不代表流程失败。

### Worker 容灾演练

依次重启 `ghidra-worker`、`control-worker`、`api`、`postgres` 和 `minio`，未删除卷。每次重启后容器恢复运行，API `/healthz` 返回 `ok`，PostgreSQL/MinIO 健康检查通过，Temporal Payload Cleanup Schedule 仍可查询。此前发现的 Ghidra 镜像旧版本和 PostgreSQL Relation 约束不一致问题已修复：统一 SQLite/PostgreSQL 对 `EXTRACTED_FROM` 的 Evidence 支撑约束，并使用本地已校验 SHA-256 的 Ghidra 12.1.2 包重建镜像。

## 测试证据

- `pytest -q`：150 passed。
- `python -m ruff check src tests scripts`：通过。
- `python -m compileall -q src tests scripts`：通过。
- 真实白象基线：6/6 PASS。
- Docker Compose 运行态：API、Temporal、控制 Worker、静态工具 Worker、Ghidra Worker、PostgreSQL、MinIO 均恢复。
- Temporal Schedule 真实触发：Workflow `COMPLETED`。

## 仍明确不属于 W4 完成范围

- 外部 GPT/Claude/Qwen/Kimi/GLM 的真实 API 密钥调用尚未在本环境执行；统一网关、结构化输出、超时和降级代码已存在，生产接入仍需供应商凭据和合规批准。
- W5-W7 的多 Agent 对抗式共识、完整 STIX/RAG、动态行为分析不在本轮范围。
- 真实样本基线目前验证流程和可追溯性，不构成检出率或家族归因结论。
- 白象样本中无法识别的二进制载荷会按限制项记录，系统不会将其误报为已完成深度分析。

## Docker 清理

清理应只针对 BuildKit 缓存和悬空镜像，保留 `postgres-data`、`minio-data`、`content-data` 数据卷。禁止使用 `docker compose down -v`。
