# W2/W3 完成与验收记录

更新日期：2026-08-03

本记录只覆盖 Excel 工作表“多智能体的深度逆向应用”中的 W2 与 W3。参考报告不在任何输入、Prompt、知识快照或生成上下文中；它们只能由离线评估流程使用。

| 工作项 | 实现与审查证据 | 状态 |
| --- | --- | --- |
| W2：预设命令目录、四通道 Schema | 严格 Pydantic 合同、冻结预设目录摘要、工具白名单与 LangGraph 编排；`tests/test_platform_contracts.py` | 已完成 |
| W2：Case/Task/Artifact/状态码 | SQLAlchemy 领域模型、受控状态迁移、Artifact 角色与覆盖义务、不可变任务快照 | 已完成 |
| W2：FastAPI/PostgreSQL/对象存储/LangGraph | 版本化 FastAPI API、PostgreSQL Compose 服务、可选本地或 S3/MinIO 内容存储、已编译 LangGraph | 已完成并通过真实容器集成 |
| W2：哈希、Magic/MIME、只读入库、审计 | SHA-256/SHA-1/MD5、文件头优先 MIME、内容寻址哈希复核、只读 ZIP/目录接入、任务审计 API | 已完成 |
| W2：Prompt、工具与资源控制 | 版本/哈希化系统 Prompt、非信任上下文分离、五个独立队列与 Worker 工具白名单、只读根文件系统、CPU/内存/PID 限制与 Ghidra 超时 | 已完成 |
| W3：Ghidra Headless | 固定 Ghidra 12.1.2、JDK 21、Headless 后处理脚本；对 `notepad.exe` 实测成功 | 已完成 |
| W3：PE/脚本/文档载体 | PE 节区/导入/导出；Python AST 与脚本词法解析；PDF、OOXML、OLE 只读载体解析 | 已完成 |
| W3：函数/Xref/CFG | Ghidra 导出函数、调用/Xref、基本块与 CFG 边；写入带函数入口/RVA 锚点的 Evidence | 已完成 |
| W3：函数模糊指纹 | 64 位 SimHash，存为 `function_simhash` Evidence；相似序列距离测试 | 已完成 |
| W3：分诊与静态 Agent 初版 | `TriageAgent` 决定角色/义务；`StaticAnalysisAgent` 消费已登记函数/Xref/CFG Evidence，最多生成十条保守的函数复核 Candidate Claim；Prompt/路由元数据审计 | 已完成 |

## 本轮验证

- `python -m pytest -q`：64 通过。
- `python -m ruff check src tests scripts/verify_ghidra.py`：通过。
- `python -m ruff format --check src tests scripts/verify_ghidra.py`：33 个受控 Python 文件全部通过；样本语料、历史审查快照与第三方 skill 脚本不属于应用 lint 边界。
- `python -m compileall -q src tests scripts/verify_ghidra.py` 和 `node --check src/threat_report_agent/static/app.js`：通过。
- `docker compose -f docker-compose.yml --profile tooling config --quiet`：通过。
- HTTP 冒烟：无害 Python 脚本完成上传、脚本提取、分诊、证据、审计与报告主链路。
- 真实容器链：FastAPI、PostgreSQL、MinIO、Temporal 和 intake/parser/script/document/Ghidra 五个隔离 Worker 均在线运行；五个 Temporal 队列均有 Workflow/Activity poller。
- 真实 Ghidra 服务链：对 Windows 自带 `notepad.exe` 静态分析成功，`pe-parser` 与 `ghidra-headless` 均为 `SUCCEEDED`；产出 519 个函数、2,600 个 Xref、6,512 个 CFG block 和 519 个函数 SimHash。
- 持久化与追溯：MinIO 保留输入与 2,589,734 字节 Ghidra 输出，复算 SHA-256 与 ToolRun 引用一致；PostgreSQL 对 Ghidra 只保留 117 字节摘要，并保存 15,575 条 Evidence 与 14 条 Candidate Claim；三个 Temporal Workflow 均为 `COMPLETED`；当前 38 个审计事件全部通过完整性校验，其中序号 36 为 HMAC-SHA256 任务终态封印，序号 37-38 为同一不可变 Snapshot 的报告生成与重组事件。
- 跨载体实测：合成 ZIP（不含参考报告）同时走通 `static-intake`、`static-script`、`static-document` 和 `static-parser`；20 个 manifest 条目全部只有对象引用，没有内联样本内容；跨队列工具请求被 `TOOL_NOT_ALLOWED_ON_WORKER` 拒绝。
- 报告实测：同一 Snapshot 重组 12 个模块，不重跑分析；保留全部 15,575 个 Evidence ID，Markdown 为 29,252 字节，DOCX 为 46,097 字节且可由 `python-docx` 重新打开。DOCX 下载耗时 0.295 秒。

## 本轮取消、恢复与镜像重建验收

- 最新 API 镜像为 `sha256:dbb934cf5054...`，Ghidra Worker clean build 镜像为 `sha256:7f7d7dbbd504...`。Worker 通过清华 Debian 镜像和 HTTPS GitHub 加速入口完成构建，Ghidra ZIP 仍以官方 SHA-256、唯一顶层目录和 12.1.2 版本目录作硬校验。
- 取消任务 `5e98c1f3-a496-431d-82bd-73b6a932b0fa` 在 Ghidra ToolRun 为 `RUNNING` 时调用公开取消 API，服务端 23.979 秒返回 200。Task 与 ToolRun 分别为 `CANCELLED` 和 `CANCELLED/GHIDRA_CANCELLED`，Temporal 关闭事件为 `WORKFLOW_EXECUTION_CANCELED`，Worker 中无 Java/Ghidra 残留进程；5,021 条审计事件连续、完整性有效并有取消终态 HMAC 封印。
- 恢复任务 `6e9feb66-774f-43e4-9304-611e0cd18dc2` 在 Ghidra Activity 执行中重启唯一 Worker。Temporal 将同一 `execute_static_tool` 调度为 attempt 2 并完成原 Workflow；Task 最终 `SUCCEEDED/PARTIAL`，三个 ToolRun 全部 `SUCCEEDED`，5,030 条审计事件完整且有成功终态 HMAC 封印。

## 运行状态

验证后的 Compose 服务继续运行，演示入口为 `http://localhost:8000`。
真实 PE 任务的 `PARTIAL` 结果只表示未配置主模型而使用确定性报告措辞，
不表示 W2/W3 工具失败。完整机器可读提取与证据链已保留。

## 已知但不虚报为完成的边界

- Worker 已脱离公网、按队列隔离并使用工具白名单，但对象存储仍是桶级凭据，不是单 ToolRun 临时对象授权。
- Analysis Package 已支持导出，但尚无导入/重放入口；Worker 具备 trace 元数据，但尚未完整 Span 化。
- 独立 Audit Sealer/WORM、真实模型调用与 Agent 对抗验证属于已确认的后置硬化/后续阶段，本记录不宣称完成。
