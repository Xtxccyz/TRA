# 第一期实现状态

更新日期：2026-08-03

## 已形成闭环

当前代码已经打通：

Artifact 输入、Case、Analysis Task、Content Blob、ToolRun、Evidence、Claim/Relation、Analysis Snapshot 与 Report Revision。

底层分析固定执行全部一期静态模块；报告模块选择只改变 Report Revision 的呈现内容。完整 JSON 分析包不受呈现选择影响。Markdown 人工编辑会创建 MANUAL_EDIT Revision，不会生成或改写 Evidence 与 Claim。

## 已实现能力

| 范围 | 当前实现 |
|---|---|
| 输入隔离 | 任务请求、样本包、背景上下文和知识快照分区固化；API 不提供评测基准报告入口 |
| 安全接入 | 本地文件夹相对路径与符号链接检查；ZIP 路径穿越、重复路径、加密条目、文件数、展开体积和递归深度检查 |
| 静态分诊 | SHA-256/SHA-1/MD5、Magic、熵、字符串、PE 头、节区和导入 |
| 专项模块 | 加密/编码、高熵节区、加载/注入 API、URL/IP/域名、反调试/虚拟化指标 |
| 证据链 | Evidence 绑定 Artifact、Content Blob、ToolRun 与文件偏移或容器内部路径 |
| 结论层 | 原子静态推断 Claim、支持 Evidence、候选 ATT&CK 映射和未知组织归因 |
| 报告 | 全模块 JSON/Markdown/DOCX/PDF；同 Snapshot 重组；不可变人工编辑版本；人类报告按 Evidence 分组且保留稳定引用，机器 trace 保留全部 Evidence ID |
| 展示 | 样本提交、四通道清单、任务状态、组件、Claim、Evidence 跳转和报告编辑 |
| 部署 | FastAPI、PostgreSQL、MinIO、Temporal 与 intake/parser/script/document/Ghidra 五个隔离 Worker 已按 Compose 真实启动并通过 PE、ZIP、脚本、DOCX 端到端验证 |

## 已完成真实部署验收

本轮使用 Windows 自带 `notepad.exe` 经 FastAPI 提交，实际走通
API -> PostgreSQL/MinIO -> Temporal -> 隔离 Ghidra Worker -> Evidence/审计/报告链路。
`pe-parser` 与 `ghidra-headless` 均为 `SUCCEEDED`；Ghidra 产出 519 个函数、
2,600 个 Xref、6,512 个 CFG block 和 519 个函数 SimHash。任务持久化
15,575 条 Evidence 与 14 条 Candidate Claim，当前审计链 38 个事件均通过完整性校验；
序号 36 的任务终态 HMAC-SHA256 封印有效，后续两条事件记录同一不可变 Snapshot 的报告生成与重组。

该任务结果为 `PARTIAL` 的唯一原因是当前未配置主模型，报告采用确定性措辞回退；
这不影响 W2/W3 的确定性静态提取验收。

同一 Analysis Snapshot 已验证无需重跑即可重组 12 个报告模块。完整 Evidence ID
数量保持 15,575，呈现层按类型分组后 Markdown 为 29,252 字节，DOCX 为
46,097 字节并可重新打开编辑。

## 本轮可靠性与可重建性验收

- API 与 Ghidra Worker 已分别部署
  `sha256:dbb934cf5054...` 和 `sha256:7f7d7dbbd504...`。Ghidra Worker
  clean build 通过清华 Debian 镜像和 HTTPS GitHub 加速入口完成，官方
  Ghidra SHA-256 校验保持为硬失败条件。
- 真实取消任务 `5e98c1f3-a496-431d-82bd-73b6a932b0fa` 在 Ghidra 运行中
  取消成功。API、Task、ToolRun、Temporal Workflow 与容器进程树五层状态
  一致，审计链有效并生成取消终态 HMAC 封印。
- 真实恢复任务 `6e9feb66-774f-43e4-9304-611e0cd18dc2` 在唯一 Ghidra
  Worker 重启后由 Temporal 以 attempt 2 自动恢复，同一 Workflow 最终完成，
  三个 ToolRun 全部成功，审计链有效并生成成功终态 HMAC 封印。
- 全量受控代码门禁为 64 个 pytest 全部通过，Ruff check/format、
  compileall、Node 语法和 Compose config 全部通过。

## 未完成但不得降级的范围

1. 模型网关、专长 Agent、结构化 Action Proposal、策略裁决和 LangGraph 调查图尚未进入真实模型运行路径。
2. 解密模块当前识别静态线索，尚未把可确定解码/解密结果递归登记为新 Artifact。
3. 加载链目前覆盖容器包含关系与加载指标，尚未重建函数级父子加载链。
4. 对抗验证当前只有 Claim/Evidence 契约，串行验证 Hook、拒绝记录和冲突 Gate 尚未实现。
5. 受限模型载荷访问、WORM、保留冻结与 Case 证据销毁仍按既定优先级后置。
6. 单 ToolRun 临时对象存储凭据、Analysis Package 导入/重放入口和 Worker
   全量 OpenTelemetry Span 尚未实现。

以上缺口会使受影响任务得到 PARTIAL 或明确 ToolRun 失败，不允许以报告已生成替代 COMPLETE。

## 2026-08-05 Post-Migration Validation

The Docker runtime was rebuilt after moving Docker Desktop WSL data to `D:\DockerDesktop\wsl`.
The current stack uses configurable `CONTAINER_REGISTRY_PREFIX` (defaulting to the reachable
DaoCloud mirror in this environment), and all ten services are running. BuildKit cache was
cleaned to 0 B while project images and PostgreSQL/MinIO volumes were retained.

The latest container acceptance task is recorded in
`docs/w2-w3-final-validation-20260805.md`. It completed the PE, Temporal and Ghidra path with
three successful ToolRuns, 19,183 Evidence records, 14 Candidate Claims, a generated report,
and a valid 3,644-event audit chain. The only PARTIAL reason is the intentionally unconfigured
primary model and deterministic report fallback.

The latest controlled test gate is 87 pytest tests passed, compileall passed, Ruff passed, and
Compose config passed. Deferred items remain explicitly listed below and are not silently
promoted to complete: production Model Gateway calls, adversarial consensus execution,
independent Audit Sealer/WORM, per-ToolRun object grants, and package import/replay.

## 2026-08-05 Directory archive regression closure

The remaining review gap for directory submissions is closed. Directory intake now uses the same
recursive ZIP expansion, parent relation tracking, depth/size/file-count limits and encrypted-entry
gate as direct ZIP submission. Temporal directory mode defers archive expansion to the isolated
intake Worker so local enumeration and Worker expansion cannot duplicate members. The full
regression gate is 87 pytest tests, Ruff, compileall and Compose config all passing. Docker BuildKit
cache is 0 B after the API/static Worker rebuild; project images and PostgreSQL/MinIO volumes remain.

## 2026-08-12 W2-W4 corrective status (superseded for strict review)

The authoritative W2-W4 result is now `docs/w2-w4-completion-validation-20260812.md` plus
`docs/w2-w4-review-addendum-20260812.md`. The controlled gate is 105 pytest tests, Ruff check,
Ruff format check, compileall, the three root fuzzy-hash tools, and Compose configuration.

The W4 baseline now includes real similarity retrieval, auditable OpenAI-compatible and native
Anthropic model routes, TOP-15 deep-function review, embedded child Artifacts, daily audit sealing,
and the public Case archive/evidence purge lifecycle. This remains a development baseline. OIDC/RBAC,
restricted encrypted model-payload retention, independent WORM/Merkle sealing, ATT&CK RAG,
benchmarks, adversarial consensus, and release hardening remain W5-W7 work.

## 2026-08-13 W5 ATT&CK candidate mapping baseline

Added the bounded W5 baseline documented in `docs/w5-attack-mapping-baseline-20260813.md`.
The packaged versioned ATT&CK snapshot is loaded by `attack_mapping.py`; only structured Behavior
Claims with same-Task Evidence can produce candidate mappings. Each analysis with a mappable
behavior creates an auditable `attack-mapping-index` ToolRun, and `behavior_attack` exposes the mapping reason, status, snapshot
version/SHA-256, and supporting Evidence IDs. Full STIX/RAG, benchmark evaluation, and adversarial
consensus remain open and are not claimed complete.

## 2026-08-14 strict remediation

See `docs/w2-w4-strict-remediation-20260814.md` for the current acceptance record. The
remediation adds server-side Principal authorization, production Worker enforcement, REQUIRED
Artifact completion checks, disposal read barriers, task-wide function similarity, Action Proposal
policy audit, Claim validation, bounded static decoding, encrypted model payload storage, and
report approval/publication gates. The repository passes 115 pytest tests. Independent production
WORM/Merkle sealing, OIDC/JWT integration, full recursive PDF/OLE extraction, real dependency
certification, benchmarks, replay and disaster recovery remain release gates and are not claimed
complete.

## 2026-08-17 strict acceptance supersession

The 2026-08-14 paragraph above is historical. The authoritative current record is
`docs/w2-w4-strict-remediation-20260814.md`. Since that note was written, the repository has
closed the remaining W2S/W3/W4 correctness gaps and the regression suite is now 124 tests:

- RS256 OIDC/JWKS validation covers issuer, audience, key id, signature and cache-backed key lookup.
- Case retention freeze blocks evidence purge and model-payload expiry until an Admin releases it.
- Expired model bodies are deleted only after shared storage references are gone; ModelCall metadata and audit events remain.
- Analysis Packages replay from their immutable Snapshot without the database and reject Snapshot tampering.
- Audit seals carry a Merkle root and are checked against the event chain and immutable payload.
- S3/MinIO audit payloads use a dedicated bucket and Object Lock request; ordinary content and model payloads stay in the business bucket.
- Real Docker acceptance was completed earlier with PostgreSQL, MinIO, Temporal, all static Workers and Ghidra 12.1.2. Docker is stopped after acceptance and cleanup must preserve data volumes.

Production-owned OIDC registration, HSM/KMS signing, external WORM certification, W5+ adversarial consensus,
full ATT&CK STIX/RAG, dynamic analysis, benchmark thresholds and disaster-recovery certification remain
explicit future release boundaries.
