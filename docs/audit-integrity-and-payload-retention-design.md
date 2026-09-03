# 审计完整性与受限载荷保留设计

本设计落实 ADR-0026、0027、0028 和 0029。它以 PostgreSQL 为业务元数据和来源关系的权威存储，以 S3 兼容对象存储保存字节内容，以独立签名封存检测篡改；不把运维日志、Trace 或模型自然语言输出提升为证据。

## 交付顺序

本文定义一期正式交付必须满足的最终契约，但不构成当前静态闭环的开发关键路径。当前随主链路实现稳定对象ID、来源关系、基础Audit Event、工具与模型版本和Trace关联；受限载荷全文、细粒度访问、保留与销毁、签名封存、WORM、完整性核验和灾备恢复安排在静态闭环、报告质量和性能基线之后，作为一期正式部署前的硬化工作完成。

## 不变量

1. 每个报告结论可以回溯到其 Claim、Evidence、ToolRun、Artifact 和原始内容摘要。
2. 每次模型调用可回放其脱敏后的实际消息、上下文清单、解析结果和来源对象版本，但正文只能由 Auditor 或应急审计访问者读取。
3. 任何已封存事件、对象摘要或来源关系在被替换、删除或重排后均会在核验中失败。
4. 受限模型正文可按保留策略销毁；其身份、摘要、来源关系、销毁理由和审计封存不随正文消失。
5. 报告进入 APPROVED 前，其 Analysis Snapshot 必须通过完整性核验并已有审计封存。
6. Case的事实基础一期不自动删除；未来Case证据销毁不得改变既有Report Status，并必须显式反映到快照的历史核验状态。

## 审计流

| 审计流 | 承载对象 | 典型事件 |
|---|---|---|
| task:{task_id} | 一次 Analysis Task | Artifact 发现、ToolRun、Evidence、Claim、Relation、Model Call、策略裁决、任务状态 |
| case:{case_id} | 跨任务的 Case | 输入接收、Gate、Report Revision、批准、发布、保留冻结、正文销毁 |
| system | 无法归属单个 Case 的动作 | 策略版本发布、知识快照发布、密钥轮换、完整性核验任务 |

每个事件只写入一个审计流。跨流动作保存稳定对象引用和 trace_id，不试图以数据库写入时间伪造全系统绝对顺序。

## PostgreSQL 记录

audit_stream 保存 stream_id、边界类型与对象、下一序号、最后事件摘要和创建时间。追加事件时，只锁定本流的 head 行，在同一事务内写入 audit_event 与新的 head；不同 Task 因此不会争用全局锁。

audit_event 至少保存：

- event_id、stream_id、sequence、event_type、schema_version、发生时间
- principal 快照、服务身份、授权上下文、前后状态和关联 trace_id
- 目标对象的类型、ID 和版本，及相关对象引用
- 规范事件字节的 prev_event_hash 与 event_hash

事件签名使用 AuditEnvelope v1 的确定性 CBOR 编码；显示与查询可使用派生 JSON，但哈希只针对规范字节计算。所有身份、ID、时间、枚举和值域都在 Schema 中固定，Schema 变更创建新版本，不重写旧事件。

payload_manifest 保存每个大对象的内容摘要、大小、媒体类型、Schema 版本、存储区域、对象版本、加密与安全分级、保留策略版本及正文状态。Artifact、ToolRun、Evidence、Model Call、Report Revision 和审计事件只引用 Manifest，不把大对象复制进 PostgreSQL。

## 对象存储与权限

| 存储区域 | 内容 | 不可变与销毁规则 | 可写主体 |
|---|---|---|---|
| content-blobs | 样本、提取 Artifact、工具原始输出、报告渲染物 | 内容寻址且禁止覆盖；一期不自动到期，未来仅通过Case证据销毁Gate处置 | 受限接入与Tool Worker |
| restricted-audit-payloads | 脱敏后真实模型请求、原始响应及其他受限审计正文 | 加密、内容寻址、禁止覆盖；不使用WORM，以支持归档后180天的正文销毁 | 仅 Model Gateway；保留服务拥有受策略约束的删除权 |
| audit-seals | 签名审计封存、公钥、核验报告 | 启用版本保护和WORM；不含样本或模型正文；一期不自动过期 | 仅 Audit Sealer |

应用 API、Agent、Tool Worker 和普通 Admin 没有 restricted-audit-payloads 的删除权限。正文读取始终经过 API 授权，Auditor 具备常规读取权；其他人必须使用未过期的审计访问授权。对象 URI、平台凭证、解压密码和模型正文不得写入 Operational Log 或 Trace 属性。

## 封存和核验

1. 每个 Audit Event 生成 event_hash = SHA-256(canonical_event_bytes)，规范字节中包含同一流的 prev_event_hash。
2. Audit Sealer 每日按 UTC 收集当天各流的新事件摘要，按 stream_id、sequence 固定排序后生成 Merkle 根、签名、key_id 和时间窗。Task 终态、报告批准和正文销毁还会立即触发一次封存，不等待日终。
3. 封存对象与 PostgreSQL 中的 audit_seal 记录相互引用。私钥只对 Audit Sealer 可见；验签公钥可供 Auditor 和核验服务读取。
4. 完整性核验重新计算保留正文的内容摘要、每条审计流哈希链和相应封存签名。正文已按策略销毁时，核验其 Manifest、销毁事件和销毁前封存，不把“正文不可读”误报为篡改。

核验结果为 VALID、HISTORICAL_VALID、UNSEALED 或 FAILED。只有引用对象均仍可读取且封存有效的 VALID Snapshot 可以进入外部发布 Gate；到期正文已经销毁的历史案件可为 HISTORICAL_VALID，但不能声称可再次取得原始模型正文。

## 保留与销毁

模型受限审计正文默认在 Case 归档后继续保留 180 天。保留冻结存在时不得销毁。到期后，保留服务先写入销毁请求事件，删除所有对象版本和受控副本，再写入结果事件与不可读正文销毁墓碑；后者保留对象摘要、策略版本、执行身份和时间。

原始样本、派生Artifact、ToolRun原始输出和Evidence所依赖内容随Case长期保留，一期不自动到期。未来的Case证据销毁只能针对已归档Case，经Case证据销毁Gate批准后执行，并在执行前列出受影响Task、Analysis Snapshot、Report Revision和Content Blob。完成后保留对象身份、摘要、来源关系和销毁审计；既有报告的APPROVED或PUBLISHED状态不回退，但相关Snapshot进入HISTORICAL_VALID。Content Blob可能由多个Case共享，单Case销毁时先撤销该Case的Artifact、ToolRun和Manifest引用及其访问路径；只有权威关系查询证明全部Case均不存在未处置引用时，保留服务才能物理删除字节。该资格不能以缓存引用计数作为真值。

Case证据销毁Gate只在Case已归档、全部Task处于终态、无保留冻结且影响清单生成后开放。申请人不能复核或执行自身请求；Reviewer以evidence_purge.review核对受影响的报告、快照和共享Content Blob，另一名Admin以evidence_purge.execute授权保留服务撤销引用或回收字节。申请、复核、授权、执行开始、逐对象结果和最终核验均写入Case审计流；生产环境的三个Principal必须不同，单用户演示例外必须显式标记。

保留冻结记录明确的范围、理由、创建人、创建时间、到期时间和策略版本。Reviewer或Auditor可以创建和延期，另一名Admin才可解除；保留服务在任何销毁前实时查询有效冻结，不得依赖缓存。冻结不会改变Auditor、应急审计访问或Case证据销毁Gate之外的任何读取或审批权限。

承载受限正文的备份、灾备副本和缓存必须使用同一或更短的保留窗口，并由部署验收证明其不会在正文销毁后恢复为可读内容。audit-seals 仅保留摘要和签名，因此不适用正文的180天销毁规则。

## 第一阶段验收

1. 修改已封存 Audit Event 的字段、顺序或前序摘要，核验必须为 FAILED。
2. 替换保留期内对象存储的正文，内容摘要核验必须为 FAILED。
3. 删除保留期内正文，核验必须为 FAILED；合法到期销毁后应为 HISTORICAL_VALID。
4. 非 Auditor、过期授权、错误对象范围或自我批准的应急审计访问必须被拒绝并留下 Audit Event。
5. 报告批准在 Snapshot 为 UNSEALED 或 FAILED 时必须被拒绝。
6. 独立 Task 并行追加审计事件时，不得出现跨 Task 的全局锁争用或同一流内的序号断裂。
7. Case归档不得自动删除原始样本、派生Artifact、ToolRun原始输出或Evidence所依赖内容；未经Case证据销毁Gate不得处置它们。
8. 两个Case共享同一Content Blob时，销毁其中一个Case只能撤销本Case访问；另一个Case仍可复核，直到全部有效引用均被处置后才允许物理回收。
9. Case未归档、存在非终态Task或保留冻结、申请人自复核/自执行、Reviewer与执行Admin为同一Principal时，Case证据销毁Gate必须拒绝。
10. 保留冻结必须阻止其范围内的所有销毁；创建或延期冻结不得授予正文读取权，解除冻结必须由不同Principal的Admin审计批准。
