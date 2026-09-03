# 审计、运维日志和性能Trace分离并贯穿全链路

一期把可观测性作为正式能力：Audit Event记录不可变业务动作，结构化Operational Log用于故障诊断，OpenTelemetry Trace与指标用于性能和调用链分析。case_id、task_id、artifact_id、tool_run_id、model_call_id和trace_id贯穿FastAPI、LangGraph、Temporal、Tool Worker、Model Gateway、Report Revision及人工Gate，使每次分析、重试、缓存复用、裁决和输出都可以定位和回放。

## Consequences

Audit Event追加写入并由独立数据库权限禁止更新或删除，记录操作者、对象、时间、前后状态和关联Trace；定期生成哈希链校验值并归档到对象存储，以发现篡改。具体的审计流、签名封存和正文到期销毁边界由ADR-0029规定。Operational Log使用JSON输出并默认排除样本正文、解压密码、Token和其他凭证；日志本身不是Evidence，需要用于结论时必须显式固化并建立锚点。

一期暴露Prometheus兼容指标和基础性能面板，记录排队、执行、重试、Token、缓存命中、存储及模块耗时。后续平台可以接入Loki、OpenSearch或既有可观测系统，但不得改变Audit Event和Trace关联契约。
