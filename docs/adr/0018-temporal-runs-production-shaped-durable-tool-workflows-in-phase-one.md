# 一期用Temporal承载生产形态的耐久ToolRun

一期不把Temporal缩减为启动验证，也不让它接管业务真值。LangGraph负责调查决策、分支和人工暂停，PostgreSQL保存Case、Task、Artifact、Evidence和Claim；Temporal以生产形态的受控切片承载Ghidra及其他长时间ToolRun，真实实现超时、重试、心跳、取消、幂等和服务重启恢复。

## Consequences

每次长工具调用创建独立ToolRun Workflow，活动按输入准备、工具执行、输出校验和结果登记分段；二进制与大输出写入对象存储，Workflow历史只传引用。幂等键至少包含Analysis Task、Content Blob哈希、工具版本、参数和环境版本；取消从Task传播到活动。不同安全或资源类型使用独立Task Queue，本地开发可通过同一TaskExecutor契约使用同步执行器。

一期验收必须覆盖Ghidra运行中Worker终止后恢复、重复提交不重复执行、超时重试、人工取消和结果落盘。后续IDA、Unicorn和沙箱继续复用该执行契约，不能要求迁移既有业务对象。
