# 静态工具也在隔离Worker中处理不可信输入

一期虽然不执行恶意样本，但Ghidra、Office/PDF解析器和解包器仍处理攻击者可控数据，因此所有ToolRun在非管理员、无公网、资源受限的隔离Worker中运行。样本只读挂载，Worker只获取当前ToolRun所需对象引用，输出先写临时目录并经校验后登记到对象存储；Agent生成脚本只能作为Artifact保存，不进入执行队列。

## Consequences

Ghidra、脚本解析和文档/载体解析使用独立Temporal Task Queue，可按风险配置不同Worker镜像与限额。CPU、内存、磁盘、进程数和时间均受硬限制，任务结束后销毁临时目录。后续实际执行样本必须进入隔离虚拟机或专用沙箱，不得通过提升静态Worker权限来实现动态能力。
