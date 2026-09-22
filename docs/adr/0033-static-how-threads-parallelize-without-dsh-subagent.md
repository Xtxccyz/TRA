# 静态 HOW 按调查线程并行，不按 DSH subagent 并行

编码/配置与进程/线程是可并行的调查线程，共享 Case、Evidence 和一份 Report Revision；仅在解码明文的消费者处强制 Join。实现阶段允许按文件所有权并行改码。分析阶段不打开 DSH subagent：专长 Agent 仍是同一运行时上的逻辑角色，多个角色读同一 ToolRun 仍是一个证据来源。

首期只做 Lite：落地可并行的调查线程契约，以及无依赖 ToolRun 的后端并行执行。一次分析仍是一条 DSH 会话在提议动作。多路专长模型并发达套留到 Resume 正例 HOW 过关之后，不为并行先造空调度器。
