# 首期不挂 DSH 宿主执行工具

首期分析主链路保持 threat-static：DSH 只提供对话循环和 `defineTool`，不向模型暴露 bash、web、skill、subagent。需要执行语义时只能提议 `CONTROLLED_EMULATE`，由隔离 emu-worker 跑授权窗口。未来动态分析和专长 Agent 进程拓扑推迟到静态主链路能交付 HOW 之后再选执行器；不得用「以后要多智能体」为现在打开宿主工具辩护。
