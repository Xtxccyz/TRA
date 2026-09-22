# 工具选择条件（IDA / qiling / flare-emu / speakeasy）

> 分析流程的「第 2 步」参考。先静态后动态，能用静态解决就不上仿真。

---

## 前置止损门（先判复杂度，再决定上不上工具）

PE 摸底后、投入 IDA 深挖前，先判样本复杂度。**明显是常规恶意软件就停止，不逐函数分析。**

常规恶意软件特征组合（命中即判误报、停止）：

- 仅标准库/公开算法常量（glibc rand `0x41C64E6D`、标准 RC4/AES），无任何原创常量
- 教科书式组合：DLL 侧加载 + RunOnce/Run 持久化 + UAC `runas` 提权，无附加原创技术
- 常见进程名伪装（RuntimeBroker/svchost/nvml.dll）作为核心手段
- 导出表全是 stub（转发/占位），逻辑仅藏在 DllMain 单线程
- 无 PDB、无架构特征、无原创密码学，且 ≤1 个弱信号命中特征库

停止动作：判 ❌ 误报 → 写 `analysis_notes.md` → `add_sample_log.py` 落日志 → 不落 fact、不进 IDA 深挖。

> 弱信号（如 glibc rand 常量）不足以推翻"常规恶意软件"判定。原创常量/原创密码学/架构特征才是国家级硬信号；标准库常量是任何 C 程序都有的背景噪声。

---

## 决策顺序

```
有样本文件？
 ├─ 是 → IDA 静态反编译，定位解密函数 / 提取字符串 / 查导入导出
 │        └─ 静态解不出解密逻辑？
 │             ├─ 定位到某段加密代码 → flare-emu 爆破
 │             ├─ 用户态 PE 需运行时结果 → speakeasy 仿真 dump
 │             └─ 需完整执行流程 + 网络/注册表 → qiling
 └─ 否 → 只有流量/内存 dump → 用 crypto.py 直接试算法
```

---

## IDA（静态分析）

**用途**：反编译、定位解密函数、提取字符串/导入/导出、看调用链。

**触发条件**：
- 有样本文件，需理解逻辑
- 定位某常量/字符串的 xref（谁引用了它）
- 需看函数级行为（注册回调、安装流程）

**配合**：IDA MCP（`idb_open` / `survey_binary` / `decompile` / `xrefs_to` / `find_regex`）。

**注意**：`Machine=0` 的 PE（去特征化）IDA 可能无法识别架构，用同内容的正常头副本分析。

---

## flare-emu（单段加密爆破）

**用途**：对定位到的单个函数/代码段，模拟执行直接得到解密结果（不用人工读懂算法）。

**触发条件**：
- 已用 IDA 定位到解密函数，但算法复杂/多层嵌套，不想手动还原
- 想直接拿「函数输出」而非「理解函数」

**环境**：`E:\claudework\apt-anay\.venv-flare`（unicorn 1.x），`sys.path.insert(0, tools/flare-emu)` 后 `import flare_emu`。

**局限**：单文件工具，不在 PyPI（已 git clone）。主要配 IDA（flare_emu_ida.py）。

---

## speakeasy（PE 仿真 + API hook + dump）

**用途**：仿真用户态 PE，hook API 调用，dump 运行时解密的内存。

**触发条件**：
- 用户态 PE（exe/dll），需运行时解密结果
- 需观察 API 调用序列（哪些 API、什么参数）
- 想 dump 解密后的 payload（反射加载的 DLL、解密字符串）

**环境**：`E:\claudework\apt-anay\.venv-flare\Scripts\python.exe -m speakeasy -t <file> -d <dumpdir> -o report.json`

**局限**：不仿真内核驱动（.sys）。内核驱动用 IDA 静态。

---

## qiling（深度仿真 + 网络/注册表模拟）

**用途**：完整执行流程仿真，模拟网络/注册表/文件系统。

**触发条件**：
- 需完整跑通加载链（多层解密 → 反射加载 → C2 通信）
- 需模拟特定环境（注册表键、网络响应）

**环境**：系统 `py`（unicorn 2.1.4），`from qiling import Qiling`。

**局限**：内核驱动需完整内核环境，仿真成本高。优先静态 + flare-emu。

---

## 环境隔离（重要）

unicorn 1.x 与 2.x API 不兼容，**必须隔离**：

| 工具 | Python | unicorn |
|------|--------|---------|
| qiling | 系统 `py` (3.11) | 2.1.4 |
| speakeasy + flare-emu | `.venv-flare` | 1.0.2 |

qiling 安装会把系统 unicorn 升到 2.1.4，直接 break speakeasy。二者分属不同 venv。
