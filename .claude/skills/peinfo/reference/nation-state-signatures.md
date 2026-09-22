# 国家级工具特征库

> 用于「优先关注国家级工具特征」模式。命中已知常量只定位副本/复用，真正目标是识别同类工程哲学的**未曝光工具**。

---

## 一、NSA Equation Group（已实测）

### 1.1 加密原语（三层分工）

| 原语 | 算法 | 常量 | 用途 |
|------|------|------|------|
| CR-001 | LCG 流密码 | `seed = 0xDD483B8F - 0x6033A96D*seed`，`byte ^= (seed>>8)&0xFF` | 资源封装 / 数据解密 |
| CR-007 | 95 字节替换表（双射） | `plain = table[ord(c)-0x20]` | 字符串混淆（API 名/路径） |
| CR-011 | glibc rand LCG | `seed = 0x41C64E6D*seed + 0x3039`，`byte ^= (seed>>16)&0xFF` | 驱动字符串解密 |
| CR-013 | Numerical Recipes LCG | `seed = 0x19660D*seed + 0x3C6EF35F`；三变体：单字节 `byte ^= (seed>>16)&0xFF\|0x80`、宽字符 `word ^= (seed>>16)&0xFFFF\|0x8000`、HIBYTE `byte ^= (seed>>24)&0xFF`(10_100.sys 配置块字段，不强制 bit7) | SSDT 服务名 / 模块名 / 配置块字段混淆 |
| 仿射密码 | affine cipher | 两轮：轮1 `al=(al+bl)*bh`、轮2 `al=al*bh+bl`（密钥 bl/bh 来自 payload 内 4 字节） | 10_101.bin 加密 shellcode payload |
| CR-014 | LCG 环境变量名 | `seed = 0x29AF3011*seed + 0x933D10AC`，`Name[i]=seed%26+65` | 10_111.exe 从 PID 派生环境变量名（12 字母） |

> **注意 CR-007 方向**：早期 fact 记 `table.index(c)+0x20` 是反的，正确是 `table[ord(c)-0x20]`。用 `crypto.cr007_decrypt` 已修正。

### 1.2 组件与框架

| 组件 | 角色 |
|------|------|
| DanderSpritz | 总框架（DeMi / DecibelMinute） |
| DiBa_Target.dll | 引导持久化 bootkit（BitLocker/EFI/MBR/多引导） |
| KisuComms_Target.dll | KiSu/KillSuit 内存反射加载器 + 通信（EventPair 信号） |
| DoubleFeatureDll.dll | 后渗透 dashboard（DoubleFeature） |
| fast16 | 反分析 + 持久化伪装（防火墙检测 + 服务/驱动伪装） |
| mpdkg32.dll | DiBa 用户态驱动通信/注入（IOCTL 0x220000 系列 + 用户态回调表注册 + EventPair + 跨进程注入） |

### 1.3 内嵌驱动身份（PDB GUID 指纹）

| 驱动 | PDB | GUID | age | 说明 |
|------|-----|------|-----|------|
| 10_102.sys | fvepxy.pdb | `77ee4659-0de7-4d6e-b814-5419bf4b6531` | 15 | NSA 自定义驱动（伪装 fvevol；Check Point 2021 记 fvexpy.sys 拼写少 p） |
| 10_104.sys | drmkflt.pdb | `fecd64c2-2a25-43bc-b727-32fa07b073fc` | 15 | 内核监控/钩子驱动（5类回调），导入 fvepxy.__RCSO/__UCSO |
| 10_106.sys | hidsvc.pdb | `2596320c-0d7c-4745-a815-0be20de38dca` | 1 | 进程注入/反射加载/对象管理 |
| 10_103.exe | mpdkg32.pdb | `671a38a8-d51b-4645-89a5-82009e176948` | 16 | 用户态 DLL（i386，非驱动），驱动通信/注入，IOCTL 0x220000 系列 + 用户态回调表注册 |
| 10_100.sys | 无 PDB（stripped） | — | — | 服务配置维护驱动（i386），读 `\Parameters\Data` 加密配置块 + KeGetPreviousMode 内核态门控 + IOCTL 0x223F5C 驱动通信 |
| 10_101.bin | 无 PDB（shellcode） | — | — | 加密 shellcode stage（4229B），仿射密码两轮解密器 + 加密 payload（0xC6 占 30%），内存基址 0x01003000 |
| 10_107.bin | 无 PDB（boot sector） | — | — | 双 boot sector bootloader（42395B），OEM "NTFS"（NTLDR）+ "NTFDS"（BOOTMGR+TCPA），多版本 Windows 引导 |
| 10_111.exe | 无 PDB（DLL，.exe 扩展） | — | — | 用户态 helper DLL（8704B），5 熵源 PRNG 哨兵 0xBB40E64E + LCG 环境变量通信 + SetEvent |

**识别要点**：这些驱动**无 VS_VERSION_INFO**（正常微软系统驱动必有，此处缺失 = 非微软编译）+ 注入 rootkit 能力（SSDT/进程注入/反射加载）+ 自定义段（.MSRK / INIT rwx）。命中 PDB GUID = NSA 驱动确认。**拼写差异**：Check Point 2021 记 `fvexpy.sys`（少 p，MD5 F7F382A0C610177431B27B93C4C87AC1，DoubleFeature 框架），本文实测 `fvepxy.pdb`（含 p，MD5 a895647e6f0c93af8d4081ede96bde33，DiBa 框架）——同源码跨框架复用，不同编译版本。**PDB GUID 是 Check Point 未提供的精确指纹。**

**释放 IOC**（CR-007 密文解密）：驱动释放到 `%systemroot%\system32\drivers\<名>.sys`（如 `fvepxy.sys`），服务注册到 `\registry\machine\system\CurrentControlSet\Services`（值 Type/Start/ImagePath）。`\system32\drivers\fvepxy.sys` + 服务名 = DiBa bootkit 直接指纹。

**fvepxy SSDT hook 服务清单**（CR-013 解密，sub_22071 批量 11 个 + sub_21414 单服务 1 个）：

| 服务 | 类别 | 注入用途 |
|------|------|---------|
| ZwCreateThread / ZwOpenThread / ZwSuspendThread / ZwResumeThread | 线程 | 目标进程创建/劫持/控制执行线程 |
| ZwSetContextThread / ZwGetContextThread / ZwQueryInformationThread / ZwTerminateThread | 线程上下文 | 线程上下文读写/监控/终止 |
| ZwWriteVirtualMemory / ZwReadVirtualMemory | 内存 | 读写目标进程内存（注入 payload） |
| NtClose | 句柄 | 隐藏注入句柄痕迹 |

**功能定性**：fvepxy 非隐藏文件/进程、非破坏磁盘——是 **内核级跨进程注入器**（SSDT hook 线程+内存+句柄三维度，注入 payload + 反射加载）。解析流程：解密 `ntdll.dll`（wide seed=15416）→ ntdll 导出表查服务名→服务号→读/写 `KeServiceDescriptorTable[服务号]`。

**fvepxy 完整功能链 + 归因指纹**（CR-013 解密验证）：

| 特征 | 值 | 归因信号 |
|------|-----|---------|
| 设备名 | `\DosDevices\rmpdk%dg`（rmpdk0g~rmpdk31g，32 符号链接） | 公开零记录 NSA 命名 |
| PreviousMode 操纵 | hash `0x63B96EA1` 动态找 KTHREAD.PreviousMode 偏移 → 直接写字段 | 高级内核绕过（KernelMode 跳过安全检查） |
| 注入 stub | `pop ebx; mov edx,[ebx+C]; mov ecx,[ebx+8]; jmp ecx`（15 字节跳板） | 线程注入 shellcode |
| 初始化 hook | DriverEntry hook ExAllocatePool + PsSetCreateProcessNotifyRoutine | 进程监控 + 分配监控 |
| 动态 API | PEB 遍历 ntdll.dll → 导出表找 `RtlGetLongestNtPathLength` | 动态解析模式 |
| SSDT 间接调用 | `*(_DWORD*)dword_3EFXX` 调 ZwXXX（不 import） | 绕过 IAT/SSDT hook 检测 |

**PreviousMode 绕过细节**：sub_236DB 通过 `ObReferenceObjectByHandle(NtCurrentThread)` 拿到 KTHREAD 对象，直接写 `KTHREAD[word_3EF90] = a1`。word_3EF90 偏移由 sub_2365B 用 hash `0x63B96EA1` 动态计算（避免硬编码偏移，跨 Windows 版本兼容）。这是 fvepxy 最高价值的绕过技术指纹。

**hidsvc 功能架构 + 归因指纹**（10_106.sys，反射式加载 rootkit）：

| 特征 | 值 | 归因信号 |
|------|-----|---------|
| 设备名 | `\Driver\msvss`（CR-013 宽字符解密，seed 0x17B4） | 伪装微软卷影复制服务 msvss.sys，公开零记录 |
| IOCTL 码 | `0x85892400 ~ 0x8589241C`（8 个） | Check Point 仅记 0x85892408，本文补全 |
| 内部命令 ID | `0x222000 ~ 0x222010` | 双层命令分发 |
| Pool tag | `0x656C6946`（"File"） | 全局内存分配标签 |
| API hash | `0x1A6B8613`（position-weighted XOR） | 动态解析内核 API 名 |
| 反射加载 | 手动 PE 加载器（memcpy 逐节段） | 不落盘 |
| PIC | 返回 retaddr 获取 EIP | 位置无关代码 |
| 文件 wipe | ZwWriteFile 写 0 覆盖 | 文件破坏能力 |

**hidsvc 功能定性**：反射式加载内核 rootkit，具备**注入 + 文件破坏双重能力**。与 fvepxy（纯注入）对比：hidsvc 额外有 sub_11C19 文件 wipe（经 IOCTL 0x8589240C 传路径 → sub_11D25 轮询 → ZwWriteFile 写 0）。API hash 0x1A6B8613 是 hidsvc 独特加密原语（区别于 fvepxy CR-013、DiBa CR-001/007/011）。

**drmkflt 功能架构 + 归因指纹**（10_104.sys，内核监控/钩子驱动）：

| 特征 | 值 | 归因信号 |
|------|-----|---------|
| 驱动协同 | 导入 fvepxy.__RCSO/__UCSO，magic 0x1A1A0000 | fvepxy/drmkflt IPC 接口 |
| 内核回调 | 5 类：进程/线程/镜像/注册表/对象 | 完整监控套件 |
| API 解析 | 手动 PE 导出表遍历（不用 MmGetSystemRoutineAddress） | 高级 NSA 特征 |
| 加密 | CR-011 glibc LCG 解密 12 个 API 名 | 与 FlAv 共享原语 |
| Pool tag | 0x656C6946 ("File") | 与 hidsvc 同 |

**drmkflt 功能定性**：内核监控/钩子驱动——DriverEntry 经 `__RCSO(0x1A1A0000, 回调)` 注册到 fvepxy，sub_14C12 手动遍历 ntoskrnl.exe 导出表（ZwQuerySystemInformation(SystemModuleInformation) + 手动解析导出表 + strncmp，不用 MmGetSystemRoutineAddress），CR-011 解密 12 个 API 名（ExAllocatePoolWithTag/ZwAllocateVirtualMemory/ZwFreeVirtualMemory/PsSetCreateProcessNotifyRoutine/PsSetCreateThreadNotifyRoutine/PsRemoveCreateThreadNotifyRoutine/PsSetLoadImageNotifyRoutine/PsRemoveLoadImageNotifyRoutine/CmRegisterCallback/CmUnRegisterCallback/ObRegisterCallbacks/ObUnRegisterCallbacks），注册 5 类内核回调（进程/线程/镜像/注册表/对象）做全系统监控，PsCreateSystemThread 创建系统线程。与 fvepxy（SSDT hook 注入器）、hidsvc（反射加载 rootkit）对比：drmkflt 是监控层。Check Point 2021 仅记录 drmkflt.sys MD5（BroughtHotShot 9C6D1ED1），未分析功能。

**10_100.sys 功能架构 + 归因指纹**（10_100.sys，服务配置维护驱动）：

| 特征 | 值 | 归因信号 |
|------|-----|---------|
| 配置块 | `\Parameters\Data`（Data[0..3]=LCG seed，Data+12 字段8=计数器/字段9=版本上限） | 加密配置块 + 使用次数/有效期机制 |
| 加密 | CR-013 LCG HIBYTE 变体 `byte ^= (seed>>24)&0xFF` | 新变体，区别于单字节/宽字符 |
| IOCTL | `0x223F5C`（向其他驱动发命令） | device type 0x22 家族，与 mpdkg32 0x220000 同族 |
| PreviousMode | KeGetPreviousMode 内核态门控（READ/WRITE 拒绝 UserMode） | 与 fvepxy PreviousMode 操纵同族防御思想 |
| 版本检测 | PsGetVersion + CSDVersion "Service Pack" atoi | 装载前置检查 |
| 无 PDB | 无 CodeView RSDS + 无 VS_VERSION_INFO | 非微软编译 |

**10_100.sys 功能定性**：DiBa bootkit 服务配置维护驱动——读服务注册表 `\Parameters\Data` 加密配置块（LCG seed + 加密计数器 + 版本上限），计数器递增达上限失效（植入授权/有效期机制）。READ/WRITE 均检查 KeGetPreviousMode，仅内核态可读写。sub_11B60 打开目标驱动文件发 IOCTL 0x223F5C。与 fvepxy（SSDT hook 注入）、drmkflt（内核监控）、hidsvc（反射 rootkit）、10_108.exe（启动配置检测）对比：10_100.sys 是配置存储/维护层，其他驱动经 IOCTL 读写配置。CR-013 HIBYTE 变体（seed>>24，不强制 bit7）是本驱动独有，与已记录单字节（seed>>16|0x80）、宽字符（seed>>16|0x8000）构成 CR-013 三个变体。

### 1.4 magic 值

| magic | 上下文 |
|-------|--------|
| `0xBB40E64E` | 5 熵源 PRNG 未初始化哨兵 |
| `0xBB370A33` | DiBa 安装函数内部 |
| `0xD0C0FFEE` | DiBa 配置数据（10_109.bin） |
| `"NTFDS"` | DiBa boot sector OEM ID（标准 NTFS 恒为 `"NTFS"`，第 4 位 S→D 自定义，10_107.bin） |

### 1.5 架构特征（风格判据）

- **5 熵源 PRNG**：SystemTime ^ PID ^ TID ^ TickCount ^ QueryPerfCounter
- **驱动协同接口**：fvepxy 导出 `__RCSO`/`__UCSO`，drmkflt 导入并注册回调（magic `0x1A1A0000`）
- **动态 API 解析**：`MmGetSystemRoutineAddress` 内核侧 / PEB+hash 用户侧
- **堆上动态代码**：加密存储，HeapAlloc 后解密执行（静态分析不可见）

### 1.6 SOTI 引导扇区持久化（DiBa bootkit 定义性动作）

DiBa 四种持久化之一（DEFAULT / LAUNCHER / **SOTI** / JUVI）。SOTI 是真正的引导级持久化，区别于驱动释放+服务注册（LAUNCHER 路径，LC-026）。

| 步骤 | 实现 | 归因信号 |
|------|------|---------|
| 写 VBR 非 MBR | `sub_1000F2EC` memcmp boot sector 偏移+3 的 9 字节 OEM ID（`"NTFS"`）确认后才覆盖 | 精准替换卷引导记录，非粗暴写 MBR——工程化 |
| MD4 known-good 校验 | advapi32 `SystemFunction007`（动态 LoadLibrary）hash 当前 boot sector，比对 known-good 列表，非已知拒绝覆盖 | 自带 boot sector hash 库，避免覆盖第三方 bootloader / 已感染扇区 |
| Native API 写盘 | `ZwCreateFile`(sub_1002319F) + `ZwReadFile`(sub_10022DE8) + `ZwWriteFile`，导入表 WriteFile=0 | 全动态解析，静态 IAT 不可见 |
| container 文件藏 payload | payload 藏 NTFS container 文件，boot sector 经 `St_GetObjectId`(ZwQueryInformationFile FileObjectIdInfo) + `St_OpenFileById` 按 object id 定位 | 绕过文件系统枚举，非可见路径 |
| container 文件名 | `GetSystemWindowsDirectoryW` + 16 次尝试避冲突 | 随机化命名 |
| 分区识别 | `GetLogicalDriveStringsW`+`QueryDosDeviceW` 卷↔盘符，boot/system 分区分离 | 兼容多分区 |
| 兼容检查 | ≥64MB 内存、OS 版本、EFI、BitLocker(`FveGetStatusW` via fveapi.dll)、Vista 以下 boot≠system 拒绝 | 穷举边界条件，防御性安装 |

**关键 IOC**：VBR OEM ID 字段非标准 `"NTFS"` 而是 `"NTFDS"`（10_107.bin）；系统卷引导扇区被非微软 boot sector 覆盖。

### 1.7 DeMi 框架接口 provider ID

DiBa 模块在 DeMi 框架中的接口标识（`DiBa_Target_BH.xml` 明文）：

```xml
<Module name="DiBa_Target_BH" id="3051">
    <Interfaces>
        <Interface provider="0x01011069" id="0x01010031"/>
    </Interfaces>
```

- `provider="0x01011069"` = DiBa_Target_BH 模块（id 3051）对外暴露的接口 provider ID
- 该值出现在 DLL `.data` 段结构体（模块描述符），**无直接代码 xref**——由 DeMi 框架遍历结构体读取，非加密/协议相关神秘值
- 版本映射：`DiBa_Target_BH_2000.dll` 仅用于 Win2000（5.0），5.1+/6.x 用 `DiBa_Target_BH.dll`

---

## 二、CIA（待补）

> 尚无客观样本数据。待 CIA 泄露样本按 NSA 同流程批量入 facts 后，从样本归纳特征补充此节。当前**不凭先验臆断**。

---

## 三、美网军 / 五眼联盟（待补）

> 同上，待客观样本数据后补充。

---

## 四、风格判据（识别未曝光工具的通用原则）

**正向信号**（命中越多越像国家级）：
1. 原创密码学（自定义流密码 / 多熵源 PRNG / RSA+AES 组合）
2. 平台化/模块化架构（插件系统 / VTable 抽象 / 配置驱动）
3. 动态 API 解析（PEB 遍历 + 自定义 hash / XOR 解密 API 名）
4. 内核/驱动级组件（文件系统过滤 / SSDT / 反射加载）
5. 内嵌脚本载荷（Lua 等）
6. 反分析深度（堆上动态代码、专业混淆，非商业 packer）
7. 工程化残留（SCCS 版本串、PDB 残留、专业命名）
8. 编译时间戳美东工作时段

**反向信号**（商品化，排除）：AV 家族名列表、Delphi/VB 表单、商业 packer、搜索引擎更新、单层 XOR 无原创常量、2019+ 时间戳。

**常规恶意软件止损清单**（命中即判误报、停止深挖，不进 IDA 逐函数分析）：

- 仅标准库/公开算法常量（glibc rand `0x41C64E6D`、标准 RC4/AES），无任何原创常量
- 教科书式组合：DLL 侧加载 + RunOnce/Run 持久化 + UAC `runas` 提权，无附加原创技术
- 常见进程名伪装（RuntimeBroker/svchost/nvml.dll）作为核心手段
- 导出表全是 stub（转发/占位），逻辑仅藏在 DllMain 单线程
- 无 PDB、无架构特征、无原创密码学，且 ≤1 个弱信号命中特征库

停止动作：判 ❌ 误报 → 写 `analysis_notes.md` → `add_sample_log.py` 落日志 → 不落 fact。

> **高阶程度是独立归因信号**：除比对已知手法相似性外，单独评估工程复杂度。相似性答"像不像已知工具"，高阶程度答"够不够格"。命中单个弱信号（如 glibc rand 常量）不足以推翻"常规恶意软件"判定——标准库常量是任何 C 程序都有的背景噪声，原创常量/原创密码学/架构特征才是国家级硬信号。

**判定**：正向 ≥2 且无反向 = 国家级风格候选，进入深挖；命中止损清单任一 = 常规恶意软件，判误报停止。
