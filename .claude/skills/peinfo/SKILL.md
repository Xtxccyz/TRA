---
name: peinfo
description: PE/ELF 等二进制格式的通用解密分析工具包。含加密原语库(RC4/XOR/LCG/替换表)、PE/ELF 解析工具、国家级工具特征库(NSA/CIA/美网军)、IDA/qiling/flare-emu/speakeasy 工具选择条件、样本查重(本地语料，需自带索引)。用 /peinfo 引导。
---

# peinfo — 二进制解密分析工具包

## 何时使用

用户 `/peinfo` 触发，或任务涉及以下任一：

- 二进制（PE/ELF/其他）静态/动态逆向分析
- 加密数据解密（RC4 / XOR / 自定义流密码 / 替换表）
- 国家级 APT 工具特征识别（NSA / CIA / 美网军 / 五眼联盟）
- 需要判断用哪个仿真工具（IDA / qiling / flare-emu / speakeasy）
- 需要给样本定身份 / 谈归因 / 写 fact → **先用 `scripts/corpus_lookup.py --index <index.json>` 查本地语料（强制，见下）**

## 使用流程

### 第 0 步：先确认分析目标（必须）

**每次启动先问用户**（或根据任务上下文判断）：

> 本次分析优先关注【国家级工具特征】（NSA / CIA / 美网军等），还是【普通分析】（不预设归属）？

- **选「国家级」**：加载 `reference/nation-state-signatures.md`，用 `scripts/constants.py` 的已知常量 / PDB GUID / magic 值做特征匹配。命中已知指纹只是定位副本/复用，真正的目标是识别「同类工程哲学」的未曝光工具。
- **选「普通」**：跳过特征库，用 `scripts/crypto.py` 的通用算法做纯技术分析，不预设归属。

> 注意：选「国家级」不等于只匹配已知常量——那只能找已知样本的副本。风格判据（原创密码学 / 平台化架构 / 动态 API 解析 / 内核组件 / 反分析深度）才是识别未曝光工具的钥匙。

### 第 1 步：识别文件格式

```python
from scripts.pe_tools import get_pdb, get_imports, get_exports, get_sections, get_resources
from scripts.elf_tools import elf_header, elf_sections, elf_symbols  # ELF 时用
```

提取：格式、架构、PDB（RSDS GUID + age + 名）、导入/导出表、资源、节信息。

### 第 2 步：定位加密，选工具

读 `reference/tool-selection.md`，按场景选：

| 工具 | 用途 | 触发条件 |
|------|------|---------|
| IDA | 静态反编译、定位解密函数 | 有样本文件，需看逻辑 |
| flare-emu | 单段加密代码爆破 | 定位到某函数，需直接得到解密结果 |
| speakeasy | PE 仿真 + API hook + dump 内存 | 用户态 PE，需运行时解密结果 |
| qiling | 深度仿真 + 网络/注册表模拟 | 需完整执行流程、模拟环境 |

### 第 3 步：解密

```python
from scripts.crypto import rc4_decrypt, xor_decrypt, cr001_lcg_decrypt, cr007_decrypt, cr011_glibc_decrypt, cr013_nr_decrypt
from scripts.scan import scan_cr013_strings   # 自动定位 CR-013 加密字符串，免 IDA 手工找 seed/密文
```

按识别出的算法调用对应函数。算法未知时先用 IDA/flare-emu 定位，再回来套用。

**CR-013 加密字符串优先用 `scan_cr013_strings` 自动解**：扫描 `.text` 的 `mov eax, imm16`（负 word）+ `push imm32`（seed）模式，全自动解出 DiBa 驱动里的注册表路径/服务名/设备名（实测 10_108.exe 解出 SAFEBOOT/SystemBootDevice 等 10 串，hidsvc 解出设备名 `\Driver\msvss`）。

### 第 3.5 步：公开样本库查重 —— ⛔ 本仓库不提供

`hash_lookup.py`（MalwareBazaar / MalShare 查询）**未纳入本仓库**，原因有两条：

- 它需要从本地文件读取 API key（原环境为 `E:\CA\...\info_MalwareBazaar.DB`），本机不存在；本项目禁令明确禁止改动或引入 API key。
- 它会对 `mb-api.abuse.ch` / `malshare.com` 发起外部网络请求。本产品分析样本时**不得**主动外联，这条边界与 T4 隔离契约一致。

需要公开样本库结论时：**不要**自己写查询代码、不要去找 key 文件。改为在报告里记录未查询，并在分析限制中说明。

**这两库对国家级 APT 样本覆盖极差**（实测 Slingshot 10 个 IOC 只命中 1 个）。**库里的空结果 ≠ 样本不存在**，只是这两库没收。

**从原工具保留下来的两条硬规则（比脚本更重要）**：

1. **「不在某个公开 IOC 列表里」永远不能作为「属于该家族」的论据。** 缺席证明不了任何事。
   要主张归属，只能给出**正面证据**（内部名 / 独有常量 / 协议魔数 / 构建指纹对得上公开描述）。
2. **样本的 `source` 字段必须写清来源**（从哪来、哪一批、谁给的）。缺来源字段 = 无法回溯 = 迟早误归因。

### ⛔ 强制前置：样本进 fact 前先查本地语料（不可跳过）

**任何样本在写进 fact / 写归因结论之前，必须先跑本地语料查重。**

```bash
py ".agents/skills/peinfo/scripts/corpus_lookup.py" <文件路径或MD5> ...
py ".agents/skills/peinfo/scripts/corpus_lookup.py" --index <index.json> <输入> ...   # 指定索引
py ".agents/skills/peinfo/scripts/corpus_lookup.py" --show-indexes   # 看会用哪些索引
```

> ⚠️ 本仓库**没有**已归集的本地恶意语料索引：脚本里原来的索引路径指向原作者的另一个项目
> （`E:\claudework\apt-anay\...`），在本机不存在。因此它多数情况下会以退出码 2
> （no usable index）结束——那是**没有索引**，不是「样本干净」。要用它就必须先用
> `--index` 传入你自己维护的索引文件。不要把它当成默认可用的结论来源。

判读：

| 输出 | 含义 | 动作 |
|------|------|------|
| `ABSENT from local corpus (clean)` | 本地语料没有 → 外部来样 | 可继续分析 |
| `PRESENT in local corpus:` + 路径 | **该文件是我们已归集的语料** | **先解释来源再谈归因** |
| 退出码 3 | 有命中 | 同上一行；退出码 0 = 干净 |

**命中时不是"禁止使用"，是"必须先答一句：这文件为什么会到我们手上？"** 答不上来就不许写归因。

**为什么强制**：MD5 `61110bea`（SHA256 `515374423b…`）曾被判为"未公开的 Slingshot 用户态核心 RAT"，
唯一理由是"不在 Kaspersky 公开的 5 个 MD5 里"。它实际与本地语料里已有的
`EQGRP_Lost_in_Translation-master/windows/Resources/Df/Uploads/i386-winnt/DoubleFeatureDll.dll.unfinalized`
**逐字节相同**（397,824 B）。据此写出的 4 条 fact + 一条"Slingshot↔NSA 跨机构算法级代码复用"结论
全部作废撤回。**这条查询 30 秒。**
完整复盘：项目内 `knowledge/nation-state-tools/nsa/slingshot/notes/misattribution-61110bea.md`

**两条硬规则**（比脚本更重要）：

1. **「不在某个公开 IOC 列表里」永远不能作为「属于该家族」的论据。** 缺席证明不了任何事。
   要主张归属，只能给出**正面证据**（内部名 / 独有常量 / 协议魔数 / 构建指纹对得上公开描述）。
2. **样本的 `source` 字段必须写清来源**（从哪来、哪一批、谁给的）。缺来源字段 = 无法回溯 = 迟早误归因。

### 第 4 步：落分析笔记（可选）

若属长期逆向项目，按 [[analysis-notes-then-fact-workflow]] 流程：先写临时 notes（标证据等级），样本全分析完再落 fact。

## 脚本清单

| 脚本 | 内容 |
|------|------|
| `scripts/crypto.py` | 通用算法（RC4/XOR/LCG/base64）+ NSA 特有（CR-001 LCG / CR-007 替换表 / CR-011 glibc rand / CR-013 Numerical Recipes LCG） |
| `scripts/scan.py` | 加密字符串自动定位器：扫 `.text` 找 CR-013 加密字符串 + seed，全自动解密 |
| `scripts/pe_tools.py` | PE 解析：PDB(RSDS)、导入/导出表、资源(RT_RCDATA)、节、RVA↔偏移 |
| `scripts/elf_tools.py` | ELF 解析：header、节、符号、导入 |
| `scripts/constants.py` | 常量库：magic 值、PDB GUID、加密常量、算法↔组件对照 |
| `scripts/corpus_lookup.py` | 样本库查重（**本地语料，强制前置**）：文件路径或 MD5 → 是否已在本地已归集语料里，命中给绝对路径。命中退 3，干净退 0。**本仓库需用 `--index` 自带索引** |

> 原工具包的 `scripts/hash_lookup.py`（MalwareBazaar / MalShare 外部查询）**未纳入本仓库**：
> 它依赖本地 API key 文件并对境外服务发起网络请求，与本项目的样本分析禁网边界冲突。

## 参考文档

| 文档 | 内容 |
|------|------|
| `reference/nation-state-signatures.md` | NSA/CIA/美网军 国家级工具特征（加密原语、PDB、架构、行为） |
| `reference/tool-selection.md` | IDA/qiling/flare-emu/speakeasy 的选择条件、触发条件、环境隔离 |

## 环境

- 系统 Python 3.11（`py`）跑本 skill 脚本，无第三方依赖（纯标准库）。
- 仿真工具环境隔离见 `reference/tool-selection.md`（unicorn 版本冲突）。
