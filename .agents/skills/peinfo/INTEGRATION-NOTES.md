# peinfo 纳入本仓库的说明与产品集成设计

来源：`C:\Users\王宪韬\Desktop\peinfo`（他人制作的 skill，纯标准库、无第三方依赖）。
纳入位置：`.agents/skills/peinfo/`（本仓库 skill 正文的规范位置，见 `docs/code-map.md`）。

## 一、纳入范围与排除项

| 文件 | 处理 | 原因 |
|---|---|---|
| `scripts/crypto.py` | ✅ 纳入 | 纯标准库；RC4/XOR/LCG/替换表原语 + CR-001/007/011/013 家族算法；带自测用例（`python crypto.py` 通过） |
| `scripts/scan.py` | ✅ 纳入 | CR-013 加密字符串自动定位（扫 `.text` 的 `mov eax, imm16` + `push imm32` seed 模式） |
| `scripts/pe_tools.py` | ✅ 纳入 | PE 解析：PDB(RSDS)、导入/导出、资源、节、RVA↔偏移 |
| `scripts/elf_tools.py` | ✅ 纳入 | ELF 解析：header、节、符号、导入 |
| `scripts/constants.py` | ✅ 纳入 | magic 值 / PDB GUID / 加密常量 / 算法↔组件对照 |
| `reference/*.md` | ✅ 纳入 | 国家级工具特征、仿真工具选择条件 |
| `scripts/corpus_lookup.py` | ⚠️ 纳入但默认不可用 | 方法有价值；但其索引路径硬编码为原作者的另一个项目（`E:\claudework\apt-anay\...`）。本仓库必须用 `--index` 自带索引，否则退出码 2 = **没有索引**，不等于「样本干净」 |
| `scripts/hash_lookup.py` | ❌ **排除** | ① 需从本地文件读 API key（`E:\CA\...\info_MalwareBazaar.DB`），本机不存在，且本项目禁令禁止改动/引入 API key；② 会对 `mb-api.abuse.ch` / `malshare.com` 发起外部请求，与本产品分析样本时的禁网边界（T4 隔离契约）冲突 |

同时已清理 `SKILL.md` 中对原环境的引用：删除 `C:/Users/stan/...` 调用路径与 API key 文件位置说明，把「公开样本库查询」一节改写为「本仓库不提供」，保留其两条**方法论硬规则**（缺席不能证明归属；样本必须写清 source）。

## 二、可以怎么用（已可用）

供**分析 Agent** 在调查过程中使用，不改变产品运行时行为：

- 遇到疑似非 XOR 的配置解码（RC4 / LCG 变体 / 替换表）时，先用 `crypto.py` 的对应原语离线复算，把「算法 + 明文」作为可验证事实。
- `scan_cr013_strings` 用于 DiBa/Equation Group 系样本的字符串自动解密。
- `pe_tools.py` / `elf_tools.py` 用于核对 PDB、导入导出、节与资源（与 Ghidra 结果交叉验证，属**独立证据来源**）。
- `corpus_lookup.py` 的**出处核对**思想对应本产品的样本保真要求：写归因结论前先能回答「这份样本为什么会在我们手上」。

## 三、产品运行时集成设计（待实施，排在 G5 之后）

**目标能力类型**：`编码、解密与配置还原` 的 HOW —— 算法或公式、明文、输出消费者（Join）。

**设计（不新建调查引擎，只扩展现有解码恢复路径）**：

1. 把 `crypto.py` 的原语移植为 `src/threat_report_agent/` 下的解码候选生成器（纯函数，无 I/O），
   与现有 XOR 路径并列，产出同形状的 `decode_candidate`：
   - 输入：已定位的密文缓冲 + 候选密钥/seed（来自调用点立即数或 `READ_BYTES`）。
   - 输出：`{algorithm, key_or_seed, plaintext, confidence}`，交给现有 `verify_xor_decode_candidate`
     同族的 verifier 与 `DECODE_CANDIDATE` 动作。
2. 候选**必须**经现有证据契约判定，不得直接写 Claim：
   - 明文要能被现有 `dataflow.decoded_output_consumer`（ADR-0035 对象别名 Join）连到消费者；
   - 连不上就保持 `UNKNOWN(consumer)`，不得因「解出来了」就宣称闭合。
3. 新增原语纳入既有测试口径：正向用例（RC4/LCG 已知向量）+ 反例（错 key 不得产出看似明文的结果）。
4. **不得**引入 `hash_lookup` 式外部查询；`corpus_lookup` 若要进产品，必须先有本仓库自有的语料索引
   与明确的授权边界。

**为什么排在 G5 之后**：改变解码恢复路径会改变分析行为与证据，从而作废 G5 已采集的平台证据；
这与本计划「代码批次稳定后再做一次平台验收」的纪律冲突（计划 §14.5）。
