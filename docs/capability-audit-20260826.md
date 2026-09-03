# 威胁报告 Agent 系统能力审查报告

**审查日期**: 2026-08-26  
**审查范围**: 第三轮迭代需求实现完整性  
**审查方法**: 静态代码审查、契约验证、架构对比、测试结果复核

---

## 执行摘要

**核心结论**: 当前实现**部分满足**第三轮迭代需求。系统已具备结构化调查框架的**数据模型和基础组件**，但**缺失关键的递归调查循环、动作目录、以及模型驱动的假设验证机制**。

**关键发现**:
- ✅ 已实现: InvestigationThread、Hypothesis、Mechanism 契约层
- ✅ 已实现: DeterministicSeedRanker、QuestionCentricContextBuilder
- ✅ 已实现: XOR 静态验证、跨函数机制链、进程创建标志解码
- ⚠️ 部分实现: 状态机存在但无实际状态转换逻辑
- ❌ 缺失: Action Catalog (GET_CALLERS/TRACE_API_ARGUMENT/DECODE_CANDIDATE 等)
- ❌ 缺失: 证据驱动递归调查循环 (Hypothesis → Action → Evidence → Update)
- ❌ 缺失: 动态模拟器执行集成 (仅有探测适配器)

---

## 第一部分：需求对比分析

### 1.1 核心架构对比

**需求文档要求的主链**:
```
Artifact
   ↓
Deterministic Static Extraction
   ↓
Evidence Graph
   ↓
Seed Generation
   ↓
Investigation Queue
   ↓
┌────────────────────────────────────┐
│        Investigation Thread        │
│                                    │
│ Question → Context → Hypothesis    │
│    ↓                               │
│ Action Proposal                    │
│    ↓                               │
│ Tool / Verification                │
│    ↓                               │
│ New Evidence                       │
│    ↓                               │
│ Update Hypothesis ───┐             │
│          ↑           │             │
│          └───────────┘             │
└────────────────────────────────────┘
   ↓
Mechanism → Claim → Relation → Timeline → Report
```

**当前实际实现**:
```
Artifact
   ↓
Deterministic Static Extraction (✅)
   ↓
Evidence (✅)
   ↓
DeterministicSeedRanker (✅ 生成 InvestigationSeed)
   ↓
[缺失: Investigation Queue 调度器]
   ↓
[缺失: Investigation Thread 状态机实际执行]
   ↓
StaticAnalysisAgent.propose_claims() (✅ 规则生成 Claim)
   ↓
Mechanism (✅ 契约存在, ⚠️ 填充逻辑有限)
   ↓
Claim (✅) → Relation (✅) → Report (✅)
```

**差距**: 核心的**递归调查循环不存在**。当前系统是"一次性静态分析 → 规则生成 Claim"，而非"问题驱动 → 假设 → 缺证据 → 调用工具 → 更新假设 → 再验证"的循环。

### 1.2 Investigation Thread 状态机对比

**需求要求的 10 个状态**:
```
DISCOVERED → PRIORITIZED → CONTEXT_READY → HYPOTHESIZING
→ INVESTIGATING → VERIFYING → MECHANISM_READY → CLAIM_READY
→ RELATED → CLOSED

支持: UNKNOWN, BLOCKED, REJECTED, CONTRADICTED
```

**当前实现验证**:
```python
# contracts.py:76-79
state: Literal[
    "DISCOVERED", "PRIORITIZED", "CONTEXT_READY", "HYPOTHESIZING",
    "INVESTIGATING", "VERIFYING", "MECHANISM_READY", "CLAIM_READY",
    "UNKNOWN", "CLOSED",
]
```

✅ **状态定义存在**  
❌ **状态转换逻辑不存在** - 未找到任何代码实现状态转换函数或状态机驱动器

**检索结果**:
```bash
# 搜索状态转换代码
grep -r "DISCOVERED.*PRIORITIZED\|state.*transition" src/
# 结果: 仅在 contracts.py 中定义，无实际使用
```

### 1.3 Action Catalog 对比

**需求要求的 Action 类型** (第三轮文档第五节):
```
GET_FUNCTION
GET_CALLERS
GET_CALLEES
GET_XREFS_TO
GET_XREFS_FROM
GET_STRINGS_REFERENCED
GET_DATA_REFERENCES
READ_BYTES
GET_DECOMPILE
GET_PCODE_SLICE
GET_CFG_SLICE
TRACE_API_ARGUMENT
TRACE_RETURN_VALUE
TRACE_GLOBAL_USAGE
DECODE_CANDIDATE
EVALUATE_CONSTANT
COMPARE_FUNCTION
```

**当前实现验证**:
```bash
# 搜索 Action 类型定义
grep -r "GET_CALLERS\|TRACE_API_ARGUMENT\|DECODE_CANDIDATE" src/
# 结果: 未找到任何匹配
```

❌ **完全缺失** - ActionProposal 契约存在，但无任何预定义的 action_type 枚举或验证逻辑

**当前 ActionProposal 契约**:
```python
# contracts.py:50-63
class ActionProposal(FrozenContract):
    tool_name: str  # ← 仅为自由字符串，无类型约束
    target_artifact_id: str
    reason: str
    expected_evidence: tuple[str, ...]
    # ...
```

**差距**: 需求要求的结构化 Action Catalog 完全不存在，无法支持"模型提出 TRACE_API_ARGUMENT → 确定性验证器执行"的工作流。

### 1.4 Hypothesis ≠ Claim 分离验证

**需求要求** (第三轮文档第三节):
> "Hypothesis 也要正式成为数据对象"  
> "模型这时候没有资格产生最终 Claim"  
> "Hypothesis ≠ Claim，在数据库层彻底拆开"

**当前实现**:
- ✅ Hypothesis 契约存在 (contracts.py:88-96)
- ✅ Claim 表存在 (models.py:139-160)
- ❌ **Hypothesis 无对应数据库表** - 仅为内存契约，未持久化
- ❌ **无 Hypothesis → Claim 升级逻辑** - 未找到验证门限或转换函数

**数据库模型检查**:
```python
# models.py 中所有表
CaseRecord, AnalysisTask, ContentBlob, Artifact, ToolRun,
Evidence, Claim, ClaimEvidence, ModelCall, Relation,
AnalysisSnapshot, ReportRevision, GateRecord, TaskSecret,
AuditEvent, AuditChainHead, AuditSeal, EvidencePurgeRequest

# 结果: 无 Hypothesis 表
```

### 1.5 Context Builder 对比

**需求要求** (第三轮文档第六、七节):
> "Context Builder 不应该'给函数上下文'，而应该'给问题上下文'"  
> "为当前 Investigation Question 构建最小充分证据包"

**当前实现**:
```python
# orchestration.py:96-134
class QuestionCentricContextBuilder:
    def build(self, *, question: str, artifact: dict, 
              evidence: list, hypotheses: list | None) -> dict:
        packet = {
            "question": question,  # ✅
            "artifact": artifact,  # ✅
            "hypotheses": hypotheses or [],  # ✅
            "evidence": [],
            "omitted_evidence_count": 0,  # ✅ 边界控制
        }
        # 按大小截断 evidence
```

✅ **基本满足** - 实现了问题中心上下文，但缺少需求文档中的:
- ❌ P-code slice
- ❌ Call graph (callers/callees)
- ❌ Existing contradictions
- ❌ Open unknowns

### 1.6 Mechanism 层验证

**需求要求** (第三轮文档第十一节):
```
Evidence → Mechanism → Claim
```

**当前实现**:
```python
# contracts.py:98-106
class Mechanism(FrozenContract):
    id: str
    thread_id: str
    dimension: str
    steps: tuple[str, ...]  # ✅
    evidence_ids: tuple[str, ...]  # ✅
    status: Literal["CONFIRMED", "INFERRED", "UNKNOWN"]
    limitations: tuple[str, ...]
```

✅ **契约层完整**  
⚠️ **生成逻辑有限** - `service.py` 中仅在特定函数链场景生成 Mechanism，未形成系统性的 Evidence → Mechanism 提升路径

---

## 第二部分：动态模拟器集成验证

### 2.1 需求明确性

用户原始需求明确提到:
> "所以我们做静态分析也需要一些动态模拟的工具，比如 flare-emu、qiling 模拟器以及 https://github.com/mandiant/speakeasy"

**期望**: 集成动态模拟器以达到 Resume 报告的深度

### 2.2 当前实现状态

**检查结果**:
```python
# simulation_adapters.py:1-62
"""Capability probes for optional, isolated user-mode emulation.

The first phase does not execute samples. This module intentionally exposes a
probe and a policy object only; a future worker adapter can implement the
actual emulation behind the same contract.
"""

def detect_simulation_capabilities() -> tuple[SimulationCapability, ...]:
    return tuple(
        SimulationCapability(
            name=name,
            import_name=module,
            installed=importlib.util.find_spec(module) is not None,
        )
        for name, module in {"flare-emu": "flare_emu", ...}.items()
    )
```

```bash
# 搜索实际使用
grep -r "flare.emu\|qiling\|speakeasy" src/ --include="*.py" | wc -l
# 结果: 3 (仅在 simulation_adapters.py 的检测代码中)
```

❌ **仅有探测器，无执行逻辑** - 系统可以检测这些库是否安装，但不调用它们

**审查意见**: 当前模拟器集成为 **placeholder 设计**，完全未实现动态执行能力。

---

## 第三部分：Resume 报告能力对比

### 3.1 Resume 报告核心特征

用户认可的 Resume 报告深度体现在:

1. **XOR 配置完整恢复**:
   - 密文地址: 0x14004C8E1, 0x14004C910, 0x14004C92F
   - 算法: `plaintext[i] = ciphertext[i] ^ key[i%16] ^ counter`
   - 完整解密: C2 URL、文件名

2. **跨函数行为链**:
   - Phase 1 (环境检测) → Phase 2 (C2准备) → ... → Phase 8 (循环)
   - 明确的函数调用关系和数据流

3. **父进程伪造 (PPID Spoofing)**:
   - CreateToolhelp32Snapshot → Process32First/Next → explorer.exe 匹配
   - OpenProcess(PROCESS_CREATE_PROCESS)
   - UpdateProcThreadAttribute(PARENT_PROCESS)
   - CreateProcessW 完整链路

### 3.2 当前系统能力对比

| Resume 报告能力 | 当前系统状态 | 验证依据 |
|---|---|---|
| XOR 静态解密 | ✅ **已实现** | `verify_xor_decode_candidate()`, `analyze_xor_decode_window()` |
| CreateProcess 标志解码 | ✅ **已实现** | `static_analysis.py` 可解析 `0x09080008` 标志位 |
| 跨函数调用链 | ⚠️ **部分实现** | `build_cross_function_chains()` 存在但边界有限 |
| 递归线索追踪 | ❌ **未实现** | 无 "发现 explorer.exe → 追踪 Xref → 发现 OpenProcess" 循环 |
| Phase 1-8 时序恢复 | ⚠️ **有基础** | Relation 图可构建时序，但无自动推导 |
| 动态 API 名称解析 | ✅ **已实现** | WinHTTP API 解码验证存在 |
| PPID Spoofing 完整链 | ⚠️ **可生成部分 Evidence** | 可识别 API，但无"假设 → 验证 → 升级为 Claim"循环 |

**关键差距**: Resume 报告的深度来自**人工分析师的递归调查**:
```
发现 explorer.exe 字符串
  → 追踪 Xref
  → 发现进程枚举
  → 追踪 PID 使用
  → 发现 OpenProcess
  → 追踪句柄使用
  → 发现 UpdateProcThreadAttribute
  → 验证常量
  → 确认 PPID Spoofing
```

当前系统缺少这个**"发现 → 追踪 → 发现"的循环驱动器**。

---

## 第四部分：测试结果验证

### 4.1 代码测试覆盖

**测试通过情况**:
```
pytest -q: 199 passed
ruff: All checks passed
compileall: 通过
```

✅ **单元测试完整且通过**

**但测试内容分析**:
```python
# test_agents.py
def test_triage_agent_assigns_document_role_with_versioned_prompt_metadata()
def test_static_agent_derives_supported_behavior_claims_from_static_facts()
def test_static_agent_does_not_infer_behavior_from_unrelated_facts()
```

⚠️ **测试仅覆盖确定性规则引擎** - 无 Investigation Thread 状态转换、Action Proposal 验证、或递归调查循环的测试

### 4.2 Resume 样本端到端测试

**官方报告声称**:
```
Resume.pdf ... .exe.VIR:
  - lifecycle SUCCEEDED, outcome PARTIAL
  - 14 Artifacts, 61,173 Evidence, 200 Claims, 658 Relations
  - 135 mechanism/cross-function Claims
  - 17 candidate ATT&CK mappings
```

✅ **系统可处理 Resume 样本**  
⚠️ **但结果为 PARTIAL，非 COMPLETE**

**PARTIAL 原因**:
> "bounded resource/decoded children are not all recognized as PE/script/document types"

**审查意见**: 系统成功提取了大量 Evidence，但 **PARTIAL 状态表明未达到 Resume 报告所需的完整深度**。

---

## 第五部分：严重缺失项

### 5.1 核心缺失: 递归调查循环

**需求文档第三轮核心**:
> "证据驱动递归调查法 (Evidence-Driven Recursive Investigation)"  
> "Hypothesis → What evidence is missing? → Action → Evidence → Update Hypothesis"

**当前状态**: **完全未实现**

**影响**: 这是第三轮迭代的**核心需求**，缺失意味着系统无法实现"像分析师一样思考和追踪线索"的目标。

### 5.2 核心缺失: Investigation Queue 调度器

**需求文档第十节**:
> "Investigation Queue 才是 Orchestrator 的核心"  
> "Priority Queue 按价值排序问题"

**当前状态**: **不存在**

- DeterministicSeedRanker 可生成种子
- 但无队列调度器决定先分析哪个、何时继续、何时停止

### 5.3 核心缺失: Verifier Agent 与 Investigator Agent 分离

**需求文档第十二节**:
> "Verifier Agent 和 Investigator Agent 必须拆开"  
> "不要让同一个 Agent 提出结论 + 验证自己的结论"

**当前状态**: **未分离**

当前仅有 `StaticAnalysisAgent.propose_claims()`，没有独立的验证器角色。

### 5.4 核心缺失: Claim Gate

**需求文档第十三节**:
> "Claim Gate 必须是代码，不是 Prompt"  
> "required evidence: process enumeration AND target process match AND OpenProcess..."

**当前状态**: **无 Claim Gate 逻辑**

Claim 直接从 `propose_claims()` 生成，无证据完整性门限检查。

---

## 第六部分：已实现的亮点

尽管存在重大缺失，以下组件已实现且质量较高:

### 6.1 ✅ 四通道输入隔离
```python
# contracts.py:43-48
class FourChannelInput(FrozenContract):
    task_request: TaskRequestInput
    sample_package: SamplePackageInput
    background_context: BackgroundContextInput
    knowledge_snapshot: KnowledgeSnapshotInput
```
**质量评价**: 完整实现，符合 W2 要求

### 6.2 ✅ 审计链与 HMAC 封印
- AuditEvent、AuditChainHead、AuditSeal 完整
- HMAC 签名验证存在
- 支持审计链完整性检查

### 6.3 ✅ XOR 静态验证
```python
def verify_xor_decode_candidate(
    ciphertext: bytes,
    key_table: bytes,
    counter_initial: int,
    counter_step: int
) -> bytes | None
```
**质量评价**: 满足 Resume 报告中 XOR 解密需求

### 6.4 ✅ 跨函数机制链
```python
def build_cross_function_chains(...) -> tuple[ChainFact, ...]
```
**质量评价**: 可生成函数调用链，但边界有限

### 6.5 ✅ Methodology 信号提取
```python
# methodology.py:247-298
def build_profile(observations, *, name, artifact_id, fact_library) -> AnalysisProfile
```
**质量评价**: 六维信号提取 (loading_chain, cryptography, c2_design, anti_analysis, build_system, codenames) 完整实现

---

## 第七部分：最终判定

### 7.1 需求满足度评分

| 需求类别 | 满足度 | 评分 (0-100) |
|---|---|---|
| **数据模型** | 契约完整，部分无表 | 70 |
| **状态机定义** | 状态枚举存在，转换缺失 | 40 |
| **递归调查循环** | 完全缺失 | 0 |
| **Action Catalog** | 完全缺失 | 0 |
| **Context Builder** | 基础实现，缺细节 | 60 |
| **Mechanism 层** | 契约存在，生成有限 | 50 |
| **Hypothesis ↔ Claim** | 分离不完整 | 40 |
| **Verifier 独立性** | 未分离 | 0 |
| **Claim Gate** | 完全缺失 | 0 |
| **动态模拟器** | 仅探测器 | 10 |
| **XOR 静态验证** | 完整实现 | 100 |
| **跨函数链** | 部分实现 | 60 |
| **审计链** | 完整实现 | 100 |
| **报告生成** | 完整实现 | 95 |

**综合满足度**: **42.5% (425/1000)**

### 7.2 关键问题总结

**架构层面**:
1. ❌ 缺少核心的 **Investigation Loop Driver**
2. ❌ 缺少 **Investigation Queue** 和优先级调度
3. ❌ 缺少 **Action Catalog** 及其执行器

**Agent 层面**:
4. ❌ Investigator 与 Verifier 未分离
5. ❌ Hypothesis 无持久化表
6. ❌ 无 Hypothesis → Claim 升级逻辑
7. ❌ 无 Claim Gate 证据门限检查

**工具层面**:
8. ❌ 动态模拟器完全未集成
9. ⚠️ Action Catalog 缺失导致无法支持"TRACE_API_ARGUMENT"等需求操作

**能力层面**:
10. ⚠️ 可处理 Resume 样本但结果为 PARTIAL
11. ⚠️ 无法自动完成"发现线索 → 追踪 Xref → 发现新证据"的递归调查

---

## 第八部分：差距分析

### 8.1 与第三轮需求的差距

**第三轮文档标题**: "Agentic Reverse Engineering State Machine"

**核心承诺**:
> "这三个东西叠起来，我认为已经不只是方法论了，实际上已经是一套可以开始编码的 Agentic Reverse Engineering Engine。"

**实际状态**:
- ✅ 数据模型已定义 (InvestigationThread, Hypothesis, Mechanism)
- ❌ **状态机引擎未实现**
- ❌ **Agentic 特性缺失** (无模型驱动的假设、动作提议、验证循环)

当前系统本质上仍是 **静态分析规则引擎 + LLM 可选增强**，而非第三轮要求的 **Agentic Investigation Engine**。

### 8.2 与 Resume 报告深度的差距

**Resume 报告关键特征**:
1. 完整的 Phase 1-8 行为时序
2. XOR 配置的完整算法恢复
3. PPID Spoofing 的完整证据链
4. 动态 API 名称的完整解密

**当前系统能力**:
1. ⚠️ 可生成 Relation 和部分时序，但无自动推导
2. ✅ XOR 算法恢复已实现
3. ⚠️ 可识别相关 API，但无"假设 → 验证 → 确认"循环
4. ✅ API 名称解密已实现

**根本差距**: Resume 报告的深度来自**分析师的递归调查思维**，当前系统只能做**一次性静态扫描 + 规则匹配**。

---

## 第九部分：建议

### 9.1 是否满足用户目标？

**用户原始目标**:
> "我们的目的就是无论我们分析什么样的样本，都可以产出如我给你的这份报告一般的深度和广度以及抓取能力"

**审查结论**: **不满足**

**理由**:
1. Resume 报告的深度来自递归调查，当前系统无此能力
2. 动态模拟器未集成，无法覆盖动态行为分析
3. Investigation Loop 缺失，无法"发现线索 → 追踪 → 再发现"

### 9.2 建议的补全优先级

**P0 (必须实现)**:
1. **Investigation Loop Driver** - 核心递归调查引擎
2. **Investigation Queue** - 问题优先级调度
3. **Action Catalog** - 至少 10-15 种基础动作
4. **Hypothesis 持久化** - 创建数据库表
5. **Claim Gate** - 证据完整性检查

**P1 (重要但可后续)**:
6. Verifier Agent 分离
7. Context Builder 增强 (P-code, call graph)
8. Mechanism 生成系统化
9. 动态模拟器集成 (至少一种)

**P2 (优化)**:
10. Investigation Thread 状态转换可视化
11. Unknown/Contradiction 持久化
12. Relation 自动时序推导

### 9.3 技术债务警告

当前系统存在**概念性技术债务**:

1. **命名不匹配**: 许多组件名为"Investigation"但实际是静态规则引擎
2. **契约空壳**: InvestigationThread/Hypothesis/Mechanism 定义完整但使用有限
3. **架构承诺未兑现**: 文档和代码注释承诺了 Agentic 能力，但未实现

**建议**: 在对外宣称"已实现第三轮迭代"之前，必须补全核心的 Investigation Loop，否则会造成能力预期与实际的巨大落差。

---

## 附录A: 代码结构统计

**总代码量**: 18,235 行 (src/threat_report_agent/*.py)

**核心文件**:
- service.py: 2,776 行 (主服务逻辑)
- static_analysis.py: 939 行 (静态分析)
- tool_execution.py: 843 行 (Temporal 工作流)
- methodology.py: 628 行 (信号提取)
- reporting.py: 未统计 (报告生成)

**Investigation 相关**:
- contracts.py: InvestigationThread (65-86), Hypothesis (88-96), Mechanism (98-106)
- orchestration.py: DeterministicSeedRanker (50-94), QuestionCentricContextBuilder (96-134)
- 实际状态机逻辑: **0 行**

---

## 附录B: 测试覆盖分析

**测试通过**: 199 passed

**测试类型分布**:
- 单元测试: Triage, StaticAnalysis, XOR 验证, 函数相似度
- 集成测试: 端到端 Resume/ComHost 样本处理
- 契约测试: FourChannelInput, ActionProposal 验证

**缺失的测试**:
- ❌ Investigation Thread 状态转换
- ❌ Action Proposal 执行与验证
- ❌ Hypothesis 生成与更新
- ❌ Claim Gate 证据完整性
- ❌ 递归调查循环

---

## 结论

当前实现在**数据模型和基础组件**层面完成度较高 (约 70%)，但在**核心 Agentic Investigation 能力**层面完成度极低 (约 10%)。

系统**可以运行**，可以处理样本并生成报告，但**无法达到用户期望的 Resume 报告级别的深度和递归调查能力**。

**最关键的差距**: 第三轮迭代文档的核心 —— **"证据驱动递归调查法"** —— 在当前代码中**不存在**。

---

**审查人员**: Claude Opus 5 (代码审查 Agent)  
**审查完成时间**: 2026-08-26
