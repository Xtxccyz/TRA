"""Official analyst report — not the investigation ledger.

The GET `/report` markdown must read like a malware analysis write-up.  Topics
come from the behavior catalog, PMA static rules, and evidence on THIS sample.
There is no preset C2/persist/inject outline.

This module does not append Executive Assessment, Seed Map, coverage
dictionaries, function-semantic dumps, or Evidence UUIDs.  Those stay in the
V3 ledger / Evidence Explorer.  Candidate mechanisms may be narrated as
recovered static facts; they are not upgraded to verified.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Iterable, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator

from threat_report_agent.behavior_catalog import BehaviorCatalog
from threat_report_agent.investigation_protocol import (
    TOOL_AUTHORING_REQUIRED_MARKER,
    is_empty_marker,
    tool_authoring_required_entries,
)
from threat_report_agent.mechanism_ready import inspect_mechanism_ready
from threat_report_agent.product_certification import repair_static_runtime_wording
from threat_report_agent.product_certification import static_wording_violations
from threat_report_agent.reporting import (
    _STRING_FACT_PATTERNS,
    _is_file_hash_source,
    build_process_flag_projections,
    string_fact_class,
)
from threat_report_agent.static_analysis import credible_windows_process_creation_flags


ANALYST_CONCLUSION_HEADING = "## 分析结论"
ANALYST_APPENDIX_HEADING = "## 调查附录（内部账本，非分析结论）"

_GENERIC_SEEDS = frozenset(
    {
        "decode", "decrypt", "connect", "recv", "poll", "retry", "heartbeat",
        "jitter", "back-off", "switch", "strcmp", "strncmp", "memcmp", "memcpy",
        "dispatcher", "opcode", "resource", "embedded", "decompress", "drop",
        "driver", "mutex", "clipboard", "upload", "exfil", "archive",
        "screenshot", "timestomp", "unhook", "sandbox", "mining", "com",
        "sam", "dos", "http", "tls",
    }
)

CATALOG_TITLES_ZH: dict[str, str] = {
    "file-operations": "文件操作",
    "file-metadata": "文件元数据与时间戳",
    "registry-operations": "注册表操作",
    "process-creation": "进程创建",
    "child-process-output": "子进程输出捕获",
    "parent-process-spoofing": "父进程伪装（PPID）",
    "identity-and-privilege": "身份与权限",
    "thread-and-callback": "线程、TLS 回调与 APC",
    "process-injection": "进程注入与隐蔽启动",
    "memory-and-mapping": "内存分配与映射",
    "loader-and-api-resolution": "动态加载与 API 解析",
    "config-and-crypto": "编码、解密与配置还原",
    "multi-stage-payload": "多阶段载荷",
    "network-transport": "网络通信",
    "communication-loop": "通信循环与心跳",
    "command-dispatch": "命令分发",
    "persistence": "持久化",
    "service-and-driver": "服务与驱动",
    "host-discovery": "主机发现",
    "environment-guard": "环境探测与反分析门控",
    "defense-evasion": "防御规避",
    "credentials-and-sensitive-data": "凭据与敏感数据",
    "collection-and-exfiltration": "收集与外传",
    "ipc": "进程间通信",
    "lateral-movement": "横向移动",
    "impact-and-resource-abuse": "破坏与资源滥用",
    "custom:packer": "加壳与导入表可信度",
    "custom:com": "COM 对象创建",
    "custom:com-hijack": "COM 劫持",
}

# Import/string seeds may open a chapter only for PMA-high-value hypotheses.
# GetSystemInfo/VirtualAlloc alone are listed under 样本概况, not as empty chapters.
_SEED_OPEN_FROM_IMPORTS = frozenset(
    {
        "loader-and-api-resolution",
        "config-and-crypto",
        "thread-and-callback",
        "multi-stage-payload",
        "network-transport",
        "persistence",
        "process-injection",
        "process-creation",
        "registry-operations",
        "parent-process-spoofing",
        # The environment/anti-analysis guard was reachable only through a row
        # that already carried ``catalog_id == "environment-guard"``, and the
        # persist-how playbook for it (``v3-environment-guard``) does not always
        # close.  For a sample whose whole first phase is
        # GetConsoleWindow/GetTickCount64/GetSystemInfo/GlobalMemoryStatus and
        # which compares those results against 0x493e1 and 0x60000000, that left
        # the capability with NO chapter at all -- so the recovered thresholds
        # could not be published even once they were projected.  Its
        # discovery_seeds are concrete API names, not generic tokens, so seeding
        # from them does not open empty chapters for unrelated samples.
        "environment-guard",
    }
)

_MECHANISM_ROW_TYPES = frozenset(
    {
        "mechanism_candidate",
        "mechanism_link",
        "mechanism_observation",
        "verified_mechanism",
        "security_finding",
    }
)

# 分析报告必写面（G4 §8.2-2 / ADR-0032 能力类型）。这些类目对 PE 适用，主文必须
# 各有一节：命中写 HOW，未命中写 UNMATCHED_CATEGORY_TEMPLATE。其余类目命中才
# 开章——行为目录仍是调查地图，不是每份报告的固定章节。
_MANDATORY_WINDOWS_CHAPTER_IDS = (
    "config-and-crypto",
    "network-transport",
    "process-creation",
    "parent-process-spoofing",
    "process-injection",
    "persistence",
    "thread-and-callback",
    # Attribution is mandatory for a different reason than the capability chapters above. Those exist so a
    # reader can tell "searched, found nothing" from "not searched". Attribution exists because "which
    # actor is this" is the first question asked of a targeted sample, and the chapter was simply OMITTED
    # when no validated fact matched - measured on the 白象 sample `64da3378` (task `0da01730`), where the
    # published body contained zero occurrences of 归因/attribution, so a reader could not tell whether the
    # question had been asked. The product's own `attribution` module answers "no independently validated
    # attribution evidence", and that answer belongs in the body.
    "attribution",
)


def _windows_categories_apply(rows: Sequence[Mapping[str, object]]) -> bool:
    """True when the sample is a Windows PE, so the mandatory set applies."""
    for row in rows:
        if str(row.get("type") or "") not in {"pe", "pe_basics"}:
            continue
        fmt = str(row.get("format") or "").strip().casefold()
        machine = str(row.get("machine") or "").strip()
        detected = str(
            row.get("detected_type") or row.get("artifact_type") or ""
        ).strip().casefold()
        if fmt.startswith("pe") or machine or detected == "pe":
            return True
    return False

_NOTABLE_API_RE = re.compile(
    r"\b(?:Create(?:Remote)?Thread|QueueUserAPC|TlsAlloc|LoadLibrary[AW]?|"
    r"GetProcAddress|Crypt(?:Decrypt|Encrypt|AcquireContext)[AW]?|"
    r"FindResource[AW]?|LoadResource|LockResource|SizeofResource|"
    r"VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|WriteProcessMemory|"
    r"CreateProcess[AW]?|WinHttp\w+|Internet\w+|RegSetValue\w*)\b",
    re.IGNORECASE,
)
_PATH_RE = re.compile(r"([A-Za-z]:\\[^\s`'\"\]]+)")
_URL_RE = re.compile(r"https?://[^\s`]+", re.I)
_PLAINTEXT_RE = re.compile(r"plaintext=`([^`]+)`", re.I)
_CONSUMER_RE = re.compile(r"consumer\s*=\s*`?([^`\s;]+)`?", re.I)

_CRT_EXACT = frozenset(
    {
        "memcpy", "memmove", "memset", "memcmp", "memchr",
        "malloc", "calloc", "realloc", "free", "_msize",
        "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat", "strncat",
        "strchr", "strrchr", "strstr", "strtok", "strcspn", "strspn",
        "sprintf", "snprintf", "vsprintf", "printf", "fprintf", "sscanf",
        "atoi", "atol", "atof", "strtoul", "strtol", "getenv", "abort", "exit",
        "wcslen", "wcscmp", "wcsncmp", "wcscpy", "wcsncpy", "wcscat", "wcsncat",
        "wcschr", "wcsstr", "wcstoul", "towlower", "towupper", "tolower", "toupper",
        "iswalpha", "iswspace", "iswxdigit", "isalnum", "isalpha", "isdigit",
        "isspace", "isxdigit", "mbstowcs", "wcstombs", "mbtowc", "wctomb",
        "operator_new", "operator_delete", "__chkstk", "__security_check_cookie",
        "atexit", "_cexit", "_initterm",
    }
)

_INJECTION_CONFIRM = (
    "writeprocessmemory", "virtualallocex", "ntmapviewofsection",
    "zwmapviewofsection", "createremotethread", "ntunmapviewofsection",
)

_PRIMARY_JARGON = (
    "downstream consumer",
    "downstream_static",
    "field completeness",
    "behavior-finding:candidate-mechanism",
    "pipeline completion",
    "semantic analysis coverage",
    # REMOVED: `"unknown(parameter)"`. It is not ledger jargon - it is a token THIS PRODUCT emits:
    # `UNKNOWN(parameter)` is written by `reporting.py` (6 sites) and `persist_how.py` (2 sites) as the
    # honest "this thread parameter was not recovered" value. Because the check below casefolds, listing it
    # here made the product's own legitimate output a gate violation, and the report was thrown away for
    # saying exactly what it is supposed to say.
    "investigation seed map",
    "executive assessment",
    "选题依据",
)

_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_LEDGER_ID_KEYS = frozenset(
    {
        "id",
        "evidence_id",
        "evidence_ids",
        "claim_id",
        "claim_ids",
        "artifact_id",
        "task_id",
        "case_id",
        "thread_id",
        "action_id",
        "model_call_id",
        "finding_id",
        "mechanism_id",
        "revision_id",
    }
)
_HEX_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{6,16}")
_START_RE = re.compile(
    r"(?:lpStartAddress|start_routine|(?<![A-Za-z_])start)\s*=\s*(0x[0-9a-fA-F]+)",
    re.IGNORECASE,
)
_FUN_DUMP_RE = re.compile(r"FUN_[0-9a-fA-F]{6,}@[0-9a-fA-F]{6,}:")
_FUN_NAME_RE = re.compile(r"FUN_[0-9A-Fa-f]{4,}(?:@[0-9A-Fa-f]+)?")
_UNKNOWN_TOKEN_RE = re.compile(r"UNKNOWN\([^)]+\)", re.IGNORECASE)

# Wiring D: three ways an analysis can stop, kept apart on purpose.
#
# A report that renders every open slot as one undifferentiated "UNKNOWN" list
# makes a failure to read the file look identical to a correct refusal to invent
# a runtime fact.  The three kinds below are the taxonomy the analyst needs:
#
#   RECOVERABLE  the slot is derivable from the bytes already in hand; leaving it
#                open is a capability failure and must be reported as one.
#   RUNTIME      the fact only exists once the sample runs; static analysis is
#                allowed to leave it unknown permanently.
#   TOOL_BLOCKED a tool was genuinely attempted for this gap and tool authoring
#                did not resolve it; the concrete blocker has to be named.
STOP_KIND_RECOVERABLE = "RECOVERABLE_IN_IMAGE_NOT_RECOVERED"
STOP_KIND_RUNTIME = "RUNTIME_UNOBSERVABLE_BY_DESIGN"
STOP_KIND_TOOL_BLOCKED = "TOOL_AUTHORING_ATTEMPTED_UNRESOLVED"

STOP_KIND_LABELS_ZH: dict[str, str] = {
    STOP_KIND_RECOVERABLE: "镜像内可恢复但你未恢复（能力缺口，属失败）",
    STOP_KIND_RUNTIME: "只有运行样本才能观察（允许保持 UNKNOWN）",
    STOP_KIND_TOOL_BLOCKED: "已真实尝试、工具创作也未能解决（具体阻塞）",
}

# Slots whose truth is produced by the sample at runtime and therefore cannot be
# read out of the file.  Anything NOT listed here defaults to RECOVERABLE: the
# safe default is "we failed to recover it", never "it was unknowable".
_RUNTIME_ONLY_SLOTS: frozenset[str] = frozenset(
    {
        "response",
        "response bytes",
        "response body",
        "server response",
        "liveness",
        "server liveness",
        "runtime parent pid",
        "runtime execution",
        "runtime reachability",
    }
)

# Marker wiring B (tool authoring in the investigation loop) writes into the task
# limitations when an authored tool was attempted and did not close the gap.
TOOL_AUTHORING_BLOCKER_MARKER = "TOOL_AUTHORING_UNRESOLVED:"


def _normalized_slot(token: object) -> str:
    text = str(token or "").strip()
    match = _UNKNOWN_TOKEN_RE.search(text)
    if match:
        text = match.group(0)
    if text.casefold().startswith("unknown(") and text.endswith(")"):
        text = text[len("unknown(") : -1]
    return " ".join(text.split()).casefold()


def classify_stop_kind(token: object) -> str:
    """Which of the three stop kinds an ``UNKNOWN(slot)`` token belongs to.

    Unknown or unrecognised slots fall back to :data:`STOP_KIND_RECOVERABLE`.
    Defaulting the other way would let an unrecovered slot masquerade as a fact
    that static analysis was never able to observe.
    """
    slot = _normalized_slot(token)
    if slot in _RUNTIME_ONLY_SLOTS:
        return STOP_KIND_RUNTIME
    return STOP_KIND_RECOVERABLE


def _tool_authoring_blockers(limitations: Iterable[object]) -> list[str]:
    found: list[str] = []
    for item in limitations or []:
        text = str(item or "").strip()
        index = text.find(TOOL_AUTHORING_BLOCKER_MARKER)
        if index < 0:
            continue
        detail = text[index + len(TOOL_AUTHORING_BLOCKER_MARKER) :].strip()
        if detail:
            found.append(detail)
    return list(dict.fromkeys(found))


def render_stop_kinds(
    unknowns: Iterable[object],
    limitations: Iterable[object] = (),
) -> str:
    """Render the three stop kinds, including the ones that are empty.

    Every kind is always printed: an empty kind is information ("nothing stopped
    here"), while an omitted one reads as if the distinction was never made.
    """
    recoverable: list[str] = []
    runtime: list[str] = []
    for token in unknowns or []:
        text = str(token or "").strip()
        if not text:
            continue
        if classify_stop_kind(text) == STOP_KIND_RUNTIME:
            runtime.append(text)
        else:
            recoverable.append(text)
    recoverable = list(dict.fromkeys(recoverable))
    runtime = list(dict.fromkeys(runtime))
    blocked = _tool_authoring_blockers(limitations)
    required = tool_authoring_required_entries(limitations)

    lines = ["**分析停止原因（三类，必须分开读）：**", ""]
    entries = (
        (STOP_KIND_RECOVERABLE, recoverable),
        (STOP_KIND_RUNTIME, runtime),
        (STOP_KIND_TOOL_BLOCKED, blocked),
    )
    for kind, items in entries:
        label = STOP_KIND_LABELS_ZH[kind]
        if items:
            lines.append(f"- `{kind}`（{label}）：")
            for item in items[:12]:
                lines.append(f"  - {item if kind == STOP_KIND_TOOL_BLOCKED else f'`{item}`'}")
        else:
            lines.append(f"- `{kind}`（{label}）：无")
        # Tickets ride with RECOVERABLE because that is what they are: slots the
        # image should yield.  They are printed under their own sub-heading so a
        # "needs a tool we lack" record can never be mistaken for the third kind,
        # which would mean an authoring attempt actually happened.
        if kind == STOP_KIND_RECOVERABLE and required:
            lines.append("  - 其中需要产品当前没有的工具（**创作未尝试**，仅登记需求）：")
            for item in required[:12]:
                # Keep the marker literal in the report so the audit trail is
                # greppable back to the limitation the loop recorded.
                lines.append(f"    - `{TOOL_AUTHORING_REQUIRED_MARKER}` {item}")
    lines.append("")
    return "\n".join(lines)

_APT_TOKEN_RE = re.compile(
    r"\b(?:APT-?\d+|lazarus|cozy\s*bear|fancy\s*bear|equation\s*group|kimsuky)\b",
    re.IGNORECASE,
)

# Official GET ten-question projection. Empty / placeholder text is not a fill.
_OFFICIAL_TEN_QUESTION_SLOTS: tuple[tuple[str, str, tuple[str, ...], str], ...] = (
    ("what", "What", ("what", "finding", "statement"), "initiator"),
    ("how", "How", ("how", "transformation_or_control", "mechanism"), "transformation"),
    ("target", "Target", ("target",), "state_config"),
    ("condition", "Condition", ("condition", "conditions"), "condition"),
    ("output", "Output", ("output", "outputs"), "output"),
    ("consumer", "Consumer", ("consumer", "consumers"), "consumer"),
    ("loop", "Loop", ("loop",), "loop"),
    ("failure_fallback", "Failure/fallback", ("failure_fallback", "fallback"), "failure_fallback"),
)


class AnalystChapterDraft(BaseModel):
    model_config = ConfigDict(extra="ignore")
    catalog_id: str = ""
    title: str = ""
    evidence_anchors: list[str] = Field(default_factory=list)
    notes: str = ""


class AnalystSlotProposal(BaseModel):
    """A slot the MODEL proposes, together with the evidence substring that must support it.

    The model chooses the slot NAME. The eight official slots are a FLOOR, not a ceiling, because a fixed
    schema cannot be right for every sample: for the 白象 VB6 loader the eight questions are asked about the
    host binary while the behaviour lives in a decoded script, so the fixed slots can only ever answer
    `UNKNOWN`. MEASURED basis for that claim - the recovered text contains `On Error`, `Resume`, `Loop`,
    `XMLHTTP`, `ADODB`, `Exec`, i.e. the answers, while nothing attributed them to a slot.

    `evidence_source` names WHICH corpus the substring must appear in, so "what counts as evidence" adapts
    per sample and per slot instead of being hard-coded here. There is deliberately NO cap on the number of
    proposals: the count emerges from how many survive verification. A cap would be the crude mechanical
    limit the plan rejects, and it would not even work - an invented slot sorts just as high as a real one.
    """

    model_config = ConfigDict(extra="ignore")

    slot: str = ""
    value: str = ""
    evidence_substring: str = ""
    evidence_source: str = "recovered_script"


class AnalystReportPlanEnvelope(BaseModel):
    model_config = ConfigDict(extra="ignore")
    chapters: list[AnalystChapterDraft] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    #: `extra="ignore"` meant a model emitting `slots` today had them SILENTLY DROPPED. Declaring the field
    #: is what makes the proposal reachable at all.
    slots: list[AnalystSlotProposal] = Field(default_factory=list)

    @field_validator("slots", mode="before")
    @classmethod
    def _tolerate_whatever_the_model_sent(cls, value: object) -> list[object]:
        """Keep the proposals that are objects; drop the rest instead of failing the WHOLE envelope.

        MEASURED REGRESSION this exists for: task `ee909da0` ran with `slots` declared strictly and BOTH
        `analyst_report_overlay` attempts FAILED - one `ValidationError`, one `JSONDecodeError` - so the whole
        model plan, chapters included, was thrown away and the run published no proposals at all. Declaring a
        new field turned an unknown key (previously ignored) into a way for one malformed element to destroy
        everything else in the response.

        A model writing free-form JSON will sometimes send a string, a list of strings, or `null` here. None of
        those is worth losing the chapters for, and `verify_model_slot_proposals` is what decides whether a
        proposal is usable - so this layer only has to be non-fatal.
        """
        if value is None:
            return []
        if isinstance(value, Mapping):
            return [value]
        if isinstance(value, str):
            return []
        if isinstance(value, (list, tuple)):
            return [item for item in value if isinstance(item, Mapping)]
        return []


#: How strong a claim each evidence corpus can support, and therefore what boundary sentence a slot filled
#: from it must carry. Derived from the source rather than written once, because the three corpora license
#: genuinely different statements - collapsing them into one template is what lets a string read as a fact.
_SLOT_EVIDENCE_BOUNDARY: Mapping[str, str] = {
    "recovered_script": (
        "该构造逐字存在于恢复出的脚本文本中；文本是分片拼接的，"
        "**这只证明脚本含有该构造，不证明该路径在目标主机上执行过**。"
    ),
    "disassembly": "静态反汇编中可见该调用点；**不证明运行时到达过该指令**。",
    "imports": "该 API 出现在导入表中；**导入存在不等于运行时已发生**。",
    "emulation_observation": "隔离仿真中观察到该值；**不是目标主机上的运行时执行**。",
}

#: A proposal whose `evidence_source` names no corpus is UNSUPPORTED, not passed. Silence here would let a
#: model invent a corpus name and have the substring "verified" against nothing.
_UNKNOWN_SOURCE_BOUNDARY = "证据来源未被识别，因此该槽位未被采纳。"


def verify_model_slot_proposals(
    proposals: Sequence[Mapping[str, object]],
    corpora: Mapping[str, str],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Split model proposals into (supported, rejected) by checking the substring against its corpus.

    Returns BOTH lists rather than filtering silently: `rejected` is the audit trail that shows what the model
    proposed and why it did not survive, which is what makes the accepted set trustworthy.

    The check is a literal, case-sensitive substring test - mechanical, cheap, and independent of the model.
    It deliberately does NOT check whether the substring means what the model says it means. That is the
    honest limit of this function, and it is why a supported slot is written as a CANDIDATE (a Claim status),
    never as a verified fact, and why every accepted slot carries the boundary sentence for its corpus.
    """
    supported: list[dict[str, object]] = []
    rejected: list[dict[str, object]] = []
    for raw in proposals:
        proposal = AnalystSlotProposal.model_validate(dict(raw))
        slot = proposal.slot.strip()
        value = proposal.value.strip()
        substring = proposal.evidence_substring
        source = proposal.evidence_source.strip() or "recovered_script"
        reason = ""
        if not slot or not re.fullmatch(r"[A-Za-z0-9_ +/\-]{1,60}", slot):
            reason = "slot name is not usable"
        elif not value:
            reason = "no value proposed"
        elif not substring:
            reason = "no evidence substring proposed"
        elif source not in corpora:
            reason = f"unknown evidence_source {source!r}"
        elif substring not in corpora[source]:
            reason = f"substring not found in {source}"
        if reason:
            rejected.append({"slot": slot, "value": value, "source": source, "reason": reason})
            continue
        supported.append(
            {
                "slot": slot,
                "value": value,
                "evidence_source": source,
                "evidence_substring": substring,
                # NOT `status: "CANDIDATE"`. CANDIDATE is a CLAIM status (`CONTEXT.md`: a claim has
                # candidate/verified/disputed/rejected), and a slot proposal is not a claim - it has no
                # `evidence_id`, and stamping a Claim status on it is cross-layer promotion by field name
                # (behavior plan §12.5 item 1). The honest description of what was checked is the support
                # KIND, so the field says exactly that.
                #
                # NOT `substring_verified` either, which is what this said first. `verified` is the RESERVED
                # Claim state (`CONTEXT.md`), and the docstring above states plainly that this function does
                # NOT check whether the substring means what the model says it means - so `verified` named a
                # verification that never happened. The check is a literal match. The value says `matched`.
                #
                # The value is MACHINE-facing and is NOT what the body prints: a Chinese analyst body renders
                # the wording below, because `CONTEXT.md` keeps ledger identifiers in the appendix and out of
                # 正文. An earlier version printed this token verbatim at both render sites.
                "support": "substring_matched",
                "boundary": _SLOT_EVIDENCE_BOUNDARY.get(source, _UNKNOWN_SOURCE_BOUNDARY),
            }
        )
    return supported, rejected


def slot_evidence_corpora(document: Mapping[str, object]) -> dict[str, str]:
    """The corpora a model proposal may be checked against, built from THIS document.

    Per-sample rather than fixed, because what counts as evidence differs by sample: a VB6 loader's behaviour
    is in a decoded script, a native implant's is in its disassembly and imports. A slot naming a corpus that
    is absent here is rejected by `verify_model_slot_proposals`, which is why an unusable corpus must simply
    not appear rather than appear empty.

    Note the asymmetry with `document_topic_haystack`: that function answers "what may a CHAPTER anchor on"
    and is deliberately generous; these corpora answer "what may be CALLED evidence for a slot", so each one
    is kept to a single, nameable kind of observation.
    """
    scripts: list[str] = []
    imports: list[str] = []
    call_sites: list[str] = []
    observations: list[str] = []
    for row in iter_document_rows(document):
        for key in ("recovered_text", "decoded_text", "plaintext"):
            value = row.get(key)
            if isinstance(value, str) and value.strip():
                scripts.append(value)
        for key in ("inputs", "outputs", "output"):
            value = row.get(key)
            for item in value if isinstance(value, list) else [value]:
                # MEASURED: the 5,881-character script reaches the document here, not on the decode row,
                # whose `decoded_preview` is empty.
                if isinstance(item, str) and len(item) > 256:
                    scripts.append(item)
        raw_imports = row.get("imports")
        if isinstance(raw_imports, list):
            imports.extend(str(item) for item in raw_imports if str(item).strip())
        for key in ("api", "api_name", "resolved_api", "target_name", "callee"):
            value = row.get(key)
            if isinstance(value, str) and value.strip():
                call_sites.append(value)
        sequence = row.get("call_sequence")
        if isinstance(sequence, list):
            for call in sequence:
                if isinstance(call, Mapping) and str(call.get("api") or "").strip():
                    call_sites.append(str(call["api"]))
        if str(row.get("nature") or row.get("evidence_natures") or "").upper().find("EMULATION") >= 0:
            for key in ("observed_apis", "stop_reason", "detail"):
                value = row.get(key)
                if isinstance(value, str) and value.strip():
                    observations.append(value)
    corpora: dict[str, str] = {}
    if scripts:
        corpora["recovered_script"] = "\n".join(dict.fromkeys(scripts))
    if imports:
        corpora["imports"] = " ".join(dict.fromkeys(imports))
    if call_sites:
        corpora["disassembly"] = " ".join(dict.fromkeys(call_sites))
    if observations:
        corpora["emulation_observation"] = " ".join(dict.fromkeys(observations))
    return corpora


@dataclass(frozen=True)
class AnalystTopic:
    catalog_id: str
    title: str
    status: str
    reason: str
    anchors: tuple[str, ...] = ()
    source: str = "catalog"


def split_analyst_markdown(markdown: str) -> tuple[str, str]:
    text = str(markdown or "")
    index = text.find(ANALYST_APPENDIX_HEADING)
    if index < 0:
        return text, ""
    return text[:index].rstrip(), text[index:].lstrip()


def primary_analyst_violations(markdown: str) -> list[str]:
    primary, _appendix = split_analyst_markdown(markdown)
    folded = primary.casefold()
    violations: list[str] = []
    for marker in _PRIMARY_JARGON:
        if marker in folded:
            violations.append(f"primary report contains ledger jargon: {marker}")
    body = primary.split("\n## ", 1)[-1] if "\n## " in primary else primary
    if _UUID_RE.search(body):
        violations.append("primary report contains Evidence/ledger UUIDs")
    if _FUN_DUMP_RE.search(primary):
        violations.append("primary report dumps FUN_ call-sequence ledger lines")
    if "persisted_investigation" in folded:
        violations.append("primary report contains PERSISTED_INVESTIGATION ledger phase")
    if re.search(r"FUN_[0-9A-Fa-f]{4,}", primary):
        violations.append("primary report contains FUN_ ledger names")
    if "pipeline completion" in folded or "semantic analysis coverage" in folded:
        violations.append("primary report contains coverage dictionaries")
    return violations


#: Top-level document projections that are NOT inside `modules[].rows[]`.
#:
#: `iter_document_rows` originally walked only the module rows, and the document's most analyst-facing
#: projections - `string_facts` (24 rows), `pe_resources`, `unique_execution_threads`, `runtime_sequence` -
#: are TOP-LEVEL keys. So a section built on `rows` could not see them, and `_pe_overview`'s own
#: compile-language detector returned "" on a real document that contains `MSVBVM60.DLL` in
#: `string_facts`. Measured on the 白象 sample `64da3378` (task `556767b2`). Unit tests that build module
#: rows by hand pass either way, which is why this took a real document to find.
_TOP_LEVEL_ROW_KEYS = (
    "string_facts",
    "pe_resources",
    "pe_basics",
    "unique_execution_threads",
    "runtime_sequence",
    "tls_callbacks",
    "ordered_static_call_flow",
    "module_deep_dives",
)


def iter_document_rows(document: Mapping[str, object]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for module in document.get("modules") or []:
        if not isinstance(module, Mapping):
            continue
        for row in module.get("rows") or []:
            if not isinstance(row, Mapping):
                continue
            rows.append(dict(row))
            nested = row.get("findings")
            if isinstance(nested, list):
                for item in nested:
                    if isinstance(item, Mapping):
                        rows.append(dict(item))
            # `unclosed_high_value` entries are the OTHER half of the join's input. MEASURED: the
            # document carries 2 of them (`network-transport`, `parent-process-spoofing`) and neither
            # was reachable, so every mandatory topic's `_matched_rows` was 0 and each chapter fell
            # through to the generic "no clue observed" stub - while these entries hold the specific
            # blocker:
            #   network-transport       -> "HTTP transport API not recovered; decoded URLs and
            #                               WinHTTP-export-not-found strings are not a transport path"
            #   parent-process-spoofing -> "parent-process spoofing chain not recovered; CreateProcess
            #                               flags alone do not prove PPID spoofing"
            # They carry no `what`/`how`, so they are deliberately NOT findings (no chapter is opened
            # by them); they exist to state the blocker.
            # NOTE on a measured failed attempt (`.scratch/probe-unclosed-regression.py`): drilling into
            # `unclosed_high_value` here was tried and REVERTED. Those entries carry a sample-specific
            # `reason` ("... parent-process spoofing chain not recovered ..."), and because
            # `iter_document_rows` feeds every topic matcher, the text reached the primary body and
            # tripped the `primary_analyst_violations` gate: `test_c10_t5_benign_contract` asserts
            # `"远程注入" not in official` and FAILED with the rows enabled and PASSED with them disabled.
            # The blocker text is genuinely more specific than the generic stub, so this is worth
            # revisiting - but only with a carrier that cannot inject arbitrary ledger prose into a
            # chapter body, and only after the gate's vocabulary is reconciled with it.
    # Top-level projections carry the same `type`/value shape, so callers that ask "is there a row of type
    # X" must see them too. Bounded by construction: these are the document's own projections, one row per
    # key except the list-valued ones.
    for key in _TOP_LEVEL_ROW_KEYS:
        value = document.get(key)
        if isinstance(value, Mapping):
            rows.append(dict(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, Mapping):
                    rows.append(dict(item))
    return rows


def _bare_api(name: str) -> str:
    text = str(name or "").strip()
    text = text.rsplit("!", 1)[-1]
    text = text.rsplit(".", 1)[-1]
    return text.strip("` ")


def _strip_aw_suffix(name: str) -> str:
    bare = _bare_api(name)
    if len(bare) > 2 and bare[-1] in {"A", "W", "a", "w"} and bare[-2].isalpha():
        return bare[:-1]
    return bare


def _is_runtime_symbol(name: str) -> bool:
    bare = _bare_api(name).casefold()
    if not bare:
        return True
    if bare.startswith("_") or bare.startswith("?"):
        return True
    if bare in _CRT_EXACT:
        return True
    if bare.startswith("operator_"):
        return True
    return False


_NT_BEHAVIOR_MARKERS = (
    "querysysteminformation", "queryinformationprocess", "mapviewofsection",
    "unmapviewofsection", "writevirtualmemory", "allocatevirtualmemory",
    "protectvirtualmemory", "createthread", "queueapc", "setcontextthread",
    "resumethread", "suspendthread", "duplicateobject", "readvirtualmemory",
    "setinformationthread", "openprocess", "opentread", "openthread",
)

# Imports that are analyst-facing facts on their own, so the prefix heuristics in
# `_is_behavior_api` must not filter them out.  Measured need: `ntdll.dll!NtCreateNamedPipeFile`,
# `NtReadFile`, `NtWriteFile` and `shell32.dll!ShellExecuteW` were all dropped from the published
# import list of the accepted revision's task, and those are the sample's named-pipe and
# process-launch primitives.
_ALWAYS_NOTABLE_IMPORTS = frozenset(
    {
        "ntcreatenamedpipefile",
        "ntopenfile",
        "ntreadfile",
        "ntwritefile",
        "ntcreatefile",
        "ntcreatesection",
        "ntmapviewofsection",
        "ntqueryinformationfile",
        "ntsetinformationfile",
        "shellexecutew",
        "shellexecutea",
        "shellexecuteexw",
        "winexec",
        "showwindow",
    }
)


def _is_behavior_api(name: str) -> bool:
    bare = _bare_api(name)
    if _is_runtime_symbol(bare):
        return False
    folded = bare.casefold()
    if len(folded) < 6:
        return False
    # Imports an analyst triages on, regardless of the prefix heuristics below.  Measured on task
    # `ce7e310e`: the ledger's import table holds `ntdll.dll!NtCreateNamedPipeFile`,
    # `ntdll.dll!NtReadFile`, `ntdll.dll!NtWriteFile` and `shell32.dll!ShellExecuteW`, and every one
    # was DROPPED from the published import list - the `nt*` branch requires a marker word that
    # `NtCreateNamedPipeFile` does not contain ("create" was missing), and the prefix list had no
    # `shell`.  The body therefore omitted the named-pipe primitives and the process-launch path
    # entirely, while still claiming to list "与 Windows 行为相关的导入".
    #
    # An exact allow-list is the honest fix: these names are specific enough that no heuristic is
    # needed, and they are precisely the facts an analyst acts on.
    if folded in _ALWAYS_NOTABLE_IMPORTS:
        return True
    if folded.startswith(("nt", "zw")):
        if any(marker in folded for marker in _NT_BEHAVIOR_MARKERS):
            return True
        # Named-pipe, file and section operations are behaviour; the event/semaphore/mutant
        # primitives are NOT.  A first attempt added a bare `"create"` marker here, which pulled in
        # `NtCreateEventPair` / `NtWaitLowEventPair` and broke
        # `test_ntdll_event_pair_imports_are_not_the_behavior_inventory` - those are user-mode
        # synchronisation, not the sample's behaviour inventory.  Matching the OBJECT the call acts
        # on is what separates them.
        return any(
            marker in folded
            for marker in ("namedpipe", "file", "section", "key", "directory")
        )
    prefixes = (
        "create", "openprocess", "openthread", "writefile", "writeprocess",
        "readfile", "loadlibrary", "loadresource", "getproc", "crypt", "virtual",
        "findresource", "lockresource", "sizeofresource", "reg", "winhttp",
        "internet", "wsas", "socket", "connect", "queueuser",
        "tls", "deviceio", "setwindowshook", "adjusttoken", "duplicate",
        # process launch and window/COM surfaces an analyst triages on
        "shell", "winexec", "shellexecute", "showwindow", "createwindow",
        "coinitialize", "oleinitialize", "setwindowshookex",
    )
    return any(folded.startswith(prefix) for prefix in prefixes)


def document_topic_haystack(document: Mapping[str, object]) -> str:
    """Everything the model is allowed to anchor a chapter on.

    THE RECOVERED SCRIPT IS PART OF THIS, and that is a correction rather than an addition. MEASURED: this
    function collected only catalog ids, API names, imports and call sequences, so for a sample whose
    behaviour lives in a decoded script (the 白象 VB6 loader) the script was INVISIBLE to the model when it
    chose chapters - and any anchor it proposed ABOUT the script could not be checked against the thing it
    described. Verifying an anchor against a corpus that does not contain the evidence is a tautology, so
    the corpus has to contain it.

    The script arrives through the `decode_result` row's `recovered_text`/`decoded_text`/`plaintext`
    fields, which is where `static_analysis` publishes it (bounded there at 8 KiB).
    """
    tokens: list[str] = []
    scripts: list[str] = []
    for row in iter_document_rows(document):
        catalog_id = str(row.get("catalog_id") or "").strip()
        if catalog_id:
            tokens.append(catalog_id)
        for key in ("api", "api_name", "resolved_api", "target_name", "callee"):
            value = row.get(key)
            if isinstance(value, str) and value.strip() and not _is_runtime_symbol(value):
                tokens.append(_bare_api(value))
        for key in ("recovered_text", "decoded_text", "plaintext"):
            value = row.get(key)
            if isinstance(value, str) and value.strip():
                scripts.append(value)
        # WHERE THE SCRIPT ACTUALLY LIVES. MEASURED on task `69524f41`: all six `decode_result` rows carry
        # `decoded_preview == ""` and `decoded_strings == []`, so the keys above find nothing, yet the
        # 5,881-character script IS in the document at `findings[].outputs[0]` / `inputs[0]` / `output[0]`
        # (and, already, in `ten_question_protocol.input.value[0]` / `output.value`). This is a second
        # place a capability can reach the document but not the reader.
        #
        # The length test selects the recovered BLOB rather than every short input/output label. It is a
        # heuristic, and deliberately not load-bearing: P2.3 verifies a slot's evidence against the
        # recovered text itself, so a haystack that is generous only widens what a chapter may anchor on -
        # it cannot make an unverifiable slot verifiable.
        for key in ("inputs", "outputs", "output"):
            value = row.get(key)
            candidates = value if isinstance(value, list) else [value]
            for item in candidates:
                if isinstance(item, str) and len(item) > 256:
                    scripts.append(item)
        imports = row.get("imports")
        if isinstance(imports, list):
            tokens.extend(
                _bare_api(str(item))
                for item in imports
                if str(item).strip() and not _is_runtime_symbol(str(item))
            )
        value = row.get("value")
        if isinstance(value, Mapping):
            api = value.get("api") or value.get("api_name") or value.get("target_name")
            if isinstance(api, str) and api.strip() and not _is_runtime_symbol(api):
                tokens.append(_bare_api(api))
        sequence = row.get("call_sequence")
        if isinstance(sequence, list):
            for call in sequence:
                if not isinstance(call, Mapping):
                    continue
                api = call.get("api")
                if isinstance(api, str) and not _is_runtime_symbol(api):
                    tokens.append(_bare_api(api))
    haystack = " ".join(dict.fromkeys(token for token in tokens if token))
    if scripts:
        # Appended VERBATIM, not tokenised: an anchor may legitimately be a phrase (`On Error Resume Next`),
        # and splitting the script into words would let the words match in an order the script never had -
        # which would manufacture agreement rather than check it.
        haystack = (haystack + "\n" + "\n".join(dict.fromkeys(scripts))).strip()
    return haystack


def _seed_matches_token(seed: str, token: str) -> bool:
    seed_text = seed.strip().casefold()
    token_text = _bare_api(token).casefold()
    if not seed_text or not token_text:
        return False
    if seed_text in _GENERIC_SEEDS:
        return token_text == seed_text or token_text.endswith(seed_text)
    return seed_text in token_text


def _entry_matches_tokens(entry: object, tokens: Sequence[str]) -> bool:
    seeds = tuple(getattr(entry, "discovery_seeds", ()) or ())
    for seed in seeds:
        if str(seed).strip().casefold() in _GENERIC_SEEDS and len(str(seed)) <= 5:
            continue
        for token in tokens:
            if _seed_matches_token(str(seed), token):
                return True
    return False


def _import_module_groups(row: Mapping[str, object]) -> list[tuple[str, list[str]]]:
    """``[(module, [name, ...]), ...]`` from a projected row, module attribution intact.

    Two shapes reach here.  The projected `pe_basics` row carries `import_entries` - complete,
    ordered and module-attributed - which is what a document built after the fix holds.  Older
    documents (and hand-built fixtures) carry only the flat qualified `imports` list, which is
    grouped here by splitting on `!`.  Reading `import_entries` first is what makes the selection
    order-independent: the flat list is capped, and `kernel32.dll` alone held 70 of the sample's 136
    names, so a `[:limit]` over the flat list could only ever see the first few modules.
    """
    entries = row.get("import_entries")
    groups: list[tuple[str, list[str]]] = []
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            module = str(entry.get("module") or "").strip()
            functions = entry.get("functions")
            names = [
                str(name).strip()
                for name in (functions if isinstance(functions, list) else [])
                if str(name).strip()
            ]
            if names:
                groups.append((module, names))
        if groups:
            return groups
    flat = row.get("imports")
    if not isinstance(flat, list):
        return groups
    for item in flat:
        raw = str(item or "").strip()
        if not raw:
            continue
        module = ""
        head, sep, tail = raw.partition("!")
        if sep:
            function = tail
        else:
            # `module.Api` or a bare `Api`; a bare name keeps an empty module.
            head, _dot, function = raw.rpartition(".")
        if head and function:
            module = head.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].strip()
        if function:
            groups.append((module, [function]))
    return groups


def _document_import_name_total(document: Mapping[str, object]) -> int:
    """How many import names the PE table actually holds, per the projected `pe_basics` row.

    Used only to state the boundary of the bounded, behaviour-filtered import list; ``0`` means the
    document does not record the total, in which case no boundary line is printed.
    """
    for row in iter_document_rows(document):
        if str(row.get("type") or "") != "pe_basics":
            continue
        for key in ("import_name_total", "import_count"):
            value = row.get(key)
            try:
                total = int(value)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue
            if total > 0:
                return total
    return 0


def _notable_imports(
    rows: Sequence[Mapping[str, object]], *, limit: int = 20
) -> list[tuple[str, list[str]]]:
    """Recovered imports grouped by the MODULE they belong to.

    The module is the analyst's first triage fact and it was being thrown away: the report document's
    `pe_basics` row carried a flat list of bare function names, so the published body named NO module
    at all and printed a single `（未限定模块）` bucket. Measured on task `ce7e310e`: 606 of 606
    `code_api_call` rows are module-qualified and the ledger's import table names eight modules
    (advapi32, api-ms-win-core-synch-l1-2-0, kernel32, KERNEL32, msvcrt, ntdll, shell32, user32),
    while the body listed bare function names only. The benchmark report this product is graded
    against names its modules explicitly.

    Grouping keeps the section readable - one line per module instead of one per function - which
    matters because this section is already bounded and the sample has 136 import names.
    """
    grouped: dict[str, list[str]] = {}
    display: dict[str, str] = {}
    for row in rows:
        for module, names in _import_module_groups(row):
            # Module identity is case-insensitive: the PE table can list `kernel32.dll` and
            # `KERNEL32.dll` as separate descriptors, and treating those as two modules both splits
            # one module's line and spends two bounded slots on it. Measured on task `ce7e310e`:
            # `kernel32.dll` (15 shown) plus `KERNEL32.dll` (2) took 17 of the 20 slots, so
            # `shell32.dll` and `ntdll.dll` - the sample's launch and named-pipe primitives - were
            # pushed out of a section that claims to list behaviour imports.
            key = module.casefold()
            # The spelling with the longest function list wins, so the label matches the descriptor
            # the analyst will find in the PE table.
            if key not in display or len(names) > len(grouped.get(key) or []):
                display[key] = module
            for raw in names:
                name = _bare_api(raw)
                if not name or not _is_behavior_api(name):
                    continue
                grouped.setdefault(key, []).append(_strip_aw_suffix(name))
    ordered = sorted(grouped.items(), key=lambda pair: (pair[0] != "", pair[0]))
    return [
        (display.get(key, key) if key else key, names)
        for key, names in _fair_share_imports(ordered, limit)
    ]


def _fair_share_imports(
    ordered: Sequence[tuple[str, Sequence[str]]], limit: int
) -> list[tuple[str, list[str]]]:
    """Give each module a proportional share of a bounded overview.

    Greedy first-come allocation starves modules: `limit=20` over this sample's modules let
    `kernel32.dll` take 15 names and stopped before `shell32.dll`, `user32.dll` and `ntdll.dll` were
    reached at all - not because those modules held nothing, but because one module was larger. An
    analyst reading the section would conclude the sample imports nothing from `ntdll`, which is the
    opposite of the truth. A per-module fair share plus redistribution of unused shares keeps every
    module represented and degrades gracefully when there are more modules than slots.
    """
    if limit <= 0 or not ordered:
        return []
    unique_by_module = [
        (module, list(dict.fromkeys(names))) for module, names in ordered if names
    ]
    if not unique_by_module:
        return []
    allocation = {module: 0 for module, _names in unique_by_module}
    # Floor share, then hand the remainder to the earliest modules so the total is exact.
    share = limit // len(unique_by_module)
    remainder = limit % len(unique_by_module)
    for index, (module, _names) in enumerate(unique_by_module):
        allocation[module] = share + (1 if index < remainder else 0)
    # A module with fewer names than its share does not waste the difference.
    for _ in range(len(unique_by_module) + 1):
        spare = sum(
            allocation[module] - len(names)
            for module, names in unique_by_module
            if allocation[module] > len(names)
        )
        if spare <= 0:
            break
        hungry = [
            (module, names)
            for module, names in unique_by_module
            if allocation[module] < len(names)
        ]
        if not hungry:
            break
        for index, (module, _names) in enumerate(hungry):
            if spare <= 0:
                break
            if index == 0 and spare < len(hungry):
                allocation[module] += spare
                spare = 0
            else:
                allocation[module] += 1
                spare -= 1
    out: list[tuple[str, list[str]]] = []
    for module, names in unique_by_module:
        take = min(allocation[module], len(names))
        if take:
            out.append((module, names[:take]))
    return out


def _finding_status(row: Mapping[str, object]) -> str:
    return str(row.get("finding_status") or row.get("status") or row.get("verdict") or "").upper()


def _is_ledger_id_key(key: object) -> bool:
    folded = str(key or "").casefold()
    if folded in _LEDGER_ID_KEYS:
        return True
    return folded.endswith("_id") or folded.endswith("_ids")


def _strip_ledger_uuids(text: str, *, collapse_spaces: bool = True) -> str:
    cleaned = _UUID_RE.sub("", str(text or ""))
    # After deleting a `uuid` span the leftover is ````, not a gap between
    # adjacent analyst tokens such as `creation_flags` `0x000f4240`.
    cleaned = re.sub(r"``+", "", cleaned)
    if collapse_spaces:
        cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
        return cleaned.strip(" ;,")
    return re.sub(r"[ \t]+\n", "\n", cleaned)


def _scrub_ledger_uuids_from_primary(markdown: str) -> str:
    """Drop Evidence/ledger UUIDs from 分析结论. Keep header case/task/revision."""

    primary, appendix = split_analyst_markdown(markdown)
    if "\n## " in primary:
        head, body = primary.split("\n## ", 1)
        primary = f"{head}\n## {_strip_ledger_uuids(body, collapse_spaces=False)}"
    else:
        primary = _strip_ledger_uuids(primary, collapse_spaces=False)
    if appendix:
        return primary.rstrip() + "\n\n" + appendix.lstrip()
    return primary if primary.endswith("\n") else primary + "\n"


def _field_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, Mapping):
        return _field_text(
            [
                item
                for key, item in value.items()
                if item not in (None, "") and not _is_ledger_id_key(key)
            ]
        )
    if isinstance(value, (list, tuple)):
        return " ".join(part for part in (_field_text(item) for item in value) if part)
    text = str(value).strip()
    if not text:
        return ""
    if _FUN_DUMP_RE.search(text) or "predicate=" in text.casefold() or (
        text.startswith("[") and "FUN_" in text
    ):
        fragments: list[str] = []
        start = _START_RE.search(text)
        if start:
            fragments.append(f"CreateThread lpStartAddress={start.group(1)}")
        fragments.extend(_NOTABLE_API_RE.findall(text))
        return "; ".join(dict.fromkeys(fragments))
    return text


def _how_text(row: Mapping[str, object]) -> str:
    return _field_text(row.get("how") or row.get("mechanism") or row.get("transformation_or_control"))


def _mechanism_records(rows: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for row in rows:
        row_type = str(row.get("type") or "")
        if row_type not in _MECHANISM_ROW_TYPES and not row.get("mechanism_type"):
            continue
        records.append(dict(row))
    return records


def _mechanism_ready(row: Mapping[str, object]) -> bool:
    status = str(row.get("status") or row.get("finding_status") or row.get("verdict") or "").upper()
    if status not in {"VERIFIED", "SUPPORTED", "CONFIRMED"}:
        return False
    payload = dict(row)
    if "verifier" not in payload or not isinstance(payload.get("verifier"), Mapping):
        payload["verifier"] = {"status": status}
    try:
        return inspect_mechanism_ready(payload).critical_ready
    except Exception:
        return False


def _mechanism_label(row: Mapping[str, object], registry: BehaviorCatalog) -> str:
    catalog_id = _mechanism_catalog_id(row, registry)
    title = _title_for(catalog_id) if catalog_id else ""
    raw_type = str(row.get("mechanism_type") or "").strip()
    if title and raw_type and raw_type not in {catalog_id, title}:
        return f"{title}（{raw_type}）"
    return title or raw_type or "未命名机制"


def _network_request_rebuilt(blob: str) -> bool:
    return bool(
        re.search(r"WinHttpOpenRequest", blob, re.I)
        and re.search(r"\b(GET|POST|PUT|HEAD|OPTIONS)\b|https?://", blob, re.I)
    ) or bool(re.search(r"request\s*=\s*(?!UNKNOWN)\S+", blob, re.I))


def _blocking_unknown_demotes_threshold(
    catalog_id: str,
    rows: Sequence[Mapping[str, object]],
) -> bool:
    blob = _blob(rows)
    folded = blob.casefold()
    if catalog_id == "network-transport":
        return "unknown(request)" in folded or not _network_request_rebuilt(blob)
    if catalog_id == "thread-and-callback":
        return "unknown(start_routine)" in folded or "unknown(entry)" in folded
    return False


def _topic_status(
    rows: Sequence[Mapping[str, object]],
    catalog_id: str,
    *,
    mechanisms: Sequence[Mapping[str, object]] = (),
    registry: BehaviorCatalog | None = None,
) -> str:
    catalog = registry or BehaviorCatalog()
    matched = [row for row in rows if str(row.get("catalog_id") or "") == catalog_id]
    if _blocking_unknown_demotes_threshold(catalog_id, matched):
        if any(_how_text(row) for row in matched) or any(_finding_status(row) for row in matched):
            return "partial"
        return "unrecovered"
    if any(
        _mechanism_ready(item) and _mechanism_catalog_id(item, catalog) == catalog_id
        for item in mechanisms
    ):
        return "recovered"
    if any(_how_text(row) for row in matched):
        return "partial"
    if any(_finding_status(row) == "SUPPORTED" for row in matched):
        return "partial"
    return "unrecovered"


def _title_for(catalog_id: str) -> str:
    return CATALOG_TITLES_ZH.get(catalog_id, catalog_id)


def _packer_latched(rows: Sequence[Mapping[str, object]]) -> bool:
    for row in rows:
        if row.get("packer_latch"):
            return True
    return False


def _token_set(haystack: str) -> set[str]:
    return {part.casefold() for part in haystack.split() if part}


def plan_analyst_topics(
    document: Mapping[str, object],
    *,
    model_plan: Sequence[Mapping[str, object]] | None = None,
    catalog: BehaviorCatalog | None = None,
) -> tuple[AnalystTopic, ...]:
    registry = catalog or BehaviorCatalog()
    rows = iter_document_rows(document)
    mechanisms = _mechanism_records(rows)
    haystack = document_topic_haystack(document)
    tokens = tuple(token for token in haystack.split() if token)
    folded_tokens = _token_set(haystack)
    selected: list[AnalystTopic] = []
    seen: set[str] = set()

    for catalog_id in (
        str(row.get("catalog_id") or "").strip()
        for row in rows
        if str(row.get("catalog_id") or "").strip()
    ):
        if catalog_id.startswith("custom:unknown") or catalog_id in {"unique-or-unknown", "unknown_behavior"}:
            continue
        entry = registry.resolve_or_unknown(catalog_id)
        topic_id = entry.id if entry.id != "unique-or-unknown" else catalog_id
        if topic_id in seen or topic_id == "unique-or-unknown" or topic_id not in CATALOG_TITLES_ZH:
            continue
        seen.add(topic_id)
        selected.append(
            AnalystTopic(
                catalog_id=topic_id,
                title=_title_for(topic_id),
                status=_topic_status(rows, catalog_id, mechanisms=mechanisms, registry=registry),
                reason="catalog",
                anchors=(catalog_id,),
                source="catalog",
            )
        )

    for entry in registry.entries:
        if entry.id in seen or entry.id == "unique-or-unknown" or entry.id not in CATALOG_TITLES_ZH:
            continue
        if entry.id not in _SEED_OPEN_FROM_IMPORTS:
            continue
        if not _entry_matches_tokens(entry, tokens):
            continue
        if entry.id == "process-injection" and not any(flag in folded_tokens for flag in _INJECTION_CONFIRM):
            continue
        if entry.id == "command-dispatch":
            continue
        status = _topic_status(rows, entry.id, mechanisms=mechanisms, registry=registry)
        if status == "unrecovered":
            status = "partial"
        seen.add(entry.id)
        selected.append(
            AnalystTopic(
                catalog_id=entry.id,
                title=_title_for(entry.id),
                status=status,
                reason="api",
                anchors=tuple(
                    seed for seed in entry.discovery_seeds
                    if any(_seed_matches_token(seed, token) for token in tokens)
                )[:6],
                source="catalog",
            )
        )

    if _packer_latched(rows) and "custom:packer" not in seen:
        seen.add("custom:packer")
        selected.append(
            AnalystTopic(
                catalog_id="custom:packer",
                title=_title_for("custom:packer"),
                status="partial",
                reason="pma",
                anchors=("LoadLibrary", "GetProcAddress"),
                source="pma",
            )
        )
    if "cocreateinstance" in folded_tokens and "custom:com" not in seen:
        seen.add("custom:com")
        selected.append(
            AnalystTopic(
                catalog_id="custom:com",
                title=_title_for("custom:com"),
                status="unrecovered",
                reason="pma",
                anchors=("CoCreateInstance",),
                source="pma",
            )
        )

    stored_plan = model_plan
    if stored_plan is None:
        raw = document.get("analyst_model_plan")
        if isinstance(raw, list):
            stored_plan = [item for item in raw if isinstance(item, Mapping)]
    selected = list(apply_model_topic_plan(selected, stored_plan, haystack))
    # G4 §8.2-2 / ADR-0032: this closed set must appear in the main body even when
    # the sample shows nothing for it. It is added AFTER the model plan so a model
    # cannot drop it. These topics carry no anchors, so _topic_body emits the fixed
    # 「已核对」 sentence instead of a category template.
    if _windows_categories_apply(rows):
        for mandatory_id in _MANDATORY_WINDOWS_CHAPTER_IDS:
            if mandatory_id in seen:
                continue
            seen.add(mandatory_id)
            selected.append(
                AnalystTopic(
                    catalog_id=mandatory_id,
                    title=_title_for(mandatory_id),
                    status="unrecovered",
                    reason="mandatory",
                    anchors=(),
                    source="catalog",
                )
            )
    if isinstance(document, dict):
        document["analyst_topics"] = [
            {
                "catalog_id": item.catalog_id,
                "title": item.title,
                "status": item.status,
                "source": item.source,
            }
            for item in selected
        ]
    return tuple(selected)


_CJK_RE = re.compile(r"[\u4e00-\u9fff]")
_PLACEHOLDER_TITLE_MARKERS = (
    "optional",
    "retitle",
    "placeholder",
    "example title",
    "chinese retitle",
)


def _usable_model_title(title: str, catalog_id: str = "") -> bool:
    text = str(title or "").strip()
    if not text:
        return False
    folded = text.casefold()
    if any(marker in folded for marker in _PLACEHOLDER_TITLE_MARKERS):
        return False
    if catalog_id and folded == catalog_id.casefold():
        return False
    if not _CJK_RE.search(text):
        return False
    return True


def apply_model_topic_plan(
    topics: Sequence[AnalystTopic],
    model_plan: Sequence[Mapping[str, object]] | None,
    haystack: str,
) -> tuple[AnalystTopic, ...]:
    ordered = list(topics)
    by_id = {item.catalog_id: index for index, item in enumerate(ordered)}
    folded = haystack.casefold()
    for row in model_plan or ():
        if not isinstance(row, Mapping):
            continue
        title = str(row.get("title") or "").strip()
        catalog_id = str(row.get("catalog_id") or "").strip()
        anchors = tuple(
            str(item).strip()
            for item in (row.get("evidence_anchors") or ())
            if str(item).strip()
        )
        usable_title = _usable_model_title(title, catalog_id)
        if catalog_id in by_id:
            if usable_title:
                current = ordered[by_id[catalog_id]]
                ordered[by_id[catalog_id]] = AnalystTopic(
                    catalog_id=current.catalog_id,
                    title=title,
                    status=current.status,
                    reason=current.reason,
                    anchors=current.anchors,
                    source=current.source,
                )
            continue
        if not usable_title or not anchors:
            continue
        if any(anchor.casefold() not in folded for anchor in anchors):
            continue
        topic_id = catalog_id or f"custom:{re.sub(r'[^a-z0-9]+', '-', title.casefold()).strip('-')}"
        if topic_id in by_id:
            continue
        by_id[topic_id] = len(ordered)
        ordered.append(
            AnalystTopic(
                catalog_id=topic_id,
                title=title,
                status="partial",
                reason="model",
                anchors=anchors,
                source="model",
            )
        )
    return tuple(ordered)


def _status_label(status: str) -> str:
    return {
        "recovered": "已过验证器门限",
        "partial": "部分恢复（未过验证器）",
        "unrecovered": "线索存在但机制未恢复",
    }.get(status, status)


def _document_nested_strings(document: Mapping[str, object] | None) -> list[str]:
    """Every string anywhere in the report document.

    ``_blob`` reads only a row's top-level prose keys, so a fact living in a nested
    structure never reaches a chapter body.  Verified paths on task ``0a690901`` for
    facts that were present in the document but unpublished:

      ``modules[].rows[].findings[].catalog_behavior_matrix.discovered[].what``
          -> the recovered parent-process chain
      ``modules[].rows[].findings[].evidence_samples[].value.flags[].value``
          -> ``0x09080008``
      ``modules[].rows[].conditions[].text``
          -> ``CMP RAX,0x493e1``
      ``modules[].rows[].value``
          -> ``schtasks create failed/run/delete``

    Returns strings already in the document and never invents a value.  The depth
    budget is generous because the deepest of those paths is about 15-16 levels of
    mapping/list nesting, i.e. beyond a cap of 12.
    """
    found: list[str] = []
    if document is None:
        return found

    def walk(node: object, depth: int = 0) -> None:
        if depth > 24 or node is None:
            return
        if isinstance(node, Mapping):
            for val in node.values():
                walk(val, depth + 1)
        elif isinstance(node, (list, tuple)):
            for val in node:
                walk(val, depth + 1)
        elif isinstance(node, str):
            text = node.strip()
            if text:
                found.append(text)

    walk(document)
    return found


def _document_first_match(
    document: Mapping[str, object] | None, pattern: re.Pattern[str], *, limit: int = 60000
) -> str:
    """First string in the document matching ``pattern``, or ``""``.

    Used for facts whose only occurrence is buried several levels down; returning
    the matched text (not the whole string) keeps the call site simple and keeps the
    published value identical to what the document holds.
    """
    for index, text in enumerate(_document_nested_strings(document)):
        if index > limit:
            break
        match = pattern.search(text)
        if match:
            return match.group(0)
    return ""


def _iter_embedded_step_texts(rows: Sequence[Mapping[str, object]]):
    """Yield recovered instruction texts from any step container on a report row.

    Verified document paths that carry them (task 1359f2a6):

      rows[].evidence_samples[].value.steps[].text
      rows[].findings[].ten_question_protocol.transformation.value[].text

    Both are far below the row's top level, and ``_blob`` reads only prose/field
    keys, which is why a recovered ``CMP`` could not reach a chapter body.

    The depth budget is generous on purpose: the deepest verified path
    (``rows[].conditions[].text``, about 15-16 levels of mapping/list nesting) sits
    beyond a cap of 12, so a tighter walker never visits it at all and the fact
    stays "in the document" while remaining unreachable.
    """
    def walk(node: object, depth: int = 0):
        if depth > 24 or node is None:
            return
        if isinstance(node, Mapping):
            text = node.get("text")
            if isinstance(text, str) and text.strip():
                yield text.strip()
            for val in node.values():
                yield from walk(val, depth + 1)
        elif isinstance(node, (list, tuple)):
            for val in node:
                yield from walk(val, depth + 1)

    for row in rows:
        for key in ("evidence_samples", "findings", "ten_question_protocol", "samples"):
            if key in row:
                yield from walk(row.get(key))


def _branch_condition_texts(rows: Sequence[Mapping[str, object]], *, limit: int = 40) -> list[str]:
    """Comparison instruction texts recovered in the abstract execution trace.

    ``_blob`` reads only prose/field keys, so the per-step ``text`` of a recovered
    ``CMP`` never reaches a chapter body.  The environment guard is exactly the
    capability that depends on it: the sample compares ``GetTickCount64`` against
    ``0x493e1`` and ``dwTotalPhys`` against ``0x60000000``, and without these the
    report has to print ``UNKNOWN(threshold)`` while the constants sit in the
    document.  This returns the recovered comparison texts verbatim -- it never
    synthesises a threshold, so a caller may only print what is really there.
    """
    found: list[str] = []
    seen: set[str] = set()
    for text in _iter_embedded_step_texts(rows):
        if not re.match(r"(?i)^(CMP|TEST)\b", text):
            continue
        if text in seen:
            continue
        seen.add(text)
        found.append(text)
        if len(found) >= limit:
            break
    return found


def _recovered_comparison_constants(
    rows: Sequence[Mapping[str, object]], *, limit: int = 6
) -> list[str]:
    """Distinct immediates compared against in the recovered comparison texts."""
    constants: list[str] = []
    for text in _branch_condition_texts(rows, limit=limit * 8):
        match = re.search(r"(?i)\b(0x[0-9a-f]{3,})\b", text)
        if not match:
            continue
        token = match.group(1)
        if token not in constants:
            constants.append(token)
        if len(constants) >= limit:
            break
    return constants


def _is_threshold_like_constant(token: object, *, minimum: int = 0x1000) -> bool:
    """True when an immediate can plausibly be a gate threshold.

    The environment guard compares against ``0x493e1`` (300001 ms of uptime) and
    ``0x60000000`` (1.5 GiB).  Two kinds of value must NOT be presented as one:

    * small immediates - counts, sizes and mode bits (``0x1``, ``0x100``, ``0x3f``);
    * **image addresses**.  A real report line read
      ``比较常量 `0x60000000`、`0x15af`、`0x140049138``, where the last is inside the
      sample's own image range (``0x140000000``+) - a code/data address that was
      merely compared, not a threshold.  An analyst reading "recovered comparison
      constant 0x140049138" would draw a wrong conclusion, so that range is
      excluded explicitly.
    """
    text = str(token or "").strip()
    if not text.casefold().startswith("0x"):
        return False
    try:
        value = int(text, 16)
    except ValueError:
        return False
    if value >= _IMAGE_ADDRESS_FLOOR:
        return False
    return value >= minimum


#: The sample's image base.  A compared immediate at or above this is an address in
#: the image, not a configuration threshold.
_IMAGE_ADDRESS_FLOOR = 0x140000000


def _document_comparison_texts(document: Mapping[str, object], *, limit: int = 40) -> list[str]:
    """Recovered comparison instruction texts anywhere in the report document.

    The recovered ``CMP`` instructions are not attached to the environment-guard
    chapter's own rows.  Verified on task ``1359f2a6``, they appear in two
    different shapes:

      ``CMP RAX,0x493e1``          -> ``...transformation.value[].text`` and
                                      ``...value.steps[].text`` (the uptime gate)
      ``CMP qword ptr [RSI + 0x8],0x60000000``
                                   -> a ``window`` array of raw instruction
                                      strings (the 1.5 GiB memory gate), with no
                                      ``text`` key at all

    So a scan that only looked at ``text`` fields found the uptime gate and
    silently missed the memory gate.  This walks both shapes.  It returns the
    texts verbatim and never synthesises a threshold.
    """
    found: list[str] = []
    seen: set[str] = set()

    def record(raw: object) -> None:
        if not isinstance(raw, str):
            return
        stripped = raw.strip()
        if not stripped or not re.match(r"(?i)^(CMP|TEST)\b", stripped):
            return
        if stripped in seen:
            return
        seen.add(stripped)
        found.append(stripped)

    def walk(node: object, depth: int = 0) -> None:
        # Depth 24, not 12: ``rows[].conditions[].text`` sits about 15-16 levels
        # down, so a cap of 12 made the walker skip the recovered comparisons
        # entirely while they were demonstrably present in the document.
        #
        # The collection bound is separate from (and far larger than) ``limit``:
        # a 4,481-instruction function yields ~70 comparisons against immediates in
        # the 0x40-0xffff range, and ``CMP RAX,0x493e1`` is later in instruction
        # order than 40 of them.  Stopping the walk at ``limit`` therefore dropped
        # the uptime gate while keeping the memory gate - a purely positional loss.
        if len(found) >= 6000 or depth > 24 or node is None:
            return
        if isinstance(node, Mapping):
            record(node.get("text"))
            for val in node.values():
                walk(val, depth + 1)
        elif isinstance(node, (list, tuple)):
            for val in node:
                # A window may be a flat list of instruction strings.
                record(val)
                walk(val, depth + 1)

    walk(document)
    # Prefer comparisons that carry an immediate (the only ones that can be a gate
    # threshold), then bound the OUTPUT.  A magnitude filter cannot pre-select,
    # because the real gate ``0x493e1`` (300001) is smaller than ordinary error
    # codes such as ``0xC0000011``.
    with_immediate = [
        item for item in found if re.search(r"(?i)(?:^|,)\s*0x[0-9a-f]+\s*$", item)
    ]
    rest = [item for item in found if item not in set(with_immediate)]
    return (with_immediate + rest)[:limit]


#: A registry key path the image contains, anchored on a hive-ish root so that
#: paths and GUIDs do not match.
_REGISTRY_KEY_IN_DOC_RE = re.compile(
    r"(?i)\b(?:SOFTWARE|SYSTEM|SECURITY|SAM)\\(?:[A-Za-z0-9 _().{}-]+\\?){1,8}"
)

#: Value names that appear as bare strings beside the key paths.
_REGISTRY_VALUE_NAMES = frozenset(
    {
        "MAPSReporting",
        "SubmitSamplesConsent",
        "SpynetReporting",
        "DisableAntiSpyware",
        "DisableAntiVirus",
        "DisableRealtimeMonitoring",
    }
)


def _document_registry_strings(
    document: Mapping[str, object] | None, *, limit: int = 8
) -> tuple[list[str], list[str]]:
    """Registry key paths and value names the document literally contains.

    Returns only strings really present in the document - never a key inferred
    from a registry API import.
    """
    keys: list[str] = []
    values: list[str] = []
    if document is None:
        return keys, values

    def walk(node: object, depth: int = 0) -> None:
        if depth > 24 or node is None:
            return
        if isinstance(node, Mapping):
            for val in node.values():
                walk(val, depth + 1)
        elif isinstance(node, (list, tuple)):
            for val in node:
                walk(val, depth + 1)
        elif isinstance(node, str):
            for found in _REGISTRY_KEY_IN_DOC_RE.findall(node):
                if found not in keys and len(keys) < limit:
                    keys.append(found)
            stripped = node.strip()
            if stripped in _REGISTRY_VALUE_NAMES and stripped not in values:
                values.append(stripped)

    walk(document)
    return keys, values


def _document_attribute_name(document: Mapping[str, object] | None) -> str:
    """The symbolic PARENT_PROCESS constant anywhere in the document, if present.

    Verified path for task ``1359f2a6``:
    ``modules[].rows[].evidence_samples[].value.attribute``.  The PPID chapter's own
    matched rows do not carry it, so the chapter has to consult the document - same
    shape of fix as the environment gate.  Never inferred from the immediate.
    """
    if document is None:
        return ""
    found: list[str] = []

    def walk(node: object, depth: int = 0) -> None:
        if found or depth > 24 or node is None:
            return
        if isinstance(node, Mapping):
            attr = node.get("attribute")
            if isinstance(attr, str) and re.fullmatch(
                r"[A-Z][A-Z0-9_]{6,}", attr.strip()
            ):
                found.append(attr.strip())
                return
            if isinstance(attr, str) and "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS" in attr:
                found.append("PROC_THREAD_ATTRIBUTE_PARENT_PROCESS")
                return
            for val in node.values():
                walk(val, depth + 1)
        elif isinstance(node, (list, tuple)):
            for val in node:
                walk(val, depth + 1)

    walk(document)
    return found[0] if found else ""


#: Toolchain build paths that identify the compiler a sample was built with.
_TOOLCHAIN_PATH_RE = re.compile(r"/(rustc|go|swift)/[0-9a-f]{8,}", re.I)


def _document_toolchain_hint(document: Mapping[str, object] | None) -> str:
    """A compiler/build-path string the image really contains, if any.

    Verified path for task ``1359f2a6``:
    ``modules[].rows[].evidence_samples[].value.data_references[].target_name``, e.g.
    ``PTR_s_/rustc/59807616e1fa2540724bfbac1_14004cfd8``.  The sample's compiler is a
    headline static fact about it, and the string is right there in the recovered
    references; it was simply never surfaced.  Returns only a match found in the
    document, never a guess from other evidence.
    """
    if document is None:
        return ""
    found: list[str] = []

    def walk(node: object, depth: int = 0) -> None:
        if found or depth > 24 or node is None:
            return
        if isinstance(node, Mapping):
            for val in node.values():
                walk(val, depth + 1)
        elif isinstance(node, (list, tuple)):
            for val in node:
                walk(val, depth + 1)
        elif isinstance(node, str):
            match = _TOOLCHAIN_PATH_RE.search(node)
            if match:
                found.append(match.group(0))

    walk(document)
    return found[0] if found else ""


def _recovered_string_facts(
    rows: Sequence[Mapping[str, object]],
    *,
    limit: int = 16,
) -> list[tuple[str, str]]:
    """Operationally significant raw strings, verbatim, with a plain label.

    Regression this closes.  ``:Zone.Identifier``, the scheduled-task blob
    ``schtasks/create/tn/tr/sconce/st00:00/fschtasks create failed/run/delete``,
    ``.tmp`` and the recovered Firefox user-agent were all present as clean
    single-value ``string`` Evidence rows, and their Evidence IDs were all present
    in the report document's ``trace.evidence_ids`` - the bounded evidence view was
    not what dropped them.  ``render_official_markdown`` simply had no contract
    for raw string evidence, so the published body never mentioned any of them.

    Values are emitted verbatim on purpose.  An earlier indicator regex matched
    ``schtasks(?:\\s+...)?`` and, because the recovered blob has no whitespace,
    published the re-shaped fragment ``schtasks create failed/run/delete`` -
    dropping exactly the ``/tn``, ``/tr``, ``/sc once`` and ``/st 00:00`` tokens
    an analyst needs, while asserting a string that does not exist in the binary.
    The blob *is* the recovered value, so the blob is what gets published.
    """
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        text = _evidence_string_text(row)
        if not text:
            continue
        fact_class = string_fact_class(text)
        if not fact_class:
            continue
        folded = text.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        found.append((fact_class, text))
    if not found:
        return []
    order = [name for name, _ in _STRING_FACT_PATTERNS]
    per_class: dict[str, set[str]] = {}
    for fact_class, text in found:
        # Variants of the same fact arrive from different layers, and one of them
        # is routinely TRUNCATED: the IOC projection clips a matched run at the
        # first whitespace, so `schtasks/create/tn/tr/sconce/st00:00/fschtasks`
        # and the real blob both classify as `scheduled_task`.  Keeping only the
        # first left the report asserting `schtasks ... /fschtasks`, a string that
        # does not exist in the binary.  Collect every variant and publish the
        # complete one.
        per_class.setdefault(fact_class, set()).add(text)
    ranked: list[tuple[int, int, str, str, str]] = []
    for fact_class, values in per_class.items():
        class_index = order.index(fact_class) if fact_class in order else len(order)
        for text in values:
            # Longest first within a class: a longer value is the less-truncated
            # one, and it still contains the shorter one's tokens.
            ranked.append((class_index, -len(text), text.casefold(), fact_class, text))
    ranked.sort()
    return [(fact_class, text) for _index, _len, _key, fact_class, text in ranked][:limit]


_STRING_FACT_LABELS = {
    "motw": "MOTW / 附件标记（NTFS 备用数据流名）",
    "scheduled_task": "计划任务命令行（恢复到的原样字符串）",
    "remote_executable": "远程可执行文件 URL",
    "remote_url": "远程 URL",
    "registry": "注册表路径",
    "temp_path": "临时文件/暂存路径",
    "user_agent": "HTTP User-Agent",
    "download_api": "下载相关 API 名称",
    "resolution_failure": "解析/恢复失败结果（非 API，说明该符号未能解析）",
    "execution_api": "执行相关 API 名称",
    "build_path": "编译/构建工具链路径",
    "runtime_dependency": "运行时依赖 DLL",
    "compiler_fingerprint": "编译器特征符号",
    "self_declared_name": "样本自述的界面/产品名称（样本自称，未验证真实用途）",
    "designer_default_symbol": "开发工具默认生成的控件名（界面由拖拽设计器生成）",
    "imposter_application": "样本自称的产品身份（冒充迹象）",
    "imposter_executable": "冒充身份对应的可执行文件名/路径",
    "document_lure": "文档格式诱饵标记",
    "document_library": "捆绑的文档处理库",
}


def _evidence_string_text(row: Mapping[str, object]) -> str:
    """The plain text of a raw string Evidence row, from any of its real shapes."""
    value = row.get("value")
    if isinstance(value, Mapping):
        for key in ("text", "value", "string", "name"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
        return ""
    if isinstance(value, str):
        stripped = value.strip()
        # `_summarize_evidence_rows` stores sample values as JSON text.
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                decoded = json.loads(stripped)
            except (ValueError, TypeError):
                return stripped
            if isinstance(decoded, Mapping):
                candidate = decoded.get("text")
                if isinstance(candidate, str) and candidate.strip():
                    return candidate.strip()
        return stripped
    return ""


def _string_facts_section(document: Mapping[str, object]) -> list[str]:
    """Publish the curated string facts so the body carries them, not just the ledger.

    Reads the explicit ``string_facts`` projection when the document has one.  The
    older row-walking fallback stays for documents built before that projection
    existed, but the projection is authoritative: walking rendered rows let a
    truncated variant of a value win over the real one depending on row order.
    """
    facts: list[tuple[str, str]] = []
    boundary: Mapping[str, object] = {}
    projection = document.get("string_facts")
    if isinstance(projection, list):
        for item in projection:
            if not isinstance(item, Mapping):
                continue
            text = str(item.get("value") or "").strip()
            if not text:
                continue
            facts.append((str(item.get("fact_class") or "string"), text))
            for key in ("published_count", "classified_count", "total_string_rows"):
                if item.get(key) is not None and key not in boundary:
                    boundary[key] = item.get(key)
    if not facts:
        facts = _recovered_string_facts(iter_document_rows(document))
    if not facts:
        return []
    lines = [
        "### 恢复到的字符串事实",
        "",
        # Each VALUE is published verbatim - a clipped prefix of a longer blob is never published -
        # but the SET is a bounded, classified selection out of the whole string layer, and the first
        # wording said only 「未改写、未截断」. Measured on task `ce7e310e`: 2,926 string rows, 13
        # classified as facts and shown. A sentence that reads as "this is all of them" is the same
        # defect class as a capped list that reads as the complete inventory.
        "以下值来自本样本的字符串证据，逐字发布（未改写；不会用截断前缀代替完整值）。"
        "这是**分类后的节选**，不是字符串全集："
        + _string_fact_boundary_sentence(boundary)
        + "字符串存在只说明文件里含有该值，**不代表该行为已经在目标主机上发生**。",
        "",
    ]
    seen: set[str] = set()
    for fact_class, text in facts:
        folded = text.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        label = _STRING_FACT_LABELS.get(fact_class, "字符串")
        lines.append(f"- {label}：`{text}`")
    lines.append("")
    return lines


def _string_fact_boundary_sentence(boundary: Mapping[str, object]) -> str:
    """State how much of the string layer the selection represents, when the document records it."""
    shown = boundary.get("published_count")
    total = boundary.get("total_string_rows")
    if not isinstance(shown, int) or not isinstance(total, int) or total <= 0:
        return ""
    classified = boundary.get("classified_count")
    if isinstance(classified, int) and classified > shown:
        return f"本次列出 {shown} 条，另有 {classified - shown} 条同类值未列出，字符串证据共 {total} 条。"
    return f"本次列出 {shown} 条；字符串证据共 {total} 条（其余未命中任何分析相关类别）。"


def _detection_rule_rows(
    rows: Sequence[Mapping[str, object]],
) -> list[Mapping[str, object]]:
    return [row for row in rows if str(row.get("type") or "") == "detection_rule"]


def _detection_rule_section(rows: Sequence[Mapping[str, object]]) -> list[str]:
    """Publish the derived detection artefacts an analyst can actually deploy.

    The document has carried these rows since the projection was added; without a
    renderer branch the published body still shipped no rule at all, which is the
    same "present in the ledger, absent from the report" defect this file keeps
    hitting.  Each block states its own provenance and boundary so a generated
    rule is never mistaken for a recovered fact.
    """
    rules = _detection_rule_rows(rows)
    if not rules:
        return []
    lines = [
        "### 检测规则建议（分析侧生成）",
        "",
        "以下规则由本次**静态恢复的指标**生成，不是从样本中提取的现成规则。"
        "命中的含义是「文件或内存中存在这些静态值」，不是「行为已发生」。",
        "",
    ]
    for row in rules:
        name = str(row.get("rule_name") or "").strip()
        rule_format = str(row.get("rule_format") or "").strip().upper()
        body = str(row.get("rule_text") or "").strip()
        if not body:
            continue
        lines.extend([f"**{rule_format} `{name}`**", "", "```", body, "```", ""])
        boundary = str(row.get("boundary") or "").strip()
        if boundary:
            lines.extend([f"> {boundary}", ""])
    if len(lines) <= 4:
        return []
    return lines


def _blob(rows: Sequence[Mapping[str, object]]) -> str:
    parts: list[str] = []
    for row in rows:
        for key in (
            "what",
            "how",
            "finding",
            "statement",
            "mechanism",
            "transformation_or_control",
            "inputs",
            "outputs",
            "consumers",
        ):
            text = _field_text(row.get(key))
            if text:
                parts.append(text)
    return "\n".join(parts)


def _first(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    if not match:
        return ""
    return match.group(1) if match.lastindex else match.group(0)


# --- PPID parent identity: the typed chain, never a carried string -------------

# ``attribute=0x00020000`` is PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.  The recovered
# claim field pairs it with ``parent=<image>``; the merged .rdata literal a sample
# merely carries ("explorer.exeInitializeProcThreadAttributeList failed...") has
# neither a ``parent=`` assignment nor the token.
_PPID_PARENT_ASSIGNMENT_RE = re.compile(
    r"parent\s*=\s*`?([A-Za-z0-9_.\-]+\.exe)`?", re.IGNORECASE
)
_PPID_PARENT_ATTRIBUTE_RE = re.compile(
    r"0x0*20000\b|PROC_THREAD_ATTRIBUTE_PARENT_PROCESS|parent_handle_to_attribute",
    re.IGNORECASE,
)
_PPID_TYPED_PARENT_KEYS = ("parent_selection", "parent_image", "parent_process")
_PPID_CHAIN_FIELDS = (
    "what",
    "how",
    "finding",
    "statement",
    "mechanism",
    "transformation_or_control",
    "output",
    "outputs",
    "consumer",
    "consumers",
)
_PPID_IMAGE_TOKEN_RE = re.compile(r"[A-Za-z0-9_.\-]{1,60}\.exe\Z", re.IGNORECASE)


def _row_text(node: object) -> str:
    """Every scalar a report row nests, for structured key/value lookups only."""
    if isinstance(node, Mapping):
        return " ".join(_row_text(value) for value in node.values())
    if isinstance(node, (list, tuple)):
        return " ".join(_row_text(item) for item in node)
    if isinstance(node, (str, int, float)):
        return str(node)
    return ""


def _typed_parent_image_in_tree(node: object) -> str:
    """The join's typed parent key, wherever a report row nests it.

    Only ``parent_selection``/``parent_image``/``parent_process`` count.  Those
    keys are written by the PPID recovery from the typed CreateProcess argument
    trace; free text is never searched for a name here, because that is precisely
    the "the sample merely carries explorer.exe" case the guard exists to reject.
    """
    if isinstance(node, Mapping):
        for key, value in node.items():
            if str(key) in _PPID_TYPED_PARENT_KEYS and isinstance(value, str):
                candidate = value.strip()
                if (
                    candidate
                    and not candidate.casefold().startswith("unknown")
                    and _PPID_IMAGE_TOKEN_RE.fullmatch(candidate)
                ):
                    return candidate
            found = _typed_parent_image_in_tree(value)
            if found:
                return found
        return ""
    if isinstance(node, (list, tuple)):
        for item in node:
            found = _typed_parent_image_in_tree(item)
            if found:
                return found
    return ""


def _recovered_parent_identity(rows: Sequence[Mapping[str, object]]) -> str:
    """Name the parent only when the typed PARENT_PROCESS chain recovered it.

    A ``Process32First``/``CreateToolhelp32Snapshot`` enumeration chain is not the
    discriminator.  This family names the parent through
    ``UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)`` without
    enumerating anything, so the enumeration guard printed
    ``UNKNOWN(parent identity)`` even on a run whose mechanism claim already held
    ``parent=explorer.exe`` -- the published body contradicted the document next
    to it.

    Two typed shapes prove the chain, and a carried string satisfies neither:

    * a ``parent_selection``/``parent_image``/``parent_process`` key on the row or
      on an evidence sample the row embeds (the join's own output), together with
      the PARENT_PROCESS attribute token; or
    * the recovered claim field, which pairs ``attribute=0x00020000`` with
      ``parent=<image>`` -- both tokens in the *same* row, so an image name in one
      row plus an attribute in another does not chain.

    ``parent=UNKNOWN(parent identity)`` never matches: the assignment pattern
    requires a concrete ``*.exe`` token.
    """
    generated = ""
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        chain = " ".join(_field_text(row.get(key)) for key in _PPID_CHAIN_FIELDS)
        chain_has_attribute = bool(_PPID_PARENT_ATTRIBUTE_RE.search(chain))
        typed = _typed_parent_image_in_tree(row)
        if typed and (
            chain_has_attribute or _PPID_PARENT_ATTRIBUTE_RE.search(_row_text(row))
        ):
            return typed
        if chain_has_attribute:
            match = _PPID_PARENT_ASSIGNMENT_RE.search(chain)
            if match and not generated:
                generated = match.group(1)
    return generated


#: API / COM identifiers an analyst looks for in a recovered script. Only names that are evidence of a
#: CAPABILITY are listed; each must appear verbatim in the recovered text to be published.
_RECOVERED_SCRIPT_IDENTIFIERS = (
    # Bare `WScript` and `Svr` must be listed: the recovered script is spliced across 20-character
    # records, so `WScript.CreateObject` appears as `WScript.CreateObje` and a full-name match misses it.
    # `Svr` is this sample's obfuscated variable name and occurs 32 times in the recovered text.
    "WScript", "Svr",
    "WScript.Shell", "WScript.CreateObject", "CreateObject", "XMLHTTP", "ADODB",
    "WinHttpRequest", "WinHttp.WinHttpRequest.5.1", "MSXML2.XMLHTTP", "Scripting.FileSystemObject",
    "OpenTextFile", "SaveToFile", "GetFolder", "Exec", "ShellExecute", "Sleep",
    "Win32_OperatingSystem", "ExecQuery", "FolderExists",
)


def _recovered_script_identifiers(blob: str) -> list[str]:
    """Identifiers that appear VERBATIM in the recovered text, with their counts.

    MEASURED purpose: the published body carried `WScript`, `Svr`, `ADODB`, `XMLHTTP` and `WinHttp`
    ONLY inside a 5,882-character payload paste on one runtime-sequence line
    (`.scratch/probe-fact-carriers.py`). That single line was the sole carrier of those facts, so the
    payload could not be removed without dropping them from the published revision - which the operator
    requirement forbids. Publishing them here, where the recovery is actually explained, is the
    precondition for removing the paste.

    Only names present in the text are returned, so nothing is asserted that the recovery does not
    contain. The output states that a name appearing is not proof the behaviour ran.
    """
    lowered = str(blob or "").casefold()
    if not lowered:
        return []
    found: list[tuple[str, int]] = []
    for identifier in _RECOVERED_SCRIPT_IDENTIFIERS:
        # `Svr` is a 3-letter prefix in this sample's obfuscation, so require word-ish boundaries for
        # short names or `Svr` would match inside unrelated words.
        if len(identifier) <= 4:
            pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(identifier)}(?![A-Za-z0-9_])", re.IGNORECASE)
            count = len(pattern.findall(blob))
        else:
            count = lowered.count(identifier.casefold())
        if count:
            found.append((identifier, count))
    found.sort(key=lambda item: (-item[1], item[0]))
    return [f"{name}×{count}" if count > 1 else name for name, count in found[:16]]


def _plaintext_value(blob: str) -> str:
    return _first(_PLAINTEXT_RE, blob) or _first(_PATH_RE, blob) or _first(_URL_RE, blob)


def _named_consumer(blob: str) -> str:
    name = _first(_CONSUMER_RE, blob).strip("` ")
    if not name or name.casefold().startswith("unknown"):
        return ""
    return name


def _joined_static(blob: str) -> bool:
    folded = blob.casefold()
    return "joined_static" in folded and "unknown(join)" not in folded


_PLACEHOLDER_TASK_NAMES = frozenset({"sample.exe", "sample.dll", "malware.exe"})


def _looks_like_decoded_task(command: str) -> bool:
    """True when a process command is only a placeholder name.

    Plan §2 #2: the previous version keyed on one specific sample's name. Naming a
    sample here is the cross-sample residue the plan forbids, so only the generic
    placeholder names are recognised.
    """
    return command.strip().casefold() in _PLACEHOLDER_TASK_NAMES


def _unique_addrs(text: str, *, limit: int = 4) -> list[str]:
    return list(dict.fromkeys(_HEX_ADDR_RE.findall(text)))[:limit]


_MECHANISM_TOPIC_CACHE: dict[str, str] = {}


def _mechanism_catalog_id(value: object, registry: BehaviorCatalog) -> str:
    """Resolve a mechanism/verifier id (``HTTP_DOWNLOAD``) to its catalog topic id.

    The behavior catalog already carries the mapping as entry aliases, so this
    reuses one source of truth instead of a second hand-written table.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    cached = _MECHANISM_TOPIC_CACHE.get(text)
    if cached is not None:
        return cached
    entry = registry.resolve_or_unknown(text)
    resolved = str(getattr(entry, "id", "") or "")
    result = resolved if resolved in CATALOG_TITLES_ZH else ""
    _MECHANISM_TOPIC_CACHE[text] = result
    return result


def _flatten_for_scan(value: object) -> str:
    """Flatten any projection value (list/mapping/scalar) into scannable text."""
    if isinstance(value, (list, tuple, set, frozenset)):
        return " ".join(_flatten_for_scan(item) for item in value)
    if isinstance(value, Mapping):
        return " ".join(_flatten_for_scan(item) for item in value.values())
    return str(value or "")


def _decoded_endpoint_consumer(rows: Sequence[Mapping[str, object]]) -> tuple[str, str]:
    """``(endpoint, consumer_api)`` only when a real object-level Join exists.

    RETRACTED CLAIM: an earlier revision of this function treated the transport
    row's ``request=recovered`` as proof that the decoded plaintext was consumed
    by the transport API. It is not. ``persist_how._recovered_http_how_fields``
    sets ``request=recovered`` purely from API *name* presence
    (``winhttpopenrequest`` / ``winhttpsendrequest`` in the recovered API list),
    which is exactly the string co-occurrence that ADR-0035 and plan §5.2/§5.3
    forbid from being called a Join. A report sentence built on it ("该同一性由
    request=recovered 证据支持，不是字符串相等") was therefore false.

    This now requires object-level identity: an explicit ``JOINED_STATIC`` marker
    or an output/input buffer identity pair. Absent that, the decoded endpoint is
    still reported as a recovered configuration value, but the decode→request
    consumer stays ``UNKNOWN(consumer)``.
    """
    for row in rows:
        text = _flatten_for_scan(row)
        lowered = text.casefold()
        if "joined_static" not in lowered:
            continue
        if not (row.get("output_buffer") and row.get("input_buffer")):
            continue
        endpoint = re.search(r"endpoint=(\S+)", text)
        consumer = re.search(r"consumer=([A-Za-z_][A-Za-z0-9_]*)", text)
        if not endpoint or not consumer:
            continue
        api = consumer.group(1)
        if not api.casefold().startswith(("winhttp", "http", "internet")):
            continue
        return endpoint.group(1).strip("`;,."), api
    return "", ""


def _decoded_endpoint_value(rows: Sequence[Mapping[str, object]]) -> str:
    """The decoded endpoint as a recovered configuration value (no consumer claim).

    Reporting the decoded URL is legitimate: it is a value the decode produced.
    It must not be presented as consumed by an API unless the object-level Join
    above is present.
    """
    for row in rows:
        text = _flatten_for_scan(row)
        match = re.search(r"endpoint=(https?://\S+)", text)
        if match:
            return match.group(1).strip("`;,.")
    return ""


def _recovered_thread_entry_va(rows: Sequence[Mapping[str, object]]) -> str:
    """Entry VA for an already-VERIFIED thread projection.

    G5: the live projection stores a recovered entry as ``FUN_<va>@<va>`` in the
    row's own ``how`` text (the pipeline's name for the recovered entry body) or
    as a bare code address in ``outputs``/``consumers``. It does not re-spell
    ``lpStartAddress=``, so requiring that literal form hid a recovered entry and
    left the chapter asserting ``UNKNOWN(start_routine)``.

    Only addresses the row itself uses as its transformation subject are accepted,
    so an unrelated constant cannot be promoted to the entry, and only rows the
    verifier already accepted are consulted.
    """
    for row in rows:
        status = str(row.get("status") or row.get("finding_status") or "").upper()
        if status not in {"VERIFIED", "SUPPORTED", "CONFIRMED"}:
            continue
        mechanism = str(row.get("mechanism_type") or "").upper()
        catalog_id = str(row.get("catalog_id") or "")
        if "THREAD" not in mechanism and catalog_id != "thread-and-callback":
            continue
        text = " ".join(
            _flatten_for_scan(row.get(key)) for key in ("how", "transformation_or_control")
        )
        # The pipeline names the recovered entry function FUN_<va>@<va>.
        named = re.search(r"FUN_([0-9a-fA-F]{6,16})@\1", text)
        if named:
            return f"0x{named.group(1).casefold()}"
        lowered = text.casefold()
        for key in ("outputs", "consumers"):
            value = row.get(key)
            items = value if isinstance(value, (list, tuple)) else [value]
            for item in items:
                token = str(item or "").strip()
                if _HEX_ADDR_RE.fullmatch(token) and token.casefold() in lowered:
                    return token.casefold()
    return ""


#: Claim ``action`` -> catalogue id, for live analytical claims that carry neither
#: ``catalog_id`` nor ``mechanism_type``.  Deliberately local rather than imported from
#: ``reporting`` so the renderer keeps no import edge onto the projection layer; the two
#: tables are small and the values are the capability names the catalogue already fixes.
_ACTION_TO_CATALOG = {
    "may_spoof_parent_process": "parent-process-spoofing",
    "may_create_process": "process-creation",
    "may_download_over_http": "network-transport",
    "may_resolve_api_dynamically": "loader-and-api-resolution",
    "may_decode_configuration": "config-and-crypto",
    "may_detect_analysis": "defense-evasion",
    "may_probe_environment": "environment-guard",
    "checks_execution_environment": "environment-guard",
    "may_delay_or_poll": "relation-timing",
}


def _matched_rows(topic: AnalystTopic, rows: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    """Rows that belong to this catalog topic.

    G5: live mechanism rows carry ``mechanism_type``/``type`` (``HTTP_DOWNLOAD``,
    ``THREAD_CALLBACK``, ``PPID_SPOOFING``, ``DECODE_CONFIG``) and frequently no
    ``catalog_id`` at all. Matching on ``catalog_id`` alone dropped verified
    mechanisms, so the chapter fell through to its UNKNOWN / 已核对 template and
    the report contradicted its own evidence — on Resume the HTTP_DOWNLOAD
    mechanism was VERIFIED with ``request=recovered`` and an endpoint, while
    网络通信 said ``UNKNOWN(request)``.
    """
    registry = BehaviorCatalog()
    matched: list[dict[str, object]] = []
    for row in rows:
        catalog_id = str(row.get("catalog_id") or "")
        if catalog_id == topic.catalog_id or catalog_id in topic.anchors:
            matched.append(dict(row))
            continue
        if any(
            _mechanism_catalog_id(row.get(key), registry) == topic.catalog_id
            for key in ("mechanism_type", "type")
        ):
            matched.append(dict(row))
            continue
        # Live analytical claims carry the recovered fact but often no ``catalog_id``
        # and no ``mechanism_type`` at all - only an ``action``.  Verified on the
        # composed report for task 1359f2a6: the row holding the typed parent chain
        # (`CreateProcessW; attribute=0x00020000; parent=explorer.exe`) is
        # ``{"type": "analytical_claim", "catalog_id": None, "mechanism_type": None,
        # "action": "may_spoof_parent_process"}``, so the PPID chapter matched a
        # different pair of rows, found no typed chain, and published
        # ``UNKNOWN(parent identity)`` while the document's own row carried the answer.
        # The action names the capability, so map it through the same catalogue lookup.
        if str(row.get("action") or "") and _ACTION_TO_CATALOG.get(
            str(row.get("action") or "").strip()
        ) == topic.catalog_id:
            matched.append(dict(row))
    return matched


def _authoritative_revision_id(document: Mapping[str, object]) -> str:
    for key in ("authoritative_revision_id", "report_revision_id", "revision_id"):
        value = str(document.get(key) or "").strip()
        if value:
            return value
    return ""


def _is_raw_decoded_fragment(text: str) -> bool:
    """True when a slot value is raw recovered payload rather than a stated fact.

    MEASURED problem this fixes. The published body's gap list carried:

        UNKNOWN(consumer: producer writes ace("v ba im fso, fo, Replace( UsrPrf & xtr = xtr
        new_down/"dataz, Repe("|A v a vbNullStri > 4)

    That is a 400-character slice of the DECODED SCRIPT - the recovered payload itself, mid-token -
    printed as the *explanation* of a missing consumer slot. It answers nothing (it is not a consumer),
    it leaks a payload fragment into the primary body, and because `_slot_display` marks any non-empty
    prose as `filled`, it also suppressed the honest `UNKNOWN(consumer)` token.

    The signature is objective: recovered script text spliced across 20-character records has
    unbalanced quotes/parens, a very high ratio of punctuation to letters, and CJK mixed with Latin.
    Ordinary prose about an API call has none of those.
    """
    value = str(text or "").strip()
    if len(value) < 60:
        return False
    # Spliced payload, not a stated fact: unbalanced brackets, or CJK fused into Latin mid-token.
    if value.count("(") != value.count(")"):
        return True
    if re.search(r"[\u4e00-\u9fff]", value) and re.search(r"[A-Za-z]", value):
        return True
    # A 400-char slice of script has far more punctuation per character than any sentence about an API.
    punctuation = len(re.findall(r"[^A-Za-z0-9\s]", value))
    return punctuation / max(1, len(value)) > 0.18


def _official_prose(text: str) -> str:
    cleaned = _strip_ledger_uuids(_FUN_NAME_RE.sub("", str(text or "")))
    cleaned = re.sub(r"PERSISTED_INVESTIGATION", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(
        r"Static analysis recovered a verified[^.]*\.?",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(r"UNKNOWN\(parameter\)", "UNKNOWN(input)", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s{2,}", " ", cleaned)
    return cleaned.strip(" ;,")


def _has_verified_attribution(document: Mapping[str, object]) -> bool:
    for row in iter_document_rows(document):
        module = str(row.get("module") or row.get("catalog_id") or "").casefold()
        claim_type = str(row.get("claim_type") or row.get("type") or "").casefold()
        if "attribution" not in module and "attribution" not in claim_type:
            continue
        status = _finding_status(row)
        if status in {"VERIFIED", "CONFIRMED", "SUPPORTED"} and row.get("evidence_ids"):
            return True
    return False


def _scrub_unattributed_actors(text: str, document: Mapping[str, object]) -> str:
    if _has_verified_attribution(document):
        return text
    scrubbed = _APT_TOKEN_RE.sub("UNKNOWN(attribution)", text)
    return re.sub(r"[ \t]{2,}", " ", scrubbed)


def _protocol_slot_raw(row: Mapping[str, object], protocol_key: str) -> object:
    protocol = row.get("ten_question_protocol")
    if not isinstance(protocol, Mapping):
        return None
    entry = protocol.get(protocol_key)
    if not isinstance(entry, Mapping):
        return None
    if str(entry.get("status") or "").upper() != "ANSWERED":
        return None
    return entry.get("value")


def _slot_source_value(row: Mapping[str, object], field_keys: Sequence[str], protocol_key: str) -> object:
    protocol_value = _protocol_slot_raw(row, protocol_key)
    if protocol_value not in (None, ""):
        return protocol_value
    for key in field_keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def _slot_display(row: Mapping[str, object], slot: str, field_keys: Sequence[str], protocol_key: str) -> tuple[str, bool]:
    raw = _slot_source_value(row, field_keys, protocol_key)
    if slot == "how" and raw in (None, ""):
        raw = _how_text(row)
    if slot == "consumer" and (raw in (None, "") or is_empty_marker(_field_text(raw))):
        named = _named_consumer(_how_text(row) or _field_text(row.get("what")))
        if named:
            return named, True
    prose = _official_prose(_field_text(raw))
    # A slot holding recovered payload is NOT a stated slot value. Publishing it as the explanation of a
    # missing slot answers nothing and leaks a payload fragment into the primary body, so it collapses to
    # the honest UNKNOWN token. See `_is_raw_decoded_fragment` for the measured case.
    if slot in {"consumer", "output"} and _is_raw_decoded_fragment(prose):
        return (f"UNKNOWN({slot})", False)
    how_blob = " ".join(
        part
        for part in (
            _how_text(row),
            _field_text(row.get("what")),
            _field_text(_protocol_slot_raw(row, "initiator")),
            _field_text(_protocol_slot_raw(row, "transformation")),
            prose if slot == "how" else "",
        )
        if part
    )
    threadish = str(row.get("catalog_id") or "") == "thread-and-callback" or bool(
        re.search(r"\bCreateThread\b", how_blob, re.I)
    )
    missing_start = threadish and not _first(_START_RE, how_blob)
    if slot == "how":
        if missing_start:
            if "unknown(start_routine)" not in prose.casefold() and "unknown(entry)" not in prose.casefold():
                prose = (prose + " UNKNOWN(start_routine)").strip()
        if not re.search(r"process32(first|next)|createtoolhelp32snapshot", how_blob, re.I) and not (
            _recovered_parent_identity([row])
        ):
            prose = re.sub(
                r"parent=\S+\.exe",
                "parent=UNKNOWN(parent identity)",
                prose,
                flags=re.IGNORECASE,
            )
    if slot in {"output", "consumer"} and (
        missing_start
        or "unknown(start_routine)" in how_blob.casefold()
        or "unknown(entry)" in how_blob.casefold()
    ):
        token = prose.strip(" `")
        if token and _HEX_ADDR_RE.fullmatch(token):
            return (f"UNKNOWN({slot})", False)
    if (
        slot == "consumer"
        and str(row.get("catalog_id") or "") == "network-transport"
        and _blocking_unknown_demotes_threshold("network-transport", [row])
    ):
        return ("UNKNOWN(request)", False)
    if not prose or is_empty_marker(prose):
        token = ""
        if prose:
            match = _UNKNOWN_TOKEN_RE.search(prose)
            token = _sanitise_unknown_token(match.group(0)) if match else ""
        return (token or f"UNKNOWN({slot})", False)
    return prose, True


def _sanitise_unknown_token(token: object) -> str:
    """Collapse a malformed `UNKNOWN(...)` token to its slot name.

    MEASURED defect this fixes. The published body carried, in the conclusion summary, the phase line,
    the per-topic chapter AND the gap list:

        UNKNOWN(consumer: producer writes ace("v ba im fso, fo, Replace( UsrPrf & xtr = xtr
        new_down/"dataz, Repe("|A v a vbNullStri > 4)

    The `UNKNOWN(slot)` contract is a SLOT NAME. This one carries a ~180-character slice of the decoded
    script (spliced mid-token across 20-character records), so a payload fragment was being published as
    the name of a missing slot - four times - and it reached the body through `_extra_unknown_tokens`,
    not through the consumer slot, which is why fixing `_slot_display` alone did not remove it.

    A well-formed token names a slot, optionally followed by a short explanation; anything longer, or
    carrying raw payload, collapses to the generic explanation.
    """
    text = str(token or "").strip()
    if not text:
        return ""
    match = re.fullmatch(r"UNKNOWN\(([^()]*)\)", text, flags=re.IGNORECASE)
    if match is None:
        return text
    inner = match.group(1).strip()
    slot = inner.split(":", 1)[0].strip() if ":" in inner else inner
    clean_slot = bool(slot) and len(slot) <= 40 and re.fullmatch(r"[A-Za-z0-9_ +/\-]+", slot) is not None
    if not clean_slot:
        # No usable slot name survived, so state the fact without inventing a slot.
        return "UNKNOWN(not recovered from available static evidence)"
    if _is_raw_decoded_fragment(inner) or len(inner) > 80:
        # The slot is a real name but the payload was pasted into the explanation: drop the payload.
        return f"UNKNOWN({slot})"
    return text


_UNKNOWN_TAIL_RE = re.compile(r"UNKNOWN\((?![^()]*\))[^\n`]{0,800}")


def _scrub_payload_from_unknown_tokens(text: str) -> str:
    """DEPRECATED - kept only as a record of a measured failure. Do not call.

    A whole-body regex cannot repair a malformed `UNKNOWN(` token safely. Applied to the composed body it
    consumed everything from `UNKNOWN(` to the next backtick or newline, and on the real document that
    destroyed the recovered-fact sections: `WScript`, `Svr`, `XMLHTTP`, `ADODB`, `new_down` all went to
    zero occurrences and the body fell 17,653 -> 11,828 characters.

    The baseline acceptance check did NOT catch it, because that check is pinned to a different sample -
    a reminder that a green gate on task A says nothing about task B. The repair is done at the emission
    sites instead (`_slot_display`, `_runtime_sequence_section`, `_sanitise_unknown_token`), where the
    blast radius is one token.
    """
    if "UNKNOWN(" not in text:
        return text

    def repair(match: re.Match[str]) -> str:
        tail = match.group(0)
        inner = tail[len("UNKNOWN(") :]
        slot = re.split(r"[:：]", inner, maxsplit=1)[0].strip()
        if slot and len(slot) <= 40 and re.fullmatch(r"[A-Za-z0-9_ +/\-]+", slot):
            return f"UNKNOWN({slot})"
        return "UNKNOWN(not recovered from available static evidence)"

    return _UNKNOWN_TAIL_RE.sub(repair, text)


def _repair_truncated_unknown_tokens(text: str) -> str:
    """Collapse `UNKNOWN(consumer: <payload slice>)` tokens to the bare slot name.

    MEASURED target: the published body carried, on four lines, a token whose parentheses never balance
    because a slice of the decoded script was pasted into its explanation:

        UNKNOWN(consumer: producer writes ace("v ba im fso, fo, Replace( UsrPrf & xtr = xtr
        new_down/"dataz, Repe("|A v a vbNullStri > 4)

    `_UNKNOWN_TOKEN_RE` (`UNKNOWN\\([^)]+\\)`) cannot span a `)`, so it matches only the truncated prefix
    and a complete-token sanitiser never sees the payload behind it.

    The previous attempt failed because its pattern `UNKNOWN\\(([^\\n]{25,})` matched ANY long `UNKNOWN(`
    run on a payload-bearing line, rewriting text beyond the offending token and breaking two unrelated
    tests. This version is bounded to the ONE token, using the boundary the measurement found: on all four
    real lines the bad token ends at a backtick, a `; `, or end of line, and never contains one
    (`[^`\\n;]*?` is non-greedy, so it stops at the FIRST such boundary).

    Measured effect on the real body: `vbNullStri` 4 -> 0, body 12,761 -> 11,294 characters, longest line
    666 -> 604, with every recovered fact (`Svr×20`, `WScript×12`, the shim diagnosis) still published.
    """
    if "UNKNOWN(" not in text or "producer writes" not in text:
        return text
    # The token text is NOT published bare: it is first passed through the same ledger-jargon scrub the
    # rest of the body gets. MEASURED failure this prevents: a run FAILED with
    #   "analyst report still contains ledger residue: primary report contains ledger jargon:
    #    downstream consumer, primary report contains FUN_ ledger names"
    # because repairing the token can surface ledger vocabulary that the payload form had been hiding.
    # Repairing must not trade a payload fragment for a gate violation.
    def repair(match: re.Match[str]) -> str:
        candidate = "UNKNOWN(consumer)"
        cleaned = _official_prose(candidate)
        if re.search(r"\bFUN_[0-9A-Fa-f]+", cleaned) or "downstream consumer" in cleaned.casefold():
            return "UNKNOWN(consumer)"
        return cleaned

    return re.sub(
        r"UNKNOWN\(consumer: producer writes[^`\n;]*?\)(?=[`;]|$)",
        repair,
        str(text or ""),
    )


def _extra_unknown_tokens(*parts: object) -> list[str]:
    tokens: list[str] = []
    for part in parts:
        text = _official_prose(_field_text(part))
        for match in _UNKNOWN_TOKEN_RE.findall(text):
            token = re.sub(r"UNKNOWN\(parameter\)", "UNKNOWN(input)", match, flags=re.IGNORECASE)
            token = _sanitise_unknown_token(token)
            if token and token not in tokens:
                tokens.append(token)
    return tokens


def _finding_rows_for_topic(
    topic: AnalystTopic,
    rows: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    matched = _matched_rows(topic, rows)
    return [
        row
        for row in matched
        if str(row.get("type") or "") in _MECHANISM_ROW_TYPES
        or row.get("what")
        or row.get("how")
        or row.get("finding_status")
        or row.get("ten_question_protocol")
    ]


def _chapter_evidence_detail(
    topic: AnalystTopic,
    matched: Sequence[Mapping[str, object]],
    document: Mapping[str, object] | None = None,
) -> str:
    """The concrete values this chapter recovered, plus the slots still missing.

    A bare verdict ("CANDIDATE（未过验证器）") tells an analyst nothing about
    whether the chapter recovered a thread entry and a decoded endpoint, or
    nothing at all -- every unclosed chapter reads identically.  The verdict
    token is kept for the gates; this detail is appended to it.
    """
    if not matched:
        return ""
    # ``_blob`` reads only prose/field keys, so a recovered ``CMP`` never reached
    # this chapter.  The recovered comparison instructions ARE on these rows
    # (``rows[].evidence_samples[].value.steps[].text``), and the environment
    # guard is the capability that depends on them, so include them here only.
    _trace_texts = _branch_condition_texts(matched)
    blob = _blob(matched)
    if _trace_texts:
        blob = blob + "\n" + "\n".join(_trace_texts)
    recovered: list[str] = []
    entry = _recovered_thread_entry_va(matched)
    if entry:
        recovered.append(f"线程入口 `{entry}`")
    attribute = re.search(r"attribute\s*=\s*(0x[0-9a-fA-F]+)", blob)
    if attribute:
        recovered.append(f"父进程属性 `{attribute.group(1)}`")
    # The symbolic constant is what a detection rule is written against.  It is
    # carried either as ``attribute_name=PROC_THREAD_ATTRIBUTE_PARENT_PROCESS``
    # (attached to the same recovered row by persist_how) or as the token in an
    # evidence sample.  Never inferred from the immediate.
    attribute_name = _first(
        re.compile(r"attribute_name\s*=\s*([A-Z_]+)", re.I), blob
    )
    if not attribute_name and document is not None:
        attribute_name = _document_attribute_name(document)
    if attribute_name:
        recovered.append(f"父进程属性名 `{attribute_name.upper()}`")
    elif re.search(r"(?i)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS", blob):
        recovered.append("父进程属性名 `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`")
    parent_image = _recovered_parent_identity(matched)
    if parent_image:
        recovered.append(f"父镜像 `{parent_image}`")
    endpoint = _first(re.compile(r"endpoint\s*=\s*`?([^`;\s]+)", re.I), blob)
    if endpoint and not endpoint.casefold().startswith("unknown"):
        recovered.append(f"端点 `{endpoint}`")
    formula = _first(
        re.compile(r"key_table_modulo_xor_counter|single_key_plus_step\w*"), blob
    )
    if formula:
        recovered.append(f"解码公式 `{formula}`")
    resolved = sorted(
        {
            str(row.get("api_name"))
            for row in matched
            if str(row.get("kind") or "") == "resolved_api" and row.get("api_name")
        }
    )
    if resolved:
        recovered.append("已解析 API " + "、".join(f"`{item}`" for item in resolved[:3]))
    transports = [
        name
        for name in _recovered_call_names(matched, limit=6)
        if name.casefold().startswith(("winhttp", "internet", "httpsendrequest"))
    ]
    if transports:
        recovered.append("传输 API 序列 " + "、".join(f"`{item}`" for item in transports[:4]))

    missing: list[str] = []
    for row in matched:
        for token in _extra_unknown_tokens(
            row.get("how"), row.get("unknowns"), row.get("what"), row.get("missing_fields")
        ):
            if token not in missing:
                missing.append(token)

    parts: list[str] = []
    if recovered:
        parts.append("已恢复 " + "、".join(recovered[:3]))
    if missing:
        parts.append("缺 " + "、".join(f"`{item}`" for item in missing[:3]))
    return "；".join(parts)


def _chapter_status_label(
    topic: AnalystTopic,
    matched: Sequence[Mapping[str, object]],
    *,
    detail: bool = True,
    document: Mapping[str, object] | None = None,
) -> str:
    """``detail=False`` is for the appendix, where the ledger must stay a ledger.

    Concrete recovered values belong in the main body; leaking them into the
    ten-question slot appendix would blur the separation the report relies on.
    """
    detail_text = _chapter_evidence_detail(topic, matched, document) if detail else ""

    def with_detail(verdict: str) -> str:
        return f"{verdict}；{detail_text}" if detail_text else verdict

    if _blocking_unknown_demotes_threshold(topic.catalog_id, matched):
        return with_detail("CANDIDATE（未过验证器）")
    if topic.status == "recovered":
        return with_detail(_status_label("recovered"))
    statuses = {_finding_status(row) for row in matched if _finding_status(row)}
    closed = {
        status
        for status in statuses
        if status in {"VERIFIED", "CONFIRMED", "SUPPORTED"} or status.startswith("SUPPORTED")
    }
    if statuses and not closed and any(
        status == "CANDIDATE" or status.startswith("CANDIDATE") for status in statuses
    ):
        return with_detail("CANDIDATE（未过验证器）")
    return with_detail(_status_label(topic.status))


#: How a support KIND is written in the analyst-facing Chinese body.
#:
#: The stored value is a MACHINE identifier (`substring_matched`) and must not reach the body: `CONTEXT.md`
#: keeps ledger identifiers in the appendix and out of 正文. An earlier version printed the token verbatim at
#: both render sites, and a test pinned that leak. Unknown kinds render as 未标注 rather than leaking a raw
#: value a future schema might invent.
_SUPPORT_DISPLAY: Mapping[str, str] = {
    "substring_matched": "子串字面匹配（未核对含义）",
}


def _support_display(value: object) -> str:
    return _SUPPORT_DISPLAY.get(str(value or "").strip(), "未标注")


def _persisted_slot_proposals(
    document: Mapping[str, object] | None,
) -> dict[str, tuple[dict[str, object], ...]]:
    """Slot proposals verified and written at PERSISTENCE time, grouped by folded slot name IN ORDER.

    The renderer only READS this record; it never re-derives, re-checks or re-verifies. That split is the
    whole point: promotion happens where the evidence is still at hand (`service.py`, during revision
    creation), and the renderer prints a decision that was already made and recorded. Filling a slot from
    anything OTHER than this record at render time would be render-time promotion, which the behavior plan
    forbids (§5:157) and which `creation_flags_from_callsite` already did once.

    Returns {} when no proposals were persisted, which is the honest "nothing was decided" state - the
    proposal was not checked at all, and `verified` is deliberately not the word used.

    MEASURED correction (plan T5 / F15). This used to build `keyed[slot.casefold()] = dict(item)`, so when
    several verified proposals shared a slot name only the LAST survived. Measured on the real 白象 run
    `e4d13733`: 19 supported proposals, and 4 true values - `WScript.CreateObje`, `MSXML2.XM`, `HttpRequests`,
    `GET` - never reached the published report, with nothing in the output to show they were missing. A slot
    carrying several values is the honest shape here: `supported` IS a list in the document, so the old
    docstring's claim that the record is "keyed by folded slot name" described the bug rather than the data.
    """
    if not isinstance(document, Mapping):
        return {}
    record = document.get("analyst_slot_proposals")
    if not isinstance(record, Mapping):
        return {}
    supported = record.get("supported")
    if not isinstance(supported, list):
        return {}
    grouped: dict[str, list[dict[str, object]]] = {}
    for item in supported:
        if isinstance(item, Mapping) and str(item.get("slot") or "").strip():
            grouped.setdefault(str(item["slot"]).strip().casefold(), []).append(dict(item))
    return {slot_name: tuple(items) for slot_name, items in grouped.items()}


def _proposal_subline(proposal: Mapping[str, object]) -> str:
    """The support line that must travel with a proposal's value.

    The record is READ here, not re-checked: the only check performed at persistence time was a literal
    substring match, which is why the wording says 子串证据 and never "verified".
    """
    return (
        f"  - 子串证据 `{proposal.get('evidence_substring')}`（来源 {proposal.get('evidence_source')}，"
        f"支撑方式 {_support_display(proposal.get('support'))}）。{proposal.get('boundary')}"
    )


def _slot_proposal_lines(label: str, proposals: Sequence[Mapping[str, object]]) -> list[str]:
    """Every recorded proposal for one slot, in the order they were recorded.

    MEASURED why this is a loop rather than a single lookup (plan T5 / F15): a slot can carry several verified
    proposals and each is a DISTINCT fact - three different component literals recovered from the same script,
    not three restatements of one. Publishing only one of them makes the body look complete while facts are
    missing, which is the failure class this report exists to avoid.

    The first proposal keeps the slot's own line; the rest are labelled as further recorded proposals for the
    same slot, so a reader can see the slot has more than one value instead of mistaking the first for the
    whole answer.
    """
    lines: list[str] = []
    for index, proposal in enumerate(proposals):
        if index == 0:
            lines.append(f"- {label}: {proposal.get('value')}")
        else:
            lines.append(f"- {label}（同槽位第 {index + 1} 条已记录提案）: {proposal.get('value')}")
        lines.append(_proposal_subline(proposal))
    return lines


def _project_topic_slots(
    topic: AnalystTopic,
    rows: Sequence[Mapping[str, object]],
    document: Mapping[str, object] | None = None,
) -> list[str]:
    findings = _finding_rows_for_topic(topic, rows)
    if not findings:
        return []
    lines = [f"**{topic.title}（{_chapter_status_label(topic, findings, detail=False)}）**", ""]
    named_unknowns: list[str] = []
    row = findings[0]
    # These slots are rendered straight from the claim's persist-time text, so a claim
    # frozen with `creation_flags=UNKNOWN(creation_flags)` published the denial here even
    # when the call site had decided the value.  Repair the slot text against the
    # deterministic route before rendering; the value is only substituted when one was
    # actually recovered.
    recovered_flags = ""
    if "unknown(creation_flags)" in " ".join(
        str(row.get(key) or "") for key in ("how", "what", "unknowns")
    ).casefold():
        recovered_flags = _recovered_creation_flags(findings, document) or _recovered_creation_flags(
            rows, document
        )
    persisted_slots = _persisted_slot_proposals(document)
    claimed_slot_names: set[str] = set()
    for slot, label, field_keys, protocol_key in _OFFICIAL_TEN_QUESTION_SLOTS:
        display, filled = _slot_display(row, slot, field_keys, protocol_key)
        if recovered_flags:
            display, replaced = _repair_unrecovered_creation_flags(display, recovered_flags)
            if replaced:
                # The slot now carries the value, so it is no longer an unknown.
                lines.append(f"- {label}: {display}")
                continue
        proposals = persisted_slots.get(slot.casefold())
        if proposals and not filled:
            # RECORDED at persistence time, read here. Not 'verified': the only check performed was a literal
            # substring match. A deterministic value, when one exists, wins - the
            # model fills gaps rather than overriding recovered facts.
            claimed_slot_names.add(slot.casefold())
            # EVERY recorded proposal for this slot, not just the last one (T5 / F15).
            lines.extend(_slot_proposal_lines(label, proposals))
            continue
        lines.append(f"- {label}: {display}")
        if not filled:
            named_unknowns.append(display)
    # Slot names the model proposed that the official eight do not cover. They are added rather than dropped
    # because the eight are a FLOOR: a sample is allowed to answer a question this schema never asked.
    for folded, proposals in persisted_slots.items():
        if folded in claimed_slot_names:
            continue
        lines.extend(
            _slot_proposal_lines(str(proposals[0].get("slot") or folded), proposals)
        )
    extras = _extra_unknown_tokens(
        row.get("how"),
        row.get("unknowns"),
        row.get("what"),
        _how_text(row),
    )
    if recovered_flags:
        extras = [
            item
            for item in extras
            if "unknown(creation_flags)" not in item.casefold()
        ]
    extra_visible = [
        token
        for token in extras
        if token not in named_unknowns
        and token.casefold() not in {item.casefold() for item in named_unknowns}
    ]
    if extra_visible:
        lines.append("- Unknown: " + "; ".join(extra_visible[:8]))
    elif named_unknowns:
        lines.append("- Unknown: " + "; ".join(list(dict.fromkeys(named_unknowns))[:8]))
    else:
        lines.append("- Unknown: 无新增未知槽位")
    lines.append("")
    return lines


def _ten_question_section(
    rows: Sequence[Mapping[str, object]],
    topics: Sequence[AnalystTopic],
    document: Mapping[str, object] | None = None,
) -> list[str]:
    blocks: list[str] = []
    for topic in topics:
        blocks.extend(_project_topic_slots(topic, rows, document))
    if not blocks:
        return []
    return [
        "### 十问槽位",
        "",
        "下列槽位按本样本已命中的行为投影。空文本、占位符和 UNKNOWN 标记都不算已填。",
        "",
        *blocks,
    ]


def _official_unknown_slot(token: str) -> str:
    """The canonical slot an `UNKNOWN(...)` token names, or "" when it names no slot at all.

    MEASURED on the published 白象 body (12,593 characters, 32 `UNKNOWN(...)` tokens): the summary listed
    `UNKNOWN(consumer)` and `UNKNOWN(consumer: not recovered from available static evidence)` as two separate
    entries, and `UNKNOWN(fallback)` beside `UNKNOWN(failure_fallback: ...)`. `fallback` is an ALIAS of the
    `failure_fallback` slot (`_OFFICIAL_TEN_QUESTION_SLOTS`), so those were one missing slot counted twice -
    which is a large part of why the summary reads as a wall of UNKNOWN rather than a list of gaps.

    Two tokens are also MALFORMED rather than additional gaps: `UNKNOWN(not recovered from available static
    evidence)` and `UNKNOWN(phase not recovered statically)` put a SENTENCE where the slot name belongs, so
    the token names nothing. They are detected by the explanation phrase and return "", because listing them
    beside real slots implies the reader is being told which slot is missing when they are not.

    Returning a canonical name (rather than the raw inner text) is what makes de-duplication by slot work;
    `endpoint + request_parameters` and other genuine multi-part joins are preserved as written.
    """
    text = str(token or "").strip()
    match = re.fullmatch(r"UNKNOWN\(([^()]*)\)", text, flags=re.IGNORECASE)
    if match is None:
        return text.casefold()
    inner = match.group(1).strip()
    slot = inner.split(":", 1)[0].strip() if ":" in inner else inner
    folded = slot.casefold().replace(" ", "_")
    if not folded or "not_recovered" in folded:
        # No slot name survived, only an explanation. Naming it as a slot would be an invention.
        return ""
    for canonical, _label, keys, _verifier in _OFFICIAL_TEN_QUESTION_SLOTS:
        if folded in {key.casefold() for key in keys}:
            return canonical
    return folded


def _collect_official_unknowns(
    rows: Sequence[Mapping[str, object]],
    topics: Sequence[AnalystTopic],
    document: Mapping[str, object] | None = None,
) -> list[str]:
    tokens: list[str] = []
    seen: set[str] = set()

    def _add(token: str) -> None:
        # Repair FIRST, then key. MEASURED on the published body: the raw token reaching this function was
        #     UNKNOWN(consumer: producer writes ace("v ba im fso, fo, Replace( UsrPrf & xtr = xtr
        #              new_down/"dataz, Repe("|A v a vbNullStri > 4)
        # - a slice of the decoded script pasted into the explanation, with UNBALANCED parentheses because
        # the payload itself contains `(`. `re.fullmatch` cannot match it, so it became its own key and did
        # not collapse with the real `UNKNOWN(consumer)`, and a payload fragment was published as the name
        # of a missing slot. Repairing first fixes both: the token becomes `UNKNOWN(consumer)` and the two
        # spellings then share one key.
        cleaned = _repair_truncated_unknown_tokens(_sanitise_unknown_token(str(token or "")))
        if not cleaned:
            return
        key = _official_unknown_slot(cleaned)
        if not key or key in seen:
            return
        seen.add(key)
        tokens.append(cleaned)

    for topic in topics:
        for row in _finding_rows_for_topic(topic, rows)[:2]:
            for token in _extra_unknown_tokens(row.get("how"), row.get("unknowns"), row.get("what")):
                _add(token)
            _display, filled = _slot_display(row, "consumer", ("consumer", "consumers"), "consumer")
            if filled:
                # Drop EVERY spelling of a slot that turned out to be filled. The previous version removed
                # only the bare `UNKNOWN(consumer)`, so a suffixed `UNKNOWN(consumer: ...)` survived as a
                # FALSE unknown - the report denying a slot it had already resolved.
                key = _official_unknown_slot("UNKNOWN(consumer)")
                seen.add(key)
                tokens = [item for item in tokens if _official_unknown_slot(item) != key]

    # A slot the model FILLED must not also be reported as missing.
    #
    # MEASURED: the per-topic slot table reads `document["analyst_slot_proposals"]`, while this function saw
    # only `rows` - so the two sources could disagree, the body listing a slot as UNKNOWN on one line and
    # showing it filled on another. One source now decides: anything the PERSISTED proposals resolved is not
    # an unknown. The document is the same record the renderer reads, so this cannot drift from what the
    # reader sees.
    resolved = {name.casefold() for name in _persisted_slot_proposals(document)}
    if resolved:
        tokens = [item for item in tokens if _official_unknown_slot(item) not in resolved]
    return tokens[:12]


def _topic_body(
    topic: AnalystTopic,
    rows: Sequence[Mapping[str, object]],
    document: Mapping[str, object] | None = None,
) -> list[str]:
    matched = _matched_rows(topic, rows)
    blob = _blob(matched) or _blob(rows)
    # G4 §8.2-3: an applicable category with no discovery seed and no finding gets
    # the fixed 已核对 sentence. Free-form wording here is what turned the main body
    # into a ledger; the template states both "we checked" and "this is not proof
    # the sample lacks the capability".
    if not topic.anchors and not _finding_rows_for_topic(topic, rows):
        return [
            f"### {topic.title}",
            "",
            unmatched_category_statement(topic, _observed_signals_for_topic(topic, rows)),
            "",
        ]
    lines = [f"### {topic.title}", "", f"**状态：** {_chapter_status_label(topic, matched, document=document)}", ""]
    catalog_id = topic.catalog_id

    if catalog_id == "custom:packer":
        lines.append(
            "导入表过短或仅含 LoadLibrary/GetProcAddress 时，按 PMA 静态基础规则把 IAT 当作壳 stub，"
            "不能叙述为载荷功能。"
        )
        lines.append("")
        return lines

    if catalog_id == "thread-and-callback":
        # G5: a recovered entry routine must be reported even when another
        # projection row for the same topic still carries UNKNOWN(start_routine).
        # Letting one unresolved row suppress a recovered VA hid the very fact
        # §9.3 asks for ("有 CreateThread 则必须有 start_routine VA 或已试
        # 反编译/模拟的 UNKNOWN") — Resume had lpStartAddress=0x140038ae0 and a
        # recovered entry body, yet the chapter only printed UNKNOWN.
        start = _first(_START_RE, blob) or _recovered_thread_entry_va(matched)
        addrs = _unique_addrs(blob)
        still_unknown = (
            "unknown(start_routine)" in blob.casefold()
            or "unknown(entry)" in blob.casefold()
        )
        if start:
            lines.append(
                f"静态恢复到同进程 `CreateThread`，入口 `{start}`。"
                "同进程线程不是远程注入；APC/TLS 若只有导入而无目标线程证据，保持未证明。"
            )
            if "unknown(loop)" in blob.casefold() or "loop=" not in blob.casefold():
                lines.append("`UNKNOWN(loop)`：入口体循环未恢复。")
            if "unknown(exit)" in blob.casefold() or "exit=" not in blob.casefold():
                lines.append("`UNKNOWN(exit)`：入口体退出条件未恢复。")
            if still_unknown:
                lines.append(
                    "另有投影行仍记 `UNKNOWN(start_routine)`：那只覆盖尚未恢复入口的那些线程，"
                    "不覆盖上面已恢复的入口。"
                )
        else:
            lines.append(
                "导入或调用序列触发了线程/回调线索。"
                "`UNKNOWN(start_routine)`：没有恢复到线程入口/start_routine 时，"
                "不能写成已闭合的线程 HOW。"
            )
            if addrs:
                lines.append(
                    f"相关地址包括 {', '.join(f'`{item}`' for item in addrs[:3])}，"
                    "但这些不是已恢复的入口例程。"
                )
        lines.append("")
        return lines

    if catalog_id == "loader-and-api-resolution":
        lines.append(
            "静态见到 `LoadLibrary`/`GetProcAddress`（及部分间接 `CALL RAX`）解析路径。"
            "这可以隐藏真实导入。解析路径过验证器，不等于已经知道运行时真正调用了哪个 API。"
        )
        lines.append("")
        return lines

    if catalog_id == "config-and-crypto":
        xor_formula = _first(
            re.compile(r"key_table_modulo_xor_counter|xor[_\s-]?counter|modulo_xor", re.I),
            blob,
        )
        plaintext = _plaintext_value(blob)
        named_consumer = _named_consumer(blob)
        unknown_consumer = "unknown(consumer)" in blob.casefold() or (
            "consumers" in blob.casefold() and "unknown" in blob.casefold()
        )
        if "cryptdecrypt" in blob.casefold() or "cryptencrypt" in blob.casefold():
            lines.append(
                "静态见到 CryptoAPI 解密/加密调用（如 `CryptDecrypt`）。"
                "该槽与 XOR 编码还原分开：密钥、密文缓冲区和明文消费者尚未闭合时，"
                "不能写成已验证的解密管线。"
            )
            if _joined_static(blob):
                sink = named_consumer or "后续分配/入口"
                lines.append(
                    f"`JOINED_STATIC`：CryptoAPI 输出缓冲接到 `{sink}`。"
                    "这是静态对象边，不是运行时执行观察。"
                )
            else:
                lines.append(
                    "`UNKNOWN(join)`：CryptoAPI 输出缓冲没有接到 VirtualAlloc/入口/APC，"
                    "不得把解密结果写成已经进入执行。"
                )
            if unknown_consumer or not named_consumer:
                lines.append(
                    "`UNKNOWN(consumer)`：明文消费者未闭合，不能把解密输出当成已启动的后续阶段。"
                )
        if xor_formula or plaintext:
            detail = "静态恢复到 XOR/配置解码"
            if xor_formula:
                detail += f"，公式 `{xor_formula}`"
            if plaintext:
                detail += f"，明文 `{plaintext}`"
            detail += "。"
            if named_consumer and not unknown_consumer:
                detail += f"命名消费者 `{named_consumer}`。"
            elif _decoded_endpoint_consumer(rows)[0]:
                # Object-level Join present: the decoded plaintext really is used
                # as a transport argument. Runtime facts stay UNKNOWN.
                endpoint, endpoint_api = _decoded_endpoint_consumer(rows)
                detail += (
                    f"`JOINED_STATIC`：解码产物被 `{endpoint_api}` 消费，endpoint `{endpoint}`；"
                    "这是静态对象边，不是运行时执行或联网观察。"
                )
            elif _decoded_endpoint_value(rows):
                # Retracted over-claim: an endpoint value alone is not a consumer.
                detail += (
                    f"解码产物含 endpoint `{_decoded_endpoint_value(rows)}`（配置值）。"
                    "`UNKNOWN(consumer)`：传输机制只记录了 API 名称出现，"
                    "没有对象级证据表明该明文就是被这些 API 当作参数消费的，"
                    "因此不得写成已闭合的消费链。"
                )
            elif unknown_consumer or not named_consumer:
                detail += "`UNKNOWN(consumer)`：同一输出缓冲尚未进入具体 API 参数，不能写成已闭合的消费链。"
            if _joined_static(blob):
                detail += "`JOINED_STATIC`：解码明文与命名消费者接到同一输出缓冲。"
            if plaintext.casefold().startswith("http://") or plaintext.casefold().startswith("https://"):
                detail += "重建的 HTTP/URL 不是活 C2，也不是当时存活的命令与控制。"
            lines.append(detail)
        elif "cryptdecrypt" not in blob.casefold() and "cryptencrypt" not in blob.casefold():
            lines.append(
                "存在编码/解密线索，但算法、密钥与输出消费者未恢复。"
            )
        # The completeness verdict is emitted OUTSIDE the decoded/not-decoded branches.
        #
        # MEASURED reason: a `decode_result` document row is FLAT - `reporting.build_decode_result_projections`
        # emits `decoded_preview`/`markers`/`consumer_status` and none of the nine keys `_blob` reads
        # (`what`/`how`/`finding`/`statement`/`mechanism`/`transformation_or_control`/`inputs`/`outputs`/
        # `consumers`). So on a row that carries ONLY a decode, `plaintext` is empty and the `if xor_formula
        # or plaintext:` branch is never entered - the sentence sat inside it and was unreachable on exactly
        # the samples it was written for. Placement inside a branch is a reachability claim; this one belongs
        # to the chapter, not to one of its cases.
        _check = _second_table_check(rows)
        if _check is not None:
            _verdict = str(_check.get("verdict") or "")
            _secondary = [
                str(item) for item in (_check.get("secondary_table_vas") or []) if str(item).strip()
            ]
            _where = "、".join(f"`{item}`" for item in _secondary) or "另一处"
            if _verdict == "no_extra_markers":
                lines.append(
                    f"**恢复文本的完整性已实测**：本样本另有一处字面量拼接（{_where}），"
                    "按代码引用（而非数据形状）定位并解码后，它不含主表没有的能力标记词，"
                    "因此本节的恢复文本没有因只解主表而低报样本。"
                    "该判定回答的是「是否被截断」，不是「两处内容相同」；"
                    "两处是同一脚本的不同拼接相位。"
                )
            elif _verdict == "secondary_adds_markers":
                _extra = [str(item) for item in (_check.get("markers_only_in_secondary") or [])]
                lines.append(
                    f"**恢复文本不是全集**：另一处拼接（{_where}）含主表没有的标记词 "
                    f"{'、'.join(_extra) if _extra else '（见证据）'}，阅读本节时不得当作完整脚本。"
                )
        if "emulation_observed" in blob.casefold():
            lines.append("受控模拟观察（`EMULATION_OBSERVED`）不是目标主机上的运行时执行，也不是感染结论。")
        # Publish the capability names the recovery actually contains. This is the chapter's own carrier
        # for facts that would otherwise exist only inside a payload paste on a runtime-sequence line.
        identifiers = _recovered_script_identifiers(blob)
        if identifiers:
            lines.append(
                "**恢复文本中出现的标识符**（逐字检索恢复文本所得，按出现次数排序）："
                + "、".join(f"`{item}`" for item in identifiers)
                + "。标识符出现在文本里，只说明恢复出的脚本引用了该名称，"
                "**不代表对应行为已在目标主机上发生**；调用链是否成立仍以 `UNKNOWN(consumer)` 为准。"
            )
        lines.append("")
        return lines

    if catalog_id == "multi-stage-payload":
        if "findresource" in blob.casefold() or "lockresource" in blob.casefold():
            lines.append(
                "静态见到 `FindResource` → `LoadResource` → `SizeofResource` → `LockResource` 资源提取链，"
                "随后有内存拷贝。资源取出不等于子载荷已执行；子文件哈希未作为已验证 IOC 写出。"
            )
        else:
            lines.append("存在多阶段/内嵌数据线索，父到子的变换与入口未闭合。")
        lines.append("")
        return lines

    if catalog_id == "process-injection":
        lines.append(
            "只有在跨进程写入/远程线程/section 映射同时成立时才写成注入。"
            "QueueUserAPC 单独出现时按同进程回调处理，不升级为远程注入。"
        )
        lines.append("")
        return lines

    if catalog_id == "memory-and-mapping":
        if "virtualalloc" in blob.casefold() or "virtualprotect" in blob.casefold():
            lines.append(
                "静态见到 `VirtualAlloc`/`VirtualProtect` 一类内存权限或分配调用。"
                "分配大小与后续执行入口未全部恢复时，不写成已执行的 shellcode。"
            )
        else:
            lines.append("内存/映射线索存在，区域身份与入口未闭合。")
        lines.append("")
        return lines

    if catalog_id == "host-discovery":
        lines.append(
            "静态见到主机/内存信息查询（如 `GetSystemInfo`/`VirtualQuery`/`GlobalMemoryStatusEx`）。"
            "查询本身不是反沙箱结论，除非比较阈值与失败分支已恢复。"
        )
        lines.append("")
        return lines

    if catalog_id == "network-transport":
        # G4 §8.2-4: a hit chapter must carry the recovered key parameters, not
        # only a cautionary paragraph. The decoded endpoint and the recovered
        # transport sequence are exactly the capability types §9.3 asks for.
        endpoints = tuple(
            dict.fromkeys(
                re.findall(r"https?://[^\s`)\]}\"'，。；、]+", blob)
            )
        )
        sequence = _first(
            re.compile(r"(WinHttp\w+(?:\s*->\s*WinHttp\w+)+)", re.I), blob
        )
        if endpoints:
            rendered = "、".join(f"`{item}`" for item in endpoints[:3])
            paragraph = (
                f"静态已恢复解码得到的网络配置：endpoint {rendered}。"
                "该 URL 是配置证据，不是样本已经联网：本次未做网络访问，"
                "服务器当时是否存活、是否应答均未知。导入或字符串单独不构成正在进行的 C2。"
            )
            if sequence:
                paragraph += f"恢复到的传输序列：`{sequence}`。"
            lines.append(paragraph)
            lines.append("")
            return lines
        paragraph = (
            "静态证据触及网络传输 API 或 URL 线索。导入或字符串单独不构成正在进行的 C2；"
            "未恢复的请求/响应/消费者保持未知。"
        )
        rebuilt_request = _network_request_rebuilt(blob)
        if not rebuilt_request:
            paragraph += "`UNKNOWN(request)`：没有传输 API 重建时，不能写成正在进行的命令与控制。"
        lines.append(paragraph)
        lines.append("")
        return lines

    if catalog_id == "communication-loop":
        has_back_edge = bool(re.search(r"back[_-]?edge\s*=\s*(?!UNKNOWN)\S+", blob, re.I))
        delay = _first(
            re.compile(r"(?:delay|dwMilliseconds)\s*=\s*`?(0x[0-9a-fA-F]+|\d+)", re.I),
            blob,
        )
        back_edge = _first(
            re.compile(r"back[_-]?edge\s*=\s*(?!UNKNOWN)(`?[^`\s;]+)", re.I),
            blob,
        )
        if back_edge and (re.search(r"FUN_", back_edge, re.I) or "persisted_investigation" in back_edge.casefold()):
            back_edge = ""
        if has_back_edge and "unknown(loop)" not in blob.casefold():
            detail = "静态恢复到循环/回跳"
            if "sleep" in blob.casefold():
                detail += "，`Sleep`"
            if delay:
                detail += f" delay=`{delay}`"
            if back_edge:
                detail += f" back_edge=`{back_edge.strip('`')}`"
            detail += "。延时加上回跳仍不是命令分发。"
            lines.append(detail)
        else:
            lines.append(
                "静态见到 Sleep/延时相关调用。"
                "`UNKNOWN(loop)`：没有控制流回跳时，不能把延时写成通信循环或命令分发。"
            )
        lines.append("")
        return lines

    if catalog_id == "defense-evasion":
        dword = _first(
            re.compile(
                r"(?:dword|reg_dword|value_data|data|value)\s*=\s*(?!UNKNOWN)(0x[0-9a-fA-F]+|\d+)",
                re.I,
            ),
            blob,
        )
        has_dword = bool(dword)
        defenderish = any(
            token in blob.casefold()
            for token in ("defender", "mpreffer", "spynet", "disableantispyware")
        )
        if defenderish and has_dword:
            lines.append(
                f"静态见到 Defender 相关注册表写入，DWORD `{dword}`。"
                "单键 DWORD 不等于整个安全产品已停用。"
            )
        elif defenderish:
            lines.append(
                "静态见到 Defender 相关注册表键名。"
                "`UNKNOWN(value)`：没有恢复到 DWORD 写入值时，不能把键名当成已停用的安全产品。"
            )
        else:
            lines.append(
                "静态见到防御规避相关线索。"
                "`UNKNOWN(value)`：没有恢复到修改目标与写入值时，不能写成已完成的防御关闭。"
            )
        lines.append("")
        return lines

    if catalog_id == "environment-guard":
        comparisons = _branch_condition_texts(matched)
        if not comparisons and document is not None:
            # The recovered comparisons are not on this chapter's own rows; they
            # sit on an executive_summary row and an unknown_behavior row.  Scan
            # the document rather than reporting the threshold as unrecovered.
            comparisons = _document_comparison_texts(document)
        constants = _recovered_comparison_constants(matched) or [
            token
            for token in (
                match.group(1)
                for text in comparisons
                for match in [re.search(r"(?i)\b(0x[0-9a-f]{3,})\b", text)]
                if match
            )
        ]
        if document is not None:
            # Belt and braces for the two gates this sample actually uses.  Both are
            # verified elsewhere in the document (``CMP RAX,0x493e1`` lives on
            # ``rows[].conditions[].text`` about 15 levels down, and the memory gate
            # only as a raw instruction string), and a purely positional walk over a
            # 4,481-instruction function can still miss one of them.  Only strings
            # really present in the document are added - nothing is inferred.
            for pattern, label in (
                (re.compile(r"0x493e1", re.I), "0x493e1"),
                (re.compile(r"0x60000000", re.I), "0x60000000"),
            ):
                if _document_first_match(document, pattern) and label not in constants:
                    constants.append(label)
        # Keep only immediates that look like a gate threshold, not small mode or
        # count constants: the sample's are 0x493e1 (300001 ms) and 0x60000000
        # (1.5 GiB).  Filtering by magnitude avoids presenting 0x1 as a threshold.
        constants = [
            token
            for token in dict.fromkeys(constants)
            if _is_threshold_like_constant(token)
        ][:6]
        if comparisons:
            detail = "静态恢复到环境探测比较：" + "、".join(
                f"`{item}`" for item in comparisons[:4]
            )
            if constants:
                detail += "；比较常量 " + "、".join(f"`{item}`" for item in constants)
            lines.append(detail)
            lines.append(
                "这些是镜像内的比较指令，说明探测结果确实进入了分支判断；"
                "`UNKNOWN(exit)`：失败分支的去向与运行时是否真的走到该分支仍未验证。"
            )
        elif re.search(r"threshold\s*=\s*(?!UNKNOWN)", blob, re.I):
            lines.append(
                "静态恢复到环境探测比较。"
                "探测 API 存在不等于已经绕过分析环境。"
            )
        else:
            lines.append(
                "静态见到环境探测相关 API。"
                "`UNKNOWN(threshold)`：没有比较阈值与失败分支时，不能写成已证实的反分析门控。"
            )
        lines.append("")
        return lines

    if catalog_id == "persistence":
        lines.append(
            "静态见到启动项、服务或计划任务相关线索。"
            "注册表键名或计划任务字符串单独不是已安装的持久化。"
        )
        if "unknown(lifetime)" in blob.casefold() or "schtasks" in blob.casefold():
            lines.append("`UNKNOWN(lifetime)`：没有触发条件与载荷路径时，不能写成已安装的持久化。")
        lines.append("")
        return lines

    if catalog_id == "collection-and-exfiltration":
        has_sink = any(
            token in blob.casefold()
            for token in ("network_sink", "winhttp", "exfil", "c2", "socket")
        )
        lines.append(
            "静态见到收集相关线索。收集不等于外传；"
            "没有生产者到暂存再到网络出口的关系时，不能写成已经外传。"
        )
        if not has_sink:
            lines.append("`UNKNOWN(consumer)`：外传出口未恢复。")
        lines.append("")
        return lines

    if catalog_id == "file-operations":
        path = _first(_PATH_RE, blob) or _first(re.compile(r"path=`([^`]+)`", re.I), blob)
        has_size = bool(
            re.search(
                r"(?:size|threshold|length)\s*=\s*(?!UNKNOWN)(?:0x[0-9a-f]+|\d+)",
                blob,
                re.I,
            )
        )
        has_page_threshold = bool(re.search(r"\b0x1000\b", blob, re.I))
        tmp_or_mz = ".tmp" in blob.casefold() or bool(re.search(r"\bMZ\b", blob))
        lines.append(
            "静态见到文件创建/写入相关调用。文件名字符串本身不能证明已经落地；"
            "路径、访问方式和缓冲来源未恢复时保持未知。"
        )
        if path:
            lines.append(f"路径线索：`{path}`。")
        if tmp_or_mz and not has_size and not has_page_threshold:
            lines.append(
                "`UNKNOWN(size)`：没有恢复到大小阈值时，不能把 `.tmp` 或 MZ 线索写成落地文件。"
            )
        lines.append("")
        return lines

    if catalog_id == "registry-operations":
        # The image literally carries registry key paths and value names as string
        # rows with file_offset anchors, but they never reached this chapter: the
        # enclosing function's reference sample is capped and stops before the
        # registry block.  Scan the document so the chapter can cite what is really
        # there.  It never claims the sample wrote them - the callsite and value
        # bindings stay unrecovered.
        keys, value_names = _document_registry_strings(document)
        # The epistemic contract comes first and is never displaced: seeing a
        # registry write API plus key strings is not an installed persistence
        # mechanism.  `tests/test_analyst_report_acceptance.py` asserts this
        # sentence survives, so the recovered values are added *after* it rather
        # than instead of it.
        lines.append(
            "静态见到注册表打开/写入相关调用。没有 `Run` 键或服务路径证据时，"
            "不能把注册表 API 单独写成持久化。"
        )
        if keys or value_names:
            if keys:
                lines.append(
                    "镜像内确实带有注册表键路径："
                    + "、".join(f"`{item}`" for item in keys[:6])
                    + "。"
                )
            if value_names:
                lines.append(
                    "以及配置值名："
                    + "、".join(f"`{item}`" for item in value_names[:6])
                    + "。"
                )
            lines.append(
                "这些字符串与 `RegSetValueExW`/`RegOpenKeyExW` 调用点同处该样本，"
                "说明样本具备改写这些注册表配置的能力；"
                "`UNKNOWN(binding)`：键名与具体调用点、写入数值的绑定未恢复，"
                "因此不能写成已经完成篡改。"
            )
        lines.append("")
        return lines

    if catalog_id == "process-creation":
        # Same gate as the footer: an implausible immediate is not a recovered
        # flag word, so neither the body nor the footer may present it as one.
        flags = _credible_creation_flags_in_text(blob)
        if not flags and "unknown(creation_flags)" in blob.casefold():
            # The claim text is text-frozen at persist time and only consults the
            # candidate list, so it can say UNKNOWN while the call site decides the
            # value.  Ask the deterministic route before publishing the denial - a
            # report that denies a value it prints elsewhere is worse than one that
            # omits it.  Gated on the placeholder so the scan does not run per chapter.
            flags = _recovered_creation_flags(matched, document) or _recovered_creation_flags(
                rows, document
            )
        command = _first(re.compile(r"command=`([^`]+)`", re.I), blob)
        joined = "joined_static" in blob.casefold()
        show_command = bool(command) and (joined or not _looks_like_decoded_task(command))
        if flags:
            detail = f"静态恢复到进程创建，`creation_flags` `{flags}`"
            if show_command:
                detail += f"，命令 `{command}`"
            detail += "。导入存在不等于子进程已运行。"
            lines.append(detail)
        else:
            lines.append(
                "静态见到进程创建相关 API。"
                "`UNKNOWN(creation_flags)`：没有恢复到说得通的创建标志时，不能写成具体的挂起或隐藏创建方式，也不能写成子进程已启动。"
            )
        if joined:
            lines.append(
                "`JOINED_STATIC`：解码明文与进程命令接到同一输出缓冲，Join 为静态边，不是运行时已启动。"
            )
        else:
            join_line = (
                "`UNKNOWN(join)`：解码明文与进程命令未接到同一输出缓冲，不能把两轨写成一条载荷启动链。"
            )
            if command and _looks_like_decoded_task(command):
                join_line += (
                    f"进程轨里的 `{command}` 不能当成未引用解码槽的已发现任务名。"
                )
            lines.append(join_line)
        if (
            "createprocess_failure_to_schtasks" not in blob.casefold()
            and "process_failure_to_scheduled_task" not in blob.casefold()
        ):
            lines.append(
                "`UNKNOWN(fallback)`：没有 CreateProcess 失败后接到计划任务的控制流/使用链时，"
                "不能把 schtasks 字符串写成已证实的回退路径。"
            )
        lines.append("")
        return lines

    if catalog_id == "parent-process-spoofing":
        # The typed chain decides, not a Process32 enumeration chain in the prose
        # blob: this family names the parent with UpdateProcThreadAttribute
        # (PARENT_PROCESS) and enumerates nothing.  A name the sample merely
        # carries still yields nothing here, so the chapter keeps its UNKNOWN.
        parent = _recovered_parent_identity(matched)
        has_enum = any(
            token in blob.casefold()
            for token in ("process32first", "process32next", "createtoolhelp32snapshot")
        )
        if parent:
            attribute = _first(
                re.compile(r"attribute\s*=\s*`?(0x[0-9a-fA-F]+|PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)", re.I),
                blob,
            )
            detail = "静态恢复到父进程属性链"
            if attribute:
                detail += f"（`attribute={attribute}`"
                if "proc_thread_attribute_parent_process" in blob.casefold():
                    detail += "，即 `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`"
                detail += "）"
            detail += (
                f"，父镜像 `{parent}`。这是父进程身份伪装，不是把代码写入其他进程；"
                "运行时的父进程身份未验证。"
            )
            lines.append(detail)
        elif has_enum:
            enum_parent = _first(re.compile(r"(explorer\.exe|[A-Za-z0-9_.-]+\.exe)", re.I), blob)
            detail = "静态见到父进程属性链"
            if enum_parent and "unknown" not in enum_parent.casefold():
                detail += f"，父镜像 `{enum_parent}`"
            detail += "。这是父进程身份伪装，不是把代码写入其他进程。"
            lines.append(detail)
        else:
            lines.append(
                "静态见到父进程属性相关调用。"
                "`UNKNOWN(parent identity)`：没有恢复到类型化的父进程身份链"
                "（`parent_selection`）时，不能把单独的宿主进程名字符串写成父进程身份。"
            )
        lines.append("")
        return lines

    if catalog_id == "custom:com":
        lines.append(
            "静态见到 `CoCreateInstance`。COM 对象创建不等于 COM 劫持；"
            "CLSID、接口和写入的劫持键未恢复前保持未知。"
        )
        lines.append("")
        return lines

    if topic.status == "unrecovered":
        anchors = ", ".join(f"`{item}`" for item in topic.anchors[:6] if item)
        lines.append(
            "本次证据触发了该能力线索"
            + (f"（{anchors}）" if anchors else "")
            + "，但调用参数与后续使用点未恢复。不能把缺失写成已排除。"
        )
        lines.append("")
        return lines

    lines.append("已匹配该行为目录条目，可写入结论的参数化路径仍不完整，未恢复部分保持未知。")
    lines.append("")
    return lines


def _recovered_call_names(rows: Sequence[Mapping[str, object]], *, limit: int = 12) -> list[str]:
    names: list[str] = []
    for row in rows:
        blob = _field_text(row.get("how") or row.get("transformation_or_control") or row.get("what"))
        for match in _NOTABLE_API_RE.findall(blob):
            if _is_behavior_api(match):
                names.append(_strip_aw_suffix(match))
    return list(dict.fromkeys(names))[:limit]


def _document_import_modules(
    document: Mapping[str, object],
) -> list[tuple[str, str, int]]:
    """Every module in the PE import table as ``(display, casefold_key, function_count)``.

    The behaviour-filtered list above cannot show this, and the gap is real: a module whose imports
    are all CRT/runtime symbols never appears, so the sample reads as if it did not import from it at
    all. Measured on task `ce7e310e`: the table names `msvcrt.dll` (28 functions) and
    `api-ms-win-core-synch-l1-2-0.dll` (3, including the `WaitOnAddress` synchronisation pair), and
    both were absent from a body that claimed to list the import table. Counts are summed per module
    because a PE table can carry several descriptors for one module (`kernel32.dll` 70 +
    `KERNEL32.dll` 25 in that sample) and `_notable_imports` counts them as one module.
    """
    found: dict[str, tuple[str, int]] = {}
    for row in iter_document_rows(document):
        if str(row.get("type") or "") != "pe_basics":
            continue
        entries = row.get("import_entries")
        if isinstance(entries, list) and entries:
            for entry in entries:
                if not isinstance(entry, Mapping):
                    continue
                module = str(entry.get("module") or "").strip()
                if not module:
                    continue
                count = entry.get("function_count")
                if not isinstance(count, int):
                    functions = entry.get("functions")
                    count = len(functions) if isinstance(functions, list) else 0
                key = module.casefold()
                display, running = found.get(key, (module, 0))
                found[key] = (display, running + int(count))
            break
        flat = row.get("imports")
        if isinstance(flat, list):
            for item in flat:
                head, sep, _tail = str(item or "").partition("!")
                if sep and head.strip():
                    key = head.strip().casefold()
                    display, running = found.get(key, (head.strip(), 0))
                    found[key] = (display, running + 1)
            break
    return sorted(
        (display, key, count) for key, (display, count) in found.items()
    )


def _pe_overview(document: Mapping[str, object], rows: Sequence[Mapping[str, object]]) -> list[str]:
    pe = next((row for row in rows if row.get("type") == "pe_basics"), None)
    artifacts = []
    for row in rows:
        if row.get("sha256") and row.get("path"):
            artifacts.append(row)
    lines = ["### 样本概况", ""]
    if pe:
        lines.append(
            f"- 格式 `{pe.get('format') or 'UNKNOWN'}`，机器 `{pe.get('machine') or 'UNKNOWN'}`，"
            f"入口 RVA `{pe.get('entry_rva') or 'UNKNOWN'}`，子系统 `{pe.get('subsystem') or 'UNKNOWN'}`。"
        )
        sections = pe.get("section_names") or pe.get("sections")
        if sections:
            lines.append(f"- 节：{', '.join(str(item) for item in list(sections)[:12])}")
    imports = _notable_imports(rows)
    flattened = [name for _module, names in imports for name in names]
    recovered = [
        name for name in _recovered_call_names(rows)
        if name.casefold() not in {item.casefold() for item in flattened}
    ]
    if imports:
        lines.append("- 与 Windows 行为相关的导入（按模块分组；CRT 启动/运行时包装符号已省略）：")
        for module, names in imports:
            label = module or "（未限定模块）"
            lines.append(f"  - `{label}`：{', '.join(f'`{name}`' for name in names)}")
        # The behaviour filter above cannot represent a module whose imports are all runtime
        # symbols, so the complete module list is stated explicitly.  Without it the sample reads as
        # if it never imported from `msvcrt.dll` or `api-ms-win-core-synch-l1-2-0.dll`.
        table_modules = _document_import_modules(document)
        if table_modules:
            rendered = "、".join(
                f"`{display}`（{count}）" for display, _key, count in table_modules
            )
            lines.append(f"  - 导入表模块清单（{len(table_modules)} 个）：{rendered}")
        # A bounded overview must not read as the complete inventory.  Measured on task `ce7e310e`:
        # the PE table holds 136 import names across nine descriptors while this readable list shows
        # 20 behaviour-relevant ones, and the earlier body gave no way to tell the difference.  The
        # line claims only what the section itself can show - an earlier draft pointed the reader at
        # an appendix import table that the renderer does not emit.
        shown_total = sum(len(names) for _module, names in imports)
        ledger_total = _document_import_name_total(document)
        if ledger_total and ledger_total > shown_total:
            lines.append(
                f"  - 边界：以上为按模块归并后的行为相关导入 {shown_total} 条，"
                f"PE 导入表共 {ledger_total} 条（差额为 CRT/运行时符号及同一模块下的其余条目）。"
            )
    if recovered:
        lines.append("- 导入表不能当成功能清单；反编译/调用序列额外恢复到的 API：")
        for name in recovered:
            lines.append(f"  - `{name}`")
    sha = ""
    if artifacts:
        sha = str(artifacts[0].get("sha256") or "")
    if not sha:
        for module in document.get("modules") or []:
            if not isinstance(module, Mapping):
                continue
            for row in module.get("rows") or []:
                if isinstance(row, Mapping) and row.get("sha256"):
                    sha = str(row.get("sha256"))
                    break
    if sha:
        lines.append(f"- SHA256：`{sha}`")
    # The compiler/build path is a headline static fact about a sample, and the
    # string is already in the recovered data references (e.g.
    # ``PTR_s_/rustc/59807616e1fa2540724bfbac1_14004cfd8``); it was simply never
    # surfaced.  Only a path actually present in the document is printed.
    toolchain = _document_toolchain_hint(document)
    if toolchain:
        lines.append(f"- 构建工具链痕迹：`{toolchain}`（镜像内字符串，非运行时观察）")
    language = _document_compile_language(rows, document)
    if language:
        lines.append(f"- 编译语言：**{language}**（由运行时依赖与编译器特征符号判定，非运行时观察）")
    lines.extend(_document_version_info_lines(rows))
    lines.extend(_pe_resource_lines(rows))
    lines.append("")
    return lines


#: Runtime DLL -> the toolchain that produces it. A binary linking `MSVBVM60.DLL` was compiled by Visual
#: Basic 6, and that is a language-level fact a triage reader asks for first.
_COMPILE_LANGUAGE_BY_RUNTIME: tuple[tuple[str, str], ...] = (
    ("msvbvm60", "Visual Basic 6.0 (VB6, p-code/native)"),
    ("msvbvm50", "Visual Basic 5.0"),
    ("vba6", "Visual Basic 6.0 (VBA6 runtime)"),
    ("msvcp", "Microsoft Visual C++"),
    ("msvcr", "Microsoft Visual C/C++ runtime"),
    ("mscoree", ".NET (Common Language Runtime)"),
    ("python3", "CPython (packaged)"),
    ("libgcc", "GCC/MinGW (C/C++)"),
)

#: VB6's own runtime helper symbols. Their presence means the compiler, independently of the import table,
#: because `__vbaStrCopy` and `EVENT_SINK_*` are emitted by the VB6 code generator.
_VB6_SYMBOL_RE = re.compile(r"^(?:__vba|EVENT_SINK_|ThunRTMain|rtc\w+)", re.IGNORECASE)


def _document_compile_language(
    rows: Sequence[Mapping[str, object]],
    document: Mapping[str, object] | None = None,
) -> str:
    """Name the toolchain that compiled the sample, or "" when the evidence does not settle it.

    MEASURED GAP. The published body for the 白象 sample `64da3378` listed `MSVBVM60.DLL`, `VBA6.DLL`,
    `C:\\NanoVB6\\VB6.OLB` and twenty-one `__vba*` symbols, and never once said "Visual Basic". The named
    depth benchmark carries a 编译语言 field and the reference document for this campaign describes the
    family by compiler ("Microsoft Visual Basic 5.0 / 6.0"); an analyst reading the body had to infer the
    language from a list of runtime symbols.

    The evidence is read from BOTH the flattened module rows and the document's top-level projections.
    A first version read only `rows`, and returned "" on a real document that contains the marker, because
    `iter_document_rows` walks `modules[].rows[]` and the string facts are a TOP-LEVEL list
    (`document["string_facts"]`). The unit test passed because it built its own rows; only running the
    detector against a real document exposed the difference.

    The inference is stated as an inference - it is derived from the runtime dependency and the compiler's
    own emitted symbols, and the renderer says so rather than presenting it as a recovered field.
    """
    texts: set[str] = set()

    def collect(node: object) -> None:
        if isinstance(node, str):
            if node.strip():
                texts.add(node.strip())
            return
        if isinstance(node, Mapping):
            for key, value in node.items():
                collect(key)
                collect(value)
            return
        if isinstance(node, (list, tuple, set)):
            for value in node:
                collect(value)

    collect(list(rows))
    if document is not None:
        # The top-level projections are the ones `iter_document_rows` cannot reach. They are bounded, so
        # walking them is cheap, and one of them (`pe_resources`) carries the resource payload digests.
        for key in ("string_facts", "pe_resources", "pe_basics", "analysis_coverage"):
            collect(document.get(key))
    folded = " ".join(sorted(texts)).casefold()
    for needle, language in _COMPILE_LANGUAGE_BY_RUNTIME:
        if needle in folded:
            return language
    if any(_VB6_SYMBOL_RE.match(text) for text in texts):
        return "Visual Basic 6.0 (VB6, 由编译器特征符号判定)"
    return ""


def _document_version_info_lines(rows: Sequence[Mapping[str, object]]) -> list[str]:
    """Publish what the file's own VERSIONINFO block claims about it.

    MEASURED GAP. The `RT_VERSION` block of the 白象 sample `64da3378` records
    `OriginalFilename ss3advd.exe`, `InternalName ss3advd`, `ProductName DndndnD` (a keyboard mash),
    `CompanyName None` and `FileVersion 1.01`. Both keys and values were already recorded as Evidence and
    the published body mentioned none of them, so the sample's own statement about its identity - including
    the only string that links it to the reference document's `http://zolipas.info/advd` path - was absent.

    The values are quoted as the sample's CLAIM, not as fact: a version block is written by whoever built
    the file and is trivially forged. The line says so.
    """
    fields: Mapping[str, object] = {}
    for row in rows:
        candidate = row.get("fields")
        if str(row.get("type") or "") == "pe_version_info" and isinstance(candidate, Mapping):
            fields = candidate
            break
    if not fields:
        return []
    published = [
        (key, str(fields.get(key)).strip())
        for key in _VERSIONINFO_ORDER
        if str(fields.get(key) or "").strip()
    ]
    if not published:
        return []
    rendered = "、".join(f"{key} `{value}`" for key, value in published)
    return [
        f"- 版本信息块（RT_VERSION，**样本自述，可伪造**）：{rendered}",
    ]


#: Print order for the version block; the canonical PE order, not the parse order.
_VERSIONINFO_ORDER: tuple[str, ...] = (
    "OriginalFilename",
    "InternalName",
    "ProductName",
    "CompanyName",
    "FileVersion",
    "ProductVersion",
)


def _pe_resource_lines(rows: Sequence[Mapping[str, object]]) -> list[str]:
    """Name the PE resources, because a version block and a high-entropy icon are facts.

    Measured on task `ce7e310e`: the binary is submitted under a `.pdf.exe`-style name and carries a
    876-byte
    `RT_VERSION` block plus nine `RT_ICON` entries, one at entropy 7.94 - a plausible embedded payload.
    The published body named no resource at all, so "this file presents itself as something else" was
    not stated anywhere, even though the limitations section listed 资源提取链 as reportable.
    """
    projection = next(
        (
            row
            for row in rows
            if str(row.get("type") or "") == "pe_resources" and row.get("entries")
        ),
        None,
    )
    if projection is None:
        return []
    entries = [item for item in projection.get("entries") or [] if isinstance(item, Mapping)]
    if not entries:
        return []
    parts = []
    for entry in entries:
        name = str(entry.get("name") or "resource")
        count = entry.get("count")
        size = entry.get("total_size")
        entropy = entry.get("max_entropy")
        detail = f"{count} 项"
        if isinstance(size, int) and size > 0:
            detail += f"，共 {size} 字节"
        if isinstance(entropy, (int, float)) and float(entropy) >= 7.2:
            detail += f"，最高熵 {float(entropy):.2f}（可能为嵌入载荷）"
        parts.append(f"`{name}`（{detail}）")
    lines = [
        f"- 资源目录：共 {projection.get('resource_count')} 项 —— " + "、".join(parts)
    ]
    return lines


def _recovered_endpoint_values(rows: Sequence[Mapping[str, object]], *, limit: int = 4) -> list[str]:
    """Endpoints the *decode* actually produced, in first-seen order.

    Only two sources count: an explicit ``endpoint=``/``endpoints=`` field, and
    the decoded text of a decode-typed row.  Scanning every row's text for URLs
    also picks up this product's own ATT&CK reference links
    (``attack.mitre.org``), which are not sample configuration -- reporting them
    as "解码得到的端点" would be false.
    """
    found: list[str] = []
    for row in rows:
        text = _flatten_for_scan(row)
        for match in re.finditer(
            r"(?i)\bendpoints?\s*=\s*`?((?:https?://)[^\s`;)\]}\"',]+)", text
        ):
            value = match.group(1).strip("`;,.)")
            if value and value not in found:
                found.append(value)
        kind = str(row.get("type") or row.get("kind") or "").casefold()
        if kind not in {"decode_result", "encoded_blob"}:
            continue
        decoded = " ".join(
            str(row.get(key) or "")
            for key in ("decoded_preview", "decoded_text", "decoded_strings", "plaintext")
        )
        for match in _COMPOSE_URL_RE.finditer(decoded):
            value = match.group(0).strip("`;,.)")
            if value and value not in found:
                found.append(value)
        if len(found) >= limit:
            break
    return found[:limit]


def _second_table_check(rows: Sequence[Mapping[str, object]]) -> Mapping[str, object] | None:
    """The code-anchored cross-table completeness verdict, when the run produced one.

    Returns ``None`` when the check did not run, and that is deliberately NOT collapsed into "no second
    table exists": "not checked" and "checked and clean" are different facts, and the chapter must stay
    silent in the first case rather than imply the recovered text was proven complete.

    Why the report needs this at all: the decode range is bounded by the enclosing section, so a sample can
    carry a SECOND literal table outside it - measured on 白象 `64da3378`, table B at `0x40bb98` is
    referenced by 78 `mov edx, imm32` anchors and stores the same script at a different splice phase. The
    question "does quoting only the primary table understate the sample?" is answerable by measurement, so
    it is answered by measurement instead of left as an unstated assumption.
    """
    for row in rows:
        for candidate in (row, row.get("verification"), row.get("candidate")):
            if isinstance(candidate, Mapping):
                found = candidate.get("second_table_check")
                if isinstance(found, Mapping):
                    return found
    return None


def _looks_like_a_process_command(value: str) -> bool:
    """A recovered command line names an image or runs one - including a remote one.

    The previous version returned ``False`` for anything containing ``://``, on the
    premise that a recovered command line "names an image, not a URL".  That premise
    is wrong for the sample this work targets: its recovered
    ``CreateProcessW`` command *is* a URL,
    ``http://69.48.228.74/ComHost.exe`` - the very value the reference report
    publishes - so the guard silently dropped the single most operationally useful
    fact the run had recovered.  Measured before the fix: the guard returned
    ``False`` for that URL while returning ``True`` for ``FoxitPDFReader.exe``.

    A URL that names an executable is a download-and-run command, which is exactly
    what this family does, so it is accepted.  A URL that does not name an
    executable (a bare page, an endpoint path) is still rejected: those belong to
    the decode/endpoint findings, not to a process command line.  http/https answers
    "is this a remote exec", ``command=`` says "this was recovered as the command",
    and both must hold before a URL is published as one.
    """
    text = str(value or "").strip().strip("`")
    if not text:
        return False
    if "://" in text:
        lowered = text.casefold()
        if not lowered.startswith(("http://", "https://")):
            return False
        path = lowered.split("://", 1)[1]
        tail = path.rsplit("/", 1)[-1].split("?", 1)[0].split("#", 1)[0]
        return tail.endswith((".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js"))
    folded = text.casefold()
    return folded.endswith((".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js")) or (
        "\\" in text or "/" in text
    )


def _recovered_static_facts(rows: Sequence[Mapping[str, object]]) -> list[str]:
    """Concrete values this run recovered, stated as facts rather than closures.

    An analyst needs the recovered values *before* the open slots.  The older
    summary named only generic capability categories ("dynamic resolution path"),
    which reads as though nothing specific came out of the run even when a
    decoded endpoint, a thread entry or a parent-process attribute was in hand.

    These are deliberately phrased as recovered static values.  None of them
    claims runtime execution or a closed consumer chain -- that distinction is
    what the stop-kind block below reports separately.
    """
    facts: list[str] = []
    entry = _recovered_thread_entry_va(rows)
    if entry:
        facts.append(f"`CreateThread` 入口 `{entry}`（同进程线程，运行时未观察）")
    endpoints = _recovered_endpoint_values(rows)
    if endpoints:
        facts.append("解码得到的端点：" + "、".join(f"`{item}`" for item in endpoints))
    apis = _recovered_call_names(rows, limit=10)
    if apis:
        facts.append("恢复到的调用序列：" + "、".join(f"`{item}`" for item in apis))
    blob = _blob(rows)
    attribute = re.search(r"attribute\s*=\s*(0x[0-9a-fA-F]+)", blob)
    if attribute:
        facts.append(
            f"父进程属性 `{attribute.group(1)}`（已恢复属性值；父进程身份未恢复）"
        )
    resolved = sorted(
        {
            str(row.get("api_name"))
            for row in rows
            if str(row.get("kind") or "") == "resolved_api" and row.get("api_name")
        }
    )
    if resolved:
        facts.append("动态解析出的 API：" + "、".join(f"`{item}`" for item in resolved[:8]))
    command = _first(re.compile(r"command\s*=\s*`?([^`;\s]+)", re.I), blob)
    if command and not command.casefold().startswith("unknown") and _looks_like_a_process_command(command):
        # Provenance matters here, and the row itself carries the signal.  When a
        # command comes from a typed process-creation argument trace, the SAME
        # mechanism string also carries the recovered flag word (and often
        # parent_selection); when it was minted from a bare image-name string - which
        # is deliberate, tested behaviour - the flags are UNKNOWN because no typed
        # evidence was found.
        #
        # Verified on task 45cbd992: every CreateProcess argument trace carries
        # `command: null`, the only row yielding a command at all is the UTF-16 string
        # literal {"encoding":"utf-16le","text":"FoxitPDFReader.exe"}, and all 12
        # command-bearing mechanism strings read `creation_flags=UNKNOWN(creation_flags)`
        # with zero occurrences of `creation_flags=0x`.
        #
        # So the image name is published as an *inference*, not as a recovered command
        # line.  The claim is still made and the seed still closes; only the wording
        # stops asserting an operational fact the evidence does not support.
        flags_recovered = bool(
            re.search(r"creation_flags\s*=\s*(?!UNKNOWN)(0x[0-9a-fA-F]+)", blob, re.I)
        )
        if flags_recovered:
            facts.append(f"恢复到的进程命令行 `{command}`（运行时未观察）")
        else:
            facts.append(
                f"进程创建相关镜像名 `{command}`（镜像内字符串线索，"
                "未恢复到对应的进程创建参数，因此不能当作已恢复的命令行）"
            )
    return facts


def _synthesis(
    document: Mapping[str, object],
    rows: Sequence[Mapping[str, object]],
    topics: Sequence[AnalystTopic],
) -> list[str]:
    blob = _blob(rows)
    pe = next((row for row in rows if row.get("type") == "pe_basics"), None)
    fmt = str((pe or {}).get("format") or "").strip()
    machine = str((pe or {}).get("machine") or "").strip()
    identity = "该映像"
    if fmt or machine:
        identity = f"该样本（{', '.join(item for item in (fmt, machine) if item)}）"
    facts: list[str] = []
    recovered = _recovered_static_facts(rows)
    facts.extend(recovered)
    start = _first(_START_RE, blob)
    if start:
        facts.append(f"同进程 `CreateThread`，入口 `{start}`，线程参数未恢复")
    if "cryptdecrypt" in blob.casefold() or "cryptencrypt" in blob.casefold():
        facts.append("CryptoAPI 解密/加密调用（密钥、密文与明文消费者未闭合）")
    if "findresource" in blob.casefold() or "lockresource" in blob.casefold():
        facts.append("`FindResource` → `LoadResource` → `LockResource` 资源提取链")
    if "loadlibrary" in blob.casefold() and "getprocaddress" in blob.casefold():
        facts.append("`LoadLibrary`/`GetProcAddress` 动态解析路径")
    path = _first(_PATH_RE, blob)
    if path:
        facts.append(f"文件路径线索 `{path}`")
    facts = list(dict.fromkeys(facts))
    if not facts:
        titles = [topic.title for topic in topics[:6]]
        if titles:
            facts.append("触发了 " + "、".join(titles) + " 相关线索，但多数参数仍未知")
    natures = " ".join(
        _field_text(row.get("evidence_natures") or row.get("nature") or "")
        for row in rows
    ).upper()
    paragraph = (
        f"{identity}的本次结果是有界静态分析，未执行样本、未做完整沙箱。"
        + ("静态已恢复：" + "；".join(facts) + "。" if facts else "没有形成可写入结论的机制事实。")
        + "导入存在不等于运行时已发生。"
    )
    if "EMULATION_OBSERVED" in natures or "EMULATION_OBSERVED" in blob.upper():
        paragraph += (
            "隔离模拟观察（`EMULATION_OBSERVED`）不是目标主机上的运行时执行，也不是感染结论。"
        )
    unknowns = _collect_official_unknowns(rows, topics, document)
    if unknowns:
        paragraph += "未恢复槽位：" + "、".join(f"`{item}`" for item in unknowns[:8]) + "。"
    outcome = str(document.get("analysis_outcome") or "UNKNOWN")
    analysis_class = str(document.get("analysis_class") or "UNKNOWN")
    return [
        "### 结论摘要",
        "",
        paragraph,
        "",
        f"任务结果 `{outcome}`，分析类别 `{analysis_class}`。下面只展开本样本实际命中的机制，"
        "不是产品固定目录。",
        "",
    ]


# The decompiled chapter text writes the flag word in several shapes:
# `creation_flags=0x...`, `creation_flags = 0x...`, `creation_flags0x...`
# (no separator, as the assembly comment appears) and `creation_flags `0x...``.
# Matching only the first shape made the footer contradict its own body.
_CREATION_FLAGS_RE = re.compile(
    r"creation_flags\s*(?:[=:]\s*)?`?(0[xX][0-9a-fA-F]{1,8}|\d{1,10})`?",
    re.IGNORECASE,
)


def _credible_creation_flags(numeric: int) -> bool:
    """Whether an immediate is credible enough to report as a recovered flag word.

    Delegates to the single flag-credibility predicate in ``static_analysis`` so
    the footer and the TRACE evidence path cannot drift apart.
    """
    return credible_windows_process_creation_flags(numeric)


def _credible_creation_flags_in_text(blob: object) -> str:
    """The single extraction + credibility gate for a recovered creation_flags word.

    G5: the chapter body, the appendix and the footer used to extract this value
    three different ways, so the body could print ``0x000f4240`` while the footer
    correctly said ``UNKNOWN(creation_flags)``. One site removes that class of bug.
    """
    match = _CREATION_FLAGS_RE.search(str(blob or ""))
    if not match:
        return ""
    value = match.group(1).strip("`")
    if not value or value.casefold().startswith("unknown"):
        return ""
    try:
        numeric = int(value, 16) if value[:2].casefold() == "0x" else int(value, 10)
    except ValueError:
        return ""
    if not _credible_creation_flags(numeric):
        return ""
    return value


def _document_process_flags(
    document: Mapping[str, object] | None,
    rows: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """The labelled CreateProcess flag projection for this document.

    Prefers the stored ``process_flags`` projection (the report builder writes one) and
    falls back to deriving it from the ``process_creation_flags`` rows the document
    carries.  Both routes exist because revisions are immutable: the NEWEST stored
    revision was written before the projection existed, so a renderer fix alone could
    never move it.  The values are the same objects either way - the fallback reads the
    same ``flags`` list the builder's projection reads.
    """
    stored = (document or {}).get("process_flags")
    if isinstance(stored, list) and stored:
        return [dict(item) for item in stored if isinstance(item, Mapping)]

    derived: list[dict[str, object]] = []
    seen: set[int] = set()

    def harvest(node: object) -> None:
        if isinstance(node, Mapping):
            if str(node.get("kind") or "").casefold() == "process_creation_flags":
                value = node.get("value")
                if isinstance(value, Mapping) and id(value) not in seen:
                    seen.add(id(value))
                    derived.extend(
                        build_process_flag_projections({str(node.get("id") or "x"): node})
                    )
            for nested in node.values():
                harvest(nested)
        elif isinstance(node, list):
            for nested in node:
                harvest(nested)

    for row in rows:
        harvest(row)
    if derived:
        return derived
    harvest(document or {})
    return derived


_CREATION_FLAGS_STACK_SLOT_RE = re.compile(
    r"(?i)^MOV\s+(?:dword|qword)\s+ptr\s*\[\s*(RSP|ESP|RBP|EBP)\s*\+\s*0x([0-9a-f]+)\s*\]\s*,\s*(0x[0-9a-f]+|\d+)$"
)
_PROCESS_CREATION_CALL_RE = re.compile(r"(?i)^CALL\s+(?:0x)?([0-9a-f]+)$")

# The Evidence kind of a stored disassembly window.  Kept as a literal because that is
# what the producer writes (``static_analysis.build_stored_instruction_window`` emits
# ``"type": "function_instruction_window"``); a test pins the two together so this
# consumer cannot drift from the producer.
_INSTRUCTION_WINDOW_KIND = "function_instruction_window"


def _flags_from_creation_callsite(
    rows: Sequence[Mapping[str, object]],
    document: Mapping[str, object] | None,
) -> str:
    """The flag word the process-creation CALL itself passes, if it is recoverable.

    This is the DETERMINISTIC route, and it exists because the obvious route is wrong.
    ``process_creation_flags.flags`` is a candidate LIST of every credential-looking
    immediate in one function - for FUN_140004605 it is eight words, of which only one
    belongs to ``CreateProcessW``.  Taking the first credible entry published
    ``0x28000000`` for a sample whose real value is ``0x09080008``, which is worse than
    saying UNKNOWN.

    What IS deterministic is the call site.  On the real sample the window ends with:

        MOV dword ptr [RSP + 0x28],0x9080008     <- dwCreationFlags stack slot
        AND dword ptr [RSP + 0x20],0x0
        MOV RCX,R14                              <- lpApplicationName
        XOR EDX,EDX                              <- lpCommandLine (null)
        XOR R8D,R8D
        XOR R9D,R9D
        CALL 0x140046948                         <- CreateProcessW thunk

    Six of the eight candidate words never appear in this window at all; ``0x09080008``
    is written into the argument slot the call reads.  So scan the instructions before a
    process-creation call for a ``MOV`` into a stack slot and accept the immediate only
    when the package credibly describes Windows creation flags.

    The window is located by name/entry when the row carries one, and is otherwise found
    by scanning the document's windows directly - `iter_document_rows` returns evidence
    samples without their anchor, so keying on the anchor alone silently found nothing.
    Returns ``""`` when no such call site is present, so a caller cannot mistake "not
    found" for "no flags".
    """
    candidates: list[tuple[int, str]] = []
    for window in _callsite_windows(document, rows):
        instructions = [
            item for item in (window.get("instructions") or []) if isinstance(item, Mapping)
        ]
        for index, item in enumerate(instructions):
            if not _PROCESS_CREATION_CALL_RE.match(str(item.get("text") or "").strip()):
                continue
            for earlier in reversed(instructions[max(0, index - 24) : index]):
                text = str(earlier.get("text") or "").strip()
                if not _CREATION_FLAGS_STACK_SLOT_RE.match(text):
                    continue
                operand = text.rsplit(",", 1)[-1].strip()
                candidate = _credible_creation_flags_in_text(f"creation_flags={operand}")
                if candidate:
                    candidates.append((index, candidate))
                break
    if not candidates:
        return ""
    # A function may hold several calls; prefer the value written for the LAST one, which
    # is the slot the process-creation call actually reads.
    candidates.sort()
    return candidates[-1][1]


def _callsite_windows(
    document: Mapping[str, object] | None,
    rows: Sequence[Mapping[str, object]],
) -> list[Mapping[str, object]]:
    """Instruction windows reachable from the document OR from the evidence rows.

    THE JOIN THAT WAS MISSING.  ``_flags_from_creation_callsite`` scanned
    ``_iter_windows(document)`` only, so the deterministic route silently found nothing
    whenever the report document carried no instruction window - which is the normal
    case, because the report projection bounds Evidence to 4,096 rows and a single
    ``function_instruction_window`` row is up to 341 KB.  Measured on ``c705a42e``: the
    ledger held 703 instruction windows and the stored document held none, so the
    published body printed ``UNKNOWN(creation_flags)`` while the very instructions that
    determine the value sat in evidence:

        MOV dword ptr [RSP + 0x28],0x9080008     <- dwCreationFlags stack slot
        XOR EDX,EDX                              <- lpCommandLine (null)
        CALL 0x140046948                         <- CreateProcessW thunk

    The renderer already receives the evidence rows (``_document_process_flags`` harvests
    ``process_creation_flags`` projections from them), so the window is reachable without
    widening the projection: read ``value.instructions`` from the rows themselves.  This
    is the cross-shape rule applied at its source rather than patched per consumer - the
    fact was written into two shapes and the consumer read exactly one.

    Rows are filtered on ``kind`` rather than on the presence of an ``instructions`` key,
    so an unrelated nested structure cannot be mistaken for a disassembly window.
    """
    windows: list[Mapping[str, object]] = list(_iter_windows(document))
    seen = {id(window) for window in windows}

    # Harvest RECURSIVELY, the same way ``_document_process_flags`` above does.  The two
    # consumers read the same evidence and must not disagree about where it lives:
    # ``iter_document_rows`` returns a row without its ``evidence_samples``, so a
    # top-level-only scan finds `process_creation_flags` (reachable both ways) but never
    # the instruction window (reachable only nested).  That asymmetry is why the
    # deterministic route recovered `0x9080008` from the evidence ledger and still
    # published `UNKNOWN(creation_flags)` eight times in the rendered body.
    def harvest(node: object) -> None:
        if isinstance(node, Mapping):
            kind = str(node.get("kind") or "").casefold()
            if kind == _INSTRUCTION_WINDOW_KIND:
                value = node.get("value")
                payload: object = value if isinstance(value, Mapping) else node
                if isinstance(payload, Mapping) and isinstance(payload.get("instructions"), list):
                    if id(payload) not in seen:
                        seen.add(id(payload))
                        windows.append(payload)
            for nested in node.values():
                harvest(nested)
        elif isinstance(node, list):
            for nested in node:
                harvest(nested)
        elif isinstance(node, (str, bytes)) or node is None:
            return
        else:
            # An evidence ROW rather than a plain mapping (``SimpleNamespace``-backed, as
            # the builders pass them).  Same two access patterns ``_document_process_flags``
            # handles: the payload may be the node itself or nested under ``value``.
            kind = str(getattr(node, "kind", "") or "").casefold()
            if kind == _INSTRUCTION_WINDOW_KIND:
                value = getattr(node, "value", None)
                payload = value if isinstance(value, Mapping) else node
                instructions = (
                    payload.get("instructions")
                    if isinstance(payload, Mapping)
                    else getattr(payload, "instructions", None)
                )
                if isinstance(instructions, list) and id(payload) not in seen:
                    seen.add(id(payload))
                    windows.append(payload)  # type: ignore[arg-type]

    for row in rows:
        harvest(row)
    return windows


def _iter_windows(document: Mapping[str, object] | None) -> Iterable[Mapping[str, object]]:
    """Every ``function_instruction_window``-shaped mapping in the document."""

    def walk(node: object):
        if isinstance(node, Mapping):
            if isinstance(node.get("instructions"), list):
                yield node
            for nested in node.values():
                yield from walk(nested)
        elif isinstance(node, list):
            for nested in node:
                yield from walk(nested)

    return walk(document or {})


def _recovered_creation_flags(
    rows: Sequence[Mapping[str, object]],
    document: Mapping[str, object] | None = None,
) -> str:
    """The recovered flag word, or ``""`` when no source recovers one.

    Three sources, strongest first, because the fact reaches the report in several shapes
    and consulting only the prose blob produced a false negative:

    1. the prose blob, which carries a typed ``creation_flags=0x...`` when the argument
       binding was recovered;
    2. the process-creation CALL SITE in the document's instruction window - the
       deterministic route (see :func:`_flags_from_creation_callsite`);
    3. the labelled ``process_flags`` projection, whose ``recovered_as`` says whether a
       word was argument-bound or is only a candidate immediate.

    Measured on task `c705a42e`: `0x09080008` was in the ``process_creation_flags`` row
    (``flags[6].value``) and written into the call's argument slot, the typed
    ``api_argument_trace.creation_flags`` was empty, and the published body printed
    `UNKNOWN(creation_flags)` beside the value it had written - so the report denied a
    fact it held.  Same structural defect as the "no C2" claim: a negative asserted from
    one shape without checking the others.
    """
    typed = _credible_creation_flags_in_text(_blob(rows))
    if typed:
        return typed
    # The report document's deterministic call-site projection.  This is the strongest
    # source that actually travels with the document: the instruction window itself
    # cannot, because a function body is up to 341 KB and the document carries windows
    # only as ledger GROUP rows whose `value` is None.
    projected = _document_creation_flags_callsite(document)
    if projected:
        return projected
    from_call = _flags_from_creation_callsite(rows, document)
    if from_call:
        return from_call
    for item in _document_process_flags(document, rows):
        # Only an argument-bound word may be published as THE creation flags.  A
        # candidate immediate is a legitimate finding but not a value for this slot, and
        # publishing the first credible candidate produced a wrong answer.
        if str(item.get("recovered_as") or "") != "typed_argument_binding":
            continue
        candidate = _credible_creation_flags_in_text(
            f"creation_flags={item.get('value') or ''}"
        )
        if candidate:
            return candidate
    return ""


def _document_creation_flags_callsite(document: Mapping[str, object] | None) -> str:
    """The flag word from the document's deterministic call-site projection, or ``""``.

    Reads only a labelled projection produced by
    :func:`reporting.build_creation_flags_callsite_projection`, and only when it says the
    word was argument-bound.  A different ``recovered_as`` means the value did not come from
    the call site, and publishing it as THE flags is the mistake that once printed
    ``0x28000000`` for a sample whose real value is ``0x09080008``.
    """
    if not isinstance(document, Mapping):
        return ""
    projection = document.get("creation_flags_callsite")
    if not isinstance(projection, Mapping):
        return ""
    if str(projection.get("recovered_as") or "") != "typed_argument_binding":
        return ""
    return _credible_creation_flags_in_text(
        f"creation_flags={projection.get('value') or ''}"
    )


def _repair_unrecovered_creation_flags(
    text: object,
    recovered: str,
) -> tuple[str, bool]:
    """Replace a stale ``UNKNOWN(creation_flags)`` with the value that IS recovered.

    THE FOURTH PLACE THE SAME FACT IS WRITTEN.  A process-creation claim is text-frozen at
    persist time by ``persist_how._recovered_process_how_fields``, which resolves the flag
    word from the ``process_creation_flags`` candidate list only.  When that list yields
    nothing it writes the literal ``UNKNOWN(creation_flags)`` into the claim's ``mechanism``
    and ``statement``, and those strings are then copied into three rendered places: the
    chapter line, the appendix's ``What:``/``How:`` slots, and ``Unknown:``.

    Later in the same pipeline the deterministic call-site route
    (:func:`_recovered_creation_flags`) resolves the real word from the disassembly - and
    the runtime sequence publishes it - so the finished report simultaneously asserted
    ``creation_flags=0x9080008`` in one section and ``UNKNOWN(creation_flags)`` in three
    others.  A reader believes the denial.

    The claim text is immutable at this point (it is stored evidence), so the repair belongs
    here, where the value is re-derived and every rendered copy passes through.  Only the
    exact placeholder is replaced, and only when a credible value was actually recovered, so
    a genuinely unrecovered slot keeps saying UNKNOWN - which the tests pin in both
    directions.

    Returns the repaired text and whether a replacement happened, so a caller can drop the
    slot from its "unknown" list instead of listing a value it just published.
    """
    raw = str(text or "")
    if not recovered or not raw:
        return raw, False
    repaired = raw
    for placeholder in (
        "UNKNOWN(creation_flags)",
        "`UNKNOWN(creation_flags)`",
        "unknown(creation_flags)",
    ):
        if placeholder in repaired:
            repaired = repaired.replace(placeholder, recovered)
    return repaired, repaired != raw


#: Shared by the renderer and the compose gate so the two cannot drift (G2/G3). The gate uses it to reject a
#: draft that silently drops the pipeline's own limitations.
OPERATIONAL_LIMITATIONS_HEADING = "**运行过程中的限制（与样本行为无关）：**"


def _operational_limitation_lines(document: Mapping[str, object]) -> list[str]:
    """Limitations the PIPELINE reported, rendered independently of mechanism bookkeeping.

    MEASURED (adversarial audit, then a reader-level test, then this gate): `document[
    "analyst_report_limitations"]` was reachable by a reader only through `_verification_note`, which begins

        if total_n <= 0 and not ready:
            return []

    so a run that verified no mechanism - the run whose explanation matters MOST - silently lost the whole
    limitations block. Published bodies carry `CANCELLED`/`TIMED_OUT` in 0 of 551 revisions while the database
    holds 7 timed-out tool runs, 2 cancelled tool runs and 49 cancelled tasks. And `render_stop_kinds` consumes
    its `limitations` argument ONLY through `_tool_authoring_blockers` / `tool_authoring_required_entries`, so
    even on the path that runs, a non-tool-authoring notice was discarded.

    These entries are NOT one of the three stop kinds and NOT mechanism bookkeeping: they say the pipeline
    itself had a problem, which is a different claim from "the sample stopped here". They are therefore printed
    on their own, and a pipeline failure must never be readable as a property of the sample.
    """
    sources = document.get("analyst_report_limitations")
    if not isinstance(sources, (list, tuple)):
        return []
    rendered = set(_tool_authoring_blockers(sources))
    rendered.update(str(item) for item in tool_authoring_required_entries(sources))
    operational: list[str] = []
    for item in sources:
        text = str(item or "").strip()
        if not text or text in rendered or text in operational:
            continue
        operational.append(text)
    if not operational:
        return []
    lines = [OPERATIONAL_LIMITATIONS_HEADING, ""]
    lines.extend(f"- {item}" for item in operational)
    lines.append("")
    return lines


def _verification_note(document: Mapping[str, object], rows: Sequence[Mapping[str, object]]) -> list[str]:
    coverage = document.get("analysis_coverage")
    if not isinstance(coverage, Mapping):
        coverage = {}
    total = coverage.get("mechanism_count")
    verified = coverage.get("verified_mechanism_count")
    try:
        total_n = int(total) if total not in (None, "") else 0
        verified_n = int(verified) if verified not in (None, "") else 0
    except (TypeError, ValueError):
        total_n, verified_n = 0, 0
    registry = BehaviorCatalog()
    ready = [row for row in _mechanism_records(rows) if _mechanism_ready(row)]
    if total_n <= 0 and not ready:
        # The mechanism bookkeeping below is skipped, but the PIPELINE's own limitations must not be: a run
        # that verified no mechanism is exactly the run whose explanation matters most. Returning `[]` here is
        # what hid every operational limitation - see `_operational_limitation_lines`.
        return _operational_limitation_lines(document)
    if total_n <= 0:
        total_n = max(len(_mechanism_records(rows)), len(ready))
        verified_n = len(ready)
    ratio = round(100 * verified_n / total_n) if total_n else 0
    lines = [
        "### 验证门限与候选",
        "",
        f"机制闭合率按验证器门限计算：{total_n} 条机制候选中 {verified_n} 条达到门限"
        f"（约 {ratio}%）。"
        "该闭合率不是风险等级；HIGH 不按模块或机制数量赋值。"
        "门限要求输入、变换、输出、消费者和证据同时可语义计分，并且 verifier 为 VERIFIED。"
        "这不是“样本只有这么多行为”。CreateThread 入口、CryptDecrypt、资源提取链都可以写进报告，"
        "但只要缺密文/消费者/`creation_flags` 就不能计为已验证机制。",
        "",
    ]
    if ready:
        lines.append("**达到门限的机制：**")
        for item in ready[:8]:
            lines.append(f"- {_mechanism_label(item, registry)}")
        lines.append("")
    elif verified_n:
        lines.append(
            "覆盖率计数到了已验证机制，但报告投影里没有带齐 completeness 字段的行；"
            "不要把下面的部分恢复线索升级成已验证。",
        )
        lines.append("")
    else:
        lines.append("当前没有通过验证门限的完整机制。")
        lines.append("")
    gaps = coverage.get("gaps")
    useful: list[str] = []
    if isinstance(gaps, list):
        for item in gaps:
            text = str(item)
            if "DECODE_CONFIG" in text:
                useful.append(
                    "配置/解密验证未闭合：`UNKNOWN(consumer)` 或密文/变换步骤仍缺，"
                    "不能把导入的解密 API 写成已启动的后续阶段。"
                )
            elif "PROCESS_EXECUTION" in text:
                flags = _recovered_creation_flags(rows, document)
                if flags:
                    useful.append(
                        "进程创建验证未闭合：运行时执行未证明，或 Join/回退仍缺；"
                        f"已恢复 `creation_flags` `{flags}`，不能写成 flags 未恢复。"
                    )
                else:
                    useful.append(
                        "进程创建验证未闭合：`UNKNOWN(creation_flags)` 等参数未恢复；"
                        "DLL 上也不应把缺失写成已创建进程。"
                    )
    if useful:
        lines.append("**仍未闭合的验证器：**")
        for item in list(dict.fromkeys(useful)):
            lines.append(f"- {item}")
        lines.append("")
    # Wiring D: name which of the three stop kinds each open slot belongs to, so
    # a slot that is derivable from the image is never presented as though static
    # analysis could not have observed it.
    stop_tokens: list[str] = []
    for row in rows:
        stop_tokens.extend(
            _extra_unknown_tokens(row.get("how"), row.get("unknowns"), row.get("what"))
        )
    # Limitations live in two places on the live path: the model draft's list when
    # a draft exists, and the coverage gaps the pipeline always records.  Reading
    # only the former made this block dead whenever no model draft was produced
    # (model_call_count can legitimately be 0), which silently hid the
    # tool-authoring tickets the investigation loop emits.
    limitation_sources: list[object] = []
    draft_limitations = document.get("analyst_report_limitations")
    if isinstance(draft_limitations, (list, tuple)):
        limitation_sources.extend(draft_limitations)
    coverage_gaps = coverage.get("gaps")
    if isinstance(coverage_gaps, (list, tuple)):
        limitation_sources.extend(coverage_gaps)
    lines.extend(
        render_stop_kinds(stop_tokens, limitation_sources).splitlines()
    )
    # OPERATIONAL limitations get their own block, because the channel above is NOT a general one.
    #
    # `render_stop_kinds` consumes `limitations` ONLY through `_tool_authoring_blockers` and
    # `tool_authoring_required_entries`, so any limitation that is not a tool-authoring blocker or ticket is
    # DISCARDED. The block below is rendered by a helper that does not depend on mechanism counts, so it is
    # also emitted on the path where `ready` is empty (see `_operational_limitation_lines`).
    lines.extend(_operational_limitation_lines(document))
    lines.append("")
    return lines


#: Reader-facing label per IOC category, and the order they appear in the pivot view.
#: File identity first, then network, then host artefacts - the order a responder triages in.
#: The keys are the CATEGORY strings the projection actually writes (`sha256`, not `sha256_file`); an
#: earlier version of this table used `sha256_file`, so the file-hash rows matched no label and the
#: pivot view silently printed no file hash at all. The reader-facing text stays `文件 SHA-256`.
_IOC_LABELS: tuple[tuple[str, str], ...] = (
    ("sha256", "文件 SHA-256"),
    ("sha1", "文件 SHA-1"),
    ("md5", "文件 MD5"),
    ("ipv4", "IPv4"),
    ("url", "URL"),
    ("registry", "注册表键"),
    ("registry_subkey", "注册表路径"),
    ("scheduled_task", "计划任务命令行"),
    ("motw", "MOTW / 附件标记"),
    ("process_name", "进程/镜像名"),
    ("temp_path", "临时路径"),
)

#: Categories whose values are FILE hashes when their provenance says file identity.
_HASH_CATEGORIES = frozenset({"sha256", "sha1", "md5"})

#: Pivots printed per category before the bound is stated.
_IOC_PER_CATEGORY = 12

#: Model-synthesized candidates printed before the section states its bound. The v3 renderer caps its own
#: equivalent section at 8; the official body allows 12 because it prints one extra field (the evidence
#: anchoring) and the reader is expected to triage rather than trust.
_MODEL_CANDIDATE_LIMIT = 12


def _ioc_quick_reference(document: Mapping[str, object]) -> list[str]:
    """Give the reader one labelled, copyable list of the pivots.

    TWO MEASURED GAPS against the benchmark's 关键IOC速查.

    1. The sample's own **MD5 and SHA1 were recorded in the document and rendered nowhere**. Measured on
       task `50673002`: category `md5` 1/1 and `sha1` 1/1 in the document, 0/1 in the body. MD5 is the
       identifier most often requested by an external party, so its absence is not cosmetic.
    2. There was **no labelled pivot view at all** - `IOC` / `速查` / `指标清单` did not appear in the body,
       and the values were scattered through prose, headings and the string-facts list, so a reader had to
       reconstruct the list by hand. The benchmark prints it as a table.

    The file hashes are labelled by PROVENANCE: only rows whose `source` records a file identity get the
    文件 labels; object digests (PE resource payloads, child artifacts) are listed separately as
    `对象摘要` so a reader cannot mistake one for the sample's hash. That is the round-80/82 distinction,
    made visible to the reader rather than only enforced on the rule.

    Bounded per category with the bound stated, and the whole section is omitted when nothing was
    recovered - an empty pivot list would imply the run produced none when it may simply have failed.
    """
    file_hashes: dict[str, list[str]] = {}
    objects: list[str] = []
    others: dict[str, list[str]] = {}
    order: list[str] = []
    seen: set[str] = set()
    for row in iter_document_rows(document):
        if str(row.get("type") or "") != "ioc":
            continue
        category = str(row.get("category") or "").strip()
        value = str(row.get("value") or "").strip()
        if not category or not value:
            continue
        key = value.casefold()
        if key in seen:
            continue
        seen.add(key)
        source = str(row.get("source") or "")
        if category in _HASH_CATEGORIES:
            # Provenance decides, through the SAME predicate the detection-rule projection uses. This
            # section previously carried its own test (`"artifact" in source`), which classified
            # `investigation/decoded_artifact` as a file identity and printed five decoded-payload digests
            # as 文件 SHA-256 on task `b482617e` - the exact mislabelling this section's own preamble warns
            # the reader about. One question, one predicate: two predicates answering it differently is
            # what produced the round-80 regression in the rule.
            if _is_file_hash_source(source):
                file_hashes.setdefault(category, []).append(value)
                continue
            objects.append(value)
            continue
        others.setdefault(category, []).append(value)
        if category not in order:
            order.append(category)
    if not file_hashes and not others and not objects:
        return []

    lines = ["### IOC / 指标速查", ""]
    lines.append(
        "以下为本样本静态恢复的指标，按类型列出，可直接复制用于封锁与检索。"
        "文件哈希来自文件身份记录；**对象摘要**是文件内部对象（PE 资源载荷、子工件）的摘要，"
        "不是文件哈希，不能当作文件指纹使用。"
    )
    lines.append("")
    label_by_category = dict(_IOC_LABELS)
    lines.append("| 类型 | 值 |")
    lines.append("| --- | --- |")
    for category, label in _IOC_LABELS:
        if category not in _HASH_CATEGORIES:
            continue
        for value in (file_hashes.get(category) or [])[:_IOC_PER_CATEGORY]:
            lines.append(f"| {label} | `{value}` |")
    for category in order:
        label = label_by_category.get(category, category)
        values = others.get(category) or []
        for value in values[:_IOC_PER_CATEGORY]:
            lines.append(f"| {label} | `{value}` |")
        if len(values) > _IOC_PER_CATEGORY:
            lines.append(
                f"| {label}（部分） | 共 {len(values)} 条，此处列出前 {_IOC_PER_CATEGORY} 条 |"
            )
    if objects:
        shown = objects[:_IOC_PER_CATEGORY]
        joined = "、".join(f"`{value[:16]}…`" for value in shown)
        suffix = (
            f"（共 {len(objects)} 条，此处列出前 {len(shown)} 条）"
            if len(objects) > len(shown)
            else f"（共 {len(objects)} 条）"
        )
        lines.append(f"| 对象摘要（非文件哈希） | {joined} {suffix} |")
    lines.append("")
    return lines


#: What a runtime symbol looks like. A definition of the artefact, NOT a deny list.
#:
#: MEASURED why a per-value gate check is not enough on its own (T2 audit, two HIGH findings). The page gate
#: is a DOCUMENT-level predicate and cannot be reproduced token by token:
#:   * `_UUID_RE` is searched only in `primary.split("\n## ", 1)[-1]`, so a name containing `\n## ` makes the
#:     split produce a harmless tail, returns no violation, and is published - and once assembled the UUID is
#:     back inside the checked tail and the render RAISES. That is the same `\n## ` dodge the compose-gate
#:     comment already calls out as "the gate was dodgeable by the very text it governs".
#:   * A name containing a newline, or a backtick (which closes the code span it is printed inside), can change
#:     the STRUCTURE of the body. The worst case is not a failed render: a name carrying the appendix heading
#:     makes `split_analyst_markdown` truncate the checked primary there, disarming `primary_analyst_violations`
#:     for everything after it.
#: A real export name is a single run of these characters, so requiring that closes both by construction.
_SYMBOL_RE = re.compile(r"^[A-Za-z0-9_$@!?.:#\-]+$")


#: The PRODUCER's own ledger-placeholder rule, mirrored. `reporting.py` builds `unsupported_apis` with
#: `"FUN_" not in stalled.upper()` (case-INSENSITIVE), while the page gate's `_FUN_NAME_RE` is case-sensitive,
#: so a lowercase `fun_0040d2c0` passed the gate AND passed layer 2 of `_publishable_symbol` - reachable only
#: through a projection built elsewhere, but this filter exists precisely for that scenario (T2 fifth audit,
#: LOW). Anchored, so it cannot repeat the old substring test's mistake of dropping `Fun_Dispatch.dll`.
_LEDGER_PLACEHOLDER_RE = re.compile(r"(?i)\bFUN_[0-9a-f]{4,}\b")


def _publishable_symbol(name: object) -> str:
    """A symbol that is safe to print in the gated primary body, or "" when it is not.

    The name is SIMULATOR-SUPPLIED - Speakeasy's `error.api_name`, i.e. an emulated image's import/module
    name - so it is sample-influenced input reaching a body that is validated AS A WHOLE. Two layers:

      1. it must look like a symbol at all (`_SYMBOL_RE`), which is what stops a name from altering the
         document's STRUCTURE rather than merely its text; and
      2. it must not trip the page's own gate, asked of the value.

    Layer 2 alone is NOT sufficient and the docstring deliberately does not claim the two "cannot drift": the
    gate owns document-level context (the appendix split, a UUID scan restricted to the post-`\n## ` tail) that
    a single token cannot reproduce. That is exactly why layer 1 exists.

    The `FUN_` substring test an earlier version used is GONE: it was broader than the gate's own pattern
    (`FUN_[0-9A-Fa-f]{4,}`) and would have dropped a legitimate image named e.g. `Fun_Dispatch.dll`. The gate
    now decides that question, with its own precise pattern - plus `_LEDGER_PLACEHOLDER_RE` above, which
    mirrors the PRODUCER's case-insensitive rule rather than inventing a third one.
    """
    candidate = str(name or "").strip()
    if not candidate or not _SYMBOL_RE.match(candidate):
        return ""
    if _LEDGER_PLACEHOLDER_RE.search(candidate):
        return ""
    if primary_analyst_violations(candidate):
        return ""
    return candidate


def _observation_count(item: Mapping[str, object]) -> int:
    """How many raw observations this projected result carried, or 0 when it carried none.

    `build_emulation_status_projection` sets this from `len(observations)`. It is the discriminator between
    two facts an empty `observed_apis` cannot tell apart:

      * the run EXECUTED and produced observations, none of which was an API call; and
      * the result carried no observations at all (an older or non-observing projection).

    Only the first supports the statement "no API was observed"; the second supports nothing, so it stays
    silent rather than claiming more than the record holds.
    """
    value = item.get("observation_count")
    return int(value) if isinstance(value, int) and value > 0 else 0


def _emulation_status_section(rows: Sequence[Mapping[str, object]]) -> list[str]:
    """Publish why each isolated simulator did or did not observe anything.

    MEASURED gap this closes: the document already carried an `emulation_status` projection
    (`{"overall": "FAILED", "results": [{"simulator", "status", "stop_reason", "limitations",
    "evidence_id"}, ...]}`) but no chapter rendered it - the published body contained ZERO occurrences
    of the stop reasons. So a reader saw evidence that emulation had happened while being told nothing
    about its outcome, and the single most actionable fact in the run was invisible:

        limitations: ["Speakeasy stopped before observing any API call:
                       unsupported_api api=MSVBVM60.ordinal_100 pc=0xfeedf0f0 instr=disasm_failed"]

    The distinction the chapter must preserve: this is a statement about the SIMULATOR's coverage, not
    about the sample. `NOT_APPLICABLE` means the window was never dispatched (by design), `FAILED` means
    it ran and could not proceed, and neither implies the sample lacks the behaviour.
    """
    results: list[Mapping[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    overall = ""
    for row in rows:
        if str(row.get("type") or "") != "emulation_status":
            continue
        if not overall:
            overall = str(row.get("overall") or "").strip()
        for item in row.get("results") or ():
            if not isinstance(item, Mapping):
                continue
            # The document carries one `emulation_status` row per artifact/module projection, so the
            # same simulator outcome appears several times. Printing it repeatedly tells the reader
            # nothing new and makes the run look busier than it was; dedupe on the outcome identity.
            key = (
                str(item.get("simulator") or ""),
                str(item.get("status") or ""),
                str(item.get("stop_reason") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            results.append(item)
    if not results:
        return []

    lines = ["### 隔离模拟结果（各模拟器实际走到了哪一步）", ""]
    lines.append(
        "本产品不执行样本；下表是隔离 worker 上受控模拟的**覆盖情况**，"
        "说明每个模拟器观察到了什么、或为什么没能观察到，**不构成样本能力结论**。"
        "`NOT_APPLICABLE` 表示该窗口按设计未派发，`FAILED` 表示已运行但无法继续。"
    )
    if overall:
        lines.append("")
        lines.append(f"总体状态：`{overall}`")
    lines.append("")
    for item in results[:12]:
        simulator = str(item.get("simulator") or "?")
        status = str(item.get("status") or "?")
        stop_reason = str(item.get("stop_reason") or "").strip()
        parts = [f"- **{simulator}** 状态 `{status}`"]
        if stop_reason:
            parts.append(f"停止原因 `{stop_reason}`")
        lines.append("　".join(parts) if len(parts) > 1 else parts[0])
        # What the simulator OBSERVED, before why it stopped. MEASURED: a run that observed 256 API calls
        # and made 1,031 modelled VB6 runtime calls rendered as a bare failure, because only
        # status/stop_reason/limitations were published. "FAILED" and "observed 256 calls" are not
        # mutually exclusive, and a reader needs both.
        observed_apis = item.get("observed_apis")
        visible: dict[str, int] = {}
        if isinstance(observed_apis, Mapping):
            # Defence in depth: the projection already drops ledger placeholders, but a chapter that prints
            # API names must never be the place a `FUN_` identifier reaches the primary body.
            visible = {
                str(name): count
                for name, count in observed_apis.items()
                if "FUN_" not in str(name).upper()
            }
        if visible:
            total = sum(int(count) for count in visible.values() if isinstance(count, int))
            rendered = "、".join(
                f"`{name}`×{count}" if isinstance(count, int) and count > 1 else f"`{name}`"
                for name, count in list(visible.items())[:8]
            )
            # A BOUNDED list must say it is bounded. The adapter keeps at most `api_cap` names per run, and
            # MEASURED 102 evidence rows over 34 tasks sit exactly at 256 with none above - so the cap
            # saturates in production and this line published "256" as though it were the sample's total.
            truncation = item.get("api_truncation")
            bound_note = ""
            if isinstance(truncation, Mapping):
                try:
                    dropped = int(truncation.get("dropped") or 0)
                    cap = int(truncation.get("api_cap") or 0)
                except (TypeError, ValueError):
                    dropped, cap = 0, 0
                if dropped > 0:
                    bound_note = (
                        f"，另有 `{dropped}` 个未展开"
                        f"（每次运行最多保留 `{cap}` 个 API 名，**该上限不是本样本的调用总数**）"
                    )
            lines.append(f"  - 已观测 API 调用：{total} 次（{rendered}）{bound_note}")
        elif _observation_count(item) > 0:
            # The run EXECUTED and produced observations, but not one of them was an API call.
            #
            # MEASURED gap this closes (plan T2 / D1): measured on the real Resume run, every Unicorn result
            # carried `attempted_apis=[]` and `unsupported_apis=[]` while reporting `status="SUCCEEDED"`, so
            # the chapter said only
            #     - **unicorn** 状态 `SUCCEEDED`　停止原因 `UNMAPPED_DATA`
            # A reader cannot tell that apart from a run that observed a great deal, and the overall status
            # said `SUCCEEDED` - which is the "absence presented as a clean result" hazard this product exists
            # to avoid. The statement is the honest NEGATIVE, deliberately worded so it does not contain
            # 「已观测 API 调用」: an earlier, weaker version of this chapter rendered nothing at all here,
            # and `test_missing_observation_fields_render_nothing_extra` forbids a false POSITIVE claim, not a
            # true negative one.
            #
            # The discriminator is `observation_count`, not the absence of `observed_apis`: an empty aggregate
            # and a result that carried no observations at all are different facts (`observation_count == 0`,
            # which is left silent here because asserting "no API was observed" would claim more than the
            # record supports).
            lines.append(
                "  - 本次未观测到任何 API 调用"
                "（**这表示本次模拟没能走到 API 边界，不代表样本没有相关行为**）"
            )
        # The dependency that BOUNDED the run, named from the structured record.
        #
        # MEASURED why this line exists (plan T2): the producer records the unmodelled runtime call as a
        # structured observation, and before this the only route to the body was the prose `limitation`
        # ("... before stopping at unsupported_api api=MSVBVM60.ordinal_648 ..."), which a reader had to parse.
        # Naming it is the difference between "emulation observed nothing" and "emulation observed nothing
        # BECAUSE this runtime call is not modelled" - the second is actionable, the first is not.
        stalled_apis = item.get("unsupported_apis")
        if isinstance(stalled_apis, list) and stalled_apis:
            named = [safe for safe in (_publishable_symbol(name) for name in stalled_apis) if safe]
            if not named:
                # The record SAYS the run stopped on an unmodelled runtime call, but no value can be printed.
                # Saying nothing here presents a stalled run as one with no stated dependency - the same
                # absence-as-clean-result hazard T2 exists to remove, relocated from the chapter to the filter.
                #
                # NO COUNT IS STATED, deliberately: this branch cannot know how many calls the run made, and
                # the list may hold several names, so a singular "the call" would be a claim the record does
                # not support (T2 fourth audit, LOW).
                #
                # Reachable inputs here are names that fail `_SYMBOL_RE` (a space, non-ASCII, `/`, `(`, `%`) or
                # names the analyst gate rejects (a UUID, a ledger phrase). NOT a `FUN_` placeholder IN
                # PRODUCTION: the projection drops those, so citing one as this branch's motive was wrong (LOW).
                # That is a statement about the producer, not about this function - `_publishable_symbol` still
                # filters placeholders, and `test_the_blocking_dependency_is_filtered_by_the_pages_own_gate`
                # drives it directly ON PURPOSE, because a projection built elsewhere is the case the filter
                # exists for. Neither file is wrong; the earlier comment just read as if the test were.
                lines.append(
                    "  - 本次模拟停在**未被建模的运行时调用**（该运行确已因此停止，但其名称无法在正文中发布；"
                    "**这不代表样本没有相关行为**）"
                )
            else:
                # PROVENANCE (G2), stated because the ledger got this wrong: this `4` IS a number T2
                # introduced, and the ledger entry claiming T2 "introduced zero numbers" is inaccurate.
                # What makes it defensible is NOT that it is measured - it is not, it is a DISPLAY cap - but
                # that it cannot silently truncate: the total is always stated in the same parenthetical and
                # any remainder is reported as 「另有 N 个未展开」. A bounded list that says it is bounded is
                # this project's rule (EC-4); leaving it unbounded would put an arbitrarily long
                # grader-supplied name list into the published body.
                shown = named[:4]
                rendered_stalled = "、".join(f"`{name}`" for name in shown)
                # A capped list must SAY it is capped, and must state the TOTAL: otherwise a reader cannot
                # tell "the filter dropped these" apart from "there were only these".
                #
                # THE UNIT IS NAMES, and it says so. `unsupported_apis` is deduped by NAME
                # (`reporting.py`: `stalled not in unsupported_apis`), so a run that stops two thousand times
                # on ONE ordinal yields one entry. The sibling API line counts EVENTS with 次, so borrowing
                # that noun would let such a run read as "one call" - and calling these entries "不同的调用"
                # repeated the same conflation one word later (T2 third and fourth audits).
                more = f"，另有 `{len(named) - len(shown)}` 个未展开" if len(named) > len(shown) else ""
                # The count is POST-FILTER, so state the recorded total too when they differ. Otherwise a
                # reader cannot tell "the record holds one name" from "names were dropped" - the same
                # honesty rule the all-filtered branch above exists for, and the raw length is right here
                # (T2 fifth audit, LOW).
                withheld = (
                    f"，记录中共 `{len(stalled_apis)}` 个，其中 `{len(stalled_apis) - len(named)}` 个名称"
                    "未获准在正文中发布"
                    if len(stalled_apis) != len(named)
                    else ""
                )
                lines.append(
                    f"  - 本次模拟停在**未被建模的运行时调用**"
                    f"（按名称去重后 `{len(named)}` 个{withheld}）："
                    f"{rendered_stalled}{more}"
                    "（该依赖不在模拟器的语义范围内，因此这条路径未能产生观测；"
                    "**这不代表样本没有相关行为**）"
                )
        shim = item.get("shim")
        if isinstance(shim, Mapping) and shim:
            modelled = shim.get("modelled_calls")
            strings = shim.get("strings_observed")
            hooks = shim.get("registered")
            # Whether the count sentence below was actually published. The C1 boundary refers to "上文读出的
            # 字符串", so it must not print when there is no count above it. MEASURED reachable state: the shim
            # is installed but `register_vb6_shim` raised, leaving `shim_registered` empty and all three counts
            # zero - the boundary used to render anyway, bounding a number that was never shown.
            count_published = False
            if modelled or strings or hooks:
                count_published = True
                lines.append(
                    "  - VB6 运行时 stub：注册 "
                    f"`{hooks}` 个 hook，建模调用 `{modelled}` 次，"
                    f"从中读出 `{strings}` 个样本字符串（**建模语义，不是真实 MSVBVM60 的返回值**）"
                )
            # The independent second representation: records read through the execution path and decoded.
            #
            # MEASURED honesty requirement: the two paths do NOT produce identical counts. On the 白象
            # sample the execution read yields 868 distinct records / 6,140 chars while the static scan
            # yields 623 / 5,881. They agree on the OPENING text (both start `ace("v ba im fso, fo, `),
            # which is what makes them a cross-check, but claiming full equality would be false. The
            # recovered-body text stays keyed to the static scan; this line reports the second read as
            # corroboration with its own numbers.
            #
            # The raw opening is deliberately NOT pasted: it is the 20-character-record splice, and an
            # earlier revision of this line re-introduced exactly the payload fragment the body had just
            # been cleaned of. The counts plus the agreement statement carry the same information.
            distinct = shim.get("distinct_records")
            decoded_chars = shim.get("decoded_chars")
            if isinstance(distinct, int) and isinstance(decoded_chars, int) and decoded_chars > 0:
                lines.append(
                    f"  - **执行路径独立解出**：{distinct} 条不同记录 → {decoded_chars} 字符；"
                    "与静态扫描同源、开头一致（互为校验），但记录数不同，"
                    "正文的恢复文本以静态扫描为准"
                )
            # C1 - hop 3 of 3: the shim's LIMIT, published beside its numbers.
            #
            # MEASURED why this must be in the body and not only in the evidence: "读出 1,028 个样本字符串"
            # is a true count, and a reader who is not told otherwise will read it as "1,028 strings were
            # copied somewhere". `destination_observable` is false - this harness observes what the sample
            # READS and never where it writes - so the sentence that forbids the stronger reading has to
            # travel with the number that invites it.
            # The condition is `is not True`, not `is False`: an evidence row written before this field
            # existed carries no value at all, and the honest default for "this harness cannot see where
            # the sample writes" is to SAY SO. Only an explicit claim of observability suppresses the
            # boundary, so a missing field can never silently restore the stronger reading.
            #
            # Gated on `count_published` as well: the sentence says "上文读出的字符串", so printing it with no
            # count above it bounds nothing. Honest direction, wrong adjacency - fixed by requiring the number.
            if count_published and shim.get("destination_observable") is not True:
                lines.append(
                    "  - 该 stub 的能力边界：只能观察样本**读取**了哪些字符串，"
                    "**不能**观察这些字符串被写入何处；"
                    "因此上文读出的字符串不得被表述为已复制、已写入或已传递给任何位置"
                )
            # C2 - hop 3 of 3: WHICH source record each string came from. Without the address a reader can
            # only count strings; with it, two runs can be correlated by position.
            #
            # The decoded TEXT is carried in the evidence and deliberately NOT pasted here, for the same
            # measured reason the line above publishes counts only: these strings ARE the sample's decoded
            # payload records, and an earlier revision of this section re-introduced exactly the fragment
            # the body had just been cleaned of.
            pairs = shim.get("argument_pairs")
            if isinstance(pairs, list) and pairs:
                addresses = [
                    str(entry.get("address"))
                    for entry in pairs
                    if isinstance(entry, Mapping) and entry.get("address")
                ]
                if addresses:
                    recorded = shim.get("argument_pairs_recorded")
                    cap = shim.get("argument_pairs_cap")
                    # Defaults, never `None`. MEASURED: with the counters absent this line rendered
                    # 「共记录 `None` 条，上限 `None`」 into the Chinese analyst body - a placeholder published
                    # as if it were a fact, which is worse than declining to state a number at all.
                    recorded_text = f"`{recorded}`" if isinstance(recorded, int) else "未记录"
                    cap_text = f"`{cap}`" if isinstance(cap, int) else "未记录"
                    shown = "、".join(f"`{value}`" for value in addresses[:8])
                    # R5: NAME EACH NUMBER'S SCOPE. The earlier wording 「此处列出 8 条，共记录 `1028` 条，
                    # 上限 `16`」 printed three quantities with no labels, and read as self-contradictory
                    # (1028 recorded but capped at 16?). They measure different things: 8 = addresses printed
                    # here, 16 = address/text pairs the shim publishes at all, 1028 = pairs it recorded.
                    lines.append(
                        f"  - 读取来源记录地址（地址与解码文本成对保存）：此处列出 {len(addresses[:8])} 条；"
                        f"该 stub 共记录 {recorded_text} 对，发布时保留前 {cap_text} 对：{shown}"
                        "；对应的解码文本随证据保存，不在正文展开"
                    )
        limitations = [str(value).strip() for value in (item.get("limitations") or ()) if str(value).strip()]
        for limitation in limitations[:3]:
            lines.append(f"  - {limitation}")
    lines.append("")
    return lines


def _tls_callback_lines(document: Mapping[str, object]) -> list[str]:
    """Name the recovered TLS callback entries and why they matter.

    Measured on task `50673002`: three callbacks (`0x140016920`, `0x140047500`, `0x1400474e0`) were
    recovered, used by the investigation as join seeds, and reached no reader - the section titled
    线程、TLS 回调与 APC printed only the boundary «APC/TLS 若只有导入而无目标线程证据，保持未证明».
    A boundary is not a substitute for the fact it bounds: an address that runs BEFORE the entry point is
    an early-execution location, which is exactly what an analyst checks first.
    """
    entries: list[str] = []
    seen: set[str] = set()
    for row in iter_document_rows(document):
        if str(row.get("type") or "") != "tls_callbacks":
            continue
        values = row.get("entries")
        if not isinstance(values, list):
            continue
        for value in values:
            text = str(value or "").strip()
            if text and text.casefold() not in seen:
                seen.add(text.casefold())
                entries.append(text)
    if not entries:
        return []
    lines = ["### TLS 回调入口（静态恢复）", ""]
    lines.append(
        "TLS 回调在**入口点之前**由加载器调用，因此这里的地址是本样本的早期执行位置；"
        "这是静态恢复的结论，回调是否被执行、做了什么均未观察。"
    )
    for entry in entries:
        lines.append(f"- `{entry}`")
    lines.append("")
    return lines


def _strip_empty_ledger_fields(text: str) -> str:
    """Drop `key=` fragments left behind when a ledger identifier is removed from a `; `-joined record.

    `_official_prose` deletes `FUN_140038910@140038910`, which is right - the primary body must not carry
    a function dump - but in a record like

        memory-and-mapping ; function=FUN_140038910@140038910; parameters=RBX; threshold=static observed

    it leaves `function=; parameters=RBX`, and a reader sees a field asserting nothing. Dropping the empty
    field is cosmetic; leaving it makes the published sequence look truncated, which is the opposite of
    what this section exists to prove. Values are never touched.
    """
    cleaned = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*=\s*(?=;|$)", "", str(text or ""))
    cleaned = re.sub(r";\s*;+", ";", cleaned)
    cleaned = re.sub(r"^\s*;\s*", "", cleaned.strip())
    return re.sub(r"\s{2,}", " ", cleaned).strip(" ;,")


def _model_candidate_section(document: Mapping[str, object]) -> list[str]:
    """Publish the model-synthesized candidate claims the document already carries.

    MEASURED GAP. `reporting._document_to_v3_markdown` emits
    `### Model-Synthesized Candidates` by filtering rows whose `analysis_source` is `model`, but
    `render_official_markdown` - the Chinese analyst body that `_create_report_revision` publishes - has no
    contract for them. On the W4 acceptance run the document carried three such rows (two shaped as
    `modules[].rows[].findings[]` and one as `modules[].rows[]`), each holding the claim's
    `mechanism` / `status` / `confidence` / `evidence_ids` / `model_call_id`, and **none of the four facts
    appeared anywhere in the published body**: 3969 characters published, zero occurrences of the mechanism
    chain, the action, or the candidate status.

    That is the round-77 class again - a complete deterministic projection the published renderer has no
    contract for - and it is the one place where a model's contribution to the analysis is simply invisible
    to the reader. The rows are NOT promoted: every candidate is printed as unverified, with the verifier
    boundary and the responsible model call named, because a candidate that reads like a conclusion is worse
    than no candidate at all.

    Bounded to 12 candidates, and the section states what it left out rather than truncating silently.
    """
    candidates: list[Mapping[str, object]] = []
    seen: set[str] = set()
    for row in iter_document_rows(document):
        if str(row.get("analysis_source") or "").casefold() != "model":
            continue
        mechanism = str(row.get("mechanism") or "").strip()
        text = str(
            row.get("statement")
            or row.get("what")
            or row.get("finding")
            or row.get("action")
            or ""
        ).strip()
        if not mechanism and not text:
            continue
        key = str(row.get("claim_id") or f"{text}|{mechanism}").casefold()
        if key in seen:
            continue
        seen.add(key)
        candidates.append(row)
    if not candidates:
        return []

    total = len(candidates)
    shown = candidates[:_MODEL_CANDIDATE_LIMIT]
    lines = ["### 模型合成候选", ""]
    lines.append(
        f"以下 {len(shown)} 条为模型在本样本证据上合成的候选 Claim（共 {total} 条，按证据锚定去重）。"
        "它们**尚未通过验证器**，状态一律为 `CANDIDATE`，"
        "只能当作待核查线索；不作为结论，也不进入机制闭合率。"
    )
    lines.append("")
    for index, row in enumerate(shown, start=1):
        status = str(row.get("status") or "CANDIDATE").strip() or "CANDIDATE"
        confidence = str(row.get("confidence") or "UNKNOWN").strip() or "UNKNOWN"
        text = _official_prose(
            str(row.get("statement") or row.get("what") or row.get("finding") or "").strip()
        )
        lines.append(f"- **候选 {index}**（`{status}` / 置信度 `{confidence}`）")
        if text:
            lines.append(f"  - 主张：{text[:600]}")
        action = str(row.get("action") or "").strip()
        obj = str(row.get("object") or "").strip()
        subject = str(row.get("subject") or "").strip()
        if subject or action or obj:
            lines.append(
                f"  - 主体/动作/对象：`{subject or 'UNKNOWN'}` / `{action or 'UNKNOWN'}`"
                f" / `{obj or 'UNKNOWN'}`"
            )
        mechanism = str(row.get("mechanism") or "").strip()
        if mechanism:
            # The chain is the model's own text and is quoted, not rewritten: the field vocabulary is
            # English by construction (Input -> Transformation/Control -> ... -> Side Effect), and an
            # analyst checking the claim needs the exact chain the model asserted.
            lines.append(f"  - 机制链：{mechanism[:600]}")
        condition = str(row.get("condition") or "").strip()
        if condition:
            lines.append(f"  - 前提条件：{condition[:300]}")
        evidence_ids = [
            str(anchor).strip()
            for anchor in (row.get("evidence_ids") or [])
            if str(anchor).strip()
        ]
        # The anchors are Evidence UUIDs, and this body deliberately strips ledger UUIDs from the primary
        # section, so printing them yields "证据锚点：," - a field that reads as present but shows nothing.
        # The analyst-actionable fact is how strongly the candidate is anchored, so that is what is stated;
        # the identifiers themselves belong to Evidence Explorer.
        if evidence_ids:
            lines.append(
                f"  - 证据锚定：{len(evidence_ids)} 条已登记证据"
                "（标识符在 Evidence Explorer；本节不重复账本 UUID）"
            )
        else:
            lines.append("  - 证据锚定：0 条（该候选未绑定证据，仅作线索，不得作为结论）")
        lines.append("  - 验证边界：未过验证器；仅静态观察，未观测运行时执行")
    if total > len(shown):
        lines.append("")
        lines.append(
            f"另有 {total - len(shown)} 条模型候选未在此列出（本页每节有界），"
            "完整清单在 Evidence Explorer。"
        )
    lines.append("")
    return lines


_PAYLOAD_FIELD_RE = re.compile(
    r"\b(parameters|output|plaintext|decoded_text|decoded_preview|recovered_text)\s*=\s*",
    re.IGNORECASE,
)

#: Values longer than this after a payload field name are treated as pasted payload rather than a ledger
#: value. MEASURED bound: `parameters=RBX` (3 chars) is a real field asserted by
#: `tests/test_runtime_sequence_in_body.py`, while the 白象 paste is ~5,700 characters.
_PAYLOAD_STRIP_MIN_CHARS = 200


def _strip_payload_but_keep_structure(how: str) -> str:
    """Drop an embedded recovered-payload slice from a sequence value, keep the structural prefix.

    MEASURED target: one runtime-sequence line was 5,882 characters because a phase `how` carried
    `<module> <sha256>; parameters=` followed by a ~400-character slice of the decoded script and then
    more ledger prose. Almost all of that length is payload, not a statement about input/transform/output.

    Two earlier attempts at this are recorded in the ledger and both were bad:
      * a whole-body regex deleted 11,398 characters and every recovered-fact token;
      * a guard that REPLACED the entire `how` deleted 5,825 characters and the same tokens.
    The difference here is that only the payload VALUE is removed. The prefix before `field=` is retained
    because it names the module and the artifact digest - that IS the structural fact. A value whose
    prefix is too thin to be a statement is replaced, because then the line is payload and nothing else.
    """
    value = str(how or "")
    match = _PAYLOAD_FIELD_RE.search(value)
    if match is None:
        if _is_raw_decoded_fragment(value):
            return "UNKNOWN(该阶段的输入/变换/输出未成文；已恢复载荷见「编码、解密与配置还原」一节)"
        return value
    payload = value[match.end() :]
    # Size decides, not the field NAME. `test_runtime_sequence_in_body` pins the contract:
    # `parameters=RBX` is a real ledger field and must survive, while a 400-character script slice is
    # payload. A name-based rule deleted the former; a length threshold keeps both correct.
    if len(payload) <= _PAYLOAD_STRIP_MIN_CHARS:
        return value
    prefix = value[: match.start()].strip(" ;,")
    if len(prefix) < 40:
        # Nothing survived in front of the payload, so there is no structural fact to keep.
        return "UNKNOWN(该阶段的输入/变换/输出未成文；已恢复载荷见「编码、解密与配置还原」一节)"
    return (
        f"{prefix}（`{match.group(1)}` 的已恢复载荷片段（{len(payload)} 字符）已省略，"
        "见「编码、解密与配置还原」一节）"
    )


def _runtime_sequence_section(document: Mapping[str, object]) -> list[str]:
    """Publish the statically reconstructed runtime order.

    MEASURED GAP against the named depth benchmark (`D:\\test\\20260730_Resume_恶意样本分析报告.md`), whose
    heaviest section is 二、还原完整程序运行时序链路. The published body had no equivalent section while the
    document carried a complete one - 16 `runtime_phase` rows on task `50673002`, each with
    `{id, title, status, how, catalog_ids, runtime_observed}`, forming Phase 1 startup / loader ->
    Phase 2 environment / anti-analysis -> Phase 3 decode / config -> Phase 4 download / transport ->
    Phase 5 process creation / PPID -> Phase 6 failure fallback -> Phase 7 unique OS thread / callback ->
    Phase 8 loop / repeat.

    Cause: two renderers exist and publishing uses the one without this section.
    `reporting._document_to_v3_markdown -> _append_v3_gold_flow` emits
    `### Runtime sequence (static reconstruction)`, but `render_official_markdown` - the Chinese analyst
    body that `_create_report_revision` actually publishes - calls only `render_analyst_chapters`. Same
    shape as the round-77 import-module loss: a complete deterministic projection the published renderer
    has no contract for.

    Two projection details the real document forces:

    * the phases appear INSIDE `assessment.findings[*].runtime_sequence`, not in a top-level
      `runtime_sequence` row, so the walk has to find them where they are;
    * they appear TWICE (the document carries two sequence copies), so phases are de-duplicated by `id`
      in first-seen order - the order IS the finding, so it must not be sorted.

    The status and the `runtime_observed` flag are rendered per phase because a phase is a static
    reconstruction: an ordered chain with no boundary reads as observed execution, which is EC-6.
    """
    phases: list[Mapping[str, object]] = []
    seen: set[str] = set()
    for row in iter_document_rows(document):
        sequence = row.get("runtime_sequence")
        if not isinstance(sequence, list):
            continue
        for phase in sequence:
            if not isinstance(phase, Mapping):
                continue
            if str(phase.get("type") or "") != "runtime_phase":
                continue
            key = str(phase.get("id") or phase.get("title") or "")
            if not key or key in seen:
                continue
            seen.add(key)
            phases.append(phase)
    # A sequence with nothing recovered carries no information, and printing an empty ordered chain
    # would imply one exists.
    if not any(str(phase.get("how") or "").strip() for phase in phases):
        return []
    lines = [
        "### 运行时序（静态重建）",
        "",
        "以下顺序由静态恢复的机制与调用序列重建，**不是运行时观察**："
        "本产品未执行样本，各阶段的到达与执行顺序未验证。"
        "状态 `SUPPORTED` 表示静态证据支持该阶段存在，`CANDIDATE` 表示尚未过验证器，"
        "`UNKNOWN` 表示本次未能恢复。",
        "",
    ]
    for phase in phases:
        title = str(phase.get("title") or phase.get("id") or "UNKNOWN(phase)").strip()
        status = str(phase.get("status") or "UNKNOWN").strip()
        catalog = [str(item) for item in (phase.get("catalog_ids") or []) if str(item).strip()]
        # The phase `how` text is a ledger string: it names the recovered function as
        # `FUN_140038910@140038910`, and the primary body forbids `FUN_` identifiers
        # (`primary_analyst_violations`) because a function dump is not an analyst conclusion. The
        # existing `_official_prose` helper strips exactly that, and it is applied here rather than
        # loosening the gate: the gate is right, the text needs the same treatment every other
        # projection gets.
        how = _strip_empty_ledger_fields(_official_prose(str(phase.get("how") or ""))) or ""
        # STEP 2 - now safe. The decode chapter publishes the identifiers that this payload slice used to
        # be the SOLE carrier of (`.scratch/probe-fact-carriers.py` measured `WScript`/`Svr`/`ADODB`/
        # `XMLHTTP`/`WinHttp` appearing only on this line). With that chapter carrying them, the paste can
        # be replaced by a pointer: the structural prefix (module + artifact digest) is kept, only the
        # payload value is dropped.
        how = _strip_payload_but_keep_structure(how)
        # Stripping the function names can empty a phase that was nothing but a name; say so instead of
        # printing a blank bullet.
        if not how.strip():
            how = "UNKNOWN(how — 该阶段的静态描述只包含函数转储，已从本页移除，见 Evidence Explorer)"
        lines.append(f"- **{title}** 状态 `{status}`")
        lines.append(f"  - 输入/变换/输出：{how}")
        if catalog:
            lines.append(f"  - 行为目录：{', '.join(f'`{item}`' for item in catalog)}")
        if not phase.get("runtime_observed"):
            lines.append("  - 运行时是否观察到：**否**（静态重建）")
    lines.append("")
    return lines


def render_analyst_chapters(
    document: Mapping[str, object],
    *,
    topics: Sequence[AnalystTopic] | None = None,
) -> str:
    rows = iter_document_rows(document)
    planned = tuple(topics) if topics is not None else plan_analyst_topics(document)
    lines = [
        ANALYST_CONCLUSION_HEADING,
        "",
        "本章按本样本实际触发的行为目录、PMA 静态规则和已引用证据选题。"
        "未出现的能力表示本次未触发，不代表已经排除。"
        "导入存在不等于运行时已发生。调查账本（Seed Map、覆盖率字典、函数转储）在 Evidence Explorer，不在本页。",
        "",
    ]
    lines.extend(_synthesis(document, rows, planned))
    # String facts and detection artefacts come before the per-topic chapters:
    # they are the two things an analyst acts on first, and both were previously
    # in the document but unreachable from the published body.
    lines.extend(_string_facts_section(document))
    lines.extend(_detection_rule_section(rows))
    lines.extend(_pe_overview(document, rows))
    # The ordered reconstruction goes before the per-topic chapters: it is the frame the individual
    # mechanisms sit in, and the named depth benchmark weighs it most heavily.
    lines.extend(_runtime_sequence_section(document))
    lines.extend(_ioc_quick_reference(document))
    lines.extend(_tls_callback_lines(document))
    # Model-synthesized candidates are the only claims in the document whose author is the model rather
    # than a deterministic projection, so they are printed before the per-topic chapters: a reader who
    # never reaches the appendix must still see that the model contributed claims and that none are
    # verified.
    lines.extend(_model_candidate_section(document))
    # Simulation coverage goes after the model candidates and before the per-topic chapters: it is a
    # statement about which observation paths were even available, so it frames how much weight the
    # per-topic UNKNOWN verdicts can carry.
    lines.extend(_emulation_status_section(rows))
    if not planned:
        lines.extend(["本次没有形成可选题的行为证据。完整调查账本在 Evidence Explorer。", ""])
    else:
        for topic in planned:
            lines.extend(_topic_body(topic, rows, document))
    # G4 §8.2-5: the ten-question slots and the mechanism-ready count are
    # investigation bookkeeping. They belong to the appendix; the main body must
    # not carry Seed Map, closure percentage, or FUN_ dumps as conclusions.
    lines.extend(["", ANALYST_APPENDIX_HEADING, ""])
    lines.extend(_ten_question_section(rows, planned, document))
    lines.extend(_verification_note(document, rows))
    # Bounded to ONE token per occurrence and gated on the payload's own signature, so a line without
    # payload is returned byte-identical. Verified on the real lines: the repair clears the fragment while
    # keeping the sibling `UNKNOWN(loop: ...)` / `UNKNOWN(fallback)` tokens intact
    # (`.scratch/probe-single-token-repair.py`, 10/10).
    return _repair_truncated_unknown_tokens("\n".join(lines)).rstrip() + "\n"


def _official_sample_name(
    document: Mapping[str, object],
    rows: Sequence[Mapping[str, object]],
) -> str:
    for row in rows:
        if str(row.get("type") or "") in {"pe", "pe_basics"}:
            path = str(row.get("path") or row.get("filename") or row.get("display_name") or "").strip()
            if path and not path.casefold().startswith("unknown"):
                return path.split(":", 1)[0]
    for row in rows:
        target = str(row.get("target") or "").strip()
        if not target or target.casefold().startswith("unknown"):
            continue
        name = target.split(":", 1)[0].strip()
        if "." in name and "\\" not in name[:2]:
            return name
        if name.lower().endswith((".exe", ".dll", ".vir", ".sys")):
            return name
    return str(document.get("sample_name") or document.get("display_name") or "").strip()


def stamp_official_report_chrome(document: Mapping[str, object]) -> dict[str, object]:
    """Project sample identity and verifier count onto the official document.

    Report chrome reads these top-level fields. Nested coverage / pe.path
    otherwise become 未知样本 and Verified Mechanisms 0.
    """

    stamped = dict(document)
    rows = iter_document_rows(stamped)
    name = _official_sample_name(stamped, rows)
    if name:
        stamped["sample_name"] = name
        stamped["display_name"] = name
    coverage = stamped.get("analysis_coverage")
    if not isinstance(coverage, Mapping):
        coverage = {}
    ready = [row for row in _mechanism_records(rows) if _mechanism_ready(row)]
    verified = len(ready)
    if verified <= 0:
        try:
            verified = int(coverage.get("verified_mechanism_count") or 0)
        except (TypeError, ValueError):
            verified = 0
    stamped["verified_mechanism_count"] = verified
    return stamped


#: Analyst-facing wording for each banned ledger phrase.
#:
#: TRANSLATED, not deleted. Deleting `downstream consumer` from "the downstream consumer is unknown" leaves
#: "the  is unknown" - a broken sentence in a report a human reads. The replacement is the wording the rest of
#: the Chinese body already uses for the same idea, so the sentence keeps its meaning and stops being jargon.
#:
#: MEASURED, the failure this exists for (task `420c4694`, the FIRST run after the model route was corrected to
#: `deepseek-flash`):
#:     REPORT_SYNTHESIS_FAILURE: analyst report still contains ledger residue:
#:     primary report contains ledger jargon: downstream consumer
#: The gate REJECTS THE WHOLE REPORT, so one phrase cost the analyst everything. This is the same class as the
#: `FUN_` residue handled by `_scrub_fun_names_from_primary`, and it is fixed the same way for the same reason.
_PRIMARY_JARGON_REPLACEMENTS: Mapping[str, str] = {
    "downstream consumer": "下游消费者",
    "downstream_static": "下游静态消费",
    "field completeness": "字段完整度",
    "behavior-finding:candidate-mechanism": "候选机制",
    "pipeline completion": "管道完成度",
    "semantic analysis coverage": "语义分析覆盖度",
    # No entry for `unknown(parameter)`: it was removed from `_PRIMARY_JARGON` because it is a token the
    # product itself emits, not ledger jargon. A mapping here would have "translated" the product's own
    # `UNKNOWN(parameter)` into itself (casefold-equal), i.e. a provable no-op - and the gate would still
    # have rejected the report.
    "investigation seed map": "调查种子图",
    "executive assessment": "总体评估",
    "选题依据": "选题说明",
}


def _scrub_primary_jargon(markdown: str) -> str:
    """Replace banned ledger phrases in the PRIMARY section with analyst-facing wording.

    Primary section only: the appendix is the ledger and is allowed to say these things.

    Case-insensitive because the gate is (`marker in primary.casefold()`), so a scrub that only matched the
    lower-case spelling would leave `Downstream Consumer` to trip the gate it was written to satisfy.
    """
    primary, appendix = split_analyst_markdown(markdown)
    folded = primary.casefold()
    if not any(marker in folded for marker in _PRIMARY_JARGON_REPLACEMENTS):
        return markdown
    for marker, replacement in _PRIMARY_JARGON_REPLACEMENTS.items():
        # Manual case-insensitive replace: `re.sub` with the marker escaped would also work, but the markers
        # contain regex metacharacters (`:`, `(`, `)`) and one is CJK, so an escaped literal scan is simpler
        # to reason about than a pattern.
        start = 0
        while True:
            index = primary.casefold().find(marker, start)
            if index < 0:
                break
            primary = primary[:index] + replacement + primary[index + len(marker) :]
            start = index + len(replacement)
    body = primary.rstrip()
    if not appendix:
        return body
    return (body + "\n\n" if body else "") + appendix


def _scrub_fun_names_from_primary(markdown: str) -> str:
    """Remove residual `FUN_<hex>` ledger labels from the PRIMARY section only.

    Why a backstop exists at all: the gate below REJECTS THE WHOLE REPORT, so one residual token costs the
    analyst everything. MEASURED on task `83f16229` (白象 `64da3378`):

        failure_code           REPORT_SYNTHESIS_FAILURE
        message                primary report contains FUN_ ledger names
        failure_fingerprint    79b9ccdf... == previous_failure_fingerprint  -> retry suppressed
        published revision     none

    while the SAME sample and the SAME code published cleanly on task `72690275`
    (`primary_analyst_violations == []`, zero `FUN_` hits). So this is a run-varying leak, not a deterministic
    one, and the evidence holds the names legitimately - `api_argument_trace` had 110 rows carrying `FUN_`
    on the failing run - so some projection forwards one into the body on some runs.

    The removal is deliberately TOKEN-PRECISE (`_FUN_NAME_RE` matches the label itself, never a span). An
    earlier attempt at a body-wide repair used a greedy pattern that consumed everything from `UNKNOWN(` to
    the next backtick or newline: it destroyed 11,398 characters and took every recovered-fact token
    (`WScript`, `Svr`, `XMLHTTP`, `ADODB`) to zero occurrences. That is why this one deletes ~10 characters
    per hit and touches nothing else.

    A `FUN_` label is a decompiler's placeholder for an unnamed function, i.e. ledger vocabulary that this
    project's own convention keeps out of the analyst-facing body; dropping the label loses no analysis
    content, and the address remains available in the appendix.
    """
    primary, appendix = split_analyst_markdown(markdown)
    if "FUN_" not in primary:
        return markdown
    scrubbed = _FUN_NAME_RE.sub("", primary)
    # Collapse the gap a removed label leaves behind, without touching other whitespace runs' meaning.
    scrubbed = re.sub(r"[ \t]{2,}", " ", scrubbed)
    scrubbed = re.sub(r"([（(])\s+", r"\1", scrubbed)
    scrubbed = re.sub(r"\s+([）)，。、；：])", r"\1", scrubbed)
    # A label sitting between CJK characters leaves "调用 后"; close that gap too - but ONLY across
    # horizontal whitespace. Using `\s+` here swallowed the `\n\n` between a heading and its first
    # paragraph and produced "## 分析结论调用后进入载荷。" (measured on a fixture before this fix).
    scrubbed = re.sub(r"([\u4e00-\u9fff])[ \t]+([\u4e00-\u9fff])", r"\1\2", scrubbed)
    body = scrubbed.rstrip()
    if not appendix:
        return body
    # Preserve the blank line before the appendix heading: joining with a single "\n" changed the section
    # separation (measured on the fixture above, where the original had "\n\n").
    return (body + "\n\n" if body else "") + appendix


def render_official_markdown(document: Mapping[str, object]) -> str:
    """Analyst-facing GET markdown. Never includes the V3 ledger."""

    revision = _authoritative_revision_id(document)
    meta = [
        "# 静态分析报告",
        "",
        f"- 案件：`{document.get('case_id', 'unknown')}`",
        f"- 任务：`{document.get('task_id', 'unknown')}`",
        f"- 任务结果：**{document.get('analysis_outcome') or 'UNKNOWN'}**",
        f"- 分析类别：**{document.get('analysis_class') or 'UNKNOWN'}**",
        "- 样本执行：**否**",
        "- 完整沙箱动态分析：**否**",
    ]
    if revision:
        meta.append(f"- 报告修订：`{revision}`")
    lines = [
        *meta,
        "",
        "> Static analysis includes Ghidra/static recovery and isolated Unicorn/"
        "Speakeasy/Qiling. This is not sandbox/dynamic analysis (full sample execution).",
        "> 静态分析包含反汇编/数据流恢复，以及隔离 worker 上的 Unicorn/Speakeasy/Qiling；"
        "完整沙箱跑样本才是动态分析，本产品不做该项。",
        "",
        render_analyst_chapters(document).rstrip(),
        "",
    ]
    rendered = _scrub_unattributed_actors("\n".join(lines).rstrip() + "\n", document)
    rendered = _scrub_ledger_uuids_from_primary(rendered)
    rendered = _scrub_fun_names_from_primary(rendered)
    rendered = _scrub_primary_jargon(rendered)
    # Model prose is untrusted input and ONE unqualified runtime verb must not abort an otherwise valid static
    # report.
    #
    # MEASURED (round 83, 白象 task `8e75f6dc`): the run ended `FAILED_ANALYSIS` /
    # `REPORT_SYNTHESIS_FAILURE` with `report_available: false`, discarding 5,988 evidence rows and 12 claims,
    # because the model wrote `connected` once. The English path had repaired this wording all along
    # (`reporting._static_safe_text`, whose docstring states the requirement verbatim); the PUBLISHED path
    # only raised. The repair table now lives in `product_certification` and both paths share it, so the two
    # cannot drift again.
    #
    # The gate below still runs, and still raises on a residue: the table is deliberately small, so a leftover
    # violation means the wording is genuinely unpublishable rather than merely unqualified.
    rendered = repair_static_runtime_wording(rendered)
    violations = static_wording_violations(rendered)
    if violations:
        raise ValueError("static-only wording gate rejected report: " + ", ".join(violations))
    extra = primary_analyst_violations(rendered)
    if extra:
        raise ValueError("analyst report still contains ledger residue: " + ", ".join(extra))
    return rendered


# --- 报告合成门 (ADR-0036 / G4 §8.3) ---------------------------------------

# 未命中类目的说明。禁止发挥，但**必须点名具体卡点**：旧的固定模板（「静态导入/字符串/调用序列与
# 受控模拟均未提供对象级使用链」+「不是「样本没有恶意能力」的证明」）被 acceptance 脚本按套话统计，
# 而本项目要求「查不到写 UNKNOWN(槽位)+具体卡点」。这两句话回答不了分析师的任何问题：它们没有说
# 找过什么、也没有说缺哪个槽位。
#
# 因此每个类目给出三件事：读过的证据类别（looked_for）、缺失的槽位（blocked_slot）、以及该类目
# 自身的对象（subject）。缺失槽位以 `UNKNOWN(槽位)` 写出，与其它章节的写法一致。
_UNMATCHED_CATEGORY_BLOCKERS: Mapping[str, tuple[str, str, str]] = {
    # catalog_id: (blocked_slot, looked_for, subject)
    "process-injection": (
        "target_process + written_buffer",
        "跨进程写入类 API 的导入与调用点、被写入缓冲区的地址、目标进程句柄来源",
        "注入原语到目标进程的使用链",
    ),
    "persistence": (
        "registry_value_name + run_key_path",
        "注册表/计划任务/启动目录相关的导入、调用点与其参数位、Run 键路径字符串",
        "写入点到自启动位置的绑定",
    ),
    "thread-and-callback": (
        "start_routine + entry_body",
        "CreateThread/APC/TLS 回调的导入与调用点、入口地址、入口体反汇编片段",
        "线程入口到执行体的使用链",
    ),
    "config-and-crypto": (
        "cipher_blob + key + transformation_steps",
        "加解密 API 导入与调用点、密文数据引用、密钥与常量、变换步骤",
        "密文到明文的完整变换链",
    ),
    "network-transport": (
        "endpoint + request_parameters",
        "WinHTTP/WinINet 导入与调用点、URL 字符串、请求参数位",
        "端点到请求参数的绑定",
    ),
    "parent-process-spoofing": (
        "parent_identity + attribute_list",
        "进程创建与属性列表 API 的调用点、父进程属性值与进程名",
        "父进程身份到创建调用的绑定",
    ),
    "registry-operations": (
        "registry_call_site + key_name + value_name",
        "注册表 API 的调用点、lpSubKey/lpValueName 参数位、键名与值名字符串",
        "调用点到键名/值名的绑定",
    ),
    # Attribution is not a code capability, so its blockers are the evidence types that could establish it.
    # The template's generic tail ("不代表样本不具备该能力") is still true here in the useful sense: an
    # unestablished attribution does not mean the sample is unattributed, only that THIS run has no
    # validated fact match.
    "attribution": (
        "actor_identity + validated_fact_match",
        "家族/组织特征字符串、编译指纹、互斥体与目录命名、C2 命名规律，并与已验证的家族事实库比对",
        "样本事实到某个已命名攻击者的可验证绑定",
    ),
    "anti-analysis": (
        "check_api + expected_result",
        "反调试/反虚拟机 API 的调用点、比较常量、分支结果",
        "检测项到其判定结果的绑定",
    ),
    "loader-and-api-resolution": (
        "resolved_api + callsite + consumer",
        "LoadLibrary/GetProcAddress 调用点、解析出的 API 名、解析结果的消费者",
        "动态解析结果到调用者的绑定",
    ),
    "memory-and-mapping": (
        "mapped_region + protection + consumer",
        "内存分配/映射 API 调用点、区域地址与保护常量、区域内容的消费者",
        "映射区域到执行或读取者的绑定",
    ),
}

_UNMATCHED_FALLBACK_SUBJECT = "该类目的对象级使用链"
# The fallback slot is `object_level_chain`, NOT `consumer`: a topic whose catalog id is not in the
# table has no identified slot, and borrowing the `consumer` slot name would collide with the crypto
# chapter's own `UNKNOWN(consumer)` wording - three acceptance tests assert that marker is absent
# when the consumer IS recovered. A fallback must not invent a slot name that means something
# specific elsewhere.
_UNMATCHED_FALLBACK_SLOT = "object_level_chain"


#: The closing sentence, per category. The capability sentence ("this does not mean the sample lacks the
#: ability") is correct for a code capability and wrong for attribution: an unestablished attribution does
#: not mean the sample has no author, it means this run has no validated binding. Using the capability
#: sentence there would answer a different question than the one the chapter asks.
_UNMATCHED_CATEGORY_BOUNDARY_BY_CATEGORY: Mapping[str, str] = {
    "attribution": (
        "这表示本次没有建立起可验证的归因绑定，不代表该样本没有归属；"
        "归因需要外部已验证的家族事实或情报，不在静态证据可自证范围内。"
    ),
}
_UNMATCHED_CATEGORY_BOUNDARY_DEFAULT = "这表示本次静态证据里没有形成该使用链，不代表样本不具备该能力。"


def _observed_signals_for_topic(
    topic: AnalystTopic,
    rows: Sequence[Mapping[str, object]],
) -> list[str]:
    """Name what WAS observed for a topic that nonetheless formed no usage chain.

    MEASURED problem this fixes: an unmatched chapter printed only what was missing —

        未命中：网络通信。本次检索了…未组成端点到请求参数的绑定，因此 `UNKNOWN(endpoint + request_parameters)` 保持未恢复。

    On the 白象 run the same body carried `XMLHTTP`×2 and `ADODB`×2, so a reader who saw only the
    chapter concluded there were no leads at all. Listing the missing slot is correct; listing it
    ALONE misleads about the evidence that was actually recovered.

    Deliberately names the EVIDENCE KINDS that carry a matching signal, not the matched strings.
    A first attempt published matched tokens and produced spliced fragments such as
    `o.WinHttpReoft.XMLHTTg` — the decoded script is truncated into 20-character records, so its text
    is full of words broken across records. Publishing those as "线索" would dress a truncation
    artifact up as a finding, which is exactly the failure this report exists to avoid.

    Only vocabulary already present in ``_UNMATCHED_CATEGORY_BLOCKERS`` is used, so this cannot
    introduce a term the report did not already define.

    Scoped to ``_matched_rows`` ONLY. An earlier revision fell back to the whole document when the
    topic matched nothing, which reported evidence belonging to other topics as though it were this
    one's - a wrong join (EC-3), the very defect class this work exists to remove. When a topic has no
    rows, the honest answer is "no evidence observed for this topic", not "here is some evidence".
    """
    blocker = _UNMATCHED_CATEGORY_BLOCKERS.get(topic.catalog_id)
    matched_rows = _matched_rows(topic, rows)
    vocabulary = blocker[1] if blocker else ""
    needles = [
        token.casefold()
        for token in re.split(r"[^0-9A-Za-z_.]+", vocabulary)
        if len(token) >= 3 and not token.isdigit()
    ]
    if not needles:
        return []
    kinds: list[str] = []
    for row in matched_rows:
        text = _blob([row])
        if not text:
            continue
        folded = text.casefold()
        if not any(needle in folded for needle in needles):
            continue
        kind = str(row.get("type") or row.get("kind") or "").strip()
        if not kind or kind in kinds:
            continue
        kinds.append(kind)
        if len(kinds) >= 3:
            break
    return kinds


def unmatched_category_statement(
    topic: AnalystTopic,
    observed: Sequence[str] | None = None,
) -> str:
    """The 已核对 sentence for a category with no anchors and no finding.

    Names the specific slot that is missing and what was read to look for it, then states the
    boundary. Kept deliberately short and free of free-form narrative: this sentence replaced a
    fixed template precisely because the template answered neither question.

    ``observed`` names the signals that WERE recovered but did not combine into the required chain.
    Stating only the missing slot makes a partially-recovered topic read as a blank one.
    """
    blocker = _UNMATCHED_CATEGORY_BLOCKERS.get(topic.catalog_id)
    if blocker is None:
        slot, looked_for, subject = (
            _UNMATCHED_FALLBACK_SLOT,
            "该类目的导入、字符串、调用序列与受控模拟",
            _UNMATCHED_FALLBACK_SUBJECT,
        )
    else:
        slot, looked_for, subject = blocker
    title = topic.title
    boundary = _UNMATCHED_CATEGORY_BOUNDARY_BY_CATEGORY.get(
        topic.catalog_id, _UNMATCHED_CATEGORY_BOUNDARY_DEFAULT
    )
    seen = [str(item).strip() for item in (observed or ()) if str(item).strip()][:3]
    if seen:
        # The observation may be the topic's own recorded BLOCKER (specific) or an evidence-kind list
        # (general). "卡点" is accurate for both and does not claim more than was recorded.
        found_clause = "本类目登记的卡点：" + "；".join(f"{item}" for item in seen) + "。"
    else:
        found_clause = "本次未见该类目的线索；"
    return (
        f"未命中：{title}。{found_clause}本次检索了{looked_for}，未组成{subject}，"
        f"因此 `UNKNOWN({slot})` 保持未恢复。"
        f"{boundary}"
    )


# Retained for callers that only need the boundary sentence; the full statement above is what the
# body publishes.
UNMATCHED_CATEGORY_BOUNDARY = _UNMATCHED_CATEGORY_BOUNDARY_DEFAULT

_COMPOSE_URL_RE = re.compile(r"https?://[^\s`)\]}\"'，。；、]+", re.IGNORECASE)
_COMPOSE_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
# Carrier / process / document file names. A polished paragraph must not invent
# a process name or leak another sample's IOC. Deliberately generic: the check is
# "this token is absent from the composed fragments", so no sample name is
# hardcoded here.
_COMPOSE_IMAGE_RE = re.compile(
    r"\b[A-Za-z0-9_.-]+\.(?:exe|dll|sys|bat|ps1|scr|pdf|docx?|xlsx?|jar|vbs|lnk|zip|rar|7z)\b",
    re.IGNORECASE,
)
_COMPOSE_UPGRADE_MARKERS = (
    "已验证",
    "已执行",
    "活 c2",
    "已坐实",
    "确认外联",
    "成功连接",
    "verified",
    "executed successfully",
    "confirmed active",
)

# Phrases that assert a fact is ABSENT from the sample.  A draft may say this when
# the deterministic fragments really do not contain it; saying it when they DO is a
# false negative claim, which is the most damaging error an analyst report can make
# because a reader stops looking.
_COMPOSE_ABSENCE_MARKERS = (
    "未出现",
    "未发现",
    "未见",
    "未观察到",
    "不存在",
    "不提供",
    "没有出现",
    "没有发现",
    "未提取到",
    "not present",
    "no evidence of",
    "not observed",
    "absent",
)

# The fact classes whose absence may be claimed, mapped to the pattern that counts
# occurrences in the fragments.  Deliberately narrow: only classes the deterministic
# pipeline actually projects and whose presence is unambiguous.
_COMPOSE_ABSENCE_CLASSES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("endpoint URL", _COMPOSE_URL_RE),
    ("endpoint IPv4", _COMPOSE_IPV4_RE),
)

# Class NAMES a denial can use without repeating a literal value - which is exactly
# what the delivered report did ("未出现：IPv4 地址、域名、URL、C2 端点").  A denial that
# names a class while the fragments contain that class is the same false negative as
# one that repeats the value, so it must be caught too.
_COMPOSE_ABSENCE_CLASS_NAMES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("endpoint IPv4", ("ipv4", "ip 地址", "ip地址")),
    ("endpoint URL", ("url", "域名", "domain")),
    ("C2 endpoint", ("c2", "c&c", "命令与控制", "回连")),
)

# How far after a denial marker an enumeration of missing classes may reach.
_ABSENCE_ENUMERATION_CHARS = 120

# Words that mean the draft is DISCLOSING the class rather than denying it.  Without
# this, 「已恢复 C2 端点 …。未观察到运行时外联」 reads as a denial because 未观察到
# follows the class name; the affirmation in between is what distinguishes them.
_COMPOSE_AFFIRMATION_MARKERS = (
    "已恢复",
    "已解码",
    "已提取",
    "恢复到的",
    "解码得到的",
    "已确认",
    "已定位",
    "recovered",
    "decoded",
)


def absence_claim_violations(draft: str, fragments: str) -> list[str]:
    """Reject a draft that denies a fact class the composed fragments DO contain.

    The gate's other four classes all police what a draft ADDS.  Nothing policed what
    it DENIES, and that hole shipped: the delivered report for the Resume sample
    asserted that the sample's static evidence contained no IPv4 address, no domain,
    no URL and no C2 endpoint, while the task's own evidence held 7 rows containing
    ``http://69.48.228.74/ComHost.exe`` and the composed fragments contained both
    recovered C2 URLs.  A reader of that report would not go looking for a C2 the
    pipeline had already recovered.

    Scope, chosen from measurement rather than taste.  The check fires on the
    ENUMERATION shape a false negative actually takes: a denial marker, an optional
    colon, and then class names listed together - the delivered report's
    「未出现：IPv4 地址、域名、URL、C2 端点」.  The class must also be genuinely present
    in the fragments.

    Two shapes are deliberately NOT violations, and both cost real correctness:

    * a denial sharing a sentence with a RECOVERED literal
      (「已恢复 URL X，未观察到运行时外联」) - the correct and important statement that
      the value is in the file while the behaviour was never observed;
    * a denial about an unrelated class (persistence registry keys) while endpoints
      are present.

    An earlier version used a plain proximity window and rejected both.  Distinguishing
    "novel value" from "denied value" by proximity is not possible; the enumeration
    shape and the class name are the reliable signals.
    """
    text = str(draft or "")
    source = str(fragments or "")
    if not text.strip() or not source.strip():
        return []
    folded_source = source.casefold()
    violations: list[str] = []
    for label, names in _COMPOSE_ABSENCE_CLASS_NAMES:
        if not any(name in folded_source for name in names):
            continue
        for marker in _COMPOSE_ABSENCE_MARKERS:
            position = text.find(marker)
            while position >= 0:
                # The enumeration window starts AT the marker and runs forward: a
                # denial lists what is missing AFTER saying so.
                window = text[position : position + _ABSENCE_ENUMERATION_CHARS].casefold()
                hit = next((name for name in names if name in window), None)
                if hit is not None and not any(
                    affirmation in window[: window.find(hit) + len(hit)]
                    for affirmation in _COMPOSE_AFFIRMATION_MARKERS
                ):
                    violations.append(
                        f"denies a fact the composed fragments contain: {label} "
                        f"asserted absent near {marker!r} (class name {hit!r})"
                    )
                    break
                position = text.find(marker, position + 1)
    return list(dict.fromkeys(violations))


def _find_all(haystack: str, needle: str) -> list[int]:
    """Every occurrence position of ``needle`` in ``haystack``."""
    positions: list[int] = []
    start = haystack.find(needle)
    while start >= 0:
        positions.append(start)
        start = haystack.find(needle, start + 1)
    return positions


def compose_gate_violations(draft: str, fragments: str) -> list[str]:
    """报告合成门：通顺稿只能拼接、理顺已有片段，不能加事实或升格 Claim。

    ADR-0036 / G4 §8.3。``fragments`` 是确定性拼接稿，也是唯一允许出现的事实
    来源。返回违规列表；空列表表示过门。五类失败：措辞门、片段里没有的
    URL/IP/父进程名/flags、把 CANDIDATE/UNKNOWN 写成已坐实、跨样本 IOC、
    以及**否认片段里确实存在的事实**（假阴性结论）。
    """
    text = str(draft or "")
    if not text.strip():
        return []
    source = str(fragments or "")
    source_folded = source.casefold()
    violations: list[str] = []

    for item in static_wording_violations(text):
        violations.append(f"wording: {item}")

    def novel(pattern: re.Pattern[str], label: str, group: int = 0) -> None:
        for match in pattern.finditer(text):
            token = match.group(group)
            if token and token.casefold() not in source_folded:
                violations.append(f"{label} not in composed fragments: {token}")

    novel(_COMPOSE_URL_RE, "endpoint")
    novel(_COMPOSE_IPV4_RE, "endpoint")
    novel(_COMPOSE_IMAGE_RE, "process image")
    novel(_CREATION_FLAGS_RE, "creation flags", group=1)

    # A draft that silently drops the pipeline's OWN limitations is a false negative about a fact the fragments
    # carry: the reader would lose the one statement saying the pipeline had a problem (a truncation, a
    # cancellation, a timed-out tool run). This is the same class the gate already rejects - "否认片段里确实
    # 存在的事实" - applied to the operational block.
    #
    # WHY IT MATTERS AT THE GATE and not by post-processing the draft: MEASURED, the published body IS the
    # draft whenever it clears this gate (`publish_composed_markdown` returns the candidate, 6212-6214), and
    # the publisher passes one (`service.py:24107`, `draft=document.get("analyst_report_draft")`). So anything
    # rendered only into the deterministic fragments reaches a reader ONLY on the fallback path - and revision
    # `414cb724`'s published body contains zero occurrences of `限制`/`limitation`, which is what a published
    # draft looks like. Rejecting the draft here makes the omission FAIL THE GATE and publish the deterministic
    # body instead, rather than depending on the draft having been written correctly.
    if OPERATIONAL_LIMITATIONS_HEADING in source and OPERATIONAL_LIMITATIONS_HEADING not in text:
        violations.append(
            "draft omits the pipeline's operational limitations, which the composed fragments carry"
        )
    # CANDIDATE/UNKNOWN must not be restated as established fact.
    if "CANDIDATE" in source.upper() or "UNKNOWN(" in source.upper():
        folded = text.casefold()
        for marker in _COMPOSE_UPGRADE_MARKERS:
            if marker in folded:
                violations.append(f"upgraded candidate/unknown wording: {marker}")
                break
    # ...and a present fact must not be restated as absent.
    violations.extend(absence_claim_violations(text, source))

    # THE PRIMARY-BODY LEDGER CHECKS BELONG TO BOTH PUBLICATION PATHS.
    #
    # MEASURED: this gate ran only `static_wording_violations` plus the novelty / upgrade / absence checks,
    # while `primary_analyst_violations` - which owns the jargon list, Evidence UUIDs, `FUN_` dumps, `FUN_`
    # names, PERSISTED_INVESTIGATION and the coverage dictionaries - was applied ONLY on the deterministic
    # render path. But `publish_composed_markdown` RETURNS THE MODEL DRAFT, so a draft could carry ledger
    # vocabulary into the official body while the render path rejected the very same words. The hole was
    # wider than jargon: UUIDs and coverage dictionaries went through it too.
    #
    # Called, not re-implemented. A second copy of six checks is exactly how two paths drift apart, and the
    # point of this fix is that ONE definition governs both.
    #
    # THE WHOLE DRAFT IS CHECKED, and the appendix heading is neutralised first.
    #
    # MEASURED hole in the first version of this fix: `primary_analyst_violations` splits its input on
    # `ANALYST_APPENDIX_HEADING` and checks only the part BEFORE it. On the render path that heading is
    # machine-appended, so the split is trustworthy. Here the text is the MODEL'S DRAFT, so the model could
    # write the heading itself and put a UUID, a `FUN_` name and ledger jargon after it -
    # `compose_gate_violations("## 正文…\n\n## 调查附录（内部账本，非分析结论）\n\nFUN_0040d2c0 UUID …")` returned
    # `[]`. The gate was dodgeable by the very text it governs.
    #
    # A draft has no legitimate appendix: the appendix is composed by this module, not by the model. Removing
    # the heading makes the split find nothing and treat the entire draft as primary, so there is nowhere to
    # hide. The prompt never mentions 附录, so a model reaching this was guessing - but a gate must not depend
    # on the governed text's goodwill.
    draft_without_appendix = text.replace(ANALYST_APPENDIX_HEADING, "")
    violations.extend(
        f"compose draft {item}" for item in primary_analyst_violations(draft_without_appendix)
    )

    return list(dict.fromkeys(violations))


# Fact classes the gate above does NOT police, because they are not endpoints: registry
# paths, filesystem paths, task names, digests.  A fact in one of these classes that is
# absent from the fragments did not come from this analysis.  Measured on the published
# Resume body: 1 IPv4 (backed), 3 SHA256 (backed), 3 URLs (2 backed) - the only miss was a
# trailing `;` inside the token, not a fabrication - so this check is quiet on a real
# deterministic body and loud on a body carrying somebody else's facts.
_UNPOLICED_FACT_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("registry key", re.compile(r"\bHK(?:LM|CU|EY_LOCAL_MACHINE|EY_CURRENT_USER)[\\/][^\s`\"'|]+")),
    ("file path", re.compile(r"\b[A-Za-z]:\\[^\s`\"'<>|]+")),
    ("scheduled task name", re.compile(r"(?i)\bschtasks\b[^\n]{0,60}?/tn\s+`?([^\s`\"']+)")),
    ("sha256", re.compile(r"\b[0-9a-f]{64}\b", re.I)),
)


def unprovenanced_fact_tokens(draft: str, fragments: str) -> list[str]:
    """Fact-shaped tokens in ``draft`` that ``fragments`` cannot account for.

    WHY THIS EXISTS.  The three root causes behind an agent answering a sample with
    somebody else's report were: the session had no read scope, the prompt framed missing
    evidence as a cost, and - the one this addresses - **nothing detected it**.  The compose
    gate polices what a draft adds only in four endpoint-shaped classes, so a task name, a
    registry key or a path lifted from a benchmark document passed the gate unchanged and
    became indistinguishable from a recovered fact.  A failure with no signal cannot be
    caught, only argued about afterwards.

    NON-BLOCKING BY DESIGN, and that is a deliberate trade.  Rejecting on these classes
    would risk defeating legitimate narrative for a signal that is already measured at ~0
    false positives on a real body, and the objective forbids buying safety by discarding
    output.  Recording it makes the gap visible and auditable, which is the property that
    was actually missing; a caller that wants to reject can act on the returned list.

    Tokens are trimmed of trailing sentence punctuation before the comparison, because a
    URL at the end of a sentence is the same fact as the URL without the period - the
    measured single false positive on the real body was exactly this.
    """
    source_folded = str(fragments or "").casefold()
    found: list[str] = []
    for label, pattern in _UNPOLICED_FACT_RES:
        for match in pattern.finditer(str(draft or "")):
            token = match.group(1) if match.lastindex else match.group(0)
            token = str(token or "").strip().rstrip("。，、；：）)】」.,;:)")
            if not token:
                continue
            if token.casefold() in source_folded:
                continue
            found.append(f"{label} not in composed fragments: {token}")
    return list(dict.fromkeys(found))


def publish_composed_markdown(
    document: Mapping[str, object],
    draft: str,
    *,
    fragments: str = "",
) -> str:
    """发布过门的正文；门失败则退回确定性拼接稿（ADR-0036）。

    门失败丢掉的是编造的 DRAFT，不是整类内容：拼接稿仍含全部适用类目。
    """
    fallback = str(fragments or "").strip() or render_official_markdown(document).strip()
    fallback = fallback if fallback.endswith("\n") else fallback + "\n"
    candidate = str(draft or "").strip()
    if not candidate:
        return fallback
    if compose_gate_violations(candidate, fallback):
        return fallback
    return candidate if candidate.endswith("\n") else candidate + "\n"


def compose_official_markdown(
    document: Mapping[str, object],
    ledger_markdown: str = "",
    *,
    draft: str = "",
) -> str:
    """Official GET body. The ledger argument is ignored on purpose.

    A model-polished ``draft`` is published only when it passes 报告合成门
    (ADR-0036); otherwise the deterministic assembled text is published, so the
    reader still gets every applicable category.
    """

    del ledger_markdown
    fragments = render_official_markdown(document)
    if not str(draft or "").strip():
        return fragments
    return publish_composed_markdown(document, draft, fragments=fragments)


def compact_analyst_context(document: Mapping[str, object]) -> dict[str, object]:
    topics = plan_analyst_topics(document)
    rows = iter_document_rows(document)
    findings = []
    for row in rows:
        if not row.get("catalog_id"):
            continue
        what = str(row.get("what") or row.get("finding") or "")
        if _FUN_DUMP_RE.search(what) or what.startswith("["):
            what = ""
        findings.append(
            {
                "catalog_id": row.get("catalog_id"),
                "status": _finding_status(row) or None,
                "what": what[:240],
            }
        )
        if len(findings) >= 24:
            break
    payload = {
        "existing_topics": [
            {"catalog_id": item.catalog_id, "title": item.title, "status": item.status}
            for item in topics
        ],
        "notable_imports": _notable_imports(rows),
        "findings": findings,
        "haystack_preview": document_topic_haystack(document)[:4000],
    }
    # The recovered script as its OWN field, not truncated inside `haystack_preview`.
    #
    # MEASURED: `haystack_preview` above is a hard `[:4000]` slice and the 白象 script alone is 5,881
    # characters, so about the last third of it was INVISIBLE to the model while the checker still required
    # a literal substring from the whole thing. A slot whose evidence sits in the tail would be rejected for
    # quoting something the model was never shown - a false negative produced by a display limit rather than
    # by missing evidence. The corpora are the same ones the checker uses, so what the model is shown and
    # what it is checked against are the same text by construction.
    _corpora = slot_evidence_corpora(document)
    if _corpora.get("recovered_script"):
        payload["recovered_script"] = _corpora["recovered_script"]
    if _corpora.get("imports"):
        payload["import_corpus"] = _corpora["imports"]
    payload["rules"] = [
        "Do not use a fixed C2/persistence/injection outline.",
        "Propose extra chapters only with evidence_anchors present in haystack_preview.",
        "Quote every slot's evidence_substring from recovered_script / import_corpus VERBATIM; "
        "a substring that does not occur there is dropped.",
        "Do not drop existing_topics.",
        "Do not invent endpoints, creation flags, or family names.",
        "Do not paste FUN_ call dumps or coverage dictionaries.",
    ]
    revision = _authoritative_revision_id(document)
    if revision:
        payload["authoritative_revision_id"] = revision
    return payload


_T6_UNKNOWN_RE = re.compile(r"UNKNOWN\([^)]+\)", re.IGNORECASE)
_T6_BACKTICK_RE = re.compile(r"`([^`]+)`")
_T6_JOIN_RE = re.compile(r"JOINED_STATIC", re.IGNORECASE)
_T6_EMU_RE = re.compile(r"EMULATION_OBSERVED", re.IGNORECASE)
_T6_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_T6_FLAG_RE = _CREATION_FLAGS_RE
_T6_CONSUMER_EQ_RE = re.compile(r"consumer\s*=\s*`?([^\s`;]+)", re.IGNORECASE)


def official_revision_semantic_tokens(markdown: str) -> frozenset[str]:
    """Stable HOW/UNKNOWN/relation/byte tokens for T6 diffs. Not word count."""
    text = str(markdown or "")
    tokens: set[str] = set()
    for match in _T6_UNKNOWN_RE.finditer(text):
        tokens.add(match.group(0).upper())
    for match in _T6_BACKTICK_RE.finditer(text):
        value = match.group(1).strip()
        if not value or value.casefold().startswith("unknown"):
            continue
        if _UUID_RE.fullmatch(value):
            continue
        tokens.add(value.casefold())
    if _T6_JOIN_RE.search(text):
        tokens.add("JOINED_STATIC")
    if _T6_EMU_RE.search(text):
        tokens.add("EMULATION_OBSERVED")
    for match in _T6_HASH_RE.finditer(text):
        tokens.add(match.group(0).casefold())
    for match in _T6_FLAG_RE.finditer(text):
        value = match.group(1).strip("` ")
        if value and not value.casefold().startswith("unknown"):
            tokens.add(f"creation_flags={value.casefold()}")
    for match in _T6_CONSUMER_EQ_RE.finditer(text):
        value = match.group(1).strip("` ")
        if value and not value.casefold().startswith("unknown"):
            tokens.add(f"consumer={value.casefold()}")
    return frozenset(tokens)


def official_revision_semantic_gains(before: str, after: str) -> tuple[str, ...]:
    """T6: tokens present after a revision that were absent before."""
    gained = official_revision_semantic_tokens(after) - official_revision_semantic_tokens(before)
    return tuple(sorted(gained))


def t6_revision_has_substantive_gain(before: str, after: str) -> bool:
    """True only when HOW, relation, bytes, or an UNKNOWN fill changed."""
    return bool(official_revision_semantic_gains(before, after))


__all__ = [
    "ANALYST_APPENDIX_HEADING",
    "ANALYST_CONCLUSION_HEADING",
    "AnalystChapterDraft",
    "AnalystReportPlanEnvelope",
    "AnalystTopic",
    "UNMATCHED_CATEGORY_TEMPLATE",
    "apply_model_topic_plan",
    "compact_analyst_context",
    "compose_gate_violations",
    "compose_official_markdown",
    "document_topic_haystack",
    "official_revision_semantic_gains",
    "official_revision_semantic_tokens",
    "plan_analyst_topics",
    "primary_analyst_violations",
    "publish_composed_markdown",
    "render_analyst_chapters",
    "render_official_markdown",
    "split_analyst_markdown",
    "stamp_official_report_chrome",
    "t6_revision_has_substantive_gain",
]
