from __future__ import annotations

import io
import json
import re
import hashlib
from html import escape
from typing import Any, Iterable, Mapping, Sequence

from docx import Document
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer
from threat_report_agent.investigation.behavior_catalog import BehaviorCatalog
from threat_report_agent.investigation import (
    recovered_thread_parameter,
)
from threat_report_agent.facts.thread_start import recovered_thread_start_address
from threat_report_agent.emulation.controlled_emulation import PLACEHOLDER_STATUSES as _EMU_PLACEHOLDER_STATUSES
from threat_report_agent.product_certification import repair_static_runtime_wording
from threat_report_agent.product_certification import static_wording_violations
from threat_report_agent.investigation.mechanism_completeness import (
    has_semantic_value,
    is_navigation_value,
    mechanism_completeness_score,
    mechanism_is_critical_ready,
)
from threat_report_agent.deep_analysis_quality import apply_adversarial_downgrades, deep_analysis_metrics
from threat_report_agent.investigation.investigation_protocol import (
    TEN_QUESTION_SLOTS,
    fill_protocol,
    function_call_names,
    is_empty_marker,
)
from threat_report_agent.investigation.semantic_predicates import normalize_api_symbol, semantic_category
from threat_report_agent.static.static_analysis import (
    credible_windows_process_creation_flags,
    decode_windows_process_creation_flags,
    is_specialist_ppid_creation_flag,
)


REPORT_MODULES = (
    "executive_summary",
    "input_manifest",
    "artifact_inventory",
    "static_triage",
    "decryption",
    "loader",
    "c2_network",
    "anti_analysis",
    "behavior_attack",
    "attribution",
    "evidence_ledger",
    "limitations",
)

#: ADR-0006's input channels and the frozen status the snapshot stamps each one with. ONE table, because two
#: readers depend on it: the `input_manifest` report module and the `input_partition` Document fact that the
#: OFFICIAL body reads. A second hand-written copy is how the ledger and the official body start disagreeing.
INPUT_CHANNEL_LABELS: tuple[tuple[str, str, str], ...] = (
    ("task_request", "任务请求", "frozen"),
    ("sample_package", "样本包", "frozen"),
    ("background_context", "背景上下文", "isolated"),
    ("knowledge_snapshot", "知识快照", "versioned"),
)

#: The channel that is deliberately NOT an analysis input (ADR-0006 / FR-18). Named once here so the module
#: summary, the row and the Document fact cannot drift apart.
EXCLUDED_INPUT_CHANNEL = "评测基准报告"

#: The reader-facing isolation sentence. It is the SAME sentence `render_ledger_markdown` prints, so a reader
#: moving between the official body and the ledger cannot read two different policies.
INPUT_PARTITION_STATEMENT = (
    f"{EXCLUDED_INPUT_CHANNEL}：已隔离，仅用于分析完成后的对比评估，不作为本次分析输入。"
)

#: Document key carrying the structured input partition (producer: this module; consumer:
#: `analyst_report._input_partition_lines`). The renderer reads the Document and never re-derives the sentence.
INPUT_PARTITION_DOCUMENT_KEY = "input_partition"

# Kunglao completeness applied to the analyst document: unanswered work may
# remain named, but a one-round HOW must not be sliced off at 96 KiB.
REPORT_MAX_MARKDOWN_BYTES = 256 * 1024
# Product vocabulary: Unicorn/Speakeasy/Qiling are static analysis. Dynamic
# analysis is a full sandbox run of the sample, which this product does not do.
STATIC_SCOPE_BANNER_EN = (
    "> Static analysis includes Ghidra/static recovery and isolated Unicorn/"
    "Speakeasy/Qiling. This is not sandbox/dynamic analysis (full sample execution)."
)
STATIC_SCOPE_BANNER_ZH = (
    "> 静态分析包含反汇编/数据流恢复，以及隔离 worker 上的 Unicorn/Speakeasy/Qiling；"
    "完整沙箱跑样本才是动态分析，本产品不做该项。"
)
REPORT_V3_REQUIRED_SECTIONS = (
    "Executive Assessment",
    "Artifact Summary",
    "Key Static Findings",
    "Verified Mechanisms",
    "Reconstructed Static Behavior Flow",
    "IOC / Indicators",
    "Detection / Hunting Opportunities",
    "ATT&CK Reference",
    "Unknowns / Static Boundaries",
    "Analysis Coverage",
)
# Root/contracts may populate this later. Reporting only consumes it.
# Path: strategy_snapshot["investigation"]["static_analysis_plan"]
STATIC_ANALYSIS_PLAN_SNAPSHOT_KEY = "static_analysis_plan"
STATIC_ANALYSIS_PLAN_SNAPSHOT_PATH = "investigation.static_analysis_plan"
_RAW_DUMP_MARKERS = (
    "## 完整 Strings",
    "## Full Strings",
    "## 完整 Imports",
    "## Full Imports",
    "function_similarity dump",
)

# These Claims preserve useful navigation and scheduling facts in the
# immutable ledger, but they do not describe a sample mechanism.  Projecting
# them as candidate mechanisms makes report closure metrics measure the
# scheduler rather than the artifact.
_NON_MECHANISM_CLAIM_TYPES = frozenset(
    {
        "FUNCTION_REVIEW_PRIORITY",
        "FALLBACK_CODE_CALL_GRAPH",
        # Cross-function navigation claims remain auditable in the ledger and
        # relation graph; without a typed mechanism/verifier they are not a
        # mechanism candidate by themselves.
        "CROSS_FUNCTION_MECHANISM",
    }
)

# Kunglao leftover remainder: persist-skip CONTROLLED_EMULATE writes a
# DEFERRED_TO_WORKER placeholder. The isolated worker result is the remainder.


def apply_report_display_budget(markdown: str) -> str:
    """Keep one-round HOW inside the display budget without a silent 96 KiB cut.

    Unanswered low-priority detail may be omitted, but the published document
    must still name that truncation instead of dropping mid-section.
    """
    encoded = str(markdown or "").encode("utf-8")
    if len(encoded) <= REPORT_MAX_MARKDOWN_BYTES:
        return markdown
    kib = REPORT_MAX_MARKDOWN_BYTES // 1024
    notice = (
        f"\n\n> 报告正文已达到 {kib} KiB 展示预算；其余低优先级明细未内嵌。"
        "完整 Evidence、ToolRun 和原始输出请通过 Evidence Explorer 按 task_id 查询。\n"
    )
    budget = REPORT_MAX_MARKDOWN_BYTES - len(notice.encode("utf-8"))
    return encoded[: max(0, budget)].decode("utf-8", errors="ignore").rstrip() + notice


def report_bloat_violations(markdown: str) -> list[str]:
    """Return deterministic release-gate violations for the primary report."""
    violations: list[str] = []
    size = len(markdown.encode("utf-8"))
    if size > REPORT_MAX_MARKDOWN_BYTES:
        violations.append(f"markdown exceeds {REPORT_MAX_MARKDOWN_BYTES} bytes ({size})")
    for marker in _RAW_DUMP_MARKERS:
        if marker.casefold() in markdown.casefold():
            violations.append(f"forbidden raw-dump marker: {marker}")
    # Keep the primary report readable while leaving the complete ledger in
    # Evidence Explorer. These checks are intentionally heading-scoped so a
    # normal narrative containing the word "string" is unaffected.
    for heading in ("interesting strings", "有趣字符串", "strings of interest"):
        match = re.search(rf"(?is){re.escape(heading)}.*?(?=\n## |\Z)", markdown)
        if match and len(re.findall(r"(?m)^\s*[-*]\s+", match.group(0))) > 20:
            violations.append("visible interesting strings exceed 20")
    return violations


def build_verified_security_findings(
    mechanisms: list[Any] | None,
    claims: list[Any],
    evidence_by_id: dict[str, Any],
) -> list[dict[str, object]]:
    """Project formal findings only from VERIFIED mechanisms.

    A candidate Claim or a bare import/string can remain visible as supporting
    analysis, but cannot become a Critical Finding until a verifier has marked
    its mechanism verified and supplied complete provenance.
    """
    findings: list[dict[str, object]] = []
    claim_by_id = {str(getattr(item, "id", "")): item for item in claims}
    for mechanism in mechanisms or []:
        def mechanism_value(key: str, default: object = None) -> object:
            if isinstance(mechanism, Mapping):
                return mechanism.get(key, default)
            return getattr(mechanism, key, default)

        if isinstance(mechanism, dict):
            status = str(mechanism.get("status", "")).upper()
            mechanism_id = str(mechanism.get("id", ""))
            raw_claim_id = mechanism.get("claim_id")
            claim_id = str(raw_claim_id) if raw_claim_id else ""
            claim_ids = [str(item) for item in mechanism.get("claim_ids", []) if item]
            evidence_ids = [str(item) for item in mechanism.get("evidence_ids", []) if item]
            verifier = mechanism.get("verifier", {})
            target = str(mechanism.get("target", "mechanism"))
            how = " -> ".join(str(item) for item in mechanism.get("transformation_or_control", []))
        else:
            status = str(getattr(mechanism, "status", "")).upper()
            mechanism_id = str(getattr(mechanism, "id", ""))
            raw_claim_id = getattr(mechanism, "claim_id", None)
            claim_id = str(raw_claim_id) if raw_claim_id else ""
            claim_ids = [str(item) for item in (getattr(mechanism, "claim_ids", ()) or ()) if item]
            evidence_ids = [str(item) for item in getattr(mechanism, "evidence_ids", ()) if item]
            verifier = getattr(mechanism, "verifier", {}) or {}
            target = str(getattr(mechanism, "target", "mechanism"))
            how = " -> ".join(str(item) for item in getattr(mechanism, "transformation_or_control", ()))
        # A deduplicated projection can represent several Claims in
        # ``claim_ids`` while retaining ``claim_id`` only for legacy replay.
        # Resolve the first available Claim so verified mechanisms cannot be
        # silently dropped from the analyst-facing report.
        ordered_claim_ids = list(dict.fromkeys(item for item in [claim_id, *claim_ids] if item))
        claim = next((claim_by_id[item] for item in ordered_claim_ids if item in claim_by_id), None)
        primary_claim_id = next((item for item in ordered_claim_ids if item in claim_by_id), "")
        if status != "VERIFIED" or not mechanism_id or not evidence_ids:
            continue
        mechanism_mapping = mechanism if isinstance(mechanism, dict) else {
            key: getattr(mechanism, key)
            for key in ("target", "inputs", "transformation_or_control", "conditions", "outputs", "consumers", "side_effects", "evidence_ids", "completeness", "verifier")
            if hasattr(mechanism, key)
        }
        if "completeness" in mechanism_mapping:
            if not mechanism_is_critical_ready(mechanism_mapping):
                continue
        if _report_is_attribution(mechanism_mapping, claim):
            continue
        if claim is None:
            continue
        valid_evidence = [item for item in evidence_ids if item in evidence_by_id]
        if not valid_evidence:
            continue
        statement = str(getattr(claim, "statement", ""))
        mechanism_type = str(
            (verifier.get("mechanism_type") if isinstance(verifier, dict) else "")
            or getattr(claim, "module", "static")
        ).casefold()
        security_meaning = {
            "decode_config": "Static evidence shows a data transformation path that can hide configuration or payload content; detections should inspect the decoder inputs and downstream consumer rather than plaintext strings alone.",
            "dynamic_api_resolution": "The sample resolves high-value APIs indirectly, so import-only detection can understate its capabilities; hunt for the resolver, API identity material, and its consumer call.",
            "ppid_spoofing": "The recovered startup-attribute chain can make a child appear to originate from a selected parent process; monitor STARTUPINFOEX parent-process attributes and unusual parent/child relationships.",
            "etw_patch": "The static patch sequence targets event-reporting code, which could reduce telemetry if reached; compare the target bytes and protection changes with known ETW patch patterns.",
        }.get(mechanism_type, f"The verified static mechanism exposes a security-relevant {mechanism_type.replace('_', ' ')} behavior; the cited data/control path is the appropriate detection pivot.")
        def field_values(key: str) -> list[str]:
            raw = mechanism_value(key, ())
            if isinstance(raw, (list, tuple, set)):
                return [str(item) for item in raw if item not in (None, "")]
            return [str(raw)] if raw not in (None, "") else []

        mechanism_type_value = str(
            mechanism_value("mechanism_type", "")
            or (verifier.get("mechanism_type") if isinstance(verifier, Mapping) else "")
            or getattr(claim, "module", "static")
        )
        findings.append({
            "type": "security_finding",
            "critical": True,
            "verdict": "SUPPORTED",
            "confidence": getattr(claim, "confidence", "HIGH"),
            "finding_id": f"finding:{mechanism_id}",
            "mechanism_id": mechanism_id,
            "mechanism_type": mechanism_type_value,
            "claim_id": primary_claim_id,
            "claim_ids": ordered_claim_ids,
            "evidence_ids": valid_evidence[:5],
            "what": statement or f"Verified mechanism targets {target}.",
            "how": how or str(getattr(claim, "mechanism", "")),
            "target": target,
            "inputs": field_values("inputs"),
            "transformation_or_control": field_values("transformation_or_control"),
            "conditions": field_values("conditions"),
            "outputs": field_values("outputs"),
            "consumers": field_values("consumers"),
            "side_effects": field_values("side_effects"),
            "completeness": mechanism_value("completeness"),
            "security_meaning": security_meaning,
            "boundary": "Static evidence; runtime execution and intent are not observed.",
            "verifier": verifier,
        })
    return findings


def build_mechanism_projections(
    claims: list[Any],
    links_by_claim: dict[str, list[str]],
    evidence_by_id: dict[str, Any],
) -> list[dict[str, object]]:
    """Recover an auditable mechanism shape from an evidence-backed Claim.

    Static parsers often expose the same facts in several rows. This helper
    turns those rows into the common Input -> Transformation/Control ->
    Condition -> Output -> Consumer -> Side Effect vocabulary. It remains a
    candidate until a specialist verifier accepts it, so completeness never
    implies runtime execution.
    """
    projections: list[dict[str, object]] = []
    for claim in claims:
        if str(getattr(claim, "claim_type", "")).upper() in _NON_MECHANISM_CLAIM_TYPES:
            continue
        evidence_ids = list(dict.fromkeys(links_by_claim.get(str(claim.id), [])))[:32]
        if not evidence_ids:
            continue
        evidence = [evidence_by_id[item] for item in evidence_ids if item in evidence_by_id]
        kinds = {str(getattr(item, "kind", "")).casefold() for item in evidence}
        values = [getattr(item, "value", {}) for item in evidence]
        text_parts: list[str] = []
        api_names: list[str] = []
        for value in values:
            if isinstance(value, dict):
                for key in ("api", "name", "target_name", "target_function", "function"):
                    if value.get(key):
                        api_names.append(str(value[key]))
                for key in ("text", "indicator", "format", "algorithm", "chain_type"):
                    if value.get(key):
                        text_parts.append(str(value[key]))
        # Function-level observations contain the data/control-flow details
        # needed for an analyst-grade explanation. Keep these compact and
        # provenance-preserving; the complete rows remain in Evidence.
        ordered_calls: list[str] = []
        data_inputs: list[str] = []
        argument_inputs: list[str] = []
        downstream: list[str] = []
        for context in values:
            if not isinstance(context, Mapping):
                continue
            call_targets = context.get("call_targets")
            if isinstance(call_targets, (list, tuple)):
                for call in call_targets:
                    if isinstance(call, Mapping):
                        name = call.get("target_name") or call.get("target_function") or call.get("api")
                        if name:
                            ordered_calls.append(str(name))
            call_sequence = context.get("call_sequence")
            if isinstance(call_sequence, (list, tuple)):
                for call in call_sequence:
                    if isinstance(call, Mapping):
                        name = call.get("api") or call.get("target_name") or call.get("target_function")
                        if name:
                            ordered_calls.append(str(name))
            references = context.get("data_references")
            if isinstance(references, (list, tuple)):
                for reference in references:
                    if isinstance(reference, Mapping):
                        value_text = reference.get("text") or reference.get("name") or reference.get("target_name") or reference.get("to")
                        if value_text not in (None, ""):
                            data_inputs.append(str(value_text))
            arguments = context.get("arguments")
            if isinstance(arguments, (list, tuple)):
                for argument in arguments:
                    if isinstance(argument, Mapping):
                        value_text = argument.get("value") or argument.get("resolved") or argument.get("source_instruction")
                        if value_text not in (None, "", False):
                            argument_inputs.append(str(value_text))
            if context.get("consumer"):
                downstream.append(str(context["consumer"]))
            raw_consumers = context.get("downstream_consumers")
            if isinstance(raw_consumers, (list, tuple)):
                downstream.extend(str(item) for item in raw_consumers if item not in (None, ""))
        ordered_calls = list(dict.fromkeys(ordered_calls))
        data_inputs = list(dict.fromkeys(data_inputs))
        argument_inputs = list(dict.fromkeys(argument_inputs))
        downstream = list(dict.fromkeys(downstream))
        api_names.extend(ordered_calls)

        action = str(getattr(claim, "action", "static_mechanism"))
        object_name = str(getattr(claim, "object", "static target"))
        mechanism_text = str(getattr(claim, "mechanism", "static evidence path"))
        condition = str(getattr(claim, "condition", "static evidence only"))
        inputs = tuple(dict.fromkeys(
            item for item in text_parts
            if any(token in item.casefold() for token in ("resource", "encoded", "cipher", "input", "buffer", "string", "payload"))
        ))
        inputs = tuple(dict.fromkeys((*inputs, *data_inputs[:8], *argument_inputs[:8])))
        if not inputs and any("string" in kind or "resource" in kind for kind in kinds):
            inputs = ("statically recovered resource/string/buffer",)
        transforms = tuple(dict.fromkeys(
            ([mechanism_text] if not is_navigation_value(mechanism_text) else [])
            + [item for item in text_parts if any(token in item.casefold() for token in ("xor", "decode", "decrypt", "decompress", "transform", "resolve", "permission"))]
            + ([" -> ".join(ordered_calls[:12])] if ordered_calls else [])
            + ([" -> ".join(api_names[:8])] if api_names and not is_navigation_value(api_names) and not ordered_calls else [])
        ))
        outputs = (object_name,) if object_name else ()
        consumers = tuple(dict.fromkeys(
            (*downstream[:8], *api_names[-4:])
            if not is_navigation_value(api_names)
            else tuple(downstream[:8])
        ))
        side_effect_map = {
            "may_decode_or_decrypt": "prepares transformed configuration or payload data",
            "decompresses_or_decodes": "prepares decompressed or decoded data for a downstream consumer",
            "extracts_resource_payload": "extracts embedded resource bytes for later processing",
            "may_load_or_prepare_memory": "prepares a module or executable memory region for a downstream call",
            "may_spoof_parent_process": "constructs alternate parent-process startup attributes",
            "may_create_process": "may start a child process if the recovered command is executed",
            "may_start_os_thread": "may start a same-process OS thread if the recovered start routine is executed",
            "may_resolve_api_dynamically": "may load a secondary module and prepare a resolved entry point",
            "may_decode_configuration": "may materialize decoded configuration for a later consumer",
            "references_network_endpoint": "constructs or references a network transport path",
            "checks_execution_environment": "branches on environment or debugger state",
            "queries_service_state": "reads service state for a subsequent decision",
        }
        side_effects = (side_effect_map[action],) if action in side_effect_map else ()
        # Keep the mechanism contract total. UNKNOWN fields are explicit
        # epistemic markers, not inferred runtime values, and therefore do not
        # contribute to the completeness score below.
        input_fields = list(inputs) or ["UNKNOWN(input)"]
        transform_fields = list(transforms) or ["UNKNOWN(transformation_or_control)"]
        condition_fields = [condition] if condition else ["UNKNOWN(condition)"]
        output_fields = list(outputs) or ["UNKNOWN(output)"]
        consumer_fields = list(consumers) or ["UNKNOWN(consumer)"]
        side_effect_fields = list(side_effects) or ["UNKNOWN(side_effect)"]
        action_mechanism_types = {
            "may_create_process": "PROCESS_EXECUTION",
            "may_start_os_thread": "THREAD_CALLBACK",
            "may_resolve_api_dynamically": "DYNAMIC_API_RESOLUTION",
            "may_decode_configuration": "DECODE_CONFIG",
            "may_spoof_parent_process": "PPID_SPOOFING",
            "may_decode_or_decrypt": "DECODE_CONFIG",
        }
        projection = {
            "type": "mechanism_candidate",
            "mechanism_id": f"candidate-mechanism:{claim.id}",
            "claim_id": claim.id,
            "mechanism_type": action_mechanism_types.get(action, ""),
            "status": "VERIFIED" if str(getattr(claim, "status", "")).upper() == "VERIFIED" else "CANDIDATE",
            "target": str(getattr(claim, "subject", object_name)),
            "inputs": input_fields,
            "transformation_or_control": transform_fields,
            "conditions": condition_fields,
            "outputs": output_fields,
            "consumers": consumer_fields,
            "side_effects": side_effect_fields,
            "evidence_ids": evidence_ids[:5],
            # Candidates must tell the analyst what is still unresolved and
            # which benign/alternative explanations remain open.  These fields
            # are intentionally conservative and never promote a candidate to
            # a verified mechanism.
            "alternative_hypotheses": [
                "benign library or parser use",
                "unresolved static data/control-flow path",
            ],
            "unknowns": [
                "runtime execution and intent are not observed",
                "the downstream consumer is not fully closed statically",
            ],
            "limitations": [
                "static evidence does not establish successful execution",
            ],
            "completeness": 0,
        }
        projection["completeness"] = mechanism_completeness_score(projection)
        projections.append(projection)
    # Collapse equivalent projections generated from duplicated import/xref
    # facts.  The Evidence ledger and Claim rows remain untouched; this only
    # controls the analyst-facing mechanism view and keeps candidate noise from
    # drowning the few distinct static paths.
    deduped: list[dict[str, object]] = []
    by_key: dict[str, dict[str, object]] = {}
    for projection in projections:
        key_payload = {
            "target": projection.get("target"),
            "inputs": projection.get("inputs"),
            "transformation_or_control": projection.get("transformation_or_control"),
            "conditions": projection.get("conditions"),
            "outputs": projection.get("outputs"),
            "consumers": projection.get("consumers"),
            "side_effects": projection.get("side_effects"),
        }
        key = json.dumps(key_payload, ensure_ascii=True, sort_keys=True, default=str)
        current = by_key.get(key)
        if current is None:
            clone = dict(projection)
            clone["claim_ids"] = [str(projection["claim_id"])] if projection.get("claim_id") else []
            by_key[key] = clone
            deduped.append(clone)
            continue
        claim_id = projection.get("claim_id")
        if claim_id and str(claim_id) not in current.setdefault("claim_ids", []):
            current["claim_ids"].append(str(claim_id))
        current["evidence_ids"] = list(dict.fromkeys(
            [str(item) for item in current.get("evidence_ids", []) if item]
            + [str(item) for item in projection.get("evidence_ids", []) if item]
        ))[:12]
        if str(projection.get("status", "")).upper() in {"VERIFIED", "SUPPORTED", "CONFIRMED"}:
            current["status"] = projection.get("status")
        current["completeness"] = max(
            int(current.get("completeness", 0) or 0),
            int(projection.get("completeness", 0) or 0),
        )
    return deduped[:128]


_STATIC_LINK_MECHANISM_TYPES = {
    "mechanism_dynamic_api_link": "DYNAMIC_API_RESOLUTION",
    "mechanism_http_transport_link": "HTTP_DOWNLOAD",
    "mechanism_shell_output_link": "SHELL_OUTPUT",
    "mechanism_etw_patch_link": "ETW_PATCH",
}


def build_static_link_mechanism_projections(
    evidence_by_id: Mapping[str, Any],
) -> list[dict[str, object]]:
    """Project specialist ``STATIC_DERIVED`` links into mechanism records.

    The deterministic correlator emits a first-class Evidence row because the
    link itself is an auditable derivation.  This helper makes that row visible
    in the immutable investigation snapshot even when no Claim has been
    created yet.  It deliberately keeps every projection ``CANDIDATE``:
    correlation is useful semantic evidence, but it is not runtime proof and
    cannot bypass a specialist verifier or Claim Gate.
    """
    projections: list[dict[str, object]] = []
    for link_id, link in evidence_by_id.items():
        def read_source(item: Any, key: str, default: object = None) -> object:
            if isinstance(item, Mapping):
                return item.get(key, default)
            return getattr(item, key, default)

        kind = str(read_source(link, "kind", "")).casefold()
        mechanism_type = _STATIC_LINK_MECHANISM_TYPES.get(kind)
        if mechanism_type is None:
            continue
        value = read_source(link, "value", {})
        if not isinstance(value, Mapping):
            continue
        source_ids = [
            str(item)
            for item in value.get("source_evidence_ids", ())
            if str(item).strip()
        ]
        # A derived link without source provenance is not a usable mechanism
        # projection.  The source rows are required for evidence navigation
        # and for a later verifier to reproduce the derivation.
        if not source_ids:
            continue
        # A derived link intentionally carries only a compact summary.  The
        # source rows remain the authority for function/RVA and callsite
        # anchors, so recover those fields here before rendering HOW.  Older
        # reports dropped this information and consequently rendered a
        # cross-function mechanism as ``function@RVA unknown`` even though
        # the link anchor and indirect-pointer evidence contained it.
        source_rows = [evidence_by_id[item_id] for item_id in source_ids if item_id in evidence_by_id]

        link_anchor = read_source(link, "anchor", {})
        link_anchor = link_anchor if isinstance(link_anchor, Mapping) else {}

        def first_anchor(*keys: str) -> object:
            for key in keys:
                value = link_anchor.get(key)
                if value not in (None, ""):
                    return value
            for row in source_rows:
                anchor = read_source(row, "anchor", {})
                anchor = anchor if isinstance(anchor, Mapping) else {}
                value = next((anchor.get(key) for key in keys if anchor.get(key) not in (None, "")), None)
                if value not in (None, ""):
                    return value
                value = read_source(row, key, None)
                if value not in (None, ""):
                    return value
                row_value = read_source(row, "value", {})
                if isinstance(row_value, Mapping):
                    value = next((row_value.get(key) for key in keys if row_value.get(key) not in (None, "")), None)
                    if value not in (None, ""):
                        return value
            return None

        function_entry = first_anchor("function_entry", "entry", "rva")
        rva = first_anchor("rva", "entry_rva")
        function_name = first_anchor("function", "name")

        def callsites_for(names: object, *, field: str = "") -> list[str]:
            wanted = {
                str(item).casefold()
                for item in (names if isinstance(names, (list, tuple, set)) else (names,))
                if str(item).strip()
            }
            found: list[str] = []
            for row in source_rows:
                value = read_source(row, "value", {})
                if not isinstance(value, Mapping):
                    continue
                # Resolver/pointer link rows expose explicit callsite fields.
                if field and value.get(field) not in (None, ""):
                    found.append(str(value[field]))
                for key in ("call_targets", "calls", "references_from", "callees"):
                    nested = value.get(key)
                    if not isinstance(nested, (list, tuple)):
                        continue
                    for call in nested:
                        if not isinstance(call, Mapping):
                            continue
                        api = str(call.get("target_name") or call.get("target_function") or call.get("api") or "").casefold()
                        address = call.get("from") or call.get("address") or call.get("callsite")
                        if address not in (None, "") and (not wanted or api in wanted):
                            found.append(str(address))
                # API argument traces have their API and callsite at row level.
                api = str(value.get("api") or value.get("target_name") or "").casefold()
                address = value.get("callsite") or value.get("from") or value.get("address")
                if address not in (None, "") and (not wanted or api in wanted):
                    found.append(str(address))
            return list(dict.fromkeys(found))[:8]

        raw_value = read_source(link, "value", {})
        raw_value = raw_value if isinstance(raw_value, Mapping) else {}
        resolver_names = raw_value.get("resolver") or raw_value.get("apis") or ()
        consumer_names = raw_value.get("consumer_apis") or raw_value.get("consumer") or ()
        resolver_callsites = callsites_for(resolver_names, field="resolver_callsite")
        consumer_callsites = callsites_for(consumer_names, field="consumer_callsite")
        artifact_id = str(read_source(link, "artifact_id", "") or "")
        identity = json.dumps(
            {
                "mechanism_type": mechanism_type,
                "artifact_id": artifact_id,
                "link_id": str(link_id),
                "source_evidence_ids": source_ids,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        mechanism_id = "derived-mechanism:" + mechanism_type.casefold() + ":" + hashlib.sha256(
            identity.encode("utf-8")
        ).hexdigest()[:16]

        def values(*keys: str, fallback: str = "UNKNOWN") -> list[str]:
            result: list[str] = []
            for key in keys:
                raw = value.get(key)
                if isinstance(raw, (list, tuple, set)):
                    result.extend(str(item) for item in raw if str(item).strip())
                elif raw not in (None, ""):
                    result.append(str(raw))
            return list(dict.fromkeys(result)) or [fallback]

        if mechanism_type == "DYNAMIC_API_RESOLUTION":
            inputs = values("module", "entry_point", fallback="module and entry-point name")
            transforms = values("relationship", fallback="resolver result is passed to a function-pointer consumer")
            outputs = values("function_pointer", fallback="resolved function address")
            consumers = values("consumer", "consumer_apis", fallback="resolved entry-point consumer")
            side_effects = ["prepares a resolved API entry point; runtime loading is unobserved"]
        elif mechanism_type == "HTTP_DOWNLOAD":
            inputs = values("endpoint", "transport", fallback="statically recovered endpoint or transport")
            transforms = values("relationship", fallback="request/response transport path")
            outputs = values("response_side_effect", "side_effect", fallback="response bytes")
            consumers = values("consumer", fallback="UNKNOWN(consumer)")
            side_effects = ["may receive response bytes; network access was not performed"]
        elif mechanism_type == "SHELL_OUTPUT":
            inputs = values("input", "shell", fallback="child-process command or standard stream")
            transforms = values("relationship", fallback="child process output is connected to a pipe")
            outputs = values("output_capture", "side_effect", fallback="captured child-process output")
            consumers = values("consumer", fallback="pipe reader")
            side_effects = ["captures a child-process output channel; process execution is unobserved"]
        else:  # ETW_PATCH
            inputs = values("entry", fallback="EtwEventWrite target")
            transforms = values("relationship", "condition", fallback="target protection is changed before patching")
            outputs = values("patch_bytes", fallback="patched instruction bytes")
            consumers = values("flush", fallback="FlushInstructionCache")
            side_effects = ["may alter an ETW provider target; memory writes were not executed"]

        # Put the recovered callsites into the analyst-facing HOW path.  The
        # exact values are static anchors, not claims that the calls execute.
        # Keeping them in the transformation string also makes the compact
        # report useful without forcing an Evidence Explorer drill-down.
        if resolver_callsites and mechanism_type == "DYNAMIC_API_RESOLUTION":
            transforms.append("resolver callsite=" + ", ".join(resolver_callsites))
        if consumer_callsites and mechanism_type == "DYNAMIC_API_RESOLUTION":
            transforms.append("consumer callsite=" + ", ".join(consumer_callsites))
        # For transport, shell and patch paths there is no single resolver;
        # retain the source call sequence as an explicit static callsite map.
        if mechanism_type in {"HTTP_DOWNLOAD", "SHELL_OUTPUT", "ETW_PATCH"}:
            all_callsites = list(dict.fromkeys([
                *callsites_for(raw_value.get("apis") or (), field=""),
                *callsites_for(raw_value.get("consumer") or (), field="consumer_callsite"),
            ]))
            if all_callsites:
                transforms.append("static callsites=" + ", ".join(all_callsites))

        provenance = {
            "link_evidence_id": str(link_id),
            "source_evidence_ids": source_ids,
            "nature": str(read_source(link, "nature", "STATIC_DERIVED")),
            "evaluator": (
                value.get("derivation", {}).get("evaluator")
                if isinstance(value.get("derivation"), Mapping)
                else "derive_static_mechanism_links"
            ),
            "input_digest": (
                value.get("derivation", {}).get("input_digest")
                if isinstance(value.get("derivation"), Mapping)
                else None
            ),
            "output_digest": (
                value.get("derivation", {}).get("output_digest")
                if isinstance(value.get("derivation"), Mapping)
                else None
            ),
        }
        target = artifact_id or mechanism_type
        if function_entry not in (None, ""):
            target = _format_function_location(
                str(function_name or f"FUN_{function_entry}"), str(function_entry)
            )
        projection = {
                "type": "mechanism_link",
                "mechanism_id": mechanism_id,
                "mechanism_type": mechanism_type,
                "dimension": mechanism_type,
                "artifact_id": artifact_id or None,
                "status": "CANDIDATE",
                "target": target,
                "function": str(function_name) if function_name not in (None, "") else None,
                "function_entry": str(function_entry) if function_entry not in (None, "") else None,
                "rva": rva,
                "inputs": inputs,
                "transformation_or_control": transforms,
                "conditions": [
                    "static linked evidence only; runtime reachability and intent are unobserved"
                ],
                "outputs": outputs,
                "consumers": consumers,
                "side_effects": side_effects,
                "evidence_ids": list(dict.fromkeys([str(link_id), *source_ids]))[:12],
                "resolver_callsites": resolver_callsites,
                "consumer_callsites": consumer_callsites,
                "provenance": provenance,
                "alternative_hypotheses": [
                    "the correlated path may be dead code or a benign library use",
                    "static ordering does not establish runtime execution",
                ],
                "unknowns": [
                    "runtime reachability and successful API calls",
                    "actual data values at execution time",
                ],
                "limitations": [
                    "derived from static facts only; no sample execution or network access"
                ],
                "completeness": 0,
            }
        projection["completeness"] = mechanism_completeness_score(projection)
        projections.append(projection)
    return projections[:128]


_OBSERVED_MECHANISM_KINDS = {
    "mechanism_chain",
    "cross_function_chain",
    "mechanism_decode_window",
    "mechanism_memory_permission",
    "mechanism_environment_check",
    "mechanism_dynamic_resolution",
    "indirect_function_pointer_link",
    # A concrete procedure-name recovery is a first-class mechanism input:
    # it bridges the resolver call and the otherwise opaque function pointer.
    "resolved_api",
    "function_semantic_summary",
}

_SEMANTIC_CATEGORY_TO_CATALOG = {
    "network": ("network-transport", "NETWORK_DOWNLOAD"),
    "execution": ("process-creation", "PROCESS_EXECUTION"),
    "injection": ("process-injection", "PROCESS_INJECTION"),
    "persistence": ("registry-operations", "REGISTRY_CONFIGURATION"),
    "dynamic_resolution": ("loader-and-api-resolution", "DYNAMIC_API_RESOLUTION"),
    "loader": ("memory-and-mapping", "MEMORY_PERMISSION_CHANGE"),
    "timing_query": ("environment-guard", "ENVIRONMENT_CHECK"),
    "environment_query": ("environment-guard", "ENVIRONMENT_CHECK"),
    "anti_analysis": ("environment-guard", "ENVIRONMENT_CHECK"),
    "file_io": ("file-operations", "FILE_IO"),
}


def _catalog_from_semantic_calls(calls: object) -> tuple[str, str]:
    """Map a recovered decompile call sequence onto a catalog id and mechanism type."""
    apis: list[str] = []
    categories: list[str] = []
    if isinstance(calls, (list, tuple)):
        for call in calls:
            if not isinstance(call, Mapping):
                continue
            api = str(call.get("api") or call.get("target_name") or "").casefold()
            if api:
                apis.append(api)
            category = str(call.get("category") or semantic_category(api) or "").casefold()
            if category:
                categories.append(category)
    joined = " ".join(apis)
    if any("createthread" in api and "remote" not in api for api in apis):
        return "thread-and-callback", "THREAD_CALLBACK"
    if any("crypt" in api or "rc4" in api or "aes" in api for api in apis):
        return "config-and-crypto", "DECODE_TRANSFORM"
    if any("winhttp" in api or "wininet" in api or "internet" in api for api in apis):
        return "network-transport", "NETWORK_DOWNLOAD"
    if any("updateprocthreadattribute" in api or "proc_thread_attribute_parent" in joined for api in apis):
        return "parent-process-spoofing", "PPID_SPOOFING"
    if any("virtualprotect" in api or "virtualalloc" in api for api in apis):
        return "memory-and-mapping", "MEMORY_PERMISSION_CHANGE"
    if any("gettickcount" in api or "globalmemory" in api or "isdebugger" in api for api in apis):
        return "environment-guard", "ENVIRONMENT_CHECK"
    mapped = [category for category in categories if category in _SEMANTIC_CATEGORY_TO_CATALOG]
    if mapped:
        dominant = max(set(mapped), key=mapped.count)
        return _SEMANTIC_CATEGORY_TO_CATALOG[dominant]
    return "unique-or-unknown", "STATIC_DECOMPILE_PATH"


def _mechanism_categories(value: Mapping[str, object], steps: list[object]) -> set[str]:
    """Return normalized semantic categories carried by an observation."""
    categories: set[str] = set()
    raw_categories = value.get("categories")
    if isinstance(raw_categories, (list, tuple, set)):
        categories.update(str(item).casefold() for item in raw_categories if str(item).strip())
    for step in steps:
        if isinstance(step, Mapping):
            category = step.get("category")
            if category not in (None, ""):
                categories.add(str(category).casefold())
    return categories


def _select_mechanism_projections(
    projections: list[dict[str, object]], *, limit: int = 12,
) -> list[dict[str, object]]:
    """Keep a compact analyst view without starving a mechanism family.

    The immutable snapshot still contains every projection.  The bounded
    Markdown view reserves one slot for each available mechanism type before
    filling the remaining slots by priority/completeness.
    """
    if len(projections) <= limit:
        return list(projections)
    priority_order = (
        "PROCESS_EXECUTION",
        "THREAD_CALLBACK",
        "DECODE_CONFIG",
        "DYNAMIC_API_RESOLUTION",
        "PPID_SPOOFING",
        "SHELL_OUTPUT",
        "HTTP_DOWNLOAD",
        "NETWORK_DOWNLOAD",
        "MEMORY_PERMISSION_CHANGE",
        "ENVIRONMENT_CHECK",
        "INDIRECT_API_DISPATCH",
        "DECODE_TRANSFORM",
    )
    selected: list[dict[str, object]] = []
    selected_ids: set[str] = set()
    by_type: dict[str, list[dict[str, object]]] = {}
    for row in projections:
        by_type.setdefault(str(row.get("mechanism_type", "UNKNOWN")).upper(), []).append(row)
    for mechanism_type in priority_order:
        candidates = by_type.get(mechanism_type, [])
        if not candidates:
            continue
        row = candidates[0]
        row_id = str(row.get("mechanism_id", id(row)))
        if row_id not in selected_ids:
            selected.append(row)
            selected_ids.add(row_id)
        if len(selected) >= limit:
            return selected[:limit]
    for row in projections:
        row_id = str(row.get("mechanism_id", id(row)))
        if row_id in selected_ids:
            continue
        selected.append(row)
        selected_ids.add(row_id)
        if len(selected) >= limit:
            break
    return selected


def build_observed_mechanism_projections(
    evidence_by_id: Mapping[str, Any],
) -> list[dict[str, object]]:
    """Turn high-value observed static facts into analyst-readable candidates.

    These rows are deliberately *not* verifier findings.  They are the bridge
    between the disassembler's typed observations and the report's mechanism
    view, so a sample with no closed Claim still explains the concrete path,
    function/RVA and remaining static boundary instead of falling back to a
    list of imports or generic action labels.
    """
    projections: list[dict[str, object]] = []

    def read(item: Any, key: str, default: object = None) -> object:
        if isinstance(item, Mapping):
            return item.get(key, default)
        return getattr(item, key, default)

    def text_list(value: object) -> list[str]:
        if isinstance(value, (list, tuple, set)):
            return [str(item) for item in value if str(item).strip()]
        if value not in (None, ""):
            return [str(value)]
        return []

    for evidence_id, item in evidence_by_id.items():
        kind = str(read(item, "kind", "")).casefold()
        if kind not in _OBSERVED_MECHANISM_KINDS:
            continue
        value = read(item, "value", {})
        value = value if isinstance(value, Mapping) else {}
        anchor = read(item, "anchor", {})
        anchor = anchor if isinstance(anchor, Mapping) else {}
        # Some normalizers emit a file-level mechanism row and put the
        # function-level observations in ``source_evidence_ids``.  Recover
        # those anchors before constructing the analyst projection; otherwise
        # an actionable resolver or decode fact is rendered at RVA unknown.
        source_ids = [str(source_id) for source_id in text_list(value.get("source_evidence_ids"))]
        source_rows = [evidence_by_id[source_id] for source_id in source_ids if source_id in evidence_by_id]

        def source_value(key: str, *fallback_keys: str) -> object:
            keys = (key, *fallback_keys)
            for candidate in keys:
                direct = anchor.get(candidate)
                if direct not in (None, ""):
                    return direct
                direct = value.get(candidate)
                if direct not in (None, ""):
                    return direct
            for source in source_rows:
                source_anchor = read(source, "anchor", {})
                source_anchor = source_anchor if isinstance(source_anchor, Mapping) else {}
                source_data = read(source, "value", {})
                source_data = source_data if isinstance(source_data, Mapping) else {}
                for candidate in keys:
                    candidate_value = source_anchor.get(candidate)
                    if candidate_value not in (None, ""):
                        return candidate_value
                    candidate_value = source_data.get(candidate)
                    if candidate_value not in (None, ""):
                        return candidate_value
            return None

        chain_type = str(value.get("chain_type") or kind).strip()
        catalog_id = ""
        if kind == "function_semantic_summary":
            catalog_id, mechanism_type = _catalog_from_semantic_calls(value.get("call_sequence"))
        else:
            mechanism_type = {
                "mechanism_chain": chain_type.upper(),
                "cross_function_chain": "CROSS_FUNCTION_CHAIN",
                "mechanism_decode_window": "DECODE_TRANSFORM",
                "mechanism_memory_permission": "MEMORY_PERMISSION_CHANGE",
                "mechanism_environment_check": "ENVIRONMENT_CHECK",
                "mechanism_dynamic_resolution": "DYNAMIC_API_RESOLUTION",
                "indirect_function_pointer_link": "INDIRECT_API_DISPATCH",
                "resolved_api": "DYNAMIC_API_RESOLUTION",
            }[kind]
        function = str(source_value("function", "name") or "").strip()
        function_entry = str(
            source_value("function_entry", "entry", "entry_rva") or ""
        ).strip()
        if not function and function_entry:
            function = f"FUN_{function_entry}"
        rva = source_value("rva", "entry_rva")
        location = _format_function_location(function or "function", function_entry or "RVA unknown")

        steps = value.get("steps") if isinstance(value.get("steps"), list) else []
        step_names = [
            str(step.get("name") or step.get("api") or step.get("operation"))
            for step in steps
            if isinstance(step, Mapping) and (step.get("name") or step.get("api") or step.get("operation"))
        ]
        calls = text_list(value.get("calls"))
        apis = text_list(value.get("apis"))
        categories = _mechanism_categories(value, steps)
        nature = str(read(item, "nature", "STATIC_OBSERVED") or "STATIC_OBSERVED").upper()

        resolver_callsites: list[str] = text_list(value.get("resolver_callsites"))
        consumer_callsites: list[str] = text_list(value.get("consumer_callsites"))
        for key, target in (("resolver_callsite", resolver_callsites), ("consumer_callsite", consumer_callsites)):
            direct_callsite = value.get(key)
            if direct_callsite not in (None, ""):
                target.append(str(direct_callsite))
        resolver_tokens = {"getprocaddress", "ldrgetprocedureaddress", "loadlibrarya", "loadlibraryw"}
        consumer_tokens = {"winhttpopen", "winhttpsendrequest", "winhttpreceiveresponse"}
        for source in source_rows:
            source_value_map = read(source, "value", {})
            if not isinstance(source_value_map, Mapping):
                continue
            for key, target in (("resolver_callsite", resolver_callsites), ("consumer_callsite", consumer_callsites)):
                candidate = source_value_map.get(key)
                if candidate not in (None, ""):
                    target.append(str(candidate))
            nested_rows: list[object] = []
            for key in ("call_targets", "calls", "references_from", "call_sequence"):
                nested = source_value_map.get(key)
                if isinstance(nested, (list, tuple)):
                    nested_rows.extend(nested)
            for call in nested_rows:
                if not isinstance(call, Mapping):
                    continue
                api = str(call.get("target_name") or call.get("target_function") or call.get("api") or "").casefold()
                address = call.get("from") or call.get("address") or call.get("callsite")
                if address in (None, ""):
                    continue
                if api in resolver_tokens:
                    resolver_callsites.append(str(address))
                if api in consumer_tokens:
                    consumer_callsites.append(str(address))
        resolver_callsites = list(dict.fromkeys(resolver_callsites))[:8]
        consumer_callsites = list(dict.fromkeys(consumer_callsites))[:8]

        if kind == "cross_function_chain":
            functions = text_list(value.get("functions"))
            chain_categories = text_list(value.get("categories"))
            transformation = " -> ".join(chain_categories or ["bounded call-graph path"])
            inputs = ["bounded recovered inter-function call graph"]
            outputs = ["downstream mechanism categories recovered along the path"]
            consumers = [functions[-1]] if functions else ["downstream function not recovered"]
            side_effect = "may connect distinct capability functions; branch reachability and runtime execution are unobserved"
            function = " -> ".join(functions) if functions else function
            # The chain already carries its full function path; attaching the
            # first symbolic name as an RVA would create a misleading
            # ``FUN_A -> FUN_B@FUN_A`` locator.
            function_entry = ""
            location = function or "call-graph path"
        elif kind == "mechanism_chain":
            chain = list(dict.fromkeys(step_names))
            transformation = " -> ".join(chain[:12]) or chain_type.replace("_", " ")
            # Older evidence producers used ``network_download`` for both
            # HTTP transport and a CreateProcess/ReadFile stdout pipe.  A
            # call name alone is insufficient: require the typed categories
            # to distinguish a pipe from a real network transport path.
            has_network = any(token in categories for token in {"network", "network_io", "transport"})
            has_execution = any(token in categories for token in {"execution", "process", "process_creation"})
            has_file_io = any(token in categories for token in {"file_io", "file", "filesystem"})
            pipe_chain = has_execution and has_file_io and not has_network
            if chain_type.casefold() == "network_download" and pipe_chain:
                mechanism_type = "SHELL_OUTPUT"
                # The legacy chain label is occasionally attached to a
                # CreateProcess/ReadFile pipe path.  Keep the observed calls,
                # but describe the evidence-supported pipe semantics instead
                # of claiming that a network transfer was observed.
                inputs = ["child-process handle or redirected pipe"]
                outputs = ["captured stdout/stderr bytes"]
                side_effect = "may capture child-process output; network transfer and process success are unobserved"
            elif chain_type.casefold() == "network_download" and has_network:
                mechanism_type = "NETWORK_DOWNLOAD"
                inputs = [
                    "network request inputs and transport state (concrete values may be unresolved)"
                ]
                outputs = ["response bytes or downstream file/execute consumer"]
                side_effect = "may transfer data or materialize a downstream artifact; network access and success are unobserved"
            else:
                inputs = [
                    "source bytes/file handle before transformation"
                    if any("file" in name.casefold() or "read" in name.casefold() for name in chain)
                    else "function inputs (concrete values not recovered)"
                ]
                outputs = [
                    "resolved module/function or downstream operation"
                    if any(name.casefold() in {"loadlibrarya", "loadlibraryw", "getprocaddress"} for name in chain)
                    else "intermediate result consumed by the same function"
                ]
                side_effect = "may materialize a loader/transport/execution path; runtime reachability is unobserved"
            consumers = [name for name in chain[-4:] if name]
        elif kind == "mechanism_decode_window":
            algorithm = str(value.get("algorithm") or "decode candidate")
            loop_count = value.get("xor_count") or value.get("loop_branch_count")
            key_candidates = text_list(value.get("key_candidates"))
            transformation = f"{algorithm}"
            if loop_count:
                transformation += f" ({loop_count} transform/loop indicators)"
            inputs = ["buffer referenced by the instruction window"]
            if key_candidates:
                inputs.append(f"key candidates: {', '.join(key_candidates[:4])}")
            outputs = ["transformed buffer candidate"]
            consumers = ["downstream consumer not recovered"]
            side_effect = "may prepare decoded/decrypted data; decoded output was not observed"
        elif kind == "mechanism_memory_permission":
            api = str(value.get("api") or "VirtualProtect")
            transformation = f"{api} -> {value.get('protection') or 'protection change candidate'}"
            inputs = ["target memory region (address not recovered)"]
            outputs = ["memory protection state candidate"]
            consumers = [api]
            side_effect = "may make a region writable/executable; no memory write was executed"
        elif kind == "mechanism_environment_check":
            transformation = " -> ".join(apis or calls[:8]) or "environment query"
            inputs = ["process/environment state"]
            outputs = ["branch decision based on queried state"]
            consumers = ["conditional branch in the anchored function"]
            side_effect = "may alter analysis/runtime path based on environment checks"
        elif kind == "mechanism_dynamic_resolution":
            if apis:
                transformation = " -> ".join(apis)
                inputs = ["module name and exported entry-point name"]
            else:
                transformation = "UNKNOWN(resolver API identity)"
                inputs = ["UNKNOWN(module name and exported entry-point name)"]
            outputs = ["resolved function pointer"]
            consumers = ["UNKNOWN(indirect call/jump consumer)"]
            side_effect = "may hide API imports from the static import table; runtime resolution is unobserved"
        elif kind == "resolved_api":
            resolver = str(value.get("resolver") or "").strip() or "resolver identity not recovered"
            api_name = str(value.get("api_name") or value.get("api") or "unresolved API")
            consumer = str(value.get("consumer") or "indirect CALL/JMP consumer not recovered")
            resolver_callsite = value.get("resolver_callsite") or "callsite unknown"
            consumer_callsite = value.get("consumer_callsite")
            transformation = f"{resolver}({api_name}) @ {resolver_callsite}"
            if consumer_callsite:
                transformation += f" -> indirect consumer @ {consumer_callsite}"
            inputs = [
                f"procedure-name argument recovered as {api_name}",
                "module handle / resolver context (module may remain unresolved)",
            ]
            outputs = ["function pointer for the recovered API"]
            consumers = [consumer]
            side_effect = "supports a hidden-import/API-dispatch path; invocation success and runtime reachability are unobserved"
        elif kind == "function_semantic_summary":
            how = _how_from_semantic_payload(value)
            formatted = [
                item
                for item in (
                    _format_semantic_call(call)
                    for call in (value.get("call_sequence") or [])
                    if isinstance(call, Mapping)
                )
                if item
            ]
            transformation = how or " -> ".join(formatted[:12]) or "static decompile path recovered"
            inputs = [
                str(item.get("value") or "")
                for item in (value.get("inputs") or [])
                if isinstance(item, Mapping) and item.get("value") not in (None, "")
            ][:8] or ["function inputs recovered from decompile"]
            outputs = formatted[-3:] or ["ordered static call sequence"]
            consumers = [
                str(item.get("api") if isinstance(item, Mapping) else item)
                for item in (value.get("consumers") or [])[:6]
                if str(item.get("api") if isinstance(item, Mapping) else item).strip()
            ] or formatted[-2:] or ["downstream consumer not recovered"]
            side_effect = str(
                value.get("boundary")
                or "static reconstruction only; runtime reachability and side effects are unobserved"
            )
            nested_function = value.get("function")
            if isinstance(nested_function, Mapping):
                function = str(nested_function.get("name") or function)
            elif str(nested_function or "").strip():
                function = str(nested_function)
            function_entry = str(value.get("function_entry") or value.get("entry") or function_entry)
            location = _format_function_location(function or "function", function_entry or "RVA unknown")
        else:
            resolver = str(value.get("resolver") or "GetProcAddress")
            consumer = str(value.get("consumer") or "indirect CALL/JMP")
            storage = str(value.get("storage") or "temporary storage")
            transformation = f"{resolver} @ {value.get('resolver_callsite', 'callsite')} -> {storage} -> {consumer} @ {value.get('consumer_callsite', 'callsite')}"
            inputs = ["module/entry-point identity supplied to the resolver"]
            outputs = ["function pointer stored in register or memory"]
            consumers = [consumer]
            side_effect = "may dispatch to an API without a direct import; target API identity is unresolved statically"

        # Resolver and pointer evidence may be attached to a file-level
        # observation rather than the row itself. Preserve those exact static
        # locations in HOW so the analyst can jump directly to the producer
        # and consumer callsites.
        if resolver_callsites and mechanism_type in {"DYNAMIC_API_RESOLUTION", "INDIRECT_API_DISPATCH"}:
            transformation += " | resolver callsite=" + ", ".join(resolver_callsites)
        if consumer_callsites and mechanism_type in {"DYNAMIC_API_RESOLUTION", "INDIRECT_API_DISPATCH"}:
            transformation += " | consumer callsite=" + ", ".join(consumer_callsites)

        source_ids = [str(evidence_id)]
        source_ids.extend(str(item_id) for item_id in text_list(value.get("source_evidence_ids")))
        projection = {
            "type": "mechanism_observation",
            "mechanism_id": f"observed-mechanism:{str(evidence_id)}",
            "mechanism_type": mechanism_type,
            "catalog_id": catalog_id or None,
            "dimension": mechanism_type,
            "artifact_id": str(read(item, "artifact_id", "") or "") or None,
            "status": "CANDIDATE",
            "target": location,
            "function": function or None,
            "function_entry": function_entry or None,
            "rva": rva,
            "inputs": inputs,
            "transformation_or_control": [transformation],
            "conditions": [
                (
                    "static observed evidence; runtime reachability and intent are unobserved"
                    if nature.startswith("STATIC")
                    else f"{nature} evidence; reachability, intent, and complete execution context remain bounded"
                )
            ],
            "outputs": outputs,
            "consumers": consumers,
            "side_effects": [side_effect],
            "evidence_ids": list(dict.fromkeys(source_ids))[:12],
            "resolver_callsites": resolver_callsites,
            "consumer_callsites": consumer_callsites,
            "confidence": str(value.get("confidence") or "MEDIUM").upper(),
            "verification": value.get("verification") or value.get("verification_result") or "structural static observation only",
            "alternative_hypotheses": [
                "benign/library use or dead code",
                "unresolved static data/control-flow path",
            ],
            "unknowns": [
                "runtime execution and final data values",
                "target identity or downstream success where not recovered",
            ],
            "limitations": [
                "derived from observed static facts; no sample execution or sample network access"
            ],
            "provenance": {
                "observation_evidence_id": str(evidence_id),
                "source_kind": kind,
                "nature": nature,
                "categories": sorted(categories),
                "anchor": dict(anchor),
            },
        }
        if nature.startswith("DYNAMIC"):
            projection["conditions"] = [
                "dynamic observed evidence; sample execution context, reachability, and intent remain bounded"
            ]
            projection["limitations"] = [
                "derived from runtime observation; static causality and complete input/output values may remain unresolved"
            ]
        projection["ordered"] = bool(
            (kind == "mechanism_chain" and len(step_names) >= 2)
            or (kind == "cross_function_chain" and len(text_list(value.get("functions"))) >= 2)
        )
        projection["observation_nature"] = nature
        projection["completeness"] = mechanism_completeness_score(projection)
        projections.append(projection)
    # Keep one analyst-facing row for identical observations, but merge every
    # source id/callsite into that row.  Earlier code dropped duplicate rows
    # wholesale, which made a concise projection look complete while hiding
    # corroborating Evidence links from the report reader.
    deduped: list[dict[str, object]] = []
    by_key: dict[tuple[object, ...], dict[str, object]] = {}
    for row in projections:
        key = (
            # Mechanism identity is scoped to an Artifact.  Without this
            # boundary, equivalent observations from two contained samples
            # merge into one row and a verified mechanism on one Artifact can
            # suppress evidence belonging to the other.
            row.get("artifact_id"), row.get("mechanism_type"), row.get("target"),
            tuple(row.get("transformation_or_control", [])),
            tuple(row.get("consumers", [])),
        )
        existing = by_key.get(key)
        if existing is not None:
            for field in ("evidence_ids", "resolver_callsites", "consumer_callsites"):
                merged = list(dict.fromkeys([
                    *(
                        existing.get(field, [])
                        if isinstance(existing.get(field), (list, tuple))
                        else []
                    ),
                    *(
                        row.get(field, [])
                        if isinstance(row.get(field), (list, tuple))
                        else []
                    ),
                ]))
                existing[field] = merged[:32]
            provenance = existing.get("provenance")
            if isinstance(provenance, Mapping):
                merged_observations = list(dict.fromkeys([
                    str(provenance.get("observation_evidence_id"))
                    if provenance.get("observation_evidence_id") else "",
                    *(
                        provenance.get("merged_observation_evidence_ids", [])
                        if isinstance(provenance.get("merged_observation_evidence_ids"), (list, tuple))
                        else []
                    ),
                    str((row.get("provenance") or {}).get("observation_evidence_id"))
                    if isinstance(row.get("provenance"), Mapping)
                    and (row.get("provenance") or {}).get("observation_evidence_id")
                    else "",
                ]))
                provenance["merged_observation_evidence_ids"] = [item for item in merged_observations if item][:32]
            continue
        by_key[key] = row
        deduped.append(row)
    priority = {
        "mechanism_chain": 0,
        "mechanism_decode_window": 1,
        "mechanism_dynamic_resolution": 2,
        "resolved_api": 2,
        "indirect_function_pointer_link": 3,
        "mechanism_memory_permission": 4,
        "mechanism_environment_check": 5,
    }
    deduped.sort(
        key=lambda row: (
            priority.get(str((row.get("provenance") or {}).get("source_kind", "")), 99),
            -int(row.get("completeness", 0) or 0),
        )
    )
    return deduped[:64]


def report_analytical_violations(
    document: dict[str, object],
    *,
    enforce_core_count: bool = False,
) -> list[str]:
    """Return hard Report V2 violations for security-finding provenance."""
    violations: list[str] = []
    findings: list[dict[str, object]] = []
    for module in document.get("modules", []):
        if not isinstance(module, dict):
            continue
        for row in module.get("rows", []):
            if isinstance(row, dict) and row.get("type") == "security_finding":
                findings.append(row)
    if enforce_core_count and not 5 <= len(findings) <= 15:
        violations.append(f"core finding count must be 5-15 (got {len(findings)})")
    for index, finding in enumerate(findings, start=1):
        for key in ("mechanism_id", "claim_id", "evidence_ids", "what", "how", "security_meaning", "boundary"):
            if not finding.get(key):
                violations.append(f"finding {index} missing {key}")
        verifier = finding.get("verifier", {})
        verifier_status = verifier.get("status", "") if isinstance(verifier, dict) else ""
        if str(verifier_status).upper() != "VERIFIED":
            violations.append(f"finding {index} is not backed by VERIFIED mechanism")
        if len(finding.get("evidence_ids", [])) > 5:
            violations.append(f"finding {index} exposes more than 5 supporting evidence items")
        if str(finding.get("security_meaning", "")).strip() == "Requires deterministic verification before escalation.":
            violations.append(f"finding {index} uses generic security meaning placeholder")
        if str(finding.get("action", "")).casefold() in {
            "prioritizes", "references", "matches", "calls", "contains_rva_level_call_sites",
        }:
            violations.append(f"finding {index} is navigation-only")
        completeness = finding.get("completeness")
        if completeness is not None:
            try:
                if float(completeness) >= 80 and (
                    not has_semantic_value("inputs", finding.get("inputs"))
                    or not has_semantic_value("consumers", finding.get("consumers"))
                ):
                    violations.append(f"finding {index} has unknown mandatory mechanism fields at high completeness")
            except (TypeError, ValueError):
                violations.append(f"finding {index} has invalid mechanism completeness")
    return violations


def report_v3_quality_violations(document: dict[str, object]) -> list[str]:
    """Validate the product-level Report V3 contract without judging prose."""
    violations: list[str] = []
    if str(document.get("report_version", "")) != "3.0":
        violations.append("report_version must be 3.0")
    if not document.get("analysis_class"):
        violations.append("analysis_class is required")
    if not isinstance(document.get("analysis_coverage"), dict):
        violations.append("analysis_coverage must be an object")
    if not document.get("case_id") or not document.get("task_id"):
        violations.append("case_id and task_id are required")
    module_rows = [
        row
        for module in document.get("modules", [])
        if isinstance(module, dict)
        for row in module.get("rows", [])
        if isinstance(row, dict)
    ]
    # BehaviorFinding is the canonical semantic report contract.  Validate it
    # here (rather than trusting the Markdown renderer) so an incomplete
    # projection cannot pass the same release gate as a complete finding.
    behavior_rows = [row for row in module_rows if row.get("type") == "behavior_finding"]
    for module in document.get("modules", []):
        if not isinstance(module, dict):
            continue
        for parent in module.get("rows", []):
            if not isinstance(parent, dict) or parent.get("type") != "analyst_assessment":
                continue
            nested = parent.get("findings", [])
            if isinstance(nested, list):
                behavior_rows.extend(
                    row for row in nested
                    if isinstance(row, dict) and row.get("type") == "behavior_finding"
                )
    seen_behavior_ids: set[str] = set()
    required_behavior_fields = (
        "finding_id", "what", "how", "target", "condition", "output", "consumer",
        "evidence_ids", "unknowns",
    )
    for index, finding in enumerate(behavior_rows, start=1):
        finding_id = str(finding.get("finding_id") or finding.get("id") or "")
        if finding_id and finding_id in seen_behavior_ids:
            continue
        if finding_id:
            seen_behavior_ids.add(finding_id)
        for key in required_behavior_fields:
            if key not in finding or not _report_has_value(finding.get(key)):
                violations.append(f"behavior finding {index} missing {key}")
        status = _report_status(finding.get("finding_status") or finding.get("status"))
        evidence_ids = _report_ids(finding.get("evidence_ids"))
        if status in _BEHAVIOR_CLOSED_STATUSES and not evidence_ids:
            violations.append(f"behavior finding {index} is closed without Evidence")
        # A closed status cannot be manufactured by a report projection.  A
        # candidate may carry a high model confidence, but it must remain a
        # candidate in the machine-readable row as well as in rendered text.
        if status in _BEHAVIOR_CLOSED_STATUSES and finding.get("verdict") == "CANDIDATE":
            violations.append(f"behavior finding {index} has conflicting candidate verdict")
    behavior_relation_rows = [row for row in module_rows if row.get("type") == "behavior_relation"]
    for index, relation in enumerate(behavior_relation_rows, start=1):
        if not _report_ids(relation.get("evidence_ids")) and not relation.get("claim_id"):
            violations.append(f"behavior relation {index} has no Evidence or Claim support")
    findings = [row for row in module_rows if row.get("type") == "security_finding"]
    for index, finding in enumerate(findings, start=1):
        if not finding.get("mechanism_id") or not finding.get("claim_id") or not finding.get("evidence_ids"):
            violations.append(f"core finding {index} is not fully traceable")

    # M06 is a bounded-readiness contract rather than a blanket requirement
    # that every draft report be complete.  A partial report may carry blocked
    # critic/S4 entries, but it must not advertise itself as complete or ready
    # for release.  Also reject a contradictory critic payload where the
    # structured check reports failures while claiming PASS.
    quality = document.get("analysis_quality")
    if isinstance(quality, dict):
        critic = quality.get("critic")
        if isinstance(critic, dict):
            overclaim_checks = critic.get("overclaim_checks")
            critic_status = str(critic.get("status") or "").upper()
            if isinstance(overclaim_checks, list) and overclaim_checks and critic_status == "PASS":
                violations.append("analysis_quality critic reports overclaim checks but status PASS")
            closed_overclaims: list[str] = []
            if isinstance(overclaim_checks, list):
                rows_by_id = {
                    str(
                        row.get("mechanism_id")
                        or row.get("finding_id")
                        or row.get("claim_id")
                        or row.get("relation_id")
                    ): row
                    for row in module_rows
                    if row.get("mechanism_id") or row.get("finding_id") or row.get("claim_id") or row.get("relation_id")
                }
                for item in overclaim_checks:
                    if not isinstance(item, dict):
                        continue
                    row = rows_by_id.get(str(item.get("row_id") or ""))
                    status = str((row or {}).get("status") or (row or {}).get("verdict") or (row or {}).get("finding_status") or "").upper()
                    if status in _BEHAVIOR_CLOSED_STATUSES:
                        closed_overclaims.append(str(item.get("row_id") or "row"))
            if closed_overclaims:
                violations.append(
                    "analysis_quality critic found overclaim checks on closed findings: "
                    + ", ".join(sorted(set(closed_overclaims))[:16])
                )

        s4_rows = quality.get("s4_orchestration")
        blocked_s4 = [
            str(row.get("thread_id") or "thread")
            for row in s4_rows
            if isinstance(row, dict) and str(row.get("status") or "").upper() == "BLOCKED"
        ] if isinstance(s4_rows, list) else []
        readiness = str(quality.get("readiness") or "").upper()
        outcome = str(document.get("analysis_outcome") or "").upper()
        if blocked_s4 and (readiness == "READY_FOR_REPORT" or outcome == "COMPLETE"):
            violations.append(
                "analysis_quality has blocked S4 threads but report is marked "
                + ("READY_FOR_REPORT" if readiness == "READY_FOR_REPORT" else "COMPLETE")
            )
        if isinstance(critic, dict) and str(critic.get("status") or "").upper() == "BLOCKED" and (
            readiness == "READY_FOR_REPORT" or outcome == "COMPLETE"
        ):
            violations.append("analysis_quality critic is BLOCKED but report is marked complete/ready")
        # M04: the readiness gate owns the "is this revision complete" claim.  A
        # document that carries the gate verdict cannot contradict it, whatever
        # stamped the outcome.
        gate = quality.get("readiness_gate")
        if isinstance(gate, dict):
            gate_status = str(gate.get("status") or "").upper()
            if gate_status in {"PARTIAL", "BOUNDED"} and (
                readiness == "READY_FOR_REPORT" or outcome == "COMPLETE"
            ):
                violations.append(
                    "M04 readiness gate is "
                    + gate_status
                    + " but report is marked "
                    + ("READY_FOR_REPORT" if readiness == "READY_FOR_REPORT" else "COMPLETE")
                    + "; publish it as PARTIAL/BOUNDED instead"
                )
        self_check = quality.get("m06_self_check")
        if isinstance(self_check, dict) and str(self_check.get("status") or "").upper() == "BLOCKED":
            downgraded = self_check.get("downgraded")
            if isinstance(downgraded, list) and not downgraded:
                violations.append(
                    "M06 self-check is BLOCKED but no conclusion was downgraded or kept UNKNOWN/CANDIDATE"
                )
    top_level_sections = document.get("report_sections")
    if isinstance(top_level_sections, list):
        sections = top_level_sections
    else:
        report_structure = next((row for row in module_rows if row.get("type") == "report_structure"), None)
        sections = report_structure.get("sections", []) if isinstance(report_structure, dict) else []
    if tuple(sections) != REPORT_V3_REQUIRED_SECTIONS:
        violations.append("Report V3 required sections are missing or reordered")
    return violations


_ONE_ROUND_HIGH_VALUE_CATALOG_IDS = frozenset(
    {
        "process-creation",
        "parent-process-spoofing",
        "network-transport",
        "loader-and-api-resolution",
        "config-and-crypto",
    }
)


def _iter_catalog_matrices(document: Mapping[str, object]) -> list[dict[str, object]]:
    matrices: list[dict[str, object]] = []
    for module in document.get("modules") or []:
        if not isinstance(module, Mapping):
            continue
        for row in module.get("rows") or []:
            if not isinstance(row, Mapping):
                continue
            if row.get("type") == "catalog_behavior_matrix":
                matrices.append(dict(row))
            nested = row.get("catalog_behavior_matrix")
            if isinstance(nested, Mapping) and (
                nested.get("type") == "catalog_behavior_matrix" or "discovered" in nested
            ):
                matrices.append(dict(nested))
    return matrices


def _persist_shape_in_what(text: object) -> bool:
    blob = str(text or "").casefold()
    return (
        "foxit" in blob
        or "command=" in blob
        or "command `" in blob
        or "creation_flags" in blob
    )


def _document_has_unknown_slots(document: Mapping[str, object], markdown: str = "") -> bool:
    blob = str(markdown or "")
    if "key unknowns" in blob.casefold() or "unknown(" in blob.casefold():
        return True
    for module in document.get("modules") or []:
        if not isinstance(module, Mapping):
            continue
        for row in module.get("rows") or []:
            if not isinstance(row, Mapping):
                continue
            if row.get("key_unknowns"):
                return True
            summary = str(row.get("summary") or "")
            if "key unknowns" in summary.casefold() or "unknown(" in summary.casefold():
                return True
            if row.get("unknowns"):
                return True
            findings = row.get("findings")
            if isinstance(findings, list):
                for finding in findings:
                    if isinstance(finding, Mapping) and finding.get("unknowns"):
                        return True
    return False


def _one_round_readiness_notes(document: Mapping[str, object], markdown: str = "") -> list[str]:
    notes: list[str] = []
    has_unknowns = _document_has_unknown_slots(document, markdown)
    for matrix in _iter_catalog_matrices(document):
        for row in matrix.get("discovered") or []:
            if not isinstance(row, Mapping):
                continue
            catalog_id = str(row.get("catalog_id") or "")
            if catalog_id not in _ONE_ROUND_HIGH_VALUE_CATALOG_IDS:
                continue
            how = str(row.get("how") or "").strip()
            if how and how.casefold() != "not recovered":
                continue
            if has_unknowns:
                notes.append(
                    f"{catalog_id} How is empty or not recovered; recorded as a Key unknowns note"
                )
            else:
                notes.append(f"{catalog_id} How is empty or not recovered")
    return list(dict.fromkeys(notes))


def _assessment_how_texts(document: Mapping[str, object], markdown: str = "") -> list[str]:
    """Executive How bodies from assessment rows and leftover markdown."""
    texts: list[str] = []
    for module in document.get("modules") or []:
        if not isinstance(module, Mapping):
            continue
        for row in module.get("rows") or []:
            if not isinstance(row, Mapping) or row.get("type") != "assessment":
                continue
            summary = str(row.get("summary") or "")
            if "How:" in summary:
                texts.append(summary.split("How:", 1)[-1].split("Key unknowns:", 1)[0])
    for line in str(markdown or "").splitlines():
        if "How:" in line:
            texts.append(line.split("How:", 1)[-1].split("Key unknowns:", 1)[0])
            break
    return texts


def _executive_cover_texts(document: Mapping[str, object], markdown: str = "") -> list[str]:
    """Full Executive Assessment prose, including Mechanism chain after How."""
    texts = list(_assessment_how_texts(document, markdown))
    for module in document.get("modules") or []:
        if not isinstance(module, Mapping):
            continue
        for row in module.get("rows") or []:
            if not isinstance(row, Mapping) or row.get("type") != "assessment":
                continue
            summary = str(row.get("summary") or "").strip()
            if summary:
                texts.append(summary)
    blob = str(markdown or "")
    if "## 1. Executive Assessment" in blob:
        texts.append(blob.split("## 1. Executive Assessment", 1)[1].split("## 2.", 1)[0])
    return texts


def report_one_round_readiness_violations(
    document: dict[str, object],
    markdown: str = "",
) -> list[str]:
    """Kunglao summary_discriminator mapping: leftover dump vs persist, not a raise-gate.

    Empty high-value How is a note when UNKNOWN slots exist and must not reject
    the document. Callers stamp results onto analysis_quality; they must not add
    these strings to _create_report_revision's raise list.
    """
    violations: list[str] = []
    discovered: list[Mapping[str, object]] = []
    for matrix in _iter_catalog_matrices(document):
        for row in matrix.get("discovered") or []:
            if isinstance(row, Mapping):
                discovered.append(row)
    named_ids = [
        str(row.get("catalog_id") or "")
        for row in discovered
        if str(row.get("catalog_id") or "") not in {"", "unique-or-unknown", "unknown"}
    ]
    if named_ids and any(str(row.get("catalog_id") or "") == "unique-or-unknown" for row in discovered):
        violations.append(
            "unique-or-unknown remains in discovered catalog while a named catalog_id exists"
        )
    for row in discovered:
        catalog_id = str(row.get("catalog_id") or "")
        how = str(row.get("how") or "")
        what = str(row.get("what") or "")
        if catalog_id == "process-creation" and _is_fun_call_sequence_dump(how) and (
            _persist_shape_in_what(what) or _persist_argument_how(what)
        ):
            violations.append(
                "process-creation How contains a FUN_*/ShellExecuteW/GetEnvironmentStringsW "
                "decompile dump over persist Foxit/command/creation_flags What"
            )
        if catalog_id == "parent-process-spoofing" and _is_fun_call_sequence_dump(how):
            violations.append(
                "parent-process-spoofing How is a FUN_* call-sequence dump, "
                "not typed attribute/parent"
            )
        if catalog_id == "loader-and-api-resolution" and _is_fun_call_sequence_dump(how):
            violations.append(
                "loader-and-api-resolution How is a FUN_* decompile dump, "
                "not named API+consumer"
            )
    for cover in _executive_cover_texts(document, markdown):
        if _is_fun_call_sequence_dump(cover):
            violations.append(
                "executive cover contains a FUN_* call-sequence dump over persist process"
            )
            break
    return list(dict.fromkeys(violations))


def _stamp_one_round_readiness(document: dict[str, object], markdown: str = "") -> None:
    """Stamp readiness onto the document so PARTIAL reports still emit."""
    violations = report_one_round_readiness_violations(document, markdown)
    notes = _one_round_readiness_notes(document, markdown)
    payload: dict[str, object] = {
        "complete": not violations,
        "violations": violations,
    }
    if notes:
        payload["notes"] = notes
    quality = document.get("analysis_quality")
    if not isinstance(quality, dict):
        quality = {}
        document["analysis_quality"] = quality
    quality["one_round_readiness"] = payload
    for module in document.get("modules") or []:
        if not isinstance(module, dict):
            continue
        for row in module.get("rows") or []:
            if isinstance(row, dict) and row.get("type") == "analysis_quality":
                row["one_round_readiness"] = payload


def core_finding_mechanism_coverage(document: dict[str, object]) -> float:
    """Return the proportion of core findings with complete traceability."""
    findings = [
        row
        for module in document.get("modules", [])
        if isinstance(module, dict)
        for row in module.get("rows", [])
        if isinstance(row, dict) and row.get("type") == "security_finding"
    ]
    if not findings:
        return 1.0
    valid = sum(
        bool(row.get("mechanism_id") and row.get("claim_id") and row.get("evidence_ids"))
        for row in findings
    )
    return valid / len(findings)

MODULE_TITLES = {
    "executive_summary": "执行摘要",
    "input_manifest": "输入清单与隔离状态",
    "artifact_inventory": "样本与组件清单",
    "static_triage": "静态分诊",
    "decryption": "解密与解码分析",
    "loader": "加载器与加载链分析",
    "c2_network": "C2 与网络分析",
    "anti_analysis": "反分析能力",
    "behavior_attack": "行为与 ATT&CK 映射",
    "attribution": "证据聚合与归因",
    "evidence_ledger": "证据账本",
    "limitations": "分析限制与审计摘要",
}


def normalize_modules(selected: list[str] | None) -> list[str]:
    if not selected:
        return list(REPORT_MODULES)
    invalid = sorted(set(selected) - set(REPORT_MODULES))
    if invalid:
        raise ValueError(f"Unknown report modules: {', '.join(invalid)}")
    selected_set = set(selected)
    return [module for module in REPORT_MODULES if module in selected_set]


def _prose_limit(value: object, limit: int = 1200) -> str:
    """Render HOW/what as analyst prose, not a JSON dump of a list."""
    if isinstance(value, (list, tuple)):
        parts = [
            str(item).strip()
            for item in value
            if str(item).strip() and not str(item).strip().startswith("UNKNOWN(")
        ]
        text = "; ".join(parts)
    else:
        text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _short(value: object, limit: int = 280) -> str:
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return rendered if len(rendered) <= limit else rendered[: limit - 3] + "..."


def _module(
    module_id: str,
    summary: str,
    rows: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    materialized_rows = rows or []
    return {
        "id": module_id,
        "title": MODULE_TITLES.get(module_id, module_id),
        "summary": summary,
        "analysis_status": (
            "COMPLETED_WITH_FINDINGS" if materialized_rows else "COMPLETED_NO_FINDINGS"
        ),
        "finding_count": len(materialized_rows),
        "rows": materialized_rows,
    }


_STRING_FACT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("motw", re.compile(r"Zone\.Identifier", re.IGNORECASE)),
    ("scheduled_task", re.compile(r"schtasks|registertaskdefinition", re.IGNORECASE)),
    ("remote_executable", re.compile(r"https?://\S+\.(?:exe|dll|ps1|bat|cmd|vbs|js|scr)\b", re.IGNORECASE)),
    ("remote_url", re.compile(r"https?://\S+", re.IGNORECASE)),
    ("registry", re.compile(r"SOFTWARE\\|SYSTEM\\|HKEY_", re.IGNORECASE)),
    ("temp_path", re.compile(r"\.tmp\b|%TEMP%|%TMP%|\\Temp\\", re.IGNORECASE)),
    ("user_agent", re.compile(r"Mozilla/|User-Agent", re.IGNORECASE)),
    # A resolver/recovery OUTCOME, not an API.  Measured on task `ce7e310e`: the string layer holds
    # `WinHTTP export not found`, and classifying it as `download_api` published it in the body's API
    # list as if it were an API the sample calls - the product's own dynamic-resolution failure
    # rendered as a capability.  It MUST stay before `download_api`: `string_fact_class` returns the
    # first match, and the first draft of this pattern sat after it, so the wrong class silently won.
    ("resolution_failure", re.compile(
        r"\bexport not found\b|\b(?:GetProcAddress|LoadLibrary)\b[^\r\n]{0,40}\bfailed\b|"
        r"\bnot found\b[^\r\n]{0,20}\b(?:export|symbol|procedure|import)\b|"
        r"\b(?:failed|failure)\b[^\r\n]{0,20}\b(?:resolve|resolv|lookup)\b",
        re.IGNORECASE,
    )),
    ("download_api", re.compile(r"WinHttp|InternetOpen|URLDownloadToFile|HttpSendRequest", re.IGNORECASE)),
    ("execution_api", re.compile(
        r"CreateProcess|ShellExecute|CreateThread|LoadLibrary|GetProcAddress|"
        # A SCRIPT HOST is an execution capability: `Wscript.Shell` + `.Exec`/`.Run` is how a dropper starts a
        # process without importing CreateProcess at all. Measured on the 白象 sample `64da3378` (task
        # `b482617e`): the raw string layer holds `Wscript.Shell`, `Exec` and `Status`, i.e. the sample
        # carries the wherewithal to run a command and report to the C2, and the published body's
        # 网络通信/执行 reading named no script host because `Wscript.Shell` matched no class and was dropped.
        #
        # The method forms carry a leading dot or an opening parenthesis on purpose. A first draft used a
        # bare `\bExec\b`, which matches the word "exec" inside any English sentence and would have labelled
        # ordinary prose as an execution API in every future report.
        r"Wscript\.Shell|WScript\.Shell|cscript\.exe|wscript\.exe|"
        r"\.Exec\b|\.Exec\(|\.Run\(|ShellExecuteEx|WinExec",
        re.IGNORECASE,
    )),
    # Toolchain provenance and loader dependencies.  Recognised because a sample's BUILD PATH
    # and the RUNTIME it will load are facts an analyst acts on, and they were reaching
    # evidence but not the published body: measured on a Visual Basic 6 sample (task
    # `6be962d4`) the extractor held `C:\NanoVB6\VB6.OLB`, `MSVBVM60.DLL`, `VBA6.DLL` and
    # `__vbaVarMove`, and the 5,611-character body contained none of them.  `compiler_fingerprint`
    # is deliberately narrow - the VB6 runtime's own symbols - so it identifies a toolchain
    # without turning every `_` -prefixed symbol into a "fact".
    ("build_path", re.compile(r"[A-Za-z]:\\[^\"'<>|]*\.(?:olb|lib|obj|pdb|def|idl|vcxproj|dsp|vbp)\b", re.IGNORECASE)),
    ("runtime_dependency", re.compile(r"\b(?:MSVBVM\d+|VBA\d|MSVCR\d+|MSVCP\d+|mscoree|python\d+|libgcc|libstdc\+\+|Qt\d?Core|node)\w*\.dll\b", re.IGNORECASE)),
    ("compiler_fingerprint", re.compile(r"__(?:vba|vba[A-Za-z]+)|EVENT_SINK_|ThunRTMain|MSVBVM", re.IGNORECASE)),
    # What the sample CALLS ITSELF, and the default window/control names its designer emitted.
    #
    # Measured on the 白象 sample `64da3378` (task `b482617e`): the binary is a Visual Basic 6 dropper whose
    # form caption is `Wallpaper Changer` and whose controls are the VB6 designer defaults `Form1` and
    # `Timer1`. The published 9,286-character body named none of them, so a reader could not see that the
    # sample presents itself as a wallpaper utility. The reference document for this campaign describes the
    # family as `轻量级APT` built on 简易社会工程学 - the pretext IS the analyst-relevant fact, and it was
    # recorded in the string layer and rendered nowhere.
    #
    # The label deliberately says "自述名称" rather than "冒充": a form caption is a claim by the sample, not
    # proof of impersonation, and stating the weaker true thing is the whole point of this product.
    #
    # The alternation is anchored and multi-token on purpose. A first draft listed bare `Form`, `Timer`,
    # `Label` and `Text`, which the class matcher would have applied to any string CONTAINING those words -
    # `Information` contains `Form` - so the class would have claimed product identities for unrelated text.
    # Each alternative here is the sample's own full caption or a `<Kind><Number>` designer default.
    ("self_declared_name", re.compile(
        r"^(?:Wallpaper|Screen\s?saver|Desktop)\s+(?:Changer|Switcher|Manager|Updater|Widget)$|"
        r"^[A-Za-z][A-Za-z0-9 ]{0,28}\s+(?:Changer|Updater|Installer|Setup|Optimizer|Booster|Activator|"
        r"Cleaner|Tweaker|Widget)$",
        re.IGNORECASE,
    )),
    ("designer_default_symbol", re.compile(
        r"^(?:Form|Timer|Command|Label|Frame|Picture|Option|Check|Combo|List|Drive|Dir|File|Menu|Shape|"
        r"Line|Image|Data|Text)\d+$",
        re.IGNORECASE,
    )),
    # A sample that carries another product's identity, and the document lures around it.  These are
    # placed last because the operational classes above are more specific, and they exist because
    # measured on task `ce7e310e` the accepted body named no identity at all: the binary is submitted
    # under a `.pdf.exe`-style name, carries a 876-byte `RT_VERSION` resource plus nine `RT_ICON`
    # entries,
    # and its string layer holds `Adobe Acrobat Reader DC 23.006.20380`, `AcroRd32.exe`,
    # `Adobe PDF Library`, `PDFNetC64.dll`, `PDF-1.7` and `%PDF-1.4` - with `Adobe` appearing 0 times
    # in the published body.  Impersonating a PDF reader while being delivered as a `.pdf.exe` is the
    # first thing an analyst triages, and the report could not state it.
    #
    # The classes are deliberately narrow: `_IMPOSTER_EXE_RE` requires a KNOWN product identity, so a
    # benign `C:\Windows\System32\kernel32.dll` stays unclassified rather than entering the body as a
    # claim about the sample.
    ("imposter_application", re.compile(
        # Narrow on purpose.  A first attempt listed bare `Edge`, which matched the Rust debug
        # assertion `assertion failed: edge.height == self.node.height - 1` and published that as
        # "the sample claims this identity" twice in the body.  Product names here are multi-token or
        # unambiguous; anything that is also an English word or a data-structure name is excluded.
        r"Adobe\s+(?:Acrobat|Reader|PDF)|Acrobat\s+Reader|AcroRd32|AcroCEF|AdobeARMservice|"
        r"Microsoft\s+(?:Office|Word|Excel|Outlook|Edge)|WinWord\.exe|PowerPoint|WordPad|"
        r"Oracle\s+Corporation|Java\(TM\)|Sun\s+Microsystems|Symantec|Kaspersky|TeamViewer|"
        r"AnyDesk|Google\s+Chrome|Mozilla\s+Firefox|OneDrive|Dropbox",
        re.IGNORECASE,
    )),
    ("imposter_executable", re.compile(
        r"[A-Za-z]:\\[^\"'<>|\r\n]*\.(?:exe|scr|com)\b|"
        r"\b(?:AcroRd32|AcroCEF|winword|excel|powerpnt|chrome|firefox|msedge|outlook)\.exe\b",
        re.IGNORECASE,
    )),
    ("document_lure", re.compile(
        r"PDF-\d\.\d|%PDF-|endstream|endobj|\bRT_VERSION\b|"
        r"\.(?:pdf|docx?|xlsx?|pptx?|rtf|odt)\b",
        re.IGNORECASE,
    )),
    ("document_library", re.compile(
        r"\b(?:PDFNet|PDFNetC\d*|AcroForm|Adobe\s+PDF\s+Library|Foxit|Nitro|poppler|mupdf|"
        r"libpdf|iText|PDFium)\w*\.?(?:dll)?\b",
        re.IGNORECASE,
    )),
)


def string_fact_class(text: object) -> str:
    """Classify a raw string's analyst value, or ``""`` when it is noise.

    Used to keep operationally significant strings visible in the bounded ledger
    view.  Returning a class does NOT promote the string to a claim: the ledger
    still reports it as ``kind=string`` with its own Evidence ID.
    """
    value = str(text or "").strip()
    if len(value) < 4:
        return ""
    for name, pattern in _STRING_FACT_PATTERNS:
        if pattern.search(value):
            return name
    return ""


def _string_fact_rank(row: Mapping[str, object]) -> tuple[int, int, str]:
    """Sort key that puts high-signal strings before disassembly byte noise."""
    raw = row.get("value")
    text = ""
    if isinstance(raw, Mapping):
        text = str(raw.get("text") or "")
    elif raw is not None:
        text = str(raw)
    fact = string_fact_class(text)
    order = [name for name, _ in _STRING_FACT_PATTERNS]
    return (
        0 if fact else 1,
        order.index(fact) if fact in order else len(order),
        text.casefold(),
    )


def build_string_fact_projection(
    evidence: Iterable[Any],
    *,
    limit: int = 24,
) -> list[dict[str, object]]:
    """Curated, deduplicated string facts for the analyst body.

    The sample's operationally significant strings - `:Zone.Identifier`, the
    scheduled-task blob, `.tmp`, the recovered user-agent, Defender registry
    keys - live only in the raw string layer.  The ledger view collapses its
    2,926 string rows into a single bounded group, and the renderer had no
    contract for raw strings at all, so none of them reached the published body
    even though every Evidence ID was in `trace.evidence_ids`.

    This projection is built from the Evidence rows themselves, so the value it
    publishes is the parser's own value.  When several strings classify the same
    way, the LONGEST wins: a shorter variant is a clipped prefix of the real blob,
    and publishing it would assert a string that does not exist in the binary.
    """
    by_class: dict[str, set[str]] = {}
    evidence_ids: dict[str, list[str]] = {}
    for item in evidence:
        row = _evidence_mapping(item)
        if str(row.get("kind") or "").casefold() != "string":
            continue
        value = row.get("value")
        text = ""
        if isinstance(value, Mapping):
            text = str(value.get("text") or "").strip()
        elif isinstance(value, str):
            text = value.strip()
        if not text:
            continue
        fact_class = string_fact_class(text)
        if not fact_class:
            continue
        by_class.setdefault(fact_class, set()).add(text)
        evidence_id = str(row.get("id") or row.get("evidence_id") or "")
        if evidence_id:
            evidence_ids.setdefault(text, [])
            if evidence_id not in evidence_ids[text]:
                evidence_ids[text].append(evidence_id)

    order = [name for name, _ in _STRING_FACT_PATTERNS]
    ranked: list[tuple[int, int, str, str, str]] = []
    for fact_class, values in by_class.items():
        class_index = order.index(fact_class) if fact_class in order else len(order)
        # Longest first, then drop any value that is merely a prefix of one already
        # kept.  Two rows can describe the same recovered string at different
        # truncations; publishing both makes the body assert a value that is not
        # in the binary.
        ordered = sorted(values, key=lambda item: (-len(item), item.casefold()))
        kept: list[str] = []
        for text in ordered:
            if any(other.startswith(text) for other in kept):
                continue
            kept.append(text)
        for text in kept:
            ranked.append((class_index, -len(text), text.casefold(), fact_class, text))
    ranked.sort()
    # Fair share across classes, with the leftover filled in rank order.
    #
    # MEASURED STARVATION. Ranking is (class order, longest first), and the class order is a priority list,
    # so a class that appears EARLY and has many members consumes the whole budget. On the 白象 sample
    # `64da3378` (task `b482617e`) the raw string layer holds 78 VB6 runtime symbols and exactly one
    # operational string, `Wscript.Shell`; `compiler_fingerprint` precedes `execution_api`, so all 24
    # published facts were compiler symbols and the section that exists to surface operational strings
    # surfaced none of them. The count fields said "classified_count 43 of 1034", which is true and still
    # does not tell a reader that the one interesting string was crowded out.
    #
    # Each class gets an equal share of the budget before any class gets a second round, so a large class
    # cannot hide a small one. This is the same shape as `_notable_imports`, which already had to stop 30
    # module-crowding imports from displacing everything else.
    order_index = {name: index for index, name in enumerate(order)}
    per_class: dict[str, list[tuple[int, int, str, str, str]]] = {}
    for entry in ranked:
        per_class.setdefault(entry[3], []).append(entry)
    class_sequence = sorted(per_class, key=lambda name: order_index.get(name, len(order)))
    quota = max(1, limit // max(1, len(class_sequence)))
    selected: list[tuple[int, int, str, str, str]] = []
    selected_keys: set[tuple[str, str]] = set()
    for name in class_sequence:
        for entry in per_class[name][:quota]:
            selected.append(entry)
            selected_keys.add((entry[3], entry[4]))
    if len(selected) < limit:
        for entry in ranked:
            if len(selected) >= limit:
                break
            if (entry[3], entry[4]) in selected_keys:
                continue
            selected.append(entry)
            selected_keys.add((entry[3], entry[4]))
    selected.sort()
    # The count fields must describe the WHOLE layer, so the true classified total is captured before the
    # selection replaces `ranked`. Reporting `len(selected)` there would have claimed the sample had exactly
    # 24 notable strings when it had 79 - the section's own honesty bound, defeated by its own selection.
    classified_total = len(ranked)
    ranked = selected[:limit]
    # The bound is recorded rather than left implicit.  The section header claims the values are
    # published 未改写、未截断, which is true of each VALUE - a clipped prefix of a longer blob is
    # never published - but NOT of the set: this projection keeps at most `limit`, and the whole
    # string layer is far larger (2,926 rows on task `ce7e310e`, of which 13 classified).  Stating the
    # three counts lets a reader tell "the sample has 13 notable strings" from "13 were shown".
    total_strings = 0
    for item in evidence:
        row = _evidence_mapping(item)
        if str(row.get("kind") or "").casefold() == "string":
            total_strings += 1
    out = [
        {
            "type": "string_fact",
            "fact_class": fact_class,
            "value": text,
            "evidence_ids": evidence_ids.get(text, [])[:4],
            "static_only": True,
            "boundary": "字符串存在于文件中；不表示该行为已在目标主机上发生。",
        }
        for _index, _length, _key, fact_class, text in ranked[:limit]
    ]
    if out:
        out[0]["published_count"] = len(out)
        out[0]["classified_count"] = classified_total
        out[0]["total_string_rows"] = total_strings
        out[0]["selection_limit"] = limit
    return out


def _summarize_evidence_rows(
    rows: list[dict[str, object]],
) -> list[dict[str, object]]:
    grouped: dict[tuple[object, ...], list[dict[str, object]]] = {}
    for row in rows:
        key = (
            row.get("artifact_id"),
            row.get("module"),
            row.get("kind"),
            row.get("nature"),
        )
        grouped.setdefault(key, []).append(row)

    summaries: list[dict[str, object]] = []
    # The ledger is an index, not a second evidence dump. Keep deterministic
    # representative samples while bounding the number of groups and IDs so a
    # large PE cannot make the primary report fail its own anti-bloat gate.
    for (artifact_id, module, kind, nature), group in list(grouped.items())[:96]:
        evidence_ids = [str(item["evidence_id"]) for item in group if item.get("evidence_id")]
        tool_run_ids = list(
            dict.fromkeys(str(item["tool_run_id"]) for item in group if item.get("tool_run_id"))
        )
        # A raw-string group can hold thousands of rows, so `group[:1]` showed one
        # arbitrary member: for task 1359f2a6 the single `string` group holds 2,926
        # rows and the sample was a disassembly fragment.  `:Zone.Identifier`, the
        # `schtasks` blob and `.tmp` were all in that group and none of them
        # reached the report.  Order high-signal strings first, then take a small
        # bounded sample so a defender sees the values that matter.
        if kind == "string":
            ordered = sorted(group, key=_string_fact_rank)
            sample_size = 12
        else:
            ordered = group
            sample_size = 1
        selected_samples = ordered[:sample_size]
        summaries.append(
            {
                "type": "evidence_group",
                "artifact_id": artifact_id,
                "module": module,
                "kind": kind,
                "nature": nature,
                "count": len(group),
                "tool_run_ids": tool_run_ids,
                "evidence_ids": evidence_ids[:5],
                "evidence_ids_truncated": len(evidence_ids) > 5,
                "samples": [
                    {
                        key: (_short(item[key], 240) if key == "value" else item[key])
                        for key in ("evidence_id", "value", "anchor")
                        if key in item
                    }
                    for item in selected_samples
                ],
                "samples_truncated": len(group) > len(selected_samples),
            }
        )
    if len(grouped) > len(summaries):
        summaries.append({
            "type": "evidence_group_overflow",
            "omitted_group_count": len(grouped) - len(summaries),
            "reason": "bounded primary report; query Evidence Explorer for the complete ledger",
        })
    return summaries


# How many evidence samples one claim row may carry into the report. The bound keeps the primary
# body readable; WHICH rows fill it is a separate decision (see `select_claim_evidence_samples`).
#
# 12 rather than 6, because with 5 API families tied at the same priority a 6-slot budget gives the
# fifth family nothing: measured on claim `ea919b46`, the depth-1/depth-2 passes hand every slot to
# `UpdateProcThreadAttribute`, `CreateProcessW`, `NtReadFile` and `OpenProcess` and `RegSetValueExW`'s
# 20 rows are starved. 12 lets each of the tied families publish its complete x64 register argument
# set, and the renderer already truncates to 16 samples per row, so this stays a bounded projection.
_CLAIM_EVIDENCE_SAMPLE_LIMIT = 12

# How many rows any one evidence group may contribute to that sample. Without it a single API fills
# every slot: claim `ea919b46` cites 35 `api_argument_trace` rows of which six are `CreateProcessW`.
# The value is 4 because a Windows x64 call recovers at most four register arguments (RCX/RDX/R8/R9),
# so a cap of 4 lets a group publish its COMPLETE argument set - `dwType = 0x4` is only meaningful
# next to the callsite it belongs to - while still leaving slots for other families.
_CLAIM_SAMPLE_PER_GROUP = 4

# Evidence kinds whose payload IS the join an analyst needs (a recovered argument, a decoded value,
# a mechanism link). A bare `string`/`xref`/`function_call` row is context, not a conclusion, so
# these are ranked ahead of them when the bound forces a choice.
_CLAIM_SAMPLE_PRIORITY: dict[str, int] = {
    "api_argument_trace": 100,
    "mechanism_dynamic_api_link": 96,
    "mechanism_http_transport_link": 96,
    "mechanism_decode_window": 94,
    "decode_result": 92,
    "value_flow": 90,
    "data_reference": 88,
    "resolved_api": 86,
    "api_argument_recovery": 84,
    "process_creation_flags": 82,
    "function_data_correlation": 80,
    "function_context": 70,
    "function_mechanism": 68,
    "function_instruction_window": 66,
    "code_api_call": 64,
    "function_call": 60,
    "string_semantics": 50,
    "string": 40,
    "xref": 30,
}


def select_claim_evidence_samples(
    evidence_ids: Sequence[str],
    evidence_by_id: Mapping[str, Any],
    *,
    limit: int = _CLAIM_EVIDENCE_SAMPLE_LIMIT,
) -> list[str]:
    """Choose which of a claim's cited evidence rows travel into the report document.

    MEASURED DEFECT. `_claim_row` published `evidence_ids[:6]` - a positional slice of the citation
    list. Measured on task `de738f12`: claims cite up to **75** evidence rows (35 of them
    `api_argument_trace`), the ledger holds 28 rows for `RegSetValueExW` of which 21 are cited and
    resolvable, and **0** reached the document. Whether the registry-write join survived was a
    position lottery against 75 candidates - and that join is exactly what the objective's R1 asks
    for ("注册表调用点↔键名/值名参数"). Same defect shape as `_summarize_evidence_rows` taking
    `group[:1]`, which lost `:Zone.Identifier` from a 2,926-row string group.

    A KIND rank is NOT enough, and the first version of this function proved it on the real data:
    claim `ea919b46` cites 35 `api_argument_trace` rows, so all 35 tied at the same priority, the
    tie-break fell back to citation order, and `UpdateProcThreadAttribute` plus five
    `CreateProcessW` rows took every slot while the registry traces sat at positions 29-33. Six
    facets of one API family is not a sample - it is the same lottery one level down.

    The selection takes at most ``_CLAIM_SAMPLE_PER_GROUP`` rows from any one bucket, walking buckets
    in rank order. That cap is what stops a single API from consuming the budget - measured on claim
    `ea919b46`, six `CreateProcessW` rows otherwise fill every slot - while a group that HAS only one
    or two rows still gets its full argument set published rather than a truncated half-fact. Six
    facets of one call is a sample of one; six different calls with one argument each states six
    half-facts. Two per call, across several calls, is the shape that is actually useful.
    """
    if limit <= 0:
        return []
    unique: list[str] = []
    seen: set[str] = set()
    for identifier in evidence_ids:
        text = str(identifier or "")
        if not text or text in seen:
            continue
        seen.add(text)
        unique.append(text)
    if len(unique) <= limit:
        return unique

    def identity(identifier: str) -> tuple[int, str]:
        """(negative priority, group key). Argument traces group by the API they trace."""
        item = evidence_by_id.get(identifier)
        kind = str(getattr(item, "kind", "") or "")
        priority = _CLAIM_SAMPLE_PRIORITY.get(kind, 10)
        value = getattr(item, "value", None)
        if kind == "api_argument_trace" and isinstance(value, Mapping):
            return (-priority, f"api:{str(value.get('api') or '')}")
        return (-priority, f"kind:{kind}")

    buckets: dict[tuple[int, str], list[str]] = {}
    order_index: dict[tuple[int, str], int] = {}
    for identifier in unique:
        key = identity(identifier)
        buckets.setdefault(key, []).append(identifier)
        order_index.setdefault(key, len(order_index))
    ordered = sorted(buckets.items(), key=lambda pair: (pair[0][0], order_index[pair[0]]))

    per_group = max(1, _CLAIM_SAMPLE_PER_GROUP)
    chosen: list[str] = []
    depth = 0
    while len(chosen) < limit:
        progressed = False
        for _key, members in ordered:
            if depth >= min(len(members), per_group):
                continue
            chosen.append(members[depth])
            progressed = True
            if len(chosen) >= limit:
                return chosen
        if not progressed:
            break
        depth += 1
    return chosen


def _claim_row(
    claim: Any,
    links_by_claim: dict[str, list[str]],
    evidence_by_id: dict[str, Any] | None = None,
) -> dict[str, object]:
    """Render a Claim as an analyst finding instead of a database record."""
    evidence_ids = links_by_claim.get(claim.id, [])
    evidence_by_id = evidence_by_id or {}
    evidence_samples = []
    for evidence_id in select_claim_evidence_samples(evidence_ids, evidence_by_id):
        item = evidence_by_id.get(evidence_id)
        if item is None:
            continue
        evidence_samples.append({
            "evidence_id": evidence_id,
            "kind": item.kind,
            "value": item.value,
            "anchor": item.anchor,
        })
    attack_mapping = getattr(claim, "attack_mapping", {}) or {}
    attack_techniques = [
        {
            "technique_id": item.get("technique_id"),
            "name": item.get("technique_name"),
            "status": item.get("status", "candidate"),
            "confidence": item.get("confidence", getattr(claim, "confidence", "LOW")),
            "evidence_count": len(item.get("evidence_ids", [])),
        }
        for item in attack_mapping.get("mappings", [])
        if isinstance(item, dict) and item.get("technique_id")
    ]
    row = {
        "type": "analytical_claim",
        "module": claim.module,
        "claim_id": claim.id,
        "analysis_source": (
            "model" if getattr(claim, "model_call_id", None) else "deterministic_static_rules"
        ),
        "model_call_id": getattr(claim, "model_call_id", None),
        "finding": claim.statement,
        "what": claim.statement,
        "how": claim.mechanism,
        "subject": claim.subject,
        "action": claim.action,
        "object": claim.object,
        "mechanism": claim.mechanism,
        "condition": claim.condition,
        "status": claim.status,
        "confidence": claim.confidence,
        "evidence_ids": evidence_ids,
        "evidence_count": len(evidence_ids),
        "evidence_samples": evidence_samples,
        "attack_mapping": attack_mapping,
        # Keep the identifiers visible in rendered reports.  The full mapping
        # remains available for machine consumers, while this compact view is
        # not lost to the Markdown field-length guard.
        "attack_techniques": attack_techniques,
    }
    return _apply_name_only_seed_downgrades([row])[0]


def _build_investigation_timeline(
    *, claims: list[Any], evidence: list[Any], relations: list[Any], task: Any,
    links_by_claim: dict[str, list[str]]
) -> list[dict[str, object]]:
    """Render an auditable event sequence, never private model reasoning."""
    timeline: list[dict[str, object]] = []
    strategy = task.strategy_snapshot if isinstance(getattr(task, "strategy_snapshot", None), dict) else {}
    investigation = strategy.get("investigation", {}) if isinstance(strategy, dict) else {}
    for ranking in investigation.get("seed_rankings", []) if isinstance(investigation, dict) else []:
        if isinstance(ranking, dict):
            timeline.append({
                "phase": "DISCOVERED->PRIORITIZED",
                "artifact_id": ranking.get("artifact_id"),
                "priority": ranking.get("priority"),
                "question": ranking.get("question"),
                "rationale": ranking.get("rationale"),
            })
    # Seed clusters are the bounded bridge from raw observations to an
    # analyst question.  Keep them in the same auditable timeline as state
    # transitions so report readers can see why a thread was selected without
    # replaying the complete Evidence ledger.
    for seed in investigation.get("seed_queue", []) if isinstance(investigation, dict) else []:
        if isinstance(seed, dict):
            timeline.append({
                "phase": "SEED_CLUSTER_QUEUED",
                "cluster_id": seed.get("cluster_id"),
                "artifact_id": seed.get("artifact_id"),
                "category": seed.get("category"),
                "priority": seed.get("priority"),
                "question": seed.get("question"),
                "evidence_ids": list(seed.get("evidence_ids", []))[:32],
                "hypotheses": list(seed.get("hypotheses", []))[:4],
                "status": seed.get("status", "QUEUED"),
            })
    runtime = investigation.get("runtime", {}) if isinstance(investigation, dict) else {}
    for event in runtime.get("events", []) if isinstance(runtime, dict) else []:
        if not isinstance(event, dict):
            continue
        timeline.append({
            "phase": str(event.get("phase", "investigation")),
            "state": event.get("state"),
            "action_id": event.get("action_id"),
            "evidence_ids": list(event.get("evidence_ids", [])),
            "message": event.get("message"),
        })
    for gate in runtime.get("gates", []) if isinstance(runtime, dict) else []:
        if isinstance(gate, dict):
            timeline.append({
                "phase": "CLAIM_GATE",
                "thread_id": gate.get("thread_id"),
                "hypothesis_id": gate.get("hypothesis_id"),
                "status": gate.get("status"),
                "accepted": gate.get("accepted"),
                "missing": list(gate.get("missing", [])),
                "contradictions": list(gate.get("contradictions", [])),
                # Shows whether a candidate was actually investigated across
                # its required static facets without exposing model reasoning.
                "deep_static_coverage": gate.get("deep_static_coverage", {}),
            })
    for claim in sorted(
        claims,
        key=lambda item: (str(getattr(item, "created_at", "")), str(item.id)),
    ):
        if claim.module == "static_triage" and claim.claim_type not in {"CROSS_FUNCTION_MECHANISM", "MECHANISM_CHAIN"}:
            continue
        timeline.append({
            "phase": "MECHANISM_READY->CLAIM_READY",
            "claim_id": claim.id,
            "module": claim.module,
            "action": claim.action,
            "status": claim.status,
            "confidence": claim.confidence,
            "evidence_ids": links_by_claim.get(claim.id, []),
        })
    # Replace the intentionally empty placeholder above using the actual links
    # supplied by the caller in the compact relation rows below.
    for relation in relations:
        timeline.append({
            "phase": "CLAIM_READY->RELATION",
            "relation_id": relation.id,
            "relation": relation.relation_type,
            "status": relation.status,
            "evidence_id": relation.evidence_id,
            "claim_id": relation.claim_id,
        })
    return timeline[:256]


def _claim_row_list(
    claims: list[Any],
    links_by_claim: dict[str, list[str]],
    evidence_by_id: dict[str, Any] | None = None,
) -> list[dict[str, object]]:
    ranked = sorted(
        claims,
        key=lambda item: (
            0 if getattr(item, "model_call_id", None) else 1,
            0 if item.confidence == "HIGH" else 1 if item.confidence == "MEDIUM" else 2,
            -len(links_by_claim.get(item.id, [])),
        ),
    )
    return [_claim_row(item, links_by_claim, evidence_by_id) for item in ranked[:12]]


def _is_reference_noise(row: Mapping[str, object]) -> bool:
    """Identify navigation/reference inventory that belongs in the explorer."""
    action = str(row.get("action", "")).casefold()
    text = " ".join(
        str(row.get(key, "")) for key in ("finding", "statement", "what", "how", "mechanism")
    ).casefold()
    return (
        action in {"prioritizes", "references", "matches", "calls", "contains_rva_level_call_sites"}
        or any(marker in text for marker in (
            "xref/cfg/instruction prominence", "api call-site density", "call-site density",
            "ghidra call references", "function-level static references", "raw function reference",
            "contains rva-level call sites", "matches knowledge fact",
        ))
    )


# ---------------------------------------------------------------------------
# Behavior-centric report projections
# ---------------------------------------------------------------------------
#
# The persistence layer intentionally keeps Claims, Mechanisms and Relations
# as the source of truth.  These helpers are a presentation projection only:
# they do not create or upgrade a Claim, and they fail closed when provenance
# is absent.  Keeping this boundary in one place prevents the Markdown/DOCX
# views from accidentally turning an import, a scheduler row, or an
# attribution hint into a malware behavior.

_BEHAVIOR_CLOSED_STATUSES = frozenset({"VERIFIED", "SUPPORTED", "CONFIRMED"})
_BEHAVIOR_RELATION_TYPES = frozenset(
    {
        "CONTAINS",
        "DROPS",
        "EXTRACTED_FROM",
        "LOADS",
        "DECRYPTS",
        "EXECUTES",
        "INJECTS",
        "CREATES",
        "CALLS",
        "COMMUNICATES_WITH",
        "USES",
    }
)
_BEHAVIOR_STATUS_VALUES = frozenset(
    {
        *_BEHAVIOR_CLOSED_STATUSES,
        "CANDIDATE",
        "INFERRED",
        "UNKNOWN",
        "NOT_IDENTIFIED",
        "REJECTED",
        "REFUTED",
        "BLOCKED",
    }
)
_BEHAVIOR_SEVERITY_VALUES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})
_BEHAVIOR_FIELD_KEYS = (
    "target",
    "inputs",
    "transformation_or_control",
    "conditions",
    "outputs",
    "consumers",
    "side_effects",
)

# These markers are epistemic states, not recovered facts.  They are kept in
# the report as explicit placeholders so the analyst can see which part of a
# behavior contract is open, but they must never satisfy a populated-field or
# verification gate.
_REPORT_UNKNOWN_PREFIXES = (
    "unknown",
    "not_identified",
    "not identified",
    "unresolved",
    "n/a",
    "na",
)

# ---------------------------------------------------------------------------
# M04 report readiness gate + M06 adversarial self-check.
#
# The V3 contract already listed the eight behavior-template slots, but it
# accepted ANY non-empty string in each of them and it had no document-level
# verdict.  Two defects followed from that:
#
#   * a slot could hold a bare `UNKNOWN`/`N/A` with no reason, which reads as a
#     recovered fact to a template checker and as an unexplained hole to an
#     analyst;
#   * a document whose core findings were incomplete still reached revision
#     creation carrying `analysis_outcome=COMPLETE`, because the only signal
#     was per-finding and nothing downgraded the document.
#
# M06 adds the second obligation: before a high-value conclusion enters a
# report revision, the adversarial over-claim check must be a TRACEABLE
# artefact (persisted with the revision), must cover the six named
# evidence-to-behaviour leaps, and a conclusion that fails it must be
# downgraded rather than left closed or HIGH.
# ---------------------------------------------------------------------------

#: The M04 behavior template.  Singlar key = document field, value = the label
#: used in the named UNKNOWN marker (`UNKNOWN(condition not recovered ...)`).
BEHAVIOR_TEMPLATE_SLOTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("what", ("what", "statement")),
    ("how", ("how", "transformation_or_control", "mechanism")),
    ("target", ("target", "object")),
    ("condition", ("condition", "conditions")),
    ("output", ("output", "outputs")),
    ("consumer", ("consumer", "consumers")),
    ("evidence", ("evidence_ids", "supporting_evidence_ids")),
    ("unknown", ("unknowns", "limitations", "missing")),
)

#: A slot may be absent, but not SILENTLY absent: the row must say which slot is
#: missing and what would be needed.  A bare marker is not an explanation.
_SLOT_REASON_MARKERS: tuple[str, ...] = (
    "not recovered",
    "unrecovered",
    "missing",
    "not applicable",
    "n/a",
    "requires",
    "needed",
    "unavailable",
    "not observed",
    "no evidence",
    "unsupported",
    "blocked",
)

#: The six evidence-to-behaviour leaps M06 requires the self-check to cover.
#: `rule_id` is the identifier recorded in the artefact; `over_claim` is what a
#: reader must not be told when the check fails.
M06_SELF_CHECK_RULES: tuple[dict[str, str], ...] = (
    {
        "rule_id": "API_IS_BEHAVIOR",
        "over_claim": "an API or string name presented as a recovered behavior",
        "required": "how + condition + output + consumer + evidence",
    },
    {
        "rule_id": "NETWORK_IS_C2",
        "over_claim": "a network endpoint or API presented as live C2 / beaconing",
        "required": "loop/back-edge + protocol or tasking + response consumer",
    },
    {
        "rule_id": "REGISTRY_IS_PERSISTENCE",
        "over_claim": "a scheduled task or registry key presented as persistence",
        "required": "trigger + payload + lifetime/re-execution relation",
    },
    {
        "rule_id": "PROCESS_API_IS_INJECTION",
        "over_claim": "a process/thread/APC API or PPID string presented as injection",
        "required": "cross-process target + source/target region relation",
    },
    {
        "rule_id": "COLLECTION_IS_EXFILTRATION",
        "over_claim": "collection presented as exfiltration",
        "required": "collection source + staging + network sink relation",
    },
    {
        "rule_id": "SIMULATION_IS_RUNTIME",
        "over_claim": "an emulation/stub result presented as observed runtime behaviour",
        "required": "EMULATION_OBSERVED nature, explicitly labelled as isolated emulation",
    },
)

#: Readiness states.  `PARTIAL` is an unmet slot/source obligation; `BOUNDED` is
#: an honest-but-limited report (static boundary, blocked S4, downgraded
#: over-claim); `READY` means the M04 template is satisfied for every core
#: finding.  `PARTIAL` outranks `BOUNDED`.
READINESS_STATUSES: tuple[str, ...] = ("READY", "BOUNDED", "PARTIAL")

#: Statuses that may carry a HIGH/CRITICAL severity into a revision.
_SEVERITY_BEARING_STATUSES = frozenset({*_BEHAVIOR_CLOSED_STATUSES, "CANDIDATE", "INFERRED", "OBSERVED"})

#: Statuses that count as a recorded S4 orchestration closure for M06.
_S4_CLOSURE_STATUSES = frozenset({"CLOSED", "NOT_APPLICABLE", "RECORDED"})


def _normalized_slot_name(value: object) -> str:
    return str(value or "").strip().casefold().replace("-", "_").replace(" ", "_")


def _slot_reason_is_recorded(slot: str, reasons: Iterable[object]) -> bool:
    """Whether the row STATES why this slot is empty (M04: N/A, never invented).

    The reason must name the slot AND carry an explanation marker, so a generic
    "runtime execution and intent are not observed" cannot silently justify
    every open slot.  `condition not recovered from available static evidence`
    is an explanation; a bare `condition` is not.
    """
    target = _normalized_slot_name(slot)
    for raw in reasons:
        text = str(raw or "").strip()
        if not text:
            continue
        folded = text.casefold()
        if target not in _normalized_slot_name(text):
            continue
        if any(marker in folded for marker in _SLOT_REASON_MARKERS):
            return True
    return False


def _behavior_template_slot(
    row: Mapping[str, object],
    keys: Sequence[str],
) -> tuple[str, str]:
    """Classify one template slot as ``value`` / ``explained_unknown`` / ``unexplained``."""
    for key in keys:
        if key not in row:
            continue
        value = row.get(key)
        if _report_has_semantic_value(value):
            return "value", ""
        if isinstance(value, str):
            # A non-empty string here is a MARKER (`UNKNOWN(...)`, `N/A`), not a
            # reason: it says the slot is open without saying which slot or why.
            # Empty/whitespace is simply absent.  Only a real explanation - which
            # `_slot_reason_is_recorded` looks for in the row's reason list -
            # turns this into an accepted not-applicable slot.
            return "explained_unknown" if value.strip() else "unexplained", (
                "" if value.strip() else f"{key} is empty"
            )
        if _report_has_value(value):
            return "explained_unknown", f"{key}: {str(value)[:120]}"
        if key == "evidence_ids":
            return "unexplained", "evidence_ids is empty"
        if key in {"sources", "source_ids"}:
            return "unexplained", f"{key} is empty"
        return "explained_unknown", ""
    return "unexplained", f"{keys[0]} is absent"


def _row_unknown_reasons(row: Mapping[str, object]) -> list[str]:
    reasons: list[str] = []
    for key in ("unknowns", "limitations", "missing"):
        reasons.extend(str(item) for item in _report_values(row.get(key)) if str(item).strip())
    return reasons


def _gate_row_identity(row: Mapping[str, object], index: int) -> str:
    # `relation_id` precedes `claim_id`: a relation row carries both, and M06
    # records its over-claim hits under this same identity, so an edge that is
    # blocked must be addressable by its own id rather than by its Claim.
    return str(
        row.get("relation_id")
        or row.get("finding_id")
        or row.get("id")
        or row.get("mechanism_id")
        or row.get("claim_id")
        or f"row-{index}"
    )


def _gate_row_is_core(row: Mapping[str, object]) -> bool:
    """A core finding is a closed behavior/security conclusion of this revision."""
    row_type = str(row.get("type") or "")
    if row_type not in {"behavior_finding", "security_finding"}:
        return False
    status = str(
        row.get("finding_status") or row.get("status") or row.get("verdict") or ""
    ).upper()
    return status in _BEHAVIOR_CLOSED_STATUSES


def _gate_row_is_high_value(row: Mapping[str, object]) -> bool:
    if str(row.get("type") or "") not in {"behavior_finding", "security_finding"}:
        return False
    severity = str(row.get("severity") or row.get("risk") or "").upper()
    if severity in {"HIGH", "CRITICAL"}:
        return True
    status = str(
        row.get("finding_status") or row.get("status") or row.get("verdict") or ""
    ).upper()
    return status in _BEHAVIOR_CLOSED_STATUSES


def _s4_closure_recorded(quality: Mapping[str, object]) -> tuple[bool, list[str]]:
    """M06: is every high-value item's S4 orchestration state recorded?

    A thread records itself through `analysis_quality.s4_orchestration` (the
    same rows the live writer consumes).  `deep_analysis_metrics` does not emit
    a row when the run had no investigation thread at all, which is exactly the
    case where nothing recorded S4 - hence the explicit check rather than a
    truthiness test on the list.
    """
    rows = quality.get("s4_orchestration")
    if not isinstance(rows, list) or not rows:
        return False, ["no S4 orchestration state recorded"]
    open_rows: list[str] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        status = str(row.get("status") or "").upper()
        if status and status not in _S4_CLOSURE_STATUSES:
            open_rows.append(f"{row.get('thread_id') or 'thread'}={status or 'UNRECORDED'}")
    if open_rows:
        return False, open_rows
    return True, []


def _document_rows(document: Mapping[str, object]) -> list[Mapping[str, object]]:
    return [
        row
        for module in document.get("modules") or []
        if isinstance(module, Mapping)
        for row in module.get("rows") or []
        if isinstance(row, Mapping)
    ]


def _stamp_quality(document: dict[str, object]) -> dict[str, object]:
    quality = document.get("analysis_quality")
    if not isinstance(quality, dict):
        quality = {}
        document["analysis_quality"] = quality
    for module in document.get("modules") or []:
        if not isinstance(module, dict):
            continue
        for row in module.get("rows") or []:
            if isinstance(row, dict) and row.get("type") == "analysis_quality":
                row["readiness_gate"] = quality.get("readiness_gate")
                row["m06_self_check"] = quality.get("m06_self_check")
                row["behavior_edge_gate"] = quality.get("behavior_edge_gate")
                row["readiness"] = quality.get("readiness")
                row["critic"] = quality.get("critic")
    return quality


def _write_readiness_gate(document: dict[str, object], gate: dict[str, object]) -> None:
    quality = _stamp_quality(document)
    quality["readiness_gate"] = gate
    # `_apply_honest_analysis_outcome` (service) derives PARTIAL from a
    # non-READY readiness, so an unmet gate also survives the live revision
    # writer which runs after this builder.
    if str(gate.get("status") or "").upper() != "READY":
        quality["readiness"] = "BOUNDED_WITH_LIMITATIONS"
    # Re-stamp: the module-row copy above was written before the verdict existed.
    _stamp_quality(document)
    outcome = str(document.get("analysis_outcome") or "").upper()
    if outcome == "COMPLETE" and str(gate.get("status") or "").upper() == "PARTIAL":
        document["analysis_outcome"] = "PARTIAL"


def behavior_report_readiness_gate(document: Mapping[str, object]) -> dict[str, object]:
    """M04/M06 readiness verdict for one report document.

    Every core Finding must carry What / How / Target / Condition / Output /
    Consumer / Evidence / Unknown.  A slot may be genuinely not applicable, but
    then the row must SAY so; an empty or bare-marker slot is an unmet gate.
    A HIGH-value conclusion also needs its S4 orchestration state recorded
    before it can enter a revision.  When the gate is unmet the status is
    ``PARTIAL``/``BOUNDED`` rather than a silently complete report.
    """
    rows = _document_rows(document)
    core: list[dict[str, object]] = []
    overclaim_downgraded = document.get("_m06_downgraded_row_ids")
    downgraded_ids = (
        {str(item) for item in overclaim_downgraded}
        if isinstance(overclaim_downgraded, (list, tuple, set, frozenset))
        else set()
    )
    for index, row in enumerate(rows, start=1):
        status = str(
            row.get("finding_status") or row.get("status") or row.get("verdict") or ""
        ).upper()
        if str(row.get("type") or "") not in {"behavior_finding", "security_finding"}:
            continue
        reasons = _row_unknown_reasons(row)
        missing: list[str] = []
        unexplained: list[str] = []
        for slot, keys in BEHAVIOR_TEMPLATE_SLOTS:
            verdict, detail = _behavior_template_slot(row, keys)
            if verdict == "value":
                continue
            if verdict == "explained_unknown" or _slot_reason_is_recorded(slot, reasons):
                continue
            missing.append(slot)
            unexplained.append(detail or f"{slot} is empty")
        if not missing:
            continue
        identity = _gate_row_identity(row, index)
        # M06 and M04 meet here: a conclusion the self-check already downgraded
        # is no longer a closed core finding, so its open slots are recorded as
        # a downgrade rather than as an unexplained core obligation.
        entry = {
            "finding_id": identity,
            "status": status or "UNRECORDED",
            "missing_slots": missing,
            "unexplained": unexplained,
        }
        if identity in downgraded_ids and status not in _BEHAVIOR_CLOSED_STATUSES:
            entry["disposition"] = "DOWNGRADED_BY_M06_SELF_CHECK"
        core.append(entry)

    unexplained_core = [item for item in core if not item.get("disposition")]
    high_value = [row for row in rows if _gate_row_is_high_value(row)]
    s4_ok, s4_gaps = _s4_closure_recorded(
        document.get("analysis_quality") if isinstance(document.get("analysis_quality"), Mapping) else {}
    )
    if unexplained_core:
        status = "PARTIAL"
    elif not s4_ok and high_value:
        status = "BOUNDED"
    else:
        status = "READY"

    summary = {
        "READY": "every core finding carries the M04 behavior template",
        "BOUNDED": "readiness is bounded: " + "; ".join(s4_gaps[:4]),
        "PARTIAL": "PARTIAL: core findings have unexplained template slots: "
        + ", ".join(
            f"{item['finding_id']}[{'+'.join(item['missing_slots'])}]" for item in unexplained_core[:6]
        ),
    }[status]
    return {
        "requirement": "M04",
        "status": status,
        "complete": status == "READY",
        "core_requirements": [
            {"slot": slot, "field": keys[0]} for slot, keys in BEHAVIOR_TEMPLATE_SLOTS
        ],
        "core_findings_checked": sum(
            1
            for row in rows
            if str(row.get("type") or "") in {"behavior_finding", "security_finding"}
        ),
        "core_findings_incomplete": core,
        "unexplained_core_findings": [item["finding_id"] for item in unexplained_core],
        "high_value_findings": len(high_value),
        "s4_orchestration_recorded": s4_ok,
        "s4_orchestration_gaps": s4_gaps,
        "summary": summary,
        "rules": [
            "a template slot may be absent but not silently absent: the row must state the slot and why",
            "not-applicable slots are reported as N/A with a reason, never invented",
            "an unmet gate is reported as PARTIAL/BOUNDED, never as a silently complete report",
        ],
    }


def _report_is_injects_self_loop(row: Mapping[str, object]) -> bool:
    """Same-artifact INJECTS is not a cross-process injection edge."""
    relation_type = str(row.get("relation_type") or row.get("relation") or "").strip().upper()
    if relation_type not in {"INJECTS", "INJECT"}:
        return False
    source = str(row.get("source_artifact_id") or row.get("source_object") or "").strip()
    target = str(row.get("target_artifact_id") or row.get("target_object") or "").strip()
    source_finding = str(row.get("source_finding_id") or "").strip()
    target_finding = str(row.get("target_finding_id") or "").strip()
    if source and source == target:
        return True
    if source_finding and source_finding == target_finding:
        return True
    return bool(source) and not target


def _report_is_unknown_marker(value: object) -> bool:
    """Return whether a report value only states absence/uncertainty."""
    if value is None:
        return True
    text = str(value).strip().casefold()
    if not text:
        return True
    for prefix in _REPORT_UNKNOWN_PREFIXES:
        if text == prefix or (
            text.startswith(prefix)
            and len(text) > len(prefix)
            and not text[len(prefix)].isalnum()
        ):
            return True
    # Keep negation handling narrow: descriptive boundaries such as
    # ``runtime execution and intent are not observed`` are uncertainty
    # markers, while a normal sentence containing ``not`` is not discarded.
    return bool(re.match(
        r"^(?:no|not)\s+(?:evidence|value|input|output|consumer|target|condition|data|relation)\b",
        text,
    ))


def _report_has_semantic_value(value: object) -> bool:
    """Check that a scalar/collection contains at least one real fact."""
    if _report_is_unknown_marker(value):
        return False
    if isinstance(value, Mapping):
        return any(_report_has_semantic_value(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_report_has_semantic_value(item) for item in value)
    return True


_M06_RUNTIME_CLAIM_RE = re.compile(
    r"已运行|已执行成功|运行时确认"
    r"|(?<!not )(?<!never )(?<!was not )"
    r"(?:runtime confirmed|executed successfully|actual runtime|runtime observed)",
    re.IGNORECASE,
)


def _overclaim_text(row: Mapping[str, object]) -> str:
    """Flatten the fields an over-claim conclusion actually asserts."""
    fields = (
        "what", "how", "mechanism", "statement", "security_meaning", "target",
        "inputs", "transformation_or_control", "conditions", "outputs", "consumers",
        "condition", "output", "consumer", "side_effects", "loop", "unknowns",
        "semantic_interpretation", "relation_type", "source_artifact_id",
        "target_artifact_id", "source_object", "target_object", "parent", "parent_image",
    )
    return " ".join(
        str(row.get(key) or "") for key in fields
    ).casefold()


def _overclaim_field_present(row: Mapping[str, object], keys: Sequence[str]) -> bool:
    for key in keys:
        if _report_has_semantic_value(row.get(key)):
            return True
    return False


def _overclaim_hits(rows: Iterable[Mapping[str, object]]) -> list[dict[str, object]]:
    """The six M06 leaps, evaluated once per row.

    This is deliberately a GATE, not a classifier: a hit means the row must be
    downgraded or acquire the missing typed relation.  It never promotes.
    """
    hits: list[dict[str, object]] = []
    for index, row in enumerate(rows, start=1):
        row_type = str(row.get("type") or "")
        relation_type = str(row.get("relation_type") or row.get("relation") or "").upper()
        if row_type not in {
            "behavior_finding", "security_finding", "mechanism_candidate",
            "mechanism_link", "mechanism_observation", "analytical_claim",
            "behavior_relation",
        } and relation_type not in {"INJECTS", "INJECT"}:
            continue
        identity = _gate_row_identity(row, index)
        text = _overclaim_text(row)
        natures = " ".join(
            str(item) for item in _report_values(row.get("evidence_natures"))
        ).upper()
        for key in ("nature", "evidence_nature", "execution_context"):
            natures += " " + str(row.get(key) or "").upper()

        def add(rule_id: str, missing: Sequence[str], detail: str) -> None:
            hits.append({
                "rule_id": rule_id,
                "row_id": identity,
                "row_type": row_type or relation_type,
                "status": "BLOCKED",
                "missing": list(missing),
                "detail": detail,
                "action": "DOWNGRADE_OR_RECOVER_TYPED_EVIDENCE",
                "reason": next(
                    item["over_claim"] for item in M06_SELF_CHECK_RULES if item["rule_id"] == rule_id
                ),
            })

        # -- API or string treated as behaviour --------------------------------
        what = str(row.get("what") or row.get("statement") or "").strip()
        seed_only = bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{2,}", what, re.IGNORECASE)) or bool(
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*[AW]?", what, re.IGNORECASE)
        )
        if seed_only and not (
            _overclaim_field_present(row, ("how", "transformation_or_control", "mechanism"))
            and _overclaim_field_present(row, ("condition", "conditions"))
            and _overclaim_field_present(row, ("output", "outputs"))
            and _overclaim_field_present(row, ("consumer", "consumers"))
        ):
            add(
                "API_IS_BEHAVIOR",
                ["how", "condition", "output", "consumer"],
                f"what is the bare API/string seed {what!r}",
            )

        # -- network / registry / persistence ---------------------------------
        c2_tokens = ("active c2", "beacon", "heartbeat", "command and control", "c2 channel", "c2 通道")
        if any(token in text for token in c2_tokens):
            loop_markers = ("loop", "back-edge", "back edge", "poll", "jitter", "tasking", "response consumer")
            if not any(marker in text for marker in loop_markers):
                add("NETWORK_IS_C2", ["loop_or_back_edge", "protocol_or_tasking", "response_consumer_relation"], "C2 wording without a recovered loop")
        persistence_tokens = ("persistence", "persist", "持久化", "驻留")
        persistence_targets = ("registry", "runonce", "run key", "scheduled task", "schtasks", "service", "startup", "启动项", "计划任务", "注册表")
        if any(token in text for token in persistence_tokens) and any(
            token in text for token in persistence_targets
        ):
            missing = [marker for marker in ("trigger", "lifetime", "payload") if marker not in text]
            if not any(marker in text for marker in ("trigger", "lifetime", "re-execution", "reexecution")):
                missing.append("trigger_to_payload_relation")
            add("REGISTRY_IS_PERSISTENCE", missing, "registry/task row asserted as persistence")

        # -- process/thread/APC/PPID as injection ------------------------------
        injection_tokens = (
            "process injection", "remote injection", "injected into", "process hollowing",
            "apc injection", "queueuserapc", "ntqueueapcthread", "queue apc",
            "same-process apc", "same process apc", "ppid spoof", "ppid spoofing",
            "远程注入", "注入",
        )
        is_injects_self_loop = (
            relation_type in {"INJECTS", "INJECT"}
            and bool(str(row.get("source_artifact_id") or row.get("source_object") or "").strip())
            and str(row.get("source_artifact_id") or row.get("source_object") or "").strip()
            == str(row.get("target_artifact_id") or row.get("target_object") or "").strip()
        )
        if is_injects_self_loop:
            add("PROCESS_API_IS_INJECTION", ["distinct_target_artifact", "cross_process_target"], "INJECTS edge has no distinct target")
        elif any(token in text for token in injection_tokens):
            required = ("cross_process", "target_process", "source_region", "target_region")
            missing = [marker for marker in required if marker not in text]
            if missing:
                add("PROCESS_API_IS_INJECTION", missing, "process/APC/PPID wording without a cross-process relation")

        # -- collection as exfiltration ---------------------------------------
        if "exfiltration" in text or "exfiltrated" in text or "外传" in text:
            required = ("collection_source", "staging", "network_sink")
            missing = [marker for marker in required if marker not in text]
            add("COLLECTION_IS_EXFILTRATION", missing + ["collected_to_network_relation"], "collection asserted as exfiltration")

        # -- emulation / stub as a real runtime observation --------------------
        # The wording must be AFFIRMATIVE.  A static report legitimately says
        # 「样本未运行」/「not executed」, which contains the same token and must
        # not be read as an over-claim - a gate that fires on the honest
        # boundary statement would train the reader to ignore it.
        runtime_hit = _M06_RUNTIME_CLAIM_RE.search(text) is not None
        if runtime_hit and not (
            "EMULATION_OBSERVED" in natures or "DYNAMIC_OBSERVED" in natures
        ):
            add("SIMULATION_IS_RUNTIME", ["EMULATION_OBSERVED evidence nature or real runtime provenance"], "runtime wording without observed provenance")
    return hits


def _row_failed_rules(hits: Iterable[Mapping[str, object]]) -> dict[str, list[str]]:
    failed: dict[str, list[str]] = {}
    for hit in hits:
        failed.setdefault(str(hit.get("row_id") or ""), []).append(str(hit.get("rule_id") or ""))
    return failed


def _write_m06_self_check(document: dict[str, object]) -> None:
    """M06: degrade any conclusion that fails the adversarial self-check.

    The check is recorded as a structured, revision-scoped artefact
    (`analysis_quality.m06_self_check`) rather than being left as the model's
    private reasoning, and a failing conclusion loses its closed status and its
    severity instead of being reported as established behavior.
    """
    rows = _document_rows(document)
    hits = _overclaim_hits(rows)
    failed = _row_failed_rules(hits)
    downgraded: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        identity = _gate_row_identity(row, 0)
        rules = failed.get(identity)
        if not rules:
            continue
        status = str(
            row.get("finding_status") or row.get("status") or row.get("verdict") or ""
        ).upper()
        next_status = "UNKNOWN" if "INJECTS_SELF_LOOP" in rules or "PROCESS_API_IS_INJECTION" in rules else "CANDIDATE"
        # `_gate_row_identity` is also the key M06 used, so the comparison above is exact.
        blocked_closed = status in _BEHAVIOR_CLOSED_STATUSES
        blocked_severity = str(row.get("severity") or row.get("risk") or "").upper() in {"HIGH", "CRITICAL"}
        if not blocked_closed and not blocked_severity and status == next_status:
            continue
        marker = (
            "UNKNOWN(M06 self-check failed: "
            + ", ".join(sorted(set(rules)))
            + "; typed relation missing)"
        )
        unknowns = [item for item in _report_values(row.get("unknowns")) if str(item).strip()]
        if marker not in unknowns:
            unknowns.append(marker)
        row["finding_status"] = next_status
        row["status"] = next_status
        row["verdict"] = next_status
        row["validation_status"] = next_status
        row["severity"] = "UNASSESSED"
        row["unknowns"] = unknowns
        row["maliciousness_assessment"] = (
            "not_assessed" if next_status == "UNKNOWN" else "candidate_security_relevant_behavior"
        )
        row["m06_self_check_downgrade"] = True
        downgraded.append({
            "finding_id": identity,
            "previous_status": status or "UNRECORDED",
            "status": next_status,
            "rules": sorted(set(rules)),
        })
    checks = [
        {
            "rule_id": rule["rule_id"],
            "over_claim": rule["over_claim"],
            "required": rule["required"],
            "status": "BLOCKED" if any(hit["rule_id"] == rule["rule_id"] for hit in hits) else "CHECKED",
            "hits": [hit["row_id"] for hit in hits if hit["rule_id"] == rule["rule_id"]],
        }
        for rule in M06_SELF_CHECK_RULES
    ]
    artefact = {
        "requirement": "M06",
        "gate": True,
        "traceable": True,
        "rules_covered": [rule["rule_id"] for rule in M06_SELF_CHECK_RULES],
        "checks": checks,
        "hits": hits,
        "downgraded": downgraded,
        "status": "BLOCKED" if hits else "PASS",
        "note": (
            "A failing conclusion is downgraded to UNKNOWN/CANDIDATE and its severity is "
            "cleared; this artefact is persisted with the revision, not left as model reasoning."
        ),
    }
    quality = _stamp_quality(document)
    quality["m06_self_check"] = artefact
    critic = quality.get("critic")
    if not isinstance(critic, dict):
        critic = {}
        quality["critic"] = critic
    critic["self_check"] = artefact
    if hits:
        existing = critic.get("overclaim_checks")
        merged = list(existing) if isinstance(existing, list) else []
        merged.extend(
            {
                "rule_id": hit["rule_id"],
                "row_id": hit["row_id"],
                "status": hit["status"],
                "missing": hit["missing"],
                "action": hit["action"],
                "reason": hit["reason"],
                "source": "M06_SELF_CHECK",
            }
            for hit in hits
        )
        critic["overclaim_checks"] = merged
        if str(critic.get("status") or "").upper() != "BLOCKED":
            critic["status"] = "BLOCKED"
    document["_m06_downgraded_row_ids"] = [item["finding_id"] for item in downgraded]
    if downgraded and str(document.get("analysis_outcome") or "").upper() == "COMPLETE":
        document["analysis_outcome"] = "PARTIAL"


def _stamp_behavior_readiness(document: dict[str, object]) -> dict[str, object]:
    """M06 then M04, in that order, and persist both verdicts on the revision."""
    _write_m06_self_check(document)
    downgraded_ids = list(document.pop("_m06_downgraded_row_ids", []) or [])
    _write_edge_gate(document)
    gate = behavior_report_readiness_gate(document)
    gate["m06_downgraded_findings"] = downgraded_ids
    _write_readiness_gate(document, gate)
    return gate


def _edge_basis(row: Mapping[str, object]) -> str:
    """B05: the stated basis of a graph edge.

    An edge whose basis is ``UNSTATED`` may not be presented as a supported
    relation: the reader cannot tell "recovered from this instruction window"
    from "the two rows appeared in the same function".
    """
    basis = str(row.get("basis") or row.get("basis_kind") or row.get("evidence_basis") or "").strip()
    if basis:
        return basis.upper()
    if _report_ids(row.get("evidence_ids")):
        return "EVIDENCE"
    if _report_ids(row.get("claim_ids")) or row.get("claim_id"):
        return "CLAIM"
    return "UNSTATED"


def _string_fact_summary_check(document: Mapping[str, object]) -> dict[str, object]:
    """B05: no string/API fact may be summarised as behaviour.

    MEASURED class this exists for: a bare API name (or a recovered string)
    reaching the executive summary as though the behaviour had been recovered.
    A string fact is a SEED; it may appear as an indicator or a lead, never as
    the summary's answer to "what does it do".
    """
    coverage = document.get("analysis_coverage")
    coverage = coverage if isinstance(coverage, Mapping) else {}
    seeds: list[str] = [str(item) for item in _report_values(coverage.get("string_only_claims")) if str(item).strip()]
    facts = document.get("string_facts")
    fact_labels: set[str] = set()
    if isinstance(facts, Mapping):
        for item in _report_values(facts.get("facts")):
            if isinstance(item, Mapping):
                value = str(item.get("value") or "").strip()
                if value:
                    fact_labels.add(value)
    else:
        for module in document.get("modules") or []:
            if not isinstance(module, Mapping):
                continue
            for row in module.get("rows") or []:
                if isinstance(row, Mapping) and row.get("type") == "string_fact":
                    value = str(row.get("value") or "").strip()
                    if value:
                        fact_labels.add(value)
    prompt = document.get("analysis_prompt")
    prompt = prompt if isinstance(prompt, Mapping) else {}
    summary_texts = [str(prompt.get("summary") or "")]
    for module in document.get("modules") or []:
        if not isinstance(module, Mapping):
            continue
        if str(module.get("id") or "") == "executive_summary":
            summary_texts.append(str(module.get("summary") or ""))
    summary = " ".join(summary_texts).casefold()
    hits = [
        label for label in sorted(set(seeds) | fact_labels)
        if label and label.casefold() in summary
    ]
    return {
        "rule": "string_or_api_is_not_a_summary_behaviour",
        "status": "BLOCKED" if hits else "PASS",
        "summary_only_facts": hits[:16],
        "checked": len(set(seeds) | fact_labels),
    }


def behavior_report_edge_gate(document: Mapping[str, object]) -> dict[str, object]:
    """B05: every projected graph edge carries a stated basis.

    The edge itself is not deleted: an edge derived from a Claim is still shown,
    explicitly labelled ``CLAIM``, and an edge with nothing behind it is
    recorded as ``UNSTATED`` instead of being rendered as a supported relation.
    """
    edges: list[dict[str, object]] = []
    unbacked: list[str] = []
    for index, row in enumerate(_document_rows(document), start=1):
        if str(row.get("type") or "") != "behavior_relation":
            continue
        identity = _gate_row_identity(row, index)
        basis = _edge_basis(row)
        record = {
            "relation_id": identity,
            "relation_type": str(row.get("relation_type") or row.get("relation") or ""),
            "basis": basis,
            "evidence_ids": _report_ids(row.get("evidence_ids"))[:8],
            "claim_ids": _report_ids(
                [row.get("claim_id"), *_report_ids(row.get("claim_ids"))]
            )[:8],
        }
        edges.append(record)
        if basis == "UNSTATED":
            unbacked.append(identity)
    return {
        "requirement": "B05",
        "status": "BOUNDED" if unbacked else "PASS",
        "edges": edges,
        "edges_without_basis": unbacked,
        "summary_string_check": _string_fact_summary_check(document),
        "rule": "an edge with no Evidence, Claim or typed basis is labelled UNSTATED, never rendered as supported",
    }


def _write_edge_gate(document: dict[str, object]) -> None:
    gate = behavior_report_edge_gate(document)
    quality = _stamp_quality(document)
    quality["behavior_edge_gate"] = gate
    for module in document.get("modules") or []:
        if not isinstance(module, dict):
            continue
        for row in module.get("rows") or []:
            if not isinstance(row, dict) or row.get("type") != "behavior_relation":
                continue
            row["basis"] = _edge_basis(row)
    if str(gate.get("status")) != "PASS" and str(document.get("analysis_outcome") or "").upper() == "COMPLETE":
        document["analysis_outcome"] = "PARTIAL"


def _report_is_attribution(source: Mapping[str, object], claim: Any | None = None) -> bool:
    """Keep organization/activity association out of behavior conclusions."""
    if str(source.get("module", "")).casefold() == "attribution":
        return True
    if str(source.get("claim_type", "")).casefold() == "attribution":
        return True
    if claim is not None:
        return (
            str(_report_value(claim, "module", "")).casefold() == "attribution"
            or str(_report_value(claim, "claim_type", "")).casefold() == "attribution"
        )
    return False


def _report_record(item: Any, keys: tuple[str, ...] = ()) -> dict[str, object]:
    """Return a shallow JSON-like mapping for ORM rows and test fixtures."""
    if isinstance(item, Mapping):
        return dict(item)
    wanted = keys or (
        "id", "mechanism_id", "claim_id", "claim_ids", "status", "verdict", "module", "action",
        "claim_type", "catalog_id", "behavior_id", "behavior_type",
        "mechanism_type", "artifact_id", "artifact_ids", "target",
        "what", "how", "statement", "subject", "action", "object",
        "mechanism", "condition", "conditions", "input", "inputs", "output",
        "outputs", "consumer", "consumers", "side_effects", "unknowns",
        "limitations", "missing", "severity", "risk", "confidence",
        "evidence_ids", "supporting_evidence_ids", "refuting_evidence_ids",
        "nature", "execution_context", "thread_id", "thread_ids", "relation_ids",
        "relation_type", "source_artifact_id", "target_artifact_id", "evidence_id",
        "source_finding_id", "target_finding_id", "source_object", "target_object",
        "condition", "provenance",
    )
    return {key: getattr(item, key) for key in wanted if hasattr(item, key)}


def _report_value(item: Any, key: str, default: object = None) -> object:
    if isinstance(item, Mapping):
        return item.get(key, default)
    return getattr(item, key, default)


def _report_values(value: object) -> list[object]:
    """Normalize a report field without flattening structured argument maps."""
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if item not in (None, "")]
    return [value]


def _report_ids(value: object) -> list[str]:
    return list(dict.fromkeys(str(item) for item in _report_values(value) if str(item).strip()))


def _report_has_value(value: object) -> bool:
    if value is None or value == "":
        return False
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return bool(str(value).strip())


def _report_status(value: object, default: str = "CANDIDATE") -> str:
    status = str(value or default).strip().upper()
    return status if status in _BEHAVIOR_STATUS_VALUES else status or default


def _report_behavior_catalog_id(source: Mapping[str, object], claim: Any | None) -> str:
    """Canonical catalog id. Persist claim_type is not a behavior family."""
    catalog = BehaviorCatalog()
    generic = {
        "investigated_mechanism",
        "behavior_finding",
        "unknown_behavior",
        "unknown",
        "claim",
    }
    action_map = {
        "may_create_process": "process-creation",
        "may_start_os_thread": "thread-and-callback",
        "may_resolve_api_dynamically": "loader-and-api-resolution",
        "may_decode_configuration": "config-and-crypto",
        "may_decode_or_decrypt": "config-and-crypto",
        "may_spoof_parent_process": "parent-process-spoofing",
    }
    candidates: list[str] = []
    for key in ("catalog_id", "behavior_id", "behavior_type", "mechanism_type"):
        value = source.get(key)
        if value not in (None, ""):
            candidates.append(str(value))
    action = str(source.get("action") or "").strip()
    if claim is not None:
        for key in ("catalog_id", "behavior_id", "behavior_type", "mechanism_type", "action"):
            value = _report_value(claim, key)
            if value not in (None, ""):
                candidates.append(str(value))
        action = action or str(_report_value(claim, "action") or "").strip()
    if action:
        mapped = action_map.get(action)
        if mapped:
            candidates.append(mapped)
    fallback = ""
    for candidate in candidates:
        token = candidate.strip()
        if not token or token.casefold().replace("-", "_") in generic:
            continue
        entry = catalog.by_id(token)
        if entry is None:
            continue
        if entry.id in {"unique-or-unknown", "unknown"}:
            fallback = entry.id
            continue
        return entry.id
    return fallback or "unknown_behavior"


def _report_artifact_scope(
    evidence_ids: list[str],
    source: Mapping[str, object],
    evidence_by_id: Mapping[str, Any],
) -> tuple[str | None, list[str]]:
    explicit = _report_ids(source.get("artifact_ids"))
    explicit.extend(_report_ids(source.get("artifact_id")))
    observed = [
        str(_report_value(evidence_by_id[item], "artifact_id", ""))
        for item in evidence_ids
        if item in evidence_by_id and _report_value(evidence_by_id[item], "artifact_id", "")
    ]
    artifact_ids = list(dict.fromkeys(item for item in [*explicit, *observed] if item))
    return (artifact_ids[0] if len(artifact_ids) == 1 else None), artifact_ids


def _report_field(
    source: Mapping[str, object],
    claim: Any | None,
    *keys: str,
) -> object:
    for key in keys:
        value = source.get(key)
        if _report_has_semantic_value(value):
            return value
    if claim is not None:
        for key in keys:
            value = _report_value(claim, key)
            if _report_has_semantic_value(value):
                return value
    return []


def _report_unknowns(
    source: Mapping[str, object],
    claim: Any | None,
    fields: Mapping[str, object],
    evidence_natures: list[str],
) -> list[str]:
    unknowns: list[str] = []
    for owner in (source, _report_record(claim) if claim is not None else {}):
        for key in ("unknowns", "limitations", "missing"):
            unknowns.extend(str(value) for value in _report_values(owner.get(key)) if str(value).strip())
    for key in _BEHAVIOR_FIELD_KEYS:
        if not _report_has_semantic_value(fields.get(key)):
            unknowns.append(f"{key} not recovered from available static evidence")
    unknowns.append("runtime execution and intent are not observed")
    return list(dict.fromkeys(unknowns))[:16]


def _report_semantic_interpretation(
    status: str,
    action: object,
    target: object,
    unknowns: list[str],
) -> str:
    action_text = str(action or "behavior").strip().replace("_", " ")
    target_text = str(target or "the recovered target").strip()
    if status in _BEHAVIOR_CLOSED_STATUSES:
        return (
            f"Static evidence supports a {action_text} path affecting {target_text}; "
            "this interpretation does not assert successful runtime execution."
        )
    if status in {"REJECTED", "REFUTED"}:
        return f"The proposed {action_text} behavior is rejected by the recorded evidence."
    if status in {"UNKNOWN", "NOT_IDENTIFIED", "BLOCKED"}:
        return f"The proposed {action_text} behavior cannot be resolved from the available evidence."
    suffix = f" Remaining gaps: {', '.join(unknowns[:2])}." if unknowns else ""
    return (
        f"Static evidence is consistent with a possible {action_text} path affecting {target_text}; "
        f"the finding remains a candidate and requires further relation closure.{suffix}"
    )


_PROTOCOL_FIELD_SLOTS = (
    ("initiator", "what"),
    ("input", "inputs"),
    ("state_config", "target"),
    ("transformation", "transformation_or_control"),
    ("condition", "conditions"),
    ("side_effect", "side_effects"),
    ("output", "outputs"),
    ("consumer", "consumers"),
)


def _protocol_projection(
    finding: Mapping[str, object],
    investigation_threads: Iterable[Any],
    evidence_by_id: Mapping[str, Any] | None = None,
) -> dict[str, object]:
    """Attach the ten-question protocol; unanswered slots stay UNKNOWN+reason.

    Kunglao DISPATCH_VERIFIER: persist HOW evidence fills slots even when the
    investigation thread never ran TRACE and has no stored protocol.
    """
    protocol = fill_protocol([])
    for thread in investigation_threads:
        record = _report_record(thread)
        thread_id = str(record.get("id") or record.get("thread_id") or "")
        if thread_id and thread_id not in _report_ids(finding.get("investigation_thread_ids")):
            continue
        existing = record.get("protocol")
        if isinstance(existing, Mapping):
            protocol = fill_protocol([], existing=existing)
            break
    evidence_rows = [
        _evidence_mapping(evidence_by_id[evidence_id])
        for evidence_id in _report_ids(
            finding.get("evidence_ids") or finding.get("supporting_evidence_ids")
        )
        if evidence_by_id and evidence_id in evidence_by_id
    ]
    if evidence_rows:
        protocol = fill_protocol(evidence_rows, existing=protocol)
    for slot, field_name in _PROTOCOL_FIELD_SLOTS:
        current = protocol.get(slot) or {}
        if str(current.get("status") or "").upper() == "ANSWERED":
            continue
        value = finding.get(field_name)
        if not _report_has_semantic_value(value):
            continue
        if _is_fun_call_sequence_dump(value):
            continue
        protocol[slot] = {
            "status": "ANSWERED",
            "value": value,
            "evidence_ids": list(finding.get("evidence_ids") or [])[:8],
            "reason": "",
            "question": current.get("question") or dict(TEN_QUESTION_SLOTS).get(slot, ""),
        }
    persist_how = _prefer_persist_how(
        finding.get("how"),
        finding.get("what"),
        finding.get("transformation_or_control"),
    )
    for slot, row in list(protocol.items()):
        if not isinstance(row, Mapping):
            continue
        if not _is_fun_call_sequence_dump(row.get("value")):
            continue
        if persist_how:
            protocol[slot] = {
                **row,
                "status": "ANSWERED",
                "value": persist_how,
                "reason": "",
            }
            continue
        protocol[slot] = {
            **row,
            "status": "UNKNOWN",
            "value": "",
            "reason": (
                "FUN_* call-sequence dump is Evidence Explorer content, not a typed How"
            ),
        }
    unanswered = [
        f"UNKNOWN({slot}: {row.get('reason') or 'not recovered from available static evidence'})"
        for slot, row in protocol.items()
        if isinstance(row, Mapping) and str(row.get("status") or "").upper() != "ANSWERED"
    ]
    unknowns = list(finding.get("unknowns") or [])
    for item in unanswered:
        if item not in unknowns:
            unknowns.append(item)
    return {"ten_question_protocol": protocol, "unknowns": unknowns[:32]}


def build_behavior_findings(
    claims: list[Any] | tuple[Any, ...] | None = None,
    mechanisms: list[Any] | tuple[Any, ...] | None = None,
    *,
    mechanism_projections: list[Mapping[str, object]] | tuple[Mapping[str, object], ...] | None = None,
    links_by_claim: Mapping[str, list[str]] | None = None,
    claim_evidence: list[Any] | tuple[Any, ...] | None = None,
    evidence_by_id: Mapping[str, Any] | None = None,
    investigation_threads: list[Any] | tuple[Any, ...] | None = None,
    snapshot_id: str | None = None,
) -> list[dict[str, object]]:
    """Project evidence-backed Claims/Mechanisms into behavior findings.

    The projection deliberately preserves source status.  In particular, a
    Claim with ``confidence=HIGH`` remains ``CANDIDATE`` until its Mechanism
    and verifier status say otherwise.  No finding is emitted without at
    least one Evidence row that exists in ``evidence_by_id``.
    """
    claims = list(claims or ())
    mechanisms = list(mechanisms or ())
    mechanism_projections = list(mechanism_projections or ())
    links_by_claim = links_by_claim or {}
    evidence_by_id = evidence_by_id or {}
    claim_evidence = list(claim_evidence or ())
    investigation_threads = list(investigation_threads or ())

    support_by_claim: dict[str, list[str]] = {}
    refute_by_claim: dict[str, list[str]] = {}
    for link in claim_evidence:
        claim_id = str(_report_value(link, "claim_id", "") or "")
        evidence_id = str(_report_value(link, "evidence_id", "") or "")
        if not claim_id or not evidence_id or evidence_id not in evidence_by_id:
            continue
        stance = str(_report_value(link, "stance", "SUPPORTS") or "SUPPORTS").upper()
        destination = refute_by_claim if stance in {"REFUTES", "REFUTED", "CONTRADICTS"} else support_by_claim
        destination.setdefault(claim_id, []).append(evidence_id)
    for claim_id, ids in links_by_claim.items():
        support_by_claim.setdefault(str(claim_id), []).extend(
            item for item in _report_ids(ids) if item in evidence_by_id
        )
    for destination in (support_by_claim, refute_by_claim):
        for key, ids in destination.items():
            destination[key] = list(dict.fromkeys(ids))

    claim_by_id = {str(_report_value(item, "id", "")): item for item in claims}
    findings: list[dict[str, object]] = []
    represented_claim_ids: set[str] = set()
    seen_identity: set[str] = set()

    sources = [*mechanisms, *mechanism_projections]
    for raw_source in sources:
        source = _report_record(raw_source)
        source_id = str(source.get("mechanism_id") or source.get("id") or "")
        claim_ids = _report_ids(source.get("claim_ids"))
        claim_id = str(source.get("claim_id") or "")
        if claim_id:
            claim_ids.insert(0, claim_id)
        claim_ids = list(dict.fromkeys(item for item in claim_ids if item))
        linked_claim = next((claim_by_id[item] for item in claim_ids if item in claim_by_id), None)
        # Attribution is rendered in its own isolated module.  It may remain
        # a candidate technical association, but it is never a behavior
        # finding and cannot contribute to the executive behavior summary.
        if _report_is_attribution(source, linked_claim):
            continue
        evidence_ids = _report_ids(source.get("evidence_ids"))
        for item in claim_ids:
            evidence_ids.extend(support_by_claim.get(item, []))
        evidence_ids = list(dict.fromkeys(item for item in evidence_ids if item in evidence_by_id))
        if not evidence_ids:
            continue
        artifact_id, artifact_ids = _report_artifact_scope(evidence_ids, source, evidence_by_id)
        status = _report_status(source.get("status") or _report_value(linked_claim, "status", "CANDIDATE"))
        # A mechanism projection may have a generic status but an underlying
        # Claim has a terminal rejection. Preserve the explicit source status;
        # otherwise prefer the Claim's lifecycle state.
        if not source.get("status") and linked_claim is not None:
            status = _report_status(_report_value(linked_claim, "status", "CANDIDATE"))
        catalog_id = _report_behavior_catalog_id(source, linked_claim)
        fields = {
            "target": _report_field(source, linked_claim, "target", "object", "subject"),
            "inputs": _report_field(source, linked_claim, "inputs", "input"),
            "transformation_or_control": _report_field(
                source, linked_claim, "transformation_or_control", "how", "mechanism"
            ),
            "conditions": _report_field(source, linked_claim, "conditions", "condition"),
            "outputs": _report_field(source, linked_claim, "outputs", "output"),
            "consumers": _report_field(source, linked_claim, "consumers", "consumer"),
            "side_effects": _report_field(source, linked_claim, "side_effects"),
        }
        # Every analyst-facing finding has a total behavior shape.  Missing
        # values are explicit UNKNOWN markers rather than empty cells, and
        # the marker remains excluded from semantic completeness checks.
        unknown_labels = {
            "target": "target",
            "inputs": "input",
            "transformation_or_control": "transformation_or_control",
            "conditions": "condition",
            "outputs": "output",
            "consumers": "consumer",
            "side_effects": "side_effect",
        }
        for field_name, label in unknown_labels.items():
            if not _report_has_semantic_value(fields[field_name]):
                fields[field_name] = [
                    f"UNKNOWN({label} not recovered from available static evidence)"
                ]
        catalog_entry = BehaviorCatalog().by_id(catalog_id) if catalog_id else None
        evidence_ids = _catalog_semantic_evidence_ids(catalog_entry, evidence_ids, evidence_by_id)
        persist_how = _flatten_report_how(fields["transformation_or_control"])
        persist_what = _flatten_report_how(
            source.get("what") or _report_value(linked_claim, "statement", "")
        )
        semantic_how = _how_from_semantic_evidence(evidence_ids, evidence_by_id)
        persist_body = _prefer_persist_how(persist_how, persist_what)
        if persist_body:
            fields["transformation_or_control"] = [persist_body]
        elif semantic_how and not _semantic_call_sequence_dump(semantic_how):
            fields["transformation_or_control"] = [semantic_how]
        target = fields["target"]
        action = _report_value(linked_claim, "action", source.get("action", catalog_id))
        unknowns = _report_unknowns(
            source,
            linked_claim,
            fields,
            list(dict.fromkeys(
                str(_report_value(evidence_by_id[item], "nature", "UNKNOWN") or "UNKNOWN").upper()
                for item in evidence_ids
            )),
        )
        evidence_natures = list(dict.fromkeys(
            str(_report_value(evidence_by_id[item], "nature", "UNKNOWN") or "UNKNOWN").upper()
            for item in evidence_ids
        ))
        finding_identity = source_id or (claim_ids[0] if claim_ids else catalog_id)
        scope_suffix = artifact_id or ("multi" if len(artifact_ids) > 1 else "unknown")
        identity = f"behavior-finding:{finding_identity}:{scope_suffix}"
        if identity in seen_identity:
            continue
        seen_identity.add(identity)
        represented_claim_ids.update(claim_ids)
        severity = str(source.get("severity") or "").upper()
        if status not in _BEHAVIOR_CLOSED_STATUSES or severity not in _BEHAVIOR_SEVERITY_VALUES:
            severity = "UNASSESSED"
        thread_ids: list[str] = []
        for thread in investigation_threads:
            thread_map = _report_record(thread)
            thread_evidence = set(_report_ids(thread_map.get("evidence_ids")))
            if thread_evidence.intersection(evidence_ids) or (
                source_id and source_id in _report_ids(thread_map.get("mechanism_ids"))
            ):
                thread_id = str(thread_map.get("id") or thread_map.get("thread_id") or "")
                if thread_id:
                    thread_ids.append(thread_id)
        supporting_ids = [
            item
            for claim_id_item in claim_ids
            for item in support_by_claim.get(claim_id_item, [])
        ]
        if not claim_ids:
            supporting_ids.extend(evidence_ids)
        supporting_ids = list(dict.fromkeys(item for item in supporting_ids if item in evidence_by_id))
        finding = {
            "type": "behavior_finding",
            "id": identity,
            "finding_id": identity,
            "catalog_id": catalog_id,
            "artifact_id": artifact_id,
            "artifact_ids": artifact_ids,
            "claim_ids": claim_ids,
            "mechanism_ids": [source_id] if source_id else [],
            "what": str(
                source.get("what")
                or _report_value(linked_claim, "statement", "")
                or f"{action or 'behavior'} {target or 'target'}"
            ),
            "how": fields["transformation_or_control"],
            "function": source.get("function") or None,
            "function_entry": source.get("function_entry") or source.get("rva") or None,
            "rva": source.get("rva") or source.get("function_entry") or None,
            "target": target,
            "condition": fields["conditions"],
            "output": fields["outputs"],
            "consumer": fields["consumers"],
            "inputs": fields["inputs"],
            "transformation_or_control": fields["transformation_or_control"],
            "conditions": fields["conditions"],
            "outputs": fields["outputs"],
            "consumers": fields["consumers"],
            "side_effects": fields["side_effects"],
            "finding_status": status,
            "status": status,
            "verdict": status,
            "confidence": _report_value(linked_claim, "confidence", source.get("confidence", "LOW")),
            "evidence_natures": evidence_natures,
            "supporting_evidence_ids": supporting_ids,
            "refuting_evidence_ids": list(dict.fromkeys(
                item for claim_id_item in claim_ids for item in refute_by_claim.get(claim_id_item, [])
            )),
            "evidence_ids": evidence_ids[:32],
            "semantic_interpretation": _report_semantic_interpretation(status, action, target, unknowns),
            "maliciousness_assessment": (
                "security_relevant_static_behavior"
                if status in _BEHAVIOR_CLOSED_STATUSES
                else "candidate_security_relevant_behavior"
                if status not in {"UNKNOWN", "NOT_IDENTIFIED", "REJECTED", "REFUTED", "BLOCKED"}
                else "not_assessed"
            ),
            "severity": severity,
            "unknowns": unknowns,
            "investigation_thread_ids": list(dict.fromkeys(thread_ids)),
            "execution_context": (
                "CONTROLLED_EMULATION_AND_STATIC"
                if "EMULATION_OBSERVED" in evidence_natures
                else "STATIC_ONLY"
            ),
            "relation_ids": [],
            "source": "mechanism_projection" if source_id else "claim_projection",
        }
        if snapshot_id:
            finding["snapshot_id"] = snapshot_id
        finding.update(_protocol_projection(finding, investigation_threads, evidence_by_id))
        findings.append(finding)

    # Claims without a mechanism record are still useful as explicit
    # candidates, provided they have real supporting Evidence.  Navigation
    # and attribution rows are intentionally excluded from this behavior view.
    for claim in claims:
        claim_id = str(_report_value(claim, "id", "") or "")
        if not claim_id or claim_id in represented_claim_ids:
            continue
        claim_type = str(_report_value(claim, "claim_type", "") or "").upper()
        if claim_type in _NON_MECHANISM_CLAIM_TYPES or str(_report_value(claim, "module", "")).casefold() == "attribution":
            continue
        claim_row = {
            "action": _report_value(claim, "action", ""),
            "statement": _report_value(claim, "statement", ""),
            "mechanism": _report_value(claim, "mechanism", ""),
        }
        if _is_reference_noise(claim_row):
            continue
        evidence_ids = list(dict.fromkeys(
            item for item in [*support_by_claim.get(claim_id, []), *_report_ids(links_by_claim.get(claim_id, []))]
            if item in evidence_by_id
        ))
        if not evidence_ids:
            continue
        source = _report_record(claim)
        # Re-run the projection through a one-item source so field and status
        # semantics stay identical to mechanism-backed findings.
        source.setdefault("claim_id", claim_id)
        source.setdefault("evidence_ids", evidence_ids)
        projected = build_behavior_findings(
            [claim],
            [],
            mechanism_projections=[source],
            links_by_claim={claim_id: evidence_ids},
            claim_evidence=claim_evidence,
            evidence_by_id=evidence_by_id,
            investigation_threads=investigation_threads,
            snapshot_id=snapshot_id,
        )
        for finding in projected:
            identity = str(finding.get("finding_id", ""))
            if identity and identity not in seen_identity:
                seen_identity.add(identity)
                findings.append(finding)
        represented_claim_ids.add(claim_id)
    findings, _ = apply_adversarial_downgrades(findings)
    findings = _apply_name_only_seed_downgrades(findings)
    return findings[:128]


_HIGH_VALUE_UNCLOSED_CATALOG_IDS = frozenset(
    {
        "thread-and-callback",
        "process-creation",
        "loader-and-api-resolution",
        "process-injection",
        "communication-loop",
        "command-dispatch",
        "persistence",
        "config-and-crypto",
        "network-transport",
        "multi-stage-payload",
    }
)
_UNIQUE_THREAD_API_MARKERS = (
    "createthreadex",
    "createthread",
    "tpallocwork",
    "submitthreadpoolwork",
    "createthreadpoolwait",
    "createthreadpooltimer",
    "tlssetvalue",
    "addvectoredexceptionhandler",
    "setwaitabletimer",
    "createtimerqueuetimer",
)
_THREAD_START_CREATOR_MARKERS = (
    "createthreadex",
    "createthread",
    "tpallocwork",
    "submitthreadpoolwork",
    "createthreadpoolwait",
    "createthreadpooltimer",
)
_API_ARGUMENT_NAMES = {
    "createthread": ("lpThreadAttributes", "dwStackSize", "lpStartAddress", "lpParameter"),
    "createthreadex": ("lpThreadAttributes", "dwStackSize", "lpStartAddress", "lpParameter"),
    "cryptacquirecontextw": ("phProv", "szContainer", "szProvider", "dwProvType", "dwFlags"),
    "cryptacquirecontexta": ("phProv", "szContainer", "szProvider", "dwProvType", "dwFlags"),
    "cryptgenkey": ("hProv", "Algid", "dwFlags", "dwKeyLen", "phKey"),
    "cryptencrypt": ("hKey", "hHash", "Final", "dwFlags", "pbData", "pdwDataLen"),
    "cryptdecrypt": ("hKey", "hHash", "Final", "dwFlags", "pbData", "pdwDataLen"),
    "cryptimportkey": ("hProv", "pbData", "dwDataLen", "hPubKey", "dwFlags", "phKey"),
    "virtualprotect": ("lpAddress", "dwSize", "flNewProtect", "lpflOldProtect"),
    "getexitcodethread": ("hThread", "lpExitCode"),
    "sleep": ("dwMilliseconds",),
    "loadlibrarya": ("lpLibFileName",),
    "loadlibraryw": ("lpLibFileName",),
    "getprocaddress": ("hModule", "lpProcName"),
    "winhttpopen": ("pszAgentW", "dwAccessType", "pszProxyW", "pszProxyBypassW"),
    "winhttpconnect": ("hSession", "pswzServerName", "nServerPort", "dwReserved"),
    "winhttpopenrequest": ("hConnect", "pwszVerb", "pwszObjectName", "pwszVersion"),
    "winhttpsendrequest": ("hRequest", "lpszHeaders", "dwHeadersLength", "lpOptional"),
    "winhttpreceiveresponse": ("hRequest", "lpReserved"),
    "winhttpreaddata": ("hRequest", "lpBuffer", "dwNumberOfBytesToRead", "lpdwNumberOfBytesRead"),
    "regopenkeyexw": ("hKey", "lpSubKey", "ulOptions", "samDesired"),
    "regopenkeyexa": ("hKey", "lpSubKey", "ulOptions", "samDesired"),
    "regsetvalueexw": ("hKey", "lpValueName", "Reserved", "dwType"),
    "regsetvalueexa": ("hKey", "lpValueName", "Reserved", "dwType"),
    "openprocess": ("dwDesiredAccess", "bInheritHandle", "dwProcessId"),
    "updateprocthreadattribute": ("lpAttributeList", "dwFlags", "Attribute", "lpValue"),
    "createprocessw": ("lpApplicationName", "lpCommandLine", "lpProcessAttributes", "lpThreadAttributes"),
    "createprocessa": ("lpApplicationName", "lpCommandLine", "lpProcessAttributes", "lpThreadAttributes"),
}
_CRYPTO_ALG_IDS = {
    0x6801: "CALG_RC4",
    0x6603: "CALG_3DES",
    0x660E: "CALG_AES",
    0x6610: "CALG_AES_128",
    0x6611: "CALG_AES_192",
    0x6612: "CALG_AES_256",
    0x8004: "CALG_SHA1",
    0x800C: "CALG_SHA_256",
}
_PAGE_PROTECT = {
    0x04: "PAGE_READWRITE",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
}


def _evidence_mapping(item: Any) -> dict[str, object]:
    if isinstance(item, Mapping):
        return dict(item)
    return {
        "id": str(getattr(item, "id", "") or ""),
        "kind": str(getattr(item, "kind", "") or ""),
        "artifact_id": str(getattr(item, "artifact_id", "") or ""),
        "value": getattr(item, "value", {}) or {},
        "anchor": getattr(item, "anchor", {}) or {},
    }


def _address_lookup_keys(*values: object) -> list[str]:
    """Join FUN_140038ae0, 140038ae0, and 0x140038ae0 as the same persist identity."""
    keys: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        keys.append(text)
        stripped = text.split("@", 1)[0].strip()
        for prefix in ("FUN_", "fun_", "sub_", "thunk_"):
            if stripped.startswith(prefix):
                stripped = stripped[len(prefix):]
                break
        candidates = [stripped]
        if stripped.lower().startswith("0x"):
            candidates.append(stripped[2:])
        elif stripped:
            candidates.append("0x" + stripped)
        for candidate in candidates:
            if not candidate:
                continue
            keys.append(candidate)
            parsed = None
            try:
                parsed = int(candidate, 0)
            except ValueError:
                if re.fullmatch(r"[0-9a-fA-F]{4,16}", candidate):
                    try:
                        parsed = int(candidate, 16)
                    except ValueError:
                        parsed = None
            if parsed is None:
                continue
            keys.append(f"0x{parsed:x}")
            keys.append(f"0x{parsed:08x}")
            keys.append(f"{parsed:x}")
            keys.append(str(parsed))
    return list(dict.fromkeys(keys))


def _catalog_entry_for_finding(catalog: BehaviorCatalog, finding: Mapping[str, object]) -> Any:
    for key in ("catalog_id", "behavior_id", "behavior_type"):
        value = finding.get(key)
        if value in (None, "", "unknown_behavior"):
            continue
        entry = catalog.by_id(str(value))
        if entry is not None:
            return entry
    return None


_NAME_ONLY_HOW_RE = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9]*)(?:A|W)?"
    r"(?:\s*(?:->|,|;)\s*(?:[A-Za-z_][A-Za-z0-9]*)(?:A|W)?)*$"
)


def _semantic_scalar(value: object) -> str:
    """Return the first recovered scalar, skipping UNKNOWN placeholders."""
    if isinstance(value, Mapping):
        for key in ("value", "name", "api", "text", "function", "function_entry"):
            text = _semantic_scalar(value.get(key))
            if text:
                return text
        return ""
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            text = _semantic_scalar(item)
            if text:
                return text
        return ""
    text = str(value or "").strip()
    return "" if not text or is_empty_marker(text) else text


def _flatten_report_how(value: object) -> str:
    """Join HOW fields while dropping explicit UNKNOWN placeholders."""
    if isinstance(value, (list, tuple, set, frozenset)):
        parts = [_semantic_scalar(item) for item in value]
        return "; ".join(item for item in parts if item)
    return _semantic_scalar(value)


def _strip_unknown_how_tokens(text: str) -> str:
    cleaned = re.sub(r"UNKNOWN\([^)]*\)", " ", text, flags=re.I)
    cleaned = re.sub(r"\b(?:not recovered|unknown)\b", " ", cleaned, flags=re.I)
    cleaned = re.sub(r"\s*(?:->|,|;)\s*", " -> ", cleaned)
    return re.sub(r"(?:^|->|,|;|\s)+|(?:->|,|;|\s)+$", "", cleaned).strip(" ->,;")


def _how_text_is_name_only_seed(text: str) -> bool:
    """True when HOW is only an API/import name, not function/RVA/params/consumer."""
    cleaned = _strip_unknown_how_tokens(text)
    if not cleaned:
        return True
    if "(" in cleaned and ")" in cleaned:
        inner = cleaned[cleaned.find("(") + 1:cleaned.rfind(")")].strip()
        if inner and not is_empty_marker(inner):
            return False
    if any(marker in cleaned for marker in ("=", "@", "0x", "0X", "function=", "consumer=", "parameters=")):
        return False
    compact = re.sub(r"\s+", "", cleaned)
    return bool(_NAME_ONLY_HOW_RE.fullmatch(cleaned) or _NAME_ONLY_HOW_RE.fullmatch(compact))


_FUN_DUMP_FLOOD_APIS = (
    "getconsolewindow",
    "showwindow",
    "gettickcount64",
    "getsysteminfo",
    "globalmemorystatus",
    "getenvironmentstrings",
    "shellexecute",
)


def _semantic_call_sequence_dump(text: object) -> bool:
    """True for ShellExecuteW / GetEnvironmentStringsW decompile lists over persist HOW."""
    blob = str(text or "").casefold()
    return "shellexecutew" in blob or "getenvironmentstringsw" in blob


def _is_fun_call_sequence_dump(text: object) -> bool:
    """True for a FUN_*@ decompile flood, not a short named-API How with a FUN label."""
    blob = str(text or "")
    if _semantic_call_sequence_dump(blob):
        return True
    if not re.search(r"FUN_[0-9A-Fa-f]+@", blob):
        return False
    folded = blob.casefold()
    arrows = blob.count(" -> ")
    flood_hits = sum(1 for token in _FUN_DUMP_FLOOD_APIS if token in folded)
    if flood_hits >= 1 and arrows >= 1:
        return True
    if arrows >= 6:
        return True
    if "memcpy" in folded and arrows >= 3:
        return True
    return False


def _cover_location_suffix(target: object, entry: object) -> str:
    """Executive Interpretation may cite a sample, not a FUN_*@ decompile label."""
    target_text = str(target or "").strip()
    entry_text = str(entry or "").strip()
    loc = _format_function_location(target_text, entry_text) if entry_text else target_text
    if re.search(r"(?i)FUN_[0-9A-Fa-f]+@", loc) or loc.upper().startswith("FUN_"):
        if target_text and "FUN_" not in target_text.upper():
            return f" ({target_text})"
        return ""
    return f" ({loc})" if loc else ""


def _is_catalog_label_noise(text: object, catalog_id: str = "") -> bool:
    """Drop `process-creation FUN_*@rva` labels that are not recovered What/How."""
    blob = str(text or "").strip()
    if not blob:
        return True
    if _is_fun_call_sequence_dump(blob):
        return True
    label = rf"(?:{re.escape(catalog_id)}\s+)?" if catalog_id else r"(?:[\w-]+\s+)?"
    if re.fullmatch(label + r"FUN_[0-9A-Fa-f]+@[0-9A-Fa-f]+", blob, re.I):
        return True
    if catalog_id and blob.casefold() in {catalog_id, f"{catalog_id} function"}:
        return True
    return False


def _persist_argument_how(text: object) -> bool:
    """True when persist already recovered command/flags/start, not a decompile list."""
    if _is_fun_call_sequence_dump(text):
        return False
    blob = str(text or "").casefold()
    return any(
        token in blob
        for token in (
            "command=",
            "command `",
            "creation_flags=",
            "lpstartaddress=",
            "attribute=0x",
            "parent=",
            "consumed by",
            "module=",
            "consumer=winhttp",
            "consumer=jmp",
            "start=0x",
        )
    )


def _prefer_persist_how(*candidates: object) -> str:
    """Prefer a persist command/flags/parent/winhttp HOW that is not a decompile dump."""
    texts = [_flatten_report_how(item) for item in candidates]
    for text in texts:
        if _persist_argument_how(text):
            return text
    return ""


def _catalog_row_how(
    finding: Mapping[str, object],
    *,
    entry: Any,
    cited: Iterable[str],
    evidence_by_id: Mapping[str, Any],
    current_how: str = "",
) -> str:
    """Keep persist command/flags/parent HOW; never fall back to a FUN_* decompile list."""
    del entry, cited, evidence_by_id
    finding_how = _module_how_from_finding(finding)
    finding_what = _flatten_report_how(finding.get("what") or finding.get("finding"))
    persist = _prefer_persist_how(current_how, finding_how, finding_what)
    if persist:
        return persist
    if finding_how and finding_how.casefold() != "not recovered" and not _is_fun_call_sequence_dump(finding_how):
        return finding_how
    if current_how and current_how.casefold() != "not recovered" and not _is_fun_call_sequence_dump(current_how):
        return current_how
    return "not recovered"


def _finding_has_recovered_how(finding: Mapping[str, object]) -> bool:
    """True when a finding recovered a concrete HOW, not an UNKNOWN placeholder."""
    how = _module_how_from_finding(finding)
    if not how or is_empty_marker(how) or how.casefold() == "not recovered":
        return False
    raw = _flatten_report_how(finding.get("how") or finding.get("transformation_or_control"))
    if _is_fun_call_sequence_dump(raw) and not _persist_argument_how(finding.get("what")):
        return False
    return not _how_text_is_name_only_seed(how)


_COVER_NOISE_CATALOG_IDS = frozenset({"", "unknown", "unknown_behavior", "unique-or-unknown"})


def _is_cover_noise_finding(
    finding: Mapping[str, object],
    *,
    named_ids: set[str] | None = None,
) -> bool:
    """Drop FUN dumps and unknown_behavior once a named catalog row exists."""
    catalog_id = str(finding.get("catalog_id") or "")
    how = _flatten_report_how(
        finding.get("how") or finding.get("transformation_or_control") or finding.get("mechanism")
    )
    what = _flatten_report_how(finding.get("what") or finding.get("finding"))
    if _is_fun_call_sequence_dump(how) and not _persist_argument_how(what):
        return True
    if catalog_id in _COVER_NOISE_CATALOG_IDS and named_ids:
        return True
    return False


def _prefer_named_catalog_findings(
    rows: Iterable[Mapping[str, object]],
) -> list[Mapping[str, object]]:
    """Keep one persist How per catalog_id; unknown_behavior yields to named rows."""
    material = [row for row in rows if isinstance(row, Mapping)]
    named_ids = {
        str(row.get("catalog_id") or "")
        for row in material
        if str(row.get("catalog_id") or "") not in _COVER_NOISE_CATALOG_IDS
    }
    filtered = [
        row for row in material if not _is_cover_noise_finding(row, named_ids=named_ids)
    ]
    winners: dict[str, Mapping[str, object]] = {}
    ordered: list[Mapping[str, object]] = []
    for row in filtered:
        catalog_id = str(row.get("catalog_id") or "")
        if not catalog_id or catalog_id in _COVER_NOISE_CATALOG_IDS:
            ordered.append(row)
            continue
        how = _flatten_report_how(row.get("how") or row.get("transformation_or_control"))
        what = _flatten_report_how(row.get("what"))
        persist = bool(_prefer_persist_how(how, what))
        current = winners.get(catalog_id)
        if current is None:
            winners[catalog_id] = row
            ordered.append(row)
            continue
        current_how = _flatten_report_how(
            current.get("how") or current.get("transformation_or_control")
        )
        current_persist = bool(_prefer_persist_how(current_how, current.get("what")))
        if persist and not current_persist:
            ordered[ordered.index(current)] = row
            winners[catalog_id] = row
    return ordered


def _analyst_finding_rank(row: Mapping[str, object]) -> tuple[int, int]:
    """Persist process command HOW before PPID/GetProcAddress flood."""
    recovered = 0 if _finding_has_recovered_how(row) else 1
    blob = " ".join(
        str(row.get(key) or "")
        for key in (
            "what", "how", "action", "catalog_id", "mechanism_type",
            "transformation_or_control", "mechanism",
        )
    ).casefold()
    if any(
        token in blob
        for token in (
            "may_create_process",
            "command=",
            "command `",
        )
    ):
        family = 0
    elif any(
        token in blob
        for token in (
            "lpstartaddress",
            "may_start_os_thread",
        )
    ):
        family = 1
    elif str(row.get("action") or "").casefold() == "may_resolve_api_dynamically":
        family = 6
    elif any(
        token in blob
        for token in (
            "parent-process",
            "updateprocthreadattribute",
            "ppid",
            "spoof",
        )
    ):
        family = 2
    elif any(
        token in blob
        for token in (
            "createprocess",
            "creation_flags",
            "cmd.exe",
            "process-creation",
            "process_execution",
            "createthread",
        )
    ):
        family = 3
    elif any(
        token in blob
        for token in ("decode", "xor", "plaintext", "key_table", "may_decode")
    ):
        family = 4
    elif "jmp " in blob or "consumer=" in blob:
        family = 5
    else:
        family = 10
    return (recovered, family)


def _protocol_slot_value(finding: Mapping[str, object], slot: str) -> str:
    protocol = finding.get("ten_question_protocol")
    if not isinstance(protocol, Mapping):
        return ""
    row = protocol.get(slot)
    if not isinstance(row, Mapping):
        return ""
    if str(row.get("status") or "").upper() != "ANSWERED":
        return ""
    return _semantic_scalar(row.get("value"))


def _module_how_from_finding(finding: Mapping[str, object]) -> str:
    """Prefer recovered function/parameter/threshold/consumer/fallback over an API list."""
    parts: list[str] = []
    how_text = _flatten_report_how(finding.get("how") or finding.get("transformation_or_control"))
    what_text = _flatten_report_how(finding.get("what") or finding.get("finding"))
    persist_what = _persist_argument_how(what_text)
    if how_text and how_text.casefold() != "not recovered" and not _how_text_is_name_only_seed(how_text):
        if _is_fun_call_sequence_dump(how_text):
            if persist_what:
                parts.append(what_text)
        elif persist_what and not _persist_argument_how(how_text):
            parts.append(what_text)
        else:
            parts.append(how_text)
    elif persist_what:
        parts.append(what_text)
    labeled = (
        ("function", _semantic_scalar(finding.get("function") or finding.get("function_entry"))),
        ("parameters", _protocol_slot_value(finding, "input") or _protocol_slot_value(finding, "state_config")),
        ("threshold", _protocol_slot_value(finding, "condition")),
        (
            "consumer",
            _protocol_slot_value(finding, "consumer")
            or _semantic_scalar(finding.get("consumer") or finding.get("consumers")),
        ),
        ("failure fallback", _protocol_slot_value(finding, "failure_fallback")),
    )
    seed_tokens = _api_seed_tokens(
        " ".join(
            (
                _flatten_report_how(finding.get("what")),
                _flatten_report_how(finding.get("how") or finding.get("transformation_or_control")),
                _flatten_report_how(finding.get("action")),
            )
        )
    )
    for label, text in labeled:
        if not text or is_empty_marker(text):
            continue
        echoed = _api_seed_tokens(text)
        if echoed and echoed <= seed_tokens and _how_text_is_name_only_seed(text):
            continue
        if any(text in part for part in parts):
            continue
        parts.append(f"{label}={text}")
    return "; ".join(parts[:8]) or "not recovered"


_INJECTION_NAME_SEEDS = frozenset(
    {
        "createthread", "createthreadex", "queueuserapc", "ntqueueapcthread",
        "ntcreatethreadex", "rtlcreateuserthread", "updateprocthreadattribute",
        "openprocess", "writeprocessmemory", "virtualallocex", "ppid",
    }
)
_NETWORK_NAME_SEEDS = frozenset(
    {
        "winhttpopen", "winhttpconnect", "winhttpopenrequest", "winhttpsendrequest",
        "winhttpreceiveresponse", "winhttpreaddata", "http", "https",
        "internetopen", "httpsendrequest", "wsasend", "connect",
    }
)
_PERSISTENCE_NAME_SEEDS = frozenset(
    {
        "schtasks", "registertaskdefinition", "regsetvalueexw", "regsetvalueexa",
        "regsetvalueex", "regcreatekeyexw", "regcreatekeyexa",
    }
)
_IMPORT_NAME_SEEDS = frozenset(
    {
        "loadlibraryw", "loadlibrarya", "loadlibrary", "getprocaddress",
        "ldrloaddll", "ldrgetprocedureaddress",
    }
)
_NAME_ONLY_API_SEEDS = (
    _INJECTION_NAME_SEEDS | _NETWORK_NAME_SEEDS | _PERSISTENCE_NAME_SEEDS | _IMPORT_NAME_SEEDS
)
_OVERCLAIMED_ATTACK_PREFIXES = {
    "T1055": _INJECTION_NAME_SEEDS | _IMPORT_NAME_SEEDS,
    "T1071": _NETWORK_NAME_SEEDS,
    "T1547": _PERSISTENCE_NAME_SEEDS,
}


def _api_seed_tokens(text: str) -> set[str]:
    tokens: set[str] = set()
    blob = str(text or "")
    for raw in re.findall(r"[A-Za-z_][A-Za-z0-9]*", blob):
        norm = normalize_api_symbol(raw).casefold()
        folded = raw.casefold()
        if norm in _NAME_ONLY_API_SEEDS:
            tokens.add(norm)
        elif folded in _NAME_ONLY_API_SEEDS:
            tokens.add(folded)
    return tokens


def _row_seed_blob(row: Mapping[str, object]) -> str:
    parts = [
        _flatten_report_how(row.get(key))
        for key in (
            "what", "how", "finding", "statement", "action", "object", "mechanism",
            "target", "inputs", "transformation_or_control", "conditions",
            "outputs", "consumers", "consumer",
        )
    ]
    return " ".join(item for item in parts if item)


def _name_only_behavior_seed(row: Mapping[str, object]) -> bool:
    """True when the row is only an API/import/task name without recovered HOW."""
    if not _api_seed_tokens(_row_seed_blob(row)):
        return False
    return not _finding_has_recovered_how(row)


def _blocked_attack_prefixes(row: Mapping[str, object]) -> tuple[str, ...]:
    if not _name_only_behavior_seed(row):
        return ()
    tokens = _api_seed_tokens(_row_seed_blob(row))
    return tuple(
        prefix
        for prefix, seeds in _OVERCLAIMED_ATTACK_PREFIXES.items()
        if tokens & seeds
    )


def _technique_matches_prefix(technique_id: object, prefixes: Iterable[str]) -> bool:
    text = str(technique_id or "").strip().upper()
    if not text:
        return False
    return any(text == prefix or text.startswith(f"{prefix}.") for prefix in prefixes)


def _filter_overclaimed_attack_techniques(
    techniques: Iterable[Mapping[str, object]] | None,
    prefixes: Iterable[str],
) -> list[dict[str, object]]:
    blocked = tuple(prefixes)
    if not blocked:
        return [dict(item) for item in techniques or () if isinstance(item, Mapping)]
    return [
        dict(item)
        for item in techniques or ()
        if isinstance(item, Mapping) and not _technique_matches_prefix(item.get("technique_id"), blocked)
    ]


def _apply_name_only_seed_downgrades(
    rows: Iterable[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Keep name-only CreateThread/APC/HTTP/schtasks/PPID/import seeds as CANDIDATE."""
    closed = {"VERIFIED", "SUPPORTED", "CONFIRMED", "INFERRED", "OBSERVED"}
    result: list[dict[str, object]] = []
    for raw in rows:
        row = dict(raw)
        prefixes = _blocked_attack_prefixes(row)
        if prefixes:
            techniques = row.get("attack_techniques")
            if isinstance(techniques, list):
                row["attack_techniques"] = _filter_overclaimed_attack_techniques(techniques, prefixes)
            mapping = row.get("attack_mapping")
            if isinstance(mapping, Mapping):
                mappings = mapping.get("mappings")
                if isinstance(mappings, list):
                    row["attack_mapping"] = {
                        **dict(mapping),
                        "mappings": _filter_overclaimed_attack_techniques(mappings, prefixes),
                    }
        if _name_only_behavior_seed(row):
            status = str(row.get("status") or row.get("finding_status") or row.get("verdict") or "").upper()
            if status in closed:
                row["status"] = "CANDIDATE"
                row["finding_status"] = "CANDIDATE"
                row["verdict"] = "CANDIDATE"
                row["validation_status"] = "CANDIDATE"
                row["maliciousness_assessment"] = "candidate_security_relevant_behavior"
                row["severity"] = "UNASSESSED"
                row["adversarial_downgrade"] = True
        result.append(row)
    return result


_STUB_IAT_API_NAMES = frozenset(
    {
        "loadlibrary",
        "loadlibrarya",
        "loadlibraryw",
        "loadlibraryex",
        "loadlibraryexa",
        "loadlibraryexw",
        "getprocaddress",
        "ldrloaddll",
        "ldrgetprocedureaddress",
    }
)
_PLAN_COMPLETED_STATUSES = frozenset(
    {"COMPLETED", "COMPLETE", "CLOSED", "DONE", "VERIFIED", "SUPPORTED", "CONFIRMED"}
)
_PLAN_BLOCKED_STATUSES = frozenset(
    {"BLOCKED", "FAILED", "STATIC_BOUNDARY", "NOT_APPLICABLE", "N/A", "NA"}
)
_PLAN_UNKNOWN_FIELD_ALIASES = {
    "creation_flags": "creation_flags",
    "creation flags": "creation_flags",
    "flags": "creation_flags",
    "start_routine": "start_routine",
    "start routine": "start_routine",
    "lpstartaddress": "start_routine",
    "lp_start_address": "start_routine",
    "parent_identity": "parent_identity",
    "parent identity": "parent_identity",
    "parent": "parent_identity",
    "parent_image": "parent_identity",
    "parent_name": "parent_identity",
}
_FUN_LABEL_RE = re.compile(r"FUN_[0-9A-Fa-f]+(?:@[0-9A-Fa-f]+)?", re.I)


def _task_investigation_snapshot(task: Any) -> dict[str, object]:
    strategy = getattr(task, "strategy_snapshot", None)
    if not isinstance(strategy, Mapping):
        return {}
    investigation = strategy.get("investigation")
    return dict(investigation) if isinstance(investigation, Mapping) else {}


def _extract_static_analysis_plan(source: object) -> dict[str, object]:
    """Read ``investigation.static_analysis_plan``. Missing key → empty plan."""
    if source is None:
        return {}
    if isinstance(source, Mapping) and (
        "items" in source or "packer_latch" in source or STATIC_ANALYSIS_PLAN_SNAPSHOT_KEY in source
    ):
        nested = source.get(STATIC_ANALYSIS_PLAN_SNAPSHOT_KEY)
        if isinstance(nested, (Mapping, list, tuple)):
            return _normalize_static_analysis_plan(nested)
        if "items" in source or "packer_latch" in source:
            return _normalize_static_analysis_plan(source)
    strategy = source
    if not isinstance(strategy, Mapping):
        strategy = getattr(source, "strategy_snapshot", None)
    if not isinstance(strategy, Mapping):
        return {}
    investigation = strategy.get("investigation")
    if not isinstance(investigation, Mapping):
        return {}
    raw = investigation.get(STATIC_ANALYSIS_PLAN_SNAPSHOT_KEY)
    if raw is None:
        return {}
    return _normalize_static_analysis_plan(raw)


def _normalize_static_analysis_plan(raw: object) -> dict[str, object]:
    """Tolerate a list of items or an object. Never raise on old-task shapes."""
    items_raw: object
    packer_latch = False
    schema_version = "1"
    if isinstance(raw, Mapping):
        items_raw = raw.get("items", raw.get("plan", raw.get("tasks")))
        packer_latch = bool(raw.get("packer_latch") or raw.get("packer") or raw.get("packed"))
        schema_version = str(raw.get("schema_version") or raw.get("version") or "1")
    else:
        items_raw = raw
    items: list[dict[str, object]] = []
    if isinstance(items_raw, Mapping):
        items_iter = items_raw.values()
    elif isinstance(items_raw, (list, tuple)):
        items_iter = items_raw
    else:
        items_iter = ()
    for index, item in enumerate(items_iter):
        if not isinstance(item, Mapping):
            continue
        item_id = str(item.get("id") or item.get("catalog_id") or f"plan-{index + 1}").strip()
        title = _plan_public_text(item.get("title") or item.get("question") or item_id)
        status = str(item.get("status") or "UNKNOWN").strip().upper() or "UNKNOWN"
        unknowns = [
            token
            for token in (_named_unknown_token(value) for value in _report_values(item.get("unknowns")))
            if token
        ]
        next_method = _plan_public_text(item.get("next_method") or item.get("next") or "")
        item_packer = bool(
            item.get("packer_latch")
            or str(item.get("kind") or "").casefold() in {"packer", "unpack", "stub"}
            or any(token in item_id.casefold() for token in ("packer", "unpack", "stub"))
            or any(token in title.casefold() for token in ("packer", "unpack", "packed stub"))
        )
        packer_latch = packer_latch or item_packer
        items.append(
            {
                "id": item_id,
                "title": title or item_id,
                "status": status,
                "bucket": _plan_status_bucket(status),
                "unknowns": unknowns,
                "next_method": next_method,
                "packer_latch": item_packer,
                "kind": str(item.get("kind") or item.get("catalog_id") or "").strip(),
            }
        )
    return {
        "schema_version": schema_version,
        "snapshot_key": STATIC_ANALYSIS_PLAN_SNAPSHOT_PATH,
        "packer_latch": packer_latch,
        "items": items,
    }


def _plan_status_bucket(status: str) -> str:
    upper = str(status or "").strip().upper()
    if upper in _PLAN_COMPLETED_STATUSES:
        return "completed"
    if upper in _PLAN_BLOCKED_STATUSES:
        return "blocked"
    return "unknown"


def _plan_public_text(value: object, limit: int = 240) -> str:
    """Analyst-facing plan text: no FUN_* dumps as payload HOW."""
    text = str(value or "").strip()
    if not text:
        return ""
    if _is_fun_call_sequence_dump(text):
        return ""
    text = _FUN_LABEL_RE.sub("", text)
    text = re.sub(r"\s{2,}", " ", text).strip(" ;,")
    return text[:limit]


def _named_unknown_token(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    match = re.fullmatch(r"UNKNOWN\(([^)]+)\)", text, re.I)
    if match:
        text = match.group(1).strip()
    key = re.sub(r"[\s-]+", "_", text.casefold())
    field = _PLAN_UNKNOWN_FIELD_ALIASES.get(text.casefold(), _PLAN_UNKNOWN_FIELD_ALIASES.get(key, key or text))
    if not field:
        return ""
    return f"UNKNOWN({field})"


def _is_stub_iat_capability(text: object) -> bool:
    """True for LoadLibrary/GetProcAddress-only IAT, not a recovered payload HOW."""
    blob = _flatten_report_how(text)
    if not blob:
        return False
    tokens = _api_seed_tokens(blob)
    stub_tokens = {item for item in tokens if item in _STUB_IAT_API_NAMES}
    if not stub_tokens:
        return False
    if tokens - _STUB_IAT_API_NAMES:
        return False
    folded = blob.casefold()
    dlls = re.findall(r"[a-z0-9_\-]+\.dll", folded)
    if any(name not in {"kernel32.dll", "ntdll.dll"} for name in dlls):
        return False
    match = re.search(r"lplibfilename\s*=\s*([^\s,;)]+)", folded)
    if match:
        module = match.group(1).strip("`'\"")
        if module not in {"", "unknown", "kernel32", "kernel32.dll", "ntdll", "ntdll.dll"}:
            return False
    return True


def _row_is_stub_iat_capability(row: Mapping[str, object]) -> bool:
    blob = " ".join(
        _flatten_report_how(row.get(key))
        for key in ("what", "how", "mechanism", "finding", "action", "transformation_or_control")
    )
    return _is_stub_iat_capability(blob)


def _static_plan_packer_latch(
    plan: Mapping[str, object] | None,
    findings: Iterable[Mapping[str, object]] | None = None,
    evidence_by_id: Mapping[str, Any] | None = None,
) -> bool:
    if isinstance(plan, Mapping) and plan.get("packer_latch"):
        return True
    for item in (plan or {}).get("items") or [] if isinstance(plan, Mapping) else ():
        if isinstance(item, Mapping) and item.get("packer_latch"):
            return True
    for finding in findings or ():
        if not isinstance(finding, Mapping):
            continue
        if finding.get("packer_latch") or finding.get("packer"):
            return True
        blob = " ".join(
            str(finding.get(key) or "")
            for key in ("catalog_id", "what", "how", "finding", "kind")
        ).casefold()
        if "packer_latch" in blob or "packed stub" in blob:
            return True
        if re.search(r"\b(?:packer|packed|unpack)\b", blob):
            return True
    for item in (evidence_by_id or {}).values():
        row = _evidence_mapping(item)
        blob = f"{row.get('kind') or ''} {row.get('value') or ''}".casefold()
        if "packer_latch" in blob or "packed stub" in blob:
            return True
    return False


def _evidence_has_recovered_creation_flags(evidence_rows: Iterable[Mapping[str, object]]) -> bool:
    for row in evidence_rows:
        kind = str(row.get("kind") or "").casefold()
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        if kind == "process_creation_flags":
            flags = value.get("creation_flags") or value.get("flags") or value.get("value")
            if flags not in (None, "", [], {}):
                return True
        blob = str(value)
        if re.search(r"creation_flags\s*[:=]\s*(?!UNKNOWN)", blob, re.I) and "unknown(creation_flags)" not in blob.casefold():
            return True
        if re.search(r"creation_flags\s*[:=]\s*0x[0-9a-f]+", blob, re.I):
            return True
    return False


def _evidence_token_present(
    evidence_rows: Iterable[Mapping[str, object]],
    tokens: tuple[str, ...],
    *,
    exclude: tuple[str, ...] = (),
) -> bool:
    """True when any row mentions one of ``tokens`` (and none of ``exclude``).

    This used to join every row's kind and value into one ledger-wide string and
    then substring-search it.  On a real 703-function sample the ledger holds
    ~40k rows / 6.7 GiB of JSON, so the join raised ``MemoryError`` and report
    synthesis died before it could publish anything - which is why completeness
    fixes looked like no-ops: the builder crashed instead of producing a body.

    Scanning row by row keeps peak memory to a single row's text and short
    circuits on the first hit.  Semantics are unchanged: a token counts when it
    appears in a row's own ``kind`` or ``value`` text.  ``exclude`` preserves the
    previous "present but explicitly unknown" behaviour for callers that need it.
    """
    for row in evidence_rows:
        text = f"{row.get('kind') or ''} {row.get('value') or ''}".casefold()
        if any(token in text for token in tokens) and not any(item in text for item in exclude):
            return True
    return False


def _evidence_has_process_seed(evidence_rows: Iterable[Mapping[str, object]]) -> bool:
    return _evidence_token_present(
        evidence_rows,
        ("createprocess", "createprocessw", "createprocessa", "shellexecute"),
    )


def _evidence_has_thread_seed(evidence_rows: Iterable[Mapping[str, object]]) -> bool:
    return _evidence_token_present(
        evidence_rows,
        ("createthread", "createthreadex", "queueuserapc", "rtlcreateuserthread", "ntcreatethread"),
    )


def _evidence_has_recovered_start_routine(evidence_rows: Iterable[Mapping[str, object]]) -> bool:
    for row in evidence_rows:
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        if not value:
            continue
        start = recovered_thread_start_address(value)
        if start and not str(start).startswith("UNKNOWN"):
            return True
    return False


def _evidence_has_parent_seed(evidence_rows: Iterable[Mapping[str, object]]) -> bool:
    return _evidence_token_present(
        evidence_rows,
        (
            "updateprocthreadattribute",
            "proc_thread_attribute_parent_process",
            "parent_handle_to_attribute",
            "parent-process",
            "parent_process",
        ),
    )


def _has_parent_handle_relation(rows: Iterable[Mapping[str, object]]) -> bool:
    """True when a recovered parent handle reaches the parent-process attribute."""
    for row in rows:
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        if not isinstance(value, Mapping):
            continue
        if str(value.get("relation") or "") == "parent_handle_to_attribute":
            return True
        if "parent_handle_to_attribute" in str(value):
            return True
    return False


def _evidence_has_recovered_parent_identity(evidence_rows: Iterable[Mapping[str, object]]) -> bool:
    """Require a typed parent image/name tied to the recovered attribute chain.

    A lone ``explorer.exe`` string is still not parent identity: many samples
    merely carry the name as data.  But the PPID join in ``static_analysis``
    now emits a *typed* ``parent_selection`` on the CreateProcess argument trace,
    and only when OpenProcess -> UpdateProcThreadAttribute(PARENT_PROCESS) ->
    CreateProcess resolved inside one function.  Rejecting ``explorer.exe``
    outright therefore threw away the one case where it is actually proven, and
    the report kept printing ``UNKNOWN(parent identity)`` while the mechanism
    claim held ``explorer.exe``.
    """
    rows = list(evidence_rows)
    chained = _has_parent_handle_relation(rows)
    for row in rows:
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        if not isinstance(value, Mapping):
            continue
        typed = str(value.get("parent_selection") or "").strip()
        if (
            typed
            and not typed.casefold().startswith("unknown")
            and chained
            and str(value.get("attribute") or "").strip()
        ):
            return True
        for key in ("parent_identity", "parent_image", "parent_name", "parent"):
            text = str(value.get(key) or "").strip()
            if text and not text.casefold().startswith("unknown") and text.casefold() != "explorer.exe":
                return True
        blob = str(value)
        if re.search(r"parent(?:_identity|_image|_name)?\s*[:=]\s*(?!UNKNOWN)(?!explorer\.exe)", blob, re.I):
            assigned = re.search(r"parent(?:_identity|_image|_name)?\s*[:=]\s*([^\s;]+)", blob, re.I)
            if assigned and assigned.group(1).casefold() not in {"explorer.exe", "unknown"}:
                return True
    return False


def _named_missing_process_thread_fields(
    evidence_by_id: Mapping[str, Any] | None = None,
    findings: Iterable[Mapping[str, object]] | None = None,
    plan: Mapping[str, object] | None = None,
) -> dict[str, list[str]]:
    """Named PROCESS/THREAD gaps: UNKNOWN(creation_flags|start_routine|parent_identity)."""
    missing: dict[str, list[str]] = {}
    evidence_rows = [_evidence_mapping(item) for item in (evidence_by_id or {}).values()]

    def add(catalog_id: str, field: str) -> None:
        token = field if field.startswith("UNKNOWN(") else f"UNKNOWN({field})"
        current = missing.setdefault(catalog_id, [])
        if token not in current:
            current.append(token)

    if _evidence_has_process_seed(evidence_rows) and not _evidence_has_recovered_creation_flags(evidence_rows):
        add("process-creation", "creation_flags")
    if _evidence_has_thread_seed(evidence_rows) and not _evidence_has_recovered_start_routine(evidence_rows):
        add("thread-and-callback", "start_routine")
    if _evidence_has_parent_seed(evidence_rows) and not _evidence_has_recovered_parent_identity(evidence_rows):
        add("parent-process-spoofing", "parent_identity")
    for finding in findings or ():
        if not isinstance(finding, Mapping):
            continue
        catalog_id = str(finding.get("catalog_id") or "")
        how = _flatten_report_how(finding.get("how") or finding.get("transformation_or_control"))
        what = _flatten_report_how(finding.get("what"))
        blob = f"{how} {what}".casefold()
        if catalog_id == "process-creation" and "creation_flags" not in blob:
            add("process-creation", "creation_flags")
        if catalog_id == "thread-and-callback" and "unknown(start_routine)" in blob:
            add("thread-and-callback", "start_routine")
        for unknown in _report_values(finding.get("unknowns")):
            token = _named_unknown_token(unknown)
            if token and catalog_id:
                add(catalog_id, token)
    if isinstance(plan, Mapping):
        for item in plan.get("items") or []:
            if not isinstance(item, Mapping):
                continue
            catalog_id = str(item.get("kind") or item.get("id") or "")
            for unknown in item.get("unknowns") or []:
                token = str(unknown)
                if token.startswith("UNKNOWN(") and catalog_id:
                    add(catalog_id, token)
    return missing


def _unclosed_named_reason(catalog_id: str, missing: Iterable[str] | None = None) -> str:
    named = [str(item) for item in (missing or []) if str(item).strip()]
    if named:
        rendered = ", ".join(named)
        return (
            f"{rendered}: {catalog_id} was seeded by typed evidence; "
            "named fields not recovered; static boundary"
        )
    return _unclosed_seed_reason(catalog_id)


def _deferred_missing_label(item: Mapping[str, object]) -> str:
    """Compact unanswered-lead label. Named PROCESS gaps beat a generic HOW."""
    catalog_id = str(item.get("catalog_id") or "").casefold()
    blob = " ".join(
        (
            _flatten_report_how(item.get("how")),
            _flatten_report_how(item.get("what")),
            " ".join(str(value) for value in _report_values(item.get("unknowns"))),
        )
    ).casefold()
    if catalog_id == "process-creation" or "creation_flags" in catalog_id:
        if "creation_flags=" not in blob or "unknown(creation_flags)" in blob:
            return "UNKNOWN(creation_flags)"
    if catalog_id == "parent-process-spoofing" or "parent_identity" in blob:
        if "parent_identity=" not in blob or "unknown(parent_identity)" in blob:
            return "UNKNOWN(parent_identity)"
    return "HOW"


def _project_static_analysis_plan_row(plan: Mapping[str, object] | None) -> dict[str, object] | None:
    if not isinstance(plan, Mapping) or not plan.get("items"):
        return None
    return {
        "type": "static_analysis_plan",
        "snapshot_key": STATIC_ANALYSIS_PLAN_SNAPSHOT_PATH,
        "schema_version": plan.get("schema_version") or "1",
        "packer_latch": bool(plan.get("packer_latch")),
        "items": [dict(item) for item in plan.get("items") or [] if isinstance(item, Mapping)],
    }


def build_catalog_behavior_matrix(
    findings: Iterable[Mapping[str, object]] | None = None,
    *,
    evidence_by_id: Mapping[str, Any] | None = None,
    catalog: BehaviorCatalog | None = None,
    static_analysis_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Project discovered catalogue rows only; unused categories stay off the page.

    Seeded high-value categories without a finding are returned as unclosed
    limitations, not as empty table rows.
    """
    catalog = catalog or BehaviorCatalog()
    evidence_by_id = evidence_by_id or {}
    plan = _normalize_static_analysis_plan(static_analysis_plan) if static_analysis_plan else {}
    packer_latch = _static_plan_packer_latch(plan, findings, evidence_by_id)
    named_missing = _named_missing_process_thread_fields(evidence_by_id, findings, plan)
    evidence_rows = [_evidence_mapping(item) for item in evidence_by_id.values()]
    seeded_ids = {entry.id for item in catalog.matching_evidence(evidence_rows) for entry in [item]}
    discovered: list[dict[str, object]] = []
    seen: set[str] = set()
    for finding in findings or ():
        if not isinstance(finding, Mapping):
            continue
        if _report_is_attribution(finding):
            continue
        entry = _catalog_entry_for_finding(catalog, finding)
        if entry is None:
            continue
        if entry.id == "unique-or-unknown" and str(finding.get("catalog_id") or "") not in {
            "unique-or-unknown",
            "unknown",
        }:
            continue
        if packer_latch and _row_is_stub_iat_capability(finding):
            continue
        if entry.id in seen:
            current = next(row for row in discovered if row["catalog_id"] == entry.id)
            extra_what = str(finding.get("what") or "").strip()
            if (
                extra_what
                and extra_what not in str(current.get("what") or "")
                and not _is_catalog_label_noise(extra_what, entry.id)
            ):
                current["what"] = f"{current.get('what')}; {extra_what}"
            extra_how = _catalog_row_how(
                finding,
                entry=entry,
                cited=_catalog_semantic_evidence_ids(
                    entry,
                    _report_ids(finding.get("evidence_ids") or finding.get("supporting_evidence_ids")),
                    evidence_by_id,
                ),
                evidence_by_id=evidence_by_id,
                current_how=str(current.get("how") or ""),
            )
            current_how = str(current.get("how") or "")
            persist_winner = _prefer_persist_how(current_how, extra_how)
            if persist_winner:
                current["how"] = persist_winner
            elif (
                extra_how
                and extra_how not in current_how
                and extra_how.casefold() != "not recovered"
                and not _is_fun_call_sequence_dump(extra_how)
                and not (_persist_argument_how(current_how) and not _persist_argument_how(extra_how))
            ):
                current["how"] = f"{current_how}; {extra_how}" if current_how else extra_how
            evidence_ids = current.setdefault("evidence_ids", [])
            for evidence_id in _report_ids(finding.get("evidence_ids") or finding.get("supporting_evidence_ids")):
                if evidence_id not in evidence_ids:
                    evidence_ids.append(evidence_id)
            continue
        seen.add(entry.id)
        what_text = finding.get("what") or finding.get("finding") or entry.id
        cited = _report_ids(finding.get("evidence_ids") or finding.get("supporting_evidence_ids"))
        how_ids = _catalog_semantic_evidence_ids(entry, cited, evidence_by_id)
        how_text = _catalog_row_how(
            finding,
            entry=entry,
            cited=how_ids,
            evidence_by_id=evidence_by_id,
        )
        discovered.append(
            {
                "type": "catalog_behavior",
                "catalog_id": entry.id,
                "category": entry.category,
                "what": str(what_text),
                "how": how_text,
                "status": str(finding.get("finding_status") or finding.get("status") or "CANDIDATE").upper(),
                "evidence_ids": how_ids[:8],
            }
        )
    _fold_unique_os_into_catalog(discovered, seen, evidence_by_id, catalog)
    named_discovered = [row for row in discovered if row["catalog_id"] != "unique-or-unknown"]
    if named_discovered:
        discovered = named_discovered
        seen = {str(row["catalog_id"]) for row in discovered}
    if packer_latch:
        discovered = [
            row for row in discovered
            if not _is_stub_iat_capability(row.get("how") or row.get("what"))
        ]
        seen = {str(row["catalog_id"]) for row in discovered}
        if "loader-and-api-resolution" in seeded_ids and "loader-and-api-resolution" not in seen:
            named_missing.setdefault("loader-and-api-resolution", [])
            token = "UNKNOWN(payload_how)"
            if token not in named_missing["loader-and-api-resolution"]:
                named_missing["loader-and-api-resolution"].append(token)
    unclosed = [
        {
            "catalog_id": entry.id,
            "status": "UNKNOWN",
            "reason": _unclosed_named_reason(entry.id, named_missing.get(entry.id)),
        }
        for entry in catalog.entries
        if entry.id in _HIGH_VALUE_UNCLOSED_CATALOG_IDS
        and entry.id in seeded_ids
        and entry.id not in seen
    ]
    if "network-transport" not in seen and not any(
        str(item.get("catalog_id") or "") == "network-transport" for item in unclosed
    ):
        unclosed.append(
            {
                "catalog_id": "network-transport",
                "status": "UNKNOWN",
                "reason": (
                    "HTTP transport API not recovered; decoded URLs and "
                    "WinHTTP-export-not-found strings are not a transport path"
                ),
            }
        )
    if "parent-process-spoofing" not in seen and not any(
        str(item.get("catalog_id") or "") == "parent-process-spoofing" for item in unclosed
    ):
        unclosed.append(
            {
                "catalog_id": "parent-process-spoofing",
                "status": "UNKNOWN",
                "reason": _ppid_remainder_reason(evidence_rows),
            }
        )
    return {
        "type": "catalog_behavior_matrix",
        "discovered": discovered,
        "unclosed_high_value": unclosed,
    }


def _unclosed_seed_reason(catalog_id: str) -> str:
    return (
        f"UNKNOWN(what/how): {catalog_id} was seeded by typed evidence; "
        "no recovered finding; static boundary"
    )


def _unique_os_catalog_how(thread: Mapping[str, object]) -> str:
    api = str(thread.get("api") or "CreateThread")
    return (
        f"{api} start={thread.get('start_routine') or 'UNKNOWN(start_routine)'}; "
        f"parameter={thread.get('parameter') or 'UNKNOWN(parameter)'}; "
        f"loop={thread.get('loop') or 'UNKNOWN(loop)'}; "
        f"exit={thread.get('exit') or 'UNKNOWN(exit)'}; "
        f"emulator={thread.get('emulator_status') or 'NOT_ATTEMPTED'}"
    )


def _fold_unique_os_into_catalog(
    discovered: list[dict[str, object]],
    seen: set[str],
    evidence_by_id: Mapping[str, Any],
    catalog: BehaviorCatalog,
) -> None:
    """Recovered Unique OS start/loop/exit is the thread-and-callback How, not an open gap."""
    entry = catalog.by_id("thread-and-callback")
    for thread in build_unique_execution_threads(evidence_by_id):
        start = str(thread.get("start_routine") or "")
        if not start or start.upper().startswith("UNKNOWN"):
            continue
        how = _unique_os_catalog_how(thread)
        what = (
            f"{thread.get('api') or 'CreateThread'} start={start}; "
            f"exit={thread.get('exit') or 'UNKNOWN(exit)'}; "
            "runtime thread start is unverified"
        )
        evidence_ids = [str(item) for item in (thread.get("evidence_ids") or []) if item][:8]
        if "thread-and-callback" in seen:
            current = next(row for row in discovered if row["catalog_id"] == "thread-and-callback")
            persist_winner = _prefer_persist_how(current.get("how"), how)
            if persist_winner:
                current["how"] = persist_winner
            elif "start=" in how.casefold() and "start=" not in str(current.get("how") or "").casefold():
                current["how"] = how
            continue
        seen.add("thread-and-callback")
        discovered.append(
            {
                "type": "catalog_behavior",
                "catalog_id": "thread-and-callback",
                "category": entry.category if entry is not None else "thread",
                "what": what,
                "how": how,
                "status": "CANDIDATE",
                "evidence_ids": evidence_ids,
            }
        )


def _ppid_remainder_reason(evidence_rows: Iterable[Mapping[str, object]]) -> str:
    """Write PPID as UNKNOWN remainder. Do not treat 0x000f4240 as 0x09080008."""
    blob = " ".join(
        f"{row.get('kind') or ''} {row.get('value') or ''} {row.get('anchor') or ''}"
        for row in evidence_rows
        if isinstance(row, Mapping)
    ).casefold()
    has_chain = any(
        token in blob
        for token in (
            "updateprocthreadattribute",
            "proc_thread_attribute_parent_process",
            "parent_handle_to_attribute",
        )
    )
    if "0x09080008" in blob.replace(" ", ""):
        return (
            "UNKNOWN(what/how): parent-process-spoofing was seeded; "
            "no recovered finding; static boundary"
        )
    if has_chain:
        return (
            "PPID specialist token 0x09080008 not recovered; "
            "OpenProcess/UpdateProcThreadAttribute/CreateProcess is recorded "
            "and creation flags remain PARTIAL"
        )
    return (
        "parent-process spoofing chain not recovered; CreateProcess flags "
        "alone do not prove PPID spoofing"
    )


def _unique_thread_api_name(value: Mapping[str, object]) -> str | None:
    for key in ("api", "api_name", "target_name", "target_function", "callee"):
        text = str(value.get(key) or "").strip()
        if not text:
            continue
        normalized = re.sub(r"^[^!]+!", "", text).rsplit(".", 1)[-1].casefold()
        if any(marker in normalized for marker in _UNIQUE_THREAD_API_MARKERS) and "createremotethread" not in normalized:
            return text
    nested = value.get("call_targets")
    if isinstance(nested, list):
        for item in nested:
            if isinstance(item, Mapping):
                found = _unique_thread_api_name(item)
                if found:
                    return found
    return None


def _canonical_unique_thread_api(api: str) -> str:
    text = re.sub(r"^[^!]+!", "", str(api or "")).rsplit(".", 1)[-1]
    match = re.match(r"(?:PTR_|IAT_|imp_)?(CreateThread(?:Ex)?)", text, re.I)
    if match:
        return match.group(1)
    return text


def _thread_emulator_status(
    *,
    start: str,
    entry: str,
    emulator_by_entry: Mapping[str, str],
    overall_emu: str,
) -> str:
    """Prefer a real worker status. Persist SUPERSEDED placeholders are not Unique OS HOW."""
    placeholder = ""
    for key in _address_lookup_keys(start, entry):
        status = str(emulator_by_entry.get(key) or "")
        if not status:
            continue
        if status.upper() in _EMU_PLACEHOLDER_STATUSES:
            placeholder = placeholder or status
            continue
        return status
    if overall_emu == "SUCCEEDED":
        return "OVERALL_SUCCEEDED"
    if placeholder:
        return placeholder
    return "NOT_ATTEMPTED"


def _looks_like_code_address(value: object) -> bool:
    text = str(value or "").strip()
    if re.fullmatch(r"(?:FUN_|sub_|thunk_)[0-9a-fA-F]+", text):
        return True
    match = re.fullmatch(r"(?:0x)?([0-9a-fA-F]+)", text)
    return bool(match and len(match.group(1)) >= 5)


def _thread_argument_trace_payload(
    api: str,
    arguments: object,
    *,
    function_entry: str = "",
    callsite: object = None,
) -> dict[str, object]:
    """Normalize GET_DECOMPILE argument_index rows onto the TRACE argument shape."""
    names = _API_ARGUMENT_NAMES.get(normalize_api_symbol(api), ())
    rows: list[dict[str, object]] = []
    if isinstance(arguments, (list, tuple)):
        for item in arguments:
            if not isinstance(item, Mapping):
                continue
            index = item.get("index", item.get("argument_index"))
            payload = dict(item)
            payload["index"] = index
            name = str(item.get("name") or "").strip()
            if not name and isinstance(index, int) and 0 <= index < len(names):
                name = names[index]
            if name:
                payload["name"] = name
            if payload.get("resolved") is not True:
                payload["resolved"] = _argument_is_meaningful(item)
            rows.append(payload)
    result: dict[str, object] = {"api": api, "function_entry": function_entry, "arguments": rows}
    if callsite not in (None, ""):
        result["callsite"] = callsite
    return result


def _semantic_thread_payloads(row: Mapping[str, object]) -> list[dict[str, object]]:
    kind = str(row.get("kind") or "")
    value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
    payload: dict[str, object] = dict(value)
    if kind == "decompile_slice":
        nested_fn = value.get("function")
        nested = value.get("summary")
        if isinstance(nested_fn, Mapping):
            payload.update(nested_fn)
        if isinstance(nested, Mapping):
            payload.update(nested)
    elif kind != "function_semantic_summary":
        return []
    entry = str(
        (row.get("anchor") or {}).get("function_entry")
        if isinstance(row.get("anchor"), Mapping)
        else ""
    ) or str(payload.get("function_entry") or payload.get("entry") or "")
    found: list[dict[str, object]] = []
    calls = payload.get("call_sequence")
    if not isinstance(calls, (list, tuple)):
        return found
    for call in calls:
        if not isinstance(call, Mapping):
            continue
        api = _unique_thread_api_name(call)
        if not api:
            continue
        found.append(
            _thread_argument_trace_payload(
                api,
                call.get("arguments"),
                function_entry=entry,
                callsite=call.get("callsite"),
            )
        )
    return found


def _semantic_thread_lookup(
    evidence_by_id: Mapping[str, Any],
) -> dict[tuple[str, str], dict[str, object]]:
    lookup: dict[tuple[str, str], dict[str, object]] = {}
    for item in evidence_by_id.values():
        row = _evidence_mapping(item)
        for payload in _semantic_thread_payloads(row):
            api = str(payload.get("api") or "")
            entry = str(payload.get("function_entry") or "")
            key = (entry, api.casefold())
            start = recovered_thread_start_address(payload)
            if start and not _looks_like_code_address(start):
                start = None
            parameter = recovered_thread_parameter(payload)
            current = lookup.get(key)
            current_start = str((current or {}).get("start_routine") or "")
            if current is None or (start and (not current_start or current_start.startswith("UNKNOWN"))):
                lookup[key] = {
                    "api": api,
                    "function_entry": entry,
                    "start_routine": start,
                    "parameter": parameter,
                    "row_id": str(row.get("id") or ""),
                }
    return lookup


def build_unique_execution_threads(
    evidence_by_id: Mapping[str, Any] | None = None,
) -> list[dict[str, object]]:
    """Surface OS thread/callback starts as a distinct report object from injection."""
    evidence_by_id = evidence_by_id or {}
    emulator_by_entry: dict[str, str] = {}
    overall_emu = ""
    for item in evidence_by_id.values():
        row = _evidence_mapping(item)
        if str(row.get("kind") or "") != "simulation_result":
            continue
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        anchor = row.get("anchor") if isinstance(row.get("anchor"), Mapping) else {}
        entry = str(anchor.get("function_entry") or value.get("function_entry") or "")
        status = str(value.get("status") or "UNKNOWN")
        folded = status.upper()
        placeholder = folded in _EMU_PLACEHOLDER_STATUSES
        if folded == "SUCCEEDED":
            overall_emu = "SUCCEEDED"
        for key in _address_lookup_keys(entry):
            existing = str(emulator_by_entry.get(key) or "")
            if placeholder:
                emulator_by_entry.setdefault(key, status)
                continue
            if existing.upper() in _EMU_PLACEHOLDER_STATUSES or folded == "SUCCEEDED" or not existing:
                emulator_by_entry[key] = status
    semantic_starts = _semantic_thread_lookup(evidence_by_id)
    rows = sorted(
        (_evidence_mapping(item) for item in evidence_by_id.values()),
        key=lambda row: (0 if str(row.get("kind") or "") == "api_argument_trace" else 1, str(row.get("id") or "")),
    )
    threads: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        api = _unique_thread_api_name(value)
        if not api:
            continue
        anchor = row.get("anchor") if isinstance(row.get("anchor"), Mapping) else {}
        entry = str(
            anchor.get("function_entry")
            or value.get("function_entry")
            or value.get("entry")
            or ""
        )
        start = recovered_thread_start_address(value) or str(
            value.get("start_routine")
            or value.get("lpStartAddress")
            or value.get("start_address")
            or ""
        )
        if start and not _looks_like_code_address(start):
            start = ""
        parameter = recovered_thread_parameter(value) or str(
            value.get("parameter") or value.get("lpParameter") or ""
        )
        lookup = semantic_starts.get((entry, api.casefold())) or semantic_starts.get(
            (entry, _canonical_unique_thread_api(api).casefold())
        )
        if lookup:
            start = start or str(lookup.get("start_routine") or "")
            if start and not _looks_like_code_address(start):
                start = ""
            parameter = parameter or str(lookup.get("parameter") or "")
        canonical_api = _canonical_unique_thread_api(api)
        identity = (entry, canonical_api.casefold())
        if identity in seen:
            if start and _looks_like_code_address(start):
                for thread in threads:
                    if (
                        str(thread.get("function_entry") or "") == (entry or "UNKNOWN(function_entry)")
                        and _canonical_unique_thread_api(str(thread.get("api") or "")).casefold() == canonical_api.casefold()
                        and str(thread.get("start_routine") or "").startswith("UNKNOWN")
                    ):
                        thread["start_routine"] = start
                        if parameter:
                            thread["parameter"] = parameter or thread.get("parameter")
            continue
        seen.add(identity)
        loop, exit_cond, shared = _thread_body_from_evidence(evidence_by_id, start)
        start_text = start or "UNKNOWN(start_routine)"
        normalized_api = canonical_api.casefold()
        is_creator = any(marker in normalized_api for marker in _THREAD_START_CREATOR_MARKERS)
        if str(start_text).startswith("UNKNOWN") and not is_creator:
            continue
        emulator_status = _thread_emulator_status(
            start=start, entry=entry, emulator_by_entry=emulator_by_entry, overall_emu=overall_emu
        )
        evidence_ids = [str(row.get("id") or "")]
        if lookup and lookup.get("row_id") and str(lookup["row_id"]) not in evidence_ids:
            evidence_ids.append(str(lookup["row_id"]))
        threads.append(
            {
                "type": "unique_execution_thread",
                "api": canonical_api or api,
                "function_entry": entry or "UNKNOWN(function_entry)",
                "start_routine": start or "UNKNOWN(start_routine)",
                "parameter": parameter or "UNKNOWN(parameter)",
                "loop": loop,
                "exit": exit_cond,
                "shared_state": shared,
                "emulator_status": emulator_status,
                "evidence_ids": evidence_ids,
            }
        )
    for identity, item in semantic_starts.items():
        api = str(item.get("api") or "")
        entry = str(item.get("function_entry") or "")
        canonical_api = _canonical_unique_thread_api(api)
        canonical_identity = (entry, canonical_api.casefold())
        if canonical_identity in seen or identity in seen:
            continue
        start = str(item.get("start_routine") or "")
        parameter = str(item.get("parameter") or "")
        loop, exit_cond, shared = _thread_body_from_evidence(evidence_by_id, start)
        start_text = start or "UNKNOWN(start_routine)"
        normalized_api = canonical_api.casefold()
        is_creator = any(marker in normalized_api for marker in _THREAD_START_CREATOR_MARKERS)
        if str(start_text).startswith("UNKNOWN") and not is_creator:
            continue
        seen.add(canonical_identity)
        emulator_status = _thread_emulator_status(
            start=start, entry=entry, emulator_by_entry=emulator_by_entry, overall_emu=overall_emu
        )
        threads.append(
            {
                "type": "unique_execution_thread",
                "api": canonical_api or api,
                "function_entry": entry or "UNKNOWN(function_entry)",
                "start_routine": start or "UNKNOWN(start_routine)",
                "parameter": parameter or "UNKNOWN(parameter)",
                "loop": loop,
                "exit": exit_cond,
                "shared_state": shared,
                "emulator_status": emulator_status,
                "evidence_ids": [str(item.get("row_id") or "")],
            }
        )
    if not threads:
        pe = build_pe_basics_projection(evidence_by_id) or {}
        for name in pe.get("imports") or []:
            canonical = _canonical_unique_thread_api(str(name or ""))
            normalized = canonical.casefold()
            if (
                any(marker in normalized for marker in _THREAD_START_CREATOR_MARKERS)
                and "createremotethread" not in normalized
            ):
                threads.append(
                    {
                        "type": "unique_execution_thread",
                        "api": canonical,
                        "function_entry": "UNKNOWN(function_entry)",
                        "start_routine": "UNKNOWN(start_routine)",
                        "parameter": "UNKNOWN(parameter)",
                        "loop": "UNKNOWN(loop)",
                        "exit": "UNKNOWN(exit)",
                        "shared_state": "UNKNOWN(shared_state)",
                        "emulator_status": _thread_emulator_status(
                            start="",
                            entry="",
                            emulator_by_entry=emulator_by_entry,
                            overall_emu=overall_emu,
                        ),
                        "evidence_ids": [],
                    }
                )
                break
        if not threads and pe.get("entry_rva") not in (None, ""):
            threads.append(
                {
                    "type": "unique_execution_thread",
                    "api": "UNKNOWN(thread_api)",
                    "function_entry": "UNKNOWN(function_entry)",
                    "start_routine": "UNKNOWN(start_routine)",
                    "parameter": "UNKNOWN(parameter)",
                    "loop": "UNKNOWN(loop)",
                    "exit": "UNKNOWN(exit)",
                    "shared_state": "UNKNOWN(shared_state)",
                    "emulator_status": _thread_emulator_status(
                        start="",
                        entry="",
                        emulator_by_entry=emulator_by_entry,
                        overall_emu=overall_emu,
                    ),
                    "evidence_ids": [],
                }
            )
    return threads[:16]


_THREAD_EXIT_APIS = frozenset(
    {
        "exitthread",
        "terminatethread",
        "exitprocess",
        "rtlexituserthread",
        "ntterminateprocess",
        "ntterminatethread",
    }
)
_THREAD_WAIT_APIS = frozenset(
    {
        "waitforsingleobject",
        "waitformultipleobjects",
        "waitonaddress",
        "msgwaitformultipleobjects",
        "ntwaitforsingleobject",
        "sleepex",
    }
)


def _immediate_hex_values(value: object) -> list[int]:
    """Recover integer immediates from nested static payload text."""
    blob = str(value or "")
    found: list[int] = []
    for match in re.finditer(r"0x0*([0-9A-Fa-f]+)\b", blob):
        try:
            parsed = int(match.group(1), 16)
        except ValueError:
            continue
        found.append(parsed)
    return found


def _recovered_crypto_algids(
    evidence_by_id: Mapping[str, Any] | None = None,
    *,
    function_entry: str = "",
    payload: Mapping[str, object] | None = None,
) -> list[tuple[int, str]]:
    """Decode CryptoAPI ALG_IDs from a function payload or same-entry evidence."""
    hits: list[tuple[int, str]] = []
    seen: set[int] = set()
    entry_keys = set(_address_lookup_keys(function_entry)) if function_entry else set()

    def consider(blob: object) -> None:
        for parsed in _immediate_hex_values(blob):
            name = _CRYPTO_ALG_IDS.get(parsed)
            if name and parsed not in seen:
                seen.add(parsed)
                hits.append((parsed, name))

    if payload is not None:
        consider(payload)
    for item in (evidence_by_id or {}).values():
        row = _evidence_mapping(item)
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        anchor = row.get("anchor") if isinstance(row.get("anchor"), Mapping) else {}
        row_entry = str(
            (value or {}).get("function_entry")
            or (value or {}).get("entry")
            or (anchor or {}).get("function_entry")
            or ""
        )
        if entry_keys and row_entry and not (set(_address_lookup_keys(row_entry)) & entry_keys):
            continue
        consider(value)
        consider(anchor)
    return hits


def _with_decoded_crypto_algids(
    calls: list[str],
    how: str,
    algids: list[tuple[int, str]],
) -> tuple[list[str], str]:
    if not algids:
        return calls, how
    labels = [f"0x{algid:x} ({name})" for algid, name in algids]
    note = "decoded " + ", ".join(labels)
    annotated = list(calls)
    if not any("CALG_" in str(item) for item in annotated):
        annotated.append(note)
    if "CALG_" not in (how or ""):
        how = f"{how}; {note}" if how else note
    return annotated, how


def _format_semantic_call(call: Mapping[str, object]) -> str:
    api = str(
        call.get("api")
        or call.get("target_name")
        or call.get("target_function")
        or call.get("name")
        or ""
    ).strip()
    if not api:
        return ""
    visible, _ = _partition_arguments(call.get("arguments"))
    names = _API_ARGUMENT_NAMES.get(normalize_api_symbol(api), ())
    bits: list[str] = []
    for argument in visible[:6]:
        index = argument.get("argument_index", argument.get("index"))
        name = str(argument.get("name") or "").strip()
        if not name and isinstance(index, int) and 0 <= index < len(names):
            name = names[index]
        value = str(argument.get("value") or "").strip()
        if not value:
            continue
        bit = (
            f"{name}={_decode_known_constant(api, name, value)}"
            if name
            else _decode_known_constant(api, name, value)
        )
        if bit not in bits:
            bits.append(bit)
    return f"{api}({', '.join(bits)})" if bits else api


def _parse_immediate(value: str) -> int | None:
    text = str(value or "").strip().rstrip(",")
    try:
        return int(text, 0)
    except ValueError:
        return None


def _decode_known_constant(api: str, name: str, value: str) -> str:
    parsed = _parse_immediate(value)
    if parsed is None:
        return value
    api_n = normalize_api_symbol(api)
    name_n = name.casefold()
    if "crypt" in api_n and parsed in _CRYPTO_ALG_IDS:
        return f"{value} ({_CRYPTO_ALG_IDS[parsed]})"
    if "virtualprotect" in api_n or "flnewprotect" in name_n:
        label = _PAGE_PROTECT.get(parsed)
        if label:
            return f"{value} ({label})"
    if "getexitcode" in api_n and parsed == 0x103:
        return f"{value} (STILL_ACTIVE)"
    if "dwcreationflags" in name_n:
        flags = decode_windows_process_creation_flags(parsed).get("set_flags") or []
        if flags:
            return f"{value} ({'|'.join(str(item) for item in flags)})"
    return value


def _predicate_texts(value: Mapping[str, object]) -> list[str]:
    raw_conditions = value.get("conditions")
    if not isinstance(raw_conditions, (list, tuple)):
        return []
    texts = [
        str(item.get("text") or "").strip()
        for item in raw_conditions
        if isinstance(item, Mapping) and str(item.get("text") or "").strip()
    ]
    with_imm = [text for text in texts if re.search(r"0x[0-9A-Fa-f]+", text)]
    return list(dict.fromkeys([*with_imm, *texts]))[:6]


def _how_from_semantic_payload(value: Mapping[str, object]) -> str:
    calls = value.get("call_sequence")
    meaningful, _ = _meaningful_semantic_calls(list(calls) if isinstance(calls, tuple) else calls)
    formatted = [item for item in (_format_semantic_call(call) for call in meaningful[:12]) if item]
    names = formatted or function_call_names(value)
    raw_function = value.get("function")
    if isinstance(raw_function, Mapping):
        function = str(raw_function.get("name") or "").strip()
    else:
        function = str(raw_function or "").strip()
    entry = str(value.get("function_entry") or value.get("entry") or "").strip()
    consumers: list[str] = []
    raw_consumers = value.get("consumers")
    if isinstance(raw_consumers, (list, tuple)):
        for item in raw_consumers[:4]:
            if isinstance(item, Mapping) and item.get("api"):
                consumers.append(str(item["api"]))
    predicates = _predicate_texts(value)
    parts: list[str] = []
    loc = "@".join(piece for piece in (function, entry) if piece)
    if names:
        path = " -> ".join(names[:12])
        parts.append(f"{loc}: {path}" if loc else path)
    elif loc:
        parts.append(loc)
    if consumers:
        parts.append("consumer=" + ", ".join(dict.fromkeys(consumers)))
    if predicates:
        parts.append("predicate=" + "; ".join(predicates))
    return "; ".join(parts)


def _how_from_semantic_evidence(
    evidence_ids: Iterable[str],
    evidence_by_id: Mapping[str, Any],
) -> str:
    """Build module-level HOW from GET_DECOMPILE rows, not XOR or API lists."""
    chunks: list[str] = []
    for evidence_id in evidence_ids:
        item = evidence_by_id.get(evidence_id)
        if item is None:
            continue
        row = _evidence_mapping(item)
        kind = str(row.get("kind") or "")
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        if kind == "function_semantic_summary":
            chunk = _how_from_semantic_payload(value)
            if chunk:
                chunks.append(chunk)
            continue
        if kind != "decompile_slice":
            continue
        nested_fn = value.get("function")
        nested = value.get("summary")
        payload: dict[str, object] = {}
        if isinstance(nested_fn, Mapping):
            payload.update(nested_fn)
        if isinstance(nested, Mapping):
            payload.update(nested)
        chunk = _how_from_semantic_payload(payload)
        if chunk:
            chunks.append(chunk)
    return "; ".join(dict.fromkeys(chunks))


def _semantic_row_text(row: Mapping[str, object]) -> str:
    value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
    payload: dict[str, object] = dict(value)
    if str(row.get("kind") or "") == "decompile_slice":
        nested_fn = value.get("function")
        nested = value.get("summary")
        if isinstance(nested_fn, Mapping):
            payload.update(nested_fn)
        if isinstance(nested, Mapping):
            payload.update(nested)
    parts = [_how_from_semantic_payload(payload)]
    calls = payload.get("call_sequence")
    if isinstance(calls, (list, tuple)):
        for call in calls:
            if isinstance(call, Mapping):
                parts.append(str(call.get("api") or ""))
    return " ".join(parts).casefold()


def _catalog_semantic_evidence_ids(
    entry: Any,
    cited_ids: Iterable[str],
    evidence_by_id: Mapping[str, Any],
) -> list[str]:
    ids = list(dict.fromkeys(str(item) for item in cited_ids if str(item)))
    seeds = tuple(
        str(seed).strip()
        for seed in (getattr(entry, "discovery_seeds", ()) or ())
        if str(seed).strip()
    ) if entry is not None else ()
    useful_seeds = tuple(seed for seed in seeds if len(seed) >= 5)
    if not useful_seeds:
        return ids
    cited_artifacts = {
        str(_evidence_mapping(evidence_by_id[item]).get("artifact_id") or "")
        for item in ids
        if item in evidence_by_id
    }
    cited_artifacts.discard("")
    if not cited_artifacts:
        return ids
    for item in evidence_by_id.values():
        row = _evidence_mapping(item)
        if str(row.get("kind") or "") not in {"function_semantic_summary", "decompile_slice"}:
            continue
        evidence_id = str(row.get("id") or "")
        if not evidence_id or evidence_id in ids:
            continue
        if str(row.get("artifact_id") or "") not in cited_artifacts:
            continue
        blob = _semantic_row_text(row)
        if any(seed.casefold() in blob for seed in useful_seeds):
            ids.append(evidence_id)
    return ids


def _evidence_function_entry(row: Mapping[str, object], value: Mapping[str, object]) -> str:
    """Join persist FUN_ names, hex entries, and nested Ghidra function maps."""
    anchor = row.get("anchor") if isinstance(row.get("anchor"), Mapping) else {}

    def first_locator(*candidates: object) -> str:
        for candidate in candidates:
            if candidate in (None, "") or isinstance(candidate, Mapping):
                continue
            text = str(candidate).strip()
            if text:
                return text
        return ""

    entry = first_locator(
        anchor.get("function_entry"),
        value.get("function_entry"),
        value.get("entry"),
        value.get("entry_rva"),
        value.get("name"),
        value.get("function"),
    )
    if entry:
        return entry
    nested_fn = value.get("function")
    if isinstance(nested_fn, Mapping):
        return first_locator(
            nested_fn.get("entry"),
            nested_fn.get("entry_rva"),
            nested_fn.get("name"),
            nested_fn.get("function"),
        )
    return ""




def _instruction_texts(value: Mapping[str, object]) -> list[str]:
    texts: list[str] = []
    for key in ("instructions", "disassembly", "ops"):
        items = value.get(key)
        if not isinstance(items, (list, tuple)):
            continue
        for item in items:
            if isinstance(item, Mapping):
                text = item.get("text") or item.get("mnemonic") or item.get("op")
                if text not in (None, ""):
                    texts.append(str(text))
            elif isinstance(item, str) and item.strip():
                texts.append(item.strip())
    return texts


def _api_leaf_name(name: str) -> str:
    return re.sub(r"^[^!]+!", "", name).rsplit(".", 1)[-1].casefold()


def _thread_exit_from_names_and_ops(call_names: Iterable[str], instruction_texts: Iterable[str]) -> str:
    exit_names = [name for name in call_names if _api_leaf_name(str(name)) in _THREAD_EXIT_APIS]
    if exit_names:
        return "returns via " + ", ".join(list(dict.fromkeys(exit_names))[:4])
    ops = " ".join(str(item) for item in instruction_texts)
    if re.search(r"(?i)\b(retn?|iret)\b", ops):
        return "returns from start routine"
    for text in instruction_texts:
        leaf = _api_leaf_name(str(text))
        if any(api in leaf for api in _THREAD_EXIT_APIS):
            return "returns via " + str(text)
    return ""


def _is_local_function_callee(name: str) -> bool:
    folded = str(name or "").strip().casefold()
    if not folded:
        return False
    if folded.startswith(("fun_", "sub_", "thunk_")):
        return True
    return bool(re.fullmatch(r"(?:0x)?[0-9a-f]{6,}", folded))


def _thread_exit_from_one_hop_callees(
    evidence_by_id: Mapping[str, Any],
    call_names: Iterable[str],
    start: str,
) -> str:
    start_keys = set(_address_lookup_keys(start))
    for name in call_names:
        if not _is_local_function_callee(str(name)):
            continue
        callee_keys = set(_address_lookup_keys(name))
        if start_keys & callee_keys:
            continue
        for item in evidence_by_id.values():
            row = _evidence_mapping(item)
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            entry = _evidence_function_entry(row, value)
            if not (callee_keys & set(_address_lookup_keys(entry, value.get("name"), value.get("function")))):
                continue
            recovered = _thread_exit_from_names_and_ops(
                function_call_names(value),
                _instruction_texts(value),
            )
            if recovered:
                return recovered
    return ""


def _wait_loop_exit(call_names: Iterable[str], loop: str) -> str:
    blob = " ".join((*[str(item) for item in call_names], str(loop or ""))).casefold()
    if any(api in blob for api in _THREAD_WAIT_APIS):
        return "wait-loop; no ExitThread recovered"
    return ""


def _thread_body_from_evidence(
    evidence_by_id: Mapping[str, Any],
    start: str,
) -> tuple[str, str, str]:
    loop = "UNKNOWN(loop)"
    exit_cond = "UNKNOWN(exit)"
    shared = "UNKNOWN(shared_state)"
    start_keys = set(_address_lookup_keys(start))
    start_call_names: list[str] = []
    start_ops: list[str] = []
    if not start_keys or str(start or "").strip().casefold().startswith("unknown"):
        return loop, exit_cond, shared
    ghidra_kinds = frozenset({"function_semantic_summary", "decompile_slice"})
    fallback_kinds = frozenset({"function_context", "function", "cfg_block", "function_instruction_window"})

    def consume(kinds: frozenset[str]) -> None:
        nonlocal loop, exit_cond, shared
        for item in evidence_by_id.values():
            row = _evidence_mapping(item)
            kind = str(row.get("kind") or "")
            if kind not in kinds:
                continue
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            entry = _evidence_function_entry(row, value)
            if not (start_keys & set(_address_lookup_keys(entry))):
                continue
            payload = dict(value)
            if kind == "decompile_slice":
                nested_fn = value.get("function")
                nested = value.get("summary")
                if isinstance(nested_fn, Mapping):
                    payload.update(nested_fn)
                if isinstance(nested, Mapping):
                    payload.update(nested)
            if loop.startswith("UNKNOWN") and (payload.get("loop") or payload.get("back_edge")):
                loop = str(payload.get("loop") or payload.get("back_edge"))
            if exit_cond.startswith("UNKNOWN") and (payload.get("exit") or payload.get("return_condition")):
                exit_cond = str(payload.get("exit") or payload.get("return_condition"))
            if shared.startswith("UNKNOWN") and (payload.get("shared_state") or payload.get("parameter_object")):
                shared = str(payload.get("shared_state") or payload.get("parameter_object"))
            call_names = function_call_names(payload)
            ops = _instruction_texts(payload)
            start_call_names.extend(call_names)
            start_ops.extend(ops)
            if loop.startswith("UNKNOWN") and call_names:
                loop = " -> ".join(call_names[:8])
            if loop.startswith("UNKNOWN") and kind in ghidra_kinds:
                predicates = [
                    str(item.get("text"))
                    for item in (payload.get("conditions") or ())
                    if isinstance(item, Mapping) and item.get("text")
                ]
                if predicates:
                    loop = "predicate " + "; ".join(predicates[:3])
            if exit_cond.startswith("UNKNOWN"):
                recovered_exit = _thread_exit_from_names_and_ops(call_names, ops)
                if recovered_exit:
                    exit_cond = recovered_exit
            if shared.startswith("UNKNOWN"):
                consumers = payload.get("consumers")
                names = [
                    str(item.get("api") or "")
                    for item in (consumers if isinstance(consumers, (list, tuple)) else ())[:4]
                    if isinstance(item, Mapping) and item.get("api")
                ]
                if names:
                    shared = "; ".join(names)
            if shared.startswith("UNKNOWN"):
                references = payload.get("data_references")
                texts: list[str] = []
                if isinstance(references, (list, tuple)):
                    for reference in references[:8]:
                        if isinstance(reference, Mapping):
                            text = reference.get("text") or reference.get("name") or reference.get("target_name")
                            if text not in (None, ""):
                                texts.append(str(text))
                        elif isinstance(reference, str) and reference.strip():
                            texts.append(reference.strip())
                if texts:
                    shared = "; ".join(texts[:4])

    consume(ghidra_kinds)
    consume(fallback_kinds)
    if exit_cond.startswith("UNKNOWN"):
        recovered_exit = _thread_exit_from_names_and_ops(start_call_names, start_ops)
        if recovered_exit:
            exit_cond = recovered_exit
    if exit_cond.startswith("UNKNOWN"):
        hop_exit = _thread_exit_from_one_hop_callees(evidence_by_id, start_call_names, start)
        if hop_exit:
            exit_cond = hop_exit
    if exit_cond.startswith("UNKNOWN"):
        wait_exit = _wait_loop_exit(start_call_names, loop)
        if wait_exit:
            exit_cond = wait_exit
    return loop, exit_cond, shared


_RUNTIME_PHASES: tuple[tuple[str, str, frozenset[str]], ...] = (
    ("startup", "Phase 1 — startup / loader", frozenset({"loader-and-api-resolution", "memory-and-mapping", "multi-stage-payload"})),
    ("anti_analysis", "Phase 2 — environment / anti-analysis", frozenset({"environment-guard", "defense-evasion", "host-discovery"})),
    ("decode", "Phase 3 — decode / config", frozenset({"config-and-crypto"})),
    ("network", "Phase 4 — download / transport", frozenset({"network-transport"})),
    ("process", "Phase 5 — process creation / PPID", frozenset({"parent-process-spoofing", "process-creation"})),
    ("fallback", "Phase 6 — failure fallback", frozenset({"persistence"})),
    ("thread", "Phase 7 — unique OS thread / callback", frozenset({"thread-and-callback"})),
    ("loop", "Phase 8 — loop / repeat", frozenset({"communication-loop"})),
)


def build_runtime_sequence(
    findings: Iterable[Mapping[str, object]] | None = None,
    *,
    unique_threads: Iterable[Mapping[str, object]] | None = None,
    decoded_configs: Iterable[Mapping[str, object]] | None = None,
    process_flags: Iterable[Mapping[str, object]] | None = None,
    pe_entry: Mapping[str, object] | None = None,
    instruction_windows: Iterable[Mapping[str, object]] | None = None,
) -> list[dict[str, object]]:
    """Order recovered behaviors into a static Phase 1–8 sequence.

    Missing phases stay UNKNOWN.  A fallback is only written when a failure
    path was recovered; this does not invent schtasks or PPID spoofing.

    ``instruction_windows`` carries the function instruction windows, which is where the
    deterministic process-creation flag word lives - see
    :func:`creation_flags_from_callsite`.
    """
    rows = [dict(item) for item in findings or () if isinstance(item, Mapping)]
    by_catalog: dict[str, dict[str, object]] = {}
    fallbacks: list[str] = []
    for row in rows:
        catalog_id = str(row.get("catalog_id") or "")
        if catalog_id:
            current = by_catalog.get(catalog_id)
            if current is None or str(row.get("finding_status") or row.get("status") or "").upper() == "SUPPORTED":
                by_catalog[catalog_id] = row
        fallback = _protocol_slot_value(row, "failure_fallback")
        if fallback:
            fallbacks.append(fallback)
    thread_rows = [dict(item) for item in unique_threads or () if isinstance(item, Mapping)]
    phases: list[dict[str, object]] = []
    for phase_id, title, catalog_ids in _RUNTIME_PHASES:
        matched = [by_catalog[item] for item in catalog_ids if item in by_catalog]
        how_parts: list[str] = []
        for item in matched:
            what_text = str(item.get("what") or item.get("finding") or "").strip()
            how_text = _module_how_from_finding(item)
            if what_text and not is_empty_marker(what_text):
                how_parts.append(what_text)
            if how_text and how_text != "not recovered" and how_text not in how_parts:
                how_parts.append(how_text)
        status = "UNKNOWN"
        if any(str(item.get("finding_status") or item.get("status") or "").upper() in {"SUPPORTED", "VERIFIED"} for item in matched):
            status = "SUPPORTED"
        elif matched:
            status = "CANDIDATE"
        if phase_id == "startup":
            entry = pe_entry if isinstance(pe_entry, Mapping) else {}
            entry_rva = entry.get("entry_rva")
            image_base = entry.get("image_base")
            if entry_rva not in (None, ""):
                try:
                    rva_int = int(str(entry_rva), 0)
                except (TypeError, ValueError):
                    rva_int = None
                if rva_int is not None:
                    how_parts.append(f"PE AddressOfEntryPoint={rva_int:#x}")
                    try:
                        base_int = int(str(image_base), 0) if image_base not in (None, "") else None
                    except (TypeError, ValueError):
                        base_int = None
                    if base_int:
                        how_parts.append(f"entry_va={base_int + rva_int:#x}")
                    if status == "UNKNOWN":
                        status = "CANDIDATE"
        if phase_id == "thread" and thread_rows:
            status = "CANDIDATE" if status == "UNKNOWN" else status
            for thread in thread_rows[:3]:
                start = str(thread.get("start_routine") or "")
                if start and not start.startswith("UNKNOWN"):
                    how_parts.append(f"start={start}")
                else:
                    how_parts.append("UNKNOWN(start_routine)")
                parameter = str(thread.get("parameter") or "")
                if parameter and not parameter.startswith("UNKNOWN"):
                    how_parts.append(f"parameter={parameter}")
        if phase_id == "fallback" and fallbacks and status == "UNKNOWN":
            status = "CANDIDATE"
            how_parts.extend(fallbacks[:2])
        if phase_id == "fallback":
            for row in decoded_configs or ():
                if not isinstance(row, Mapping):
                    continue
                preview = str(row.get("decoded_preview") or row.get("decoded_text") or "")
                lowered = preview.casefold()
                if "fail" in lowered or "not found" in lowered:
                    if preview not in how_parts:
                        how_parts.append(preview[:240])
                    if status == "UNKNOWN":
                        status = "CANDIDATE"
        if phase_id == "decode":
            for row in decoded_configs or ():
                if not isinstance(row, Mapping):
                    continue
                if str(row.get("verification_status") or "").upper() != "VERIFIED_STATIC_DATA":
                    continue
                for text in list(row.get("decoded_strings") or [])[:4]:
                    if text and text not in how_parts:
                        how_parts.append(str(text)[:240])
                preview = str(row.get("decoded_preview") or row.get("decoded_text") or "").strip()
                if preview and preview not in how_parts:
                    how_parts.append(preview[:240])
                formula = str(row.get("formula") or "").strip()
                if formula:
                    how_parts.append(f"formula={formula}")
            if how_parts and status == "UNKNOWN":
                status = "SUPPORTED"
        if phase_id == "network":
            # Decoded http:// belongs to decode/config. A URL is not a
            # recovered WinHTTP/WinINet path and must not close Phase 4.
            pass
        if phase_id == "process":
            for row in process_flags or ():
                if not isinstance(row, Mapping):
                    continue
                flag_value = str(row.get("value") or "").strip()
                names = [
                    str(name)
                    for name in (row.get("set_flags") or [])
                    if str(name).strip()
                ]
                if flag_value:
                    # Label the value with the slot it belongs to AND how it was
                    # recovered.  Emitting a bare immediate left `process_blob` without
                    # the token "creation_flags", so the check below appended
                    # `UNKNOWN(creation_flags)` directly beside the recovered value.
                    # Measured on task `c705a42e`: the body printed the flag word and
                    # denied the slot in the same document.
                    provenance = str(row.get("recovered_as") or "").strip()
                    if provenance == "candidate_immediate":
                        how_parts.append(
                            f"creation_flags candidate_immediate={flag_value}"
                        )
                    else:
                        how_parts.append(f"creation_flags={flag_value}")
                if names:
                    how_parts.append(", ".join(names[:8]))
                interpretation = str(row.get("interpretation") or "").strip()
                if interpretation:
                    how_parts.append(interpretation[:240])
            process_blob = " ".join(how_parts).casefold()
            process_seeded = (
                "process-creation" in by_catalog
                or any("createprocess" in process_blob for _ in (0,))
                or any(
                    "createprocess" in str(item.get("what") or item.get("how") or "").casefold()
                    for item in matched
                )
            )
            if process_seeded:
                # The deterministic flag word comes from the process-creation CALL SITE,
                # not from the candidate list: publishing the first credible candidate
                # gave a wrong answer (`0x28000000` for a sample whose value is
                # `0x09080008`).
                #
                # It is INSERTED at the front, not appended: the phase text is
                # `"; ".join(how_parts[:4])`, so the candidate-list entries already fill
                # the four published slots and an appended flag was silently dropped -
                # the same truncation shape as the R3 defects.
                callsite_flags = creation_flags_from_callsite(
                    {"windows": list(instruction_windows or ())}
                )
                if callsite_flags:
                    how_parts.insert(0, f"creation_flags={callsite_flags}")
                elif (
                    "creation_flags" not in process_blob
                    and "unknown(creation_flags)" not in process_blob
                ):
                    how_parts.insert(0, "UNKNOWN(creation_flags)")
            parent_seeded = "parent-process-spoofing" in by_catalog or any(
                token in process_blob
                for token in ("updateprocthreadattribute", "parent_identity", "parent_image")
            )
            parent_recovered = any(
                token in process_blob
                for token in ("parent_identity=", "parent_image=", "parent_name=")
            )
            if parent_seeded and not parent_recovered:
                how_parts.append("UNKNOWN(parent_identity)")
            if how_parts and status == "UNKNOWN":
                status = "CANDIDATE"
        if phase_id == "loop":
            loop_slots = [
                _protocol_slot_value(item, "loop")
                for item in rows
                if _protocol_slot_value(item, "loop")
            ]
            if loop_slots and status == "UNKNOWN":
                status = "CANDIDATE"
                how_parts.extend(loop_slots[:2])
        phases.append(
            {
                "type": "runtime_phase",
                "id": phase_id,
                "title": title,
                "status": status,
                "how": "; ".join(how_parts[:4]) or "UNKNOWN(phase not recovered statically)",
                "catalog_ids": [str(item.get("catalog_id") or "") for item in matched],
                "runtime_observed": False,
            }
        )
    return phases


def _runtime_phase_is_empty_shell(phase: Mapping[str, object] | None) -> bool:
    """True when a Phase 1–8 slot has no recovered HOW and should stay closed."""
    if not isinstance(phase, Mapping):
        return True
    status = str(phase.get("status") or "").upper()
    how = str(phase.get("how") or "").strip()
    if status != "UNKNOWN":
        return False
    return (not how) or how.casefold().startswith("unknown(phase")


def build_behavior_relations(
    relations: list[Any] | tuple[Any, ...] | None,
    behavior_findings: list[Mapping[str, object]] | tuple[Mapping[str, object], ...] | None,
    *,
    evidence_by_id: Mapping[str, Any] | None = None,
    links_by_claim: Mapping[str, list[str]] | None = None,
    claim_evidence: list[Any] | tuple[Any, ...] | None = None,
    artifacts: list[Any] | tuple[Any, ...] | None = None,
) -> list[dict[str, object]]:
    """Project supported component Relations into behavior graph edges.

    Endpoints may remain artifact/object scoped when several findings share an
    artifact.  We never pick an arbitrary finding in that case, and an
    unbacked Relation is omitted rather than rendered as an unsupported arrow.
    """
    evidence_by_id = evidence_by_id or {}
    links_by_claim = links_by_claim or {}
    claim_evidence = list(claim_evidence or ())
    artifacts = list(artifacts or ())
    findings = [_report_record(item) for item in (behavior_findings or ())]
    by_artifact: dict[str, list[str]] = {}
    by_claim: dict[str, list[str]] = {}
    for finding in findings:
        finding_id = str(finding.get("finding_id") or finding.get("id") or "")
        if not finding_id:
            continue
        for artifact_id in _report_ids(finding.get("artifact_ids")) + _report_ids(finding.get("artifact_id")):
            by_artifact.setdefault(artifact_id, []).append(finding_id)
        for claim_id in _report_ids(finding.get("claim_ids")):
            by_claim.setdefault(claim_id, []).append(finding_id)
    known_claim_ids = set(by_claim)
    artifact_names = {
        str(_report_value(item, "id", "")): str(
            _report_value(item, "logical_path", "") or _report_value(item, "path", "") or _report_value(item, "id", "")
        )
        for item in artifacts
        if _report_value(item, "id", "")
    }
    claim_support: dict[str, list[str]] = {}
    for link in claim_evidence:
        claim_id = str(_report_value(link, "claim_id", "") or "")
        evidence_id = str(_report_value(link, "evidence_id", "") or "")
        stance = str(_report_value(link, "stance", "SUPPORTS") or "SUPPORTS").upper()
        if claim_id and evidence_id in evidence_by_id and stance not in {"REFUTES", "REFUTED", "CONTRADICTS"}:
            claim_support.setdefault(claim_id, []).append(evidence_id)
    for claim_id, ids in links_by_claim.items():
        claim_support.setdefault(str(claim_id), []).extend(
            item for item in _report_ids(ids) if item in evidence_by_id
        )
    for claim_id, ids in claim_support.items():
        claim_support[claim_id] = list(dict.fromkeys(ids))

    projected: list[dict[str, object]] = []
    for relation in relations or ():
        row = _report_record(relation)
        relation_id = str(row.get("id") or row.get("relation_id") or "")
        relation_type = str(row.get("relation_type") or row.get("relation") or "").upper()
        source_artifact_id = str(row.get("source_artifact_id") or "")
        target_artifact_id = str(row.get("target_artifact_id") or "")
        if (
            not relation_id
            or relation_type not in _BEHAVIOR_RELATION_TYPES
            or not source_artifact_id
            or not target_artifact_id
        ):
            continue
        evidence_ids = _report_ids(row.get("evidence_ids"))
        evidence_id = str(row.get("evidence_id") or "")
        if evidence_id:
            evidence_ids.append(evidence_id)
        claim_id = str(row.get("claim_id") or "")
        if claim_id:
            evidence_ids.extend(claim_support.get(claim_id, []))
        evidence_ids = list(dict.fromkeys(item for item in evidence_ids if item in evidence_by_id))
        # A graph edge must have a real evidence/claim support path.  Merely
        # naming two artifacts is not enough.
        if not evidence_ids and not claim_id:
            continue
        # A dangling Claim reference is not provenance.  Evidence-backed
        # structural rows remain compatible with legacy snapshots, but a
        # claim-only edge must point to a Claim represented by one of the
        # projected findings; otherwise it would render an unsupported arrow.
        if claim_id and claim_id not in known_claim_ids and not evidence_ids:
            continue
        source_finding_ids = list(dict.fromkeys(by_artifact.get(source_artifact_id, [])))
        target_finding_ids = list(dict.fromkeys(by_artifact.get(target_artifact_id, [])))
        source_finding_id = source_finding_ids[0] if len(source_finding_ids) == 1 else None
        target_finding_id = target_finding_ids[0] if len(target_finding_ids) == 1 else None
        raw_status = _report_status(row.get("status"), "INFERRED" if claim_id else "UNKNOWN")
        if raw_status in {"OBSERVED", "CONFIRMED"} and not evidence_ids:
            raw_status = "CANDIDATE"
        validation_status = raw_status
        if claim_id and raw_status in {"OBSERVED", "CONFIRMED"} and not row.get("evidence_id"):
            # Claim-only relations are inferred, even if a legacy row used a
            # terminal status label.
            validation_status = "SUPPORTED" if raw_status == "CONFIRMED" and evidence_ids else "CANDIDATE"
        natures = list(dict.fromkeys(
            str(_report_value(evidence_by_id[item], "nature", "UNKNOWN") or "UNKNOWN").upper()
            for item in evidence_ids
        ))
        projected.append({
            "type": "behavior_relation",
            "relation_id": relation_id,
            "relation_type": relation_type,
            "relation": relation_type.lower(),
            "source_artifact_id": source_artifact_id,
            "target_artifact_id": target_artifact_id,
            "source_object": artifact_names.get(source_artifact_id, source_artifact_id),
            "target_object": artifact_names.get(target_artifact_id, target_artifact_id),
            "source_finding_id": source_finding_id,
            "target_finding_id": target_finding_id,
            "source_finding_ids": source_finding_ids,
            "target_finding_ids": target_finding_ids,
            "is_behavior_edge": bool(source_finding_id and target_finding_id),
            "claim_id": claim_id or None,
            "evidence_ids": evidence_ids[:32],
            "supporting_evidence_ids": evidence_ids[:32],
            "condition": row.get("condition") or "relation condition not recorded",
            "provenance": {
                "relation_id": relation_id,
                "source_artifact_id": source_artifact_id,
                "target_artifact_id": target_artifact_id,
                "claim_id": claim_id or None,
                "evidence_ids": evidence_ids[:32],
                "evidence_natures": natures,
            },
            "evidence_natures": natures,
            "validation_status": validation_status,
            "status": validation_status,
            "unknowns": (
                ["source or target behavior is ambiguous because multiple findings share the artifact"]
                if not (source_finding_id and target_finding_id)
                else []
            ),
        })
    projected, _ = apply_adversarial_downgrades(projected)
    return projected[:256]


def _build_assessment(
    *, task: Any, artifacts: list[Any], claims: list[Any],
    links_by_claim: dict[str, list[str]], evidence_by_id: dict[str, Any], model_calls: list[Any],
    mechanisms: list[Any] | None = None,
    mechanism_projections: list[dict[str, object]] | None = None,
    behavior_findings: list[dict[str, object]] | None = None,
) -> tuple[str, list[dict[str, object]]]:
    """Build a concise, evidence-backed assessment for the report front page."""
    behavior_findings = list(behavior_findings or ())
    behavior_claims = [
        item for item in claims
        if str(_report_value(item, "module", "")).casefold()
        not in {"static_triage", "attribution"}
    ]
    analyst_claims = [
        item for item in claims
        if str(_report_value(item, "module", "")).casefold() != "attribution"
        if not (
            str(_report_value(item, "module", "")).casefold() == "static_triage"
            and str(_report_value(item, "action", "")).casefold() in {"prioritizes", "matches"}
        )
        and not _is_reference_noise({
            "action": _report_value(item, "action", ""),
            "statement": _report_value(item, "statement", ""),
            "mechanism": _report_value(item, "mechanism", ""),
        })
    ]
    model_claims = [item for item in claims if getattr(item, "model_call_id", None)]
    modules = {
        str(_report_value(item, "module", ""))
        for item in behavior_claims
        if _report_value(item, "module", "")
    }
    # Severity and evidence confidence are independent dimensions.  The old
    # implementation used the number of Claim modules as a HIGH-risk proxy,
    # which made three unrelated candidate rows look like a confirmed threat.
    # Only an explicit severity attached to a closed, provenance-complete
    # mechanism is eligible for the severity field; absence is reported as
    # UNASSESSED instead of guessed from module diversity.
    def _as_mapping(item: Any) -> dict[str, object]:
        return _report_record(item)

    projected_rows = [_as_mapping(item) for item in behavior_findings]
    projected_rows.extend(
        _as_mapping(item)
        for item in [*(mechanisms or ()), *(mechanism_projections or ())]
        if _as_mapping(item).get("evidence_ids")
    )
    behavior_rows_for_assessment = [
        row for row in projected_rows
        if str(row.get("module", "")).casefold() != "attribution"
        and not _is_reference_noise(row)
    ]
    closed_behavior_rows = [
        row for row in behavior_rows_for_assessment
        if str(row.get("finding_status") or row.get("status") or row.get("verdict") or "").upper()
        in _BEHAVIOR_CLOSED_STATUSES
        and (
            row.get("type") == "behavior_finding"
            or mechanism_is_critical_ready(row)
        )
    ]
    candidate_behavior_rows = [
        row for row in behavior_rows_for_assessment
        if row not in closed_behavior_rows
        and str(row.get("finding_status") or row.get("status") or row.get("verdict") or "").upper()
        not in {"REJECTED", "REFUTED", "UNKNOWN", "NOT_IDENTIFIED", "BLOCKED"}
    ]
    explicit_severities = [
        str(row.get("severity") or row.get("risk") or "").upper()
        for row in closed_behavior_rows
        if str(row.get("severity") or row.get("risk") or "").upper() in _BEHAVIOR_SEVERITY_VALUES
    ]
    severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    severity = (
        max(explicit_severities, key=lambda value: severity_rank[value])
        if explicit_severities
        else "UNASSESSED"
    )
    # Candidate confidence is deliberately capped at LOW, even when a model
    # or rule emitted a HIGH confidence label.  A confidence label cannot
    # replace the required behavior relation/verifier closure.
    if closed_behavior_rows:
        evidence_confidence = "HIGH"
    elif candidate_behavior_rows:
        evidence_confidence = "LOW"
    else:
        evidence_confidence = "NONE"
    risk = severity  # legacy API key; ``severity`` is the authoritative name.
    source = "model_and_deterministic" if model_claims else "deterministic_static_fallback"
    module_order = ("decryption", "loader", "anti_analysis", "c2_network", "execution")
    chain_claims = []
    # Legacy callers that do not provide mechanism projections retain the
    # compact inferred chain used by older report fixtures. Production report
    # snapshots always pass ``mechanisms`` (possibly empty), so an unclosed
    # candidate cannot leak into the primary semantic behavior flow.
    # ``mechanism_projections`` is supplied by the production report builder
    # even when no verifier mechanism closed.  Only the old fixture path (no
    # mechanism inputs at all) may use the compact module-label chain.
    legacy_chain_mode = mechanisms is None and not any(
        item.get("type") in {"mechanism_observation", "mechanism_link"}
        for item in (mechanism_projections or [])
    )
    if legacy_chain_mode:
        for module in module_order:
            candidates = [item for item in claims if item.module == module]
            if not candidates:
                continue
            selected = max(
                candidates,
                key=lambda item: (
                    0 if item.confidence == "HIGH" else 1 if item.confidence == "MEDIUM" else 2,
                    -len(links_by_claim.get(item.id, [])),
                ),
            )
            chain_labels = {
                "may_decode_or_decrypt": "resource -> decompress/decode/integrity-check",
                "may_load_or_prepare_memory": "extract/resolve payload -> prepare memory",
                "may_detect_analysis": "check environment/service state",
                "references_network_endpoint": "reference network endpoint",
                "may_execute": "potential process/command execution",
            }
            chain_claims.append(chain_labels.get(selected.action, f"{selected.action} {selected.object}"))
    def as_mapping(item: Any) -> dict[str, object]:
        if isinstance(item, dict):
            result = dict(item)
        else:
            result = {
            key: getattr(item, key)
            for key in (
                "id", "mechanism_id", "claim_id", "status", "target", "inputs",
                "transformation_or_control", "conditions", "outputs", "consumers",
                "side_effects", "evidence_ids", "completeness", "verifier",
                "mechanism_type", "function", "function_entry", "rva", "type",
            )
            if hasattr(item, key)
            }
        verifier = result.get("verifier")
        if not result.get("mechanism_type") and isinstance(verifier, Mapping):
            result["mechanism_type"] = verifier.get("mechanism_type")
        return result

    projected_mechanisms = [
        as_mapping(item)
        for item in [*(mechanisms or []), *(mechanism_projections or [])]
    ]
    semantic_mechanisms = [
        item for item in projected_mechanisms
        if str(item.get("status", "")).upper() in {"VERIFIED", "SUPPORTED", "CONFIRMED"}
        and mechanism_is_critical_ready(item)
    ]
    # A report still needs to explain the strongest static path when the
    # verifier correctly leaves it as a candidate.  Candidate observations
    # are labelled as inferred and retain their static boundary; they are
    # never used to create a formal security finding.
    def _scope_signature(item: Mapping[str, object]) -> tuple[str, str, str, str]:
        return (
            str(item.get("mechanism_type", "")).upper(),
            str(item.get("function_entry") or item.get("rva") or ""),
            str(item.get("function") or ""),
            str(item.get("artifact_id") or ""),
        )

    verified_scopes = {
        _scope_signature(item)
        for item in semantic_mechanisms
        if _scope_signature(item)[1] or _scope_signature(item)[2]
    }
    candidate_flow_mechanisms = sorted(
        [
            item for item in projected_mechanisms
            if item.get("type") in {"mechanism_observation", "mechanism_link"}
            and item not in semantic_mechanisms
            and _scope_signature(item) not in verified_scopes
        ],
        key=lambda item: (
            -int(item.get("completeness", 0) or 0),
            0 if item.get("function_entry") or item.get("rva") else 1,
        ),
    )
    # Production snapshots must never flatten unrelated functions into one
    # causal arrow.  Render a flow only for an explicitly ordered observation
    # (or verifier-backed mechanism); otherwise retain independent paths.
    independent_paths: list[str] = []
    ordered_paths: list[str] = []
    if not legacy_chain_mode:
        ordered_candidates: list[tuple[dict[str, object], str]] = []
        for item in [*semantic_mechanisms, *candidate_flow_mechanisms]:
            transform = " -> ".join(
                str(value) for value in (item.get("transformation_or_control") or [])[:3]
                if value and not str(value).startswith("UNKNOWN(")
            )
            if not transform:
                continue
            target = str(item.get("target") or "function")
            entry = str(item.get("function_entry") or item.get("rva") or "")
            # Mechanism targets can already carry an ``@RVA`` suffix. Route
            # every assessment path through the same formatter used by the
            # detailed sections so the executive chain never emits
            # ``name@RVA@RVA`` after projection/deduplication.
            location = _format_function_location(target, entry) if entry else target
            path = f"{location}: {transform}"
            if _is_fun_call_sequence_dump(path) or _is_fun_call_sequence_dump(transform):
                continue
            independent_paths.append(path)
            if bool(item.get("ordered")) or item.get("type") == "mechanism_chain":
                ordered_candidates.append((item, path))
        flow_scopes = {
            (
                str(item.get("artifact_id") or ""),
                str(item.get("function_entry") or item.get("rva") or ""),
                str(item.get("function") or ""),
            )
            for item, _ in ordered_candidates
        }
        if ordered_candidates and len(flow_scopes) == 1:
            ordered_paths = [path for _, path in ordered_candidates]
            chain_claims = list(dict.fromkeys(ordered_paths[:6]))
            mechanism_chain = " ; ".join(chain_claims)
        elif independent_paths:
            mechanism_chain = "independent static paths: " + " | ".join(independent_paths[:6])
        else:
            mechanism_chain = "no evidence-backed mechanism chain established"
    else:
        mechanism_chain = " -> ".join(chain_claims) if len(chain_claims) >= 3 else "no evidence-backed mechanism chain established"

    # Turn the strongest typed observations into one short analyst narrative.
    # This is deliberately deterministic and bounded: it explains why a path
    # matters without inventing runtime outcomes or flattening unrelated
    # functions into a single execution timeline.
    mechanism_interpretations = {
        "DYNAMIC_API_RESOLUTION": "dynamic API resolution can hide imports and route calls through recovered function pointers",
        "DYNAMIC_LOADER": "a file I/O or loader path is present; a dropped secondary module is not established without a recovered child artifact or LoadLibrary consumer",
        "DECODE_TRANSFORM": "a bounded transform/decode loop can prepare hidden configuration or payload data",
        "ENVIRONMENT_CHECK": "environment and memory queries can gate later branches and are consistent with analysis-sensitive control flow",
        "MEMORY_PERMISSION_CHANGE": "a memory-permission transition can prepare executable or writable regions for a downstream consumer",
        "NETWORK_DOWNLOAD": "a transport path can receive response data for a downstream file or execution consumer",
        "HTTP_DOWNLOAD": "an HTTP-oriented path can receive response data; network success is not observed",
        "SHELL_OUTPUT": "a child-process path can connect redirected output to a reader; process success is not observed",
        "PPID_SPOOFING": "startup attributes can select an alternate parent process for a child creation path",
        "REGISTRY_CONFIGURATION": "a registry path can alter host configuration when the write branch is reached",
        "SCHEDULED_TASK": "task scheduler tokens can form a short-lived execution or fallback path",
        "INDIRECT_API_DISPATCH": "an indirect call can dispatch through a pointer whose final API identity remains unresolved",
    }
    narrative_items: list[str] = []
    for item in [*semantic_mechanisms, *candidate_flow_mechanisms]:
        mechanism_type = str(item.get("mechanism_type", "")).upper()
        interpretation = mechanism_interpretations.get(mechanism_type)
        if not interpretation:
            continue
        target = str(item.get("target") or "sample")
        entry = str(item.get("function_entry") or item.get("rva") or "")
        text = interpretation + _cover_location_suffix(target, entry)
        if text not in narrative_items:
            narrative_items.append(text)
        if len(narrative_items) >= 4:
            break
    interpretation_text = (
        " Interpretation: " + "; ".join(narrative_items) + "."
        if narrative_items else ""
    )
    # The front page answers the analyst's three first questions directly:
    # what was found, how the path is supported, and what remains unknown.
    # Keep this prose bounded and derive it only from behavior projections;
    # attribution/reference rows are intentionally absent from this list.
    # Prefer canonical BehaviorFinding rows for the executive summary.  Raw
    # mechanism observations are useful supporting material but often lack
    # the complete What/How/Condition/Output/Consumer shape and would make
    # the summary read like a field inventory.
    # Kunglao DISPATCH_VERIFIER: persist process/decode/named-API HOW must
    # lead the front page. A GetProcAddress(ExportN) flood is not recovered
    # process construction and must not starve CreateProcess command/flags.
    candidate_summary_rows = [
        row for row in behavior_findings
        if not _report_is_attribution(row)
    ] or behavior_rows_for_assessment[:4]
    plan = _extract_static_analysis_plan(getattr(task, "strategy_snapshot", None))
    packer_latch = _static_plan_packer_latch(plan, behavior_findings, evidence_by_id)
    if packer_latch:
        candidate_summary_rows = [
            row for row in candidate_summary_rows if not _row_is_stub_iat_capability(row)
        ]
    summary_rows = sorted(candidate_summary_rows, key=_analyst_finding_rank)
    how_candidates = [
        _prose_limit(_module_how_from_finding(row), 400)
        for row in summary_rows
        if _finding_has_recovered_how(row)
        and not (packer_latch and _is_stub_iat_capability(_module_how_from_finding(row)))
    ]
    persist_hows = [item for item in how_candidates if _persist_argument_how(item)]
    typed_hows = [
        item
        for item in how_candidates
        if not _is_fun_call_sequence_dump(item)
    ]
    how_parts = persist_hows or typed_hows
    what_candidates = [
        _prose_limit(str(row.get("what") or row.get("finding") or "").strip(), 280)
        for row in summary_rows
        if str(row.get("what") or row.get("finding") or "").strip()
    ]
    persist_whats = [
        _prose_limit(str(row.get("what") or row.get("finding") or "").strip(), 280)
        for row in summary_rows
        if str(row.get("what") or row.get("finding") or "").strip()
        and (
            _persist_argument_how(_module_how_from_finding(row))
            or _persist_argument_how(row.get("what") or "")
        )
    ]
    what_parts = persist_whats or what_candidates
    unknown_parts = list(dict.fromkeys(
        str(unknown)
        for row in summary_rows
        for unknown in _report_values(row.get("unknowns"))
        if str(unknown).strip()
    ))
    what_text = "; ".join(what_parts[:3]) or "no evidence-backed behavior was closed"
    decoded_configs = [
        row
        for row in build_decode_result_projections(evidence_by_id)
        if str(row.get("verification_status") or "").upper() == "VERIFIED_STATIC_DATA"
    ]
    if decoded_configs and not persist_hows:
        decode_bits = [
            str(item.get("decoded_preview") or item.get("decoded_text") or "")
            for item in decoded_configs[:3]
            if str(item.get("decoded_preview") or item.get("decoded_text") or "").strip()
        ]
        if decode_bits:
            how_parts = [*how_parts, *decode_bits]
    how_text = "; ".join(how_parts[:3]) or "the implementation path was not recovered"
    catalog_matrix = build_catalog_behavior_matrix(
        summary_rows,
        evidence_by_id=evidence_by_id,
        static_analysis_plan=plan,
    )
    unique_threads = build_unique_execution_threads(evidence_by_id)
    process_flags = build_process_flag_projections(evidence_by_id)
    runtime_sequence = build_runtime_sequence(
        summary_rows or behavior_findings,
        unique_threads=unique_threads,
        decoded_configs=decoded_configs,
        process_flags=process_flags,
        pe_entry=build_pe_entry_projection(evidence_by_id),
        instruction_windows=instruction_windows_from_evidence(evidence_by_id),
    )
    if unique_threads and all(
        str(item.get("start_routine") or "").startswith("UNKNOWN") for item in unique_threads
    ):
        unknown_parts.insert(0, "UNKNOWN(start_routine)")
    named_missing = _named_missing_process_thread_fields(evidence_by_id, summary_rows, plan)
    for tokens in named_missing.values():
        for token in tokens:
            if token and token not in unknown_parts:
                unknown_parts.insert(0, token)
    for item in catalog_matrix.get("unclosed_high_value") or []:
        reason = str(item.get("reason") or "").strip()
        if reason and reason not in unknown_parts:
            unknown_parts.append(reason)
    unknown_text = "; ".join(unknown_parts[:4]) or "no additional unknowns were recorded"
    cover_chain = mechanism_chain
    if _is_fun_call_sequence_dump(cover_chain):
        cover_chain = (
            "typed How above; function-level call sequences are in Evidence Explorer"
        )
    summary = (
        f"What: {what_text}. How: {how_text}. Key unknowns: {unknown_text}. "
        f"Static assessment: severity={severity}; Evidence confidence: {evidence_confidence} "
        f"(source={source}, outcome={task.outcome or 'UNKNOWN'}). "
        f"Mechanism chain: {cover_chain}. "
        f"This is a static hypothesis set, not proof of runtime execution.{interpretation_text}"
    )
    rows: list[dict[str, object]] = [{
        "type": "assessment",
        "verdict": (
            "SUPPORTED_STATIC_BEHAVIOR" if closed_behavior_rows
            else "CANDIDATE_STATIC_BEHAVIOR" if candidate_behavior_rows
            else "NO_BEHAVIOR_INDICATORS_FOUND"
        ),
        "risk": risk,
        "severity": severity,
        "conclusion_confidence": evidence_confidence,
        "evidence_confidence": evidence_confidence,
        "confidence_basis": (
            "verified mechanism closure and evidence provenance; candidate diversity is not a confidence signal"
        ),
        "finding_count": len(analyst_claims),
        "behavior_module_count": len(modules),
        "behavior_finding_count": len(behavior_rows_for_assessment),
        "closed_behavior_count": len(closed_behavior_rows),
        "candidate_behavior_count": len(candidate_behavior_rows),
        "what": what_text,
        "how": how_text,
        "key_unknowns": unknown_parts[:8],
        "catalog_behavior_matrix": catalog_matrix,
        "unique_execution_threads": unique_threads,
        "runtime_sequence": runtime_sequence,
        "model_claim_count": len(model_claims),
        "model_call_count": len(model_calls),
        "static_only": not any(
            str(_evidence_mapping(item).get("kind") or "") == "simulation_result"
            for item in evidence_by_id.values()
        ),
    }]
    rows.extend(_claim_row(item, links_by_claim, evidence_by_id) for item in sorted(
        analyst_claims,
        key=lambda item: (
            0 if getattr(item, "model_call_id", None) else 1,
            0 if item.module != "static_triage" else 1,
            0 if item.confidence == "HIGH" else 1 if item.confidence == "MEDIUM" else 2,
            -len(links_by_claim.get(item.id, [])),
        ),
    )[:8])
    # BehaviorFinding rows are the primary analyst projection.  Keep them
    # separate from legacy analytical_claim rows so clients can render a
    # behavior view without parsing prose or treating a candidate as verified.
    # They follow the legacy rows here for snapshot compatibility; the
    # dedicated behavior_attack module exposes them first for new clients.
    rows.extend(dict(item) for item in behavior_findings[:24])
    rows.append({
        "type": "mechanism_chain",
        "chain": chain_claims,
        "rendered": mechanism_chain if legacy_chain_mode or ordered_paths else "",
        "status": (
            "confirmed" if semantic_mechanisms and not candidate_flow_mechanisms and len(chain_claims) >= 3
            else "inferred" if chain_claims else "unknown"
        ),
        "ordered": bool(mechanisms is None or ordered_paths),
        "independent_paths": independent_paths[:8] if mechanisms is not None and not ordered_paths else [],
        "evidence_backed": bool(chain_claims or independent_paths),
        "evidence_ids": list(dict.fromkeys(
            evidence_id
            for item in semantic_mechanisms
            for evidence_id in item.get("evidence_ids", [])
        ))[:12],
    })
    if task.limitations:
        emulator_attempted = any(
            str(_evidence_mapping(item).get("kind") or "") == "simulation_result"
            for item in evidence_by_id.values()
        )
        rows.append({
            "type": "next_step",
            "priority": "P1",
            "action": (
                "Review isolated emulator results and remaining UNKNOWN slots; "
                "do not treat stubbed APIs as recovered plaintext."
                if emulator_attempted
                else "Continue static recovery of unresolved buffers, start routines, and consumers; "
                "the isolated emulator runs automatically when static recovery stalls."
            ),
            "reason": "The current result still has explicit analysis limitations.",
        })
    return summary, rows


def _detection_rule_slug(value: object, *, fallback: str) -> str:
    """A YARA-safe identifier fragment.

    YARA identifiers are ``[A-Za-z_][A-Za-z0-9_]*``.  A SHA256 already satisfies
    that, so the digest itself becomes the useful part of the rule name - the most
    convenient thing to paste into a scanner.
    """
    text = str(value or "").strip()
    slug = re.sub(r"[^A-Za-z0-9_]", "_", text)
    slug = re.sub(r"_{2,}", "_", slug).strip("_")
    if not slug:
        return fallback
    if not (slug[0].isalpha() or slug[0] == "_"):
        slug = f"_{slug}"
    return slug[:96] or fallback


def _detection_rule_name(strings: Sequence[tuple[str, str]]) -> str:
    """A stable rule name built from the strongest recovered value."""
    digest = next((value for category, value in strings if category == "sha256"), "")
    if digest:
        # A digest needs no sanitising, and the full value is the most useful
        # identifier.  Truncate only for the human-readable name.
        return f"threat_static_{digest[:16]}"
    for category, value in strings:
        if category == "url":
            return f"threat_static_{_detection_rule_slug(value, fallback='url')[:48]}"
    return f"threat_static_{_detection_rule_slug(strings[0][1], fallback='sample')[:48]}"


#: Provenance fragments that mark a digest as a FILE identity rather than an object digest.
#:
#: A rule's `// sha256` slot is a file hash: it is what a defender pastes into a blocklist and what a
#: scanning engine compares against a file on disk. Measured across three producers, only one of them
#: yields such a value:
#:
#:     static_triage/file_identity      the sample itself                    <- a file hash
#:     artifact/content_sha256          the immutable Artifact identity      <- a file hash
#:     static_triage/pe_structure       PE resource payload digests          <- NOT a file hash
#:     investigation/embedded_object    materialised child artifact digests  <- NOT a file hash
#:     investigation/bytes_read         extracted-buffer digests             <- NOT a file hash
#:     investigation/decoded_artifact   decoded payload digests              <- NOT a file hash
#:
#: Task `50673002` published a rule named `threat_static_0b05c0df699028e6` whose two `sha256` entries
#: were both resource-payload digests, with the sample's own hash absent from the rule entirely. Round 80
#: fixed the `pe_structure` producer; the digests then arrived as `investigation/embedded_object`, which
#: is the patch-per-producer habit the objective forbids. This is the consumer-side rule instead.
#:
#: The two token sets below replace a substring test, and the replacement is the point.
#: `_FILE_HASH_SOURCES = ("file_identity", "artifact")` was read as `marker in source`, so
#: `investigation/decoded_artifact` counted as a file identity because "artifact" is a substring of
#: "decoded_artifact". Measured on task `b482617e` (白象 sample `64da3378`): five decoded-payload digests
#: were published in the rule's `strings:` block as `// sha256`, asserting that they identify the file. The
#: sample's own hash was also in the block, so `any of them` still matched and nothing looked broken - a
#: one-token distinction that a substring cannot express, and the reason this is now a token comparison.
_FILE_HASH_TOKENS = frozenset({"file_identity", "content_sha256"})

#: Tokens marking a digest as belonging to an object INSIDE the file. Consulted first, so a source naming
#: both an object and an artifact (`investigation/decoded_artifact`) resolves to the object reading.
_OBJECT_DIGEST_TOKENS = frozenset(
    {
        "embedded_object",
        "decoded_artifact",
        "decoded",
        "resource",
        "pe_structure",
        "bytes_read",
        "extracted",
        "child",
        "payload",
        "section",
    }
)


def _source_tokens(source: object) -> set[str]:
    return {token for token in re.split(r"[/:\\|]+", str(source or "").casefold()) if token}


def _is_file_hash_source(source: object) -> bool:
    """True only when the digest identifies the file itself.

    One predicate answers this question for the whole module. Two predicates answering it differently is
    what produced the round-80 regression: the selection filtered a digest while the naming step added it
    back.
    """
    tokens = _source_tokens(source)
    if tokens & _OBJECT_DIGEST_TOKENS:
        return False
    return bool(tokens & _FILE_HASH_TOKENS)


def _detection_rule_strings(iocs: Sequence[Mapping[str, object]]) -> list[tuple[str, str]]:
    """Pick detection strings from recovered indicators, strongest class first.

    Only values already in the report are used, and short or ambiguous tokens are
    rejected: a rule that fires on ``.tmp`` or on ``cmd.exe`` alone would be noise
    for a defender, and noise is worse than no rule.

    Selection is round-robin across classes rather than class-by-class.  Taking
    the strongest class to exhaustion filled every slot with digests and dropped
    the URL and the scheduled-task blob - the two pivots a responder actually
    hunts on - so the published rule could not see the C2 it was written about.

    Digests are additionally filtered by provenance: a `sha256` indicator may only come from a row whose
    `source` records a FILE identity (see `_FILE_HASH_SOURCES`). Object digests stay in the report as
    pivots; they just do not get published as the file's hash.
    """
    wanted = ("sha256", "url", "ipv4", "registry_subkey", "registry", "scheduled_task")
    by_class: dict[str, list[str]] = {}
    seen: set[str] = set()
    for category in wanted:
        values: list[str] = []
        for row in iocs:
            if str(row.get("category") or "") != category:
                continue
            if category == "sha256" and not _is_file_hash_source(row.get("source")):
                continue
            value = str(row.get("value") or "").strip()
            if len(value) < 6 or value.casefold() in seen:
                continue
            seen.add(value.casefold())
            values.append(value)
        if values:
            by_class[category] = values

    picked: list[tuple[str, str]] = []
    depth = 0
    while len(picked) < 8 and any(depth < len(values) for values in by_class.values()):
        for category in wanted:
            values = by_class.get(category) or []
            if depth < len(values):
                picked.append((category, values[depth]))
                if len(picked) >= 8:
                    break
        depth += 1
    return picked


def build_detection_rule_projection(
    iocs: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Turn recovered static indicators into a detection artefact.

    Why this exists.  The benchmark deliverable carries a detection rule and the
    product published none: `render_official_markdown` had no contract for IOC or
    ATT&CK rows at all, so a run could recover a URL, a digest and a scheduled-task
    blob and still hand the analyst nothing they could deploy.  An analyst-usable
    report needs the pivot *and* something to hunt with.

    Boundary - this is derived analytics, not a recovered fact.  Every value placed
    in the artefact comes from a static indicator already in the document, each row
    carries ``derived_only=True`` and the Evidence IDs it was built from, and the
    text says the rule was written by the analysis rather than lifted from the
    sample.  No indicator means no rule.
    """
    strings = _detection_rule_strings(iocs)
    if not strings:
        return []
    # EC-5.  Two defects were measured on task `ce7e310e` in the published rule, and both made it a
    # broken indicator - a deployable artefact that cannot identify the sample it was written for:
    #
    #   $s0 = "0b05c0df699028e6cfc4c02147e91b7a4ecbc79569004caaf550ebcdb25c63a3" // sha256
    #   $s5 = "168d16f912e21ee7d521f5d0a59b08f96161b9e5b98aae21f6d5e0d7ca8a0db6" // sha256
    #   sample file_identity.sha256 = 6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145
    #
    # `$s0` is the digest the rule NAME is derived from, so the rule's first indicator identified the
    # report rather than any file.  `$s5` was a PE resource-payload digest.  Both reached the rule
    # because a digest-string list was sorted by category and the first `sha256` was taken, with no
    # check that it was the sample's own hash.  The file hash must be the one the rule can actually
    # match on, and an indicator that self-references the rule name is removed outright.
    sample_sha256 = next(
        (
            str(row.get("value") or "").strip()
            for row in iocs
            if str(row.get("category") or "") == "sha256"
            and _is_file_hash_source(row.get("source"))
        ),
        "",
    )
    # The rule name must not be derived from a value that is NOT a file hash, and it must not collide
    # with a digest it then has to remove.
    #
    # `_detection_rule_name` takes the first `sha256` in the selection. After the provenance filter that
    # is a file hash, which is a legitimate name - measured on task `ce7e310e` the rule is
    # `threat_static_6bb6bfcbe68de690` with `$s0 = "6bb6bfcb..."`, naming the sample. The collision this
    # guards against is a rule named after a digest that is then filtered out of its own `strings:`
    # block, which would leave the name pointing at nothing in the rule. When every name-eligible digest
    # collides, the name is built from the other recovered values instead and the file hash is KEPT -
    # dropping the sample's own hash to protect a name would invert the priority.
    #
    # Two predicates for one question is what broke this before: `sample_sha256` used a string test while
    # the selection used `_is_file_hash_source`, so a digest the filter removed was prepended back.
    # There is now one predicate and one naming rule.
    #
    # NAMING: never derive the rule name from a digest.
    #
    # `_detection_rule_name` prefers the first `sha256`, and that created a circular contradiction that
    # only showed up on a sample with a file hash and nothing else: naming the rule after the sample hash
    # made the collision filter drop the sample hash, and with no other indicator the rule then had zero
    # strings and was not emitted at all - `{"category": "sha256", "value": <sample>,
    # "source": "static_triage/file_identity"}` produced NO rule, while the same input plus a URL produced
    # one. A rule named after a digest also reads as if the name were the detection, which it is not.
    #
    # A name built from a recovered URL or process name is both descriptive and collision-free, so the
    # digest stays where it belongs - in `strings:`.
    def _name_from_descriptive(strings_in: Sequence[tuple[str, str]]) -> str:
        descriptive = [
            (category, value)
            for category, value in strings_in
            if category != "sha256"
        ]
        return _detection_rule_name(descriptive or list(strings_in))

    rule_name = _name_from_descriptive(strings)
    name_suffix = rule_name.rsplit("_", 1)[-1].casefold()
    # A collision is "the name's trailing token begins a digest in the selection", which is exactly the
    # case where the filter below would delete an indicator to protect the name. Resolve it by renaming
    # with a prefix no digest can produce, so the digest stays in `strings:`.
    #
    # This branch is reached by the shape that has a file hash and NO descriptive value: the fallback
    # name IS that digest, and the earlier guard `sample.casefold().startswith(name_suffix)` was true for
    # the digest itself, so the sample hash was filtered out AND refused re-adding - a rule with zero
    # strings, silently not emitted. One sample shape produced no detection artefact while the same shape
    # plus a URL produced one.
    if name_suffix and any(
        category == "sha256" and value.casefold().startswith(name_suffix)
        for category, value in strings
    ):
        rule_name = f"threat_static_bounded_{sample_sha256[:16] or 'sample'}"
        name_suffix = rule_name.rsplit("_", 1)[-1].casefold()
    strings = [
        (category, value)
        for category, value in strings
        if not (category == "sha256" and value.casefold().startswith(name_suffix) and name_suffix)
    ]
    # The rule must carry the sample's own hash when the run recovered one.  "Already present" is the
    # only reason to skip: a digest absent because it collided with the name cannot happen here, because
    # the collision branch above renamed the rule instead of dropping the hash.
    if sample_sha256 and not any(
        category == "sha256" and value.casefold() == sample_sha256.casefold()
        for category, value in strings
    ):
        strings = [("sha256", sample_sha256), *strings]
    if not strings:
        return []
    evidence_ids = list(
        dict.fromkeys(
            str(item)
            for row in iocs
            for item in (row.get("evidence_ids") or ())
            if str(item).strip()
        )
    )[:12]
    body = ["rule " + rule_name, "{", "    meta:"]
    body.append('        description = "Static artifacts recovered by bounded static analysis"')
    body.append('        author = "threat-report-agent (generated, not recovered from the sample)"')
    body.append('        boundary = "presence in the file; execution and network use are unobserved"')
    body.append("    strings:")
    for index, (category, value) in enumerate(strings):
        replacement = value.replace("\\", "\\\\").replace('"', '\\"')
        body.append(f'        $s{index} = "{replacement}"   // {category}')
    body.append("    condition:")
    body.append("        any of them")
    body.append("}")
    yara_text = "\n".join(body)

    rows: list[dict[str, object]] = [
        {
            "type": "detection_rule",
            "rule_format": "yara",
            "rule_name": rule_name,
            "rule_text": yara_text,
            "indicator_values": [value for _, value in strings],
            "evidence_ids": evidence_ids,
            "derived_only": True,
            "confidence": "MEDIUM",
            "boundary": (
                "由本次静态恢复的指标生成，不是从样本中提取的现成规则；"
                "命中只说明文件/内存中存在这些静态值，不代表行为已经发生。"
            ),
        }
    ]

    # EDR / Sysmon hunting.  Only emitted when an actual process or registry
    # artefact was recovered, so the block never describes a behaviour the run
    # did not see.
    process_names = [
        str(row.get("value") or "").strip()
        for row in iocs
        if str(row.get("category") or "") == "process_name" and str(row.get("value") or "").strip()
    ]
    registry = [
        str(row.get("value") or "").strip()
        for row in iocs
        if str(row.get("category") or "") in {"registry", "registry_subkey"}
        and str(row.get("value") or "").strip()
    ]
    scheduled = [
        str(row.get("value") or "").strip()
        for row in iocs
        if str(row.get("category") or "") == "scheduled_task" and str(row.get("value") or "").strip()
    ]
    # A recovered parent-process attribute is the ONLY thing that justifies a PPID-spoofing hunting
    # line.  This used to be emitted unconditionally, so every report claimed it:
    #
    #   "- EID 1 (process creation): alert on a child image whose command line carries any recovered
    #    URL or process name, and whose parent does not match its real creator (STARTUPINFOEX
    #    parent-process attribute is the static reason to suspect this)."
    #
    # Measured by an independent correctness review of task `643e4366`: the same report's PPID section
    # said the chain was NOT joined (UNKNOWN(parent_identity + attribute_list)), its
    # `process_creation_flags` row recorded `0x08000000` = CREATE_NO_WINDOW with the interpretation
    # "no extended startup information flag observed" (so no `EXTENDED_STARTUPINFO_PRESENT` and no
    # attribute list exists), and the sentence was byte-identical in 33 reports including one for a
    # different sample.  A deployable hunting rule justified by a reason that does not apply produces
    # false positives and discredits the rule, which is worse than emitting no rule.
    parent_attribute = next(
        (
            str(row.get("value") or "").strip()
            for row in iocs
            if "parent" in str(row.get("category") or "").casefold()
            and str(row.get("value") or "").strip()
        ),
        "",
    )
    urls = [
        str(row.get("value") or "").strip()
        for row in iocs
        if str(row.get("category") or "") in {"url", "ipv4"} and str(row.get("value") or "").strip()
    ]
    edr_lines = [
        "EDR / Sysmon hunting (analyst-side, derived from the static artifacts above):",
    ]
    # EID 1 is only emitted when this run actually recovered a command-line or image-name indicator,
    # and it names them instead of promising "any recovered URL or process name".
    if urls or process_names:
        carriers = ", ".join(
            f"`{item}`" for item in [*urls[:2], *process_names[:2]]
        )
        edr_lines.append(
            f"- EID 1 (process creation): alert on a child image whose command line carries {carriers}."
        )
    if parent_attribute:
        edr_lines.append(
            "- EID 1 (process creation): this run recovered a parent-process attribute "
            f"(`{parent_attribute}`), so a child whose recorded parent does not match its real "
            "creator is worth alerting on."
        )
    if process_names:
        edr_lines.append(
            "- EID 1 (process creation): watch for anomalous use of "
            + ", ".join(f"`{item}`" for item in process_names[:4])
            + " as a child or parent image."
        )
    if scheduled:
        edr_lines.append(
            "- EID 4698 / 106 (scheduled task registered): alert on a task whose action "
            "contains any token recovered above; short-lived create/run/delete triples are "
            "the high-signal shape."
        )
    if registry:
        edr_lines.append(
            "- EID 13 (registry value set): alert on writes to "
            + ", ".join(f"`{item}`" for item in registry[:4])
            + ", especially Defender exclusion and SpyNet/telemetry values."
        )
    rows.append(
        {
            "type": "detection_rule",
            "rule_format": "edr",
            "rule_name": f"{rule_name}_edr",
            "rule_text": "\n".join(edr_lines),
            "indicator_values": [value for _, value in strings],
            "evidence_ids": evidence_ids,
            "derived_only": True,
            "confidence": "MEDIUM",
            "boundary": (
                "由本次静态恢复的指标生成的排查建议，不是从样本中提取的规则；"
                "未观察到任何一条事件实际发生。"
            ),
        }
    )
    return rows


# These projections deliberately live in the report layer.  An indicator is
# useful to an analyst even when its enclosing mechanism is still a candidate,
# but it must remain explicitly static-derived and retain the exact Evidence
# rows that produced it.  Keeping this separate from the parser avoids turning
# every string/import into a finding while still making high-value pivots
# visible in the bounded report.
_STATIC_INDICATOR_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("url", re.compile(r"https?://[^\s\"'<>]{4,240}", re.IGNORECASE)),
    ("ipv4", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")),
    ("registry", re.compile(r"(?:HK(?:LM|CU|CR|U|CC)|HKEY_[A-Z_]+)[\\/][^\s\"']{3,220}", re.IGNORECASE)),
    # Mark-of-the-web / attachment zone marker.  `:Zone.Identifier` is an NTFS
    # alternate data stream name - the single clearest "this file arrived as a
    # download or mail attachment" artifact in the string layer.  It was absent
    # from every pattern, so the report never mentioned it.
    ("motw", re.compile(r"\bZone\.Identifier\b", re.IGNORECASE)),
    # Temp staging.  Requires a real temporary-path shape or a `.tmp` file name;
    # the previous pattern demanded `%TEMP%`/`\Temp\` and missed a plain `.tmp`.
    ("temp_path", re.compile(
        r"(?:%TEMP%|%TMP%|%APPDATA%|%PROGRAMDATA%|\\Temp\\|\\AppData\\)[^\s\"']{0,180}"
        r"|\b[A-Za-z0-9_.-]{1,64}\.tmp\b",
        re.IGNORECASE,
    )),
    # A scheduled-task string.  The value the parser recovered for this sample is
    # CONTIGUOUS - `schtasks/create/tn/tr/sconce/st00:00/fschtasks create failed/run/delete`
    # with no separators - so `schtasks(\s+...)?` matched only up to the first
    # non-space break and published the mangled tail
    # `schtasks create failed/run/delete`, silently dropping /tn, /tr, /sc once
    # and /st 00:00.  Capture the whole non-whitespace token instead: the blob is
    # the recovered value, and a fragment that no longer exists in the binary is
    # worse than the verbatim blob.
    ("scheduled_task", re.compile(
        r"(?:schtasks(?:\.exe)?|registertaskdefinition)[^\s]{0,300}",
        re.IGNORECASE,
    )),
    ("process_name", re.compile(r"\b(?:explorer|powershell|cmd|wscript|cscript|rundll32|regsvr32)\.exe\b", re.IGNORECASE)),
)

# A disassembly row can legitimately contain many hexadecimal constants.  Hash
# indicators are therefore accepted only from explicitly named digest fields
# (or from the immutable Artifact identity below), never by regex-scanning an
# arbitrary instruction/string payload.
_TRUSTED_DIGEST_FIELDS = {
    "sha256": ("sha256", "content_sha256", "file_sha256", "sample_sha256"),
    "sha1": ("sha1", "content_sha1", "file_sha1", "sample_sha1"),
    "md5": ("md5", "content_md5", "file_md5", "sample_md5"),
}
_REGISTRY_SUBKEY_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])(?:SOFTWARE|SYSTEM|ControlSet\d+)(?:[\\/][A-Za-z0-9 _().-]{1,64}){1,6}",
    re.IGNORECASE,
)
_REGISTRY_WRITE_TOKENS = (
    "regsetvalue", "regcreatekey", "regopenkey", "regdelete", "regqueryvalue",
    "registry write", "registry key",
)


def _evidence_scalar_strings(value: object, *, depth: int = 0, budget: int = 256) -> list[str]:
    """Extract bounded scalar text from nested Evidence values.

    Ghidra rows can contain thousands of instruction objects.  Report
    projection must remain deterministic and cheap, so traversal is bounded
    and intentionally ignores non-scalar objects after the budget is reached.
    """
    if budget <= 0 or depth > 5:
        return []
    if isinstance(value, str):
        return [value[:4096]]
    if isinstance(value, Mapping):
        result: list[str] = []
        remaining = budget
        for item in value.values():
            values = _evidence_scalar_strings(item, depth=depth + 1, budget=remaining)
            result.extend(values)
            remaining = max(0, remaining - len(values))
            if remaining <= 0:
                break
        return result
    if isinstance(value, (list, tuple, set)):
        result = []
        for item in list(value)[:budget]:
            result.extend(_evidence_scalar_strings(item, depth=depth + 1, budget=budget - len(result)))
            if len(result) >= budget:
                break
        return result[:budget]
    return []


def _named_digest_values(
    value: object, *, depth: int = 0, budget: int = 64, max_depth: int = 5
) -> list[tuple[str, str]]:
    """Return only explicitly named, well-formed digest values from Evidence.

    ``max_depth`` lets a caller restrict how far into a nested payload a digest may be found.  The
    default keeps the historical full traversal for callers that want every named digest; the IOC
    projection passes ``max_depth=1`` because a FILE indicator must come from the identity fields of
    the row, not from a digest that merely happens to live somewhere inside it.

    Measured on task `ce7e310e`: `pe_structure.value.resources.entries[*].sha256` holds the digest of
    each PE resource payload, and the full traversal collected all eleven of them as `sha256` IOCs
    with `confidence: HIGH` and `source: static_triage/pe_structure` - eleven values that cannot
    identify the file, published side by side with the one that can.  The detection rule then picked
    one of them (`$s5`) as its file-hash indicator, so the deployable artefact keyed on a resource
    digest while the sample's real SHA-256 was absent from the rule entirely.
    """
    if budget <= 0 or depth > max_depth:
        return []
    if isinstance(value, Mapping):
        found: list[tuple[str, str]] = []
        for key, item in value.items():
            normalized_key = str(key).casefold()
            for category, fields in _TRUSTED_DIGEST_FIELDS.items():
                expected_length = {"sha256": 64, "sha1": 40, "md5": 32}[category]
                if normalized_key in fields and isinstance(item, str):
                    digest = item.strip()
                    if re.fullmatch(rf"[0-9a-f]{{{expected_length}}}", digest, re.IGNORECASE):
                        found.append((category, digest))
            if len(found) >= budget:
                break
            found.extend(
                _named_digest_values(
                    item, depth=depth + 1, budget=budget - len(found), max_depth=max_depth
                )
            )
            if len(found) >= budget:
                break
        return found[:budget]
    if isinstance(value, (list, tuple, set)):
        found = []
        for item in list(value)[:budget]:
            found.extend(
                _named_digest_values(
                    item, depth=depth + 1, budget=budget - len(found), max_depth=max_depth
                )
            )
            if len(found) >= budget:
                break
        return found[:budget]
    return []


#: A registry path the image contains, e.g.
#: ``SOFTWARE\Microsoft\Windows Defender\SpyNet``.  Anchored on a known hive-ish
#: root so ordinary backslash-heavy strings (paths, GUIDs) do not match.
_REGISTRY_KEY_STRING_RE = re.compile(
    r"(?i)\b(SOFTWARE|SYSTEM|SECURITY|SAM)\\(?:[A-Za-z0-9 _().{}-]+\\?){1,8}"
)

#: A Defender/AV configuration value name.  These appear as bare strings next to
#: the key paths and are what a detection rule keys on.
_REGISTRY_VALUE_NAME_RE = re.compile(
    r"^(?:MAPSReporting|SubmitSamplesConsent|SpynetReporting|DisableAntiSpyware|"
    r"DisableAntiVirus|DisableRealtimeMonitoring|Exclusions|Paths)$"
)


def build_registry_key_projection(
    evidence_by_id: Mapping[str, Any],
) -> dict[str, object]:
    """Project registry key paths and value names the image literally contains.

    Why this exists.  The sample carries a Windows Defender tampering
    configuration as plain strings, each with a ``file_offset`` anchor:

        SOFTWARE\\Microsoft\\Windows Defender\\SpyNet                  306105
        SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SpyNet        306148
        MAPSReporting                                                  306200
        SubmitSamplesConsent                                           306214
        SpynetReporting                                                306235
        SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths       306735

    The report could not state any of them.  The cause is not that the strings are
    missing from evidence - they are present as ``string`` rows - but that the
    per-function reference sample for the enclosing function holds exactly 64
    references and stops before the registry block, so nothing ever carried them
    into the document.  This projection reads the ``string`` evidence directly,
    which is complete, and keeps each value next to its own anchor rather than
    making the renderer join across rows.

    This is a projection, not a new join: it copies strings that are really in the
    image.  It does NOT claim the sample wrote them - the value/data binding and
    the callsite binding are still unrecovered, and ``bound_to_write`` records
    only whether a registry write API was seen at all.
    """
    write_tokens = ("regsetvalue", "regcreatekey", "regopenkey", "regdeletevalue")
    keys: list[dict[str, object]] = []
    values: list[str] = []
    write_api_seen = False
    seen_keys: set[str] = set()

    for evidence_id, item in evidence_by_id.items():
        kind = str(
            (item.get("kind") if isinstance(item, Mapping) else getattr(item, "kind", ""))
            or ""
        )
        if kind != "string":
            continue
        value = item.get("value") if isinstance(item, Mapping) else getattr(item, "value", None)
        if not isinstance(value, Mapping):
            continue
        text = str(value.get("text") or "").strip()
        if not text:
            continue
        anchor = item.get("anchor") if isinstance(item, Mapping) else getattr(item, "anchor", None)
        offset = anchor.get("offset") if isinstance(anchor, Mapping) else None

        match = _REGISTRY_KEY_STRING_RE.search(text)
        if match:
            key = match.group(0)
            if key.casefold() not in seen_keys:
                seen_keys.add(key.casefold())
                keys.append(
                    {
                        "key": key,
                        "file_offset": offset,
                        "evidence_id": str(evidence_id),
                    }
                )
            continue
        if _REGISTRY_VALUE_NAME_RE.fullmatch(text) and text not in values:
            values.append(text)

    for _evidence_id, item in evidence_by_id.items():
        blob = str(
            (item.get("value") if isinstance(item, Mapping) else getattr(item, "value", ""))
            or ""
        ).casefold()
        if any(token in blob for token in write_tokens):
            write_api_seen = True
            break

    return {
        "type": "registry_keys",
        "present": bool(keys or values),
        "keys": keys,
        "value_names": values,
        "write_api_seen": write_api_seen,
        # Deliberately explicit: seeing the strings and a write API in one image is
        # not proof that any particular value was written.
        "bound_to_write": False,
        "runtime_effect_proven": False,
    }


def build_static_indicator_projections(
    evidence_by_id: Mapping[str, Any],
    artifacts: list[Any] | None = None,
) -> list[dict[str, object]]:
    """Build analyst-facing static IOC rows from typed Evidence.

    Values are not promoted solely because they look like a URL or command:
    every row is marked ``STATIC_DERIVED`` and links back to the source
    Evidence and anchor.  This is the report's hunting index, not runtime
    telemetry and not a malware-family attribution.
    """
    grouped: dict[tuple[str, str], dict[str, object]] = {}

    def read(item: Any, key: str, default: object = None) -> object:
        if isinstance(item, Mapping):
            return item.get(key, default)
        return getattr(item, key, default)

    prepared_evidence: list[tuple[str, Any, str, str, dict[str, object], object, list[str]]] = []
    for evidence_id, item in evidence_by_id.items():
        kind = str(read(item, "kind", "unknown"))
        module = str(read(item, "module", "static_triage"))
        # Background/knowledge channels are intentionally isolated from the
        # sample report.  They may inform a later comparison workflow, but
        # must never become sample IOCs or hunting pivots here.
        if module.casefold() in {"background_context", "knowledge_snapshot", "evaluation"}:
            continue
        anchor = read(item, "anchor", {})
        anchor = dict(anchor) if isinstance(anchor, Mapping) else {}
        value = read(item, "value", {})
        prepared_evidence.append((str(evidence_id), item, kind, module, anchor, value, _evidence_scalar_strings(value)))

    all_evidence_text = "\n".join(
        text.casefold()
        for _, _, _, _, _, _, values in prepared_evidence
        for text in values
    )
    registry_context_present = any(token in all_evidence_text for token in _REGISTRY_WRITE_TOKENS)

    def add_indicator(
        category: str,
        indicator: str,
        *,
        evidence_id: str,
        module: str,
        kind: str,
        anchor: Mapping[str, object],
    ) -> None:
        if len(indicator) < 4:
            return
        key = (category, indicator.casefold())
        row = grouped.get(key)
        if row is None:
            row = grouped[key] = {
                "type": "ioc",
                "classification": "STATIC_DERIVED",
                "category": category,
                "value": indicator,
                "source": f"{module}/{kind}",
                "evidence_ids": [],
                "anchors": [],
                "static_only": True,
                "confidence": "HIGH" if category in {"url", "ipv4", "sha256", "sha1", "md5"} else "MEDIUM",
                "boundary": "Static value recovered from Evidence; presence, reachability, and successful use are unobserved.",
            }
        row["evidence_ids"] = list(dict.fromkeys([*row.get("evidence_ids", []), evidence_id]))[:8]
        if anchor and anchor not in row["anchors"]:
            row["anchors"] = [*row["anchors"], dict(anchor)][:4]

    for evidence_id, _, kind, module, anchor, value, source_values in prepared_evidence:
        for source_text in source_values:
            for category, pattern in _STATIC_INDICATOR_PATTERNS:
                for match in pattern.findall(source_text):
                    indicator = str(match).rstrip(".,;)]}>")
                    if category == "ipv4":
                        try:
                            octets = [int(part) for part in indicator.split(".")]
                            if any(part > 255 for part in octets):
                                continue
                        except ValueError:
                            continue
                    add_indicator(category, indicator, evidence_id=evidence_id, module=module, kind=kind, anchor=anchor)

            # Some Windows APIs take only a subkey (for example SOFTWARE\\...) rather
            # than a hive-qualified path.  Keep this useful pivot only in a registry
            # context, or for high-specificity Defender/Run keys.
            subkey_allowed = (
                kind.casefold() in {"string", "api_argument_trace", "function_call"}
                or "registry" in module.casefold()
            ) and (
                registry_context_present
                or any(token in source_text.casefold() for token in ("windows defender", "\\run", "\\runonce"))
            )
            if subkey_allowed:
                for match in _REGISTRY_SUBKEY_PATTERN.findall(source_text):
                    add_indicator("registry_subkey", match.rstrip(".,;)]}>"), evidence_id=evidence_id, module=module, kind=kind, anchor=anchor)

        # `max_depth=1` restricts file digests to the row's own identity fields.  A digest nested
        # deeper (`resources.entries[*].sha256`) identifies a REGION of the file, and publishing it
        # as a file IOC is EC-5: the value cannot identify the sample.  Measured on task `ce7e310e`,
        # the full traversal contributed eleven such values as HIGH-confidence `sha256` IOCs.
        for category, digest in _named_digest_values(value, max_depth=1):
            add_indicator(category, digest, evidence_id=evidence_id, module=module, kind=kind, anchor=anchor)

    # Artifact hashes are identity IOCs even when the parser did not emit a
    # file_identity Evidence row.  They are safe to expose and essential for
    # blocklist/hunting workflows.
    for artifact in artifacts or []:
        digest = str(read(artifact, "content_sha256", "") or "").strip()
        if not re.fullmatch(r"[0-9a-f]{64}", digest, re.IGNORECASE):
            continue
        key = ("sha256", digest.casefold())
        grouped.setdefault(key, {
            "type": "ioc",
            "classification": "STATIC_DERIVED",
            "category": "sha256",
            "value": digest,
            "source": "artifact/content_sha256",
            "evidence_ids": [],
            "anchors": [],
            "static_only": True,
            "confidence": "HIGH",
            "boundary": "Static file identity; this does not establish execution or network activity.",
        })

    # Stable ordering makes snapshots/reviews reproducible and puts direct
    # network and file identity pivots before contextual command strings.
    category_order = {"sha256": 0, "sha1": 1, "md5": 2, "url": 3, "ipv4": 4, "registry": 5, "registry_subkey": 6, "scheduled_task": 7, "motw": 8, "process_name": 9, "temp_path": 10}
    rows = list(grouped.values())
    rows.sort(key=lambda row: (category_order.get(str(row.get("category")), 99), str(row.get("value", "")).casefold()))
    return rows[:96]


def build_static_attack_candidates(
    evidence_by_id: Mapping[str, Any],
) -> list[dict[str, object]]:
    """Derive conservative ATT&CK candidates from multi-signal Evidence.

    The conjunctions intentionally mirror analyst reasoning: API presence by
    itself is insufficient.  Each mapping remains ``candidate`` and carries
    the exact source IDs so a later verifier can promote or reject it.
    """
    rows: list[tuple[str, str, str, tuple[str, ...]]] = []

    def read(item: Any, key: str, default: object = None) -> object:
        if isinstance(item, Mapping):
            return item.get(key, default)
        return getattr(item, key, default)

    evidence_text: dict[str, str] = {
        str(evidence_id): " ".join(
            [
                # The typed Evidence kind is a trusted semantic signal.  It
                # must participate in ATT&CK correlation even when a producer
                # stores only numeric/opaque details in ``value`` (for
                # example a decode window with no literal 'xor' label).
                str(read(item, "kind", "")),
                *_evidence_scalar_strings(read(item, "value", {})),
            ]
        ).casefold()
        for evidence_id, item in evidence_by_id.items()
        if str(read(item, "module", "")).casefold() not in {"background_context", "knowledge_snapshot", "evaluation"}
    }
    def ids_any(*terms: str) -> tuple[str, ...]:
        return tuple(
            evidence_id for evidence_id, text in evidence_text.items()
            if any(term.casefold() in text for term in terms)
        )[:12]

    registry_ids = ids_any("regsetvalue", "regopenkey", "regcreatekey", "registry")
    defender_ids = ids_any("windows defender", "defender", "spynet", "disableantispyware", "mpreffer")
    if registry_ids and defender_ids:
        rows.append(("T1112", "Modify Registry", "Defender-related registry write path", tuple(dict.fromkeys([*registry_ids, *defender_ids]))[:12]))
        rows.append(("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defender configuration names are coupled to a registry-write capability", tuple(dict.fromkeys([*registry_ids, *defender_ids]))[:12]))

    ppid_ids = ids_any("updateprocthreadattribute", "proc_thread_attribute_parent_process")
    parent_context_ids = ids_any("openprocess", "explorer.exe", "parent process", "parent-process")
    if ppid_ids and parent_context_ids:
        rows.append(("T1134.004", "Parent PID Spoofing", "Parent-process attribute setup is linked to process enumeration/opening evidence", tuple(dict.fromkeys([*ppid_ids, *parent_context_ids]))[:12]))

    task_ids = ids_any("schtasks", "registertaskdefinition", "task scheduler")
    task_control_ids = ids_any("/create", "\\create", "/run", "/delete", "sc once")
    if task_ids and task_control_ids:
        rows.append(("T1053.005", "Scheduled Task/Job: Scheduled Task", "Task Scheduler command/control tokens are present in static evidence", tuple(dict.fromkeys([*task_ids, *task_control_ids]))[:12]))

    network_ids = ids_any("winhttp", "wininet", "httpsendrequest", "httpopenrequest", "socket", "network_download")
    url_ids = ids_any("http://", "https://")
    if network_ids and url_ids:
        rows.append(("T1105", "Ingress Tool Transfer", "A statically recovered endpoint is coupled to a transport/API path", tuple(dict.fromkeys([*network_ids, *url_ids]))[:12]))

    decode_ids = ids_any("mechanism_decode_window", "xor", "decode", "decrypt", "encoded_blob")
    if decode_ids:
        rows.append(("T1140", "Deobfuscate/Decode Files or Information", "A bounded decode/XOR evidence path is present; plaintext use remains unobserved", decode_ids))

    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for technique_id, name, reason, evidence_ids in rows:
        if technique_id in seen:
            continue
        seen.add(technique_id)
        result.append({
            "type": "attack_mapping_candidate",
            "status": "candidate",
            "attack_techniques": [{
                "technique_id": technique_id,
                "name": name,
                "status": "candidate",
                "confidence": "MEDIUM",
                "evidence_count": len(evidence_ids),
                "reason": reason,
                "static_only": True,
            }],
            "evidence_ids": list(evidence_ids),
            "reason": reason,
            "analysis_source": "deterministic_static_correlation",
            "boundary": "Candidate ATT&CK mapping from static conjunctions; execution and technique success are not observed.",
        })
    return result


def build_decode_result_projections(
    evidence_by_id: Mapping[str, Any],
) -> list[dict[str, object]]:
    """Project verified static byte replays into the decryption module.

    ``decode_result`` is produced by the bounded XOR verifier.  It is useful
    analyst material (a preview, verification scope, and a statically linked
    consumer), but it is never runtime telemetry.  Keep the projection small
    and retain source IDs so the full result remains available in the ledger.
    """
    rows: list[dict[str, object]] = []

    def read(item: Any, key: str, default: object = None) -> object:
        if isinstance(item, Mapping):
            return item.get(key, default)
        return getattr(item, key, default)

    def text_list(value: object, limit: int = 16) -> list[str]:
        if isinstance(value, (list, tuple, set)):
            return [str(item) for item in value if item not in (None, "")][:limit]
        if value not in (None, ""):
            return [str(value)]
        return []

    for evidence_id, item in evidence_by_id.items():
        if str(read(item, "kind", "")).casefold() != "decode_result":
            continue
        value = read(item, "value", {})
        value = value if isinstance(value, Mapping) else {}
        verification = value.get("verification")
        verification = verification if isinstance(verification, Mapping) else {}
        candidate = value.get("candidate")
        candidate = candidate if isinstance(candidate, Mapping) else {}
        anchor = read(item, "anchor", {})
        anchor = anchor if isinstance(anchor, Mapping) else {}

        status = str(
            value.get("verification_status")
            or verification.get("status")
            or "UNKNOWN"
        ).upper()
        consumers = value.get("consumer_candidates")
        consumers = consumers if isinstance(consumers, list) else []
        consumer_rows = [
            {
                "evidence_id": str(row.get("evidence_id")),
                "kind": str(row.get("kind") or "function_call"),
                "api": row.get("api") or row.get("target_name") or row.get("target_function"),
                "function_entry": row.get("function_entry"),
            }
            for row in consumers[:16]
            if isinstance(row, Mapping) and row.get("evidence_id")
        ]
        source_ids = [str(evidence_id)]
        source_ids.extend(text_list(value.get("source_evidence_ids"), 24))
        source_ids.extend(str(row["evidence_id"]) for row in consumer_rows)
        source_ids = list(dict.fromkeys(source_ids))[:24]
        decoded_preview = (
            verification.get("decoded_preview")
            or verification.get("decoded_text")
            or verification.get("decoded_strings", [None])[0]
            if isinstance(verification.get("decoded_strings"), list) and verification.get("decoded_strings")
            else verification.get("decoded_preview") or verification.get("decoded_text")
        )
        decoded_strings = text_list(verification.get("decoded_strings"), 16)
        function_entry = (
            value.get("function_entry")
            or candidate.get("function_entry")
            or anchor.get("function_entry")
        )
        rva = value.get("rva") or candidate.get("rva") or anchor.get("rva")
        rows.append(
            {
                "type": "decode_result",
                "evidence_id": str(evidence_id),
                "artifact_id": str(read(item, "artifact_id", "") or "") or None,
                "source_kind": value.get("source_kind") or "decode_candidate",
                "verification_status": status,
                "verification_scope": verification.get("verification_scope", {}),
                # Completeness verdict for the recovered text (see
                # `literal_table.discover_anchored_literal_tables`): whether a SECOND literal table exists
                # and whether it carries markers the primary one lacks.
                #
                # Carried as a TOP-LEVEL key on this row because the renderer receives document rows, not
                # the raw `verification` mapping - and the nested mapping is dropped when the document is
                # built. MEASURED on task `cc6a822b`: `second_table_check` was present in `evidence` and in
                # the snapshot's `object_versions`, but the revision document contained it ZERO times, so
                # `analyst_report._second_table_check` found nothing and the chapter stayed silent about a
                # check that had actually run. A capability that cannot reach the body is not a capability.
                "second_table_check": verification.get("second_table_check"),
                "file_offset": verification.get("file_offset"),
                "virtual_address": verification.get("virtual_address"),
                "function_entry": function_entry,
                "rva": rva,
                "formula": verification.get("formula") or candidate.get("formula"),
                "length": verification.get("length"),
                "printable_ratio": verification.get("printable_ratio"),
                "markers": text_list(verification.get("markers"), 12),
                "decoded_preview": str(decoded_preview)[:512] if decoded_preview not in (None, "") else None,
                "decoded_strings": decoded_strings,
                "consumer_status": str(value.get("consumer_status") or "NOT_IDENTIFIED"),
                "consumer_candidates": consumer_rows,
                "consumer_evidence_ids": list(dict.fromkeys(
                    [str(item_id) for item_id in text_list(value.get("consumer_evidence_ids"), 16)]
                    + [str(row["evidence_id"]) for row in consumer_rows]
                ))[:16],
                "source_evidence_ids": source_ids,
                "plaintext_recovered": bool(decoded_preview or decoded_strings),
                "static_only": True,
                "boundary": (
                    "Static bytes were replayed against a bounded decode hypothesis; "
                    "runtime execution is unobserved; reachability and successful consumer use are also unobserved."
                ),
            }
        )
    for evidence_id, item in evidence_by_id.items():
        if str(read(item, "kind", "")).casefold() != "decoded_artifact":
            continue
        value = read(item, "value", {})
        value = value if isinstance(value, Mapping) else {}
        child_id = value.get("child_artifact_id")
        sha256 = value.get("sha256")
        if not child_id and not sha256:
            continue
        rows.append(
            {
                "type": "decode_result",
                "evidence_id": str(evidence_id),
                "artifact_id": str(read(item, "artifact_id", "") or "") or None,
                "source_kind": value.get("source") or "recovered_child",
                "verification_status": "RECOVERED_CHILD",
                "child_artifact_id": child_id,
                "sha256": sha256,
                "length": value.get("size"),
                "decoded_preview": None,
                "decoded_strings": [],
                "consumer_status": "NOT_IDENTIFIED",
                "consumer_candidates": [],
                "consumer_evidence_ids": [],
                "source_evidence_ids": [str(evidence_id)],
                "plaintext_recovered": False,
                "static_only": True,
                "boundary": (
                    "Recovered child bytes were materialized into a new Artifact and "
                    "re-entered static analysis; runtime execution is unobserved."
                ),
            }
        )
    return rows[:32]


_CREATION_FLAGS_SLOT_RE = re.compile(
    r"(?i)^MOV\s+(?:dword|qword)\s+ptr\s*\[\s*(RSP|ESP|RBP|EBP)\s*\+\s*0x([0-9a-f]+)\s*\]\s*,"
    r"\s*(0x[0-9a-f]+|\d+)$"
)
_PROCESS_CREATION_CALL_RE = re.compile(r"(?i)^CALL\s+(?:0x)?([0-9a-f]+)$")


def iter_document_windows(document: Mapping[str, object] | None) -> list[Mapping[str, object]]:
    """Every instruction-window-shaped mapping in a document."""
    found: list[Mapping[str, object]] = []

    def walk(node: object) -> None:
        if isinstance(node, Mapping):
            if isinstance(node.get("instructions"), list):
                found.append(node)
            for nested in node.values():
                walk(nested)
        elif isinstance(node, list):
            for nested in node:
                walk(nested)

    walk(document or {})
    return found


def instruction_windows_from_evidence(
    evidence_by_id: Mapping[str, Any],
) -> list[Mapping[str, object]]:
    """The instruction windows a builder pass holds, in document-shaped form.

    `build_runtime_sequence` runs before the document exists, so it cannot be handed the
    document; it is handed this instead.  Each entry is ``{"instructions": [...]}``, which
    is exactly the shape :func:`creation_flags_from_callsite` scans, so the deterministic
    flag word can be resolved from the evidence the pass already has.
    """
    windows: list[Mapping[str, object]] = []
    for item in evidence_by_id.values():
        kind = str(getattr(item, "kind", "") or (item.get("kind") if isinstance(item, Mapping) else "") or "")
        if kind != "function_instruction_window":
            continue
        value = getattr(item, "value", None)
        if value is None and isinstance(item, Mapping):
            value = item.get("value")
        if isinstance(value, Mapping) and isinstance(value.get("instructions"), list):
            windows.append(value)
    return windows


def creation_flags_from_callsite(document: Mapping[str, object] | None) -> str:
    """The flag word the process-creation CALL itself passes, if recoverable.

    This is the DETERMINISTIC route, and it exists because the obvious route is wrong.
    ``process_creation_flags.flags`` is a candidate LIST of every credential-looking
    immediate in one function: for FUN_140004605 it holds eight words, of which one
    belongs to ``CreateProcessW``.  Publishing the first credible entry produced
    ``0x28000000`` for a sample whose real value is ``0x09080008`` - a wrong answer is
    worse than UNKNOWN, so the list is never mined for a guess.

    What IS deterministic is the call site.  On the real sample the window ends with:

        MOV dword ptr [RSP + 0x28],0x9080008     <- dwCreationFlags stack slot
        AND dword ptr [RSP + 0x20],0x0
        MOV RCX,R14                              <- lpApplicationName
        XOR EDX,EDX                              <- lpCommandLine (null)
        XOR R8D,R8D
        XOR R9D,R9D
        CALL 0x140046948                         <- CreateProcessW thunk

    Six of the eight candidate words never appear in this window at all.  So scan the
    instructions before a process-creation call for a ``MOV`` into a stack slot and accept
    the immediate only when it credibly describes Windows creation flags.  Returns ``""``
    when no such call site is present, so a caller cannot mistake "not found" for "no
    flags".
    """
    candidates: list[tuple[int, int, str]] = []
    for window_index, window in enumerate(iter_document_windows(document)):
        instructions = [
            item for item in (window.get("instructions") or []) if isinstance(item, Mapping)
        ]
        for index, item in enumerate(instructions):
            if not _PROCESS_CREATION_CALL_RE.match(str(item.get("text") or "").strip()):
                continue
            for earlier in reversed(instructions[max(0, index - 24) : index]):
                text = str(earlier.get("text") or "").strip()
                if not _CREATION_FLAGS_SLOT_RE.match(text):
                    continue
                operand = text.rsplit(",", 1)[-1].strip()
                if credible_windows_process_creation_flags(_parse_flag_word(operand)):
                    candidates.append((index, window_index, operand))
                break
    if not candidates:
        return ""
    # Prefer the write for the LAST call in the first window that has one.
    candidates.sort()
    return candidates[-1][2]


def _parse_flag_word(value: object) -> int:
    text = str(value or "").strip().strip("`")
    if not text:
        return 0
    try:
        return int(text, 16) if text[:2].casefold() == "0x" else int(text, 10)
    except ValueError:
        return 0


def instruction_window_carries_process_creation_flags(window: object) -> bool:
    """True when an instruction window's text holds a process-creation call site.

    Used at REPORT-PROJECTION time to decide which instruction windows survive the
    bounded evidence selection.  The bounded window previously kept only windows matching
    the CryptoAPI markers (`0x6801` / `calg`), so no window carrying a CreateProcess call
    site was ever selected.  Measured on task ``c705a42e``:

        ledger instruction windows                 703
        windows mentioning the flag immediate        1
        windows in the stored report document        0
        rows the renderer can see                    0   (556 rows, none a window)

    so the published body printed ``UNKNOWN(creation_flags)`` although the deciding
    instructions were in evidence.  A fact that cannot reach the consumer is absent as far
    as the report is concerned, however well the producer stored it.

    Deliberately text-only and allocation-light: it runs over every window in the ledger
    once per report projection, and the alternative - parsing each payload - is the kind of
    cost that made this pipeline stall in the first place.  The markers are exact strings
    from the disassembly text, so a plain substring test has no false positives to worry
    about; the authoritative parse still happens later in
    :func:`creation_flags_from_callsite`, which is what actually publishes a value.

    Each instruction is tested SEPARATELY.  ``_CREATION_FLAGS_SLOT_RE`` is anchored with
    ``^...$`` and has no ``re.MULTILINE``, so a pattern meant to describe one line never
    matches a joined multi-line blob - the first version of this predicate joined the
    window and silently matched nothing at all.
    """
    if isinstance(window, Mapping):
        instructions = window.get("instructions")
    else:
        instructions = None
    if isinstance(instructions, list):
        texts: list[str] = []
        for item in instructions:
            if isinstance(item, Mapping):
                text = item.get("text")
            elif isinstance(item, str):
                text = item
            else:
                text = None
            if text:
                texts.append(str(text))
    else:
        # Not a window payload.  A bare string was accepted here at first, which made any
        # stray text carrying a slot-write line look like a disassembly window and would
        # have pulled a whole function body into the report on a substring match.
        return False

    for text in texts:
        # Cheap gate first: only an argument-slot write is interesting, and the call must
        # be in the same window.
        if "ptr [" not in text.casefold():
            continue
        match = _CREATION_FLAGS_SLOT_RE.match(text.strip())
        if not match:
            continue
        if credible_windows_process_creation_flags(_parse_flag_word(match.group(3))):
            return True
    return False


def build_creation_flags_callsite_projection(
    evidence_by_id: Mapping[str, Any],
) -> dict[str, object] | None:
    """The ``dwCreationFlags`` word the process-creation CALL passes, as a projection.

    WHY A PROJECTION AND NOT A WIDER GATE.  The renderer receives the report DOCUMENT, and
    the only channels into it are claim-linked ``evidence_samples`` (capped at 6 per claim)
    and ledger GROUP rows, which hold evidence ids rather than values.  Measured on task
    ``de738f12``: the bounded projection keeps the deciding instruction window, and
    ``creation_flags_from_callsite`` resolves ``0x9080008`` from it, yet the document's only
    two ``function_instruction_window`` entries are GROUP rows with ``value: None`` - so the
    renderer could not see the window at all and printed ``UNKNOWN(creation_flags)`` eight
    times while the same document's runtime sequence published the value.

    A 341 KB function body must not be copied into the document to fix that.  The
    deterministic word and its provenance are what a consumer needs, so project exactly
    those, in the same spirit as ``document["process_flags"]``.

    Returns ``None`` when no call site decides a credible flag word, so an absent key is
    never mistaken for a recovered one and a caller cannot read a fabricated default.
    """
    windows = instruction_windows_from_evidence(evidence_by_id)
    if not windows:
        return None
    decided = creation_flags_from_callsite({"windows": windows})
    if not decided:
        return None
    return {
        "type": "creation_flags_callsite",
        "value": decided,
        "recovered_as": "typed_argument_binding",
        "source": "process-creation call site (instruction window)",
        "window_count": len(windows),
        "runtime_effect_proven": False,
    }


def build_process_flag_projections(
    evidence_by_id: Mapping[str, Any],
) -> list[dict[str, object]]:
    """Project statically decoded CreateProcess flags without inventing modes.

    Each row carries ``recovered_as`` naming the layer it came from.  That provenance is
    load-bearing, not decoration: the ``process_creation_flags`` scan keeps a CANDIDATE
    LIST of immediates seen in a function, while a typed ``api_argument_trace`` binds one
    word to the ``dwCreationFlags`` argument.  A consumer that receives both without
    labels cannot tell them apart, and the only safe-looking thing it can do is print
    ``UNKNOWN(creation_flags)`` - which is exactly the false negative this fixes:

    measured on task `c705a42e`, `0x09080008` was in the ``process_creation_flags`` row
    while ``api_argument_trace.creation_flags`` was empty, so the published body printed
    ``UNKNOWN(creation_flags)`` next to the value it had just written out.
    """
    rows: list[dict[str, object]] = []

    def read(item: Any, key: str, default: object = None) -> object:
        if isinstance(item, Mapping):
            return item.get(key, default)
        return getattr(item, key, default)

    for evidence_id, item in evidence_by_id.items():
        if str(read(item, "kind", "")).casefold() != "process_creation_flags":
            continue
        value = read(item, "value", {})
        value = value if isinstance(value, Mapping) else {}
        flags = value.get("flags")
        flag_rows = flags if isinstance(flags, list) else []
        typed = bool(value.get("creation_flags") or value.get("flags_typed"))
        if not flag_rows and isinstance(value.get("set_flags"), list):
            flag_rows = [value]
        for flag in flag_rows[:8]:
            if not isinstance(flag, Mapping):
                continue
            names = [str(name) for name in (flag.get("set_flags") or []) if str(name).strip()]
            rows.append(
                {
                    "type": "process_creation_flags",
                    "evidence_id": str(evidence_id),
                    "value": flag.get("value") or value.get("value"),
                    # Provenance.  `typed_argument_binding` means the word was bound to
                    # the dwCreationFlags argument; `candidate_immediate` means the scan
                    # found this immediate in the process and mapped its bits, which is
                    # real recovered data but not a proven argument binding.
                    "recovered_as": (
                        "typed_argument_binding" if typed else "candidate_immediate"
                    ),
                    "set_flags": names,
                    "unknown_bits": flag.get("unknown_bits"),
                    "contains_create_suspended": bool(flag.get("contains_create_suspended")),
                    "contains_create_new_console": bool(flag.get("contains_create_new_console")),
                    "interpretation": flag.get("interpretation"),
                    "runtime_effect_proven": bool(flag.get("runtime_effect_proven") or value.get("runtime_effect_proven")),
                }
            )
    return rows[:16]


def build_pe_entry_projection(
    evidence_by_id: Mapping[str, Any],
) -> dict[str, object] | None:
    """Project PE AddressOfEntryPoint without inventing CRT or loader names."""
    basics = build_pe_basics_projection(evidence_by_id)
    if not basics or basics.get("entry_rva") in (None, ""):
        return None
    return {"entry_rva": basics.get("entry_rva"), "image_base": basics.get("image_base")}


#: Bound on the flat ``imports`` list carried into the report document.
#:
#: This is an explicit, reported boundary rather than a silent truncation: the document also carries
#: ``import_entries`` (complete, ordered) and ``import_name_total``, so a consumer that needs every
#: name can take it and one that needs a readable overview can take the bounded list.  Measured on
#: task `ce7e310e`: 9 import descriptors / 136 function names, of which the previous flat cap of 80
#: silently dropped 56 - the tail of `kernel32.dll` plus all of `msvcrt.dll` - while the published
#: section still read as if it were the complete inventory.
_PE_IMPORT_NAME_CAP = 160


def _pe_import_name_groups(
    imports: object,
) -> list[tuple[str, list[str]]]:
    """``[(module, [function, ...]), ...]`` in descriptor order, modules never merged.

    The module is the analyst's first triage fact, and it was being destroyed here: the projection
    flattened `{"module": "advapi32.dll", "functions": [...]}` into bare function strings, so the
    published body could not name a single module and printed one `（未限定模块）` bucket instead.
    Measured on task `ce7e310e`: the ledger holds eight module names and 136 import names, and all
    606 `code_api_call` rows are module-qualified.
    """
    groups: list[tuple[str, list[str]]] = []
    if not isinstance(imports, list):
        return groups
    for dll in imports:
        if not isinstance(dll, Mapping):
            continue
        module = str(
            # `module` is what the producer writes: a real `pe_structure.imports` entry is
            # `{"functions": [...], "module": "advapi32.dll", "thunk_rva": ..., "thunk_width": ...}`.
            # Reading only `dll`/`name` meant the module was ALWAYS empty, so every import was
            # published unqualified - making `ntdll.dll!NtReadFile` indistinguishable from a WinHTTP
            # import.
            dll.get("module")
            or dll.get("dll")
            or dll.get("name")
            or dll.get("module_name")
            or ""
        ).strip()
        functions = dll.get("functions")
        names = [
            str(name).strip()
            for name in (functions if isinstance(functions, list) else [])
            if str(name).strip()
        ]
        if names:
            groups.append((module, names))
    return groups


def _pe_import_symbols(
    groups: Sequence[tuple[str, list[str]]], *, cap: int = _PE_IMPORT_NAME_CAP
) -> list[str]:
    """Module-qualified symbols, round-robined across modules so the cap cannot starve a module.

    A flat `module!name` list capped in descriptor order looks complete while hiding whole modules:
    `kernel32.dll` alone holds 70 of this sample's 136 names, so a downstream `[:80]` saw four
    modules and `advapi32.dll`, `shell32.dll`, `user32.dll` were represented by luck of ordering.
    Round-robin makes any prefix a cross-section of every module in the table.
    """
    remaining = [list(names) for _module, names in groups]
    modules = [module for module, _names in groups]
    out: list[str] = []
    depth = 0
    while len(out) < cap:
        added = False
        for index, names in enumerate(remaining):
            if depth >= len(names):
                continue
            symbol = names[depth]
            out.append(f"{modules[index]}!{symbol}" if modules[index] else symbol)
            added = True
            if len(out) >= cap:
                break
        if not added:
            break
        depth += 1
    return out


def _pe_import_entries(
    groups: Sequence[tuple[str, list[str]]]
) -> list[dict[str, object]]:
    """The `{module, functions}` structure carried into the document, described in every slot.

    `module` is `""` when the PE import table did not name one, and the renderer labels that
    explicitly rather than guessing a module.
    """
    return [
        {"module": module, "functions": list(names), "function_count": len(names)}
        for module, names in groups
    ]


def build_pe_resource_projection(
    evidence_by_id: Mapping[str, Any],
) -> dict[str, object] | None:
    """Surface the PE resource directory as analyst facts.

    The parser already records the resource tree - `pe_structure.resources` holds
    `{rva, size, count, entries, rcdata_count, rcdata_total_size, high_entropy_count}` and a
    `resource_inventory` Evidence row repeats it - but nothing projected it into the report
    document, so the published body never mentioned resources at all.

    Measured on task `ce7e310e`, where that costs a headline fact: the binary is submitted under a
    `.pdf.exe`-style name, carries an 876-byte `RT_VERSION` resource, nine `RT_ICON` entries (one at
    entropy 7.94, i.e. a plausible embedded payload) and an `RT_GROUP_ICON` directory - and the body
    said nothing about any of it while its limitations section still listed "资源提取链" as something
    that "can be written into the report".
    """
    for item in evidence_by_id.values():
        if str(_evidence_field(item, "kind", "")).casefold() != "pe_structure":
            continue
        value = _evidence_field(item, "value", {})
        value = value if isinstance(value, Mapping) else {}
        resources = value.get("resources")
        if not isinstance(resources, Mapping):
            continue
        raw_entries = resources.get("entries")
        entries = [entry for entry in raw_entries if isinstance(entry, Mapping)] if isinstance(
            raw_entries, list
        ) else []
        if not entries:
            continue
        # Group by resource type so the report says "9 icons, 1 version block", not 11 opaque rows.
        by_type: dict[int, list[Mapping[str, object]]] = {}
        for entry in entries:
            raw_type = entry.get("type")
            try:
                type_id = int(raw_type)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                type_id = -1
            by_type.setdefault(type_id, []).append(entry)
        groups = []
        for type_id in sorted(by_type):
            group = by_type[type_id]
            entropies = []
            for entry in group:
                try:
                    entropies.append(float(entry.get("entropy") or 0.0))
                except (TypeError, ValueError):
                    continue
            groups.append(
                {
                    "type_id": type_id,
                    "name": _PE_RESOURCE_TYPE_NAMES.get(type_id, f"type-{type_id}"),
                    "count": len(group),
                    "total_size": sum(int(entry.get("size") or 0) for entry in group),
                    "max_entropy": round(max(entropies), 5) if entropies else 0.0,
                }
            )
        return {
            "type": "pe_resources",
            "resource_count": int(resources.get("count") or len(entries)),
            "entries": groups,
            "resource_types": [group["name"] for group in groups],
            "high_entropy_count": int(resources.get("high_entropy_count") or 0),
            "rcdata_count": int(resources.get("rcdata_count") or 0),
            "rcdata_total_size": int(resources.get("rcdata_total_size") or 0),
        }
    return None


#: The string keys a PE VERSIONINFO block may carry. A block is a sequence of `key\0value\0` pairs, so a
#: value is a string that is NOT in this set.
_VERSIONINFO_KEYS: tuple[str, ...] = (
    "Comments",
    "CompanyName",
    "FileDescription",
    "FileVersion",
    "InternalName",
    "LegalCopyright",
    "LegalTrademarks",
    "OriginalFilename",
    "PrivateBuild",
    "ProductName",
    "ProductVersion",
    "SpecialBuild",
)

#: Keys worth publishing. The rest is metadata noise; these four answer "what does the file call itself",
#: which is how a sample is matched to a campaign.
_VERSIONINFO_PUBLISHED_KEYS: tuple[str, ...] = (
    "OriginalFilename",
    "InternalName",
    "ProductName",
    "CompanyName",
)


def extract_versioninfo_fields(
    evidence: Iterable[Any],
) -> dict[str, str]:
    """Pair the recovered VERSIONINFO keys with their values, or return {} when it cannot be done.

    MEASURED GAP. The PE `RT_VERSION` block records `OriginalFilename ss3advd.exe`, `InternalName ss3advd`,
    `ProductName DndndnD` (a keyboard mash), `CompanyName None` and `FileVersion 1.01`. Both the keys and the
    values are already recorded as `string` Evidence rows - the parser reads the block as UTF-16LE - and the
    published body for the 白象 sample `64da3378` mentioned none of them, so the sample's own claim about its
    identity never reached the analyst. `OriginalFilename` is the one string that links that binary to the
    reference document's `http://zolipas.info/advd` path.

    Pairing uses the byte offsets the parser recorded: a key takes the nearest following string that is not
    itself a key, with its own encoding preferred, and each value is consumed once. That is deterministic
    and needs no adjacency in the tuple order. When a block is incomplete the result is short rather than
    guessed - a wrong original filename would be worse than an absent one.
    """
    entries: list[tuple[int, str, str, str]] = []

    def collect(item: Any) -> None:
        row = _evidence_mapping(item)
        if str(row.get("kind") or "").casefold() != "string":
            return
        value = row.get("value")
        text = ""
        encoding = ""
        if isinstance(value, Mapping):
            text = str(value.get("text") or "").strip()
            encoding = str(value.get("encoding") or "").casefold()
        elif isinstance(value, str):
            text = value.strip()
        if not text:
            return
        anchor = row.get("anchor")
        offset: int | None = None
        if isinstance(anchor, Mapping):
            try:
                offset = int(anchor.get("offset"))  # type: ignore[arg-type]
            except (TypeError, ValueError):
                offset = None
        if offset is None:
            # Without an offset the pair cannot be established, and guessing adjacency from iteration
            # order would invent a filename. Skip instead.
            return
        entries.append((offset, text, encoding, str(row.get("id") or "")))

    for item in evidence:
        collect(item)
    if not entries:
        return {}

    key_set = {key.casefold() for key in _VERSIONINFO_KEYS}
    entries.sort(key=lambda item: item[0])
    fields: dict[str, str] = {}
    used: set[int] = set()
    for index, (_offset, text, encoding, _ident) in enumerate(entries):
        if text.casefold() not in key_set:
            continue
        for candidate_index in range(index + 1, len(entries)):
            if candidate_index in used:
                continue
            _cand_offset, candidate, candidate_encoding, _cand_ident = entries[candidate_index]
            if candidate.casefold() in key_set:
                break  # the next key started: this one has no value in the recovered set
            if encoding == "utf-16le" and candidate_encoding and candidate_encoding != "utf-16le":
                # The block is UTF-16LE; an ASCII row at a later offset belongs to a different structure.
                continue
            used.add(candidate_index)
            fields.setdefault(text, candidate)
            break
    return fields


#: PE resource type IDs an analyst names directly.  Windows defines these in `winuser.h`; the parser
#: records the numeric id, and a numeric id is not a fact a reader can act on.
_PE_RESOURCE_TYPE_NAMES: dict[int, str] = {    1: "RT_CURSOR",
    2: "RT_BITMAP",
    3: "RT_ICON",
    4: "RT_MENU",
    5: "RT_DIALOG",
    6: "RT_STRING",
    7: "RT_FONTDIR",
    8: "RT_FONT",
    9: "RT_ACCELERATOR",
    10: "RT_RCDATA",
    11: "RT_MESSAGETABLE",
    12: "RT_GROUP_CURSOR",
    14: "RT_GROUP_ICON",
    16: "RT_VERSION",
    17: "RT_DLGINCLUDE",
    19: "RT_PLUGPLAY",
    20: "RT_VXD",
    21: "RT_ANICURSOR",
    22: "RT_ANIICON",
    23: "RT_HTML",
    24: "RT_MANIFEST",
}


def _evidence_field(item: Any, key: str, default: object = None) -> object:
    """Read a field from an Evidence row that may be an ORM object or a plain mapping."""
    if isinstance(item, Mapping):
        return item.get(key, default)
    return getattr(item, key, default)


def build_tls_callback_projection(
    evidence_by_id: Mapping[str, Any],
) -> dict[str, object] | None:
    """Surface the recovered TLS callback entries, in the order the parser recorded them.

    A TLS callback runs BEFORE the entry point, so an address there is an early-execution location - a
    first-class analyst fact and one the named benchmark records at the end of its 2.2 CRT初始化阶段.

    Measured on task `50673002`: three `tls_callback` evidence rows exist and the pipeline already treats
    them as significant enough to use as investigation join seeds (`InvestigationPlanner._tls_callback_starts`),
    but the DOCUMENT carried no row with `tls_callbacks` at all, so no renderer could reach them. The
    published section titled 线程、TLS 回调与 APC therefore printed

        APC/TLS 若只有导入而无目标线程证据，保持未证明

    - a correct boundary describing a fact the run actually had. Projecting the entries is the fix; the
    renderer then states both the addresses and the boundary.

    Order is preserved: the callback order in the TLS directory is part of the fact, so this must not
    sort. Two spellings are accepted because both occur - a typed `tls_callback` row carries `entry`,
    and the PE structure carries a `tls_callbacks` table with `entry`/`rva`.
    """
    entries: list[str] = []
    seen: set[str] = set()
    for item in evidence_by_id.values():
        kind = str(_evidence_field(item, "kind", "")).casefold()
        if kind in {"tls_callback", "tls_metadata", "thread_callback"}:
            value = _evidence_field(item, "value", {})
            value = value if isinstance(value, Mapping) else {}
            candidate = value.get("entry") or value.get("callback") or value.get("address")
            text = str(candidate or "").strip()
            if text and text.casefold() not in seen:
                seen.add(text.casefold())
                entries.append(text)
            continue
        if kind != "pe_structure":
            continue
        value = _evidence_field(item, "value", {})
        value = value if isinstance(value, Mapping) else {}
        callbacks = value.get("tls_callbacks")
        if not isinstance(callbacks, (list, tuple)):
            continue
        for callback in callbacks:
            if not isinstance(callback, Mapping):
                continue
            text = str(callback.get("entry") or callback.get("rva") or "").strip()
            if text and text.casefold() not in seen:
                seen.add(text.casefold())
                entries.append(text)
    if not entries:
        return None
    return {"type": "tls_callbacks", "entries": entries, "count": len(entries)}


def build_pe_basics_projection(
    evidence_by_id: Mapping[str, Any],
) -> dict[str, object] | None:
    """Surface recovered PE header facts without inventing CRT/loader names."""

    def read(item: Any, key: str, default: object = None) -> object:
        if isinstance(item, Mapping):
            return item.get(key, default)
        return getattr(item, key, default)

    for item in evidence_by_id.values():
        if str(read(item, "kind", "")).casefold() != "pe_structure":
            continue
        value = read(item, "value", {})
        value = value if isinstance(value, Mapping) else {}
        entry = value.get("entry_rva") or value.get("address_of_entry_point")
        if entry in (None, ""):
            continue
        imports = value.get("imports")
        import_groups = _pe_import_name_groups(imports)
        import_count = sum(len(names) for _module, names in import_groups)
        # Complete, ordered, module-attributed: the renderer prefers this so its `[:limit]` selection
        # is order-independent and always sees every module (see `_pe_import_name_groups`).
        import_entries = _pe_import_entries(import_groups)
        # Bounded, qualified, round-robined: for consumers that treat `imports` as a flat name list.
        import_names = _pe_import_symbols(import_groups)
        sections = value.get("sections")
        section_names = [
            str(item.get("name") or "").strip()
            for item in sections
            if isinstance(item, Mapping) and str(item.get("name") or "").strip()
        ] if isinstance(sections, list) else []
        return {
            "type": "pe_basics",
            "format": value.get("format"),
            "machine": value.get("machine"),
            "entry_rva": entry,
            "image_base": value.get("image_base"),
            "subsystem": value.get("subsystem"),
            "section_names": section_names[:16],
            "import_count": import_count,
            "import_name_total": import_count,
            "import_entries": import_entries,
            "imports": import_names,
            "import_cap": _PE_IMPORT_NAME_CAP,
            "imports_truncated": import_count > len(import_names),
            "exports": list(value.get("exports") or [])[:16] if isinstance(value.get("exports"), list) else [],
            "pdb_path": value.get("pdb_path"),
        }
    return None


#: APIs whose return value is an environment reading the sample may gate on.
_ENVIRONMENT_PROBE_APIS = (
    "gettickcount64",
    "gettickcount",
    "globalmemorystatusex",
    "globalmemorystatus",
    "getsysteminfo",
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "getsystemtimes",
)


def _threshold_like_constant(token: object, *, minimum: int = 0x1000) -> bool:
    """True when an immediate is large enough to be a gate threshold.

    The environment guard compares against ``0x493e1`` (300001 ms of uptime) and
    ``0x60000000`` (1.5 GiB).  Small immediates in the same function are counts,
    sizes and mode bits (``0x1``, ``0x100``, ``0x3f``), and presenting one of those
    as "the recovered threshold" would be a fabricated claim.  Kept local rather
    than imported from ``analyst_report`` so the report layer does not depend on
    the renderer.
    """
    text = str(token or "").strip()
    if not text.casefold().startswith("0x"):
        return False
    try:
        return int(text, 16) >= minimum
    except ValueError:
        return False


def build_environment_gate_projection(
    evidence_by_id: Mapping[str, Any],
) -> dict[str, object]:
    """Project the recovered environment-probe comparisons and their constants.

    Why this exists: the sample compares ``GetTickCount64`` against ``0x493e1``
    (300001 ms) and ``MEMORYSTATUS.dwTotalPhys`` against ``0x60000000`` (1.5 GiB)
    before doing anything else, and both comparisons ARE recovered.  But
    ``ordered_static_call_flow`` carries only formatted *call* sequences
    (``_format_semantic_call``), so a ``CMP`` never reaches a document field, no
    chapter can cite it, and the report has to print ``UNKNOWN(threshold)`` while
    the constant sits in the evidence.

    Key correction: an ``abstract_execution_trace`` step has keys ``api,
    confidence, index, inputs, operation, outputs, path_condition, source_anchor``
    - there is deliberately NO ``text`` key.  The recovered comparison lives in
    ``step["path_condition"]`` (e.g. ``"RAX cmp 0X100"``), and the memory gate's
    ``CMP qword ptr [RSI + 0x8],0x60000000`` additionally appears as a raw
    instruction string on ``function_instruction_window`` rows.  An earlier
    version of this projection read ``step["text"]``, found nothing, and reported
    ``present: false`` - dead code that would have looked like a working fix.

    This is a projection, not a new join: it copies the recovered comparison and
    its immediate verbatim and never synthesises a threshold.
    """
    comparisons: list[dict[str, object]] = []
    seen: set[str] = set()

    def record(text: str, *, function: str = "", entry: str = "") -> None:
        stripped = text.strip()
        if not stripped or stripped in seen:
            return
        # ``path_condition`` also carries non-comparison entries such as
        # "branch at instruction 12 unresolved"; only real comparisons count.
        if not re.match(r"(?i)^\S+\s+(cmp|test)\b", stripped):
            return
        # Only a comparison against an IMMEDIATE carries a gate threshold.  A
        # memory operand such as ``RAX cmp QWORD PTR [RBX + 0X10]`` is an address
        # offset, and treating it as a threshold would present 0x10 as one.
        immediate = ""
        parts = [part.strip() for part in stripped.split(",")]
        if len(parts) >= 2 and re.fullmatch(r"(?i)0x[0-9a-f]+", parts[-1]):
            immediate = parts[-1]
        elif re.fullmatch(r"(?i)\S+\s+cmp\s+0x[0-9a-f]+", stripped):
            immediate = stripped.rsplit(None, 1)[-1]
        if not immediate or not _threshold_like_constant(immediate, minimum=0x10000):
            return
        seen.add(stripped)
        comparisons.append(
            {
                "text": stripped,
                "constant": immediate,
                "function": function,
                "entry": entry,
            }
        )

    # A *gate* is a comparison whose left operand holds the return value of an
    # environment probe.  The abstract trace records calls in ``step["api"]`` and
    # uses the ABI return register, so the probe's result can be followed to the
    # compare that consumes it.  Without this, the projection listed every large
    # immediate compared anywhere in the function (0X110000, 0X10F800, error
    # codes) and calling those "thresholds" would be a fabricated claim.
    _RETURN_REGISTER = {"rax", "eax", "ax", "al"}
    probe_results: list[int] = []  # step indexes where a probe call returned

    def collect_probe_results(steps: object) -> None:
        if not isinstance(steps, (list, tuple)):
            return
        for step in steps:
            if not isinstance(step, Mapping):
                continue
            api = str(step.get("api") or "").casefold()
            if any(token in api for token in _ENVIRONMENT_PROBE_APIS):
                index = step.get("index")
                if isinstance(index, int):
                    probe_results.append(index)

    def is_probe_gated(stripped: str, steps: object, position: int) -> bool:
        """True when this comparison follows a probe call in the same trace."""
        if not probe_results:
            return False
        # The compare must consume the ABI return register and come after a probe.
        head = stripped.split(None, 1)[0].casefold()
        if head not in _RETURN_REGISTER:
            return False
        return any(index < position for index in probe_results)

    for item in evidence_by_id.values():
        if len(comparisons) >= 32:
            break
        row = _evidence_mapping(item)
        kind = str(row.get("kind") or "")
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        if not isinstance(value, Mapping):
            continue
        if kind == "abstract_execution_trace":
            function = str(value.get("function") or "")
            entry = str(value.get("entry") or "")
            steps = value.get("steps")
            if isinstance(steps, (list, tuple)):
                probe_results.clear()
                collect_probe_results(steps)
                for position, step in enumerate(steps):
                    if not isinstance(step, Mapping):
                        continue
                    condition = step.get("path_condition")
                    if not isinstance(condition, str):
                        continue
                    if not is_probe_gated(condition, steps, position):
                        continue
                    record(condition, function=function, entry=entry)
        elif kind == "function_instruction_window":
            function = str(value.get("name") or value.get("function") or "")
            entry = str(value.get("entry") or "")
            instructions = value.get("instructions")
            if isinstance(instructions, (list, tuple)):
                for instruction in instructions:
                    if not isinstance(instruction, Mapping):
                        continue
                    text = instruction.get("text")
                    if isinstance(text, str) and re.match(r"(?i)^(CMP|TEST)\b", text.strip()):
                        record(text, function=function, entry=entry)

    constants = [
        token
        for token in dict.fromkeys(
            str(item["constant"]) for item in comparisons if item.get("constant")
        )
        if _threshold_like_constant(token)
    ]
    return {
        "type": "environment_gate",
        "present": bool(comparisons),
        "comparisons": comparisons,
        "constants": constants,
        "runtime_effect_proven": False,
    }


def build_ordered_static_call_flow(
    evidence_by_id: Mapping[str, Any],
) -> list[dict[str, object]]:
    """Project recovered decompile call sequences as an ordered static 时序."""
    steps: list[dict[str, object]] = []
    seen: set[str] = set()
    for item in evidence_by_id.values():
        row = _evidence_mapping(item)
        kind = str(row.get("kind") or "")
        if kind not in {"function_semantic_summary", "decompile_slice"}:
            continue
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        if not isinstance(value, Mapping):
            continue
        calls = value.get("call_sequence")
        if not isinstance(calls, (list, tuple)) or not calls:
            continue
        meaningful, _ = _meaningful_semantic_calls(list(calls))
        formatted = [item for item in (_format_semantic_call(call) for call in meaningful[:16]) if item]
        if not formatted:
            continue
        function = value.get("function")
        if isinstance(function, Mapping):
            function = function.get("name")
        entry = str(value.get("function_entry") or value.get("entry") or "")
        identity = f"{function or ''}@{entry}".casefold()
        if identity in seen:
            continue
        seen.add(identity)
        how = _how_from_semantic_payload(value)
        formatted, how = _with_decoded_crypto_algids(
            formatted,
            how,
            _recovered_crypto_algids(evidence_by_id, function_entry=entry, payload=value),
        )
        steps.append(
            {
                "function": function,
                "function_entry": entry,
                "how": how,
                "calls": formatted,
                "consumers": list(value.get("consumers") or [])[:8],
                "unknowns": list(value.get("unknowns") or [])[:8],
                "evidence_id": str(row.get("id") or ""),
            }
        )
    def _flow_priority(item: Mapping[str, object]) -> tuple[int, str]:
        blob = " ".join(
            [
                str(item.get("how") or ""),
                " ".join(str(call) for call in (item.get("calls") or [])),
            ]
        ).casefold()
        score = 0
        for token, weight in (
            ("createprocess", 20),
            ("creation_flags", 16),
            ("cmd.exe", 16),
            ("updateprocthreadattribute", 14),
            ("crypt", 12),
            ("calg_", 12),
            ("lpstartaddress", 12),
            ("rc4", 10),
            ("createthread", 8),
            ("xor", 6),
            ("loadlibrary", 6),
            ("virtualprotect", 5),
            ("virtualalloc", 4),
            ("getprocaddress", 3),
        ):
            if token in blob:
                score += weight
        return (-score, str(item.get("function_entry") or ""))

    _overlay_persist_how_on_ordered_flow(steps, evidence_by_id)
    steps.sort(key=_flow_priority)
    return steps[:24]


def _ordered_flow_step_keys(step: Mapping[str, object]) -> list[str]:
    return _address_lookup_keys(step.get("function_entry"), step.get("function"))


def _merge_persist_how_call(
    steps: list[dict[str, object]],
    by_key: dict[str, dict[str, object]],
    *,
    entry: str,
    call: str,
    how: str,
    evidence_id: str,
) -> None:
    """Kunglao leftover remainder: persist HOW must appear in the ordered 时序."""
    call_text = str(call or "").strip()
    how_text = str(how or call_text).strip()
    if not call_text:
        return
    step = None
    for key in _address_lookup_keys(entry):
        step = by_key.get(key.casefold())
        if step is not None:
            break
    if step is None:
        step = {
            "function": entry,
            "function_entry": entry,
            "how": how_text,
            "calls": [call_text],
            "consumers": [],
            "unknowns": [],
            "evidence_id": evidence_id,
        }
        steps.append(step)
        for key in _ordered_flow_step_keys(step):
            by_key.setdefault(key.casefold(), step)
        return
    calls = [str(item) for item in (step.get("calls") or []) if str(item).strip()]
    if not any(call_text.casefold() in item.casefold() for item in calls):
        step["calls"] = [call_text, *calls][:16]
    current_how = str(step.get("how") or "")
    if how_text and how_text.casefold() not in current_how.casefold():
        step["how"] = f"{current_how}; {how_text}" if current_how else how_text
    if evidence_id and not step.get("evidence_id"):
        step["evidence_id"] = evidence_id


def _overlay_persist_how_on_ordered_flow(
    steps: list[dict[str, object]],
    evidence_by_id: Mapping[str, Any],
) -> None:
    """Join persist traces onto decompile 时序. Prologue windows are not HOW."""
    by_key: dict[str, dict[str, object]] = {}
    for step in steps:
        for key in _ordered_flow_step_keys(step):
            by_key.setdefault(key.casefold(), step)
    for item in evidence_by_id.values():
        row = _evidence_mapping(item)
        kind = str(row.get("kind") or "")
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        if not isinstance(value, Mapping):
            continue
        anchor = row.get("anchor") if isinstance(row.get("anchor"), Mapping) else {}
        entry = str(
            value.get("function_entry")
            or anchor.get("function_entry")
            or value.get("entry")
            or ""
        )
        evidence_id = str(row.get("id") or "")
        if not entry.strip():
            continue
        if kind == "api_argument_trace":
            api = str(value.get("api") or "CreateProcess")
            command = str(value.get("command") or value.get("command_line") or "").strip()
            flags = str(value.get("creation_flags") or value.get("flags") or "").strip()
            if is_specialist_ppid_creation_flag(flags) and not command:
                flags = ""
            if command or flags:
                parts = [api]
                if command:
                    parts.append(f"command={command}")
                if flags:
                    parts.append(f"creation_flags={flags}")
                call = " ".join(parts)
                _merge_persist_how_call(
                    steps,
                    by_key,
                    entry=entry,
                    call=call,
                    how=call,
                    evidence_id=evidence_id,
                )
            start = recovered_thread_start_address(value)
            if start:
                call = f"{api} lpStartAddress={start}"
                _merge_persist_how_call(
                    steps,
                    by_key,
                    entry=entry,
                    call=call,
                    how=call,
                    evidence_id=evidence_id,
                )
        elif kind == "resolved_api":
            api_name = str(value.get("api_name") or value.get("api_identity") or "").strip()
            consumer = str(value.get("consumer") or value.get("consumer_callsite") or "").strip()
            if api_name and consumer:
                call = f"{api_name} consumer={consumer}"
                _merge_persist_how_call(
                    steps,
                    by_key,
                    entry=entry,
                    call=call,
                    how=call,
                    evidence_id=evidence_id,
                )


def build_module_deep_dives(
    steps: Iterable[Mapping[str, object]] | None = None,
) -> list[dict[str, object]]:
    """Group recovered function HOW into gold-like module chapters."""
    grouped: dict[str, list[dict[str, object]]] = {}
    for step in steps or ():
        if not isinstance(step, Mapping):
            continue
        calls = [str(item) for item in (step.get("calls") or []) if str(item).strip()]
        categories = [
            semantic_category(call.split("(", 1)[0]) or "other"
            for call in calls
        ]
        category = max(set(categories), key=categories.count) if categories else "other"
        grouped.setdefault(category, []).append(dict(step))
    return [
        {"type": "module_deep_dive", "category": category, "steps": items[:8]}
        for category, items in grouped.items()
        if items
    ]


def build_emulation_status_projection(
    evidence_by_id: Mapping[str, Any],
) -> dict[str, object]:
    """Always expose whether isolated emulation was attempted and why."""
    results: list[dict[str, object]] = []
    for item in evidence_by_id.values():
        row = _evidence_mapping(item)
        if str(row.get("kind") or "") != "simulation_result":
            continue
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        anchor = row.get("anchor") if isinstance(row.get("anchor"), Mapping) else {}
        # Aggregate what the simulator OBSERVED, not just why it stopped.
        #
        # MEASURED gap this closes: the projection carried only `status`/`stop_reason`/`limitations`, so a
        # run that observed **256 API calls** and made **1,031 modelled VB6 runtime calls** rendered as a
        # bare failure. The counts are aggregated here rather than copied, because the raw list holds 259
        # entries and copying it would inflate the document without adding information - what a reader
        # needs is which APIs were touched and how often.
        observations = value.get("observations") if isinstance(value.get("observations"), list) else []
        api_counts: dict[str, int] = {}
        shim_summary: dict[str, object] = {}
        # The runtime calls the run could NOT make because the emulator does not model them.
        #
        # MEASURED why this is aggregated here (plan T2): the producer records these as
        # `{"event": "unsupported_api", "name": ...}` observations, and this projection is a WHITELIST - a
        # field it does not carry never reaches the chapter. Without this the published body could not name
        # what blocked a run from the structured record, and the only route left was the prose `limitation`,
        # which a consumer would have to parse. Order is preserved (first-failure first) because the FIRST
        # unmodelled dependency is the one that bounded the run.
        unsupported_apis: list[str] = []
        # What the adapter's own bounds removed, carried so the chapter can say the list is bounded. MEASURED:
        # 102 evidence rows over 34 tasks hold exactly 256 api names and none holds 257, so the cap saturates
        # and the body published "已观测 API 调用：256 次" as though it were a total.
        api_truncation: dict[str, object] | None = None
        for observation in observations:
            if not isinstance(observation, Mapping):
                continue
            event = str(observation.get("event") or "")
            if event == "api_truncated":
                # This dict is a WHITELIST like every other branch here, so each field is named explicitly
                # rather than forwarded wholesale.
                api_truncation = {
                    "kept": observation.get("kept"),
                    "dropped": observation.get("dropped"),
                    "entry_points_dropped": observation.get("entry_points_dropped"),
                    "api_cap": observation.get("api_cap"),
                    "entry_point_cap": observation.get("entry_point_cap"),
                }
            elif event == "api":
                name = str(observation.get("name") or "").strip()
                # A Ghidra placeholder (`FUN_0040d2c0`) is a ledger identifier, not an API name. The
                # primary body is gated against ledger jargon, and publishing these counts forwarded such
                # a name into the published revision - which failed the run with
                # "primary report contains FUN_ ledger names". Filtered at the projection so a count can
                # never carry a ledger name into the body.
                if name and "FUN_" not in name.upper():
                    api_counts[name] = api_counts.get(name, 0) + 1
            elif event == "unsupported_api":
                # Same ledger-name filter as the counts above, for the same measured reason: this value is
                # printed in the primary body, and a `FUN_` name there fails the run.
                stalled = str(observation.get("name") or "").strip()
                if stalled and "FUN_" not in stalled.upper() and stalled not in unsupported_apis:
                    unsupported_apis.append(stalled)
            elif event == "vb6_shim":
                shim_summary = {
                    "registered": observation.get("registered"),
                    "modelled_calls": observation.get("modelled_calls"),
                    "strings_observed": observation.get("strings_observed"),
                    # The second, independent representation: records read through the EXECUTION path,
                    # decoded. Publishing it lets the report show the static scan and the execution-driven
                    # read agreeing, which is the cross-check the objective asks for.
                    "distinct_records": observation.get("distinct_records"),
                    "decoded_chars": observation.get("decoded_chars"),
                    "decoded_preview": observation.get("decoded_preview"),
                    # C1/C2 - hop 2 of 3. This dict is a WHITELIST: a field carried by the `vb6_shim`
                    # observation but not named here is dropped before the renderer can see it, so a field
                    # added only upstream still cannot reach the published body. MEASURED: the shim's
                    # `destination_observable` flag and its `argument_pairs` were absent from all three
                    # hops, and the run reported a shim that "never ran" while modelling 1,031 calls.
                    "destination_observable": observation.get("destination_observable"),
                    "sample_strings_cap": observation.get("sample_strings_cap"),
                    "argument_pairs": observation.get("argument_pairs") or [],
                    "argument_pairs_cap": observation.get("argument_pairs_cap"),
                    "argument_pairs_recorded": observation.get("argument_pairs_recorded"),
                }
        results.append(
            {
                "status": str(value.get("status") or "UNKNOWN"),
                "simulator": value.get("simulator"),
                "stop_reason": value.get("stop_reason") or value.get("deferred"),
                "function_entry": value.get("function_entry") or anchor.get("function_entry"),
                "limitations": list(value.get("limitations") or [])[:6],
                "evidence_id": str(row.get("id") or ""),
                "observation_count": len(observations),
                "observed_apis": dict(
                    sorted(api_counts.items(), key=lambda pair: (-pair[1], pair[0]))[:12]
                ),
                "shim": shim_summary,
                # The dependency that bounded the run, for the chapter to NAME rather than leaving a reader
                # to parse the prose limitation (plan T2).
                "unsupported_apis": unsupported_apis,
                # Whitelisted like everything else here: without this key the chapter cannot know the api list
                # was bounded, and a bounded list published as a total is the defect this carries.
                "api_truncation": api_truncation,
            }
        )
    if results:
        placeholders = _EMU_PLACEHOLDER_STATUSES
        real_simulators = {
            str(item.get("simulator") or "").casefold()
            for item in results
            if str(item.get("status") or "").upper() not in placeholders
        }
        if real_simulators:
            results = [
                item
                for item in results
                if str(item.get("status") or "").upper() not in placeholders
            ]
        results = [
            item
            for item in results
            if str(item.get("status") or "").upper() != "SUPERSEDED_BY_WORKER"
        ]
        statuses = {str(item.get("status") or "").upper() for item in results}
        real = {item for item in statuses if item not in placeholders}
        if "SUCCEEDED" in real:
            overall = "SUCCEEDED"
        elif "FAILED" in real:
            overall = "FAILED"
        elif "UNSUPPORTED" in real:
            overall = "UNSUPPORTED"
        elif "DISABLED_BY_POLICY" in real or "DISABLED_BY_POLICY" in statuses:
            overall = "DISABLED_BY_POLICY"
        elif "DEFERRED_TO_WORKER" in statuses:
            overall = "DEFERRED_TO_WORKER"
        elif real:
            overall = next(iter(real))
        else:
            overall = next(iter(statuses), "UNKNOWN")
        next_step = (
            "Review isolated emulator output as static evidence; stubbed APIs are not recovered plaintext, and this is not a sandbox run."
            if overall == "SUCCEEDED"
            else "Isolated emu-worker will emulate granted windows as static analysis; this is not host or sandbox execution."
            if overall == "DEFERRED_TO_WORKER"
            else "Enable SIMULATION_PROFILE=static-first-controlled-emulation in Docker so emu-worker can run granted bytes as static analysis."
            if overall == "DISABLED_BY_POLICY"
            else "Recorded emulator limitation; continue static recovery of start routines and decode windows. Emulator failure remains static analysis, not a sandbox/dynamic run."
        )
        return {
            "type": "emulation_status",
            "overall": overall,
            "attempted": True,
            "results": results[:12],
            "next_step": next_step,
        }
    return {
        "type": "emulation_status",
        "overall": "NOT_ATTEMPTED",
        "attempted": False,
        "results": [],
        "next_step": (
            "Isolated CONTROLLED_EMULATE runs after static recovery stalls; "
            "the reconstructed static sequence below is still the authority for HOW."
        ),
    }


def _input_partition_fact(request: Mapping[str, object] | None) -> dict[str, object] | None:
    """ADR-0006's input partition as a STRUCTURED Document fact, or `None` when the snapshot does not state it.

    Producer half of P-1.1's contract: `analyst_report._input_partition_lines` prints this fact and nothing else,
    so the official body can say which channels the analysis read and which channel was deliberately NOT an input
    (ADR-0006 / FR-18: the benchmark report never enters the analysis, prompt, knowledge snapshot, RAG or agent
    context).

    Returns `None` rather than an empty structure when the frozen request does not carry all four channels: a
    document assembled from a stub request must not gain a claim about inputs it never had. That is also the half
    that keeps "no limitation" from being rendered as a limitation.
    """
    if not isinstance(request, Mapping):
        return None
    if not all(key in request for key, _label, _status in INPUT_CHANNEL_LABELS):
        return None
    return {
        "analysis_channels": [
            {"channel": label, "status": status} for _key, label, status in INPUT_CHANNEL_LABELS
        ],
        "excluded_channels": [
            {"channel": EXCLUDED_INPUT_CHANNEL, "used_by_analysis": False}
        ],
        "statement": INPUT_PARTITION_STATEMENT,
        # Provenance: a reader can re-derive the fact from the frozen request instead of trusting the sentence.
        "source": "task.request_snapshot",
    }


def build_report_document(
    *,
    case: Any,
    task: Any,
    artifacts: list[Any],
    tool_runs: list[Any],
    evidence: list[Any],
    claims: list[Any],
    claim_evidence: list[Any],
    relations: list[Any],
    gates: list[Any],
    model_calls: list[Any] | None = None,
    investigation_threads: list[Any] | None = None,
    investigation_hypotheses: list[Any] | None = None,
    investigation_actions: list[Any] | None = None,
    analysis_turn_results: list[Any] | None = None,
    mechanisms: list[Any] | None = None,
    selected_modules: list[str],
) -> dict[str, object]:
    model_calls = model_calls or []
    investigation_threads = investigation_threads or []
    investigation_hypotheses = investigation_hypotheses or []
    investigation_actions = investigation_actions or []
    # Post-action Turn results are exposed through the task/trace APIs.  Keep
    # the report builder forward-compatible without duplicating the audit
    # ledger in every report module.
    analysis_turn_results = analysis_turn_results or []
    evidence_by_id = {item.id: item for item in evidence}
    links_by_claim: dict[str, list[str]] = {}
    for link in claim_evidence:
        if link.stance == "SUPPORTS":
            links_by_claim.setdefault(link.claim_id, []).append(link.evidence_id)

    module_claims: dict[str, list[Any]] = {}
    for claim in claims:
        module_claims.setdefault(claim.module, []).append(claim)
    module_evidence: dict[str, list[Any]] = {}
    for item in evidence:
        module_evidence.setdefault(item.module, []).append(item)

    successful_model_calls = [item for item in model_calls if item.status == "SUCCEEDED"]
    model_claims = [item for item in claims if getattr(item, "model_call_id", None)]
    mechanism_projections = build_mechanism_projections(claims, links_by_claim, evidence_by_id)
    # Specialist static links are first-class Evidence and may be produced
    # before a Claim is accepted.  Keep them in the analyst-facing report as
    # candidate mechanism rows; only the verifier-backed ``mechanisms`` input
    # can produce a formal security finding below.  Put these links first so
    # the bounded report view cannot hide the useful semantic paths behind a
    # large number of generic function candidates.
    static_link_projections = build_static_link_mechanism_projections(evidence_by_id)
    observed_projections = build_observed_mechanism_projections(evidence_by_id)
    decode_result_projections = build_decode_result_projections(evidence_by_id)
    # Observation rows are the most specific static signal available to the
    # analyst.  Put them ahead of correlated links and generic Claims so the
    # bounded report preserves function/RVA and concrete API/data paths.
    mechanism_projections = observed_projections + static_link_projections + [
        item
        for item in mechanism_projections
        if item.get("type") != "mechanism_link"
    ]
    behavior_findings = build_behavior_findings(
        claims=claims,
        mechanisms=mechanisms,
        mechanism_projections=mechanism_projections,
        links_by_claim=links_by_claim,
        claim_evidence=claim_evidence,
        evidence_by_id=evidence_by_id,
        investigation_threads=investigation_threads,
    )
    static_analysis_plan = _extract_static_analysis_plan(getattr(task, "strategy_snapshot", None))
    packer_latch = _static_plan_packer_latch(
        static_analysis_plan, behavior_findings, evidence_by_id
    )
    if packer_latch:
        behavior_findings = [
            dict(row, finding_status="CANDIDATE", status="CANDIDATE", verdict="CANDIDATE")
            if _row_is_stub_iat_capability(row)
            and str(row.get("status") or row.get("finding_status") or "").upper()
            in {"VERIFIED", "SUPPORTED", "CONFIRMED"}
            else row
            for row in behavior_findings
        ]
    behavior_relations = build_behavior_relations(
        relations,
        behavior_findings,
        evidence_by_id=evidence_by_id,
        links_by_claim=links_by_claim,
        claim_evidence=claim_evidence,
        artifacts=artifacts,
    )
    finding_by_id = {
        str(item.get("finding_id") or item.get("id")): item
        for item in behavior_findings
        if item.get("finding_id") or item.get("id")
    }
    for relation in behavior_relations:
        for finding_id in (
            relation.get("source_finding_id"), relation.get("target_finding_id")
        ):
            if finding_id in finding_by_id:
                relation_ids = finding_by_id[finding_id].setdefault("relation_ids", [])
                if relation.get("relation_id") not in relation_ids:
                    relation_ids.append(relation.get("relation_id"))
    assessment_summary, assessment_rows = _build_assessment(
        task=task,
        artifacts=artifacts,
        claims=claims,
        links_by_claim=links_by_claim,
        evidence_by_id=evidence_by_id,
        model_calls=model_calls,
        mechanisms=mechanisms,
        mechanism_projections=mechanism_projections,
        behavior_findings=behavior_findings,
    )
    investigation_timeline = _build_investigation_timeline(
        claims=claims,
        evidence=evidence,
        relations=relations,
        task=task,
        links_by_claim=links_by_claim,
    )
    investigation_timeline.extend(
        {
            "phase": "PERSISTED_INVESTIGATION",
            "thread_id": getattr(item, "id", None),
            "state": getattr(item, "state", None),
            "question": getattr(item, "question", None),
            "evidence_ids": list(getattr(item, "evidence_ids", []) or []),
            "action_ids": list(getattr(item, "action_ids", []) or []),
        }
        for item in investigation_threads
    )
    investigation_timeline.extend(
        {
            "phase": "HYPOTHESIS_STATUS",
            "hypothesis_id": getattr(item, "id", None),
            "thread_id": getattr(item, "thread_id", None),
            "status": getattr(item, "status", None),
            "confidence": getattr(item, "confidence", None),
            "evidence_ids": list(getattr(item, "evidence_ids", []) or []),
        }
        for item in investigation_hypotheses
    )
    investigation_timeline.extend(
        {
            "phase": "ACTION_STATUS",
            "action_id": getattr(item, "id", None),
            "action_type": getattr(item, "action_type", None),
            "reason": getattr(item, "reason", None),
            "analysis_plan": (
                (getattr(item, "parameters", {}) or {}).get("_analysis_plan", {})
                if isinstance(getattr(item, "parameters", {}), Mapping)
                else {}
            ),
            "status": getattr(item, "status", None),
            "result_evidence_ids": list(getattr(item, "result_evidence_ids", []) or []),
        }
        for item in investigation_actions
    )

    # Quality is computed from the same immutable report inputs that produce
    # the visible modules.  It is a readiness signal, not a claim promotion
    # mechanism: candidates remain candidates and static-only boundaries stay
    # explicit.
    quality = deep_analysis_metrics(
        document={"modules": []},
        mechanisms=[
            item if isinstance(item, Mapping) else {
                key: getattr(item, key) for key in (
                    "id", "claim_id", "status", "target", "inputs",
                    "transformation_or_control", "conditions", "outputs",
                    "consumers", "side_effects", "evidence_ids", "verifier",
                ) if hasattr(item, key)
            }
            for item in (mechanisms or [])
        ],
        mechanism_projections=mechanism_projections,
        investigation_threads=[
            item if isinstance(item, Mapping) else {
                "id": getattr(item, "id", ""),
                "state": getattr(item, "state", ""),
                "question": getattr(item, "question", ""),
                "action_ids": list(getattr(item, "action_ids", []) or []),
                "evidence_ids": list(getattr(item, "evidence_ids", []) or []),
                "protocol": getattr(item, "protocol", None) if hasattr(item, "protocol") else (
                    item.get("protocol") if isinstance(item, Mapping) else None
                ),
                "s_ladder": getattr(item, "s_ladder", None) if hasattr(item, "s_ladder") else (
                    item.get("s_ladder") if isinstance(item, Mapping) else None
                ),
            }
            for item in investigation_threads
        ],
        investigation_actions=[
            item if isinstance(item, Mapping) else {
                "id": getattr(item, "id", ""),
                "status": getattr(item, "status", ""),
                "origin": (
                    (getattr(item, "parameters", {}) or {}).get("origin")
                    or (
                        "model"
                        if (getattr(item, "parameters", {}) or {}).get("_planner_turn_id")
                        else "deterministic_fallback"
                    )
                ),
                "scheduler": (getattr(item, "parameters", {}) or {}).get("scheduler"),
                "planner_turn_id": (getattr(item, "parameters", {}) or {}).get("_planner_turn_id"),
                "result_evidence_ids": getattr(item, "result_evidence_ids", []),
            }
            for item in investigation_actions
        ],
    )

    all_modules: dict[str, dict[str, object]] = {}
    all_modules["executive_summary"] = _module(
        "executive_summary",
        (
            f"任务以 {task.lifecycle} 收尾，分析完整度为 {task.outcome or '未计算'}。"
            f"共登记 {len(artifacts)} 个 Artifact、{len(evidence)} 条 Evidence、"
            f"{len(claims)} 条 Claim 和 {len(relations)} 条 Relation。"
        ),
        [
            {
                "type": "analyst_assessment",
                "summary": assessment_summary,
                "findings": assessment_rows,
            },
            build_catalog_behavior_matrix(
                behavior_findings,
                evidence_by_id=evidence_by_id,
                static_analysis_plan=static_analysis_plan,
            ),
            *([_project_static_analysis_plan_row(static_analysis_plan)] if _project_static_analysis_plan_row(static_analysis_plan) else []),
            {
                "type": "unique_execution_threads",
                "threads": build_unique_execution_threads(evidence_by_id),
            },
            {
                "type": "pe_basics",
                **(build_pe_basics_projection(evidence_by_id) or {"present": False}),
            },
            {
                "type": "pe_resources",
                **(build_pe_resource_projection(evidence_by_id) or {"present": False}),
            },
            # What the file's own VERSIONINFO block claims about it. Reaches the analyst as the sample's
            # CLAIM, because a version block is written by whoever built the file.
            #
            # `evidence` is a LIST here, not a mapping: this builder receives `evidence: list[Any]` while
            # other projections take `evidence_by_id`. Calling `.values()` on it raised AttributeError and
            # failed 115 tests at once - the whole document build, not just this row.
            {
                "type": "pe_version_info",
                "fields": extract_versioninfo_fields(evidence),
                "boundary": "版本信息块由构建者写入，可伪造；这是样本自述，不是已核实的来源。",
            },
            # A TLS callback runs before the entry point; the pipeline already uses these rows as join
            # seeds, and this is what makes them reachable from the published body.
            build_tls_callback_projection(evidence_by_id) or {"type": "tls_callbacks", "entries": []},
            {
                "type": "ordered_static_call_flow",
                "steps": build_ordered_static_call_flow(evidence_by_id),
            },
            build_environment_gate_projection(evidence_by_id),
            build_registry_key_projection(evidence_by_id),
            {
                "type": "module_deep_dives",
                "modules": build_module_deep_dives(build_ordered_static_call_flow(evidence_by_id)),
            },
            build_emulation_status_projection(evidence_by_id),
            {
                "type": "runtime_sequence",
                "phases": build_runtime_sequence(
                    behavior_findings,
                    unique_threads=build_unique_execution_threads(evidence_by_id),
                    decoded_configs=build_decode_result_projections(evidence_by_id),
                    process_flags=build_process_flag_projections(evidence_by_id),
                    pe_entry=build_pe_entry_projection(evidence_by_id),
        instruction_windows=instruction_windows_from_evidence(evidence_by_id),
                ),
            },
            {
                "case_id": case.id,
                "task_id": task.id,
                "target_granularity": f"{task.target_breadth} x {task.target_depth}",
                "actual_granularity": task.actual_granularity,
                "analysis_class": getattr(task, "analysis_class", None),
                "analysis_coverage": getattr(task, "coverage", {}) or {},
                "report_status": "DRAFT",
            },
            {
                "type": "report_structure",
                "version": "3.0",
                "sections": [
                    "Executive Assessment", "Artifact Summary", "Key Static Findings",
                    "Verified Mechanisms", "Reconstructed Static Behavior Flow",
                    "IOC / Indicators", "Detection / Hunting Opportunities",
                    "ATT&CK Reference", "Unknowns / Static Boundaries", "Analysis Coverage",
                ],
            },
            {
                "type": "model_analysis_provenance",
                "successful_calls": len(successful_model_calls),
                "model_claims": len(model_claims),
                "calls": [
                    {
                        "model_call_id": item.id,
                        "module": item.module,
                        "provider": item.provider,
                        "model": item.model,
                        "status": item.status,
                        "error_type": item.error_type,
                        "latency_ms": item.latency_ms,
                    }
                    for item in model_calls
                ],
            },
            {
                "type": "investigation_timeline",
                "private_chain_of_thought": False,
                "events": investigation_timeline,
                "explanation": "Only structured questions, actions, evidence links, state transitions, and verification outcomes are exposed.",
            },
            {
                "type": "analysis_quality",
                **quality,
            },
        ],
    )
    request = task.request_snapshot
    # ONE channel table (`INPUT_CHANNEL_LABELS`) feeds both this module and the `input_partition` Document fact
    # below, so the ledger projection and the OFFICIAL body cannot state two different input policies.
    all_modules["input_manifest"] = _module(
        "input_manifest",
        f"四类输入保持分区；{EXCLUDED_INPUT_CHANNEL}不属于任何分析输入通道。",
        [
            {
                "channel": label,
                "status": status,
                "source": request.get(key, {}),
            }
            for key, label, status in INPUT_CHANNEL_LABELS
        ]
        + [
            # MEASURED (`.scratch/ghidra-c3/preflight/p11-probe-facts.json`): this row reached the stored Report
            # Document and stopped there. `render_ledger_markdown` printed it; the official body did not.
            {
                "channel": EXCLUDED_INPUT_CHANNEL,
                "status": "not_present",
                "source": {"used_by_analysis": False},
            },
        ],
    )
    all_modules["artifact_inventory"] = _module(
        "artifact_inventory",
        "相同内容可共享 Content Blob，但每次出现均保留独立 Artifact 与来源路径。",
        [
            {
                "artifact_id": item.id,
                "path": item.logical_path,
                "sha256": item.content_sha256,
                "type": item.detected_type,
                "role": item.role,
                "obligation": item.obligation,
                "parent_artifact_id": item.parent_artifact_id,
            }
            for item in artifacts
        ],
    )
    all_modules["static_triage"] = _module(
        "static_triage",
        "文件身份、格式、PE 结构和静态元数据来自确定性工具输出。",
        _summarize_evidence_rows(
            [
                {
                    "evidence_id": item.id,
                    "artifact_id": item.artifact_id,
                    "kind": item.kind,
                    "value": item.value,
                    "anchor": item.anchor,
                }
                for item in module_evidence.get("static_triage", [])
            ]
        ),
    )
    all_modules["static_triage"]["rows"].extend(
        {
            "type": "analytical_claim",
            "claim_id": item.id,
            "analysis_source": (
                "model" if getattr(item, "model_call_id", None) else "deterministic_static_rules"
            ),
            "model_call_id": getattr(item, "model_call_id", None),
            "statement": item.statement,
            "subject": item.subject,
            "action": item.action,
            "object": item.object,
            "mechanism": item.mechanism,
            "condition": item.condition,
            "status": item.status,
            "confidence": item.confidence,
            "evidence_ids": links_by_claim.get(item.id, []),
        }
        for item in module_claims.get("static_triage", [])
    )
    # Promote the bounded function semantic projections ahead of the raw
    # evidence groups.  These rows are the analyst-facing explanation layer:
    # ordered static calls and arguments are visible, while execution and
    # branch outcomes remain explicitly unobserved.
    for item in [
        row for row in module_evidence.get("static_triage", [])
        if row.kind == "function_semantic_summary" and isinstance(row.value, dict)
    ][:64]:
        value = item.value
        all_modules["static_triage"]["rows"].append({
            "type": "function_semantic_summary",
            "evidence_id": item.id,
            "artifact_id": item.artifact_id,
            "function": value.get("function"),
            "function_entry": value.get("function_entry"),
            "call_sequence": list(value.get("call_sequence", []))[:48],
            "inputs": list(value.get("inputs", []))[:96],
            "conditions": list(value.get("conditions", []))[:32],
            "consumers": list(value.get("consumers", []))[:48],
            "recovered_argument_count": value.get("recovered_argument_count", 0),
            "confidence": value.get("confidence", "LOW"),
            "unknowns": list(value.get("unknowns", []))[:16],
            "boundary": value.get("boundary"),
            "static_only": True,
        })
    # Put the deep-disassembly scale next to the findings.  This is useful to
    # reviewers and makes a successful Ghidra run distinguishable from a
    # parser-only result without requiring them to inspect the evidence ledger.
    for run in tool_runs:
        if run.tool_name != "ghidra-headless":
            continue
        output = run.output if isinstance(run.output, dict) else {}
        all_modules["static_triage"]["rows"].append(
            {
                "type": "tool_summary",
                "tool": f"{run.tool_name}@{run.tool_version}",
                "tool_run_id": run.id,
                "artifact_id": run.artifact_id,
                "status": run.status,
                "function_count": output.get("function_count", 0),
                "xref_count": output.get("xref_count", 0),
                "cfg_block_count": output.get("cfg_block_count", 0),
                "symbol_count": output.get("symbol_count", 0),
                "output_reference": (
                    {"sha256": run.output_sha256, "storage_key": run.output_storage_key}
                    if run.output_sha256 and run.output_storage_key
                    else None
                ),
            }
        )
    # Abstract execution is an analysis product, not a flat parser field.
    # Render its predicted stages, candidate mechanisms, path conditions and
    # unknowns explicitly so a reviewer can see how the static evidence was
    # interpreted while retaining the runtime/non-runtime distinction.
    for item in [
        item for item in module_evidence.get("static_triage", [])
        if item.kind == "abstract_execution_trace" and isinstance(item.value, dict)
    ][:12]:
        value = item.value
        steps = value.get("steps", []) if isinstance(value.get("steps"), list) else []
        candidates = value.get("mechanism_candidates", []) if isinstance(value.get("mechanism_candidates"), list) else []
        all_modules["static_triage"]["rows"].append(
            {
                "type": "static_simulation_prediction",
                "evidence_id": item.id,
                "artifact_id": item.artifact_id,
                "function": value.get("function"),
                "entry": value.get("entry"),
                "simulation_kind": value.get("simulation_kind"),
                "runtime_observed": value.get("runtime_observed", False),
                "predicted": value.get("predicted", True),
                "confidence": value.get("confidence", "LOW"),
                "predicted_steps": [
                    {
                        "index": step.get("index"),
                        "operation": step.get("operation"),
                        "api": step.get("api"),
                        "inputs": step.get("inputs", {}),
                        "outputs": step.get("outputs", {}),
                        "path_condition": step.get("path_condition"),
                        "source_anchor": step.get("source_anchor", {}),
                    }
                    for step in steps[:16]
                    if isinstance(step, dict)
                ],
                "mechanism_candidates": candidates[:8],
                "path_conditions": value.get("path_conditions", [])[:16],
                "unknowns": value.get("unknowns", [])[:16],
                "limitations": value.get("limitations", [])[:16],
            }
        )
    # Render recovered call arguments as a compact analyst-facing semantic
    # record. The underlying Evidence row remains the source of truth; this
    # projection makes HOW (callsite, parameters and consumer) visible without
    # dumping the complete instruction ledger.
    semantic_evidence = [
        item
        for evidence_rows in module_evidence.values()
        for item in evidence_rows
        if item.kind == "api_argument_trace" and isinstance(item.value, dict)
    ]
    # A single callsite can produce several equivalent trace rows (one per
    # source instruction/evidence edge).  Keep the analyst-facing projection
    # one row per callsite while retaining every source evidence id for
    # drill-down.  This prevents the report from looking like a raw ledger.
    argument_groups: dict[tuple[str, str, str], dict[str, object]] = {}
    for item in semantic_evidence:
        value = item.value
        args = value.get("arguments", []) if isinstance(value.get("arguments"), list) else []
        recovered_count = int(value.get("recovered_argument_count", 0) or 0)
        normalized_args = [
            {
                "index": arg.get("index"),
                "register": arg.get("register"),
                "value": arg.get("value"),
                "resolved": arg.get("resolved", False),
                "source_kind": arg.get("source_kind"),
                "source_instruction": arg.get("source_instruction"),
            }
            for arg in args[:8]
            if isinstance(arg, dict)
        ]
        visible_args, unresolved_slots = _partition_arguments(normalized_args)
        # Empty traces add no analyst value when the callsite is already
        # represented by the mechanism chain.  Keep them in the Evidence
        # ledger, but do not repeat sixteen identical "nothing recovered"
        # rows in the primary report.  Some parsers emit placeholder dicts,
        # so check for meaningful fields rather than list non-emptiness.
        has_meaningful_args = bool(visible_args)
        if not has_meaningful_args and recovered_count <= 0:
            continue
        # The same callsite may be represented by an imported API and by a
        # generated ``PTR_<api>_<rva>`` alias.  They are one semantic event,
        # so group by location rather than by the spelling of the symbol.
        key = tuple(
            str(value.get(name) or "")
            for name in ("function", "function_entry", "callsite")
        )
        row = argument_groups.get(key)
        source_ids = [str(source_id) for source_id in value.get("source_evidence_ids", []) if source_id]
        source_ids.append(str(item.id))
        if row is None:
            argument_groups[key] = row = {
                "type": "api_argument_recovery",
                "evidence_id": item.id,
                "artifact_id": item.artifact_id,
                "api": value.get("api"),
                "function": value.get("function"),
                "function_entry": value.get("function_entry"),
                "callsite": value.get("callsite"),
                "arguments": normalized_args,
                "recovered_argument_count": recovered_count,
                "visible_recovered_argument_count": len(visible_args),
                "unresolved_argument_slots": unresolved_slots,
                "consumer": value.get("consumer"),
                "downstream_consumers": list(value.get("downstream_consumers", [])),
                "trace_quality": value.get("trace_quality"),
                "source_evidence_ids": list(dict.fromkeys(source_ids)),
                "static_only": True,
            }
            all_modules["static_triage"]["rows"].append(row)
            continue
        existing_args = row.setdefault("arguments", [])
        seen_args = {
            (arg.get("index"), arg.get("register"), arg.get("value"))
            for arg in existing_args
            if isinstance(arg, dict)
        }
        for arg in normalized_args:
            identity = (arg.get("index"), arg.get("register"), arg.get("value"))
            if identity not in seen_args:
                existing_args.append(arg)
                seen_args.add(identity)
        row["recovered_argument_count"] = max(
            int(row.get("recovered_argument_count", 0) or 0),
            recovered_count,
        )
        merged_args = row.get("arguments", [])
        if isinstance(merged_args, list):
            row["visible_recovered_argument_count"] = sum(
                1 for argument in merged_args if _argument_is_meaningful(argument)
            )
            row["unresolved_argument_slots"] = sum(
                1 for argument in merged_args
                if isinstance(argument, Mapping) and not _argument_is_meaningful(argument)
            )
        # Prefer a human-readable imported API over an implementation alias.
        candidate_api = str(value.get("api") or "")
        current_api = str(row.get("api") or "")
        if current_api.startswith("PTR_") and candidate_api and not candidate_api.startswith("PTR_"):
            row["api"] = candidate_api
        candidate_consumer = str(value.get("consumer") or "")
        current_consumer = str(row.get("consumer") or "")
        if current_consumer.startswith("PTR_") and candidate_consumer and not candidate_consumer.startswith("PTR_"):
            row["consumer"] = candidate_consumer
        row["source_evidence_ids"] = list(dict.fromkeys(
            list(row.get("source_evidence_ids", [])) + source_ids
        ))[:32]
        row["downstream_consumers"] = list(dict.fromkeys(
            list(row.get("downstream_consumers", []))
            + [str(consumer) for consumer in value.get("downstream_consumers", []) if consumer]
        ))[:12]
    # Render the bounded seed map as an analyst-facing queue, not as raw
    # import/string rows.  The complete source Evidence remains available in
    # the ledger and is referenced by each cluster's evidence_ids.
    seed_maps = [
        item
        for evidence_rows in module_evidence.values()
        for item in evidence_rows
        if item.kind == "investigation_seed_map" and isinstance(item.value, dict)
    ]
    for item in seed_maps[:16]:
        value = item.value
        clusters = value.get("clusters", []) if isinstance(value.get("clusters"), list) else []
        all_modules["static_triage"]["rows"].append(
            {
                "type": "investigation_seed_map",
                "evidence_id": item.id,
                "artifact_id": item.artifact_id,
                "cluster_count": value.get("cluster_count", len(clusters)),
                "total_cluster_count": value.get(
                    "total_cluster_count", value.get("cluster_count", len(clusters))
                ),
                "deferred_cluster_count": value.get("deferred_cluster_count", 0),
                "high_value_cluster_count": value.get("high_value_cluster_count", 0),
                "clusters": [
                    {
                        "id": cluster.get("id"),
                        "category": cluster.get("category"),
                        "priority": cluster.get("priority"),
                        "question": cluster.get("question"),
                        "hypotheses": list(cluster.get("hypotheses", []))[:4],
                        "evidence_ids": list(cluster.get("evidence_ids", []))[:32],
                        "static_only": True,
                    }
                    for cluster in clusters[:64]
                    if isinstance(cluster, dict)
                ],
                "static_only": True,
            }
        )
    # Claims are the analysis product. Move them ahead of low-level evidence
    # groups so reviewers see findings before the audit ledger.
    _static_claim_rows = _claim_row_list(
        module_claims.get("static_triage", []), links_by_claim, evidence_by_id
    )
    _static_claim_rows.extend(
        _claim_row_list(
            [item for item in claims if item.module not in {"static_triage", "behavior_attack"}],
            links_by_claim,
            evidence_by_id,
        )
    )
    _static_evidence_rows = [
        row for row in all_modules["static_triage"]["rows"]
        if row.get("type") != "analytical_claim"
    ]
    all_modules["static_triage"]["rows"] = _static_claim_rows + _static_evidence_rows
    all_modules["static_triage"]["summary"] = assessment_summary
    attack_chain_rows = [
        {
            "relation_id": item.id,
            "source_artifact_id": item.source_artifact_id,
            "relation": item.relation_type.lower(),
            "target_artifact_id": item.target_artifact_id,
            "state": (
                "confirmed"
                if item.evidence_id and item.status in {"OBSERVED", "CONFIRMED"}
                else "inferred"
                if item.claim_id
                else "unknown"
            ),
            "evidence_id": item.evidence_id,
            "claim_id": item.claim_id,
        }
        for item in relations
        if not _report_is_injects_self_loop(_report_record(item))
    ]
    if not attack_chain_rows:
        attack_chain_rows.append(
            {
                "relation": "component_chain",
                "state": "unknown",
                "reason": "no evidence-backed component relation was established",
            }
        )
    for module_id in ("decryption", "loader", "c2_network", "anti_analysis"):
        scoped_claims = module_claims.get(module_id, [])
        summary = (
            f"形成 {len(scoped_claims)} 条静态推断 Claim；"
            "未发现不等于运行时能力不存在，结论仅限当前静态证据。"
        )
        all_modules[module_id] = _module(
            module_id,
            summary,
            [
                {
                    "type": "analytical_claim",
                    "claim_id": item.id,
                    "status": item.status,
                    "confidence": item.confidence,
                    "statement": item.statement,
                    "evidence_ids": links_by_claim.get(item.id, []),
                    "analysis_source": (
                        "model"
                        if getattr(item, "model_call_id", None)
                        else "deterministic_static_rules"
                    ),
                    "model_call_id": getattr(item, "model_call_id", None),
                }
                for item in scoped_claims[:24]
            ],
        )
        if module_id == "decryption" and decode_result_projections:
            all_modules[module_id]["rows"].extend(decode_result_projections)
    all_modules["behavior_attack"] = _module(
        "behavior_attack",
        "BehaviorFinding/BehaviorRelation 由有来源的 Claim、Mechanism、Evidence 和 Relation 投影；候选不会自动升级。",
        behavior_relations[:64]
        + behavior_findings[:64]
        + attack_chain_rows[:64]
        + _apply_name_only_seed_downgrades(
            [
                {
                    "claim_id": item.id,
                    "subject": item.subject,
                    "action": item.action,
                    "object": item.object,
                    "what": getattr(item, "statement", None) or item.action,
                    "how": item.mechanism,
                    "mechanism": item.mechanism,
                    "condition": item.condition,
                    "status": item.status,
                    "attack_mapping": item.attack_mapping,
                    "attack_techniques": [
                        {
                            "technique_id": mapping.get("technique_id"),
                            "name": mapping.get("technique_name"),
                            "status": mapping.get("status", "candidate"),
                            "confidence": mapping.get("confidence", item.confidence),
                            "evidence_count": len(mapping.get("evidence_ids", [])),
                        }
                        for mapping in (item.attack_mapping or {}).get("mappings", [])
                        if isinstance(mapping, dict) and mapping.get("technique_id")
                    ],
                    "evidence_ids": links_by_claim.get(item.id, []),
                    "analysis_source": (
                        "model"
                        if getattr(item, "model_call_id", None)
                        else "deterministic_static_rules"
                    ),
                    "model_call_id": getattr(item, "model_call_id", None),
                }
                # A verifier-backed static mechanism is more useful to an analyst
                # than an arbitrary earlier candidate Claim. Keep the report's
                # bounded behavior view ordered by evidence closure rather than
                # database insertion order.
                for item in sorted(
                    claims,
                    key=lambda item: (
                        getattr(item, "claim_type", "") != "STATIC_MECHANISM_LINK",
                        str(getattr(item, "status", "")).upper() not in {"SUPPORTED", "VERIFIED", "CONFIRMED"},
                        str(getattr(item, "id", "")),
                    ),
                )[:32]
            ]
        ),
    )
    verified_findings = build_verified_security_findings(mechanisms, claims, evidence_by_id)
    all_modules["behavior_attack"]["rows"].extend(verified_findings)
    # Evidence-backed ATT&CK candidates are derived from multi-signal
    # conjunctions (for example Defender strings + registry-write APIs).  This
    # keeps the report useful when a specialist verifier has not yet closed a
    # mechanism, without promoting a bare import/string into a conclusion.
    all_modules["behavior_attack"]["rows"].extend(
        build_static_attack_candidates(evidence_by_id)
    )
    # Keep mechanism-shaped candidates visible to the analyst without
    # promoting them to Security Findings. This gives the report useful HOW
    # detail even when the specialist verifier cannot close the mechanism.
    verified_by_claim: dict[str, Any] = {}
    for item in mechanisms or []:
        if isinstance(item, Mapping):
            raw_ids = [item.get("claim_id"), *(item.get("claim_ids") or ())]
        else:
            raw_ids = [getattr(item, "claim_id", None), *(getattr(item, "claim_ids", ()) or ())]
        for raw_id in raw_ids:
            if raw_id:
                verified_by_claim.setdefault(str(raw_id), item)
    # A specialist verifier closes one concrete, evidence-backed path.  Do
    # not treat an artifact/type pair as a semantic wildcard: the same PE can
    # contain several independent resolver or shell-output paths.  Suppression
    # is therefore limited to a complete verifier record plus an exact scope
    # and evidence closure (or an explicitly scope-less duplicate whose full
    # evidence set is contained by the verified record).
    def _read_record(item: Any, key: str, default: object = None) -> object:
        if isinstance(item, Mapping):
            return item.get(key, default)
        return getattr(item, key, default)

    def _string_set(value: object) -> set[str]:
        if isinstance(value, (list, tuple, set)):
            return {str(item) for item in value if str(item).strip()}
        if value not in (None, ""):
            return {str(value)}
        return set()

    def _record_callsites(record: Mapping[str, object], evidence_ids: set[str]) -> set[str]:
        """Recover an exact callsite scope for suppression comparisons."""
        direct: set[str] = set()
        for key in (
            "callsite", "callsites", "resolver_callsite", "consumer_callsite",
            "resolver_callsites", "consumer_callsites",
        ):
            direct.update(_string_set(record.get(key)))
        # Explicit mechanism metadata is authoritative.  If present, do not
        # widen its scope by silently importing callsites from unrelated
        # source rows; malformed records should fail closed.
        if direct:
            return direct
        recovered: set[str] = set()
        for evidence_id in evidence_ids:
            source = evidence_by_id.get(evidence_id)
            if source is None:
                continue
            anchor = _read_record(source, "anchor", {})
            if isinstance(anchor, Mapping):
                for key in ("callsite", "resolver_callsite", "consumer_callsite"):
                    recovered.update(_string_set(anchor.get(key)))
            value = _read_record(source, "value", {})
            if not isinstance(value, Mapping):
                continue
            for key in ("callsite", "resolver_callsite", "consumer_callsite"):
                recovered.update(_string_set(value.get(key)))
            for key in ("call_targets", "calls", "references_from", "callees", "call_sequence"):
                nested = value.get(key)
                if not isinstance(nested, (list, tuple)):
                    continue
                for call in nested:
                    if isinstance(call, Mapping):
                        recovered.update(_string_set(
                            call.get("callsite") or call.get("from") or call.get("address")
                        ))
        return recovered

    verified_suppressors: list[dict[str, object]] = []
    for verified in (mechanisms or []):
        if isinstance(verified, Mapping):
            record = dict(verified)
        else:
            record = {
                key: getattr(verified, key)
                for key in (
                    "id", "mechanism_id", "mechanism_type", "status", "verifier",
                    "function_entry", "rva", "function", "artifact_id", "evidence_ids",
                    "target", "inputs", "transformation_or_control", "conditions",
                    "outputs", "consumers", "side_effects",
                )
                if hasattr(verified, key)
            }
        verifier = record.get("verifier") if isinstance(record.get("verifier"), Mapping) else {}
        status = str(record.get("status", "")).upper()
        if status not in {"VERIFIED", "SUPPORTED", "CONFIRMED"}:
            continue
        # A status label alone is not enough to hide an analyst-visible path.
        # This prevents malformed historical records from improving the
        # report score by suppressing otherwise useful candidates.
        if not mechanism_is_critical_ready(record):
            continue
        mechanism_type = str(
            record.get("mechanism_type") or verifier.get("mechanism_type") or ""
        ).upper()
        artifact_id = str(record.get("artifact_id") or "")
        evidence_ids = {
            str(item) for item in (record.get("evidence_ids") or ()) if item
        }
        if not artifact_id and evidence_ids:
            evidence_artifacts = {
                str(getattr(evidence_by_id[item], "artifact_id", ""))
                for item in evidence_ids
                if item in evidence_by_id and getattr(evidence_by_id[item], "artifact_id", None)
            }
            if len(evidence_artifacts) == 1:
                artifact_id = next(iter(evidence_artifacts))
        mechanism_id = str(record.get("mechanism_id") or record.get("id") or "")
        if not mechanism_id or not mechanism_type or not artifact_id or not evidence_ids:
            continue
        # Suppression is a presentation optimization, so it must fail closed
        # when provenance is incomplete or crosses the artifact/nature
        # boundary.  A malformed verifier must never hide a candidate row.
        evidence_valid = True
        for evidence_id in evidence_ids:
            source = evidence_by_id.get(evidence_id)
            if source is None:
                evidence_valid = False
                break
            source_artifact_id = str(_read_record(source, "artifact_id", "") or "")
            source_nature = str(
                _read_record(source, "nature", "STATIC_OBSERVED")
                or "STATIC_OBSERVED"
            ).upper()
            if source_artifact_id != artifact_id or source_nature not in {
                "STATIC_OBSERVED", "STATIC_DERIVED", "STATIC_INFERRED",
            }:
                evidence_valid = False
                break
        if not evidence_valid:
            continue
        verified_suppressors.append({
            "mechanism_id": mechanism_id,
            "mechanism_type": mechanism_type,
            "artifact_id": artifact_id,
            "function_entry": str(record.get("function_entry") or record.get("rva") or ""),
            "function": str(record.get("function") or ""),
            "evidence_ids": evidence_ids,
            "callsites": _record_callsites(record, evidence_ids),
        })
    suppressed_projections: list[dict[str, object]] = []
    for projection in mechanism_projections:
        projection_type = str(projection.get("mechanism_type", "")).upper()
        projection_entry = str(projection.get("function_entry") or projection.get("rva") or "")
        projection_function = str(projection.get("function") or "")
        projection_artifact = str(projection.get("artifact_id") or "")
        projection_evidence_ids = {
            str(item) for item in projection.get("evidence_ids", []) if item
        }
        if str(projection.get("status", "")).upper() == "CANDIDATE" and projection_type and projection_artifact:
            for suppressor in verified_suppressors:
                if (
                    suppressor["mechanism_type"] != projection_type
                    or suppressor["artifact_id"] != projection_artifact
                    or not projection_evidence_ids
                    or not projection_evidence_ids.issubset(suppressor["evidence_ids"])
                ):
                    continue
                suppressor_entry = str(suppressor.get("function_entry") or "")
                suppressor_function = str(suppressor.get("function") or "")
                projection_callsites = _record_callsites(projection, projection_evidence_ids)
                suppressor_callsites = set(suppressor.get("callsites") or ())
                # When either record exposes callsite scope, require exact
                # equality. A verifier that bundled two independent
                # callsites could otherwise suppress a distinct candidate
                # merely because one address overlaps; missing scope also
                # fails closed when the candidate is callsite-specific.
                callsites_compatible = projection_callsites == suppressor_callsites
                candidate_scoped = bool(projection_entry or projection_function)
                suppressor_scoped = bool(suppressor_entry or suppressor_function)
                same_scope = (
                    candidate_scoped
                    and suppressor_scoped
                    and projection_entry == suppressor_entry
                    and projection_function == suppressor_function
                    and callsites_compatible
                )
                scope_less_duplicate = not candidate_scoped and not suppressor_scoped
                # A specialist record may be artifact-scoped while its exact
                # source closure identifies one observation.  In that case a
                # scoped candidate is still a safe duplicate only when all of
                # its evidence is covered by that closure.  Independent
                # functions/callsites have disjoint evidence and remain
                # visible.
                evidence_closure_duplicate = (
                    candidate_scoped
                    and not suppressor_scoped
                    and projection_evidence_ids.issubset(suppressor["evidence_ids"])
                    and callsites_compatible
                )
                if not (same_scope or scope_less_duplicate or evidence_closure_duplicate):
                    continue
                projection["suppressed_by_verified"] = True
                projection["suppressed_by_mechanism_id"] = suppressor["mechanism_id"]
                projection["suppression_reason"] = (
                    "exact artifact/mechanism scope and evidence closure"
                    if same_scope or evidence_closure_duplicate
                    else "scope-less duplicate fully covered by verified evidence"
                )
                projection["suppressed_evidence_ids"] = sorted(projection_evidence_ids)
                suppressed_projections.append({
                    "projection_id": projection.get("mechanism_id"),
                    "mechanism_type": projection_type,
                    "artifact_id": projection_artifact,
                    "function": projection.get("function"),
                    "function_entry": projection.get("function_entry") or projection.get("rva"),
                    "evidence_ids": sorted(projection_evidence_ids),
                    "suppressed_by_mechanism_id": suppressor["mechanism_id"],
                    "reason": projection["suppression_reason"],
                })
                break
        verified = verified_by_claim.get(str(projection.get("claim_id")))
        if verified is not None:
            source = verified if isinstance(verified, dict) else {
                key: getattr(verified, key)
                for key in ("status", "verifier", "completeness", "evidence_ids")
                if hasattr(verified, key)
            }
            for key in (
                "status", "verifier", "completeness", "evidence_ids", "target",
                "inputs", "transformation_or_control", "conditions", "outputs",
                "consumers", "side_effects",
            ):
                if source.get(key) is not None:
                    projection[key] = source[key]
    # Keep the analyst-facing body concise.  The complete candidate set stays
    # available in the immutable snapshot and Evidence Explorer; showing all
    # of it here would recreate the field-list report that this contract is
    # designed to prevent.
    visible_mechanism_projections = [
        item for item in mechanism_projections if not item.get("suppressed_by_verified")
    ]
    all_modules["behavior_attack"]["rows"].extend(
        _select_mechanism_projections(visible_mechanism_projections, limit=12)
    )
    # Derive static IOC and hunting pivots only from semantically closed
    # mechanisms. API presence alone remains in the evidence explorer.
    closed_projections = [
        item for item in mechanism_projections
        if str(item.get("status", "")).upper() in {"VERIFIED", "SUPPORTED", "CONFIRMED"}
        and mechanism_is_critical_ready(item)
    ]
    # The report may intentionally suppress a duplicated candidate projection
    # once its specialist mechanism is verified. Detection pivots must still
    # be derived from that verified mechanism record, not from whichever
    # candidate happened to remain in the bounded report body.
    closed_keys = {
        str(item.get("mechanism_id") or item.get("id") or "")
        for item in closed_projections
    }
    for item in mechanisms or []:
        if isinstance(item, Mapping):
            record = dict(item)
        else:
            record = {
                key: getattr(item, key)
                for key in (
                    "id", "mechanism_id", "status", "target", "inputs",
                    "transformation_or_control", "conditions", "outputs",
                    "consumers", "side_effects", "evidence_ids", "verifier",
                )
                if hasattr(item, key)
            }
        record_id = str(record.get("mechanism_id") or record.get("id") or "")
        if (
            str(record.get("status", "")).upper() in {"VERIFIED", "SUPPORTED", "CONFIRMED"}
            and mechanism_is_critical_ready(record)
            and record_id not in closed_keys
        ):
            closed_projections.append(record)
            closed_keys.add(record_id)
    # Static values are projected independently of mechanism closure.  A
    # recovered URL, registry path, or scheduled-task command is an analyst
    # pivot even when the surrounding control-flow path remains a candidate.
    static_iocs: list[dict[str, object]] = build_static_indicator_projections(
        evidence_by_id, artifacts
    )
    # An analyst-usable deliverable needs something deployable, not only observed
    # values.  Derived from the same recovered indicators, explicitly marked as
    # analysis-side output, and empty when nothing usable was recovered.
    detection_rules: list[dict[str, object]] = build_detection_rule_projection(static_iocs)
    hunting_rows: list[dict[str, object]] = []
    for item in closed_projections:
        evidence_ids = list(item.get("evidence_ids", []))[:8]
        target = str(item.get("target", "static mechanism"))
        action_text = " ".join(str(value) for value in item.get("transformation_or_control", []))
        lower = action_text.casefold()
        if any(token in lower for token in ("http", "socket", "network", "endpoint")):
            static_iocs.append({
                "type": "ioc", "classification": "STATIC_DERIVED", "category": "mechanism_endpoint",
                "value": target, "source": "verified network mechanism", "evidence_ids": evidence_ids,
                "static_only": True,
                "boundary": "Verified static mechanism target; network access and successful transfer are unobserved.",
            })
            hunting_rows.append({"type": "hunting_opportunity", "statement": "Hunt for the recovered transport/endpoint construction and correlate it with the cited function path; this is a static pivot, not an observed connection.", "evidence_ids": evidence_ids})
        if any(token in lower for token in ("loadlibrary", "getprocaddress", "module", "resolve")):
            hunting_rows.append({"type": "hunting_opportunity", "statement": "Hunt for indirect module/API resolution using the recovered resolver and consumer relationship.", "evidence_ids": evidence_ids})
        if any(token in lower for token in ("xor", "decode", "decrypt", "decompress", "payload")):
            hunting_rows.append({"type": "hunting_opportunity", "statement": "Hunt for the recovered decoder pattern and embedded payload/resource characteristics before plaintext materialization.", "evidence_ids": evidence_ids})
        if any(token in lower for token in ("parent", "startupinfoex", "attribute")):
            hunting_rows.append({"type": "hunting_opportunity", "statement": "Hunt for STARTUPINFOEX parent-process attributes and anomalous parent/child relationships matching the cited static chain.", "evidence_ids": evidence_ids})
    # Several verified records can describe the same analyst-facing hunting
    # pivot. Merge those rows while retaining every bounded evidence reference
    # instead of showing duplicated guidance in the report.
    unique_hunting_rows: dict[str, dict[str, object]] = {}
    for row in hunting_rows:
        statement = str(row["statement"])
        existing = unique_hunting_rows.get(statement)
        if existing is None:
            unique_hunting_rows[statement] = row
            continue
        merged_evidence = list(
            dict.fromkeys(
                [
                    *[str(item) for item in existing.get("evidence_ids", [])],
                    *[str(item) for item in row.get("evidence_ids", [])],
                ]
            )
        )
        existing["evidence_ids"] = merged_evidence[:8]
    # Add directly actionable hunting guidance for the static IOC classes.
    # Each suggestion points back to the IOC's Evidence IDs and explicitly
    # states that no runtime event was observed.
    ioc_hunting_text = {
        "url": "Hunt DNS/HTTP telemetry for the statically recovered URL and correlate any request with the cited artifact; URL presence is not proof of contact.",
        "ipv4": "Hunt network telemetry for the statically recovered IP and correlate it with the sample hash; no connection was performed by static analysis.",
        "registry": "Monitor unauthorized writes to the statically referenced registry path and require process lineage correlation; the write is not observed here.",
        "scheduled_task": "Hunt short-lived Scheduled Task command sequences matching the statically recovered tokens (/create, /run, /delete); creation success is unknown.",
        "process_name": "Hunt anomalous parent/child relationships or interpreter launches involving the statically referenced process name; execution is unobserved.",
        "temp_path": "Hunt creation and deletion of files matching the statically recovered temporary path pattern; materialization is not observed.",
        "mechanism_endpoint": "Hunt the recovered transport/endpoint construction and correlate it with the cited function path; this is a static pivot, not an observed connection.",
    }
    for ioc in static_iocs:
        category = str(ioc.get("category", ""))
        statement = ioc_hunting_text.get(category)
        if not statement:
            continue
        statement = f"{statement} Indicator: {ioc.get('value')}"
        existing = unique_hunting_rows.get(statement)
        if existing is None:
            unique_hunting_rows[statement] = {
                "type": "hunting_opportunity",
                "statement": statement,
                "evidence_ids": list(ioc.get("evidence_ids", []))[:8],
                "static_only": True,
            }
        else:
            existing["evidence_ids"] = list(dict.fromkeys([
                *existing.get("evidence_ids", []), *ioc.get("evidence_ids", [])
            ]))[:8]
    all_modules["c2_network"]["rows"].extend(static_iocs)
    all_modules["c2_network"]["rows"].extend(list(unique_hunting_rows.values())[:24])
    # Detection artefacts sit with the behaviour/ATT&CK material rather than in
    # the network chapter: they are hunting guidance built from the whole
    # recovered indicator set, not a network observation.
    all_modules["behavior_attack"]["rows"].extend(detection_rules)
    all_modules["attribution"] = _module(
        "attribution",
        "当前静态证据不足以形成组织归因；仅保留技术关联候选，禁止由单一相似特征强行归因。",
        [
            *[
                {
                    "type": "analysis_profile",
                    "evidence_id": item.id,
                    "artifact_id": item.artifact_id,
                    "profile": item.value,
                    "anchor": item.anchor,
                }
                for item in module_evidence.get("attribution", [])
                if item.kind == "analysis_profile"
            ],
            *[
                {
                    "type": "fact_match",
                    "evidence_id": item.id,
                    "artifact_id": item.artifact_id,
                    "match": item.value,
                    "anchor": item.anchor,
                }
                for item in module_evidence.get("attribution", [])
                if item.kind == "fact_match"
            ],
            {
                "level": "organization",
                "conclusion": "unknown",
                "reason": "no independently validated attribution evidence",
            },
            {
                "level": "technical",
                "conclusion": "candidate behaviors available",
                "claim_ids": [item.id for item in claims],
            },
        ],
    )
    all_modules["evidence_ledger"] = _module(
        "evidence_ledger",
        "每条事实绑定 Artifact、ToolRun 与可复核锚点；模型文字不进入本表。",
        _summarize_evidence_rows(
            [
                {
                    "evidence_id": item.id,
                    "artifact_id": item.artifact_id,
                    "tool_run_id": item.tool_run_id,
                    "module": item.module,
                    "kind": item.kind,
                    "nature": item.nature,
                    "value": item.value,
                    "anchor": item.anchor,
                }
                for item in evidence
            ]
        ),
    )
    all_modules["limitations"] = _module(
        "limitations",
        "限制直接影响 Analysis Outcome，不以已生成报告替代分析完整度。",
        [{"type": "analysis_limitation", "detail": detail} for detail in task.limitations]
        + [
            {
                "type": "model_call",
                "model_call_id": call.id,
                "provider": call.provider,
                "model": call.model,
                "status": call.status,
                "prompt": f"{call.prompt_id}@{call.prompt_version}",
                "prompt_sha256": call.prompt_sha256,
                "request_sha256": call.request_sha256,
                "response_sha256": call.response_sha256,
                "latency_ms": call.latency_ms,
                "error_type": call.error_type,
                "error_detail": (call.parameters or {}).get("error_detail"),
                "http_status": (call.parameters or {}).get("http_status"),
            }
            for call in model_calls
        ]
        + [
            {
                "type": "tool_run",
                "tool_run_id": run.id,
                "tool": f"{run.tool_name}@{run.tool_version}",
                "status": run.status,
                "error": run.error,
                "output_reference": (
                    {
                        "sha256": run.output_sha256,
                        "storage_key": run.output_storage_key,
                    }
                    if run.output_sha256 and run.output_storage_key
                    else None
                ),
            }
            for run in tool_runs
        ]
        + [
            {
                "type": "gate",
                "gate_id": gate.id,
                "gate_type": gate.gate_type,
                "status": gate.status,
                "reason": gate.reason,
            }
            for gate in gates
        ],
    )
    # Recompute after every report module has been assembled.  The first
    # lightweight quality object is replaced here with the final analyst-view
    # score so IOC, flow, and limitation sections participate in the gate.
    quality = deep_analysis_metrics(
        document={"modules": list(all_modules.values())},
        mechanisms=[
            item if isinstance(item, Mapping) else {
                key: getattr(item, key) for key in (
                    "id", "claim_id", "status", "target", "inputs",
                    "transformation_or_control", "conditions", "outputs",
                    "consumers", "side_effects", "evidence_ids", "verifier",
                ) if hasattr(item, key)
            }
            for item in (mechanisms or [])
        ],
        mechanism_projections=mechanism_projections,
        investigation_threads=[
            item if isinstance(item, Mapping) else {
                "id": getattr(item, "id", ""),
                "state": getattr(item, "state", ""),
                "question": getattr(item, "question", ""),
                "action_ids": list(getattr(item, "action_ids", []) or []),
                "evidence_ids": list(getattr(item, "evidence_ids", []) or []),
                "protocol": getattr(item, "protocol", None) if hasattr(item, "protocol") else (
                    item.get("protocol") if isinstance(item, Mapping) else None
                ),
                "s_ladder": getattr(item, "s_ladder", None) if hasattr(item, "s_ladder") else (
                    item.get("s_ladder") if isinstance(item, Mapping) else None
                ),
            }
            for item in investigation_threads
        ],
        investigation_actions=[
            item if isinstance(item, Mapping) else {
                "id": getattr(item, "id", ""),
                "status": getattr(item, "status", ""),
                "origin": (
                    (getattr(item, "parameters", {}) or {}).get("origin")
                    or (
                        "model"
                        if (getattr(item, "parameters", {}) or {}).get("_planner_turn_id")
                        else "deterministic_fallback"
                    )
                ),
                "scheduler": (getattr(item, "parameters", {}) or {}).get("scheduler"),
                "planner_turn_id": (getattr(item, "parameters", {}) or {}).get("_planner_turn_id"),
                "result_evidence_ids": getattr(item, "result_evidence_ids", []),
            }
            for item in investigation_actions
        ],
    )
    for row in all_modules.get("executive_summary", {}).get("rows", []):
        if isinstance(row, dict) and row.get("type") == "analysis_quality":
            row.clear()
            row.update({"type": "analysis_quality", **quality})
    document = {
        "schema_version": "1.0",
        "report_version": "3.0",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "case_id": case.id,
        "task_id": task.id,
        "analysis_outcome": task.outcome,
        "analysis_class": getattr(task, "analysis_class", None),
        "analysis_coverage": getattr(task, "coverage", {}) or {},
        "analysis_quality": quality,
        "selected_modules": selected_modules,
        "modules": [all_modules[module_id] for module_id in selected_modules],
        # Curated string facts as an explicit projection, not something the
        # renderer has to rediscover by walking every row.  Walking the rendered
        # modules meant a truncated variant of a value could win over the real
        # one depending on row order, which is exactly how the report ended up
        # asserting `schtasks .../fschtasks` - a string absent from the binary.
        "string_facts": build_string_fact_projection(evidence),
        "trace": {
            "artifact_ids": [item.id for item in artifacts],
            "tool_run_ids": [item.id for item in tool_runs],
            "evidence_ids": list(evidence_by_id),
            "claim_ids": [item.id for item in claims],
            "relation_ids": [item.id for item in relations],
            "model_call_ids": [item.id for item in model_calls],
            "behavior_finding_ids": [
                str(item.get("finding_id") or item.get("id"))
                for item in behavior_findings
                if item.get("finding_id") or item.get("id")
            ],
            "behavior_relation_ids": [
                str(item.get("relation_id"))
                for item in behavior_relations
                if item.get("relation_id")
            ],
            # Suppression is presentation-only deduplication.  Keep every
            # suppressed projection and its supporting IDs in the trace so a
            # reviewer can distinguish "duplicate" from "not analyzed".
            "suppressed_mechanism_projections": suppressed_projections,
        },
    }
    # ADR-0006's input partition, carried as a STRUCTURED fact so the canonical official renderer can state it
    # instead of a hand-written sentence. Absent (not empty) when the frozen request declares no channels; see
    # `_input_partition_fact`.
    partition_fact = _input_partition_fact(request)
    if partition_fact:
        document[INPUT_PARTITION_DOCUMENT_KEY] = partition_fact
    revision_id = str(
        getattr(task, "authoritative_revision_id", None)
        or getattr(task, "report_revision_id", None)
        or getattr(task, "revision_id", None)
        or ""
    ).strip()
    if revision_id:
        document["authoritative_revision_id"] = revision_id
        document["report_revision_id"] = revision_id
    # Labelled CreateProcess flag projection, alongside `string_facts`.  Without an
    # explicit carrier the renderer only saw the ledger GROUP row for
    # `process_creation_flags` (which holds evidence ids, not values), so
    # `_recovered_creation_flags` read an empty prose blob and the body stamped
    # `UNKNOWN(creation_flags)` even though the run had recovered the immediate.
    process_flag_projection = build_process_flag_projections(evidence_by_id)
    if process_flag_projection:
        document["process_flags"] = process_flag_projection
    # The deterministic call-site word, which the candidate list above cannot decide: the
    # list holds eight immediates for this function and only one is written into the
    # argument slot CreateProcessW reads.  Without this the renderer had no channel to the
    # instruction window (the document carries instruction windows only as ledger GROUP
    # rows, whose `value` is None) and denied a slot whose value it published elsewhere.
    callsite_flag_projection = build_creation_flags_callsite_projection(evidence_by_id)
    if callsite_flag_projection:
        document["creation_flags_callsite"] = callsite_flag_projection
    _stamp_one_round_readiness(document)
    # M04/M06 run LAST so they judge the assembled revision: every behavior
    # finding, security finding and critic row is already projected, and the
    # verdict they stamp is the one the revision carries.
    _stamp_behavior_readiness(document)
    return document


def _gate_section_markdown(document: Mapping[str, object]) -> str:
    """The M04 / M06 verdicts, written into the artefact a reviewer reads.

    These are GATES, not the model's private reasoning, so they are published:
    a reader must be able to see that a revision is PARTIAL because a core
    finding has an unexplained template slot, which high-value conclusions the
    adversarial self-check downgraded and on which rule, and whether the S4
    orchestration state was recorded before the revision was composed.
    """
    quality = document.get("analysis_quality")
    if not isinstance(quality, Mapping):
        return ""
    gate = quality.get("readiness_gate")
    self_check = quality.get("m06_self_check")
    lines = ["", "### M04 报告就绪门 / M06 对抗式自检", ""]
    if isinstance(gate, Mapping):
        lines.append(f"- M04 status: **{gate.get('status') or 'UNRECORDED'}**")
        lines.append(
            "- M04 requirement: What / How / Target / Condition / Output / Consumer / "
            "Evidence / Unknown，缺项必须写明原因（N/A + 理由），不得编造。"
        )
        incomplete = gate.get("core_findings_incomplete")
        if isinstance(incomplete, list) and incomplete:
            for item in incomplete[:8]:
                if not isinstance(item, Mapping):
                    continue
                slots = "+".join(str(slot) for slot in item.get("missing_slots") or [])
                disposition = str(item.get("disposition") or "UNEXPLAINED")
                lines.append(
                    f"- M04 open slot: `{item.get('finding_id')}` [{slots}] -> {disposition}"
                )
        if gate.get("s4_orchestration_recorded") is False:
            lines.append(
                "- M06 S4: 未记录编排闭合状态 -> "
                + "; ".join(str(item) for item in (gate.get("s4_orchestration_gaps") or [])[:4])
            )
        else:
            lines.append("- M06 S4: 高价值结论的编排闭合状态已记录。")
    else:
        lines.append("- M04 status: **UNRECORDED**（未运行报告就绪门）")
    if isinstance(self_check, Mapping):
        lines.append(f"- M06 self-check: **{self_check.get('status') or 'UNRECORDED'}**")
        checks = self_check.get("checks")
        if isinstance(checks, list):
            for item in checks:
                if not isinstance(item, Mapping):
                    continue
                if str(item.get("status") or "").upper() == "BLOCKED":
                    lines.append(
                        f"- M06 BLOCKED `{item.get('rule_id')}`: "
                        f"{item.get('over_claim')}；需要 {item.get('required')}；"
                        f"命中 {', '.join(str(hit) for hit in (item.get('hits') or [])[:4])}"
                    )
        downgraded = self_check.get("downgraded")
        if isinstance(downgraded, list):
            for item in downgraded[:8]:
                if not isinstance(item, Mapping):
                    continue
                lines.append(
                    f"- M06 降级: `{item.get('finding_id')}` {item.get('previous_status')} -> "
                    f"{item.get('status')}（{', '.join(str(rule) for rule in item.get('rules') or [])}）"
                )
            if not downgraded and str(self_check.get("status") or "").upper() == "BLOCKED":
                lines.append(
                    "- M06 失败但没有结论被降级：该报告不得把失败结论当作已确认行为。"
                )
    else:
        lines.append("- M06 self-check: **UNRECORDED**（未运行对抗式自检）")
    lines.append("")
    return "\n".join(lines)


def render_ledger_markdown(document: dict[str, object]) -> str:
    """The V3 LEDGER projection of an immutable document.

    THIS IS NOT THE OFFICIAL REPORT BODY, and it must never become one. The single official producer is
    `threat_report_agent.report.analyst_report.compose_official_markdown`, and a published Report Revision's
    markdown comes only from there; HTML/DOCX/PDF all render the same Document.

    WHY THIS EXIT EXISTS AT ALL: the ledger projection is a distinct artifact that tests (and any future ledger
    reader) need to inspect, and before plan step P2-R.5 the only way to obtain it was `document_to_markdown`, a
    name that made it look like a second way to produce the body. MEASURED at the retirement
    (`.scratch/p2r5-branch-split.py`, `.scratch/p2r5_legacy_plugin.py`): the old function had ZERO production
    callers, and of its two branches the V3 projection was depended on by 49 tests while the pre-V3 renderer was
    depended on by exactly 7 - each of whose assertions the projection also satisfies, under a clearer label. The
    pre-V3 renderer therefore went with the old exit.
    """
    markdown = _document_to_v3_markdown(document)
    _stamp_one_round_readiness(document, markdown)
    return markdown


def _candidate_security_meaning(row: dict[str, object]) -> str:
    """Return a concrete analyst value for a candidate, or an empty value.

    Candidates are deliberately lower confidence than Core Findings, but a
    useful report still explains what the evidence would mean operationally.
    """
    module = str(row.get("module", "")).casefold()
    action = str(row.get("action", "")).casefold()
    if module == "decryption" or "decode" in action or "decrypt" in action:
        return "The evidence suggests hidden configuration or payload data; inspect the decoder input and downstream consumer for detection pivots."
    if module == "loader" or "load" in action:
        return "The evidence suggests a loader or memory-preparation path; correlate module names, resolved APIs, and the consuming call."
    if module == "c2_network" or "network" in action:
        return "The evidence suggests a statically referenced transport path; hunt the endpoint and data construction without treating it as an observed connection."
    if module == "anti_analysis" or "environment" in action:
        return "The evidence suggests environment-sensitive branching; inspect the comparison and branch consumer before escalating an evasion claim."
    if module == "execution" or "execute" in action:
        return "The evidence suggests a process or command path; verify the argument data and control-flow consumer before treating it as execution."
    return "The evidence is an analyst lead that requires the cited data/control path to be verified before escalation."


_CANDIDATE_MECHANISM_PRIORITY = {
    "PROCESS_EXECUTION": 0,
    "THREAD_CALLBACK": 1,
    "DECODE_CONFIG": 2,
    "ETW_PATCH": 3,
    "PPID_SPOOFING": 4,
    "SHELL_OUTPUT": 5,
    "DYNAMIC_LOADER": 6,
    "NETWORK_DOWNLOAD": 7,
    "HTTP_DOWNLOAD": 7,
    "DYNAMIC_API_RESOLUTION": 8,
    "INDIRECT_API_DISPATCH": 9,
    "MEMORY_PERMISSION_CHANGE": 10,
    "ENVIRONMENT_CHECK": 11,
}


def _candidate_mechanism_path(row: Mapping[str, object]) -> str:
    """Return the compact typed path supplied by a mechanism projection."""
    raw = row.get("transformation_or_control", [])
    if isinstance(raw, (list, tuple, set)):
        return " -> ".join(str(value) for value in raw if value)[:1400]
    return str(raw or "")[:1400]


def _is_actionable_candidate_mechanism(row: Mapping[str, object]) -> bool:
    """Reject incomplete pattern hits from the primary analyst narrative.

    A bounded XOR loop, lone API import, or stage label is useful scheduling
    evidence but is not a useful report finding.  This screen retains only
    multi-step paths whose reported type is supported by the actual recovered
    calls/data.  The original row stays in the immutable evidence ledger.
    """
    if str(row.get("status", "CANDIDATE")).upper() not in {
        "CANDIDATE", "SUPPORTED", "VERIFIED", "CONFIRMED"
    }:
        return False
    if not row.get("evidence_ids"):
        return False
    mechanism_type = str(row.get("mechanism_type", "")).upper()
    path = _candidate_mechanism_path(row).casefold()
    consumers = " ".join(str(value) for value in row.get("consumers", [])).casefold()
    inputs = " ".join(str(value) for value in row.get("inputs", [])).casefold()
    combined = " ".join((path, consumers, inputs))

    if mechanism_type == "PROCESS_EXECUTION":
        has_api = any(
            token in combined for token in ("createprocess", "shellexecute", "winexec")
        )
        has_command = any(token in combined for token in ("command", "cmd.exe"))
        has_flags = "creation_flags" in combined or "0x" in combined
        specialist_only = (
            "0x09080008" in combined.replace(" ", "")
            and not has_command
        )
        return has_api and (has_command or has_flags) and not specialist_only
    if mechanism_type == "THREAD_CALLBACK":
        blob = " ".join(
            (
                combined,
                " ".join(str(value) for value in row.get("outputs", [])).casefold(),
            )
        )
        creator = any(
            token in blob
            for token in (
                "createthread",
                "rtlcreateuserthread",
                "ntcreatethread",
                "queueuserapc",
                "may_start_os_thread",
                "lpstartaddress",
            )
        )
        recovered_start = bool(re.search(r"(?:fun_|sub_|thunk_|0x)[0-9a-f]{5,}", blob))
        return creator and recovered_start and "unknown(start_routine)" not in blob
    if mechanism_type == "DECODE_CONFIG":
        return any(
            token in combined
            for token in ("xor", "formula", "decode", "plaintext", "key_table", "decoded")
        )
    if mechanism_type == "DYNAMIC_LOADER":
        materialize = any(token in combined for token in ("createfile", "writefile", "movefile", "copyfile"))
        load = any(token in combined for token in ("loadlibrary", "ldrload"))
        return materialize and load
    if mechanism_type == "DYNAMIC_API_RESOLUTION":
        resolver = any(
            token in combined for token in ("getprocaddress", "ldrgetprocedureaddress")
        )
        consumer = any(token in combined for token in ("call ", "jmp ", "consumer"))
        module = any(token in combined for token in ("loadlibrary", "getmodulehandle", "module"))
        # Kunglao DISPATCH_VERIFIER: a recovered export plus JMP/CALL consumer
        # is reportable HOW even when the resolver name never landed in this
        # row. Do not hide SetThreadDescription/JMP R8, and do not invent
        # kernel32.dll as module_input.
        resolver_noise = {
            "getprocaddress",
            "ldrgetprocedureaddress",
            "loadlibrary",
            "loadlibrarya",
            "loadlibraryw",
            "getmodulehandle",
            "getmodulehandlea",
            "getmodulehandlew",
            "module",
            "jmp",
            "call",
            "consumer",
            "indirect",
            "pointer",
            "function",
            "address",
            "resolver",
            "procedure",
            "argument",
            "recovered",
            "handle",
            "context",
            "unresolved",
        }
        named_export = any(
            token not in resolver_noise
            for token in re.findall(r"[a-z][a-z0-9_]{5,}", combined)
        )
        return (named_export and consumer) or (resolver and (consumer or module))
    if mechanism_type == "INDIRECT_API_DISPATCH":
        return "getprocaddress" in combined and any(token in combined for token in ("call ", "jmp ", "consumer"))
    if mechanism_type == "PPID_SPOOFING":
        chain = all(
            token in combined
            for token in ("openprocess", "updateprocthreadattribute", "createprocess")
        )
        specialist = "0x09080008" in combined.replace(" ", "")
        return chain and specialist
    if mechanism_type == "SHELL_OUTPUT":
        return all(token in combined for token in ("createpipe", "createprocess", "readfile"))
    if mechanism_type in {"NETWORK_DOWNLOAD", "HTTP_DOWNLOAD"}:
        network_terms = ("winhttp", "wininet", "internetopen", "httpsendrequest", "httpopenrequest", "socket")
        return sum(token in combined for token in network_terms) >= 2
    if mechanism_type == "ETW_PATCH":
        return all(token in combined for token in ("etweventwrite", "virtualprotect")) and any(
            token in combined for token in ("flushinstructioncache", "33 c0 c3", "patch byte", "write bytes")
        )
    if mechanism_type == "MEMORY_PERMISSION_CHANGE":
        return "virtualprotect" in combined and any(
            token in combined for token in ("write", "memcpy", "flushinstructioncache", "execute")
        )
    if mechanism_type == "ENVIRONMENT_CHECK":
        return sum(token in combined for token in ("gettickcount", "globalmemorystatus", "getsysteminfo", "virtualquery")) >= 2
    if mechanism_type == "DECODE_TRANSFORM":
        # A larger bounded loop is a useful analyst lead even when the
        # plaintext consumer is unresolved. Tiny XOR/register-mixing windows
        # remain ledger-only noise. A verified ``decode_result`` is rendered
        # separately with stronger semantics.
        loop_match = re.search(r"\((\d+)\s+(?:transform/loop|transform|loop)\s+indicators", combined)
        return bool(loop_match and int(loop_match.group(1)) >= 16)
    return False


def _candidate_mechanism_finding(row: Mapping[str, object]) -> dict[str, object]:
    """Create an analyst-readable, explicitly conditional finding."""
    mechanism_type = str(row.get("mechanism_type", "static mechanism")).upper()
    target = str(row.get("target") or row.get("function") or "the recovered function")
    path = _candidate_mechanism_path(row)
    narratives = {
        "PROCESS_EXECUTION": (
            f"Static argument recovery in {target} reconstructs a child-process construction path.",
            "The recovered command and creation flags are a process-creation pivot; runtime spawn, parent identity, and process success remain unobserved.",
        ),
        "THREAD_CALLBACK": (
            f"Static argument recovery in {target} reconstructs a same-process OS thread start.",
            "The recovered lpStartAddress is a thread-start pivot; runtime start, loop, and shared-state consumers remain unobserved.",
        ),
        "DECODE_CONFIG": (
            f"Static decode recovery in {target} reconstructs a bounded transform and its output consumer.",
            "The recovered formula and plaintext are a configuration pivot; runtime use of the decoded bytes remains unobserved.",
        ),
        "DYNAMIC_LOADER": (
            f"Static data/control-flow in {target} links file materialization, dynamic module loading, and cleanup.",
            "The recovered path is consistent with a local loader chain. The loaded bytes, exact module identity, path reachability, and load success remain unobserved.",
        ),
        "DYNAMIC_API_RESOLUTION": (
            f"Static data/control-flow in {target} links module loading, procedure resolution, and an indirect consumer.",
            "This supports an import-hiding resolver path. A direct import-table review can therefore understate the APIs available to the sample.",
        ),
        "INDIRECT_API_DISPATCH": (
            f"Static data/control-flow in {target} links procedure resolution to an indirect call or jump consumer.",
            "This is a concrete hidden-API dispatch pivot, but the target API and invocation result remain bounded by the recovered evidence.",
        ),
        "PPID_SPOOFING": (
            f"Static data/control-flow in {target} links process opening, parent-process attribute setup, and process creation.",
            "The path is consistent with parent-process selection/spoofing. The selected parent and child creation outcome are not runtime observations.",
        ),
        "SHELL_OUTPUT": (
            f"Static data/control-flow in {target} links pipe creation, process creation, and output readback.",
            "This supports a candidate child-process output-capture path; command content, reachability, and process success are not observed.",
        ),
        "NETWORK_DOWNLOAD": (
            f"Static data/control-flow in {target} links multiple transport operations into a candidate request/response path.",
            "This is a static transport capability candidate, not evidence of a network connection, response, or downloaded payload.",
        ),
        "HTTP_DOWNLOAD": (
            f"Static data/control-flow in {target} links multiple HTTP transport operations into a candidate request/response path.",
            "This is a static transport capability candidate, not evidence of a network connection, response, or downloaded payload.",
        ),
        "ETW_PATCH": (
            f"Static data/control-flow in {target} links an EtwEventWrite target, protection change, and in-memory patch sequence.",
            "If the recovered branch is reached, the sequence could suppress event-reporting telemetry. Runtime reachability and patch success remain unobserved.",
        ),
        "MEMORY_PERMISSION_CHANGE": (
            f"Static data/control-flow in {target} links a memory-protection change to a recovered write or execution consumer.",
            "The mechanism can be a loader or patching pivot, but the affected bytes and runtime effect remain unobserved.",
        ),
        "ENVIRONMENT_CHECK": (
            f"Static data/control-flow in {target} combines multiple environment queries before a branch decision.",
            "This supports an environment-sensitive guard candidate; the exact policy and runtime branch outcome remain unobserved.",
        ),
        "DECODE_TRANSFORM": (
            f"Static instructions in {target} contain a bounded XOR/transform loop that may process embedded bytes.",
            "The loop is a useful decode/configuration pivot, but plaintext recovery and downstream consumption remain unobserved.",
        ),
    }
    what, security_meaning = narratives.get(
        mechanism_type,
        (f"Static data/control-flow in {target} supports a {mechanism_type} candidate.", _candidate_security_meaning(dict(row))),
    )
    return {
        "finding_id": f"candidate:{row.get('mechanism_id', 'observed')}",
        "verdict": "CANDIDATE",
        "confidence": row.get("confidence", "MEDIUM"),
        "what": what,
        "how": path,
        "security_meaning": security_meaning,
        "boundary": "Static evidence only; runtime reachability, intent, and success are not observed.",
        "claim_id": row.get("claim_id"),
        "mechanism_id": row.get("mechanism_id", "observed-mechanism"),
        "evidence_ids": list(row.get("evidence_ids", []))[:5],
        "candidate": True,
    }


def _select_actionable_candidate_mechanisms(rows: list[dict[str, object]], *, limit: int) -> list[dict[str, object]]:
    """Deduplicate and rank reportable candidates without changing the ledger."""
    selected: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in sorted(
        rows,
        key=lambda item: (
            _CANDIDATE_MECHANISM_PRIORITY.get(str(item.get("mechanism_type", "")).upper(), 99),
            0 if str(item.get("confidence", "")).upper() == "HIGH" else 1,
            -int(item.get("completeness", 0) or 0),
        ),
    ):
        if not _is_actionable_candidate_mechanism(row):
            continue
        identity = (
            str(row.get("mechanism_type", "")).upper(),
            str(row.get("function_entry") or row.get("target") or ""),
            _candidate_mechanism_path(row),
        )
        if identity in seen:
            continue
        seen.add(identity)
        selected.append(row)
        if len(selected) >= limit:
            break
    return selected


def _static_safe_text(value: object) -> str:
    """Normalize unqualified model wording to a static, conditional claim.

    Model prose is untrusted input to the report renderer.  A single
    unqualified runtime verb must not abort an otherwise valid static report,
    nor may it be emitted as if execution had been observed.  Existing
    explicitly negative/modal wording is left untouched by the gate; only
    text that fails the wording predicate is rewritten.

    The rewrite table now lives in `product_certification` so the English and the published Chinese paths
    share ONE definition. MEASURED: they did not, and the published path therefore threw away a whole report
    over one word (task `8e75f6dc`).
    """
    text = str(value or "").strip()
    if not text or not static_wording_violations(text):
        return text
    return repair_static_runtime_wording(text)


def _format_function_location(function: object, entry: object) -> str:
    """Render a function locator once, even when the name already has a suffix."""
    function_text = str(function or "").strip()
    entry_text = str(entry or "").strip()
    if not function_text:
        return entry_text or "function"
    if not entry_text or entry_text.casefold() in {"unknown", "rva unknown", "none"}:
        return function_text

    def same_locator(left: str, right: str) -> bool:
        def normalize(value: str) -> str:
            value = value.strip().casefold()
            return value[2:] if value.startswith("0x") else value

        return normalize(left) == normalize(right)

    # Some older projections persisted ``function@entry`` as the function
    # field and the renderer appended the same entry again.  Fallback regions
    # are themselves composite locators (``fallback_region@0x7000``), so
    # comparing only the final ``0x7000`` token leaves a repeated composite
    # suffix behind.  Remove an exact entry suffix first, then collapse any
    # repeated ``base@entry`` form while preserving unrelated labels.
    parts = function_text.split("@")
    entry_parts = entry_text.split("@")
    if len(parts) > len(entry_parts) and all(
        same_locator(left, right)
        for left, right in zip(parts[-len(entry_parts):], entry_parts)
    ):
        parts = parts[: -len(entry_parts)]
    while len(parts) > 1 and same_locator(parts[-1], entry_text):
        parts.pop()
    base = "@".join(parts).strip()
    # A composite entry can already be present once with a ``FUN_`` or
    # ``function_`` prefix on its first component (for example
    # ``FUN_fallback_region@0x7000``).  In that case appending the composite
    # entry again would produce the triple locator seen in older reports.
    if len(entry_parts) > 1 and len(parts) >= len(entry_parts):
        start = len(parts) - len(entry_parts)
        prefixed_first = parts[start].casefold()
        entry_first = entry_parts[0].casefold()
        if (
            (
                prefixed_first in {f"fun_{entry_first}", f"function_{entry_first}"}
                or same_locator(prefixed_first, entry_first)
            )
            and all(
                same_locator(left, right)
                for left, right in zip(parts[start + 1 :], entry_parts[1:])
            )
        ):
            return base
    return f"{base}@{entry_text}" if base else entry_text


_UNKNOWN_ARGUMENT_VALUES = {
    "", "unknown", "unresolved", "none", "null", "?", "n/a", "not recovered",
}
_REGISTER_TOKEN_RE = re.compile(
    r"(?:[er]?(?:ax|bx|cx|dx|si|di|sp|bp|ip)|r[0-9]{1,2}[dwb]?|(?:sil|dil|bpl|spl|[abcd][lh]))",
    re.IGNORECASE,
)


def _is_register_placeholder(value: str) -> bool:
    """Recognize legacy unresolved values such as ``RBX/RBP/RDI/RSI``."""
    tokens = [item.strip() for item in re.split(r"[/,|]", value) if item.strip()]
    return bool(tokens) and all(_REGISTER_TOKEN_RE.fullmatch(item) for item in tokens)


_STACK_FRAME_VALUE_RE = re.compile(
    r"\b(?:[ER](?:SP|BP))\b",
    re.IGNORECASE,
)


def _argument_is_meaningful(argument: object) -> bool:
    """Return whether an argument has analyst-useful static provenance.

    Ghidra emits one placeholder row for every ABI slot.  A placeholder can
    carry the register name as ``value`` in older snapshots, so checking only
    for a non-empty value would leak noise such as ``RBX [unknown]`` into the
    analyst report.  Keep expressions and concrete producers, but suppress
    unresolved register-only placeholders and stack-frame spills.
    """
    if not isinstance(argument, Mapping):
        return False
    value = str(argument.get("value") or "").strip()
    source_kind = str(argument.get("source_kind") or "").strip().casefold()
    register = str(argument.get("register") or "").strip().casefold()
    if value.casefold() in _UNKNOWN_ARGUMENT_VALUES:
        return False
    if _STACK_FRAME_VALUE_RE.search(value) or source_kind in {"stack_local", "stack"}:
        return False
    if argument.get("resolved") is True:
        return True
    if source_kind in {"unknown", "unresolved", "none"}:
        # ``unknown`` is an explicit statement that no data-flow value was
        # recovered.  Older projections copied the source instruction or the
        # register token into ``value``; neither is analyst-useful evidence.
        return False
    if source_kind in {"register_or_expression", "register", "expression"}:
        # A bare register (or a slash-separated register list) is the common
        # legacy placeholder.  Keep non-register expressions because they can
        # still encode a meaningful static address calculation.
        if _is_register_placeholder(value) or value.casefold() == register:
            return False
    # The analyst projection prints the recovered value, not the producer
    # instruction.  A producer-only row therefore remains unresolved until a
    # concrete value is available.
    return bool(value)


def _partition_arguments(arguments: object) -> tuple[list[Mapping[str, object]], int]:
    """Split argument rows into useful rows and unresolved slot count."""
    if not isinstance(arguments, (list, tuple)):
        return [], 0
    visible: list[Mapping[str, object]] = []
    unresolved = 0
    for argument in arguments:
        if not isinstance(argument, Mapping):
            continue
        if _argument_is_meaningful(argument):
            visible.append(argument)
        else:
            unresolved += 1
    return visible, unresolved


_UNRESOLVED_INTERNAL_TARGET_RE = re.compile(
    r"^(?:FUN_|PTR_FUN_|PTR_PTR_)",
    re.IGNORECASE,
)


def _is_unresolved_internal_call(call: Mapping[str, object]) -> bool:
    """Identify internal/pointer labels with no resolved semantic identity.

    Ghidra's ``FUN_`` and pointer labels are useful navigation evidence, but
    an unresolved label is not an analyst-facing API call.  Keep a row visible
    when an exporter or prior resolver supplied a meaningful category or a
    concrete target API; only the unresolved, unclassified form is hidden.
    """
    raw_api = str(call.get("api") or "").strip()
    if not _UNRESOLVED_INTERNAL_TARGET_RE.match(raw_api):
        return False
    category = str(call.get("category") or "").strip().casefold()
    if category and category != "unclassified_call":
        return False
    target_values = (
        call.get("resolved_api"),
        call.get("resolved_target"),
        call.get("target"),
        call.get("target_function"),
    )
    return not any(semantic_category(value) for value in target_values)


def _unresolved_internal_call_clues(calls: object) -> tuple[list[Mapping[str, object]], int]:
    """Return bounded parameter clues for hidden unresolved call labels."""
    if not isinstance(calls, list):
        return [], 0
    clues: list[Mapping[str, object]] = []
    count = 0
    for call in calls:
        if not isinstance(call, Mapping) or not _is_unresolved_internal_call(call):
            continue
        count += 1
        arguments, _ = _partition_arguments(call.get("arguments", []))
        if not arguments:
            continue
        clues.append(
            {
                "callsite": call.get("callsite") or call.get("address"),
                "arguments": arguments[:8],
            }
        )
    return clues[:16], count


def _meaningful_semantic_calls(calls: object) -> tuple[list[Mapping[str, object]], int]:
    """Select analyst-useful calls while retaining the full ledger upstream."""
    if not isinstance(calls, list):
        return [], 0
    meaningful: list[Mapping[str, object]] = []
    omitted = 0
    for call in calls:
        if not isinstance(call, Mapping):
            continue
        # Some historical Ghidra projections carried data/label references
        # into ``call_sequence`` with useful-looking argument rows. They are
        # still navigation noise, not callable API identities; never let
        # argument presence promote them into the analyst-facing report.
        raw_api = str(call.get("api") or "").strip()
        if re.match(r"^(?:PTR_)?(?:LAB|DAT)_", raw_api, re.IGNORECASE):
            omitted += 1
            continue
        if _is_unresolved_internal_call(call):
            omitted += 1
            continue
        arguments = call.get("arguments", [])
        has_value = (
            any(_argument_is_meaningful(argument) for argument in arguments)
            if isinstance(arguments, list)
            else False
        )
        category = str(call.get("category") or "")
        recovered_category = semantic_category(call.get("api"))
        if category != "unclassified_call" or recovered_category or has_value:
            meaningful.append(call)
        else:
            omitted += 1
    # Imported symbols and pointer aliases can produce two rows for one
    # callsite (for example ``virtualquery`` and ``VirtualQuery``). Collapse
    # only rows with an explicit source address; calls without an address are
    # retained because exporter order may be their only distinction. Merge
    # argument provenance so this presentation-only projection never loses a
    # recovered constant or string clue.
    deduped: list[Mapping[str, object]] = []
    by_identity: dict[tuple[str, str], int] = {}
    for call in meaningful:
        normalized = normalize_api_symbol(call.get("api"))
        callsite = str(call.get("callsite") or call.get("address") or "").strip().casefold()
        if not normalized or not callsite:
            deduped.append(call)
            continue
        identity = (normalized, callsite)
        existing_index = by_identity.get(identity)
        if existing_index is None:
            by_identity[identity] = len(deduped)
            deduped.append(dict(call))
            continue
        existing = dict(deduped[existing_index])
        existing_api = str(existing.get("api") or "")
        candidate_api = str(call.get("api") or "")
        # Prefer a plain, conventionally cased import over a lowercase or
        # decorated alias for the analyst-facing label.
        if (
            (existing_api.islower() and not candidate_api.islower())
            or existing_api.casefold().startswith(("ptr_", "__imp_", "imp_", "j_", "thunk_", "stub_"))
        ):
            existing["api"] = candidate_api
        old_args = existing.get("arguments", [])
        new_args = call.get("arguments", [])
        merged_args: list[Mapping[str, object]] = [
            argument for argument in old_args if isinstance(argument, Mapping)
        ] if isinstance(old_args, list) else []
        if isinstance(new_args, list):
            seen_args = {
                (
                    argument.get("argument_index", argument.get("index")),
                    argument.get("register"),
                    str(argument.get("value")),
                )
                for argument in merged_args
            }
            for argument in new_args:
                if not isinstance(argument, Mapping):
                    continue
                key = (
                    argument.get("argument_index", argument.get("index")),
                    argument.get("register"),
                    str(argument.get("value")),
                )
                if key not in seen_args:
                    merged_args.append(argument)
                    seen_args.add(key)
        existing["arguments"] = merged_args
        existing["recovered_argument_count"] = max(
            int(existing.get("recovered_argument_count", 0) or 0),
            int(call.get("recovered_argument_count", 0) or 0),
        )
        deduped[existing_index] = existing
    return deduped, omitted


def _semantic_call_label(call: Mapping[str, object]) -> tuple[str, str]:
    """Return a concise API/category pair, repairing stale Ghidra labels."""
    raw_api = str(call.get("api") or "")
    recovered_category = semantic_category(raw_api)
    category = str(call.get("category") or "unclassified_call")
    if recovered_category:
        category = recovered_category
        normalized = normalize_api_symbol(raw_api)
        # Preserve conventional API casing where the source symbol already
        # contains it; normalized text is only used for PTR_/__imp_ labels.
        if raw_api.casefold().startswith(("ptr_", "__imp_", "imp_", "j_", "thunk_", "stub_")):
            raw_api = normalized
    return raw_api, category


def _append_v3_gold_flow(
    lines: list[str],
    rows: list[dict[str, object]],
    assessment: Mapping[str, object],
) -> None:
    """Emit gold-bar HOW/emu/IOC before bulky findings so the display budget cannot drop them."""

    def compact(value: object, limit: int = 360) -> str:
        text = _static_safe_text(value).replace("\n", " ").strip()
        return text if len(text) <= limit else text[: limit - 3] + "..."
    emu_status = next((row for row in rows if row.get("type") == "emulation_status"), {})
    if emu_status:
        lines.extend(
            [
                "### Controlled emulation (isolated worker, not host execution)",
                "",
                "- scope: static analysis via Unicorn/Speakeasy/Qiling; not sandbox/dynamic sample execution",
                f"- overall=**{compact(emu_status.get('overall') or 'NOT_ATTEMPTED', 40)}** "
                f"attempted={bool(emu_status.get('attempted'))}",
                f"- next_step: {compact(emu_status.get('next_step'), 700)}",
            ]
        )
        for result in (emu_status.get("results") or [])[:8]:
            if not isinstance(result, dict):
                continue
            lines.append(
                f"- simulator={compact(result.get('simulator'), 40)} "
                f"status=**{compact(result.get('status'), 40)}** "
                f"stop={compact(result.get('stop_reason'), 80)} "
                f"entry={compact(result.get('function_entry'), 80)}"
            )
            if result.get("limitations"):
                lines.append(f"  - limitations: {compact(result.get('limitations'), 500)}")
        lines.append("")
    ordered_flow = next((row for row in rows if row.get("type") == "ordered_static_call_flow"), {})
    ordered_steps = [
        item for item in (ordered_flow.get("steps") or []) if isinstance(item, dict)
    ] if isinstance(ordered_flow, dict) else []
    if ordered_steps:
        lines.extend(["### Ordered static call sequence (reconstructed)", ""])
        for step in ordered_steps[:16]:
            location = compact(
                _format_function_location(step.get("function"), step.get("function_entry")),
                240,
            )
            lines.append(f"- `{location}`")
            how = compact(step.get("how") or "", 1400)
            if how:
                lines.append(f"  - How: {how}")
            for call in (step.get("calls") or [])[:12]:
                lines.append(f"  - {compact(call, 700)}")
            if step.get("unknowns"):
                lines.append(f"  - unknowns: {compact(step.get('unknowns'), 500)}")
        lines.append("")
    deep_dives = next((row for row in rows if row.get("type") == "module_deep_dives"), {})
    dive_modules = [
        item for item in (deep_dives.get("modules") or []) if isinstance(item, dict)
    ] if isinstance(deep_dives, dict) else []
    if dive_modules:
        lines.extend(["### Module deep-dives (static reconstruction)", ""])
        for module in dive_modules[:8]:
            lines.append(f"#### Module: {compact(module.get('category') or 'other', 80)}")
            for step in (module.get("steps") or [])[:6]:
                if not isinstance(step, dict):
                    continue
                location = compact(
                    _format_function_location(step.get("function"), step.get("function_entry")),
                    240,
                )
                lines.append(f"- `{location}`")
                how = compact(step.get("how") or "", 1400)
                if how:
                    lines.append(f"  - How: {how}")
                for call in (step.get("calls") or [])[:10]:
                    lines.append(f"  - {compact(call, 700)}")
            lines.append("")
    sequence_block = next((row for row in rows if row.get("type") == "runtime_sequence"), {})
    sequence_phases = [
        item for item in sequence_block.get("phases", []) if isinstance(item, dict)
    ] if isinstance(sequence_block, dict) else []
    if not sequence_phases and isinstance(assessment, dict):
        nested = assessment.get("findings", [])
        if isinstance(nested, list):
            for item in nested:
                if isinstance(item, dict) and item.get("runtime_sequence"):
                    sequence_phases = [
                        phase for phase in item.get("runtime_sequence", []) if isinstance(phase, dict)
                    ]
                    break
    sequence_phases = [
        phase for phase in sequence_phases
        if not _runtime_phase_is_empty_shell(phase)
    ]
    if sequence_phases:
        lines.extend(["### Runtime sequence (static reconstruction)", ""])
        for phase in sequence_phases:
            lines.append(
                f"- **{compact(phase.get('title') or phase.get('id'), 80)}** "
                f"status=**{compact(phase.get('status') or 'UNKNOWN', 40)}** "
                f"— {compact(phase.get('how') or 'UNKNOWN(phase)', 700)}"
            )
        lines.append("")
    decode_results = [row for row in rows if row.get("type") == "decode_result"]
    if decode_results:
        lines.extend(["### Static Decode Result", ""])
        for index, result in enumerate(decode_results[:8], start=1):
            lines.extend(
                [
                    f"- Result {index}: evidence=`{result.get('evidence_id', 'unknown')}` | "
                    f"status=**{result.get('verification_status', 'UNKNOWN')}**",
                    f"  - formula: {compact(result.get('formula') or 'unknown', 180)}",
                ]
            )
            if result.get("decoded_preview"):
                lines.append(f"  - decoded preview: {compact(result.get('decoded_preview'), 700)}")
        lines.append("")
    ioc_rows = [row for row in rows if row.get("type") in {"indicator", "ioc"}]
    lines.extend(["## 6. IOC / Indicators", ""])
    if ioc_rows:
        for row in ioc_rows[:24]:
            value = row.get("value") or row.get("indicator") or row.get("statement")
            category = row.get("category") or row.get("indicator_type") or "static_indicator"
            confidence = row.get("confidence") or "UNKNOWN"
            evidence_ids = list(row.get("evidence_ids", []))[:5] if isinstance(row.get("evidence_ids"), list) else []
            lines.append(
                f"- `{compact(category, 80)}` **{compact(value, 500)}** "
                f"(classification={row.get('classification', 'STATIC_DERIVED')}, confidence={confidence})"
            )
            if evidence_ids:
                lines.append(f"  - Evidence: {compact(evidence_ids, 300)}")
        lines.append("")
    else:
        lines.append("未提取到可安全报告的静态 IOC。")
        lines.append("")


def _s4_display_status(row: Mapping[str, object]) -> tuple[str, str]:
    """Render persist leftover remainder as CLOSED/RECORDED, not BLOCKED.

    Vacuous CLOSED with neither TRACE attempts nor persist Evidence stays
    BLOCKED. Persist HOW skip and honest HTTP/PPID UNKNOWN are report content.
    """
    status = str(row.get("status") or "").upper()
    reason = str(row.get("reason") or "").strip()
    action_ids = [item for item in (row.get("action_ids") or []) if item]
    evidence_ids = [item for item in (row.get("evidence_ids") or []) if item]
    if status in {"CLOSED", "RECORDED"} and (action_ids or evidence_ids):
        return status, reason or (
            "persist/verifier-ready HOW is leftover remainder; isolated emu is not another TRACE round"
            if status == "CLOSED"
            else "honest static boundary is report UNKNOWN/CANDIDATE content, not a planner ticket"
        )
    vacuous_boundary = status in {"CLOSED", "STATIC_BOUNDARY"} and not action_ids and not evidence_ids
    if vacuous_boundary or status == "STATIC_BOUNDARY":
        gap = reason or (
            "S4 CLOSED with empty attempts is not STATIC_BOUNDARY; "
            "retain BLOCKED/PARTIAL until S1-S3 attempts or an explicit N/A reason exist"
        )
        return "BLOCKED", gap
    if status == "BLOCKED":
        return "BLOCKED", reason or "S4 remains open; missing S1-S3 attempts or explicit N/A"
    if status == "NOT_APPLICABLE":
        return "NOT_APPLICABLE", reason or "thread was explicitly marked not applicable"
    if status == "CLOSED":
        return "CLOSED", reason or "S1-S3 were attempted or marked N/A; S4 is recorded closed"
    return status or "PARTIAL", reason or "S4 gap not recorded"


def _document_to_v3_markdown(document: dict[str, object]) -> str:
    """Render a concise analyst report from the immutable document model.

    Rows are an internal projection format, not a report layout.  This
    renderer deliberately selects only analyst material and leaves raw
    Evidence/ToolRun rows reachable through the trace and Evidence Explorer.
    """
    modules = [item for item in document.get("modules", []) if isinstance(item, dict)]
    rows = [
        row for module in modules
        for row in module.get("rows", [])
        if isinstance(row, dict)
    ]
    plan_row = next((row for row in rows if row.get("type") == "static_analysis_plan"), {})
    packer_latch = bool(isinstance(plan_row, dict) and plan_row.get("packer_latch"))
    if not packer_latch:
        packer_latch = _static_plan_packer_latch(
            plan_row if isinstance(plan_row, dict) else {},
            [
                row for row in rows
                if row.get("type") in {"behavior_finding", "catalog_behavior"}
            ],
        )
    assessment = next((row for row in rows if row.get("type") == "analyst_assessment"), {})
    summary = str(assessment.get("summary", "")).strip()
    behavior_projection_rows = [
        row for row in rows
        if row.get("type") == "behavior_finding"
        and row.get("evidence_ids")
        and not _report_is_attribution(row)
    ]
    # Executive-summary rows carry the same canonical BehaviorFinding objects
    # as the dedicated behavior module.  Include those nested rows so a
    # caller selecting only the executive module still receives the complete
    # behavior template rather than an empty overview.
    nested_assessment_findings = assessment.get("findings", []) if isinstance(assessment, dict) else []
    for row in nested_assessment_findings if isinstance(nested_assessment_findings, list) else []:
        if (
            isinstance(row, dict)
            and row.get("type") == "behavior_finding"
            and row.get("evidence_ids")
            and not _report_is_attribution(row)
        ):
            behavior_projection_rows.append(row)
    deduped_behavior_rows: list[dict[str, object]] = []
    seen_behavior_ids: set[str] = set()
    for row in behavior_projection_rows:
        identity = str(row.get("finding_id") or row.get("id") or "")
        if identity and identity in seen_behavior_ids:
            continue
        if identity:
            seen_behavior_ids.add(identity)
        deduped_behavior_rows.append(row)
    behavior_projection_rows = sorted(deduped_behavior_rows, key=_analyst_finding_rank)
    behavior_relation_rows = [
        row for row in rows
        if row.get("type") == "behavior_relation"
        and (row.get("evidence_ids") or row.get("claim_id"))
    ]
    findings: list[dict[str, object]] = [
        row for row in rows if row.get("type") == "security_finding"
    ]
    # A candidate claim is useful context, but it is never presented as a
    # verified security finding. Keep only the best few and require evidence.
    # Function-reference/navigation rows belong in the trace, not the analyst
    # finding list; they do not state a recovered mechanism by themselves.
    def is_navigation_candidate(row: dict[str, object]) -> bool:
        if _report_is_attribution(row):
            return True
        action = str(row.get("action", "")).casefold()
        text = " ".join(
            str(row.get(key, ""))
            for key in ("finding", "statement", "what", "how", "mechanism")
        ).casefold()
        return (
            action in {"references", "prioritizes", "matches", "calls", "contains_rva_level_call_sites", "exhibits_cross_function_chain"}
            or any(marker in text for marker in ("xref/cfg/instruction prominence", "call-site density", "raw function reference", "knowledge fact"))
        ) and (
            "function" in text or "xref" in text or "rva" in text or "knowledge fact" in text
        )

    # BehaviorFinding is the canonical analyst projection.  Formal security
    # findings remain first, while candidate/supported behavior rows fill the
    # view without changing their source status.
    formal_ids = {
        str(row.get("mechanism_id")) for row in findings if row.get("mechanism_id")
    }
    named_cover_ids = {
        str(row.get("catalog_id") or "")
        for row in behavior_projection_rows
        if str(row.get("catalog_id") or "") not in _COVER_NOISE_CATALOG_IDS
    }
    for row in behavior_projection_rows:
        if not _finding_has_recovered_how(row):
            continue
        mechanism_id = str(
            (row.get("mechanism_ids") or [row.get("mechanism_id")])[0]
            if (row.get("mechanism_ids") or row.get("mechanism_id"))
            else ""
        )
        if mechanism_id and mechanism_id in formal_ids:
            continue
        status = str(row.get("finding_status") or row.get("status") or "CANDIDATE").upper()
        recovered_how = _module_how_from_finding(row)
        if _is_cover_noise_finding(row, named_ids=named_cover_ids):
            continue
        findings.append({
            "finding_id": row.get("finding_id") or row.get("id") or f"behavior:{mechanism_id or 'unknown'}",
            "verdict": status,
            "confidence": (
                "HIGH" if status in {"VERIFIED", "CONFIRMED"}
                else "MEDIUM" if status == "SUPPORTED"
                else "LOW" if status in {"CANDIDATE", "INFERRED"}
                else "UNKNOWN"
            ),
            "what": row.get("what") or "Static behavior candidate.",
            "how": recovered_how,
            "catalog_id": row.get("catalog_id"),
            "security_meaning": row.get("semantic_interpretation") or row.get("maliciousness_assessment") or "Static behavior projection; intent is not established.",
            "boundary": "Static evidence only; runtime behavior is not observed.",
            "mechanism_id": mechanism_id or row.get("mechanism_id") or "unknown",
            "claim_id": (row.get("claim_ids") or [None])[0],
            "evidence_ids": list(row.get("evidence_ids", []))[:5],
            "target": row.get("target"),
            "inputs": row.get("inputs"),
            "conditions": row.get("conditions"),
            "outputs": row.get("outputs"),
            "consumers": row.get("consumers"),
            "unknowns": row.get("unknowns", []),
            "candidate": status not in {"VERIFIED", "CONFIRMED", "SUPPORTED"},
            "behavior_finding": True,
        })
    findings = [dict(row) for row in _prefer_named_catalog_findings(findings)]

    if not findings:
        # Prefer concrete observed mechanism rows over broad rule Claims in
        # the analyst-facing finding list.  This is what turns a disassembly
        # result into an explanation rather than another import inventory.
        observed_rows = _select_actionable_candidate_mechanisms(
            [
                row for row in rows
                if row.get("type") == "mechanism_observation" and row.get("evidence_ids")
            ],
            limit=8,
        )
        for row in observed_rows:
            findings.append(_candidate_mechanism_finding(row))
        if findings:
            # Keep the existing Claim fallback below for reports where the
            # observed rows do not fill the bounded analyst view.
            pass
    if not findings:
        # The assessment row is intentionally nested to keep the document
        # model compact. Promote its evidence-backed claim summaries into the
        # candidate section when no verified mechanism exists.
        nested_candidates = assessment.get("findings", []) if isinstance(assessment, dict) else []
        for row in nested_candidates if isinstance(nested_candidates, list) else []:
            if not isinstance(row, dict) or not row.get("evidence_ids"):
                continue
            if is_navigation_candidate(row) or _is_reference_noise(row):
                continue
            finding_text = str(row.get("finding") or row.get("statement") or "")
            if (
                str(row.get("module", "")).casefold() in {"static_triage", "attribution"}
                and str(row.get("action", "")).casefold() in {"prioritizes", "matches"}
            ) or "matches knowledge fact" in finding_text.casefold():
                continue
            findings.append({
                "finding_id": f"candidate:{row.get('claim_id', 'unknown')}",
                "verdict": row.get("verdict", "CANDIDATE"),
                "confidence": row.get("confidence", "LOW"),
                "what": row.get("finding") or row.get("statement") or "Static behavior candidate.",
                "how": row.get("mechanism") or "Evidence-linked static call/data path.",
                "security_meaning": _candidate_security_meaning(row),
                "boundary": "Static evidence only; runtime behavior is not observed.",
                "claim_id": row.get("claim_id"),
                "mechanism_id": row.get("mechanism_id", "candidate-mechanism"),
                "evidence_ids": list(row.get("evidence_ids", []))[:5],
                "candidate": True,
            })
            if len(findings) >= 40:
                break
    if not findings:
        for row in rows:
            if row.get("type") not in {"analytical_claim", "claim"}:
                continue
            if not row.get("evidence_ids"):
                continue
            if is_navigation_candidate(row) or _is_reference_noise(row):
                continue
            findings.append({
                "finding_id": f"candidate:{row.get('claim_id', 'unknown')}",
                "verdict": "CANDIDATE",
                "confidence": row.get("confidence", "LOW"),
                "what": row.get("statement", "Static behavior candidate."),
                "how": row.get("mechanism", "Evidence-linked static call/data path."),
                "security_meaning": _candidate_security_meaning(row),
                "boundary": "Static evidence only; runtime behavior is not observed.",
                "claim_id": row.get("claim_id"),
                "mechanism_id": row.get("mechanism_id", "candidate-mechanism"),
                "evidence_ids": list(row.get("evidence_ids", []))[:5],
                "candidate": True,
            })
            if len(findings) >= 40:
                break
    findings = sorted(findings, key=_analyst_finding_rank)[:40]
    if packer_latch:
        findings = [
            row for row in findings
            if not _is_stub_iat_capability(row.get("how") or row.get("what"))
        ]

    artifacts = [row for row in rows if "artifact_id" in row and row.get("path")]
    unique_artifacts: list[dict[str, object]] = []
    seen_artifacts: set[str] = set()
    for item in artifacts:
        key = str(item.get("artifact_id"))
        if key in seen_artifacts:
            continue
        seen_artifacts.add(key)
        unique_artifacts.append(item)

    coverage = document.get("analysis_coverage")
    coverage = coverage if isinstance(coverage, dict) else {}
    dimensions = coverage.get("dimensions", {})
    dimensions = dimensions if isinstance(dimensions, dict) else {}
    pipeline = coverage.get("pipeline_completion", coverage.get("pipeline", {}))
    semantic = coverage.get("semantic_coverage", dimensions)
    semantic = semantic if isinstance(semantic, dict) else {}
    quality = document.get("analysis_quality")
    quality = quality if isinstance(quality, dict) else {}

    # Coverage is computed from the semantic-flow evaluator and remains the
    # source of truth even when the renderer intentionally keeps independent
    # paths separate.  ``rendered_flow_rows`` is only a presentation detail.
    behavior_flow_present = bool(coverage.get("behavior_flow_present", False))

    def compact(value: object, limit: int = 360) -> str:
        text = _static_safe_text(value).replace("\n", " ").strip()
        return text if len(text) <= limit else text[: limit - 3] + "..."

    lines = [
        "# 静态分析报告",
        "",
        f"- Case ID: `{document.get('case_id', 'unknown')}`",
        f"- Analysis Task ID: `{document.get('task_id', 'unknown')}`",
        f"- Task Outcome: **{document.get('analysis_outcome') or 'UNKNOWN'}**",
        f"- Analysis Class: **{document.get('analysis_class') or 'UNKNOWN'}**",
        "- Task Outcome is a Legacy task-completion field retained for compatibility; it does not override Analysis Class.",
        "- Sample execution: **false**",
        "- Sandbox/dynamic analysis: **false**",
        "",
        STATIC_SCOPE_BANNER_EN,
        STATIC_SCOPE_BANNER_ZH,
        "> 本报告仅呈现分析结论；完整 Evidence、ToolRun、函数和字符串明细请通过 Evidence Explorer 查询。",
        "",
        "## 1. Executive Assessment",
        "",
        _static_safe_text(summary) or "未形成足够的证据支持综合评估。",
        "",
        f"- Core findings: {len(findings)}",
        f"- Pipeline completion: {compact(pipeline or 'not reported')}",
        f"- Semantic analysis coverage: {compact(semantic or 'not reported')}",
        f"- Semantic behavior flow: nodes={coverage.get('semantic_flow_nodes', 0)}, "
        f"edges={coverage.get('semantic_flow_edges', 0)}, "
        f"present={behavior_flow_present}, "
        f"relation coverage={coverage.get('dimensions', {}).get('relation_flow_coverage', 0.0) if isinstance(coverage.get('dimensions'), dict) else 0.0}",
        f"- Deep analysis readiness: **{quality.get('readiness', 'BOUNDED_WITH_LIMITATIONS')}**",
        f"- Report depth score: **{quality.get('report_depth', {}).get('score', 0) if isinstance(quality.get('report_depth'), dict) else 0}/100** (not verified HOW closure)",
        f"- High-value seed closure: **{quality.get('high_value_seed_closure_rate', 0)}**",
        "",
        "## 2. Artifact Summary",
        "",
    ]
    if unique_artifacts:
        for item in unique_artifacts[:32]:
            lines.append(
                f"- `{compact(item.get('path'), 180)}` | type={item.get('type', 'unknown')} | "
                f"role={item.get('role', 'unknown')} | sha256={compact(item.get('sha256'), 24)}"
            )
    else:
        lines.append("- 未提供 Artifact 摘要。")
    pe_basics = next((row for row in rows if row.get("type") == "pe_basics" and row.get("entry_rva") not in (None, "")), {})
    if pe_basics:
        lines.extend(
            [
                "",
                "### PE basics (static header)",
                "",
                f"- format={compact(pe_basics.get('format') or 'UNKNOWN', 40)} "
                f"machine={compact(pe_basics.get('machine') or 'UNKNOWN', 40)} "
                f"image_base={compact(pe_basics.get('image_base'), 40)} "
                f"entry_rva={compact(pe_basics.get('entry_rva'), 40)} "
                f"subsystem={compact(pe_basics.get('subsystem'), 40)}",
                f"- sections: {compact(pe_basics.get('section_names') or [], 400)}",
                f"- import_count={compact(pe_basics.get('import_count'), 40)}",
            ]
        )
        imports = pe_basics.get("imports")
        if isinstance(imports, list) and imports:
            lines.append("- recovered imports:")
            for name in imports[:80]:
                lines.append(f"  - `{compact(name, 180)}`")
        if packer_latch:
            lines.append(
                "- packer latch: LoadLibrary/GetProcAddress-only IAT is a stub, not a payload capability"
            )
        lines.append("")
    plan_items = [
        item for item in (plan_row.get("items") or []) if isinstance(item, dict)
    ] if isinstance(plan_row, dict) else []
    if plan_items:
        lines.extend(["", "### Static analysis plan", ""])
        lines.append(f"- snapshot_key: `{STATIC_ANALYSIS_PLAN_SNAPSHOT_PATH}`")
        if packer_latch:
            lines.append(
                "- packer_latch: **true** — stub IAT is not treated as sample HOW"
            )
        lines.append(
            "- Plan completion is not verifier acceptance; Gold/readiness is not HOW closure."
        )
        for bucket, heading in (
            ("completed", "Completed"),
            ("unknown", "UNKNOWN"),
            ("blocked", "Blocked"),
        ):
            bucket_items = [
                item for item in plan_items
                if str(item.get("bucket") or _plan_status_bucket(str(item.get("status") or ""))) == bucket
            ]
            if not bucket_items:
                continue
            lines.extend(["", f"#### {heading}", ""])
            for item in bucket_items[:32]:
                title = compact(item.get("title") or item.get("id") or "plan-item", 240)
                status = compact(item.get("status") or "UNKNOWN", 40)
                lines.append(f"- `{compact(item.get('id') or 'item', 80)}` status=**{status}** {title}")
                unknowns = [
                    compact(token, 80)
                    for token in (item.get("unknowns") or [])
                    if str(token).strip()
                ]
                if unknowns:
                    lines.append(f"  - unknowns: {', '.join(unknowns)}")
                next_method = compact(item.get("next_method") or "", 240)
                if next_method:
                    lines.append(f"  - next_method: {next_method}")
        lines.append("")
    lines.extend(["", "### Behavior Overview", ""])
    catalog_matrix = next(
        (row for row in rows if row.get("type") == "catalog_behavior_matrix"),
        {},
    )
    discovered_catalog = [
        item for item in catalog_matrix.get("discovered", []) if isinstance(item, dict)
    ] if isinstance(catalog_matrix, dict) else []
    if packer_latch:
        discovered_catalog = [
            item for item in discovered_catalog
            if not _is_stub_iat_capability(item.get("how") or item.get("what"))
        ]
    if discovered_catalog:
        lines.extend(["#### Discovered catalog behaviors", ""])
        for item in discovered_catalog[:24]:
            lines.extend(
                [
                    f"- `{compact(item.get('catalog_id') or '', 80)}` "
                    f"({compact(item.get('category') or '', 80)}) "
                    f"status=**{compact(item.get('status') or 'CANDIDATE', 40)}**",
                    f"  - What: {compact(item.get('what') or '', 700)}",
                    f"  - How: {compact(item.get('how') or '', 1400)}",
                    f"  - Evidence: {compact(item.get('evidence_ids') or [], 200)}",
                ]
            )
        lines.append("")
    unique_thread_block = next(
        (row for row in rows if row.get("type") == "unique_execution_threads"),
        {},
    )
    unique_threads = [
        item for item in unique_thread_block.get("threads", []) if isinstance(item, dict)
    ] if isinstance(unique_thread_block, dict) else []
    if unique_threads:
        lines.extend(["#### Unique OS threads / callbacks", ""])
        for item in unique_threads[:12]:
            start = _semantic_scalar(item.get("start_routine"))
            if start:
                lines.append(
                    f"- `{compact(item.get('api') or 'thread', 80)}` at "
                    f"{compact(item.get('function_entry') or 'UNKNOWN(function_entry)', 80)} "
                    f"start={compact(start, 160)} "
                    f"parameter={compact(item.get('parameter') or 'UNKNOWN(parameter)', 120)} "
                    f"loop={compact(item.get('loop') or 'UNKNOWN(loop)', 160)} "
                    f"exit={compact(item.get('exit') or 'UNKNOWN(exit)', 160)} "
                    f"shared_state={compact(item.get('shared_state') or 'UNKNOWN(shared_state)', 160)} "
                    f"emulator={compact(item.get('emulator_status') or 'NOT_ATTEMPTED', 80)}"
                )
            else:
                lines.append(
                    f"- `{compact(item.get('api') or 'thread', 80)}` at "
                    f"{compact(item.get('function_entry') or 'unknown target', 80)} "
                    f"status=**CANDIDATE** UNKNOWN(start_routine)"
                )
        lines.append("")
    _append_v3_gold_flow(lines, rows, assessment)
    recovered_behavior_rows = _prefer_named_catalog_findings(
        sorted(
            [
                item for item in behavior_projection_rows
                if _finding_has_recovered_how(item)
                and not (packer_latch and _row_is_stub_iat_capability(item))
            ],
            key=_analyst_finding_rank,
        )
    )
    deferred_behavior_rows = _prefer_named_catalog_findings(
        [
            item for item in behavior_projection_rows
            if not _finding_has_recovered_how(item)
            or (packer_latch and _row_is_stub_iat_capability(item))
        ]
    )
    if recovered_behavior_rows:
        for item in recovered_behavior_rows[:8]:
            status = str(item.get("finding_status") or item.get("status") or "CANDIDATE").upper()
            what = compact(item.get("what") or "Static behavior candidate.", 700)
            how = compact(_module_how_from_finding(item), 1400)
            target = compact(item.get("target") or "unknown target", 260)
            unknowns = compact(item.get("unknowns") or ["runtime execution and intent are not observed"], 520)
            evidence_ids = compact(list(item.get("evidence_ids", []))[:5], 260)
            protocol_lines = []
            for slot, _question in TEN_QUESTION_SLOTS:
                slot_value = _protocol_slot_value(item, slot)
                if slot_value and not _is_fun_call_sequence_dump(slot_value):
                    protocol_lines.append(f"  - {slot}: {compact(slot_value, 520)}")
            lines.extend([
                f"- `{compact(item.get('catalog_id') or item.get('finding_id') or 'behavior', 160)}` "
                f"status=**{status}** target={target}",
                f"  - What: {what}",
                f"  - How: {how}",
                f"  - Condition: {compact(item.get('conditions') or item.get('condition') or 'UNKNOWN(condition)', 520)}",
                f"  - Output: {compact(item.get('outputs') or item.get('output') or 'UNKNOWN(output)', 520)}",
                f"  - Consumer: {compact(item.get('consumers') or item.get('consumer') or 'UNKNOWN(consumer)', 520)}",
                *protocol_lines,
                f"  - Key unknowns: {unknowns}",
                f"  - Evidence: {evidence_ids}",
            ])
        if deferred_behavior_rows:
            lines.extend(["", "#### Deferred unanswered behavior leads", ""])
            for item in deferred_behavior_rows[:24]:
                missing = _deferred_missing_label(item)
                lines.append(
                    f"- `{compact(item.get('catalog_id') or item.get('finding_id') or 'behavior', 160)}` "
                    f"status=**{compact(item.get('finding_status') or item.get('status') or 'CANDIDATE', 40)}** "
                    f"target={compact(item.get('target') or 'unknown target', 160)} "
                    f"missing={missing}"
                )
    elif deferred_behavior_rows:
        lines.extend(["#### Deferred unanswered behavior leads", ""])
        for item in deferred_behavior_rows[:24]:
            missing = _deferred_missing_label(item)
            lines.append(
                f"- `{compact(item.get('catalog_id') or item.get('finding_id') or 'behavior', 160)}` "
                f"status=**{compact(item.get('finding_status') or item.get('status') or 'CANDIDATE', 40)}** "
                f"missing={missing}"
            )
    else:
        lines.append("- 未形成有 Evidence 支撑的行为级 Finding。")
    lines.extend(["", "## 3. Key Static Findings", ""])
    if findings:
        for index, finding in enumerate(findings[:8], start=1):
            verdict = finding.get("verdict") or ("CANDIDATE" if finding.get("candidate") else "SUPPORTED")
            confidence = finding.get("confidence", "UNKNOWN")
            lines.extend([
                f"### Finding {index}: {compact(finding.get('finding_id', 'static-finding'), 120)}",
                f"- Verdict: **{verdict}** | Confidence: **{confidence}**",
                f"- What: {compact(finding.get('what'), 700)}",
                f"- How: {compact(finding.get('how'), 1400)}",
                f"- Behavior status: **{finding.get('verdict')}**",
                f"- Target: {compact(finding.get('target') or 'UNKNOWN(target)', 360)}",
                f"- Condition: {compact(finding.get('conditions') or finding.get('condition') or 'UNKNOWN(condition)', 500)}",
                f"- Output: {compact(finding.get('outputs') or finding.get('output') or 'UNKNOWN(output)', 360)}",
                f"- Consumer: {compact(finding.get('consumers') or finding.get('consumer') or 'UNKNOWN(consumer)', 360)}",
                f"- Remaining unknowns: {compact(finding.get('unknowns') or 'none recorded', 600)}",
                f"- Security meaning: {compact(finding.get('security_meaning'), 700)}",
                f"- Boundary: {compact(finding.get('boundary'), 500)}",
                f"- Mechanism ID: `{finding.get('mechanism_id', 'unknown')}`",
                f"- Claim ID: `{finding.get('claim_id', 'unknown')}`",
                f"- Supporting evidence: {compact(list(finding.get('evidence_ids', []))[:5], 300)}",
                "",
            ])
    else:
        lines.append("未形成经过证据引用的核心 Finding；请查看 Unknowns / Static Boundaries。\n")

    lines.extend(["## 4. Verified Mechanisms", ""])
    verified = [
        item for item in findings
        if str(item.get("verdict", "")).upper() in {"VERIFIED", "CONFIRMED", "SUPPORTED"}
        and not item.get("candidate")
        and not (packer_latch and _is_stub_iat_capability(item.get("how") or item.get("what")))
    ]
    if verified:
        for item in verified:
            lines.append(
                f"- `{item.get('mechanism_id')}`: {compact(item.get('how'), 700)} "
                f"(evidence: {compact(list(item.get('evidence_ids', []))[:5], 240)})"
            )
    else:
        lines.append("当前没有通过验证门限的完整机制；候选结论不会升级为确凿结论。")
    candidates = [
        row for row in rows
        if row.get("type") in {"mechanism_candidate", "mechanism_link", "mechanism_observation"}
    ]
    # Keep the candidate section aligned with the analyst finding gate.  A
    # low-signal XOR window or an unresolved pointer is still available in
    # Evidence Explorer, but showing it beside concrete loader/transport
    # paths makes the report read like an import dump.  Specialist links and
    # verified rows retain their existing visibility; only generic observed
    # candidates are screened here.
    actionable_candidates = _select_actionable_candidate_mechanisms(
        [row for row in candidates if row.get("type") == "mechanism_observation"],
        limit=12,
    )
    candidates = [
        row for row in candidates
        if row.get("type") != "mechanism_observation"
    ] + actionable_candidates
    candidates = _select_mechanism_projections(candidates, limit=12)
    if packer_latch:
        candidates = [
            row for row in candidates
            if not _is_stub_iat_capability(
                " ".join(str(value) for value in (row.get("transformation_or_control") or []))
                or row.get("how")
                or row.get("what")
            )
        ]
    if candidates:
        lines.extend(["", "### Candidate Mechanisms", ""])
        for item in candidates[:12]:
            chain = " -> ".join(
                str(value) for value in item.get("transformation_or_control", []) if value
            )
            location = ""
            if item.get("function") or item.get("function_entry") or item.get("rva"):
                entry = item.get("function_entry") or item.get("rva") or "unknown"
                location = f" | location={compact(_format_function_location(item.get('function') or 'function', entry), 160)}"
            lines.extend([
                f"- `{item.get('mechanism_id')}` | status={item.get('status', 'CANDIDATE')} | field completeness={item.get('completeness', 0)}/100",
                f"  - Type: {compact(item.get('mechanism_type') or item.get('dimension') or item.get('type'), 160)}{location}",
                f"  - Input: {compact(item.get('inputs') or 'unknown', 500)}",
                f"  - Transformation/Control: {compact(chain or 'unknown', 700)}",
                f"  - Condition: {compact(item.get('conditions') or 'unknown', 500)}",
                f"  - Output: {compact(item.get('outputs') or 'UNKNOWN(output)', 500)}",
                f"  - Consumer: {compact(item.get('consumers') or 'UNKNOWN(consumer)', 500)}",
                f"  - Side Effect: {compact(item.get('side_effects') or 'UNKNOWN(side_effect)', 500)}",
                f"  - Evidence: {compact(item.get('evidence_ids', [])[:5], 300)}",
                f"  - Verification boundary: {compact(item.get('verification') or item.get('limitations') or 'static observation only', 500)}",
                "  - Note: field completeness measures populated mechanism fields; it is not verification confidence.",
            ])

    model_candidates = [
        row for row in rows
        if row.get("type") == "analytical_claim"
        and str(row.get("analysis_source", "")).casefold() == "model"
        and row.get("evidence_ids")
    ]
    lines.extend(["", "### Model-Synthesized Candidates", ""])
    if model_candidates:
        for index, row in enumerate(model_candidates[:8], start=1):
            lines.extend([
                f"- Model candidate {index}: {compact(row.get('statement') or row.get('finding'), 900)}",
                f"  - Mechanism: {compact(row.get('mechanism'), 900)}",
                f"  - Status: **{row.get('status', 'CANDIDATE')}** | Confidence: **{row.get('confidence', 'UNKNOWN')}**",
                f"  - Model call: `{row.get('model_call_id', 'unknown')}`",
                f"  - Evidence: {compact(row.get('evidence_ids', [])[:5], 300)}",
            ])
    else:
        lines.append(
            "- No model-synthesized candidate was accepted for display; model calls, "
            "rejected drafts, and evidence delivery remain available in the analysis trace."
        )
    lines.extend(["", "## 5. Reconstructed Static Behavior Flow", ""])
    lines.append("Ordered sequence, isolated-emulation status, module deep-dives and IOC are in Artifact Summary above.")
    if behavior_relation_rows:
        visible_relations = [
            row for row in behavior_relation_rows[:32]
            if not _report_is_injects_self_loop(row)
        ]
        if visible_relations:
            lines.extend(["### Evidence-backed Behavior Relations", ""])
            for relation in visible_relations:
                source = compact(
                    relation.get("source_object") or relation.get("source_artifact_id") or "unknown source",
                    260,
                )
                target = compact(
                    relation.get("target_object") or relation.get("target_artifact_id") or "unknown target",
                    260,
                )
                relation_name = compact(relation.get("relation_type") or relation.get("relation"), 120)
                validation = str(relation.get("validation_status") or relation.get("status") or "UNKNOWN").upper()
                support = compact(list(relation.get("evidence_ids", []))[:5], 260)
                edge_note = "behavior edge" if relation.get("is_behavior_edge") else "artifact/object relation"
                lines.append(
                    f"- `{source}` --[{relation_name}; {validation}]--> `{target}` "
                    f"({edge_note}; evidence={support})"
                )
                if relation.get("unknowns"):
                    lines.append(f"  - unknowns: {compact(relation.get('unknowns'), 500)}")
    chains = [row for row in rows if row.get("type") == "mechanism_chain" and row.get("rendered")]
    if not chains and isinstance(assessment, dict):
        nested = assessment.get("findings", [])
        chains = [
            row for row in nested
            if isinstance(row, dict)
            and row.get("type") == "mechanism_chain"
            and row.get("rendered")
        ]
    if chains:
        for chain in chains[:5]:
            lines.append(f"- {compact(chain.get('rendered'), 1200)} ({chain.get('status', 'unknown')})")
    else:
        independent = []
        if isinstance(assessment, dict):
            independent = [
                str(path)
                for row in assessment.get("findings", [])
                if isinstance(row, dict) and row.get("type") == "mechanism_chain"
                for path in row.get("independent_paths", [])
                if path
            ]
        if independent:
            lines.append("未恢复出跨函数有序因果链；以下为相互独立的静态观察路径：")
            for path in independent[:8]:
                lines.append(f"- {compact(path, 1200)} (independent observation)")
        else:
            lines.append("未恢复出有序的静态行为链。")
    predictions = [row for row in rows if row.get("type") == "static_simulation_prediction"]
    if predictions:
        lines.extend(["", "### Static Abstract Execution Prediction", ""])
        for prediction in predictions[:8]:
            function = compact(prediction.get("function") or prediction.get("entry"), 180)
            lines.append(
                f"- {function}: runtime_observed={prediction.get('runtime_observed', False)}, "
                f"confidence={prediction.get('confidence', 'UNKNOWN')}"
            )
            steps = prediction.get("predicted_steps", [])
            if isinstance(steps, list):
                labels = [
                    str(step.get("api") or step.get("operation"))
                    for step in steps[:8]
                    if isinstance(step, dict) and (step.get("api") or step.get("operation"))
                ]
                if labels:
                    lines.append(f"  - predicted path: {' -> '.join(labels)}")

    decode_results = [row for row in rows if row.get("type") == "decode_result"]
    if decode_results:
        lines.extend(["", "### Static Decode Result", ""])
        for index, result in enumerate(decode_results[:12], start=1):
            lines.extend([
                f"- Result {index}: evidence=`{result.get('evidence_id', 'unknown')}` | "
                f"status=**{result.get('verification_status', 'UNKNOWN')}**",
                f"  - location: function_entry={compact(result.get('function_entry'), 120)}, "
                f"rva={compact(result.get('rva'), 80)}, file_offset={compact(result.get('file_offset'), 80)}",
                f"  - formula: {compact(result.get('formula') or 'unknown', 180)} | "
                f"length={compact(result.get('length'), 80)} | printable_ratio={compact(result.get('printable_ratio'), 80)}",
                f"  - markers: {compact(result.get('markers') or [], 240)}",
            ])
            if result.get("decoded_preview"):
                lines.append(f"  - decoded preview: {compact(result.get('decoded_preview'), 700)}")
            if result.get("decoded_strings"):
                lines.append(f"  - decoded strings: {compact(result.get('decoded_strings'), 700)}")
            lines.extend([
                f"  - consumer status: {compact(result.get('consumer_status'), 160)}",
                f"  - static consumers: {compact(result.get('consumer_candidates') or [], 700)}",
                f"  - consumer evidence: {compact(result.get('consumer_evidence_ids') or [], 300)}",
                f"  - source evidence: {compact(result.get('source_evidence_ids') or [], 300)}",
                f"  - boundary: {compact(result.get('boundary'), 700)}",
                "",
            ])

    argument_traces = [row for row in rows if row.get("type") == "api_argument_recovery"]
    if argument_traces:
        lines.extend(["", "### Static API Argument Recovery", ""])
        for trace in argument_traces[:16]:
            args = trace.get("arguments", [])
            visible_args, unresolved_slots = _partition_arguments(args)
            recovered_count = (
                len(visible_args)
                if isinstance(args, (list, tuple))
                else int(trace.get("recovered_argument_count", 0) or 0)
            )
            lines.extend([
                f"- `{compact(trace.get('api'), 180)}` at `{compact(trace.get('callsite'), 80)}` "
                f"in `{compact(trace.get('function'), 180)}` ({compact(trace.get('function_entry'), 80)})",
                f"  - consumer: {compact(trace.get('consumer'), 240)}",
                f"  - recovered arguments: {compact(recovered_count, 80)}",
            ])
            for arg in visible_args[:8]:
                lines.append(
                    f"  - arg{arg.get('index')} ({arg.get('register')}): "
                    f"{compact(arg.get('value'), 360)} [{arg.get('source_kind') or 'unknown'}]"
                )
            if unresolved_slots:
                lines.append(f"  - unresolved argument slots: {unresolved_slots}")
            reported_count = int(trace.get("recovered_argument_count", 0) or 0)
            if reported_count != recovered_count and reported_count:
                lines.append(f"  - recovered argument total: {compact(reported_count, 80)}")
            if trace.get("downstream_consumers"):
                lines.append(f"  - downstream consumers: {compact(trace.get('downstream_consumers'), 400)}")
            lines.append(f"  - evidence: {compact(trace.get('source_evidence_ids', [])[:8], 300)}")

    semantic_summaries = [
        row for row in rows if row.get("type") == "function_semantic_summary"
    ]
    if semantic_summaries:
        lines.extend(["", "### Function-Level Semantic Recovery", ""])
        # Keep the analyst-facing report bounded around the highest-priority
        # function rows. The immutable Evidence ledger still contains every
        # summary, so truncation here is presentation-only and must be visible
        # to the reviewer.
        visible_summaries = semantic_summaries[:40]
        for summary_row in visible_summaries:
            lines.extend([
                f"- `{compact(_format_function_location(summary_row.get('function'), summary_row.get('function_entry')), 240)}` "
                f"confidence={compact(summary_row.get('confidence'), 40)} "
                f"evidence=`{compact(summary_row.get('evidence_id'), 80)}`",
            ])
            calls = summary_row.get("call_sequence", [])
            if isinstance(calls, list) and calls:
                lines.append("  - ordered static calls:")
                # Navigation labels remain in the immutable ledger, while the
                # report keeps semantic calls and concrete argument leads.
                meaningful_calls, omitted_calls = _meaningful_semantic_calls(calls)
                internal_clues, omitted_internal_calls = _unresolved_internal_call_clues(calls)
                for call in meaningful_calls[:16]:
                    if not isinstance(call, dict):
                        continue
                    api_name, api_category = _semantic_call_label(call)
                    lines.append(
                        f"    - {compact(api_name, 160)} @ {compact(call.get('callsite'), 90)} "
                        f"[{compact(api_category, 80)}]"
                    )
                    args = call.get("arguments", [])
                    visible_args, unresolved_slots = _partition_arguments(args)
                    for arg in visible_args[:6]:
                        lines.append(
                            f"      - arg{arg.get('argument_index')}: {compact(arg.get('value'), 260)} "
                            f"[{compact(arg.get('source_kind') or 'unknown', 80)}]"
                        )
                    if unresolved_slots:
                        lines.append(f"      - unresolved argument slots: {unresolved_slots}")
                if omitted_calls:
                    lines.append(
                        f"  - omitted low-information navigation calls: {omitted_calls} "
                        "(full static ledger retained)"
                    )
                if omitted_internal_calls:
                    lines.append(
                        f"  - omitted_unresolved_internal_calls: {omitted_internal_calls} "
                        "(parameter clues summarized; full static ledger retained)"
                    )
                    if internal_clues:
                        lines.append("  - unresolved internal parameter clues:")
                        for clue in internal_clues:
                            clue_arguments = clue.get("arguments", [])
                            rendered_arguments = "; ".join(
                                f"arg{argument.get('argument_index', argument.get('index'))}="
                                f"{compact(argument.get('value'), 260)} "
                                f"[{compact(argument.get('source_kind') or 'unknown', 80)}]"
                                for argument in clue_arguments
                                if isinstance(argument, Mapping)
                            )
                            if rendered_arguments:
                                lines.append(
                                    f"    - callsite {compact(clue.get('callsite') or 'unknown', 90)}: "
                                    f"{rendered_arguments}"
                                )
            conditions = summary_row.get("conditions", [])
            if isinstance(conditions, list) and conditions:
                lines.append("  - predicates:")
                for condition in conditions[:8]:
                    if isinstance(condition, dict):
                        lines.append(
                            f"    - {compact(condition.get('address'), 90)}: {compact(condition.get('text'), 320)} "
                            "[outcome UNKNOWN]"
                        )
            consumers = summary_row.get("consumers", [])
            if consumers:
                lines.append(f"  - downstream consumers: {compact(consumers, 700)}")
            if summary_row.get("unknowns"):
                lines.append(f"  - unknowns: {compact(summary_row.get('unknowns'), 900)}")
            lines.append(f"  - boundary: {compact(summary_row.get('boundary'), 600)}")
        omitted_summaries = len(semantic_summaries) - len(visible_summaries)
        if omitted_summaries > 0:
            lines.append(
                f"- omitted lower-priority function summaries: {omitted_summaries} "
                "(full static ledger retained)"
            )

    # The seed map is the durable bridge from parser observations to the
    # investigation scheduler.  Keep it visible in the analyst projection so
    # reviewers can verify that analysis started from bounded questions rather
    # than a raw field dump; full source Evidence remains in the ledger.
    seed_rows = [row for row in rows if row.get("type") == "investigation_seed_map"]
    lines.extend(["", "## Investigation Seed Map", ""])
    if seed_rows:
        for seed in seed_rows[:16]:
            lines.append(
                f"- Artifact `{compact(seed.get('artifact_id'), 120)}`: "
                f"{compact(seed.get('cluster_count', 0), 40)} clusters "
                f"(visible; total discovered="
                f"{compact(seed.get('total_cluster_count', seed.get('cluster_count', 0)), 40)}) "
                f"(high-value={compact(seed.get('high_value_cluster_count', 0), 40)})"
            )
            deferred_count = int(seed.get("deferred_cluster_count", 0) or 0)
            if deferred_count:
                lines.append(
                    f"  - deferred by admission window: {deferred_count} "
                    "(not treated as a negative finding; schedule in a continuation run)"
                )
            clusters = seed.get("clusters", [])
            if isinstance(clusters, list):
                for cluster in clusters[:64]:
                    if not isinstance(cluster, dict):
                        continue
                    lines.append(
                        f"  - `{compact(cluster.get('id', 'cluster'), 120)}` "
                        f"[{compact(cluster.get('category', 'generic'), 80)}] "
                        f"priority={compact(cluster.get('priority', 0), 40)}: "
                        f"{compact(cluster.get('question'), 600)}"
                    )
                    hypotheses = cluster.get("hypotheses", [])
                    if hypotheses:
                        lines.append(f"    - competing hypotheses: {compact(hypotheses, 500)}")
                    evidence_ids = cluster.get("evidence_ids", [])
                    if evidence_ids:
                        lines.append(f"    - evidence: {compact(evidence_ids[:8], 300)}")
        lines.append("- static_only: true")
    else:
        lines.append("- 未生成有界调查种子；请查看 Evidence Explorer 中的原始静态证据。")

    lines.extend(["", "## 6. IOC / Indicators", ""])
    ioc_rows = [row for row in rows if row.get("type") in {"indicator", "ioc"}]
    if ioc_rows:
        for row in ioc_rows[:40]:
            value = row.get("value") or row.get("indicator") or row.get("statement")
            category = row.get("category") or row.get("indicator_type") or "static_indicator"
            confidence = row.get("confidence") or "UNKNOWN"
            evidence_ids = list(row.get("evidence_ids", []))[:5] if isinstance(row.get("evidence_ids"), list) else []
            lines.append(
                f"- `{compact(category, 80)}` **{compact(value, 500)}** "
                f"(classification={row.get('classification', 'STATIC_DERIVED')}, confidence={confidence})"
            )
            if evidence_ids:
                lines.append(f"  - Evidence: {compact(evidence_ids, 300)}")
            if row.get("source"):
                lines.append(f"  - Source: {compact(row.get('source'), 240)}")
            if row.get("boundary"):
                lines.append(f"  - Boundary: {compact(row.get('boundary'), 500)}")
    else:
        lines.append("未提取到可安全报告的静态 IOC。")

    lines.extend(["", "## 7. Detection / Hunting Opportunities", ""])
    hunting = [row for row in rows if row.get("type") in {"hunting_opportunity", "detection_opportunity"}]
    if hunting:
        for row in hunting[:20]:
            lines.append(f"- {compact(row.get('statement') or row.get('description') or row.get('value'), 700)}")
    else:
        lines.append("基于当前证据可执行的 Hunting Suggestions 尚未形成。")

    lines.extend(["", "## 8. ATT&CK Reference", ""])
    techniques: dict[str, str] = {}
    for row in rows:
        prefixes = _blocked_attack_prefixes(row) if isinstance(row, Mapping) else ()
        for technique in row.get("attack_techniques", []) if isinstance(row.get("attack_techniques"), list) else []:
            if not isinstance(technique, dict) or not technique.get("technique_id"):
                continue
            if _technique_matches_prefix(technique.get("technique_id"), prefixes):
                continue
            techniques[str(technique["technique_id"])] = str(technique.get("name") or "")
    if techniques:
        for technique_id, name in sorted(techniques.items()):
            lines.append(f"- `{technique_id}` {name}".rstrip())
    else:
        lines.append("未形成基于 Supported Claim 或 Verified Mechanism 的 ATT&CK 映射。")

    lines.extend(["", "## 9. Unknowns / Static Boundaries", ""])
    unknowns = [row for row in rows if row.get("type") in {"analysis_limitation", "next_step"}]
    unclosed_catalog = []
    matrix_row = next((row for row in rows if row.get("type") == "catalog_behavior_matrix"), {})
    if isinstance(matrix_row, dict):
        unclosed_catalog = [
            item for item in matrix_row.get("unclosed_high_value", []) if isinstance(item, dict)
        ]
    s4_rows = []
    if isinstance(quality, dict):
        raw_s4 = quality.get("s4_orchestration")
        if isinstance(raw_s4, list):
            s4_rows = [row for row in raw_s4 if isinstance(row, dict)]
    wrote_boundary = False
    if s4_rows:
        lines.extend(["#### S4 orchestration", ""])
        for row in s4_rows[:24]:
            status, gap = _s4_display_status(row)
            lines.append(
                f"- `{compact(row.get('thread_id') or 'thread', 160)}` "
                f"status=**{status}** "
                f"gap={compact(gap, 500)}"
            )
        lines.append("")
        wrote_boundary = True
    if unknowns or unclosed_catalog:
        for row in unknowns[:30]:
            lines.append(f"- {compact(row.get('detail') or row.get('reason') or row.get('action'), 900)}")
        for item in unclosed_catalog[:12]:
            status = str(item.get("status") or "UNKNOWN")
            reason = str(item.get("reason") or item.get("catalog_id") or "")
            lines.append(
                f"- `{compact(item.get('catalog_id') or 'catalog', 80)}` "
                f"status=**{status}** {compact(reason, 900)}"
            )
        wrote_boundary = True
    if not wrote_boundary:
        lines.append("无额外限制记录；这不表示运行时行为已被观察。")
    lines.extend(["", "## 10. Analysis Coverage", ""])
    if semantic:
        for key, value in semantic.items():
            lines.append(f"- {key}: {value}")
    if coverage.get("score") is not None:
        lines.append(f"- semantic score: {coverage.get('score')}")
    if isinstance(pipeline, dict):
        if pipeline.get("score") is not None:
            lines.append(f"- pipeline score: {pipeline.get('score')}")
        pipeline_dimensions = pipeline.get("dimensions", {})
        if isinstance(pipeline_dimensions, dict):
            for key, value in pipeline_dimensions.items():
                lines.append(f"- pipeline {key}: {value}")
    gaps = coverage.get("gaps", [])
    if gaps:
        lines.append(f"- gaps: {compact(gaps, 1200)}")
    lines.extend([
        "",
        "### Analysis Traceability",
        "",
        f"- Evidence records: {len((document.get('trace') or {}).get('evidence_ids', [])) if isinstance(document.get('trace'), dict) else 0}",
        f"- Claim records: {len((document.get('trace') or {}).get('claim_ids', [])) if isinstance(document.get('trace'), dict) else 0}",
        f"- Tool runs: {len((document.get('trace') or {}).get('tool_run_ids', [])) if isinstance(document.get('trace'), dict) else 0}",
        "- Investigation persistence: `PERSISTED_INVESTIGATION`; state transitions, actions and evidence remain queryable.",
        "- 评测基准报告：已隔离，仅用于分析完成后的对比评估，不作为本次分析输入。",
        "- 完整账本未内嵌到主报告，按 ID 可追溯到 Evidence Explorer。",
        "",
    ])
    rendered = "\n".join(lines).rstrip() + "\n"
    violations = static_wording_violations(rendered)
    if violations:
        raise ValueError("static-only wording gate rejected report: " + ", ".join(violations))
    # A projection should naturally fit. If a pathological model string is
    # still too large, truncate only the prose body and retain the gate note.
    return apply_report_display_budget(rendered)


def markdown_to_docx(markdown: str) -> bytes:
    document = Document()
    for line in markdown.splitlines():
        if line.startswith("# "):
            document.add_heading(line[2:], level=0)
        elif line.startswith("## "):
            document.add_heading(line[3:], level=1)
        elif line.startswith("### "):
            document.add_heading(line[4:], level=2)
        elif line.startswith("- "):
            document.add_paragraph(line[2:], style="List Bullet")
        elif line.startswith("> "):
            document.add_paragraph(line[2:], style="Quote")
        elif line:
            document.add_paragraph(line)
    output = io.BytesIO()
    document.save(output)
    return output.getvalue()


def markdown_to_pdf(markdown: str) -> bytes:
    font_name = "STSong-Light"
    try:
        pdfmetrics.getFont(font_name)
    except KeyError:
        pdfmetrics.registerFont(UnicodeCIDFont(font_name))
    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        "ChineseBody",
        parent=styles["BodyText"],
        fontName=font_name,
        fontSize=9,
        leading=14,
        alignment=TA_LEFT,
        wordWrap="CJK",
    )
    title = ParagraphStyle("ChineseTitle", parent=body, fontSize=18, leading=24, spaceAfter=8)
    heading = ParagraphStyle("ChineseHeading", parent=body, fontSize=13, leading=18, spaceBefore=8)
    output = io.BytesIO()
    pdf = SimpleDocTemplate(
        output,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="静态分析报告",
    )
    story: list[object] = []
    for line in markdown.splitlines():
        if line.startswith("# "):
            if story:
                story.append(PageBreak())
            story.append(Paragraph(escape(line[2:]), title))
        elif line.startswith("## "):
            story.append(Paragraph(escape(line[3:]), heading))
        elif line.startswith("### "):
            story.append(Paragraph(escape(line[4:]), body))
        elif line:
            cleaned = line[2:] if line.startswith(("- ", "> ")) else line
            story.append(Paragraph(escape(cleaned), body))
        else:
            story.append(Spacer(1, 3 * mm))
    pdf.build(story)
    return output.getvalue()
