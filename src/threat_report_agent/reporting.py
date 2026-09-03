from __future__ import annotations

import io
import json
import re
import hashlib
from html import escape
from typing import Any, Mapping

from docx import Document
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer
from threat_report_agent.product_certification import static_wording_violations
from threat_report_agent.mechanism_completeness import (
    has_semantic_value,
    is_navigation_value,
    mechanism_completeness_score,
    mechanism_is_critical_ready,
)
from threat_report_agent.deep_analysis_quality import deep_analysis_metrics


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

REPORT_MAX_MARKDOWN_BYTES = 40 * 1024
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
_RAW_DUMP_MARKERS = (
    "## 完整 Strings",
    "## Full Strings",
    "## 完整 Imports",
    "## Full Imports",
    "function_similarity dump",
)


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
        if isinstance(mechanism, dict):
            status = str(mechanism.get("status", "")).upper()
            mechanism_id = str(mechanism.get("id", ""))
            claim_id = str(mechanism.get("claim_id", ""))
            evidence_ids = [str(item) for item in mechanism.get("evidence_ids", []) if item]
            verifier = mechanism.get("verifier", {})
            target = str(mechanism.get("target", "mechanism"))
            how = " -> ".join(str(item) for item in mechanism.get("transformation_or_control", []))
        else:
            status = str(getattr(mechanism, "status", "")).upper()
            mechanism_id = str(getattr(mechanism, "id", ""))
            claim_id = str(getattr(mechanism, "claim_id", ""))
            evidence_ids = [str(item) for item in getattr(mechanism, "evidence_ids", ()) if item]
            verifier = getattr(mechanism, "verifier", {}) or {}
            target = str(getattr(mechanism, "target", "mechanism"))
            how = " -> ".join(str(item) for item in getattr(mechanism, "transformation_or_control", ()))
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
        claim = claim_by_id.get(claim_id)
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
        }.get(mechanism_type, f"The verified static mechanism exposes a security-relevant {mechanism_type.replace('_', ' ')} capability; the cited data/control path is the appropriate detection pivot.")
        findings.append({
            "type": "security_finding",
            "critical": True,
            "verdict": "SUPPORTED",
            "confidence": getattr(claim, "confidence", "HIGH"),
            "finding_id": f"finding:{mechanism_id}",
            "mechanism_id": mechanism_id,
            "claim_id": claim_id,
            "evidence_ids": valid_evidence[:5],
            "what": statement or f"Verified mechanism targets {target}.",
            "how": how or str(getattr(claim, "mechanism", "")),
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
        action = str(getattr(claim, "action", "static_mechanism"))
        object_name = str(getattr(claim, "object", "static target"))
        mechanism_text = str(getattr(claim, "mechanism", "static evidence path"))
        condition = str(getattr(claim, "condition", "static evidence only"))
        inputs = tuple(dict.fromkeys(
            item for item in text_parts
            if any(token in item.casefold() for token in ("resource", "encoded", "cipher", "input", "buffer", "string", "payload"))
        ))
        if not inputs and any("string" in kind or "resource" in kind for kind in kinds):
            inputs = ("statically recovered resource/string/buffer",)
        transforms = tuple(dict.fromkeys(
            ([mechanism_text] if not is_navigation_value(mechanism_text) else [])
            + [item for item in text_parts if any(token in item.casefold() for token in ("xor", "decode", "decrypt", "decompress", "transform", "resolve", "permission"))]
            + ([" -> ".join(api_names[:8])] if api_names and not is_navigation_value(api_names) else [])
        ))
        outputs = (object_name,) if object_name else ()
        consumers = tuple(dict.fromkeys(
            api_names[-4:]
            if not is_navigation_value(api_names)
            else ()
        ))
        side_effect_map = {
            "may_decode_or_decrypt": "prepares transformed configuration or payload data",
            "decompresses_or_decodes": "prepares decompressed or decoded data for a downstream consumer",
            "extracts_resource_payload": "extracts embedded resource bytes for later processing",
            "may_load_or_prepare_memory": "prepares a module or executable memory region for a downstream call",
            "may_spoof_parent_process": "constructs alternate parent-process startup attributes",
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
        projection = {
            "type": "mechanism_candidate",
            "mechanism_id": f"candidate-mechanism:{claim.id}",
            "claim_id": claim.id,
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
        kind = str(getattr(link, "kind", "")).casefold()
        mechanism_type = _STATIC_LINK_MECHANISM_TYPES.get(kind)
        if mechanism_type is None:
            continue
        value = getattr(link, "value", {})
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
        artifact_id = str(getattr(link, "artifact_id", "") or "")
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
            consumers = values("consumer", fallback="WinHttpSendRequest")
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

        provenance = {
            "link_evidence_id": str(link_id),
            "source_evidence_ids": source_ids,
            "nature": str(getattr(link, "nature", "STATIC_DERIVED")),
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
        projection = {
                "type": "mechanism_link",
                "mechanism_id": mechanism_id,
                "mechanism_type": mechanism_type,
                "dimension": mechanism_type,
                "artifact_id": artifact_id or None,
                "status": "CANDIDATE",
                "target": artifact_id or mechanism_type,
                "inputs": inputs,
                "transformation_or_control": transforms,
                "conditions": [
                    "static linked evidence only; runtime reachability and intent are unobserved"
                ],
                "outputs": outputs,
                "consumers": consumers,
                "side_effects": side_effects,
                "evidence_ids": list(dict.fromkeys([str(link_id), *source_ids]))[:12],
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
    "mechanism_decode_window",
    "mechanism_memory_permission",
    "mechanism_environment_check",
    "mechanism_dynamic_resolution",
    "indirect_function_pointer_link",
}


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
        chain_type = str(value.get("chain_type") or kind).strip()
        mechanism_type = {
            "mechanism_chain": chain_type.upper(),
            "mechanism_decode_window": "DECODE_TRANSFORM",
            "mechanism_memory_permission": "MEMORY_PERMISSION_CHANGE",
            "mechanism_environment_check": "ENVIRONMENT_CHECK",
            "mechanism_dynamic_resolution": "DYNAMIC_API_RESOLUTION",
            "indirect_function_pointer_link": "INDIRECT_API_DISPATCH",
        }[kind]
        function = str(value.get("function") or anchor.get("function") or "").strip()
        function_entry = str(
            value.get("entry") or value.get("entry_rva") or anchor.get("function_entry")
            or anchor.get("entry") or ""
        ).strip()
        if not function and function_entry:
            function = f"FUN_{function_entry}"
        rva = value.get("entry_rva", anchor.get("rva"))
        location = f"{function or 'function'}@{function_entry or 'RVA unknown'}"

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

        if kind == "mechanism_chain":
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
            transformation = " -> ".join(apis or ["LoadLibrary", "GetProcAddress"])
            inputs = ["module name and exported entry-point name"]
            outputs = ["resolved function pointer"]
            consumers = ["indirect call/jump consumer"]
            side_effect = "may hide API imports from the static import table; runtime resolution is unobserved"
        else:
            resolver = str(value.get("resolver") or "GetProcAddress")
            consumer = str(value.get("consumer") or "indirect CALL/JMP")
            storage = str(value.get("storage") or "temporary storage")
            transformation = f"{resolver} @ {value.get('resolver_callsite', 'callsite')} -> {storage} -> {consumer} @ {value.get('consumer_callsite', 'callsite')}"
            inputs = ["module/entry-point identity supplied to the resolver"]
            outputs = ["function pointer stored in register or memory"]
            consumers = [consumer]
            side_effect = "may dispatch to an API without a direct import; target API identity is unresolved statically"

        source_ids = [str(evidence_id)]
        source_ids.extend(str(item_id) for item_id in text_list(value.get("source_evidence_ids")))
        projection = {
            "type": "mechanism_observation",
            "mechanism_id": f"observed-mechanism:{str(evidence_id)}",
            "mechanism_type": mechanism_type,
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
        projection["ordered"] = bool(kind == "mechanism_chain" and len(step_names) >= 2)
        projection["observation_nature"] = nature
        projection["completeness"] = mechanism_completeness_score(projection)
        projections.append(projection)
    # Keep the first occurrence for identical observations; the evidence
    # ledger still retains every source row for full traceability.
    deduped: list[dict[str, object]] = []
    seen: set[tuple[object, ...]] = set()
    for row in projections:
        key = (
            row.get("mechanism_type"), row.get("target"),
            tuple(row.get("transformation_or_control", [])),
            tuple(row.get("consumers", [])),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    priority = {
        "mechanism_chain": 0,
        "mechanism_decode_window": 1,
        "mechanism_dynamic_resolution": 2,
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
    findings = [row for row in module_rows if row.get("type") == "security_finding"]
    for index, finding in enumerate(findings, start=1):
        if not finding.get("mechanism_id") or not finding.get("claim_id") or not finding.get("evidence_ids"):
            violations.append(f"core finding {index} is not fully traceable")
    top_level_sections = document.get("report_sections")
    if isinstance(top_level_sections, list):
        sections = top_level_sections
    else:
        report_structure = next((row for row in module_rows if row.get("type") == "report_structure"), None)
        sections = report_structure.get("sections", []) if isinstance(report_structure, dict) else []
    if tuple(sections) != REPORT_V3_REQUIRED_SECTIONS:
        violations.append("Report V3 required sections are missing or reordered")
    return violations


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
        "title": MODULE_TITLES[module_id],
        "summary": summary,
        "analysis_status": (
            "COMPLETED_WITH_FINDINGS" if materialized_rows else "COMPLETED_NO_FINDINGS"
        ),
        "finding_count": len(materialized_rows),
        "rows": materialized_rows,
    }


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
                    for item in group[:1]
                ],
                "samples_truncated": len(group) > 1,
            }
        )
    if len(grouped) > len(summaries):
        summaries.append({
            "type": "evidence_group_overflow",
            "omitted_group_count": len(grouped) - len(summaries),
            "reason": "bounded primary report; query Evidence Explorer for the complete ledger",
        })
    return summaries


def _claim_row(
    claim: Any,
    links_by_claim: dict[str, list[str]],
    evidence_by_id: dict[str, Any] | None = None,
) -> dict[str, object]:
    """Render a Claim as an analyst finding instead of a database record."""
    evidence_ids = links_by_claim.get(claim.id, [])
    evidence_by_id = evidence_by_id or {}
    evidence_samples = []
    for evidence_id in evidence_ids[:6]:
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
    return {
        "type": "analytical_claim",
        "module": claim.module,
        "claim_id": claim.id,
        "analysis_source": (
            "model" if getattr(claim, "model_call_id", None) else "deterministic_static_rules"
        ),
        "model_call_id": getattr(claim, "model_call_id", None),
        "finding": claim.statement,
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


def _build_assessment(
    *, task: Any, artifacts: list[Any], claims: list[Any],
    links_by_claim: dict[str, list[str]], evidence_by_id: dict[str, Any], model_calls: list[Any],
    mechanisms: list[Any] | None = None,
    mechanism_projections: list[dict[str, object]] | None = None,
) -> tuple[str, list[dict[str, object]]]:
    """Build a concise, evidence-backed assessment for the report front page."""
    behavior_claims = [item for item in claims if item.module != "static_triage"]
    analyst_claims = [
        item for item in claims
        if not (
            item.module == "static_triage"
            and str(getattr(item, "action", "")).casefold() in {"prioritizes", "matches"}
        )
        and not _is_reference_noise({
            "action": getattr(item, "action", ""),
            "statement": getattr(item, "statement", ""),
            "mechanism": getattr(item, "mechanism", ""),
        })
    ]
    model_claims = [item for item in claims if getattr(item, "model_call_id", None)]
    modules = {item.module for item in behavior_claims}
    risk = "HIGH" if len(modules) >= 3 else "MEDIUM" if behavior_claims else "LOW"
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
            path = f"{target}: {transform}"
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
    summary = (
        f"Static assessment: {risk} confidence of suspicious behavior indicators. "
        f"The task produced {len(analyst_claims)} evidence-backed analytical claims across {len(artifacts)} artifacts "
        f"(source={source}, outcome={task.outcome or 'UNKNOWN'}). "
        f"Mechanism chain: {mechanism_chain}. "
        "This is a static hypothesis set, not proof of runtime execution."
    )
    rows: list[dict[str, object]] = [{
        "type": "assessment",
        "verdict": "SUSPICIOUS_STATIC_INDICATORS" if behavior_claims else "NO_BEHAVIOR_INDICATORS_FOUND",
        "risk": risk,
        "confidence_basis": "number and diversity of evidence-backed Claims",
        "finding_count": len(analyst_claims),
        "behavior_module_count": len(modules),
        "model_claim_count": len(model_claims),
        "model_call_count": len(model_calls),
        "static_only": True,
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
        rows.append({
            "type": "next_step",
            "priority": "P1",
            "action": "Resolve unsupported or decoded payloads and rerun function-level parsing; validate hypotheses with a controlled dynamic phase.",
            "reason": "The current result is static-only and has explicit analysis limitations.",
        })
    return summary, rows


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
    # Observation rows are the most specific static signal available to the
    # analyst.  Put them ahead of correlated links and generic Claims so the
    # bounded report preserves function/RVA and concrete API/data paths.
    mechanism_projections = observed_projections + static_link_projections + [
        item
        for item in mechanism_projections
        if item.get("type") != "mechanism_link"
    ]
    assessment_summary, assessment_rows = _build_assessment(
        task=task,
        artifacts=artifacts,
        claims=claims,
        links_by_claim=links_by_claim,
        evidence_by_id=evidence_by_id,
        model_calls=model_calls,
        mechanisms=mechanisms,
        mechanism_projections=mechanism_projections,
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
        investigation_threads=[
            item if isinstance(item, Mapping) else {"id": getattr(item, "id", ""), "state": getattr(item, "state", "")}
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
    all_modules["input_manifest"] = _module(
        "input_manifest",
        "四类输入保持分区；评测基准报告不属于任何分析输入通道。",
        [
            {
                "channel": "任务请求",
                "status": "frozen",
                "source": request.get("task_request", {}),
            },
            {
                "channel": "样本包",
                "status": "frozen",
                "source": request.get("sample_package", {}),
            },
            {
                "channel": "背景上下文",
                "status": "isolated",
                "source": request.get("background_context", {}),
            },
            {
                "channel": "知识快照",
                "status": "versioned",
                "source": request.get("knowledge_snapshot", {}),
            },
            {
                "channel": "评测基准报告",
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
        # Empty traces add no analyst value when the callsite is already
        # represented by the mechanism chain.  Keep them in the Evidence
        # ledger, but do not repeat sixteen identical "nothing recovered"
        # rows in the primary report.  Some parsers emit placeholder dicts,
        # so check for meaningful fields rather than list non-emptiness.
        has_meaningful_args = any(
            arg.get("value") not in (None, "", "UNKNOWN")
            or arg.get("resolved")
            or arg.get("source_instruction")
            for arg in normalized_args
        )
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
        for item in module_evidence.get("static_triage", [])
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
                    for cluster in clusters[:12]
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
    all_modules["behavior_attack"] = _module(
        "behavior_attack",
        "ATT&CK 映射由原子 Behavior Claim 推导；正式 Security Finding 仅来自 VERIFIED Mechanism。",
        attack_chain_rows[:64]
        + [
            {
                "claim_id": item.id,
                "subject": item.subject,
                "action": item.action,
                "object": item.object,
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
            for item in claims[:32]
        ],
    )
    verified_findings = build_verified_security_findings(mechanisms, claims, evidence_by_id)
    all_modules["behavior_attack"]["rows"].extend(verified_findings)
    # Keep mechanism-shaped candidates visible to the analyst without
    # promoting them to Security Findings. This gives the report useful HOW
    # detail even when the specialist verifier cannot close the mechanism.
    verified_by_claim = {
        str(getattr(item, "claim_id", item.get("claim_id") if isinstance(item, dict) else "")): item
        for item in (mechanisms or [])
        if getattr(item, "claim_id", None) or (isinstance(item, dict) and item.get("claim_id"))
    }
    verified_scopes: set[tuple[str, str, str, str]] = set()
    verified_evidence_by_type: dict[str, set[str]] = {}
    for verified in (mechanisms or []):
        if isinstance(verified, Mapping):
            verifier = verified.get("verifier") if isinstance(verified.get("verifier"), Mapping) else {}
            mechanism_type = str(verified.get("mechanism_type") or verifier.get("mechanism_type") or "").upper()
            function_entry = str(verified.get("function_entry") or verified.get("rva") or "")
            function = str(verified.get("function") or "")
            artifact_id = str(verified.get("artifact_id") or "")
            verified_evidence_ids = {
                str(item) for item in verified.get("evidence_ids", []) if item
            }
        else:
            verifier = getattr(verified, "verifier", {}) or {}
            mechanism_type = str(getattr(verified, "mechanism_type", "") or (verifier.get("mechanism_type") if isinstance(verifier, Mapping) else "")).upper()
            function_entry = str(getattr(verified, "function_entry", "") or getattr(verified, "rva", "") or "")
            function = str(getattr(verified, "function", "") or "")
            artifact_id = str(getattr(verified, "artifact_id", "") or "")
            verified_evidence_ids = {
                str(item) for item in (getattr(verified, "evidence_ids", ()) or ()) if item
            }
        if mechanism_type and (function_entry or function):
            verified_scopes.add((mechanism_type, function_entry, function, artifact_id))
        if mechanism_type and verified_evidence_ids:
            verified_evidence_by_type.setdefault(mechanism_type, set()).update(verified_evidence_ids)
    for projection in mechanism_projections:
        projection_type = str(projection.get("mechanism_type", "")).upper()
        projection_entry = str(projection.get("function_entry") or projection.get("rva") or "")
        projection_function = str(projection.get("function") or "")
        projection_artifact = str(projection.get("artifact_id") or "")
        projection_evidence_ids = {
            str(item) for item in projection.get("evidence_ids", []) if item
        }
        if (
            str(projection.get("status", "")).upper() == "CANDIDATE"
            and projection_type
            and (
                (
                    (projection_entry or projection_function)
                    and (projection_type, projection_entry, projection_function, projection_artifact) in verified_scopes
                )
                or bool(projection_evidence_ids & verified_evidence_by_type.get(projection_type, set()))
            )
        ):
            projection["suppressed_by_verified"] = True
            continue
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
    static_iocs: list[dict[str, object]] = []
    hunting_rows: list[dict[str, object]] = []
    for item in closed_projections:
        evidence_ids = list(item.get("evidence_ids", []))[:8]
        target = str(item.get("target", "static mechanism"))
        action_text = " ".join(str(value) for value in item.get("transformation_or_control", []))
        lower = action_text.casefold()
        if any(token in lower for token in ("http", "socket", "network", "endpoint")):
            static_iocs.append({"type": "STATIC_DERIVED", "value": target, "source": "verified network mechanism", "evidence_ids": evidence_ids})
            hunting_rows.append({"type": "hunting_opportunity", "statement": "Hunt for the recovered transport/endpoint construction and correlate it with the cited function path; this is a static pivot, not an observed connection.", "evidence_ids": evidence_ids})
        if any(token in lower for token in ("loadlibrary", "getprocaddress", "module", "resolve")):
            hunting_rows.append({"type": "hunting_opportunity", "statement": "Hunt for indirect module/API resolution using the recovered resolver and consumer relationship.", "evidence_ids": evidence_ids})
        if any(token in lower for token in ("xor", "decode", "decrypt", "decompress", "payload")):
            hunting_rows.append({"type": "hunting_opportunity", "statement": "Hunt for the recovered decoder pattern and embedded payload/resource characteristics before plaintext materialization.", "evidence_ids": evidence_ids})
        if any(token in lower for token in ("parent", "startupinfoex", "attribute")):
            hunting_rows.append({"type": "hunting_opportunity", "statement": "Hunt for STARTUPINFOEX parent-process attributes and anomalous parent/child relationships matching the cited static chain.", "evidence_ids": evidence_ids})
    all_modules["c2_network"]["rows"].extend(static_iocs)
    all_modules["c2_network"]["rows"].extend(hunting_rows[:24])
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
        investigation_threads=[
            item if isinstance(item, Mapping) else {"id": getattr(item, "id", ""), "state": getattr(item, "state", "")}
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
    return {
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
        "trace": {
            "artifact_ids": [item.id for item in artifacts],
            "tool_run_ids": [item.id for item in tool_runs],
            "evidence_ids": list(evidence_by_id),
            "claim_ids": [item.id for item in claims],
            "relation_ids": [item.id for item in relations],
            "model_call_ids": [item.id for item in model_calls],
        },
    }


def document_to_markdown(document: dict[str, object]) -> str:
    # Report V3 documents have a stable analyst-facing projection.  The
    # legacy renderer remains available for old snapshots that predate the
    # V3 section contract, but new reports must never render the full ledger.
    if (
        str(document.get("report_version", "")) == "3.0"
        and isinstance(document.get("report_sections"), list)
    ):
        return _document_to_v3_markdown(document)

    lines = [
        "# 恶意样本静态分析报告",
        "",
        f"- Case ID: {chr(96)}{document['case_id']}{chr(96)}",
        f"- Analysis Task ID: {chr(96)}{document['task_id']}{chr(96)}",
        f"- Task Outcome: **{document.get('analysis_outcome') or '未计算'}**",
        f"- Analysis Class: **{document.get('analysis_class') or '未分类'}**",
        "",
        "> Reconstructed from static control/data-flow evidence. This is not runtime observation.",
        "> 本报告仅基于静态证据。Claim 与 ATT&CK 映射均应通过证据引用复核。",
        "",
    ]
    for module in document["modules"]:  # type: ignore[index]
        lines.extend([f"## {module['title']}", "", str(module["summary"]), ""])
        rows = module.get("rows", [])
        if not rows:
            lines.extend(["无可报告发现。", ""])
            continue
        for index, row in enumerate(rows, start=1):
            if row.get("type") == "analyst_assessment":
                lines.extend(["### Analyst Assessment", "", str(row.get("summary", "")), ""])
                for finding_index, finding in enumerate(row.get("findings", []), start=1):
                    if not isinstance(finding, dict):
                        continue
                    label = finding.get("finding") or finding.get("action") or finding.get("type")
                    lines.append(f"#### Finding {finding_index}: {label}")
                    for key in (
                        "verdict", "risk", "confidence", "evidence_count", "evidence_ids",
                        "analysis_source", "mechanism", "condition", "reason", "priority",
                        "attack_techniques",
                    ):
                        if key in finding:
                            lines.append(f"- {key}: {_short(finding[key])}")
                    if finding.get("evidence_samples"):
                        lines.append("- supporting_evidence:")
                        for sample in finding["evidence_samples"]:
                            lines.append(f"  - {_short(sample)}")
                    lines.append("")
                continue
            if row.get("type") == "security_finding":
                lines.extend([
                    f"### Security Finding {index}: {row.get('finding_id', 'unknown')}",
                    f"- mechanism_id: `{row.get('mechanism_id')}`",
                    f"- claim_id: `{row.get('claim_id')}`",
                    f"- WHAT: {row.get('what', '')}",
                    f"- HOW: {row.get('how', '')}",
                    f"- SECURITY MEANING: {row.get('security_meaning', '')}",
                    f"- BOUNDARY: {row.get('boundary', '')}",
                    f"- supporting_evidence: {_short(row.get('evidence_ids', []), 600)}",
                    "",
                ])
                continue
            if row.get("type") == "analysis_profile":
                profile = row.get("profile") if isinstance(row.get("profile"), dict) else {}
                assessment = profile.get("assessment", {}) if isinstance(profile, dict) else {}
                lines.extend(
                    [
                        f"### {index}. Analysis Profile ({row.get('artifact_id', 'unknown')})",
                        f"- profile_evidence_id: `{row.get('evidence_id')}`",
                        f"- expected_verdict: {_short(assessment.get('expected_verdict'))}",
                        f"- actual_verdict: {_short(assessment.get('actual_verdict'))}",
                        f"- valid_match_rate: {_short(assessment.get('valid_match_rate'))}",
                        f"- dimension_coverage: {_short(profile.get('dimension_coverage', {}))}",
                        f"- matched_fact_ids: {_short(assessment.get('matched_fact_ids', []))}",
                        f"- excluded_fact_ids: {_short(assessment.get('excluded_fact_ids', []))}",
                        "",
                    ]
                )
                continue
            if row.get("type") == "investigation_timeline":
                lines.extend(["### Investigation Timeline", ""])
                lines.append(f"- private_chain_of_thought: {row.get('private_chain_of_thought', False)}")
                for event in row.get("events", []):
                    if isinstance(event, dict):
                        lines.append(f"- {event.get('phase', 'event')}: {_short(event)}")
                lines.append("")
                continue
            if row.get("type") == "static_simulation_prediction":
                lines.extend(
                    [
                        "### Static Abstract Execution Prediction",
                        f"- evidence_id: `{row.get('evidence_id')}`",
                        f"- function: {_short(row.get('function'))} @ {_short(row.get('entry'))}",
                        f"- simulation_kind: {_short(row.get('simulation_kind'))}",
                        f"- runtime_observed: {_short(row.get('runtime_observed'))}",
                        f"- confidence: {_short(row.get('confidence'))}",
                    ]
                )
                candidates = row.get("mechanism_candidates", [])
                if candidates:
                    lines.append("- mechanism_candidates:")
                    for candidate in candidates:
                        lines.append(f"  - {_short(candidate)}")
                steps = row.get("predicted_steps", [])
                if steps:
                    lines.append("- predicted_steps:")
                    for step in steps:
                        label = step.get("api") or step.get("operation")
                        lines.append(f"  - {step.get('index')}: {label} -> {_short(step.get('outputs', {}))}")
                for key in ("path_conditions", "unknowns", "limitations"):
                    values = row.get(key, [])
                    if values:
                        lines.append(f"- {key}: {_short(values)}")
                lines.append("")
                continue
            if row.get("type") == "api_argument_recovery":
                lines.extend(
                    [
                        "### Static API Argument Recovery",
                        f"- evidence_id: `{row.get('evidence_id')}`",
                        f"- API: {_short(row.get('api'))}",
                        f"- function: {_short(row.get('function'))} @ {_short(row.get('function_entry'))}",
                        f"- callsite: {_short(row.get('callsite'))}",
                        f"- consumer: {_short(row.get('consumer'))}",
                        f"- recovered_arguments: {_short(row.get('recovered_argument_count'))}",
                    ]
                )
                arguments = row.get("arguments", [])
                if arguments:
                    lines.append("- arguments:")
                    for argument in arguments:
                        if isinstance(argument, dict):
                            lines.append(
                                f"  - arg{argument.get('index')} ({argument.get('register')}): "
                                f"{_short(argument.get('value'))}"
                                f" [{argument.get('source_kind') or 'unknown'}]"
                            )
                if row.get("downstream_consumers"):
                    lines.append(f"- downstream_consumers: {_short(row.get('downstream_consumers'))}")
                lines.append("- static_only: true")
                lines.append("")
                continue
            if row.get("type") == "investigation_seed_map":
                lines.extend(
                    [
                        "### Investigation Seed Map",
                        f"- evidence_id: `{row.get('evidence_id')}`",
                        f"- artifact_id: `{row.get('artifact_id')}`",
                        f"- clusters: {_short(row.get('cluster_count', 0))} "
                        f"(high-value: {_short(row.get('high_value_cluster_count', 0))})",
                    ]
                )
                for cluster in row.get("clusters", [])[:12]:
                    if not isinstance(cluster, dict):
                        continue
                    lines.append(
                        f"- {cluster.get('id', 'cluster')} [{cluster.get('category', 'generic')}] "
                        f"priority={cluster.get('priority', 0)}: {cluster.get('question', '')}"
                    )
                    if cluster.get("hypotheses"):
                        lines.append(f"  - competing_hypotheses: {_short(cluster.get('hypotheses'))}")
                    if cluster.get("evidence_ids"):
                        lines.append(f"  - evidence_ids: {_short(cluster.get('evidence_ids'), 600)}")
                lines.append("- static_only: true")
                lines.append("")
                continue
            if row.get("type") == "fact_match":
                match = row.get("match") if isinstance(row.get("match"), dict) else {}
                lines.extend(
                    [
                        f"### {index}. Fact Match {match.get('fact_id', 'unknown')}",
                        f"- match_evidence_id: `{row.get('evidence_id')}`",
                        f"- status: {_short(match.get('status'))}",
                        f"- indicator: {_short(match.get('indicator_type'))}={_short(match.get('indicator_value'))}",
                        f"- signal_value: {_short(match.get('signal_value'))}",
                        f"- reason: {_short(match.get('reason'))}",
                        f"- evidence_ids: {_short(match.get('evidence_ids', []))}",
                        "",
                    ]
                )
                continue
            lines.append(
                f"### {index}. {row.get('claim_id') or row.get('evidence_id') or row.get('path') or row.get('type') or '记录'}"
            )
            for key, value in row.items():
                if key in {"claim_id", "evidence_id", "path", "type"}:
                    continue
                rendered = _short(value).replace("|", "\\|")
                lines.append(f"- {key}: {rendered}")
            lines.append("")
    rendered = "\n".join(lines).rstrip() + "\n"
    wording_violations = static_wording_violations(rendered)
    if wording_violations:
        raise ValueError("static-only wording gate rejected report: " + ", ".join(wording_violations))
    # Keep the primary analyst document bounded even when a parser emits a
    # very large number of heterogeneous evidence groups. The complete,
    # content-addressed ledger remains available through Evidence Explorer;
    # this projection preserves its trace IDs without allowing a report dump
    # to DOS the UI or fail task finalization.
    encoded = rendered.encode("utf-8")
    if len(encoded) > REPORT_MAX_MARKDOWN_BYTES:
        notice = (
            "\n\n> 报告正文已达到 40 KiB 展示预算；其余低优先级明细未内嵌。"
            "完整 Evidence、ToolRun 和原始输出请通过 Evidence Explorer 按 task_id 查询。\n"
        )
        budget = REPORT_MAX_MARKDOWN_BYTES - len(notice.encode("utf-8"))
        rendered = encoded[: max(0, budget)].decode("utf-8", errors="ignore").rstrip() + notice
    return rendered


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


_STATIC_RUNTIME_REWRITES: tuple[tuple[str, str], ...] = (
    (r"\bconnected\b", "would connect"),
    (r"\bdownloaded successfully\b", "would download"),
    (r"\bexecuted successfully\b", "would execute"),
    (r"\bprocess spawned\b", "process creation would occur"),
    (r"\bregistry modification succeeded\b", "registry modification may succeed"),
    (r"\bserver responded\b", "a server response would be expected"),
    (r"\bc2 active\b", "C2 activity would be possible"),
    (r"\bobserved at runtime\b", "would be observed at runtime"),
    (r"\bdynamic_observed\b", "dynamic observation candidate"),
    (r"\bpersisted successfully\b", "would persist"),
    (r"\bexecuted\b", "would execute"),
)


def _static_safe_text(value: object) -> str:
    """Normalize unqualified model wording to a static, conditional claim.

    Model prose is untrusted input to the report renderer.  A single
    unqualified runtime verb must not abort an otherwise valid static report,
    nor may it be emitted as if execution had been observed.  Existing
    explicitly negative/modal wording is left untouched by the gate; only
    text that fails the wording predicate is rewritten.
    """
    text = str(value or "").strip()
    if not text or not static_wording_violations(text):
        return text
    for pattern, replacement in _STATIC_RUNTIME_REWRITES:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text


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
    assessment = next((row for row in rows if row.get("type") == "analyst_assessment"), {})
    summary = str(assessment.get("summary", "")).strip()
    findings: list[dict[str, object]] = [
        row for row in rows if row.get("type") == "security_finding"
    ]
    # A candidate claim is useful context, but it is never presented as a
    # verified security finding. Keep only the best few and require evidence.
    # Function-reference/navigation rows belong in the trace, not the analyst
    # finding list; they do not state a recovered mechanism by themselves.
    def is_navigation_candidate(row: dict[str, object]) -> bool:
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

    if not findings:
        # Prefer concrete observed mechanism rows over broad rule Claims in
        # the analyst-facing finding list.  This is what turns a disassembly
        # result into an explanation rather than another import inventory.
        observed_rows = [
            row for row in rows
            if row.get("type") == "mechanism_observation" and row.get("evidence_ids")
        ]
        observed_rows.sort(
            key=lambda row: (
                -int(row.get("completeness", 0) or 0),
                0 if row.get("function_entry") or row.get("rva") else 1,
            )
        )
        for row in observed_rows[:8]:
            finding_text = (
                f"Static observation at {row.get('target')}: "
                f"{row.get('mechanism_type', 'mechanism')} is supported by a typed "
                "function/data path."
            )
            findings.append({
                "finding_id": f"candidate:{row.get('mechanism_id', 'observed')}",
                "verdict": "CANDIDATE",
                "confidence": row.get("confidence", "MEDIUM"),
                "what": finding_text,
                "how": " -> ".join(str(item) for item in row.get("transformation_or_control", [])),
                "security_meaning": "This is an evidence-backed static capability candidate; it is a hunting pivot, not runtime proof.",
                "boundary": "Static evidence only; runtime reachability, intent, and successful output are not observed.",
                "claim_id": None,
                "mechanism_id": row.get("mechanism_id", "observed-mechanism"),
                "evidence_ids": list(row.get("evidence_ids", []))[:5],
                "candidate": True,
            })
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
            if len(findings) >= 15:
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
            if len(findings) >= 15:
                break
    findings = findings[:15]

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

    rendered_flow_rows = [
        row for row in rows
        if row.get("type") == "mechanism_chain" and row.get("rendered")
    ]
    if not rendered_flow_rows and isinstance(assessment, dict):
        rendered_flow_rows = [
            row for row in assessment.get("findings", [])
            if isinstance(row, dict)
            and row.get("type") == "mechanism_chain"
            and row.get("rendered")
        ]

    def compact(value: object, limit: int = 360) -> str:
        text = _static_safe_text(value).replace("\n", " ").strip()
        return text if len(text) <= limit else text[: limit - 3] + "..."

    lines = [
        "# 恶意样本静态分析报告",
        "",
        f"- Case ID: `{document.get('case_id', 'unknown')}`",
        f"- Analysis Task ID: `{document.get('task_id', 'unknown')}`",
        f"- Task Outcome: **{document.get('analysis_outcome') or 'UNKNOWN'}**",
        f"- Analysis Class: **{document.get('analysis_class') or 'UNKNOWN'}**",
        "- Task Outcome is a Legacy task-completion field retained for compatibility; it does not override Analysis Class.",
        "- Sample execution: **false**",
        "",
        "> Reconstructed from static control/data-flow evidence. This is not runtime observation.",
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
        f"present={bool(rendered_flow_rows)}, "
        f"relation coverage={coverage.get('dimensions', {}).get('relation_flow_coverage', 0.0) if isinstance(coverage.get('dimensions'), dict) else 0.0}",
        f"- Deep analysis readiness: **{quality.get('readiness', 'BOUNDED_WITH_LIMITATIONS')}**",
        f"- Report depth score: **{quality.get('report_depth', {}).get('score', 0) if isinstance(quality.get('report_depth'), dict) else 0}/100**",
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
    lines.extend(["", "## 3. Key Static Findings", ""])
    if findings:
        for index, finding in enumerate(findings, start=1):
            verdict = finding.get("verdict") or ("CANDIDATE" if finding.get("candidate") else "SUPPORTED")
            confidence = finding.get("confidence", "UNKNOWN")
            lines.extend([
                f"### Finding {index}: {compact(finding.get('finding_id', 'static-finding'), 120)}",
                f"- Verdict: **{verdict}** | Confidence: **{confidence}**",
                f"- What: {compact(finding.get('what'), 700)}",
                f"- How: {compact(finding.get('how'), 700)}",
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
    verified = [item for item in findings if str(item.get("verdict", "")).upper() in {"VERIFIED", "CONFIRMED", "SUPPORTED"} and not item.get("candidate")]
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
    if candidates:
        lines.extend(["", "### Candidate Mechanisms", ""])
        for item in candidates[:12]:
            chain = " -> ".join(
                str(value) for value in item.get("transformation_or_control", []) if value
            )
            location = ""
            if item.get("function") or item.get("function_entry") or item.get("rva"):
                location = (
                    f" | location={compact(item.get('function') or 'function', 120)}"
                    f"@{compact(item.get('function_entry') or item.get('rva') or 'unknown', 80)}"
                )
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

    argument_traces = [row for row in rows if row.get("type") == "api_argument_recovery"]
    if argument_traces:
        lines.extend(["", "### Static API Argument Recovery", ""])
        for trace in argument_traces[:16]:
            lines.extend([
                f"- `{compact(trace.get('api'), 180)}` at `{compact(trace.get('callsite'), 80)}` "
                f"in `{compact(trace.get('function'), 180)}` ({compact(trace.get('function_entry'), 80)})",
                f"  - consumer: {compact(trace.get('consumer'), 240)}",
                f"  - recovered arguments: {compact(trace.get('recovered_argument_count'), 80)}",
            ])
            args = trace.get("arguments", [])
            if isinstance(args, list):
                for arg in args[:8]:
                    if isinstance(arg, dict):
                        lines.append(
                            f"  - arg{arg.get('index')} ({arg.get('register')}): "
                            f"{compact(arg.get('value'), 360)} [{arg.get('source_kind') or 'unknown'}]"
                        )
            if trace.get("downstream_consumers"):
                lines.append(f"  - downstream consumers: {compact(trace.get('downstream_consumers'), 400)}")
            lines.append(f"  - evidence: {compact(trace.get('source_evidence_ids', [])[:8], 300)}")

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
                f"(high-value={compact(seed.get('high_value_cluster_count', 0), 40)})"
            )
            clusters = seed.get("clusters", [])
            if isinstance(clusters, list):
                for cluster in clusters[:12]:
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
            lines.append(f"- {compact(row.get('value') or row.get('indicator') or row.get('statement'), 500)}")
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
        for technique in row.get("attack_techniques", []) if isinstance(row.get("attack_techniques"), list) else []:
            if isinstance(technique, dict) and technique.get("technique_id"):
                techniques[str(technique["technique_id"])] = str(technique.get("name") or "")
    if techniques:
        for technique_id, name in sorted(techniques.items()):
            lines.append(f"- `{technique_id}` {name}".rstrip())
    else:
        lines.append("未形成基于 Supported Claim 或 Verified Mechanism 的 ATT&CK 映射。")

    lines.extend(["", "## 9. Unknowns / Static Boundaries", ""])
    unknowns = [row for row in rows if row.get("type") in {"analysis_limitation", "next_step"}]
    if unknowns:
        for row in unknowns[:30]:
            lines.append(f"- {compact(row.get('detail') or row.get('reason') or row.get('action'), 900)}")
    else:
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
    encoded = rendered.encode("utf-8")
    if len(encoded) > REPORT_MAX_MARKDOWN_BYTES:
        notice = (
            "\n\n> 报告正文超过展示预算；低优先级分析明细未内嵌。"
            "完整 Evidence、ToolRun 和原始输出请通过 Evidence Explorer 查询。\n"
        )
        budget = REPORT_MAX_MARKDOWN_BYTES - len(notice.encode("utf-8"))
        rendered = encoded[: max(0, budget)].decode("utf-8", errors="ignore").rstrip() + notice
    return rendered


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
        title="恶意样本静态分析报告",
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
