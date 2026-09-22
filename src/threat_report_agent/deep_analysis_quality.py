"""Deterministic quality gates for analyst-grade static analysis.

This module evaluates the *shape and provenance* of an investigation result.  It
never executes an artifact and never turns a candidate into a verified claim.
The output is intentionally small enough to persist in a report snapshot while
the complete evidence ledger remains available through the explorer.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import re

from threat_report_agent.investigation.investigation_protocol import s4_closed_has_audit_trail
from threat_report_agent.investigation.mechanism_completeness import (
    has_semantic_value,
    mechanism_completeness_score,
)
from threat_report_agent.investigation.mechanism_ready import inspect_mechanism_ready


_STRONG_LABELS = (
    "active c2",
    "confirmed injection",
    "manual mapper",
    "credential theft",
    "exfiltration",
    "successfully persisted",
    "complete defender bypass",
)
_NAVIGATION_ACTIONS = {"prioritizes", "references", "matches", "calls"}
_STATIC_CERTAINTY_TERMS = (
    "active c2", "connected to", "executed successfully", "runtime confirmed",
    "injected into", "exfiltrated successfully", "successfully persisted",
)
_CLOSED_STATUSES = {"VERIFIED", "SUPPORTED", "CONFIRMED"}
# These are the mechanism projections that can appear in an analyst-facing
# report.  Keep quality metrics aligned with the report renderer: an
# unresolved observation/link is still visible candidate noise even when it
# is not represented by the legacy ``mechanism_candidate`` type.
_REPORT_MECHANISM_TYPES = frozenset(
    {"mechanism_candidate", "mechanism_link", "mechanism_observation", "security_finding"}
)


def _is_visible_mechanism(row: Mapping[str, object]) -> bool:
    """Return whether a mechanism participates in analyst-facing metrics.

    ``suppressed_by_verified`` is presentation-only deduplication.  The
    source Evidence remains immutable and auditable, but the duplicate must
    not lower closure/readiness metrics or inflate candidate noise when a
    snapshot is replayed with both visible and hidden projections.
    """
    return not bool(row.get("suppressed_by_verified"))
NO_NEW_EVIDENCE_CATEGORIES = frozenset(
    {
        "LOW_INFORMATION_ACTION",
        "TOOL_EXTRACTION_GAP",
        "EVIDENCE_ALREADY_PRESENT",
        "SELECTOR_ERROR",
        "TARGET_ERROR",
        "DEDUP_SUPPRESSED",
        "STATIC_BOUNDARY",
    }
)

_AUTOPSY_NEXT_ACTIONS = {
    "LOW_INFORMATION_ACTION": "CHOOSE_HIGHER_INFORMATION_ACTION",
    "TOOL_EXTRACTION_GAP": "RETRY_WITH_DETERMINISTIC_TOOL",
    "EVIDENCE_ALREADY_PRESENT": "REUSE_EXISTING_EVIDENCE",
    "SELECTOR_ERROR": "PROVIDE_ANCHORED_SELECTOR",
    "TARGET_ERROR": "RESOLVE_TARGET_FROM_ARTIFACT",
    "DEDUP_SUPPRESSED": "USE_EXISTING_ACTION_RESULT",
    "STATIC_BOUNDARY": "RECORD_STATIC_BOUNDARY",
}

_ADVERSARIAL_RULES = {
    "NETWORK_IS_C2": "A network/API observation is not a C2 or beacon conclusion without a loop, protocol/tasking, and response-consumer relation.",
    "REGISTRY_IS_PERSISTENCE": "A registry operation is not persistence without a trigger, payload, lifetime/re-execution semantics, and a supported relation.",
    "PROCESS_API_IS_INJECTION": "Process/thread/APC APIs are not injection without a cross-process target, source/target memory relation, and execution transfer.",
    "INJECTS_SELF_LOOP": "An INJECTS relation with the same source and target artifact is not cross-process injection.",
    "COLLECTION_IS_EXFILTRATION": "Collection is not exfiltration without a producer-to-staging-to-network-sink relation.",
    "SIMULATION_IS_RUNTIME": "A stub, static abstraction, or unlabelled emulator result is not real runtime observation.",
    "API_IS_BEHAVIOR": "An API or string name is a seed, not a behavior, without HOW, condition, output, and consumer evidence.",
}
_INJECTION_OVERCLAIM_RULES = frozenset({"PROCESS_API_IS_INJECTION", "INJECTS_SELF_LOOP"})
_INJECTION_OVERCLAIM_STATUSES = frozenset({
    "VERIFIED", "SUPPORTED", "CONFIRMED", "INFERRED", "OBSERVED",
})
_CHECKED_OVERCLAIM_TYPES = frozenset({
    "mechanism_candidate", "mechanism_link", "mechanism_observation",
    "security_finding", "analytical_claim", "behavior_finding", "behavior_relation",
})


def _flatten_text(value: object) -> str:
    """Flatten report fields for deterministic rule checks without parsing prose semantics."""
    if isinstance(value, Mapping):
        return " ".join(
            f"{key} {_flatten_text(item)}" for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return " ".join(_flatten_text(item) for item in value)
    return str(value or "")


def _overclaim_row_identity(row: Mapping[str, object], fallback: str = "") -> str:
    return str(
        row.get("relation_id")
        or row.get("finding_id")
        or row.get("mechanism_id")
        or row.get("claim_id")
        or row.get("id")
        or fallback
        or ""
    )


def _relation_type_of(row: Mapping[str, object]) -> str:
    return str(row.get("relation_type") or row.get("relation") or "").strip().upper()


def _injects_endpoints(row: Mapping[str, object]) -> tuple[str, str]:
    source = str(
        row.get("source_artifact_id") or row.get("source_object") or ""
    ).strip()
    target = str(
        row.get("target_artifact_id") or row.get("target_object") or ""
    ).strip()
    return source, target


def _is_injects_self_loop(row: Mapping[str, object]) -> bool:
    """True when an INJECTS edge has no distinct target artifact/process."""
    nested = row.get("relations")
    if isinstance(nested, (list, tuple)):
        if any(
            _is_injects_self_loop(item)
            for item in nested
            if isinstance(item, Mapping)
        ):
            return True
    if _relation_type_of(row) not in {"INJECTS", "INJECT"}:
        return False
    source, target = _injects_endpoints(row)
    source_finding = str(row.get("source_finding_id") or "").strip()
    target_finding = str(row.get("target_finding_id") or "").strip()
    if source and source == target:
        return True
    if source_finding and source_finding == target_finding:
        return True
    if source and not target:
        return True
    return False


def _adversarial_overclaim_checks(rows: Iterable[Mapping[str, object]]) -> list[dict[str, object]]:
    """Find common evidence-to-behaviour leaps before a report is released.

    This is deliberately a gate, not a classifier.  A hit means the row must
    remain candidate/unknown or acquire the missing typed relation; it never
    changes a row to a stronger status on its own.
    """
    checks: list[dict[str, object]] = []
    row_fields = (
        "statement", "what", "how", "mechanism", "security_meaning", "target",
        "inputs", "transformation_or_control", "conditions", "outputs", "consumers",
        "side_effects", "loop", "loop_repetition", "unknowns", "evidence_natures",
        "relation_ids", "relations", "mechanism_type", "verifier",
        "relation_type", "relation", "source_artifact_id", "target_artifact_id",
        "source_object", "target_object",
    )
    for row in rows:
        row_type = str(row.get("type") or "")
        relation_type = _relation_type_of(row)
        if row_type not in _CHECKED_OVERCLAIM_TYPES and relation_type not in {"INJECTS", "INJECT"}:
            continue
        text = " ".join(_flatten_text(row.get(key)) for key in row_fields).casefold()
        identity = _overclaim_row_identity(row, row_type or relation_type)
        evidence_natures = _flatten_text(row.get("evidence_natures")).upper()

        def add(rule_id: str, missing: list[str]) -> None:
            checks.append({
                "rule_id": rule_id,
                "row_id": identity,
                "status": "BLOCKED",
                "missing": missing,
                "action": "DOWNGRADE_OR_RECOVER_TYPED_EVIDENCE",
                "reason": _ADVERSARIAL_RULES[rule_id],
            })

        if _is_injects_self_loop(row):
            add("INJECTS_SELF_LOOP", ["distinct_target_artifact", "cross_process_target"])

        if any(token in text for token in ("active c2", "beacon", "heartbeat", "command and control")):
            loop_markers = ("loop", "back-edge", "back edge", "poll", "jitter", "tasking", "response consumer")
            if not any(marker in text for marker in loop_markers):
                add("NETWORK_IS_C2", ["loop_or_back_edge", "protocol_or_tasking", "response_consumer_relation"])

        if "persistence" in text and any(token in text for token in ("registry", "runonce", "scheduled task", "service", "startup")):
            persistence_markers = ("trigger", "lifetime", "re-execution", "reexecution", "trigger_to_payload", "payload")
            missing = [marker for marker in ("trigger", "lifetime", "payload") if marker not in text]
            if missing or not any(marker in text for marker in persistence_markers):
                add("REGISTRY_IS_PERSISTENCE", missing or ["trigger_to_payload_relation"])

        if any(token in text for token in (
            "process injection", "remote injection", "injected into", "process hollowing",
            "apc injection", "queueuserapc", "ntqueueapcthread", "queue apc",
            "same-process apc", "same process apc", "ppid spoof", "ppid spoofing",
        )):
            required = ("cross_process", "target_process", "source_region", "target_region")
            missing = [marker for marker in required if marker not in text]
            if missing:
                add("PROCESS_API_IS_INJECTION", missing)

        if "exfiltration" in text or "exfiltrated" in text:
            required = ("collection_source", "staging", "network_sink")
            missing = [marker for marker in required if marker not in text]
            if missing:
                add("COLLECTION_IS_EXFILTRATION", missing + ["collected_to_network_relation"])

        if any(token in text for token in ("runtime confirmed", "executed successfully", "actual runtime", "runtime observed")):
            if "EMULATION_OBSERVED" not in evidence_natures and "DYNAMIC_OBSERVED" not in evidence_natures:
                add("SIMULATION_IS_RUNTIME", ["EMULATION_OBSERVED evidence nature or real runtime provenance"])

        what = _flatten_text(row.get("what")).strip()
        if row_type in {"behavior_finding", "security_finding", "analytical_claim"} and re.fullmatch(r"(?:[A-Za-z_][A-Za-z0-9]*)(?:A|W)?", what or ""):
            if not all(_flatten_text(row.get(key)).strip() for key in ("how", "conditions", "outputs", "consumers")):
                add("API_IS_BEHAVIOR", ["how", "conditions", "outputs", "consumers"])
    return checks


def _s4_orchestration_status(
    threads: Iterable[Mapping[str, object]],
    actions: Iterable[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Persist the S4 closure/boundary decision for every investigation thread."""
    action_by_id = {str(row.get("id")): row for row in actions if row.get("id")}
    result: list[dict[str, object]] = []
    for row in threads:
        thread_id = str(row.get("id") or row.get("thread_id") or "")
        state = str(row.get("state") or "").upper()
        action_ids = [str(item) for item in (row.get("action_ids") or []) if item]
        evidence_ids = [str(item) for item in (row.get("evidence_ids") or []) if item]
        if state in {"REJECTED", "CONTRADICTED", "NOT_APPLICABLE"}:
            status = "NOT_APPLICABLE"
            reason = "thread was rejected or explicitly marked not applicable"
        elif state in {"CLAIM_READY", "MECHANISM_READY", "CLOSED", "CANDIDATE"} and evidence_ids:
            # Kunglao leftover remainder: persist HOW skip writes CLAIM_READY
            # with Evidence and zero TRACE actions. That is report content,
            # not a vacuous S4 CLOSED that should ask the operator to 再深入.
            status = "CLOSED"
            reason = (
                "thread reached a verifier-ready state with recorded actions and evidence"
                if action_ids
                else (
                    "persist/verifier-ready HOW is leftover remainder; "
                    "isolated emu is not another TRACE round"
                )
            )
        elif state in {"UNKNOWN", "PARTIAL", "UNSUPPORTED", "STATIC_BOUNDARY"} and evidence_ids:
            status = "RECORDED"
            reason = (
                "honest static boundary is report UNKNOWN/CANDIDATE content, "
                "not a planner ticket"
            )
        elif isinstance(row.get("s_ladder"), Mapping):
            ladder = row.get("s_ladder") or {}
            ladder_status = str(ladder.get("s4_orchestration") or "").upper()
            if ladder_status == "CLOSED" and s4_closed_has_audit_trail(ladder):
                status = "CLOSED"
                reason = "S1-S3 were attempted or marked N/A/unsupported; S4 is recorded closed"
            elif ladder_status == "CLOSED":
                status = "BLOCKED"
                reason = (
                    "S4 CLOSED with empty attempts is not an auditable S1-S3 trail; "
                    "retain BLOCKED until attempts or an explicit family N/A reason exist"
                )
            elif state in {"CLAIM_READY", "MECHANISM_READY", "CLOSED"} and action_ids and evidence_ids:
                status = "CLOSED"
                reason = "thread reached a verifier-ready state with recorded actions and evidence"
            else:
                status = "BLOCKED"
                reason = "S4 remains open because S1-S3 are incomplete or blocked"
        elif state in {"CLAIM_READY", "MECHANISM_READY", "CLOSED"} and action_ids and evidence_ids:
            status = "CLOSED"
            reason = "thread reached a verifier-ready state with recorded actions and evidence"
        else:
            failed = [
                action_by_id[action_id]
                for action_id in action_ids
                if action_id in action_by_id
                and str(action_by_id[action_id].get("status") or "").upper() in {"FAILED", "BLOCKED", "CANCELLED"}
            ]
            status = "BLOCKED"
            reason = (
                "thread has a recorded failed/boundary action"
                if failed
                else "S4 orchestration closure was not reached; retain the frontier and unknowns"
            )
        result.append({
            "thread_id": thread_id,
            "state": state,
            "status": status,
            "question": str(row.get("question") or ""),
            "action_ids": action_ids[:64],
            "evidence_ids": evidence_ids[:64],
            "reason": reason,
        })
    return result


def _mapping(item: object) -> Mapping[str, object]:
    if isinstance(item, Mapping):
        return item
    return {key: getattr(item, key) for key in (
        "id", "status", "verdict", "action", "statement", "what", "how",
        "security_meaning", "mechanism_id", "claim_id", "evidence_ids",
        "target", "inputs", "transformation_or_control", "conditions",
        "outputs", "consumers", "side_effects", "verifier", "completeness",
        "alternatives_considered", "alternative_hypotheses", "unknowns", "limitations",
        "critical", "mechanism_type",
        "origin", "scheduler", "planner_turn_id", "error", "failure_interpretation",
        "new_evidence_ids", "result_evidence_ids", "new_evidence_count", "autopsy_category",
        "outcome", "target_artifact_id", "artifact_id", "target_selector", "parameters",
        "source_evidence_ids", "dedupe_key", "action_key", "artifact_boundary",
        "existing_evidence_ids", "evidence_already_present", "target_resolved", "target_found",
        "target_missing", "dedupe_suppressed", "static_boundary", "tool_status", "tool_error",
        "information_score", "hypothesis_delta", "mechanism_delta",
        "eliminated_hypothesis_ids", "competing_hypotheses_eliminated",
        "excluded_hypothesis_ids", "rejected_hypothesis_ids", "mechanism_fields_completed",
        "completed_fields", "fields_completed",
        "autopsy", "next_action",
    ) if hasattr(item, key)}


def _rows(document: Mapping[str, object]) -> list[Mapping[str, object]]:
    return [
        row
        for module in document.get("modules", [])
        if isinstance(module, Mapping)
        for row in module.get("rows", [])
        if isinstance(row, Mapping)
    ]


def _first_selector_value(selector: Mapping[str, object]) -> object:
    for key in ("target", "api", "function", "function_entry", "entry", "rva", "address"):
        value = selector.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            return value
    return None


def _has_nonempty(value: object) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, Mapping):
        return bool(value)
    if isinstance(value, (list, tuple, set)):
        return bool(value)
    return bool(value)


def no_new_evidence_autopsy(action: Mapping[str, object]) -> dict[str, object]:
    """Classify a zero-yield action without treating absence as refutation.

    The classifier consumes only action/result metadata and is intentionally
    deterministic.  It always returns a finite category plus the selector,
    target, dedupe key, artifact scope and a bounded next action so the
    planner, UI and evaluator can explain why a model proposal produced no
    new Evidence.
    """
    raw_selector = action.get("target_selector")
    selector = dict(raw_selector) if isinstance(raw_selector, Mapping) else {}
    target = _first_selector_value(selector)
    if target is None:
        for key in ("target", "api", "function", "function_entry", "entry", "rva", "address"):
            value = action.get(key)
            if isinstance(value, (str, int)) and str(value).strip():
                target = value
                break
    target_text = str(target).strip() if target is not None else None
    artifact_boundary = (
        action.get("artifact_boundary")
        or action.get("artifact_id")
        or action.get("target_artifact_id")
    )
    dedupe_key = action.get("dedupe_key") or action.get("action_key")
    failure_interpretation = str(action.get("failure_interpretation") or "").upper()
    explicit_category = str(action.get("autopsy_category") or "").upper()

    # Explicit static-boundary metadata is authoritative because retrying an
    # action cannot create runtime facts under the static-only policy.
    if explicit_category in NO_NEW_EVIDENCE_CATEGORIES:
        category = explicit_category
    elif failure_interpretation == "STATIC_BOUNDARY" or action.get("static_boundary") is True:
        category = "STATIC_BOUNDARY"
    elif not selector or any(
        not isinstance(value, (str, int)) or not str(value).strip()
        for value in selector.values()
    ):
        category = "SELECTOR_ERROR"
    elif action.get("target_resolved") is False or action.get("target_found") is False or action.get("target_missing") is True:
        category = "TARGET_ERROR"
    elif action.get("dedupe_suppressed") is True or str(action.get("outcome") or "").upper() in {
        "DEDUP_SUPPRESSED", "DUPLICATE"
    }:
        category = "DEDUP_SUPPRESSED"
    elif _has_nonempty(action.get("existing_evidence_ids")) or action.get("evidence_already_present") is True:
        category = "EVIDENCE_ALREADY_PRESENT"
    elif str(action.get("tool_status") or "").upper() in {"FAILED", "TIMED_OUT", "CANCELLED"} or action.get("tool_error"):
        category = "TOOL_EXTRACTION_GAP"
    elif not _has_nonempty(action.get("source_evidence_ids")) or action.get("information_score") in {0, 0.0, "0"}:
        category = "LOW_INFORMATION_ACTION"
    else:
        # A valid, bounded query that yielded nothing is still a low-yield
        # action; it must never be silently labelled as an unknown cause.
        category = "LOW_INFORMATION_ACTION"

    return {
        "category": category,
        "target_selector": selector,
        "target": target_text,
        "dedupe_key": str(dedupe_key) if dedupe_key is not None else None,
        "artifact_boundary": str(artifact_boundary) if artifact_boundary is not None else None,
        "next_action": _AUTOPSY_NEXT_ACTIONS[category],
        "reason": {
            "LOW_INFORMATION_ACTION": "The bounded query ran but did not discriminate the hypothesis.",
            "TOOL_EXTRACTION_GAP": "The selected static extractor failed, timed out, or returned no usable result.",
            "EVIDENCE_ALREADY_PRESENT": "The requested observation is already represented in the Evidence ledger.",
            "SELECTOR_ERROR": "The action did not provide a valid anchored target selector.",
            "TARGET_ERROR": "The selector could not be resolved within the artifact scope.",
            "DEDUP_SUPPRESSED": "An equivalent action/result was already scheduled or completed.",
            "STATIC_BOUNDARY": "The requested fact is outside the static-only evidence boundary.",
        }[category],
    }


def action_is_productive(action: Mapping[str, object]) -> bool:
    """Return whether a completed static action made an auditable gain.

    New Evidence is the ordinary success case. A model action can also be
    useful when a verifier records that it eliminated a competing hypothesis
    or completed a missing mechanism field. Free-form rationale never counts
    as a gain, and a failed/no-evidence action never receives productivity
    credit.
    """
    outcome = str(action.get("outcome") or action.get("status") or "").upper()
    if outcome in {"NO_NEW_EVIDENCE", "FAILED", "INVALID", "REJECTED", "BLOCKED"}:
        return False
    evidence_ids = action.get("new_evidence_ids")
    if evidence_ids is None:
        evidence_ids = action.get("result_evidence_ids")
    if _has_nonempty(evidence_ids) or int(action.get("new_evidence_count", 0) or 0) > 0:
        return True

    hypothesis_delta = action.get("hypothesis_delta")
    mechanism_delta = action.get("mechanism_delta")
    for key in (
        "eliminated_hypothesis_ids",
        "competing_hypotheses_eliminated",
        "excluded_hypothesis_ids",
        "rejected_hypothesis_ids",
        "eliminated",
        "excluded",
    ):
        if _has_nonempty(action.get(key)):
            return True
        if isinstance(hypothesis_delta, Mapping) and _has_nonempty(hypothesis_delta.get(key)):
            return True
    for key in ("mechanism_fields_completed", "completed_fields", "fields_completed", "new_fields"):
        if _has_nonempty(action.get(key)):
            return True
        if isinstance(mechanism_delta, Mapping) and _has_nonempty(mechanism_delta.get(key)):
            return True
    if outcome in {
        "HYPOTHESIS_ELIMINATED",
        "COMPETING_HYPOTHESIS_ELIMINATED",
        "MECHANISM_FIELDS_COMPLETED",
        "MECHANISM_UPDATED",
    }:
        return True

    if isinstance(hypothesis_delta, Mapping):
        before = hypothesis_delta.get("before")
        after = hypothesis_delta.get("after")
        if isinstance(before, (list, tuple)) and isinstance(after, (list, tuple)):
            before_open = {
                str(item.get("id"))
                for item in before
                if isinstance(item, Mapping)
                and str(item.get("status", "")).upper() in {"OPEN", "CANDIDATE", "INVESTIGATING"}
            }
            after_rejected = {
                str(item.get("id"))
                for item in after
                if isinstance(item, Mapping)
                and str(item.get("status", "")).upper() in {"REJECTED", "REFUTED", "CONTRADICTED", "EXCLUDED"}
            }
            if before_open & after_rejected:
                return True
    return False


def report_depth_score(document: Mapping[str, object]) -> dict[str, object]:
    """Score the analyst-facing report using the published 100-point rubric."""
    rows = _rows(document)
    mechanisms = [
        row for row in rows
        if row.get("type") in _REPORT_MECHANISM_TYPES and _is_visible_mechanism(row)
    ]
    closed = [
        row for row in mechanisms
        if str(row.get("status") or row.get("verdict") or "").upper()
        in {"VERIFIED", "SUPPORTED", "CONFIRMED"}
        and inspect_mechanism_ready(row).critical_ready
    ]

    def ratio(predicate) -> float:
        return min(1.0, sum(1 for row in closed if predicate(row)) / max(1, len(closed)))

    how = ratio(lambda row: all(
        has_semantic_value(key, row.get(key))
        for key in ("inputs", "transformation_or_control", "outputs", "consumers")
    ))
    detail = ratio(lambda row: bool(row.get("target")) and bool(row.get("evidence_ids")))
    security = ratio(lambda row: bool(str(row.get("security_meaning", "")).strip()))
    config = min(1.0, sum(
        1 for row in rows
        if any(token in str(row.get(key, "")).casefold() for key in (
            "statement", "how", "mechanism", "transformation_or_control"
        ) for token in ("decode", "decrypt", "xor", "resolve", "hash", "config"))
    ) / 3.0)
    flow = 1.0 if any(row.get("type") == "mechanism_chain" and row.get("rendered") for row in rows) else 0.0
    ioc = 1.0 if any(row.get("type") in {"indicator", "ioc", "hunting_opportunity"} for row in rows) else 0.0
    unknown = 1.0 if any(row.get("type") in {"analysis_limitation", "next_step"} for row in rows) else 0.0
    dimensions = {
        "mechanism_how": round(how * 25, 2),
        "orchestration_flow": round(flow * 15, 2),
        "config_deobfuscation": round(config * 15, 2),
        "function_argument_detail": round(detail * 15, 2),
        "security_meaning": round(security * 10, 2),
        "ioc_hunting": round(ioc * 10, 2),
        "unknown_precision": round(unknown * 10, 2),
    }
    score = round(sum(dimensions.values()), 2)
    return {
        "score": score,
        "threshold": 80,
        "status": "PASS" if score >= 80 else "BOUNDED",
        "dimensions": dimensions,
        "closed_mechanisms": len(closed),
        "candidate_mechanisms": len(mechanisms) - len(closed),
    }


def critic_pass(document: Mapping[str, object]) -> dict[str, object]:
    """Run a deterministic adversarial pass over report-visible assertions."""
    rows = _rows(document)
    unsupported: list[str] = []
    navigation: list[str] = []
    candidate_only: list[str] = []
    alternatives_missing: list[str] = []
    wording_violations: list[str] = []
    unknown_details: list[str] = []
    unknown_metadata_missing: list[str] = []
    for row in rows:
        text = " ".join(str(row.get(key, "")) for key in (
            "statement", "what", "how", "mechanism", "security_meaning"
        )).casefold()
        status = str(row.get("status") or row.get("verdict") or "").upper()
        verifier = row.get("verifier") if isinstance(row.get("verifier"), Mapping) else {}
        identity = str(row.get("mechanism_id") or row.get("claim_id") or row.get("type") or "row")
        if any(label in text for label in _STRONG_LABELS) and str(verifier.get("status", "")).upper() != "VERIFIED":
            unsupported.append(identity)
        if str(row.get("action", "")).casefold() in _NAVIGATION_ACTIONS:
            navigation.append(str(row.get("claim_id") or row.get("type") or "row"))
        if row.get("type") in {"mechanism_candidate", "analytical_claim"} and status not in {"VERIFIED", "SUPPORTED", "CONFIRMED"}:
            candidate_only.append(identity)

        if row.get("type") in {"mechanism_candidate", "security_finding", "analytical_claim"}:
            alternatives = (
                row.get("alternative_hypotheses")
                or row.get("alternatives_considered")
                or verifier.get("alternative_hypotheses")
                or verifier.get("alternatives_considered")
            )
            # Every mechanism hypothesis must expose the competing
            # explanation set.  A candidate does not need to be closed, but
            # it must say which alternatives remain open for the verifier.
            is_mechanism = row.get("type") in {"mechanism_candidate", "security_finding", "analytical_claim"}
            if is_mechanism and status not in {"UNKNOWN", ""} and not alternatives:
                alternatives_missing.append(identity)

            required_fields = (
                "target", "inputs", "transformation_or_control", "conditions",
                "outputs", "consumers", "evidence_ids",
            )
            missing = [field for field in required_fields if not row.get(field)]
            if missing and status in _CLOSED_STATUSES:
                unknown_details.append(f"{identity}: missing {', '.join(missing)}")
            if is_mechanism and status in {"CANDIDATE", "UNKNOWN", "BLOCKED"} and not (
                row.get("unknowns") or row.get("limitations") or row.get("missing") or row.get("reason")
            ):
                unknown_metadata_missing.append(f"{identity}: unresolved mechanism lacks explicit unknowns/limitations")

            # Strong statuses without static qualification are unsafe in a
            # static-only report, even when a verifier happened to pass.
            if status in {"SUPPORTED", "CONFIRMED"} and any(term in text for term in _STATIC_CERTAINTY_TERMS):
                if not any(token in text for token in ("static", "may", "could", "possible", "candidate")):
                    wording_violations.append(identity)
            elif status in {"SUPPORTED", "CONFIRMED"} and missing:
                wording_violations.append(identity)
    overclaim_checks = _adversarial_overclaim_checks(rows)
    return {
        "unsupported_claims": sorted(set(unsupported)),
        "alternative_hypotheses_not_ruled_out": sorted(set(alternatives_missing))[:64],
        "critical_unknowns": [
            str(row.get("detail") or row.get("reason"))
            for row in rows if row.get("type") in {"analysis_limitation", "next_step"}
        ][:32] + unknown_details[:32] + unknown_metadata_missing[:32],
        "unknown_fields_missing": sorted(set(unknown_metadata_missing))[:64],
        "candidate_only_findings": sorted(set(candidate_only))[:64],
        "navigation_rows_excluded": sorted(set(navigation))[:64],
        "static_wording_violations": sorted(set(wording_violations))[:64],
        "overclaim_checks": overclaim_checks[:128],
        "status": "PASS" if not unsupported and not wording_violations and not alternatives_missing and not unknown_metadata_missing and not overclaim_checks else "BLOCKED",
    }


_CLOSED_FINDING_STATUSES = frozenset({"VERIFIED", "SUPPORTED", "CONFIRMED"})


def apply_adversarial_downgrades(
    rows: Iterable[Mapping[str, object]],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Downgrade closed findings that fail structured overclaim checks.

    M06: a blocked API-is-behavior / network-is-C2 / registry-is-persistence
    check cannot remain a VERIFIED/SUPPORTED/CONFIRMED row.  The critic still
    records the check; the finding itself becomes CANDIDATE/UNKNOWN.
    Same-artifact INJECTS and process-API-as-injection rows, including
    INFERRED self-loops, cannot remain closed or HIGH injection.
    """
    materialized = [dict(row) for row in rows]
    checks = _adversarial_overclaim_checks(materialized)
    blocked_by_id: dict[str, set[str]] = {}
    for item in checks:
        row_id = str(item.get("row_id") or "")
        if not row_id:
            continue
        blocked_by_id.setdefault(row_id, set()).add(str(item.get("rule_id") or ""))
    if not blocked_by_id:
        return materialized, checks
    downgraded: list[dict[str, object]] = []
    for row in materialized:
        identity = _overclaim_row_identity(row)
        status = str(row.get("status") or row.get("verdict") or row.get("finding_status") or "").upper()
        rules = blocked_by_id.get(identity, set())
        injection_overclaim = bool(rules & _INJECTION_OVERCLAIM_RULES)
        should_downgrade = bool(rules) and (
            status in _CLOSED_FINDING_STATUSES
            or (injection_overclaim and status in _INJECTION_OVERCLAIM_STATUSES)
        )
        if should_downgrade:
            unknown = "UNKNOWN(adversarial overclaim check failed; typed relation missing)"
            unknowns = [item for item in list(row.get("unknowns") or []) if item]
            if unknown not in unknowns:
                unknowns.append(unknown)
            next_status = "UNKNOWN" if "INJECTS_SELF_LOOP" in rules else "CANDIDATE"
            row = {
                **row,
                "status": next_status,
                "finding_status": next_status,
                "verdict": next_status,
                "validation_status": next_status,
                "maliciousness_assessment": (
                    "not_assessed"
                    if next_status == "UNKNOWN"
                    else "candidate_security_relevant_behavior"
                ),
                "severity": "UNASSESSED",
                "is_behavior_edge": False if injection_overclaim else row.get("is_behavior_edge"),
                "unknowns": unknowns,
                "adversarial_downgrade": True,
            }
        elif injection_overclaim and str(row.get("severity") or "").upper() == "HIGH":
            row = {**row, "severity": "UNASSESSED", "adversarial_downgrade": True}
        downgraded.append(row)
    return downgraded, checks


def deep_analysis_metrics(
    *,
    document: Mapping[str, object],
    mechanisms: Iterable[Mapping[str, object]] = (),
    mechanism_projections: Iterable[Mapping[str, object]] = (),
    investigation_threads: Iterable[Mapping[str, object]] = (),
    investigation_actions: Iterable[Mapping[str, object]] = (),
) -> dict[str, object]:
    """Return closure, noise, action productivity and report-depth metrics."""
    mechanism_rows = [
        _mapping(item) for item in mechanisms
        if _is_visible_mechanism(_mapping(item))
    ]
    projection_rows = [
        _mapping(item) for item in mechanism_projections
        if _is_visible_mechanism(_mapping(item))
    ]
    # The ORM Mechanism record deliberately stores lifecycle/verifier state,
    # while the report projection carries the analyst-facing unknowns,
    # limitations, and concrete field values.  Quality must inspect the same
    # semantic rows that the user sees.  Merge by stable mechanism identity and
    # prefer the richer projection without dropping a formal ORM record that
    # has no visible counterpart.
    if projection_rows:
        def mechanism_identity(row: Mapping[str, object]) -> str:
            return str(
                row.get("mechanism_id")
                or row.get("id")
                or row.get("claim_id")
                or ""
            )

        merged: list[Mapping[str, object]] = []
        seen: set[str] = set()
        for row in projection_rows:
            identity = mechanism_identity(row)
            if identity and identity in seen:
                continue
            if identity:
                seen.add(identity)
            merged.append(row)
        for row in mechanism_rows:
            identity = mechanism_identity(row)
            if identity and identity in seen:
                continue
            if identity:
                seen.add(identity)
            merged.append(row)
        mechanism_rows = [dict(row) for row in merged]
    # A formal mechanism record can carry the same presentation marker during
    # replay.  Apply the filter after merging as well so it cannot re-enter
    # the population through the ORM collection.
    mechanism_rows = [row for row in mechanism_rows if _is_visible_mechanism(row)]
    if not mechanism_rows:
        # Some API task projections expose mechanisms only through the frozen
        # report document.  Derive the same rows here so evaluation does not
        # silently report an empty mechanism population (and a false 100%
        # candidate-noise rate) when the caller omits the optional collection.
        mechanism_rows = [
            row for row in _rows(document)
            if row.get("type") in _REPORT_MECHANISM_TYPES and _is_visible_mechanism(row)
        ]
    thread_rows = [_mapping(item) for item in investigation_threads]
    action_rows = [_mapping(item) for item in investigation_actions]
    seeds = len(thread_rows)
    closed_seeds = sum(
        1 for row in thread_rows
        if str(row.get("state", "")).upper() in {
            "MECHANISM_READY", "CLAIM_READY", "UNKNOWN", "BLOCKED",
            "REJECTED", "CONTRADICTED", "CLOSED",
        }
    )
    productive = sum(1 for row in action_rows if action_is_productive(row))

    def is_model_action(row: Mapping[str, object]) -> bool:
        origin = str(row.get("origin", "")).casefold()
        # An explicit origin is authoritative.  Planner metadata can be
        # copied onto a deterministic fallback during replay, but that must
        # never grant model-contribution credit.
        if origin:
            return origin == "model"
        scheduler = str(row.get("scheduler", "")).casefold()
        return scheduler == "model_plan" or bool(row.get("planner_turn_id"))

    model_actions = [row for row in action_rows if is_model_action(row)]
    accepted_model_actions = [
        row
        for row in model_actions
        if str(row.get("status", row.get("outcome", ""))).upper()
        not in {"REJECTED", "INVALID", "BLOCKED"}
    ]
    useful_model_actions = [row for row in accepted_model_actions if action_is_productive(row)]
    model_action_productivity = (
        len(useful_model_actions) / len(accepted_model_actions)
        if accepted_model_actions
        else 0.0
    )
    autopsy_rows: list[dict[str, object]] = []
    for row in accepted_model_actions:
        outcome = str(row.get("outcome") or row.get("status") or "").upper()
        if outcome != "NO_NEW_EVIDENCE" and str(row.get("error", "")).upper() != "NO_NEW_EVIDENCE":
            continue
        autopsy = no_new_evidence_autopsy(row)
        category = str(row.get("autopsy_category") or autopsy["category"]).upper()
        autopsy_rows.append(
            {
                "action_id": row.get("id"),
                "action_type": row.get("action_type"),
                "category": category,
                "target_selector": autopsy["target_selector"],
                "target": autopsy["target"],
                "dedupe_key": autopsy["dedupe_key"],
                "artifact_boundary": autopsy["artifact_boundary"],
                "next_action": autopsy["next_action"],
                "reason": autopsy["reason"],
            }
        )
    document_mechanisms = [
        row for row in _rows(document)
        if row.get("type") in _REPORT_MECHANISM_TYPES and _is_visible_mechanism(row)
    ]
    candidate_count = sum(
        1 for row in document_mechanisms
        if str(row.get("status", row.get("verdict", ""))).upper()
        not in _CLOSED_STATUSES
    )
    quality = report_depth_score(document)
    critic = critic_pass(document)
    closure = closed_seeds / seeds if seeds else 0.0
    action_productivity = productive / len(action_rows) if action_rows else 0.0
    unresolved = [
        row for row in mechanism_rows
        if str(row.get("status", row.get("verdict", ""))).upper() not in _CLOSED_STATUSES
    ]

    def has_unknown_record(row: Mapping[str, object]) -> bool:
        for key in ("unknowns", "limitations", "missing", "reason"):
            value = row.get(key)
            if isinstance(value, str) and value.strip():
                return True
            if isinstance(value, (list, tuple, set)) and value:
                return True
        return False

    unknown_recorded_rate = (
        sum(1 for row in unresolved if has_unknown_record(row)) / len(unresolved)
        if unresolved else 1.0
    )
    # Candidate noise is a visible-report ratio.  Do not add the candidate
    # count to the denominator again: the candidate rows are already part of
    # the mechanism population, and double-counting makes the metric depend
    # on whether the caller supplied an optional projection collection.
    candidate_population = len(document_mechanisms) or len(mechanism_rows)
    candidate_noise_ratio = min(1.0, candidate_count / max(1, candidate_population))
    blockers: list[str] = []
    if seeds and closure < 0.9:
        blockers.append("seed_closure")
    if (seeds or action_rows) and (not action_rows or action_productivity < 0.6):
        blockers.append("action_productivity")
    critical_rows = [
        row for row in mechanism_rows
        if row.get("critical") is True
        or row.get("type") == "security_finding"
        or str(row.get("severity", "")).upper() in {"CRITICAL", "HIGH"}
    ] or mechanism_rows
    critical_ready_count = sum(
        1 for row in critical_rows
        if str(row.get("status", row.get("verdict", ""))).upper() in _CLOSED_STATUSES
        and inspect_mechanism_ready(row).critical_ready
    )
    if critical_rows and critical_ready_count / len(critical_rows) < 0.8:
        blockers.append("critical_mechanism_closure")
    if candidate_noise_ratio > 0.2:
        blockers.append("candidate_noise")
    if unresolved and unknown_recorded_rate < 1.0:
        blockers.append("unknowns")
    if quality["score"] < 80:
        blockers.append("report_depth")
    if critic["status"] == "BLOCKED":
        blockers.append("critic")
    s4_orchestration = _s4_orchestration_status(thread_rows, action_rows)
    if any(row["status"] == "BLOCKED" for row in s4_orchestration):
        blockers.append("s4_orchestration")
    return {
        "high_value_seed_closure_rate": round(closure, 4),
        "candidate_noise_ratio": round(candidate_noise_ratio, 4),
        "mechanism_completeness": round(
            sum(mechanism_completeness_score(row) for row in mechanism_rows) / max(1, len(mechanism_rows)), 2
        ),
        "critical_mechanism_closure_rate": round(
            critical_ready_count / max(1, len(critical_rows)), 4
        ),
        "action_productivity_rate": round(action_productivity, 4),
        "accepted_model_actions": len(accepted_model_actions),
        "useful_model_actions": len(useful_model_actions),
        "model_productivity_breakdown": {
            "new_evidence": sum(
                1 for row in useful_model_actions
                if _has_nonempty(row.get("new_evidence_ids") or row.get("result_evidence_ids"))
                or int(row.get("new_evidence_count", 0) or 0) > 0
            ),
            "hypothesis_elimination": sum(
                1 for row in useful_model_actions
                if str(row.get("outcome", "")).upper()
                in {"HYPOTHESIS_ELIMINATED", "COMPETING_HYPOTHESIS_ELIMINATED"}
                or _has_nonempty(row.get("eliminated_hypothesis_ids"))
                or _has_nonempty(row.get("competing_hypotheses_eliminated"))
            ),
            "mechanism_completion": sum(
                1 for row in useful_model_actions
                if str(row.get("outcome", "")).upper()
                in {"MECHANISM_FIELDS_COMPLETED", "MECHANISM_UPDATED"}
                or _has_nonempty(row.get("mechanism_fields_completed"))
                or _has_nonempty(row.get("completed_fields"))
                or _has_nonempty(row.get("fields_completed"))
            ),
        },
        "model_action_productivity_rate": round(model_action_productivity, 4),
        "no_new_evidence_autopsy": autopsy_rows,
        "unknown_recorded_rate": round(unknown_recorded_rate, 4),
        "readiness_blockers": tuple(dict.fromkeys(blockers)),
        "report_depth": quality,
        "critic": critic,
        "s4_orchestration": s4_orchestration,
        "readiness": "READY_FOR_REPORT" if not blockers and quality["score"] >= 80 else "BOUNDED_WITH_LIMITATIONS",
        "static_only": True,
    }


__all__ = [
    "NO_NEW_EVIDENCE_CATEGORIES",
    "action_is_productive",
    "apply_adversarial_downgrades",
    "critic_pass",
    "deep_analysis_metrics",
    "no_new_evidence_autopsy",
    "report_depth_score",
]
