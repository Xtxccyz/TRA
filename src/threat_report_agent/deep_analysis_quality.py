"""Deterministic quality gates for analyst-grade static analysis.

This module evaluates the *shape and provenance* of an investigation result.  It
never executes an artifact and never turns a candidate into a verified claim.
The output is intentionally small enough to persist in a report snapshot while
the complete evidence ledger remains available through the explorer.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from threat_report_agent.mechanism_completeness import (
    has_semantic_value,
    mechanism_completeness_score,
    mechanism_is_critical_ready,
)


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
        if row.get("type") in {"mechanism_candidate", "security_finding"}
    ]
    closed = [
        row for row in mechanisms
        if str(row.get("status") or row.get("verdict") or "").upper()
        in {"VERIFIED", "SUPPORTED", "CONFIRMED"}
        and mechanism_is_critical_ready(row)
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
        "status": "PASS" if not unsupported and not wording_violations and not alternatives_missing and not unknown_metadata_missing else "BLOCKED",
    }


def deep_analysis_metrics(
    *,
    document: Mapping[str, object],
    mechanisms: Iterable[Mapping[str, object]] = (),
    investigation_threads: Iterable[Mapping[str, object]] = (),
    investigation_actions: Iterable[Mapping[str, object]] = (),
) -> dict[str, object]:
    """Return closure, noise, action productivity and report-depth metrics."""
    mechanism_rows = [_mapping(item) for item in mechanisms]
    if not mechanism_rows:
        # Some API task projections expose mechanisms only through the frozen
        # report document.  Derive the same rows here so evaluation does not
        # silently report an empty mechanism population (and a false 100%
        # candidate-noise rate) when the caller omits the optional collection.
        mechanism_rows = [
            row for row in _rows(document)
            if row.get("type") in {"mechanism_candidate", "security_finding", "analytical_claim"}
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
        scheduler = str(row.get("scheduler", "")).casefold()
        return origin == "model" or scheduler == "model_plan" or bool(row.get("planner_turn_id"))

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
        if row.get("type") in {"mechanism_candidate", "security_finding", "analytical_claim"}
    ]
    candidate_count = sum(
        1 for row in document_mechanisms
        if row.get("type") == "mechanism_candidate"
        and str(row.get("status", "")).upper() not in {"VERIFIED", "SUPPORTED", "CONFIRMED"}
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
        and mechanism_is_critical_ready(row)
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
        "readiness": "READY_FOR_REPORT" if not blockers and quality["score"] >= 80 else "BOUNDED_WITH_LIMITATIONS",
        "static_only": True,
    }


__all__ = [
    "NO_NEW_EVIDENCE_CATEGORIES",
    "action_is_productive",
    "critic_pass",
    "deep_analysis_metrics",
    "no_new_evidence_autopsy",
    "report_depth_score",
]
