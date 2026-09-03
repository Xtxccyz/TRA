"""Evaluator-only Round 11 generalization and failure taxonomy helpers."""

from __future__ import annotations

from typing import Mapping

from threat_report_agent.product_certification import FailureRootCause, evaluate_gold


def classify_failure(result: Mapping[str, object]) -> str | None:
    """Assign one primary root cause, in the order of the analysis chain."""
    if result.get("analysis_class") == "FAILED_ANALYSIS":
        if result.get("artifact_error"):
            return FailureRootCause.ARTIFACT_FAILURE.value
        if result.get("tool_error"):
            return FailureRootCause.TOOL_RESULT_FAILURE.value
        if result.get("report_error"):
            return FailureRootCause.REPORT_FAILURE.value
        return FailureRootCause.PRODUCT_FAILURE.value
    if not result.get("threads"):
        return FailureRootCause.SEED_DISCOVERY_FAILURE.value
    if result.get("question_error"):
        return FailureRootCause.QUESTION_FAILURE.value
    if result.get("retrieval_error"):
        return FailureRootCause.RETRIEVAL_FAILURE.value
    if result.get("delivery_error"):
        return FailureRootCause.DELIVERY_FAILURE.value
    if result.get("context_error"):
        return FailureRootCause.CONTEXT_QUALITY_FAILURE.value
    if result.get("action_error"):
        return FailureRootCause.ACTION_FAILURE.value
    if result.get("mechanism_error"):
        return FailureRootCause.MECHANISM_SYNTHESIS_FAILURE.value
    if result.get("verifier_error"):
        return FailureRootCause.VERIFIER_FAILURE.value
    if result.get("claim_gate_error"):
        return FailureRootCause.CLAIM_GATE_FAILURE.value
    if result.get("boundary_error"):
        return FailureRootCause.BOUNDARY_CLASSIFICATION_FAILURE.value
    return None


def build_failure_taxonomy(results: list[Mapping[str, object]]) -> dict[str, object]:
    counts: dict[str, int] = {}
    rows: list[dict[str, object]] = []
    for result in results:
        cause = classify_failure(result)
        if cause is None:
            continue
        counts[cause] = counts.get(cause, 0) + 1
        rows.append({"sample_id": result.get("sample_id"), "root_cause": cause})
    return {"version": "round11-failure-taxonomy-v1", "counts": counts, "failures": rows}


__all__ = ["build_failure_taxonomy", "classify_failure", "evaluate_gold"]

