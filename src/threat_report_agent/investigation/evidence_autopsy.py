"""P3.3f-1, cluster A: the PURE leaf for the no-new-evidence autopsy judgement.

WHY THIS MODULE EXISTS. `_run_investigation_loop` (3,523 lines, P3.3f) closes over exactly one name that plan section
3.2 does not admit into `investigation/`: `no_new_evidence_autopsy`, which lives in
`threat_report_agent.deep_analysis_quality`. MEASURED (`.scratch/p33f-layer-scan.py`): it was the ONLY forbidden name of
the loop's 63 - every other one comes from an allowed layer, stdlib, or `service.py` itself.

WHY IT IS SUNK RATHER THAN ROUTED THROUGH THE HOST PORT. Its whole closure is 87 lines plus two constants
(`NO_NEW_EVIDENCE_CATEGORIES`, `_AUTOPSY_NEXT_ACTIONS`) and two tiny predicates (`_first_selector_value`,
`_has_nonempty`), measured with `.scratch/p33f-sink-measure.py`. It reads no host state and imports nothing but stdlib,
so it belongs in the same shape this phase already uses for pure helpers (P3.3e's `derivation_support.py`) instead of
costing the loop's port a member and the host a wrapper.

WHAT STAYS BEHIND, and the trap this step had to avoid: the two occurrences of this name inside
`investigation/investigation.py` LOOK like a pre-existing `investigation -> deep_analysis_quality` edge, and a
grep-based scan would conclude the edge is already there and simply add the import. THEY ARE STRING LITERALS - the module
does not import `deep_analysis_quality` at all. Adding the import would therefore have been a genuinely new forbidden
edge, and the phase's `emulation.controlled_emulation` ruling says a pre-existing use would not have licensed it either.

`deep_analysis_quality.py` keeps the name reachable (it re-exports everything that moved and still calls it), so its own
readers, `service.py`'s five call sites and the test files that read it are unchanged. That re-export is a P4 deletion
target, recorded in the step's records.
"""
from __future__ import annotations

from typing import Mapping


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

