"""Reference-isolated mechanism scorecards for offline evaluation.

This module consumes a completed task view and evaluator-supplied Gold data.
It is intentionally outside ``src/threat_report_agent`` so runtime analysis
cannot import it by accident. The evaluator compares support structures only;
it never writes conclusions back into an Agent task.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping


_COMPONENTS = (
    "entry",
    "input",
    "transformation",
    "condition",
    "output",
    "side_effect",
    "consumer",
    "anchors",
)


@dataclass(frozen=True)
class ComponentResult:
    component: str
    status: str
    evidence_ids: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class MechanismResult:
    mechanism_id: str
    status: str
    completeness: float
    components: tuple[ComponentResult, ...]
    discrepancy: str | None

    def as_dict(self) -> dict[str, object]:
        return {
            "mechanism_id": self.mechanism_id,
            "status": self.status,
            "completeness": self.completeness,
            "components": [
                {
                    **item.__dict__,
                    "evidence_ids": list(item.evidence_ids),
                }
                for item in self.components
            ],
            "discrepancy": self.discrepancy,
        }


def _text(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, default=str).casefold()


def _evidence_matches(evidence: list[Mapping[str, Any]], tokens: tuple[str, ...]) -> list[Mapping[str, Any]]:
    if not tokens:
        return []
    required = tuple(token.casefold() for token in tokens)
    # A semantic component may be distributed over several Evidence rows
    # (e.g. OpenProcess, an attribute constant, and CreateProcessW). Return
    # the union only when every required token is covered; this preserves
    # provenance without requiring extractors to coalesce unrelated facts.
    matching = [
        row
        for row in evidence
        if any(token in _text({"value": row.get("value"), "anchor": row.get("anchor")}) for token in required)
    ]
    if all(
        any(token in _text({"value": row.get("value"), "anchor": row.get("anchor")}) for row in matching)
        for token in required
    ):
        return matching
    return []


def _evidence_mentions(evidence: list[Mapping[str, Any]], tokens: tuple[str, ...]) -> list[Mapping[str, Any]]:
    """Return partial mechanism leads without treating them as component support."""
    if not tokens:
        return []
    candidates = tuple(token.casefold() for token in tokens)
    return [
        row
        for row in evidence
        if any(token in _text({"value": row.get("value"), "anchor": row.get("anchor")}) for token in candidates)
    ]


def _classify_gap(task_view: Mapping[str, Any], tokens: tuple[str, ...]) -> str:
    evidence = [
        row for row in task_view.get("evidence", []) if isinstance(row, Mapping)
    ]
    leads = _evidence_mentions(evidence, tokens)
    if not leads:
        return "missing_static_evidence"
    delivery = task_view.get("evidence_delivery", {})
    records = delivery.get("records", []) if isinstance(delivery, Mapping) else []
    lead_ids = {str(row.get("id")) for row in leads}
    if any(
        record.get("evidence_id") in lead_ids and record.get("stage") == "CANDIDATE"
        and record.get("exclusion_reason")
        for record in records
        if isinstance(record, Mapping)
    ):
        return "retrieval_failure"
    limitations = " ".join(str(item).casefold() for item in task_view.get("limitations", []))
    if "dynamic" in limitations and any(
        marker in limitations
        for marker in ("require", "authoriz", "unavailable", "boundary")
    ):
        return "requires_authorized_dynamic_phase"
    if "unsupported" in limitations and any(
        marker in limitations for marker in ("child", "artifact", "carrier", "decoder")
    ):
        return "unsupported_child_type_or_static_boundary"
    investigation = task_view.get("investigation", {})
    actions = investigation.get("actions", []) if isinstance(investigation, Mapping) else []
    if not actions:
        return "action_planning_failure"
    if not task_view.get("claims"):
        return "analysis_or_verifier_failure"
    if any("dynamic" in str(item).casefold() for item in task_view.get("limitations", [])):
        return "requires_authorized_dynamic_phase"
    return "unsupported_child_type_or_static_boundary"


def build_semantic_differential(
    task_view: Mapping[str, Any],
    gold: Mapping[str, Any],
) -> dict[str, object]:
    """Score Gold mechanisms outside the Agent path.

    ``gold`` has the schema ``{"version": str, "mechanisms": [{"id": str,
    "components": {component: [required_anchor_tokens]}}]}``. Anchor tokens
    are evaluator-only. They are never returned to the caller as model context.
    """
    evidence = [row for row in task_view.get("evidence", []) if isinstance(row, Mapping)]
    delivery = task_view.get("evidence_delivery", {})
    delivery_records = delivery.get("records", []) if isinstance(delivery, Mapping) else []
    excluded_ids = {
        str(record.get("evidence_id"))
        for record in delivery_records
        if isinstance(record, Mapping)
        and record.get("stage") == "CANDIDATE"
        and record.get("exclusion_reason")
    }
    # Retrieval is a view over the immutable Evidence ledger.  An excluded
    # candidate must not poison a component when another matching row was
    # delivered successfully.  Keep the full set for gap classification so a
    # component whose *only* matches were excluded is still reported as a
    # retrieval failure rather than silently becoming "missing".
    effective_evidence = [
        row for row in evidence if str(row.get("id")) not in excluded_ids
    ]
    results: list[MechanismResult] = []
    for mechanism in gold.get("mechanisms", []):
        if not isinstance(mechanism, Mapping):
            continue
        mechanism_id = str(mechanism.get("id", ""))
        expected = mechanism.get("components", {})
        if not mechanism_id or not isinstance(expected, Mapping):
            continue
        components: list[ComponentResult] = []
        for component in _COMPONENTS:
            tokens_raw = expected.get(component, ())
            tokens = tuple(str(item) for item in tokens_raw if str(item)) if isinstance(tokens_raw, list) else ()
            if not tokens:
                components.append(ComponentResult(component, "NOT_APPLICABLE", (), "not required by rubric"))
                continue
            matched = _evidence_matches(effective_evidence, tokens)
            ids = tuple(str(row.get("id")) for row in matched if row.get("id"))
            if matched:
                components.append(ComponentResult(component, "SUPPORTED", ids, "anchored static evidence present"))
            elif _evidence_matches(evidence, tokens):
                # Every matching row was excluded from delivery.  This is a
                # retrieval problem, not evidence absence and not a semantic
                # refutation.
                components.append(
                    ComponentResult(
                        component,
                        "UNKNOWN",
                        ids,
                        "retrieval_failure",
                    )
                )
            else:
                components.append(
                    ComponentResult(
                        component,
                        "UNKNOWN",
                        (),
                        _classify_gap(task_view, tokens),
                    )
                )
        applicable = [item for item in components if item.status != "NOT_APPLICABLE"]
        supported = [item for item in applicable if item.status == "SUPPORTED"]
        completeness = len(supported) / len(applicable) if applicable else 1.0
        missing = [item for item in applicable if item.status != "SUPPORTED"]
        if not missing:
            status = "SUPPORTED"
            discrepancy = None
        elif any(item.reason == "requires_authorized_dynamic_phase" for item in missing):
            status = "STATIC_BOUNDARY"
            discrepancy = "requires_authorized_dynamic_phase"
        else:
            status = "UNKNOWN"
            discrepancy = missing[0].reason
        results.append(MechanismResult(mechanism_id, status, completeness, tuple(components), discrepancy))
    return {
        "evaluator_only": True,
        "gold_version": str(gold.get("version", "unversioned")),
        "task_id": task_view.get("id"),
        "mechanisms": [item.as_dict() for item in results],
        "summary": {
            "supported": sum(item.status == "SUPPORTED" for item in results),
            "unknown": sum(item.status == "UNKNOWN" for item in results),
            "static_boundary": sum(item.status == "STATIC_BOUNDARY" for item in results),
        },
    }
