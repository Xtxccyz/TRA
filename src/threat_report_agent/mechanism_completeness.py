"""Shared semantic completeness scoring for mechanism projections."""

from __future__ import annotations

from collections.abc import Mapping, Sequence


FIELD_WEIGHTS: tuple[tuple[str, int], ...] = (
    ("target", 10),
    ("inputs", 15),
    ("transformation_or_control", 20),
    ("conditions", 10),
    ("outputs", 15),
    ("consumers", 15),
    ("side_effects", 10),
    ("evidence_ids", 5),
)
_UNKNOWN_MARKERS = ("unknown(", "unknown:", "<unknown>", "not recovered", "unresolved")
_NAVIGATION_MARKERS = {
    "prioritizes", "references", "matches", "calls", "xref", "cfg prominence",
    "call-site density", "contains rva-level call sites", "function review priority",
}


def _values(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value.strip(),) if value.strip() else ()
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    return (str(value).strip(),) if str(value).strip() else ()


def is_unknown_value(value: object) -> bool:
    values = _values(value)
    return not values or any(
        any(marker in item.casefold() for marker in _UNKNOWN_MARKERS)
        for item in values
    )


def is_navigation_value(value: object) -> bool:
    values = _values(value)
    return any(
        any(marker in item.casefold() for marker in _NAVIGATION_MARKERS)
        for item in values
    )


def has_semantic_value(key: str, value: object) -> bool:
    """Return whether a field carries actual mechanism semantics."""
    if is_unknown_value(value) or is_navigation_value(value):
        return False
    values = " ".join(_values(value)).casefold()
    if key == "evidence_ids":
        return bool(_values(value))
    if key == "conditions" and values in {"static evidence only", "static only", "static evidence"}:
        # Boundary is useful context but not a mechanism condition by itself.
        return False
    if key == "transformation_or_control" and any(marker in values for marker in _NAVIGATION_MARKERS):
        return False
    if key == "side_effects" and any(marker in values for marker in _NAVIGATION_MARKERS):
        return False
    return True


def mechanism_completeness_score(mechanism: Mapping[str, object]) -> int:
    """Score only semantic fields and apply mandatory-field hard caps."""
    score = sum(weight for key, weight in FIELD_WEIGHTS if has_semantic_value(key, mechanism.get(key)))
    input_known = has_semantic_value("inputs", mechanism.get("inputs"))
    consumer_known = has_semantic_value("consumers", mechanism.get("consumers"))
    transform_known = has_semantic_value("transformation_or_control", mechanism.get("transformation_or_control"))
    side_effect_known = has_semantic_value("side_effects", mechanism.get("side_effects"))
    if not input_known:
        score = min(score, 70)
    if not consumer_known:
        score = min(score, 75)
    if not input_known and not consumer_known:
        score = min(score, 60)
    if not transform_known:
        score = min(score, 40)
    if not side_effect_known:
        score = min(score, 50)
    return max(0, min(100, score))


def mechanism_is_critical_ready(mechanism: Mapping[str, object]) -> bool:
    """A VERIFIED mechanism must meet semantic and provenance requirements."""
    return (
        mechanism_completeness_score(mechanism) >= 80
        and has_semantic_value("target", mechanism.get("target"))
        and has_semantic_value("transformation_or_control", mechanism.get("transformation_or_control"))
        and has_semantic_value("outputs", mechanism.get("outputs"))
        and has_semantic_value("consumers", mechanism.get("consumers"))
        and has_semantic_value("evidence_ids", mechanism.get("evidence_ids"))
        and str((mechanism.get("verifier") or {}).get("status", "")).upper() == "VERIFIED"
    )


def verify_semantic_closure(mechanism: Mapping[str, object]) -> dict[str, object]:
    """Run the bounded static verifier over one projected mechanism.

    This verifier checks semantic field quality and provenance. It never
    claims that a sample executed; runtime reachability remains a boundary.
    """
    score = mechanism_completeness_score(mechanism)
    checks = {
        "target": has_semantic_value("target", mechanism.get("target")),
        "input": has_semantic_value("inputs", mechanism.get("inputs")),
        "transformation": has_semantic_value("transformation_or_control", mechanism.get("transformation_or_control")),
        "output": has_semantic_value("outputs", mechanism.get("outputs")),
        "consumer": has_semantic_value("consumers", mechanism.get("consumers")),
        "side_effect": has_semantic_value("side_effects", mechanism.get("side_effects")),
        "evidence_provenance": has_semantic_value("evidence_ids", mechanism.get("evidence_ids")),
    }
    reasons = [name for name, passed in checks.items() if not passed]
    accepted = score >= 80 and len(_values(mechanism.get("evidence_ids"))) >= 2 and not reasons
    return {
        "status": "VERIFIED" if accepted else "CANDIDATE",
        "accepted": accepted,
        "score": score,
        "checks": [{"name": name, "passed": passed} for name, passed in checks.items()],
        "missing": reasons,
        "reason": "semantic fields and static provenance satisfy the bounded verifier" if accepted else "missing semantic closure fields: " + ", ".join(reasons),
    }


__all__ = [
    "FIELD_WEIGHTS", "has_semantic_value", "is_navigation_value", "is_unknown_value",
    "mechanism_completeness_score", "mechanism_is_critical_ready", "verify_semantic_closure",
]
