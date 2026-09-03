from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class ValidationResult:
    decision: str  # AGREE, DISAGREE, N/A
    accepted: bool
    reason: str
    evidence_ids: tuple[str, ...]
    source_independence: str = "same_static_source"


def validate_claim_evidence(
    evidence_ids: list[str] | tuple[str, ...],
    allowed_ids: set[str],
    *,
    module: str | None = None,
    allowed_modules: set[str] | None = None,
    evidence_natures: Mapping[str, str] | None = None,
    disallowed_natures: frozenset[str] = frozenset({"BACKGROUND_REPORTED"}),
) -> ValidationResult:
    unique = tuple(dict.fromkeys(evidence_ids))
    if not unique:
        return ValidationResult("DISAGREE", False, "claim has no Evidence references", unique)
    unknown = sorted(set(unique) - allowed_ids)
    if unknown:
        return ValidationResult(
            "DISAGREE", False, f"claim references unknown Evidence: {unknown}", unique
        )
    if evidence_natures is not None:
        disallowed = sorted(
            evidence_id
            for evidence_id in unique
            if evidence_natures.get(evidence_id) in disallowed_natures
        )
        if disallowed:
            return ValidationResult(
                "DISAGREE",
                False,
                f"claim references disallowed Evidence nature: {disallowed}",
                unique,
            )
    if allowed_modules is not None and module not in allowed_modules:
        return ValidationResult(
            "DISAGREE", False, f"claim module is outside the analysis contract: {module}", unique
        )
    return ValidationResult(
        "AGREE", True, "all Evidence references are in the frozen context", unique
    )
