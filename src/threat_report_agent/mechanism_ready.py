"""Mechanism readiness façade: one projection, four independent answers.

Playbook ClaimGate, catalog contracts, protocol fill, completeness scoring,
and report HOW projection remain separate engines. Callers ask this module
instead of combining those engines ad hoc.

CANDIDATE never becomes ``critical_ready``. Recovered persist HOW is not a
verified mechanism.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from threat_report_agent.mechanism_completeness import (
    has_semantic_value,
    mechanism_completeness_score,
    mechanism_is_critical_ready,
    verify_semantic_closure,
)


@dataclass(frozen=True)
class MechanismReady:
    """Layered readiness of one mechanism projection.

    Fields are independent. ``persist_how_recovered`` may be true while
    ``critical_ready`` is false. ``claim_eligible`` comes from investigation
    coverage when present; it is not inferred from completeness.

    ``critical_ready`` is the certification/report count. Specialist mint still
    uses ``mechanism_is_critical_ready`` so a CANDIDATE row can be upgraded
    when semantic fields and verifier pass.
    """

    completeness: int
    persist_how_recovered: bool
    claim_eligible: bool
    critical_ready: bool
    missing: tuple[str, ...]


def inspect_mechanism_ready(mechanism: Mapping[str, object]) -> MechanismReady:
    """Read readiness from a mechanism projection mapping.

    Does not run ClaimGate, catalog evaluate, or the report FUN-dump filter.
    Those stay in investigation / behavior_catalog / reporting.
    """
    completeness = mechanism_completeness_score(mechanism)
    closure = verify_semantic_closure(mechanism)
    missing = tuple(str(item) for item in (closure.get("missing") or ()) if item)
    how = mechanism.get("transformation_or_control")
    if not has_semantic_value("transformation_or_control", how):
        how = mechanism.get("how")
    persist_how_recovered = has_semantic_value("transformation_or_control", how)
    coverage = mechanism.get("coverage")
    claim_eligible = bool(
        isinstance(coverage, Mapping) and coverage.get("claim_eligible")
    )
    status = str(mechanism.get("status") or "").upper()
    return MechanismReady(
        completeness=completeness,
        persist_how_recovered=persist_how_recovered,
        claim_eligible=claim_eligible,
        critical_ready=mechanism_is_critical_ready(mechanism) and status != "CANDIDATE",
        missing=missing,
    )


__all__ = ["MechanismReady", "inspect_mechanism_ready"]
