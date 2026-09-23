"""P3.3 layer item 1: the investigation loop-path and persist-HOW SKIP policy.

WHY THIS MODULE EXISTS HERE RATHER THAN IN `task/`: `task/analysis_task_orchestration.py` imports `investigation`, so
policy that `investigation/` itself needs cannot live in task - the import would be a cycle. MEASURED: this cluster is
16 module-level names / 169 lines and self-contained; the loop (`P3.3f`) and the action-proposal slice (`P3.3c(2)`, which needs
`action_is_model_or_human`) were both BLOCKED on exactly this.

`task/analysis_task_orchestration.py` re-exports every name below, so existing importers keep working and
`task.analysis_task_orchestration.<name> is investigation.loop_path.<name>` stays true.

MOVED VERBATIM from that module; the only changes are this header and the imports it needs.
"""
from __future__ import annotations

from dataclasses import dataclass
from threat_report_agent.investigation.investigation import recovery_actions_for_gap
from types import SimpleNamespace
from typing import (
    Callable,
    Iterable,
    Mapping,
)

# Keyword supporting seeds still get durable UNKNOWN threads so reports and
# multi-seed tests see the question, but leftover TRACE is not charged.
SUPPORTING_SKIP_CATEGORIES = frozenset(
    {
        "persistence",
        "evasion",
        "pe_parser",
        "injection",
        "entrypoint",
    }
)

SLOT_DEAD_LETTER_ATTEMPTS = 3

PERSIST_HOW_READY = "ready"

PERSIST_HOW_BOUNDARY = "boundary"

PERSIST_HOW_MINE = "mine"

PersistHowSeedFn = Callable[..., object | None]

PersistHowBoundaryFn = Callable[..., object | None]


@dataclass(frozen=True)
class PersistHowDecision:
    """Whether leftover TRACE may run after persist HOW facts are already in the ledger."""

    disposition: str
    result: object | None = None
    playbook: object | None = None


def unique_os_thread_playbook() -> SimpleNamespace:
    return SimpleNamespace(id="unique-os-thread", mechanism_type="THREAD_CALLBACK")


def resolve_persist_how_skip(
    *,
    playbook: object | None,
    evidence: Iterable[object],
    thread_id: str,
    artifact_id: str,
    cluster_category: str,
    model_actions_only: bool,
    proposed_actions: Iterable[object],
    historical_attempts: int,
    seed_result: PersistHowSeedFn,
    static_boundary: PersistHowBoundaryFn,
    unique_thread: PersistHowSeedFn,
    supporting_boundary: PersistHowBoundaryFn,
) -> PersistHowDecision:
    """Decide persist HOW skip before budget deferral or DeepMiningPlanner.

    Persist CANDIDATE/UNKNOWN is report content. Leftover TRACE cannot invent
    missing catalog tokens. Required recovery tools and first-round model
    catalog actions cancel skip so the seed stays mineable.
    """
    persist_ready = (
        seed_result(
            playbook=playbook,
            evidence=evidence,
            thread_id=thread_id,
            artifact_id=artifact_id,
        )
        if playbook is not None and not model_actions_only
        else None
    )
    persist_boundary = (
        static_boundary(
            playbook=playbook,
            evidence=evidence,
            thread_id=thread_id,
            artifact_id=artifact_id,
        )
        if playbook is not None and persist_ready is None and not model_actions_only
        else None
    )
    resolved_playbook = playbook
    if (
        persist_boundary is None
        and persist_ready is None
        and playbook is None
        and not model_actions_only
    ):
        unique_ready = unique_thread(
            evidence=evidence,
            thread_id=thread_id,
            artifact_id=artifact_id,
        )
        if unique_ready is not None:
            persist_ready = unique_ready
            resolved_playbook = unique_os_thread_playbook()
        elif cluster_category in SUPPORTING_SKIP_CATEGORIES:
            persist_boundary = supporting_boundary(
                evidence=evidence,
                thread_id=thread_id,
                artifact_id=artifact_id,
                category=cluster_category,
            )
    if (
        persist_ready is None
        and persist_boundary is None
        and int(historical_attempts or 0) >= SLOT_DEAD_LETTER_ATTEMPTS
    ):
        persist_boundary = static_boundary(
            playbook=resolved_playbook,
            evidence=evidence,
            thread_id=thread_id,
            artifact_id=artifact_id,
        ) or supporting_boundary(
            evidence=evidence,
            thread_id=thread_id,
            artifact_id=artifact_id,
            category=cluster_category,
        )
    persist_gate = None
    if persist_ready is not None:
        persist_gate = getattr(persist_ready, "gate", None)
    elif persist_boundary is not None:
        persist_gate = getattr(persist_boundary, "gate", None)
    persist_recovery = (
        recovery_actions_for_gap(
            str(getattr(resolved_playbook, "mechanism_type", "") or ""),
            getattr(persist_gate, "missing", ()) or (),
            evidence=evidence if isinstance(evidence, Iterable) else (),
        )
        if resolved_playbook is not None
        else ()
    )
    if persist_ready is not None and (
        persist_recovery or any(action_is_model_or_human(item) for item in proposed_actions)
    ):
        persist_ready = None
        persist_boundary = None
    if persist_ready is not None:
        return PersistHowDecision(PERSIST_HOW_READY, persist_ready, resolved_playbook)
    if persist_boundary is not None:
        return PersistHowDecision(PERSIST_HOW_BOUNDARY, persist_boundary, resolved_playbook)
    return PersistHowDecision(PERSIST_HOW_MINE, None, resolved_playbook)


LOOP_PATH_PERSIST_READY = "persist_ready"

LOOP_PATH_PERSIST_BOUNDARY = "persist_boundary"

LOOP_PATH_BUDGET_DEFER = "budget_defer"

LOOP_PATH_PLANNER = "planner"


def next_investigation_loop_path(
    persist_how: PersistHowDecision,
    *,
    budget_exhausted: bool,
) -> str:
    """Persist HOW skip beats budget; budget beats DeepMiningPlanner.

    READY / BOUNDARY still run leftover CONTROLLED_EMULATE. MINE with a full
    budget defers the seed instead of charging TRACE. There is no zero-cost
    skip that treats an empty proposal list as persist-ready.
    """
    if persist_how.disposition == PERSIST_HOW_READY:
        return LOOP_PATH_PERSIST_READY
    if persist_how.disposition == PERSIST_HOW_BOUNDARY:
        return LOOP_PATH_PERSIST_BOUNDARY
    if budget_exhausted:
        return LOOP_PATH_BUDGET_DEFER
    return LOOP_PATH_PLANNER


def action_is_model_or_human(item: object) -> bool:
    """First-round analyze catalog actions must survive persist HOW skip."""
    provenance = getattr(item, "provenance", None)
    if isinstance(provenance, Mapping):
        origin = str(provenance.get("origin") or "").casefold()
        if origin in {"model", "human"}:
            return True
    if str(getattr(item, "planner_turn_id", "") or "").strip():
        return True
    parameters = getattr(item, "parameters", None)
    if not isinstance(parameters, Mapping):
        parameters = {}
    origin = str(parameters.get("origin") or "").casefold()
    if origin in {"model", "human"}:
        return True
    if parameters.get("_planner_turn_id") or parameters.get("_model_provenance"):
        return True
    return False
