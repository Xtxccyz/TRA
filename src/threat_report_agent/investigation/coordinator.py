"""P3.3 investigation coordinator: the port an investigation slice needs from its host, plus the slice behind it.

STATUS: slice P3.3b (frontier helpers) has moved. Plan 7.1 orders every migration in nine steps - step 2 is
"先建立最小公开接口和 contract test" and step 3 is "移动同一份实现" - and P3.3 is executed in the six slices its
measurement produced (`docs/p33-investigation-coordinator-design-20260922.md`), smallest port cost first.

WHAT MOVED IN P3.3b: `_build_investigation_frontier`, `_convergence_frontier_fingerprint`, `_frontier_value_present`,
`_unattempted_seed_thread_ids` and `_mechanism_missing_fields` (MEASURED: its only use in service.py is inside the
moved `_build_investigation_frontier`, so it travels with the slice rather than widening the port), plus the
module-level pair `frontier_status_is_open` / `deferred_keeps_planner_open` and the two frozensets they close over.

THE SLICE IS SMALLER THAN THE FRAGMENT SCAN SUGGESTED, AND A PLAN RULE IS WHY. Four members that the scan grouped
with this one stayed on the host:

  `_is_unique_thread_seed_row`, `_unique_thread_start_keys` and `_unique_execution_threads_for_view` read
  `_address_lookup_keys` / `build_unique_execution_threads` from `report/reporting.py`, and plan 3.2's
  allowed-dependency matrix (line 132) lets `investigation/` import only contracts, facts, static/emulation/tools
  interfaces and the model port - "未列出的边默认禁止". Moving them would therefore have created a NEW forbidden
  `investigation -> report` edge, so they did not move; `_select_unique_thread_seed_rows` stayed with them because it
  calls two of them. MEASURED with `.scratch/p33b-edge.py`, which had to be pointed at the PRE-MOVE revision: run
  against the working tree it first reported "no member needs report.reporting", because by then the bodies it was
  scanning had already been replaced by one-line delegations.

  Unblocking that sub-slice is its own step and needs the shared helpers pushed DOWN to a layer `investigation/` may
  import (facts/ or static/), exactly the shape of the `facts -> investigation` decision recorded in
  `docs/plan-conflict-resolutions-20260922.md`: move the thing first, then the edge, never one alone.

THE PORT (ONE member, and that matches the design's own measurement): `database`. The design's slice table measured
this slice's need as "无（切片内自洽，只需 `database`）" and it was right; the first implementation of this step
exported two class constants that only a STAYING member reads, which was a port widened on a false claim.

WHY THE MOVE SPLITS HOST STATE FROM CLOSURE STATE, as a rule rather than case by case:

  * a CLASS ATTRIBUTE read through the receiver stays on the host (`_CATALOG_HOW_SEED_SCAN_LIMIT` is also read by
    un-moved code; `_UNIQUE_THREAD_VIEW_KINDS` is an attribute of `AnalysisService` whose only reader also stayed);
  * MODULE-LEVEL state that only a moved function closes over TRAVELS with that function, because this module may not
    import service - if the frozensets had stayed, the moved predicates could not read them at all;
  * no shim is kept for the two frozensets: MEASURED, nothing else in the repository reads them, and the two functions
    they belong to are the same objects in both namespaces (`service.frontier_status_is_open is
    coordinator.frontier_status_is_open`).

    python -m pytest -q tests/test_investigation_coordinator_contract.py
"""
from __future__ import annotations

from typing import Mapping, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from threat_report_agent.investigation.investigation import (
    ActionType,
    InvestigationThreadState,
    investigation_frontier_fingerprint,
)
from threat_report_agent.models import (
    AnalysisTask,
    Artifact,
    Evidence,
    InvestigationActionRecord,
    InvestigationHypothesisRecord,
    InvestigationThreadRecord,
)

#: The measured host needs of the slices moved so far - the ONLY things an investigation slice may require of its host.
#: Pinned by `tests/test_investigation_coordinator_contract.py`, which re-derives it from `service.py` and fails if it
#: grew or if a member became unused, so widening it is a deliberate act (the P3.2g precedent).
INVESTIGATION_HOST_MEMBERS: tuple[str, ...] = ("database",)


class InvestigationHost(Protocol):
    """What an investigation slice may use on the object that owns it.

    One member, because the measurement says so. `database` is annotated loosely ON PURPOSE: plan 3.2's matrix does
    not list `database` among the modules `investigation/` may import ("未列出的边默认禁止"), and no module under
    `investigation/` imports it today, so naming the concrete type here would create a new edge just to describe an
    attribute this code only ever calls methods on at runtime.
    """

    database: object


def missing_investigation_host_members(host: object) -> tuple[str, ...]:
    """Return the `INVESTIGATION_HOST_MEMBERS` this object does not provide, in declaration order.

    Empty means the object satisfies the port. The executable form of the contract, so "does this host still work for
    the investigation slices?" is answerable at runtime and not only by a type checker.
    """
    return tuple(name for name in INVESTIGATION_HOST_MEMBERS if not hasattr(host, name))


# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Moved implementation (P3.3b): identical to its old home in service.py. The receiver it used to reach through
# `self`/`cls` is now an explicit `host: InvestigationHost` parameter, and ONLY where the body still needs one.
# ---------------------------------------------------------------------------


def _build_investigation_frontier(
    session: Session,
    *,
    task: AnalysisTask,
    artifacts: list[Artifact],
    completed_actions: list[dict[str, object]],
) -> dict[str, object]:
    """Build the planner's durable, question-driven investigation frontier.

        This projection deliberately contains only structured state already
        persisted by the investigator: hypotheses, mechanism gaps, attempted
        actions and deferred work.  It is not model reasoning and never grants
        tool authority.  Keeping it in one bounded packet prevents the planner
        from seeing a generic placeholder while the report contains a much
        richer (but unresolved) mechanism ledger.
        """
    strategy = dict(task.strategy_snapshot or {})
    investigation = strategy.get("investigation", {})
    investigation = investigation if isinstance(investigation, Mapping) else {}
    artifact_ids = {str(item.id) for item in artifacts}
    artifact_paths = {str(item.id): str(item.logical_path) for item in artifacts}
    mechanisms = [
        dict(item)
        for item in investigation.get("mechanisms", [])
        if isinstance(item, Mapping)
        and (not item.get("artifact_id") or str(item.get("artifact_id")) in artifact_ids)
    ]
    threads = [
        dict(item)
        for item in investigation.get("threads", [])
        if isinstance(item, Mapping)
        and (not item.get("artifact_id") or str(item.get("artifact_id")) in artifact_ids)
    ]
    hypotheses = list(
        session.scalars(
            select(InvestigationHypothesisRecord).where(
                InvestigationHypothesisRecord.task_id == task.id
            )
        )
    )
    persisted_actions = list(
        session.scalars(
            select(InvestigationActionRecord)
            .where(InvestigationActionRecord.task_id == task.id)
            .order_by(InvestigationActionRecord.created_at, InvestigationActionRecord.id)
        )
    )
    hypothesis_rows: list[dict[str, object]] = []
    for row in hypotheses[:128]:
        hypothesis_rows.append(
            {
                "id": str(row.id),
                "thread_id": str(row.thread_id),
                "artifact_id": next(
                    (
                        str(thread.get("artifact_id"))
                        for thread in threads
                        if str(thread.get("id")) == str(row.thread_id)
                    ),
                    "",
                ),
                "statement": str(row.statement),
                "dimension": str(row.dimension),
                "status": str(row.status),
                "confidence": str(row.confidence),
                "evidence_ids": [str(item) for item in (row.evidence_ids or [])][:24],
                "required_evidence": [str(item) for item in (row.required_evidence or [])][:16],
                "contradictory_evidence_ids": [
                    str(item) for item in (row.contradictory_evidence_ids or [])
                ][:16],
            }
        )
    mechanism_rows: list[dict[str, object]] = []
    open_unknowns: list[str] = []
    for mechanism in mechanisms[:128]:
        missing = _mechanism_missing_fields(mechanism)
        status = str(mechanism.get("status") or "UNKNOWN").upper()
        mechanism_id = str(mechanism.get("id") or mechanism.get("mechanism_id") or "")
        artifact_id = str(mechanism.get("artifact_id") or "")
        path = artifact_paths.get(artifact_id, artifact_id)
        row = {
            "id": mechanism_id,
            "artifact_id": artifact_id,
            "artifact_path": path,
            "thread_id": str(mechanism.get("thread_id") or ""),
            "type": str(mechanism.get("type") or mechanism.get("dimension") or ""),
            "status": status,
            "missing_fields": missing,
            "evidence_ids": [str(item) for item in (mechanism.get("evidence_ids") or [])][:24],
            "unknowns": [str(item) for item in (mechanism.get("unknowns") or mechanism.get("limitations") or [])][:12],
        }
        mechanism_rows.append(row)
        if frontier_status_is_open(status):
            if missing:
                open_unknowns.append(
                    f"{path or artifact_id or 'artifact'} / {mechanism_id or 'mechanism'}: missing "
                    + ", ".join(missing)
                )
            for unknown in row["unknowns"]:
                open_unknowns.append(f"{path or artifact_id}: {unknown}")
    # A thread can be unresolved even when its mechanism projection has not
    # materialized yet. Keep that frontier visible to the planner.
    for thread in threads[:128]:
        state = str(thread.get("state") or "UNKNOWN").upper()
        if frontier_status_is_open(state):
            question = str(thread.get("question") or "").strip()
            if question:
                open_unknowns.append(
                    f"thread {thread.get('id')}: {question} (state={state})"
                )
    deferred = [
        dict(item)
        for item in investigation.get("deferred_frontier", [])
        if isinstance(item, Mapping)
    ][:128]
    work_ledger = [
        dict(item)
        for item in investigation.get("work_ledger", [])
        if isinstance(item, Mapping)
    ][:128]
    unfinished_ledger = [
        item
        for item in work_ledger
        if str(item.get("status") or "").upper() in {"OPEN", "IN_PROGRESS", "DEFERRED"}
        and deferred_keeps_planner_open(item)
    ]
    if unfinished_ledger:
        open_unknowns.append(
            f"investigation work ledger has {len(unfinished_ledger)} unfinished item(s)"
        )
    action_rows: list[dict[str, object]] = []
    for row in persisted_actions[-128:]:
        params = dict(row.parameters or {})
        action_rows.append(
            {
                "id": str(row.id),
                "artifact_id": str(row.artifact_id),
                "thread_id": str(row.thread_id),
                "action_type": str(row.action_type),
                "status": str(row.status),
                "outcome": "NO_NEW_EVIDENCE" if row.error == "NO_NEW_EVIDENCE" else str(row.status),
                "target_selector": dict(row.target_selector or {}),
                "result_evidence_ids": [str(item) for item in (row.result_evidence_ids or [])][:24],
                "error": str(row.error or ""),
                "failure_interpretation": str(row.failure_interpretation),
                "autopsy": dict(params.get("_autopsy", {})) if isinstance(params.get("_autopsy"), Mapping) else {},
                "convergence": dict(params.get("_convergence", {})) if isinstance(params.get("_convergence"), Mapping) else {},
            }
        )
    # Include the bounded in-memory completion history when a planner turn
    # has just executed but its rows have not yet been projected into the
    # investigation snapshot.
    for item in completed_actions[-32:]:
        if not isinstance(item, Mapping):
            continue
        action_rows.append(
            {
                "id": str(item.get("source_action_id") or item.get("action_key") or ""),
                "artifact_id": str(item.get("artifact_id") or ""),
                "action_type": str(item.get("action_type") or ""),
                "status": str(item.get("status") or ""),
                "outcome": str(item.get("outcome") or ""),
                "target_selector": dict(item.get("target_selector") or {}) if isinstance(item.get("target_selector"), Mapping) else {},
                "result_evidence_ids": [str(value) for value in (item.get("new_evidence_ids") or [])][:24],
                "error": str(item.get("error") or ""),
                "autopsy": dict(item.get("autopsy") or {}) if isinstance(item.get("autopsy"), Mapping) else {},
                "convergence": dict(item.get("convergence") or {}) if isinstance(item.get("convergence"), Mapping) else {},
            }
        )
    # Stable de-duplication keeps the prompt small while preserving the
    # latest status for each action identity.
    deduped_actions: list[dict[str, object]] = []
    seen_action_ids: set[str] = set()
    for row in reversed(action_rows):
        identity = str(row.get("id") or "")
        if identity and identity in seen_action_ids:
            continue
        if identity:
            seen_action_ids.add(identity)
        deduped_actions.append(row)
    deduped_actions.reverse()
    if not open_unknowns and deferred:
        planner_deferred = [item for item in deferred if deferred_keeps_planner_open(item)]
        if planner_deferred:
            open_unknowns.append("deferred investigation frontier remains")
    convergence_projection = investigation.get("convergence", {})
    if not isinstance(convergence_projection, Mapping):
        convergence_projection = {}
    return {
        "version": "behavior-frontier-v1",
        "hypotheses": hypothesis_rows,
        "mechanisms": mechanism_rows,
        "open_unknowns": list(dict.fromkeys(open_unknowns))[:96],
        "deferred_frontier": deferred,
        "work_ledger": work_ledger,
        "recent_actions": deduped_actions[-96:],
        "convergence": {
            str(key): dict(value)
            for key, value in convergence_projection.items()
            if isinstance(value, Mapping)
        },
        "thread_states": [
            {
                "id": str(item.get("id") or ""),
                "artifact_id": str(item.get("artifact_id") or ""),
                "state": str(item.get("state") or "UNKNOWN"),
                "question": str(item.get("question") or ""),
                "seed_kind": str(item.get("seed_kind") or ""),
            }
            for item in threads[:128]
        ],
    }


def _convergence_frontier_fingerprint(rows: object) -> str:
    """Hash the semantic evidence frontier, excluding provenance IDs."""
    normalized: list[dict[str, object]] = []
    if isinstance(rows, Mapping):
        rows = [rows]
    if not isinstance(rows, (list, tuple, set, frozenset)):
        rows = []
    for row in rows:
        if isinstance(row, Evidence):
            normalized.append(
                {
                    "kind": row.kind,
                    "nature": row.nature,
                    "value": row.value,
                    "anchor": row.anchor,
                }
            )
        elif isinstance(row, Mapping):
            normalized.append(
                {
                    "kind": row.get("kind"),
                    "nature": row.get("nature"),
                    "value": row.get("value"),
                    "anchor": row.get("anchor"),
                }
            )
    return investigation_frontier_fingerprint(normalized)


def _frontier_value_present(value: object) -> bool:
    """Return whether a mechanism field contains a concrete semantic value.

        Planner context must distinguish an omitted field from an analyst-facing
        placeholder.  In particular, strings such as ``UNKNOWN`` or
        ``not recovered`` must remain open questions instead of making a thread
        look closed merely because a projection contains text.
        """
    if value is None:
        return False
    values = value if isinstance(value, (list, tuple, set)) else (value,)
    for item in values:
        text = str(item).strip()
        if not text:
            continue
        lowered = text.casefold()
        if lowered.startswith("unknown(") or lowered.startswith("unknown:"):
            continue
        if lowered in {
            "unknown", "n/a", "na", "not recovered", "unresolved",
            "not identified", "none", "null",
        }:
            continue
        return True
    return False


def _unattempted_seed_thread_ids(host: InvestigationHost, task_id: str) -> tuple[str, ...]:
    """Return durable seed threads that still have no attempted investigation."""
    with host.database.session_factory() as session:
        threads = list(
            session.scalars(
                select(InvestigationThreadRecord).where(
                    InvestigationThreadRecord.task_id == task_id
                )
            )
        )
        attempted: set[str] = set()
        for action in session.scalars(
            select(InvestigationActionRecord).where(
                InvestigationActionRecord.task_id == task_id,
                InvestigationActionRecord.status.in_(("SUCCEEDED", "FAILED")),
            )
        ):
            if (action.parameters or {}).get("deferred"):
                continue
            thread_id = str(action.thread_id or "").strip()
            if thread_id:
                attempted.add(thread_id)
    return tuple(
        thread.id
        for thread in threads
        if thread.id not in attempted
        and str(thread.state or "")
        not in {
            InvestigationThreadState.CLAIM_READY.value,
            InvestigationThreadState.CLOSED.value,
            InvestigationThreadState.UNKNOWN.value,
            InvestigationThreadState.REJECTED.value,
            InvestigationThreadState.CONTRADICTED.value,
        }
    )


def _mechanism_missing_fields(mechanism: Mapping[str, object]) -> list[str]:
    """Compute the semantic fields still needed for a mechanism closure."""
    required = (
        ("target", "target object or region"),
        ("inputs", "input/source provenance"),
        ("transformation_or_control", "transformation or control logic"),
        ("conditions", "branch/trigger condition"),
        ("outputs", "output or side effect"),
        ("consumers", "downstream consumer"),
        ("evidence_ids", "supporting evidence anchors"),
    )
    return [label for key, label in required if not _frontier_value_present(mechanism.get(key))]


_FRONTIER_CLOSED_STATUSES = frozenset(
    {
        "VERIFIED",
        "SUPPORTED",
        "CONFIRMED",
        "REJECTED",
        "CONTRADICTED",
        "CANDIDATE",
        "CLAIM_READY",
        "MECHANISM_READY",
        "CLOSED",
        "UNKNOWN",
        "PARTIAL",
        "UNSUPPORTED",
        "STATIC_BOUNDARY",
    }
)


_PLANNER_CLOSED_DEFERRED_REASONS = frozenset(
    {
        "INVESTIGATION_BUDGET_EXHAUSTED",
        "INVESTIGATION_ROUND_LIMIT",
        "TIMEBOX",
    }
)


def frontier_status_is_open(status: object) -> bool:
    return str(status or "UNKNOWN").upper() not in _FRONTIER_CLOSED_STATUSES


def deferred_keeps_planner_open(item: object) -> bool:
    """True when leftover deferred work is still a planner TRACE ticket.

    Kunglao leftover remainder: isolated CONTROLLED_EMULATE and persist-closed
    HOW that hit the 64-cap are report UNKNOWN/CANDIDATE, not another chat round.
    """
    if not isinstance(item, Mapping):
        return False
    action_type = str(item.get("action_type") or "").upper()
    if action_type in {"CONTROLLED_EMULATE", ActionType.CONTROLLED_EMULATE.value}:
        return False
    reason = str(item.get("reason") or "").upper()
    return reason not in _PLANNER_CLOSED_DEFERRED_REASONS
