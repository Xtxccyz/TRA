"""P3.3 investigation coordinator: the port an investigation slice needs from its host, plus the slice behind it.

STATUS: slices P3.3b (frontier helpers), P3.3a (the ledger), P3.3c (action-proposal validation) and P3.3d (the
convergence contract) have moved. Plan 7.1 orders every migration in nine steps - step 2 is "先建立最小公开接口和
contract test" and step 3 is "移动同一份实现" - and P3.3 is executed in the six slices its measurement produced
(`docs/p33-investigation-coordinator-design-20260922.md`), smallest port cost first.

WHAT MOVED IN P3.3b: `_build_investigation_frontier`, `_convergence_frontier_fingerprint`, `_frontier_value_present`,
`_unattempted_seed_thread_ids` and `_mechanism_missing_fields` (MEASURED: its only use in service.py is inside the
moved `_build_investigation_frontier`, so it travels with the slice rather than widening the port), plus the
module-level pair `frontier_status_is_open` / `deferred_keeps_planner_open` and the two frozensets they close over.

WHAT MOVED IN P3.3a: `_persist_evidence_delivery_ledger`, `_finalize_tail_ledger`, `_park_open_ledger`,
`_work_ledger` and `_ledger_ids` (a `@staticmethod`: no receiver, so it ships with no host parameter at all). Their
only host references are `database` and `_audit`, which is why the port grew by exactly one member.

WHAT MOVED IN P3.3c: `_grounded_planner_action_candidates`, `_action_payload`, `_deterministic_action_plan`,
`_planner_user_action` (an instance method whose body needs NO host: its delegation keeps `self` for call shape and
deliberately does not forward it) and `_bound_completed_actions` (a classmethod whose delegation forwards `cls`). Four
other members of that slice stayed for measured layer reasons - see the design record section 13.1. BOTH of those
reasons have since been REMOVED, so P3.3c(2) is movable: P3.3 layer item 1 moved `action_is_model_or_human` into this
package (`investigation/loop_path.py`), and layer item 4 moved `DynamicPlanAction` into
`threat_report_agent.contracts`, which this package may import and which the model port also exposes. Neither name is a
layer blocker any more; they were when this slice moved.

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

THE PORT (six members, each measured): `database`, `_audit`, `_MAX_COMPLETED_ACTION_EVIDENCE_IDS`,
`_CONVERGENCE_ALTERNATES`, `_CONVERGENCE_EXPECTED_KINDS` and `_canonical_json`.

  * `database` came with P3.3b: the design's slice table measured that slice's need as
    "无（切片内自洽，只需 `database`）" and it was right. The FIRST implementation exported two class constants that
    only a STAYING member reads, which was a port widened on a false claim - corrected to one member before commit.
  * `_audit` came with P3.3a: the ledger writes an audit event. MEASURED on the five ledger members, `_audit` is
    their only host reference besides `database`, and `_audit_event_hash` is reached THROUGH `_audit` (which stays a
    host operation), so it is not a port member.
  * `_MAX_COMPLETED_ACTION_EVIDENCE_IDS` came with P3.3c: `_bound_completed_actions` bounds evidence ids with it. It
    is a CLASS constant that `tests/test_ghidra_performance.py` pins on `AnalysisService`, so it cannot move; the
    slice was FIRST reported as needing no host at all, and the contract test - not the measurement - caught that.
  * the last three came with P3.3d: `_canonical_json` is a `@staticmethod` shared by eight call sites, seven of them
    outside the moved cluster, and `_CONVERGENCE_ALTERNATES` / `_CONVERGENCE_EXPECTED_KINDS` are ANNOTATED class
    attributes. A probe had reported those two as module-level (it looked only for `ast.Assign`), which would have
    moved two class attributes out of the class; the class/module split is now read through one helper that handles
    both assignment forms.

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

import hashlib
import re

from typing import Mapping, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from threat_report_agent.investigation.investigation import (
    ActionCatalog,
    ActionSpec,
    ActionType,
    DeepMiningPlanner,
    InvestigationThreadState,
    investigation_frontier_fingerprint,
    investigation_method_id,
    investigation_next_method,
)
from threat_report_agent.investigation.investigation_ledger import (
    LEDGER_UNKNOWN,
    defer_item,
    deferred_item_ids,
    open_item_ids,
    terminate_item,
)
from threat_report_agent.models import (
    AnalysisTask,
    Artifact,
    AuditEvent,
    Evidence,
    EvidenceDeliveryTrace,
    InvestigationActionRecord,
    InvestigationHypothesisRecord,
    InvestigationThreadRecord,
)
from threat_report_agent.static.evidence_recovery import (
    EvidenceDeliveryLedger,
    EvidenceStage,
    FailureInterpretation,
)

#: The measured host needs of the slices moved so far - the ONLY things an investigation slice may require of its host.
#: Pinned by `tests/test_investigation_coordinator_contract.py`, which re-derives it from `service.py` and fails if it
#: grew or if a member became unused, so widening it is a deliberate act (the P3.2g precedent).
#:
#: WIDENED ONCE, ON PURPOSE, IN P3.3a (one member -> two): the ledger slice writes an audit event through the host's
#: `_audit` writer. MEASURED with `.scratch/p32-measure-cluster.py` on the five ledger members - `_audit` is their
#: only host reference besides `database`, and `_audit_event_hash` is reached THROUGH `_audit` (which stays a host
#: operation), so it is not a port member.
#:
#: WIDENED AGAIN IN P3.3c (two -> three): `_bound_completed_actions` bounds evidence ids with the host's
#: `_MAX_COMPLETED_ACTION_EVIDENCE_IDS` class constant. This one is a MEASUREMENT FAILURE STORY worth keeping: the
#: slice was first reported as "host need: NONE" because `.scratch/p32-measure-cluster.py` scanned only `self.` and the
#: reference is `cls._MAX_COMPLETED_ACTION_EVIDENCE_IDS` (a classmethod). The CONTRACT TEST caught it, not the tool -
#: the host-reference pin exists for exactly this. The tool now scans `self.` AND `cls.`, and takes `--from <rev>` so
#: it cannot silently measure a post-move tree.
#:
#: WIDENED AGAIN IN P3.3d (three -> six): the convergence slice reaches the shared helper `_canonical_json` and reads
#: two CLASS constants, `_CONVERGENCE_ALTERNATES` / `_CONVERGENCE_EXPECTED_KINDS`. A probe first reported those two as
#: "class-level=no" and therefore as module-level state that would TRAVEL - it was looking only for `ast.Assign` while
#: both are ANNOTATED class attributes. Had that reading been trusted, the extractor would have tried to move two class
#: attributes into this module. The class/module split is now read through one helper that handles both forms.
INVESTIGATION_HOST_MEMBERS: tuple[str, ...] = (
    "database",
    # --- added by P3.3a (the ledger slice) ---
    "_audit",
    # --- added by P3.3c (the action-proposal slice) ---
    "_MAX_COMPLETED_ACTION_EVIDENCE_IDS",
    # --- added by P3.3d (the convergence slice) ---
    "_CONVERGENCE_ALTERNATES",
    "_CONVERGENCE_EXPECTED_KINDS",
    "_canonical_json",
)


class InvestigationHost(Protocol):
    """What an investigation slice may use on the object that owns it.

    Six members, each measured. `database` is annotated loosely ON PURPOSE: plan 3.2's matrix does not list
    `database` among the modules `investigation/` may import ("未列出的边默认禁止"), and no module under
    `investigation/` imports it today, so naming the concrete type here would create a new edge just to describe an
    attribute this code only ever calls methods on at runtime. The rest are declared with the shapes the host really
    has them in: two methods (`_audit`, `_canonical_json`) and three class constants.

    WHY THE CLASS CONSTANT IS ON THE PORT RATHER THAN MOVED WITH ITS READER: MEASURED, its only reader inside
    service.py moved in P3.3c, but it is a CLASS ATTRIBUTE and `tests/test_ghidra_performance.py:116,118` pins
    `AnalysisService._MAX_COMPLETED_ACTION_EVIDENCE_IDS`, so it must stay on the class. Same rule as P3.3b's
    `_CATALOG_HOW_SEED_SCAN_LIMIT`: a class attribute read through the receiver stays on the host and is declared
    here; only MODULE-LEVEL closure state travels with a moved function.
    """

    database: object
    _MAX_COMPLETED_ACTION_EVIDENCE_IDS: int
    _CONVERGENCE_ALTERNATES: dict[ActionType, tuple[ActionType, ...]]
    _CONVERGENCE_EXPECTED_KINDS: dict[ActionType, tuple[str, ...]]

    @staticmethod
    def _canonical_json(value: object) -> str: ...

    def _audit(
        self,
        session: Session,
        *,
        case_id: str | None,
        event_type: str,
        actor: str,
        object_type: str,
        object_id: str,
        payload: dict[str, object],
        task_id: str | None = None,
    ) -> AuditEvent: ...


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


# ---------------------------------------------------------------------------
# Moved implementation (P3.3b): identical to its old home in service.py. The receiver it used to reach through
# `self`/`cls` is now an explicit `host: InvestigationHost` parameter, and ONLY where the body still needs one.
# ---------------------------------------------------------------------------


def _persist_evidence_delivery_ledger(
    host: InvestigationHost,
    session: Session,
    *,
    task: AnalysisTask,
    artifact_id: str | None,
    ledger: EvidenceDeliveryLedger,
    model_call_id: str | None,
) -> None:
    """Append unseen funnel events; Evidence itself remains immutable.

        This method is idempotent for a turn.  It permits a caller to persist
        delivery before a failed response and append later model-reference or
        verifier-acceptance events without updating the original trace rows.
        """
    subject_keys = tuple(dict.fromkeys(event.evidence_id for event in ledger.events))
    existing = (
        set(
            session.execute(
                select(EvidenceDeliveryTrace.subject_key, EvidenceDeliveryTrace.stage).where(
                    EvidenceDeliveryTrace.task_id == task.id,
                    EvidenceDeliveryTrace.turn_id == ledger.turn_id,
                    EvidenceDeliveryTrace.subject_key.in_(subject_keys),
                )
            ).all()
        )
        if subject_keys
        else set()
    )
    existing_evidence_ids = (
        set(
            session.scalars(
                select(Evidence.id).where(
                    Evidence.task_id == task.id, Evidence.id.in_(subject_keys)
                )
            ).all()
        )
        if subject_keys
        else set()
    )
    evidence_artifacts = (
        {
            str(evidence_id): str(evidence_artifact_id)
            for evidence_id, evidence_artifact_id in session.execute(
                select(Evidence.id, Evidence.artifact_id).where(
                    Evidence.task_id == task.id,
                    Evidence.id.in_(subject_keys),
                )
            ).all()
        }
        if subject_keys
        else {}
    )
    added = 0
    for event in ledger.events:
        key = (event.evidence_id, event.stage.value)
        if key in existing:
            continue
        details = dict(event.details)
        role = details.pop("context_role", None)
        score = details.pop("selection_score", None)
        exclusion = details.pop("exclusion_reason", None)
        session.add(
            EvidenceDeliveryTrace(
                task_id=task.id,
                artifact_id=artifact_id or evidence_artifacts.get(event.evidence_id),
                thread_id=event.thread_id or None,
                model_call_id=model_call_id,
                turn_id=event.turn_id,
                subject_key=event.evidence_id,
                evidence_id=(
                    event.evidence_id if event.evidence_id in existing_evidence_ids else None
                ),
                stage=event.stage.value,
                context_role=str(role) if role else None,
                selection_score=float(score) if score is not None else None,
                exclusion_reason=str(exclusion) if exclusion else None,
                details=details,
            )
        )
        added += 1
    if added:
        host._audit(
            session,
            case_id=task.case_id,
            task_id=task.id,
            event_type="evidence.delivery_traced",
            actor="evidence-retriever",
            object_type="EvidenceDeliveryTrace",
            object_id=ledger.turn_id[:80],
            payload={
                "turn_id": ledger.turn_id,
                "thread_id": ledger.thread_id,
                "record_count": added,
                "model_call_id": model_call_id,
            },
        )


def _finalize_tail_ledger(host: InvestigationHost, task_id: str) -> None:
    """After the dedicated tail pass, remaining 待完成 become honest UNKNOWN."""
    with host.database.session_factory.begin() as session:
        task = session.get(AnalysisTask, task_id)
        if task is None:
            return
        snapshot = dict((task.strategy_snapshot or {}).get("investigation") or {})
        ledger = [dict(item) for item in (snapshot.get("work_ledger") or []) if isinstance(item, Mapping)]
        for item_id in deferred_item_ids(ledger):
            ledger = terminate_item(
                ledger,
                item_id,
                LEDGER_UNKNOWN,
                reason="TAIL_PASS_UNCLOSED",
            )
            thread = session.get(InvestigationThreadRecord, item_id)
            if thread is not None and thread.state not in {
                InvestigationThreadState.CLAIM_READY.value,
                InvestigationThreadState.CLOSED.value,
            }:
                thread.state = InvestigationThreadState.UNKNOWN.value
        snapshot["work_ledger"] = ledger
        task.strategy_snapshot = {
            **(task.strategy_snapshot or {}),
            "investigation": snapshot,
        }


def _park_open_ledger(host: InvestigationHost, task_id: str) -> None:
    """Coverage made no progress: park remaining OPEN items as 待完成."""
    with host.database.session_factory.begin() as session:
        task = session.get(AnalysisTask, task_id)
        if task is None:
            return
        snapshot = dict((task.strategy_snapshot or {}).get("investigation") or {})
        ledger = [dict(item) for item in (snapshot.get("work_ledger") or []) if isinstance(item, Mapping)]
        for item_id in open_item_ids(ledger):
            ledger = defer_item(ledger, item_id, reason="COVERAGE_STALLED")
            thread = session.get(InvestigationThreadRecord, item_id)
            if thread is not None and thread.state not in {
                InvestigationThreadState.CLAIM_READY.value,
                InvestigationThreadState.CLOSED.value,
            }:
                thread.state = InvestigationThreadState.BLOCKED.value
        snapshot["work_ledger"] = ledger
        task.strategy_snapshot = {
            **(task.strategy_snapshot or {}),
            "investigation": snapshot,
        }


def _work_ledger(host: InvestigationHost, task_id: str) -> list[dict[str, object]]:
    with host.database.session_factory() as session:
        task = session.get(AnalysisTask, task_id)
        if task is None:
            return []
        snapshot = dict((task.strategy_snapshot or {}).get("investigation") or {})
        raw = snapshot.get("work_ledger") or []
        if not isinstance(raw, list):
            return []
        return [dict(item) for item in raw if isinstance(item, Mapping)]


def _ledger_ids(ledger: EvidenceDeliveryLedger, stage: EvidenceStage) -> list[str]:
    return sorted({event.evidence_id for event in ledger.events if event.stage == stage})


# ---------------------------------------------------------------------------
# Moved implementation (P3.3 slices): identical to its old home in service.py. The receiver it used to reach
# through `self`/`cls` is now an explicit `host: InvestigationHost` parameter, and ONLY where the body still
# needs one. This banner is deliberately SLICE-AGNOSTIC: it used to name the first slice, so the second slice's
# code was appended under a label that lied about which step moved it.
# ---------------------------------------------------------------------------


def _grounded_planner_action_candidates(
    context_manifest: list[dict[str, object]],
    *,
    artifact_ids: set[str],
    limit: int = 6,
) -> list[dict[str, object]]:
    """Offer a small set of evidence-grounded planning choices to a model.

        A planner still chooses whether a lead deserves work and which candidate
        to use.  The service derives these choices solely from delivered static
        Evidence so an empty JSON object cannot be mistaken for planning when
        the next safe step is already concrete.  This is advisory prompt input,
        never an execution authorization or a deterministic action disguised as
        model output.
        """
    candidates: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()

    def value_for(
        mapping: Mapping[str, object],
        names: tuple[str, ...],
    ) -> str:
        for name in names:
            value = mapping.get(name)
            if isinstance(value, (str, int)) and str(value).strip():
                return str(value).strip()
        return ""

    for item in context_manifest:
        artifact_id = str(item.get("artifact_id") or "")
        evidence_id = str(item.get("evidence_id") or "")
        if not artifact_id or artifact_id not in artifact_ids or not evidence_id:
            continue
        if str(item.get("nature")) == "BACKGROUND_REPORTED":
            continue
        anchor = item.get("anchor")
        anchor = anchor if isinstance(anchor, Mapping) else {}
        value = item.get("value")
        value = value if isinstance(value, Mapping) else {}
        # A model-directed function action needs function-scoped Evidence.
        # PE-header entry RVAs are navigation metadata, not a recovered
        # function target, and must not turn into deep probing actions.
        function_target = DeepMiningPlanner._function_key(item)
        api_target = value_for(
            value,
            ("api", "api_name", "target_name", "target_function", "name", "indicator"),
        )
        # Imports and function-context rows sometimes preserve the API
        # only in an explicit call-target array.  The first bounded call
        # target is a valid Xref lead when no direct locator exists.
        if not api_target:
            for field in ("call_targets", "calls", "functions"):
                nested = value.get(field)
                if not isinstance(nested, (list, tuple)):
                    continue
                for child in nested:
                    if not isinstance(child, Mapping):
                        continue
                    api_target = value_for(
                        child,
                        ("api", "api_name", "target_name", "target_function", "name"),
                    )
                    if api_target:
                        break
                if api_target:
                    break
        if function_target:
            target = function_target
            action_type = ActionType.TRACE_API_ARGUMENT
            expected = ["api_argument_trace", "function_context"]
            question = (
                "Which concrete arguments and call-site condition reach the "
                    "cited function, and which static consumer receives its output?"
            )
            hypothesis = (
                "The cited function contains a statically recoverable mechanism "
                    "whose arguments or data flow distinguish it from a dead helper."
            )
            alternatives = [
                "The function is an initialization or compatibility helper without a security-relevant consumer."
            ]
            missing = ["argument data flow", "call-site condition", "downstream consumer"]
            failure = (
                "The delivered function anchor did not expose a bounded static argument "
                    "path; the mechanism remains unknown rather than absent."
            )
        elif api_target and not re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", api_target):
            target = api_target
            action_type = ActionType.GET_XREFS_TO
            expected = ["xref", "function_context"]
            question = (
                "Which concrete static callsite or data reference anchors the cited API, "
                    "before any function-level inference is attempted?"
            )
            hypothesis = (
                "The cited API has an artifact-local static reference that can anchor "
                    "a bounded mechanism investigation."
            )
            alternatives = ["The API is an unused import or compatibility dependency."]
            missing = ["artifact-local callsite or data reference"]
            failure = (
                "No artifact-local Xref was recovered for the cited API; this does not "
                    "establish runtime absence."
            )
        else:
            continue
        identity = (artifact_id, target.casefold())
        if identity in seen:
            continue
        seen.add(identity)
        candidates.append(
            {
                "evidence_id": evidence_id,
                "target_selector": {"target": target},
                "action": {
                    "action_type": action_type.value,
                    "target_artifact_id": artifact_id,
                    "priority": len(candidates) + 1,
                    "reason": "Use the delivered static anchor to reduce mechanism uncertainty.",
                    "question": question,
                    "hypothesis": hypothesis,
                    "alternatives": alternatives,
                    "missing_evidence": missing,
                    "failure_meaning": failure,
                    "evidence_ids": [evidence_id],
                    "target_selector": {"target": target},
                    "expected_evidence_kinds": expected,
                    "success_condition": "new_targeted_evidence",
                    "failure_interpretation": "NO_NEW_EVIDENCE",
                },
            }
        )
        if len(candidates) >= limit:
            break
    return candidates


def _action_payload(row: InvestigationActionRecord) -> dict[str, object]:
    parameters = dict(row.parameters or {})
    model_provenance = parameters.get("_model_provenance", {})
    if not isinstance(model_provenance, Mapping):
        model_provenance = {}
    planner_turn_id = parameters.get("_planner_turn_id")
    planner_turn_id = (
        str(planner_turn_id).strip()
        if isinstance(planner_turn_id, (str, int)) and str(planner_turn_id).strip()
        else None
    )
    origin = parameters.get("origin")
    origin = str(origin).strip() if isinstance(origin, str) and origin.strip() else None
    if origin not in {"model", "human", "deterministic_fallback"}:
        origin = "model" if planner_turn_id else "deterministic_fallback"
    raw_source_ids = parameters.get("_source_evidence_ids", [])
    if not isinstance(raw_source_ids, (list, tuple, set)):
        raw_source_ids = []
    return {
        "id": row.id,
        "task_id": row.task_id,
        "thread_id": row.thread_id,
        "hypothesis_id": row.hypothesis_id,
        "artifact_id": row.artifact_id,
        "action_type": row.action_type,
        "reason": row.reason,
        "parameters": parameters,
        "target_selector": row.target_selector,
        "expected_evidence_kinds": row.expected_evidence_kinds,
        "source_evidence_ids": [
            str(item)
            for item in raw_source_ids
            if isinstance(item, (str, int)) and str(item).strip()
        ][:32],
        "success_condition": row.success_condition,
        "failure_interpretation": row.failure_interpretation,
        "cost_units": row.cost_units,
        "priority": row.priority,
        "status": row.status,
        "attempts": row.attempts,
        "depends_on": row.depends_on,
        "result_evidence_ids": row.result_evidence_ids,
        "error": row.error,
        "origin": origin,
        "planner_turn_id": planner_turn_id,
        "model_provenance": dict(model_provenance),
        "model_call_id": model_provenance.get("model_call_id"),
        "model_run_id": model_provenance.get("model_run_id"),
        "provider": model_provenance.get("provider"),
        "model": model_provenance.get("model"),
        "created_at": row.created_at.isoformat(),
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
    }


def _deterministic_action_plan(artifacts: list[Artifact]) -> list[str]:
    """Return the mandatory artifact order used when planning is unavailable."""
    return [item.id for item in artifacts]


def _planner_user_action(
    *,
    configured: bool,
    provider: str,
    model: str,
    http_status: object,
    last_status: str | None,
) -> str:
    route = "/".join(item for item in (str(provider or "").strip(), str(model or "").strip()) if item)
    route = route or "unconfigured"
    if http_status in {402, "402"}:
        return (
            f"对话模型线路 {route} 返回 HTTP 402（配额或余额不足）。"
                "请打开左下角设置 →「模型」检查同一条线路。"
        )
    if http_status in {401, 403, "401", "403"}:
        return (
            f"对话模型线路 {route} 认证失败（HTTP {http_status}）。"
                "请检查左下角设置 →「模型」中的 API Key。"
        )
    if last_status in {"FAILED", "TIMEOUT", "EMPTY", "ERROR"}:
        return (
            f"对话模型线路 {route} 调用失败（{last_status}）。"
                "请在左下角设置 →「模型」检查供应商、模型名和密钥。"
        )
    if not configured:
        return (
            "调查与对话共用左下角设置 →「模型」。"
                "请在「模型」中填写供应商后再点「分析」。"
        )
    return (
        "调查与对话共用左下角设置 →「模型」。后端先跑确定性静态队列，"
            "后续调查由该对话模型通过工具完成。"
    )


def _bound_completed_actions(
    host: InvestigationHost,
    actions: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Keep planner history auditable without replaying unbounded IDs.

        A single parser action can produce thousands of Evidence rows.  The
        full set remains queryable from the Evidence ledger; planner Turns
        only need a bounded sample plus the authoritative count to correlate
        the next decision and stay below the model context limit.
        """
    bounded: list[dict[str, object]] = []
    for raw in actions:
        if not isinstance(raw, Mapping):
            continue
        item = dict(raw)
        raw_ids = item.get("new_evidence_ids")
        if isinstance(raw_ids, (list, tuple, set)):
            evidence_ids = [str(value) for value in raw_ids if str(value).strip()]
            item["new_evidence_ids"] = evidence_ids[: host._MAX_COMPLETED_ACTION_EVIDENCE_IDS]
            if len(evidence_ids) > host._MAX_COMPLETED_ACTION_EVIDENCE_IDS:
                item["new_evidence_ids_truncated"] = (
                    len(evidence_ids) - host._MAX_COMPLETED_ACTION_EVIDENCE_IDS
                )
        bounded.append(item)
    return bounded


# ---------------------------------------------------------------------------
# Moved implementation (P3.3 slices): identical to its old home in service.py. The receiver it used to reach
# through `self`/`cls` is now an explicit `host: InvestigationHost` parameter, and ONLY where the body still
# needs one. This banner is deliberately SLICE-AGNOSTIC: it used to name the first slice, so the second slice's
# code was appended under a label that lied about which step moved it.
# ---------------------------------------------------------------------------


def _convergence_failure_contract(
    host: InvestigationHost,
    action: ActionSpec,
    *,
    outcome: str,
    frontier_before: str,
    frontier_after: str,
    existing_method_ids: object = (),
    error_type: str | None = None,
) -> dict[str, object]:
    """Build the durable three-question failure contract for one attempt."""
    plan = action.plan if isinstance(action.plan, Mapping) else {}
    convergence_plan = plan.get("convergence", {})
    is_alternate = (
        isinstance(convergence_plan, Mapping)
        and bool(convergence_plan.get("alternate_of"))
    )
    contract = DeepMiningPlanner.failure_contract(
        action,
        outcome=outcome,
        frontier_before=frontier_before,
        frontier_after=frontier_after,
        existing_method_ids=existing_method_ids,
        error_type=error_type,
    )
    planned_next = plan.get("next_method_action_type") or plan.get("next_method")
    attempted_types = {
        str(item).split(":", 1)[0]
        for item in (
            existing_method_ids
            if isinstance(existing_method_ids, (list, tuple, set, frozenset))
            else ()
        )
        if str(item).strip()
    }
    current_type = str(getattr(action.action_type, "value", action.action_type))
    attempted_types.add(current_type)
    # A placeholder CONTROLLED_EMULATE is a dispatch ticket, not a
    # completed method. STATIC_BOUNDARY waits for the worker result.
    if (
        current_type == ActionType.CONTROLLED_EMULATE.value
        and str(outcome or "").upper()
        in {"NO_NEW_EVIDENCE", "NEUTRAL", "DEFERRED_TO_WORKER", "WORKER_REQUIRED"}
    ):
        attempted_types.discard(ActionType.CONTROLLED_EMULATE.value)
    if is_alternate:
        # Two dry static methods are a backtrack, not a boundary, until
        # isolated emulation has been attempted for this selector.
        if ActionType.CONTROLLED_EMULATE.value not in attempted_types:
            if str(contract.get("next_method") or "") in {"", "STATIC_BOUNDARY"}:
                next_name = investigation_next_method(action.action_type, attempted_types)
                contract["next_method"] = next_name
                contract["next_method_action_type"] = (
                    None if next_name == "STATIC_BOUNDARY" else next_name
                )
            contract["requires_alternate"] = str(contract.get("next_method")) not in {
                "",
                "STATIC_BOUNDARY",
            }
            contract["alternate_of"] = convergence_plan.get("alternate_of")
            return contract
        contract["next_method"] = "STATIC_BOUNDARY"
        contract["next_method_action_type"] = None
        contract["requires_alternate"] = False
        contract["alternate_of"] = convergence_plan.get("alternate_of")
        return contract
    if planned_next and str(planned_next) not in {"", "STATIC_BOUNDARY"}:
        contract["next_method"] = str(planned_next)
        contract["next_method_action_type"] = str(planned_next)
        contract["requires_alternate"] = True
    elif not contract.get("next_method_action_type"):
        alternate_type = _convergence_alternate_type(host, action.action_type, existing_method_ids)
        if alternate_type is not None:
            contract["next_method"] = alternate_type.value
            contract["next_method_action_type"] = alternate_type.value
            contract["requires_alternate"] = True
    contract["alternate_of"] = None
    return contract


def _build_convergence_alternate(
    host: InvestigationHost,
    *,
    original: InvestigationActionRecord,
    thread_id: str,
    hypothesis_id: str,
    artifact_id: str,
) -> ActionSpec | None:
    """Materialize one bounded alternate probe from a failed action row."""
    params = dict(original.parameters or {})
    convergence = params.get("_convergence", {})
    if not isinstance(convergence, Mapping) or not convergence.get("requires_alternate"):
        return None
    raw_type = convergence.get("next_method_action_type")
    try:
        alternate_type = ActionType(str(raw_type))
    except (TypeError, ValueError):
        return None
    # A second static fallback is still one hop short of HOW closure.
    # Allow GET_DECOMPILE then CONTROLLED_EMULATE after an alternate
    # already failed; do not chain arbitrary families forever.
    if convergence.get("alternate_of"):
        chained = str(raw_type)
        if chained not in {
            ActionType.GET_DECOMPILE.value,
            ActionType.CONTROLLED_EMULATE.value,
        }:
            return None
        attempted = {
            str(item).split(":", 1)[0]
            for item in (convergence.get("attempted_method_ids") or [])
            if str(item).strip()
        }
        attempted.add(str(original.action_type))
        if chained in attempted:
            return None
    selector = dict(original.target_selector or {})
    if not selector:
        return None
    expected = host._CONVERGENCE_EXPECTED_KINDS.get(
        alternate_type, ("specialist_observation",)
    )
    source_ids = params.get("_source_evidence_ids", [])
    if not isinstance(source_ids, (list, tuple, set, frozenset)):
        source_ids = []
    source_ids = tuple(
        str(item).strip()
        for item in source_ids
        if isinstance(item, (str, int)) and str(item).strip()
    )[:32]
    original_plan = params.get("_analysis_plan", {})
    original_plan = dict(original_plan) if isinstance(original_plan, Mapping) else {}
    method_id = str(convergence.get("method_id") or investigation_method_id(
        original.action_type, selector, original_plan
    ))
    alternate_convergence = {
        "alternate_of": method_id,
        "method_id": investigation_method_id(alternate_type, selector, original_plan),
        "attempted_method_ids": list(convergence.get("attempted_method_ids", [])),
        "parent_attempt_id": original.id,
    }
    plan = {
        **original_plan,
        "convergence": alternate_convergence,
        "question": (
            f"Use {alternate_type.value} as a complementary method after "
            f"{original.action_type} produced no usable evidence."
        ),
        "failure_meaning": (
            "A second method failure is a bounded static limitation; it is not refutation."
        ),
        "planner_protocol": "plan-first-static-v1-convergence-v1",
    }
    stable_id = hashlib.sha256(
        host._canonical_json(
            {
                "task_id": original.task_id,
                "thread_id": thread_id,
                "artifact_id": artifact_id,
                "parent_action": original.id,
                "action_type": alternate_type.value,
                "selector": selector,
            }
        ).encode("utf-8")
    ).hexdigest()[:24]
    return ActionSpec(
        id=f"{thread_id}:convergence:{stable_id}",
        action_type=alternate_type,
        thread_id=thread_id,
        hypothesis_id=hypothesis_id,
        artifact_id=artifact_id,
        priority=max(1, int(original.priority or 50) - 1),
        reason=(
            f"bounded alternate {alternate_type.value} after "
            f"{original.action_type} produced no new evidence"
        ),
        parameters=selector,
        target_selector=selector,
        expected_evidence_kinds=expected,
        success_condition="new_targeted_evidence",
        failure_interpretation=FailureInterpretation.STATIC_BOUNDARY,
        cost_units=ActionCatalog.default().require(alternate_type).cost_units,
        source_evidence_ids=source_ids,
        planner_turn_id=params.get("_planner_turn_id"),
        provenance=(
            dict(params.get("_model_provenance", {}))
            if isinstance(params.get("_model_provenance"), Mapping)
            else {}
        ),
        plan=plan,
    )


def _convergence_completed_fields(
    evidence: object,
    coverage: Mapping[str, object] | None = None,
) -> list[str]:
    """Summarize completed semantic facets without inventing conclusions."""
    fields: set[str] = set()
    if isinstance(coverage, Mapping):
        for target in coverage.get("targets", ()):
            if not isinstance(target, Mapping):
                continue
            for action_type in target.get("observed_action_types", ()):
                if str(action_type).strip():
                    fields.add(f"evidence:{str(action_type)}")
    rows = evidence if isinstance(evidence, (list, tuple, set, frozenset)) else ()
    semantic_keys = {
        "initiator", "input", "inputs", "state", "config", "transformation",
        "transformation_or_control", "condition", "conditions", "side_effect",
        "side_effects", "output", "outputs", "consumer", "consumers", "loop",
        "failure", "fallback",
    }
    for row in rows:
        value = row.value if isinstance(row, Evidence) else row.get("value") if isinstance(row, Mapping) else None
        if isinstance(value, Mapping):
            fields.update(str(key) for key in value if str(key) in semantic_keys)
    return sorted(fields)[:64]


def _convergence_alternate_type(
    host: InvestigationHost,
    action_type: ActionType | str,
    attempted: object = (),
) -> ActionType | None:
    attempted_names = {str(item) for item in attempted} if isinstance(attempted, (list, tuple, set, frozenset)) else set()
    next_name = investigation_next_method(action_type, attempted_names)
    if next_name != "STATIC_BOUNDARY":
        try:
            return ActionType(next_name)
        except ValueError:
            return None
    try:
        current = ActionType(action_type)
    except ValueError:
        return None
    for candidate in host._CONVERGENCE_ALTERNATES.get(current, ()):
        if candidate.value not in attempted_names:
            return candidate
    return None


def _convergence_method_id(
    action_type: ActionType | str,
    selector: Mapping[str, object] | None = None,
    plan: Mapping[str, object] | None = None,
) -> str:
    """Return a stable semantic strategy identity for one target probe."""
    return investigation_method_id(action_type, selector, plan)
