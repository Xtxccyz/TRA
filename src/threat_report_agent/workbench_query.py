"""Workbench read-only queries: the analyst-facing views served to the HTTP adapter (plan §P3.6).

This module is the new home of the READ-ONLY slice of `AnalysisService`'s workbench surface. Plan §P3.6 asks for
"Evidence, timeline, report revision and similar read-only queries that do not enter the analysis loop", with the success
criteria that **a query never changes a snapshot or a revision** and that **the HTTP adapter is not imported by
`investigation`**.

WHICH MEMBERS, AND WHY NOT THE OTHERS. The design (docs/p36-workbench-query-design-20260922.md) measured every
workbench-shaped member and split them by BEHAVIOUR rather than by name:

* **moved here (P3.6-1)**: `task_view` (395), `workbench_domain_view` (374), `workbench_query_evidence` (62),
  `model_configuration_view` (58), `workbench_thread` (46), plus the two view helpers whose only readers are in this
  slice (`_config_route_view`, `_unique_execution_threads_for_view`).
* **deliberately NOT moved**: `workbench_submit_action`, `workbench_write_report_file`, `workbench_start_static_analysis`,
  `workbench_model_complete`, `workbench_link_session`, `request_evidence_purge`, `execute_evidence_purge`,
  `workbench_unbind_analysis` and `workbench_wait_for_analysis_update` - operations that change state or DRIVE the
  analysis. `workbench_wait_for_analysis_update` is the sharp case: its name looks like a query and it advances analysis
  state, so moving it would put a behaviour change inside a structural step.
* **moved here (P3.6-2)**: `workbench_capabilities` (105 lines). It was left behind by P3.6-1 because it reads
  `ActionCatalog`, and P3.6-2's decision (docs/p36-capability-slice-design-20260922.md section 6.3) is to PASS THE
  CATALOG IN from the delegation rather than import it: `workbench_query` still imports nothing from
  `investigation.*`, and the import gate's stated blind spot (an unlisted edge cannot be machine-checked at all -
  `docs/import-policy.json` `_recorded_allowed_edges_note`) is therefore not triggered. The host owns the
  `ActionCatalog` import and hands the instance over, exactly as it already hands over `_analysis_planner_payload`.

READ-ONLY IS A PROPERTY TO KEEP, NOT A CLAIM TO MAKE. Every moved body was measured to contain ZERO
`session.add`/`delete`/`flush`/`commit`/`merge` calls (the `scalars`/`scalar` calls are SELECT reads), and the tracked
contract test asserts that property for this module so a later slice cannot quietly turn a reader into a writer.

THE HOST, AND THE MEASUREMENT DEFECT THIS SLICE FOUND. `WorkbenchQueryReaderHost` declares the EXACT set of host members
the bodies still reach. Two class constants - `_CATALOG_HOW_SEED_SCAN_LIMIT` and `_UNIQUE_THREAD_VIEW_KINDS` - started
out as TRAVELLING names because a scan of `service.py` showed no `self.`/`cls.` reader outside this slice. The first
application of this move then broke 37 tests with
`AttributeError: 'AnalysisService' object has no attribute '_CATALOG_HOW_SEED_SCAN_LIMIT'` raised from
`investigation/derivation.py` - i.e. from a MIGRATED module that reads the constant THROUGH ITS OWN HOST PIN. **The
reader analysis has to include every host pin in the repository, not just the readers inside `service.py`**; a class
constant reached through `host.` is invisible to a `self.`/`cls.` scan. Both constants are therefore PIN members here.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Protocol

from sqlalchemy import String, case, cast, or_, select
from sqlalchemy.orm import Session

from .emulation.policy import simulation_policy_from_settings
from .models import (
    AnalysisFailureRecord,
    AnalysisTask,
    Artifact,
    BlindRun,
    CaseRecord,
    Claim,
    ClaimEvidence,
    Evidence,
    EvidenceDeliveryTrace,
    InvestigationActionRecord,
    InvestigationHypothesisRecord,
    InvestigationThreadRecord,
    ModelCall,
    ModelConfiguration,
    Relation,
    ReportRevision,
    utcnow,
)
from .report.reporting import build_unique_execution_threads

#: The host members this slice's bodies still reach, each because it has a reader OUTSIDE the slice (the design's rule:
#: a pin member without an outside reader is dead interface, and a body reference that is neither moved nor pinned is a
#: runtime `NameError`).
#:   `database`                        - the session factory, read by 75 members
#:   `settings`                        - the settings object, read by 33 members
#:   `_action_payload`                 - read by `workbench_submit_action` and `workbench_action`
#:   `_audit_timestamp`                - read by `_audit_event_hash` and `task_status`
#:   `_elapsed_ms`                     - read by `_context_payload_v3`, `_analysis_progress` and `task_status`
#:   `_failure_payload`                - read by `_context_payload_v3` and `task_status`
#:   `_model_calls_env_enabled`        - read by `__init__` and `reload_model_configuration`
#:   `_model_status_payload`           - read by `_analysis_planner_payload`
#:   `_report_inputs`                  - read by `_freeze_snapshot` and `analysis_trace`
#:   `THREAT_CONTEXT_PROTOCOL`         - read by `_context_payload_v3` (outside the slice) and by the P3.6-2 body
#:   `THREAT_TOOL_CONTRACT_VERSION`    - read by `_context_payload_v3` (outside the slice) and by the P3.6-2 body
#:   `_analysis_planner_payload`       - read by `_context_payload_v3` and `workbench_analysis_planner_model_view`
#:                                       (both outside the slice) and by the P3.6-2 body. Keeping it on the host is what
#:                                       keeps `_model_status_payload`/`_planner_user_action`/`investigation.coordinator`
#:                                       OUT of this module: the closure behind it stays behind the pin.
#:   `_CATALOG_HOW_SEED_SCAN_LIMIT`    - read by `investigation/derivation.py` THROUGH ITS OWN HOST PIN (the defect that
#:                                       broke 37 tests when it travelled: a host-pin read is invisible to a `self.`/`cls.`
#:                                       scan of `service.py`)
#:   `_UNIQUE_THREAD_VIEW_KINDS`       - PINNED CONSERVATIVELY, and the measurement is now exact: a scan of EVERY
#:                                       `*_HOST_MEMBERS` tuple in the repository finds this name read by NO pin but
#:                                       this module's own, so the design's rule would let it travel (pin 10). It
#:                                       stays pinned because the first attempt at this pin judged two class
#:                                       constants to be travelling and broke 37 tests (a class attribute read
#:                                       through another module's host pin is invisible to a `self.`/`cls.` scan of
#:                                       `service.py`), and re-running the move to change one pin member is a
#:                                       separate, gate-heavy step - recorded as a deviation for P3.6-2, not hidden.
#:
#: THREE NAMES WERE ONCE DELIBERATELY NOT PINNED HERE, and P3.6-2 is the step that moved the reader that made them
#: real: `THREAT_CONTEXT_PROTOCOL`, `THREAT_TOOL_CONTRACT_VERSION` and `_analysis_planner_payload` are read by
#: `workbench_capabilities` and by `_context_payload_v3`. While `workbench_capabilities` was still on the host, pinning
#: them here would have been dead interface (the bidirectional assertion in the contract test caught exactly that);
#: now the slice's bodies read all three, so all three are pin members. MEASURED BEFORE PINNING (design section 5.4,
#: re-measured on this tree by `.scratch/p36-2-hostpins-now.py`): neither class constant appears in ANY of the five
#: `*_HOST_MEMBERS` tuples in the repository, so - unlike `_CATALOG_HOW_SEED_SCAN_LIMIT`, which `derivation.py` reads
#: through its own pin - they can be pinned WITHOUT being moved.
WORKBENCH_QUERY_HOST_MEMBERS: tuple[str, ...] = (
    "_CATALOG_HOW_SEED_SCAN_LIMIT",
    "_UNIQUE_THREAD_VIEW_KINDS",
    "_action_payload",
    "_analysis_planner_payload",
    "_audit_timestamp",
    "_elapsed_ms",
    "_failure_payload",
    "_model_calls_env_enabled",
    "_model_status_payload",
    "_report_inputs",
    "THREAT_CONTEXT_PROTOCOL",
    "THREAT_TOOL_CONTRACT_VERSION",
    "database",
    "settings",
)


class WorkbenchQueryReaderHost(Protocol):
    """What the moved read-only bodies may use on the object that owns them (generated from the host's signatures)."""

    _CATALOG_HOW_SEED_SCAN_LIMIT: int
    _UNIQUE_THREAD_VIEW_KINDS: tuple
    THREAT_CONTEXT_PROTOCOL: str  # class constant on AnalysisService
    THREAT_TOOL_CONTRACT_VERSION: str  # class constant on AnalysisService
    @staticmethod
    def _action_payload(row: InvestigationActionRecord) -> dict[str, object]: ...
    def _analysis_planner_payload(self, failure: AnalysisFailureRecord | None = None, model_calls: list[ModelCall] | tuple[ModelCall, ...] | None = None) -> dict[str, object]: ...
    @staticmethod
    def _audit_timestamp(value: object) -> str: ...
    @staticmethod
    def _elapsed_ms(task: AnalysisTask, *, now: datetime | None = None) -> int | None: ...
    @staticmethod
    def _failure_payload(row) -> dict[str, object] | None: ...
    _model_calls_env_enabled: object  # instance attribute set in __init__
    def _model_status_payload(self, failure: AnalysisFailureRecord | None, model_calls: list[ModelCall] | tuple[ModelCall, ...] | None = None) -> dict[str, object]: ...
    def _report_inputs(self, session: Session, task_id: str) -> dict[str, list[Any]]: ...
    database: object  # instance attribute set in __init__
    settings: object  # instance attribute set in __init__


class ActionCatalogProjection(Protocol):
    """The minimal `ActionCatalog` surface `workbench_capabilities` uses, declared WITHOUT importing the catalog.

    WHY THIS IS A PROTOCOL AND NOT AN IMPORT (P3.6-2 design section 6.3, option (c)): importing `ActionCatalog` from
    `threat_report_agent.investigation` would add a `workbench_query -> investigation` module edge that
    `check-import-graph.py --strict` CANNOT police (`workbench_query` is not a source in any `forbidden_edges` pair,
    and the gate's registration check is per-NODE, not per-edge - `docs/import-policy.json`
    `_recorded_allowed_edges_note` states the blind spot). The host therefore constructs the catalog and passes it in,
    and this Protocol describes the shape it must have: `ActionCatalog.default().names()` and
    `.require(name).cost_units` are the only two things this slice touches.
    """

    def names(self) -> tuple[str, ...]: ...
    def require(self, action_type: object) -> object: ...


# ---------------------------------------------------------------------------
# Moved implementation (P3.6-1 slice): identical to its old home in service.py. The receiver it used to reach
# through `self`/`cls` is now an explicit `host: WorkbenchQueryReaderHost` parameter, and ONLY where the body still
# needs one. This banner is deliberately SLICE-AGNOSTIC: it used to name the first slice, so the second slice's
# code was appended under a label that lied about which step moved it. P3.4-0 made the label a parameter for the
# same reason - a `report/` module appended under a banner claiming a P3.3 slice is that defect again.
# ---------------------------------------------------------------------------


def task_view(host: WorkbenchQueryReaderHost, task_id: str) -> dict[str, object]:
    with host.database.session_factory() as session:
        task = session.get(AnalysisTask, task_id)
        if task is None:
            raise LookupError(task_id)
        case = session.get(CaseRecord, task.case_id)
        failure = session.scalar(
            select(AnalysisFailureRecord).where(AnalysisFailureRecord.task_id == task.id)
        )
        inputs = host._report_inputs(session, task_id)
        claim_evidence_map: dict[str, list[str]] = {}
        for link in inputs["claim_evidence"]:
            if link.stance == "SUPPORTS":
                claim_evidence_map.setdefault(link.claim_id, []).append(link.evidence_id)
        disposed_artifact_ids = {
            artifact.id for artifact in inputs["artifacts"] if artifact.disposed_at is not None
        }
        revisions = list(
            session.scalars(
                select(ReportRevision)
                .where(ReportRevision.task_id == task_id)
                .order_by(ReportRevision.created_at.desc())
            )
        )
        delivery_rows = list(
            session.scalars(
                select(EvidenceDeliveryTrace)
                .where(EvidenceDeliveryTrace.task_id == task_id)
                .order_by(EvidenceDeliveryTrace.created_at, EvidenceDeliveryTrace.id)
            )
        )
        blind_rows = list(
            session.scalars(
                select(BlindRun)
                .where(BlindRun.task_id == task_id)
                .order_by(BlindRun.created_at, BlindRun.id)
            )
        )
        delivery_counts: dict[str, int] = {}
        for item in delivery_rows:
            delivery_counts[item.stage] = delivery_counts.get(item.stage, 0) + 1
        return {
            "id": task.id,
            "case_id": task.case_id,
            "trace_id": task.trace_id,
            "case_title": case.title if case else "",
            "lifecycle": task.lifecycle,
            "outcome": task.outcome,
            "analysis_class": task.analysis_class,
            "failure": host._failure_payload(failure),
            "analysis_coverage": task.coverage or {},
            "target_granularity": {
                "breadth": task.target_breadth,
                "depth": task.target_depth,
            },
            "actual_granularity": task.actual_granularity,
            "selected_report_modules": task.selected_modules,
            "limitations": task.limitations,
            "request_snapshot": task.request_snapshot,
            "strategy_snapshot": task.strategy_snapshot,
            "blind_runs": [
                {
                    "id": item.id,
                    "status": item.status,
                    "snapshot": item.snapshot,
                    "snapshot_sha256": item.snapshot_sha256,
                    "created_at": item.created_at.isoformat(),
                }
                for item in blind_rows
            ],
            "artifacts": [
                {
                    "id": item.id,
                    "logical_path": item.logical_path,
                    "sha256": item.content_sha256,
                    "detected_type": item.detected_type,
                    "role": item.role,
                    "obligation": item.obligation,
                    "parent_artifact_id": item.parent_artifact_id,
                    "disposed": item.disposed_at is not None,
                }
                for item in inputs["artifacts"]
            ],
            "tool_runs": [
                {
                    "id": item.id,
                    "artifact_id": item.artifact_id,
                    "tool": item.tool_name,
                    "version": item.tool_version,
                    "status": item.status,
                    "error": item.error,
                    "parameters": {
                        key: item.parameters[key]
                        for key in ("scheduler", "planned_tools", "analysis_modules")
                        if key in (item.parameters or {})
                    },
                    "output_reference": (
                        {
                            "sha256": item.output_sha256,
                            "storage_key": item.output_storage_key,
                        }
                        if item.output_sha256 and item.output_storage_key
                        else None
                    ),
                    "execution": {
                        key: item.environment[key]
                        for key in (
                            "case_id",
                            "trace_id",
                            "tool_run_id",
                            "executor",
                            "execution_mode",
                            "workflow_id",
                            "task_queue",
                            "environment_version",
                        )
                        if key in item.environment
                    },
                    "started_at": (
                        host._audit_timestamp(item.started_at) if item.started_at else None
                    ),
                    "finished_at": (
                        host._audit_timestamp(item.finished_at) if item.finished_at else None
                    ),
                }
                for item in inputs["tool_runs"]
            ],
            "model_calls": [
                {
                    "id": item.id,
                    "module": item.module,
                    "turn_id": item.turn_id,
                    "phase": item.phase,
                    "provider": item.provider,
                    "model": item.model,
                    "origin": str(item.parameters.get("origin") or "model"),
                    "attempt": item.attempt,
                    "status": item.status,
                    "prompt_id": item.prompt_id,
                    "prompt_version": item.prompt_version,
                    "prompt_sha256": item.prompt_sha256,
                    "request_sha256": item.request_sha256,
                    "response_sha256": item.response_sha256,
                    "payload_schema_version": item.payload_schema_version,
                    "encryption_key_id": item.encryption_key_id,
                    "security_classification": item.security_classification,
                    "access_policy": item.access_policy,
                    "input_tokens": item.input_tokens,
                    "output_tokens": item.output_tokens,
                    "latency_ms": item.latency_ms,
                    "error_type": item.error_type,
                    "http_status": item.parameters.get("http_status"),
                    "endpoint_path": item.parameters.get("endpoint_path"),
                    "error_detail": item.parameters.get("error_detail"),
                    "agent_run_id": item.parameters.get("agent_run_id"),
                    "context_evidence_count": item.parameters.get("context_evidence_count"),
                    "context_bytes": item.parameters.get("context_bytes"),
                }
                for item in inputs["model_calls"]
            ],
            "analysis_turns": [
                {
                    "id": item.id,
                    "thread_id": item.thread_id,
                    "turn_id": item.turn_id,
                    "phase": item.phase,
                    "hypothesis_before": item.hypothesis_before,
                    "retrieval_request": item.retrieval_request,
                    "candidate_evidence_ids": item.candidate_evidence_ids,
                    "selected_evidence_ids": item.selected_evidence_ids,
                    "delivered_evidence_ids": item.delivered_evidence_ids,
                    "context_manifest": [
                        {
                            key: value
                            for key, value in manifest.items()
                            if key
                            in {
                                "evidence_id",
                                "artifact_id",
                                "kind",
                                "nature",
                                "context_role",
                                "selection_score",
                                "selection_rationale",
                                "quota_group",
                                "trust_zone",
                            }
                        }
                        for manifest in item.context_manifest
                        if isinstance(manifest, dict)
                    ],
                    "model_call_id": item.model_call_id,
                    "raw_response": (
                        {
                            "sha256": item.raw_response_sha256,
                            "storage_key": item.raw_response_storage_key,
                        }
                        if item.raw_response_sha256 and item.raw_response_storage_key
                        else None
                    ),
                    "action_proposals": item.action_proposals,
                    "policy_decisions": item.policy_decisions,
                    "tool_run_ids": item.tool_run_ids,
                    "new_evidence_ids": item.new_evidence_ids,
                    "verifier_result": item.verifier_result,
                    "hypothesis_after": item.hypothesis_after,
                    "mechanism_state": item.mechanism_state,
                    "stop_reason": item.stop_reason,
                    "created_at": item.created_at.isoformat(),
                }
                for item in inputs["analysis_turns"]
            ],
            "analysis_turn_results": [
                {
                    "id": item.id,
                    "parent_turn_id": item.parent_turn_id,
                    "thread_id": item.thread_id,
                    "turn_id": item.turn_id,
                    "phase": item.phase,
                    "completed_actions": item.completed_actions,
                    "tool_run_ids": item.tool_run_ids,
                    "new_evidence_ids": item.new_evidence_ids,
                    "verifier_result": item.verifier_result,
                    "hypothesis_after": item.hypothesis_after,
                    "mechanism_state": item.mechanism_state,
                    "stop_reason": item.stop_reason,
                    "created_at": item.created_at.isoformat(),
                }
                for item in inputs["analysis_turn_results"]
            ],
            "claims": [
                {
                    "id": item.id,
                    "module": item.module,
                    "claim_type": item.claim_type,
                    "subject": item.subject,
                    "action": item.action,
                    "object": item.object,
                    "mechanism": item.mechanism,
                    "condition": item.condition,
                    "nature": item.nature,
                    "statement": item.statement,
                    "status": item.status,
                    "confidence": item.confidence,
                    "attack_mapping": item.attack_mapping,
                    "model_call_id": item.model_call_id,
                    "evidence_ids": claim_evidence_map.get(item.id, []),
                }
                for item in inputs["claims"]
            ],
            "claim_evidence": [
                {
                    "claim_id": item.claim_id,
                    "evidence_id": item.evidence_id,
                    "stance": item.stance,
                }
                for item in inputs["claim_evidence"]
            ],
            "relations": [
                {
                    "id": item.id,
                    "source_artifact_id": item.source_artifact_id,
                    "target_artifact_id": item.target_artifact_id,
                    "relation_type": item.relation_type,
                    "evidence_id": item.evidence_id,
                    "claim_id": item.claim_id,
                    "status": item.status,
                }
                for item in inputs["relations"]
            ],
            "evidence": [
                {
                    "id": item.id,
                    "artifact_id": item.artifact_id,
                    "module": item.module,
                    "kind": item.kind,
                    "nature": item.nature,
                    "value": (
                        {"redacted": True, "reason": "artifact_disposed"}
                        if item.artifact_id in disposed_artifact_ids
                        else item.value
                    ),
                    "anchor": item.anchor,
                }
                for item in inputs["evidence"]
            ],
            "gates": [
                {
                    "id": item.id,
                    "type": item.gate_type,
                    "status": item.status,
                    "reason": item.reason,
                    "context": item.context,
                }
                for item in inputs["gates"]
            ],
            "evidence_delivery": {
                "counts": delivery_counts,
                "records": [
                    {
                        "turn_id": item.turn_id,
                        "thread_id": item.thread_id,
                        "model_call_id": item.model_call_id,
                        "subject_key": item.subject_key,
                        "evidence_id": item.evidence_id,
                        "stage": item.stage,
                        "context_role": item.context_role,
                        "selection_score": item.selection_score,
                        "exclusion_reason": item.exclusion_reason,
                        "details": item.details,
                    }
                    for item in delivery_rows
                ],
            },
            "investigation": {
                "threads": [
                    {
                        "id": item.id,
                        "artifact_id": item.artifact_id,
                        "state": item.state,
                        "question": item.question,
                        "seed_kind": item.seed_kind,
                        "evidence_ids": item.evidence_ids,
                        "hypothesis_ids": item.hypothesis_ids,
                        "action_ids": item.action_ids,
                        "transition_count": item.transition_count,
                    }
                    for item in inputs["investigation_threads"]
                ],
                "hypotheses": [
                    {
                        "id": item.id,
                        "thread_id": item.thread_id,
                        "statement": item.statement,
                        "dimension": item.dimension,
                        "status": item.status,
                        "confidence": item.confidence,
                        "evidence_ids": item.evidence_ids,
                        "required_evidence": item.required_evidence,
                    }
                    for item in inputs["investigation_hypotheses"]
                ],
                "actions": [
                    {
                        "id": item.id,
                        "thread_id": item.thread_id,
                        "hypothesis_id": item.hypothesis_id,
                        "artifact_id": item.artifact_id,
                        "action_type": item.action_type,
                        "parameters": item.parameters,
                        "target_selector": item.target_selector,
                        "expected_evidence_kinds": item.expected_evidence_kinds,
                        "success_condition": item.success_condition,
                        "failure_interpretation": item.failure_interpretation,
                        "cost_units": item.cost_units,
                        "status": item.status,
                        "priority": item.priority,
                        "attempts": item.attempts,
                        "depends_on": item.depends_on,
                        "result_evidence_ids": item.result_evidence_ids,
                        "error": item.error,
                    }
                    for item in inputs["investigation_actions"]
                ],
            },
            "mechanism_effectiveness_traces": [
                {
                    "id": item.id,
                    "trace_version": item.trace_version,
                    "mechanism_id": item.mechanism_id,
                    "mechanism_type": item.mechanism_type,
                    "artifact_id": item.artifact_id,
                    "seed": item.seed,
                    "question": item.question,
                    "competing_hypotheses": item.competing_hypotheses,
                    "action_proposals": item.action_proposals,
                    "tool_runs": item.tool_run_ids,
                    "new_evidence_ids": item.new_evidence_ids,
                    "evidence_delta": item.evidence_delta,
                    "hypothesis_delta": item.hypothesis_delta,
                    "mechanism_delta": item.mechanism_delta,
                    "verifier_result": item.verifier_result,
                    "claim_gate": item.claim_gate,
                    "report_projection": item.report_projection,
                    "model_action_productivity": item.model_action_productivity,
                    "trace_sha256": item.trace_sha256,
                    "created_at": item.created_at.isoformat(),
                }
                for item in inputs["mechanism_effectiveness_traces"]
            ],
            "latest_report_revision_id": revisions[0].id if revisions else None,
            "authoritative_report_revision_id": revisions[0].id if revisions else None,
            "created_at": task.created_at.isoformat(),
            "finished_at": task.finished_at.isoformat() if task.finished_at else None,
        }


def workbench_domain_view(host: WorkbenchQueryReaderHost, task_id: str) -> dict[str, object]:
    """Stable, bounded projection for DSH views.

        This endpoint is polled by the workbench tabs.  It must not call
        ``task_view`` because that projection intentionally materializes every
        Evidence row for export and can contain tens of thousands of rows.
        Raw evidence remains available through the paginated query endpoint.
        """
    with host.database.session_factory() as session:
        task = session.get(AnalysisTask, task_id)
        if task is None:
            raise LookupError(task_id)
        failure = session.scalar(
            select(AnalysisFailureRecord).where(AnalysisFailureRecord.task_id == task.id)
        )
        case = session.get(CaseRecord, task.case_id)
        artifacts = list(
            session.scalars(
                select(Artifact)
                .where(Artifact.task_id == task_id)
                .order_by(Artifact.created_at, Artifact.id)
            )
        )
        threads = list(
            session.scalars(
                select(InvestigationThreadRecord)
                .where(InvestigationThreadRecord.task_id == task_id)
                .order_by(InvestigationThreadRecord.created_at, InvestigationThreadRecord.id)
            )
        )
        hypotheses = list(
            session.scalars(
                select(InvestigationHypothesisRecord)
                .where(InvestigationHypothesisRecord.task_id == task_id)
                .order_by(
                    InvestigationHypothesisRecord.created_at, InvestigationHypothesisRecord.id
                )
            )
        )
        actions = list(
            session.scalars(
                select(InvestigationActionRecord)
                .where(InvestigationActionRecord.task_id == task_id)
                .order_by(InvestigationActionRecord.created_at, InvestigationActionRecord.id)
            )
        )
        claims_rows = list(
            session.scalars(
                select(Claim)
                .where(Claim.task_id == task_id)
                .order_by(Claim.created_at, Claim.id)
            )
        )
        claim_evidence = list(
            session.scalars(
                select(ClaimEvidence)
                .join(Claim, Claim.id == ClaimEvidence.claim_id)
                .where(Claim.task_id == task_id)
            )
        )
        evidence_by_claim: dict[str, list[str]] = {}
        for link in claim_evidence:
            if link.stance == "SUPPORTS":
                evidence_by_claim.setdefault(link.claim_id, []).append(link.evidence_id)
        claims = [
            {
                "id": item.id,
                "module": item.module,
                "claim_type": item.claim_type,
                "subject": item.subject,
                "action": item.action,
                "object": item.object,
                "mechanism": item.mechanism,
                "condition": item.condition,
                "nature": item.nature,
                "statement": item.statement,
                "status": item.status,
                "confidence": item.confidence,
                "attack_mapping": item.attack_mapping,
                "model_call_id": item.model_call_id,
                "evidence_ids": evidence_by_claim.get(item.id, []),
            }
            for item in claims_rows
        ]
        relations_rows = list(
            session.scalars(
                select(Relation)
                .where(Relation.task_id == task_id)
                .order_by(Relation.created_at, Relation.id)
            )
        )
        relations = [
            {
                "id": item.id,
                "source_artifact_id": item.source_artifact_id,
                "target_artifact_id": item.target_artifact_id,
                "relation_type": item.relation_type,
                "evidence_id": item.evidence_id,
                "claim_id": item.claim_id,
                "status": item.status,
            }
            for item in relations_rows
        ]
        revisions = list(
            session.scalars(
                select(ReportRevision)
                .where(ReportRevision.task_id == task_id)
                .order_by(ReportRevision.created_at.desc(), ReportRevision.id.desc())
            )
        )
        artifact_payload = [
            {
                "id": item.id,
                "logical_path": item.logical_path,
                "sha256": item.content_sha256,
                "detected_type": item.detected_type,
                "role": item.role,
                "obligation": item.obligation,
                "parent_artifact_id": item.parent_artifact_id,
                "disposed": item.disposed_at is not None,
            }
            for item in artifacts
        ]
        strategy = task.strategy_snapshot or {}
        strategy_investigation = (
            strategy.get("investigation", {}) if isinstance(strategy, dict) else {}
        )
        thread_protocols = (
            strategy_investigation.get("thread_protocols", {})
            if isinstance(strategy_investigation, dict)
            else {}
        )
        snapshot_thread_rows = (
            strategy_investigation.get("threads", [])
            if isinstance(strategy_investigation, dict)
            else []
        )

        def _thread_protocol_fields(thread_id: str) -> tuple[dict[str, object], dict[str, object]]:
            meta = thread_protocols.get(thread_id) if isinstance(thread_protocols, dict) else None
            protocol: dict[str, object] = {}
            ladder: dict[str, object] = {}
            if isinstance(meta, dict):
                if isinstance(meta.get("protocol"), dict):
                    protocol = dict(meta["protocol"])
                if isinstance(meta.get("s_ladder"), dict):
                    ladder = dict(meta["s_ladder"])
            if not protocol or not ladder:
                for row in snapshot_thread_rows:
                    if isinstance(row, dict) and row.get("id") == thread_id:
                        if not protocol and isinstance(row.get("protocol"), dict):
                            protocol = dict(row["protocol"])
                        if not ladder and isinstance(row.get("s_ladder"), dict):
                            ladder = dict(row["s_ladder"])
                        break
            return protocol, ladder

        thread_payload = []
        for item in threads:
            protocol, ladder = _thread_protocol_fields(item.id)
            thread_payload.append(
                {
                    "id": item.id,
                    "artifact_id": item.artifact_id,
                    "state": item.state,
                    "question": item.question,
                    "seed_kind": item.seed_kind,
                    "evidence_ids": item.evidence_ids,
                    "hypothesis_ids": item.hypothesis_ids,
                    "action_ids": item.action_ids,
                    "transition_count": item.transition_count,
                    "protocol": protocol,
                    "s_ladder": ladder,
                }
            )
        hypothesis_payload = [
            {
                "id": item.id,
                "thread_id": item.thread_id,
                "statement": item.statement,
                "dimension": item.dimension,
                "status": item.status,
                "confidence": item.confidence,
                "evidence_ids": item.evidence_ids,
                "required_evidence": item.required_evidence,
            }
            for item in hypotheses
        ]
        action_payload = [host._action_payload(item) for item in actions]
        model_calls = list(
            session.scalars(
                select(ModelCall)
                .where(ModelCall.task_id == task_id)
                .order_by(ModelCall.created_at.desc(), ModelCall.id.desc())
                .limit(8)
            )
        )
        unique_execution_threads = _unique_execution_threads_for_view(host, session, task_id)
        task_payload = {
            "id": task.id,
            "case_id": task.case_id,
            "case_title": case.title if case else "",
            "trace_id": task.trace_id,
            "lifecycle": task.lifecycle,
            "outcome": task.outcome,
            "analysis_class": task.analysis_class,
            "target_granularity": {"breadth": task.target_breadth, "depth": task.target_depth},
            "actual_granularity": task.actual_granularity,
            "limitations": task.limitations,
            "latest_report_revision_id": revisions[0].id if revisions else None,
            "authoritative_report_revision_id": revisions[0].id if revisions else None,
            "created_at": task.created_at.isoformat(),
            "started_at": task.started_at.isoformat() if task.started_at else None,
            "finished_at": task.finished_at.isoformat() if task.finished_at else None,
            "elapsed_ms": host._elapsed_ms(task),
            "server_time": utcnow().isoformat(),
            "failure": host._failure_payload(failure),
            "model_status": host._model_status_payload(failure, model_calls),
            "unique_execution_threads": unique_execution_threads,
        }
        snapshot_mechanisms = [
            dict(item)
            for item in (
                strategy_investigation.get("mechanisms", [])
                if isinstance(strategy_investigation, dict)
                else []
            )
            if isinstance(item, dict)
        ]
    result = {
        "schema_version": 1,
        "task": task_payload,
        "artifacts": artifact_payload,
        "threads": thread_payload,
        "hypotheses": hypothesis_payload,
        "actions": action_payload,
        "unique_execution_threads": unique_execution_threads,
        "work_ledger": [
            dict(item)
            for item in (
                strategy_investigation.get("work_ledger", [])
                if isinstance(strategy_investigation, dict)
                else []
            )
            if isinstance(item, dict)
        ][:128],
        # Claims are the normal domain source, but specialist investigation
        # results are also persisted in the task snapshot.  Include both
        # projections so a verified mechanism is not hidden merely because
        # its Claim is materialized in a later transaction or has no
        # human-facing mechanism text yet.
        "mechanisms": [],
        "claims": claims,
        "relations": relations,
        "sample_timeline": [],
        "report": {
            "revision_id": revisions[0].id if revisions else None,
            "available": bool(revisions),
        },
    }
    mechanism_rows: list[dict[str, object]] = []
    by_mechanism_key: dict[str, dict[str, object]] = {}
    for candidate in snapshot_mechanisms:
        if not isinstance(candidate, dict):
            continue
        key = str(candidate.get("mechanism_id") or candidate.get("id") or "")
        if not key:
            continue
        current = by_mechanism_key.get(key)
        if current is None:
            current = dict(candidate)
            by_mechanism_key[key] = current
            mechanism_rows.append(current)
            continue
        for field, value in candidate.items():
            if value not in (None, "", [], {}):
                current[field] = value
    for candidate in claims:
        if not isinstance(candidate, dict) or not candidate.get("mechanism"):
            continue
        key = str(
            candidate.get("mechanism_id") or candidate.get("id") or candidate.get("claim_id")
        )
        current = by_mechanism_key.get(key)
        if current is None:
            current = dict(candidate)
            by_mechanism_key[key] = current
            mechanism_rows.append(current)
            continue
        # Merge non-empty fields from the second projection without
        # downgrading a verified status or replacing rich fields with
        # empty/placeholder values.
        for field, value in candidate.items():
            if value in (None, "", [], {}):
                continue
            if field == "status" and str(current.get(field, "")).upper() in {
                "VERIFIED",
                "SUPPORTED",
                "CONFIRMED",
            }:
                continue
            if field in {"evidence_ids", "claim_ids"}:
                current[field] = list(
                    dict.fromkeys(
                        [
                            *(item for item in current.get(field, []) if item),
                            *(item for item in value if item),
                        ]
                    )
                )
            else:
                current[field] = value
    result["mechanisms"] = mechanism_rows[:128]
    # ``task_view`` intentionally contains the strategy/runtime records
    # needed for the audit trace, while the compact Workbench task
    # projection omits them.  Build the timeline once here so both the
    # aggregate view and the dedicated collection endpoint expose the same
    # bounded, non-sensitive sequence.
    investigation_state = (
        strategy.get("investigation", {}) if isinstance(strategy, dict) else {}
    )
    timeline: list[dict[str, object]] = []
    if isinstance(investigation_state, dict):
        for item in investigation_state.get("seed_rankings", []):
            if isinstance(item, dict):
                timeline.append(
                    {
                        "phase": "DISCOVERED->PRIORITIZED",
                        "artifact_id": item.get("artifact_id"),
                        "priority": item.get("priority"),
                        "question": item.get("question"),
                        "rationale": item.get("rationale"),
                    }
                )
        runtime = investigation_state.get("runtime", {})
        if isinstance(runtime, dict):
            for item in runtime.get("events", []):
                if isinstance(item, dict):
                    timeline.append(
                        {
                            "phase": str(item.get("phase", "investigation")),
                            "state": item.get("state"),
                            "action_id": item.get("action_id"),
                            "evidence_ids": list(item.get("evidence_ids", [])),
                            "message": item.get("message"),
                        }
                    )
    for claim in claims:
        if isinstance(claim, dict) and claim.get("mechanism"):
            timeline.append(
                {
                    "phase": "MECHANISM_READY->CLAIM_READY",
                    "claim_id": claim.get("id"),
                    "module": claim.get("module"),
                    "action": claim.get("action"),
                    "status": claim.get("status"),
                    "confidence": claim.get("confidence"),
                    "evidence_ids": list(claim.get("evidence_ids", [])),
                }
            )
    for relation in relations:
        if isinstance(relation, dict):
            timeline.append(
                {
                    "phase": "CLAIM_READY->RELATION",
                    "relation_id": relation.get("id"),
                    "relation": relation.get("relation_type"),
                    "status": relation.get("status"),
                    "evidence_id": relation.get("evidence_id"),
                    "claim_id": relation.get("claim_id"),
                }
            )
    result["sample_timeline"] = timeline[:256]
    return result


def workbench_query_evidence(
    host: WorkbenchQueryReaderHost,
    *,
    task_id: str,
    kind: str | None = None,
    module: str | None = None,
    artifact_id: str | None = None,
    limit: int = 100,
    filter_text: str | None = None,
) -> dict[str, object]:
    """Query stored evidence, optionally addressable by function or address.

        ``filter_text`` matches the row's ``anchor`` or ``value`` text.  Without
        it the caller can only page a flat list of a kind -- 1283 ``function_call``
        rows with no way to ask "show me function X".  That flatness is what made
        deep investigation impossible for the agent: it could read summaries but
        never drill into a specific function or address.
        """
    limit = max(1, min(limit, 500))
    needle = str(filter_text or "").strip()
    with host.database.session_factory() as session:
        if session.get(AnalysisTask, task_id) is None:
            raise LookupError(task_id)
        query = select(Evidence).where(Evidence.task_id == task_id)
        if kind:
            query = query.where(Evidence.kind == kind)
        if module:
            query = query.where(Evidence.module == module)
        if artifact_id:
            query = query.where(Evidence.artifact_id == artifact_id)
        if needle:
            # Accept the forms an analyst actually types and that Ghidra emits:
            # 0x140038ae0, 140038ae0, FUN_140038ae0.
            variants = {needle, needle.casefold()}
            stripped = needle.casefold().removeprefix("0x").removeprefix("fun_")
            if stripped:
                variants.update({stripped, f"0x{stripped}", f"fun_{stripped}"})
            clauses = []
            for token in variants:
                pattern = f"%{token}%"
                clauses.append(cast(Evidence.anchor, String).ilike(pattern))
                clauses.append(cast(Evidence.value, String).ilike(pattern))
            query = query.where(or_(*clauses))
        rows = list(
            session.scalars(query.order_by(Evidence.created_at, Evidence.id).limit(limit))
        )
        return {
            "task_id": task_id,
            "items": [
                {
                    "id": row.id,
                    "artifact_id": row.artifact_id,
                    "module": row.module,
                    "kind": row.kind,
                    "nature": row.nature,
                    "value": row.value,
                    "anchor": row.anchor,
                }
                for row in rows
            ],
            "limit": limit,
        }


def model_configuration_view(host: WorkbenchQueryReaderHost) -> dict[str, object]:
    with host.database.session_factory() as session:
        row = session.get(ModelConfiguration, "active")
        if row is None:
            primary_configured = host.settings.primary_model.configured
            return {
                "source": "user" if primary_configured else "unconfigured",
                "revision": 0,
                "enabled": host.settings.model_calls_enabled and primary_configured,
                "context_max_bytes": host.settings.model_context_max_bytes,
                "timeout_s": host.settings.model_timeout_s,
                "max_tokens": host.settings.model_max_tokens,
                "primary": {
                    "provider": host.settings.primary_model.provider,
                    "base_url": host.settings.primary_model.base_url,
                    "model": host.settings.primary_model.model,
                    "api_style": host.settings.primary_model.api_style,
                    "enabled": host.settings.primary_model.enabled,
                    "stream": host.settings.primary_model.stream,
                    "supports_json_mode": host.settings.primary_model.supports_json_mode,
                    "temperature": host.settings.primary_model.temperature,
                    "top_p": host.settings.primary_model.top_p,
                    "disable_reasoning": host.settings.primary_model.disable_reasoning,
                    "configured": primary_configured,
                    "api_key_configured": bool(host.settings.primary_model.api_key),
                },
                "fallback": {
                    "provider": host.settings.fallback_model.provider,
                    "base_url": host.settings.fallback_model.base_url,
                    "model": host.settings.fallback_model.model,
                    "api_style": host.settings.fallback_model.api_style,
                    "enabled": host.settings.fallback_model.enabled,
                    "stream": host.settings.fallback_model.stream,
                    "supports_json_mode": host.settings.fallback_model.supports_json_mode,
                    "temperature": host.settings.fallback_model.temperature,
                    "top_p": host.settings.fallback_model.top_p,
                    "disable_reasoning": host.settings.fallback_model.disable_reasoning,
                    "configured": host.settings.fallback_model.configured,
                    "api_key_configured": bool(host.settings.fallback_model.api_key),
                },
            }
        return {
            "source": "database",
            "revision": row.revision,
            # Keep the stored preference visible, but expose ``enabled``
            # as the effective value so clients cannot mistake a
            # persisted preference for permission to make network calls.
            "enabled": bool(row.enabled) and host._model_calls_env_enabled,
            "stored_enabled": bool(row.enabled),
            "deployment_enabled": host._model_calls_env_enabled,
            "context_max_bytes": row.context_max_bytes,
            "timeout_s": row.timeout_s,
            "max_tokens": row.max_tokens,
            "updated_by": row.updated_by,
            "updated_at": row.updated_at.isoformat(),
            "primary": _config_route_view(host, row, "primary"),
            "fallback": _config_route_view(host, row, "fallback"),
        }


def workbench_thread(host: WorkbenchQueryReaderHost, thread_id: str) -> dict[str, object]:
    with host.database.session_factory() as session:
        row = session.get(InvestigationThreadRecord, thread_id)
        if row is None:
            raise LookupError(thread_id)
        task = session.get(AnalysisTask, row.task_id)
        if task is None:
            raise LookupError(thread_id)
        hypothesis_rows = list(
            session.scalars(
                select(InvestigationHypothesisRecord).where(
                    InvestigationHypothesisRecord.thread_id == row.id
                )
            )
        )
        action_rows = list(
            session.scalars(
                select(InvestigationActionRecord)
                .where(InvestigationActionRecord.thread_id == row.id)
                .order_by(InvestigationActionRecord.created_at)
            )
        )
        return {
            "schema_version": 1,
            "id": row.id,
            "task_id": row.task_id,
            "artifact_id": row.artifact_id,
            "state": row.state,
            "question": row.question,
            "seed_kind": row.seed_kind,
            "evidence_ids": row.evidence_ids,
            "transition_count": row.transition_count,
            "hypotheses": [
                {
                    "id": item.id,
                    "statement": item.statement,
                    "dimension": item.dimension,
                    "status": item.status,
                    "confidence": item.confidence,
                    "evidence_ids": item.evidence_ids,
                    "required_evidence": item.required_evidence,
                }
                for item in hypothesis_rows
            ],
            "actions": [host._action_payload(item) for item in action_rows],
        }


def _config_route_view(host: WorkbenchQueryReaderHost, row: ModelConfiguration, slot: str) -> dict[str, object]:
    prefix = f"{slot}_"
    ciphertext = getattr(row, f"{prefix}api_key_ciphertext")
    stored_enabled = bool(getattr(row, f"{prefix}enabled")) and bool(row.enabled)
    return {
        "provider": getattr(row, f"{prefix}provider"),
        "base_url": getattr(row, f"{prefix}base_url"),
        "model": getattr(row, f"{prefix}model"),
        "api_style": getattr(row, f"{prefix}api_style"),
        "enabled": stored_enabled,
        "stored_enabled": stored_enabled,
        "effective_enabled": stored_enabled and host._model_calls_env_enabled,
        "stream": bool(getattr(row, f"{prefix}stream", True)),
        "supports_json_mode": bool(getattr(row, f"{prefix}supports_json_mode", True)),
        "temperature": float(getattr(row, f"{prefix}temperature", 0.0)),
        "top_p": float(getattr(row, f"{prefix}top_p", 1.0)),
        "disable_reasoning": bool(getattr(row, f"{prefix}disable_reasoning", True)),
        "configured": bool(ciphertext)
        and bool(getattr(row, f"{prefix}base_url"))
        and bool(getattr(row, f"{prefix}model")),
        "api_key_configured": bool(ciphertext),
    }


def _unique_execution_threads_for_view(
    host: WorkbenchQueryReaderHost, session: Session, task_id: str
) -> list[dict[str, object]]:
    """Bounded OS-thread rows for DSH task_gaps; not a full evidence dump."""
    rows = list(
        session.scalars(
            select(Evidence)
            .where(
                Evidence.task_id == task_id,
                Evidence.kind.in_(host._UNIQUE_THREAD_VIEW_KINDS),
            )
            .order_by(
                case(
                    (Evidence.kind == "api_argument_trace", 0),
                    (Evidence.kind == "tls_callback", 1),
                    (Evidence.kind == "thread_callback", 1),
                    else_=2,
                ),
                Evidence.created_at,
                Evidence.id,
            )
            .limit(host._CATALOG_HOW_SEED_SCAN_LIMIT)
        )
    )
    compact: list[dict[str, object]] = []
    for item in build_unique_execution_threads({row.id: row for row in rows})[:16]:
        if not isinstance(item, Mapping):
            continue
        compact.append(
            {
                "type": "unique_execution_thread",
                "api": item.get("api"),
                "function_entry": item.get("function_entry"),
                "start_routine": item.get("start_routine"),
                "parameter": item.get("parameter"),
                "loop": item.get("loop"),
                "exit": item.get("exit"),
                "shared_state": item.get("shared_state"),
                "emulator_status": item.get("emulator_status"),
                "evidence_ids": [
                    str(evidence_id)
                    for evidence_id in (item.get("evidence_ids") or [])
                    if evidence_id
                ][:8],
            }
        )
    return compact


# ---------------------------------------------------------------------------
# Moved implementation (P3.6-2 slice): `workbench_capabilities`, verbatim from its old home in service.py except for
# the receiver rename (`self` -> `host`) and the catalog, which the DELEGATION supplies rather than this module
# importing it. See `ActionCatalogProjection` above for why that is not an import.
# ---------------------------------------------------------------------------


def workbench_capabilities(
    host: WorkbenchQueryReaderHost, catalog: ActionCatalogProjection
) -> dict[str, object]:
    # NO DOCSTRING ON PURPOSE - MEASURED, not an omission. `test_delegations_keep_the_implementations_docstring`
    # compares this body's `__doc__` with the service delegation's for EXACT string equality, and the delegation
    # documents the P3.6-2 decision as a COMMENT, so the synchronized value is `None` on both sides. Copying the
    # text into a docstring here cannot work: `__doc__` is the RAW string, this body is indented 4 spaces and the
    # delegation 8, and neither the test nor any gate calls `inspect.cleandoc`. Binding
    # `workbench_capabilities.__doc__` from `service.AnalysisService` at module level was also rejected: it needs
    # `from threat_report_agent.service import ...` inside this module, the one import
    # `test_the_module_never_imports_the_service_layer` exists to forbid.
    #
    # WHY THIS BODY IS NOT SIMPLY `host`-ONLY: the catalog arrives as a PARAMETER (design section 6.3 option (c)),
    # which is what keeps `workbench_query` free of any `investigation` import. The pin, the Protocol and the
    # parameter list are all asserted in `tests/test_workbench_query_contract.py`; the tamper that proves the import
    # assertion bites is `.scratch/p36-2-canfail.py` T4.
    actions = []
    for name in catalog.names():
        actions.append(
            {
                "name": name,
                "description": f"Bounded read-only static investigation action: {name}",
                "input_schema": {"type": "object", "additionalProperties": True},
                "output_schema": {"type": "object", "additionalProperties": True},
                "security_class": "READ_ONLY_STATIC",
                "estimated_cost": catalog.require(name).cost_units,
            }
        )
    model_callable_tools = [
        "threat_get_capabilities",
        "threat_get_session_analysis_context",
        "threat_list_session_artifacts",
        "threat_list_session_workspace_artifacts",
        "threat_import_workspace_artifact",
        "threat_start_static_analysis",
        "threat_get_analysis_status",
        "threat_wait_for_analysis_update",
        "threat_propose_static_action",
        "threat_get_action_result",
        "threat_query_current_analysis_evidence",
        "threat_get_thread_summary",
        "threat_get_mechanism",
        "threat_get_report_summary",
        "threat_bind_existing_analysis",
        "threat_unbind_analysis",
    ]
    policy = simulation_policy_from_settings(host.settings)
    return {
        "api_version": 1,
        # ``actions`` is retained for API v1 clients.  New model callers
        # must use the single policy-gated proposal tool below.
        "actions": actions,
        "backend_static_action_catalog": actions,
        "model_callable_tools": [
            {"name": name, "security_class": "SESSION_SCOPED_STATIC"}
            for name in model_callable_tools
        ],
        "action_submission_tool": "threat_propose_static_action",
        "unavailable_capabilities": [
            "sample_execution",
            "host_sample_execution",
            "network_access",
            "arbitrary_shell",
        ],
        "workspace": {
            "supported": bool(
                str(getattr(host.settings, "workbench_workspace_root", "") or "").strip()
            ),
            "root_token": "configured-read-only-root"
            if str(getattr(host.settings, "workbench_workspace_root", "") or "").strip()
            else None,
            "path_mode": "workspace_relative",
        },
        "profiles": ["threat-static"],
        "tool_contract_version": host.THREAT_TOOL_CONTRACT_VERSION,
        "session_context_protocol": host.THREAT_CONTEXT_PROTOCOL,
        "capability_profile": "threat-static",
        "static_only": not policy.enabled,
        "sample_execution": False,
        "network_access": False,
        "isolated_emulation": {
            "available": policy.enabled,
            "profile": policy.profile,
            "host_sample_execution": False,
            "speakeasy_real_pe": "emu-worker-only",
            "qiling": {
                "status": (
                    "UNSUPPORTED"
                    if not (
                        str(policy.qiling_rootfs or "").strip()
                        and Path(policy.qiling_rootfs).is_dir()
                    )
                    else "CONFIGURED"
                ),
                "stop_reason": (
                    None
                    if str(policy.qiling_rootfs or "").strip()
                    and Path(policy.qiling_rootfs).is_dir()
                    else "ROOTFS_REQUIRED"
                ),
                "rootfs_configured": bool(str(policy.qiling_rootfs or "").strip()),
                "applicable_path": "linux_elf_usermode",
            },
            "description": (
                "Granted-window emulation runs automatically in the isolated "
                "emu-worker after static recovery stalls. Speakeasy on a real PE "
                "runs only in that worker. Qiling's applicable path is a pinned "
                "Linux user-mode rootfs plus a Linux ELF; Windows PE is recorded "
                "as NOT_LINUX_ELF rather than ROOTFS_REQUIRED. Granted-window "
                "emulation is static analysis on the isolated worker, not host "
                "sample execution and not sandbox/dynamic analysis."
            ),
        },
        "analysis_planner_model": {
            **host._analysis_planner_payload(),
            "owned_by": "dsh-conversation",
            "configure_in": "Settings → 模型",
        },
    }

