"""Failure and limitation PROJECTION: the pure half of plan P3.2's `TaskRunner` slice.

WHAT THIS MODULE IS: the functions that turn task/artifact/tool-run state into the OPERATIONAL LIMITATIONS and failure
payloads a report carries. Plan P3.2 lists "failure/limitation projection" among the pieces to take out of
`AnalysisService`, and it is the piece the plan treats most carefully - "结构迁移不新增限制丢失" - so it was the first
slice extracted.

WHY THESE FIVE AND NOT ALL OF THEM: MEASURED (`.scratch/p32-seam-analysis.py`): P3.2's five responsibilities cover 19
methods whose helper closure is 163 class members, 31 of them shared with outside methods, so a wholesale `TaskRunner`
extraction is not a bounded move. `.scratch/p32-slice-ranking.py` then ranked the candidates by how self-contained they
are, and these five came out with an EMPTY method closure - no `self`, no other class member, no state. They were
`@staticmethod`s inside the class, so moving them changes nothing except where they are defined.

WHY THEY LOOK THE WAY THEY DO: the bodies are byte-identical to the methods they came from, apart from the indentation
and the name. That is deliberate - a "structural move" that rewrites logic is a behaviour change wearing a move's
clothes, and the identity check in `.scratch/p32a-extract.py` enforces it.

WHAT IS NOT HERE YET: `AnalysisService._record_analysis_failure` and `._is_task_cancelled` are also projection, but
they take `self` (the first uses service state, the second reads `self.database`), so they need the collaborator
designed before they can move - plan P3.2's failure clause says to go back to the interface design in that case rather
than force it.
"""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from threat_report_agent.database import Database
from threat_report_agent.models import (
    AnalysisFailureRecord,
    AnalysisTask,
    Artifact,
    AuditEvent,
    ToolRun,
)
from threat_report_agent.runtime_contracts import classify_failure, retry_decision
from threat_report_agent.task.status import TaskLifecycle, ToolRunStatus



def failure_payload(row: AnalysisFailureRecord | None) -> dict[str, object] | None:
    if row is None:
        return None
    return {
        "task_id": row.task_id,
        "lifecycle": row.lifecycle,
        "analysis_class": row.analysis_class,
        "failure_code": row.failure_code,
        "failure_stage": row.failure_stage,
        "failed_component": row.failed_component,
        "failed_activity": row.failed_activity,
        "retryable": row.retryable,
        "retry_after_seconds": row.retry_after_seconds,
        "failure_fingerprint": row.failure_fingerprint,
        "last_successful_stage": row.last_successful_stage,
        "last_event_id": row.last_event_id,
        "tool_run_id": row.tool_run_id,
        "temporal_workflow_id": row.temporal_workflow_id,
        "report_available": row.report_available,
        "attempt_number": row.attempt_number,
        "retry_of_task_id": row.retry_of_task_id,
        "retry_suppressed": row.retry_suppressed,
        "detail": row.detail,
        "created_at": row.created_at.isoformat(),
    }


def static_decode_recovery_from_limitations(limitations: Iterable[object]) -> str:
    """Summarise an already-registered static decode recovery, read from data in hand.

        MEASURED reason the ticket needs this: the 白象 run published

            TOOL_AUTHORING_REQUIRED: DECODE_CONFIG on 64da3378… needs a tool the product does not
            have; missing evidence: key, algorithm, counter, step, consumer, …

        while the same run's evidence held `DECODED_STATIC`, a four-step `decode_chain` and 5,881
        recovered characters. Two claims there are false: the product HAS the tool
        (`literal_table.py`) and the algorithm WAS recovered.

        Deliberately PURE - it reads the limitation strings the run already produced instead of
        querying the database. An earlier version opened its own session at this point and broke the
        audit chain: `StaleDataError: UPDATE statement on table 'audit_chain_heads' expected to update
        1 row(s); 0 were matched`, failing 8 investigation tests. The investigation loop must not
        open a second session mid-run.
        """
    for item in limitations or []:
        text = str(item or "")
        if "DECODED_STATIC" in text or "utf16le-asciihex-record-table" in text:
            return " ".join(text.split())[:400]
    return ""


def completion_limitations(
    session: Session, task_id: str, artifacts: list[Artifact]
) -> list[str]:
    """Check every REQUIRED artifact instead of deriving COMPLETE from an empty list."""
    limitations: list[str] = []
    for artifact in artifacts:
        if artifact.obligation != "REQUIRED":
            continue
        if artifact.disposed_at is not None:
            limitations.append(f"Required artifact disposed: {artifact.logical_path}.")
            continue
        if artifact.detected_type in {"unknown", "unsupported", "binary"}:
            limitations.append(
                f"Required artifact type is unsupported/unknown: {artifact.logical_path}."
            )
        successful = session.scalar(
            select(ToolRun.id).where(
                ToolRun.task_id == task_id,
                ToolRun.artifact_id == artifact.id,
                ToolRun.status == "SUCCEEDED",
            )
        )
        if successful is None:
            limitations.append(
                f"Required artifact was not successfully analyzed: {artifact.logical_path}."
            )
    return limitations


def failed_tool_run_limitations(session: Session, task_id: str) -> list[str]:
    """Every tool run that did NOT succeed, carrying its OWN status and error.

        MEASURED (adversarial audit): published bodies contain `CANCELLED`/`TIMED_OUT` in 0 of 551 revisions
        while the database holds 7 timed-out tool runs, 2 cancelled tool runs, 49 cancelled tasks and 217
        FAILED emulator runs. `_completion_limitations` notices a missing success only for REQUIRED artifacts
        and emits one generic sentence - "Required artifact was not successfully analyzed" - so the REASON was
        discarded and a reader could not tell a cancellation from a timeout from a crashed activity. A run that
        was cancelled and retried three times (measured in ghidra-worker's log) is indistinguishable from a run
        that simply produced less.

        Deliberately NOT capped: entries are deduplicated and the reason is an opaque short token, so repeats
        collapse. Adding a `[:N]` here would be a fresh unannounced truncation of the kind this report forbids.
        """
    rows = session.execute(
        select(ToolRun.tool_name, ToolRun.status, ToolRun.error)
        .where(ToolRun.task_id == task_id, ToolRun.status != "SUCCEEDED")
        .order_by(ToolRun.tool_name, ToolRun.status)
    ).all()
    limitations: list[str] = []
    for tool_name, status, error in rows:
        # "no error recorded" states what we HAVE, not a claim that none occurred.
        reason = str(error or "").strip() or "no error recorded"
        entry = f"Tool run {tool_name or 'unknown'} ended {status}: {reason}."
        if entry not in limitations:
            limitations.append(entry)
    return limitations


def merge_operational_limitations(document: dict[str, object], task: object) -> None:
    """Merge the TASK's own limitations into the document key the renderer actually reads.

        `document["analyst_report_limitations"]` is a two-endpoint channel: ONE writer
        (`_overlay_analyst_report_plan`) and ONE reader (`analyst_report.py`, via `_verification_note` and
        `_operational_limitation_lines`). That writer previously only ever saw the MODEL's self-reported
        limitations, while the pipeline's operational limitations live on the TASK row (`models.py:75`).
        MEASURED consequence: published bodies contain `CANCELLED`/`TIMED_OUT` in 0 of 551 revisions while the
        database holds 7 TIMED_OUT tool runs, 2 CANCELLED tool runs and 49 cancelled tasks - and a truncation
        notice written into `task.limitations` reached no reader at all.

        Kept separate from the `if parsed.limitations:` branch at the call site: gating the merge on the MODEL
        having spoken would reproduce the same absence-as-clean-result shape one level removed, because a run
        with operational failures and a silent model would still render nothing.

        ENTRIES ARE LABELLED. A `[pipeline]` prefix lets a reader tell a PIPELINE limitation from a MODEL-stated
        one; without it the model's silence is indistinguishable from the pipeline's failure, which is the very
        confusion that let a failed run read as a clean one.

        NO NEW CAP is introduced: the task's list is produced by the pipeline and is already bounded, and a
        `[:N]` here would be a fresh unannounced truncation of the kind this report forbids.
        """
    operational = [
        str(item).strip() for item in (getattr(task, "limitations", None) or []) if str(item).strip()
    ]
    if not operational:
        return
    merged = list(document.get("analyst_report_limitations") or [])
    for item in operational:
        labelled = item if item.startswith("[pipeline]") else f"[pipeline] {item}"
        if labelled not in merged:
            merged.append(labelled)
    document["analyst_report_limitations"] = merged


def record_analysis_failure(
    session: Session,
    task: AnalysisTask,
    exc: BaseException,
    *,
    stage: str = "ANALYSIS",
    event_id: str | None = None,
) -> dict[str, object]:
    """Persist a sanitized failure contract for every failed attempt."""
    latest_tool = session.scalar(
        select(ToolRun)
        .where(ToolRun.task_id == task.id, ToolRun.status == ToolRunStatus.FAILED.value)
        .order_by(ToolRun.finished_at.desc(), ToolRun.id.desc())
    )
    latest_events = list(
        session.scalars(
            select(AuditEvent)
            .where(AuditEvent.task_id == task.id)
            .order_by(AuditEvent.chain_sequence.desc(), AuditEvent.id.desc())
            .limit(64)
        )
    )
    failure_event_types = {
        "analysis_task.failed",
        "analysis_task.cancelled",
        "analysis_task.cancel_requested",
        "gate.approval_failed",
    }
    latest_event = next(
        (
            item
            for item in latest_events
            if item.event_type not in failure_event_types
            and not item.event_type.endswith(".failed")
        ),
        None,
    )
    last_successful_stage = str(latest_event.event_type)[:160] if latest_event else "UNKNOWN"
    contract = classify_failure(
        exc,
        stage=stage,
        failed_component=(latest_tool.tool_name if latest_tool else None),
        failed_activity=(latest_tool.tool_name if latest_tool else None),
        last_successful_stage=last_successful_stage,
    )
    existing = session.scalar(
        select(AnalysisFailureRecord).where(AnalysisFailureRecord.task_id == task.id)
    )
    detail = {key: value for key, value in contract.items() if key != "message"}
    detail["message"] = str(contract.get("message", ""))[:500]
    workflow_id = None
    if latest_tool is not None and isinstance(latest_tool.environment, dict):
        candidate = latest_tool.environment.get("workflow_id")
        if candidate:
            workflow_id = str(candidate)[:240]
    previous_task = session.scalar(
        select(AnalysisTask)
        .join(
            AnalysisFailureRecord,
            AnalysisFailureRecord.task_id == AnalysisTask.id,
        )
        .where(
            AnalysisTask.case_id == task.case_id,
            AnalysisTask.id != task.id,
            AnalysisTask.lifecycle == TaskLifecycle.FAILED.value,
        )
        .order_by(AnalysisTask.finished_at.desc(), AnalysisTask.created_at.desc())
    )
    # A just-flushed task can be visible through the join before its
    # failure row is committed. Never allow a failure record to point to
    # itself, even if a database backend returns an unexpected identity
    # comparison result during autoflush.
    if previous_task is not None and str(previous_task.id) == str(task.id):
        previous_task = None
    previous_failure = (
        session.scalar(
            select(AnalysisFailureRecord).where(
                AnalysisFailureRecord.task_id == previous_task.id
            )
        )
        if previous_task is not None
        else None
    )
    previous_fingerprint = (
        existing.failure_fingerprint
        if existing is not None
        else (previous_failure.failure_fingerprint if previous_failure is not None else None)
    )
    decision = retry_decision(
        retryable=bool(contract["retryable"]),
        previous_fingerprint=previous_fingerprint,
        fingerprint=str(contract["failure_fingerprint"]),
    )
    retry_of_task_id = previous_task.id if previous_task is not None else None
    attempt_number = (
        (existing.attempt_number + 1)
        if existing is not None
        else ((previous_failure.attempt_number + 1) if previous_failure is not None else 1)
    )
    values = {
        "lifecycle": "FAILED",
        "analysis_class": "FAILED_ANALYSIS",
        "failure_code": str(contract["failure_code"]),
        "failure_stage": str(contract["failure_stage"]),
        "failed_component": str(contract["failed_component"]),
        "failed_activity": str(contract["failed_activity"]),
        "retryable": bool(contract["retryable"]),
        "retry_after_seconds": contract["retry_after_seconds"],
        "failure_fingerprint": str(contract["failure_fingerprint"]),
        "last_successful_stage": str(contract["last_successful_stage"]),
        "last_event_id": event_id or (latest_event.id if latest_event else None),
        "tool_run_id": latest_tool.id if latest_tool else None,
        "temporal_workflow_id": workflow_id,
        "report_available": False,
        "attempt_number": attempt_number,
        "retry_of_task_id": retry_of_task_id,
        "retry_suppressed": bool(decision["retry_suppressed"]),
        "detail": {
            **detail,
            "retry": decision,
            "retry_reason": decision.get("reason"),
            "requested_by": "system",
            "previous_failure_fingerprint": previous_fingerprint,
        },
    }
    if existing is None:
        session.add(AnalysisFailureRecord(task_id=task.id, **values))
    else:
        for key, value in values.items():
            setattr(existing, key, value)
    return {**values, "task_id": task.id, "retry": decision}


def is_task_cancelled(
    database: Database,
    task_id: str,
    *,
    observing: Session | None = None,
) -> bool:
    """Answer "has this task been cancelled" without disturbing a caller's transaction.

        Reading the lifecycle is a pure probe, but a probe is not free when the engine hands out a single
        shared connection (sqlite in-memory uses ``StaticPool``; a nested ``sessionmaker`` call then borrows
        the very connection that owns the caller's open transaction).  Closing such a borrowed session makes
        SQLAlchemy roll that connection back, which silently discards the caller's uncommitted work.  The
        observable consequence was a report synthesis that flushed its ``analysis_snapshots`` row and then
        failed the ``report_revisions.snapshot_id`` foreign key because the row had been rolled back by this
        probe.

        ``observing`` lets a caller that already holds a session -- and therefore already owns the
        transaction -- answer the question inside that transaction instead.  A read-only sibling session is
        used only when the bound session can no longer be used, and the fallback keeps the previous
        behaviour for callers with no session to share.
        """
    session = observing
    if session is not None:
        try:
            task = session.get(AnalysisTask, task_id)
        except Exception:
            # A failed or closed session must not turn a cancellation probe into a hard error.
            session = None
        else:
            return task is None or task.lifecycle == TaskLifecycle.CANCELLED.value
    with database.session_factory() as fallback:
        task = fallback.get(AnalysisTask, task_id)
        return task is None or task.lifecycle == TaskLifecycle.CANCELLED.value
