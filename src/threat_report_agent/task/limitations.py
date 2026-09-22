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

from threat_report_agent.models import AnalysisFailureRecord, Artifact, ToolRun



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
