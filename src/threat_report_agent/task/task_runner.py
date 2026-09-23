"""P3.2 task runner: the port the task path needs from its host, plus the first cluster that moved behind it.

STATUS: LOAD-BEARING since P3.2c. Plan 7.1 orders every migration in nine steps: step 2 is "在新包先建立最小公开接口
和 contract test" - the port and its pin below, added while nothing depended on them - and step 3 is "移动同一份实现",
which is the `creation` cluster now living in this file. `AnalysisService.create_submission_task` and
`.prepare_blind_run` are one-line delegations to the functions here, and `SubmissionResult` travelled with the cluster
because its return type was DEFINED in service.py; service.py re-exports it, so
`threat_report_agent.service.SubmissionResult` still resolves to the same object.

STILL ON THE HOST, DELIBERATELY (MEASURED by `.scratch/p32c-creation-analysis.py`): the workbench-binding pair
`bind_historical_analysis` (a 2-line forwarder) and `workbench_bind_existing_analysis` (its 90-line implementation).
Moving them needs THREE host helpers that are not on the port - `_context_payload_v3`, `_context_state_for_task_v3`,
`_require_session_id` - so they are their own cluster with their own deliberate port widening instead of riding along
with the creation move.

DONE IN P3.2c: the cluster's ONLY host needs are `_audit`, `content_store` and `database`, a subset of the port, so
this move required NO widening; `tests/test_task_runner_contract.py` re-derives that from the source each run.

WHY A PORT AT ALL (MEASURED, `.scratch/p32design-candidates.py` and `.scratch/p32design-scale.py`):

  * The P3.2 wish list is 19 methods / 585 lines of `AnalysisService` covering task creation, lifecycle, budget,
    cancellation and the limitation/outcome projections.
  * Their full helper closure is 18 more members / 1,040 lines, but all of it is reached TRANSITIVELY through the
    entry points below, so it stays on the host. Only ONE closure member would travel with the cluster
    (`workbench_bind_existing_analysis`, 90 lines, used by no outside method).
  * The port-relevant spine - members the candidates touch DIRECTLY that also have at least one user OUTSIDE the
    candidate set - is exactly the six members pinned in `TASK_HOST_MEMBERS`. An earlier "31 shared members of a
    163-member closure" figure counted the whole transitive closure and made the cluster look unbounded; the
    measured direct spine is what a port actually has to provide, and it is small.
  * So the whole of P3.2 is at most 675 lines / 20 members behind a 6-member port, and it can be moved one cluster
    at a time: `creation` (DONE in P3.2c: 2 methods + the dataclass that is their return type, spine 3) ->
    `lifecycle` (1, spine 2) -> `budget` (spine 1: `task_view`) -> `cancellation` (2, spine 6 - the only cluster
    that needs `_seal_task_audit_chain`) -> workbench binding (spine 3 plus 3 further helpers, so it is the ONE
    cluster that widens the port).

WHY TWO PRIVATE NAMES APPEAR ON A PORT (a deliberate, reviewable choice):

  `_audit` and `_seal_task_audit_chain` are host-private, and naming them here is not an oversight. The host is
  `AnalysisService`, whose PUBLIC surface is a contract in its own right: P3.1 fixed it to four stable operation
  groups and `tests/test_service_facade_contract.py` plus `tests/test_task_runner_contract.py` pin it, and plan 7.10
  keeps the HTTP boundary on public members only. Publishing `audit` / `seal_task_audit_chain` as new public methods
  just to make the port look tidy would widen that published surface for a purely internal collaboration, so the port
  states the host's real name instead. A future P3/P4 step that genuinely needs a public audit entry point should
  rename the member AND update this port and its pin together, in one deliberate change.

`missing_task_host_members` is the executable form of the port, so "does this object satisfy the host contract?" is
answerable at runtime rather than only by a type checker.

    python -m pytest -q tests/test_task_runner_contract.py
"""
from __future__ import annotations

from typing import Protocol

import hashlib
import io
import zipfile
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from threat_report_agent.config import Settings
from threat_report_agent.content_store import ContentStore
from threat_report_agent.contracts import (
    BackgroundContextInput,
    FourChannelInput,
    KnowledgeSnapshotInput,
    SamplePackageInput,
    TaskRequestInput,
)
from threat_report_agent.database import Database
# `Artifact`, `Evidence` and `ToolRun` were added deliberately for P3.2e (the budget cluster reads tool runs,
# evidence rows and artifacts): the extractor REFUSES to widen a live module's imports on its own, so the widening
# is recorded here rather than appearing as a side effect of a move.
from threat_report_agent.models import AnalysisTask, Artifact, AuditEvent, CaseRecord, Evidence, ToolRun, new_id
from threat_report_agent.report.reporting import normalize_modules
from threat_report_agent.task.status import TaskLifecycle

#: The measured direct spine of the P3.2 candidate set - the ONLY things a task cluster may require of its host.
#: Pinned by `tests/test_task_runner_contract.py`, which re-derives it from `service.py` and fails if it grew, so
#: adding a seventh member is a deliberate act rather than a silent widening of the port.
TASK_HOST_MEMBERS: tuple[str, ...] = (
    "_audit",
    "_seal_task_audit_chain",
    "content_store",
    "database",
    "settings",
    "task_view",
)


class TaskHost(Protocol):
    """What the task path may use on the object that owns it.

    Deliberately three pieces of HOST STATE plus three HOST OPERATIONS and nothing else: state the task path reads
    (`settings`, `database`, `content_store`), the audit writer it must call (`_audit`), the terminal audit-chain
    seal that only cancellation needs (`_seal_task_audit_chain`), and the public read of a task (`task_view`).

    `task_view` being here is the one member that is a PUBLISHED facade operation (P3.1's "read status" group):
    the budget cluster asks the host for the task view rather than reading task rows itself, which keeps that read
    single-sourced.
    """

    settings: Settings
    database: Database
    content_store: ContentStore

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

    def _seal_task_audit_chain(
        self,
        session: Session,
        task: AnalysisTask,
        terminal_event_type: str,
    ) -> None: ...

    def task_view(self, task_id: str) -> dict[str, object]: ...


def missing_task_host_members(host: object) -> tuple[str, ...]:
    """Return the `TASK_HOST_MEMBERS` this object does not provide, in declaration order.

    Empty means the object satisfies the port. Used by the contract test to prove `AnalysisService` DOES satisfy it
    (and that a stub missing a member is reported rather than silently accepted).
    """
    return tuple(name for name in TASK_HOST_MEMBERS if not hasattr(host, name))


# ---------------------------------------------------------------------------
# Moved implementation (P3.2c): the creation cluster, identical to its old home except that the receiver it
# used to reach through `self` is now the explicit `host: TaskHost` parameter. `SubmissionResult` travelled with
# it because the cluster's return type was defined in service.py; service.py re-exports it, so its public path
# is unchanged.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SubmissionResult:
    case_id: str
    task_id: str
    lifecycle: str
    outcome: str | None
    report_revision_id: str | None
    gate_id: str | None = None


def create_submission_task(
    host: TaskHost,
    *,
    case_id: str,
    filename: str,
    submitted_size: int,
    content: bytes | None = None,
    source_kind: str = "file",
    background_context: str = "",
    background_context_input: BackgroundContextInput | None = None,
    selected_modules: list[str] | None = None,
    idempotency_key: str | None = None,
    trace_id: str | None = None,
    actor: str = "demo-analyst",
) -> tuple[SubmissionResult, bool]:
    modules = normalize_modules(selected_modules)
    if content is not None and submitted_size != len(content):
        raise ValueError("submitted_size must match the submitted content")
    content_sha256 = hashlib.sha256(content).hexdigest() if content is not None else None
    normalized_key = idempotency_key.strip() if idempotency_key else None
    if normalized_key is not None and not 1 <= len(normalized_key) <= 200:
        raise ValueError("Idempotency-Key must contain between 1 and 200 characters")
    with host.database.session_factory.begin() as session:
        case = session.get(CaseRecord, case_id)
        if case is None:
            raise LookupError(f"Case {case_id} does not exist")
        if normalized_key is not None:
            existing = session.scalar(
                select(AnalysisTask).where(
                    AnalysisTask.case_id == case_id,
                    AnalysisTask.submission_key == normalized_key,
                )
            )
            if existing is not None:
                existing_sha256 = existing.request_snapshot.get("sample_package", {}).get(
                    "content_sha256"
                )
                if (
                    content_sha256 is not None
                    and existing_sha256 is not None
                    and content_sha256 != existing_sha256
                ):
                    raise ValueError(
                        "Idempotency-Key is already bound to different sample content"
                    )
                return (
                    SubmissionResult(
                        case_id,
                        existing.id,
                        existing.lifecycle,
                        existing.outcome,
                        None,
                    ),
                    False,
                )
        stored_submission = host.content_store.put(content) if content is not None else None
        if stored_submission is not None and stored_submission.sha256 != content_sha256:
            raise RuntimeError("Content store returned an unexpected SHA-256")
        is_container_scope = source_kind in {"zip", "local_folder"} or (
            content is not None and zipfile.is_zipfile(io.BytesIO(content))
        )
        preset_id = (
            "first-phase-full-static" if is_container_scope else "single-sample-static-deep"
        )
        target_breadth = "B1" if is_container_scope else "B0"
        target_depth = "D2" if is_container_scope else "D3"
        manifest = FourChannelInput(
            task_request=TaskRequestInput(
                preset_id=preset_id,
                target_breadth=target_breadth,
                target_depth=target_depth,
                selected_report_modules=tuple(modules),
            ),
            sample_package=SamplePackageInput(
                source_kind=source_kind,
                display_name=filename,
                submitted_size=submitted_size,
                content_sha256=content_sha256,
                storage_key=(
                    stored_submission.storage_key if stored_submission is not None else None
                ),
            ),
            background_context=(
                background_context_input or BackgroundContextInput(content=background_context)
            ),
            knowledge_snapshot=KnowledgeSnapshotInput(snapshot_id="phase1-static-rules-v1"),
        )
        task = AnalysisTask(
            case_id=case_id,
            trace_id=trace_id or new_id(),
            submission_key=normalized_key,
            lifecycle="PENDING",
            target_breadth=target_breadth,
            target_depth=target_depth,
            selected_modules=modules,
            request_snapshot=manifest.model_dump(mode="json"),
        )
        session.add(task)
        session.flush()
        task_id = task.id
        host._audit(
            session,
            case_id=case_id,
            task_id=task_id,
            event_type="analysis_task.created",
            actor=actor,
            object_type="AnalysisTask",
            object_id=task_id,
            payload={
                "selected_report_modules": modules,
                "input_sha256": content_sha256,
            },
        )
        return SubmissionResult(case_id, task_id, task.lifecycle, None, None), True


def prepare_blind_run(
    host: TaskHost,
    task_id: str,
    *,
    scorecard_version: str = "blind-v2",
    actor: str = "blind-evaluator",
) -> None:
    """Mark a queued task for the reference-isolated Blind v2 protocol."""
    if not scorecard_version or len(scorecard_version) > 120:
        raise ValueError("scorecard_version must contain between 1 and 120 characters")
    with host.database.session_factory.begin() as session:
        task = session.get(AnalysisTask, task_id, with_for_update=True)
        if task is None:
            raise LookupError(task_id)
        if task.lifecycle != TaskLifecycle.PENDING.value:
            raise ValueError("blind mode must be prepared before task execution")
        background = task.request_snapshot.get("background_context") or {}
        if isinstance(background, dict) and str(background.get("content", "")).strip():
            raise ValueError("reference-isolated blind runs cannot contain background context")
        task.strategy_snapshot = {
            **(task.strategy_snapshot or {}),
            "blind_run": {
                "enabled": True,
                "scorecard_version": scorecard_version,
                "reference_isolated": True,
                "status": "PREPARED",
            },
        }
        host._audit(
            session,
            case_id=task.case_id,
            task_id=task.id,
            event_type="blind_run.prepared",
            actor=actor,
            object_type="AnalysisTask",
            object_id=task.id,
            payload={"scorecard_version": scorecard_version, "reference_isolated": True},
        )


# ---------------------------------------------------------------------------
# Moved implementation (P3.2): identical to its old home except that the receiver it used to reach through
# `self` is now the explicit `host: TaskHost` parameter.
# ---------------------------------------------------------------------------


def archive_case(host: TaskHost, case_id: str, *, actor: str = "case-reviewer") -> dict[str, object]:
    """Archive a Case only after every Analysis Task has reached a terminal state."""
    with host.database.session_factory.begin() as session:
        case = session.get(CaseRecord, case_id)
        if case is None:
            raise LookupError(case_id)
        if case.status == "ARCHIVED":
            return {
                "id": case.id,
                "title": case.title,
                "status": case.status,
            }
        active = session.scalar(
            select(AnalysisTask.id).where(
                AnalysisTask.case_id == case_id,
                AnalysisTask.lifecycle.not_in(["SUCCEEDED", "FAILED", "CANCELLED"]),
            )
        )
        if active:
            raise ValueError("Case cannot be archived while an Analysis Task is active")
        case.status = "ARCHIVED"
        host._audit(
            session,
            case_id=case.id,
            event_type="case.archived",
            actor=actor,
            object_type="Case",
            object_id=case.id,
            payload={"status": case.status},
        )
        return {"id": case.id, "title": case.title, "status": case.status}


# ---------------------------------------------------------------------------
# Moved implementation (P3.2): identical to its old home except that the receiver it used to reach through
# `self` is now the explicit `host: TaskHost` parameter.
# ---------------------------------------------------------------------------


def _deferred_budget_thread_ids(host: TaskHost, task_id: str) -> tuple[str, ...]:
    """Return high-value seeds deferred only because the action budget ended."""
    view = host.task_view(task_id)
    snapshot = dict((view.get("strategy_snapshot") or {}).get("investigation") or {})
    deferred = snapshot.get("deferred_frontier") or []
    thread_ids: list[str] = []
    for item in deferred:
        if not isinstance(item, dict):
            continue
        if str(item.get("reason") or "") != "INVESTIGATION_BUDGET_EXHAUSTED":
            continue
        thread_id = str(item.get("thread_id") or "").strip()
        if thread_id:
            thread_ids.append(thread_id)
    return tuple(dict.fromkeys(thread_ids))


def _actual_depth(session: Session, task_id: str, artifacts: list[Artifact]) -> str:
    if not artifacts:
        return "D2"
    parser_ok = session.scalar(
        select(ToolRun.id).where(
            ToolRun.task_id == task_id,
            ToolRun.status == "SUCCEEDED",
            ToolRun.tool_name.in_(
                [
                    "pe-parser",
                    "script-parser",
                    "document-carrier-parser",
                    "builtin-static-analyzer",
                ]
            ),
        )
    )
    if not parser_ok:
        return "D2"
    if any(item.detected_type in {"script", "pdf", "ooxml", "ole"} for item in artifacts):
        return "D3"
    pe_ids = [item.id for item in artifacts if item.detected_type == "pe"]
    if not pe_ids:
        return "D2"
    ghidra_ok = session.scalar(
        select(ToolRun.id).where(
            ToolRun.task_id == task_id,
            ToolRun.artifact_id.in_(pe_ids),
            ToolRun.tool_name == "ghidra-headless",
            ToolRun.status == "SUCCEEDED",
        )
    )
    function_id = session.scalar(
        select(Evidence.id)
        .where(
            Evidence.task_id == task_id,
            Evidence.artifact_id.in_(pe_ids),
            Evidence.kind == "function",
        )
        .limit(1)
    )
    fallback_code_id = session.scalar(
        select(Evidence.id)
        .where(
            Evidence.task_id == task_id,
            Evidence.artifact_id.in_(pe_ids),
            Evidence.kind.in_(
                {"code_api_call", "mechanism_decode", "mechanism_decompression_format"}
            ),
        )
        .limit(1)
    )
    return "D3" if (ghidra_ok and function_id) or fallback_code_id else "D2"
