from __future__ import annotations

from enum import StrEnum

from threat_report_agent.product_certification import AnalysisResultClass

AnalysisClass = AnalysisResultClass


class CaseStatus(StrEnum):
    OPEN = "OPEN"
    ARCHIVED = "ARCHIVED"


class TaskLifecycle(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    WAITING_GATE = "WAITING_GATE"
    PAUSED = "PAUSED"
    FINALIZING = "FINALIZING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ToolRunStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


class AnalysisOutcome(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    BLOCKED = "BLOCKED"
    UNSUPPORTED = "UNSUPPORTED"


class EvidenceNature(StrEnum):
    STATIC_OBSERVED = "STATIC_OBSERVED"
    STATIC_DERIVED = "STATIC_DERIVED"
    STATIC_INFERRED = "STATIC_INFERRED"
    BACKGROUND_REPORTED = "BACKGROUND_REPORTED"
    EMULATION_OBSERVED = "EMULATION_OBSERVED"
    DYNAMIC_OBSERVED = "DYNAMIC_OBSERVED"


class ClaimNature(StrEnum):
    STATIC_INFERRED = "STATIC_INFERRED"


class ClaimStatus(StrEnum):
    CANDIDATE = "CANDIDATE"
    VERIFIED = "VERIFIED"
    DISPUTED = "DISPUTED"
    REJECTED = "REJECTED"


class ReportStatus(StrEnum):
    DRAFT = "DRAFT"
    APPROVED = "APPROVED"
    PUBLISHED = "PUBLISHED"


class InvalidStateTransition(ValueError):
    pass


TASK_TRANSITIONS: dict[TaskLifecycle, frozenset[TaskLifecycle]] = {
    TaskLifecycle.PENDING: frozenset(
        {
            TaskLifecycle.RUNNING,
            TaskLifecycle.WAITING_GATE,
            TaskLifecycle.FAILED,
            TaskLifecycle.CANCELLED,
        }
    ),
    TaskLifecycle.RUNNING: frozenset(
        {
            TaskLifecycle.WAITING_GATE,
            TaskLifecycle.PAUSED,
            TaskLifecycle.FINALIZING,
            TaskLifecycle.FAILED,
            TaskLifecycle.CANCELLED,
        }
    ),
    TaskLifecycle.WAITING_GATE: frozenset(
        {TaskLifecycle.RUNNING, TaskLifecycle.PAUSED, TaskLifecycle.CANCELLED}
    ),
    TaskLifecycle.PAUSED: frozenset({TaskLifecycle.RUNNING, TaskLifecycle.CANCELLED}),
    TaskLifecycle.FINALIZING: frozenset(
        {TaskLifecycle.SUCCEEDED, TaskLifecycle.FAILED, TaskLifecycle.CANCELLED}
    ),
    TaskLifecycle.SUCCEEDED: frozenset(),
    TaskLifecycle.FAILED: frozenset(),
    TaskLifecycle.CANCELLED: frozenset(),
}


def transition_task(current: TaskLifecycle | str, target: TaskLifecycle | str) -> TaskLifecycle:
    current_state = TaskLifecycle(current)
    target_state = TaskLifecycle(target)
    if target_state not in TASK_TRANSITIONS[current_state]:
        raise InvalidStateTransition(f"{current_state.value} -> {target_state.value}")
    return target_state
