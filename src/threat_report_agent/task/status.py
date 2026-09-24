from __future__ import annotations

from enum import StrEnum

from threat_report_agent.product_certification import AnalysisResultClass

# MOVED to `contracts.py` (P3.5-0 M-3) and re-exported with `X as X`, so `task.status`, the root `status` shim
# and every existing importer keep the SAME objects. `contracts` is importable from every layer (plan 3.2), so the
# direction is legal and no cycle is created.
from threat_report_agent.contracts import (  # noqa: E402
    TaskLifecycle as TaskLifecycle,
    InvalidStateTransition as InvalidStateTransition,
    TASK_TRANSITIONS as TASK_TRANSITIONS,
    transition_task as transition_task,
)

AnalysisClass = AnalysisResultClass


class CaseStatus(StrEnum):
    OPEN = "OPEN"
    ARCHIVED = "ARCHIVED"




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






