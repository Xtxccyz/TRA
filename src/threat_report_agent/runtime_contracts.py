"""Runtime contracts for bounded, diagnosable agent turns.

These helpers are deliberately independent from FastAPI and Temporal.  They
provide deterministic contracts that can be used by the API, workers, and the
DSH adapter without exposing raw model payloads or private chain-of-thought.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping


@dataclass(frozen=True)
class ContextBudgetDecision:
    """A bounded model-context decision with an auditable estimate."""

    messages: tuple[dict[str, str], ...]
    input_bytes: int
    reserved_completion_bytes: int
    safety_margin_bytes: int
    max_context_bytes: int
    compacted: bool
    allowed: bool
    reason: str | None = None

    @property
    def total_bytes(self) -> int:
        return self.input_bytes + self.reserved_completion_bytes + self.safety_margin_bytes


class ContextBudgetManager:
    """Compact repeated tool output before a model call.

    The model-visible context is intentionally smaller than the immutable audit
    log.  System instructions and the latest user turn are retained; older
    tool snapshots are reduced to a bounded summary and only the newest window
    of conversational messages is kept.
    """

    def __init__(
        self,
        max_context_bytes: int,
        *,
        safety_margin_bytes: int = 64 * 1024,
        max_tool_result_bytes: int = 8 * 1024,
        max_messages: int = 96,
    ) -> None:
        if max_context_bytes < 1024:
            raise ValueError("max_context_bytes must be at least 1024")
        self.max_context_bytes = max_context_bytes
        self.safety_margin_bytes = max(0, safety_margin_bytes)
        self.max_tool_result_bytes = max(512, max_tool_result_bytes)
        self.max_messages = max(8, max_messages)

    @staticmethod
    def _encode(messages: tuple[dict[str, str], ...]) -> bytes:
        return json.dumps(
            {"messages": messages}, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")

    def _compact_message(self, message: Mapping[str, Any]) -> dict[str, str]:
        role = str(message.get("role", "user"))[:32]
        content = message.get("content", "")
        if not isinstance(content, str):
            content = json.dumps(content, ensure_ascii=False, separators=(",", ":"))
        if role == "tool" and len(content.encode("utf-8")) > self.max_tool_result_bytes:
            raw = content.encode("utf-8")
            digest = hashlib.sha256(raw).hexdigest()[:16]
            content = raw[: self.max_tool_result_bytes].decode("utf-8", errors="ignore")
            content += f"\n[tool_result_compacted sha256_prefix={digest} bytes={len(raw)}]"
        return {"role": role, "content": content}

    def prepare(
        self,
        messages: tuple[dict[str, str], ...] | list[dict[str, str]],
        *,
        reserved_completion_bytes: int,
    ) -> ContextBudgetDecision:
        original = tuple(self._compact_message(item) for item in messages)
        compacted = False
        candidate = original
        if len(candidate) > self.max_messages:
            system = tuple(item for item in candidate if item.get("role") == "system")[:2]
            tail = candidate[-(self.max_messages - len(system)) :]
            candidate = system + tail
            compacted = True

        def fits(items: tuple[dict[str, str], ...]) -> bool:
            size = len(self._encode(items))
            return size + reserved_completion_bytes + self.safety_margin_bytes <= self.max_context_bytes

        while len(candidate) > 2 and not fits(candidate):
            system = tuple(item for item in candidate if item.get("role") == "system")[:2]
            keep = max(1, self.max_messages // 2)
            candidate = system + candidate[-keep:]
            compacted = True

        input_bytes = len(self._encode(candidate))
        total = input_bytes + reserved_completion_bytes + self.safety_margin_bytes
        allowed = total <= self.max_context_bytes
        reason = None if allowed else "CONTEXT_BUDGET_EXCEEDED"
        return ContextBudgetDecision(
            messages=candidate,
            input_bytes=input_bytes,
            reserved_completion_bytes=reserved_completion_bytes,
            safety_margin_bytes=self.safety_margin_bytes,
            max_context_bytes=self.max_context_bytes,
            compacted=compacted,
            allowed=allowed,
            reason=reason,
        )


def _exception_text(exc: BaseException) -> str:
    return str(exc).strip().replace("\x00", " ")[:500]


def classify_failure(
    exc: BaseException,
    *,
    stage: str,
    failed_component: str | None = None,
    failed_activity: str | None = None,
    last_successful_stage: str | None = None,
) -> dict[str, object]:
    """Build a sanitized, stable AnalysisFailureContract projection."""

    text = _exception_text(exc).casefold()
    name = type(exc).__name__.casefold()
    # An interrupted run is a worker-level failure and must stay retryable.  This
    # is matched on an explicit marker rather than on a class-name substring: the
    # first attempt relied on `"worker" in name`, which is False for
    # `AnalysisRunOrphaned`, so the failure silently became the non-retryable
    # `STATIC_WORKFLOW_ACTIVITY_FAILED` and the sample would never have been
    # analysed again.  `code` is the stable contract, so match it directly.
    if str(getattr(exc, "code", "")) == "ANALYSIS_RUN_ORPHANED":
        code = "WORKER_FAILURE"
    elif "model" in name or "provider" in name or "api" in name and "http" in text:
        code = "MODEL_FAILURE"
    elif "timeout" in name or "timeout" in text or "deadline" in text:
        code = "TIMEOUT_FAILURE"
    elif (
        "database" in name
        or "postgres" in text
        or "psycopg" in text
        or "sqlalchemy" in text
        or "evidence_search_keys" in text
        or ("lz4" in text and "corrupt" in text)
        or "sql" in name
    ):
        code = "DB_FAILURE"
    elif "temporal" in name or "workflow" in text:
        code = "TEMPORAL_FAILURE"
    elif "worker" in name or "connection" in name or "unavailable" in text:
        code = "WORKER_FAILURE"
    elif "resource" in text or "memory" in text or "limit" in text:
        code = "RESOURCE_LIMIT_FAILURE"
    elif "report" in text or "synthesis" in text:
        code = "REPORT_SYNTHESIS_FAILURE"
    elif "mechanism" in text or "investigation" in text:
        code = "MECHANISM_LOOP_FAILURE"
    else:
        code = "STATIC_WORKFLOW_ACTIVITY_FAILED"
    retryable = code in {
        "MODEL_FAILURE",
        "TIMEOUT_FAILURE",
        "DB_FAILURE",
        "TEMPORAL_FAILURE",
        "WORKER_FAILURE",
    }
    fingerprint = hashlib.sha256(
        json.dumps(
            {"code": code, "stage": stage, "component": failed_component, "activity": failed_activity, "message": _exception_text(exc)},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "lifecycle": "FAILED",
        "analysis_class": "FAILED_ANALYSIS",
        "failure_code": code,
        "failure_stage": stage[:160],
        "failed_component": (failed_component or type(exc).__module__)[:160],
        "failed_activity": (failed_activity or type(exc).__name__)[:160],
        "retryable": retryable,
        "retry_after_seconds": 30 if retryable else None,
        "failure_fingerprint": fingerprint,
        "last_successful_stage": (last_successful_stage or "UNKNOWN")[:160],
        "message": _exception_text(exc),
        "report_available": False,
        "server_time": datetime.now(UTC).isoformat(),
    }


def retry_decision(*, retryable: bool, previous_fingerprint: str | None, fingerprint: str) -> dict[str, object]:
    """Return a deterministic retry decision; identical failures are suppressed."""

    repeated = bool(previous_fingerprint and previous_fingerprint == fingerprint)
    return {
        "retry": bool(retryable and not repeated),
        "retry_suppressed": repeated,
        "reason": "same_failure_fingerprint" if repeated else ("transient_failure" if retryable else "non_retryable_failure"),
    }
