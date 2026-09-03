"""Bounded, auditable model-agent execution.

The runtime uses explicit run states, immutable events, a context budget, and
separate terminal failure/cancellation states. It intentionally exposes no
sample-execution or arbitrary tool capability; the policy engine remains the
only authority for tool proposals.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Generic, Literal, TypeVar
from uuid import uuid4

from threat_report_agent.model_gateway import (
    ModelAttempt,
    ModelGateway,
    ModelRequest,
    ModelResponse,
    ModelUnavailable,
)
from threat_report_agent.runtime_contracts import ContextBudgetManager


T = TypeVar("T")
AgentRunStatus = Literal["SUCCEEDED", "FAILED", "CANCELLED"]


@dataclass(frozen=True)
class AgentEvent:
    name: str
    at: datetime
    payload: dict[str, object]


@dataclass(frozen=True)
class AgentRunResult(Generic[T]):
    run_id: str
    status: AgentRunStatus
    response: ModelResponse[T] | None
    attempts: tuple[ModelAttempt, ...]
    events: tuple[AgentEvent, ...]
    error: str | None = None


class AgentRuntime:
    """Run one bounded structured-output turn through the configured gateway."""

    def __init__(
        self,
        gateway: ModelGateway,
        *,
        max_context_bytes: int = 2_000_000,
        cancellation_requested: Callable[[], bool] | None = None,
    ) -> None:
        if max_context_bytes < 1024:
            raise ValueError("max_context_bytes must be at least 1024")
        self.gateway = gateway
        self.max_context_bytes = max_context_bytes
        self.context_budget = ContextBudgetManager(max_context_bytes)
        self.cancellation_requested = cancellation_requested

    def run(self, request: ModelRequest[T]) -> AgentRunResult[T]:
        run_id = str(uuid4())
        events: list[AgentEvent] = []

        def emit(name: str, **payload: object) -> None:
            events.append(AgentEvent(name, datetime.now(UTC), dict(payload)))

        emit(
            "agent.run.started",
            task_id=request.task_id,
            module=request.module,
            max_context_bytes=self.max_context_bytes,
            max_turns=1,
        )
        if self._cancelled():
            emit("agent.run.cancelled", reason="before_model_call")
            return AgentRunResult(run_id, "CANCELLED", None, (), tuple(events), "AGENT_CANCELLED")

        decision = self.context_budget.prepare(
            request.messages,
            reserved_completion_bytes=max(1024, request.max_tokens * 4),
        )
        emit(
            "agent.context.checked",
            context_bytes=decision.input_bytes,
            reserved_completion_bytes=decision.reserved_completion_bytes,
            safety_margin_bytes=decision.safety_margin_bytes,
            total_bytes=decision.total_bytes,
            compacted=decision.compacted,
        )
        if decision.compacted:
            emit("agent.context.compacted", message_count=len(decision.messages))
        if not decision.allowed:
            error = "AGENT_CONTEXT_BUDGET_EXCEEDED"
            emit("agent.run.failed", error=error)
            return AgentRunResult(run_id, "FAILED", None, (), tuple(events), error)

        try:
            response = self.gateway.complete(replace(request, messages=decision.messages))
        except ModelUnavailable as exc:
            emit(
                "agent.run.failed",
                error="MODEL_PROVIDERS_UNAVAILABLE",
                attempt_count=len(exc.attempts),
            )
            return AgentRunResult(
                run_id,
                "FAILED",
                None,
                exc.attempts,
                tuple(events),
                "MODEL_PROVIDERS_UNAVAILABLE",
            )
        except Exception as exc:  # adapter failures must not strand a task
            error = f"AGENT_RUNTIME_ERROR:{type(exc).__name__}"
            emit("agent.run.failed", error=error)
            return AgentRunResult(run_id, "FAILED", None, (), tuple(events), error)

        if self._cancelled():
            emit("agent.run.cancelled", reason="after_model_call")
            return AgentRunResult(
                run_id,
                "CANCELLED",
                None,
                response.attempts,
                tuple(events),
                "AGENT_CANCELLED",
            )
        emit(
            "agent.run.completed",
            provider=response.provider,
            model=response.model,
            attempt_count=len(response.attempts),
        )
        return AgentRunResult(run_id, "SUCCEEDED", response, response.attempts, tuple(events))

    def _cancelled(self) -> bool:
        return bool(self.cancellation_requested and self.cancellation_requested())
