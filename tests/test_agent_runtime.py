from __future__ import annotations

from dataclasses import dataclass

import pytest

from threat_report_agent.agent_runtime import AgentRuntime
from threat_report_agent.config import ModelProviderSettings
from threat_report_agent.model_gateway import (
    AtomicClaimEnvelope,
    ModelAttempt,
    ModelGateway,
    ModelRequest,
    ModelResponse,
)
from threat_report_agent.validation import validate_claim_evidence


def _request(*, message: str = "ok") -> ModelRequest[AtomicClaimEnvelope]:
    return ModelRequest(
        task_id="task-1",
        case_id="case-1",
        trace_id="trace-1",
        module="static_analysis",
        prompt_id="prompt-1",
        prompt_version="1.0.0",
        prompt_sha256="0" * 64,
        messages=({"role": "user", "content": message},),
        response_schema=AtomicClaimEnvelope,
    )


@dataclass
class _SuccessGateway:
    def complete(self, request: ModelRequest[AtomicClaimEnvelope]) -> ModelResponse[AtomicClaimEnvelope]:
        attempt = ModelAttempt("test", "model", "SUCCEEDED", None, 1, "1" * 64, "2" * 64)
        return ModelResponse(
            parsed=AtomicClaimEnvelope(claims=[]),
            model_call_id="call-1",
            provider="test",
            model="model",
            attempts=(attempt,),
            fallback_reason=None,
            request_sha256=attempt.request_sha256,
            response_sha256=attempt.response_sha256 or "",
            latency_ms=1,
            input_tokens=None,
            output_tokens=None,
            raw_response=b"{}",
        )


def test_agent_runtime_success_emits_immutable_lifecycle_events() -> None:
    result = AgentRuntime(_SuccessGateway()).run(_request())
    assert result.status == "SUCCEEDED"
    assert result.response is not None
    assert [event.name for event in result.events] == [
        "agent.run.started",
        "agent.context.checked",
        "agent.run.completed",
    ]
    with pytest.raises(AttributeError):
        result.events[0].name = "tampered"


def test_agent_runtime_rejects_context_over_budget() -> None:
    result = AgentRuntime(_SuccessGateway(), max_context_bytes=1024).run(
        _request(message="x" * 5000)
    )
    assert result.status == "FAILED"
    assert result.error == "AGENT_CONTEXT_BUDGET_EXCEEDED"
    assert result.response is None


def test_agent_runtime_honors_cancellation_before_provider_call() -> None:
    result = AgentRuntime(_SuccessGateway(), cancellation_requested=lambda: True).run(_request())
    assert result.status == "CANCELLED"
    assert result.error == "AGENT_CANCELLED"
    assert result.events[-1].name == "agent.run.cancelled"


def test_agent_runtime_records_all_provider_failures() -> None:
    gateway = ModelGateway(
        ModelProviderSettings("primary", "", "", ""),
        ModelProviderSettings("fallback", "", "", ""),
    )
    result = AgentRuntime(gateway).run(_request())
    assert result.status == "FAILED"
    assert result.error == "MODEL_PROVIDERS_UNAVAILABLE"
    assert len(result.attempts) == 2
    assert result.events[-1].payload["attempt_count"] == 2


def test_claim_validation_rejects_background_reported_evidence() -> None:
    result = validate_claim_evidence(
        ["background-1"],
        {"background-1"},
        evidence_natures={"background-1": "BACKGROUND_REPORTED"},
    )
    assert result.accepted is False
    assert "disallowed Evidence nature" in result.reason
