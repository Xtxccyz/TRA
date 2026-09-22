"""A completion budget too small for a reasoning model must be reported as exactly that.

MEASURED DEFECT. `deepseek-v4-pro` returned, for the analyst-report overlay:

    HTTP 200
    finish_reason              = 'length'
    choices[0].message.content = ''          <- empty string
    usage.completion_tokens    = 2048
    usage.completion_tokens_details.reasoning_tokens = 2048

A reasoning stream and the answer SHARE the completion budget, so a budget that is too small for the
thinking leaves nothing for the body. Every downstream symptom then named the wrong cause:

    json.loads("")                     -> JSONDecodeError
    AnalystReportPlanEnvelope.validate -> ValidationError ("chapters: missing")
    AgentRuntime                       -> MODEL_PROVIDERS_UNAVAILABLE
    _overlay_analyst_report_plan       -> except Exception: return document

so a run whose `analyst_report` module had ZERO model calls published a complete-looking deterministic
report, and the operator had no way to tell that the model had never answered. Same request at 4096 tokens
returned `finish_reason=stop` with 8 chapters.

Three things are asserted here: the diagnosis is named, a real answer is never mislabelled as exhausted,
and the completion budget is no longer clamped below the configured value.
"""
from __future__ import annotations

import json

from threat_report_agent.model_gateway import ModelGateway


def _body(finish: str, content: str, completion: int | None, reasoning: int | None) -> dict:
    usage: dict = {}
    if completion is not None:
        usage["completion_tokens"] = completion
    if reasoning is not None:
        usage["completion_tokens_details"] = {"reasoning_tokens": reasoning}
    return {
        "choices": [{"finish_reason": finish, "message": {"content": content}}],
        "usage": usage,
    }


def test_all_tokens_spent_on_reasoning_is_named() -> None:
    detail = ModelGateway._reasoning_budget_exhausted(_body("length", "", 2048, 2048))
    assert detail.startswith("REASONING_BUDGET_EXHAUSTED"), detail
    assert "2048" in detail


def test_a_truncated_answer_is_still_named_as_a_budget_problem() -> None:
    """`finish_reason=length` with no reasoning detail reported is the same class of failure."""
    detail = ModelGateway._reasoning_budget_exhausted(_body("length", "", 2048, None))
    assert detail.startswith("COMPLETION_BUDGET_EXHAUSTED"), detail
    assert "2048" in detail


def test_a_real_answer_is_never_called_exhausted() -> None:
    for finish, content, completion, reasoning in (
        ("stop", '{"chapters": []}', 300, 200),
        ("stop", '{"chapters": []}', 300, None),
        ("length", '{"chapters": [', 2048, 1000),
    ):
        assert ModelGateway._reasoning_budget_exhausted(_body(finish, content, completion, reasoning)) == ""


def test_a_partial_budget_with_content_is_not_exhausted() -> None:
    """Only a FULLY consumed reasoning budget plus an empty body counts."""
    assert ModelGateway._reasoning_budget_exhausted(_body("length", "partial text", 2048, 2048)) == ""


def test_missing_usage_is_not_guessed_at() -> None:
    """Without usage numbers the condition cannot be established, so nothing is claimed."""
    assert ModelGateway._reasoning_budget_exhausted(_body("length", "", None, None)) == ""
    assert ModelGateway._reasoning_budget_exhausted({"choices": []}) == ""
    assert ModelGateway._reasoning_budget_exhausted({}) == ""


def test_a_reported_count_without_reasoning_detail_is_still_named() -> None:
    """`finish_reason=length`, an empty body and a finite completion count is the same failure."""
    detail = ModelGateway._reasoning_budget_exhausted(_body("length", "", 2048, None))
    assert detail.startswith("COMPLETION_BUDGET_EXHAUSTED"), detail
    assert "2048" in detail


def test_it_is_used_as_the_error_detail_when_a_response_body_is_available() -> None:
    """The named condition must reach the audit record, not only a unit-test helper."""

    class FakeResponse:
        status_code = 200

        def json(self) -> dict:
            return _body("length", "", 2048, 2048)

        @property
        def content(self) -> bytes:
            return json.dumps(_body("length", "", 2048, 2048)).encode()

    class FakeProvider:
        base_url = "https://api.example.invalid/v1"
        provider = "custom"
        model = "reasoning-model"

    status, _path, detail = ModelGateway._failure_metadata(
        ValueError("schema failed"),
        FakeProvider(),
        "/chat/completions",
    )
    assert status is None

    # The response is attached to the exception in production; mirror that shape.
    class FakeError(Exception):
        response = FakeResponse()

    status, _path, detail = ModelGateway._failure_metadata(
        FakeError("schema failed"),
        FakeProvider(),
        "/chat/completions",
    )
    assert status == 200
    assert "REASONING_BUDGET_EXHAUSTED" in detail, (
        "the budget condition is still reported as a schema error, which points the operator at the "
        "prompt instead of at the budget"
    )
