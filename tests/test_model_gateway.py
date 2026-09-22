from __future__ import annotations

import json

import httpx
from pydantic import BaseModel
import pytest

from threat_report_agent.config import ModelProviderSettings
from threat_report_agent.model_gateway import (
    AtomicClaimEnvelope,
    DynamicPlanEnvelope,
    ModelGateway,
    ModelRequest,
    ModelUnavailable,
    provider_contract,
    supported_provider_contracts,
)


class Answer(BaseModel):
    value: str


def test_gateway_prefers_richest_schema_valid_plan_over_incidental_empty_object() -> None:
    """A prose ``{}`` must not erase a later executable planning envelope."""
    content = (
        "I will now provide the requested plan. {}\n"
        '{"objective":"Trace the concrete resolver callsite",'
        '"actions":[{"target_artifact_id":"artifact-1",'
        '"action_type":"GET_XREFS_TO","reason":"Anchor the imported API",'
        '"evidence_ids":["evidence-1"],'
        '"target_selector":{"target":"GetProcAddress"}}],'
        '"stop_conditions":["No grounded candidate remains."]}'
    )

    result = ModelGateway._parse_structured_output(DynamicPlanEnvelope, content)

    assert result.objective == "Trace the concrete resolver callsite"
    assert len(result.actions) == 1
    assert result.actions[0].action_type == "GET_XREFS_TO"
    assert result.actions[0].evidence_ids == ["evidence-1"]

    metadata = ModelGateway.structured_output_metadata(DynamicPlanEnvelope, content)
    assert metadata[0]["offset"] == content.index("{}")
    assert metadata[0]["schema_score"] == 0
    executable = next(item for item in metadata if item["action_count"] == 1)
    assert executable["schema_score"] > metadata[0]["schema_score"]


def test_gateway_recovers_one_complete_bare_planning_action() -> None:
    """A provider-shaped action is useful only after normal schema validation."""
    content = json.dumps(
        {
            "tool_name": "ghidra-headless",
            "action_type": "GET_XREFS_TO",
            "target_artifact_id": "artifact-1",
            "reason": "Anchor a resolver candidate in a concrete callsite.",
            "question": "Where is the resolver referenced?",
            "hypothesis": "A recovered Xref can distinguish an active resolver from an unused import.",
            "alternatives": ["The import is unused."],
            "missing_evidence": ["artifact-local callsite"],
            "failure_meaning": "The static target remains unresolved.",
            "evidence_ids": ["evidence-1"],
            "target_selector": {"target": "GetProcAddress"},
            "expected_evidence_kinds": ["xref"],
            "success_condition": "new_targeted_evidence",
        }
    )

    result = ModelGateway._parse_structured_output(DynamicPlanEnvelope, content)

    assert result.objective == "Provider emitted one bounded static action."
    assert len(result.actions) == 1
    assert result.actions[0].target_selector == {"target": "GetProcAddress"}
    assert result.actions[0].evidence_ids == ["evidence-1"]


def test_gateway_accepts_near_valid_deepseek_claim_envelope() -> None:
    """DeepSeek often returns extras, aliases, and leftover reasoning instead of a strict envelope."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "reasoning": "COM host analysis leftover; not part of the contract.",
                                    "claims": [
                                        {
                                            "module": "loader",
                                            "subject": "ComHost.exe",
                                            "action": "injects",
                                            "target": "Resume.exe",
                                            "mechanism": (
                                                "Input -> Transformation/Control -> Output"
                                            ),
                                            "statement": (
                                                "The COM host injects a secondary payload."
                                            ),
                                            "supporting_evidence_ids": ["evidence-1"],
                                            "refuting_evidence_ids": [],
                                            "confidence": "medium",
                                            "status": "INFERRED",
                                            "attack_mapping": {"technique": "T1055"},
                                        }
                                    ],
                                    "limitations": (
                                        "Consumer of the injected buffer remains UNKNOWN."
                                    ),
                                }
                            )
                        }
                    }
                ],
                "usage": {"prompt_tokens": 40, "completion_tokens": 80},
            },
        )

    gateway = ModelGateway(
        ModelProviderSettings(
            "custom",
            "https://api.deepseek.com",
            "deepseek-v4-pro",
            "secret",
            stream=False,
            supports_json_mode=True,
            disable_reasoning=True,
        ),
        ModelProviderSettings("fallback", "", "", "", enabled=False),
        transport=httpx.MockTransport(handler),
    )
    result = gateway.complete(
        ModelRequest(
            task_id="task-enrich",
            case_id="case-enrich",
            trace_id="trace-enrich",
            module="static_analysis",
            prompt_id="static-analysis-agent",
            prompt_version="1.0.0",
            prompt_sha256="a" * 64,
            messages=({"role": "user", "content": "return JSON"},),
            response_schema=AtomicClaimEnvelope,
            stream=False,
            structured_output=True,
            disable_reasoning=True,
        )
    )

    assert result.attempts[0].status == "SUCCEEDED"
    assert result.parsed.claims[0].object == "Resume.exe"
    assert result.parsed.claims[0].evidence_ids == ["evidence-1"]
    assert result.parsed.claims[0].confidence == "MEDIUM"
    assert result.parsed.claims[0].status == "CANDIDATE"
    assert result.parsed.claims[0].condition == ""
    assert result.parsed.limitations == [
        "Consumer of the injected buffer remains UNKNOWN."
    ]


def test_claim_envelope_keeps_valid_claim_when_a_sibling_is_malformed() -> None:
    """One unusable claim object must not fail an otherwise usable DeepSeek envelope."""
    result = ModelGateway._parse_structured_output(
        AtomicClaimEnvelope,
        json.dumps(
            {
                "claims": [
                    {
                        "module": "loader",
                        "subject": "ComHost.exe",
                        "action": "injects",
                        "object": "Resume.exe",
                        "mechanism": "Input -> Transformation -> Output",
                        "condition": "static evidence only",
                        "statement": "The COM host injects a secondary payload.",
                        "evidence_ids": ["evidence-1"],
                        "confidence": "MEDIUM",
                        "status": "CANDIDATE",
                    },
                    {"module": "loader", "note": "incomplete leftover object"},
                ]
            }
        ),
    )

    assert [item.evidence_ids for item in result.claims] == [["evidence-1"]]


def test_gateway_records_schema_validation_location_without_payload_values() -> None:
    """A true schema miss must fail honestly, without treating it as an HTTP outage."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps({"claims": "not-an-array"})
                        }
                    }
                ]
            },
        )

    gateway = ModelGateway(
        ModelProviderSettings(
            "custom",
            "https://api.deepseek.com",
            "deepseek-v4-pro",
            "secret",
        ),
        ModelProviderSettings("fallback", "", "", "", enabled=False),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ModelUnavailable) as raised:
        gateway.complete(
            ModelRequest(
                task_id="task-schema",
                case_id="case-schema",
                trace_id="trace-schema",
                module="static_analysis",
                prompt_id="static-analysis-agent",
                prompt_version="1.0.0",
                prompt_sha256="b" * 64,
                messages=({"role": "user", "content": "return JSON"},),
                response_schema=AtomicClaimEnvelope,
                stream=False,
                structured_output=True,
            )
        )

    attempt = raised.value.attempts[0]
    assert attempt.error_type == "ValidationError"
    assert attempt.http_status is None
    assert "claims" in (attempt.error_detail or "")
    assert "not-an-array" not in (attempt.error_detail or "")


def test_dynamic_plan_normalizes_null_dependencies_from_compatible_providers() -> None:
    """Optional provider fields may be explicit JSON null without killing a plan."""
    result = ModelGateway._parse_structured_output(
        DynamicPlanEnvelope,
        json.dumps(
            {
                "objective": "follow resolver",
                "actions": [
                    {
                        "target_artifact_id": "artifact-1",
                        "action_type": "GET_XREFS_TO",
                        "reason": "locate resolver callsites",
                        "target_selector": {"target": "GetProcAddress"},
                        "expected_evidence_kinds": ["xref"],
                        "depends_on": None,
                    }
                ],
            }
        ),
    )

    assert result.actions[0].depends_on == []


def _completion(value: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [{"message": {"content": json.dumps({"value": value})}}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 3},
        },
    )


def test_gateway_returns_validated_primary_structured_output() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _completion("primary")

    gateway = ModelGateway(
        ModelProviderSettings("deepseek", "https://primary.invalid/v1", "deep", "secret"),
        ModelProviderSettings("glm", "https://fallback.invalid/v1", "glm", "other"),
        transport=httpx.MockTransport(handler),
    )

    result = gateway.complete(
        ModelRequest(
            task_id="task-1",
            case_id="case-1",
            trace_id="trace-1",
            module="static_triage",
            prompt_id="prompt",
            prompt_version="1",
            prompt_sha256="a" * 64,
            messages=({"role": "system", "content": "return JSON"},),
            response_schema=Answer,
        )
    )

    assert result.parsed == Answer(value="primary")
    assert result.provider == "deepseek"
    assert len(result.attempts) == 1
    assert result.attempts[0].status == "SUCCEEDED"
    assert requests[0].headers["authorization"] == "Bearer secret"
    assert "secret" not in json.dumps(result.audit_view())


def test_disabled_gateway_fails_closed_without_http_request() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _completion("unexpected")

    gateway = ModelGateway(
        ModelProviderSettings("deepseek", "https://primary.invalid/v1", "deep", "secret"),
        ModelProviderSettings("glm", "https://fallback.invalid/v1", "glm", "other"),
        transport=httpx.MockTransport(handler),
        enabled=False,
    )
    with pytest.raises(ModelUnavailable, match="MODEL_CALLS_DISABLED"):
        gateway.complete(
            ModelRequest(
                task_id="task-1",
                case_id="case-1",
                trace_id="trace-1",
                module="planning",
                prompt_id="prompt",
                prompt_version="1",
                prompt_sha256="a" * 64,
                messages=({"role": "user", "content": "return JSON"},),
                response_schema=Answer,
            )
        )
    assert requests == []


def test_qwen_planning_request_forces_compact_json_without_reasoning_stream() -> None:
    """A control-plane plan must reserve its token budget for executable JSON."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _completion("planned")

    gateway = ModelGateway(
        ModelProviderSettings(
            "custom",
            "https://router.invalid/v1",
            "ali/qwen3.7-max",
            "test-secret",
            supports_json_mode=False,
            disable_reasoning=False,
        ),
        ModelProviderSettings("fallback", "", "", ""),
        transport=httpx.MockTransport(handler),
    )

    result = gateway.complete(
        ModelRequest(
            task_id="task-plan",
            case_id="case-plan",
            trace_id="trace-plan",
            module="planning",
            prompt_id="planning",
            prompt_version="1",
            prompt_sha256="b" * 64,
            messages=({"role": "user", "content": "return a bounded plan"},),
            response_schema=Answer,
            structured_output=True,
            disable_reasoning=True,
        )
    )

    assert result.parsed == Answer(value="planned")
    payload = json.loads(requests[0].content)
    assert payload["response_format"] == {"type": "json_object"}
    assert payload["enable_thinking"] is False


def test_gateway_aggregates_openai_sse_and_applies_sampling_options() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        body = (
            'data: {"choices":[{"delta":{"reasoning_content":"internal"}}]}\n\n'
            'data: {"choices":[{"delta":{"content":"{\\"value\\":"}}]}\n\n'
            'data: {"choices":[{"delta":{"content":"\\"streamed\\"}"}}],'
            '"usage":{"prompt_tokens":7,"completion_tokens":4}}\n\n'
            'data: [DONE]\n\n'
        )
        return httpx.Response(
            200,
            content=body.encode("utf-8"),
            headers={"content-type": "text/event-stream"},
        )

    gateway = ModelGateway(
        ModelProviderSettings(
            "qwen",
            "https://router.shengsuanyun.com/api/v1",
            "ali/qwen3.7-max",
            "secret",
            stream=True,
            supports_json_mode=False,
        ),
        ModelProviderSettings("fallback", "", "", ""),
        transport=httpx.MockTransport(handler),
    )
    result = gateway.complete(
        ModelRequest(
            task_id="task-1",
            case_id="case-1",
            trace_id="trace-1",
            module="static_analysis",
            prompt_id="prompt",
            prompt_version="1",
            prompt_sha256="s" * 64,
            messages=({"role": "user", "content": "return JSON"},),
            response_schema=Answer,
            temperature=0.6,
            top_p=0.7,
        )
    )

    payload = json.loads(requests[0].content)
    assert payload["stream"] is True
    assert payload["temperature"] == 0.6
    assert payload["top_p"] == 0.7
    assert "response_format" not in payload
    assert payload["enable_thinking"] is False
    assert result.parsed.value == "streamed"
    assert result.input_tokens == 7
    assert result.output_tokens == 4
    assert b"reasoning_content" in result.raw_response


def _json_gateway(handler: object) -> ModelGateway:
    return ModelGateway(
        ModelProviderSettings(
            "custom",
            "https://api.deepseek.com",
            "deepseek-flash",
            "secret",
            stream=False,
            supports_json_mode=True,
        ),
        ModelProviderSettings("fallback", "", "", ""),
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
    )


def _answer_request() -> ModelRequest:
    return ModelRequest(
        task_id="task-1",
        case_id="case-1",
        trace_id="trace-1",
        module="static_analysis",
        prompt_id="prompt",
        prompt_version="1",
        prompt_sha256="s" * 64,
        messages=({"role": "user", "content": "return JSON"},),
        response_schema=Answer,
        temperature=0.0,
        top_p=1.0,
    )


def test_gateway_parses_a_json_body_that_merely_contains_the_data_token() -> None:
    """MEASURED correctness defect: the stream/JSON discriminator was a bare substring test.

    The check used to be `if "data:" not in text`, so any NON-streaming JSON answer whose text happened to
    contain the characters `data:` was routed into the SSE parser, found no line beginning with `data:`, and
    raised `ValueError: model SSE response contained no events`. The model had answered and the run threw the
    answer away: the report degraded to zero model topics and zero slot proposals
    (`analyst_report_unavailable: MODEL_PROVIDERS_UNAVAILABLE`), under a message that blamed streaming.
    Measured on 白象 task `963d416a`.

    CORRECTION, kept here because my first reading of this was wrong and the next reader will have it too: a
    `"data"` KEY does **not** trigger the old predicate. JSON spells it `"data":`, and the closing quote sits
    between `data` and the colon. What actually triggers it is the token appearing inside a string VALUE -
    a `data:` URI, a quoted sample string, a URL, or prose. `test_…_data_uri` covers that shape directly.

    Because the trigger depends on the reply's incidental content, the failure looked like run-to-run noise
    rather than a parser bug.
    """
    body_text = json.dumps(
        {
            "choices": [
                {
                    "message": {
                        # The model quoting a recovered sample string that itself contains `data:`.
                        "content": '{"value":"ok","evidence":"the record was embedded as data:text/plain"}'
                    }
                }
            ],
            "usage": {"prompt_tokens": 11, "completion_tokens": 3},
        }
    )
    # Can-fail guard: without the old trigger substring this test proves nothing about the old predicate.
    assert "data:" in body_text, "the fixture no longer contains the substring the old predicate keyed on"

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=body_text.encode("utf-8"),
            headers={"content-type": "application/json"},
        )

    result = _json_gateway(handler).complete(_answer_request())
    assert result.parsed == Answer(value="ok")


def test_a_data_key_alone_is_not_a_stream_trigger() -> None:
    """Pins the correction above: with default separators a `"data"` key cannot produce `data:`.

    This is a fact about JSON, and pinning it stops the wrong explanation from being re-derived (it was my
    own first guess) and stops the guard in the test above from being "fixed" by adding a `data` key.
    """
    body_text = json.dumps({"choices": [{"message": {"content": '{"value":"ok"}'}}], "data": {"n": 1}})
    assert '"data":' in body_text
    assert "data:" not in body_text, (
        "json.dumps now emits `data:` for a `data` key, so the defect described in the test above has a "
        "second trigger and the comment there needs revisiting"
    )


def test_gateway_parses_a_json_body_containing_a_data_uri() -> None:
    """The same defect, reached through a string value rather than a key.

    A payload can legitimately quote a `data:` URI (or any text containing `data:`). That is still one JSON
    document, and reading it as a stream threw the answer away.
    """
    body_text = json.dumps(
        {
            "choices": [
                {"message": {"content": '{"value":"ok"}'}},
            ],
            "echo": "embedded data:text/html;base64,PHNjcmlwdD4=",
        }
    )
    assert "data:" in body_text

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=body_text.encode("utf-8"),
            headers={"content-type": "application/json"},
        )

    result = _json_gateway(handler).complete(_answer_request())
    assert result.parsed == Answer(value="ok")


def test_a_real_sse_stream_is_still_parsed_as_a_stream() -> None:
    """The narrowing must not break the case it exists for."""

    def handler(_: httpx.Request) -> httpx.Response:
        body = 'data: {"choices":[{"delta":{"content":"{\\"value\\":\\"ok\\"}"}}]}\n\ndata: [DONE]\n\n'
        return httpx.Response(
            200,
            content=body.encode("utf-8"),
            headers={"content-type": "text/event-stream"},
        )

    result = _json_gateway(handler).complete(_answer_request())
    assert result.parsed == Answer(value="ok")


def test_a_json_body_with_a_raw_u2028_before_data_is_not_treated_as_a_stream() -> None:
    """The predicate is `^data:` after a real newline - deliberately NOT `str.splitlines()`.

    MEASURED counterexample to an earlier version of this fix. `str.splitlines()` also breaks on U+000B,
    U+000C, U+001C-1E, U+0085, U+2028 and U+2029, while RFC 8259 forbids only raw U+0000-U+001F inside a JSON
    string - so U+0085/U+2028/U+2029 are LEGAL raw there. A body carrying a raw U+2028 followed by `data:`
    therefore produced a splitlines "line" beginning with `data:`, was misrouted into the SSE parser, and died
    with `invalid JSON in model SSE event`: the same "model answered, answer discarded" outcome the fix exists
    to prevent. The original substring predicate misrouted that body too, so it was never a regression - what
    was wrong was the claim that the two sets cannot overlap, which this version makes true.

    The test asserts the trap is really present (the body is valid JSON and `splitlines()` does expose a
    `data:` line), so it cannot silently stop exercising the case.
    """
    body_text = json.dumps(
        {
            "choices": [{"message": {"content": '{"value":"ok"}'}}],
            # ensure_ascii=False keeps U+2028 RAW, which is the whole point of the fixture.
            "echo": "recorded\u2028data: {'decoded': true}",
        },
        ensure_ascii=False,
    )
    # The trap must be real: valid JSON, and a naive splitlines-based predicate would be fooled by it.
    assert json.loads(body_text)["echo"].startswith("recorded\u2028data: ")
    assert any(line.startswith("data:") for line in body_text.splitlines()), (
        "splitlines() no longer exposes a `data:` line here, so this fixture stopped testing the counterexample"
    )

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=body_text.encode("utf-8"),
            headers={"content-type": "application/json"},
        )

    result = _json_gateway(handler).complete(_answer_request())
    assert result.parsed == Answer(value="ok")


def test_gateway_accepts_sse_without_done_when_json_content_already_arrived() -> None:
    """DeepSeek-style reasoning streams often omit a terminal [DONE] event."""

    def handler(_: httpx.Request) -> httpx.Response:
        body = (
            'data: {"choices":[{"delta":{"content":"{\\"value\\":\\"ok\\"}"}}]}\n\n'
        )
        return httpx.Response(
            200,
            content=body.encode("utf-8"),
            headers={"content-type": "text/event-stream"},
        )

    gateway = ModelGateway(
        ModelProviderSettings(
            "custom",
            "https://api.deepseek.com",
            "deepseek-v4-pro",
            "secret",
            stream=True,
            supports_json_mode=True,
        ),
        ModelProviderSettings("fallback", "", "", ""),
        transport=httpx.MockTransport(handler),
    )
    result = gateway.complete(
        ModelRequest(
            task_id="task-sse",
            case_id="case-sse",
            trace_id="trace-sse",
            module="static_analysis",
            prompt_id="prompt",
            prompt_version="1",
            prompt_sha256="d" * 64,
            messages=({"role": "user", "content": "return JSON"},),
            response_schema=Answer,
        )
    )
    assert result.parsed.value == "ok"


def test_gateway_uses_reasoning_content_when_message_content_is_empty() -> None:
    """Thinking models keep the envelope in reasoning_content, not content."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "reasoning_content": json.dumps({"value": "reasoned"}),
                        }
                    }
                ]
            },
        )

    gateway = ModelGateway(
        ModelProviderSettings(
            "custom",
            "https://api.deepseek.com",
            "deepseek-v4-pro",
            "secret",
            stream=False,
        ),
        ModelProviderSettings("fallback", "", "", ""),
        transport=httpx.MockTransport(handler),
    )
    result = gateway.complete(
        ModelRequest(
            task_id="task-reason",
            case_id="case-reason",
            trace_id="trace-reason",
            module="static_analysis",
            prompt_id="prompt",
            prompt_version="1",
            prompt_sha256="e" * 64,
            messages=({"role": "user", "content": "return JSON"},),
            response_schema=Answer,
            stream=False,
        )
    )
    assert result.parsed.value == "reasoned"


def test_structured_analysis_turn_disables_stream_even_if_provider_streams() -> None:
    """Workbench 模型 is one route; analysis enrichment cannot inherit chat SSE."""
    payloads: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payloads.append(json.loads(request.content))
        return _completion("compact")

    gateway = ModelGateway(
        ModelProviderSettings(
            "custom",
            "https://api.deepseek.com",
            "deepseek-v4-pro",
            "secret",
            stream=True,
            supports_json_mode=True,
        ),
        ModelProviderSettings("fallback", "", "", ""),
        transport=httpx.MockTransport(handler),
    )
    result = gateway.complete(
        ModelRequest(
            task_id="task-enrich",
            case_id="case-enrich",
            trace_id="trace-enrich",
            module="static_analysis",
            prompt_id="prompt",
            prompt_version="1",
            prompt_sha256="f" * 64,
            messages=({"role": "user", "content": "return JSON"},),
            response_schema=Answer,
            stream=False,
            structured_output=True,
        )
    )
    assert result.parsed.value == "compact"
    assert payloads[0]["stream"] is False
    assert payloads[0]["response_format"] == {"type": "json_object"}


def test_gateway_retries_openai_compatible_route_without_optional_parameters() -> None:
    """Gateways that reject vendor extensions still receive a valid JSON turn."""
    payloads: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        payloads.append(payload)
        if len(payloads) == 1:
            return httpx.Response(
                400,
                json={
                    "error": {
                        "type": "invalid_request_error",
                        "message": "response_format is not supported",
                    }
                },
            )
        return _completion("compat")

    gateway = ModelGateway(
        ModelProviderSettings(
            "custom",
            "https://router.invalid/api/v1",
            "ali/qwen3.7-max",
            "secret",
            supports_json_mode=True,
            disable_reasoning=True,
        ),
        ModelProviderSettings("fallback", "", "", ""),
        transport=httpx.MockTransport(handler),
    )
    result = gateway.complete(
        ModelRequest(
            task_id="task-compat",
            case_id="case-compat",
            trace_id="trace-compat",
            module="loader",
            prompt_id="prompt",
            prompt_version="1",
            prompt_sha256="c" * 64,
            messages=({"role": "user", "content": "return JSON"},),
            response_schema=Answer,
        )
    )
    assert result.parsed.value == "compat"
    assert len(payloads) == 2
    assert "response_format" in payloads[0]
    assert "response_format" not in payloads[1]
    assert "enable_thinking" not in payloads[1]
    assert [attempt.status for attempt in result.attempts] == ["FAILED", "SUCCEEDED"]


def test_gateway_rejects_truncated_sse_without_done_marker() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b'data: {"choices":[{"delta":{"content":"{\\"value\\":\\"partial"}}]}\n\n',
            headers={"content-type": "text/event-stream"},
        )

    gateway = ModelGateway(
        ModelProviderSettings("qwen", "https://model.invalid/v1", "qwen", "secret", stream=True),
        ModelProviderSettings("fallback", "", "", ""),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ModelUnavailable) as raised:
        gateway.complete(
            ModelRequest(
                task_id="task-1",
                case_id="case-1",
                trace_id="trace-1",
                module="static_analysis",
                prompt_id="prompt",
                prompt_version="1",
                prompt_sha256="t" * 64,
                messages=({"role": "user", "content": "return JSON"},),
                response_schema=Answer,
            )
        )
    assert raised.value.attempts[0].error_type == "ValueError"


def test_gateway_falls_back_after_primary_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "primary.invalid":
            return httpx.Response(503, json={"error": "unavailable"})
        return _completion("fallback")

    gateway = ModelGateway(
        ModelProviderSettings("claude", "https://primary.invalid/v1", "sonnet", "secret"),
        ModelProviderSettings("qwen", "https://fallback.invalid/v1", "qwen", "other"),
        transport=httpx.MockTransport(handler),
    )

    result = gateway.complete(
        ModelRequest(
            task_id="task-1",
            case_id="case-1",
            trace_id="trace-1",
            module="loader",
            prompt_id="prompt",
            prompt_version="1",
            prompt_sha256="b" * 64,
            messages=({"role": "system", "content": "return JSON"},),
            response_schema=Answer,
        )
    )

    assert result.parsed.value == "fallback"
    assert result.provider == "qwen"
    assert [item.status for item in result.attempts] == ["FAILED", "SUCCEEDED"]
    assert result.fallback_reason == "primary_failed"


def test_gateway_retries_transient_timeout_before_fallback() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ReadTimeout("provider timed out")
        return _completion("retried")

    gateway = ModelGateway(
        ModelProviderSettings("deepseek", "https://primary.invalid/v1", "deep", "secret"),
        ModelProviderSettings("fallback", "", "", ""),
        transport=httpx.MockTransport(handler),
    )
    result = gateway.complete(
        ModelRequest(
            task_id="task-1",
            case_id="case-1",
            trace_id="trace-1",
            module="static_analysis",
            prompt_id="prompt",
            prompt_version="1",
            prompt_sha256="r" * 64,
            messages=({"role": "system", "content": "return JSON"},),
            response_schema=Answer,
        )
    )

    assert result.parsed.value == "retried"
    assert calls == 2
    assert [item.status for item in result.attempts] == ["FAILED", "SUCCEEDED"]


def test_gateway_records_redacted_http_diagnostics() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={
                "error": {
                    "type": "invalid_request_error",
                    "code": "bad_request",
                    "message": "api_key=sk-secret must contain json",
                }
            },
        )

    gateway = ModelGateway(
        ModelProviderSettings("deepseek", "https://primary.invalid/v1", "deep", "secret"),
        ModelProviderSettings("fallback", "", "", ""),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ModelUnavailable) as raised:
        gateway.complete(
            ModelRequest(
                task_id="task-1",
                case_id="case-1",
                trace_id="trace-1",
                module="loader",
                prompt_id="prompt",
                prompt_version="1",
                prompt_sha256="f" * 64,
                messages=({"role": "system", "content": "return json"},),
                response_schema=Answer,
            )
        )

    attempt = raised.value.attempts[0]
    assert attempt.http_status == 400
    assert attempt.endpoint_path == "/v1/chat/completions"
    assert "<redacted>" in (attempt.error_detail or "")
    assert "sk-secret" not in json.dumps(attempt.__dict__)


def test_gateway_preserves_safe_non_json_provider_diagnostic() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            402,
            content=b"payment required: balance exhausted",
            headers={"content-type": "text/plain"},
        )

    gateway = ModelGateway(
        ModelProviderSettings("custom", "https://router.invalid/v1", "model", "secret"),
        ModelProviderSettings("fallback", "", "", ""),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ModelUnavailable) as raised:
        gateway.complete(
            ModelRequest(
                task_id="task-402",
                case_id="case-402",
                trace_id="trace-402",
                module="loader",
                prompt_id="prompt",
                prompt_version="1",
                prompt_sha256="p" * 64,
                messages=({"role": "user", "content": "return JSON"},),
                response_schema=Answer,
            )
        )
    attempt = raised.value.attempts[0]
    assert attempt.http_status == 402
    assert "balance exhausted" in (attempt.error_detail or "")


def test_gateway_preserves_streaming_non_json_provider_diagnostic() -> None:
    """Streaming transports must retain the body before raising on 4xx."""

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            402,
            stream=httpx.ByteStream(b"payment required: balance exhausted"),
            headers={"content-type": "text/plain"},
        )

    gateway = ModelGateway(
        ModelProviderSettings("custom", "https://router.invalid/v1", "model", "secret"),
        ModelProviderSettings("fallback", "", "", ""),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ModelUnavailable) as raised:
        gateway.complete(
            ModelRequest(
                task_id="task-stream-402",
                case_id="case-stream-402",
                trace_id="trace-stream-402",
                module="planning",
                prompt_id="prompt",
                prompt_version="1",
                prompt_sha256="p" * 64,
                messages=({"role": "user", "content": "return JSON"},),
                response_schema=Answer,
            )
        )

    attempt = raised.value.attempts[0]
    assert attempt.http_status == 402
    assert "balance exhausted" in (attempt.error_detail or "")


def test_gateway_accepts_schema_valid_json_with_trailing_text() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"content": '{"value":"ok"}\nAdditional context.'}}
                ]
            },
        )

    gateway = ModelGateway(
        ModelProviderSettings("deepseek", "https://primary.invalid/v1", "deep", "secret"),
        ModelProviderSettings("fallback", "", "", ""),
        transport=httpx.MockTransport(handler),
    )
    result = gateway.complete(
        ModelRequest(
            task_id="task-1",
            case_id="case-1",
            trace_id="trace-1",
            module="loader",
            prompt_id="prompt",
            prompt_version="1",
            prompt_sha256="f" * 64,
            messages=({"role": "system", "content": "return json"},),
            response_schema=Answer,
        )
    )
    assert result.parsed.value == "ok"


def test_gateway_accepts_proxy_suffix_after_json_response_body() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=(
                b'{"choices":[{"message":{"content":"{\\"value\\":\\"ok\\"}"}}]}'
                b"\nproxy-diagnostic"
            ),
        )

    gateway = ModelGateway(
        ModelProviderSettings("deepseek", "https://primary.invalid/v1", "deep", "secret"),
        ModelProviderSettings("fallback", "", "", ""),
        transport=httpx.MockTransport(handler),
    )
    result = gateway.complete(
        ModelRequest(
            task_id="task-1",
            case_id="case-1",
            trace_id="trace-1",
            module="loader",
            prompt_id="prompt",
            prompt_version="1",
            prompt_sha256="s" * 64,
            messages=({"role": "system", "content": "return JSON"},),
            response_schema=Answer,
        )
    )
    assert result.parsed.value == "ok"


def test_gateway_adapts_native_anthropic_messages() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": json.dumps({"value": "claude"})}],
                "usage": {"input_tokens": 9, "output_tokens": 2},
            },
        )

    gateway = ModelGateway(
        ModelProviderSettings(
            "anthropic",
            "https://api.anthropic.invalid/v1",
            "claude-sonnet",
            "secret",
            api_style="anthropic",
        ),
        ModelProviderSettings("fallback", "", "", ""),
        transport=httpx.MockTransport(handler),
    )

    result = gateway.complete(
        ModelRequest(
            task_id="task-1",
            case_id="case-1",
            trace_id="trace-1",
            module="loader",
            prompt_id="prompt",
            prompt_version="1",
            prompt_sha256="c" * 64,
            messages=(
                {"role": "system", "content": "return JSON"},
                {"role": "user", "content": "analyze bounded evidence"},
            ),
            response_schema=Answer,
        )
    )

    assert result.parsed.value == "claude"
    assert requests[0].url.path == "/v1/messages"
    assert requests[0].headers["x-api-key"] == "secret"
    assert "authorization" not in requests[0].headers


def test_gateway_reports_unconfigured_routes_as_failed_attempts() -> None:
    gateway = ModelGateway(
        ModelProviderSettings("primary", "", "", ""),
        ModelProviderSettings("fallback", "", "", ""),
    )

    with pytest.raises(ModelUnavailable) as raised:
        gateway.complete(
            ModelRequest(
                task_id="task-1",
                case_id="case-1",
                trace_id="trace-1",
                module="loader",
                prompt_id="prompt",
                prompt_version="1",
                prompt_sha256="d" * 64,
                messages=({"role": "system", "content": "return JSON"},),
                response_schema=Answer,
            )
        )

    assert [item.error_type for item in raised.value.attempts] == [
        "ProviderNotConfigured",
        "ProviderNotConfigured",
    ]


def test_gateway_does_not_use_empty_unused_slots_as_a_product_model() -> None:
    gateway = ModelGateway(
        ModelProviderSettings("", "", "", "", enabled=True),
        ModelProviderSettings("", "", "", "", enabled=False),
    )
    with pytest.raises(ModelUnavailable, match="MODEL_NOT_CONFIGURED") as raised:
        gateway.complete(
            ModelRequest(
                task_id="task-1",
                case_id="case-1",
                trace_id="trace-1",
                module="loader",
                prompt_id="prompt",
                prompt_version="1",
                prompt_sha256="d" * 64,
                messages=({"role": "system", "content": "return JSON"},),
                response_schema=Answer,
            )
        )
    assert raised.value.attempts == ()


def test_gateway_does_not_retry_an_identical_fallback_route() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(401, json={"error": "invalid key"})

    route = ModelProviderSettings("ali", "https://router.invalid/v1", "qwen", "secret")
    gateway = ModelGateway(route, route, transport=httpx.MockTransport(handler))
    with pytest.raises(ModelUnavailable) as raised:
        gateway.complete(
            ModelRequest(
                task_id="task-1", case_id="case-1", trace_id="trace-1", module="loader",
                prompt_id="prompt", prompt_version="1", prompt_sha256="x" * 64,
                messages=({"role": "user", "content": "return JSON"},), response_schema=Answer,
            )
        )
    assert calls == 1
    assert len(raised.value.attempts) == 1


def test_gateway_tries_same_endpoint_fallback_when_credentials_differ() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion("fallback") if calls == 2 else httpx.Response(402, json={"error": "balance"})

    primary = ModelProviderSettings("ali", "https://router.invalid/v1", "qwen", "primary-key")
    fallback = ModelProviderSettings("ali", "https://router.invalid/v1", "qwen", "fallback-key")
    gateway = ModelGateway(primary, fallback, transport=httpx.MockTransport(handler))
    result = gateway.complete(
        ModelRequest(
            task_id="task-1", case_id="case-1", trace_id="trace-1", module="loader",
            prompt_id="prompt", prompt_version="1", prompt_sha256="x" * 64,
            messages=({"role": "user", "content": "return JSON"},), response_schema=Answer,
        )
    )
    assert result.parsed.value == "fallback"
    assert result.provider == "ali"
    assert result.fallback_reason == "primary_failed"
    assert calls == 2
    assert [item.http_status for item in result.attempts] == [402, None]


def test_gateway_does_not_skip_enabled_fallback_when_primary_slot_disabled() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion("fallback")

    primary = ModelProviderSettings("ali", "https://router.invalid/v1", "qwen", "", enabled=False)
    fallback = ModelProviderSettings("ali", "https://router.invalid/v1", "qwen", "fallback-key")
    gateway = ModelGateway(primary, fallback, transport=httpx.MockTransport(handler))
    result = gateway.complete(
        ModelRequest(
            task_id="task-1", case_id="case-1", trace_id="trace-1", module="loader",
            prompt_id="prompt", prompt_version="1", prompt_sha256="x" * 64,
            messages=({"role": "user", "content": "return JSON"},), response_schema=Answer,
        )
    )
    assert result.parsed.value == "fallback"
    assert result.fallback_reason == "primary_not_configured"
    assert calls == 1


@pytest.mark.parametrize(
    ("provider", "api_style", "path", "auth_header"),
    [
        ("gpt", "openai", "/v1/chat/completions", "authorization"),
        ("claude", "anthropic", "/v1/messages", "x-api-key"),
        ("qwen", "openai-compatible", "/v1/chat/completions", "authorization"),
        ("kimi", "openai", "/v1/chat/completions", "authorization"),
        ("glm", "openai", "/v1/chat/completions", "authorization"),
    ],
)
def test_five_model_families_share_a_versioned_gateway_contract(
    provider: str, api_style: str, path: str, auth_header: str
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if provider == "claude":
            return httpx.Response(
                200,
                json={"content": [{"type": "text", "text": '{"value":"ok"}'}]},
            )
        return _completion("ok")

    settings = ModelProviderSettings(
        provider,
        "https://model.invalid/v1",
        f"{provider}-model",
        "test-secret",
        api_style=api_style,
    )
    contract = provider_contract(settings)
    assert contract["endpoint_path"] in {"/chat/completions", "/messages"}
    gateway = ModelGateway(settings, ModelProviderSettings("fallback", "", "", ""), transport=httpx.MockTransport(handler))
    result = gateway.complete(
        ModelRequest(
            task_id="task-1",
            case_id="case-1",
            trace_id="trace-1",
            module="loader",
            prompt_id="prompt",
            prompt_version="1",
            prompt_sha256="e" * 64,
            messages=(
                {"role": "system", "content": "return JSON"},
                {"role": "user", "content": "bounded"},
            ),
            response_schema=Answer,
        )
    )
    assert result.parsed.value == "ok"
    assert seen[0].url.path == path
    assert auth_header in seen[0].headers
    assert "test-secret" not in json.dumps(result.audit_view())


def test_supported_provider_contracts_are_explicit_and_credential_free() -> None:
    contracts = supported_provider_contracts()
    assert set(contracts) == {"gpt", "claude", "qwen", "kimi", "glm"}
    assert contracts["claude"]["auth_header"] == "x-api-key"
    assert contracts["gpt"]["endpoint_path"] == "/chat/completions"
    assert all(item["structured_output"] == "json_object" for item in contracts.values())
    assert all("api_key" not in json.dumps(item) for item in contracts.values())
