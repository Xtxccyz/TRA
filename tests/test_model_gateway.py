from __future__ import annotations

import json

import httpx
from pydantic import BaseModel
import pytest

from threat_report_agent.config import ModelProviderSettings
from threat_report_agent.model_gateway import (
    ModelGateway,
    ModelRequest,
    ModelUnavailable,
    provider_contract,
    supported_provider_contracts,
)


class Answer(BaseModel):
    value: str


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
