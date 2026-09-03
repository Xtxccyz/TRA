from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from dataclasses import replace
from typing import Any, Generic, Literal, TypeVar
from uuid import uuid4

import httpx
from pydantic import BaseModel, Field

from threat_report_agent.config import ModelProviderSettings


T = TypeVar("T", bound=BaseModel)


SUPPORTED_MODEL_FAMILIES = frozenset({"gpt", "claude", "qwen", "kimi", "glm"})
MODEL_PROVIDER_CONTRACTS: dict[str, dict[str, str]] = {
    "gpt": {
        "default_base_url": "https://api.openai.com/v1",
        "auth_header": "Authorization",
        "protocol": "openai-chat-completions-v1",
    },
    "claude": {
        "default_base_url": "https://api.anthropic.com/v1",
        "auth_header": "x-api-key",
        "protocol": "anthropic-messages-v1",
    },
    "qwen": {
        "default_base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "auth_header": "Authorization",
        "protocol": "openai-chat-completions-v1",
    },
    "kimi": {
        "default_base_url": "https://api.moonshot.cn/v1",
        "auth_header": "Authorization",
        "protocol": "openai-chat-completions-v1",
    },
    "glm": {
        "default_base_url": "https://open.bigmodel.cn/api/paas/v4",
        "auth_header": "Authorization",
        "protocol": "openai-chat-completions-v1",
    },
}
_MODEL_FAMILY_ALIASES = {
    "openai": "gpt",
    "gpt-4": "gpt",
    "anthropic": "claude",
    "moonshot": "kimi",
    "zhipu": "glm",
    "chatglm": "glm",
}


def model_provider_family(provider: ModelProviderSettings) -> str:
    """Return a stable audit family without restricting custom OpenAI-compatible providers."""
    name = provider.provider.strip().lower()
    return _MODEL_FAMILY_ALIASES.get(name, name if name in SUPPORTED_MODEL_FAMILIES else "custom")


def model_protocol(provider: ModelProviderSettings) -> str:
    style = provider.api_style.strip().lower()
    if style in {"anthropic", "messages"} or model_provider_family(provider) == "claude":
        return "anthropic-messages-v1"
    if style in {"openai", "openai-compatible", "chat-completions"}:
        return "openai-chat-completions-v1"
    raise ValueError(f"unsupported model provider API style: {provider.api_style}")


def provider_contract(provider: ModelProviderSettings) -> dict[str, str]:
    """Describe the offline-verifiable contract used by the unified gateway."""
    protocol = model_protocol(provider)
    family = model_provider_family(provider)
    defaults = MODEL_PROVIDER_CONTRACTS.get(family, {})
    return {
        "family": family,
        "protocol": protocol,
        "endpoint_path": "/messages" if protocol.startswith("anthropic") else "/chat/completions",
        "auth_header": "x-api-key" if protocol.startswith("anthropic") else "Authorization",
        "default_base_url": defaults.get("default_base_url", ""),
        "structured_output": "json_object",
    }


def supported_provider_contracts() -> dict[str, dict[str, str]]:
    """Return credential-free contracts for all supported model families."""
    return {
        family: {
            "family": family,
            "protocol": contract["protocol"],
            "endpoint_path": "/messages"
            if contract["protocol"].startswith("anthropic")
            else "/chat/completions",
            "auth_header": contract["auth_header"],
            "default_base_url": contract["default_base_url"],
            "structured_output": "json_object",
        }
        for family, contract in MODEL_PROVIDER_CONTRACTS.items()
    }


@dataclass(frozen=True)
class ModelRequest(Generic[T]):
    task_id: str
    case_id: str
    trace_id: str
    module: str
    prompt_id: str
    prompt_version: str
    prompt_sha256: str
    messages: tuple[dict[str, str], ...]
    response_schema: type[T]
    timeout_s: float = 60.0
    temperature: float | None = None
    top_p: float | None = None
    stream: bool | None = None
    structured_output: bool | None = None
    disable_reasoning: bool | None = None
    max_tokens: int = 4096


@dataclass(frozen=True)
class ModelAttempt:
    provider: str
    model: str
    status: str
    error_type: str | None
    latency_ms: int
    request_sha256: str
    response_sha256: str | None
    input_tokens: int | None = None
    output_tokens: int | None = None
    http_status: int | None = None
    endpoint_path: str | None = None
    error_detail: str | None = None


@dataclass(frozen=True)
class ModelResponse(Generic[T]):
    parsed: T
    model_call_id: str
    provider: str
    model: str
    attempts: tuple[ModelAttempt, ...]
    fallback_reason: str | None
    request_sha256: str
    response_sha256: str
    latency_ms: int
    input_tokens: int | None
    output_tokens: int | None
    raw_response: bytes

    def audit_view(self) -> dict[str, object]:
        return {
            "model_call_id": self.model_call_id,
            "provider": self.provider,
            "model": self.model,
            "attempts": [attempt.__dict__ for attempt in self.attempts],
            "fallback_reason": self.fallback_reason,
            "request_sha256": self.request_sha256,
            "response_sha256": self.response_sha256,
            "latency_ms": self.latency_ms,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
        }


class ModelUnavailable(RuntimeError):
    def __init__(self, message: str, attempts: tuple[ModelAttempt, ...]) -> None:
        super().__init__(message)
        self.attempts = attempts


class AtomicClaimDraft(BaseModel):
    module: str
    subject: str
    action: str
    object: str
    mechanism: str
    condition: str
    statement: str
    evidence_ids: list[str]
    confidence: Literal["LOW", "MEDIUM", "HIGH"] = "MEDIUM"
    status: Literal["CANDIDATE"] = "CANDIDATE"


class AtomicClaimEnvelope(BaseModel):
    claims: list[AtomicClaimDraft]
    limitations: list[str] = []


class DynamicPlanAction(BaseModel):
    """A model proposal; it is never an execution authorization by itself."""

    # Explicit provenance for effectiveness metrics.  The service may mark a
    # generated fallback separately, but a model response is always recorded
    # as ``model`` and never receives credit merely for being accepted.
    origin: Literal["model", "deterministic_fallback"] = "model"

    # Investigation actions are resolved through the closed Action Catalog and
    # may omit a physical tool.  The service assigns the artifact-compatible
    # read-only static tool before Policy validation.
    tool_name: str = ""
    action_type: str | None = None
    target_artifact_id: str
    priority: int = 50
    reason: str
    # Tool-level baseline scheduling may be evidence-light. A focused
    # investigation Action is validated by the service to require these fields.
    evidence_ids: list[str] = Field(default_factory=list, max_length=32)
    target_selector: dict[str, str | int] = Field(default_factory=dict)
    expected_evidence: list[str] = Field(default_factory=list, max_length=32)
    expected_evidence_kinds: list[str] = Field(default_factory=list, max_length=32)
    success_condition: str = "new_targeted_evidence"
    failure_interpretation: Literal["UNKNOWN", "NO_NEW_EVIDENCE", "STATIC_BOUNDARY"] = "UNKNOWN"
    analysis_focus: list[str] = Field(default_factory=list, max_length=32)
    depends_on: list[str] = Field(default_factory=list, max_length=32)
    parameters: dict[str, Any] = Field(default_factory=dict)
    # Control-plane provenance is assigned/verified by the service boundary.
    # Models may omit these fields; they are never trusted as authorization.
    prompt_sha256: str | None = None
    profile_digest: str | None = None
    policy_digest: str | None = None
    action_validation_digest: str | None = None
    action_validation: dict[str, Any] = Field(default_factory=dict)
    # Assigned by the service after a successful planner response.  This is
    # an audit correlation token, never an executor input supplied by a model.
    planner_turn_id: str | None = None


class DynamicPlanEnvelope(BaseModel):
    """Bounded scheduler output returned by a planning model turn.

    ``claims`` is retained as a compatibility field for providers that return the
    claim envelope despite the planning prompt. Such a response is accepted as a
    transport success but produces no model-controlled actions.
    """

    objective: str = ""
    actions: list[DynamicPlanAction] = []
    stop_conditions: list[str] = []
    limitations: list[str] = []
    claims: list[AtomicClaimDraft] | None = None


class ModelGateway:
    """Single synchronous model seam for OpenAI-compatible providers."""

    def __init__(
        self,
        primary: ModelProviderSettings,
        fallback: ModelProviderSettings,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.primary = primary
        self.fallback = fallback
        self._transport = transport

    def complete(self, request: ModelRequest[T]) -> ModelResponse[T]:
        attempts: list[ModelAttempt] = []
        fallback_reason: str | None = None
        seen_routes: set[tuple[str, str, str, str, bool, str]] = set()
        for index, provider in enumerate((self.primary, self.fallback)):
            # Route identity includes a non-reversible credential fingerprint
            # and enabled state.  Two slots may intentionally share an
            # endpoint/model while carrying different credentials; collapsing
            # them would skip the only viable fallback after a 401/402.
            credential_fingerprint = hashlib.sha256(
                provider.api_key.encode("utf-8")
            ).hexdigest()[:16] if provider.api_key else ""
            route_key = (
                provider.provider,
                provider.base_url.rstrip("/"),
                provider.model,
                provider.api_style,
                provider.enabled,
                credential_fingerprint,
            )
            if route_key in seen_routes:
                # A duplicated fallback is a configuration error, not an
                # independent recovery path. Skipping it avoids repeating a
                # credential failure and keeps the audit trail truthful.
                continue
            seen_routes.add(route_key)
            if not provider.configured:
                attempts.append(
                    ModelAttempt(
                        provider.provider,
                        provider.model,
                        "FAILED",
                        "ProviderNotConfigured",
                        0,
                        self._request_hash(request),
                        None,
                    )
                )
                if index == 0:
                    fallback_reason = "primary_not_configured"
                continue
            # A provider timeout is commonly transient (especially for large
            # evidence contexts). Retry the same configured route once before
            # moving to the fallback route. Hard failures such as 401 are not
            # retried because they will not improve without a configuration
            # change.
            retry_count = 0
            call_provider = provider
            while True:
                try:
                    result, attempt, raw_response = self._call(call_provider, request)
                    attempts.append(attempt)
                    return ModelResponse(
                        parsed=result,
                        model_call_id=str(uuid4()),
                        provider=provider.provider,
                        model=provider.model,
                        attempts=tuple(attempts),
                        fallback_reason=fallback_reason,
                        request_sha256=attempt.request_sha256,
                        response_sha256=attempt.response_sha256 or "",
                        latency_ms=attempt.latency_ms,
                        input_tokens=attempt.input_tokens,
                        output_tokens=attempt.output_tokens,
                        raw_response=raw_response,
                    )
                except Exception as exc:
                    attempt = getattr(
                        exc,
                        "attempt",
                        ModelAttempt(
                            provider.provider,
                            provider.model,
                            "FAILED",
                            type(exc).__name__,
                            0,
                            self._request_hash(request),
                            None,
                        ),
                    )
                    attempts.append(attempt)
                    if retry_count < 1 and self._is_retryable(attempt):
                        retry_count += 1
                        if self._is_optional_parameter_failure(attempt):
                            # OpenAI-compatible proxies vary in support for
                            # response_format and vendor reasoning switches.
                            # Retry once with the portable chat-completions
                            # subset; authentication and semantic 4xx errors
                            # remain non-retryable.
                            call_provider = replace(
                                provider,
                                supports_json_mode=False,
                                disable_reasoning=False,
                            )
                        continue
                    if index == 0:
                        fallback_reason = "primary_failed"
                    break
        raise ModelUnavailable("all configured model providers failed", tuple(attempts))

    @staticmethod
    def _is_retryable(attempt: ModelAttempt) -> bool:
        """Return whether a failed call is safe to retry without user input."""
        if attempt.http_status in {408, 425, 429}:
            return True
        if attempt.http_status == 400 and ModelGateway._is_optional_parameter_failure(attempt):
            return True
        return attempt.error_type in {
            "ConnectError",
            "ConnectTimeout",
            "PoolTimeout",
            "ReadTimeout",
            "WriteTimeout",
            "RemoteProtocolError",
            # Structured-output gateways occasionally emit a malformed or
            # truncated answer on one turn. A bounded retry gives the model a
            # chance to satisfy the same contract without changing evidence or
            # authorization scope.
            "JSONDecodeError",
            "ValueError",
        }

    @staticmethod
    def _is_optional_parameter_failure(attempt: ModelAttempt) -> bool:
        """Recognize a provider rejection limited to optional request fields."""
        detail = (attempt.error_detail or "").casefold()
        markers = (
            "response_format",
            "json mode",
            "json_object",
            "enable_thinking",
            "reasoning",
            "unknown parameter",
            "unsupported parameter",
            "not supported",
        )
        return any(marker in detail for marker in markers)

    def _call(
        self, provider: ModelProviderSettings, request: ModelRequest[T]
    ) -> tuple[T, ModelAttempt, bytes]:
        protocol = model_protocol(provider)
        if protocol.startswith("anthropic"):
            return self._call_anthropic(provider, request)
        stream = provider.stream if request.stream is None else request.stream
        supports_json_mode = (
            provider.supports_json_mode
            if request.structured_output is None
            else request.structured_output
        )
        disable_reasoning = (
            provider.disable_reasoning
            if request.disable_reasoning is None
            else request.disable_reasoning
        )
        payload: dict[str, Any] = {
            "model": provider.model,
            "messages": list(request.messages),
            "temperature": provider.temperature if request.temperature is None else request.temperature,
            "max_tokens": request.max_tokens,
            "top_p": provider.top_p if request.top_p is None else request.top_p,
            "stream": stream,
        }
        if supports_json_mode:
            payload["response_format"] = {"type": "json_object"}
        if disable_reasoning and self._is_qwen_reasoning_provider(provider):
            # Qwen-compatible gateways count hidden reasoning against the
            # completion budget. Structured claim turns need a bounded answer;
            # the auditable plan/tool/evidence trace remains available separately.
            payload["enable_thinking"] = False
        request_hash = hashlib.sha256(self._canonical(payload).encode()).hexdigest()
        started = time.monotonic()
        try:
            with httpx.Client(transport=self._transport, timeout=request.timeout_s) as client:
                with client.stream(
                    "POST",
                    self._endpoint(provider, "/chat/completions"),
                    headers={"Authorization": f"Bearer {provider.api_key}"},
                    json=payload,
                ) as response:
                    raw_response = response.read()
                    # Read the body before raising so streaming 4xx/5xx
                    # responses remain diagnosable after the stream closes.
                    response.raise_for_status()
            body = self._parse_stream_or_json_body(raw_response)
            content = body["choices"][0]["message"]["content"]
            parsed = self._parse_structured_output(request.response_schema, content)
            response_hash = hashlib.sha256(raw_response).hexdigest()
            usage = body.get("usage") or {}
            return (
                parsed,
                ModelAttempt(
                    provider.provider,
                    provider.model,
                    "SUCCEEDED",
                    None,
                    int((time.monotonic() - started) * 1000),
                    request_hash,
                    response_hash,
                    int(usage["prompt_tokens"]) if usage.get("prompt_tokens") is not None else None,
                    int(usage["completion_tokens"])
                    if usage.get("completion_tokens") is not None
                    else None,
                ),
                raw_response,
            )
        except Exception as exc:
            http_status, endpoint_path, error_detail = self._failure_metadata(
                exc, provider, "/chat/completions"
            )
            attempt = ModelAttempt(
                provider.provider,
                provider.model,
                "FAILED",
                type(exc).__name__,
                int((time.monotonic() - started) * 1000),
                request_hash,
                None,
                    http_status=http_status,
                    endpoint_path=endpoint_path,
                    error_detail=error_detail,
            )
            setattr(exc, "attempt", attempt)
            raise

    @classmethod
    def _parse_stream_or_json_body(cls, raw_response: bytes) -> dict[str, Any]:
        """Normalize a JSON response or OpenAI SSE stream to one response body.

        The normalized body intentionally keeps only the model content and usage;
        ``raw_response`` remains available to the caller for encrypted audit
        storage, including provider reasoning deltas and diagnostic events.
        """
        text = raw_response.decode("utf-8", errors="replace")
        if "data:" not in text:
            return cls._parse_json_bytes(raw_response)

        content_parts: list[str] = []
        usage: dict[str, Any] = {}
        saw_done = False
        saw_event = False
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if not data:
                continue
            if data == "[DONE]":
                saw_done = True
                break
            try:
                event = json.loads(data)
            except json.JSONDecodeError as exc:
                raise ValueError("invalid JSON in model SSE event") from exc
            if not isinstance(event, dict):
                continue
            saw_event = True
            event_usage = event.get("usage")
            if isinstance(event_usage, dict):
                usage.update(event_usage)
            for choice in event.get("choices") or []:
                if not isinstance(choice, dict):
                    continue
                delta = choice.get("delta") or {}
                if not isinstance(delta, dict):
                    continue
                # ``reasoning_content`` is deliberately not mixed into the
                # structured answer. It remains in encrypted raw audit payload.
                value = delta.get("content")
                if value is None:
                    value = choice.get("text")
                if value is None and isinstance(choice.get("message"), dict):
                    value = choice["message"].get("content")
                content_parts.append(cls._content_text(value))
        if not saw_event:
            raise ValueError("model SSE response contained no events")
        if not saw_done:
            raise ValueError("model SSE response ended before [DONE]")
        return {
            "choices": [{"message": {"content": "".join(content_parts)}}],
            "usage": usage,
        }

    @staticmethod
    def _content_text(value: object) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            parts: list[str] = []
            for item in value:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict) and isinstance(item.get("text"), str):
                    parts.append(item["text"])
            return "".join(parts)
        return ""

    @staticmethod
    def _is_qwen_reasoning_provider(provider: ModelProviderSettings) -> bool:
        marker = f"{provider.provider} {provider.model}".lower()
        return "qwen" in marker or "dashscope" in marker

    @staticmethod
    def _parse_json_bytes(raw_response: bytes) -> dict[str, Any]:
        try:
            body = json.loads(raw_response)
        except json.JSONDecodeError:
            raw = raw_response.decode("utf-8", errors="replace")
            decoder = json.JSONDecoder()
            body = None
            for index, character in enumerate(raw):
                if character != "{":
                    continue
                try:
                    candidate, _ = decoder.raw_decode(raw[index:])
                except json.JSONDecodeError:
                    continue
                if isinstance(candidate, dict):
                    body = candidate
                    break
            if body is None:
                raise
        if not isinstance(body, dict):
            raise TypeError("model provider response must be a JSON object")
        return body

    def _call_anthropic(
        self, provider: ModelProviderSettings, request: ModelRequest[T]
    ) -> tuple[T, ModelAttempt, bytes]:
        system_parts = [
            item["content"] for item in request.messages if item.get("role") == "system"
        ]
        messages = [item for item in request.messages if item.get("role") in {"user", "assistant"}]
        payload: dict[str, Any] = {
            "model": provider.model,
            "messages": messages,
            "temperature": provider.temperature if request.temperature is None else request.temperature,
            "top_p": provider.top_p if request.top_p is None else request.top_p,
            "max_tokens": request.max_tokens,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)
        request_hash = hashlib.sha256(self._canonical(payload).encode()).hexdigest()
        started = time.monotonic()
        try:
            with httpx.Client(transport=self._transport, timeout=request.timeout_s) as client:
                response = client.post(
                    self._endpoint(provider, "/messages"),
                    headers={
                        "x-api-key": provider.api_key,
                        "anthropic-version": "2023-06-01",
                    },
                    json=payload,
                )
            # ``post`` normally buffers the body, but explicitly reading it
            # keeps diagnostics consistent for custom transports and proxies.
            raw_response = response.read()
            response.raise_for_status()
            body = self._parse_response_body(response)
            content = next(
                item["text"]
                for item in body["content"]
                if item.get("type") == "text" and isinstance(item.get("text"), str)
            )
            parsed = self._parse_structured_output(request.response_schema, content)
            response_hash = hashlib.sha256(raw_response).hexdigest()
            usage = body.get("usage") or {}
            return (
                parsed,
                ModelAttempt(
                    provider.provider,
                    provider.model,
                    "SUCCEEDED",
                    None,
                    int((time.monotonic() - started) * 1000),
                    request_hash,
                    response_hash,
                    int(usage["input_tokens"]) if usage.get("input_tokens") is not None else None,
                    int(usage["output_tokens"]) if usage.get("output_tokens") is not None else None,
                ),
                raw_response,
            )
        except Exception as exc:
            http_status, endpoint_path, error_detail = self._failure_metadata(
                exc, provider, "/messages"
            )
            attempt = ModelAttempt(
                provider.provider,
                provider.model,
                "FAILED",
                type(exc).__name__,
                int((time.monotonic() - started) * 1000),
                request_hash,
                None,
                http_status=http_status,
                endpoint_path=endpoint_path,
                error_detail=error_detail,
            )
            setattr(exc, "attempt", attempt)
            raise

    @staticmethod
    def _request_hash(request: ModelRequest[Any]) -> str:
        return hashlib.sha256(
            ModelGateway._canonical(
                {"messages": request.messages, "module": request.module}
        ).encode()
        ).hexdigest()

    @staticmethod
    def _parse_structured_output(schema: type[T], content: object) -> T:
        """Parse the first schema-valid JSON value from a model text response.

        Some OpenAI-compatible models append a short explanation after their JSON
        object even when JSON mode is requested. We accept that transport quirk,
        but only after Pydantic validates the complete structured envelope.
        """
        if not isinstance(content, str):
            raise TypeError("model response content must be text")
        decoder = json.JSONDecoder()
        last_error: Exception | None = None
        for index, character in enumerate(content):
            if character not in "[{":
                continue
            try:
                value, _ = decoder.raw_decode(content[index:])
            except json.JSONDecodeError as exc:
                last_error = exc
                continue
            try:
                return schema.model_validate(value)
            except Exception as exc:  # keep scanning if an earlier brace was prose
                last_error = exc
        if last_error is not None:
            raise last_error
        raise ValueError("model response did not contain a JSON object")

    @staticmethod
    def _parse_response_body(response: httpx.Response) -> dict[str, Any]:
        """Decode a provider body while tolerating harmless proxy suffix text.

        A few OpenAI-compatible gateways append diagnostics after the JSON body
        or omit the JSON content-type. We still require the response to begin
        with a JSON object and let the schema parser validate the model content;
        arbitrary text is never treated as a successful model response.
        """
        try:
            body = response.json()
        except json.JSONDecodeError:
            raw = response.content.decode("utf-8", errors="replace")
            decoder = json.JSONDecoder()
            body = None
            for index, character in enumerate(raw):
                if character != "{":
                    continue
                try:
                    candidate, _ = decoder.raw_decode(raw[index:])
                except json.JSONDecodeError:
                    continue
                if isinstance(candidate, dict):
                    body = candidate
                    break
            if body is None:
                raise
        if not isinstance(body, dict):
            raise TypeError("model provider response must be a JSON object")
        return body

    @staticmethod
    def _canonical(value: object) -> str:
        return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))

    @classmethod
    def _failure_metadata(
        cls,
        exc: Exception,
        provider: ModelProviderSettings,
        suffix: str,
    ) -> tuple[int | None, str, str]:
        """Return safe diagnostics without persisting credentials or payloads."""
        response = getattr(exc, "response", None)
        status = getattr(response, "status_code", None)
        endpoint = cls._endpoint(provider, suffix)
        try:
            endpoint_path = str(httpx.URL(endpoint).path)
        except Exception:
            endpoint_path = suffix

        detail = type(exc).__name__
        if response is not None:
            try:
                body = response.json()
            except Exception:
                body = None
            if isinstance(body, dict):
                error = body.get("error")
                if isinstance(error, dict):
                    parts = [
                        str(error[key])
                        for key in ("type", "code", "message")
                        if error.get(key) is not None
                    ]
                    if parts:
                        detail = ": ".join(parts)
                elif isinstance(error, str):
                    detail = error
                elif isinstance(body.get("message"), str):
                    detail = str(body["message"])
                else:
                    detail = "provider returned a structured error"
            else:
                raw_detail = ""
                try:
                    try:
                        raw_bytes = response.content
                    except httpx.ResponseNotRead:
                        raw_bytes = response.read()
                    raw_detail = raw_bytes.decode("utf-8", errors="replace").strip()
                except Exception:
                    raw_detail = ""
                # Some billing/auth proxies return text or HTML instead of a
                # JSON error object. Keep a short, redacted fragment so the
                # operator can distinguish balance, endpoint, and policy
                # failures without persisting the response body wholesale.
                detail = raw_detail or "provider returned a non-JSON error"

        # Provider messages occasionally echo credential-shaped values. Keep only
        # a short, redacted diagnostic suitable for the audit record and UI.
        detail = re.sub(r"(?i)bearer\s+[^\s,}]+", "Bearer <redacted>", detail)
        detail = re.sub(
            r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,}]+",
            r"\1=<redacted>",
            detail,
        )
        return (int(status) if isinstance(status, int) else None, endpoint_path, detail[:512])

    @staticmethod
    def _endpoint(provider: ModelProviderSettings, suffix: str) -> str:
        base = provider.base_url.rstrip("/")
        if base.endswith(suffix):
            return base
        return base + suffix
