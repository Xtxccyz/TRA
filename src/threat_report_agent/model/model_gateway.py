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
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

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


def _claim_text(value: object, *, keys: tuple[str, ...] = ("name", "value", "target", "text", "id")) -> str:
    """Coerce a provider field to text without inventing Evidence identifiers."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return ""
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dict):
        for key in keys:
            inner = value.get(key)
            if inner not in (None, ""):
                return str(inner)
    return ""


def _coerce_evidence_ids(value: object) -> list[str]:
    """Accept documented evidence-id aliases without inventing new IDs."""
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]
    if isinstance(value, dict):
        return _coerce_evidence_ids(
            value.get("evidence_ids")
            or value.get("evidence_id")
            or value.get("id")
            or value.get("value")
        )
    if isinstance(value, (list, tuple)):
        ids: list[str] = []
        for item in value:
            if isinstance(item, str):
                stripped = item.strip()
                if stripped:
                    ids.append(stripped)
            elif isinstance(item, dict):
                extracted = _coerce_evidence_ids(
                    item.get("evidence_id") or item.get("id") or item.get("value")
                )
                ids.extend(extracted)
        return list(dict.fromkeys(ids))
    return []


def _coerce_confidence(value: object) -> str:
    """A confidence LABEL, or `UNVERIFIED` when the provider did not supply a usable one.

    MEASURED defect this replaces (third review, standards axis): every unusable input used to be coerced to
    `"MEDIUM"` - a blank, a missing field, and an unparseable value alike. That converts ABSENCE into a
    mid-strength claim, which is the project's first-class error class (`analysis-verification` EC-1): a
    consumer cannot tell "the model said medium" from "the model said nothing", and the second is not
    evidence for the first.

    `UNVERIFIED` is not a new token: `contracts.py` already uses
    `Literal["UNVERIFIED", "LOW", "MEDIUM", "HIGH"] = "UNVERIFIED"` as this repo's way of saying "the provider
    did not tell us", so this reuses the established vocabulary rather than inventing a parallel one.

    The numeric branch is GONE. It mapped `>= 0.8` to HIGH and `>= 0.4` to MEDIUM - two cut points with no
    provenance (G2: a number written into code must state where it came from), applied to a format the product
    never asks for: `prompts/static-analysis-system-v1.md` specifies "`confidence` (LOW, MEDIUM, or HIGH)".
    Rather than replace them with different chosen constants (G1/G4), a value that is not one of the four
    labels is treated as not-a-label.
    """
    if value is None:
        return "UNVERIFIED"
    text = str(value).strip().upper()
    return text if text in {"UNVERIFIED", "LOW", "MEDIUM", "HIGH"} else "UNVERIFIED"


class AtomicClaimDraft(BaseModel):
    """One model-proposed Claim. Extra provider fields are ignored, not fatal.

    Models commonly emit aliases (`target`, `supporting_evidence_ids`) and
    non-CANDIDATE labels. Those quirks are recovered here so enrichment can
    still apply the Evidence-id binding gate. Unknown IDs remain rejected
    after parse; this schema never treats a model label as verification.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    module: str = ""
    subject: str = ""
    action: str = ""
    object: str = ""
    mechanism: str = ""
    condition: str = ""
    statement: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: Literal["UNVERIFIED", "LOW", "MEDIUM", "HIGH"] = "UNVERIFIED"
    status: Literal["CANDIDATE"] = "CANDIDATE"

    @model_validator(mode="before")
    @classmethod
    def _coerce_provider_claim(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        data = dict(value)
        if not _claim_text(data.get("object")):
            data["object"] = _claim_text(
                data.get("target") or data.get("object_name") or data.get("obj")
            )
        else:
            data["object"] = _claim_text(data.get("object"))
        evidence = data.get("evidence_ids")
        if evidence in (None, "", []):
            for key in (
                "supporting_evidence_ids",
                "evidenceIds",
                "cited_evidence_ids",
                "evidence",
            ):
                if data.get(key) not in (None, "", []):
                    evidence = data[key]
                    break
        data["evidence_ids"] = _coerce_evidence_ids(evidence)
        for key in ("module", "subject", "action", "mechanism", "condition", "statement"):
            data[key] = _claim_text(data.get(key))
        data["confidence"] = _coerce_confidence(data.get("confidence"))
        # Enrichment Claims stay CANDIDATE until the verifier accepts them.
        data["status"] = "CANDIDATE"
        return data


class AtomicClaimEnvelope(BaseModel):
    """Structured enrichment output. Near-valid provider JSON is recovered.

    Extra reasoning keys are ignored. A string ``limitations`` value, a bare
    claim object, or one malformed sibling claim must not fail the whole turn.
    Evidence-id binding still happens after parse in the service.
    """

    model_config = ConfigDict(extra="ignore")

    claims: list[AtomicClaimDraft] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _recover_provider_envelope(cls, value: object) -> object:
        if isinstance(value, list):
            value = {"claims": value}
        if not isinstance(value, dict):
            return value
        data = dict(value)
        if "claims" not in data:
            for key in ("output", "result", "data", "envelope"):
                nested = data.get(key)
                if isinstance(nested, dict) and (
                    "claims" in nested or {"subject", "action", "statement"} & set(nested)
                ):
                    recovered = dict(nested)
                    if recovered.get("limitations") in (None, [], "") and data.get(
                        "limitations"
                    ) not in (None, [], ""):
                        recovered["limitations"] = data["limitations"]
                    data = recovered
                    break
                if isinstance(nested, list):
                    data = {**data, "claims": nested}
                    break
        if "claims" not in data:
            identifying = {
                "module",
                "subject",
                "action",
                "statement",
                "evidence_ids",
                "supporting_evidence_ids",
            }
            if identifying.intersection(data):
                data = {
                    "claims": [value],
                    "limitations": data.get("limitations", []),
                }
        limitations = data.get("limitations", [])
        if limitations is None:
            data["limitations"] = []
        elif isinstance(limitations, str):
            stripped = limitations.strip()
            data["limitations"] = [stripped] if stripped else []
        elif isinstance(limitations, list):
            data["limitations"] = [
                str(item) for item in limitations if item not in (None, "")
            ]
        else:
            data["limitations"] = [str(limitations)]
        claims = data.get("claims", [])
        if claims is None:
            claims = []
        elif isinstance(claims, dict):
            claims = [claims]
        if isinstance(claims, list):
            kept: list[object] = []
            for item in claims:
                try:
                    draft = AtomicClaimDraft.model_validate(item)
                except Exception:
                    continue
                if not draft.statement and not draft.subject and not draft.evidence_ids:
                    continue
                kept.append(item)
            data["claims"] = kept
        return data


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
    # A planner must describe the investigation contract, not merely name a
    # tool.  These fields are explanatory only: the service still validates
    # the catalog action, evidence citations and target selector before any
    # read-only static executor sees the proposal.
    question: str = ""
    hypothesis: str = ""
    # The bounds below are applied as a RECORDED TRUNCATION, never as a rejection. They used to be enforced by
    # `max_length=`, which raised `too_long` - and a `ValidationError` is NOT retryable
    # (`ModelGateway._is_retryable` lists transport errors, 408/425/429, an optional-parameter 400, and
    # JSONDecodeError/ValueError; "ValidationError" is absent), so ONE extra list item discarded every claim the
    # model would have contributed for that call, and `service.py` then published
    # "Model enrichment JSON did not match the atomic-claim envelope" - blaming the model for a limit the
    # product chose. MEASURED: 9 `alternatives` -> `REJECTED type=too_long`; 7 fields were capped on this model.
    #
    # PROVENANCE, stated as it actually stands (G2): these numbers (8, 16, 32) are NOT derived from a
    # measurement. They are kept as a payload-size defence - the Temporal payload limit is a measured 2 MiB
    # (plan R8) - but no arithmetic connects them to it. They are therefore recorded here as NOT ESTABLISHED,
    # pending the same measure-then-decide treatment R8 received, rather than left looking authoritative.
    alternatives: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    failure_meaning: str = ""
    # Tool-level baseline scheduling may be evidence-light. A focused
    # investigation Action is validated by the service to require these fields.
    evidence_ids: list[str] = Field(default_factory=list)
    target_selector: dict[str, str | int] = Field(default_factory=dict)
    expected_evidence: list[str] = Field(default_factory=list)
    expected_evidence_kinds: list[str] = Field(default_factory=list)
    success_condition: str = "new_targeted_evidence"
    failure_interpretation: Literal["UNKNOWN", "NO_NEW_EVIDENCE", "STATIC_BOUNDARY"] = "UNKNOWN"
    analysis_focus: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    # What the bounds above removed, as `field:kept/dropped` entries. Present so the truncation is PUBLISHED
    # rather than silent: this project's rule is that a truncated set must state that it is truncated, because
    # every surviving item can be true while an implicit claim of completeness is false (EC-4).
    truncated_fields: list[str] = Field(default_factory=list)
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

    #: Bounds applied by `_truncate_oversized_lists` below, as `field -> kept`. Kept in ONE place so the notice
    #: and the behaviour cannot drift apart (G2/G3).
    _TRUNCATION_BOUNDS: ClassVar[dict[str, int]] = {
        "alternatives": 8,
        "missing_evidence": 16,
        "evidence_ids": 32,
        "expected_evidence": 32,
        "expected_evidence_kinds": 32,
        "analysis_focus": 32,
        "depends_on": 32,
    }

    @model_validator(mode="before")
    @classmethod
    def _truncate_oversized_lists(cls, value: object) -> object:
        """Bound the list fields by TRUNCATING AND RECORDING, never by rejecting the whole answer.

        A provider that returns a valid plan with one item too many must not lose the entire contribution: the
        rejection was non-retryable, so all of its claims were dropped and the published limitation blamed an
        envelope mismatch. Truncation is announced in `truncated_fields` so a consumer can see the set is
        bounded (EC-4) instead of reading a truncated list as complete.
        """
        if not isinstance(value, dict):
            return value
        data = value
        notices: list[str] = []
        for field, bound in cls._TRUNCATION_BOUNDS.items():
            items = data.get(field)
            if isinstance(items, list) and len(items) > bound:
                notices.append(f"{field}:{bound}/{len(items) - bound}")
                if data is value:
                    data = dict(value)
                data[field] = items[:bound]
        if notices:
            existing = data.get("truncated_fields")
            carried = [str(item) for item in existing] if isinstance(existing, list) else []
            data["truncated_fields"] = carried + [item for item in notices if item not in carried]
        return data

    @field_validator("depends_on", mode="before")
    @classmethod
    def _normalize_optional_dependencies(cls, value: object) -> object:
        """Treat a provider's explicit JSON null as no dependency list."""
        return [] if value is None else value


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

    @model_validator(mode="before")
    @classmethod
    def _wrap_complete_bare_action(cls, value: object) -> object:
        """Recover one provider-shaped action without relaxing plan validation.

        Some OpenAI-compatible providers emit a complete action object at the
        top level even when asked for an envelope. Treat that as a one-action
        plan only when it has the two fields that identify an Action proposal.
        ``DynamicPlanAction`` and the service policy gate still validate every
        remaining field, evidence citation, selector and tool before use.
        """
        if not isinstance(value, dict) or "actions" in value:
            return value
        if not {"target_artifact_id", "reason"}.issubset(value):
            return value
        if not value.get("action_type") and not value.get("tool_name"):
            return value
        return {
            "objective": "Provider emitted one bounded static action.",
            "actions": [value],
        }


#: A real SSE data line: `data:` at the start of a line delimited by a raw `\n`.
#:
#: `re.MULTILINE` makes `^` match only after a real newline - deliberately NOT `str.splitlines()`, which also
#: breaks on U+000B, U+000C, U+001C-1E, U+0085, U+2028 and U+2029. RFC 8259 forbids only raw U+0000-U+001F
#: inside a JSON string, so U+0085/U+2028/U+2029 are LEGAL raw there, and a `splitlines()`-based test could be
#: fooled by them (measured; see `_parse_stream_or_json_body`).
_SSE_DATA_LINE_RE = re.compile(r"^data:", re.MULTILINE)


class ModelGateway:
    """Single synchronous model seam for OpenAI-compatible providers."""

    def __init__(
        self,
        primary: ModelProviderSettings,
        fallback: ModelProviderSettings,
        *,
        transport: httpx.BaseTransport | None = None,
        enabled: bool = True,
    ) -> None:
        self.primary = primary
        self.fallback = fallback
        self._transport = transport
        # Service instances pass the deployment-level model permission here.
        # Keeping this guard in the gateway as well prevents a future caller
        # from accidentally reaching an HTTP transport by bypassing a
        # higher-level service check. Direct gateway users retain the historic
        # enabled-by-default behavior.
        self.enabled = bool(enabled)

    def complete(self, request: ModelRequest[T]) -> ModelResponse[T]:
        if not self.enabled:
            raise ModelUnavailable(
                "MODEL_CALLS_DISABLED: model calls are disabled by deployment policy",
                (),
            )
        attempts: list[ModelAttempt] = []
        fallback_reason: str | None = None
        seen_routes: set[tuple[str, str, str, str, bool, str]] = set()
        for index, provider in enumerate((self.primary, self.fallback)):
            if not provider.enabled:
                if index == 0 and provider.has_route:
                    fallback_reason = "primary_not_configured"
                continue
            if not provider.configured and not provider.has_route:
                continue
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
        if not attempts:
            raise ModelUnavailable(
                "MODEL_NOT_CONFIGURED: no user-configured analysis model",
                (),
            )
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

    _JSON_MODE_HINT = (
        "Reply with a single json object that satisfies the required schema."
    )

    @classmethod
    def _ensure_json_mode_instruction(
        cls, messages: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Guarantee the literal word ``json`` is present in the prompt.

        Several OpenAI-compatible providers reject ``response_format:
        {"type": "json_object"}`` unless the prompt itself mentions json, e.g.
        DeepSeek answers HTTP 400 with "Prompt must contain the word 'json' in
        some form to use 'response_format' of type 'json_object'.".

        This product's prompts describe the required schema in prose without
        ever using that literal word, so *every* structured call failed at the
        provider, the retry mis-read the error body, and the deterministic
        fallback silently produced the entire report -- leaving the model with
        zero participation.  Appending one instruction changes nothing about the
        requested schema; it only satisfies the provider's precondition.
        """
        blob = " ".join(
            str(message.get("content") or "")
            for message in messages
            if isinstance(message, dict)
        ).casefold()
        if "json" in blob:
            return messages
        return [*messages, {"role": "user", "content": cls._JSON_MODE_HINT}]

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
            payload["messages"] = self._ensure_json_mode_instruction(
                list(payload["messages"])
            )
            payload["response_format"] = {"type": "json_object"}
        # Bound BEFORE the branches: the Qwen branch below does not set it, so initialising it inside the
        # if/elif/else would leave it unbound on that path and raise NameError at the point of use.
        reason_control_note = ""
        if disable_reasoning and self._is_qwen_reasoning_provider(provider):
            # Qwen-compatible gateways count hidden reasoning against the
            # completion budget. Structured claim turns need a bounded answer;
            # the auditable plan/tool/evidence trace remains available separately.
            payload["enable_thinking"] = False
        elif disable_reasoning:
            # A REQUESTED CONTROL THAT THIS GATEWAY CANNOT HONOUR MUST NOT VANISH SILENTLY.
            #
            # MEASURED, and this is the root cause of a six-round diagnostic detour: the configured route
            # (`custom` / `deepseek-v4-pro`) declares `primary_disable_reasoning = t`, so the overlay requests
            # `disable_reasoning=True` - and this function dropped it on the floor, because the only branch
            # that acts on it is Qwen-specific. The model then answered with its reasoning text in `content`:
            # 13,081 characters starting with "W", no JSON envelope, `fenced=False`, only 4 bracket characters
            # in the whole reply. `response_format={"type":"json_object"}` had been sent and was not honoured.
            #
            # What this branch does NOT do is guess a parameter name. Sending an unsupported field can turn a
            # usable request into a 400, and the operator's intent is already recorded in the configuration.
            # What it does is make the mismatch IMPOSSIBLE TO MISS: the note travels with the attempt, so
            # "reasoning was never disabled" is a fact in the record rather than something to be inferred from
            # a 13,000-character prose reply six rounds later.
            reason_control_note = (
                "disable_reasoning was requested but this gateway only implements it for Qwen-compatible "
                "providers; the request was sent with reasoning ENABLED"
            )
        request_hash = hashlib.sha256(self._canonical(payload).encode()).hexdigest()
        started = time.monotonic()
        # ``httpx`` marks a streamed response consumed after ``iter_bytes``.
        # Retain the bounded raw response in this request scope so an HTTP
        # error can still expose a redacted provider diagnostic to operators.
        raw_response: bytes | None = None
        try:
            with httpx.Client(transport=self._transport, timeout=request.timeout_s) as client:
                with client.stream(
                    "POST",
                    self._endpoint(provider, "/chat/completions"),
                    headers={"Authorization": f"Bearer {provider.api_key}"},
                    json=payload,
                ) as response:
                    raw_response = self._read_with_total_deadline(
                        response,
                        timeout_s=request.timeout_s,
                        started=started,
                    )
                    # Read the body before raising so streaming 4xx/5xx
                    # responses remain diagnosable after the stream closes.
                    response.raise_for_status()
            body = self._parse_stream_or_json_body(raw_response)
            content = self._message_content(body)
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
                exc,
                provider,
                "/chat/completions",
                raw_response=raw_response,
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
    def _read_with_total_deadline(
        response: httpx.Response,
        *,
        timeout_s: float,
        started: float,
    ) -> bytes:
        """Read a provider response without allowing an endless SSE stream.

        ``httpx`` read timeouts apply to an individual socket read.  A model
        provider can therefore keep a request alive indefinitely by emitting
        periodic reasoning or keep-alive events.  Analysis tasks need a wall
        clock bound: a late plan is less valuable than deterministic static
        progress and must not prevent report synthesis.
        """
        chunks: list[bytes] = []
        for chunk in response.iter_bytes():
            if time.monotonic() - started > timeout_s:
                raise httpx.ReadTimeout(
                    f"model response exceeded total deadline of {timeout_s:.1f}s",
                    request=response.request,
                )
            chunks.append(chunk)
        if time.monotonic() - started > timeout_s:
            raise httpx.ReadTimeout(
                f"model response exceeded total deadline of {timeout_s:.1f}s",
                request=response.request,
            )
        return b"".join(chunks)

    @classmethod
    def _parse_stream_or_json_body(cls, raw_response: bytes) -> dict[str, Any]:
        """Normalize a JSON response or OpenAI SSE stream to one response body.

        The normalized body intentionally keeps only the model content and usage;
        ``raw_response`` remains available to the caller for encrypted audit
        storage, including provider reasoning deltas and diagnostic events.
        """
        text = raw_response.decode("utf-8", errors="replace")
        # Discriminate on a line that really begins with `data:`, at a real newline boundary.
        #
        # MEASURED correctness defect this fixes (round 81, 白象 task 963d416a): the previous test was
        # `if "data:" not in text` - a bare substring test. Any perfectly good NON-streaming JSON answer whose
        # text merely contained the characters `data:` (a `data:` URI, a quoted sample string, prose) was
        # routed into the SSE parser, where nothing begins with `data:`, so `saw_event` stayed false and the
        # call raised
        #     ValueError: model SSE response contained no events
        # The model had answered; the run threw the answer away and the report degraded to "no model topics"
        # and zero slot proposals (document key `analyst_report_unavailable: MODEL_PROVIDERS_UNAVAILABLE`).
        # The message blamed streaming and hid the real cause, and because it depended on whether the reply's
        # incidental text happened to contain `data:`, it looked like run-to-run noise.
        #
        # A `"data"` KEY does NOT trigger it: JSON spells that `"data":`, and the closing quote sits between
        # `data` and the colon. This correction is stated here because the first version of this comment
        # asserted the opposite, and `tests/test_model_gateway.py` pins the JSON fact.
        #
        # The test is `^data:` under `re.MULTILINE` - NOT `str.splitlines()`. MEASURED counterexample to an
        # earlier version of this fix that DID use splitlines(): splitlines also breaks on U+000B, U+000C,
        # U+001C-1E, U+0085, U+2028 and U+2029, and RFC 8259 forbids only raw U+0000-U+001F inside a string -
        # so U+0085/U+2028/U+2029 are LEGAL raw inside a JSON string. A JSON body carrying `<U+2028>data: {`
        # therefore produced a splitlines "line" starting with `data:`, was misrouted into the SSE parser and
        # died with `invalid JSON in model SSE event` - the same "model answered, answer discarded" outcome.
        # The original substring predicate misrouted that body too, so it was never a regression; what was
        # wrong was the claim that the two sets cannot overlap. This version is the one that can make that
        # claim: a raw U+000A inside a JSON string is illegal, so no syntactically valid JSON body contains a
        # line beginning with `data:`, while every real SSE stream carries at least one.
        if not _SSE_DATA_LINE_RE.search(text):
            return cls._parse_json_bytes(raw_response)

        content_parts: list[str] = []
        reasoning_parts: list[str] = []
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
                    delta = {}
                message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
                value = delta.get("content")
                if value is None:
                    value = choice.get("text")
                if value is None:
                    value = message.get("content")
                content_parts.append(cls._content_text(value))
                reasoning = delta.get("reasoning_content")
                if reasoning is None:
                    reasoning = message.get("reasoning_content")
                reasoning_parts.append(cls._content_text(reasoning))
        content = "".join(content_parts) or "".join(reasoning_parts)
        if not saw_event:
            raise ValueError("model SSE response contained no events")
        if not saw_done:
            if not content or not cls._contains_complete_json_object(content):
                raise ValueError("model SSE response ended before [DONE]")
        return {
            "choices": [{"message": {"content": content}}],
            "usage": usage,
        }

    @staticmethod
    def _contains_complete_json_object(content: str) -> bool:
        decoder = json.JSONDecoder()
        for index, character in enumerate(content):
            if character != "{":
                continue
            try:
                decoder.raw_decode(content[index:])
            except json.JSONDecodeError:
                continue
            return True
        return False

    @staticmethod
    def _reasoning_budget_exhausted(body: dict[str, Any]) -> str:
        """Describe a completion budget that was entirely consumed by hidden reasoning, or "".

        MEASURED. `deepseek-v4-pro` was asked for a structured envelope with a 2 048-token completion
        budget and returned:

            finish_reason = 'length'
            message.content = ''                                  <- empty string
            usage.completion_tokens = 2048, reasoning_tokens = 2048

        The reasoning stream and the answer share the completion budget, so a budget that is too small for
        the model's thinking leaves nothing for the body. Every downstream symptom then lies about the
        cause: `json.loads("")` raises, the schema validator reports a missing field, `AgentRuntime`
        converts that to MODEL_PROVIDERS_UNAVAILABLE, and the report overlay silently falls back to the
        deterministic renderer - so a model that never answered looks like a model that was never asked.

        Naming the condition here is what makes it diagnosable from the audit record alone. It is returned
        as a detail string rather than raised, because the caller already has a failure path.
        """
        choices = body.get("choices")
        if not isinstance(choices, list) or not choices:
            return ""
        first = choices[0] if isinstance(choices[0], dict) else {}
        finish = str(first.get("finish_reason") or "").casefold()
        message = first.get("message") if isinstance(first.get("message"), dict) else {}
        if ModelGateway._content_text(message.get("content")).strip():
            return ""
        usage = body.get("usage") if isinstance(body.get("usage"), dict) else {}
        completion = usage.get("completion_tokens")
        details = usage.get("completion_tokens_details")
        reasoning = details.get("reasoning_tokens") if isinstance(details, dict) else None
        # A MISSING count is not a count of zero. Defaulting it to 0 made the branch below fire on any
        # `finish_reason=length` body with no usage block and report "0 completion tokens", which is a
        # confident statement about a number nobody sent.
        if completion is None and reasoning is None:
            return ""
        try:
            completion_i = int(completion) if completion is not None else 0
            reasoning_i = int(reasoning) if reasoning is not None else 0
        except (TypeError, ValueError):
            return ""
        if finish == "length" and reasoning_i > 0 and reasoning_i >= completion_i:
            return (
                f"REASONING_BUDGET_EXHAUSTED: all {completion_i} completion tokens were spent on "
                f"reasoning ({reasoning_i} reasoning_tokens, finish_reason=length) and no content was "
                "returned; raise the configured completion budget for this model"
            )
        if finish == "length" and completion_i > 0:
            return (
                f"COMPLETION_BUDGET_EXHAUSTED: finish_reason=length with {completion_i} completion "
                "tokens (reasoning_tokens not reported) and no content returned"
            )
        return ""

    @classmethod
    def _message_content(cls, body: dict[str, Any]) -> str:
        """Return structured-output text from an OpenAI-compatible body."""
        choices = body.get("choices")
        if not isinstance(choices, list) or not choices:
            return ""
        first = choices[0] if isinstance(choices[0], dict) else {}
        message = first.get("message") if isinstance(first.get("message"), dict) else {}
        content = cls._content_text(message.get("content"))
        if content:
            return content
        return cls._content_text(message.get("reasoning_content"))

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
            if time.monotonic() - started > request.timeout_s:
                raise httpx.ReadTimeout(
                    f"model response exceeded total deadline of {request.timeout_s:.1f}s",
                    request=response.request,
                )
            raw_response = response.read()
            if time.monotonic() - started > request.timeout_s:
                raise httpx.ReadTimeout(
                    f"model response exceeded total deadline of {request.timeout_s:.1f}s",
                    request=response.request,
                )
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
                error_detail=(
                    f"{error_detail} | {reason_control_note}" if reason_control_note else error_detail
                ),
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
        """Parse the richest schema-valid JSON value from a model text response.

        Some OpenAI-compatible models append a short explanation after their JSON
        object even when JSON mode is requested. Some also include incidental
        ``{}`` examples before the actual envelope. We accept those transport
        quirks only after Pydantic validates each complete candidate, then select
        the one carrying the most non-default schema information.
        """
        candidates, last_error = ModelGateway._structured_output_candidates(schema, content)
        if candidates:
            return max(candidates, key=lambda item: item[0])[2]
        if isinstance(last_error, json.JSONDecodeError):
            # Nothing parsed as JSON. Report it STRUCTURALLY rather than re-raising the scanner's surviving
            # error: that error is the LAST BRACKET the scan tried, which on a mostly-prose reply is some
            # trailing two-character fragment. MEASURED: two 白象 overlay runs were diagnosed from
            # `Expecting value: line 1 column 2 (char 1)` and the conclusion drawn ("the response does not
            # start with JSON") may not have described the response at all.
            #
            # Structural facts keep this module's stated privacy stance (`structured_output_metadata`
            # deliberately returns no model text) while separating the cases that need different fixes: a
            # fenced reply, a truncated reply, and a reply that is prose.
            stripped = content.lstrip()
            raise ValueError(
                "model response contained no parseable JSON object: "
                f"content_chars={len(content)}, "
                f"first_char={stripped[:1]!r}, "
                f"json_starts={sum(1 for ch in content if ch in '[{')}, "
                f"fenced={'```' in content}"
            ) from last_error
        if last_error is not None:
            # A REAL schema miss: JSON was found, parsed, and had the wrong shape. It keeps its own error, or
            # the caller is told "no JSON" about a response that was perfectly good JSON.
            raise last_error
        raise ValueError("model response did not contain a JSON object")

    #: Envelope field -> a key its ELEMENTS carry. Used to wrap a bare array the model returned instead of
    #: the envelope object. Key-based rather than try-each-field because every envelope model in this
    #: codebase gives its fields defaults, so a list of chapter-shaped objects would ALSO validate as
    #: `slots` (and vice versa) - the shape of the elements is the only honest discriminator.
    #:
    #: The hint for `actions` used to be `("action", "tool")`, which could NEVER match: the check below is
    #: exact membership in a set of element keys, and `DynamicPlanAction` carries `tool_name` / `action_type`
    #: / `target_artifact_id` - neither `"action"` nor `"tool"` is a key. So a bare top-level array of real
    #: plan actions was unrecoverable, while `_wrap_complete_bare_action` handled only a single dict.
    _ARRAY_SHAPE_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("slots", ("slot", "evidence_substring")),
        ("chapters", ("catalog_id", "evidence_anchors")),
        ("actions", ("tool_name", "target_artifact_id", "action_type")),
        ("claims", ("claim", "statement")),
    )

    @staticmethod
    def _wrap_bare_array(schema: type[T], value: object) -> T | None:
        """Wrap a BARE JSON ARRAY into the envelope field its elements fit, or return None.

        MEASURED failure this exists for (task `a0c1f4de`):
            `ValidationError: schema model_type (Input should be a valid dictionary or instance of
             AnalystReportPlanEnvelope)`
        The model returned a top-level ARRAY while the envelope is an object, so a perfectly good JSON value
        was discarded as unparseable. It is the same reply, one bracket shallower.

        Returns None - never raises - so an array that fits nothing still falls through to the previous
        behaviour instead of replacing one failure with another.
        """
        if not isinstance(value, list) or not value:
            return None
        if not all(isinstance(item, dict) for item in value):
            return None
        fields = getattr(schema, "model_fields", {})
        present: set[str] = set()
        for item in value:
            present.update(str(key) for key in item)
        for field_name, hints in ModelGateway._ARRAY_SHAPE_HINTS:
            if field_name not in fields or not any(hint in present for hint in hints):
                continue
            try:
                return schema.model_validate({field_name: value})
            except Exception:  # noqa: BLE001 - try the next shape; None means "unsupported"
                continue
        return None

    @staticmethod
    def structured_output_metadata(schema: type[T], content: object) -> list[dict[str, object]]:
        """Return privacy-safe JSON-candidate metadata for a structured reply.

        This diagnostic deliberately exposes offsets, keys and schema shape only.
        It neither returns model text nor field values, so callers can determine
        whether an empty envelope displaced a usable response without disclosing
        sample data, prompt data or model reasoning.
        """
        candidates, _ = ModelGateway._structured_output_candidates(schema, content)
        return [metadata for _score, metadata, _parsed in candidates]

    @staticmethod
    def _structured_output_candidates(
        schema: type[T], content: object
    ) -> tuple[list[tuple[int, dict[str, object], T]], Exception | None]:
        if not isinstance(content, str):
            raise TypeError("model response content must be text")
        decoder = json.JSONDecoder()
        candidates: list[tuple[int, dict[str, object], T]] = []
        #: Candidates recovered by WRAPPING a bare array. Kept SEPARATE on purpose.
        #:
        #: The pool is resolved with `max(candidates, key=score)` and ties go to the FIRST element, so a
        #: wrapped array that merely scores LOWER than the real envelope is still dangerous once it enters the
        #: same list - and a wrapped array can genuinely outscore it. MEASURED (found by review, reproduced
        #: against `AnalystReportPlanEnvelope`): an incidental example array plus the real envelope scored
        #: 17 vs 6, the example won, and the real chapters were discarded.
        #:
        #: So wrapping never competes: these are used only when NOTHING honestly-shaped validated.
        wrapped: list[tuple[int, dict[str, object], T]] = []
        #: Wrapping is attempted ONLY when the reply itself IS a bare array. Scanning every `[` would let an
        #: incidental example array embedded in a prose reply be wrapped at all.
        #: MEASURED shape this keeps working: the model returned the slots array as the whole reply (ledger BY).
        leading_array = content.lstrip().startswith("[")
        last_error: Exception | None = None
        for index, character in enumerate(content):
            if character not in "[{":
                continue
            try:
                value, _ = decoder.raw_decode(content[index:])
            except json.JSONDecodeError as exc:
                last_error = exc
                continue
            recovered_by_wrapping = False
            try:
                parsed = schema.model_validate(value)
            except Exception as exc:  # keep scanning if an earlier brace was prose
                patched = (
                    ModelGateway._wrap_bare_array(schema, value) if leading_array else None
                )
                if patched is None:
                    last_error = exc
                    continue
                parsed = patched
                recovered_by_wrapping = True
            score = ModelGateway._structured_output_score(parsed)
            keys = sorted(str(key) for key in value) if isinstance(value, dict) else []
            actions = value.get("actions") if isinstance(value, dict) else None
            # A wrapped candidate goes to its OWN pool so it can never displace a real envelope.
            (wrapped if recovered_by_wrapping else candidates).append(
                (
                    score,
                    {
                        "offset": index,
                        "top_level_type": type(value).__name__,
                        "top_level_keys": keys,
                        "action_count": len(actions) if isinstance(actions, list) else 0,
                        "schema_score": score,
                        "recovered_by_wrapping": recovered_by_wrapping,
                    },
                    parsed,
                )
            )
        if wrapped and leading_array:
            # The reply IS an array, so an object parsed from INSIDE it is one of its ELEMENTS, not a
            # separate envelope. Because every envelope model here defaults its fields and ignores extras, an
            # element like `{"slot": "loop"}` VALIDATES as a defaults-only envelope and scores 0 - and a
            # score-0 candidate is non-empty, so `candidates or wrapped` would hand back the empty shell and
            # throw away the correctly-wrapped whole. MEASURED in review: the first version of this fix did
            # exactly that.
            #
            # Dropping zero-score candidates is scoped to this path on purpose: elsewhere a defaults-only
            # envelope may be a legitimate (if useless) parse, and this must not change that.
            candidates = [entry for entry in candidates if entry[0] > 0]
        # `candidates or wrapped`: wrapped entries are consulted only when nothing substantive and
        # honestly-shaped parsed, so they never compete on score with a real envelope.
        return (candidates or wrapped), last_error

    @staticmethod
    def _structured_output_score(value: object) -> int:
        """Score non-default structured content without inspecting raw text."""
        if isinstance(value, BaseModel):
            return ModelGateway._structured_output_score(
                value.model_dump(exclude_defaults=True, exclude_none=True)
            )
        if isinstance(value, dict):
            return sum(
                1 + ModelGateway._structured_output_score(item)
                for item in value.values()
            )
        if isinstance(value, (list, tuple)):
            return sum(1 + ModelGateway._structured_output_score(item) for item in value)
        if value is None or value == "":
            return 0
        return 1

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
        *,
        raw_response: bytes | None = None,
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
        if isinstance(exc, json.JSONDecodeError):
            # The MESSAGE is the diagnostic, and it was being thrown away.
            #
            # MEASURED: two consecutive 白象 overlay runs failed with `JSONDecodeError` and the document
            # recorded only the type name, so they were indistinguishable from each other and from any other
            # parse failure. The message carries the position and a snippet - "Expecting value: line 1
            # column 1" (the model wrapped its JSON in prose) versus "Unterminated string starting at ..."
            # (the answer was cut off at max_tokens). Those two need DIFFERENT fixes, and no other field
            # distinguishes them: `output_tokens` is None on a failed call and `response_storage_key` is NULL,
            # so the raw response is retained nowhere.
            #
            # Bounded on purpose: the snippet is the model's own malformed output, but it is still model
            # text, so a short prefix is enough to locate the break without copying a payload into the
            # document.
            detail = f"{detail}: {str(exc)[:200]}"
        elif isinstance(exc, ValueError) and str(exc).strip():
            # A `ValueError` raised by THIS module carries a message that is the whole diagnostic - e.g. the
            # structural summary produced when no JSON candidate parsed at all. Dropping it left the document
            # recording `"error_detail": "ValueError"`, which is strictly less informative than the
            # `JSONDecodeError` branch above and made earlier runs unreadable for no reason.
            #
            # MEASURED: the run whose entire diagnostic was `ValueError` / `ValueError` - both attempts - was
            # exactly this case. The fix for `JSONDecodeError` was applied one branch too narrowly.
            #
            # Bounded, and only for messages this module authored. `ValidationError` is handled below with
            # field locations and WITHOUT values, which is a deliberate privacy position this must not undo.
            detail = f"{detail}: {str(exc)[:300]}"
        if isinstance(exc, ValidationError):
            parts: list[str] = []
            for error in exc.errors()[:8]:
                loc = ".".join(str(item) for item in error.get("loc", ()))
                err_type = str(error.get("type", "") or "")
                msg = str(error.get("msg", "") or "").split("\n", 1)[0]
                label = ":".join(part for part in (loc, err_type) if part)
                if msg:
                    label = f"{label} ({msg})" if label else msg
                if label:
                    parts.append(label)
            if parts:
                detail = "schema " + "; ".join(parts)
        if response is not None:
            try:
                body = response.json()
            except Exception:
                body = None
            if isinstance(body, dict):
                # Ask the budget question FIRST. A reasoning model that spent its whole completion budget
                # returns HTTP 200 with an empty content string, and every other branch below would report
                # that as a schema or content problem - which sends the operator to the wrong place.
                exhausted = ModelGateway._reasoning_budget_exhausted(body)
                error = body.get("error")
                if exhausted:
                    detail = exhausted
                elif isinstance(error, dict):
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
                    raw_bytes = raw_response
                    if raw_bytes is None:
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
