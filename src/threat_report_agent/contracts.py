from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, ClassVar, Iterable, Literal, Mapping

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator
from dataclasses import dataclass, field
import hashlib
import json
import re
from enum import Enum, StrEnum


class FrozenContract(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class TaskRequestInput(FrozenContract):
    preset_id: str = Field(min_length=1, max_length=120)
    target_breadth: Literal["B0", "B1", "B2", "B3", "B4"]
    target_depth: Literal["D0", "D1", "D2", "D3", "D4", "D5"]
    selected_report_modules: tuple[str, ...]


class SamplePackageInput(FrozenContract):
    source_kind: Literal["file", "zip", "local_folder"]
    display_name: str = Field(min_length=1, max_length=1024)
    submitted_size: int | None = Field(default=None, ge=0)
    content_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    storage_key: str | None = Field(default=None, min_length=1, max_length=512)


class BackgroundContextInput(FrozenContract):
    content: str = ""
    source: str = Field(default="user_supplied", min_length=1, max_length=240)
    observed_at: AwareDatetime = Field(default_factory=lambda: datetime.now(UTC))
    confidence: Literal["UNVERIFIED", "LOW", "MEDIUM", "HIGH"] = "UNVERIFIED"
    human_confirmed: bool = False
    version: str = Field(default="1.0", min_length=1, max_length=80)
    trust_zone: Literal["untrusted_background"] = "untrusted_background"


class KnowledgeSnapshotInput(FrozenContract):
    snapshot_id: str = Field(min_length=1, max_length=160)
    candidate_knowledge_included: Literal[False] = False


class FourChannelInput(FrozenContract):
    task_request: TaskRequestInput
    sample_package: SamplePackageInput
    background_context: BackgroundContextInput
    knowledge_snapshot: KnowledgeSnapshotInput


class ActionProposal(FrozenContract):
    tool_name: str = Field(min_length=1, max_length=120)
    action_type: str | None = Field(default=None, max_length=80)
    target_artifact_id: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=1, max_length=1000)
    expected_evidence: tuple[str, ...]
    cpu_seconds: int = Field(default=60, ge=1)
    memory_mb: int = Field(default=512, ge=64)
    requires_sample_execution: bool = False
    requires_network: bool = False
    investigation_thread_id: str | None = Field(default=None, max_length=120)
    hypothesis_id: str | None = Field(default=None, max_length=120)
    question: str | None = Field(default=None, max_length=1000)
    analysis_focus: tuple[str, ...] = ()
    parameters: dict[str, object] = Field(default_factory=dict)


class InvestigationThread(FrozenContract):
    """Serializable investigation state exposed to the scheduler and report.

    This is deliberately an intermediate language rather than model reasoning:
    it records the question, evidence scope, hypotheses, and bounded actions
    without storing private chain-of-thought.
    """

    id: str = Field(min_length=1, max_length=120)
    artifact_id: str = Field(min_length=1, max_length=120)
    state: Literal[
        "DISCOVERED", "PRIORITIZED", "CONTEXT_READY", "HYPOTHESIZING",
        "INVESTIGATING", "VERIFYING", "MECHANISM_READY", "CLAIM_READY",
        "UNKNOWN", "BLOCKED", "REJECTED", "CONTRADICTED", "CLOSED",
    ] = "DISCOVERED"
    question: str = Field(min_length=1, max_length=1000)
    seed_kind: str = Field(min_length=1, max_length=120)
    evidence_ids: tuple[str, ...] = ()
    hypothesis_ids: tuple[str, ...] = ()
    mechanism_ids: tuple[str, ...] = ()
    action_ids: tuple[str, ...] = ()


class Hypothesis(FrozenContract):
    id: str = Field(min_length=1, max_length=120)
    thread_id: str = Field(min_length=1, max_length=120)
    statement: str = Field(min_length=1, max_length=1200)
    dimension: str = Field(min_length=1, max_length=120)
    evidence_ids: tuple[str, ...] = ()
    confidence: Literal["LOW", "MEDIUM", "HIGH"] = "LOW"
    status: Literal["OPEN", "SUPPORTED", "WEAKENED", "REJECTED", "REFUTED", "UNKNOWN"] = "OPEN"


class Mechanism(FrozenContract):
    """Evidence-backed mechanism projection used by verifiers and reports.

    The legacy ``dimension``/``steps`` fields remain for replay compatibility;
    the typed fields are the Round 10 canonical representation.
    """

    id: str = Field(min_length=1, max_length=120)
    thread_id: str = Field(min_length=1, max_length=120)
    dimension: str = Field(min_length=1, max_length=120)
    steps: tuple[str, ...] = ()
    type: str = Field(default="STATIC_MECHANISM", min_length=1, max_length=160)
    target: str = ""
    inputs: tuple[str, ...] = ()
    transformation_or_control: tuple[str, ...] = ()
    conditions: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    side_effects: tuple[str, ...] = ()
    consumers: tuple[str, ...] = ()
    claim_id: str | None = Field(default=None, max_length=120)
    evidence_ids: tuple[str, ...] = ()
    status: Literal["CONFIRMED", "INFERRED", "UNKNOWN"] = "UNKNOWN"
    limitations: tuple[str, ...] = ()
    verifier: dict[str, object] = Field(default_factory=dict)

    @property
    def completeness_score(self) -> int:
        """Return the deterministic 0-100 completeness score from the plan."""
        weights = (
            (bool(self.target), 10),
            (bool(self.inputs), 15),
            (bool(self.transformation_or_control), 20),
            (bool(self.conditions), 10),
            (bool(self.outputs), 15),
            (bool(self.side_effects), 10),
            (bool(self.consumers), 10),
            (bool(self.evidence_ids), 10),
        )
        return sum(weight for present, weight in weights if present)


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
        for field_name, bound in cls._TRUNCATION_BOUNDS.items():
            items = data.get(field_name)
            if isinstance(items, list) and len(items) > bound:
                notices.append(f"{field_name}:{bound}/{len(items) - bound}")
                if data is value:
                    data = dict(value)
                data[field_name] = items[:bound]
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


@dataclass(frozen=True)
class PackageEntry:
    logical_path: str
    content: bytes
    parent_path: str | None
    discovery: str
    is_container: bool = False
    content_sha256: str | None = None
    storage_key: str | None = None
    stored_size: int | None = None
    detected_type: str | None = None
    mime_type: str | None = None
    type_source: str | None = None

    @property
    def size(self) -> int:
        return self.stored_size if self.stored_size is not None else len(self.content)


# ---------------------------------------------------------------------------------------------------
# P3.5-0 / M-1: the pure investigation-action contract cluster, sunk out of `investigation/investigation.py`
# and `static/evidence_recovery.py` so `emulation/` can reach it without importing an implementation module.
# Every name below is stdlib-only; both old paths re-export each name with `NAME as NAME`, so it is ONE object
# everywhere. `FailureInterpretation` is deliberately ABOVE `ActionSpec`, whose class body evaluates
# `FailureInterpretation.UNKNOWN` as a field default at import time (measured: reversed, it is a NameError).
# ---------------------------------------------------------------------------------------------------


SELECTOR_ALIASES: dict[str, str] = {
    "function_name": "function",
    "name": "function",
    "va": "address",
    "virtual_address": "address",
    "entry_point": "function_entry",
    "len": "length",
    "byte_count": "length",
    "byte_length": "length",
    "arg_index": "argument_index",
}


CATALOG_SELECTOR_KEYS: tuple[str, ...] = (
    "target",
    "api",
    "function",
    "function_entry",
    "entry",
    "rva",
    "address",
    "length",
    "size",
    "offset",
    "file_offset",
    "argument_index",
    "index",
    "callsite",
    "max_instructions",
    "formula",
    "limit",
)


_ACTION_SELECTOR_KEYS = frozenset(
    {"target", "api", "function", "function_entry", "entry", "rva", "address"}
)


_FUNCTION_SELECTOR_KEYS = frozenset({"function", "function_entry", "entry", "rva", "address"})


_FUNCTION_LOCATOR = re.compile(r"^(?:0x[0-9a-f]+|[0-9a-f]{5,}|fun_[0-9a-f]+|sub_[0-9a-f]+)$", re.IGNORECASE)


class ActionType(str, Enum):
    GET_FUNCTION = "GET_FUNCTION"
    GET_CALLERS = "GET_CALLERS"
    GET_CALLEES = "GET_CALLEES"
    GET_XREFS_TO = "GET_XREFS_TO"
    GET_XREFS_FROM = "GET_XREFS_FROM"
    GET_STRINGS_REFERENCED = "GET_STRINGS_REFERENCED"
    GET_DATA_REFERENCES = "GET_DATA_REFERENCES"
    READ_BYTES = "READ_BYTES"
    GET_DECOMPILE = "GET_DECOMPILE"
    GET_PCODE_SLICE = "GET_PCODE_SLICE"
    GET_CFG_SLICE = "GET_CFG_SLICE"
    TRACE_API_ARGUMENT = "TRACE_API_ARGUMENT"
    TRACE_RETURN_VALUE = "TRACE_RETURN_VALUE"
    TRACE_GLOBAL_USAGE = "TRACE_GLOBAL_USAGE"
    CONTROLLED_EMULATE = "CONTROLLED_EMULATE"
    DECODE_CANDIDATE = "DECODE_CANDIDATE"
    EVALUATE_CONSTANT = "EVALUATE_CONSTANT"
    COMPARE_FUNCTION = "COMPARE_FUNCTION"


class InvestigationThreadState(str, Enum):
    DISCOVERED = "DISCOVERED"
    PRIORITIZED = "PRIORITIZED"
    CONTEXT_READY = "CONTEXT_READY"
    HYPOTHESIZING = "HYPOTHESIZING"
    INVESTIGATING = "INVESTIGATING"
    VERIFYING = "VERIFYING"
    MECHANISM_READY = "MECHANISM_READY"
    CLAIM_READY = "CLAIM_READY"
    UNKNOWN = "UNKNOWN"
    BLOCKED = "BLOCKED"
    REJECTED = "REJECTED"
    CONTRADICTED = "CONTRADICTED"
    CLOSED = "CLOSED"


class FailureInterpretation(StrEnum):
    UNKNOWN = "UNKNOWN"
    NO_NEW_EVIDENCE = "NO_NEW_EVIDENCE"
    STATIC_BOUNDARY = "STATIC_BOUNDARY"


def normalize_target_selector(
    selector: Mapping[str, object] | None,
    *,
    allowed_keys: Iterable[str] | None = None,
) -> dict[str, str | int]:
    """Map DSH/model selector aliases and drop unknown keys instead of 422.

    ``function_name`` and ``length`` are the live dialect that burned
    GET_FUNCTION/READ_BYTES turns. Catalog validation still requires at least
    one allowed key after this pass.
    """
    allowed = set(allowed_keys or CATALOG_SELECTOR_KEYS)
    normalized: dict[str, str | int] = {}
    for key, value in dict(selector or {}).items():
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            continue
        if not str(value).strip():
            continue
        mapped = SELECTOR_ALIASES.get(str(key).strip(), str(key).strip())
        if mapped in allowed:
            normalized[mapped] = value
    return normalized


def action_scope_from_plan(plan: Mapping[str, object] | None) -> str:
    """Extract a stable mechanism dimension from non-authoritative plan data.

    The selector remains the only executor authorization input.  This value is
    used solely for queue de-duplication so independent mechanism questions do
    not suppress one another when they share a function/RVA target.
    """
    if not isinstance(plan, Mapping):
        return ""
    for key in ("action_scope", "mechanism_type", "mechanism", "playbook_id"):
        value = plan.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            return str(value).strip().casefold()
    contract = plan.get("deep_investigation_contract")
    if isinstance(contract, Mapping):
        category = contract.get("category")
        if isinstance(category, (str, int)) and str(category).strip():
            return str(category).strip().casefold()
    focus = plan.get("analysis_focus")
    if isinstance(focus, (list, tuple)):
        for value in focus:
            if isinstance(value, (str, int)) and str(value).strip():
                return str(value).strip().casefold()
    return ""


def canonical_token(value: object) -> str:
    return " ".join(str(value).casefold().split())


def _canonical_action_selector(value: Mapping[str, object]) -> dict[str, str]:
    """Normalize selector aliases without merging API and function scopes.

    Historical actions used ``function_entry`` while the deep-mining planner
    intentionally uses ``target`` for the same RVA.  The normal form makes
    those queries dedupe, while an API name stays in a distinct scope so an
    API-oriented query cannot suppress a function-oriented query by accident.
    """
    selector = {
        str(key): item
        for key, item in value.items()
        if str(key) in _ACTION_SELECTOR_KEYS
        and isinstance(item, (str, int))
        and str(item).strip()
    }
    if not selector:
        return {}
    function_key = next((key for key in _FUNCTION_SELECTOR_KEYS if key in selector), None)
    if function_key is not None:
        return {
            "scope": "function",
            "target": canonical_token(selector[function_key]),
        }
    if "api" in selector:
        return {"scope": "api", "target": canonical_token(selector["api"])}
    target = canonical_token(selector["target"])
    scope = (
        "function"
        if _FUNCTION_LOCATOR.fullmatch(target) or target in {"entry", "entrypoint", "main"}
        else "symbol"
    )
    return {"scope": scope, "target": target}


def canonical_action_key(action_type: str, parameters: Mapping[str, object]) -> str:
    """Return a target- and investigation-scope-sensitive action key.

    ``action_scope`` is deliberately optional for backwards compatibility.
    Legacy callers that only know the target keep their historical key, while
    mechanism-scoped investigations can run the same action type against the
    same function for independent questions (for example decode and process
    execution) without suppressing one another.
    """
    payload = dict(parameters)
    nested_selector = payload.get("target_selector")
    if isinstance(nested_selector, Mapping):
        normalized_selector = _canonical_action_selector(nested_selector)
        if normalized_selector:
            # Retain a single shape so old persisted ``function_entry``
            # selectors dedupe against newer ``target`` RVAs.
            payload = {"target_selector": normalized_selector}
    else:
        normalized_selector = _canonical_action_selector(payload)
        if normalized_selector:
            payload = {"target_selector": normalized_selector}
    scope = parameters.get("action_scope")
    if isinstance(scope, (str, int)) and str(scope).strip():
        payload["action_scope"] = canonical_token(scope)
    canonical_parameters = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical_parameters.encode("utf-8")).hexdigest()[:20]
    return f"{str(action_type).upper()}:{digest}"


@dataclass(frozen=True)
class ActionSpec:
    id: str
    action_type: ActionType
    thread_id: str
    hypothesis_id: str
    artifact_id: str
    priority: int = 50
    reason: str = ""
    parameters: Mapping[str, object] = field(default_factory=dict)
    target_selector: Mapping[str, str | int] = field(default_factory=dict)
    expected_evidence_kinds: tuple[str, ...] = ()
    success_condition: str = "new_targeted_evidence"
    failure_interpretation: FailureInterpretation = FailureInterpretation.UNKNOWN
    cost_units: int | None = None
    depends_on: tuple[str, ...] = ()
    # Evidence cited by a model when it proposes this action.  The service
    # validates these IDs and the executor uses them as the causal input set;
    # selector and catalog validation remain authoritative as well.
    source_evidence_ids: tuple[str, ...] = ()
    # Planner correlation is attached by the service boundary and is used only
    # to attribute executor output to the immutable planner turn.
    planner_turn_id: str | None = None
    # Service-derived model control metadata.  It is persisted for audit only;
    # executors never treat it as an authorization input.
    provenance: Mapping[str, object] = field(default_factory=dict)
    # Plan-first rationale carried into the durable action parameters by the
    # service.  It is never an authorization input.
    plan: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Keep legacy deterministic callers source-compatible while making the
        # selector explicit on the immutable action contract.  Model actions
        # are normalized at the service boundary before construction.
        parameters = dict(self.parameters)
        raw_selector = dict(self.target_selector)
        if raw_selector:
            selector = normalize_target_selector(raw_selector)
            if parameters:
                aliased: dict[str, object] = {}
                for key, value in parameters.items():
                    mapped = SELECTOR_ALIASES.get(str(key), str(key))
                    aliased[mapped] = value
                parameters = aliased
            else:
                parameters = dict(selector)
        else:
            selector = normalize_target_selector(parameters)
            parameters = dict(selector)
        object.__setattr__(self, "parameters", parameters)
        object.__setattr__(self, "target_selector", selector)

    @property
    def dedupe_key(self) -> str:
        scope = action_scope_from_plan(self.plan)
        return canonical_action_key(
            self.action_type.value,
            {
                "target_selector": dict(self.target_selector),
                **({"action_scope": scope} if scope else {}),
            },
        )


@dataclass(frozen=True)
class GateDecision:
    accepted: bool
    status: str
    reason: str
    evidence_ids: tuple[str, ...]
    missing: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()


@dataclass(frozen=True)
class InvestigationEvent:
    phase: str
    action_id: str | None
    state: str
    evidence_ids: tuple[str, ...]
    message: str


@dataclass(frozen=True)
class InvestigationResult:
    thread_id: str
    artifact_id: str
    thread_state: InvestigationThreadState
    hypothesis_status: str
    evidence: tuple[dict[str, object], ...]
    events: tuple[InvestigationEvent, ...]
    actions: tuple[ActionSpec, ...]
    gate: GateDecision
    # Process coverage for admitted deep targets. This remains separate from
    # ClaimGate acceptance: a target can be fully inspected and still stay
    # UNKNOWN because static evidence did not prove its mechanism.
    coverage: Mapping[str, object] = field(default_factory=dict)


class TaskLifecycle(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    WAITING_GATE = "WAITING_GATE"
    PAUSED = "PAUSED"
    FINALIZING = "FINALIZING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

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


def scoped_investigation_action_key(
    action_type: str,
    selector: Mapping[str, object],
    plan: Mapping[str, object] | None = None,
) -> str:
    """Build the durable action key with the mechanism scope, if available."""
    scope = action_scope_from_plan(plan)
    payload: dict[str, object] = {"target_selector": dict(selector)}
    if scope:
        payload["action_scope"] = scope
    return canonical_action_key(action_type, payload)
