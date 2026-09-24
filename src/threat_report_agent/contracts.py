from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, ClassVar, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator
from dataclasses import dataclass


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
