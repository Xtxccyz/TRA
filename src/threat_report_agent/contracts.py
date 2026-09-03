from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


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
