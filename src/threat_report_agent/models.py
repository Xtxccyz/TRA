from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    Index,
    insert,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import event
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, UOWTransaction, mapped_column

from threat_report_agent.static.evidence_index import evidence_search_keys


def new_id() -> str:
    return str(uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class CaseRecord(Base):
    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(String(240))
    status: Mapped[str] = mapped_column(String(32), default="OPEN")
    trace_id: Mapped[str] = mapped_column(String(36), default=new_id, index=True)
    retention_frozen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    retention_frozen_by: Mapped[str | None] = mapped_column(String(160), nullable=True)
    retention_freeze_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AnalysisTask(Base):
    __tablename__ = "analysis_tasks"
    __table_args__ = (
        UniqueConstraint("case_id", "submission_key", name="uq_task_case_submission_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    trace_id: Mapped[str] = mapped_column(String(36), default=new_id, index=True)
    submission_key: Mapped[str | None] = mapped_column(String(200), nullable=True)
    lifecycle: Mapped[str] = mapped_column(String(32), default="PENDING")
    outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Round 11 product result class.  This is intentionally separate from
    # ``lifecycle`` and ``outcome`` so a failed workflow cannot be relabeled as
    # a bounded static limitation.
    analysis_class: Mapped[str | None] = mapped_column(String(40), nullable=True)
    target_breadth: Mapped[str] = mapped_column(String(8), default="B1")
    target_depth: Mapped[str] = mapped_column(String(8), default="D2")
    request_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    strategy_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    selected_modules: Mapped[list] = mapped_column(JSON, default=list)
    actual_granularity: Mapped[dict] = mapped_column(JSON, default=dict)
    limitations: Mapped[list] = mapped_column(JSON, default=list)
    coverage: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AnalysisFailureRecord(Base):
    """Sanitized, machine-readable diagnosis for a failed analysis attempt."""

    __tablename__ = "analysis_failures"
    __table_args__ = (UniqueConstraint("task_id", name="uq_analysis_failure_task"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(ForeignKey("analysis_tasks.id"), index=True)
    lifecycle: Mapped[str] = mapped_column(String(32), default="FAILED")
    analysis_class: Mapped[str] = mapped_column(String(40), default="FAILED_ANALYSIS")
    failure_code: Mapped[str] = mapped_column(String(80))
    failure_stage: Mapped[str] = mapped_column(String(160))
    failed_component: Mapped[str] = mapped_column(String(160))
    failed_activity: Mapped[str] = mapped_column(String(160))
    retryable: Mapped[bool] = mapped_column(Boolean, default=False)
    retry_after_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    failure_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    last_successful_stage: Mapped[str] = mapped_column(String(160), default="UNKNOWN")
    last_event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    tool_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    temporal_workflow_id: Mapped[str | None] = mapped_column(String(240), nullable=True)
    report_available: Mapped[bool] = mapped_column(Boolean, default=False)
    attempt_number: Mapped[int] = mapped_column(Integer, default=1)
    retry_of_task_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    retry_suppressed: Mapped[bool] = mapped_column(Boolean, default=False)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class InteractionSessionLink(Base):
    """Maps one DSH interaction session to the authoritative backend task.

    DSH owns conversational history; the backend remains authoritative for
    analysis state.  The unique primary-task constraint prevents two primary
    sessions from racing to mutate the same investigation thread.
    """

    __tablename__ = "interaction_session_links"
    __table_args__ = (
        UniqueConstraint("task_id", name="uq_interaction_session_primary_task"),
        UniqueConstraint("dsh_session_id", name="uq_interaction_session_dsh_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("analysis_tasks.id"), index=True)
    dsh_session_id: Mapped[str] = mapped_column(String(200), index=True)
    profile: Mapped[str] = mapped_column(String(80), default="threat-static")
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE")
    trajectory_status: Mapped[str] = mapped_column(String(40), default="LIVE")
    last_backend_event_seq: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ThreatAnalysisContextRecord(Base):
    """Server-authoritative analysis context for one DSH session.

    This projection deliberately lives separately from the legacy
    ``InteractionSessionLink`` table.  A session can exist before a task is
    created (for example after upload-only intake), and can retain attached
    artifacts while remaining unbound to a task.
    """

    __tablename__ = "threat_analysis_contexts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    dsh_session_id: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    workspace_id: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    state: Mapped[str] = mapped_column(String(40), default="UNBOUND", index=True)
    attached_artifact_ids: Mapped[list] = mapped_column(JSON, default=list)
    selected_artifact_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id"), nullable=True, index=True)
    active_task_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_tasks.id"), nullable=True, index=True
    )
    task_lifecycle: Mapped[str | None] = mapped_column(String(32), nullable=True)
    analysis_class: Mapped[str | None] = mapped_column(String(40), nullable=True)
    task_outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    binding_version: Mapped[int] = mapped_column(Integer, default=1)
    context_revision: Mapped[int] = mapped_column(Integer, default=1)
    binding_event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    bound_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tool_contract_version: Mapped[str] = mapped_column(String(80), default="threat-tools-v4")
    session_context_protocol: Mapped[str] = mapped_column(String(40), default="v3")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ContentBlob(Base):
    __tablename__ = "content_blobs"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    size: Mapped[int] = mapped_column(Integer)
    media_type: Mapped[str] = mapped_column(String(160))
    storage_key: Mapped[str] = mapped_column(String(512), unique=True)
    disposed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Artifact(Base):
    __tablename__ = "artifacts"
    __table_args__ = (UniqueConstraint("task_id", "logical_path", name="uq_artifact_path"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    # Intake is intentionally decoupled from analysis.  An Artifact may be
    # attached to a DSH session before the user explicitly starts a Task.
    task_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_tasks.id"), nullable=True, index=True
    )
    content_sha256: Mapped[str] = mapped_column(ForeignKey("content_blobs.sha256"), index=True)
    parent_artifact_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifacts.id"), nullable=True, index=True
    )
    logical_path: Mapped[str] = mapped_column(String(1024))
    role: Mapped[str] = mapped_column(String(32), default="UNKNOWN")
    obligation: Mapped[str] = mapped_column(String(32), default="REQUIRED")
    detected_type: Mapped[str] = mapped_column(String(80), default="unknown")
    discovery: Mapped[str] = mapped_column(String(64), default="submitted")
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    disposed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ToolRun(Base):
    __tablename__ = "tool_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_id: Mapped[str | None] = mapped_column(ForeignKey("analysis_tasks.id"), nullable=True, index=True)
    artifact_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifacts.id"), nullable=True, index=True
    )
    tool_name: Mapped[str] = mapped_column(String(120))
    tool_version: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(32))
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    environment: Mapped[dict] = mapped_column(JSON, default=dict)
    output: Mapped[dict] = mapped_column(JSON, default=dict)
    output_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    output_storage_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(ForeignKey("analysis_tasks.id"), index=True)
    artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id"), index=True)
    tool_run_id: Mapped[str] = mapped_column(ForeignKey("tool_runs.id"), index=True)
    module: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(80), index=True)
    nature: Mapped[str] = mapped_column(String(32), default="STATIC_OBSERVED")
    value: Mapped[dict] = mapped_column(JSON)
    anchor: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EvidenceSearchKey(Base):
    """Indexed exact selectors used before loading Evidence values into context."""

    __tablename__ = "evidence_search_keys"
    __table_args__ = (
        UniqueConstraint("evidence_id", "selector", name="uq_evidence_search_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(ForeignKey("analysis_tasks.id"), index=True)
    artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id"), index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"), index=True)
    selector: Mapped[str] = mapped_column(String(160), index=True)
    kind: Mapped[str] = mapped_column(String(80), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


@event.listens_for(Session, "after_flush")
def _index_new_evidence(session: Session, flush_context: UOWTransaction) -> None:
    """Index new immutable evidence once, without altering its source payload."""
    # Ghidra post-processing can stage tens of thousands of immutable rows.
    # It explicitly defers this rebuildable projection until the batch has
    # been flushed, avoiding selector work in every intermediate flush.
    if session.info.get("defer_evidence_search_keys"):
        return
    # Evidence is emitted in large batches by the Ghidra post-processor.  The
    # previous implementation added one ORM object per selector, which made
    # SQLAlchemy spend substantial time constructing/ tracking hundreds of
    # thousands of short-lived objects before PostgreSQL could execute the
    # inserts.  Use one executemany statement per flush instead.  IDs are
    # already materialized by the Evidence flush, and the derived index keeps
    # the same selectors, foreign keys, and unique constraint semantics.
    rows: list[dict[str, str]] = []
    # Partial flushes leave unrelated Evidence in session.new. Use the
    # completed unit of work so every indexed row already has its FK parent
    # in the database, without scanning the rest of the pending session.
    for state, (is_delete, list_only) in flush_context.states.items():
        if is_delete or list_only or not state.pending:
            continue
        item = state.obj()
        if not isinstance(item, Evidence):
            continue
        for selector in evidence_search_keys(kind=item.kind, value=item.value, anchor=item.anchor):
            rows.append(
                {
                    "id": new_id(),
                    "task_id": item.task_id,
                    "artifact_id": item.artifact_id,
                    "evidence_id": item.id,
                    "selector": selector,
                    "kind": item.kind,
                }
            )
    if rows:
        session.execute(insert(EvidenceSearchKey), rows)


class EvidenceDeliveryTrace(Base):
    """Append-only per-turn record of an Evidence item's delivery lifecycle."""

    __tablename__ = "evidence_delivery_traces"
    __table_args__ = (
        UniqueConstraint(
            "turn_id", "subject_key", "stage", name="uq_delivery_trace_turn_subject_stage"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(ForeignKey("analysis_tasks.id"), index=True)
    artifact_id: Mapped[str | None] = mapped_column(ForeignKey("artifacts.id"), nullable=True, index=True)
    thread_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    model_call_id: Mapped[str | None] = mapped_column(ForeignKey("model_calls.id"), nullable=True, index=True)
    turn_id: Mapped[str] = mapped_column(String(160), index=True)
    subject_key: Mapped[str] = mapped_column(String(160), index=True)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"), nullable=True, index=True)
    stage: Mapped[str] = mapped_column(String(32), index=True)
    context_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    selection_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    exclusion_reason: Mapped[str | None] = mapped_column(String(120), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AnalysisTurnRecord(Base):
    """Immutable audit manifest for one planner/model turn.

    The raw request/response bodies remain encrypted in the content store.  This
    row keeps the durable, non-secret references and the evidence/action IDs
    needed to replay or diagnose a turn without exposing private reasoning.
    """

    __tablename__ = "analysis_turns"
    __table_args__ = (
        UniqueConstraint("task_id", "turn_id", name="uq_analysis_turn_task_turn"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(ForeignKey("analysis_tasks.id"), index=True)
    thread_id: Mapped[str] = mapped_column(String(160), index=True)
    turn_id: Mapped[str] = mapped_column(String(200), index=True)
    phase: Mapped[str] = mapped_column(String(160), index=True)
    hypothesis_before: Mapped[list] = mapped_column(JSON, default=list)
    retrieval_request: Mapped[dict] = mapped_column(JSON, default=dict)
    candidate_evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    selected_evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    delivered_evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    context_manifest: Mapped[list] = mapped_column(JSON, default=list)
    model_call_id: Mapped[str | None] = mapped_column(
        ForeignKey("model_calls.id"), nullable=True, index=True
    )
    raw_response_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_response_storage_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    action_proposals: Mapped[list] = mapped_column(JSON, default=list)
    policy_decisions: Mapped[list] = mapped_column(JSON, default=list)
    tool_run_ids: Mapped[list] = mapped_column(JSON, default=list)
    new_evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    verifier_result: Mapped[dict] = mapped_column(JSON, default=dict)
    hypothesis_after: Mapped[list] = mapped_column(JSON, default=list)
    mechanism_state: Mapped[str] = mapped_column(String(48), default="UNKNOWN")
    stop_reason: Mapped[str] = mapped_column(String(240), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AnalysisTurnResultRecord(Base):
    """Append-only post-action result for an immutable planner Turn.

    A planner manifest is written as soon as the model responds.  Tool runs
    and verifier decisions happen afterwards, so they are recorded here rather
    than mutating that original manifest.  ``turn_id`` links the result to the
    planner turn without exposing raw model payloads.
    """

    __tablename__ = "analysis_turn_results"
    __table_args__ = (
        UniqueConstraint("task_id", "turn_id", name="uq_analysis_turn_result_task_turn"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(ForeignKey("analysis_tasks.id"), index=True)
    parent_turn_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    thread_id: Mapped[str] = mapped_column(String(160), index=True)
    turn_id: Mapped[str] = mapped_column(String(200), index=True)
    phase: Mapped[str] = mapped_column(String(160), index=True)
    completed_actions: Mapped[list] = mapped_column(JSON, default=list)
    tool_run_ids: Mapped[list] = mapped_column(JSON, default=list)
    new_evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    verifier_result: Mapped[dict] = mapped_column(JSON, default=dict)
    hypothesis_after: Mapped[list] = mapped_column(JSON, default=list)
    mechanism_state: Mapped[str] = mapped_column(String(48), default="UNKNOWN")
    stop_reason: Mapped[str] = mapped_column(String(240), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BlindRun(Base):
    """Immutable configuration snapshot for a reference-isolated blind run."""

    __tablename__ = "blind_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_id: Mapped[str | None] = mapped_column(ForeignKey("analysis_tasks.id"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="CREATED")
    snapshot: Mapped[dict] = mapped_column(JSON)
    snapshot_sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Claim(Base):
    __tablename__ = "claims"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(ForeignKey("analysis_tasks.id"), index=True)
    module: Mapped[str] = mapped_column(String(64), index=True)
    claim_type: Mapped[str] = mapped_column(String(64), default="BEHAVIOR")
    subject: Mapped[str] = mapped_column(String(240))
    action: Mapped[str] = mapped_column(String(160))
    object: Mapped[str] = mapped_column(String(500))
    mechanism: Mapped[str] = mapped_column(Text, default="")
    condition: Mapped[str] = mapped_column(Text, default="")
    statement: Mapped[str] = mapped_column(Text)
    nature: Mapped[str] = mapped_column(String(32), default="STATIC_INFERRED")
    status: Mapped[str] = mapped_column(String(32), default="CANDIDATE")
    confidence: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    attack_mapping: Mapped[dict] = mapped_column(JSON, default=dict)
    model_call_id: Mapped[str | None] = mapped_column(
        ForeignKey("model_calls.id"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ClaimEvidence(Base):
    __tablename__ = "claim_evidence"

    claim_id: Mapped[str] = mapped_column(ForeignKey("claims.id"), primary_key=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"), primary_key=True)
    stance: Mapped[str] = mapped_column(String(16), default="SUPPORTS")


class ModelCall(Base):
    __tablename__ = "model_calls"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(ForeignKey("analysis_tasks.id"), index=True)
    artifact_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifacts.id"), nullable=True, index=True
    )
    # Stable control-plane identifiers make one model call unambiguous when a
    # task contains multiple planner/enrichment turns or gateway retries.
    turn_id: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    phase: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    module: Mapped[str] = mapped_column(String(64), index=True)
    provider: Mapped[str] = mapped_column(String(80))
    model: Mapped[str] = mapped_column(String(160))
    prompt_id: Mapped[str] = mapped_column(String(120))
    prompt_version: Mapped[str] = mapped_column(String(80))
    prompt_sha256: Mapped[str] = mapped_column(String(64))
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(32))
    request_sha256: Mapped[str] = mapped_column(String(64))
    request_storage_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    response_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    response_storage_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    payload_schema_version: Mapped[str] = mapped_column(String(32), default="model-payload-v1")
    encryption_key_id: Mapped[str] = mapped_column(String(64), default="local-model-payload-key")
    security_classification: Mapped[str] = mapped_column(
        String(64), default="RESTRICTED_MODEL_PAYLOAD"
    )
    access_policy: Mapped[str] = mapped_column(String(120), default="auditor_or_system_only")
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    context_manifest: Mapped[list] = mapped_column(JSON, default=list)
    input_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    error_type: Mapped[str | None] = mapped_column(String(160), nullable=True)
    payload_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    payload_disposed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ModelConfiguration(Base):
    """Encrypted, process-independent model routing configuration.

    There is one active row. API keys are ciphertext only; public views never
    expose this table directly.
    """

    __tablename__ = "model_configurations"

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default="active")
    revision: Mapped[int] = mapped_column(Integer, default=1)
    enabled: Mapped[bool] = mapped_column(default=False)
    context_max_bytes: Mapped[int] = mapped_column(Integer, default=2_000_000)
    timeout_s: Mapped[float] = mapped_column(Float, default=180.0)
    max_tokens: Mapped[int] = mapped_column(Integer, default=2048)
    primary_provider: Mapped[str] = mapped_column(String(80), default="")
    primary_base_url: Mapped[str] = mapped_column(String(512), default="")
    primary_model: Mapped[str] = mapped_column(String(160), default="")
    primary_api_style: Mapped[str] = mapped_column(String(32), default="openai")
    primary_enabled: Mapped[bool] = mapped_column(default=True)
    primary_stream: Mapped[bool] = mapped_column(Boolean, default=True)
    primary_supports_json_mode: Mapped[bool] = mapped_column(Boolean, default=True)
    primary_temperature: Mapped[float] = mapped_column(Float, default=0.0)
    primary_top_p: Mapped[float] = mapped_column(Float, default=1.0)
    primary_disable_reasoning: Mapped[bool] = mapped_column(Boolean, default=True)
    primary_api_key_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    fallback_provider: Mapped[str] = mapped_column(String(80), default="")
    fallback_base_url: Mapped[str] = mapped_column(String(512), default="")
    fallback_model: Mapped[str] = mapped_column(String(160), default="")
    fallback_api_style: Mapped[str] = mapped_column(String(32), default="openai")
    fallback_enabled: Mapped[bool] = mapped_column(default=False)
    fallback_stream: Mapped[bool] = mapped_column(Boolean, default=True)
    fallback_supports_json_mode: Mapped[bool] = mapped_column(Boolean, default=True)
    fallback_temperature: Mapped[float] = mapped_column(Float, default=0.0)
    fallback_top_p: Mapped[float] = mapped_column(Float, default=1.0)
    fallback_disable_reasoning: Mapped[bool] = mapped_column(Boolean, default=True)
    fallback_api_key_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_by: Mapped[str] = mapped_column(String(160), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ModelConfigurationAudit(Base):
    __tablename__ = "model_configuration_audits"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    revision: Mapped[int] = mapped_column(Integer)
    actor: Mapped[str] = mapped_column(String(160))
    changed_slots: Mapped[list] = mapped_column(JSON, default=list)
    key_changed_slots: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Relation(Base):
    __tablename__ = "relations"
    __table_args__ = (
        CheckConstraint(
            "evidence_id IS NOT NULL OR claim_id IS NOT NULL",
            name="ck_relation_has_support",
        ),
        CheckConstraint(
            "(relation_type IN ('CONTAINS', 'DROPS', 'EXTRACTED_FROM') AND evidence_id IS NOT NULL) "
            "OR (relation_type IN ('LOADS', 'DECRYPTS', 'EXECUTES', 'INJECTS') "
            "AND claim_id IS NOT NULL)",
            name="ck_relation_type_support",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(ForeignKey("analysis_tasks.id"), index=True)
    source_artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id"))
    target_artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id"))
    relation_type: Mapped[str] = mapped_column(String(64))
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    claim_id: Mapped[str | None] = mapped_column(ForeignKey("claims.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="OBSERVED")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AnalysisSnapshot(Base):
    __tablename__ = "analysis_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(ForeignKey("analysis_tasks.id"), index=True)
    object_versions: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MechanismEffectivenessTraceRecord(Base):
    """Immutable, redacted effectiveness trace for one mechanism investigation.

    The trace is a control-plane record: it stores structured IDs, decisions and
    bounded deltas, never raw model messages or private reasoning.  A new
    post-action investigation produces a new row rather than mutating history.
    """

    __tablename__ = "mechanism_effectiveness_traces"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(ForeignKey("analysis_tasks.id"), index=True)
    mechanism_id: Mapped[str] = mapped_column(String(160), index=True)
    mechanism_type: Mapped[str] = mapped_column(String(120), index=True)
    artifact_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifacts.id"), nullable=True, index=True
    )
    trace_version: Mapped[str] = mapped_column(String(40), default="mechanism-effectiveness-v1")
    seed: Mapped[dict] = mapped_column(JSON, default=dict)
    question: Mapped[str | None] = mapped_column(Text, nullable=True)
    competing_hypotheses: Mapped[list] = mapped_column(JSON, default=list)
    action_proposals: Mapped[list] = mapped_column(JSON, default=list)
    tool_run_ids: Mapped[list] = mapped_column(JSON, default=list)
    new_evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    evidence_delta: Mapped[dict] = mapped_column(JSON, default=dict)
    hypothesis_delta: Mapped[dict] = mapped_column(JSON, default=dict)
    mechanism_delta: Mapped[dict] = mapped_column(JSON, default=dict)
    verifier_result: Mapped[dict] = mapped_column(JSON, default=dict)
    claim_gate: Mapped[dict] = mapped_column(JSON, default=dict)
    report_projection: Mapped[dict] = mapped_column(JSON, default=dict)
    model_action_productivity: Mapped[dict] = mapped_column(JSON, default=dict)
    trace_sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReportRevision(Base):
    __tablename__ = "report_revisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(ForeignKey("analysis_tasks.id"), index=True)
    snapshot_id: Mapped[str] = mapped_column(ForeignKey("analysis_snapshots.id"), index=True)
    parent_revision_id: Mapped[str | None] = mapped_column(
        ForeignKey("report_revisions.id"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(32), default="DRAFT")
    author: Mapped[str] = mapped_column(String(160), default="system")
    selected_modules: Mapped[list] = mapped_column(JSON)
    document: Mapped[dict] = mapped_column(JSON)
    markdown: Mapped[str] = mapped_column(Text)
    edit_kind: Mapped[str] = mapped_column(String(32), default="AGENT_GENERATED")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GateRecord(Base):
    __tablename__ = "gates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(ForeignKey("analysis_tasks.id"), index=True)
    gate_type: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="PENDING")
    reason: Mapped[str] = mapped_column(Text)
    context: Mapped[dict] = mapped_column(JSON, default=dict)
    decided_by: Mapped[str | None] = mapped_column(String(160), nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class TaskSecret(Base):
    __tablename__ = "task_secrets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_id: Mapped[str] = mapped_column(ForeignKey("analysis_tasks.id"), index=True)
    secret_type: Mapped[str] = mapped_column(String(64))
    ciphertext: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class InvestigationThreadRecord(Base):
    """Durable state for one evidence-driven investigation thread."""

    __tablename__ = "investigation_threads"

    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("analysis_tasks.id"), index=True)
    artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id"), index=True)
    state: Mapped[str] = mapped_column(String(32), default="DISCOVERED")
    question: Mapped[str] = mapped_column(Text)
    seed_kind: Mapped[str] = mapped_column(String(120), default="artifact_triage")
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    hypothesis_ids: Mapped[list] = mapped_column(JSON, default=list)
    mechanism_ids: Mapped[list] = mapped_column(JSON, default=list)
    action_ids: Mapped[list] = mapped_column(JSON, default=list)
    transition_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class InvestigationHypothesisRecord(Base):
    """Versioned hypothesis whose Claim upgrade is controlled by ClaimGate."""

    __tablename__ = "investigation_hypotheses"

    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("analysis_tasks.id"), index=True)
    thread_id: Mapped[str] = mapped_column(ForeignKey("investigation_threads.id"), index=True)
    statement: Mapped[str] = mapped_column(Text)
    dimension: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(32), default="OPEN")
    confidence: Mapped[str] = mapped_column(String(16), default="LOW")
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    required_evidence: Mapped[list] = mapped_column(JSON, default=list)
    contradictory_evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class InvestigationActionRecord(Base):
    """One catalog action and its result, including failures and retries."""

    __tablename__ = "investigation_actions"

    id: Mapped[str] = mapped_column(String(160), primary_key=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("analysis_tasks.id"), index=True)
    thread_id: Mapped[str] = mapped_column(ForeignKey("investigation_threads.id"), index=True)
    hypothesis_id: Mapped[str] = mapped_column(ForeignKey("investigation_hypotheses.id"), index=True)
    artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id"), index=True)
    action_type: Mapped[str] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(Text, default="")
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    target_selector: Mapped[dict] = mapped_column(JSON, default=dict)
    expected_evidence_kinds: Mapped[list] = mapped_column(JSON, default=list)
    success_condition: Mapped[str] = mapped_column(Text, default="new_targeted_evidence")
    failure_interpretation: Mapped[str] = mapped_column(String(32), default="UNKNOWN")
    cost_units: Mapped[int] = mapped_column(Integer, default=1)
    priority: Mapped[int] = mapped_column(Integer, default=50)
    status: Mapped[str] = mapped_column(String(32), default="QUEUED")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    depends_on: Mapped[list] = mapped_column(JSON, default=list)
    result_evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_events_task_sequence", "task_id", "chain_sequence"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id"), nullable=True, index=True)
    task_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_tasks.id"), nullable=True, index=True
    )
    event_type: Mapped[str] = mapped_column(String(120), index=True)
    actor: Mapped[str] = mapped_column(String(160), default="system")
    object_type: Mapped[str] = mapped_column(String(80))
    object_id: Mapped[str] = mapped_column(String(80))
    trace_id: Mapped[str] = mapped_column(String(36), default=new_id)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    chain_version: Mapped[str] = mapped_column(String(16), default="1")
    chain_sequence: Mapped[int] = mapped_column(Integer, default=0)
    previous_hash: Mapped[str] = mapped_column(String(64), default="0" * 64)
    event_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditChainHead(Base):
    __tablename__ = "audit_chain_heads"

    scope_key: Mapped[str] = mapped_column(String(80), primary_key=True)
    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id"), nullable=True, index=True)
    task_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_tasks.id"), nullable=True, index=True
    )
    trace_id: Mapped[str] = mapped_column(String(36), index=True)
    last_event_hash: Mapped[str] = mapped_column(String(64))
    sequence: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditSeal(Base):
    __tablename__ = "audit_seals"
    __table_args__ = (
        UniqueConstraint("scope_key", "sequence", name="uq_audit_seal_scope_sequence"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scope_key: Mapped[str] = mapped_column(String(80), index=True)
    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id"), nullable=True, index=True)
    task_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_tasks.id"), nullable=True, index=True
    )
    terminal_event_type: Mapped[str] = mapped_column(String(120))
    terminal_event_hash: Mapped[str] = mapped_column(String(64))
    merkle_root: Mapped[str] = mapped_column(String(64))
    sequence: Mapped[int] = mapped_column(Integer)
    algorithm: Mapped[str] = mapped_column(String(80), default="HMAC-SHA256")
    key_id: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(String(128))
    payload_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload_storage_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    seal_window: Mapped[str | None] = mapped_column(String(32), nullable=True)
    sealed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EvidencePurgeRequest(Base):
    __tablename__ = "evidence_purge_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="PENDING_REVIEW")
    requested_by: Mapped[str] = mapped_column(String(160))
    reviewed_by: Mapped[str | None] = mapped_column(String(160), nullable=True)
    executed_by: Mapped[str | None] = mapped_column(String(160), nullable=True)
    reason: Mapped[str] = mapped_column(Text)
    impact_manifest: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
