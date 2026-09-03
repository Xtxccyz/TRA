from __future__ import annotations

from dataclasses import dataclass, replace
import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping
import base64
import binascii
import hashlib
import hmac
import json
import zipfile
import io
import time
import re
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from threat_report_agent.agents import (
    FunctionEvidenceCandidate,
    StaticAnalysisAgent,
    TriageAgent,
)
from threat_report_agent.config import ModelProviderSettings, Settings
from threat_report_agent.contracts import (
    ActionProposal,
    BackgroundContextInput,
    FourChannelInput,
    KnowledgeSnapshotInput,
    SamplePackageInput,
    TaskRequestInput,
)
from threat_report_agent.content_store import ContentStore
from threat_report_agent.database import Database
from threat_report_agent.ghidra_adapter import (
    GhidraHeadlessRunner,
    GhidraRun,
    validate_ghidra_output,
)
from threat_report_agent.intake import (
    IntakeGateRequired,
    PackageEntry,
    expand_directory,
    expand_directory_entries,
    expand_submission,
)
from threat_report_agent.orchestration import (
    DeterministicSeedRanker,
    QuestionCompiler,
    StaticInvestigationOrchestrator,
)
from threat_report_agent.evidence_recovery import (
    BoundedEvidenceRepository,
    ContextPacket,
    EvidenceDeliveryLedger,
    EvidenceStage,
    FailureInterpretation,
    QuestionCentricRetriever,
    RetrievalRequest,
    canonical_action_key,
)
from threat_report_agent.policy import PolicyRegistry
from threat_report_agent.prompts import PromptRegistry
from threat_report_agent.models import (
    AnalysisSnapshot,
    AnalysisTask,
    AnalysisFailureRecord,
    Artifact,
    AuditChainHead,
    AuditEvent,
    AuditSeal,
    BlindRun,
    CaseRecord,
    Claim,
    ClaimEvidence,
    ContentBlob,
    Evidence,
    EvidenceDeliveryTrace,
    AnalysisTurnRecord,
    AnalysisTurnResultRecord,
    MechanismEffectivenessTraceRecord,
    GateRecord,
    ModelCall,
    ModelConfiguration,
    ModelConfigurationAudit,
    Relation,
    ReportRevision,
    TaskSecret,
    ToolRun,
    InvestigationThreadRecord,
    InvestigationHypothesisRecord,
    InvestigationActionRecord,
    InteractionSessionLink,
    ThreatAnalysisContextRecord,
    new_id,
    utcnow,
)
from threat_report_agent.investigation import (
    ActionCatalog,
    ActionSpec,
    ActionType,
    InvestigationLoopDriver,
    MechanismPlaybookRegistry,
    Verifier,
    verify_mechanism,
    derive_static_mechanism_links,
)
from threat_report_agent.model_gateway import (
    AtomicClaimDraft,
    AtomicClaimEnvelope,
    DynamicPlanAction,
    DynamicPlanEnvelope,
    ModelGateway,
    ModelRequest,
    provider_contract,
)
from threat_report_agent.mechanism_completeness import (
    mechanism_completeness_score,
)
from threat_report_agent.deep_analysis_quality import no_new_evidence_autopsy
from threat_report_agent.reporting import (
    REPORT_MODULES,
    build_report_document,
    build_mechanism_projections,
    build_static_link_mechanism_projections,
    document_to_markdown,
    normalize_modules,
    report_bloat_violations,
    report_analytical_violations,
    report_v3_quality_violations,
)
from threat_report_agent.secret_store import SecretCipher
from threat_report_agent.simulation_adapters import static_phase_simulation_evidence
from threat_report_agent.static_simulation import StaticAbstractExecutor
from threat_report_agent.static_analysis import (
    StaticFact,
    analyze_xor_decode_window,
    analyze_bytes,
    build_cross_function_chains,
    correlate_data_references,
    derive_mechanism_facts,
    derive_function_mechanism_facts,
    extract_embedded_bytes,
    function_fuzzy_fingerprint,
    identify_format,
    build_investigation_seed_map,
    resolve_static_data_strings,
    classify_pe_semantics,
    build_pcode_slice,
    track_indirect_function_pointers,
    trace_static_api_arguments,
    verify_xor_decode_candidate,
)
from threat_report_agent.semantic_predicates import (
    classify_api_symbol,
    is_anti_analysis_signal,
    is_dynamic_loader_call,
    is_execution_call,
    is_injection_call,
    is_network_transport_call,
    normalize_api_symbol,
)
from threat_report_agent.function_similarity import (
    FingerprintRecord,
    FunctionSimilarityIndex,
    SimilarityQuery,
)
from threat_report_agent.attack_mapping import load_attack_snapshot, map_behavior_claim
from threat_report_agent.methodology import (
    DIMENSIONS,
    FactLibrary,
    build_profile,
)
from threat_report_agent.tool_execution import (
    ToolRunRequest,
    ToolRunResult,
    TemporalToolExecutor,
    intake_entries_from_payload,
    static_result_from_payload,
)
from threat_report_agent.validation import validate_claim_evidence
from threat_report_agent.agent_runtime import AgentRuntime
from threat_report_agent.analysis_trace import (
    build_analysis_trace,
    build_mechanism_effectiveness_traces,
)
from threat_report_agent.runtime_contracts import classify_failure, retry_decision
from threat_report_agent.status import (
    AnalysisOutcome,
    TaskLifecycle,
    ToolRunStatus,
    transition_task,
)
from threat_report_agent.product_certification import (
    aggregate_result_class,
    analysis_coverage,
    classify_artifact_result,
    semantic_flow_metrics,
)


@dataclass(frozen=True)
class SubmissionResult:
    case_id: str
    task_id: str
    lifecycle: str
    outcome: str | None
    report_revision_id: str | None
    gate_id: str | None = None


@dataclass(frozen=True)
class IntakeExecution:
    root_logical_path: str
    entry_paths: tuple[str, ...]
    result: ToolRunResult


@dataclass(frozen=True)
class ScheduledStaticAction:
    """One policy-checked static action in the investigation queue."""

    artifact_id: str
    tool_name: str
    priority: int
    reason: str
    depends_on: tuple[str, ...] = ()
    source: str = "deterministic_baseline"
    planner_turn_id: str | None = None


    @property
    def key(self) -> str:
        return f"{self.artifact_id}:{self.tool_name}"


@dataclass(frozen=True)
class RetrievedModelContext:
    """Bounded evidence selected for one model turn and its audit ledger."""

    manifest: tuple[dict[str, object], ...]
    ledger: EvidenceDeliveryLedger
    packets: tuple[ContextPacket, ...]


class ContextMismatchError(ValueError):
    """A task or artifact is not owned by the current DSH analysis context."""

    code = "CONTEXT_MISMATCH"


    


SPECIALIST_STATIC_TOOLS = frozenset(
    {
        "signal-extractor",
        "knowledge-fact-matcher",
        "rva-xref-query",
        "crypto-pattern-scanner",
        "c2-protocol-scanner",
        "build-metadata-scanner",
        "codename-scanner",
    }
)

# A reference-isolated blind run may derive signals from sample observations,
# but it must never correlate those signals with packaged or operator-supplied
# threat facts. Keep this content-addressed empty library explicit so the
# blind-run manifest can prove the boundary used for a historical result.
REFERENCE_ISOLATED_FACT_LIBRARY = FactLibrary(
    facts=(),
    sha256=hashlib.sha256(b"facts: []\n").hexdigest(),
    source="reference-isolated-empty",
)


class AnalysisService:
    SNAPSHOT_SCHEMA_VERSION = "2.0"
    THREAT_CONTEXT_PROTOCOL = "v3"
    THREAT_TOOL_CONTRACT_VERSION = "threat-tools-v4"
    THREAT_CONTEXT_STATES = frozenset(
        {
            "UNBOUND",
            "ARTIFACT_READY",
            "ANALYSIS_QUEUED",
            "ANALYSIS_RUNNING",
            "ANALYSIS_READY",
            "ANALYSIS_FAILED",
            "ANALYSIS_CANCELLED",
            "HISTORICAL_ANALYSIS_BOUND",
        }
    )
    # Keep model context focused on evidence that can support a conclusion.
    # Raw string extraction can produce tens of thousands of low-signal rows;
    # sending all of them makes providers spend their entire timeout on input
    # processing and leaves no useful synthesis for the analyst.
    _MODEL_EVIDENCE_LIMIT = 96
    _MODEL_EVIDENCE_VALUE_LIMIT = 2400
    _MAX_MODEL_REPLAN_TURNS = 12
    _MAX_CONSECUTIVE_REPLAN_NO_GAIN = 2
    # Bound expensive Ghidra post-processing while retaining enough
    # high-signal functions for D3 mechanism analysis.
    _MAX_GHIDRA_FUNCTIONS = 512
    _MAX_GHIDRA_CALL_EVIDENCE_PER_FUNCTION = 96
    _MAX_GHIDRA_XREF_EVIDENCE_PER_FUNCTION = 64
    _MAX_GHIDRA_CFG_EVIDENCE_PER_FUNCTION = 64
    _MAX_GHIDRA_SYMBOL_EVIDENCE = 4096
    # Planner history carries evidence identifiers for audit correlation, but
    # must not replay thousands of IDs into every subsequent model request.
    _MAX_COMPLETED_ACTION_EVIDENCE_IDS = 128
    _MODEL_EVIDENCE_PRIORITY = {
        "pe_structure": 100,
        "function": 98,
        "function_call": 96,
        "function_interface": 94,
        "function_mechanism": 92,
        "abstract_execution_trace": 94,
        "loader_indicator": 90,
        "execution_indicator": 90,
        "anti_analysis_indicator": 90,
        "c2_indicator": 90,
        "cfg_block": 86,
        "xref": 84,
        "import_symbol": 82,
        "export_symbol": 82,
        "decoded_artifact": 78,
        "file_identity": 74,
        "archive_member": 72,
        "encoded_blob": 64,
        "string": 10,
    }

    def __init__(
        self,
        settings: Settings,
        database: Database,
        content_store: ContentStore,
    ) -> None:
        self.settings = settings
        self.database = database
        self.content_store = content_store
        self.policy = PolicyRegistry.load_builtin()
        self.prompts = PromptRegistry.load_builtin()
        model_route = "deterministic-static-rules"
        self.triage_agent = TriageAgent(self.prompts, model_route)
        self.static_agent = StaticAnalysisAgent(self.prompts, model_route)
        self.similarity_index = FunctionSimilarityIndex.load_builtin()
        self.methodology_library = FactLibrary.load_builtin()
        self.model_gateway = ModelGateway(settings.primary_model, settings.fallback_model)
        self.evidence_repository = BoundedEvidenceRepository()
        self.evidence_retriever = QuestionCentricRetriever(max_items=32)
        self.model_config_revision = 0
        self._model_payload_cipher = SecretCipher(
            settings.gate_secret_key or settings.audit_seal_secret or "local-model-payload-key"
        )
        payload_key_material = (
            settings.gate_secret_key or settings.audit_seal_secret or "local-model-payload-key"
        )
        self._model_payload_key_id = hashlib.sha256(
            payload_key_material.encode("utf-8")
        ).hexdigest()[:16]
        self.orchestrator = StaticInvestigationOrchestrator(self.policy)

    def _record_analysis_failure(
        self,
        session: Session,
        task: AnalysisTask,
        exc: BaseException,
        *,
        stage: str = "ANALYSIS",
        event_id: str | None = None,
    ) -> dict[str, object]:
        """Persist a sanitized failure contract for every failed attempt."""
        latest_tool = session.scalar(
            select(ToolRun)
            .where(ToolRun.task_id == task.id, ToolRun.status == ToolRunStatus.FAILED.value)
            .order_by(ToolRun.finished_at.desc(), ToolRun.id.desc())
        )
        latest_events = list(
            session.scalars(
                select(AuditEvent)
                .where(AuditEvent.task_id == task.id)
                .order_by(AuditEvent.chain_sequence.desc(), AuditEvent.id.desc())
                .limit(64)
            )
        )
        failure_event_types = {
            "analysis_task.failed",
            "analysis_task.cancelled",
            "analysis_task.cancel_requested",
            "gate.approval_failed",
        }
        latest_event = next(
            (item for item in latest_events if item.event_type not in failure_event_types and not item.event_type.endswith(".failed")),
            None,
        )
        last_successful_stage = str(latest_event.event_type)[:160] if latest_event else "UNKNOWN"
        contract = classify_failure(
            exc,
            stage=stage,
            failed_component=(latest_tool.tool_name if latest_tool else None),
            failed_activity=(latest_tool.tool_name if latest_tool else None),
            last_successful_stage=last_successful_stage,
        )
        existing = session.scalar(
            select(AnalysisFailureRecord).where(AnalysisFailureRecord.task_id == task.id)
        )
        detail = {key: value for key, value in contract.items() if key != "message"}
        detail["message"] = str(contract.get("message", ""))[:500]
        workflow_id = None
        if latest_tool is not None and isinstance(latest_tool.environment, dict):
            candidate = latest_tool.environment.get("workflow_id")
            if candidate:
                workflow_id = str(candidate)[:240]
        previous_task = session.scalar(
            select(AnalysisTask)
            .join(
                AnalysisFailureRecord,
                AnalysisFailureRecord.task_id == AnalysisTask.id,
            )
            .where(
                AnalysisTask.case_id == task.case_id,
                AnalysisTask.id != task.id,
                AnalysisTask.lifecycle == TaskLifecycle.FAILED.value,
            )
            .order_by(AnalysisTask.finished_at.desc(), AnalysisTask.created_at.desc())
        )
        # A just-flushed task can be visible through the join before its
        # failure row is committed. Never allow a failure record to point to
        # itself, even if a database backend returns an unexpected identity
        # comparison result during autoflush.
        if previous_task is not None and str(previous_task.id) == str(task.id):
            previous_task = None
        previous_failure = (
            session.scalar(
                select(AnalysisFailureRecord).where(
                    AnalysisFailureRecord.task_id == previous_task.id
                )
            )
            if previous_task is not None
            else None
        )
        previous_fingerprint = (
            existing.failure_fingerprint if existing is not None else
            (previous_failure.failure_fingerprint if previous_failure is not None else None)
        )
        decision = retry_decision(
            retryable=bool(contract["retryable"]),
            previous_fingerprint=previous_fingerprint,
            fingerprint=str(contract["failure_fingerprint"]),
        )
        retry_of_task_id = previous_task.id if previous_task is not None else None
        attempt_number = (
            (existing.attempt_number + 1)
            if existing is not None
            else ((previous_failure.attempt_number + 1) if previous_failure is not None else 1)
        )
        values = {
            "lifecycle": "FAILED",
            "analysis_class": "FAILED_ANALYSIS",
            "failure_code": str(contract["failure_code"]),
            "failure_stage": str(contract["failure_stage"]),
            "failed_component": str(contract["failed_component"]),
            "failed_activity": str(contract["failed_activity"]),
            "retryable": bool(contract["retryable"]),
            "retry_after_seconds": contract["retry_after_seconds"],
            "failure_fingerprint": str(contract["failure_fingerprint"]),
            "last_successful_stage": str(contract["last_successful_stage"]),
            "last_event_id": event_id or (latest_event.id if latest_event else None),
            "tool_run_id": latest_tool.id if latest_tool else None,
            "temporal_workflow_id": workflow_id,
            "report_available": False,
            "attempt_number": attempt_number,
            "retry_of_task_id": retry_of_task_id,
            "retry_suppressed": bool(decision["retry_suppressed"]),
            "detail": {
                **detail,
                "retry": decision,
                "retry_reason": decision.get("reason"),
                "requested_by": "system",
                "previous_failure_fingerprint": previous_fingerprint,
            },
        }
        if existing is None:
            session.add(AnalysisFailureRecord(task_id=task.id, **values))
        else:
            for key, value in values.items():
                setattr(existing, key, value)
        return {**values, "task_id": task.id, "retry": decision}

    @staticmethod
    def _is_evidence_index_corruption(exc: BaseException) -> bool:
        """Recognize corruption of the rebuildable Evidence selector index.

        PostgreSQL may wrap the driver error several levels deep.  Walk the
        cause/context chain and require either the derived table name or the
        characteristic LZ4 corruption wording so ordinary parser errors are
        never routed through database repair.
        """
        seen: set[int] = set()
        current: BaseException | None = exc
        while current is not None and id(current) not in seen:
            seen.add(id(current))
            text = str(current).casefold()
            if "evidence_search_keys" in text or ("lz4" in text and "corrupt" in text):
                return True
            current = current.__cause__ or current.__context__
        return False

    def _record_derived_index_repair(
        self,
        task_id: str,
        *,
        result: dict[str, str],
        original_error: BaseException,
    ) -> None:
        """Persist the one-time derived-index repair as an audit event."""
        with self.database.session_factory.begin() as session:
            # Serialize task-control-plane mutations before any dependent
            # Evidence/Audit writes.  PostgreSQL otherwise allows concurrent
            # planner/finalizer transactions to acquire locks in opposite
            # orders and deadlock while updating the JSON snapshot.
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if task is None:
                return
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="analysis.derived_index_repaired",
                actor="system",
                object_type="EvidenceSearchKey",
                object_id="evidence_search_keys",
                payload={
                    "status": result.get("status"),
                    "table": result.get("table"),
                    "original_error_type": type(original_error).__name__,
                    "original_error_fingerprint": hashlib.sha256(
                        str(original_error).encode("utf-8", errors="replace")
                    ).hexdigest()[:16],
                    "controlled_retry": True,
                },
            )

    def _run_analysis_with_repair(
        self,
        case_id: str,
        task_id: str,
        entries: list[PackageEntry],
        modules: list[str],
        actor: str,
        intake_executions: list[IntakeExecution],
    ) -> SubmissionResult:
        """Run static analysis with one controlled derived-index recovery.

        The Evidence ledger is authoritative; ``evidence_search_keys`` is a
        rebuildable projection.  A corruption error therefore warrants one
        repair and one replay of the same immutable input.  A second failure
        is allowed to reach the normal failure contract and is never retried
        blindly.
        """
        try:
            return self._run_analysis(
                case_id, task_id, entries, modules, actor, intake_executions
            )
        except Exception as exc:
            if not self._is_evidence_index_corruption(exc):
                raise
            result = self.database.repair_evidence_search_keys()
            self._record_derived_index_repair(
                task_id, result=result, original_error=exc
            )
            with self.database.session_factory.begin() as session:
                task = session.get(AnalysisTask, task_id)
                if task is not None:
                    snapshot = dict(task.strategy_snapshot or {})
                    repair = dict(snapshot.get("derived_index_repair", {}))
                    repair["attempted"] = True
                    repair["status"] = result.get("status")
                    repair["table"] = result.get("table")
                    repair["count"] = int(repair.get("count", 0)) + 1
                    task.strategy_snapshot = {
                        **snapshot,
                        "derived_index_repair": repair,
                    }
            return self._run_analysis(
                case_id, task_id, entries, modules, actor, intake_executions
            )

    @staticmethod
    def _failure_payload(row: AnalysisFailureRecord | None) -> dict[str, object] | None:
        if row is None:
            return None
        return {
            "task_id": row.task_id,
            "lifecycle": row.lifecycle,
            "analysis_class": row.analysis_class,
            "failure_code": row.failure_code,
            "failure_stage": row.failure_stage,
            "failed_component": row.failed_component,
            "failed_activity": row.failed_activity,
            "retryable": row.retryable,
            "retry_after_seconds": row.retry_after_seconds,
            "failure_fingerprint": row.failure_fingerprint,
            "last_successful_stage": row.last_successful_stage,
            "last_event_id": row.last_event_id,
            "tool_run_id": row.tool_run_id,
            "temporal_workflow_id": row.temporal_workflow_id,
            "report_available": row.report_available,
            "attempt_number": row.attempt_number,
            "retry_of_task_id": row.retry_of_task_id,
            "retry_suppressed": row.retry_suppressed,
            "detail": row.detail,
            "created_at": row.created_at.isoformat(),
        }

    @staticmethod
    def _elapsed_ms(task: AnalysisTask, *, now: datetime | None = None) -> int | None:
        start = task.started_at or task.created_at
        end = task.finished_at or now or utcnow()
        if start is None or end is None:
            return None
        # SQLite returns timezone-aware columns as naive datetimes.  Treat
        # those values as UTC so progress/status projections remain portable
        # across SQLite test databases and PostgreSQL production databases.
        if start.tzinfo is None:
            start = start.replace(tzinfo=UTC)
        if end.tzinfo is None:
            end = end.replace(tzinfo=UTC)
        return max(0, int((end - start).total_seconds() * 1000))

    @property
    def _model_config_key(self) -> str:
        return (
            self.settings.model_config_secret_key
            or self.settings.gate_secret_key
            or self.settings.audit_seal_secret
        )

    def reload_model_configuration(self) -> None:
        """Load the persisted model routes and atomically replace the gateway."""
        with self.database.session_factory() as session:
            row = session.get(ModelConfiguration, "active")
            if row is None:
                return
            if not self._model_config_key:
                raise RuntimeError("MODEL_CONFIG_SECRET_KEY or GATE_SECRET_KEY is required")
            key = self._model_config_key
            primary = self._provider_from_config_row(row, "primary", key)
            fallback = self._provider_from_config_row(row, "fallback", key)
            self.settings = replace(
                self.settings,
                primary_model=primary,
                fallback_model=fallback,
                model_calls_enabled=bool(row.enabled),
                model_context_max_bytes=row.context_max_bytes,
                model_timeout_s=float(row.timeout_s),
                model_max_tokens=int(row.max_tokens),
            )
            self.model_gateway = ModelGateway(primary, fallback)
            self.model_config_revision = row.revision

    @staticmethod
    def _provider_from_config_row(row: ModelConfiguration, slot: str, key: str) -> Any:
        prefix = f"{slot}_"
        ciphertext = getattr(row, f"{prefix}api_key_ciphertext")
        api_key = SecretCipher(key).decrypt(ciphertext) if ciphertext else ""
        return ModelProviderSettings(
            provider=getattr(row, f"{prefix}provider"),
            base_url=getattr(row, f"{prefix}base_url"),
            model=getattr(row, f"{prefix}model"),
            api_key=api_key,
            api_style=getattr(row, f"{prefix}api_style"),
            enabled=bool(getattr(row, f"{prefix}enabled")) and bool(row.enabled),
            stream=bool(getattr(row, f"{prefix}stream", True)),
            supports_json_mode=bool(getattr(row, f"{prefix}supports_json_mode", True)),
            temperature=float(getattr(row, f"{prefix}temperature", 0.0)),
            top_p=float(getattr(row, f"{prefix}top_p", 1.0)),
            disable_reasoning=bool(getattr(row, f"{prefix}disable_reasoning", True)),
        )

    @staticmethod
    def _config_route_view(row: ModelConfiguration, slot: str) -> dict[str, object]:
        prefix = f"{slot}_"
        ciphertext = getattr(row, f"{prefix}api_key_ciphertext")
        return {
            "provider": getattr(row, f"{prefix}provider"),
            "base_url": getattr(row, f"{prefix}base_url"),
            "model": getattr(row, f"{prefix}model"),
            "api_style": getattr(row, f"{prefix}api_style"),
            "enabled": bool(getattr(row, f"{prefix}enabled")) and bool(row.enabled),
            "stream": bool(getattr(row, f"{prefix}stream", True)),
            "supports_json_mode": bool(getattr(row, f"{prefix}supports_json_mode", True)),
            "temperature": float(getattr(row, f"{prefix}temperature", 0.0)),
            "top_p": float(getattr(row, f"{prefix}top_p", 1.0)),
            "disable_reasoning": bool(getattr(row, f"{prefix}disable_reasoning", True)),
            "configured": bool(ciphertext)
            and bool(getattr(row, f"{prefix}base_url"))
            and bool(getattr(row, f"{prefix}model")),
            "api_key_configured": bool(ciphertext),
        }

    def model_configuration_view(self) -> dict[str, object]:
        with self.database.session_factory() as session:
            row = session.get(ModelConfiguration, "active")
            if row is None:
                return {
                    "source": "environment",
                    "revision": 0,
                    "enabled": self.settings.model_calls_enabled,
                    "context_max_bytes": self.settings.model_context_max_bytes,
                    "timeout_s": self.settings.model_timeout_s,
                    "max_tokens": self.settings.model_max_tokens,
                    "primary": {
                        "provider": self.settings.primary_model.provider,
                        "base_url": self.settings.primary_model.base_url,
                        "model": self.settings.primary_model.model,
                        "api_style": self.settings.primary_model.api_style,
                        "enabled": self.settings.primary_model.enabled,
                        "stream": self.settings.primary_model.stream,
                        "supports_json_mode": self.settings.primary_model.supports_json_mode,
                        "temperature": self.settings.primary_model.temperature,
                        "top_p": self.settings.primary_model.top_p,
                        "disable_reasoning": self.settings.primary_model.disable_reasoning,
                        "configured": self.settings.primary_model.configured,
                        "api_key_configured": bool(self.settings.primary_model.api_key),
                    },
                    "fallback": {
                        "provider": self.settings.fallback_model.provider,
                        "base_url": self.settings.fallback_model.base_url,
                        "model": self.settings.fallback_model.model,
                        "api_style": self.settings.fallback_model.api_style,
                        "enabled": self.settings.fallback_model.enabled,
                        "stream": self.settings.fallback_model.stream,
                        "supports_json_mode": self.settings.fallback_model.supports_json_mode,
                        "temperature": self.settings.fallback_model.temperature,
                        "top_p": self.settings.fallback_model.top_p,
                        "disable_reasoning": self.settings.fallback_model.disable_reasoning,
                        "configured": self.settings.fallback_model.configured,
                        "api_key_configured": bool(self.settings.fallback_model.api_key),
                    },
                }
            return {
                "source": "database",
                "revision": row.revision,
                "enabled": row.enabled,
                "context_max_bytes": row.context_max_bytes,
                "timeout_s": row.timeout_s,
                "max_tokens": row.max_tokens,
                "updated_by": row.updated_by,
                "updated_at": row.updated_at.isoformat(),
                "primary": self._config_route_view(row, "primary"),
                "fallback": self._config_route_view(row, "fallback"),
            }

    def update_model_configuration(self, payload: dict[str, object], *, actor: str) -> dict[str, object]:
        key = self._model_config_key
        if not key:
            raise ValueError("Configure MODEL_CONFIG_SECRET_KEY before saving model credentials")
        context_max_bytes = int(payload.get("context_max_bytes", self.settings.model_context_max_bytes))
        if context_max_bytes < 1024 or context_max_bytes > 50_000_000:
            raise ValueError("context_max_bytes must be between 1024 and 50000000")
        timeout_s = float(payload.get("timeout_s", self.settings.model_timeout_s))
        max_tokens = int(payload.get("max_tokens", self.settings.model_max_tokens))
        if timeout_s < 5 or timeout_s > 600:
            raise ValueError("timeout_s must be between 5 and 600")
        if max_tokens < 256 or max_tokens > 32768:
            raise ValueError("max_tokens must be between 256 and 32768")
        expected_revision = payload.get("expected_revision")
        changed_slots: list[str] = []
        key_changed_slots: list[str] = []
        with self.database.session_factory.begin() as session:
            row = session.get(ModelConfiguration, "active", with_for_update=True)
            if row is None:
                row = ModelConfiguration(id="active", revision=0)
                session.add(row)
                session.flush()
            if expected_revision is not None and int(expected_revision) != row.revision:
                raise ValueError(f"model configuration revision conflict; current={row.revision}")
            for slot in ("primary", "fallback"):
                route = payload.get(slot)
                if not isinstance(route, dict):
                    raise ValueError(f"{slot} route is required")
                provider = str(route.get("provider", "")).strip()
                base_url = str(route.get("base_url", "")).strip().rstrip("/")
                model = str(route.get("model", "")).strip()
                api_style = str(route.get("api_style", "openai")).strip().lower()
                route_enabled = bool(route.get("enabled", True))
                if route_enabled and (not provider or not model or not base_url):
                    raise ValueError(f"{slot} provider, base_url and model are required when enabled")
                if base_url:
                    parsed_url = urlparse(base_url)
                    local_http = parsed_url.scheme == "http" and parsed_url.hostname in {
                        "localhost",
                        "127.0.0.1",
                    }
                    if parsed_url.scheme != "https" and not local_http:
                        raise ValueError(f"{slot} base_url must use HTTPS (localhost is allowed for development)")
                    if parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment:
                        raise ValueError(f"{slot} base_url must not contain credentials, query parameters, or fragments")
                if api_style not in {"openai", "openai-compatible", "chat-completions", "anthropic", "messages"}:
                    raise ValueError(f"unsupported {slot} api_style")
                prefix = f"{slot}_"
                setattr(row, f"{prefix}provider", provider)
                setattr(row, f"{prefix}base_url", base_url)
                setattr(row, f"{prefix}model", model)
                setattr(row, f"{prefix}api_style", api_style)
                setattr(row, f"{prefix}enabled", route_enabled)
                stream = bool(route.get("stream", True))
                supports_json_mode = bool(route.get("supports_json_mode", True))
                try:
                    temperature = float(route.get("temperature", 0.0))
                    top_p = float(route.get("top_p", 1.0))
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"{slot} temperature/top_p must be numeric") from exc
                if not 0.0 <= temperature <= 2.0:
                    raise ValueError(f"{slot} temperature must be between 0 and 2")
                if not 0.0 < top_p <= 1.0:
                    raise ValueError(f"{slot} top_p must be greater than 0 and at most 1")
                setattr(row, f"{prefix}stream", stream)
                setattr(row, f"{prefix}supports_json_mode", supports_json_mode)
                setattr(row, f"{prefix}temperature", temperature)
                setattr(row, f"{prefix}top_p", top_p)
                setattr(row, f"{prefix}disable_reasoning", bool(route.get("disable_reasoning", True)))
                secret = route.get("api_key")
                if bool(route.get("clear_api_key", False)):
                    setattr(row, f"{prefix}api_key_ciphertext", None)
                    key_changed_slots.append(slot)
                elif secret is not None and str(secret):
                    plaintext = secret.get_secret_value() if hasattr(secret, "get_secret_value") else str(secret)
                    setattr(row, f"{prefix}api_key_ciphertext", SecretCipher(key).encrypt(plaintext))
                    key_changed_slots.append(slot)
                changed_slots.append(slot)
            row.enabled = bool(payload.get("enabled", False))
            row.context_max_bytes = context_max_bytes
            row.timeout_s = timeout_s
            row.max_tokens = max_tokens
            row.revision += 1
            row.updated_by = actor
            row.updated_at = utcnow()
            revision = row.revision
            session.add(
                ModelConfigurationAudit(
                    revision=revision,
                    actor=actor,
                    changed_slots=changed_slots,
                    key_changed_slots=key_changed_slots,
                )
            )
        self.reload_model_configuration()
        return self.model_configuration_view() | {"revision": revision}

    def create_case(self, title: str, actor: str = "demo-analyst") -> CaseRecord:
        with self.database.session_factory.begin() as session:
            case = CaseRecord(title=title.strip() or "Untitled analysis")
            session.add(case)
            session.flush()
            self._audit(
                session,
                case_id=case.id,
                event_type="case.created",
                actor=actor,
                object_type="Case",
                object_id=case.id,
                payload={"title": case.title},
            )
            return case

    def archive_case(self, case_id: str, *, actor: str = "case-reviewer") -> dict[str, object]:
        """Archive a Case only after every Analysis Task has reached a terminal state."""
        with self.database.session_factory.begin() as session:
            case = session.get(CaseRecord, case_id)
            if case is None:
                raise LookupError(case_id)
            if case.status == "ARCHIVED":
                return {
                    "id": case.id,
                    "title": case.title,
                    "status": case.status,
                }
            active = session.scalar(
                select(AnalysisTask.id).where(
                    AnalysisTask.case_id == case_id,
                    AnalysisTask.lifecycle.not_in(["SUCCEEDED", "FAILED", "CANCELLED"]),
                )
            )
            if active:
                raise ValueError("Case cannot be archived while an Analysis Task is active")
            case.status = "ARCHIVED"
            self._audit(
                session,
                case_id=case.id,
                event_type="case.archived",
                actor=actor,
                object_type="Case",
                object_id=case.id,
                payload={"status": case.status},
            )
            return {"id": case.id, "title": case.title, "status": case.status}

    def analyze_submission(
        self,
        *,
        case_id: str,
        filename: str,
        content: bytes,
        background_context: str = "",
        background_context_input: BackgroundContextInput | None = None,
        selected_modules: list[str] | None = None,
        actor: str = "demo-analyst",
    ) -> SubmissionResult:
        queued, _ = self.create_submission_task(
            case_id=case_id,
            filename=filename,
            submitted_size=len(content),
            content=content,
            source_kind=("zip" if content.startswith((b"PK\x03\x04", b"PK\x05\x06")) else "file"),
            background_context=background_context,
            background_context_input=background_context_input,
            selected_modules=selected_modules,
            actor=actor,
        )
        return self.execute_submission_task(
            task_id=queued.task_id,
            actor=actor,
        )

    def analyze_blind_submission(
        self,
        *,
        case_id: str,
        filename: str,
        content: bytes,
        scorecard_version: str = "blind-v2",
        selected_modules: list[str] | None = None,
        actor: str = "blind-evaluator",
    ) -> SubmissionResult:
        """Run a reference-isolated static blind investigation.

        This path cannot receive a reference report, family label, gold anchor,
        or expected conclusion. It freezes only configuration and hashes of the
        static evidence actually visible to the Agent.
        """
        queued, _ = self.create_submission_task(
            case_id=case_id,
            filename=filename,
            submitted_size=len(content),
            content=content,
            source_kind=("zip" if content.startswith((b"PK\x03\x04", b"PK\x05\x06")) else "file"),
            selected_modules=selected_modules,
            actor=actor,
        )
        self.prepare_blind_run(queued.task_id, scorecard_version=scorecard_version, actor=actor)
        return self.execute_submission_task(task_id=queued.task_id, actor=actor)

    def prepare_blind_run(
        self,
        task_id: str,
        *,
        scorecard_version: str = "blind-v2",
        actor: str = "blind-evaluator",
    ) -> None:
        """Mark a queued task for the reference-isolated Blind v2 protocol."""
        if not scorecard_version or len(scorecard_version) > 120:
            raise ValueError("scorecard_version must contain between 1 and 120 characters")
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if task is None:
                raise LookupError(task_id)
            if task.lifecycle != TaskLifecycle.PENDING.value:
                raise ValueError("blind mode must be prepared before task execution")
            background = task.request_snapshot.get("background_context") or {}
            if isinstance(background, dict) and str(background.get("content", "")).strip():
                raise ValueError(
                    "reference-isolated blind runs cannot contain background context"
                )
            task.strategy_snapshot = {
                **(task.strategy_snapshot or {}),
                "blind_run": {
                    "enabled": True,
                    "scorecard_version": scorecard_version,
                    "reference_isolated": True,
                    "status": "PREPARED",
                },
            }
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="blind_run.prepared",
                actor=actor,
                object_type="AnalysisTask",
                object_id=task.id,
                payload={"scorecard_version": scorecard_version, "reference_isolated": True},
            )

    def _freeze_blind_run_snapshot(self, task_id: str) -> str:
        """Persist the immutable v2 manifest immediately before the first blind model turn."""
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if task is None:
                raise LookupError(task_id)
            configured = dict((task.strategy_snapshot or {}).get("blind_run", {}))
            if not configured.get("enabled") or not configured.get("reference_isolated"):
                raise ValueError("task is not prepared for a reference-isolated blind run")
            existing = session.scalar(
                select(BlindRun)
                .where(BlindRun.task_id == task_id)
                .order_by(BlindRun.created_at, BlindRun.id)
            )
            if existing is not None:
                return existing.id
            evidence_rows = list(
                session.scalars(
                    select(Evidence)
                    .where(Evidence.task_id == task_id)
                    .order_by(Evidence.created_at, Evidence.id)
                    .limit(512)
                )
            )
            tool_rows = list(
                session.scalars(
                    select(ToolRun)
                    .where(ToolRun.task_id == task_id)
                    .order_by(ToolRun.tool_name, ToolRun.tool_version, ToolRun.id)
                )
            )
            initial_evidence = [
                {
                    "evidence_id": item.id,
                    "artifact_id": item.artifact_id,
                    "kind": item.kind,
                    "nature": item.nature,
                    "value_sha256": hashlib.sha256(
                        json.dumps(item.value, ensure_ascii=True, sort_keys=True, default=str).encode("utf-8")
                    ).hexdigest(),
                    "anchor_sha256": hashlib.sha256(
                        json.dumps(item.anchor, ensure_ascii=True, sort_keys=True, default=str).encode("utf-8")
                    ).hexdigest(),
                }
                for item in evidence_rows
            ]
            prompt_descriptors = [
                {
                    "id": prompt.id,
                    "version": prompt.version,
                    "sha256": prompt.sha256,
                }
                for prompt in (
                    self.prompts.require("analysis-planner-agent", "1.0.0"),
                    self.prompts.require("static-analysis-agent", "1.0.0"),
                )
            ]
            snapshot = {
                "blind_protocol": "blind-v2",
                "reference_isolated": True,
                "scorecard_version": str(configured["scorecard_version"]),
                "model_configuration": {
                    "revision": self.model_config_revision,
                    "primary": self._model_route_metadata(self.settings.primary_model),
                    "fallback": self._model_route_metadata(self.settings.fallback_model),
                    "timeout_s": self.settings.model_timeout_s,
                    "max_tokens": self.settings.model_max_tokens,
                    "context_max_bytes": self.settings.model_context_max_bytes,
                },
                "prompts": prompt_descriptors,
                "policy": {
                    "version": self.policy.policy_version,
                    "catalog_digest": self.policy.catalog_digest,
                    "action_catalog": list(ActionCatalog.default().names()),
                    "playbook_digest": MechanismPlaybookRegistry().digest,
                },
                "knowledge": {
                    "fact_library_sha256": REFERENCE_ISOLATED_FACT_LIBRARY.sha256,
                    "fact_library_source": REFERENCE_ISOLATED_FACT_LIBRARY.source,
                },
                "retrieval": {
                    "repository_version": BoundedEvidenceRepository.version,
                    "context_builder_version": "question-centric-retriever-v2",
                    "evidence_schema_version": "evidence-v2",
                },
                "tools": [
                    {"name": item.tool_name, "version": item.tool_version, "status": item.status}
                    for item in tool_rows
                ],
                "initial_evidence": initial_evidence,
            }
            serialized = json.dumps(snapshot, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            blind_run = BlindRun(
                task_id=task_id,
                status="FROZEN",
                snapshot=snapshot,
                snapshot_sha256=hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
            )
            session.add(blind_run)
            session.flush()
            task.strategy_snapshot = {
                **(task.strategy_snapshot or {}),
                "blind_run": {
                    **configured,
                    "status": "FROZEN",
                    "blind_run_id": blind_run.id,
                    "snapshot_sha256": blind_run.snapshot_sha256,
                },
            }
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="blind_run.frozen",
                actor="blind-runner",
                object_type="BlindRun",
                object_id=blind_run.id,
                payload={
                    "scorecard_version": configured["scorecard_version"],
                    "snapshot_sha256": blind_run.snapshot_sha256,
                    "initial_evidence_count": len(initial_evidence),
                    "reference_isolated": True,
                },
            )
            return blind_run.id

    def create_submission_task(
        self,
        *,
        case_id: str,
        filename: str,
        submitted_size: int,
        content: bytes | None = None,
        source_kind: str = "file",
        background_context: str = "",
        background_context_input: BackgroundContextInput | None = None,
        selected_modules: list[str] | None = None,
        idempotency_key: str | None = None,
        trace_id: str | None = None,
        actor: str = "demo-analyst",
    ) -> tuple[SubmissionResult, bool]:
        modules = normalize_modules(selected_modules)
        if content is not None and submitted_size != len(content):
            raise ValueError("submitted_size must match the submitted content")
        content_sha256 = hashlib.sha256(content).hexdigest() if content is not None else None
        normalized_key = idempotency_key.strip() if idempotency_key else None
        if normalized_key is not None and not 1 <= len(normalized_key) <= 200:
            raise ValueError("Idempotency-Key must contain between 1 and 200 characters")
        with self.database.session_factory.begin() as session:
            case = session.get(CaseRecord, case_id)
            if case is None:
                raise LookupError(f"Case {case_id} does not exist")
            if normalized_key is not None:
                existing = session.scalar(
                    select(AnalysisTask).where(
                        AnalysisTask.case_id == case_id,
                        AnalysisTask.submission_key == normalized_key,
                    )
                )
                if existing is not None:
                    existing_sha256 = existing.request_snapshot.get("sample_package", {}).get(
                        "content_sha256"
                    )
                    if (
                        content_sha256 is not None
                        and existing_sha256 is not None
                        and content_sha256 != existing_sha256
                    ):
                        raise ValueError(
                            "Idempotency-Key is already bound to different sample content"
                        )
                    return (
                        SubmissionResult(
                            case_id,
                            existing.id,
                            existing.lifecycle,
                            existing.outcome,
                            None,
                        ),
                        False,
                    )
            stored_submission = self.content_store.put(content) if content is not None else None
            if stored_submission is not None and stored_submission.sha256 != content_sha256:
                raise RuntimeError("Content store returned an unexpected SHA-256")
            is_container_scope = source_kind in {"zip", "local_folder"} or (
                content is not None and zipfile.is_zipfile(io.BytesIO(content))
            )
            preset_id = (
                "first-phase-full-static" if is_container_scope else "single-sample-static-deep"
            )
            target_breadth = "B1" if is_container_scope else "B0"
            target_depth = "D2" if is_container_scope else "D3"
            manifest = FourChannelInput(
                task_request=TaskRequestInput(
                    preset_id=preset_id,
                    target_breadth=target_breadth,
                    target_depth=target_depth,
                    selected_report_modules=tuple(modules),
                ),
                sample_package=SamplePackageInput(
                    source_kind=source_kind,
                    display_name=filename,
                    submitted_size=submitted_size,
                    content_sha256=content_sha256,
                    storage_key=(
                        stored_submission.storage_key if stored_submission is not None else None
                    ),
                ),
                background_context=(
                    background_context_input or BackgroundContextInput(content=background_context)
                ),
                knowledge_snapshot=KnowledgeSnapshotInput(snapshot_id="phase1-static-rules-v1"),
            )
            task = AnalysisTask(
                case_id=case_id,
                trace_id=trace_id or new_id(),
                submission_key=normalized_key,
                lifecycle="PENDING",
                target_breadth=target_breadth,
                target_depth=target_depth,
                selected_modules=modules,
                request_snapshot=manifest.model_dump(mode="json"),
            )
            session.add(task)
            session.flush()
            task_id = task.id
            self._audit(
                session,
                case_id=case_id,
                task_id=task_id,
                event_type="analysis_task.created",
                actor=actor,
                object_type="AnalysisTask",
                object_id=task_id,
                payload={
                    "selected_report_modules": modules,
                    "input_sha256": content_sha256,
                },
            )
            return SubmissionResult(case_id, task_id, task.lifecycle, None, None), True

    def execute_submission_task(
        self,
        *,
        task_id: str,
        filename: str | None = None,
        content: bytes | None = None,
        actor: str = "demo-analyst",
    ) -> SubmissionResult:
        with self.database.session_factory() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if task is None:
                raise LookupError(task_id)
            case_id = task.case_id
            trace_id = task.trace_id
            modules = list(task.selected_modules)
            sample_package = dict(task.request_snapshot.get("sample_package", {}))
            if task.lifecycle != TaskLifecycle.PENDING.value:
                return SubmissionResult(
                    case_id,
                    task_id,
                    task.lifecycle,
                    task.outcome,
                    None,
                )
        snapshot_filename = sample_package.get("display_name")
        if filename is None:
            filename = str(snapshot_filename or "sample.bin")
        elif snapshot_filename is not None and filename != snapshot_filename:
            raise ValueError("filename must match the frozen sample package")
        expected_sha256 = sample_package.get("content_sha256")
        if content is None:
            storage_key = sample_package.get("storage_key")
            if not isinstance(storage_key, str) or not storage_key:
                raise ValueError("Task does not contain a replayable sample storage reference")
            content = self.content_store.read(storage_key)
        if (
            isinstance(expected_sha256, str)
            and hashlib.sha256(content).hexdigest() != expected_sha256
        ):
            raise ValueError("Submitted content does not match the frozen sample package")
        try:
            stored_input = self.content_store.put(content)
            try:
                if self.settings.tool_execution_mode == "temporal":
                    entries, intake_execution = self._execute_intake_tool(
                        task_id,
                        filename,
                        content,
                        case_id=case_id,
                        trace_id=trace_id,
                    )
                    intake_executions = [intake_execution]
                else:
                    entries = expand_submission(
                        filename,
                        content,
                        max_files=self.settings.max_sample_files,
                        max_bytes=self.settings.max_sample_bytes,
                        max_depth=self.settings.max_archive_depth,
                    )
                    intake_executions = []
            except IntakeGateRequired as exc:
                exc.context.update(
                    {
                        "input_sha256": stored_input.sha256,
                        "input_storage_key": stored_input.storage_key,
                        "logical_path": filename,
                    }
                )
                return self._open_intake_gate(case_id, task_id, exc, actor)
            return self._run_analysis_with_repair(
                case_id,
                task_id,
                entries,
                modules,
                actor,
                intake_executions,
            )
        except Exception as exc:
            with self.database.session_factory.begin() as session:
                task = session.get(AnalysisTask, task_id)
                if task is not None:
                    if task.lifecycle == TaskLifecycle.CANCELLED.value:
                        return SubmissionResult(case_id, task_id, task.lifecycle, None, None)
                    task.lifecycle = transition_task(task.lifecycle, TaskLifecycle.FAILED).value
                    task.analysis_class = "FAILED_ANALYSIS"
                    task.outcome = None
                    task.finished_at = utcnow()
                    failure_event = self._audit(
                        session,
                        case_id=case_id,
                        task_id=task_id,
                        event_type="analysis_task.failed",
                        actor="system",
                        object_type="AnalysisTask",
                        object_id=task_id,
                        payload={"error_type": type(exc).__name__, "message": str(exc)},
                    )
                    self._record_analysis_failure(
                        session, task, exc, stage="INTAKE_OR_ANALYSIS", event_id=failure_event.id
                    )
                    self._seal_task_audit_chain(session, task, "analysis_task.failed")
            raise

    def analyze_directory(
        self,
        *,
        case_id: str,
        directory: str | Path,
        background_context: str = "",
        selected_modules: list[str] | None = None,
        actor: str = "demo-analyst",
    ) -> SubmissionResult:
        modules = normalize_modules(selected_modules)
        root = Path(directory).resolve()
        manifest = FourChannelInput(
            task_request=TaskRequestInput(
                preset_id="first-phase-full-static",
                target_breadth="B1",
                target_depth="D2",
                selected_report_modules=tuple(modules),
            ),
            sample_package=SamplePackageInput(
                source_kind="local_folder",
                display_name=root.name,
            ),
            background_context=BackgroundContextInput(content=background_context),
            knowledge_snapshot=KnowledgeSnapshotInput(snapshot_id="phase1-static-rules-v1"),
        )
        with self.database.session_factory.begin() as session:
            case = session.get(CaseRecord, case_id)
            if case is None:
                raise LookupError(f"Case {case_id} does not exist")
            task = AnalysisTask(
                case_id=case_id,
                lifecycle="PENDING",
                target_breadth="B1",
                target_depth="D2",
                selected_modules=modules,
                request_snapshot=manifest.model_dump(mode="json"),
            )
            session.add(task)
            session.flush()
            task_id = task.id
            self._audit(
                session,
                case_id=case_id,
                task_id=task_id,
                event_type="analysis_task.created",
                actor=actor,
                object_type="AnalysisTask",
                object_id=task_id,
                payload={
                    "selected_report_modules": modules,
                    "source_kind": "local_folder",
                },
            )
        submitted_entries: list[PackageEntry] = []
        try:
            submitted_entries = expand_directory(
                root,
                max_files=self.settings.max_sample_files,
                max_bytes=self.settings.max_sample_bytes,
                max_depth=self.settings.max_archive_depth,
                expand_archives=False,
            )
            if self.settings.tool_execution_mode == "temporal":
                # Preflight the complete directory before any Worker writes extracted objects.
                expand_directory(
                    root,
                    max_files=self.settings.max_sample_files,
                    max_bytes=self.settings.max_sample_bytes,
                    max_depth=self.settings.max_archive_depth,
                    expand_archives=True,
                )
                entries = []
                intake_executions = []
                for submitted in submitted_entries:
                    expanded, execution = self._execute_intake_tool(
                        task_id,
                        submitted.logical_path,
                        submitted.content,
                        case_id=case_id,
                        trace_id=task.trace_id,
                        root_logical_path=submitted.logical_path,
                    )
                    entries.extend(expanded)
                    intake_executions.append(execution)
                if len(entries) > self.settings.max_sample_files:
                    raise IntakeGateRequired(
                        "Expanded sample folder exceeds the configured file count",
                        {"max_files": self.settings.max_sample_files},
                    )
                if sum(entry.size for entry in entries) > self.settings.max_sample_bytes:
                    raise IntakeGateRequired(
                        "Expanded sample folder exceeds the configured size limit",
                        {"max_bytes": self.settings.max_sample_bytes},
                    )
            else:
                entries = expand_directory_entries(
                    submitted_entries,
                    max_files=self.settings.max_sample_files,
                    max_bytes=self.settings.max_sample_bytes,
                    max_depth=self.settings.max_archive_depth,
                )
                intake_executions = []
        except IntakeGateRequired as exc:
            if submitted_entries:
                exc.context["directory_manifest"] = self._persist_directory_manifest(
                    submitted_entries
                )
            return self._open_intake_gate(case_id, task_id, exc, actor)
        try:
            return self._run_analysis_with_repair(
                case_id,
                task_id,
                entries,
                modules,
                actor,
                intake_executions,
            )
        except Exception as exc:
            with self.database.session_factory.begin() as session:
                task = session.get(AnalysisTask, task_id)
                if task is not None:
                    task.lifecycle = transition_task(task.lifecycle, TaskLifecycle.FAILED).value
                    task.analysis_class = "FAILED_ANALYSIS"
                    task.finished_at = utcnow()
                    failure_event = self._audit(
                        session,
                        case_id=case_id,
                        task_id=task_id,
                        event_type="analysis_task.failed",
                        actor="system",
                        object_type="AnalysisTask",
                        object_id=task_id,
                        payload={"error_type": type(exc).__name__, "message": str(exc)},
                    )
                    self._record_analysis_failure(
                        session, task, exc, stage="DIRECTORY_ANALYSIS", event_id=failure_event.id
                    )
                    self._seal_task_audit_chain(session, task, "analysis_task.failed")
            raise

    def _execute_intake_tool(
        self,
        task_id: str,
        filename: str,
        content: bytes,
        *,
        case_id: str,
        trace_id: str,
        root_logical_path: str | None = None,
        archive_secret_id: str | None = None,
    ) -> tuple[list[PackageEntry], IntakeExecution]:
        stored = self.content_store.put(content)
        parameters: dict[str, object] = {
            "max_files": self.settings.max_sample_files,
            "max_bytes": self.settings.max_sample_bytes,
            "max_depth": self.settings.max_archive_depth,
        }
        if root_logical_path:
            parameters["root_logical_path"] = root_logical_path
        if archive_secret_id:
            parameters["archive_secret_id"] = archive_secret_id
        request = ToolRunRequest(
            case_id=case_id,
            task_id=task_id,
            trace_id=trace_id,
            artifact_id=None,
            tool_run_id=new_id(),
            tool_name="python-zipfile-safe-reader",
            tool_version="3.12",
            content_sha256=stored.sha256,
            storage_key=stored.storage_key,
            logical_path=filename,
            parameters=parameters,
            max_cpu_seconds=60,
            max_memory_mb=512,
            task_queue=self.settings.task_queue_for("python-zipfile-safe-reader"),
        )
        started_at = utcnow()
        result = asyncio.run(TemporalToolExecutor(self.settings.temporal_address).execute(request))
        result = result.model_copy(
            update={
                "started_at": result.started_at or started_at,
                "finished_at": result.finished_at or utcnow(),
                "worker_metadata": {
                    **result.worker_metadata,
                    "case_id": case_id,
                    "trace_id": trace_id,
                    "tool_run_id": request.tool_run_id,
                },
            }
        )
        if not result.output_storage_key:
            raise RuntimeError(result.error or "Temporal intake failed without output")
        payload = json.loads(self.content_store.read(result.output_storage_key))
        try:
            entries = intake_entries_from_payload(payload)
        except IntakeGateRequired as exc:
            exc.context.update(
                {
                    "output_sha256": result.output_sha256,
                    "output_storage_key": result.output_storage_key,
                    "workflow_id": result.worker_metadata.get("workflow_id"),
                    "input_sha256": stored.sha256,
                    "input_storage_key": stored.storage_key,
                    "logical_path": filename,
                }
            )
            raise
        execution = IntakeExecution(
            root_logical_path=entries[0].logical_path,
            entry_paths=tuple(entry.logical_path for entry in entries),
            result=result,
        )
        return entries, execution

    def _persist_directory_manifest(
        self,
        entries: list[PackageEntry],
    ) -> list[dict[str, object]]:
        manifest: list[dict[str, object]] = []
        for entry in entries:
            stored = self.content_store.put(entry.content)
            manifest.append(
                {
                    "logical_path": entry.logical_path,
                    "content_sha256": stored.sha256,
                    "storage_key": stored.storage_key,
                    "size": stored.size,
                }
            )
        return manifest

    def _restore_directory_manifest(
        self,
        manifest: object,
    ) -> list[PackageEntry]:
        if not isinstance(manifest, list) or not manifest:
            raise ValueError("Directory Gate manifest is missing")
        entries: list[PackageEntry] = []
        for item in manifest:
            if not isinstance(item, dict):
                raise ValueError("Directory Gate manifest entry is invalid")
            logical_path = item.get("logical_path")
            storage_key = item.get("storage_key")
            if not isinstance(logical_path, str) or not logical_path:
                raise ValueError("Directory Gate manifest path is invalid")
            if not isinstance(storage_key, str) or not storage_key:
                raise ValueError("Directory Gate manifest object reference is invalid")
            content = self.content_store.read(storage_key)
            expected_sha256 = item.get("content_sha256")
            if (
                isinstance(expected_sha256, str)
                and hashlib.sha256(content).hexdigest() != expected_sha256
            ):
                raise ValueError("Directory Gate manifest content hash mismatch")
            entries.append(
                PackageEntry(
                    logical_path=logical_path,
                    content=content,
                    parent_path=None,
                    discovery="submitted_folder",
                )
            )
        return entries

    def _open_intake_gate(
        self,
        case_id: str,
        task_id: str,
        exc: IntakeGateRequired,
        actor: str,
    ) -> SubmissionResult:
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if task is None:
                raise LookupError(task_id)
            gate = GateRecord(
                task_id=task_id,
                gate_type="INPUT_REVIEW",
                reason=exc.reason,
                context=exc.context,
            )
            session.add(gate)
            session.flush()
            task.lifecycle = transition_task(task.lifecycle, TaskLifecycle.WAITING_GATE).value
            self._audit(
                session,
                case_id=case_id,
                task_id=task_id,
                event_type="gate.opened",
                actor=actor,
                object_type="Gate",
                object_id=gate.id,
                payload={"gate_type": gate.gate_type, "reason": gate.reason},
            )
            return SubmissionResult(case_id, task_id, task.lifecycle, None, None, gate.id)

    def decide_input_gate(
        self,
        gate_id: str,
        *,
        decision: str,
        archive_password: str | None = None,
        actor: str = "demo-reviewer",
        note: str = "",
    ) -> dict[str, object]:
        normalized_decision = decision.upper()
        if normalized_decision not in {"APPROVE", "REJECT"}:
            raise ValueError("Gate decision must be APPROVE or REJECT")
        with self.database.session_factory.begin() as session:
            gate = session.get(GateRecord, gate_id)
            if gate is None:
                raise LookupError(gate_id)
            task = session.get(AnalysisTask, gate.task_id)
            if task is None:
                raise LookupError(gate.task_id)
            if gate.status != "PENDING":
                raise ValueError(f"Gate {gate_id} is already decided: {gate.status}")
            if task.lifecycle != TaskLifecycle.WAITING_GATE.value:
                raise ValueError(f"Task {task.id} is not waiting for an input Gate")
            if normalized_decision == "REJECT":
                gate.status = "REJECTED"
                gate.decided_by = actor
                gate.decision_note = note
                gate.decided_at = utcnow()
                task.lifecycle = transition_task(task.lifecycle, TaskLifecycle.CANCELLED).value
                task.finished_at = utcnow()
                self._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type="gate.rejected",
                    actor=actor,
                    object_type="Gate",
                    object_id=gate.id,
                    payload={"gate_type": gate.gate_type, "note": note},
                )
                self._seal_task_audit_chain(session, task, "gate.rejected")
                task_id = task.id
                rejected = True
                secret_id = None
                context: dict[str, object] = {}
                modules: list[str] = []
                case_id = task.case_id
                trace_id = task.trace_id
            else:
                if not archive_password:
                    raise ValueError("archive_password is required to approve this input Gate")
                secret = TaskSecret(
                    task_id=task.id,
                    secret_type="ARCHIVE_PASSWORD",
                    ciphertext=SecretCipher(self.settings.gate_secret_key).encrypt(
                        archive_password
                    ),
                )
                session.add(secret)
                session.flush()
                secret_id = secret.id
                gate.status = "APPROVED"
                gate.decided_by = actor
                gate.decision_note = note
                gate.decided_at = utcnow()
                task.lifecycle = transition_task(task.lifecycle, TaskLifecycle.RUNNING).value
                task.started_at = task.started_at or utcnow()
                self._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type="gate.approved",
                    actor=actor,
                    object_type="Gate",
                    object_id=gate.id,
                    payload={
                        "gate_type": gate.gate_type,
                        "secret_provided": True,
                        "note": note,
                    },
                )
                task_id = task.id
                rejected = False
                context = dict(gate.context)
                modules = list(task.selected_modules)
                case_id = task.case_id
                trace_id = task.trace_id

        if rejected:
            return self.task_view(task_id)
        try:
            directory_manifest = context.get("directory_manifest")
            if isinstance(directory_manifest, list) and directory_manifest:
                roots = self._restore_directory_manifest(directory_manifest)
                password = SecretCipher(self.settings.gate_secret_key).decrypt(
                    self._task_secret_ciphertext(secret_id)
                )
                preflight_entries = expand_directory_entries(
                    roots,
                    max_files=self.settings.max_sample_files,
                    max_bytes=self.settings.max_sample_bytes,
                    max_depth=self.settings.max_archive_depth,
                    archive_password=password,
                )
                if self.settings.tool_execution_mode == "temporal":
                    entries = []
                    intake_executions = []
                    for root_entry in roots:
                        expanded, execution = self._execute_intake_tool(
                            task_id,
                            root_entry.logical_path,
                            root_entry.content,
                            case_id=case_id,
                            trace_id=trace_id,
                            root_logical_path=root_entry.logical_path,
                            archive_secret_id=secret_id,
                        )
                        entries.extend(expanded)
                        intake_executions.append(execution)
                    if len(entries) > self.settings.max_sample_files:
                        raise IntakeGateRequired(
                            "Expanded sample folder exceeds the configured file count",
                            {"max_files": self.settings.max_sample_files},
                        )
                    if sum(entry.size for entry in entries) > self.settings.max_sample_bytes:
                        raise IntakeGateRequired(
                            "Expanded sample folder exceeds the configured size limit",
                            {"max_bytes": self.settings.max_sample_bytes},
                        )
                else:
                    entries = preflight_entries
                    self._mark_task_secret_consumed(secret_id)
                    intake_executions = []
            else:
                storage_key = str(context.get("input_storage_key", ""))
                logical_path = str(context.get("logical_path", "sample.zip"))
                if not storage_key:
                    raise ValueError(
                        "Input Gate cannot resume because its input reference is missing"
                    )
                content = self.content_store.read(storage_key)
                if self.settings.tool_execution_mode == "temporal":
                    entries, execution = self._execute_intake_tool(
                        task_id,
                        logical_path,
                        content,
                        case_id=case_id,
                        trace_id=trace_id,
                        archive_secret_id=secret_id,
                    )
                    intake_executions = [execution]
                else:
                    password = SecretCipher(self.settings.gate_secret_key).decrypt(
                        self._task_secret_ciphertext(secret_id)
                    )
                    entries = expand_submission(
                        logical_path,
                        content,
                        max_files=self.settings.max_sample_files,
                        max_bytes=self.settings.max_sample_bytes,
                        max_depth=self.settings.max_archive_depth,
                        archive_password=password,
                    )
                    self._mark_task_secret_consumed(secret_id)
                    intake_executions = []
            self._run_analysis_with_repair(
                case_id,
                task_id,
                entries,
                modules,
                actor,
                intake_executions,
            )
        except IntakeGateRequired as exc:
            self._restore_input_gate_after_failed_approval(
                gate_id,
                task_id,
                secret_id,
                exc,
                actor,
            )
            raise
        except Exception as exc:
            self._fail_input_gate_resume(task_id, secret_id, exc)
            raise
        return self.task_view(task_id)

    def _restore_input_gate_after_failed_approval(
        self,
        gate_id: str,
        task_id: str,
        secret_id: str,
        exc: IntakeGateRequired,
        actor: str,
    ) -> None:
        with self.database.session_factory.begin() as session:
            gate = session.get(GateRecord, gate_id)
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            secret = session.get(TaskSecret, secret_id)
            if gate is None or task is None:
                raise LookupError(gate_id)
            if secret is not None:
                secret.consumed_at = secret.consumed_at or utcnow()
            gate.status = "PENDING"
            gate.reason = exc.reason
            gate.context = {**gate.context, **exc.context}
            gate.decided_by = None
            gate.decision_note = None
            gate.decided_at = None
            task.lifecycle = transition_task(task.lifecycle, TaskLifecycle.WAITING_GATE).value
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="gate.approval_failed",
                actor=actor,
                object_type="Gate",
                object_id=gate.id,
                payload={
                    "gate_type": gate.gate_type,
                    "reason": exc.reason,
                    "secret_consumed": True,
                },
            )

    def _fail_input_gate_resume(
        self,
        task_id: str,
        secret_id: str,
        exc: Exception,
    ) -> None:
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            secret = session.get(TaskSecret, secret_id)
            if secret is not None:
                secret.consumed_at = secret.consumed_at or utcnow()
            if task is None or task.lifecycle == TaskLifecycle.CANCELLED.value:
                return
            task.lifecycle = transition_task(task.lifecycle, TaskLifecycle.FAILED).value
            task.analysis_class = "FAILED_ANALYSIS"
            task.outcome = None
            task.finished_at = utcnow()
            failure_event = self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="analysis_task.failed",
                actor="system",
                object_type="AnalysisTask",
                object_id=task.id,
                payload={"error_type": type(exc).__name__, "message": str(exc)},
            )
            self._record_analysis_failure(
                session, task, exc, stage="GATE_RESUME", event_id=failure_event.id
            )
            self._seal_task_audit_chain(session, task, "analysis_task.failed")

    def _task_secret_ciphertext(self, secret_id: str) -> str:
        with self.database.session_factory() as session:
            secret = session.get(TaskSecret, secret_id)
            if secret is None:
                raise LookupError(secret_id)
            return secret.ciphertext

    def _mark_task_secret_consumed(self, secret_id: str) -> None:
        with self.database.session_factory.begin() as session:
            secret = session.get(TaskSecret, secret_id)
            if secret is not None:
                secret.consumed_at = utcnow()

    def _run_analysis(
        self,
        case_id: str,
        task_id: str,
        entries: list[PackageEntry],
        modules: list[str],
        actor: str,
        intake_executions: list[IntakeExecution],
    ) -> SubmissionResult:
        with self.database.session_factory.begin() as session:
            case = session.get(CaseRecord, case_id)
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if case is None or task is None:
                raise LookupError(task_id)
            if task.lifecycle == TaskLifecycle.PENDING.value:
                task.lifecycle = transition_task(task.lifecycle, TaskLifecycle.RUNNING).value
            elif task.lifecycle != TaskLifecycle.RUNNING.value:
                raise ValueError(f"Task {task.id} cannot start from {task.lifecycle}")
            task.started_at = task.started_at or utcnow()
            blind_configuration = dict((task.strategy_snapshot or {}).get("blind_run", {}))
            blind_enabled = bool(
                blind_configuration.get("enabled")
                and blind_configuration.get("reference_isolated")
            )
            artifacts, entry_by_artifact = self._register_artifacts(session, task, entries)
            self._record_background_evidence(session, task, artifacts[0])
            plan = self.orchestrator.plan(
                FourChannelInput.model_validate(task.request_snapshot),
                target_artifact_id=artifacts[0].id,
            )
            preset = self.policy.require_preset(task.request_snapshot["task_request"]["preset_id"])
            prompt_versions = {
                prompt_id: "1.0.0" for prompt_id in ("static-analysis-agent", "triage-agent")
            }
            if self.settings.model_calls_enabled and self.settings.environment.lower() != "test":
                prompt_versions["analysis-planner-agent"] = "1.0.0"
            task.strategy_snapshot = {
                "preset": {
                    "id": preset.id,
                    "version": preset.version,
                    "catalog_digest": plan.preset_catalog_digest,
                },
                "tool_policy_version": self.policy.policy_version,
                "prompt_versions": prompt_versions,
                "agent_metadata": {
                    "triage": self.triage_agent.metadata,
                    "static_analysis": self.static_agent.metadata,
                },
                "model_gateway": {
                    "config_revision": self.model_config_revision,
                    "enabled": self.settings.model_calls_enabled,
                    "agent_mode": (
                        "deterministic_static_agent"
                        if not self.settings.model_calls_enabled
                        else (
                            "model_agent_with_deterministic_fallback"
                            if (
                                self.settings.primary_model.configured
                                or self.settings.fallback_model.configured
                            )
                            else "model_agent_unconfigured_fallback"
                        )
                    ),
                    "primary": self._model_route_metadata(self.settings.primary_model),
                    "fallback": self._model_route_metadata(self.settings.fallback_model),
                    "interface": "unified-model-gateway",
                    "structured_output": "atomic-claim-envelope-v1",
                    "context_max_bytes": self.settings.model_context_max_bytes,
                },
                "orchestration_stages": list(plan.stages),
                "analysis_modules": list(plan.analysis_modules),
                "action_proposals": [
                    proposal.model_dump(mode="json") for proposal in plan.action_proposals
                ],
                "policy_decisions": [
                    decision.model_dump(mode="json") for decision in plan.policy_decisions
                ],
                "investigation": {
                    "state_model": [
                        "DISCOVERED", "PRIORITIZED", "CONTEXT_READY", "HYPOTHESIZING",
                        "INVESTIGATING", "VERIFYING", "MECHANISM_READY", "CLAIM_READY",
                        "UNKNOWN", "BLOCKED", "REJECTED", "CONTRADICTED", "CLOSED",
                    ],
                    "threads": [item.model_dump(mode="json") for item in plan.investigation_threads],
                    "hypotheses": [item.model_dump(mode="json") for item in plan.hypotheses],
                    "mechanisms": [item.model_dump(mode="json") for item in plan.mechanisms],
                    "seed_rankings": list(plan.seed_rankings),
                    "context_policy": {
                        "builder": "question-centric",
                        "max_bytes": self.settings.model_context_max_bytes,
                        "private_chain_of_thought": False,
                    },
                },
                **({"blind_run": blind_configuration} if blind_enabled else {}),
            }
            ranked_seeds = DeterministicSeedRanker().rank(
                [
                    {
                        "artifact_id": item.id,
                        "detected_type": item.detected_type,
                        "evidence_kinds": (),
                    }
                    for item in artifacts
                ]
            )
            investigation_snapshot = dict(task.strategy_snapshot.get("investigation", {}))
            existing_threads = list(investigation_snapshot.get("threads", []))
            existing_ids = {
                str(item.get("artifact_id"))
                for item in existing_threads
                if isinstance(item, dict)
            }
            for seed in ranked_seeds:
                if seed.artifact_id in existing_ids:
                    continue
                thread_id = "thread-" + hashlib.sha256(
                    f"{task.id}:{seed.artifact_id}".encode("utf-8")
                ).hexdigest()[:20]
                hypothesis_id = "hypothesis-" + hashlib.sha256(
                    f"{thread_id}:mechanism".encode("utf-8")
                ).hexdigest()[:20]
                mechanism_id = "mechanism-" + hashlib.sha256(
                    f"{thread_id}:static".encode("utf-8")
                ).hexdigest()[:20]
                artifact_type = next(
                    (str(item.detected_type) for item in artifacts if item.id == seed.artifact_id),
                    "unknown",
                )
                atomic_questions = QuestionCompiler().compile(
                    "", artifact_id=seed.artifact_id, detected_type=artifact_type
                )
                primary_question = atomic_questions[0]
                existing_threads.append(
                    {
                        "id": thread_id,
                        "artifact_id": seed.artifact_id,
                        "state": "PRIORITIZED",
                        "question": primary_question.question,
                        "seed_kind": primary_question.thread_type,
                        "evidence_ids": [],
                        "hypothesis_ids": [hypothesis_id],
                        "mechanism_ids": [mechanism_id],
                        "action_ids": [],
                        "required_evidence_kinds": list(primary_question.required_evidence_kinds),
                        "success_requirements": list(primary_question.success_requirements),
                        "stop_conditions": list(primary_question.stop_conditions),
                    }
                )
                investigation_snapshot.setdefault("hypotheses", []).append(
                    {
                        "id": hypothesis_id,
                        "thread_id": thread_id,
                        "statement": "The artifact contains a recoverable static mechanism.",
                        "dimension": "mechanism_discovery",
                        "evidence_ids": [],
                        "confidence": "LOW",
                        "status": "OPEN",
                    }
                )
                investigation_snapshot.setdefault("mechanisms", []).append(
                    {
                        "id": mechanism_id,
                        "thread_id": thread_id,
                        "dimension": "static_mechanism",
                        "steps": [],
                        "evidence_ids": [],
                        "status": "UNKNOWN",
                        "limitations": ["No runtime execution or network access is permitted in this phase."],
                        "type": primary_question.thread_type,
                    }
                )
                existing_ids.add(seed.artifact_id)
            investigation_snapshot["threads"] = existing_threads
            task.strategy_snapshot = {
                **task.strategy_snapshot,
                "investigation": {
                    **investigation_snapshot,
                    "seed_rankings": [
                        {
                            "artifact_id": seed.artifact_id,
                            "priority": seed.priority,
                            "seed_kind": QuestionCompiler().compile(
                                "", artifact_id=seed.artifact_id,
                                detected_type=next(
                                    (str(item.detected_type) for item in artifacts if item.id == seed.artifact_id),
                                    "unknown",
                                ),
                            )[0].thread_type,
                            "question": QuestionCompiler().compile(
                                "", artifact_id=seed.artifact_id,
                                detected_type=next(
                                    (str(item.detected_type) for item in artifacts if item.id == seed.artifact_id),
                                    "unknown",
                                ),
                            )[0].question,
                            "rationale": seed.rationale,
                            "expected_tools": list(seed.expected_tools),
                            "required_evidence_kinds": list(QuestionCompiler().compile(
                                "", artifact_id=seed.artifact_id,
                                detected_type=next(
                                    (str(item.detected_type) for item in artifacts if item.id == seed.artifact_id),
                                    "unknown",
                                ),
                            )[0].required_evidence_kinds),
                        }
                        for seed in ranked_seeds
                    ],
                },
            }
            self._audit(
                session,
                case_id=case_id,
                task_id=task_id,
                event_type="orchestration.plan_created",
                actor="system",
                object_type="AnalysisTask",
                object_id=task_id,
                payload={
                    "preset_id": preset.id,
                    "catalog_digest": plan.preset_catalog_digest,
                    "stages": list(plan.stages),
                },
            )
            for thread in plan.investigation_threads:
                self._audit(
                    session,
                    case_id=case_id,
                    task_id=task_id,
                    event_type="investigation.thread_seeded",
                    actor="deterministic-seed-ranker",
                    object_type="InvestigationThread",
                    object_id=thread.id,
                    payload={
                        "artifact_id": thread.artifact_id,
                        "state": thread.state,
                        "question": thread.question,
                        "seed_kind": thread.seed_kind,
                    },
                )
            self._register_archive_relations(
                session,
                task,
                artifacts,
                entries,
                intake_executions,
            )
        deterministic_actions = self._deterministic_action_plan(artifacts)
        if blind_enabled:
            # Blind v2 begins with one deterministic baseline observation. The
            # frozen manifest is created immediately after that observation,
            # before any model-controlled action can be considered.
            model_actions, planning_limitations = [], []
        else:
            model_actions, planning_limitations = self._run_model_planning(
                task_id,
                artifacts,
                deterministic_actions,
                phase="initial",
            )
        limitations: list[str] = list(planning_limitations)
        execution_queue = self._build_execution_queue(deterministic_actions, model_actions, artifacts)
        planned_tools_by_artifact: dict[str, tuple[str, ...]] = {}
        for action in execution_queue:
            if action.source == "model_plan":
                planned_tools_by_artifact.setdefault(action.artifact_id, tuple())
                planned_tools_by_artifact[action.artifact_id] = tuple(
                    dict.fromkeys((*planned_tools_by_artifact[action.artifact_id], action.tool_name))
                )
        pending: list[tuple[ScheduledStaticAction, PackageEntry, int]] = [
            (
                action,
                entry_by_artifact[action.artifact_id],
                entry_by_artifact[action.artifact_id].logical_path.count("!/"),
            )
            for action in execution_queue
            if action.artifact_id in entry_by_artifact
        ]
        analyzed_ids: set[str] = set()
        completed_action_keys: set[str] = set()
        completed_actions: list[dict[str, object]] = []
        analyzed_bytes = 0
        # Planning is an evidence-driven protocol, not a one-shot tool-order
        # hint. Bound both the number of model turns and consecutive static
        # no-gain turns to keep the Agent finite and auditable.
        model_replan_turns = 0 if blind_enabled else 1
        consecutive_replan_no_gain = 0
        blind_run_id: str | None = None
        while pending:
            scheduled, entry, depth = pending.pop(0)
            artifact_id = scheduled.artifact_id
            if scheduled.key in completed_action_keys:
                continue
            if depth > self.settings.max_archive_depth:
                limitations.append(
                    f"Recursive static analysis depth exceeded for {entry.logical_path}."
                )
                continue
            if artifact_id not in analyzed_ids:
                if len(analyzed_ids) >= self.settings.max_sample_files:
                    limitations.append(
                        f"Recursive static analysis node budget exceeded ({self.settings.max_sample_files})."
                    )
                    continue
                if analyzed_bytes + entry.size > self.settings.max_sample_bytes:
                    limitations.append("Recursive static analysis byte budget exceeded.")
                    continue
                analyzed_bytes += entry.size
                analyzed_ids.add(artifact_id)
            # Commit the scheduler decision before entering the long-running
            # Worker transaction.  This keeps concurrent cancellation from
            # racing the audit-chain sequence allocation.
            with self.database.session_factory.begin() as audit_session:
                audit_task = audit_session.get(AnalysisTask, task_id)
                if audit_task is None:
                    raise LookupError(task_id)
                if audit_task.lifecycle == TaskLifecycle.CANCELLED.value:
                    return SubmissionResult(case_id, task_id, audit_task.lifecycle, None, None)
                self._audit(
                    audit_session,
                    case_id=audit_task.case_id,
                    task_id=audit_task.id,
                    event_type="orchestration.action_dequeued",
                    actor="scheduler",
                    object_type="ScheduledAction",
                    object_id=new_id(),
                    payload={
                        "action_key": scheduled.key,
                        "tool_name": scheduled.tool_name,
                        "artifact_id": scheduled.artifact_id,
                        "priority": scheduled.priority,
                        "reason": scheduled.reason,
                        "depends_on": list(scheduled.depends_on),
                        "scheduler": scheduled.source,
                    },
                )
            with self.database.session_factory.begin() as session:
                task = session.get(AnalysisTask, task_id)
                artifact = session.get(Artifact, artifact_id)
                if task is None or artifact is None:
                    raise LookupError(artifact_id)
                if task.lifecycle == TaskLifecycle.CANCELLED.value:
                    return SubmissionResult(case_id, task_id, task.lifecycle, None, None)
                planned_names = planned_tools_by_artifact.get(artifact_id, ())
                evidence_before = session.query(Evidence).filter(
                    Evidence.task_id == task_id,
                    Evidence.artifact_id == artifact_id,
                ).count()
                evidence_before_ids = set(
                    session.scalars(
                        select(Evidence.id).where(
                            Evidence.task_id == task_id,
                            Evidence.artifact_id == artifact_id,
                        )
                    )
                )
                tool_before_ids = set(
                    session.scalars(select(ToolRun.id).where(ToolRun.task_id == task_id)).all()
                )
                if scheduled.tool_name in SPECIALIST_STATIC_TOOLS:
                    limitations.extend(
                        self._run_methodology_action(
                            task_id,
                            artifact_id,
                            scheduled.tool_name,
                            scheduler=scheduled.source,
                        )
                    )
                elif scheduled.tool_name == "ghidra-headless":
                    limitations.extend(
                        self._run_ghidra(
                            task_id,
                            artifact_id,
                            entry,
                            planned_tool_names=planned_names,
                            scheduler=scheduled.source,
                        )
                    )
                else:
                    limitations.extend(
                        self._analyze_artifact(
                            session,
                            task,
                            artifact,
                            entry,
                            tool_name=scheduled.tool_name,
                            planned_tool_names=planned_names,
                            scheduler=scheduled.source,
                        )
                    )
                completed_actions.append(
                    {
                        "action_key": scheduled.key,
                        "artifact_id": artifact_id,
                        "tool_name": scheduled.tool_name,
                        "status": "completed",
                        "scheduler": scheduled.source,
                        "origin": (
                            "model"
                            if scheduled.source == "model_plan"
                            else "deterministic_fallback"
                        ),
                        "new_evidence_count": max(
                            0,
                            session.query(Evidence).filter(
                                Evidence.task_id == task_id,
                                Evidence.artifact_id == artifact_id,
                            ).count()
                            - evidence_before,
                        ),
                        "new_evidence_ids": sorted(
                            {
                                str(item)
                                for item in session.scalars(
                                    select(Evidence.id).where(
                                        Evidence.task_id == task_id,
                                        Evidence.artifact_id == artifact_id,
                                    )
                                ).all()
                                if str(item) not in evidence_before_ids
                            }
                        ),
                        "tool_run_ids": sorted(
                            {
                                str(item)
                                for item in session.scalars(
                                    select(ToolRun.id).where(ToolRun.task_id == task_id)
                                ).all()
                                if str(item) not in tool_before_ids
                            }
                        ),
                        "planner_turn_id": scheduled.planner_turn_id,
                    }
                )
                completed_action_keys.add(scheduled.key)
                # Carrier decoding and bounded Base64 extraction create immutable
                # child Artifacts. Queue each child for the same static pipeline;
                # no child is ever executed.
                child_rows = list(
                    session.scalars(
                        select(Artifact).where(
                            Artifact.task_id == task_id,
                            Artifact.parent_artifact_id == artifact_id,
                        )
                    )
                )
                for child in child_rows:
                    if any(item[0].artifact_id == child.id for item in pending):
                        continue
                    blob = session.get(ContentBlob, child.content_sha256)
                    if blob is None or blob.disposed_at is not None:
                        limitations.append(f"Child artifact content unavailable: {child.logical_path}.")
                        continue
                    child_content = self.content_store.read(blob.storage_key)
                    child_entry = PackageEntry(
                        logical_path=child.logical_path,
                        content=child_content,
                        parent_path=artifact.logical_path,
                        discovery=child.discovery,
                        is_container=zipfile.is_zipfile(io.BytesIO(child_content)),
                        content_sha256=child.content_sha256,
                        storage_key=blob.storage_key,
                        stored_size=blob.size,
                        detected_type=child.detected_type,
                        mime_type=blob.media_type,
                        type_source="recursive_static_extraction",
                    )
                    entry_by_artifact[child.id] = child_entry
                    child_queue = self._build_execution_queue([child.id], [], [child])
                    pending.extend((item, child_entry, depth + 1) for item in child_queue)
            if blind_enabled and blind_run_id is None:
                blind_run_id = self._freeze_blind_run_snapshot(task_id)
            new_evidence_count = int(completed_actions[-1].get("new_evidence_count", 0))
            if new_evidence_count > 0:
                consecutive_replan_no_gain = 0
            else:
                consecutive_replan_no_gain += 1
            if (
                self.settings.model_calls_enabled
                and self.settings.environment.lower() != "test"
                and model_replan_turns < self._MAX_MODEL_REPLAN_TURNS
                and consecutive_replan_no_gain < self._MAX_CONSECUTIVE_REPLAN_NO_GAIN
            ):
                model_replan_turns += 1
                remaining_ids = list(dict.fromkeys(item[0].artifact_id for item in pending)) or [artifact_id]
                with self.database.session_factory() as session:
                    remaining_artifacts = list(
                        session.scalars(
                            select(Artifact).where(Artifact.id.in_(remaining_ids))
                        )
                    )
                next_actions, next_limitations = self._run_model_planning(
                    task_id,
                    remaining_artifacts,
                    remaining_ids,
                    phase=(
                        f"blind_v2_after_static_action_{model_replan_turns}"
                        if blind_enabled
                        else f"replan_after_static_action_{model_replan_turns}"
                    ),
                    completed_actions=completed_actions,
                )
                limitations.extend(next_limitations)
                if next_actions:
                    # Execute the newly planned investigation actions against
                    # the evidence produced by the just-completed static
                    # action before scheduling another model turn.  This is
                    # the observable Model Action -> Policy -> Executor ->
                    # Evidence edge required by the Agent protocol.
                    limitations.extend(
                        self._run_investigation_loop(
                            task_id,
                            model_actions_only=True,
                        )
                    )
                    model_action_results = self._collect_model_action_results(
                        task_id,
                        next_actions,
                    )
                    if model_action_results:
                        completed_actions.extend(model_action_results)
                        self._finalize_pending_analysis_turn_results(
                            task_id,
                            completed_actions,
                            stop_reason="MODEL_ACTIONS_EXECUTED",
                        )
                if next_actions:
                    pending_by_key = {(item[0].artifact_id, item[0].tool_name): item for item in pending}
                    replanned_queue = self._build_execution_queue(
                        remaining_ids,
                        next_actions,
                        remaining_artifacts,
                    )
                    pending = []
                    for item in replanned_queue:
                        key = (item.artifact_id, item.tool_name)
                        if key in pending_by_key:
                            _, pending_entry, pending_depth = pending_by_key[key]
                        else:
                            pending_entry = entry_by_artifact.get(item.artifact_id)
                            if pending_entry is None:
                                continue
                            pending_depth = pending_entry.logical_path.count("!/")
                        pending.append((item, pending_entry, pending_depth))
                    for item in replanned_queue:
                        if item.source == "model_plan":
                            planned_tools_by_artifact.setdefault(item.artifact_id, tuple())
                            planned_tools_by_artifact[item.artifact_id] = tuple(
                                dict.fromkeys(
                                    (*planned_tools_by_artifact[item.artifact_id], item.tool_name)
                                )
                            )
            elif (
                self.settings.model_calls_enabled
                and self.settings.environment.lower() != "test"
                and pending
                and consecutive_replan_no_gain >= self._MAX_CONSECUTIVE_REPLAN_NO_GAIN
            ):
                limitations.append(
                    "Model replanning stopped after consecutive static actions produced no new Evidence."
                )
            elif (
                self.settings.model_calls_enabled
                and self.settings.environment.lower() != "test"
                and pending
                and model_replan_turns >= self._MAX_MODEL_REPLAN_TURNS
            ):
                limitations.append(
                    f"Model replanning turn budget reached ({self._MAX_MODEL_REPLAN_TURNS})."
                )

        if pending:
            limitations.append(
                f"Recursive static analysis node budget exceeded ({self.settings.max_sample_files})."
            )
        # Seal any final model planner turn after the execution queue drains.
        # This produces an append-only result even when no re-planning turn was
        # needed or the model returned no executable actions.
        self._finalize_pending_analysis_turn_results(
            task_id,
            completed_actions,
            stop_reason=("STATIC_QUEUE_DRAINED" if not pending else "STATIC_QUEUE_BUDGET_EXHAUSTED"),
        )
        with self.database.session_factory() as session:
            all_artifacts = list(session.scalars(select(Artifact).where(Artifact.task_id == task_id)))

        # Methodology profiles are a first-class static result even when the
        # optional planning model is unavailable.  The operation is idempotent
        # per Artifact and therefore safe after a model-selected specialist turn.
        for artifact in all_artifacts:
            limitations.extend(self._run_methodology_action(task_id, artifact.id, "signal-extractor", scheduler="deterministic_methodology"))

        # Recompile investigation questions from the evidence frontier after
        # baseline parsing. The initial seed is intentionally conservative;
        # this second pass makes subsequent model turns sample-adaptive.
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if task is not None:
                snapshot = dict(task.strategy_snapshot or {})
                investigation = dict(snapshot.get("investigation", {}))
                threads = list(investigation.get("threads", []))
                for thread in threads:
                    if not isinstance(thread, dict):
                        continue
                    artifact = session.get(Artifact, str(thread.get("artifact_id")))
                    if artifact is None:
                        continue
                    kinds = tuple(sorted({
                        str(item) for item in session.scalars(select(Evidence.kind).where(
                            Evidence.task_id == task_id,
                            Evidence.artifact_id == artifact.id,
                        )).all()
                    }))
                    questions = QuestionCompiler().compile(
                        "",
                        artifact_id=artifact.id,
                        detected_type=str(artifact.detected_type),
                        evidence_kinds=kinds,
                    )
                    if not questions:
                        continue
                    question = questions[0]
                    thread["question"] = question.question
                    thread["seed_kind"] = question.thread_type
                    thread["required_evidence_kinds"] = list(question.required_evidence_kinds)
                    thread["success_requirements"] = list(question.success_requirements)
                    thread["adaptive_signal_kinds"] = list(kinds[:24])
                investigation["threads"] = threads
                investigation["question_compiler"] = {
                    "mode": "sample_adaptive",
                    "source": "persisted static evidence kinds",
                    "runtime_execution": False,
                }
                task.strategy_snapshot = {**snapshot, "investigation": investigation}
                self._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type="investigation.questions_recompiled",
                    actor="question-compiler",
                    object_type="AnalysisTask",
                    object_id=task.id,
                    payload={
                        "mode": "sample_adaptive",
                        "thread_count": len(threads),
                    },
                )

        # Execute any actions from the initial planner turn after mandatory
        # baseline extraction has populated the evidence frontier.  This keeps
        # the first model action targetable while preserving the baseline
        # coverage guarantee.
        if self.settings.model_calls_enabled:
            limitations.extend(self._run_investigation_loop(task_id, model_actions_only=True))

        # Turn parser observations into a bounded, evidence-driven investigation
        # loop.  This persists every action and hypothesis transition and keeps
        # the private model reasoning out of the report surface.
        limitations.extend(self._run_investigation_loop(task_id))

        if self.settings.model_calls_enabled:
            limitations.extend(self._run_model_enrichment(task_id))

        self._run_attack_mapping(task_id)

        with self.database.session_factory.begin() as session:
            case = session.get(CaseRecord, case_id)
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if case is None or task is None:
                raise LookupError(task_id)
            if task.lifecycle == TaskLifecycle.CANCELLED.value:
                return SubmissionResult(case_id, task_id, task.lifecycle, None, None)
            task.limitations = sorted(
                set(limitations) | set(self._completion_limitations(session, task.id, all_artifacts))
            )
            # Keep the legacy task outcome independent from semantic-quality
            # limitations.  A successful static pipeline may still be bounded
            # by unresolved mechanisms; that boundary belongs in
            # ``analysis_class``/coverage and must remain visible in the
            # report, but it should not make a completed parser task look like
            # an operationally partial/failed task to older API clients.
            legacy_limitations = tuple(task.limitations)
            task.actual_granularity = {
                "breadth": "B1" if len(all_artifacts) > 1 else "B0",
                "depth": self._actual_depth(session, task.id, all_artifacts),
                "unmet_reasons": task.limitations,
            }
            artifact_classes = []
            for analyzed_artifact in all_artifacts:
                runs = session.scalars(
                    select(ToolRun).where(
                        ToolRun.task_id == task.id,
                        ToolRun.artifact_id == analyzed_artifact.id,
                    )
                ).all()
                structural_limitations = [
                    item for item in task.limitations
                    if any(
                        marker in str(item).casefold()
                        for marker in (
                            "missing custom dll", "required artifact", "packed", "packer",
                            "virtualized", "self-modif", "runtime-only", "runtime only",
                            "decompiler", "decompilation failed", "unresolved indirect",
                            "truncated", "damaged", "static boundary", "code recovery",
                            "cannot parse", "parsing incomplete",
                        )
                    )
                ]
                artifact_classes.append(
                    classify_artifact_result(
                        analyzed_artifact.detected_type,
                        tool_runs=[
                            {"status": run.status, "tool_name": run.tool_name}
                            for run in runs
                        ],
                        limitations=task.limitations,
                        structural_limitations=structural_limitations,
                        metadata=analyzed_artifact.metadata_json,
                    )
                )
            task.analysis_class = aggregate_result_class(artifact_classes).value
            # Materialize specialist mechanism results before computing
            # coverage. Coverage is frozen into the task snapshot and must
            # include verifier decisions produced in this finalization.
            self._materialize_mechanism_snapshot(session, task)
            # Analysis class is also a semantic readiness contract.  Parser
            # success alone cannot yield FULL_STATIC_ANALYSIS when the
            # investigation frontier is mostly unresolved or when only a
            # small fraction of independent seed threads reached a terminal
            # verification state.  Keep raw candidates visible, but expose a
            # bounded result until the mechanism evidence is actually closed.
            investigation_state = dict(
                (task.strategy_snapshot or {}).get("investigation", {})
            )
            mechanism_rows = [
                item for item in investigation_state.get("mechanisms", [])
                if isinstance(item, dict)
            ]
            closed_statuses = {"VERIFIED", "SUPPORTED", "CONFIRMED"}
            closed_rows = [
                item for item in mechanism_rows
                if str(item.get("status", "")).upper() in closed_statuses
            ]
            thread_rows = list(
                session.scalars(
                    select(InvestigationThreadRecord).where(
                        InvestigationThreadRecord.task_id == task.id
                    )
                )
            )
            terminal_states = {
                "MECHANISM_READY", "CLAIM_READY", "UNKNOWN", "BLOCKED",
                "REJECTED", "CONTRADICTED", "CLOSED",
            }
            semantic_limitations: list[str] = []
            if mechanism_rows:
                closure_rate = len(closed_rows) / max(1, len(mechanism_rows))
                candidate_ratio = (len(mechanism_rows) - len(closed_rows)) / max(1, len(mechanism_rows))
                if closure_rate < 0.8:
                    semantic_limitations.append(
                        f"Mechanism closure is {closure_rate:.0%}; unresolved static hypotheses remain."
                    )
                if candidate_ratio > 0.35:
                    semantic_limitations.append(
                        f"Candidate mechanism ratio is {candidate_ratio:.0%}; report is bounded until evidence is verified."
                    )
            if thread_rows:
                thread_closure = sum(
                    1 for row in thread_rows if str(row.state).upper() in terminal_states
                ) / max(1, len(thread_rows))
                if thread_closure < 0.9:
                    semantic_limitations.append(
                        f"Investigation seed closure is {thread_closure:.0%}; active or unresolved threads remain."
                    )
            if semantic_limitations:
                task.limitations = sorted(set(task.limitations) | set(semantic_limitations))
            task.coverage = self._build_analysis_coverage(
                session, task.id, all_artifacts, task.limitations
            )
            # Analysis class is a product contract, not a parser-success flag.
            # A static task with no verified mechanism and no semantic relation
            # flow is usable but bounded until closure evidence exists.
            coverage_payload = task.coverage if isinstance(task.coverage, dict) else {}
            verified_rate = float(coverage_payload.get("dimensions", {}).get("verified_mechanism_coverage", 0.0) or 0.0)
            relation_rate = float(coverage_payload.get("dimensions", {}).get("relation_flow_coverage", 0.0) or 0.0)
            if (
                task.analysis_class == "FULL_STATIC_ANALYSIS"
                and (
                    (verified_rate <= 0.0 and relation_rate <= 0.0)
                    or bool(semantic_limitations)
                )
            ):
                task.analysis_class = "BOUNDED_STATIC_ANALYSIS"
                # Keep the legacy lifecycle ``outcome`` independent from the
                # product result class. The semantic gap is already visible
                # in coverage dimensions and should not turn a successfully
                # completed parser task into a failed/partial lifecycle.
            task.lifecycle = transition_task(task.lifecycle, TaskLifecycle.FINALIZING).value
            session.flush()
            # ``outcome`` remains the legacy task completeness view.  The
            # explicit Round 11 class above carries UNSUPPORTED/FAILED without
            # breaking old clients that interpret unsupported input as PARTIAL.
            task.outcome = (
                AnalysisOutcome.PARTIAL.value
                if legacy_limitations or task.analysis_class == "FAILED_ANALYSIS"
                else AnalysisOutcome.COMPLETE.value
            )
            task.lifecycle = transition_task(task.lifecycle, TaskLifecycle.SUCCEEDED).value
            task.finished_at = utcnow()
            if blind_run_id:
                blind_run = session.get(BlindRun, blind_run_id)
                if blind_run is not None:
                    blind_run.status = "COMPLETED"
                task.strategy_snapshot = {
                    **(task.strategy_snapshot or {}),
                    "blind_run": {
                        **dict((task.strategy_snapshot or {}).get("blind_run", {})),
                        "status": "COMPLETED",
                    },
                }
            session.flush()
            snapshot = self._freeze_snapshot(session, task)
            report = self._create_report_revision(session, task, snapshot, modules)
            self._audit(
                session,
                case_id=case_id,
                task_id=task_id,
                event_type="analysis_task.succeeded",
                actor=actor,
                object_type="AnalysisTask",
                object_id=task_id,
                payload={
                    "outcome": task.outcome,
                    "snapshot_id": snapshot.id,
                    "report_revision_id": report.id,
                },
            )
            self._seal_task_audit_chain(session, task, "analysis_task.succeeded")
            return SubmissionResult(
                case_id,
                task_id,
                task.lifecycle,
                task.outcome,
                report.id,
            )

    def _run_attack_mapping(self, task_id: str) -> None:
        """Create a versioned, deterministic candidate ATT&CK mapping index."""
        snapshot = load_attack_snapshot()
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if task is None:
                raise LookupError(task_id)
            claims = list(
                session.scalars(
                    select(Claim).where(Claim.task_id == task_id).order_by(Claim.created_at)
                )
            )
            self._apply_attack_mapping(session, task, task_id, snapshot, claims)

    @staticmethod
    def _investigation_value_text(value: object, *, limit: int = 12_000) -> str:
        """Flatten bounded structured evidence for static action matching."""
        if isinstance(value, str):
            return value[:limit]
        if isinstance(value, dict):
            parts: list[str] = []
            for key, item in value.items():
                if len(" ".join(parts)) >= limit:
                    break
                parts.append(str(key))
                parts.append(AnalysisService._investigation_value_text(item, limit=limit))
            return " ".join(parts)[:limit]
        if isinstance(value, (list, tuple, set)):
            return " ".join(
                AnalysisService._investigation_value_text(item, limit=limit)
                for item in list(value)[:128]
            )[:limit]
        return str(value)[:limit]

    def _derive_investigation_observations(
        self,
        source_rows: list[Evidence],
        action: ActionSpec,
        *,
        artifact_content: bytes | None = None,
        pe_summary: dict[str, object] | None = None,
    ) -> list[dict[str, object]]:
        """Execute a catalog action against existing static evidence only.

        These actions are intentionally read-only.  They provide a real
        executor seam today and can later be backed by Ghidra/Qiling workers
        without changing the queue, persistence, or Claim Gate contracts.
        """
        # Keep the complete artifact-local set before applying citation scope.
        # A cited function/xref is an authorization anchor; the static query
        # may then inspect the same function's already-persisted context (call
        # edges, instruction window, CFG) without crossing the artifact
        # boundary.  This is what makes GET_DECOMPILE/GET_PCODE_SLICE useful
        # when a model cites a single xref row.
        artifact_rows = list(source_rows)
        # A model action is causally authorized only by the Evidence IDs it
        # cited.  Deterministic playbook actions have no citations and retain
        # the complete artifact-local source set.  Always enforce the artifact
        # boundary here as a second line of defense for callers that bypass the
        # planner validation path.
        # Some offline callers provide lightweight evidence-shaped objects
        # without an artifact_id (the artifact boundary is already implicit in
        # that fixture).  Enforce the boundary whenever the source carries
        # the field, while retaining compatibility with those value objects.
        if any(getattr(row, "artifact_id", None) is not None for row in artifact_rows):
            artifact_rows = [
                row for row in artifact_rows if getattr(row, "artifact_id", None) == action.artifact_id
            ]
        if action.source_evidence_ids:
            cited_ids = set(action.source_evidence_ids)
            source_rows = [row for row in artifact_rows if row.id in cited_ids]
        else:
            source_rows = artifact_rows
        known_apis = (
            "GetProcAddress",
            "LoadLibraryA",
            "LoadLibraryW",
            "OpenProcess",
            "CreateToolhelp32Snapshot",
            "Process32First",
            "Process32Next",
            "UpdateProcThreadAttribute",
            "InitializeProcThreadAttributeList",
            "CreateProcess",
            "VirtualAlloc",
            "VirtualProtect",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "WinHttpOpenRequest",
            "WinHttpSendRequest",
            "WinHttpConnect",
            "WinHttpReceiveResponse",
            "InternetOpenUrlA",
            "InternetOpenUrlW",
        )
        token_rows: list[tuple[Evidence, str]] = [
            (
                row,
                self._investigation_value_text(
                    {"value": row.value, "anchor": row.anchor}
                ),
            )
            for row in source_rows
        ]
        selector = dict(action.target_selector) or dict(action.parameters)
        target = ""
        for key in ("target", "api", "function", "function_entry", "entry", "rva", "address"):
            value = selector.get(key)
            if isinstance(value, (str, int)) and str(value).strip():
                target = str(value).strip()
                break
        target_casefold = target.casefold()

        def selectors(value: object) -> set[str]:
            if not isinstance(value, dict):
                return set()
            result: set[str] = set()
            for key in (
                "name", "entry", "function_entry", "rva", "address", "from", "to",
                "target", "target_name", "target_function", "caller", "callee",
            ):
                item = value.get(key)
                if isinstance(item, (str, int)) and str(item).strip():
                    result.add(str(item).casefold())
            return result

        all_token_rows: list[tuple[Evidence, str]] = [
            (
                row,
                self._investigation_value_text(
                    {"value": row.value, "anchor": row.anchor}
                ),
            )
            for row in artifact_rows
        ]
        wildcard_targets = {
            "global",
            "file",
            "strings",
            "string",
            "str",
            "file_header",
            "pe_header",
            "pe_headers_and_imports",
            "strings_and_signals",
            "functions_and_xrefs",
        }
        target_rows = (
            all_token_rows
            if not target_casefold or target_casefold in wildcard_targets
            else [
                (row, text)
                for row, text in all_token_rows
                if target_casefold in text.casefold()
            ]
        )
        # Normalize the planner's logical entry-point selector to the PE
        # entry RVA emitted by the deterministic parser.  Model plans often
        # say ``entry`` rather than copying a tool-specific address; treating
        # that as a global wildcard loses the actual entry function, while
        # matching the literal word ``entry`` finds nothing useful.
        if target_casefold in {"entry", "entrypoint", "entry_point", "address_of_entry_point"}:
            entry_rva = pe_summary.get("entry_rva") if isinstance(pe_summary, dict) else None
            try:
                entry_rva_int = int(str(entry_rva), 0) if entry_rva is not None else None
            except (TypeError, ValueError):
                entry_rva_int = None
            aliases = {str(entry_rva_int).casefold()} if entry_rva_int is not None else set()
            if entry_rva_int is not None:
                aliases.update({f"0x{entry_rva_int:x}".casefold(), f"{entry_rva_int:x}".casefold()})
                target_casefold = str(entry_rva_int).casefold()
            target_rows = [
                (row, text)
                for row, text in all_token_rows
                if (
                    any(
                        alias in {
                            str((row.value if isinstance(row.value, dict) else {}).get("entry_rva", "")).casefold(),
                            str((row.value if isinstance(row.value, dict) else {}).get("entry", "")).casefold(),
                            str((row.anchor if isinstance(row.anchor, dict) else {}).get("function_entry", "")).casefold(),
                        }
                        for alias in aliases
                    )
                )
            ]
        # Function/RVA actions use a cited row as the seed and expand to every
        # row sharing its function identity.  This handles Ghidra's split
        # Evidence model where context, instruction windows, CFG and calls are
        # separate rows with the same function_entry anchor.
        if target_casefold not in wildcard_targets:
            seed_keys: set[str] = set()
            # A selector that names a function is itself a bounded target. If
            # the context row matches but the instruction window does not
            # contain the textual function name, expand to sibling Evidence
            # rows sharing the same function entry. Citation-scoped model
            # actions still remain bounded by ``source_evidence_ids`` because
            # ``all_token_rows`` is the artifact-local corpus and the seed
            # keys are derived only from cited rows when citations exist.
            seed_basis = source_rows if action.source_evidence_ids else [
                row for row, _ in target_rows if row.kind in {"function", "function_context", "function_instruction_window", "function_call", "cfg_block"}
            ]
            for row in seed_basis:
                value = row.value if isinstance(row.value, dict) else {}
                anchor = row.anchor if isinstance(row.anchor, dict) else {}
                seed_keys.update(
                    selectors(
                        {
                            "name": value.get("name"),
                            "entry": value.get("entry", anchor.get("entry")),
                            "function_entry": anchor.get("function_entry"),
                            "rva": value.get("entry_rva", anchor.get("rva")),
                            "from": value.get("from", anchor.get("from")),
                            "to": value.get("to"),
                            "target_name": value.get("target_name"),
                            "target_function": value.get("target_function"),
                        }
                    )
                )
            expanded_rows: list[tuple[Evidence, str]] = []
            for row, text in all_token_rows:
                value = row.value if isinstance(row.value, dict) else {}
                anchor = row.anchor if isinstance(row.anchor, dict) else {}
                row_keys = selectors(
                    {
                        "name": value.get("name"),
                        "entry": value.get("entry", anchor.get("entry")),
                        "function_entry": anchor.get("function_entry"),
                        "rva": value.get("entry_rva", anchor.get("rva")),
                        "from": value.get("from", anchor.get("from")),
                        "to": value.get("to"),
                        "target_name": value.get("target_name"),
                        "target_function": value.get("target_function"),
                    }
                )
                if seed_keys & row_keys:
                    expanded_rows.append((row, text))
            if expanded_rows:
                target_rows = expanded_rows
        observations: list[dict[str, object]] = []

        def add(
            kind: str,
            value: dict[str, object],
            rows: list[Evidence],
            *,
            nature: str = "STATIC_DERIVED",
        ) -> None:
            if not rows:
                return
            source_evidence_ids = [item.id for item in rows[:24]]
            source_anchors = [
                item.anchor for item in rows[:24] if isinstance(item.anchor, dict) and item.anchor
            ]
            input_digest = hashlib.sha256(
                json.dumps(
                    {
                        "action_type": action.action_type.value,
                        "target": target,
                        "source_evidence_ids": source_evidence_ids,
                    },
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            output_digest = hashlib.sha256(
                json.dumps(value, ensure_ascii=True, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest()
            observations.append(
                {
                    "kind": kind,
                    "value": {
                        **value,
                        "source_evidence_ids": source_evidence_ids,
                        "derivation": {
                            "evaluator": "static-evidence-query-v2",
                            "input_evidence_ids": source_evidence_ids,
                            "input_digest": input_digest,
                            "output_digest": output_digest,
                            "exact": nature == "STATIC_DERIVED",
                        },
                    },
                    "anchor": {
                        "type": "investigation_action",
                        "action_type": action.action_type.value,
                        "target_selector": target or None,
                        "source_evidence_ids": source_evidence_ids,
                        "source_anchors": source_anchors,
                        # Preserve the stable function/RVA locator at the
                        # top level as well as in source_anchors.  Consumers
                        # use this field to jump from derived evidence back
                        # to the function without decoding provenance lists.
                        **(
                            {
                                "function_entry": next(
                                    (
                                        str(anchor["function_entry"])
                                        for anchor in source_anchors
                                        if isinstance(anchor, dict)
                                        and anchor.get("function_entry") is not None
                                        and str(anchor.get("function_entry")).strip()
                                    ),
                                    None,
                                )
                            }
                            if source_anchors
                            else {}
                        ),
                    },
                    "nature": nature,
                }
            )

        def function_identity(row: Evidence) -> set[str]:
            value = row.value if isinstance(row.value, dict) else {}
            anchor = row.anchor if isinstance(row.anchor, dict) else {}
            return selectors(
                {
                    "name": value.get("name"),
                    "entry": value.get("entry", anchor.get("entry")),
                    "function_entry": anchor.get("function_entry"),
                    "rva": value.get("entry_rva", anchor.get("rva")),
                }
            )

        def function_label(row: Evidence) -> str:
            value = row.value if isinstance(row.value, dict) else {}
            anchor = row.anchor if isinstance(row.anchor, dict) else {}
            for item in (
                value.get("name"),
                value.get("entry"),
                anchor.get("function_entry"),
                value.get("entry_rva"),
            ):
                if isinstance(item, (str, int)) and str(item).strip():
                    return str(item)
            return ""

        def function_edges(row: Evidence, field: str) -> list[dict[str, object]]:
            value = row.value if isinstance(row.value, dict) else {}
            raw = value.get(field, ())
            if not isinstance(raw, list):
                return []
            return [
                dict(item) if isinstance(item, dict) else {"target_name": str(item)}
                for item in raw
                if isinstance(item, (dict, str, int)) and str(item).strip()
            ]

        def edge_target(edge: dict[str, object]) -> str:
            for key in (
                "target_name",
                "target_function",
                "to",
                "target",
                "api",
                "indicator",
                "name",
                "entry",
            ):
                item = edge.get(key)
                if isinstance(item, (str, int)) and str(item).strip():
                    return str(item)
            return ""

        # These investigation actions use the same safe abstract executor as
        # the Ghidra persistence path.  They refine a hypothesis from existing
        # static evidence and never load or execute the sample.
        abstract_actions = {
            ActionType.READ_BYTES,
            ActionType.GET_DECOMPILE,
            ActionType.GET_PCODE_SLICE,
            ActionType.GET_CFG_SLICE,
            ActionType.TRACE_API_ARGUMENT,
            ActionType.TRACE_RETURN_VALUE,
            ActionType.TRACE_GLOBAL_USAGE,
        }
        if action.action_type in abstract_actions:
            context_rows = [row for row, _ in target_rows if row.kind == "function_context"]
            instruction_rows: list[dict[str, object]] = []
            call_rows: list[dict[str, object]] = []
            data_reference_rows: list[dict[str, object]] = []
            for row, _ in target_rows:
                if row.kind == "function_instruction_window" and isinstance(row.value, dict):
                    candidate_instructions = row.value.get("instructions", [])
                    if isinstance(candidate_instructions, list):
                        instruction_rows.extend(item for item in candidate_instructions if isinstance(item, dict))
                if row.kind in {"function_call", "function_context"} and isinstance(row.value, dict):
                    if row.kind == "function_call":
                        call_rows.append(dict(row.value))
                    else:
                        targets = row.value.get("call_targets", [])
                        if isinstance(targets, list):
                            call_rows.extend(item for item in targets if isinstance(item, dict))
                        references = row.value.get("data_references", row.value.get("references", []))
                        if isinstance(references, list):
                            data_reference_rows.extend(item for item in references if isinstance(item, dict))
            context = context_rows[0].value if context_rows and isinstance(context_rows[0].value, dict) else {}
            function = {
                "name": context.get("name", action.parameters.get("function", "investigation-target")),
                "entry": context.get("entry", action.parameters.get("entry", "")),
                "instructions": instruction_rows[:256],
                "references_from": call_rows[:256],
                "call_targets": call_rows[:256],
                "data_references": data_reference_rows[:512],
            }
            source_ids = [row.id for row, _ in target_rows if row.kind in {"function_context", "function_instruction_window", "function_call", "function_mechanism"}]
            simulated = StaticAbstractExecutor(max_steps=128).analyze(function, source_evidence_ids=source_ids)
            relevant_rows = [row for row, _ in target_rows if row.kind in {"function_context", "function_instruction_window", "function_call", "function_mechanism"}]
            add(
                "abstract_execution_trace",
                simulated.as_dict(),
                relevant_rows[:24],
                nature="STATIC_INFERRED",
            )
            if action.action_type == ActionType.GET_PCODE_SLICE:
                add(
                    "pcode_slice",
                    build_pcode_slice(
                        function,
                        source_evidence_ids=source_ids,
                        max_operations=64,
                    ),
                    relevant_rows[:24],
                    nature="STATIC_INFERRED",
                )
                for link in track_indirect_function_pointers(function):
                    add(
                        "indirect_function_pointer_link",
                        dict(link),
                        relevant_rows[:24],
                        nature="STATIC_DERIVED",
                    )
                # A compact role classification gives the agent a
                # discriminating answer for PE parsing hypotheses.  Header
                # access alone remains a validator candidate; mapper claims
                # require the separate allocation/relocation/write path.
                for role in classify_pe_semantics(function, pe_summary):
                    add("pe_semantic_classification", role, relevant_rows[:24], nature="STATIC_INFERRED")

        if action.action_type == ActionType.GET_FUNCTION:
            for row, _ in target_rows:
                if row.kind == "function":
                    add("function", dict(row.value), [row])
        elif action.action_type == ActionType.GET_STRINGS_REFERENCED:
            # Strings are first-class observations.  The old implementation
            # only emitted a function_call when a string happened to contain a
            # hard-coded API name, silently discarding ordinary paths, URLs,
            # registry keys and configuration text.
            for row, text in target_rows:
                if row.kind == "string":
                    value = dict(row.value) if isinstance(row.value, dict) else {"text": text}
                    add("string_reference", value, [row])
                elif row.kind == "function_data_correlation":
                    add("string_reference", dict(row.value) if isinstance(row.value, dict) else {"text": text}, [row])
                elif row.kind in {"import_symbol", "function_context", "function_call"}:
                    for api in known_apis:
                        if api.casefold() in text.casefold():
                            add("function_call", {"api": api, "source_kind": row.kind}, [row])
        elif action.action_type == ActionType.GET_DATA_REFERENCES:
            for row, text in target_rows:
                value = row.value if isinstance(row.value, dict) else {}
                if row.kind == "data_reference":
                    add("data_reference", dict(value), [row])
                    continue
                references = value.get("data_references", value.get("references", ()))
                if isinstance(references, list):
                    for reference in references:
                        if isinstance(reference, dict):
                            add("data_reference", dict(reference), [row])
                elif row.kind in {"string", "function_data_correlation"}:
                    add("data_reference", {"source_kind": row.kind, "text": text}, [row])
        elif action.action_type == ActionType.GET_CALLERS:
            for row, _ in target_rows:
                if row.kind != "function_context":
                    continue
                for edge in function_edges(row, "call_targets"):
                    callee = edge_target(edge)
                    if callee.casefold() != target_casefold:
                        continue
                    caller = function_label(row)
                    add(
                        "function_call",
                        {
                            "direction": "caller",
                            "caller": caller,
                            "callee": callee,
                            "api": callee,
                            "edge": edge,
                        },
                        [row],
                    )
        elif action.action_type == ActionType.GET_CALLEES:
            for row, _ in target_rows:
                if row.kind != "function_context" or target_casefold not in function_identity(row):
                    continue
                caller = function_label(row) or target
                for edge in function_edges(row, "call_targets"):
                    callee = edge_target(edge)
                    if not callee:
                        continue
                    add(
                        "function_call",
                        {
                            "direction": "callee",
                            "caller": caller,
                            "callee": callee,
                            "api": callee,
                            "edge": edge,
                        },
                        [row],
                    )
        elif action.action_type == ActionType.GET_XREFS_TO:
            # API xrefs are often cited from a PE import/indicator row. That
            # row has no function identity, so function-local expansion can
            # otherwise discard the actual Ghidra call rows and report
            # NO_NEW_EVIDENCE. The artifact-local corpus is already bounded
            # and authorized by the action's cited Evidence IDs; use it as a
            # fallback for exact API matching while retaining artifact scope.
            xref_rows = target_rows or all_token_rows
            before_xref_observations = len(observations)

            def collect_xrefs(rows_to_scan: list[tuple[Evidence, str]]) -> None:
                for row, _ in rows_to_scan:
                    if row.kind not in {
                    "function_context",
                    "xref",
                    "function_call",
                    "import_symbol",
                    "loader_indicator",
                    "execution_indicator",
                    "anti_analysis_indicator",
                    "mechanism_dynamic_resolution",
                    "mechanism_memory_permission",
                }:
                        continue
                    value = row.value if isinstance(row.value, dict) else {}
                    direct_targets = function_edges(row, "call_targets")
                    if row.kind in {
                    "xref",
                    "function_call",
                    "import_symbol",
                    "loader_indicator",
                    "execution_indicator",
                    "anti_analysis_indicator",
                    "mechanism_dynamic_resolution",
                    "mechanism_memory_permission",
                }:
                        direct_targets.append(value)
                    for edge in direct_targets:
                        referenced = edge_target(edge)
                        if referenced.casefold() != target_casefold:
                            continue
                        caller = function_label(row) or str(value.get("from", ""))
                        add(
                            "function_call",
                            {
                                "direction": "xref_to",
                                "caller": caller,
                                "referenced_target": referenced,
                                "api": referenced,
                                "edge": edge,
                            },
                            [row],
                        )

            collect_xrefs(xref_rows)
            # A PE import row can be the only exact target match, while the
            # useful caller edge lives in a Ghidra function_context row whose
            # text is not selected after citation expansion. Retry the exact
            # target over the already-authorized artifact corpus when the
            # first pass produced no call evidence.
            if len(observations) == before_xref_observations and xref_rows is not all_token_rows:
                collect_xrefs(all_token_rows)
        elif action.action_type == ActionType.GET_XREFS_FROM:
            for row, _ in target_rows:
                if row.kind != "function_context" or target_casefold not in function_identity(row):
                    continue
                source = function_label(row) or target
                for edge in function_edges(row, "call_targets"):
                    referenced = edge_target(edge)
                    if not referenced:
                        continue
                    add(
                        "function_call",
                        {
                            "direction": "xref_from",
                            "source": source,
                            "referenced_target": referenced,
                            "api": referenced,
                            "edge": edge,
                        },
                        [row],
                    )
        elif action.action_type == ActionType.TRACE_API_ARGUMENT:
            # Recover a bounded Windows x64 argument trace from the static
            # instruction window.  This is deliberately local to one function
            # and one callsite: it never treats an import/string as a call, and
            # unresolved registers remain explicit UNKNOWN values.
            call_candidates: list[tuple[str, str, Evidence]] = []
            for row, _ in target_rows:
                value = row.value if isinstance(row.value, dict) else {}
                if row.kind == "function_call":
                    api = str(value.get("api") or value.get("target_name") or value.get("target_function") or "").strip()
                    callsite = str(value.get("from") or value.get("address") or (row.anchor or {}).get("callsite") or "").strip()
                    if api:
                        call_candidates.append((api, callsite, row))
                elif row.kind == "function_context":
                    for edge in function_edges(row, "call_targets"):
                        api = edge_target(edge)
                        callsite = str(edge.get("from") or edge.get("address") or "").strip()
                        if api:
                            call_candidates.append((api, callsite, row))
            # A function may expose the call only in an instruction window;
            # use it as a callsite candidate when the target API is explicit.
            for row, text in target_rows:
                if row.kind != "function_instruction_window":
                    continue
                for match in re.finditer(r"\bCALL\s+(?:[A-Za-z0-9_.$@!]+!)?([A-Za-z_][A-Za-z0-9_@$]*)", text, re.I):
                    call_candidates.append((match.group(1), "", row))

            def parse_address(raw: object) -> int | None:
                value = str(raw or "").strip()
                if not value:
                    return None
                try:
                    return int(value, 0)
                except ValueError:
                    try:
                        return int(value, 16)
                    except ValueError:
                        return None

            def function_name(row: Evidence) -> str:
                value = row.value if isinstance(row.value, dict) else {}
                anchor = row.anchor if isinstance(row.anchor, dict) else {}
                return str(value.get("name") or value.get("function") or anchor.get("function_entry") or "")

            # Deduplicate rows/call candidates while retaining the strongest
            # function-context provenance.
            unique_calls: dict[tuple[str, str, str], tuple[str, str, Evidence]] = {}
            for api, callsite, row in call_candidates:
                if target_casefold and target_casefold not in {"api", "function", "global"}:
                    normalized = normalize_api_symbol(api)
                    if target_casefold not in {api.casefold(), normalized.casefold()} and target_casefold not in api.casefold():
                        continue
                key = (api.casefold(), callsite.casefold(), function_name(row).casefold())
                unique_calls.setdefault(key, (api, callsite, row))

            instruction_rows: list[tuple[Evidence, dict[str, object], int | None, int]] = []
            for row, _ in target_rows:
                if row.kind != "function_instruction_window" or not isinstance(row.value, dict):
                    continue
                raw_instructions = row.value.get("instructions", [])
                if not isinstance(raw_instructions, list):
                    continue
                for ordinal, instruction in enumerate(raw_instructions):
                    if not isinstance(instruction, dict):
                        continue
                    instruction_rows.append((row, instruction, parse_address(instruction.get("address") or instruction.get("offset")), ordinal))
            instruction_rows.sort(key=lambda item: (item[2] is None, item[2] if item[2] is not None else item[3]))

            arg_registers = ("RCX", "RDX", "R8", "R9")
            assignment_re = re.compile(r"\b(?:MOV|MOVABS|LEA)\s+(RCX|RDX|R8|R9)\s*,\s*(.+)$", re.I)
            for api, callsite, call_row in unique_calls.values():
                call_address = parse_address(callsite)
                # Keep only instructions in the same function window and stop
                # at the target call.  If addresses are absent, exporter order
                # is retained and the call's ordinal is the best boundary.
                scoped = [item for item in instruction_rows if function_name(item[0]).casefold() == function_name(call_row).casefold()]
                if not scoped:
                    scoped = instruction_rows
                before: list[tuple[Evidence, dict[str, object], int | None, int]] = []
                for item in scoped:
                    if call_address is not None and item[2] is not None and item[2] > call_address:
                        break
                    before.append(item)
                latest: dict[str, dict[str, object]] = {}
                for source_row, instruction, address, ordinal in before:
                    text_value = str(instruction.get("text") or instruction.get("mnemonic") or "").strip()
                    assignment = assignment_re.search(text_value)
                    if not assignment:
                        continue
                    register, raw_value = assignment.groups()
                    latest[register.upper()] = {
                        "register": register.upper(),
                        "value": raw_value.strip(),
                        "source_instruction": text_value,
                        "address": instruction.get("address") or instruction.get("offset"),
                        "source_evidence_id": source_row.id,
                    }
                args: list[dict[str, object]] = []
                for index, register in enumerate(arg_registers):
                    item = latest.get(register)
                    if item is None:
                        args.append({"index": index, "register": register, "value": "UNKNOWN", "resolved": False})
                    else:
                        raw_value = str(item.get("value", ""))
                        source_kind = (
                            "string" if raw_value.startswith(("\"", "'"))
                            else "constant" if re.fullmatch(r"(?:0x[0-9a-f]+|[-+]?\d+)", raw_value, re.I)
                            else "global" if raw_value.startswith("[")
                            else "expression"
                        )
                        args.append({"index": index, **item, "source_kind": source_kind, "resolved": True})
                downstream: list[str] = []
                if call_address is not None:
                    for candidate_api, candidate_site, _ in unique_calls.values():
                        candidate_address = parse_address(candidate_site)
                        if candidate_address is not None and candidate_address > call_address and candidate_api.casefold() != api.casefold():
                            downstream.append(candidate_api)
                source_rows_for_trace = [call_row]
                source_rows_for_trace.extend(item[0] for item in before[-8:])
                source_rows_for_trace.extend(
                    row for row, _ in target_rows
                    if row.kind == "function_call"
                    and isinstance(row.value, dict)
                    and str(row.value.get("api") or row.value.get("target_name") or row.value.get("target_function") or "").casefold() == api.casefold()
                )
                # Preserve every explicitly cited row in the derived trace.
                # A planner may cite a context row, an instruction window and
                # a callsite separately; dropping one of those IDs makes the
                # resulting evidence look less reproducible even though the
                # same static data was used for the calculation.
                source_rows_for_trace.extend(source_rows)
                source_rows_for_trace = list({str(row.id): row for row in source_rows_for_trace}.values())
                add(
                    "api_argument_trace",
                    {
                        "api": api,
                        "callsite": callsite or None,
                        "function": function_name(call_row),
                        "function_entry": (call_row.anchor or {}).get("function_entry") if isinstance(call_row.anchor, dict) else None,
                        "rva": (call_row.anchor or {}).get("rva") if isinstance(call_row.anchor, dict) else None,
                        "arguments": args,
                        "recovered_argument_count": sum(1 for item in args if item.get("resolved")),
                        "consumer": api,
                        "downstream_consumers": list(dict.fromkeys(downstream))[:8],
                        "trace_quality": "x64_register_window" if any(item.get("resolved") for item in args) else "callsite_only",
                        "static_only": True,
                    },
                    source_rows_for_trace,
                )
        elif action.action_type == ActionType.EVALUATE_CONSTANT:
            for row, text in target_rows:
                upper = text.upper()
                if "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS" in upper or "0X00020000" in upper or "0X20000" in upper:
                    add(
                        "constant",
                        {"name": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS", "value": "0x00020000", "verification": "static"},
                        [row],
                    )
        elif action.action_type == ActionType.DECODE_CANDIDATE:
            decode_rows = [
                (row, text)
                for row, text in token_rows
                if row.kind in {"mechanism_decode_window", "encoded_blob", "crypto_indicator"}
                and (target_casefold in text.casefold() or target_casefold in {"xor", "decode", "config"})
            ]
            for row, _ in decode_rows:
                if row.kind in {"mechanism_decode_window", "encoded_blob", "crypto_indicator"}:
                    candidate = dict(row.value) if isinstance(row.value, dict) else {}
                    verification = candidate.get("verification_result")
                    if artifact_content is not None and candidate.get("memory_addresses"):
                        verification = verify_xor_decode_candidate(
                            candidate,
                            artifact_content,
                            pe_summary or {},
                        )
                    if isinstance(verification, dict):
                        # A successful byte replay is only half of decoder
                        # recovery.  Link the decoded value to a statically
                        # visible consumer in the same function/RVA when one
                        # exists (LoadLibrary, resolver, transport, process,
                        # or file sink).  Keep the absence explicit instead
                        # of promoting a decoded string to a behavior claim.
                        candidate_anchor = row.anchor if isinstance(row.anchor, dict) else {}
                        candidate_function = str(
                            candidate_anchor.get("function_entry")
                            or candidate.get("function_entry")
                            or ""
                        ).casefold()
                        consumer_terms = (
                            "loadlibrary", "getprocaddress", "ldrgetprocedureaddress",
                            "winhttp", "wininet", "socket", "createprocess", "shellexecute",
                            "virtualalloc", "writefile", "readfile", "regsetvalue",
                        )
                        consumer_rows: list[Evidence] = []
                        consumer_candidates: list[dict[str, object]] = []
                        for possible in artifact_rows:
                            if possible.id == row.id:
                                continue
                            possible_anchor = possible.anchor if isinstance(possible.anchor, dict) else {}
                            possible_function = str(possible_anchor.get("function_entry") or "").casefold()
                            possible_text = self._investigation_value_text(
                                {"value": possible.value, "anchor": possible.anchor}
                            ).casefold()
                            if not any(term in possible_text for term in consumer_terms):
                                continue
                            if candidate_function and possible_function and candidate_function != possible_function:
                                # Cross-function consumers are retained only
                                # when the row carries an explicit data-flow
                                # or call edge.  Unanchored global imports do
                                # not count as a consumer.
                                if possible.kind not in {"function_call", "api_argument_trace", "value_flow", "function_data_correlation"}:
                                    continue
                            consumer_rows.append(possible)
                            value = possible.value if isinstance(possible.value, dict) else {}
                            api = value.get("api") or value.get("target_name") or value.get("target_function")
                            consumer_candidates.append({
                                "evidence_id": possible.id,
                                "kind": possible.kind,
                                "api": str(api) if api else None,
                                "function_entry": possible_anchor.get("function_entry"),
                            })
                        consumer_candidates = list({
                            (str(item.get("evidence_id")), str(item.get("api")), str(item.get("function_entry"))): item
                            for item in consumer_candidates
                        }.values())[:16]
                        decode_value = {
                            "source_kind": row.kind,
                            "candidate": {
                                key: value
                                for key, value in candidate.items()
                                if key != "verification_result"
                            },
                            "verification": verification,
                            "verification_status": verification.get("status", "UNKNOWN"),
                            "consumer_status": "LINKED_STATIC" if consumer_candidates else "NOT_IDENTIFIED",
                            "consumer_candidates": consumer_candidates,
                            "consumer_evidence_ids": [str(item["evidence_id"]) for item in consumer_candidates],
                            "static_only": True,
                        }
                        add(
                            "decode_result",
                            decode_value,
                            [row, *consumer_rows[:23]],
                        )
                    else:
                        add(
                            "decode_candidate",
                            {
                                "status": "UNVERIFIED_STATIC_CANDIDATE",
                                "source_kind": row.kind,
                                "static_only": True,
                            },
                            [row],
                        )
        elif action.action_type == ActionType.COMPARE_FUNCTION:
            for row, _ in target_rows[:8]:
                if row.kind == "function_simhash":
                    add("function_similarity_candidate", {"fingerprint": row.value}, [row])
        else:
            for row, _ in token_rows[:8]:
                if row.kind.startswith("function") or row.kind in {"xref", "cfg_block"}:
                    add("investigation_observation", {"source_kind": row.kind}, [row])
        # A model-selected investigation action should leave behind a
        # semantic, evaluator-addressable link when the static corpus already
        # contains all components of a mechanism. The correlator is read-only
        # and every emitted row is wrapped by ``add`` so it receives the same
        # derivation digest and provenance contract as other observations.
        if action.planner_turn_id:
            static_rows = [
                {
                    "id": row.id,
                    "kind": row.kind,
                    "value": row.value,
                    "anchor": row.anchor,
                }
                for row in artifact_rows
            ]
            for link in derive_static_mechanism_links(static_rows):
                link_value = link.get("value") if isinstance(link.get("value"), dict) else {}
                source_ids = {
                    str(item)
                    for item in link_value.get("source_evidence_ids", ())
                    if item
                }
                link_text = self._investigation_value_text(link_value).casefold()
                cited_ids = {str(item) for item in action.source_evidence_ids if item}
                # Keep model action output target-focused. A GET_XREFS_TO for
                # GetProcAddress may discover a resolver link, but must not
                # attach an unrelated shell/ETW link found elsewhere in the
                # same artifact. The source citation is a second valid route
                # for a model-selected function-level action.
                if target_casefold and target_casefold not in link_text and not (source_ids & cited_ids):
                    continue
                link_rows = [row for row in artifact_rows if row.id in source_ids]
                add(
                    str(link.get("kind", "investigation_mechanism_link")),
                    dict(link_value),
                    link_rows,
                    nature="STATIC_INFERRED",
                )
        # Deduplicate only identical observations.  The same API can occur at
        # multiple function/RVA anchors and each anchor is an independent
        # piece of evidence; collapsing on ``(kind, api)`` silently discarded
        # that provenance in the old implementation.
        unique: dict[tuple[str, str, str], dict[str, object]] = {}
        for item in observations:
            value = item.get("value") if isinstance(item.get("value"), dict) else {}
            source_ids = tuple(str(item_id) for item_id in value.get("source_evidence_ids", ()) if item_id)
            source_anchors = item.get("anchor", {}).get("source_anchors", ()) if isinstance(item.get("anchor"), dict) else ()
            identity = str(value.get("api", value.get("name", "")))
            anchor_key = json.dumps(source_anchors, ensure_ascii=True, sort_keys=True, default=str)
            key = (str(item.get("kind")), identity, anchor_key)
            existing = unique.get(key)
            if existing is None:
                unique[key] = item
                continue
            existing_value = existing.get("value") if isinstance(existing.get("value"), dict) else {}
            merged_ids = list(dict.fromkeys(
                [str(item_id) for item_id in existing_value.get("source_evidence_ids", ()) if item_id]
                + list(source_ids)
            ))
            existing_value["source_evidence_ids"] = merged_ids
            derivation = existing_value.get("derivation")
            if isinstance(derivation, dict):
                derivation["input_evidence_ids"] = merged_ids
                derivation["input_digest"] = hashlib.sha256(
                    json.dumps(
                        {"action_type": action.action_type.value, "target": target, "source_evidence_ids": merged_ids},
                        ensure_ascii=True,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
            existing["value"] = existing_value
            if isinstance(existing.get("anchor"), dict):
                existing["anchor"]["source_evidence_ids"] = merged_ids
        return list(unique.values())[:64]

    def _run_investigation_loop(
        self,
        task_id: str,
        *,
        model_actions_only: bool = False,
    ) -> list[str]:
        """Persist and run investigation threads for all non-container artifacts.

        ``model_actions_only`` is the immediate Action Executor path between a
        planner turn and its replan.  It runs only catalog-approved model
        proposals and deliberately does not let deterministic playbooks add
        unrelated experiments in the same turn.
        """
        limitations: list[str] = []
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if task is None:
                raise LookupError(task_id)
            artifacts = list(
                session.scalars(
                    select(Artifact)
                    .where(Artifact.task_id == task_id, Artifact.role != "CONTAINER")
                    .order_by(Artifact.created_at)
                )
            )
            snapshot = dict(task.strategy_snapshot or {}).get("investigation", {})
            snapshot_threads = {
                str(item.get("artifact_id")): item
                for item in snapshot.get("threads", [])
                if isinstance(item, dict)
            }
            # Investigation may be invoked more than once for a task (for
            # example, a model-action turn followed by deterministic
            # finalization).  Keep the durable runtime projection append-only
            # across invocations; replacing it here made the last no-op pass
            # erase the evidence of earlier actions from task snapshots.
            prior_runtime = snapshot.get("runtime", {})
            prior_runtime = prior_runtime if isinstance(prior_runtime, dict) else {}
            runtime_events: list[dict[str, object]] = [
                item for item in prior_runtime.get("events", []) if isinstance(item, dict)
            ][-512:]
            runtime_actions: list[dict[str, object]] = [
                item for item in prior_runtime.get("actions", []) if isinstance(item, dict)
            ][-128:]
            runtime_gates: list[dict[str, object]] = [
                item for item in prior_runtime.get("gates", []) if isinstance(item, dict)
            ][-128:]
            playbooks = MechanismPlaybookRegistry()
            # Expand every bounded high-value seed cluster into its own
            # durable investigation thread.  The old implementation selected
            # only the first cluster and left the remaining frontier as
            # descriptive snapshot data, making multi-seed scheduling
            # effectively write-only.  Keep the first thread identity stable
            # for replay compatibility and derive deterministic identities for
            # additional clusters.
            work_items: list[tuple[Artifact, dict[str, object]]] = []
            seed_maps = snapshot.get("seed_maps", {})
            for artifact in artifacts:
                base_seed = dict(snapshot_threads.get(artifact.id, {}) or {})
                artifact_seed_map = (
                    seed_maps.get(artifact.id, {})
                    if isinstance(seed_maps, dict)
                    else {}
                )
                clusters = (
                    artifact_seed_map.get("clusters", [])
                    if isinstance(artifact_seed_map, dict)
                    else []
                )
                bounded_clusters = [
                    item for item in clusters[:4]
                    if isinstance(item, dict) and str(item.get("question", "")).strip()
                ]
                if not bounded_clusters:
                    work_items.append((artifact, base_seed))
                    continue
                for index, cluster in enumerate(bounded_clusters):
                    cluster_seed = dict(base_seed)
                    cluster_seed["_seed_cluster"] = cluster
                    if index:
                        cluster_id = str(cluster.get("id") or f"cluster-{index}")
                        thread_id = "thread-" + hashlib.sha256(
                            f"{task.id}:{artifact.id}:{cluster_id}".encode("utf-8")
                        ).hexdigest()[:20]
                        hypothesis_id = "hypothesis-" + hashlib.sha256(
                            f"{thread_id}:mechanism".encode("utf-8")
                        ).hexdigest()[:20]
                        cluster_seed.update(
                            {
                                "id": thread_id,
                                "hypothesis_ids": [hypothesis_id],
                                "mechanism_ids": [
                                    "mechanism-"
                                    + hashlib.sha256(
                                        f"{thread_id}:static".encode("utf-8")
                                    ).hexdigest()[:20]
                                ],
                            }
                        )
                    work_items.append((artifact, cluster_seed))

            for artifact, seed_override in work_items:
                seed = dict(seed_override or snapshot_threads.get(artifact.id, {}) or {})
                # The static parser emits a bounded seed map before this
                # loop.  Consume its highest-priority cluster as the active
                # investigation question, while retaining the original
                # artifact seed as a fallback for older snapshots.
                seed_maps = snapshot.get("seed_maps", {})
                artifact_seed_map = (
                    seed_maps.get(artifact.id, {})
                    if isinstance(seed_maps, dict)
                    else {}
                )
                clusters = artifact_seed_map.get("clusters", []) if isinstance(artifact_seed_map, dict) else []
                selected_clusters = [
                    item for item in clusters
                    if isinstance(item, dict) and str(item.get("question", "")).strip()
                ][:4]
                override_cluster = seed.get("_seed_cluster")
                if isinstance(override_cluster, dict):
                    selected_clusters = [override_cluster]
                selected_cluster = selected_clusters[0] if selected_clusters else None
                if selected_cluster is not None:
                    frontier_questions = list(dict.fromkeys(
                        str(item.get("question", "")).strip()
                        for item in selected_clusters
                        if str(item.get("question", "")).strip()
                    ))
                    frontier_evidence_ids = list(dict.fromkeys(
                        str(evidence_id)
                        for item in selected_clusters
                        for evidence_id in (item.get("evidence_ids", []) if isinstance(item.get("evidence_ids", []), list) else [])
                        if str(evidence_id).strip()
                    ))[:96]
                    seed = {
                        **seed,
                        # The first cluster remains the stable primary ID for
                        # replay compatibility; the frontier fields make the
                        # bounded multi-seed decision explicit to the Agent,
                        # report, and audit consumers.
                        "seed_cluster_id": str(selected_cluster.get("id", "")),
                        "seed_cluster_ids": [str(item.get("id", "")) for item in selected_clusters],
                        "seed_cluster_categories": [str(item.get("category", "generic")) for item in selected_clusters],
                        "seed_cluster_category": str(selected_cluster.get("category", "generic")),
                        "seed_cluster_evidence_ids": frontier_evidence_ids[:32],
                        "seed_frontier_evidence_ids": frontier_evidence_ids,
                        "seed_frontier_questions": frontier_questions,
                    }
                thread_id = str(seed.get("id") or f"thread-{hashlib.sha256(f'{task.id}:{artifact.id}'.encode()).hexdigest()[:20]}")
                hypothesis_id = str((seed.get("hypothesis_ids") or [""])[0] or f"hypothesis-{hashlib.sha256(f'{thread_id}:mechanism'.encode()).hexdigest()[:20]}")
                thread = session.get(InvestigationThreadRecord, thread_id)
                if thread is None:
                    thread = InvestigationThreadRecord(
                        id=thread_id,
                        task_id=task.id,
                        artifact_id=artifact.id,
                        state="DISCOVERED",
                        question=str(seed.get("question") or "Which evidence explains the artifact's highest-risk static mechanism?"),
                        seed_kind=str(seed.get("seed_kind") or "artifact_triage"),
                        hypothesis_ids=[hypothesis_id],
                    )
                    session.add(thread)
                    session.flush()
                hypothesis = session.get(InvestigationHypothesisRecord, hypothesis_id)
                if hypothesis is None:
                    hypothesis = InvestigationHypothesisRecord(
                        id=hypothesis_id,
                        task_id=task.id,
                        thread_id=thread.id,
                        statement=str(seed.get("hypothesis_statement") or "The artifact may contain an ordered process, loading, decode, network, or evasion mechanism."),
                        dimension=str(seed.get("hypothesis_dimension") or "mechanism_discovery"),
                        status="OPEN",
                        confidence="LOW",
                        required_evidence=list(seed.get("required_evidence") or ["function_context", "function_call"]),
                    )
                    session.add(hypothesis)
                    session.flush()
                # Investigation context must remain bounded independently of
                # the parser's raw output volume.  Large binaries commonly
                # produce thousands of low-signal string rows; loading and
                # repeatedly flattening all of them holds the task transaction
                # open and can starve the API.  Keep all high-signal mechanism
                # kinds within a generous cap, then add a small deterministic
                # string/other sample for discovery.
                high_signal_kinds = {
                    "pe_structure",
                    "import_symbol",
                    "export_symbol",
                    "function",
                    "function_context",
                    "function_call",
                    "function_mechanism",
                    "function_instruction_window",
                    "function_interface",
                    "function_ioc",
                    "function_data_correlation",
                    "api_argument_trace",
                    "function_simhash",
                    "xref",
                    "cfg_block",
                    "cross_function_chain",
                    "mechanism_decode_window",
                    "mechanism_dynamic_resolution",
                    "mechanism_environment_check",
                    "mechanism_memory_permission",
                    "mechanism_process_creation",
                    "loader_indicator",
                    "execution_indicator",
                    "anti_analysis_indicator",
                    "network_indicator",
                    "resource_inventory",
                    "embedded_object",
                    "script_line",
                    "script_call",
                    "script_import",
                }
                base_evidence_filter = (
                    Evidence.task_id == task.id,
                    Evidence.artifact_id == artifact.id,
                    Evidence.nature != "BACKGROUND_REPORTED",
                )
                high_signal_rows = list(
                    session.scalars(
                        select(Evidence)
                        .where(*base_evidence_filter, Evidence.kind.in_(high_signal_kinds))
                        .order_by(Evidence.created_at, Evidence.id)
                        .limit(768)
                    )
                )
                sampled_rows = list(
                    session.scalars(
                        select(Evidence)
                        .where(*base_evidence_filter, ~Evidence.kind.in_(high_signal_kinds))
                        .order_by(Evidence.created_at, Evidence.id)
                        .limit(256)
                    )
                )
                all_source_rows = list(
                    {
                        row.id: row
                        for row in (*high_signal_rows, *sampled_rows)
                    }.values()
                )
                # SQLite returns persisted timestamps as naive values while
                # freshly-created rows in the same transaction may still be
                # timezone-aware.  Sort by their canonical textual form so a
                # multi-seed pass cannot fail merely because both forms are
                # present in one session.
                all_source_rows.sort(
                    key=lambda row: (
                        row.created_at.isoformat() if getattr(row, "created_at", None) else "",
                        row.id,
                    )
                )
                # Background reports are provenance-bearing context, never
                # authorization for a sample-derived action or mechanism.
                # Keep them in the immutable ledger/report, but isolate them
                # from playbook matching and investigation execution.
                source_rows = [
                    row for row in all_source_rows if row.nature != "BACKGROUND_REPORTED"
                ]
                profile_rows = [
                    {
                        "id": row.id,
                        "kind": row.kind,
                        "nature": row.nature,
                        "value": row.value,
                        "anchor": row.anchor,
                    }
                    for row in source_rows
                ]
                playbook = playbooks.best_match(profile_rows)
                # A single PE often contains several independent semantic
                # questions (for example API resolution and entry-point
                # timeline). Keep at least one specialist thread separate
                # from the artifact seed so the runtime can show real
                # investigation branching without duplicating raw evidence.
                spawned_thread_kind = (
                    playbook.spawned_threads[0]
                    if playbook is not None and playbook.spawned_threads
                    else "generic-mechanism-thread"
                )
                existing_for_artifact = list(
                    session.scalars(
                        select(InvestigationThreadRecord).where(
                            InvestigationThreadRecord.task_id == task.id,
                            InvestigationThreadRecord.artifact_id == artifact.id,
                        )
                    )
                )
                if len(existing_for_artifact) < 2:
                    secondary_thread_id = "thread-" + hashlib.sha256(
                        f"{task.id}:{artifact.id}:{spawned_thread_kind}".encode("utf-8")
                    ).hexdigest()[:20]
                    if secondary_thread_id == thread_id:
                        secondary_thread_id = "thread-" + hashlib.sha256(
                            f"{task.id}:{artifact.id}:secondary".encode("utf-8")
                        ).hexdigest()[:20]
                    secondary = session.get(InvestigationThreadRecord, secondary_thread_id)
                    if secondary is None:
                        secondary_hypothesis_id = "hypothesis-" + hashlib.sha256(
                            f"{secondary_thread_id}:mechanism".encode("utf-8")
                        ).hexdigest()[:20]
                        secondary_mechanism_id = "mechanism-" + hashlib.sha256(
                            f"{secondary_thread_id}:static".encode("utf-8")
                        ).hexdigest()[:20]
                        secondary = InvestigationThreadRecord(
                            id=secondary_thread_id,
                            task_id=task.id,
                            artifact_id=artifact.id,
                            state="DISCOVERED",
                            question=(
                                "Which independent static evidence path corroborates or contradicts "
                                f"the {spawned_thread_kind} mechanism?"
                            ),
                            seed_kind=spawned_thread_kind,
                            hypothesis_ids=[secondary_hypothesis_id],
                        )
                        session.add(secondary)
                        session.flush()
                        session.add(
                            InvestigationHypothesisRecord(
                                id=secondary_hypothesis_id,
                                task_id=task.id,
                                thread_id=secondary_thread_id,
                                statement=(
                                    "An independent static evidence path may corroborate the "
                                    f"{spawned_thread_kind} mechanism."
                                ),
                                dimension=spawned_thread_kind,
                                status="OPEN",
                                confidence="LOW",
                                required_evidence=list(playbook.required_evidence_kinds if playbook else ("function_context", "function_call")),
                            )
                        )
                        session.flush()
                        snapshot.setdefault("threads", []).append(
                            {
                                "id": secondary_thread_id,
                                "artifact_id": artifact.id,
                                "state": "DISCOVERED",
                                "question": secondary.question,
                                "seed_kind": spawned_thread_kind,
                                "evidence_ids": [],
                                "hypothesis_ids": [secondary_hypothesis_id],
                                "mechanism_ids": [secondary_mechanism_id],
                            }
                        )
                        snapshot.setdefault("mechanisms", []).append(
                            {
                                "id": secondary_mechanism_id,
                                "thread_id": secondary_thread_id,
                                "artifact_id": artifact.id,
                                "dimension": spawned_thread_kind,
                                "steps": [],
                                "evidence_ids": [],
                                "status": "UNKNOWN",
                                "limitations": ["Independent corroboration is pending a bounded static action."],
                                "type": spawned_thread_kind,
                            }
                        )
                        # Keep the independent branch explicit for a live
                        # model/DSH session, where a later turn can resume it.
                        # Offline deterministic runs must remain terminal: a
                        # synthetic WAITING row would look like an unfinished
                        # action to callers and break the ordinary task
                        # contract.  The branch itself is still represented in
                        # the thread snapshot in both modes.
                        deferred_action_type = ActionType.GET_STRINGS_REFERENCED
                        deferred_action_id = (
                            f"{secondary_thread_id}:waiting:{deferred_action_type.value.lower()}"
                        )
                        deferred_status = "WAITING" if self.settings.model_calls_enabled else "FAILED"
                        deferred_error = None if deferred_status == "WAITING" else "NO_NEW_EVIDENCE"
                        deferred_autopsy = (
                            no_new_evidence_autopsy(
                                {
                                    "action_type": deferred_action_type.value,
                                    "target_selector": {"target": "file"},
                                    "target_artifact_id": artifact.id,
                                    "artifact_boundary": artifact.id,
                                    "dedupe_key": canonical_action_key(
                                        deferred_action_type.value,
                                        {"target_selector": {"target": "file"}},
                                    ),
                                    "source_evidence_ids": [],
                                    "tool_status": "SUCCEEDED",
                                    "failure_interpretation": "NO_NEW_EVIDENCE",
                                }
                            )
                            if deferred_status == "FAILED"
                            else None
                        )
                        session.add(
                            InvestigationActionRecord(
                                id=deferred_action_id,
                                task_id=task.id,
                                thread_id=secondary_thread_id,
                                hypothesis_id=secondary_hypothesis_id,
                                artifact_id=artifact.id,
                                action_type=deferred_action_type.value,
                                reason=(
                                    "Independent corroboration is queued for a bounded static "
                                    "string/reference pass after the primary mechanism thread."
                                ),
                                parameters={
                                    "target": "file",
                                    "deferred": True,
                                    **({"_autopsy": deferred_autopsy} if deferred_autopsy else {}),
                                },
                                target_selector={"target": "file"},
                                expected_evidence_kinds=["string", "indicator"],
                                success_condition="new_targeted_evidence",
                                failure_interpretation="UNKNOWN",
                                cost_units=ActionCatalog.default().require(deferred_action_type).cost_units,
                                priority=80,
                                status=deferred_status,
                                error=deferred_error,
                                finished_at=utcnow() if deferred_status == "FAILED" else None,
                            )
                        )
                        secondary.action_ids = [deferred_action_id]
                        self._audit(
                            session,
                            case_id=task.case_id,
                            task_id=task.id,
                            event_type=(
                                "investigation.action_waiting"
                                if deferred_status == "WAITING"
                                else "investigation.action_no_new_evidence"
                            ),
                            actor="deterministic-seed-ranker",
                            object_type="InvestigationAction",
                            object_id=deferred_action_id,
                            payload={
                                "action_type": deferred_action_type.value,
                                "thread_id": secondary_thread_id,
                                "reason": "independent_branch_deferred",
                                "status": deferred_status,
                            },
                        )
                        self._audit(
                            session,
                            case_id=task.case_id,
                            task_id=task.id,
                            event_type="investigation.thread_seeded",
                            actor="deterministic-seed-ranker",
                            object_type="InvestigationThread",
                            object_id=secondary_thread_id,
                            payload={"seed_kind": spawned_thread_kind, "independent": True},
                        )
                profile_specs = {
                    "dynamic-api-resolution": (
                        "Which statically resolved API path explains this artifact's dynamic loading behavior?",
                        "The artifact may resolve API addresses dynamically and route them into a loading or execution path.",
                        "dynamic_api_resolution",
                    ),
                    "xor-config-recovery": (
                        "Which bounded decode path explains the artifact's encoded configuration or payload?",
                        "The artifact may contain a recoverable XOR or encoded configuration used by a later mechanism.",
                        "decode_recovery",
                    ),
                    "ppid-process-chain": (
                        "Does the artifact construct a parent-process spoofing chain, and which evidence proves it?",
                        "The artifact may construct a child process with a spoofed parent identity through an attribute-list chain.",
                        "process_creation",
                    ),
                    "entrypoint-timeline": (
                        "What ordered static call and control-flow path begins at the entrypoint?",
                        "The artifact's entrypoint may lead into an ordered execution timeline that explains its primary behavior.",
                        "entrypoint_timeline",
                    ),
                    "http-download": (
                        "Which endpoint and transport call path receives response bytes?",
                        "The artifact may download data through a statically recoverable HTTP transport path.",
                        "network_download",
                    ),
                    "process-execution": (
                        "What command, flags, and input data reach the process creation API?",
                        "The artifact may construct a child process or command from statically traced inputs.",
                        "process_execution",
                    ),
                    "defender-modification": (
                        "Which Defender registry path, value name, and data reach the write operation?",
                        "The artifact may modify Defender configuration through a statically traced registry write.",
                        "defender_modification",
                    ),
                    "etw-patch": (
                        "Does a protection change target EtwEventWrite and write the expected patch bytes?",
                        "The artifact may patch ETW reporting through a statically traceable protection and byte-write path.",
                        "etw_patch",
                    ),
                    "scheduled-task-execution": (
                        "What scheduled-task command sequence is statically reconstructed?",
                        "The artifact may use a scheduled-task execution or fallback command sequence.",
                        "scheduled_task",
                    ),
                    "plugin-module-load": (
                        "Which module is loaded, initialized, used, and released?",
                        "The artifact may load a secondary module through a statically traceable lifecycle.",
                        "plugin_lifecycle",
                    ),
                    "entry-timeline-v2": (
                        "What ordered static path leaves the entrypoint and reaches a high-value mechanism?",
                        "The artifact entrypoint may lead into an ordered call path for a high-value mechanism.",
                        "entrypoint_timeline",
                    ),
                }
                profile_spec = profile_specs.get(playbook.id) if playbook is not None else None
                if profile_spec is not None:
                    default_question, default_statement, default_dimension = profile_spec
                    if not seed.get("question"):
                        thread.question = default_question
                    if not seed.get("hypothesis_statement"):
                        hypothesis.statement = default_statement
                    hypothesis.dimension = default_dimension
                    hypothesis.required_evidence = list(playbook.required_evidence_kinds)
                    thread.seed_kind = playbook.id
                elif not seed.get("hypothesis_statement"):
                    hypothesis.dimension = "mechanism_discovery"
                    hypothesis.required_evidence = ["function_context", "function_call"]
                if selected_cluster is not None:
                    cluster_question = str(selected_cluster.get("question", "")).strip()
                    if cluster_question and thread.state in {"DISCOVERED", "PRIORITIZED", "CONTEXT_READY"}:
                        thread.question = cluster_question
                    category = str(selected_cluster.get("category", "generic"))
                    if category != "generic":
                        thread.seed_kind = f"seed-cluster:{category}"
                    runtime_events.append(
                        {
                            "thread_id": thread.id,
                            "phase": "seed_cluster_selected",
                            "action_id": None,
                            "state": thread.state,
                            "evidence_ids": list(selected_cluster.get("evidence_ids", []))[:32],
                            "message": (
                                f"Selected {selected_cluster.get('id', 'seed cluster')} "
                                f"({category}) as the bounded investigation frontier."
                            ),
                        }
                    )
                artifact_content: bytes | None = None
                content_blob = session.get(ContentBlob, artifact.content_sha256)
                if content_blob is not None and content_blob.disposed_at is None:
                    try:
                        artifact_content = self.content_store.read(content_blob.storage_key)
                    except (OSError, ValueError):
                        artifact_content = None
                pe_summary = next(
                    (
                        row.value
                        for row in source_rows
                        if row.kind == "pe_structure" and isinstance(row.value, dict)
                    ),
                    {},
                )

                def execute(action: ActionSpec) -> list[dict[str, object]]:
                    action_row = session.get(InvestigationActionRecord, action.id)
                    if action_row is None:
                        action_row = InvestigationActionRecord(
                            id=action.id,
                            task_id=task.id,
                            thread_id=thread.id,
                            hypothesis_id=hypothesis.id,
                            artifact_id=artifact.id,
                            action_type=action.action_type.value,
                            reason=action.reason,
                            parameters={
                                **dict(action.parameters),
                                "origin": (
                                    "model"
                                    if action.planner_turn_id
                                    else "deterministic_fallback"
                                ),
                                # Preserve the model's cited evidence on the
                                # durable action so queued/replayed execution
                                # retains the same authorization scope.
                                "_source_evidence_ids": list(action.source_evidence_ids),
                                **(
                                    {"_planner_turn_id": action.planner_turn_id}
                                    if action.planner_turn_id
                                    else {}
                                ),
                                **(
                                    {"_model_provenance": dict(action.provenance)}
                                    if action.provenance
                                    else {}
                                ),
                            },
                            target_selector=dict(action.target_selector),
                            expected_evidence_kinds=list(action.expected_evidence_kinds),
                            success_condition=action.success_condition,
                            failure_interpretation=action.failure_interpretation.value,
                            cost_units=action.cost_units or ActionCatalog.default().require(action.action_type).cost_units,
                            priority=action.priority,
                            depends_on=list(action.depends_on),
                        )
                        session.add(action_row)
                    action_row.status = "RUNNING"
                    action_row.attempts = int(action_row.attempts or 0) + 1
                    session.flush()
                    try:
                        # The investigation context above is deliberately
                        # bounded for planner prompts.  It must not become a
                        # correctness boundary for an approved action: a
                        # cited function may be outside that prompt window.
                        # Reload the cited rows and the bounded high-signal
                        # artifact-local corpus at execution time so targeted
                        # xref/decompile queries can recover their complete
                        # static context without crossing artifacts.
                        execution_rows = list(source_rows)
                        cited_ids = tuple(
                            dict.fromkeys(
                                str(item_id)
                                for item_id in action.source_evidence_ids
                                if str(item_id).strip()
                            )
                        )
                        if cited_ids:
                            cited_rows = list(
                                session.scalars(
                                    select(Evidence).where(
                                        Evidence.task_id == task.id,
                                        Evidence.artifact_id == artifact.id,
                                        Evidence.id.in_(cited_ids),
                                        Evidence.nature != "BACKGROUND_REPORTED",
                                    )
                                )
                            )
                            execution_rows.extend(cited_rows)
                        action_kinds = {
                            "function",
                            "function_context",
                            "function_call",
                            "function_data_correlation",
                            "function_instruction_window",
                            "function_mechanism",
                            "function_ioc",
                            "import_symbol",
                            "loader_indicator",
                            "execution_indicator",
                            "anti_analysis_indicator",
                            "mechanism_dynamic_resolution",
                            "mechanism_memory_permission",
                            "xref",
                            "cfg_block",
                            "string",
                            "data_reference",
                        }
                        # Function-targeted actions need same-function context;
                        # API/xref actions need all call-bearing rows.  Keep
                        # the query bounded while including every row emitted
                        # by the deterministic static extractors for normal
                        # sample sizes.
                        if action.target_selector or action.parameters:
                            execution_rows.extend(
                                session.scalars(
                                    select(Evidence)
                                    .where(
                                        Evidence.task_id == task.id,
                                        Evidence.artifact_id == artifact.id,
                                        Evidence.kind.in_(action_kinds),
                                        Evidence.nature != "BACKGROUND_REPORTED",
                                    )
                                    .order_by(Evidence.created_at, Evidence.id)
                                    .limit(50_000)
                                )
                            )
                        execution_rows = list({row.id: row for row in execution_rows}.values())
                        produced = self._derive_investigation_observations(
                            execution_rows,
                            action,
                            artifact_content=artifact_content,
                            pe_summary=pe_summary if isinstance(pe_summary, dict) else {},
                        )
                    except Exception as exc:
                        action_row.status = "FAILED"
                        action_row.error = f"{type(exc).__name__}: {exc}"[:512]
                        action_row.parameters = {
                            **dict(action_row.parameters or {}),
                            "_autopsy": no_new_evidence_autopsy(
                                {
                                    "action_type": action.action_type.value,
                                    "target_selector": dict(action.target_selector),
                                    "target_artifact_id": artifact.id,
                                    "artifact_boundary": artifact.id,
                                    "dedupe_key": action.dedupe_key,
                                    "source_evidence_ids": list(action.source_evidence_ids),
                                    "tool_status": "FAILED",
                                    "tool_error": type(exc).__name__,
                                }
                            ),
                        }
                        action_row.finished_at = utcnow()
                        self._audit(
                            session,
                            case_id=task.case_id,
                            task_id=task.id,
                            event_type="investigation.action_failed",
                            actor="investigator",
                            object_type="InvestigationAction",
                            object_id=action.id,
                            payload={"action_type": action.action_type.value, "error_type": type(exc).__name__},
                        )
                        raise
                    rows: list[dict[str, object]] = []
                    evidence_ids: list[str] = []
                    tool_run: ToolRun | None = None
                    if produced:
                        tool_run = ToolRun(
                            id=new_id(),
                            task_id=task.id,
                            artifact_id=artifact.id,
                            tool_name=f"investigation:{action.action_type.value.lower()}",
                            tool_version="1.0.0",
                            status="SUCCEEDED",
                            parameters={
                                "action_type": action.action_type.value,
                                "target_selector": dict(action.target_selector),
                                "source_evidence_ids": list(action.source_evidence_ids),
                                "expected_evidence_kinds": list(action.expected_evidence_kinds),
                                "success_condition": action.success_condition,
                                "failure_interpretation": action.failure_interpretation.value,
                                "dedupe_key": action.dedupe_key,
                                "scheduler": "investigation_loop",
                                "planner_turn_id": action.planner_turn_id,
                            },
                            environment={
                                "sample_execution": False,
                                "network_access": False,
                                "executor": "static_evidence_query",
                                # This executor reads already-persisted Evidence
                                # rows only; it never opens or executes sample
                                # bytes.  The explicit boundary distinguishes
                                # it from worker-backed untrusted-data tools.
                                "isolation_boundary": "database_only_no_sample_execution",
                            },
                            output={"evidence_count": len(produced)},
                            started_at=utcnow(),
                            finished_at=utcnow(),
                        )
                        session.add(tool_run)
                        session.flush()
                    for item in produced:
                        evidence = Evidence(
                            id=new_id(),
                            task_id=task.id,
                            artifact_id=artifact.id,
                            tool_run_id=tool_run.id if tool_run is not None else action_row.id[:36],
                            module="investigation",
                            kind=str(item.get("kind", "investigation_observation")),
                            nature=str(item.get("nature", "STATIC_INFERRED")),
                            value=dict(item.get("value", {})) if isinstance(item.get("value"), dict) else {},
                            anchor={
                                **(dict(item.get("anchor", {})) if isinstance(item.get("anchor"), dict) else {}),
                                "artifact_id": artifact.id,
                                "logical_path": artifact.logical_path,
                                "content_sha256": artifact.content_sha256,
                            },
                        )
                        session.add(evidence)
                        session.flush()
                        source_rows.append(evidence)
                        rows.append({"id": evidence.id, "kind": evidence.kind, "nature": evidence.nature, "value": evidence.value, "anchor": evidence.anchor})
                        evidence_ids.append(evidence.id)
                        self._audit(session, case_id=task.case_id, task_id=task.id, event_type="investigation.evidence_observed", actor="investigator", object_type="Evidence", object_id=evidence.id, payload={"action_id": action.id, "action_type": action.action_type.value, "kind": evidence.kind})
                    action_row.result_evidence_ids = evidence_ids
                    action_row.finished_at = utcnow()
                    if evidence_ids:
                        action_row.status = "SUCCEEDED"
                        action_row.error = None
                        self._audit(
                            session,
                            case_id=task.case_id,
                            task_id=task.id,
                            event_type="investigation.action_completed",
                            actor="investigator",
                            object_type="InvestigationAction",
                            object_id=action.id,
                            payload={"action_type": action.action_type.value, "evidence_count": len(evidence_ids)},
                        )
                    else:
                        # A query that ran correctly but found no eligible
                        # static observation is not a successful experiment.
                        # Persist an explicit, non-refuting outcome so the
                        # scheduler, UI and evaluator cannot mistake it for a
                        # productive investigation step.
                        action_row.status = "FAILED"
                        action_row.error = "NO_NEW_EVIDENCE"
                        selector_values = {
                            str(value).casefold()
                            for value in dict(action.target_selector).values()
                            if isinstance(value, (str, int)) and str(value).strip()
                        }
                        wildcard_targets = {
                            "global", "file", "strings", "string", "str", "file_header",
                            "pe_header", "pe_headers_and_imports", "strings_and_signals",
                            "functions_and_xrefs",
                        }
                        target_found = (
                            bool(selector_values & wildcard_targets)
                            or any(
                                any(
                                    value in self._investigation_value_text(
                                        {"value": row.value, "anchor": row.anchor}
                                    ).casefold()
                                    for value in selector_values
                                )
                                for row in execution_rows
                            )
                        )
                        expected_kinds = {
                            str(kind).casefold()
                            for kind in action.expected_evidence_kinds
                            if str(kind).strip()
                        }
                        existing_ids = [
                            row.id
                            for row in execution_rows
                            if not expected_kinds or row.kind.casefold() in expected_kinds
                        ][:32]
                        autopsy = no_new_evidence_autopsy(
                            {
                                "action_type": action.action_type.value,
                                "target_selector": dict(action.target_selector),
                                "target_artifact_id": artifact.id,
                                "artifact_boundary": artifact.id,
                                "dedupe_key": action.dedupe_key,
                                "source_evidence_ids": list(action.source_evidence_ids),
                                "existing_evidence_ids": existing_ids,
                                "target_found": target_found,
                                "target_resolved": target_found,
                                "tool_status": "SUCCEEDED",
                                "failure_interpretation": action.failure_interpretation.value,
                                "static_only": True,
                            }
                        )
                        action_row.parameters = {
                            **dict(action_row.parameters or {}),
                            "_autopsy": autopsy,
                        }
                        self._audit(
                            session,
                            case_id=task.case_id,
                            task_id=task.id,
                            event_type="investigation.action_no_new_evidence",
                            actor="investigator",
                            object_type="InvestigationAction",
                            object_id=action.id,
                            payload={
                                "action_type": action.action_type.value,
                                "failure_interpretation": FailureInterpretation.NO_NEW_EVIDENCE.value,
                                "target_selector": dict(action.target_selector),
                                **autopsy,
                            },
                        )
                    return rows

                initial = [
                    {"id": row.id, "kind": row.kind, "nature": row.nature, "value": row.value, "anchor": row.anchor}
                    for row in source_rows
                ]
                proposed_actions: list[ActionSpec] = []
                dynamic_plan = (task.strategy_snapshot or {}).get("dynamic_planning", {})
                raw_model_actions: list[object] = []
                if isinstance(dynamic_plan, dict):
                    raw_model_actions.extend(dynamic_plan.get("action_history", []))
                    raw_model_actions.extend(dynamic_plan.get("actions", []))
                executed_model_action_keys = {
                    canonical_action_key(
                        str(row.action_type),
                        {"target_selector": dict(row.target_selector or {})},
                    )
                    for row in session.scalars(
                        select(InvestigationActionRecord).where(
                            InvestigationActionRecord.task_id == task.id,
                            InvestigationActionRecord.artifact_id == artifact.id,
                            InvestigationActionRecord.status == "SUCCEEDED",
                        )
                    )
                    if row.action_type and row.target_selector
                }
                seen_model_action_keys: set[str] = set(executed_model_action_keys)
                # DSH/human proposals are persisted before execution. Feed
                # only queued, task-owned catalog actions into this loop; the
                # normal executor and verifier remain authoritative.
                queued_rows = list(
                    session.scalars(
                        select(InvestigationActionRecord).where(
                            InvestigationActionRecord.task_id == task.id,
                            InvestigationActionRecord.artifact_id == artifact.id,
                            InvestigationActionRecord.status == "QUEUED",
                        )
                    )
                )
                for queued in queued_rows:
                    try:
                        queued_type = ActionType(queued.action_type)
                        queued_failure = FailureInterpretation(queued.failure_interpretation)
                    except ValueError:
                        queued.status = "FAILED"
                        queued.error = "ACTION_CATALOG_MISMATCH"
                        continue
                    queued_key = canonical_action_key(
                        queued_type.value,
                        {"target_selector": dict(queued.target_selector or {})},
                    )
                    if queued_key in seen_model_action_keys:
                        continue
                    seen_model_action_keys.add(queued_key)
                    proposed_actions.append(
                        ActionSpec(
                            id=queued.id,
                            action_type=queued_type,
                            thread_id=thread.id,
                            hypothesis_id=hypothesis.id,
                            artifact_id=artifact.id,
                            priority=queued.priority,
                            reason=queued.reason,
                            parameters=dict(queued.parameters or {}),
                            target_selector=dict(queued.target_selector or {}),
                            expected_evidence_kinds=tuple(queued.expected_evidence_kinds or ()),
                            success_condition=queued.success_condition,
                            failure_interpretation=queued_failure,
                            cost_units=queued.cost_units,
                            source_evidence_ids=tuple(
                                str(item)
                                for item in (queued.parameters or {}).get("_source_evidence_ids", [])
                                if isinstance(item, (str, int)) and str(item).strip()
                            )[:32],
                        )
                    )
                for raw_action in raw_model_actions:
                    if not isinstance(raw_action, dict) or raw_action.get("target_artifact_id") != artifact.id:
                        continue
                    raw_type = raw_action.get("action_type")
                    if not raw_type:
                        continue
                    try:
                        action_type = ActionType(str(raw_type))
                    except ValueError:
                        continue
                    try:
                        failure_interpretation = FailureInterpretation(
                            str(raw_action.get("failure_interpretation", "UNKNOWN"))
                        )
                    except ValueError:
                        continue
                    raw_parameters = raw_action.get("parameters", {})
                    if not isinstance(raw_parameters, dict):
                        raw_parameters = {}
                    raw_selector = raw_action.get("target_selector", {})
                    if not isinstance(raw_selector, dict):
                        raw_selector = {}
                    if not raw_selector:
                        raw_selector = {
                            key: value
                            for key, value in raw_parameters.items()
                            if key in {"target", "api", "function", "function_entry", "entry", "rva", "address"}
                            and isinstance(value, (str, int))
                            and str(value).strip()
                        }
                    if not raw_selector or set(raw_selector) - {
                        "target", "api", "function", "function_entry", "entry", "rva", "address"
                    }:
                        continue
                    raw_expected = raw_action.get("expected_evidence_kinds", [])
                    if not isinstance(raw_expected, list) or not raw_expected:
                        raw_expected = raw_action.get("expected_evidence", [])
                    if not isinstance(raw_expected, list):
                        raw_expected = []
                    if not any(isinstance(item, str) and item.strip() for item in raw_expected):
                        # An incomplete model action must not abort the task;
                        # deterministic playbooks will schedule the next step.
                        continue
                    action_key = canonical_action_key(
                        str(raw_type),
                        {"target_selector": raw_selector},
                    )
                    if action_key in seen_model_action_keys:
                        continue
                    seen_model_action_keys.add(action_key)
                    proposed_actions.append(
                        ActionSpec(
                            id=f"{thread.id}:model:{len(proposed_actions)}:{action_type.value.lower()}",
                            action_type=action_type,
                            thread_id=thread.id,
                            hypothesis_id=hypothesis.id,
                            artifact_id=artifact.id,
                            priority=int(raw_action.get("priority", 25)),
                            reason=str(raw_action.get("reason", "model-proposed investigation action")),
                            parameters=raw_selector,
                            target_selector=raw_selector,
                            expected_evidence_kinds=tuple(
                                str(item) for item in raw_expected if isinstance(item, str) and item.strip()
                            )[:32],
                            success_condition=str(raw_action.get("success_condition", "new_targeted_evidence"))[:160],
                            failure_interpretation=failure_interpretation,
                            cost_units=ActionCatalog.default().require(action_type).cost_units,
                            source_evidence_ids=tuple(
                                str(item)
                                for item in raw_action.get("evidence_ids", [])
                                if isinstance(item, (str, int)) and str(item).strip()
                            )[:32],
                            planner_turn_id=(
                                str(raw_action.get("planner_turn_id"))
                                if raw_action.get("planner_turn_id")
                                else None
                            ),
                            provenance={
                                key: raw_action.get(key)
                                for key in (
                                    "prompt_sha256",
                                    "profile_digest",
                                    "policy_digest",
                                    "action_validation_digest",
                                    "action_validation",
                                )
                                if raw_action.get(key) is not None
                            },
                        )
                    )
                result = InvestigationLoopDriver(max_steps=min(32, max(8, self.settings.max_sample_files // 2))).run(
                    thread_id=thread.id,
                    artifact_id=artifact.id,
                    question=thread.question,
                    hypothesis_id=hypothesis.id,
                    hypothesis_statement=hypothesis.statement,
                    initial_evidence=initial,
                    execute=execute,
                    proposed_actions=proposed_actions,
                    allow_investigator_actions=not model_actions_only,
                )
                thread.state = result.thread_state.value
                thread.evidence_ids = [str(item.get("id")) for item in result.evidence if item.get("id")]
                thread.action_ids = [item.id for item in result.actions]
                thread.transition_count += sum(1 for item in result.events if item.phase == "state")
                thread.updated_at = utcnow()
                hypothesis.status = result.hypothesis_status
                hypothesis.confidence = "HIGH" if result.gate.accepted else "LOW"
                hypothesis.evidence_ids = list(result.gate.evidence_ids)
                hypothesis.updated_at = utcnow()
                specialized_verification = None
                if playbook is not None and playbook.mechanism_type:
                    specialized_verification = verify_mechanism(
                        playbook.mechanism_type,
                        result.evidence,
                    )
                    if not specialized_verification.accepted and artifact.detected_type == "pe":
                        missing = ", ".join(specialized_verification.missing) or "semantic closure fields"
                        boundary = (
                            f"Static boundary: no new evidence closed the "
                            f"{specialized_verification.mechanism_type} mechanism "
                            f"for {artifact.logical_path}; missing evidence: {missing}."
                        )
                        if boundary not in limitations:
                            limitations.append(boundary)
                runtime_events.extend({"thread_id": thread.id, "phase": item.phase, "action_id": item.action_id, "state": item.state, "evidence_ids": list(item.evidence_ids), "message": item.message} for item in result.events)
                runtime_actions.extend(
                    {
                        "id": item.id,
                        "action_type": item.action_type.value,
                        "thread_id": item.thread_id,
                        "hypothesis_id": item.hypothesis_id,
                        "artifact_id": item.artifact_id,
                        "priority": item.priority,
                        "reason": item.reason,
                        "target_selector": dict(item.target_selector),
                        "source_evidence_ids": list(item.source_evidence_ids),
                        "expected_evidence_kinds": list(item.expected_evidence_kinds),
                        "success_condition": item.success_condition,
                        "failure_interpretation": item.failure_interpretation.value,
                        "cost_units": item.cost_units or ActionCatalog.default().require(item.action_type).cost_units,
                        "dedupe_key": item.dedupe_key,
                        "planner_turn_id": item.planner_turn_id,
                        **(
                            dict(
                                (session.get(InvestigationActionRecord, item.id).parameters or {}).get(
                                    "_model_provenance", {}
                                )
                            )
                            if session.get(InvestigationActionRecord, item.id) is not None
                            and isinstance(
                                (session.get(InvestigationActionRecord, item.id).parameters or {}).get(
                                    "_model_provenance", {}
                                ),
                                dict,
                            )
                            else {}
                        ),
                        "result_evidence_ids": list(
                            (session.get(InvestigationActionRecord, item.id).result_evidence_ids or [])
                            if session.get(InvestigationActionRecord, item.id) is not None
                            else []
                        ),
                        "outcome": (
                            "PRODUCTIVE"
                            if session.get(InvestigationActionRecord, item.id) is not None
                            and session.get(InvestigationActionRecord, item.id).result_evidence_ids
                            else (
                                "NO_NEW_EVIDENCE"
                                if session.get(InvestigationActionRecord, item.id) is not None
                                and session.get(InvestigationActionRecord, item.id).error == "NO_NEW_EVIDENCE"
                                else "NEUTRAL"
                            )
                        ),
                        **(
                            dict(
                                (session.get(InvestigationActionRecord, item.id).parameters or {}).get(
                                    "_autopsy", {}
                                )
                            )
                            if session.get(InvestigationActionRecord, item.id) is not None
                            and isinstance(
                                (session.get(InvestigationActionRecord, item.id).parameters or {}).get(
                                    "_autopsy", {}
                                ),
                                dict,
                            )
                            else {}
                        ),
                    }
                    for item in result.actions
                )
                runtime_gates.append({"thread_id": thread.id, "hypothesis_id": hypothesis.id, "status": result.gate.status, "accepted": result.gate.accepted, "reason": result.gate.reason, "missing": list(result.gate.missing), "contradictions": list(result.gate.contradictions), "mechanism_verifier": specialized_verification.as_dict() if specialized_verification else None})
                if specialized_verification is not None:
                    seed_mechanism_ids = seed.get("mechanism_ids", [])
                    seed_mechanism_id = (
                        str(seed_mechanism_ids[0])
                        if isinstance(seed_mechanism_ids, list) and seed_mechanism_ids
                        else ""
                    )
                    for mechanism in snapshot.get("mechanisms", []):
                        if not isinstance(mechanism, dict):
                            continue
                        # Older planning snapshots may omit mechanism_ids on
                        # the thread seed. Fall back to the thread identity so
                        # a successful verifier cannot become write-only.
                        if not (
                            str(mechanism.get("id")) == seed_mechanism_id
                            or (
                                not seed_mechanism_id
                                and str(mechanism.get("thread_id")) == str(thread.id)
                            )
                        ):
                            continue
                        if specialized_verification.accepted:
                            result_rows = list(result.evidence)
                            evidence_text = [
                                self._investigation_value_text(item.get("value", {})).casefold()
                                for item in result_rows
                            ]
                            evidence_ids = list(specialized_verification.evidence_ids)
                            if specialized_verification.mechanism_type == "DYNAMIC_API_RESOLUTION":
                                module_ids = [
                                    str(item.get("id"))
                                    for item, rendered in zip(result_rows, evidence_text)
                                    if item.get("id")
                                    and any(
                                        token in rendered
                                        for token in ("lpfilename", "module", "dll", "library", "entryname", "entry point")
                                    )
                                ]
                                consumer_names = []
                                for item in result_rows:
                                    value = item.get("value", {})
                                    if not isinstance(value, dict):
                                        continue
                                    for key in ("api", "target_name", "target_function", "consumer"):
                                        candidate = value.get(key)
                                        if candidate and str(candidate).casefold() not in {"loadlibrarya", "loadlibraryw", "getprocaddress"}:
                                            consumer_names.append(str(candidate))
                                mechanism.update(
                                    {
                                        "target": artifact.logical_path,
                                        "inputs": ["module name and entry-point name data"],
                                        "transformation_or_control": [
                                            "LoadLibrary resolves the module; GetProcAddress resolves its entry point"
                                        ],
                                        "conditions": [
                                            "static call/data-flow ordering is recovered; runtime reachability is not observed"
                                        ],
                                        "outputs": ["resolved function address"],
                                        "consumers": list(dict.fromkeys(consumer_names))[:4]
                                        or ["resolved entry-point consumer"],
                                        "side_effects": [
                                            "loads a secondary module and prepares a resolved entry point"
                                        ],
                                        "evidence_ids": list(
                                            dict.fromkeys((*evidence_ids, *module_ids))
                                        )[:12],
                                    }
                                )
                            else:
                                mechanism["target"] = artifact.logical_path
                                mechanism["evidence_ids"] = evidence_ids
                            mechanism["verifier"] = specialized_verification.as_dict()
                            mechanism["status"] = "VERIFIED"
                        else:
                            mechanism["verifier"] = specialized_verification.as_dict()
                            mechanism["status"] = "UNKNOWN"
                            mechanism["evidence_ids"] = list(specialized_verification.evidence_ids)
                self._audit(session, case_id=task.case_id, task_id=task.id, event_type="investigation.thread_completed", actor="investigator-verifier", object_type="InvestigationThread", object_id=thread.id, payload={"state": thread.state, "hypothesis_status": hypothesis.status, "gate_status": result.gate.status, "action_count": len(result.actions), "evidence_count": len(result.evidence)})
                if result.gate.accepted and not model_actions_only:
                    result_text = " ".join(
                        self._investigation_value_text(item.get("value", {}))
                        for item in result.evidence
                    ).lower()
                    is_ppid = all(token in result_text for token in ("openprocess", "updateprocthreadattribute", "parent_process"))
                    if is_ppid:
                        claim_action = "may_spoof_parent_process"
                        claim_object = "parent process identity"
                        claim_mechanism = "OpenProcess -> UpdateProcThreadAttribute -> PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"
                        claim_statement = f"{artifact.logical_path} has an evidence-backed static hypothesis for parent-process spoofing."
                        attack_mapping = {"technique_id": "T1134.004", "name": "Parent PID Spoofing", "status": "candidate"}
                    else:
                        claim_action = "exhibits_static_mechanism"
                        claim_object = "ordered static behavior indicators"
                        claim_mechanism = "multiple independent static observations correlated by investigation actions"
                        claim_statement = f"{artifact.logical_path} has an evidence-backed static mechanism hypothesis; runtime execution remains unverified."
                        attack_mapping = {}
                    claim = Claim(
                        task_id=task.id,
                        module="execution",
                        claim_type="INVESTIGATED_MECHANISM",
                        subject=artifact.logical_path,
                        action=claim_action,
                        object=claim_object,
                        mechanism=claim_mechanism,
                        condition="static evidence threshold satisfied; runtime execution not proven",
                        statement=claim_statement,
                        nature="STATIC_INFERRED",
                        status="CANDIDATE",
                        confidence="HIGH",
                        attack_mapping=attack_mapping,
                    )
                    session.add(claim)
                    session.flush()
                    if specialized_verification is not None and specialized_verification.accepted:
                        for mechanism in snapshot.get("mechanisms", []):
                            if isinstance(mechanism, dict) and str(mechanism.get("thread_id")) == str(thread.id):
                                mechanism["claim_id"] = claim.id
                                mechanism["status"] = "VERIFIED"
                                # A verifier acceptance only upgrades the
                                # Claim when the resulting mechanism also has
                                # complete semantic fields. This prevents a
                                # broad API match from becoming a supported
                                # security finding without input/output
                                # provenance.
                                if mechanism_completeness_score(mechanism) >= 80:
                                    claim.status = "SUPPORTED"
                    relevant = [item for item in result.evidence if item.get("kind") in {"function_call", "constant"}]
                    if not relevant:
                        relevant = list(result.evidence[:8])
                    for item in relevant:
                        evidence_id = str(item.get("id"))
                        if evidence_id:
                            session.add(ClaimEvidence(claim_id=claim.id, evidence_id=evidence_id, stance="SUPPORTS"))
                    self._audit(session, case_id=task.case_id, task_id=task.id, event_type="investigation.claim_gate_passed", actor="verifier", object_type="Claim", object_id=claim.id, payload={"thread_id": thread.id, "hypothesis_id": hypothesis.id, "evidence_ids": [str(item.get("id")) for item in relevant]})
                else:
                    self._audit(session, case_id=task.case_id, task_id=task.id, event_type="investigation.claim_gate_unknown", actor="verifier", object_type="InvestigationHypothesis", object_id=hypothesis.id, payload={"thread_id": thread.id, "missing": list(result.gate.missing), "contradictions": list(result.gate.contradictions)})

            updated_investigation = {
                **snapshot,
                "runtime": {"events": runtime_events[-512:], "actions": runtime_actions[-128:], "gates": runtime_gates},
                "current_state": runtime_events[-1]["state"] if runtime_events else snapshot.get("current_state", "UNKNOWN"),
                "last_transition": "investigation_loop_completed",
                "private_chain_of_thought": False,
            }
            task.strategy_snapshot = {**(task.strategy_snapshot or {}), "investigation": updated_investigation}
        return limitations

    @staticmethod
    def _deterministic_action_plan(artifacts: list[Artifact]) -> list[str]:
        """Return the mandatory artifact order used when planning is unavailable."""
        return [item.id for item in artifacts]

    @staticmethod
    def _expected_evidence_for_tool(tool_name: str) -> tuple[str, ...]:
        return {
            "pe-parser": ("pe_structure", "import_symbol", "string", "resource_inventory"),
            "script-parser": ("script_import", "script_call", "script_line"),
            "document-carrier-parser": ("document_metadata", "embedded_object", "document_url"),
            "builtin-static-analyzer": ("file_identity", "string", "indicator"),
            "ghidra-headless": ("function", "xref", "cfg_block", "function_mechanism"),
        }.get(tool_name, ("specialist_observation",))

    @staticmethod
    def _analysis_focus_for_tool(tool_name: str) -> tuple[str, ...]:
        return {
            "pe-parser": ("identity", "imports", "sections", "resources"),
            "ghidra-headless": ("call_graph", "rva", "cfg", "mechanism_chain"),
            "script-parser": ("line_evidence", "imports", "calls"),
            "document-carrier-parser": ("carrier", "embedded_objects", "urls"),
            "python-zipfile-safe-reader": ("recursive_inventory", "password_gate"),
        }.get(tool_name, ("static_observation",))

    @staticmethod
    def _baseline_tools_for_artifact(artifact: Artifact) -> tuple[str, ...]:
        """Return the static coverage actions that cannot be skipped by a model."""
        parser_by_type = {
            "pe": "pe-parser",
            "script": "script-parser",
            "pdf": "document-carrier-parser",
            "ooxml": "document-carrier-parser",
            "ole": "document-carrier-parser",
        }
        parser = parser_by_type.get(artifact.detected_type, "builtin-static-analyzer")
        # Ghidra is an additional PE action.  Keeping it in the baseline queue
        # preserves the first-phase function/Xref/CFG obligation even when a
        # planner is unavailable or returns a conservative plan.
        if artifact.detected_type == "pe":
            return parser, "ghidra-headless"
        return (parser,)

    @staticmethod
    def _compatible_static_tools(artifact: Artifact) -> set[str]:
        tools = set(AnalysisService._baseline_tools_for_artifact(artifact))
        tools.add("signal-extractor")
        tools.add("knowledge-fact-matcher")
        if artifact.detected_type == "pe":
            tools.update({"rva-xref-query", "crypto-pattern-scanner", "build-metadata-scanner", "codename-scanner"})
        if artifact.detected_type in {"pe", "script", "pdf", "ooxml", "ole"}:
            tools.add("c2-protocol-scanner")
        return tools

    @staticmethod
    def _is_reference_isolated_blind(task: AnalysisTask) -> bool:
        blind_run = dict((task.strategy_snapshot or {}).get("blind_run", {}))
        return bool(blind_run.get("enabled") and blind_run.get("reference_isolated"))

    @staticmethod
    def _normalise_dependency(raw: str, action: ScheduledStaticAction) -> str:
        """Accept compact planner dependency forms without trusting free text."""
        known_tools = {
            "pe-parser", "script-parser", "document-carrier-parser", "builtin-static-analyzer",
            "ghidra-headless", *SPECIALIST_STATIC_TOOLS,
        }
        value = str(raw).strip()
        if not value:
            return ""
        if ":" in value:
            left, right = (part.strip() for part in value.split(":", 1))
            if left in known_tools:
                return f"{right}:{left}"
            return f"{left}:{right}"
        if value in known_tools:
            return f"{action.artifact_id}:{value}"
        return ""

    def _build_execution_queue(
        self,
        deterministic_actions: list[str],
        model_actions: list[DynamicPlanAction],
        artifacts: list[Artifact],
    ) -> list[ScheduledStaticAction]:
        """Expand a model proposal into an action-level, dependency-aware queue.

        The model can rank individual tools, but it cannot remove mandatory
        baseline coverage.  Unknown actions are ignored here after the planner
        policy gate has rejected them; the deterministic parser/Ghidra actions
        remain in the queue.
        """
        by_id = {item.id: item for item in artifacts}
        artifact_rank = {artifact_id: index for index, artifact_id in enumerate(deterministic_actions)}
        proposals: dict[str, DynamicPlanAction] = {}
        for action in model_actions:
            # Catalog investigation actions are consumed by the recursive
            # InvestigationLoopDriver.  This queue is reserved for baseline
            # and specialist static tools; mixing the two would execute an
            # action twice and would lose its hypothesis provenance.
            if action.action_type:
                continue
            artifact = by_id.get(action.target_artifact_id)
            if artifact is None or action.tool_name not in self._compatible_static_tools(artifact):
                continue
            key = f"{action.target_artifact_id}:{action.tool_name}"
            current = proposals.get(key)
            if current is None or action.priority < current.priority:
                proposals[key] = action

        candidates: list[ScheduledStaticAction] = []
        for index, artifact_id in enumerate(deterministic_actions):
            artifact = by_id.get(artifact_id)
            if artifact is None:
                continue
            baseline_tools = self._baseline_tools_for_artifact(artifact)
            for tool_offset, tool_name in enumerate(baseline_tools):
                key = f"{artifact_id}:{tool_name}"
                proposal = proposals.get(key)
                if proposal is None:
                    # The offset keeps parser before Ghidra in the deterministic
                    # route while still allowing a model priority to override it.
                    candidates.append(
                        ScheduledStaticAction(
                            artifact_id=artifact_id,
                            tool_name=tool_name,
                            priority=10000 + index * 10 + tool_offset,
                            reason="mandatory static coverage",
                            planner_turn_id=None,
                        )
                    )
                    continue
                dependencies = tuple(
                    dependency
                    for dependency in (
                        self._normalise_dependency(value, ScheduledStaticAction(
                            artifact_id=artifact_id,
                            tool_name=tool_name,
                            priority=proposal.priority,
                            reason=proposal.reason,
                        ))
                        for value in proposal.depends_on
                    )
                    if dependency
                )
                candidates.append(
                    ScheduledStaticAction(
                        artifact_id=artifact_id,
                        tool_name=tool_name,
                        priority=proposal.priority,
                        reason=proposal.reason,
                        depends_on=dependencies,
                        source="model_plan",
                        planner_turn_id=proposal.planner_turn_id,
                    )
                )

        # Specialist actions are additive.  They are only present when the
        # model explicitly proposes them, and remain subject to the same
        # compatibility and policy checks as baseline tools.
        for action in proposals.values():
            if action.tool_name not in SPECIALIST_STATIC_TOOLS:
                continue
            artifact = by_id.get(action.target_artifact_id)
            if artifact is None or action.tool_name not in self._compatible_static_tools(artifact):
                continue
            # Specialist analysis consumes parser observations.  Treat the
            # dependency as a scheduler invariant even when a model omits it
            # or supplies malformed free-text dependencies.  Ghidra remains an
            # optional deeper action; it must not block the deterministic
            # methodology profile when unavailable.
            baseline_tools = self._baseline_tools_for_artifact(artifact)
            required_dependencies = {f"{artifact.id}:{baseline_tools[0]}"}
            candidate = ScheduledStaticAction(
                artifact_id=action.target_artifact_id,
                tool_name=action.tool_name,
                priority=action.priority,
                reason=action.reason,
                depends_on=tuple(
                    sorted(
                        required_dependencies
                        | {
                            dependency
                            for dependency in (
                                self._normalise_dependency(
                                    value,
                                    ScheduledStaticAction(
                                        artifact_id=action.target_artifact_id,
                                        tool_name=action.tool_name,
                                        priority=action.priority,
                                        reason=action.reason,
                                    ),
                                )
                                for value in action.depends_on
                            )
                            if dependency
                        }
                    )
                ),
                source="model_plan",
                planner_turn_id=action.planner_turn_id,
            )
            if not any(item.key == candidate.key for item in candidates):
                candidates.append(candidate)

        by_key = {item.key: item for item in candidates}
        remaining = set(by_key)
        ordered: list[ScheduledStaticAction] = []
        while remaining:
            ready = [
                by_key[key]
                for key in remaining
                if all(dependency not in remaining for dependency in by_key[key].depends_on)
            ]
            if not ready:
                # A malformed dependency cycle must not deadlock analysis.  The
                # policy-approved action with the lowest priority breaks it.
                ready = [by_key[key] for key in remaining]
            ready.sort(key=lambda item: (item.priority, artifact_rank.get(item.artifact_id, 10**6), item.key))
            selected = ready[0]
            ordered.append(selected)
            remaining.remove(selected.key)
        return ordered

    def _run_methodology_action(
        self,
        task_id: str,
        artifact_id: str,
        tool_name: str,
        *,
        scheduler: str,
    ) -> list[str]:
        """Create the searchable profile and context-aware fact results.

        This is deliberately deterministic and read-only.  A model may request
        the action, but it cannot alter the fact library, evidence scope, or
        attribution verdict.
        """
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id)
            artifact = session.get(Artifact, artifact_id)
            if task is None or artifact is None:
                raise LookupError(artifact_id)
            if (
                self._is_reference_isolated_blind(task)
                and tool_name == "knowledge-fact-matcher"
            ):
                self._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task_id,
                    event_type="policy.tool_blocked",
                    actor="blind-runner",
                    object_type="ToolRun",
                    object_id=artifact_id,
                    payload={
                        "tool_name": tool_name,
                        "reason": "reference_isolated_blind_run",
                    },
                )
                return [
                    "Reference-isolated blind run blocks knowledge-fact-matcher."
                ]
            fact_library = (
                REFERENCE_ISOLATED_FACT_LIBRARY
                if self._is_reference_isolated_blind(task)
                else self.methodology_library
            )
            # Container Artifacts are intake boundaries, not samples.  Their
            # compressed bytes contain ZIP headers and filenames that would
            # create meaningless crypto/C2 signals if profiled directly.
            if artifact.role == "CONTAINER":
                return []
            # Methodology results are derived from the original static
            # observations.  Exclude our own derived rows so a retry or a
            # planner-selected specialist action cannot feed its profile back
            # into itself and create a new profile on every invocation.
            observations = list(
                session.scalars(
                    select(Evidence)
                    .where(
                        Evidence.task_id == task_id,
                        Evidence.artifact_id == artifact_id,
                        Evidence.kind.notin_(("analysis_profile", "fact_match")),
                    )
                    .order_by(Evidence.created_at, Evidence.id)
                )
            )
            existing = list(
                session.scalars(
                    select(Evidence)
                    .where(
                        Evidence.task_id == task_id,
                        Evidence.artifact_id == artifact_id,
                        Evidence.kind == "analysis_profile",
                    )
                    .order_by(Evidence.created_at.desc(), Evidence.id.desc())
                    .limit(1)
                )
            )
            if existing:
                prior_count = int(existing[0].value.get("observed_evidence_count", 0))
                if prior_count >= len(observations):
                    return []
            profile = build_profile(
                observations,
                name=artifact.logical_path,
                artifact_id=artifact.id,
                fact_library=fact_library,
            )
            run = session.scalar(
                select(ToolRun)
                .where(
                    ToolRun.task_id == task_id,
                    ToolRun.artifact_id == artifact_id,
                    ToolRun.tool_name == tool_name,
                    ToolRun.tool_version == "methodology-v1",
                    ToolRun.status == "SUCCEEDED",
                )
                .order_by(ToolRun.finished_at.desc(), ToolRun.id.desc())
            )
            created_methodology_run = run is None
            if run is None:
                run = ToolRun(
                    task_id=task_id,
                    artifact_id=artifact_id,
                    tool_name=tool_name,
                    tool_version="methodology-v1",
                    status="SUCCEEDED",
                    parameters={
                        "scheduler": scheduler,
                        "dimensions": list(DIMENSIONS),
                        "knowledge_sha256": fact_library.sha256,
                    },
                    environment={"deterministic": True, "sample_execution": False, "network_access": False},
                    output={
                        "signal_count": len(profile.signals),
                        "match_count": len(profile.matches),
                        "verdict": profile.assessment.actual_verdict,
                        "knowledge_sha256": fact_library.sha256,
                    },
                    finished_at=utcnow(),
                )
                session.add(run)
                session.flush()
            profile_evidence = Evidence(
                task_id=task_id,
                artifact_id=artifact_id,
                tool_run_id=run.id,
                module="attribution",
                kind="analysis_profile",
                nature="STATIC_INFERRED",
                value={
                    **profile.as_dict(),
                    "observed_evidence_count": len(observations),
                    "tool_name": tool_name,
                },
                anchor={
                    "type": "analysis_profile",
                    "artifact_id": artifact_id,
                    "logical_path": artifact.logical_path,
                    "knowledge_sha256": fact_library.sha256,
                },
            )
            session.add(profile_evidence)
            session.flush()
            if created_methodology_run:
                self._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task_id,
                    event_type="tool_run.completed",
                    actor=tool_name,
                    object_type="ToolRun",
                    object_id=run.id,
                    payload={
                        "tool_name": tool_name,
                        "signal_count": len(profile.signals),
                        "match_count": len(profile.matches),
                        "verdict": profile.assessment.actual_verdict,
                        "scheduler": scheduler,
                    },
                )
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task_id,
                event_type="methodology.profile_generated",
                actor=tool_name,
                object_type="Evidence",
                object_id=profile_evidence.id,
                payload={
                    "artifact_id": artifact_id,
                    "dimensions": profile.dimension_coverage,
                    "knowledge_sha256": fact_library.sha256,
                    "expected_verdict": profile.assessment.expected_verdict,
                    "actual_verdict": profile.assessment.actual_verdict,
                },
            )
            for match in profile.matches:
                match_evidence = Evidence(
                    task_id=task_id,
                    artifact_id=artifact_id,
                    tool_run_id=run.id,
                    module="attribution",
                    kind="fact_match",
                    nature="STATIC_INFERRED",
                    value=match.as_dict(),
                    anchor={
                        "type": "fact_match",
                        "fact_id": match.fact_id,
                        "signal_value": match.signal_value,
                        "artifact_id": artifact_id,
                    },
                )
                session.add(match_evidence)
                session.flush()
                status = "CANDIDATE" if match.status in {"HIT", "PARTIAL"} else "DISPUTED"
                claim = Claim(
                    task_id=task_id,
                    module="attribution",
                    claim_type="FACT_MATCH" if match.status == "HIT" else "FACT_CONTEXT_MISMATCH",
                    subject=artifact.logical_path,
                    action="matches_knowledge_fact" if match.status in {"HIT", "PARTIAL"} else "excludes_knowledge_fact",
                    object=match.fact_id,
                    mechanism="context-aware indicator matching",
                    condition="static evidence only; fact match is supporting evidence",
                    statement=(
                        f"{artifact.logical_path} matches knowledge fact {match.fact_id} via "
                        f"{match.indicator_type}={match.indicator_value} ({match.status}); {match.reason}."
                    ),
                    nature="STATIC_INFERRED",
                    status=status,
                    confidence="HIGH" if match.status == "HIT" else "LOW",
                    attack_mapping={},
                )
                session.add(claim)
                session.flush()
                support_ids = tuple(dict.fromkeys((*match.evidence_ids, match_evidence.id)))
                for evidence_id in support_ids:
                    session.add(ClaimEvidence(claim_id=claim.id, evidence_id=evidence_id, stance="SUPPORTS"))
                self._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task_id,
                    event_type="methodology.fact_matched",
                    actor="knowledge-fact-matcher",
                    object_type="Claim",
                    object_id=claim.id,
                    payload={
                        "fact_id": match.fact_id,
                        "status": match.status,
                        "evidence_ids": list(support_ids),
                    },
                )
            return []

    def _merge_planned_actions(
        self,
        deterministic_actions: list[str],
        model_actions: list[DynamicPlanAction],
        artifacts: list[Artifact],
    ) -> list[str]:
        """Apply model priority to ordering while retaining mandatory coverage."""
        valid_ids = {item.id for item in artifacts}
        ranked: list[tuple[int, int, str]] = []
        seen: set[str] = set()
        for index, action in enumerate(model_actions):
            if action.target_artifact_id in valid_ids and action.target_artifact_id not in seen:
                ranked.append((action.priority, index, action.target_artifact_id))
                seen.add(action.target_artifact_id)
        ranked.sort()
        ordered = [artifact_id for _, _, artifact_id in ranked]
        ordered.extend(artifact_id for artifact_id in deterministic_actions if artifact_id not in seen)
        return ordered

    def _run_model_planning(
        self,
        task_id: str,
        artifacts: list[Artifact],
        deterministic_actions: list[str],
        *,
        phase: str,
        completed_actions: list[dict[str, object]] | None = None,
    ) -> tuple[list[DynamicPlanAction], list[str]]:
        """Ask the model for a bounded first-turn plan and safely validate it."""
        # Unit/in-process acceptance runs intentionally exercise the deterministic
        # baseline without adding network-shaped planning calls. Production and
        # development model routes use the same seam below.
        if not self.settings.model_calls_enabled or self.settings.environment.lower() == "test":
            return [], []
        bounded_completed_actions = self._bound_completed_actions(completed_actions or [])
        if completed_actions:
            # A subsequent planning turn is a natural boundary at which the
            # previous turn's post-action result can be sealed immutably.
            self._finalize_pending_analysis_turn_results(
                task_id,
                bounded_completed_actions,
                stop_reason=f"superseded_by_{phase}",
            )
        with self.database.session_factory() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if task is None:
                raise LookupError(task_id)
            retrieved = self._retrieve_model_context(
                session,
                task=task,
                artifacts=artifacts,
                module="planning",
                phase=phase,
                completed_actions=bounded_completed_actions,
            )
            context_manifest = list(retrieved.manifest)
            hypothesis_before = [
                {
                    "id": "model-planning-mechanism",
                    "statement": "A mechanism chain can be supported by ordered static evidence.",
                    "status": "OPEN",
                }
            ]
            prompt = self.prompts.require("analysis-planner-agent", "1.0.0")
            artifact_manifest = [
                {
                    "artifact_id": item.id,
                    "logical_path": item.logical_path,
                    "detected_type": item.detected_type,
                    "role": item.role,
                    "obligation": item.obligation,
                    "parent_artifact_id": item.parent_artifact_id,
                }
                for item in artifacts
            ]
            question = (
                "Which next static action most reduces uncertainty about the artifact's mechanism, "
                "and what evidence would verify or weaken the leading hypothesis?"
            )
            context_packet = {
                "question": question,
                "artifact": {
                    "artifact_id": artifacts[0].id if artifacts else None,
                    "artifact_count": len(artifacts),
                    "paths": [item.logical_path for item in artifacts[:32]],
                },
                "hypotheses": [
                    {
                        "id": "model-planning-mechanism",
                        "statement": "A mechanism chain can be supported by ordered static evidence.",
                        "status": "OPEN",
                    }
                ],
                "retrieval_packets": [packet.as_dict() for packet in retrieved.packets],
                "open_unknowns": [
                    "runtime execution and network intent are not proven by static evidence",
                ],
                "action_history": bounded_completed_actions[-32:],
            }
            allowed_tools = [item.name for item in self.policy._tools.values()]
            if self._is_reference_isolated_blind(task):
                # Packaged fact matching is external knowledge, not sample
                # evidence. It is unavailable to a reference-isolated blind
                # planner even though ordinary static investigations may use it.
                allowed_tools = [
                    tool_name
                    for tool_name in allowed_tools
                    if tool_name != "knowledge-fact-matcher"
                ]
            request_payload = {
                "objective": "Choose the next most useful static analysis actions.",
                "question": question,
                "context_packet": context_packet,
                "artifacts": artifact_manifest,
                "evidence": context_manifest,
                "allowed_evidence_ids": [
                    str(item["evidence_id"])
                    for item in context_manifest
                    if item.get("nature") != "BACKGROUND_REPORTED"
                ],
                "allowed_tools": allowed_tools,
                "mandatory_artifact_ids": deterministic_actions,
                "completed_actions": bounded_completed_actions[-64:],
                "planning_phase": phase,
                "output_contract": "dynamic-analysis-plan-v2",
                "allowed_investigation_actions": list(ActionCatalog.default().names()),
            }
            messages = tuple(self.prompts.build_messages(prompt, request_payload))
            profile_digest = hashlib.sha256(
                self._canonical_json(
                    [packet.request.as_dict() for packet in retrieved.packets]
                ).encode("utf-8")
            ).hexdigest()
            policy_digest = hashlib.sha256(
                self._canonical_json(
                    {
                        "policy_version": self.policy.policy_version,
                        "catalog_digest": self.policy.catalog_digest,
                    }
                ).encode("utf-8")
            ).hexdigest()
            request_content = json.dumps(
                {"messages": messages, "artifact_ids": deterministic_actions},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            request_stored = self._store_model_payload(request_content)
            request = ModelRequest(
                task_id=task.id,
                case_id=task.case_id,
                trace_id=task.trace_id,
                module="planning",
                prompt_id=prompt.id,
                prompt_version=prompt.version,
                prompt_sha256=prompt.sha256,
                messages=messages,
                response_schema=DynamicPlanEnvelope,
                timeout_s=self.settings.model_timeout_s,
                max_tokens=min(2048, self.settings.model_max_tokens),
            )
        runtime_result = AgentRuntime(
            self.model_gateway,
            max_context_bytes=self.settings.model_context_max_bytes,
            cancellation_requested=lambda: self._is_task_cancelled(task_id),
        ).run(request)
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if task is None:
                raise LookupError(task_id)
            for event in runtime_result.events:
                self._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type=event.name,
                    actor="agent-runtime",
                    object_type="AgentRun",
                    object_id=runtime_result.run_id,
                    payload={"run_id": runtime_result.run_id, **event.payload},
                )
            calls = self._persist_model_attempts(
                session,
                task,
                prompt,
                runtime_result.attempts,
                request_stored,
                context_manifest,
                request=request,
                response_stored=(
                    self._store_model_payload(runtime_result.response.raw_response)
                    if runtime_result.response is not None
                    else None
                ),
                successful_call_id=(
                    runtime_result.response.model_call_id
                    if runtime_result.response is not None
                    else None
                ),
                agent_run_id=runtime_result.run_id,
                module="planning",
                turn_id=retrieved.ledger.turn_id,
                phase=phase,
                timeout_s=request.timeout_s,
                max_tokens=request.max_tokens,
            )
            response = runtime_result.response
            if response is None or runtime_result.status != "SUCCEEDED":
                self._persist_evidence_delivery_ledger(
                    session,
                    task=task,
                    artifact_id=None,
                    ledger=retrieved.ledger,
                    model_call_id=calls[-1].id if calls else None,
                )
                prior_planning = task.strategy_snapshot.get("dynamic_planning", {})
                history = list(prior_planning.get("history", []))
                history.append(
                    {
                        "phase": phase,
                        "status": "DETERMINISTIC_FALLBACK",
                        "actions": [],
                        "completed_actions": bounded_completed_actions[-64:],
                        "model_call_id": calls[-1].id if calls else None,
                    }
                )
                task.strategy_snapshot = {
                    **task.strategy_snapshot,
                    "dynamic_planning": {
                        "status": "DETERMINISTIC_FALLBACK",
                        "phase": phase,
                        "actions": [],
                        "model_call_id": calls[-1].id if calls else None,
                        "failure": runtime_result.error or "MODEL_PLANNING_UNAVAILABLE",
                        "history": history,
                    },
                    "investigation": {
                        **task.strategy_snapshot.get("investigation", {}),
                        "current_state": "UNKNOWN",
                        "last_question": "Which next static action most reduces uncertainty about the artifact's mechanism?",
                        "last_transition": "HYPOTHESIZING->UNKNOWN",
                    },
                }
                self._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type="orchestration.plan_proposed",
                    actor="analysis-planner-agent",
                    object_type="AnalysisTask",
                    object_id=task.id,
                    payload={
                        "status": "DETERMINISTIC_FALLBACK",
                        "phase": phase,
                        "action_count": 0,
                        "model_call_id": calls[-1].id if calls else None,
                    },
                )
                self._persist_analysis_turn(
                    session,
                    task=task,
                    retrieved=retrieved,
                    phase=phase,
                    hypothesis_before=hypothesis_before,
                    hypothesis_after=[{**item, "status": "UNKNOWN"} for item in hypothesis_before],
                    action_proposals=[],
                    policy_decisions=[],
                    completed_actions=bounded_completed_actions,
                    model_call=calls[-1] if calls else None,
                    mechanism_state="UNKNOWN",
                    stop_reason=runtime_result.error or "MODEL_PLANNING_UNAVAILABLE",
                )
                return [], [
                    "Model planning failed; deterministic scheduler order retained."
                ]
            allowed_ids = {item.id for item in artifacts}
            allowed_evidence_ids = {
                str(item["evidence_id"])
                for item in context_manifest
                if item.get("nature") != "BACKGROUND_REPORTED"
            }
            evidence_artifacts = {
                str(item["evidence_id"]): str(item.get("artifact_id"))
                for item in context_manifest
                if item.get("evidence_id")
            }
            selector_keys = frozenset({"target", "api", "function", "function_entry", "entry", "rva", "address"})
            valid_actions: list[DynamicPlanAction] = []
            rejected = 0
            rejected_actions: list[dict[str, object]] = []
            for action in response.parsed.actions[:64]:
                # Some OpenAI-compatible models copy the prompt's schema
                # placeholder for a baseline tool action.  Normalize only the
                # documented marker; all other unknown action types remain
                # rejected by the closed Action Catalog below.
                if action.action_type and action.action_type.strip().upper() in {
                    "OPTIONAL_CLOSED_ACTION",
                    "BASELINE_TOOL_ACTION",
                }:
                    action = action.model_copy(update={"action_type": None})
                if action.target_artifact_id not in allowed_ids:
                    rejected += 1
                    rejected_actions.append({"action": action.model_dump(mode="json"), "reason": "unknown_artifact"})
                    continue
                if action.action_type:
                    try:
                        ActionType(action.action_type)
                    except ValueError:
                        rejected += 1
                        rejected_actions.append({"action": action.model_dump(mode="json"), "reason": "action_not_in_catalog"})
                        continue
                    if not action.evidence_ids:
                        rejected += 1
                        rejected_actions.append({"action": action.model_dump(mode="json"), "reason": "uncited_investigation_action"})
                        continue
                    if not set(action.evidence_ids).issubset(allowed_evidence_ids):
                        rejected += 1
                        rejected_actions.append({"action": action.model_dump(mode="json"), "reason": "undelivered_action_evidence"})
                        continue
                    if any(
                        evidence_artifacts.get(str(evidence_id)) != action.target_artifact_id
                        for evidence_id in action.evidence_ids
                    ):
                        rejected += 1
                        rejected_actions.append(
                            {
                                "action": action.model_dump(mode="json"),
                                "reason": "cross_artifact_evidence",
                            }
                        )
                        continue
                    raw_selector = dict(action.target_selector)
                    if not raw_selector:
                        raw_selector = {
                            key: value
                            for key, value in action.parameters.items()
                            if key in selector_keys and isinstance(value, (str, int))
                        }
                    if not raw_selector or set(raw_selector) - selector_keys or not all(
                        isinstance(value, (str, int)) and str(value).strip()
                        for value in raw_selector.values()
                    ):
                        rejected += 1
                        rejected_actions.append({"action": action.model_dump(mode="json"), "reason": "invalid_target_selector"})
                        continue
                    if not self._selector_is_anchored_in_evidence(
                        raw_selector,
                        action.evidence_ids,
                        context_manifest,
                        target_artifact_id=action.target_artifact_id,
                    ):
                        rejected += 1
                        rejected_actions.append(
                            {
                                "action": action.model_dump(mode="json"),
                                "reason": "selector_not_anchored_in_cited_evidence",
                            }
                        )
                        continue
                    expected_evidence_kinds = (
                        list(action.expected_evidence_kinds)
                        if action.expected_evidence_kinds
                        else list(action.expected_evidence)
                    )
                    if not expected_evidence_kinds or not all(
                        isinstance(item, str) and item.strip()
                        for item in expected_evidence_kinds
                    ) or not action.success_condition.strip():
                        rejected += 1
                        rejected_actions.append(
                            {
                                "action": action.model_dump(mode="json"),
                                "reason": "incomplete_action_semantics",
                            }
                        )
                        continue
                    action = action.model_copy(
                        update={
                            "origin": "model",
                            "target_selector": raw_selector,
                            # A model cannot smuggle free-form action parameters
                            # across the control boundary. The verified selector
                            # is the complete executor input.
                            "parameters": raw_selector,
                            "expected_evidence": expected_evidence_kinds,
                            "expected_evidence_kinds": expected_evidence_kinds,
                            "planner_turn_id": retrieved.ledger.turn_id,
                        }
                    )
                else:
                    # Baseline tool scheduling is authorized solely by the
                    # closed tool policy and artifact compatibility. Drop any
                    # free-form model parameters so they cannot be mistaken for
                    # executor inputs at a later action boundary.
                    action = action.model_copy(
                        update={
                            "origin": "model",
                            "parameters": {},
                            "target_selector": {},
                            "analysis_focus": list(action.analysis_focus)[:32],
                            "planner_turn_id": retrieved.ledger.turn_id,
                        }
                    )
                target = next(item for item in artifacts if item.id == action.target_artifact_id)
                if action.action_type and not action.tool_name:
                    # The Action Catalog is the semantic authority; select an
                    # artifact-compatible static policy identity when a model
                    # omits a physical tool name.
                    action = action.model_copy(
                        update={"tool_name": self._baseline_tools_for_artifact(target)[0]}
                    )
                if action.action_type:
                    # Investigation actions are a separate closed catalog from
                    # baseline tool scheduling.  Their executor is the
                    # read-only evidence query below, so a model-supplied
                    # ``tool_name`` cannot bypass the catalog policy.
                    try:
                        action_type = ActionType(action.action_type)
                        definition = ActionCatalog.default().require(action_type)
                    except (ValueError, PermissionError):
                        rejected += 1
                        rejected_actions.append({"action": action.model_dump(mode="json"), "reason": "action_not_in_catalog"})
                        continue
                    if definition.sample_execution or definition.network_access:
                        rejected += 1
                        rejected_actions.append({"action": action.model_dump(mode="json"), "reason": "unsafe_action_policy"})
                        continue
                    try:
                        policy = self.policy.require_tool(action.tool_name)
                    except ValueError:
                        rejected += 1
                        rejected_actions.append({"action": action.model_dump(mode="json"), "reason": "tool_not_allowed"})
                        continue
                    if (
                        action.tool_name not in allowed_tools
                        or action.tool_name not in self._compatible_static_tools(target)
                        or policy.sample_execution
                        or policy.network_access
                    ):
                        rejected += 1
                        rejected_actions.append({"action": action.model_dump(mode="json"), "reason": "unsafe_or_incompatible_tool"})
                        continue
                else:
                    try:
                        policy = self.policy.require_tool(action.tool_name)
                    except ValueError:
                        rejected += 1
                        rejected_actions.append({"action": action.model_dump(mode="json"), "reason": "tool_not_allowed"})
                        continue
                    if action.tool_name not in self._compatible_static_tools(target):
                        rejected += 1
                        rejected_actions.append({"action": action.model_dump(mode="json"), "reason": "incompatible_artifact"})
                        continue
                    if action.tool_name not in allowed_tools:
                        rejected += 1
                        rejected_actions.append({"action": action.model_dump(mode="json"), "reason": "tool_not_in_catalog"})
                        continue
                    if policy.sample_execution or policy.network_access:
                        rejected += 1
                        rejected_actions.append({"action": action.model_dump(mode="json"), "reason": "unsafe_policy"})
                        continue
                for evidence_id in dict.fromkeys(action.evidence_ids):
                    if retrieved.ledger.stage_for(evidence_id) == EvidenceStage.DELIVERED:
                        retrieved.ledger.advance(
                            evidence_id,
                            EvidenceStage.REFERENCED_BY_MODEL,
                            details={"reference_kind": "action_proposal", "action_type": action.action_type},
                        )
                valid_actions.append(action)
            # Every accepted or rejected model proposal receives a complete,
            # service-derived provenance envelope.  These fields are audit
            # metadata only and never grant execution authority.
            def action_provenance(
                action_payload: Mapping[str, object],
                *,
                allowed: bool,
                reason: str,
            ) -> dict[str, object]:
                validation = {
                    "allowed": allowed,
                    "reason": reason,
                    "policy_version": self.policy.policy_version,
                    "catalog_digest": self.policy.catalog_digest,
                    "target_artifact_id": action_payload.get("target_artifact_id"),
                    "action_type": action_payload.get("action_type"),
                    "target_selector": action_payload.get("target_selector") or {},
                }
                digest = hashlib.sha256(
                    self._canonical_json(validation).encode("utf-8")
                ).hexdigest()
                return {
                    "prompt_sha256": prompt.sha256,
                    "profile_digest": profile_digest,
                    "policy_digest": policy_digest,
                    "action_validation_digest": digest,
                    "action_validation": validation,
                }

            annotated_actions: list[DynamicPlanAction] = []
            for action in valid_actions:
                payload = action.model_dump(mode="json")
                annotated_actions.append(
                    action.model_copy(
                        update=action_provenance(
                            payload,
                            allowed=True,
                            reason="policy_and_target_validation_passed",
                        )
                    )
                )
            valid_actions = annotated_actions
            for rejected_item in rejected_actions:
                raw_payload = rejected_item.get("action")
                if isinstance(raw_payload, Mapping):
                    raw_payload = dict(raw_payload)
                    raw_payload.update(
                        action_provenance(
                            raw_payload,
                            allowed=False,
                            reason=str(rejected_item.get("reason") or "policy_rejected"),
                        )
                    )
                    rejected_item["action"] = raw_payload
            prior_planning = task.strategy_snapshot.get("dynamic_planning", {})
            history = list(prior_planning.get("history", []))
            prior_action_history = [
                item for item in prior_planning.get("action_history", [])
                if isinstance(item, dict)
            ]
            action_history = prior_action_history + [
                {**item.model_dump(mode="json"), "planning_phase": phase}
                for item in valid_actions
            ]
            history.append(
                {
                    "phase": phase,
                    "status": "MODEL_PLAN_APPLIED" if valid_actions else "DETERMINISTIC_FALLBACK",
                    "actions": [item.model_dump(mode="json") for item in valid_actions],
                    "completed_actions": bounded_completed_actions[-64:],
                    "rejected_actions": rejected_actions[:32],
                    "model_call_id": calls[-1].id if calls else None,
                }
            )
            task.strategy_snapshot = {
                **task.strategy_snapshot,
                "dynamic_planning": {
                    "status": "MODEL_PLAN_APPLIED" if valid_actions else "DETERMINISTIC_FALLBACK",
                    "phase": phase,
                    "objective": response.parsed.objective,
                    "actions": [item.model_dump(mode="json") for item in valid_actions],
                    "stop_conditions": response.parsed.stop_conditions,
                    "limitations": response.parsed.limitations,
                    "rejected_action_count": rejected,
                    "rejected_actions": rejected_actions[:32],
                    "completed_actions": bounded_completed_actions[-64:],
                    "model_call_id": calls[-1].id if calls else None,
                    "action_history": action_history[-128:],
                    "history": history,
                },
                "investigation": {
                    **task.strategy_snapshot.get("investigation", {}),
                    "current_state": "INVESTIGATING" if valid_actions else "UNKNOWN",
                    "last_question": "Which next static action most reduces uncertainty about the artifact's mechanism, and what evidence would verify or weaken the leading hypothesis?",
                    "last_transition": "HYPOTHESIZING->INVESTIGATING" if valid_actions else "HYPOTHESIZING->UNKNOWN",
                    "action_proposals": [item.model_dump(mode="json") for item in valid_actions],
                },
            }
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="orchestration.plan_proposed",
                actor="analysis-planner-agent",
                object_type="AnalysisTask",
                object_id=task.id,
                payload={
                    "status": "MODEL_PLAN_APPLIED" if valid_actions else "DETERMINISTIC_FALLBACK",
                    "action_count": len(valid_actions),
                    "rejected_action_count": rejected,
                    "model_call_id": calls[-1].id if calls else None,
                    "phase": phase,
                },
            )
            self._persist_evidence_delivery_ledger(
                session,
                task=task,
                artifact_id=None,
                ledger=retrieved.ledger,
                model_call_id=calls[-1].id if calls else None,
            )
            policy_decisions = [
                {
                    "action_type": (item.get("action") or {}).get("action_type"),
                    "tool_name": (item.get("action") or {}).get("tool_name"),
                    "target_artifact_id": (item.get("action") or {}).get("target_artifact_id"),
                    "decision": "REJECTED",
                    "reason": item.get("reason", "policy_rejected"),
                    **{
                        key: (item.get("action") or {}).get(key)
                        for key in (
                            "prompt_sha256",
                            "profile_digest",
                            "policy_digest",
                            "action_validation_digest",
                        )
                        if isinstance(item.get("action"), Mapping)
                        and (item.get("action") or {}).get(key)
                    },
                }
                for item in rejected_actions
            ]
            policy_decisions.extend(
                {
                    "action_type": item.action_type,
                    "tool_name": item.tool_name,
                    "target_artifact_id": item.target_artifact_id,
                    "decision": "ACCEPTED",
                    "reason": "policy_and_target_validation_passed",
                    "prompt_sha256": item.prompt_sha256,
                    "profile_digest": item.profile_digest,
                    "policy_digest": item.policy_digest,
                    "action_validation_digest": item.action_validation_digest,
                }
                for item in valid_actions
            )
            self._persist_analysis_turn(
                session,
                task=task,
                retrieved=retrieved,
                phase=phase,
                hypothesis_before=hypothesis_before,
                hypothesis_after=[
                    {**item, "status": "INVESTIGATING" if valid_actions else "UNKNOWN"}
                    for item in hypothesis_before
                ],
                action_proposals=(
                    [item.model_dump(mode="json") for item in valid_actions]
                    + [
                        dict(item["action"])
                        for item in rejected_actions[:64]
                        if isinstance(item.get("action"), Mapping)
                    ]
                )[:64],
                policy_decisions=policy_decisions,
                completed_actions=bounded_completed_actions,
                model_call=calls[-1] if calls else None,
                mechanism_state="INVESTIGATING" if valid_actions else "UNKNOWN",
                stop_reason=("MODEL_PLAN_APPLIED" if valid_actions else "NO_EXECUTABLE_ACTIONS"),
            )
            limitations = list(response.parsed.limitations)
            if rejected:
                limitations.append(f"Model planner rejected {rejected} unsafe or invalid actions.")
            if not valid_actions:
                limitations.append("Model planner returned no executable actions; deterministic scheduler order retained.")
            return valid_actions, limitations

    @staticmethod
    def _ledger_ids(ledger: EvidenceDeliveryLedger, stage: EvidenceStage) -> list[str]:
        return sorted({event.evidence_id for event in ledger.events if event.stage == stage})

    @classmethod
    def _bound_completed_actions(
        cls,
        actions: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        """Keep planner history auditable without replaying unbounded IDs.

        A single parser action can produce thousands of Evidence rows.  The
        full set remains queryable from the Evidence ledger; planner Turns
        only need a bounded sample plus the authoritative count to correlate
        the next decision and stay below the model context limit.
        """
        bounded: list[dict[str, object]] = []
        for raw in actions:
            if not isinstance(raw, Mapping):
                continue
            item = dict(raw)
            raw_ids = item.get("new_evidence_ids")
            if isinstance(raw_ids, (list, tuple, set)):
                evidence_ids = [str(value) for value in raw_ids if str(value).strip()]
                item["new_evidence_ids"] = evidence_ids[: cls._MAX_COMPLETED_ACTION_EVIDENCE_IDS]
                if len(evidence_ids) > cls._MAX_COMPLETED_ACTION_EVIDENCE_IDS:
                    item["new_evidence_ids_truncated"] = len(evidence_ids) - cls._MAX_COMPLETED_ACTION_EVIDENCE_IDS
            bounded.append(item)
        return bounded

    def _persist_analysis_turn(
        self,
        session: Session,
        *,
        task: AnalysisTask,
        retrieved: RetrievedModelContext,
        phase: str,
        hypothesis_before: list[dict[str, object]],
        hypothesis_after: list[dict[str, object]],
        action_proposals: list[dict[str, object]],
        policy_decisions: list[dict[str, object]],
        completed_actions: list[dict[str, object]],
        model_call: ModelCall | None,
        mechanism_state: str,
        stop_reason: str,
        verifier_result: Mapping[str, object] | None = None,
    ) -> None:
        """Persist one immutable planner-turn manifest after its model call."""
        existing = session.scalar(
            select(AnalysisTurnRecord).where(
                AnalysisTurnRecord.task_id == task.id,
                AnalysisTurnRecord.turn_id == retrieved.ledger.turn_id,
            )
        )
        if existing is not None:
            return
        retrieval_requests = [packet.request.as_dict() for packet in retrieved.packets]
        tool_run_ids = sorted(
            {
                str(tool_id)
                for action in completed_actions
                for tool_id in action.get("tool_run_ids", [])
                if isinstance(action, Mapping)
            }
        )
        new_evidence_ids = sorted(
            {
                str(evidence_id)
                for action in completed_actions
                for evidence_id in action.get("new_evidence_ids", [])
                if isinstance(action, Mapping)
            }
        )
        record = AnalysisTurnRecord(
            task_id=task.id,
            thread_id=retrieved.ledger.thread_id,
            turn_id=retrieved.ledger.turn_id,
            phase=phase,
            hypothesis_before=hypothesis_before,
            retrieval_request={
                "requests": retrieval_requests,
                "version": retrieval_requests[0].get("version") if retrieval_requests else None,
            },
            candidate_evidence_ids=self._ledger_ids(retrieved.ledger, EvidenceStage.CANDIDATE),
            selected_evidence_ids=self._ledger_ids(retrieved.ledger, EvidenceStage.SELECTED),
            delivered_evidence_ids=self._ledger_ids(retrieved.ledger, EvidenceStage.DELIVERED),
            context_manifest=list(retrieved.manifest),
            model_call_id=model_call.id if model_call else None,
            raw_response_sha256=model_call.response_sha256 if model_call else None,
            raw_response_storage_key=model_call.response_storage_key if model_call else None,
            action_proposals=action_proposals,
            policy_decisions=policy_decisions,
            tool_run_ids=tool_run_ids,
            new_evidence_ids=new_evidence_ids,
            verifier_result=dict(verifier_result or {"status": "PENDING_POST_ACTION_VERIFICATION"}),
            hypothesis_after=hypothesis_after,
            mechanism_state=mechanism_state,
            stop_reason=stop_reason,
        )
        session.add(record)
        session.flush()

    def _persist_analysis_turn_results(
        self,
        session: Session,
        *,
        task: AnalysisTask,
        completed_actions: list[dict[str, object]],
        stop_reason: str,
    ) -> int:
        """Append post-action results for planner Turns still awaiting verification.

        Planner manifests are immutable and intentionally captured before a tool
        executes.  This method closes that audit gap by appending exactly one
        result row per pending manifest.  A result row is also immutable, so a
        later action cannot rewrite historical model state.
        """
        pending = list(
            session.scalars(
                select(AnalysisTurnRecord)
                .where(AnalysisTurnRecord.task_id == task.id)
                .order_by(AnalysisTurnRecord.created_at, AnalysisTurnRecord.id)
            )
        )
        created = 0
        normalized_actions = [
            dict(item)
            for item in completed_actions
            if isinstance(item, Mapping)
        ][-128:]
        # Deterministic baseline actions do not carry a planner token. Attribute
        # those once to the earliest pending turn; model actions are matched by
        # their explicit planner_turn_id below.
        unassigned = [
            item for item in normalized_actions if not item.get("planner_turn_id")
        ]
        for manifest in pending:
            existing = session.scalar(
                select(AnalysisTurnResultRecord).where(
                    AnalysisTurnResultRecord.task_id == task.id,
                    AnalysisTurnResultRecord.turn_id == manifest.turn_id,
                )
            )
            if existing is not None:
                continue
            # Results are attributed to the planner turn that authorized the
            # action.  Never attach the cumulative task history here: doing so
            # makes a later turn appear to have produced earlier evidence.
            actions = [
                dict(item)
                for item in normalized_actions
                if isinstance(item, Mapping)
                and str(item.get("planner_turn_id") or "") == manifest.turn_id
            ][-64:]
            if not actions and unassigned:
                actions = unassigned[-64:]
                unassigned = []
            tool_run_ids = sorted(
                {
                    str(tool_id)
                    for action in actions
                    for tool_id in action.get("tool_run_ids", [])
                    if isinstance(action, Mapping)
                }
            )
            evidence_ids = sorted(
                {
                    str(evidence_id)
                    for action in actions
                    for evidence_id in action.get("new_evidence_ids", [])
                    if isinstance(action, Mapping)
                }
            )
            new_count = sum(
                int(action.get("new_evidence_count", 0) or 0)
                for action in actions
                if isinstance(action, Mapping)
            )
            result = AnalysisTurnResultRecord(
                task_id=task.id,
                parent_turn_id=manifest.id,
                thread_id=manifest.thread_id,
                turn_id=manifest.turn_id,
                phase=manifest.phase,
                completed_actions=actions,
                tool_run_ids=tool_run_ids,
                new_evidence_ids=evidence_ids,
                verifier_result={
                    "status": "COMPLETED_STATIC_ACTIONS",
                    "new_evidence_count": new_count,
                    "evidence_references_verified": bool(evidence_ids),
                },
                hypothesis_after=list(manifest.hypothesis_after or []),
                mechanism_state=("EVIDENCE_UPDATED" if new_count else "NO_NEW_EVIDENCE"),
                stop_reason=stop_reason,
            )
            session.add(result)
            created += 1
        if created:
            session.flush()
        return created

    def _finalize_pending_analysis_turn_results(
        self,
        task_id: str,
        completed_actions: list[dict[str, object]],
        *,
        stop_reason: str,
    ) -> int:
        """Close all unclosed planner Turns at a deterministic task boundary."""
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if task is None:
                raise LookupError(task_id)
            return self._persist_analysis_turn_results(
                session,
                task=task,
                completed_actions=completed_actions,
                stop_reason=stop_reason,
            )

    def _collect_model_action_results(
        self,
        task_id: str,
        actions: list[DynamicPlanAction],
    ) -> list[dict[str, object]]:
        """Return auditable executor outcomes for the just-approved model actions.

        Planner proposals have no execution authority.  This method only reads
        ``InvestigationActionRecord`` rows created by the catalog-backed
        executor and turns their persisted output references into the
        completion history fed to the next planner turn.
        """
        expected = {
            (
                action.target_artifact_id,
                str(action.action_type),
                canonical_action_key(
                    str(action.action_type),
                    {"target_selector": dict(action.target_selector)},
                ),
            )
            for action in actions
            if action.action_type and action.target_selector
        }
        if not expected:
            return []
        with self.database.session_factory() as session:
            records = list(
                session.scalars(
                    select(InvestigationActionRecord)
                    .where(InvestigationActionRecord.task_id == task_id)
                    .order_by(InvestigationActionRecord.finished_at, InvestigationActionRecord.id)
                )
            )
            tool_runs = list(
                session.scalars(
                    select(ToolRun)
                    .where(ToolRun.task_id == task_id)
                    .order_by(ToolRun.finished_at, ToolRun.id)
                )
            )
        results: list[dict[str, object]] = []
        action_metadata = {
            (
                action.target_artifact_id,
                str(action.action_type),
                canonical_action_key(
                    str(action.action_type),
                    {"target_selector": dict(action.target_selector)},
                ),
            ): action
            for action in actions
        }
        seen: set[str] = set()
        for record in records:
            key = canonical_action_key(
                record.action_type,
                {"target_selector": dict(record.target_selector or {})},
            )
            if (record.artifact_id, record.action_type, key) not in expected or record.id in seen:
                continue
            if record.status not in {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED"}:
                continue
            seen.add(record.id)
            source_action = action_metadata.get((record.artifact_id, record.action_type, key))
            matching_tool_runs = [
                run.id
                for run in tool_runs
                if run.artifact_id == record.artifact_id
                and run.tool_name == f"investigation:{record.action_type.lower()}"
                and str((run.parameters or {}).get("dedupe_key", "")) == key
            ]
            result_ids = [str(item) for item in record.result_evidence_ids if str(item)]
            parameters = dict(record.parameters or {})
            stored_autopsy = parameters.get("_autopsy")
            autopsy = (
                dict(stored_autopsy)
                if isinstance(stored_autopsy, Mapping)
                else no_new_evidence_autopsy(
                    {
                        "action_type": record.action_type,
                        "target_selector": dict(record.target_selector or {}),
                        "target_artifact_id": record.artifact_id,
                        "artifact_boundary": record.artifact_id,
                        "dedupe_key": key,
                        "source_evidence_ids": (
                            list(source_action.evidence_ids)
                            if source_action
                            else parameters.get("_source_evidence_ids", [])
                        ),
                        "tool_status": record.status,
                        "tool_error": record.error,
                        "failure_interpretation": record.failure_interpretation,
                    }
                )
            )
            outcome = (
                "PRODUCTIVE"
                if result_ids
                else ("NO_NEW_EVIDENCE" if record.error == "NO_NEW_EVIDENCE" else record.status)
            )
            results.append(
                {
                    "action_key": f"investigation:{record.id}",
                    "artifact_id": record.artifact_id,
                    "tool_name": f"investigation:{record.action_type.lower()}",
                    "status": record.status,
                    "outcome": outcome,
                    "scheduler": "model_plan",
                    "new_evidence_count": len(result_ids),
                    "new_evidence_ids": result_ids,
                    "tool_run_ids": matching_tool_runs,
                    "source_action_id": record.id,
                    "action_type": record.action_type,
                    "target_selector": dict(record.target_selector or {}),
                    "parameters": dict(record.parameters or {}),
                    "source_evidence_ids": list(source_action.evidence_ids) if source_action else [],
                    "origin": source_action.origin if source_action else "model",
                    "dedupe_key": key,
                    "artifact_boundary": record.artifact_id,
                    "autopsy_category": autopsy.get("category"),
                    "autopsy": autopsy,
                    "target": autopsy.get("target"),
                    "next_action": autopsy.get("next_action"),
                    "planner_turn_id": (
                        str((record.parameters or {}).get("_planner_turn_id"))
                        if isinstance(record.parameters, Mapping)
                        and (record.parameters or {}).get("_planner_turn_id")
                        else (source_action.planner_turn_id if source_action else None)
                    ),
                    **(
                        dict(parameters.get("_model_provenance", {}))
                        if isinstance(parameters.get("_model_provenance"), Mapping)
                        else {}
                    ),
                }
            )
        return results
    """
            links = list(
                session.scalars(
                    select(ClaimEvidence)
                    .join(Claim, Claim.id == ClaimEvidence.claim_id)
                    .where(Claim.task_id == task_id, ClaimEvidence.stance == "SUPPORTS")
                )
            )
            evidence = {
                item.id: item
                for item in session.scalars(select(Evidence).where(Evidence.task_id == task_id))
            }
            evidence_ids_by_claim: dict[str, tuple[str, ...]] = {}
            for link in links:
                evidence_ids_by_claim.setdefault(link.claim_id, tuple())
                evidence_ids_by_claim[link.claim_id] += (link.evidence_id,)
            mapped_count = 0
            mapped_claim_ids: list[str] = []
            mapping_rows: list[dict[str, object]] = []
            for claim in claims:
                mappings = map_behavior_claim(
                    claim,
                    evidence_ids_by_claim.get(claim.id, tuple()),
                    evidence,
                    task_id=task_id,
                    snapshot=snapshot,
                )
                if not mappings:
                    continue
                claim.attack_mapping = {
                    "status": "candidate",
                    "snapshot_version": snapshot.version,
                    "snapshot_sha256": snapshot.sha256,
                    "mappings": [
                        {
                            "technique_id": mapping.technique_id,
                            "technique_name": mapping.technique_name,
                            "subtechnique_id": mapping.subtechnique_id,
                            "reason": mapping.reason,
                            "purpose": mapping.purpose,
                            "status": mapping.status,
                            "confidence": mapping.confidence,
                            "evidence_ids": list(mapping.evidence_ids),
                            "snapshot_version": mapping.snapshot_version,
                            "snapshot_sha256": mapping.snapshot_sha256,
                        }
                        for mapping in mappings
                    ],
                }
                mapped_count += len(mappings)
                mapped_claim_ids.append(claim.id)
                mapping_rows.extend(
                    {
                        "claim_id": claim.id,
                        "technique_id": mapping.technique_id,
                        "status": mapping.status,
                        "evidence_ids": list(mapping.evidence_ids),
                    }
                    for mapping in mappings
                )
            if mapped_count == 0:
                return
            tool_run = ToolRun(
                task_id=task_id,
                artifact_id=None,
                tool_name="attack-mapping-index",
                tool_version="0.1.0",
                status="SUCCEEDED",
                parameters={"snapshot_version": snapshot.version},
                environment={
                    "deterministic": True,
                    "sample_execution": False,
                    "network_access": False,
                },
                output={
                    "snapshot_version": snapshot.version,
                    "snapshot_sha256": snapshot.sha256,
                    "claim_count": len(claims),
                    "mapped_count": mapped_count,
                    "mapped_claim_ids": mapped_claim_ids,
                    "mappings": mapping_rows,
                },
                finished_at=utcnow(),
            )
            session.add(tool_run)
            session.flush()
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task_id,
                event_type="tool_run.completed",
                actor="attack-mapping-index",
                object_type="ToolRun",
                object_id=tool_run.id,
                payload={
                    "tool_name": tool_run.tool_name,
                    "snapshot_version": snapshot.version,
                    "snapshot_sha256": snapshot.sha256,
                    "mapped_count": mapped_count,
                },
            )

    """

    def _apply_attack_mapping(
        self,
        session: Session,
        task: AnalysisTask,
        task_id: str,
        snapshot: Any,
        claims: list[Claim],
    ) -> None:
        links = list(
            session.scalars(
                select(ClaimEvidence)
                .join(Claim, Claim.id == ClaimEvidence.claim_id)
                .where(Claim.task_id == task_id, ClaimEvidence.stance == "SUPPORTS")
            )
        )
        evidence = {
            item.id: item
            for item in session.scalars(select(Evidence).where(Evidence.task_id == task_id))
        }
        evidence_ids_by_claim: dict[str, tuple[str, ...]] = {}
        for link in links:
            evidence_ids_by_claim.setdefault(link.claim_id, tuple())
            evidence_ids_by_claim[link.claim_id] += (link.evidence_id,)
        mapped_count = 0
        mapped_claim_ids: list[str] = []
        mapping_rows: list[dict[str, object]] = []
        for claim in claims:
            mappings = map_behavior_claim(
                claim,
                evidence_ids_by_claim.get(claim.id, tuple()),
                evidence,
                task_id=task_id,
                snapshot=snapshot,
            )
            if not mappings:
                continue
            claim.attack_mapping = {
                "status": "candidate",
                "snapshot_version": snapshot.version,
                "snapshot_sha256": snapshot.sha256,
                "mappings": [
                    {
                        "technique_id": mapping.technique_id,
                        "technique_name": mapping.technique_name,
                        "subtechnique_id": mapping.subtechnique_id,
                        "reason": mapping.reason,
                        "purpose": mapping.purpose,
                        "status": mapping.status,
                        "confidence": mapping.confidence,
                        "evidence_ids": list(mapping.evidence_ids),
                        "snapshot_version": mapping.snapshot_version,
                        "snapshot_sha256": mapping.snapshot_sha256,
                    }
                    for mapping in mappings
                ],
            }
            mapped_count += len(mappings)
            mapped_claim_ids.append(claim.id)
            mapping_rows.extend(
                {
                    "claim_id": claim.id,
                    "technique_id": mapping.technique_id,
                    "status": mapping.status,
                    "evidence_ids": list(mapping.evidence_ids),
                }
                for mapping in mappings
            )
        if mapped_count == 0:
            return
        tool_run = ToolRun(
            task_id=task_id,
            artifact_id=None,
            tool_name="attack-mapping-index",
            tool_version="0.1.0",
            status="SUCCEEDED",
            parameters={"snapshot_version": snapshot.version},
            environment={"deterministic": True, "sample_execution": False, "network_access": False},
            output={
                "snapshot_version": snapshot.version,
                "snapshot_sha256": snapshot.sha256,
                "claim_count": len(claims),
                "mapped_count": mapped_count,
                "mapped_claim_ids": mapped_claim_ids,
                "mappings": mapping_rows,
            },
            finished_at=utcnow(),
        )
        session.add(tool_run)
        session.flush()
        self._audit(
            session,
            case_id=task.case_id,
            task_id=task_id,
            event_type="tool_run.completed",
            actor="attack-mapping-index",
            object_type="ToolRun",
            object_id=tool_run.id,
            payload={
                "tool_name": tool_run.tool_name,
                "snapshot_version": snapshot.version,
                "snapshot_sha256": snapshot.sha256,
                "mapped_count": mapped_count,
            },
        )

    def _register_artifacts(
        self,
        session: Session,
        task: AnalysisTask,
        entries: list[PackageEntry],
    ) -> tuple[list[Artifact], dict[str, PackageEntry]]:
        artifacts: list[Artifact] = []
        by_path: dict[str, Artifact] = {}
        entry_by_artifact: dict[str, PackageEntry] = {}
        for entry in entries:
            # Upload-only intake may have attached the root Artifact before a
            # Task was explicitly started. Reuse that row rather than creating
            # a duplicate artifact when the static workflow begins.
            existing = session.scalar(
                select(Artifact).where(
                    Artifact.task_id == task.id,
                    Artifact.logical_path == entry.logical_path,
                )
            )
            if existing is not None:
                artifacts.append(existing)
                by_path[entry.logical_path] = existing
                entry_by_artifact[existing.id] = entry
                continue
            if entry.content_sha256 and entry.storage_key:
                content_sha256 = entry.content_sha256
                storage_key = entry.storage_key
                content_size = entry.size
                detected_type = entry.detected_type or "unknown"
                mime_type = entry.mime_type or "application/octet-stream"
                type_source = entry.type_source or "worker_manifest"
            else:
                identity = identify_format(entry.content, entry.logical_path)
                stored = self.content_store.put(entry.content)
                content_sha256 = stored.sha256
                storage_key = stored.storage_key
                content_size = stored.size
                detected_type = identity.detected_type
                mime_type = identity.mime_type
                type_source = identity.source
            triage = self.triage_agent.triage(
                entry.logical_path,
                detected_type,
                is_container=entry.is_container,
            )
            blob = session.get(ContentBlob, content_sha256)
            if blob is None:
                blob = ContentBlob(
                    sha256=content_sha256,
                    size=content_size,
                    media_type=mime_type,
                    storage_key=storage_key,
                )
                session.add(blob)
                session.flush()
            elif blob.disposed_at is not None:
                # A re-submitted immutable byte sequence restores the backing object
                # while retaining the original provenance row and foreign keys.
                blob.disposed_at = None
            parent = by_path.get(entry.parent_path) if entry.parent_path else None
            artifact = Artifact(
                task_id=task.id,
                content_sha256=content_sha256,
                parent_artifact_id=parent.id if parent else None,
                logical_path=entry.logical_path,
                role=triage.role,
                obligation=triage.obligation,
                detected_type=detected_type,
                discovery=entry.discovery,
                metadata_json={
                    "is_container": entry.is_container,
                    "mime_type": mime_type,
                    "type_source": type_source,
                    "triage": {"rationale": triage.rationale, **triage.metadata},
                },
            )
            session.add(artifact)
            session.flush()
            artifacts.append(artifact)
            by_path[entry.logical_path] = artifact
            entry_by_artifact[artifact.id] = entry
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="artifact.registered",
                actor="system",
                object_type="Artifact",
                object_id=artifact.id,
                payload={
                    "logical_path": artifact.logical_path,
                    "sha256": artifact.content_sha256,
                    "parent_artifact_id": artifact.parent_artifact_id,
                },
            )
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="triage.decided",
                actor="triage-agent",
                object_type="Artifact",
                object_id=artifact.id,
                payload={"role": triage.role, "obligation": triage.obligation, **triage.metadata},
            )
        return artifacts, entry_by_artifact

    def _record_background_evidence(
        self, session: Session, task: AnalysisTask, root_artifact: Artifact
    ) -> None:
        """Freeze the optional background channel as provenance, never sample evidence.

        Background context is useful for triage and report context, but it is
        not an observation made by a sample parser.  A dedicated ToolRun and
        ``BACKGROUND_REPORTED`` nature keep that boundary auditable and make it
        impossible for completion gates to treat context as sample coverage.
        """
        # Enforce reference isolation at the sink as well as at blind-run
        # preparation.  A caller that forges a task snapshot or invokes the
        # analysis worker directly must not be able to persist background
        # material into a blind task, even though retrieval would later omit
        # it.  Recording only the policy decision preserves an audit trail
        # without creating a forbidden Evidence row.
        if self._is_reference_isolated_blind(task):
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="policy.background_context_blocked",
                actor="blind-runner",
                object_type="AnalysisTask",
                object_id=task.id,
                payload={"reason": "reference_isolated_blind_run"},
            )
            return
        context = task.request_snapshot.get("background_context") or {}
        if not isinstance(context, dict) or not str(context.get("content", "")):
            return
        tool_run = ToolRun(
            task_id=task.id,
            artifact_id=root_artifact.id,
            tool_name="background-context-ingest",
            tool_version="1.0.0",
            status="SUCCEEDED",
            parameters={"trust_zone": "untrusted_background"},
            environment={"sample_execution": False, "network_access": False},
            output={"source": context.get("source"), "version": context.get("version", "1.0")},
            started_at=utcnow(),
            finished_at=utcnow(),
        )
        session.add(tool_run)
        session.flush()
        evidence = Evidence(
            task_id=task.id,
            artifact_id=root_artifact.id,
            tool_run_id=tool_run.id,
            module="input_manifest",
            kind="background_context",
            nature="BACKGROUND_REPORTED",
            value={
                "content": str(context.get("content", "")),
                "source": str(context.get("source", "user_supplied")),
                "observed_at": context.get("observed_at"),
                "confidence": str(context.get("confidence", "UNVERIFIED")),
                "human_confirmed": bool(context.get("human_confirmed", False)),
                "version": str(context.get("version", "1.0")),
                "trust_zone": "untrusted_background",
            },
            anchor={
                "type": "background_context",
                "artifact_id": root_artifact.id,
                "content_sha256": root_artifact.content_sha256,
                "logical_path": root_artifact.logical_path,
                "trust_zone": "untrusted_background",
            },
        )
        session.add(evidence)
        session.flush()
        self._audit(
            session,
            case_id=task.case_id,
            task_id=task.id,
            event_type="evidence.recorded",
            actor="background-context-ingest",
            object_type="Evidence",
            object_id=evidence.id,
            payload={
                "kind": evidence.kind,
                "nature": evidence.nature,
                "tool_run_id": tool_run.id,
                "trust_zone": "untrusted_background",
            },
        )

    def _register_archive_relations(
        self,
        session: Session,
        task: AnalysisTask,
        artifacts: list[Artifact],
        entries: list[PackageEntry],
        intake_executions: list[IntakeExecution],
    ) -> None:
        by_path = {artifact.logical_path: artifact for artifact in artifacts}
        if intake_executions:
            for execution in intake_executions:
                root = by_path[execution.root_logical_path]
                selected_paths = set(execution.entry_paths)
                selected_entries = [
                    entry for entry in entries if entry.logical_path in selected_paths
                ]
                result = execution.result
                archive_members = [
                    entry for entry in selected_entries if entry.parent_path is not None
                ]
                tool_run = self._upsert_tool_run(
                    session,
                    str(result.worker_metadata.get("tool_run_id") or new_id()),
                    task_id=task.id,
                    artifact_id=root.id,
                    tool_name="python-zipfile-safe-reader",
                    tool_version="3.12",
                    status=result.status,
                    parameters={
                        "max_files": self.settings.max_sample_files,
                        "max_bytes": self.settings.max_sample_bytes,
                        "max_depth": self.settings.max_archive_depth,
                    },
                    environment={
                        "sample_execution": False,
                        "network_access": False,
                        **result.worker_metadata,
                    },
                    output={
                        "entry_count": len(selected_entries),
                        "archive_member_count": len(archive_members),
                    },
                    output_sha256=result.output_sha256,
                    output_storage_key=result.output_storage_key,
                    error=result.error,
                    started_at=result.started_at or utcnow(),
                    finished_at=result.finished_at or utcnow(),
                )
                self._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type="tool_run.completed",
                    actor="system",
                    object_type="ToolRun",
                    object_id=tool_run.id,
                    payload={
                        "tool_name": tool_run.tool_name,
                        "status": tool_run.status,
                        "output_sha256": tool_run.output_sha256,
                    },
                )
                self._record_archive_member_relations(
                    session,
                    task,
                    by_path,
                    selected_entries,
                    tool_run,
                )
            return

        children: dict[str, list[PackageEntry]] = {}
        for entry in entries:
            if entry.parent_path:
                children.setdefault(entry.parent_path, []).append(entry)
        for parent_path, members in children.items():
            parent = by_path[parent_path]
            tool_run = ToolRun(
                task_id=task.id,
                artifact_id=parent.id,
                tool_name="python-zipfile-safe-reader",
                tool_version="3.12",
                status="SUCCEEDED",
                parameters={
                    "max_files": self.settings.max_sample_files,
                    "max_bytes": self.settings.max_sample_bytes,
                    "max_depth": self.settings.max_archive_depth,
                },
                environment={
                    "sample_execution": False,
                    "network_access": False,
                    "executor": "in_process",
                    "execution_mode": self.settings.tool_execution_mode,
                },
                output={"archive_member_count": len(members)},
                finished_at=utcnow(),
            )
            session.add(tool_run)
            session.flush()
            self._record_archive_member_relations(
                session,
                task,
                by_path,
                members,
                tool_run,
            )

    @staticmethod
    def _upsert_tool_run(
        session: Session,
        tool_run_id: str,
        **values: object,
    ) -> ToolRun:
        tool_run = session.get(ToolRun, tool_run_id)
        if tool_run is None:
            tool_run = ToolRun(id=tool_run_id, **values)
            session.add(tool_run)
        else:
            for name, value in values.items():
                setattr(tool_run, name, value)
        session.flush()
        return tool_run

    def _record_archive_member_relations(
        self,
        session: Session,
        task: AnalysisTask,
        by_path: dict[str, Artifact],
        entries: list[PackageEntry],
        tool_run: ToolRun,
    ) -> None:
        for entry in entries:
            if entry.parent_path is None:
                continue
            parent = by_path[entry.parent_path]
            child = by_path[entry.logical_path]
            evidence = Evidence(
                task_id=task.id,
                artifact_id=parent.id,
                tool_run_id=tool_run.id,
                module="intake",
                kind="archive_member",
                value={
                    "child_artifact_id": child.id,
                    "logical_path": entry.logical_path,
                    "size": entry.size,
                },
                anchor={
                    "type": "container_path",
                    "artifact_id": parent.id,
                    "content_sha256": parent.content_sha256,
                    "internal_path": entry.logical_path.split("!/", 1)[-1],
                },
            )
            session.add(evidence)
            session.flush()
            for relation_type in ("CONTAINS", "EXTRACTED_FROM"):
                existing_relation = session.scalar(
                    select(Relation.id).where(
                        Relation.task_id == task.id,
                        Relation.source_artifact_id == parent.id,
                        Relation.target_artifact_id == child.id,
                        Relation.relation_type == relation_type,
                    )
                )
                if existing_relation is None:
                    session.add(
                        Relation(
                            task_id=task.id,
                            source_artifact_id=parent.id,
                            target_artifact_id=child.id,
                            relation_type=relation_type,
                            evidence_id=evidence.id,
                            status="OBSERVED",
                        )
                    )

    def _execute_static_tool(
        self,
        session: Session,
        task: AnalysisTask,
        artifact: Artifact,
        entry: PackageEntry,
        tool_name: str,
        *,
        planned_tool_names: tuple[str, ...] = (),
        scheduler: str | None = None,
    ) -> tuple[Any | None, ToolRunResult]:
        started_at = utcnow()
        tool_run_id = new_id()
        proposal = ActionProposal(
            tool_name=tool_name,
            target_artifact_id=artifact.id,
            reason=(
                "model planner selected compatible parser"
                if planned_tool_names
                else "static analysis preset"
            ),
            expected_evidence=self._expected_evidence_for_tool(tool_name),
            cpu_seconds=300 if tool_name == "ghidra-headless" else 60,
            memory_mb=4096 if tool_name == "ghidra-headless" else 512,
            investigation_thread_id=(
                (task.strategy_snapshot.get("investigation") or {}).get("threads", [{}])[0].get("id")
                if (task.strategy_snapshot.get("investigation") or {}).get("threads")
                else None
            ),
            question=(task.strategy_snapshot.get("investigation") or {}).get("last_question"),
            analysis_focus=self._analysis_focus_for_tool(tool_name),
        )
        decision = self.policy.authorize(proposal)
        self._audit(
            session,
            case_id=task.case_id,
            task_id=task.id,
            event_type="policy.action_decision",
            actor="policy-engine",
            object_type="ActionProposal",
            object_id=tool_run_id,
            payload={
                "tool_name": tool_name,
                "artifact_id": artifact.id,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "scheduler": scheduler or ("model_plan" if planned_tool_names else "deterministic_baseline"),
                "planned_tools": list(planned_tool_names),
            },
        )
        if not decision.allowed:
            raise PermissionError(decision.reason)
        if self.settings.tool_execution_mode != "temporal":
            if self.settings.environment.lower() not in {"test", "demo"}:
                raise PermissionError(
                    "in-process tool execution is restricted to explicit test/demo environments"
                )
            return analyze_bytes(entry.content, entry.logical_path), ToolRunResult(
                status="SUCCEEDED",
                started_at=started_at,
                finished_at=utcnow(),
                worker_metadata={
                    "tool_run_id": tool_run_id,
                    "executor": "in_process",
                    "execution_mode": self.settings.tool_execution_mode,
                },
            )
        blob = session.get(ContentBlob, artifact.content_sha256)
        if blob is None:
            raise LookupError(f"Content blob {artifact.content_sha256} does not exist")
        policy = self.policy.require_tool(tool_name)
        request = ToolRunRequest(
            case_id=task.case_id,
            task_id=task.id,
            trace_id=task.trace_id,
            artifact_id=artifact.id,
            tool_run_id=tool_run_id,
            tool_name=tool_name,
            tool_version="0.1.0",
            content_sha256=artifact.content_sha256,
            storage_key=blob.storage_key,
            logical_path=artifact.logical_path,
            parameters={
                "minimum_string_length": 4,
                "analysis_modules": "all",
                "scheduler": scheduler or ("model_plan" if planned_tool_names else "deterministic_baseline"),
                "planned_tools": list(planned_tool_names),
            },
            max_cpu_seconds=policy.max_cpu_seconds,
            max_memory_mb=policy.max_memory_mb,
            task_queue=self.settings.task_queue_for(tool_name),
        )
        try:
            response = asyncio.run(
                TemporalToolExecutor(self.settings.temporal_address).execute(request)
            )
        except Exception as exc:
            return None, ToolRunResult(
                status="FAILED",
                error=f"TEMPORAL_WORKFLOW_FAILED:{type(exc).__name__}",
                started_at=started_at,
                finished_at=utcnow(),
                worker_metadata={
                    "tool_run_id": tool_run_id,
                    "executor": "temporal",
                    "workflow_id": request.workflow_id,
                    "task_queue": request.task_queue,
                },
            )
        response = response.model_copy(
            update={
                "started_at": response.started_at or started_at,
                "finished_at": response.finished_at or utcnow(),
                "worker_metadata": {
                    **response.worker_metadata,
                    "case_id": task.case_id,
                    "trace_id": task.trace_id,
                    "tool_run_id": tool_run_id,
                },
            }
        )
        if response.status != "SUCCEEDED" or not response.output_storage_key:
            return None, response
        payload = json.loads(self.content_store.read(response.output_storage_key))
        try:
            return static_result_from_payload(payload), response
        except (KeyError, TypeError, ValueError) as exc:
            return None, ToolRunResult(
                status="FAILED",
                output_sha256=response.output_sha256,
                output_storage_key=response.output_storage_key,
                error=f"INVALID_STATIC_TOOL_OUTPUT:{type(exc).__name__}",
                started_at=response.started_at,
                finished_at=response.finished_at,
                worker_metadata=response.worker_metadata,
            )

    def _analyze_artifact(
        self,
        session: Session,
        task: AnalysisTask,
        artifact: Artifact,
        entry: PackageEntry,
        *,
        tool_name: str | None = None,
        planned_tool_names: tuple[str, ...] = (),
        scheduler: str | None = None,
    ) -> list[str]:
        parser_by_type = {
            "pe": "pe-parser",
            "script": "script-parser",
            "pdf": "document-carrier-parser",
            "ooxml": "document-carrier-parser",
            "ole": "document-carrier-parser",
        }
        parser_tool = parser_by_type.get(artifact.detected_type, "builtin-static-analyzer")
        compatible_tools = {
            "pe": {"pe-parser", "ghidra-headless"},
            "script": {"script-parser"},
            "pdf": {"document-carrier-parser"},
            "ooxml": {"document-carrier-parser"},
            "ole": {"document-carrier-parser"},
            "binary": {"builtin-static-analyzer"},
            "elf": {"builtin-static-analyzer"},
            "unknown": {"builtin-static-analyzer"},
        }.get(artifact.detected_type, {parser_tool})
        if tool_name is not None:
            if tool_name not in compatible_tools:
                return [f"{tool_name} is incompatible with {artifact.logical_path}."]
            parser_tool = tool_name
        else:
            for candidate in planned_tool_names:
                if candidate in compatible_tools:
                    parser_tool = candidate
                    break
        result, execution = self._execute_static_tool(
            session,
            task,
            artifact,
            entry,
            parser_tool,
            planned_tool_names=planned_tool_names,
            scheduler=scheduler,
        )
        tool_run = self._upsert_tool_run(
            session,
            str(execution.worker_metadata.get("tool_run_id") or new_id()),
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name=parser_tool,
            tool_version="0.1.0",
            status=execution.status,
            parameters={
                "minimum_string_length": 4,
                "analysis_modules": "all",
                "scheduler": scheduler or ("model_plan" if planned_tool_names else "deterministic_baseline"),
                "planned_tools": list(planned_tool_names),
            },
            environment={
                "sample_execution": False,
                "network_access": False,
                **execution.worker_metadata,
            },
            output=result.summary if result is not None else {},
            output_sha256=execution.output_sha256,
            output_storage_key=execution.output_storage_key,
            error=execution.error,
            started_at=execution.started_at or utcnow(),
            finished_at=execution.finished_at or utcnow(),
        )
        self._audit(
            session,
            case_id=task.case_id,
            task_id=task.id,
            event_type="tool_run.completed",
            actor="system",
            object_type="ToolRun",
            object_id=tool_run.id,
            payload={
                "tool_name": tool_run.tool_name,
                "status": tool_run.status,
                "error": tool_run.error,
                "output_sha256": tool_run.output_sha256,
            },
        )
        limitations: list[str] = []
        if result is None:
            limitations.append(
                f"{parser_tool} failed for {artifact.logical_path}: "
                f"{execution.error or execution.status}."
            )
        else:
            limitations.extend(
                self._record_static_result(
                    session,
                    task,
                    artifact,
                    tool_run,
                    result,
                    entry,
                )
            )
            if artifact.detected_type == "pe":
                self._record_builtin_code_signal_evidence(
                    session, task, artifact, tool_run, result
                )
        if artifact.detected_type in {"elf", "binary"} and not entry.is_container:
            limitations.append(
                f"Deep disassembly is unavailable for {artifact.logical_path} "
                f"({artifact.detected_type})."
            )
        return limitations

    def _record_static_result(
        self,
        session: Session,
        task: AnalysisTask,
        artifact: Artifact,
        tool_run: ToolRun,
        result: Any,
        entry: PackageEntry | None = None,
    ) -> list[str]:
        mechanism_facts = tuple(
            fact
            for fact in result.facts
            if fact.kind.startswith("mechanism_") or fact.kind in {"resource_inventory", "pe_header_anomaly"}
        )
        facts = tuple(result.facts)
        if not mechanism_facts:
            facts += derive_mechanism_facts(facts, subject=artifact.logical_path)
        evidence_rows: list[Evidence] = []
        for fact in facts:
            anchor = {
                **fact.anchor,
                "artifact_id": artifact.id,
                "content_sha256": artifact.content_sha256,
                "logical_path": artifact.logical_path,
            }
            fact_value = fact.value
            fact_is_derived = (
                fact.kind.startswith("mechanism_")
                or fact.kind in {
                    "resource_inventory",
                    "pe_header_anomaly",
                    "string_semantics",
                    "function_data_correlation",
                    "cross_function_chain",
                }
            )
            # Every STATIC_DERIVED row must carry an auditable input set.  A
            # few lightweight parser projections (notably string_semantics)
            # are emitted next to their source observation and historically
            # omitted this envelope, causing the strict Claim Gate to reject
            # otherwise valid claims because unrelated context rows lacked
            # provenance.  Resolve same-anchor observations first, then use a
            # bounded artifact-local observed set as the explicit fallback.
            if fact_is_derived and isinstance(fact_value, dict) and "derivation" not in fact_value:
                source_ids = [
                    str(item)
                    for item in fact_value.get("source_evidence_ids", ())
                    if str(item).strip()
                ]
                if not source_ids:
                    def _same_anchor(row: Evidence) -> bool:
                        if not isinstance(row.anchor, dict):
                            return False
                        if row.anchor.get("type") != anchor.get("type"):
                            return False
                        locator_keys = (
                            "offset",
                            "function_entry",
                            "rva",
                            "entry",
                            "address",
                            "from",
                            "to",
                        )
                        compared = [
                            key
                            for key in locator_keys
                            if anchor.get(key) is not None and row.anchor.get(key) is not None
                        ]
                        return bool(compared) and all(
                            str(row.anchor.get(key)) == str(anchor.get(key))
                            for key in compared
                        )

                    source_ids = [
                        row.id
                        for row in evidence_rows
                        if row.nature == "STATIC_OBSERVED" and _same_anchor(row)
                    ]
                if not source_ids:
                    source_ids = [
                        row.id
                        for row in evidence_rows
                        if row.nature == "STATIC_OBSERVED"
                    ][:24]
                if source_ids:
                    source_ids = list(dict.fromkeys(source_ids))[:24]
                    normalized_value = {
                        **fact_value,
                        "source_evidence_ids": source_ids,
                    }
                    input_digest = hashlib.sha256(
                        json.dumps(
                            {
                                "tool_run_id": tool_run.id,
                                "fact_kind": fact.kind,
                                "source_evidence_ids": source_ids,
                            },
                            ensure_ascii=True,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest()
                    output_digest = hashlib.sha256(
                        json.dumps(
                            normalized_value,
                            ensure_ascii=True,
                            sort_keys=True,
                            default=str,
                        ).encode("utf-8")
                    ).hexdigest()
                    fact_value = {
                        **normalized_value,
                        "derivation": {
                            "evaluator": "static-fact-normalizer-v1",
                            "input_evidence_ids": source_ids,
                            "input_digest": input_digest,
                            "output_digest": output_digest,
                            "exact": True,
                        },
                    }
            evidence = Evidence(
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=tool_run.id,
                module=fact.module,
                kind=fact.kind,
                # Parser/tool facts are observations; deterministic semantic
                # projections are derived.  This explicit split is required
                # by the Evidence/Claim contract and keeps an Agent from
                # treating a derived seed or chain as direct observation.
                nature=(
                    "STATIC_DERIVED"
                    if fact.kind.startswith("mechanism_")
                    or fact.kind in {
                        "resource_inventory",
                        "pe_header_anomaly",
                        "string_semantics",
                        "function_data_correlation",
                        "cross_function_chain",
                    }
                    else "STATIC_OBSERVED"
                ),
                value=fact_value,
                anchor=anchor,
            )
            session.add(evidence)
            session.flush()
            evidence_rows.append(evidence)
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="evidence.recorded",
                actor="system",
                object_type="Evidence",
                object_id=evidence.id,
                payload={
                    "module": evidence.module,
                    "kind": evidence.kind,
                    "tool_run_id": tool_run.id,
                },
            )
        # Persist one bounded seed map per artifact.  This is the bridge from
        # parser observations to Agentic investigation: imports/strings/xrefs
        # remain Evidence, while the map groups them into a small set of
        # answerable questions with competing hypotheses.  It is never itself
        # promoted to a behavior Claim.
        if evidence_rows:
            seed_map = build_investigation_seed_map(
                [
                    {
                        "id": row.id,
                        "kind": row.kind,
                        "value": row.value,
                        "anchor": row.anchor,
                    }
                    for row in evidence_rows
                ],
                max_clusters=12,
            )
            seed_evidence = Evidence(
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=tool_run.id,
                module="static_triage",
                kind="investigation_seed_map",
                # This is a deterministic projection of observed Evidence,
                # not an analyst Claim.  Keeping the nature explicit prevents
                # a seed cluster from being rendered as a verified behavior.
                nature="STATIC_DERIVED",
                value={
                    **seed_map,
                    "source_evidence_ids": [row.id for row in evidence_rows[:24]],
                    "derivation": {
                        "evaluator": "static-seed-cluster-v1",
                        "input_evidence_ids": [row.id for row in evidence_rows[:24]],
                        "input_digest": hashlib.sha256(
                            json.dumps(
                                [row.id for row in evidence_rows[:24]],
                                ensure_ascii=True,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        ).hexdigest(),
                        "output_digest": hashlib.sha256(
                            json.dumps(
                                seed_map,
                                ensure_ascii=True,
                                sort_keys=True,
                                default=str,
                            ).encode("utf-8")
                        ).hexdigest(),
                        "exact": True,
                    },
                },
                anchor={
                    "type": "investigation_seed_map",
                    "artifact_id": artifact.id,
                    "content_sha256": artifact.content_sha256,
                    "logical_path": artifact.logical_path,
                },
            )
            session.add(seed_evidence)
            session.flush()
            evidence_rows.append(seed_evidence)
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="evidence.recorded",
                actor="deterministic-seed-ranker",
                object_type="Evidence",
                object_id=seed_evidence.id,
                payload={
                    "kind": seed_evidence.kind,
                    "cluster_count": seed_map["cluster_count"],
                    "high_value_cluster_count": seed_map["high_value_cluster_count"],
                },
            )
            # Materialize the same frontier in the task snapshot.  The
            # snapshot is the durable input to the investigation scheduler and
            # report replay; without this projection the clustering helper is
            # effectively write-only and a resumed task falls back to a raw
            # import/string scan.  Queue entries are intentionally descriptive
            # and bounded: Action Catalog validation remains the only path to
            # executing an investigation action.
            investigation = dict((task.strategy_snapshot or {}).get("investigation", {}))
            seed_maps = dict(investigation.get("seed_maps", {}))
            seed_maps[artifact.id] = seed_map
            queue = [
                item for item in investigation.get("seed_queue", [])
                if isinstance(item, dict)
                and str(item.get("artifact_id")) != str(artifact.id)
            ]
            for cluster in seed_map.get("clusters", []):
                if not isinstance(cluster, dict):
                    continue
                queue.append(
                    {
                        "cluster_id": str(cluster.get("id")),
                        "artifact_id": artifact.id,
                        "category": str(cluster.get("category", "generic")),
                        "priority": int(cluster.get("priority", 0)),
                        "question": str(cluster.get("question", "")),
                        "evidence_ids": list(cluster.get("evidence_ids", []))[:32],
                        "hypotheses": list(cluster.get("hypotheses", []))[:4],
                        "status": "QUEUED",
                        "static_only": True,
                    }
                )
            queue.sort(key=lambda item: (int(item.get("priority", 0)) * -1, str(item.get("cluster_id", ""))))
            task.strategy_snapshot = {
                **(task.strategy_snapshot or {}),
                "investigation": {
                    **investigation,
                    "seed_maps": seed_maps,
                    "seed_queue": queue[:64],
                    "seed_map_version": "1.0",
                },
            }
        specifications = self.static_agent.propose_claims(facts, artifact.logical_path)
        for specification in specifications:
            evidence_ids = tuple(evidence_rows[index].id for index in specification.fact_indexes)
            validation = validate_claim_evidence(
                evidence_ids,
                {item.id for item in evidence_rows},
                module=specification.module,
                evidence_natures={item.id: item.nature for item in evidence_rows},
            )
            if not validation.accepted:
                raise ValueError(validation.reason)
            claim = Claim(
                task_id=task.id,
                module=specification.module,
                subject=specification.subject,
                action=specification.action,
                object=specification.object,
                mechanism=specification.mechanism,
                condition=specification.condition,
                statement=specification.statement,
                status="CANDIDATE",
                confidence=specification.confidence,
                attack_mapping=specification.attack_mapping,
            )
            session.add(claim)
            session.flush()
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="claim.created",
                actor="static-analysis-agent",
                object_type="Claim",
                object_id=claim.id,
                payload={
                    "module": claim.module,
                    "status": claim.status,
                    "confidence": claim.confidence,
                    **self.static_agent.metadata,
                },
            )
            for evidence_id in evidence_ids:
                session.add(
                    ClaimEvidence(
                        claim_id=claim.id,
                        evidence_id=evidence_id,
                        stance="SUPPORTS",
                    )
                )
            self._infer_component_relations(session, task, artifact, claim)
        if not specifications and evidence_rows and artifact.role != "CONTAINER":
            # A successful static pass with no behavior indicator still gets a
            # visible, evidence-backed profile result. This prevents a task
            # from reporting COMPLETE while exposing only raw fragments.
            profile_evidence = evidence_rows[0]
            claim = Claim(
                task_id=task.id,
                module="static_triage",
                subject=artifact.logical_path,
                action="has_static_profile",
                object="analyzed artifact",
                mechanism="deterministic static extraction",
                condition="no behavior-specific indicator met the current rule set",
                statement=(
                    f"{artifact.logical_path} was statically profiled; no behavior-specific "
                    "indicator was confirmed by the current rules."
                ),
                nature="STATIC_INFERRED",
                status="CANDIDATE",
                confidence="LOW",
                attack_mapping={},
            )
            session.add(claim)
            session.flush()
            session.add(
                ClaimEvidence(claim_id=claim.id, evidence_id=profile_evidence.id, stance="SUPPORTS")
            )
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="claim.created",
                actor="static-analysis-agent",
                object_type="Claim",
                object_id=claim.id,
                payload={
                    "module": claim.module,
                    "status": claim.status,
                    "confidence": claim.confidence,
                    "profile_only": True,
                    **self.static_agent.metadata,
                },
            )
        if artifact.detected_type in {"pdf", "ooxml", "ole"} and entry is not None:
            self._materialize_embedded_artifacts(session, task, artifact, tool_run, entry.content)
        if artifact.detected_type == "pe" and entry is not None:
            self._materialize_pe_resource_artifacts(
                session, task, artifact, tool_run, result, entry.content
            )
        if entry is not None:
            self._materialize_decoded_artifacts(
                session, task, artifact, tool_run, result, entry.content
            )
        # Child artifacts are materialized after deterministic Claims. Re-run
        # the relation projection now so a parent Claim can link to the newly
        # discovered component without making the Claim itself mutable.
        for claim in session.scalars(
            select(Claim).where(Claim.task_id == task.id, Claim.subject == artifact.logical_path)
        ):
            self._infer_component_relations(session, task, artifact, claim)
        return list(result.limitations)

    def _record_builtin_code_signal_evidence(
        self,
        session: Session,
        task: AnalysisTask,
        artifact: Artifact,
        tool_run: ToolRun,
        result: Any,
    ) -> None:
        """Persist Capstone fallback call sites as RVA-level static evidence."""
        pe = result.summary.get("pe") if isinstance(result.summary, dict) else None
        signals = pe.get("code_signals") if isinstance(pe, dict) else None
        if not isinstance(signals, dict):
            return
        calls = signals.get("api_calls", [])
        if not isinstance(calls, list) or not calls:
            return
        evidence_ids: list[str] = []
        api_names: list[str] = []
        for call in calls[:256]:
            if not isinstance(call, dict):
                continue
            api = str(call.get("api", ""))
            api_names.append(api)
            evidence = Evidence(
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=tool_run.id,
                module="static_triage",
                kind="code_api_call",
                nature="STATIC_OBSERVED",
                value={"api": api, "rva": call.get("address"), "file_offset": call.get("file_offset")},
                anchor={
                    "type": "rva_call_site",
                    "rva": call.get("address"),
                    "file_offset": call.get("file_offset"),
                    "artifact_id": artifact.id,
                    "content_sha256": artifact.content_sha256,
                    "logical_path": artifact.logical_path,
                },
            )
            session.add(evidence)
            session.flush()
            evidence_ids.append(evidence.id)
        if not evidence_ids:
            return
        unique_apis = list(dict.fromkeys(api_names))
        rva_examples = [
            f"0x{int(call.get('address')):x}"
            for call in calls[:12]
            if isinstance(call, dict) and call.get("address") is not None
        ]
        security_rvas = [
            f"0x{int(call.get('address')):x}"
            for call in calls
            if isinstance(call, dict)
            and call.get("address") is not None
            and any(
                token in str(call.get("api", "")).lower()
                for token in (
                    "findresource",
                    "loadresource",
                    "rtl",
                    "virtualprotect",
                    "globalmemorystatus",
                    "getsysteminfo",
                    "virtualquery",
                    "openscmanager",
                    "openservice",
                    "queryservicestatus",
                )
            )
        ][:16]
        rva_examples = list(dict.fromkeys((*security_rvas, *rva_examples)))
        claim = Claim(
            task_id=task.id,
            module="static_triage",
            claim_type="FALLBACK_CODE_CALL_GRAPH",
            subject=artifact.logical_path,
            action="contains_rva_level_call_sites",
            object="imported API call targets",
            mechanism="x86 Capstone fallback over executable PE sections",
            condition="Ghidra output is unavailable or architecture-inconsistent",
            statement=(
                f"{artifact.logical_path} has {len(evidence_ids)} statically recovered x86 API call sites "
                f"including {', '.join(unique_apis[:12])}; representative RVAs {', '.join(rva_examples)}. "
                "These are code-level observations, not runtime proof."
            ),
            nature="STATIC_INFERRED",
            status="CANDIDATE",
            confidence="MEDIUM",
            attack_mapping={},
        )
        session.add(claim)
        session.flush()
        for evidence_id in evidence_ids:
            session.add(ClaimEvidence(claim_id=claim.id, evidence_id=evidence_id, stance="SUPPORTS"))
        self._audit(
            session,
            case_id=task.case_id,
            task_id=task.id,
            event_type="claim.created",
            actor="static-analysis-agent",
            object_type="Claim",
            object_id=claim.id,
            payload={"claim_kind": "fallback_code_call_graph", "evidence_count": len(evidence_ids)},
        )
        first_rva = next(
            (int(call["address"]) for call in calls if isinstance(call, dict) and call.get("address") is not None),
            None,
        )
        if first_rva is not None:
            priority_claim = Claim(
                task_id=task.id,
                module="static_triage",
                claim_type="FUNCTION_REVIEW_PRIORITY",
                subject=artifact.logical_path,
                action="prioritizes",
                object=f"x86 fallback code region@RVA 0x{first_rva:x}",
                mechanism="API call-site density and security-relevant targets",
                condition="function boundaries unavailable because Ghidra architecture validation failed",
                statement=(
                    f"Prioritize the x86 code region around RVA 0x{first_rva:x} for manual review: "
                    f"the fallback recovered {len(evidence_ids)} API call sites, including security-relevant "
                    "resource, decompression, environment, service, and memory APIs."
                ),
                nature="STATIC_INFERRED",
                status="CANDIDATE",
                confidence="MEDIUM",
                attack_mapping={},
            )
            session.add(priority_claim)
            session.flush()
            for evidence_id in evidence_ids[:64]:
                session.add(ClaimEvidence(claim_id=priority_claim.id, evidence_id=evidence_id, stance="SUPPORTS"))
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="claim.created",
                actor="static-analysis-agent",
                object_type="Claim",
                object_id=priority_claim.id,
                payload={"claim_kind": "fallback_function_review_priority", "rva": first_rva},
            )

    def _materialize_pe_resource_artifacts(
        self,
        session: Session,
        task: AnalysisTask,
        parent: Artifact,
        tool_run: ToolRun,
        result: Any,
        content: bytes,
    ) -> list[str]:
        """Materialize bounded PE resources as non-executable child Artifacts."""
        pe = result.summary.get("pe") if isinstance(result.summary, dict) else None
        resources = pe.get("resources") if isinstance(pe, dict) else None
        entries = resources.get("entries", []) if isinstance(resources, dict) else []
        if not isinstance(entries, list) or not content:
            return []
        child_ids: list[str] = []
        for item in entries[:64]:
            if not isinstance(item, dict):
                continue
            offset = int(item.get("file_offset", -1))
            size = int(item.get("size", 0))
            if offset < 0 or size <= 0 or size > 4 * 1024 * 1024 or offset + size > len(content):
                continue
            resource_type = str(item.get("type", "resource"))
            resource_name = str(item.get("name", "unnamed"))
            language = str(item.get("language") or "neutral")
            logical_path = f"{parent.logical_path}!/.rsrc/{resource_type}-{resource_name}-{language}.bin"
            if session.scalar(
                select(Artifact.id).where(
                    Artifact.task_id == task.id, Artifact.logical_path == logical_path
                )
            ):
                continue
            payload = content[offset : offset + size]
            stored = self.content_store.put(payload)
            blob = session.get(ContentBlob, stored.sha256)
            if blob is None:
                blob = ContentBlob(
                    sha256=stored.sha256,
                    size=stored.size,
                    media_type="application/octet-stream",
                    storage_key=stored.storage_key,
                )
                session.add(blob)
                session.flush()
            child = Artifact(
                task_id=task.id,
                content_sha256=stored.sha256,
                parent_artifact_id=parent.id,
                logical_path=logical_path,
                role="EMBEDDED_OBJECT",
                obligation="REQUIRED",
                detected_type=identify_format(payload, logical_path).detected_type,
                discovery="pe_resource_extracted",
                metadata_json={
                    "carrier_artifact_id": parent.id,
                    "resource_type": resource_type,
                    "resource_name": resource_name,
                    "language": language,
                    "execution": False,
                },
            )
            session.add(child)
            session.flush()
            child_ids.append(child.id)
            evidence = Evidence(
                task_id=task.id,
                artifact_id=parent.id,
                tool_run_id=tool_run.id,
                module="static_triage",
                kind="pe_resource",
                nature="STATIC_OBSERVED",
                value={
                    "child_artifact_id": child.id,
                    "resource_type": resource_type,
                    "resource_name": resource_name,
                    "language": language,
                    "size": size,
                    "file_offset": offset,
                    "rva": item.get("rva"),
                    "entropy": item.get("entropy"),
                    "sha256": stored.sha256,
                },
                anchor={
                    "type": "pe_resource",
                    "file_offset": offset,
                    "rva": item.get("rva"),
                    "artifact_id": parent.id,
                },
            )
            session.add(evidence)
            session.flush()
            session.add(
                Relation(
                    task_id=task.id,
                    source_artifact_id=parent.id,
                    target_artifact_id=child.id,
                    relation_type="CONTAINS",
                    evidence_id=evidence.id,
                    status="OBSERVED",
                )
            )
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="artifact.pe_resource_extracted",
                actor="pe-parser",
                object_type="Artifact",
                object_id=child.id,
                payload={
                    "parent_artifact_id": parent.id,
                    "resource_type": resource_type,
                    "resource_name": resource_name,
                    "sha256": stored.sha256,
                },
            )
        return child_ids

    def _materialize_decoded_artifacts(
        self,
        session: Session,
        task: AnalysisTask,
        parent: Artifact,
        tool_run: ToolRun,
        result: Any,
        content: bytes,
    ) -> list[str]:
        """Decode bounded base64 indicators into immutable child Artifacts; never execute them."""
        child_ids: list[str] = []
        del content
        facts = [fact for fact in result.facts if fact.kind == "encoded_blob"]
        for index, fact in enumerate(facts[:20]):
            encoded = str(fact.value.get("indicator", fact.value.get("text", "")))
            try:
                decoded = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error):
                continue
            if not decoded or len(decoded) > 4 * 1024 * 1024:
                continue
            stored = self.content_store.put(decoded)
            blob = session.get(ContentBlob, stored.sha256)
            if blob is None:
                blob = ContentBlob(
                    sha256=stored.sha256,
                    size=stored.size,
                    media_type="application/octet-stream",
                    storage_key=stored.storage_key,
                )
                session.add(blob)
                session.flush()
            logical_path = f"{parent.logical_path}!/decoded/{index}-{stored.sha256[:12]}.bin"
            if session.scalar(
                select(Artifact.id).where(
                    Artifact.task_id == task.id, Artifact.logical_path == logical_path
                )
            ):
                continue
            child = Artifact(
                task_id=task.id,
                content_sha256=stored.sha256,
                parent_artifact_id=parent.id,
                logical_path=logical_path,
                role="DECODED_PAYLOAD",
                obligation="REQUIRED",
                detected_type=identify_format(decoded, logical_path).detected_type,
                discovery="static_decode",
                metadata_json={"decoded_from": parent.id, "execution": False},
            )
            session.add(child)
            session.flush()
            child_ids.append(child.id)
            evidence = Evidence(
                task_id=task.id,
                artifact_id=parent.id,
                tool_run_id=tool_run.id,
                module="decryption",
                kind="decoded_artifact",
                value={
                    "child_artifact_id": child.id,
                    "sha256": stored.sha256,
                    "size": len(decoded),
                },
                anchor={**fact.anchor, "artifact_id": parent.id},
            )
            session.add(evidence)
            session.flush()
            session.add(
                Relation(
                    task_id=task.id,
                    source_artifact_id=parent.id,
                    target_artifact_id=child.id,
                    relation_type="EXTRACTED_FROM",
                    evidence_id=evidence.id,
                    status="OBSERVED",
                )
            )
            # A statically decoded child is both extracted from its carrier and
            # a dropped component.  Both relations point to the same anchored
            # observation; neither implies execution.
            session.add(
                Relation(
                    task_id=task.id,
                    source_artifact_id=parent.id,
                    target_artifact_id=child.id,
                    relation_type="DROPS",
                    evidence_id=evidence.id,
                    status="OBSERVED",
                )
            )
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="artifact.decoded_extracted",
                actor="static-analysis-agent",
                object_type="Artifact",
                object_id=child.id,
                payload={"parent_artifact_id": parent.id, "sha256": stored.sha256},
            )
        return child_ids

    def _materialize_embedded_artifacts(
        self,
        session: Session,
        task: AnalysisTask,
        parent: Artifact,
        tool_run: ToolRun,
        content: bytes,
    ) -> list[str]:
        child_ids: list[str] = []
        if not content:
            blob = session.get(ContentBlob, parent.content_sha256)
            if blob is not None:
                content = self.content_store.read(blob.storage_key)
        extracted = extract_embedded_bytes(content, parent.logical_path)
        if not extracted:
            return child_ids
        for item in extracted:
            internal_path = str(item["internal_path"])
            embedded_content = bytes(item["content"])
            stored = self.content_store.put(embedded_content)
            blob = session.get(ContentBlob, stored.sha256)
            if blob is None:
                blob = ContentBlob(
                    sha256=stored.sha256,
                    size=stored.size,
                    media_type="application/octet-stream",
                    storage_key=stored.storage_key,
                )
                session.add(blob)
                session.flush()
            logical_path = f"{parent.logical_path}!/{internal_path}"
            child = session.scalar(
                select(Artifact).where(
                    Artifact.task_id == task.id,
                    Artifact.logical_path == logical_path,
                )
            )
            if child is None:
                child = Artifact(
                    task_id=task.id,
                    content_sha256=stored.sha256,
                    parent_artifact_id=parent.id,
                    logical_path=logical_path,
                    role="EMBEDDED_OBJECT",
                        obligation="REQUIRED",
                    detected_type=identify_format(embedded_content, internal_path).detected_type,
                    discovery="document_embedded_extracted",
                    metadata_json={
                        "carrier_artifact_id": parent.id,
                        "internal_path": internal_path,
                    },
                )
                session.add(child)
                session.flush()
            else:
                # Intake may already materialize the same ZIP member.
                child.role = "EMBEDDED_OBJECT"
                child.obligation = "REQUIRED"
                child.discovery = "document_embedded_extracted"
                child.metadata_json = {
                    **child.metadata_json,
                    "carrier_artifact_id": parent.id,
                    "internal_path": internal_path,
                }
            child_ids.append(child.id)
            evidence = Evidence(
                task_id=task.id,
                artifact_id=parent.id,
                tool_run_id=tool_run.id,
                module="static_triage",
                kind="embedded_artifact",
                nature="STATIC_OBSERVED",
                value={
                    "child_artifact_id": child.id,
                    "internal_path": internal_path,
                    "content_sha256": stored.sha256,
                    "size": stored.size,
                },
                anchor={
                    "type": str(item.get("anchor", {}).get("type", "embedded_payload")),
                    "internal_path": internal_path,
                    "artifact_id": parent.id,
                },
            )
            session.add(evidence)
            session.flush()
            session.add(
                Relation(
                    task_id=task.id,
                    source_artifact_id=parent.id,
                    target_artifact_id=child.id,
                    relation_type="CONTAINS",
                    evidence_id=evidence.id,
                    status="OBSERVED",
                )
            )
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="artifact.embedded_extracted",
                actor="document-carrier-parser",
                object_type="Artifact",
                object_id=child.id,
                payload={
                    "parent_artifact_id": parent.id,
                    "internal_path": internal_path,
                    "content_sha256": stored.sha256,
                },
            )
        return child_ids

    def _run_ghidra(
        self,
        task_id: str,
        artifact_id: str,
        entry: PackageEntry,
        *,
        planned_tool_names: tuple[str, ...] = (),
        scheduler: str | None = None,
    ) -> list[str]:
        with self.database.session_factory() as session:
            task = session.get(AnalysisTask, task_id)
            artifact = session.get(Artifact, artifact_id)
            if task is None or artifact is None:
                raise LookupError(artifact_id)
            if task.lifecycle == TaskLifecycle.CANCELLED.value:
                return []
            policy = self.policy.require_tool("ghidra-headless")
            started_at = utcnow()
            tool_run_id = new_id()
            case_id = task.case_id
            trace_id = task.trace_id
            artifact_sha256 = artifact.content_sha256
            artifact_path = artifact.logical_path
            request: ToolRunRequest | None = None
            if self.settings.tool_execution_mode == "temporal":
                blob = session.get(ContentBlob, artifact.content_sha256)
                if blob is None:
                    raise LookupError(f"Content blob {artifact.content_sha256} does not exist")
                request = ToolRunRequest(
                    case_id=case_id,
                    task_id=task_id,
                    trace_id=trace_id,
                    artifact_id=artifact_id,
                    tool_run_id=tool_run_id,
                    tool_name="ghidra-headless",
                    tool_version="12.1.2",
                    content_sha256=artifact_sha256,
                    storage_key=blob.storage_key,
                    logical_path=artifact_path,
                    parameters={"timeout_seconds": policy.max_cpu_seconds},
                    max_cpu_seconds=policy.max_cpu_seconds,
                    max_memory_mb=policy.max_memory_mb,
                    task_queue=self.settings.task_queue_for("ghidra-headless"),
                )

        if self.settings.tool_execution_mode == "temporal":
            assert request is not None
            try:
                response = asyncio.run(
                    TemporalToolExecutor(self.settings.temporal_address).execute(request)
                )
            except Exception as exc:
                response = ToolRunResult(
                    status="FAILED",
                    error=f"TEMPORAL_WORKFLOW_FAILED:{type(exc).__name__}",
                    worker_metadata={
                        "tool_run_id": tool_run_id,
                        "executor": "temporal",
                        "workflow_id": request.workflow_id,
                        "task_queue": request.task_queue,
                    },
                )
            response = response.model_copy(
                update={
                    "started_at": response.started_at or started_at,
                    "finished_at": response.finished_at or utcnow(),
                    "worker_metadata": {
                        **response.worker_metadata,
                        "case_id": case_id,
                        "trace_id": trace_id,
                        "tool_run_id": tool_run_id,
                        "task_queue": request.task_queue,
                        "environment_version": request.environment_version,
                    },
                }
            )
            if not response.output_storage_key:
                run = GhidraRun(response.status, {}, "", "", response.error)
            else:
                try:
                    payload = json.loads(self.content_store.read(response.output_storage_key))
                    if not isinstance(payload, dict) or payload.get("kind") != "ghidra":
                        raise ValueError("GHIDRA_OUTPUT_INVALID_SCHEMA")
                    status = str(payload.get("status", response.status))
                    output = (
                        validate_ghidra_output(payload.get("output"))
                        if status == "SUCCEEDED"
                        else {}
                    )
                    run = GhidraRun(
                        status,
                        output,
                        "",
                        "",
                        payload.get("error") or response.error,
                    )
                except json.JSONDecodeError:
                    run = GhidraRun(
                        "FAILED",
                        {},
                        "",
                        "",
                        "INVALID_GHIDRA_OUTPUT:GHIDRA_OUTPUT_INVALID_JSON",
                    )
                except (OSError, TypeError, ValueError) as exc:
                    reason = str(exc) or "GHIDRA_OUTPUT_INVALID_SCHEMA"
                    run = GhidraRun(
                        "FAILED",
                        {},
                        "",
                        "",
                        f"INVALID_GHIDRA_OUTPUT:{reason}",
                    )
            execution_metadata = response.worker_metadata
            runner_configuration: dict[str, object] = {"worker": "temporal", "available": True}
        else:
            runner = GhidraHeadlessRunner(self.settings.ghidra_home, self.settings.java_home)
            processor_override: str | None = None
            input_transform: str | None = None
            run = runner.analyze(
                entry.content, entry.logical_path, timeout_seconds=policy.max_cpu_seconds
            )
            if run.status == "SUCCEEDED":
                # A malformed Machine field can make Ghidra emit a plausible
                # looking but unrelated pseudo-function. Compare its function
                # entries with the deterministic PE entry before materializing
                # any Ghidra Evidence.
                try:
                    identity = analyze_bytes(entry.content, entry.logical_path)
                    expected_entry = int(identity.summary["pe"]["entry_rva"])
                    ghidra_entries = {
                        int(item.get("entry_rva"))
                        for item in run.output.get("functions", [])
                        if isinstance(item, dict) and item.get("entry_rva") is not None
                    }
                    if ghidra_entries and expected_entry not in ghidra_entries:
                        # Some PE samples have a damaged/zero Machine field.
                        # Ghidra then imports them as a plausible but unrelated
                        # 16-bit program.  The deterministic parser has already
                        # established PE32 semantics, so retry once with the
                        # matching x86 language before falling back to Capstone.
                        machine = str(identity.summary["pe"].get("machine", "")).lower()
                        pe_format = str(identity.summary["pe"].get("format", ""))
                        if machine == "0x0000" and pe_format == "PE32":
                            processor_override = "x86:LE:32:default"
                            retry = runner.analyze(
                                entry.content,
                                entry.logical_path,
                                timeout_seconds=policy.max_cpu_seconds,
                                processor=processor_override,
                            )
                            retry_entries = {
                                int(item.get("entry_rva"))
                                for item in retry.output.get("functions", [])
                                if isinstance(item, dict) and item.get("entry_rva") is not None
                            }
                            if retry.status == "SUCCEEDED" and expected_entry in retry_entries:
                                run = retry
                                input_transform = "PE_MACHINE_ZERO_NORMALIZED_TO_I386"
                            else:
                                run = GhidraRun(
                                    "FAILED",
                                    {},
                                    retry.stdout or run.stdout,
                                    retry.stderr or run.stderr,
                                    retry.error
                                    or f"GHIDRA_ARCHITECTURE_INCONSISTENT: expected entry RVA 0x{expected_entry:x}",
                                )
                        else:
                            run = GhidraRun(
                                "FAILED",
                                {},
                                run.stdout,
                                run.stderr,
                                f"GHIDRA_ARCHITECTURE_INCONSISTENT: expected entry RVA 0x{expected_entry:x}",
                            )
                except (KeyError, TypeError, ValueError):
                    pass
            execution_metadata = {
                "tool_run_id": tool_run_id,
                "executor": "in_process",
                "execution_mode": self.settings.tool_execution_mode,
            }
            if processor_override:
                execution_metadata["processor_override"] = processor_override
            if input_transform:
                execution_metadata["input_transform"] = input_transform
            runner_configuration = runner.configuration()
            stored_output = self.content_store.put(
                json.dumps(
                    {
                        "kind": "ghidra",
                        "status": run.status,
                        "output": run.output,
                        "error": run.error,
                    },
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            response = ToolRunResult(
                status=run.status,
                output_sha256=stored_output.sha256,
                output_storage_key=stored_output.storage_key,
                error=run.error,
                started_at=started_at,
                finished_at=utcnow(),
                worker_metadata=execution_metadata,
            )
        functions = run.output.get("functions", [])
        function_rows = functions if isinstance(functions, list) else []
        symbols = run.output.get("symbols", [])
        symbol_rows = symbols if isinstance(symbols, list) else []
        output_summary = {
            "image_base": run.output.get("image_base"),
            "function_count": len(function_rows),
            "xref_count": sum(
                len(function.get("xrefs_to_entry", []))
                for function in function_rows
                if isinstance(function, dict)
            ),
            "cfg_block_count": sum(
                len(function.get("cfg_blocks", []))
                for function in function_rows
                if isinstance(function, dict)
            ),
            "symbol_count": len(symbol_rows),
        }
        return self._persist_ghidra_result(
            task_id=task_id,
            artifact_id=artifact_id,
            tool_run_id=tool_run_id,
            policy=policy,
            run=run,
            response=response,
            runner_configuration=runner_configuration,
            execution_metadata=execution_metadata,
            started_at=started_at,
            output_summary=output_summary,
            planned_tool_names=planned_tool_names,
            scheduler=scheduler,
        )

    def _persist_ghidra_result(
        self,
        *,
        task_id: str,
        artifact_id: str,
        tool_run_id: str,
        policy: Any,
        run: GhidraRun,
        response: ToolRunResult,
        runner_configuration: dict[str, object],
        execution_metadata: dict[str, object],
        started_at: datetime,
        output_summary: dict[str, object],
        planned_tool_names: tuple[str, ...] = (),
        scheduler: str | None = None,
    ) -> list[str]:
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            artifact = session.get(Artifact, artifact_id)
            if task is None or artifact is None:
                raise LookupError(artifact_id)
            if task.lifecycle == TaskLifecycle.CANCELLED.value:
                return []
            tool_run = self._upsert_tool_run(
                session,
                tool_run_id,
                task_id=task.id,
                artifact_id=artifact.id,
                tool_name="ghidra-headless",
                tool_version="12.1.2",
                status=run.status,
                parameters={
                    "timeout_seconds": policy.max_cpu_seconds,
                    "scheduler": scheduler or ("model_plan" if planned_tool_names else "deterministic_baseline"),
                    "planned_tools": list(planned_tool_names),
                    **{
                        key: execution_metadata[key]
                        for key in ("processor_override", "input_transform")
                        if key in execution_metadata
                    },
                },
                environment={
                    **runner_configuration,
                    "sample_execution": False,
                    "network_access": False,
                    "max_memory_mb": policy.max_memory_mb,
                    **execution_metadata,
                },
                output=output_summary,
                output_sha256=response.output_sha256,
                output_storage_key=response.output_storage_key,
                error=run.error,
                started_at=response.started_at or started_at,
                finished_at=response.finished_at or utcnow(),
            )
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="tool_run.completed",
                actor="system",
                object_type="ToolRun",
                object_id=tool_run.id,
                payload={
                    "tool_name": tool_run.tool_name,
                    "status": tool_run.status,
                    "error": run.error,
                    "output_sha256": tool_run.output_sha256,
                },
            )
            if run.status != "SUCCEEDED":
                return [
                    "Ghidra function, Xref, CFG evidence unavailable for "
                    f"{artifact.logical_path}: {run.error}."
                ]
            self._record_ghidra_evidence(session, task, artifact, tool_run, run.output)
            return []

    def _record_ghidra_evidence(
        self,
        session: Session,
        task: AnalysisTask,
        artifact: Artifact,
        tool_run: ToolRun,
        output: dict[str, object],
    ) -> None:
        emitted_evidence: list[Evidence] = []

        def emit(
            kind: str,
            value: dict[str, object],
            anchor: dict[str, object],
            *,
            nature: str = "STATIC_OBSERVED",
        ) -> Evidence:
            evidence = Evidence(
                # Assign the immutable identifier before the unit-of-work
                # flush.  Ghidra can emit thousands of rows; forcing a flush
                # for every row turns persistence into an O(n) network round
                # trip and leaves real tasks stuck in RUNNING for minutes.
                id=new_id(),
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=tool_run.id,
                module="static_triage",
                kind=kind,
                nature=nature,
                value=value,
                anchor={
                    **anchor,
                    "artifact_id": artifact.id,
                    "content_sha256": artifact.content_sha256,
                    "logical_path": artifact.logical_path,
                },
            )
            session.add(evidence)
            emitted_evidence.append(evidence)
            return evidence

        emit(
            "simulation_capability",
            static_phase_simulation_evidence(),
            {"type": "capability_probe", "phase": "static-only"},
        )

        # Turn the Ghidra call/instruction view into a small, auditable
        # mechanism layer before emitting per-function rows. This is the
        # missing bridge between “API exists” and an evidence-backed analysis
        # statement such as resource extraction -> decompression -> memory
        # preparation. The layer remains static and conservative.
        mechanism_facts = derive_mechanism_facts(
            (), subject=artifact.logical_path, ghidra_output=output
        )
        mechanism_evidence_ids: list[str] = []
        for fact in mechanism_facts:
            mechanism_evidence_ids.append(
                emit(
                    fact.kind,
                    fact.value,
                    {**fact.anchor, "type": fact.anchor.get("type", "mechanism_signal")},
                ).id
            )
        if mechanism_facts:
            specifications = self.static_agent.propose_claims(
                mechanism_facts, artifact.logical_path
            )
            for specification in specifications:
                evidence_ids = tuple(
                    mechanism_evidence_ids[index]
                    for index in specification.fact_indexes
                    if 0 <= index < len(mechanism_evidence_ids)
                )
                validation = validate_claim_evidence(
                    evidence_ids,
                    set(mechanism_evidence_ids),
                    module=specification.module,
                    evidence_natures={item: "STATIC_OBSERVED" for item in mechanism_evidence_ids},
                )
                if not validation.accepted:
                    continue
                claim = Claim(
                    task_id=task.id,
                    module=specification.module,
                    subject=specification.subject,
                    action=specification.action,
                    object=specification.object,
                    mechanism=specification.mechanism,
                    condition=specification.condition,
                    statement=specification.statement,
                    nature="STATIC_INFERRED",
                    status="CANDIDATE",
                    confidence=specification.confidence,
                    attack_mapping=specification.attack_mapping,
                )
                session.add(claim)
                session.flush()
                for evidence_id in validation.evidence_ids:
                    session.add(
                        ClaimEvidence(
                            claim_id=claim.id,
                            evidence_id=evidence_id,
                            stance="SUPPORTS",
                        )
                    )
                self._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type="claim.created",
                    actor="static-analysis-agent",
                    object_type="Claim",
                    object_id=claim.id,
                    payload={
                        "module": claim.module,
                        "claim_kind": "ghidra_mechanism_chain",
                        "confidence": claim.confidence,
                        **self.static_agent.metadata,
                    },
                )

        functions = output.get("functions", [])
        function_candidates: list[FunctionEvidenceCandidate] = []
        if isinstance(functions, list):
            all_function_rows = [item for item in functions if isinstance(item, dict)]
            signal_terms = (
                'createprocess', 'shellexecute', 'winexec', 'loadlibrary',
                'getprocaddress', 'virtualalloc', 'virtualprotect',
                'writeprocessmemory', 'createremotethread', 'openprocess',
                'updateprocthreadattribute', 'internet', 'winhttp', 'wininet',
                'socket', 'connect', 'dns', 'crypt', 'decompress', 'resource',
                'isdebuggerpresent', 'virtualquery', 'gettickcount',
            )

            def function_priority(item: dict[str, object], ordinal: int) -> tuple[int, ...]:
                calls = item.get('references_from', [])
                call_rows = calls if isinstance(calls, list) else []
                names = ' '.join(
                    str(row.get('target_name') or row.get('target_function') or '').lower()
                    for row in call_rows
                    if isinstance(row, dict)
                )
                signal_count = sum(term in names for term in signal_terms)
                return (
                    signal_count,
                    len(item.get('xrefs_to_entry', []) or []),
                    len(call_rows),
                    len(item.get('cfg_blocks', []) or []),
                    len(item.get('mnemonics', []) or []),
                    -ordinal,
                )

            ranked_rows = sorted(
                enumerate(all_function_rows),
                key=lambda pair: function_priority(pair[1], pair[0]),
                reverse=True,
            )
            function_rows = [
                item for _, item in ranked_rows[: self._MAX_GHIDRA_FUNCTIONS]
            ]
            if len(function_rows) < len(all_function_rows):
                emit(
                    'ghidra_function_budget',
                    {
                        'total_functions': len(all_function_rows),
                        'processed_functions': len(function_rows),
                        'selection': 'deterministic_signal_xref_call_cfg_rank',
                    },
                    {'type': 'ghidra_postprocess_budget'},
                )
            artifact_content = b""
            artifact_blob = session.get(ContentBlob, artifact.content_sha256)
            if artifact_blob is not None:
                try:
                    artifact_content = self.content_store.read(artifact_blob.storage_key)
                except (OSError, ValueError):
                    artifact_content = b""
            deterministic_pe = {}
            if artifact_content:
                try:
                    deterministic_pe = analyze_bytes(artifact_content, artifact.logical_path).summary.get("pe") or {}
                except (TypeError, ValueError):
                    deterministic_pe = {}
            # The exporter exposes non-call references, but raw Ghidra output
            # does not include decoded string contents. Keep correlation
            # explicit and bounded; unresolved addresses remain unresolved.
            data_addresses = [
                str(reference.get("to"))
                for function_row in function_rows
                for reference in (function_row.get("references_from", []) if isinstance(function_row.get("references_from", []), list) else [])
                if isinstance(reference, dict)
                and "call" not in str(reference.get("type", "")).lower()
                and reference.get("to")
            ]
            strings_by_address: dict[str, str] = resolve_static_data_strings(
                artifact_content,
                data_addresses,
                deterministic_pe,
            )
            for item in output.get("strings", []) if isinstance(output.get("strings"), list) else []:
                if isinstance(item, dict) and item.get("address") and item.get("text"):
                    strings_by_address[str(item["address"])] = str(item["text"])
            # Only materialize the deterministic, signal-ranked function
            # budget.  Iterating the raw exporter list here would bypass the
            # cap above and turn a large binary into an unbounded evidence
            # and audit write workload.
            for function in function_rows:
                if not isinstance(function, dict):
                    continue
                entry = str(function.get("entry", ""))
                entry_rva = function.get("entry_rva")
                anchor = {"type": "function_entry", "entry": entry, "rva": entry_rva}
                supporting_ids = [
                    emit(
                        "function",
                        {
                            "name": function.get("name"),
                            "signature": function.get("signature"),
                        },
                        anchor,
                    ).id
                ]
                calls = function.get("references_from", [])
                call_rows = calls if isinstance(calls, list) else []
                call_targets = [
                    {
                        "from": call.get("from"),
                        "to": call.get("to"),
                        "type": call.get("type"),
                        "target_name": call.get("target_name"),
                        "target_function": call.get("target_function"),
                    }
                    for call in call_rows
                    if isinstance(call, dict)
                    and ("call" in str(call.get("type", "")).lower())
                ]
                data_targets = [
                    {
                        "from": call.get("from"),
                        "to": call.get("to"),
                        "type": call.get("type"),
                        "target_name": call.get("target_name"),
                    }
                    for call in call_rows
                    if isinstance(call, dict)
                    and "call" not in str(call.get("type", "")).lower()
                    and call.get("target_name")
                ]
                context_evidence = emit(
                    "function_context",
                    {
                        "name": function.get("name"),
                        "entry": entry,
                        "entry_rva": entry_rva,
                        "signature": function.get("signature"),
                        "caller_count": len(function.get("xrefs_to_entry", []) or []),
                        "callee_count": len(call_targets),
                        "data_reference_count": len(data_targets),
                        "call_targets": call_targets[:48],
                        "data_references": data_targets[:48],
                        "cfg_block_count": len(function.get("cfg_blocks", []) or []),
                        "instruction_count": len(function.get("instructions", []) or []),
                    },
                    {**anchor, "type": "function_context"},
                )
                supporting_ids.append(context_evidence.id)
                mnemonics = function.get("mnemonics", [])
                if isinstance(mnemonics, list):
                    fingerprint = function_fuzzy_fingerprint(tuple(str(item) for item in mnemonics))
                    supporting_ids.append(
                        emit(
                            "function_simhash",
                            {
                                "algorithm": "charikar-simhash-64",
                                "feature": "mnemonic-4gram",
                                "hash": "md5-prefix-64-le",
                                "value": fingerprint,
                            },
                            anchor,
                        ).id
                    )
                function_chain_facts = derive_function_mechanism_facts(
                    function,
                    subject=artifact.logical_path,
                )
                if deterministic_pe:
                    # Promote PE-role classification into the same immutable
                    # function evidence stream used by mechanism claims.  It
                    # is deliberately a hypothesis with explicit missing
                    # discriminators, so header parsing never becomes a
                    # manual-mapper conclusion by itself.
                    pe_roles = tuple(
                        role for role in classify_pe_semantics(function, deterministic_pe)
                        if role.get("role") != "UNKNOWN_PE_ROLE"
                    )
                    function_chain_facts = tuple(function_chain_facts) + tuple(
                        StaticFact(
                            "loader",
                            "pe_semantic_classification",
                            role,
                            {
                                "type": "function_pe_role",
                                "function_entry": entry,
                                "rva": entry_rva,
                                "subject": artifact.logical_path,
                            },
                        )
                        for role in pe_roles
                    )
                instructions = function.get("instructions", [])
                instruction_rows = instructions if isinstance(instructions, list) else []
                abstract_execution = StaticAbstractExecutor(max_steps=128).analyze(
                    function,
                    source_evidence_ids=tuple(supporting_ids),
                )
                function_chain_facts = tuple(function_chain_facts) + (
                    StaticFact(
                        "static_triage",
                        "abstract_execution_trace",
                        abstract_execution.as_dict(),
                        {
                            "type": "abstract_execution_trace",
                            "function_entry": entry,
                            "rva": entry_rva,
                            "subject": artifact.logical_path,
                        },
                    ),
                )
                # Persist compact semantic slices alongside the legacy
                # abstract trace.  The slice is the model-facing source/sink
                # view; the pointer links make dynamic resolver output and
                # indirect consumers explicit without claiming execution.
                function_chain_facts = tuple(function_chain_facts) + (
                    StaticFact(
                        "static_triage",
                        "pcode_slice",
                        build_pcode_slice(
                            function,
                            source_evidence_ids=tuple(supporting_ids),
                            max_operations=64,
                        ),
                        {
                            "type": "pcode_slice",
                            "function_entry": entry,
                            "rva": entry_rva,
                            "subject": artifact.logical_path,
                        },
                    ),
                )
                pointer_links = track_indirect_function_pointers(function)
                function_chain_facts = tuple(function_chain_facts) + tuple(
                    StaticFact(
                        "loader",
                        "indirect_function_pointer_link",
                        dict(link),
                        {
                            "type": "indirect_function_pointer",
                            "function_entry": entry,
                            "rva": entry_rva,
                            "subject": artifact.logical_path,
                        },
                    )
                    for link in pointer_links
                )
                decode_window = analyze_xor_decode_window(instruction_rows)
                if decode_window is not None:
                    verified = verify_xor_decode_candidate(
                        decode_window,
                        artifact_content,
                        deterministic_pe,
                    )
                    function_chain_facts = tuple(function_chain_facts) + (
                        StaticFact(
                            "decryption",
                            "mechanism_decode_window",
                            {**decode_window, "verification_result": verified},
                            {"type": "function_instruction_window", "function_entry": entry, "rva": entry_rva},
                        ),
                    )
                data_correlations = correlate_data_references(function, strings_by_address)
                if data_correlations:
                    function_chain_facts = tuple(function_chain_facts) + (
                        StaticFact(
                            "static_triage",
                            "function_data_correlation",
                            {"function": function.get("name"), "references": list(data_correlations)},
                            {"type": "function_data_reference", "function_entry": entry, "rva": entry_rva},
                        ),
                    )
                chain_evidence_ids: list[str] = []
                for chain_fact in function_chain_facts:
                    chain_evidence = emit(
                        chain_fact.kind,
                        chain_fact.value,
                        chain_fact.anchor,
                    )
                    chain_evidence_ids.append(chain_evidence.id)
                    supporting_ids.append(chain_evidence.id)
                interesting_indexes = [
                    index
                    for index, instruction in enumerate(instruction_rows)
                    if isinstance(instruction, dict)
                    and (
                        any(token in str(instruction.get("text", "")).lower() for token in (
                            "cmp ", "test ", "xor ", "call ", "lea ", "mov ", "jz ", "jnz ",
                        ))
                    )
                ]
                window_indexes: set[int] = set(range(min(24, len(instruction_rows))))
                for index in interesting_indexes[:12]:
                    window_indexes.update(range(max(0, index - 3), min(len(instruction_rows), index + 4)))
                if len(window_indexes) > 128:
                    window_indexes = set(sorted(window_indexes)[:128])
                if window_indexes:
                    instruction_evidence = emit(
                        "function_instruction_window",
                        {
                            "name": function.get("name"),
                            "entry": entry,
                            "entry_rva": entry_rva,
                            "instructions": [
                                instruction_rows[index]
                                for index in sorted(window_indexes)
                                if isinstance(instruction_rows[index], dict)
                            ],
                            "selected_for": [
                                "call/data-flow context",
                                "branch and immediate inspection",
                                "decode-pattern screening",
                            ],
                        },
                        {**anchor, "type": "instruction_window"},
                    )
                    supporting_ids.append(instruction_evidence.id)
                # Materialize deterministic call-argument recovery alongside
                # the function context. This keeps the evidence chain useful
                # to the investigator and report renderer: APIs are still
                # only static observations, but concrete register/constant /
                # string producers are available for HOW analysis.
                argument_targets = {
                    str(call.get("target_name") or call.get("target_function") or "")
                    for call in call_rows
                    if isinstance(call, dict)
                    and str(call.get("target_name") or call.get("target_function") or "").strip()
                }
                argument_targets = {
                    item for item in argument_targets
                    if any(token in item.casefold() for token in (
                        "winhttp", "wininet", "internet", "createprocess", "shellexecute",
                        "winexec", "virtualalloc", "virtualprotect", "writeprocessmemory",
                        "openprocess", "regsetvalue", "createservice", "loadlibrary",
                        "getprocaddress", "createfile", "writefile", "readfile",
                    ))
                }
                for argument_api in sorted(argument_targets)[:24]:
                    for trace in trace_static_api_arguments(function, argument_api):
                        argument_evidence = emit(
                            "api_argument_trace",
                            {
                                **trace,
                                "function_entry": entry,
                                "rva": entry_rva,
                                "consumer": argument_api,
                                "source_evidence_ids": list(supporting_ids),
                                "static_only": True,
                            },
                            {
                                **anchor,
                                "type": "api_argument_trace",
                                "callsite": trace.get("callsite"),
                                "api": argument_api,
                            },
                        )
                        supporting_ids.append(argument_evidence.id)
                for specification in self.static_agent.propose_claims(
                    function_chain_facts,
                    artifact.logical_path,
                ):
                    evidence_ids = tuple(
                        chain_evidence_ids[index]
                        for index in specification.fact_indexes
                        if 0 <= index < len(chain_evidence_ids)
                    )
                    validation = validate_claim_evidence(
                        evidence_ids,
                        set(chain_evidence_ids),
                        module=specification.module,
                        evidence_natures={item: "STATIC_OBSERVED" for item in chain_evidence_ids},
                    )
                    if not validation.accepted:
                        continue
                    claim = Claim(
                        task_id=task.id,
                        module=specification.module,
                        claim_type="MECHANISM_CHAIN",
                        subject=f"{artifact.logical_path}:{function.get('name', 'unknown')}@{entry}",
                        action=specification.action,
                        object=specification.object,
                        mechanism=specification.mechanism,
                        condition=specification.condition,
                        statement=specification.statement,
                        nature="STATIC_INFERRED",
                        status="CANDIDATE",
                        confidence=specification.confidence,
                        attack_mapping=specification.attack_mapping,
                    )
                    session.add(claim)
                    session.flush()
                    for evidence_id in validation.evidence_ids:
                        session.add(ClaimEvidence(claim_id=claim.id, evidence_id=evidence_id, stance="SUPPORTS"))
                    self._infer_component_relations(session, task, artifact, claim)
                    self._audit(
                        session,
                        case_id=task.case_id,
                        task_id=task.id,
                        event_type="claim.created",
                        actor="static-analysis-agent",
                        object_type="Claim",
                        object_id=claim.id,
                        payload={
                            "module": claim.module,
                            "claim_kind": "ghidra_mechanism_chain",
                            "function_entry": entry,
                            **self.static_agent.metadata,
                        },
                    )
                signature = str(function.get("signature", ""))
                if signature:
                    supporting_ids.append(
                        emit(
                            "function_interface",
                            {
                                "signature": signature,
                                "inputs": self._signature_inputs(signature),
                                "output": self._signature_output(signature),
                            },
                            anchor,
                        ).id
                    )
                calls = function.get("references_from", [])
                if isinstance(calls, list):
                    mechanism_names: list[str] = []
                    ioc_names: list[str] = []
                    for call in calls[: self._MAX_GHIDRA_CALL_EVIDENCE_PER_FUNCTION]:
                        if isinstance(call, dict):
                            target_name = str(
                                call.get("target_name") or call.get("target_function") or ""
                            )
                            if target_name:
                                mechanism_names.append(target_name)
                                if any(
                                    token in target_name.lower()
                                    for token in (
                                        "http",
                                        "url",
                                        "socket",
                                        "connect",
                                        "dns",
                                        "crypt",
                                    )
                                ):
                                    ioc_names.append(target_name)
                            supporting_ids.append(
                                emit(
                                    "function_call",
                                    call,
                                    {**anchor, "from": call.get("from")},
                                ).id
                            )
                    if mechanism_names:
                        supporting_ids.append(
                            emit(
                                "function_mechanism",
                                {"calls": list(dict.fromkeys(mechanism_names))},
                                anchor,
                            ).id
                        )
                    if ioc_names:
                        supporting_ids.append(
                            emit(
                                "function_ioc",
                                {"indicators": list(dict.fromkeys(ioc_names))},
                                anchor,
                            ).id
                        )
                xrefs = function.get("xrefs_to_entry", [])
                xref_rows = xrefs if isinstance(xrefs, list) else []
                for xref in xref_rows[: self._MAX_GHIDRA_XREF_EVIDENCE_PER_FUNCTION]:
                    if isinstance(xref, dict):
                        evidence = emit(
                            "xref",
                            xref,
                            {**anchor, "from": xref.get("from")},
                        )
                        if len(supporting_ids) < 22:
                            supporting_ids.append(evidence.id)
                blocks = function.get("cfg_blocks", [])
                block_rows = blocks if isinstance(blocks, list) else []
                for block in block_rows[: self._MAX_GHIDRA_CFG_EVIDENCE_PER_FUNCTION]:
                    if isinstance(block, dict):
                        evidence = emit(
                            "cfg_block",
                            block,
                            {
                                **anchor,
                                "type": "cfg_block",
                                "block_start": block.get("start"),
                            },
                        )
                        if len(supporting_ids) < 62:
                            supporting_ids.append(evidence.id)
                function_candidates.append(
                    FunctionEvidenceCandidate(
                        artifact_id=artifact.id,
                        logical_path=artifact.logical_path,
                        name=str(function.get("name", "unknown")),
                        entry=entry,
                        xref_count=len(xref_rows),
                        cfg_block_count=len(block_rows),
                        instruction_count=len(mnemonics) if isinstance(mnemonics, list) else 0,
                        evidence_ids=tuple(supporting_ids),
                    )
                )
                self._record_ghidra_behavior_claims(
                    session,
                    task,
                    artifact,
                    function,
                    tuple(supporting_ids),
                )
            # Correlate the complete deterministic Ghidra evidence stream
            # after function rows have been materialized.  This path is
            # intentionally independent of model actions: a static run must
            # preserve useful mechanism links even when no planner turn is
            # present.  The links remain STATIC_DERIVED and carry the exact
            # immutable source IDs plus input/output digests.
            static_rows = [
                {
                    "id": item.id,
                    "kind": item.kind,
                    "value": item.value,
                    "anchor": item.anchor,
                }
                for item in emitted_evidence
                if item.nature == "STATIC_OBSERVED"
            ]
            evidence_by_id = {item.id: item for item in emitted_evidence}
            for link in derive_static_mechanism_links(static_rows):
                link_value = link.get("value")
                if not isinstance(link_value, dict):
                    continue
                source_ids = list(
                    dict.fromkeys(
                        str(item)
                        for item in link_value.get("source_evidence_ids", ())
                        if str(item).strip()
                    )
                )[:24]
                source_rows = [evidence_by_id[item] for item in source_ids if item in evidence_by_id]
                if not source_rows or len(source_rows) != len(source_ids):
                    continue
                normalized_value = {
                    **link_value,
                    "source_evidence_ids": source_ids,
                    "static_only": True,
                }
                input_digest = hashlib.sha256(
                    json.dumps(
                        {
                            "tool_run_id": tool_run.id,
                            "evaluator": "derive_static_mechanism_links",
                            "source_evidence_ids": source_ids,
                        },
                        ensure_ascii=True,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
                output_digest = hashlib.sha256(
                    json.dumps(
                        normalized_value,
                        ensure_ascii=True,
                        sort_keys=True,
                        default=str,
                    ).encode("utf-8")
                ).hexdigest()
                normalized_value["derivation"] = {
                    "evaluator": "derive_static_mechanism_links",
                    "input_evidence_ids": source_ids,
                    "input_digest": input_digest,
                    "output_digest": output_digest,
                    "exact": True,
                }
                emitted = emit(
                    str(link.get("kind", "investigation_mechanism_link")),
                    normalized_value,
                    dict(link.get("anchor") or {}),
                    nature="STATIC_DERIVED",
                )
                evidence_by_id[emitted.id] = emitted
            cross_function_chains = build_cross_function_chains(function_rows)
            for chain in cross_function_chains[:128]:
                chain_evidence = emit(
                    "cross_function_chain",
                    chain,
                    {
                        "type": "call_graph_path",
                        "function_entries": list(chain.get("functions", [])),
                    },
                )
                claim = Claim(
                    task_id=task.id,
                    module="static_triage",
                    claim_type="CROSS_FUNCTION_MECHANISM",
                    subject=artifact.logical_path,
                    action="exhibits_cross_function_chain",
                    object=" -> ".join(str(item) for item in chain.get("categories", [])),
                    mechanism="bounded recovered call-graph path",
                    condition="static call graph only; branch order, data flow, and runtime execution are unverified",
                    statement=(
                        f"{artifact.logical_path} has a recovered cross-function path "
                        f"({' -> '.join(str(item) for item in chain.get('functions', []))}) "
                        f"covering {', '.join(str(item) for item in chain.get('categories', []))}."
                    ),
                    nature="STATIC_INFERRED",
                    status="CANDIDATE",
                    confidence=str(chain.get("confidence", "LOW")),
                    attack_mapping={},
                )
                session.add(claim)
                session.flush()
                session.add(ClaimEvidence(claim_id=claim.id, evidence_id=chain_evidence.id, stance="SUPPORTS"))
                relation_types = {
                    "network": "LOADS",
                    "execution": "EXECUTES",
                    "persistence": "LOADS",
                    "injection": "INJECTS",
                    "dynamic_resolution": "LOADS",
                    "anti_analysis": "DECRYPTS",
                }
                for category in chain.get("categories", []):
                    relation_type = relation_types.get(str(category))
                    if relation_type is None:
                        continue
                    existing = session.scalar(
                        select(Relation.id).where(
                            Relation.task_id == task.id,
                            Relation.source_artifact_id == artifact.id,
                            Relation.target_artifact_id == artifact.id,
                            Relation.relation_type == relation_type,
                            Relation.claim_id == claim.id,
                        )
                    )
                    if existing is None:
                        session.add(
                            Relation(
                                task_id=task.id,
                                source_artifact_id=artifact.id,
                                target_artifact_id=artifact.id,
                                relation_type=relation_type,
                                claim_id=claim.id,
                                status="INFERRED",
                            )
                        )
                self._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type="claim.created",
                    actor="static-analysis-agent",
                    object_type="Claim",
                    object_id=claim.id,
                    payload={"claim_kind": "cross_function_mechanism", "evidence_id": chain_evidence.id},
                )
        processed_function_entries = {
            str(item.get("entry"))
            for item in function_rows
            if isinstance(item, dict) and item.get("entry") is not None
        }
        self._record_function_similarity(
            session,
            task,
            artifact,
            tool_run,
            processed_function_entries=processed_function_entries,
        )
        for proposal in self.static_agent.prioritize_function_evidence(tuple(function_candidates)):
            validation = validate_claim_evidence(
                proposal.evidence_ids,
                set(proposal.evidence_ids),
                module="static_triage",
                evidence_natures={item: 'STATIC_OBSERVED' for item in proposal.evidence_ids},
            )
            if not validation.accepted:
                raise ValueError(validation.reason)
            claim = Claim(
                task_id=task.id,
                module="static_triage",
                claim_type="FUNCTION_REVIEW_PRIORITY",
                subject=proposal.subject,
                action="prioritizes",
                object=proposal.object,
                mechanism="xref/cfg/instruction prominence",
                condition="static evidence only",
                statement=proposal.statement,
                status="CANDIDATE",
                confidence=proposal.confidence,
                attack_mapping={},
            )
            session.add(claim)
            session.flush()
            for evidence_id in validation.evidence_ids:
                session.add(
                    ClaimEvidence(
                        claim_id=claim.id,
                        evidence_id=evidence_id,
                        stance="SUPPORTS",
                    )
                )
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="claim.created",
                actor="static-analysis-agent",
                object_type="Claim",
                object_id=claim.id,
                payload={
                    "module": claim.module,
                    "status": claim.status,
                    "confidence": claim.confidence,
                    "claim_kind": "function_review_priority",
                    **self.static_agent.metadata,
                },
            )
        symbols = output.get("symbols", [])
        if isinstance(symbols, list):
            symbol_rows = [item for item in symbols if isinstance(item, dict)]
            ranked_symbols = sorted(
                enumerate(symbol_rows),
                key=lambda pair: (
                    bool(pair[1].get("external")),
                    bool(pair[1].get("name")),
                    -pair[0],
                ),
                reverse=True,
            )
            for _, symbol in ranked_symbols[: self._MAX_GHIDRA_SYMBOL_EVIDENCE]:
                if isinstance(symbol, dict):
                    kind = "import_symbol" if symbol.get("external") else "export_symbol"
                    emit(kind, symbol, {"type": "symbol_address", "address": symbol.get("address")})

    def _record_ghidra_behavior_claims(
        self,
        session: Session,
        task: AnalysisTask,
        artifact: Artifact,
        function: dict[str, object],
        evidence_ids: tuple[str, ...],
    ) -> None:
        """Aggregate function call evidence into conservative atomic Claims."""
        calls = function.get("references_from", [])
        if not isinstance(calls, list) or not evidence_ids:
            return
        names = sorted(
            {
                str(call.get("target_name") or call.get("target_function"))
                for call in calls
                if isinstance(call, dict)
                and (call.get("target_name") or call.get("target_function"))
            }
        )
        if not names:
            return
        normalized_names = {normalize_api_symbol(name) for name in names}

        def has_name(values: tuple[str, ...]) -> bool:
            return any(normalize_api_symbol(value) in normalized_names for value in values)

        def has_prefix(prefixes: tuple[str, ...]) -> bool:
            return any(
                any(normalize_api_symbol(name).startswith(prefix) for prefix in prefixes)
                for name in names
            )
        categories: list[tuple[str, str, str, str, str]] = []
        if has_name(("CryptDecrypt", "CryptEncrypt", "BCryptDecrypt", "BCryptEncrypt", "AES", "RC4", "XOR")):
            categories.append(
                (
                    "decryption",
                    "may_decode_or_decrypt",
                    "embedded or transient data",
                    "Ghidra call references to cryptographic or encoding APIs",
                    "Function-level static references are not proof of runtime execution.",
                )
            )
        if has_prefix(("findresource", "loadresource", "sizeofresource", "lockresource")):
            categories.append(
                (
                    "loader",
                    "extracts_resource_payload",
                    "embedded resource bytes",
                    "FindResource/LoadResource/LockResource call chain",
                    "Resource extraction is statically observed; payload use is not confirmed.",
                )
            )
        if has_prefix(("rtldecompressbuffer",)) or has_name(("decompress",)):
            categories.append(
                (
                    "decryption",
                    "decompresses_or_decodes",
                    "resource or transient buffer",
                    "RtlDecompressBuffer/decompression call reference",
                    "Decompression and output use are not confirmed at runtime.",
                )
            )
        if any(is_anti_analysis_signal(name) for name in names):
            categories.append(
                (
                    "anti_analysis",
                    "checks_execution_environment",
                    "memory, processor, or debugger state",
                    "environment inspection API references",
                    "Branch effect and anti-analysis purpose are not confirmed statically.",
                )
            )
        if has_prefix(("openscmanager", "openservice", "queryservicestatus")):
            categories.append(
                (
                    "anti_analysis",
                    "queries_service_state",
                    "Windows service",
                    "service manager/status API references",
                    "The queried service and downstream decision are not confirmed statically.",
                )
            )
        if any(is_dynamic_loader_call(name) or is_injection_call(name) or classify_api_symbol(name).value in {"MEMORY_ALLOCATION", "MEMORY_PROTECTION"} for name in names if classify_api_symbol(name) is not None):
            categories.append(
                (
                    "loader",
                    "may_load_or_prepare_memory",
                    "code or a secondary component",
                    "Ghidra call references to loader or memory-management APIs",
                    "Function-level static references are not proof of runtime execution.",
                )
            )
        if any(is_network_transport_call(name) for name in names):
            categories.append(
                (
                    "c2_network",
                    "references_network_endpoint",
                    "network endpoint or transport",
                    "Ghidra call references to network APIs",
                    "Endpoint purpose and runtime reachability are not confirmed statically.",
                )
            )
        if any(is_execution_call(name) for name in names):
            categories.append(
                (
                    "execution",
                    "may_execute",
                    "process or command",
                    "process creation or command execution API references",
                    "Function-level static references are not proof of runtime execution.",
                )
            )
        function_name = str(function.get("name", "unknown"))
        entry = str(function.get("entry", "unknown"))
        for module, action, obj, mechanism, condition in categories:
            # These IDs were assembled exclusively from immutable Evidence
            # emitted for this function. Re-querying every task Evidence
            # row for every function creates O(functions * evidence)
            # work for large Ghidra outputs and can leave a task RUNNING.
            # Validate the same unknown-ID and nature constraints against
            # this bounded, task-scoped set instead.
            validation = validate_claim_evidence(
                evidence_ids,
                set(evidence_ids),
                module=module,
                evidence_natures={item: 'STATIC_OBSERVED' for item in evidence_ids},
            )
            if not validation.accepted:
                raise ValueError(validation.reason)
            attack_mapping: dict[str, object] = {}
            if action == "decompresses_or_decodes":
                attack_mapping = {
                    "status": "candidate",
                    "mappings": [{"technique_id": "T1140", "technique_name": "Deobfuscate/Decode Files or Information", "status": "candidate"}],
                }
            elif action == "queries_service_state":
                attack_mapping = {
                    "status": "candidate",
                    "mappings": [{"technique_id": "T1007", "technique_name": "System Service Discovery", "status": "candidate"}],
                }
            elif action == "checks_execution_environment":
                attack_mapping = {
                    "status": "candidate",
                    "mappings": [{"technique_id": "T1497", "technique_name": "Virtualization/Sandbox Evasion", "status": "candidate"}],
                }
            claim = Claim(
                task_id=task.id,
                module=module,
                claim_type="BEHAVIOR",
                subject=f"{artifact.logical_path}:{function_name}@{entry}",
                action=action,
                object=obj,
                mechanism=mechanism,
                condition=condition,
                statement=(
                    f"Function {function_name} at {entry} references {', '.join(names)} "
                    f"consistent with {module} behavior."
                ),
                nature="STATIC_INFERRED",
                status="CANDIDATE",
                confidence="MEDIUM",
                attack_mapping=attack_mapping,
            )
            session.add(claim)
            session.flush()
            for evidence_id in validation.evidence_ids:
                session.add(ClaimEvidence(claim_id=claim.id, evidence_id=evidence_id, stance="SUPPORTS"))
            self._infer_component_relations(session, task, artifact, claim)
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="claim.created",
                actor="static-analysis-agent",
                object_type="Claim",
                object_id=claim.id,
                payload={
                    "module": claim.module,
                    "claim_kind": "ghidra_function_behavior",
                    "function_entry": entry,
                    **self.static_agent.metadata,
                },
            )

    def _infer_component_relations(
        self, session: Session, task: AnalysisTask, artifact: Artifact, claim: Claim
    ) -> None:
        """Link inferred behavior Claims to extracted child components when present."""
        relation_type = {
            "decryption": "DECRYPTS",
            "loader": "INJECTS" if "inject" in claim.action else "LOADS",
            "execution": "EXECUTES",
        }.get(claim.module)
        if relation_type is None:
            return
        children = list(
            session.scalars(
                select(Artifact).where(
                    Artifact.task_id == task.id,
                    Artifact.parent_artifact_id == artifact.id,
                    Artifact.disposed_at.is_(None),
                )
            )
        )
        for child in children:
            existing = session.scalar(
                select(Relation.id).where(
                    Relation.task_id == task.id,
                    Relation.source_artifact_id == artifact.id,
                    Relation.target_artifact_id == child.id,
                    Relation.relation_type == relation_type,
                    Relation.claim_id == claim.id,
                )
            )
            if existing:
                continue
            relation = Relation(
                task_id=task.id,
                source_artifact_id=artifact.id,
                target_artifact_id=child.id,
                relation_type=relation_type,
                claim_id=claim.id,
                status="INFERRED",
            )
            session.add(relation)
            session.flush()
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="relation.created",
                actor="static-analysis-agent",
                object_type="Relation",
                object_id=relation.id,
                payload={
                    "relation_type": relation_type,
                    "claim_id": claim.id,
                    "source_artifact_id": artifact.id,
                    "target_artifact_id": child.id,
                },
            )

    @staticmethod
    def _signature_inputs(signature: str) -> list[str]:
        if "(" not in signature or ")" not in signature:
            return []
        parameters = signature.split("(", 1)[1].rsplit(")", 1)[0].strip()
        if not parameters or parameters == "void":
            return []
        return [item.strip() for item in parameters.split(",") if item.strip()]

    @staticmethod
    def _signature_output(signature: str) -> str:
        return signature.split("(", 1)[0].strip() if "(" in signature else "unknown"

    @staticmethod
    def _actual_depth(session: Session, task_id: str, artifacts: list[Artifact]) -> str:
        if not artifacts:
            return "D2"
        parser_ok = session.scalar(
            select(ToolRun.id).where(
                ToolRun.task_id == task_id,
                ToolRun.status == "SUCCEEDED",
                ToolRun.tool_name.in_(
                    [
                        "pe-parser",
                        "script-parser",
                        "document-carrier-parser",
                        "builtin-static-analyzer",
                    ]
                ),
            )
        )
        if not parser_ok:
            return "D2"
        if any(item.detected_type in {"script", "pdf", "ooxml", "ole"} for item in artifacts):
            return "D3"
        pe_ids = [item.id for item in artifacts if item.detected_type == "pe"]
        if not pe_ids:
            return "D2"
        ghidra_ok = session.scalar(
            select(ToolRun.id).where(
                ToolRun.task_id == task_id,
                ToolRun.artifact_id.in_(pe_ids),
                ToolRun.tool_name == "ghidra-headless",
                ToolRun.status == "SUCCEEDED",
            )
        )
        function_id = session.scalar(
            select(Evidence.id)
            .where(
                Evidence.task_id == task_id,
                Evidence.artifact_id.in_(pe_ids),
                Evidence.kind == "function",
            )
            .limit(1)
        )
        fallback_code_id = session.scalar(
            select(Evidence.id).where(
                Evidence.task_id == task_id,
                Evidence.artifact_id.in_(pe_ids),
                Evidence.kind.in_({"code_api_call", "mechanism_decode", "mechanism_decompression_format"}),
            ).limit(1)
        )
        return "D3" if (ghidra_ok and function_id) or fallback_code_id else "D2"

    @staticmethod
    def _completion_limitations(
        session: Session, task_id: str, artifacts: list[Artifact]
    ) -> list[str]:
        """Check every REQUIRED artifact instead of deriving COMPLETE from an empty list."""
        limitations: list[str] = []
        for artifact in artifacts:
            if artifact.obligation != "REQUIRED":
                continue
            if artifact.disposed_at is not None:
                limitations.append(f"Required artifact disposed: {artifact.logical_path}.")
                continue
            if artifact.detected_type in {"unknown", "unsupported", "binary"}:
                limitations.append(
                    f"Required artifact type is unsupported/unknown: {artifact.logical_path}."
                )
            successful = session.scalar(
                select(ToolRun.id).where(
                    ToolRun.task_id == task_id,
                    ToolRun.artifact_id == artifact.id,
                    ToolRun.status == "SUCCEEDED",
                )
            )
            if successful is None:
                limitations.append(
                    f"Required artifact was not successfully analyzed: {artifact.logical_path}."
                )
        return limitations

    @staticmethod
    def _build_analysis_coverage(
        session: Session,
        task_id: str,
        artifacts: list[Artifact],
        limitations: list[str],
    ) -> dict[str, object]:
        """Compute static coverage dimensions from persisted observations.

        Coverage describes what the pipeline inspected, not whether a claim is
        correct.  Values are bounded in ``analysis_coverage`` and missing
        dimensions are surfaced as explicit gaps in the report.
        """
        task = session.get(AnalysisTask, task_id)
        required = [item for item in artifacts if item.obligation == "REQUIRED"]
        parsed = 0
        code = 0
        functions = 0
        data_refs = 0
        mechanisms = 0
        verifiers = 0
        verified_mechanisms = 0
        semantic_flow_nodes = 0
        semantic_flow_edges = 0
        eligible_flow_mechanisms = 0
        participating_flow_mechanisms = 0
        pipeline_runs = 0
        # This function runs immediately before the immutable AnalysisSnapshot
        # is frozen; report synthesis is the current finalization step.
        reports = 1
        for artifact in required:
            runs = list(
                session.scalars(
                    select(ToolRun).where(
                        ToolRun.task_id == task_id,
                        ToolRun.artifact_id == artifact.id,
                    )
                )
            )
            if any(item.status == "SUCCEEDED" for item in runs):
                parsed += 1
                pipeline_runs += 1
            evidence = list(
                session.scalars(
                    select(Evidence).where(
                        Evidence.task_id == task_id,
                        Evidence.artifact_id == artifact.id,
                    )
                )
            )
            if evidence:
                # Code recovery requires code/function or parser facts; a
                # file_identity row alone must not inflate semantic coverage.
                if any(item.kind in {"function", "function_context", "script_function", "pe_structure", "decompile", "pcode"} for item in evidence):
                    code += 1
            if any(item.kind in {"function", "function_context", "function_call"} for item in evidence):
                functions += 1
            if any(item.kind in {"data_reference", "xref", "value_flow"} for item in evidence):
                data_refs += 1
            if any(item.kind.startswith("mechanism") or item.kind == "abstract_execution_trace" for item in evidence):
                mechanisms += 1
            claims = list(session.scalars(select(Claim).where(Claim.task_id == task_id, Claim.subject == artifact.logical_path)))
            claim_ids_for_artifact = {str(item.id) for item in claims}
            # Investigation claims are subject-addressed rather than carrying
            # an artifact FK. Include claims linked to this artifact's
            # evidence so snapshot mechanisms remain countable.
            if claim_ids_for_artifact:
                claim_evidence_rows = list(
                    session.scalars(
                        select(ClaimEvidence).where(
                            ClaimEvidence.claim_id.in_(claim_ids_for_artifact)
                        )
                    )
                )
                artifact_evidence_ids = {str(item.id) for item in evidence}
                claim_ids_for_artifact.update(
                    str(item.claim_id)
                    for item in claim_evidence_rows
                    if str(item.evidence_id) in artifact_evidence_ids
                )
            if claims:
                verifiers += 1
            verified_claim = any(
                str(item.status).upper() in {"VERIFIED", "SUPPORTED", "CONFIRMED"}
                for item in claims
            )
            # Mechanisms are materialized from the investigation snapshot
            # immediately after coverage is calculated.  Count a mechanism
            # only when its verifier explicitly accepted it; candidate claims
            # and raw parser relations are not semantic closure.
            snapshot_mechanisms = []
            strategy_snapshot = (
                task.strategy_snapshot
                if task is not None and isinstance(task.strategy_snapshot, dict)
                else {}
            )
            investigation_snapshot = strategy_snapshot.get("investigation", {})
            if isinstance(investigation_snapshot, dict):
                snapshot_mechanisms = investigation_snapshot.get("mechanisms", []) or []
            verified_snapshot_for_artifact = any(
                isinstance(item, dict)
                and (
                    str(item.get("artifact_id") or item.get("target_artifact_id") or "") == str(artifact.id)
                    or str(item.get("claim_id") or "") in claim_ids_for_artifact
                    or str(item.get("target") or "").split(":", 1)[0] == str(artifact.logical_path)
                )
                and str(item.get("status", "")).upper() in {"VERIFIED", "CONFIRMED"}
                and isinstance(item.get("verifier"), dict)
                and str(item["verifier"].get("status", "")).upper() == "VERIFIED"
                for item in snapshot_mechanisms
            )
            # Claim and mechanism projections refer to the same semantic
            # closure. Count the artifact once when either projection has an
            # explicit verifier acceptance; pipeline completion alone is not
            # semantic verification.
            if verified_claim or verified_snapshot_for_artifact:
                verified_mechanisms += 1
            artifact_mechanisms = [
                item
                for item in snapshot_mechanisms
                if isinstance(item, dict)
                and (
                    str(item.get("artifact_id") or item.get("target_artifact_id") or "") == str(artifact.id)
                    or str(item.get("claim_id") or "") in claim_ids_for_artifact
                    or str(item.get("target") or "").split(":", 1)[0] == str(artifact.logical_path)
                )
            ]
            flow_metrics = semantic_flow_metrics(artifact_mechanisms)
            semantic_flow_nodes += int(flow_metrics["semantic_flow_nodes"])
            semantic_flow_edges += int(flow_metrics["semantic_flow_edges"])
            eligible_flow_mechanisms += int(flow_metrics["eligible_mechanisms"])
            participating_flow_mechanisms += int(flow_metrics["participating_mechanisms"])
        denominator = max(1, len(required))
        relation_flow_rate = (
            participating_flow_mechanisms / eligible_flow_mechanisms
            if eligible_flow_mechanisms
            else 0.0
        )
        return analysis_coverage(
            artifact_parse=parsed / denominator,
            code_recovery=code / denominator,
            function_coverage=functions / denominator,
            data_reference_coverage=data_refs / denominator,
            mechanism_investigation=mechanisms / denominator,
            verifier_coverage=verifiers / denominator,
            report_synthesis=reports,
            gaps=limitations,
            pipeline_completion=pipeline_runs / denominator if required else 0.0,
            pipeline_dimensions={
                "artifact_parse": parsed / denominator,
                "report_synthesis": reports,
            },
            verified_mechanism_coverage=verified_mechanisms / denominator,
            relation_flow_coverage=relation_flow_rate,
            semantic_flow_nodes=semantic_flow_nodes,
            semantic_flow_edges=semantic_flow_edges,
            behavior_flow_present=(
                semantic_flow_nodes >= 3
                and semantic_flow_edges >= 2
                and participating_flow_mechanisms > 0
            ),
            coverage_applicable=eligible_flow_mechanisms > 0,
        )

    def add_component_relation(
        self,
        *,
        task_id: str,
        source_artifact_id: str,
        target_artifact_id: str,
        relation_type: str,
        evidence_id: str | None = None,
        claim_id: str | None = None,
        actor: str = "system",
    ) -> dict[str, object]:
        normalized = relation_type.upper()
        structural = {"CONTAINS", "DROPS", "EXTRACTED_FROM"}
        behavioral = {"LOADS", "DECRYPTS", "EXECUTES", "INJECTS"}
        if normalized not in structural | behavioral:
            raise ValueError(f"Unsupported component relation: {normalized}")
        if normalized in structural and not evidence_id:
            raise ValueError(f"{normalized} requires observed Evidence")
        if normalized in behavioral and not claim_id:
            raise ValueError(f"{normalized} requires an inferred Claim")
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            source = session.get(Artifact, source_artifact_id)
            target = session.get(Artifact, target_artifact_id)
            if task is None or source is None or target is None:
                raise LookupError(task_id)
            if source.task_id != task_id or target.task_id != task_id:
                raise ValueError("component relation cannot cross Analysis Task boundaries")
            if evidence_id:
                evidence = session.get(Evidence, evidence_id)
                if evidence is None or evidence.task_id != task_id:
                    raise ValueError("relation Evidence is outside the Analysis Task")
            if claim_id:
                claim = session.get(Claim, claim_id)
                if claim is None or claim.task_id != task_id:
                    raise ValueError("relation Claim is outside the Analysis Task")
            relation = Relation(
                task_id=task_id,
                source_artifact_id=source_artifact_id,
                target_artifact_id=target_artifact_id,
                relation_type=normalized,
                evidence_id=evidence_id,
                claim_id=claim_id,
                status="OBSERVED" if normalized in structural else "INFERRED",
            )
            session.add(relation)
            session.flush()
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="relation.created",
                actor=actor,
                object_type="Relation",
                object_id=relation.id,
                payload={
                    "relation_type": normalized,
                    "evidence_id": evidence_id,
                    "claim_id": claim_id,
                },
            )
            return {
                "id": relation.id,
                "relation_type": relation.relation_type,
                "status": relation.status,
                "evidence_id": relation.evidence_id,
                "claim_id": relation.claim_id,
            }

    def _record_function_similarity(
        self,
        session: Session,
        task: AnalysisTask,
        artifact: Artifact,
        source_tool_run: ToolRun,
        *,
        processed_function_entries: set[str] | None = None,
    ) -> None:
        all_source_rows = list(
            session.scalars(
                select(Evidence).where(
                    Evidence.task_id == task.id,
                    Evidence.kind == "function_simhash",
                )
            )
        )
        if not all_source_rows:
            return
        # A processed-function budget limits which functions issue a query;
        # it must not remove already persisted same-task fingerprints from the
        # comparison corpus.  Otherwise the first bounded function can never
        # match a later/unselected function and similarity becomes write-only.
        source_rows = all_source_rows
        if processed_function_entries is not None:
            source_rows = [
                row
                for row in source_rows
                if str((row.anchor or {}).get("entry", "")) in processed_function_entries
            ]
            if not source_rows:
                return
        records = tuple(
            FingerprintRecord(
                row.id,
                row.artifact_id,
                str(row.anchor.get("entry", row.id)),
                str(row.value.get("value", "")),
                str(row.value.get("algorithm", "")),
                str(row.value.get("feature", "")),
                str(row.value.get("hash", "")),
            )
            for row in all_source_rows
        )
        scopes = (
            frozenset({"CURRENT_TASK"})
            if self._is_reference_isolated_blind(task)
            else frozenset({"KNOWN_LIBRARY", "CURRENT_TASK"})
        )
        similarity_run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="function-similarity-index",
            tool_version="1.0.0",
            status="SUCCEEDED",
            parameters={"threshold": 10, "limit": 50, "scopes": sorted(scopes)},
            environment={"deterministic": True, "sample_execution": False, "network_access": False},
            output={"source_count": len(source_rows)},
            finished_at=utcnow(),
        )
        session.add(similarity_run)
        session.flush()
        self._audit(
            session,
            case_id=task.case_id,
            task_id=task.id,
            event_type="tool_run.completed",
            actor="system",
            object_type="ToolRun",
            object_id=similarity_run.id,
            payload={"tool_name": similarity_run.tool_name, "status": similarity_run.status},
        )
        for source in source_rows:
            query = SimilarityQuery(
                source.id,
                str(source.value.get("value", "")),
                scopes,
            )
            for match in self.similarity_index.search(query, records=records):
                evidence = Evidence(
                    task_id=task.id,
                    artifact_id=source.artifact_id,
                    tool_run_id=similarity_run.id,
                    module="static_triage",
                    kind="function_similarity",
                    nature="STATIC_OBSERVED",
                    value={
                        "source_evidence_id": source.id,
                        "reference_kind": match.reference_kind,
                        "reference_id": match.reference_id,
                        "distance": match.distance,
                        "threshold": match.threshold,
                        "algorithm": match.algorithm,
                        "feature": match.feature,
                        "reference_metadata": match.reference_metadata,
                        "catalog_sha256": match.catalog_sha256,
                    },
                    anchor={**source.anchor, "similarity_source": source.id},
                )
                session.add(evidence)
                session.flush()
                self._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type="evidence.recorded",
                    actor="function-similarity-index",
                    object_type="Evidence",
                    object_id=evidence.id,
                    payload={"kind": evidence.kind, "tool_run_id": similarity_run.id},
                )

    @staticmethod
    def _model_route_metadata(provider: Any) -> dict[str, object]:
        return {
            "provider": provider.provider,
            "model": provider.model,
            "api_style": provider.api_style,
            "enabled": provider.enabled,
            "stream": provider.stream,
            "supports_json_mode": provider.supports_json_mode,
            "temperature": provider.temperature,
            "top_p": provider.top_p,
            "configured": provider.configured,
            "protocol_contract": provider_contract(provider),
        }

    def _store_model_payload(self, payload: bytes):
        encrypted = self._model_payload_cipher.encrypt(base64.b64encode(payload).decode("ascii"))
        return self.content_store.put(encrypted.encode("ascii"))

    @staticmethod
    def _retrieval_target_anchors(
        completed_actions: list[dict[str, object]],
        artifact_id: str,
    ) -> tuple[str, ...]:
        """Extract only typed action targets; free-form model rationale is not a selector."""
        anchors: list[str] = []
        for action in completed_actions[-64:]:
            if not isinstance(action, dict) or action.get("target_artifact_id") not in {None, artifact_id}:
                continue
            parameters = action.get("target_selector")
            if not isinstance(parameters, dict):
                parameters = action.get("parameters")
            if not isinstance(parameters, dict):
                continue
            for name in ("target", "api", "function", "function_entry", "entry", "rva", "address"):
                value = parameters.get(name)
                if isinstance(value, (str, int)) and str(value).strip():
                    anchors.append(str(value))
        return tuple(dict.fromkeys(anchors))[:32]

    @staticmethod
    def _selector_is_anchored_in_evidence(
        selector: Mapping[str, object],
        evidence_ids: list[str],
        context_manifest: list[dict[str, object]],
        *,
        target_artifact_id: str | None = None,
    ) -> bool:
        """Require a model-selected static target to originate in cited Evidence."""
        cited_ids = set(evidence_ids)
        cited = [
            item
            for item in context_manifest
            if str(item.get("evidence_id")) in cited_ids
            and (
                target_artifact_id is None
                or str(item.get("artifact_id")) == target_artifact_id
            )
        ]
        if not cited:
            return False
        source_text = "\n".join(
            json.dumps(
                {"value": item.get("value", {}), "anchor": item.get("anchor", {})},
                ensure_ascii=True,
                sort_keys=True,
                default=str,
            ).casefold()
            for item in cited
        )
        return all(str(value).strip().casefold() in source_text for value in selector.values())

    def _build_retrieval_request(
        self,
        *,
        artifact_id: str,
        module: str,
        phase: str,
        completed_actions: list[dict[str, object]],
    ) -> RetrievalRequest:
        anchors = self._retrieval_target_anchors(completed_actions, artifact_id)
        if any(anchor.casefold() in {"getprocaddress", "loadlibrarya", "loadlibraryw"} for anchor in anchors):
            profile = "dynamic-api-resolution"
            required = (
                "import_symbol",
                "xref",
                "function_context",
                "function_call",
                "data_reference",
                "pcode_slice",
            )
        elif any(
            token in anchor.casefold()
            for anchor in anchors
            for token in ("openprocess", "updateprocthreadattribute", "parent_process", "explorer.exe")
        ):
            profile = "ppid-process-chain"
            required = (
                "function_call",
                "constant",
                "function_context",
                "xref",
            )
        elif any(
            token in anchor.casefold()
            for anchor in anchors
            for token in ("entrypoint", "entry_point", "address_of_entry_point")
        ):
            profile = "entrypoint-timeline"
            required = ("pe_structure", "function_context", "cfg_block", "function_call")
        elif any("xor" in anchor.casefold() or "decode" in anchor.casefold() for anchor in anchors):
            profile = "xor-config-recovery"
            required = (
                "mechanism_decode_window",
                "encoded_blob",
                "data_reference",
                "function_context",
                "function_instruction_window",
                "decode_result",
            )
        else:
            profile = "static-mechanism-discovery"
            required = (
                "pe_structure",
                "import_symbol",
                "xref",
                "function_context",
                "function_call",
                "function_mechanism",
                "cfg_block",
                "data_reference",
                "mechanism_chain",
                "file_identity",
                "indicator",
                "script_import",
                "script_call",
                "script_line",
                "document_metadata",
                "embedded_object",
                "background_context",
            )
        return RetrievalRequest(
            thread_id=f"model:{module}:{phase}",
            hypothesis_id=f"model:{module}:{phase}:{artifact_id}",
            artifact_id=artifact_id,
            hypothesis_type=profile,
            target_anchors=anchors,
            required_evidence_kinds=required,
            caller_depth=1 if profile != "static-mechanism-discovery" else 0,
            callee_depth=1 if profile != "static-mechanism-discovery" else 0,
            data_xref_depth=1 if profile in {"dynamic-api-resolution", "xor-config-recovery"} else 0,
            playbook_id=profile,
            candidate_limit=min(256, self._MODEL_EVIDENCE_LIMIT * 2),
        )

    def _retrieve_model_context(
        self,
        session: Session,
        *,
        task: AnalysisTask,
        artifacts: list[Artifact],
        module: str,
        phase: str,
        completed_actions: list[dict[str, object]],
    ) -> RetrievedModelContext:
        """Build a bounded, role-labelled model context from indexed candidates."""
        turn_id = f"{task.id}:{module}:{phase}"
        ledger = EvidenceDeliveryLedger(turn_id=turn_id, thread_id=f"model:{module}:{phase}")
        packets: list[ContextPacket] = []
        manifests: list[dict[str, object]] = []
        artifact_count = max(1, len(artifacts))
        # The global model budget is a hard cap, not a post-hoc display limit.
        # Allocate it before selection so ledger stages, manifests and packets
        # describe exactly the bytes that were delivered to the provider.
        per_artifact_limit = max(1, min(32, self._MODEL_EVIDENCE_LIMIT // artifact_count))
        reference_isolated = self._is_reference_isolated_blind(task)
        for artifact in artifacts[:32]:
            request = self._build_retrieval_request(
                artifact_id=artifact.id,
                module=module,
                phase=phase,
                completed_actions=completed_actions,
            )
            batch = self.evidence_repository.retrieve(session, task_id=task.id, request=request)
            blocked_rows = [
                row
                for row in batch.rows
                if reference_isolated and row.nature == "BACKGROUND_REPORTED"
            ]
            for row in blocked_rows:
                for stage in (
                    EvidenceStage.PRODUCED,
                    EvidenceStage.NORMALIZED,
                    EvidenceStage.PERSISTED,
                    EvidenceStage.ELIGIBLE,
                    EvidenceStage.CANDIDATE,
                ):
                    ledger.advance(
                        row.id,
                        stage,
                        details=(
                            {
                                "retrieval_request": request.as_dict(),
                                "candidate_query_count": batch.query_count,
                                "candidate_selector_keys": list(batch.selector_keys),
                                "graph_expansions": list(batch.graph_expansions),
                                "exclusion_reason": "reference_isolation_policy",
                            }
                            if stage == EvidenceStage.CANDIDATE
                            else {}
                        ),
                    )
            visible_rows = [row for row in batch.rows if row not in blocked_rows]
            blind_baseline = (
                reference_isolated
                and phase.casefold().startswith("blind_v2")
                # Blind mode skips the ordinary initial planner. The first
                # planner turn follows exactly one deterministic PE baseline
                # action and must still be restricted to the minimal allowlist.
                and len(completed_actions) <= 1
            )
            if blind_baseline:
                baseline_kinds = {
                    "file_identity",
                    "pe_structure",
                    "import_symbol",
                    "tls_metadata",
                }
                baseline_rows = [row for row in visible_rows if row.kind in baseline_kinds]
                excluded_baseline_rows = [row for row in visible_rows if row not in baseline_rows]
                for row in excluded_baseline_rows:
                    for stage in (
                        EvidenceStage.PRODUCED,
                        EvidenceStage.NORMALIZED,
                        EvidenceStage.PERSISTED,
                        EvidenceStage.ELIGIBLE,
                        EvidenceStage.CANDIDATE,
                    ):
                        ledger.advance(
                            row.id,
                            stage,
                            details=(
                                {"exclusion_reason": "blind_baseline_minimal_context"}
                                if stage == EvidenceStage.CANDIDATE
                                else {}
                            ),
                        )
                visible_rows = baseline_rows
            serialized = [self._model_evidence_manifest(item) for item in visible_rows]
            packet = QuestionCentricRetriever(max_items=per_artifact_limit).build(request, serialized)
            packets.append(packet)
            selected_by_id = {item.evidence_id: item for item in packet.items}
            for row in visible_rows:
                for stage in (
                    EvidenceStage.PRODUCED,
                    EvidenceStage.NORMALIZED,
                    EvidenceStage.PERSISTED,
                    EvidenceStage.ELIGIBLE,
                    EvidenceStage.CANDIDATE,
                ):
                    ledger.advance(
                        row.id,
                        stage,
                        details=(
                            {
                                "retrieval_request": request.as_dict(),
                                "candidate_query_count": batch.query_count,
                                "candidate_selector_keys": list(batch.selector_keys),
                                "graph_expansions": list(batch.graph_expansions),
                                "exclusion_reason": packet.exclusion_reasons.get(row.id),
                            }
                            if stage == EvidenceStage.CANDIDATE
                            else {}
                        ),
                    )
                item = selected_by_id.get(row.id)
                if item is None:
                    continue
                details = {
                    "context_role": item.role.value,
                    "selection_score": item.score,
                    "selection_rationale": list(item.rationale),
                    "quota_group": item.quota_group,
                }
                ledger.advance(row.id, EvidenceStage.SELECTED, details=details)
                ledger.advance(row.id, EvidenceStage.DELIVERED, details=details)
                manifests.append(
                    {
                        **self._model_evidence_manifest(row),
                        "context_role": item.role.value,
                        "selection_score": item.score,
                        "selection_rationale": list(item.rationale),
                        "retrieval_request_version": request.version,
                        "retrieval_hypothesis_id": request.hypothesis_id,
                        "playbook_id": request.playbook_id,
                        "quota_group": item.quota_group,
                    }
                )
        manifests.sort(
            key=lambda item: (
                0 if item.get("context_role") == "CORE_SUPPORT" else 1,
                -int(item.get("selection_score", 0)),
                str(item["evidence_id"]),
            )
        )
        # ``per_artifact_limit`` is allocated from the global cap, therefore no
        # selected/delivered item is silently dropped after its ledger event.
        return RetrievedModelContext(tuple(manifests), ledger, tuple(packets))

    @staticmethod
    def _model_candidate_shape_is_valid(draft: AtomicClaimDraft, evidence_count: int) -> bool:
        """Accept a well-formed model candidate without bypassing verification.

        Specialized Claim Gates remain the only path to VERIFIED mechanisms.
        Candidates may be shown to analysts when they cite multiple observations
        and use the ordered mechanism-chain vocabulary; weak API-list drafts are
        still rejected.
        """
        mechanism = str(draft.mechanism or "")
        vocabulary = (
            "input", "transformation", "condition", "output", "consumer", "side effect"
        )
        return evidence_count >= 2 and mechanism.count("->") >= 2 and any(
            token in mechanism.casefold() for token in vocabulary
        )

    def _run_model_enrichment(self, task_id: str) -> list[str]:
        with self.database.session_factory() as session:
            task = session.get(AnalysisTask, task_id)
            if task is None:
                raise LookupError(task_id)
            artifacts = list(
                session.scalars(
                    select(Artifact)
                    .where(Artifact.task_id == task_id, Artifact.role != "CONTAINER")
                    .order_by(Artifact.created_at, Artifact.id)
                )
            )
            retrieved = self._retrieve_model_context(
                session,
                task=task,
                artifacts=artifacts,
                module="static_analysis",
                phase="enrichment",
                completed_actions=list(
                    (task.strategy_snapshot or {}).get("dynamic_planning", {}).get("completed_actions", [])
                ),
            )
            context_manifest = list(retrieved.manifest)
            if not context_manifest:
                # Even an empty retrieval is a model-turn decision point.  Keep
                # the immutable manifest so operators can distinguish
                # "retriever found nothing" from a model failure.
                self._persist_analysis_turn(
                    session,
                    task=task,
                    retrieved=retrieved,
                    phase="enrichment",
                    hypothesis_before=[],
                    hypothesis_after=[],
                    action_proposals=[],
                    policy_decisions=[],
                    completed_actions=[],
                    model_call=None,
                    mechanism_state="UNKNOWN",
                    stop_reason="NO_CONTEXT",
                    verifier_result={"status": "NOT_RUN", "reason": "NO_CONTEXT"},
                )
                self._persist_evidence_delivery_ledger(
                    session,
                    task=task,
                    artifact_id=None,
                    ledger=retrieved.ledger,
                    model_call_id=None,
                )
                return ["Model enrichment had no static Evidence context."]
            prompt = self.prompts.require("static-analysis-agent", "1.0.0")
            request_payload = {
                "task_id": task.id,
                "case_id": task.case_id,
                "module": "static_analysis",
                "context_manifest": context_manifest,
                "retrieval_packets": [packet.as_dict() for packet in retrieved.packets],
                # Background context is visible as isolated context, but can
                # never be cited as support for a sample-derived Claim.
                "allowed_evidence_ids": [
                    str(item["evidence_id"])
                    for item in context_manifest
                    if item.get("nature") != "BACKGROUND_REPORTED"
                ],
                "output_contract": "atomic-claim-envelope-v2",
                "analysis_task": "mechanism_synthesis",
                "mechanism_requirements": [
                    "target", "inputs", "transformation_or_control", "conditions",
                    "outputs", "consumers", "side_effects", "evidence_ids",
                ],
                "must_emit_evidence_backed_claim": any(
                    str(item.get("kind", "")).startswith("mechanism")
                    or item.get("kind") in {"abstract_execution_trace", "function_call", "function_context"}
                    for item in context_manifest
                ),
            }
            messages = tuple(self.prompts.build_messages(prompt, request_payload))
            request_content = json.dumps(
                {"messages": messages, "context_manifest": context_manifest},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            request_stored = self._store_model_payload(request_content)
            request = ModelRequest(
                task_id=task.id,
                case_id=task.case_id,
                trace_id=task.trace_id,
                module="static_analysis",
                prompt_id=prompt.id,
                prompt_version=prompt.version,
                prompt_sha256=prompt.sha256,
                messages=messages,
                response_schema=AtomicClaimEnvelope,
                timeout_s=self.settings.model_timeout_s,
                # Keep enough completion budget for a bounded evidence-backed
                # envelope. Qwen reasoning can consume the old 1536-token cap
                # before emitting the closing JSON brace.
                max_tokens=min(4096, self.settings.model_max_tokens),
            )

        # The runtime owns cancellation, context budgets, and immutable run events;
        # the gateway remains replaceable for provider adapters and offline tests.
        # Construct one runtime per task invocation so cancellation callbacks
        # cannot leak between concurrently analyzed tasks.
        runtime = AgentRuntime(
            self.model_gateway,
            max_context_bytes=self.settings.model_context_max_bytes,
            cancellation_requested=lambda: self._is_task_cancelled(task_id),
        )
        runtime_result = runtime.run(request)
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if task is None:
                raise LookupError(task_id)
            for event in runtime_result.events:
                self._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type=event.name,
                    actor="agent-runtime",
                    object_type="AgentRun",
                    object_id=runtime_result.run_id,
                    payload={
                        "run_id": runtime_result.run_id,
                        "event_at": event.at.isoformat(),
                        **event.payload,
                    },
                )

        if runtime_result.status != "SUCCEEDED" or runtime_result.response is None:
            with self.database.session_factory.begin() as session:
                task = session.get(AnalysisTask, task_id, with_for_update=True)
                if task is None:
                    raise LookupError(task_id)
                model_calls = self._persist_model_attempts(
                    session,
                    task,
                    prompt,
                    runtime_result.attempts,
                    request_stored,
                    context_manifest,
                    request=request,
                    agent_run_id=runtime_result.run_id,
                    turn_id=retrieved.ledger.turn_id,
                    phase="enrichment",
                    timeout_s=request.timeout_s,
                    max_tokens=request.max_tokens,
                )
                self._persist_evidence_delivery_ledger(
                    session,
                    task=task,
                    artifact_id=None,
                    ledger=retrieved.ledger,
                    model_call_id=model_calls[-1].id if model_calls else None,
                )
                self._persist_analysis_turn(
                    session,
                    task=task,
                    retrieved=retrieved,
                    phase="enrichment",
                    hypothesis_before=[],
                    hypothesis_after=[],
                    action_proposals=[],
                    policy_decisions=[],
                    completed_actions=[],
                    model_call=model_calls[-1] if model_calls else None,
                    mechanism_state="UNKNOWN",
                    stop_reason=runtime_result.error or runtime_result.status,
                    verifier_result={
                        "status": "NOT_RUN",
                        "reason": runtime_result.error or runtime_result.status,
                    },
                )
            if runtime_result.status == "CANCELLED":
                return ["Agent run was cancelled; deterministic Claims were retained."]
            if runtime_result.error == "AGENT_CONTEXT_BUDGET_EXCEEDED":
                return ["Agent context exceeded the configured budget; deterministic Claims were retained."]
            failures = ", ".join(
                f"{attempt.provider}/{attempt.model}:{attempt.error_type or attempt.status}"
                for attempt in runtime_result.attempts
            )
            return [
                "Model analysis providers failed; deterministic Claims were retained."
                + (f" Attempts: {failures}." if failures else "")
            ]

        response = runtime_result.response

        response_stored = self._store_model_payload(response.raw_response)
        allowed_ids = {
            item["evidence_id"]
            for item in context_manifest
            if item.get("nature") != "BACKGROUND_REPORTED"
        }
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if task is None:
                raise LookupError(task_id)
            model_calls = self._persist_model_attempts(
                session,
                task,
                prompt,
                response.attempts,
                request_stored,
                    context_manifest,
                request=request,
                response_stored=response_stored,
                successful_call_id=response.model_call_id,
                agent_run_id=runtime_result.run_id,
                turn_id=retrieved.ledger.turn_id,
                phase="enrichment",
                timeout_s=request.timeout_s,
                max_tokens=request.max_tokens,
            )
            successful_call = next(
                item for item in reversed(model_calls) if item.status == "SUCCEEDED"
            )
            invalid_count = 0
            candidate_only_count = 0
            accepted_claim_ids: list[str] = []
            accepted_evidence_ids: list[str] = []
            for draft in response.parsed.claims[:100]:
                module = {
                    "static_analysis": "static_triage",
                    # Models commonly use the domain label ``execution``
                    # even though the frozen report contract groups it under
                    # static triage. Normalize aliases at the trust boundary
                    # instead of rejecting an otherwise valid evidence-backed
                    # candidate.
                    "execution": "static_triage",
                    "network": "c2_network",
                    "c2": "c2_network",
                    "crypto": "decryption",
                }.get(draft.module, draft.module)
                validation = validate_claim_evidence(
                    draft.evidence_ids,
                    allowed_ids,
                    module=module,
                    allowed_modules=set(REPORT_MODULES),
                    evidence_natures={
                        item["evidence_id"]: str(item.get("nature", ""))
                        for item in context_manifest
                    },
                )
                verifier_decision = Verifier().evaluate(
                    [
                        {
                            "id": evidence_id,
                            "kind": str(item.get("kind", "")),
                            "nature": str(item.get("nature", "")),
                            "value": item.get("value", {}),
                            "anchor": item.get("anchor", {}),
                        }
                        for evidence_id in validation.evidence_ids
                        for item in context_manifest
                        if str(item.get("evidence_id")) == evidence_id
                    ],
                    draft.mechanism,
                    draft.statement,
                )
                for evidence_id in dict.fromkeys(draft.evidence_ids):
                    if retrieved.ledger.stage_for(evidence_id) == EvidenceStage.DELIVERED:
                        retrieved.ledger.advance(evidence_id, EvidenceStage.REFERENCED_BY_MODEL)
                candidate_only = (
                    validation.accepted
                    and not verifier_decision.accepted
                    and self._model_candidate_shape_is_valid(
                        draft, len(validation.evidence_ids)
                    )
                )
                self._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type="claim.validation",
                    actor="validation-hook",
                    object_type="ClaimDraft",
                    object_id=successful_call.id,
                    payload={
                        "decision": validation.decision,
                        "accepted": validation.accepted,
                        "reason": validation.reason,
                        "source_independence": validation.source_independence,
                        "claim_gate_status": verifier_decision.status,
                        "claim_gate_reason": verifier_decision.reason,
                        "claim_gate_missing": list(verifier_decision.missing),
                        "accepted_as_candidate_only": candidate_only,
                    },
                )
                if not validation.accepted or (
                    not verifier_decision.accepted and not candidate_only
                ):
                    invalid_count += 1
                    continue
                if candidate_only:
                    candidate_only_count += 1
                claim = Claim(
                    task_id=task.id,
                    module=module,
                    claim_type="BEHAVIOR",
                    subject=draft.subject,
                    action=draft.action,
                    object=draft.object,
                    mechanism=draft.mechanism,
                    condition=draft.condition,
                    statement=draft.statement,
                    nature="STATIC_INFERRED",
                    status=draft.status,
                    confidence=draft.confidence,
                    attack_mapping={},
                    model_call_id=successful_call.id,
                )
                session.add(claim)
                session.flush()
                accepted_claim_ids.append(claim.id)
                for evidence_id in dict.fromkeys(draft.evidence_ids):
                    accepted_evidence_ids.append(evidence_id)
                    session.add(
                        ClaimEvidence(claim_id=claim.id, evidence_id=evidence_id, stance="SUPPORTS")
                    )
                    if retrieved.ledger.stage_for(evidence_id) == EvidenceStage.REFERENCED_BY_MODEL:
                        retrieved.ledger.advance(
                            evidence_id,
                            EvidenceStage.ACCEPTED_AS_SUPPORT,
                            details={"claim_id": claim.id, "verifier": "claim-gate-v1"},
                        )
                self._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type="claim.created",
                    actor="model-gateway",
                    object_type="Claim",
                    object_id=claim.id,
                    payload={
                        "module": claim.module,
                        "model_call_id": successful_call.id,
                        "prompt_sha256": prompt.sha256,
                    },
                )
            self._persist_evidence_delivery_ledger(
                session,
                task=task,
                artifact_id=None,
                ledger=retrieved.ledger,
                model_call_id=successful_call.id,
            )
            self._persist_analysis_turn(
                session,
                task=task,
                retrieved=retrieved,
                phase="enrichment",
                hypothesis_before=[
                    {
                        "id": "model-enrichment",
                        "statement": "A static mechanism may be supported by cited evidence.",
                        "status": "OPEN",
                    }
                ],
                hypothesis_after=[
                    {
                        "id": "model-enrichment",
                        "statement": "A static mechanism may be supported by cited evidence.",
                        "status": "SUPPORTED" if accepted_claim_ids else "UNKNOWN",
                    }
                ],
                action_proposals=[],
                policy_decisions=[],
                completed_actions=[],
                model_call=successful_call,
                mechanism_state="CLAIM_READY" if accepted_claim_ids else "UNKNOWN",
                stop_reason="MODEL_ENRICHMENT_COMPLETED",
                verifier_result={
                    "status": "COMPLETED",
                    "accepted_claim_ids": accepted_claim_ids,
                    "accepted_evidence_ids": sorted(set(accepted_evidence_ids)),
                    "invalid_draft_count": invalid_count,
                    "candidate_only_count": candidate_only_count,
                },
            )
        limitations = list(response.parsed.limitations)
        if invalid_count:
            limitations.append(
                f"Model gateway rejected {invalid_count} Claim drafts with invalid Evidence support or an unmet Claim Gate."
            )
        return limitations

    @classmethod
    def _select_model_evidence(
        cls,
        rows: list[Evidence],
        *,
        limit: int,
    ) -> list[Evidence]:
        """Select bounded, artifact-fair context for model enrichment.

        Large containers can produce thousands of low-value string rows before
        their child PE/function evidence is recorded. A per-artifact quota keeps
        the model context representative, then fills remaining slots by evidence
        priority without changing the immutable Evidence ledger.
        """
        if limit < 1:
            return []
        if len(rows) <= limit:
            return rows

        def rank(item: Evidence) -> tuple[int, datetime, str]:
            return (
                -cls._MODEL_EVIDENCE_PRIORITY.get(item.kind, 20),
                item.created_at,
                item.id,
            )

        groups: dict[str, list[Evidence]] = {}
        for item in rows:
            groups.setdefault(item.artifact_id or "", []).append(item)
        quota = max(1, limit // max(1, len(groups)))
        selected: list[Evidence] = []
        selected_ids: set[str] = set()
        for artifact_id in sorted(groups):
            for item in sorted(groups[artifact_id], key=rank)[:quota]:
                selected.append(item)
                selected_ids.add(item.id)

        # Fill in round-robin order so a large outer container cannot consume all
        # remaining slots before smaller decoded/child artifacts are represented.
        ranked_groups = {
            artifact_id: [item for item in sorted(groups[artifact_id], key=rank) if item.id not in selected_ids]
            for artifact_id in sorted(groups)
        }
        while len(selected) < limit and any(ranked_groups.values()):
            for artifact_id in sorted(ranked_groups):
                candidates = ranked_groups[artifact_id]
                if not candidates:
                    continue
                item = candidates.pop(0)
                selected.append(item)
                selected_ids.add(item.id)
                if len(selected) >= limit:
                    break
        return sorted(selected, key=lambda item: (item.created_at, item.id))

    @classmethod
    def _compact_model_value(cls, value: object, *, limit: int | None = None) -> object:
        """Bound untrusted Evidence values before placing them in a model prompt."""
        limit = limit or cls._MODEL_EVIDENCE_VALUE_LIMIT
        if isinstance(value, str):
            return value if len(value) <= limit else value[: limit - 3] + "..."
        if isinstance(value, dict):
            compact: dict[str, object] = {}
            for key, item in list(value.items())[:64]:
                compact[str(key)] = cls._compact_model_value(item, limit=max(256, limit // 2))
            return compact
        if isinstance(value, (list, tuple)):
            items = [cls._compact_model_value(item, limit=max(256, limit // 2)) for item in value[:64]]
            if len(value) > 64:
                items.append(f"... ({len(value) - 64} more items)")
            return items
        return value

    @classmethod
    def _model_evidence_manifest(cls, item: Evidence) -> dict[str, object]:
        return {
            "evidence_id": item.id,
            "artifact_id": item.artifact_id,
            "kind": item.kind,
            "nature": item.nature,
            "value": cls._compact_model_value(item.value),
            "anchor": cls._compact_model_value(item.anchor, limit=1200),
            "trust_zone": "untrusted_analysis_data",
        }

    def _persist_model_attempts(
        self,
        session: Session,
        task: AnalysisTask,
        prompt: Any,
        attempts: tuple[Any, ...],
        request_stored: Any,
        context_manifest: list[dict[str, object]],
        *,
        request: ModelRequest[Any] | None = None,
        response_stored: Any | None = None,
        successful_call_id: str | None = None,
        agent_run_id: str | None = None,
        module: str = "static_analysis",
        artifact_id: str | None = None,
        turn_id: str | None = None,
        phase: str | None = None,
        timeout_s: float = 60.0,
        max_tokens: int = 4096,
    ) -> list[ModelCall]:
        calls: list[ModelCall] = []
        fallback_reason = None
        if len(attempts) > 1:
            first_attempt = attempts[0]
            fallback_reason = (
                "primary_not_configured"
                if first_attempt.error_type == "ProviderNotConfigured"
                else "primary_failed"
            )
        for index, attempt in enumerate(attempts, 1):
            successful = attempt.status == "SUCCEEDED"
            route = next(
                (
                    provider
                    for provider in (self.settings.primary_model, self.settings.fallback_model)
                    if provider.provider == attempt.provider and provider.model == attempt.model
                ),
                self.settings.primary_model,
            )
            temperature = (
                request.temperature
                if request is not None and request.temperature is not None
                else route.temperature
            )
            top_p = (
                request.top_p
                if request is not None and request.top_p is not None
                else route.top_p
            )
            stream = (
                request.stream
                if request is not None and request.stream is not None
                else route.stream
            )
            structured_output = (
                request.structured_output
                if request is not None and request.structured_output is not None
                else route.supports_json_mode
            )
            disable_reasoning = (
                request.disable_reasoning
                if request is not None and request.disable_reasoning is not None
                else route.disable_reasoning
            )
            serialized_request_bytes = len(
                json.dumps(
                    {
                        "messages": request.messages if request is not None else (),
                        "context_manifest": context_manifest,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            call = ModelCall(
                id=(successful_call_id if successful and successful_call_id else new_id()),
                task_id=task.id,
                artifact_id=artifact_id,
                turn_id=turn_id,
                phase=phase,
                module=module,
                provider=attempt.provider,
                model=attempt.model,
                prompt_id=prompt.id,
                prompt_version=prompt.version,
                prompt_sha256=prompt.sha256,
                attempt=index,
                status=attempt.status,
                request_sha256=request_stored.sha256,
                request_storage_key=request_stored.storage_key,
                response_sha256=response_stored.sha256 if successful and response_stored else None,
                response_storage_key=(
                    response_stored.storage_key if successful and response_stored else None
                ),
                payload_schema_version="model-payload-v1",
                encryption_key_id=self._model_payload_key_id,
                security_classification="RESTRICTED_MODEL_PAYLOAD",
                access_policy="auditor_or_system_only",
                parameters={
                    "temperature": temperature,
                    "top_p": top_p,
                    "stream": stream,
                    "structured_output": structured_output,
                    "disable_reasoning": disable_reasoning,
                    "max_tokens": max_tokens,
                    "timeout_s": timeout_s,
                    "payload_encrypted": True,
                    "retention_days": self.settings.model_payload_retention_days,
                    "agent_run_id": agent_run_id,
                    "context_evidence_count": len(context_manifest),
                    "context_bytes": serialized_request_bytes,
                    "http_status": attempt.http_status,
                    "endpoint_path": attempt.endpoint_path,
                    "error_detail": attempt.error_detail,
                    "fallback_used": bool(fallback_reason and index > 1),
                    "fallback_reason": fallback_reason if index > 1 else None,
                    # Gateway payload hashes are per-attempt (and therefore
                    # remain verifiable when retry options differ).  The
                    # encrypted request_stored hash above is retained as the
                    # service-level envelope hash for compatibility.
                    "gateway_request_sha256": attempt.request_sha256,
                },
                context_manifest=[
                    {
                        "evidence_id": item["evidence_id"],
                        "artifact_id": item["artifact_id"],
                        "kind": item["kind"],
                        "trust_zone": item["trust_zone"],
                    }
                    for item in context_manifest
                ],
                input_tokens=attempt.input_tokens,
                output_tokens=attempt.output_tokens,
                latency_ms=attempt.latency_ms,
                error_type=attempt.error_type,
                payload_expires_at=utcnow()
                + timedelta(days=self.settings.model_payload_retention_days),
            )
            session.add(call)
            session.flush()
            calls.append(call)
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="model_call.completed",
                actor="model-gateway",
                object_type="ModelCall",
                object_id=call.id,
                payload={
                    "provider": call.provider,
                    "model": call.model,
                    "status": call.status,
                    "attempt": call.attempt,
                    "request_sha256": call.request_sha256,
                    "response_sha256": call.response_sha256,
                    "error_type": call.error_type,
                    "http_status": attempt.http_status,
                    "error_detail": attempt.error_detail,
                    "fallback_reason": fallback_reason if index > 1 else None,
                    "agent_run_id": agent_run_id,
                },
            )
        return calls

    def _is_task_cancelled(self, task_id: str) -> bool:
        with self.database.session_factory() as session:
            task = session.get(AnalysisTask, task_id)
            return task is None or task.lifecycle == TaskLifecycle.CANCELLED.value

    def set_retention_freeze(
        self,
        case_id: str,
        *,
        frozen: bool,
        actor: str,
        reason: str,
    ) -> dict[str, object]:
        if not reason.strip():
            raise ValueError("retention freeze changes require a reason")
        with self.database.session_factory.begin() as session:
            case = session.get(CaseRecord, case_id)
            if case is None:
                raise LookupError(case_id)
            case.retention_frozen_at = utcnow() if frozen else None
            case.retention_frozen_by = actor if frozen else None
            case.retention_freeze_reason = reason if frozen else None
            self._audit(
                session,
                case_id=case.id,
                event_type="retention.freeze_changed",
                actor=actor,
                object_type="Case",
                object_id=case.id,
                payload={"frozen": frozen, "reason": reason},
            )
            return {
                "case_id": case.id,
                "frozen": frozen,
                "frozen_at": (
                    case.retention_frozen_at.isoformat() if case.retention_frozen_at else None
                ),
                "frozen_by": case.retention_frozen_by,
                "reason": case.retention_freeze_reason,
            }

    def expire_model_payloads(
        self, *, now: datetime | None = None, actor: str = "retention-worker"
    ) -> int:
        """Delete expired encrypted model bodies while retaining audit metadata."""
        cutoff = self._as_utc(now or utcnow())
        disposed = 0
        with self.database.session_factory.begin() as session:
            calls = list(
                session.scalars(
                    select(ModelCall).where(
                        ModelCall.payload_expires_at.is_not(None),
                        ModelCall.payload_expires_at <= cutoff,
                        ModelCall.payload_disposed_at.is_(None),
                    )
                )
            )
            for call in calls:
                task = session.get(AnalysisTask, call.task_id)
                case = session.get(CaseRecord, task.case_id) if task is not None else None
                if case is not None and case.retention_frozen_at is not None:
                    continue
                keys = {
                    key
                    for key in (call.request_storage_key, call.response_storage_key)
                    if key
                }
                for storage_key in keys:
                    shared = session.scalar(
                        select(ModelCall.id).where(
                            ModelCall.id != call.id,
                            ModelCall.payload_disposed_at.is_(None),
                            (
                                (ModelCall.request_storage_key == storage_key)
                                | (ModelCall.response_storage_key == storage_key)
                            ),
                        )
                    )
                    if shared is None:
                        self.content_store.delete(storage_key)
                call.request_storage_key = None
                call.response_storage_key = None
                call.payload_disposed_at = cutoff
                call.parameters = {**call.parameters, "payload_disposed_at": cutoff.isoformat()}
                disposed += 1
                if task is not None:
                    self._audit(
                        session,
                        case_id=task.case_id,
                        task_id=task.id,
                        event_type="model_payload.expired",
                        actor=actor,
                        object_type="ModelCall",
                        object_id=call.id,
                        payload={"expired_at": cutoff.isoformat()},
                    )
        return disposed

    def _freeze_snapshot(self, session: Session, task: AnalysisTask) -> AnalysisSnapshot:
        case = session.get(CaseRecord, task.case_id)
        if case is None:
            raise LookupError(task.case_id)
        inputs = self._report_inputs(session, task.id)
        payload: dict[str, object] = {
            "schema_version": self.SNAPSHOT_SCHEMA_VERSION,
            "case": self._snapshot_record(case),
            "task": self._snapshot_record(task),
            **{
                name: [self._snapshot_record(item) for item in items]
                for name, items in inputs.items()
            },
        }
        payload["content_sha256"] = hashlib.sha256(
            self._canonical_json(payload).encode("utf-8")
        ).hexdigest()

        snapshot = AnalysisSnapshot(
            task_id=task.id,
            object_versions=payload,
        )
        session.add(snapshot)
        session.flush()
        return snapshot

    def _persist_mechanism_effectiveness_traces(
        self,
        session: Session,
        task: AnalysisTask,
    ) -> int:
        """Append redacted effectiveness traces before an immutable snapshot.

        Trace rows are derived only from durable planner manifests, action
        results and the investigation snapshot.  A content digest makes the
        operation idempotent while still allowing a later post-action refresh
        to append a new, materially different trace.
        """
        inputs = self._report_inputs(session, task.id)
        events = list(
            session.scalars(
                select(AuditEvent)
                .where(AuditEvent.task_id == task.id)
                .order_by(AuditEvent.chain_sequence)
            )
        )
        event_rows = [self._snapshot_record(item) for item in events]
        turn_rows = [self._snapshot_record(item) for item in inputs["analysis_turns"]]
        result_rows = [self._snapshot_record(item) for item in inputs["analysis_turn_results"]]
        traces = build_mechanism_effectiveness_traces(
            strategy_snapshot=dict(task.strategy_snapshot or {}),
            analysis_turns=turn_rows,
            analysis_turn_results=result_rows,
            events=event_rows,
        )
        created = 0
        for trace in traces:
            payload = {
                key: value
                for key, value in trace.items()
                if key not in {"id", "trace_sha256"}
            }
            digest = hashlib.sha256(self._canonical_json(payload).encode("utf-8")).hexdigest()
            if session.scalar(
                select(MechanismEffectivenessTraceRecord).where(
                    MechanismEffectivenessTraceRecord.task_id == task.id,
                    MechanismEffectivenessTraceRecord.trace_sha256 == digest,
                )
            ) is not None:
                continue
            artifact_id = trace.get("artifact_id")
            if artifact_id:
                artifact_id = str(artifact_id)
                if session.get(Artifact, artifact_id) is None:
                    artifact_id = None
            session.add(
                MechanismEffectivenessTraceRecord(
                    task_id=task.id,
                    mechanism_id=str(trace.get("mechanism_id") or ""),
                    mechanism_type=str(trace.get("mechanism_type") or ""),
                    artifact_id=artifact_id,
                    trace_version=str(trace.get("trace_version") or "mechanism-effectiveness-v1"),
                    seed=dict(trace.get("seed") or {}),
                    question=(str(trace["question"]) if trace.get("question") is not None else None),
                    competing_hypotheses=list(trace.get("competing_hypotheses") or []),
                    action_proposals=list(trace.get("action_proposals") or []),
                    tool_run_ids=list(trace.get("tool_runs") or []),
                    new_evidence_ids=list(trace.get("new_evidence_ids") or []),
                    evidence_delta=dict(trace.get("evidence_delta") or {}),
                    hypothesis_delta=dict(trace.get("hypothesis_delta") or {}),
                    mechanism_delta=dict(trace.get("mechanism_delta") or {}),
                    verifier_result=dict(trace.get("verifier_result") or {}),
                    claim_gate=dict(trace.get("claim_gate") or {}),
                    report_projection=dict(trace.get("report_projection") or {}),
                    model_action_productivity=dict(trace.get("model_action_productivity") or {}),
                    trace_sha256=digest,
                )
            )
            created += 1
        if created:
            session.flush()
        return created

    def _materialize_mechanism_snapshot(self, session: Session, task: AnalysisTask) -> None:
        """Persist a structured mechanism view for every evidence-backed Claim.

        Claims are the durable domain truth; the mechanism list is a compact
        report/trace projection. Materializing it at finalization makes the
        Input/Transformation/Condition/Output/Consumer/Side Effect contract
        available to API consumers without treating candidates as verified.
        """
        claims = list(session.scalars(select(Claim).where(Claim.task_id == task.id)))
        links: dict[str, list[str]] = {}
        for link in session.scalars(
            select(ClaimEvidence).where(ClaimEvidence.claim_id.in_([item.id for item in claims]))
        ):
            if link.stance == "SUPPORTS":
                links.setdefault(link.claim_id, []).append(link.evidence_id)
        evidence_by_id = {
            item.id: item
            for item in session.scalars(select(Evidence).where(Evidence.task_id == task.id))
        }
        projections = build_mechanism_projections(claims, links, evidence_by_id)
        # Specialist correlators persist their result as STATIC_DERIVED
        # Evidence.  Project those links independently of Claim creation so a
        # static mechanism remains visible in the immutable snapshot even when
        # the verifier has not yet upgraded a Claim.  This also makes the
        # Workbench/report projections useful on model-fallback runs.
        projections.extend(build_static_link_mechanism_projections(evidence_by_id))
        strategy = dict(task.strategy_snapshot or {})
        investigation = dict(strategy.get("investigation", {}))
        existing = [item for item in investigation.get("mechanisms", []) if isinstance(item, dict)]
        by_claim = {str(item.get("claim_id")): item for item in existing if item.get("claim_id")}
        for projection in projections:
            current = (
                by_claim.get(str(projection.get("claim_id")))
                if projection.get("claim_id")
                else None
            )
            if current is None and projection.get("type") == "mechanism_link":
                projected_type = str(projection.get("mechanism_type", "")).upper()

                def normalized_type(row: Mapping[str, object]) -> str:
                    raw = str(
                        row.get("mechanism_type")
                        or row.get("type")
                        or row.get("dimension")
                        or ""
                    ).upper()
                    return raw.removeprefix("TRACE_").replace("NETWORK_CONSUMER", "HTTP_DOWNLOAD")

                current = next(
                    (
                        item
                        for item in existing
                        if normalized_type(item) == projected_type
                        and (
                            not projection.get("artifact_id")
                            or not item.get("artifact_id")
                            or str(item.get("artifact_id")) == str(projection.get("artifact_id"))
                        )
                    ),
                    None,
                )
                if current is not None:
                    current.setdefault("mechanism_type", projected_type)
                    current.setdefault("artifact_id", projection.get("artifact_id"))
                    current.setdefault("provenance", projection.get("provenance", {}))
                    self._merge_mechanism_projection(current, projection)
                    # Preserve the specialist provenance fields on an existing
                    # thread mechanism while keeping its stable thread ID.
                    current["provenance"] = projection.get("provenance", current.get("provenance", {}))
                    continue
            if current is None:
                existing.append(projection)
                continue
            self._merge_mechanism_projection(current, projection)
        # A parser commonly emits several Claims for the same normalized
        # mechanism path (one per duplicated import/xref row).  Preserve the
        # raw Claims and Evidence in the ledger, but collapse equivalent
        # report projections so quality gates measure distinct mechanisms
        # instead of extractor cardinality.
        deduped: list[dict[str, object]] = []
        by_semantic_key: dict[str, dict[str, object]] = {}
        for row in existing:
            if not isinstance(row, dict):
                continue
            key_payload = {
                "target": row.get("target"),
                "inputs": row.get("inputs"),
                "transformation_or_control": row.get("transformation_or_control"),
                "conditions": row.get("conditions"),
                "outputs": row.get("outputs"),
                "consumers": row.get("consumers"),
                "side_effects": row.get("side_effects"),
            }
            semantic_key = hashlib.sha256(
                self._canonical_json(key_payload).encode("utf-8")
            ).hexdigest()
            current = by_semantic_key.get(semantic_key)
            if current is None:
                clone = dict(row)
                clone["claim_ids"] = [str(row["claim_id"])] if row.get("claim_id") else []
                by_semantic_key[semantic_key] = clone
                deduped.append(clone)
                continue
            claim_id = row.get("claim_id")
            if claim_id and str(claim_id) not in current.setdefault("claim_ids", []):
                current["claim_ids"].append(str(claim_id))
            evidence_ids = list(dict.fromkeys(
                [str(item) for item in current.get("evidence_ids", []) if item]
                + [str(item) for item in row.get("evidence_ids", []) if item]
            ))
            current["evidence_ids"] = evidence_ids[:12]
            if str(row.get("status", "")).upper() in {"VERIFIED", "SUPPORTED", "CONFIRMED"}:
                current["status"] = row.get("status")
                if row.get("verifier"):
                    current["verifier"] = row.get("verifier")
            current["completeness"] = max(
                int(current.get("completeness", 0) or 0),
                int(row.get("completeness", 0) or 0),
            )
        investigation["mechanisms"] = deduped[:128]
        task.strategy_snapshot = {**strategy, "investigation": investigation}
        # Persist the auditable control-plane trace after mechanism state has
        # been materialized and before ``_freeze_snapshot`` captures the task.
        self._persist_mechanism_effectiveness_traces(session, task)

    @staticmethod
    def _merge_mechanism_projection(
        current: dict[str, object], projection: Mapping[str, object]
    ) -> dict[str, object]:
        """Merge generic Claim projections without erasing specialist closure.

        Investigation verifiers may have populated richer semantic fields and
        marked a mechanism VERIFIED before report materialization.  The generic
        projection is useful for missing fields, but must never downgrade that
        status or replace a meaningful value with UNKNOWN/navigation text.
        """
        from threat_report_agent.mechanism_completeness import has_semantic_value

        current_status = str(current.get("status", "")).upper()
        for key in (
            "target", "inputs", "transformation_or_control", "conditions",
            "outputs", "consumers", "side_effects", "evidence_ids",
            "alternative_hypotheses", "unknowns", "limitations",
        ):
            candidate = projection.get(key)
            if not candidate:
                continue
            if current_status == "VERIFIED" and has_semantic_value(key, current.get(key)):
                continue
            current[key] = candidate
        if current_status != "VERIFIED":
            if projection.get("status"):
                current["status"] = projection["status"]
            if projection.get("verifier") and not current.get("verifier"):
                current["verifier"] = projection["verifier"]
        current.setdefault("status", "CANDIDATE")
        current.setdefault("mechanism_id", projection.get("mechanism_id"))
        current["completeness"] = mechanism_completeness_score(current)
        return current

    @staticmethod
    def _snapshot_record(record: Any) -> dict[str, object]:
        values: dict[str, object] = {}
        for column in record.__table__.columns:
            value = getattr(record, column.name)
            values[column.name] = value.isoformat() if isinstance(value, datetime) else value
        return values

    def _snapshot_report_context(self, snapshot: AnalysisSnapshot) -> dict[str, object]:
        payload = dict(snapshot.object_versions)
        expected_digest = payload.pop("content_sha256", None)
        actual_digest = hashlib.sha256(self._canonical_json(payload).encode("utf-8")).hexdigest()
        if expected_digest != actual_digest:
            raise ValueError(f"Analysis Snapshot {snapshot.id} failed integrity validation")
        payload = self._migrate_snapshot_payload(snapshot.id, payload)
        payload.setdefault("model_calls", [])
        payload.setdefault("analysis_turns", [])
        payload.setdefault("analysis_turn_results", [])
        payload.setdefault("investigation_threads", [])
        payload.setdefault("investigation_hypotheses", [])
        payload.setdefault("investigation_actions", [])
        strategy = payload.get("task", {}).get("strategy_snapshot", {}) if isinstance(payload.get("task"), dict) else {}
        investigation = strategy.get("investigation", {}) if isinstance(strategy, dict) else {}
        payload.setdefault("mechanisms", investigation.get("mechanisms", []) if isinstance(investigation, dict) else [])
        return {
            "case": SimpleNamespace(**payload["case"]),
            "task": SimpleNamespace(**payload["task"]),
            **{
                name: [SimpleNamespace(**item) for item in payload[name]]
                for name in (
                    "artifacts",
                    "tool_runs",
                    "evidence",
                    "claims",
                    "claim_evidence",
                    "relations",
                    "gates",
                    "model_calls",
                    "investigation_threads",
                    "investigation_hypotheses",
                    "investigation_actions",
                    "analysis_turn_results",
                    "mechanisms",
                )
            },
        }

    @classmethod
    def _migrate_snapshot_payload(
        cls, snapshot_id: str, payload: dict[str, object]
    ) -> dict[str, object]:
        """Read-only migration registry for immutable Analysis Snapshot payloads."""
        version = payload.get("schema_version")
        if version == cls.SNAPSHOT_SCHEMA_VERSION:
            return payload
        if version == "1.0":
            migrated = dict(payload)
            migrated["schema_version"] = cls.SNAPSHOT_SCHEMA_VERSION
            for name in (
                "relations",
                "gates",
                "model_calls",
                "analysis_turns",
                "investigation_threads",
                "investigation_hypotheses",
                "investigation_actions",
                "mechanism_effectiveness_traces",
            ):
                migrated.setdefault(name, [])
            migrated["investigation_actions"] = [
                {
                    **dict(item),
                    "target_selector": dict(item.get("target_selector", {}))
                    if isinstance(item, Mapping) and isinstance(item.get("target_selector", {}), Mapping)
                    else {},
                    "expected_evidence_kinds": list(item.get("expected_evidence_kinds", []))
                    if isinstance(item, Mapping) and isinstance(item.get("expected_evidence_kinds", []), list)
                    else [],
                    "success_condition": str(item.get("success_condition", "new_targeted_evidence"))
                    if isinstance(item, Mapping)
                    else "new_targeted_evidence",
                    "failure_interpretation": str(item.get("failure_interpretation", "UNKNOWN"))
                    if isinstance(item, Mapping)
                    else "UNKNOWN",
                    "cost_units": int(item.get("cost_units", 1))
                    if isinstance(item, Mapping)
                    else 1,
                }
                for item in migrated.get("investigation_actions", [])
                if isinstance(item, Mapping)
            ]
            return migrated
        raise ValueError(f"Analysis Snapshot {snapshot_id} uses an unsupported schema")

    def _report_inputs(self, session: Session, task_id: str) -> dict[str, list[Any]]:
        return {
            "artifacts": list(
                session.scalars(
                    select(Artifact)
                    .where(Artifact.task_id == task_id)
                    .order_by(Artifact.created_at)
                )
            ),
            "tool_runs": list(
                session.scalars(
                    select(ToolRun).where(ToolRun.task_id == task_id).order_by(ToolRun.started_at)
                )
            ),
            "evidence": list(
                session.scalars(
                    select(Evidence)
                    .where(Evidence.task_id == task_id)
                    .order_by(Evidence.created_at)
                )
            ),
            "claims": list(
                session.scalars(
                    select(Claim).where(Claim.task_id == task_id).order_by(Claim.created_at)
                )
            ),
            "claim_evidence": list(
                session.scalars(
                    select(ClaimEvidence)
                    .join(Claim, Claim.id == ClaimEvidence.claim_id)
                    .where(Claim.task_id == task_id)
                )
            ),
            "relations": list(
                session.scalars(
                    select(Relation)
                    .where(Relation.task_id == task_id)
                    .order_by(Relation.created_at)
                )
            ),
            "gates": list(
                session.scalars(
                    select(GateRecord)
                    .where(GateRecord.task_id == task_id)
                    .order_by(GateRecord.created_at)
                )
            ),
            "model_calls": list(
                session.scalars(
                    select(ModelCall)
                    .where(ModelCall.task_id == task_id)
                    .order_by(ModelCall.created_at)
                )
            ),
            "analysis_turns": list(
                session.scalars(
                    select(AnalysisTurnRecord)
                    .where(AnalysisTurnRecord.task_id == task_id)
                    .order_by(AnalysisTurnRecord.created_at, AnalysisTurnRecord.id)
                )
            ),
            "analysis_turn_results": list(
                session.scalars(
                    select(AnalysisTurnResultRecord)
                    .where(AnalysisTurnResultRecord.task_id == task_id)
                    .order_by(AnalysisTurnResultRecord.created_at, AnalysisTurnResultRecord.id)
                )
            ),
            "mechanism_effectiveness_traces": list(
                session.scalars(
                    select(MechanismEffectivenessTraceRecord)
                    .where(MechanismEffectivenessTraceRecord.task_id == task_id)
                    .order_by(
                        MechanismEffectivenessTraceRecord.created_at,
                        MechanismEffectivenessTraceRecord.id,
                    )
                )
            ),
            "investigation_threads": list(
                session.scalars(
                    select(InvestigationThreadRecord)
                    .where(InvestigationThreadRecord.task_id == task_id)
                    .order_by(InvestigationThreadRecord.created_at)
                )
            ),
            "investigation_hypotheses": list(
                session.scalars(
                    select(InvestigationHypothesisRecord)
                    .where(InvestigationHypothesisRecord.task_id == task_id)
                    .order_by(InvestigationHypothesisRecord.created_at)
                )
            ),
            "investigation_actions": list(
                session.scalars(
                    select(InvestigationActionRecord)
                    .where(InvestigationActionRecord.task_id == task_id)
                    .order_by(InvestigationActionRecord.created_at)
                )
            ),
        }

    def _create_report_revision(
        self,
        session: Session,
        task: AnalysisTask,
        snapshot: AnalysisSnapshot,
        modules: list[str],
        *,
        parent_revision_id: str | None = None,
        author: str = "system",
    ) -> ReportRevision:
        document = build_report_document(
            selected_modules=modules,
            **self._snapshot_report_context(snapshot),
        )
        markdown = document_to_markdown(document)
        violations = report_bloat_violations(markdown)
        violations.extend(report_analytical_violations(document))
        violations.extend(report_v3_quality_violations(document))
        if violations:
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="report.anti_bloat_rejected",
                actor=author,
                object_type="AnalysisSnapshot",
                object_id=snapshot.id,
                payload={"violations": violations, "markdown_bytes": len(markdown.encode("utf-8"))},
            )
            raise ValueError("report anti-bloat gate rejected document: " + "; ".join(violations))
        revision = ReportRevision(
            task_id=task.id,
            snapshot_id=snapshot.id,
            parent_revision_id=parent_revision_id,
            selected_modules=modules,
            document=document,
            markdown=markdown,
            author=author,
        )
        session.add(revision)
        session.flush()
        self._audit(
            session,
            case_id=task.case_id,
            task_id=task.id,
            event_type="report.generated",
            actor=author,
            object_type="ReportRevision",
            object_id=revision.id,
            payload={
                "snapshot_id": snapshot.id,
                "selected_modules": modules,
                "edit_kind": revision.edit_kind,
            },
        )
        return revision

    @staticmethod
    def _canonical_json(value: object) -> str:
        return json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str
        )

    @staticmethod
    def _audit_timestamp(value: object) -> str:
        if not isinstance(value, datetime):
            raise TypeError("Audit timestamp must be a datetime")
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat()

    @classmethod
    def _audit_event_hash(
        cls,
        *,
        event_id: str,
        case_id: str | None,
        task_id: str | None,
        event_type: str,
        actor: str,
        object_type: str,
        object_id: str,
        trace_id: str,
        payload: dict[str, object],
        chain_version: str,
        chain_sequence: int,
        previous_hash: str,
        created_at: object,
    ) -> str:
        record = {
            "id": event_id,
            "case_id": case_id,
            "task_id": task_id,
            "event_type": event_type,
            "actor": actor,
            "object_type": object_type,
            "object_id": object_id,
            "trace_id": trace_id,
            "payload": payload,
            "chain_version": chain_version,
            "chain_sequence": chain_sequence,
            "previous_hash": previous_hash,
            "created_at": cls._audit_timestamp(created_at),
        }
        return hashlib.sha256(cls._canonical_json(record).encode("utf-8")).hexdigest()

    def _audit_secret(self) -> bytes:
        if not self.settings.audit_seal_secret:
            if self.settings.environment.lower() not in {"test", "development", "demo"}:
                raise RuntimeError("AUDIT_SEAL_SECRET is required outside test/demo environments")
            secret = "local-development-sealer-key"
        else:
            secret = self.settings.audit_seal_secret
        return secret.encode("utf-8")

    def _audit_signature(
        self,
        scope_key: str,
        sequence: int,
        terminal_event_hash: str,
        merkle_root: str,
    ) -> tuple[str, str]:
        secret = self._audit_secret()
        material = (
            f"audit-chain-v2|{scope_key}|{sequence}|{terminal_event_hash}|{merkle_root}"
        ).encode("utf-8")
        signature = hmac.new(secret, material, hashlib.sha256).hexdigest()
        key_id = hashlib.sha256(secret).hexdigest()[:16]
        return key_id, signature

    @staticmethod
    def _merkle_root(event_hashes: list[str]) -> str:
        if not event_hashes:
            return "0" * 64
        level = [bytes.fromhex(value) for value in event_hashes]
        while len(level) > 1:
            if len(level) % 2:
                level.append(level[-1])
            level = [
                hashlib.sha256(level[index] + level[index + 1]).digest()
                for index in range(0, len(level), 2)
            ]
        return level[0].hex()

    def _audit(
        self,
        session: Session,
        *,
        case_id: str | None,
        event_type: str,
        actor: str,
        object_type: str,
        object_id: str,
        payload: dict[str, object],
        task_id: str | None = None,
    ) -> AuditEvent:
        if task_id:
            task = session.get(AnalysisTask, task_id)
            if task is None:
                raise LookupError(task_id)
            scope_key = f"task:{task.id}"
            trace_id = task.trace_id
        elif case_id:
            case = session.get(CaseRecord, case_id)
            if case is None:
                raise LookupError(case_id)
            scope_key = f"case:{case.id}"
            trace_id = case.trace_id
        else:
            raise ValueError("An audit event must have a Case or Analysis Task scope")

        head = session.get(AuditChainHead, scope_key, with_for_update=True)
        if head is None:
            head = AuditChainHead(
                scope_key=scope_key,
                case_id=case_id,
                task_id=task_id,
                trace_id=trace_id,
                last_event_hash="0" * 64,
                sequence=0,
            )
            session.add(head)
        previous_hash = head.last_event_hash
        chain_sequence = head.sequence + 1
        created_at = utcnow()
        event_id = new_id()
        event_hash = self._audit_event_hash(
            event_id=event_id,
            case_id=case_id,
            task_id=task_id,
            event_type=event_type,
            actor=actor,
            object_type=object_type,
            object_id=object_id,
            trace_id=trace_id,
            payload=payload,
            chain_version="1",
            chain_sequence=chain_sequence,
            previous_hash=previous_hash,
            created_at=created_at,
        )
        event = AuditEvent(
            id=event_id,
            case_id=case_id,
            task_id=task_id,
            event_type=event_type,
            actor=actor,
            object_type=object_type,
            object_id=object_id,
            trace_id=trace_id,
            payload=payload,
            chain_version="1",
            chain_sequence=chain_sequence,
            previous_hash=previous_hash,
            event_hash=event_hash,
            created_at=created_at,
        )
        session.add(event)
        head.last_event_hash = event_hash
        head.sequence = chain_sequence
        head.updated_at = created_at
        return event

    def _seal_task_audit_chain(
        self,
        session: Session,
        task: AnalysisTask,
        terminal_event_type: str,
    ) -> None:
        scope_key = f"task:{task.id}"
        session.flush()
        head = session.get(AuditChainHead, scope_key, with_for_update=True)
        if head is None:
            raise RuntimeError(f"No audit chain exists for {scope_key}")
        event_hashes = list(
            session.scalars(
                select(AuditEvent.event_hash)
                .where(AuditEvent.task_id == task.id)
                .order_by(AuditEvent.chain_sequence)
            )
        )
        merkle_root = self._merkle_root(event_hashes)
        key_id, signature = self._audit_signature(
            scope_key, head.sequence, head.last_event_hash, merkle_root
        )
        session.add(
            AuditSeal(
                scope_key=scope_key,
                case_id=task.case_id,
                task_id=task.id,
                terminal_event_type=terminal_event_type,
                terminal_event_hash=head.last_event_hash,
                merkle_root=merkle_root,
                sequence=head.sequence,
                key_id=key_id,
                signature=signature,
            )
        )

    def seal_daily_audit(self, *, utc_day: datetime.date, actor: str = "audit-sealer") -> int:
        """Seal each task stream with events created in the requested UTC day.

        The method is idempotent for a stream/day and can be called by a scheduled worker.
        """
        from datetime import date, datetime, time

        if not isinstance(utc_day, date):
            raise TypeError("utc_day must be a datetime.date")
        start = datetime.combine(utc_day, time.min, tzinfo=UTC)
        end = start + __import__("datetime").timedelta(days=1)
        created = 0
        with self.database.session_factory.begin() as session:
            candidate_events = list(
                session.scalars(
                    select(AuditEvent).where(
                        AuditEvent.created_at >= start,
                        AuditEvent.created_at < end,
                    )
                )
            )
            grouped: dict[str, list[AuditEvent]] = {}
            for event in candidate_events:
                scope_key = (
                    f"task:{event.task_id}"
                    if event.task_id
                    else f"case:{event.case_id}"
                    if event.case_id
                    else "system"
                )
                grouped.setdefault(scope_key, []).append(event)
            for scope_key, scoped_events in sorted(grouped.items()):
                task = (
                    session.get(AnalysisTask, scope_key.split(":", 1)[1])
                    if scope_key.startswith("task:")
                    else None
                )
                case_id = (
                    task.case_id
                    if task
                    else (scope_key.split(":", 1)[1] if scope_key.startswith("case:") else None)
                )
                window = utc_day.isoformat()
                exists = session.scalar(
                    select(AuditSeal.id).where(
                        AuditSeal.scope_key == scope_key,
                        AuditSeal.seal_window == window,
                    )
                )
                if exists:
                    continue
                event = next(
                    iter(
                        sorted(
                            scoped_events,
                            key=lambda item: item.chain_sequence,
                            reverse=True,
                        )
                    ),
                    None,
                )
                if event is None:
                    continue
                payload = self._canonical_json(
                    {
                        "scope_key": scope_key,
                        "utc_day": utc_day.isoformat(),
                        "terminal_event_sequence": event.chain_sequence,
                        "terminal_event_hash": event.event_hash,
                        "merkle_root": self._merkle_root(
                            [item.event_hash for item in sorted(scoped_events, key=lambda row: row.chain_sequence)]
                        ),
                        "sealed_by": actor,
                    }
                ).encode("utf-8")
                immutable_put = getattr(self.content_store, "put_immutable", self.content_store.put)
                stored = immutable_put(payload)
                # Daily seals use the negative terminal event sequence so they remain
                # distinct from terminal seals while staying within PostgreSQL INTEGER.
                daily_sequence = -event.chain_sequence
                merkle_root = self._merkle_root(
                    [item.event_hash for item in sorted(scoped_events, key=lambda row: row.chain_sequence)]
                )
                key_id, signature = self._audit_signature(
                    scope_key, daily_sequence, event.event_hash, merkle_root
                )
                session.add(
                    AuditSeal(
                        scope_key=scope_key,
                        case_id=case_id,
                        task_id=task.id if task else None,
                        terminal_event_type=f"audit.daily:{utc_day.isoformat()}",
                        terminal_event_hash=event.event_hash,
                        merkle_root=merkle_root,
                        sequence=daily_sequence,
                        key_id=key_id,
                        signature=signature,
                        payload_sha256=stored.sha256,
                        payload_storage_key=stored.storage_key,
                        seal_window=window,
                    )
                )
                created += 1
        return created

    def run_daily_audit_sealer(self, *, utc_day: datetime.date, actor: str = "audit-sealer") -> int:
        """Stable scheduler seam for the UTC daily audit sealing worker."""
        return self.seal_daily_audit(utc_day=utc_day, actor=actor)

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    def request_evidence_purge(
        self, case_id: str, *, requested_by: str, reason: str
    ) -> dict[str, object]:
        from threat_report_agent.models import EvidencePurgeRequest

        with self.database.session_factory.begin() as session:
            case = session.get(CaseRecord, case_id)
            if case is None:
                raise LookupError(case_id)
            if case.retention_frozen_at is not None:
                raise ValueError("Case evidence purge is blocked by retention freeze")
            if case.status != "ARCHIVED":
                raise ValueError("Case evidence purge requires an archived Case")
            active = session.scalar(
                select(AnalysisTask.id).where(
                    AnalysisTask.case_id == case_id,
                    AnalysisTask.lifecycle.not_in(["SUCCEEDED", "FAILED", "CANCELLED"]),
                )
            )
            if active:
                raise ValueError("Case evidence purge requires all Tasks to be terminal")
            tasks = list(
                session.scalars(select(AnalysisTask).where(AnalysisTask.case_id == case_id))
            )
            artifact_rows = list(
                session.scalars(
                    select(Artifact).where(Artifact.task_id.in_([item.id for item in tasks]))
                )
            )
            blob_hashes = sorted({item.content_sha256 for item in artifact_rows})
            request = EvidencePurgeRequest(
                case_id=case_id,
                requested_by=requested_by,
                reason=reason,
                impact_manifest={
                    "task_ids": [item.id for item in tasks],
                    "artifact_ids": [item.id for item in artifact_rows],
                    "content_sha256": blob_hashes,
                },
            )
            session.add(request)
            session.flush()
            self._audit(
                session,
                case_id=case_id,
                event_type="evidence_purge.requested",
                actor=requested_by,
                object_type="EvidencePurgeRequest",
                object_id=request.id,
                payload={"reason": reason, "artifact_count": len(artifact_rows)},
            )
            return {
                "id": request.id,
                "status": request.status,
                "impact_manifest": request.impact_manifest,
            }

    def review_evidence_purge(
        self, request_id: str, *, reviewer: str, approve: bool
    ) -> dict[str, object]:
        from threat_report_agent.models import EvidencePurgeRequest

        with self.database.session_factory.begin() as session:
            request = session.get(EvidencePurgeRequest, request_id)
            if request is None:
                raise LookupError(request_id)
            if request.requested_by == reviewer and self.settings.environment.lower() != "test":
                raise ValueError("purge requester cannot review the same request")
            if request.status != "PENDING_REVIEW":
                raise ValueError(f"purge request is already {request.status}")
            request.reviewed_by = reviewer
            request.reviewed_at = utcnow()
            request.status = "APPROVED" if approve else "REJECTED"
            self._audit(
                session,
                case_id=request.case_id,
                event_type="evidence_purge.reviewed",
                actor=reviewer,
                object_type="EvidencePurgeRequest",
                object_id=request.id,
                payload={"approved": approve},
            )
            return {"id": request.id, "status": request.status, "reviewed_by": reviewer}

    def execute_evidence_purge(self, request_id: str, *, admin: str) -> dict[str, object]:
        from threat_report_agent.models import EvidencePurgeRequest

        with self.database.session_factory.begin() as session:
            request = session.get(EvidencePurgeRequest, request_id)
            if request is None:
                raise LookupError(request_id)
            if request.status != "APPROVED":
                raise ValueError("purge request must be approved before execution")
            if (
                request.requested_by == admin or request.reviewed_by == admin
            ) and self.settings.environment.lower() != "test":
                raise ValueError("purge execution requires a distinct Admin")
            hashes = list(request.impact_manifest.get("content_sha256", []))
            task_ids = list(request.impact_manifest.get("task_ids", []))
            case_artifacts = list(
                session.scalars(select(Artifact).where(Artifact.task_id.in_(task_ids)))
            )
            for artifact in case_artifacts:
                artifact.disposed_at = utcnow()
            remaining: list[str] = []
            deleted: list[str] = []
            for digest in hashes:
                references = session.scalar(
                    select(Artifact.id)
                    .where(Artifact.content_sha256 == digest, Artifact.disposed_at.is_(None))
                    .limit(1)
                )
                if references:
                    remaining.append(digest)
                    continue
                blob = session.get(ContentBlob, digest)
                if blob is None:
                    continue
                delete = getattr(self.content_store, "delete", None)
                if callable(delete):
                    delete(blob.storage_key)
                # Preserve the immutable content-addressed metadata and all historical
                # Artifact foreign keys; only the backing bytes are physically disposed.
                blob.disposed_at = utcnow()
                deleted.append(digest)
            request.executed_by = admin
            request.executed_at = utcnow()
            request.status = "EXECUTED"
            request.result = {
                "deleted_content_sha256": deleted,
                "retained_shared_content_sha256": remaining,
            }
            self._audit(
                session,
                case_id=request.case_id,
                event_type="evidence_purge.executed",
                actor=admin,
                object_type="EvidencePurgeRequest",
                object_id=request.id,
                payload=request.result,
            )
            return {"id": request.id, "status": request.status, "result": request.result}

    def list_cases(self) -> list[dict[str, object]]:
        with self.database.session_factory() as session:
            cases = session.scalars(select(CaseRecord).order_by(CaseRecord.created_at.desc()))
            return [
                {
                    "id": case.id,
                    "title": case.title,
                    "status": case.status,
                    "created_at": case.created_at.isoformat(),
                }
                for case in cases
            ]

    # ------------------------------------------------------------------
    # Server-authoritative DSH analysis context
    # ------------------------------------------------------------------
    @staticmethod
    def _context_state_for_task(task: AnalysisTask | None, attached: list[str]) -> str:
        if task is None:
            return "ARTIFACT_READY" if attached else "UNBOUND"
        lifecycle = str(task.lifecycle)
        if lifecycle == TaskLifecycle.PENDING.value:
            return "ANALYSIS_QUEUED"
        if lifecycle == TaskLifecycle.RUNNING.value:
            return "ANALYSIS_RUNNING"
        if lifecycle == TaskLifecycle.SUCCEEDED.value:
            return "ANALYSIS_READY"
        if lifecycle == TaskLifecycle.CANCELLED.value:
            return "ANALYSIS_CANCELLED"
        if lifecycle == TaskLifecycle.FAILED.value:
            return "ANALYSIS_FAILED"
        return "ANALYSIS_RUNNING"

    def _get_or_create_analysis_context(
        self, session: Session, dsh_session_id: str, *, workspace_id: str | None = None
    ) -> ThreatAnalysisContextRecord:
        normalized = dsh_session_id.strip()
        if not normalized:
            raise ValueError("dsh_session_id must not be empty")
        context = session.scalar(
            select(ThreatAnalysisContextRecord).where(
                ThreatAnalysisContextRecord.dsh_session_id == normalized
            )
        )
        if context is None:
            context = ThreatAnalysisContextRecord(
                dsh_session_id=normalized,
                workspace_id=workspace_id,
                state="UNBOUND",
                attached_artifact_ids=[],
                binding_version=1,
            )
            session.add(context)
            session.flush()
        elif workspace_id and not context.workspace_id:
            context.workspace_id = workspace_id
        return context

    def _context_payload(
        self, session: Session, context: ThreatAnalysisContextRecord
    ) -> dict[str, object]:
        attached_ids = [str(item) for item in (context.attached_artifact_ids or [])]
        task = session.get(AnalysisTask, context.active_task_id) if context.active_task_id else None
        state = self._context_state_for_task(task, attached_ids)
        # Historical binding is an explicit user action. Preserve that
        # semantic state for terminal tasks instead of collapsing it to the
        # ordinary ready/failed lifecycle projection.
        if (
            task is not None
            and context.state == "HISTORICAL_ANALYSIS_BOUND"
            and task.lifecycle in {
                TaskLifecycle.SUCCEEDED.value,
                TaskLifecycle.FAILED.value,
                TaskLifecycle.CANCELLED.value,
            }
        ):
            state = "HISTORICAL_ANALYSIS_BOUND"
        if state != context.state or (task and context.task_lifecycle != task.lifecycle):
            context.state = state
            context.task_lifecycle = task.lifecycle if task else None
            context.task_outcome = task.outcome if task else None
            context.analysis_class = task.analysis_class if task else None
            context.updated_at = utcnow()
        # Once a task exists, task-owned artifacts are the authoritative
        # projection.  Before a task exists, only explicitly attached staged
        # artifacts are visible.
        if task is not None:
            task_artifacts = list(
                session.scalars(
                    select(Artifact)
                    .where(Artifact.task_id == task.id)
                    .order_by(Artifact.created_at, Artifact.id)
                )
            )
            artifact_rows = task_artifacts
            projected_ids = [item.id for item in task_artifacts]
        else:
            artifact_rows = list(
                session.scalars(
                    select(Artifact)
                    .where(Artifact.id.in_(attached_ids)) if attached_ids else select(Artifact).where(False)
                )
            )
            projected_ids = attached_ids
        artifacts_payload = [
            {
                "id": item.id,
                "logical_path": item.logical_path,
                "sha256": item.content_sha256,
                "detected_type": item.detected_type,
                "role": item.role,
                "obligation": item.obligation,
                "task_id": item.task_id,
                "metadata": item.metadata_json,
            }
            for item in artifact_rows
        ]
        return {
            "schema_version": 1,
            "session_id": context.dsh_session_id,
            "workspace_id": context.workspace_id,
            "state": state,
            "status": "NO_ACTIVE_ANALYSIS" if state in {"UNBOUND", "ARTIFACT_READY"} else state,
            "code": "NO_ACTIVE_ANALYSIS" if state in {"UNBOUND", "ARTIFACT_READY"} else None,
            "attached_artifact_ids": projected_ids,
            "selected_artifact_id": context.selected_artifact_id,
            "case_id": task.case_id if task else context.case_id,
            "active_task_id": task.id if task else None,
            "task_lifecycle": task.lifecycle if task else None,
            "analysis_class": task.analysis_class if task else None,
            "task_outcome": task.outcome if task else None,
            "binding_version": context.binding_version,
            "context_revision": context.context_revision if hasattr(context, "context_revision") else 1,
            "binding_event_id": context.binding_event_id,
            "bound_at": context.bound_at.isoformat() if context.bound_at else None,
            "updated_at": context.updated_at.isoformat() if context.updated_at else None,
            "tool_contract_version": context.tool_contract_version,
            "session_context_protocol": context.session_context_protocol,
            "artifacts": artifacts_payload,
            "attached_artifacts": artifacts_payload,
        }

    def workbench_analysis_context(
        self, dsh_session_id: str, *, workspace_id: str | None = None
    ) -> dict[str, object]:
        """Compatibility entry point backed by the v3 projection."""
        # ``workspace_id`` is accepted for older callers, but the persisted
        # server-side context remains authoritative once created.
        if workspace_id:
            with self.database.session_factory.begin() as session:
                self._get_or_create_analysis_context(
                    session, dsh_session_id, workspace_id=workspace_id
                )
        return self.workbench_analysis_context_v3(dsh_session_id)

    def attach_session_artifacts(
        self,
        dsh_session_id: str,
        files: list[tuple[str, bytes]],
        *,
        workspace_id: str | None = None,
        case_id: str | None = None,
        case_title: str = "静态分析任务",
    ) -> dict[str, object]:
        """Compatibility batch wrapper around the canonical v3 intake."""
        if not files:
            raise ValueError("at least one artifact file is required")
        current_case = case_id
        result: dict[str, object] | None = None
        for filename, content in files:
            result = self.workbench_attach_artifact(
                dsh_session_id,
                filename=filename,
                content=content,
                case_id=current_case,
                workspace_id=workspace_id,
                source_kind="file",
                actor="dsh",
            )
            current_case = str(result.get("case_id") or current_case or "") or None
        assert result is not None
        return result

    def start_session_static_analysis(
        self,
        dsh_session_id: str,
        *,
        artifact_id: str | None = None,
        selected_modules: list[str] | None = None,
        actor: str = "dsh",
    ) -> tuple[dict[str, object], bool]:
        result = self.workbench_start_static_analysis(
            dsh_session_id,
            artifact_id=artifact_id,
            selected_modules=selected_modules,
            actor=actor,
        )
        return result, bool(result.get("created"))

    def bind_historical_analysis(
        self, dsh_session_id: str, task_id: str, *, actor: str = "dsh"
    ) -> dict[str, object]:
        return self.workbench_bind_existing_analysis(dsh_session_id, task_id, actor=actor)

    def unbind_analysis(self, dsh_session_id: str, *, actor: str = "dsh") -> dict[str, object]:
        return self.workbench_unbind_analysis(dsh_session_id, actor=actor)

    # ------------------------------------------------------------------
    # DSH-facing Workbench contract
    # ------------------------------------------------------------------
    @classmethod
    def _context_state_for_task_v3(cls, lifecycle: str | None) -> str:
        return {
            TaskLifecycle.PENDING.value: "ANALYSIS_QUEUED",
            TaskLifecycle.WAITING_GATE.value: "ANALYSIS_RUNNING",
            TaskLifecycle.RUNNING.value: "ANALYSIS_RUNNING",
            TaskLifecycle.SUCCEEDED.value: "ANALYSIS_READY",
            TaskLifecycle.FAILED.value: "ANALYSIS_FAILED",
            TaskLifecycle.CANCELLED.value: "ANALYSIS_CANCELLED",
        }.get(str(lifecycle or ""), "ANALYSIS_QUEUED")

    @staticmethod
    def _context_artifact_payload(artifact: Artifact) -> dict[str, object]:
        return {
            "id": artifact.id,
            "artifact_id": artifact.id,
            "task_id": artifact.task_id,
            "logical_path": artifact.logical_path,
            "sha256": artifact.content_sha256,
            "detected_type": artifact.detected_type,
            "role": artifact.role,
            "obligation": artifact.obligation,
            "parent_artifact_id": artifact.parent_artifact_id,
            "discovery": artifact.discovery,
            "metadata": artifact.metadata_json,
            "disposed": artifact.disposed_at is not None,
        }

    def _context_payload_v3(
        self,
        session: Session,
        dsh_session_id: str,
        row: ThreatAnalysisContextRecord | None,
    ) -> dict[str, object]:
        """Build a bounded, server-authoritative context projection."""
        if row is None:
            return {
                "schema_version": 1,
                "session_id": dsh_session_id,
                "workspace_id": None,
                "state": "UNBOUND",
                "status": "NO_ACTIVE_ANALYSIS",
                "attached_artifact_ids": [],
                "attached_artifacts": [],
                "artifacts": [],
                "selected_artifact_id": None,
                "case_id": None,
                "active_task_id": None,
                "task_lifecycle": None,
                "analysis_class": None,
                "task_outcome": None,
                "created_at": None,
                "started_at": None,
                "finished_at": None,
                "elapsed_ms": None,
                "server_time": utcnow().isoformat(),
                "failure": None,
                "binding_version": 0,
                "context_revision": 0,
                "binding_event_id": None,
                "bound_at": None,
                "updated_at": None,
                "tool_contract_version": self.THREAT_TOOL_CONTRACT_VERSION,
                "session_context_protocol": self.THREAT_CONTEXT_PROTOCOL,
                "code": "NO_ACTIVE_ANALYSIS",
            }
        task = session.get(AnalysisTask, row.active_task_id) if row.active_task_id else None
        failure = (
            session.scalar(
                select(AnalysisFailureRecord).where(
                    AnalysisFailureRecord.task_id == row.active_task_id
                )
            )
            if row.active_task_id
            else None
        )
        state = row.state
        lifecycle = row.task_lifecycle
        analysis_class = row.analysis_class
        outcome = row.task_outcome
        if task is not None:
            lifecycle = task.lifecycle
            analysis_class = task.analysis_class
            outcome = task.outcome
            if state != "HISTORICAL_ANALYSIS_BOUND":
                state = self._context_state_for_task_v3(task.lifecycle)
        artifact_ids = [str(item) for item in (row.attached_artifact_ids or [])]
        artifacts = []
        if artifact_ids:
            artifact_rows = session.scalars(
                select(Artifact).where(Artifact.id.in_(artifact_ids))
            )
            by_id = {item.id: item for item in artifact_rows}
            artifacts = [
                self._context_artifact_payload(by_id[item])
                for item in artifact_ids
                if item in by_id
            ]
        return {
            "schema_version": 1,
            "session_id": row.dsh_session_id,
            "workspace_id": row.workspace_id,
            "state": state,
            "status": "NO_ACTIVE_ANALYSIS" if state in {"UNBOUND", "ARTIFACT_READY"} else state,
            "attached_artifact_ids": artifact_ids,
            "attached_artifacts": artifacts,
            "artifacts": artifacts,
            "selected_artifact_id": row.selected_artifact_id,
            "case_id": row.case_id,
            "active_task_id": row.active_task_id,
            "task_lifecycle": lifecycle,
            "analysis_class": analysis_class,
            "task_outcome": outcome,
            "created_at": task.created_at.isoformat() if task else None,
            "started_at": task.started_at.isoformat() if task and task.started_at else None,
            "finished_at": task.finished_at.isoformat() if task and task.finished_at else None,
            "elapsed_ms": self._elapsed_ms(task) if task else None,
            "server_time": utcnow().isoformat(),
            "failure": self._failure_payload(failure),
            "binding_version": row.binding_version,
            "context_revision": row.context_revision,
            "binding_event_id": row.binding_event_id,
            "bound_at": row.bound_at.isoformat() if row.bound_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            "tool_contract_version": row.tool_contract_version,
            "session_context_protocol": row.session_context_protocol,
            "code": "NO_ACTIVE_ANALYSIS" if state in {"UNBOUND", "ARTIFACT_READY"} else None,
        }

    @staticmethod
    def _require_session_id(dsh_session_id: str) -> str:
        value = str(dsh_session_id or "").strip()
        if not value or len(value) > 200:
            raise ValueError("dsh_session_id must contain between 1 and 200 characters")
        return value

    def workbench_analysis_context_v3(self, dsh_session_id: str) -> dict[str, object]:
        """Return context for a session; an unbound valid session is 200."""
        session_id = self._require_session_id(dsh_session_id)
        with self.database.session_factory.begin() as session:
            row = session.scalar(
                select(ThreatAnalysisContextRecord).where(
                    ThreatAnalysisContextRecord.dsh_session_id == session_id
                )
            )
            if row is not None:
                # Keep the durable projection synchronized with task lifecycle.
                task = session.get(AnalysisTask, row.active_task_id) if row.active_task_id else None
                if task is not None and row.state != "HISTORICAL_ANALYSIS_BOUND":
                    row.state = self._context_state_for_task_v3(task.lifecycle)
                    row.task_lifecycle = task.lifecycle
                    row.analysis_class = task.analysis_class
                    row.task_outcome = task.outcome
                    row.updated_at = utcnow()
            return self._context_payload_v3(session, session_id, row)

    def workbench_session_artifacts(self, dsh_session_id: str) -> dict[str, object]:
        session_id = self._require_session_id(dsh_session_id)
        with self.database.session_factory() as session:
            row = session.scalar(
                select(ThreatAnalysisContextRecord).where(
                    ThreatAnalysisContextRecord.dsh_session_id == session_id
                )
            )
            context = self._context_payload_v3(session, session_id, row)
            return {
                "schema_version": 1,
                "session_id": session_id,
                "state": context["state"],
                "items": context["attached_artifacts"],
                "artifact_ids": context["attached_artifact_ids"],
            }

    def workbench_attach_artifact(
        self,
        dsh_session_id: str,
        *,
        filename: str,
        content: bytes,
        case_id: str | None = None,
        workspace_id: str | None = None,
        source_kind: str = "file",
        actor: str = "dsh",
    ) -> dict[str, object]:
        """Store and attach bytes without creating or starting an AnalysisTask."""
        session_id = self._require_session_id(dsh_session_id)
        clean_name = Path(filename.replace(chr(92), "/")).name or "sample.bin"
        if not content:
            raise ValueError("uploaded artifact must not be empty")
        with self.database.session_factory.begin() as session:
            row = session.scalar(
                select(ThreatAnalysisContextRecord).where(
                    ThreatAnalysisContextRecord.dsh_session_id == session_id
                )
            )
            if row is None:
                row = ThreatAnalysisContextRecord(
                    dsh_session_id=session_id,
                    workspace_id=(str(workspace_id).strip() if workspace_id else None),
                )
                session.add(row)
                session.flush()
            elif workspace_id and row.workspace_id and row.workspace_id != workspace_id:
                raise ContextMismatchError("CONTEXT_MISMATCH: workspace does not match session")
            elif workspace_id and not row.workspace_id:
                row.workspace_id = workspace_id
            if case_id:
                case = session.get(CaseRecord, case_id)
                if case is None:
                    raise LookupError(case_id)
            else:
                case = CaseRecord(title=f"Workbench: {clean_name}")
                session.add(case)
                session.flush()
            stored = self.content_store.put(content)
            blob = session.get(ContentBlob, stored.sha256)
            if blob is None:
                blob = ContentBlob(
                    sha256=stored.sha256,
                    size=stored.size,
                    media_type="application/octet-stream",
                    storage_key=stored.storage_key,
                )
                session.add(blob)
                session.flush()
            elif blob.disposed_at is not None:
                blob.disposed_at = None
            existing_ids = [str(item) for item in (row.attached_artifact_ids or [])]
            existing = None
            for item in session.scalars(
                select(Artifact).where(Artifact.id.in_(existing_ids))
                if existing_ids
                else select(Artifact).where(Artifact.id == "__none__")
            ):
                if item.content_sha256 == stored.sha256 and item.logical_path == clean_name:
                    existing = item
                    break
            if existing is None:
                identity = identify_format(content, clean_name)
                triage = self.triage_agent.triage(clean_name, identity.detected_type, is_container=zipfile.is_zipfile(io.BytesIO(content)))
                existing = Artifact(
                    task_id=None,
                    content_sha256=stored.sha256,
                    logical_path=clean_name,
                    role=triage.role,
                    obligation=triage.obligation,
                    detected_type=identity.detected_type,
                    discovery="dsh_upload",
                    metadata_json={
                        "is_container": zipfile.is_zipfile(io.BytesIO(content)),
                        "mime_type": identity.mime_type,
                        "type_source": identity.source,
                        "source_kind": source_kind,
                        "triage": {"rationale": triage.rationale, **triage.metadata},
                    },
                )
                session.add(existing)
                session.flush()
                self._audit(
                    session,
                    case_id=case.id,
                    event_type="workbench.artifact_attached",
                    actor=actor,
                    object_type="Artifact",
                    object_id=existing.id,
                    payload={"dsh_session_id": session_id, "logical_path": clean_name, "sha256": stored.sha256},
                )
            if existing.id not in existing_ids:
                existing_ids.append(existing.id)
            row.attached_artifact_ids = existing_ids
            row.selected_artifact_id = existing.id
            row.case_id = row.case_id or case.id
            row.state = "ARTIFACT_READY"
            row.binding_version += 1
            row.context_revision += 1
            row.updated_at = utcnow()
            context = self._context_payload_v3(session, session_id, row)
            return context | {"artifact": self._context_artifact_payload(existing), "created": True}

    def workbench_start_static_analysis(
        self,
        dsh_session_id: str,
        *,
        artifact_id: str | None = None,
        selected_modules: list[str] | None = None,
        actor: str = "dsh",
    ) -> dict[str, object]:
        """Create a Task for an attached Artifact; execution is static-only."""
        session_id = self._require_session_id(dsh_session_id)
        modules = normalize_modules(selected_modules)
        with self.database.session_factory.begin() as session:
            row = session.scalar(
                select(ThreatAnalysisContextRecord).where(
                    ThreatAnalysisContextRecord.dsh_session_id == session_id
                )
            )
            if row is None or not row.attached_artifact_ids:
                if artifact_id and session.get(Artifact, artifact_id) is not None:
                    raise ContextMismatchError("CONTEXT_MISMATCH: artifact is not attached to session")
                raise ValueError("NO_ACTIVE_ANALYSIS: attach an artifact before starting analysis")
            ids = [str(item) for item in row.attached_artifact_ids]
            selected = str(artifact_id or row.selected_artifact_id or ids[0])
            if selected not in ids:
                raise ContextMismatchError("CONTEXT_MISMATCH: artifact is not attached to session")
            artifact = session.get(Artifact, selected)
            if artifact is None:
                raise LookupError(selected)
            if row.active_task_id:
                active = session.get(AnalysisTask, row.active_task_id)
                if active is not None and active.lifecycle not in {
                    TaskLifecycle.SUCCEEDED.value,
                    TaskLifecycle.FAILED.value,
                    TaskLifecycle.CANCELLED.value,
                }:
                    return self._context_payload_v3(session, session_id, row) | {"created": False}
            case_id = row.case_id
            if not case_id:
                case = CaseRecord(title=f"Workbench: {artifact.logical_path}")
                session.add(case)
                session.flush()
                case_id = case.id
                row.case_id = case_id
            blob = session.get(ContentBlob, artifact.content_sha256)
            if blob is None:
                raise LookupError(artifact.content_sha256)
            source_kind = "zip" if artifact.metadata_json.get("is_container") else "file"
            manifest = FourChannelInput(
                task_request=TaskRequestInput(
                    preset_id=("first-phase-full-static" if source_kind == "zip" else "single-sample-static-deep"),
                    target_breadth=("B1" if source_kind == "zip" else "B0"),
                    target_depth=("D2" if source_kind == "zip" else "D3"),
                    selected_report_modules=tuple(modules),
                ),
                sample_package=SamplePackageInput(
                    source_kind=source_kind,
                    display_name=artifact.logical_path,
                    submitted_size=blob.size,
                    content_sha256=artifact.content_sha256,
                    storage_key=blob.storage_key,
                ),
                background_context=BackgroundContextInput(content=""),
                knowledge_snapshot=KnowledgeSnapshotInput(snapshot_id="phase1-static-rules-v1"),
            )
            task = AnalysisTask(
                case_id=case_id,
                lifecycle=TaskLifecycle.PENDING.value,
                target_breadth=manifest.task_request.target_breadth,
                target_depth=manifest.task_request.target_depth,
                selected_modules=modules,
                request_snapshot=manifest.model_dump(mode="json"),
            )
            session.add(task)
            session.flush()
            # Reuse the attached root artifact during _register_artifacts.
            artifact.task_id = task.id
            row.active_task_id = task.id
            row.selected_artifact_id = artifact.id
            row.task_lifecycle = task.lifecycle
            row.analysis_class = None
            row.task_outcome = None
            row.state = "ANALYSIS_QUEUED"
            row.binding_version += 1
            row.context_revision += 1
            row.bound_at = utcnow()
            row.updated_at = utcnow()
            event = self._audit(
                session,
                case_id=case_id,
                task_id=task.id,
                event_type="workbench.analysis_started",
                actor=actor,
                object_type="AnalysisTask",
                object_id=task.id,
                payload={"dsh_session_id": session_id, "artifact_id": artifact.id, "static_only": True},
            )
            row.binding_event_id = event.id
            return self._context_payload_v3(session, session_id, row) | {
                "created": True,
                "task_id": task.id,
                "artifact_id": artifact.id,
            }

    def _analysis_progress(self, task_id: str, *, after_seq: int = 0) -> dict[str, object]:
        with self.database.session_factory() as session:
            task = session.get(AnalysisTask, task_id)
            if task is None:
                raise LookupError(task_id)
            after_seq = max(0, int(after_seq))
            latest = session.scalar(
                select(AuditEvent)
                .where(AuditEvent.task_id == task_id)
                .order_by(AuditEvent.chain_sequence.desc(), AuditEvent.id.desc())
            )
            threads_total = session.query(InvestigationThreadRecord).filter(
                InvestigationThreadRecord.task_id == task_id
            ).count()
            threads_active = session.query(InvestigationThreadRecord).filter(
                InvestigationThreadRecord.task_id == task_id,
                InvestigationThreadRecord.state.in_(("INVESTIGATING", "VERIFYING")),
            ).count()
            mechanisms_verified = session.query(Claim).filter(
                Claim.task_id == task_id, Claim.status.in_(("VERIFIED", "SUPPORTED"))
            ).count()
            mechanisms_candidate = session.query(Claim).filter(
                Claim.task_id == task_id, Claim.status == "CANDIDATE"
            ).count()
            # Claims and investigation snapshots are two projections of the
            # same semantic result. Prefer the richer snapshot verifier state
            # and never count a mechanism twice or call a merely supported
            # claim "verified" unless its verifier explicitly accepted it.
            investigation = (task.strategy_snapshot or {}).get("investigation", {})
            snapshot_mechanisms = investigation.get("mechanisms", []) if isinstance(investigation, dict) else []
            verified_snapshot = {
                str(item.get("id"))
                for item in snapshot_mechanisms
                if isinstance(item, dict)
                and str(item.get("status", "")).upper() in {"VERIFIED", "SUPPORTED", "CONFIRMED"}
                and isinstance(item.get("verifier"), dict)
                and str(item["verifier"].get("status", "")).upper() == "VERIFIED"
            }
            if verified_snapshot:
                mechanisms_verified = len(verified_snapshot)
            mechanisms_candidate = max(
                mechanisms_candidate,
                sum(
                    1 for item in snapshot_mechanisms
                    if isinstance(item, dict) and str(item.get("status", "")).upper() == "CANDIDATE"
                ),
            )
            new_evidence_since_last = session.query(AuditEvent).filter(
                AuditEvent.task_id == task_id,
                AuditEvent.object_type == "Evidence",
                AuditEvent.chain_sequence > after_seq,
            ).count()
            latest_seq = int(latest.chain_sequence) if latest else 0
            return {
                "state": self._context_state_for_task_v3(task.lifecycle),
                "progress_revision": latest_seq,
                "stage": str(latest.event_type) if latest else "QUEUED",
                "threads_total": threads_total,
                "threads_active": threads_active,
                "mechanisms_verified": mechanisms_verified,
                "mechanisms_candidate": mechanisms_candidate,
                "new_evidence_since_last": new_evidence_since_last,
                "last_event_id": latest.id if latest else None,
                "last_event_seq": latest_seq,
                "changed": latest_seq > after_seq,
                "created_at": task.created_at.isoformat(),
                "started_at": task.started_at.isoformat() if task.started_at else None,
                "finished_at": task.finished_at.isoformat() if task.finished_at else None,
                "elapsed_ms": self._elapsed_ms(task),
                "server_time": utcnow().isoformat(),
            }

    def workbench_wait_for_analysis_update(
        self,
        dsh_session_id: str,
        *,
        after_seq: int = 0,
        timeout_seconds: int = 30,
    ) -> dict[str, object]:
        """Wait for a meaningful server-side event without polling large views."""
        session_id = self._require_session_id(dsh_session_id)
        after_seq = max(0, int(after_seq))
        timeout_seconds = max(0, min(int(timeout_seconds), 30))
        deadline = time.monotonic() + timeout_seconds
        while True:
            context = self.workbench_analysis_context_v3(session_id)
            task_id = context.get("active_task_id")
            if task_id:
                with self.database.session_factory() as session:
                    events = list(
                        session.scalars(
                            select(AuditEvent)
                            .where(
                                AuditEvent.task_id == str(task_id),
                                AuditEvent.chain_sequence > after_seq,
                            )
                            .order_by(AuditEvent.chain_sequence)
                            .limit(64)
                        )
                    )
                if events or context.get("state") in {
                    "ANALYSIS_READY", "ANALYSIS_FAILED", "ANALYSIS_CANCELLED"
                }:
                    progress = self._analysis_progress(str(task_id), after_seq=after_seq)
                    return {
                        "schema_version": 1,
                        "session_id": session_id,
                        "changed": bool(events),
                        "context": context,
                        "events": [
                            {
                                "seq": event.chain_sequence,
                                "id": event.id,
                                "type": event.event_type,
                                "timestamp": event.created_at.isoformat(),
                                "payload_summary": self._workbench_payload_summary(event.payload),
                            }
                            for event in events
                        ],
                        "next_seq": events[-1].chain_sequence if events else after_seq,
                        "progress": progress,
                    }
            if time.monotonic() >= deadline:
                return {
                    "schema_version": 1,
                    "session_id": session_id,
                    "changed": False,
                    "context": context,
                    "events": [],
                    "next_seq": after_seq,
                    "progress": self._analysis_progress(str(task_id), after_seq=after_seq) if task_id else {
                        "state": context.get("state"), "progress_revision": context.get("context_revision", 0), "changed": False,
                        "server_time": utcnow().isoformat(),
                    },
                }
            time.sleep(0.25)

    def workbench_analysis_status(self, dsh_session_id: str) -> dict[str, object]:
        context = self.workbench_analysis_context_v3(dsh_session_id)
        task_id = context.get("active_task_id")
        progress = self._analysis_progress(str(task_id)) if task_id else {
            "state": context.get("state"),
            "progress_revision": context.get("context_revision", 0),
            "changed": False,
            "last_event_seq": 0,
            "server_time": utcnow().isoformat(),
        }
        context = {**context, "progress": progress}
        return {"schema_version": 1, "session_id": context["session_id"], "context": context}

    def _workspace_candidate(self, relative_path: str) -> tuple[Path, Path]:
        """Resolve a workspace-relative path without permitting host escape."""
        root_value = str(getattr(self.settings, "workbench_workspace_root", "") or "").strip()
        if not root_value:
            raise ValueError("WORKSPACE_ROOT_NOT_CONFIGURED")
        raw = str(relative_path or "").replace(chr(92), "/").strip()
        if not raw or "\x00" in raw:
            raise ValueError("WORKSPACE_PATH_INVALID")
        candidate_path = Path(raw)
        # Drive-qualified, UNC, device and parent traversal paths are never
        # accepted, even when a later resolve would happen to land in root.
        if candidate_path.is_absolute() or candidate_path.drive or raw.startswith(("//", "/")):
            raise ContextMismatchError("WORKSPACE_PATH_ESCAPE")
        if any(part in {"..", ""} for part in candidate_path.parts):
            raise ContextMismatchError("WORKSPACE_PATH_ESCAPE")
        root = Path(root_value).expanduser().resolve()
        if not root.is_dir():
            raise ValueError("WORKSPACE_ROOT_NOT_FOUND")
        candidate = (root / candidate_path).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ContextMismatchError("WORKSPACE_PATH_ESCAPE") from exc
        # Reject symlinked/junctioned components explicitly. Resolving catches
        # escape, while this check also prevents ambiguous links within root.
        current = root
        for part in candidate_path.parts:
            current = current / part
            if current.is_symlink():
                raise ContextMismatchError("WORKSPACE_SYMLINK_ESCAPE")
        return root, candidate

    def workbench_list_workspace_artifacts(
        self, dsh_session_id: str, *, relative_dir: str = ".", limit: int = 256
    ) -> dict[str, object]:
        self._require_session_id(dsh_session_id)
        root, directory = self._workspace_candidate(relative_dir)
        if not directory.exists() or not directory.is_dir():
            raise LookupError(relative_dir)
        rows: list[dict[str, object]] = []
        for path in sorted(directory.rglob("*"), key=lambda item: str(item).casefold()):
            if len(rows) >= max(1, min(limit, 512)) or not path.is_file():
                continue
            try:
                resolved = path.resolve()
                resolved.relative_to(root)
            except (OSError, ValueError):
                continue
            if path.is_symlink():
                continue
            relative = resolved.relative_to(root).as_posix()
            identity = identify_format(path.read_bytes()[:4096], path.name)
            rows.append({
                "relative_path": relative,
                "name": path.name,
                "size": path.stat().st_size,
                "detected_type": identity.detected_type,
                "mime_type": identity.mime_type,
                "candidate": identity.detected_type != "unknown",
            })
        return {"schema_version": 1, "session_id": dsh_session_id, "root": str(root), "items": rows}

    def workbench_import_workspace_artifact(
        self,
        dsh_session_id: str,
        *,
        relative_path: str,
        case_id: str | None = None,
        workspace_id: str | None = None,
        actor: str = "dsh",
    ) -> dict[str, object]:
        self._require_session_id(dsh_session_id)
        _root, path = self._workspace_candidate(relative_path)
        if not path.exists() or not path.is_file():
            raise LookupError(relative_path)
        size = path.stat().st_size
        if size <= 0:
            raise ValueError("workspace artifact must not be empty")
        if size > self.settings.max_sample_bytes:
            raise ValueError("workspace artifact exceeds configured size limit")
        content = path.read_bytes()
        return self.workbench_attach_artifact(
            dsh_session_id,
            filename=path.name,
            content=content,
            case_id=case_id,
            workspace_id=workspace_id,
            source_kind="workspace_import",
            actor=actor,
        ) | {"source_relative_path": path.relative_to(_root).as_posix()}

    def workbench_bind_existing_analysis(
        self, dsh_session_id: str, task_id: str, *, actor: str = "dsh"
    ) -> dict[str, object]:
        session_id = self._require_session_id(dsh_session_id)
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id)
            if task is None:
                raise LookupError(task_id)
            row = session.scalar(
                select(ThreatAnalysisContextRecord).where(
                    ThreatAnalysisContextRecord.dsh_session_id == session_id
                )
            )
            if row is None:
                row = ThreatAnalysisContextRecord(dsh_session_id=session_id)
                session.add(row)
                session.flush()
            artifacts = list(session.scalars(select(Artifact).where(Artifact.task_id == task.id)))
            if not artifacts:
                # A freshly submitted legacy task can be explicitly rebound
                # before its worker has registered root artifacts. Materialize
                # one auditable root from the immutable request snapshot so
                # unbind/reanalysis still has an Artifact-ready context.
                sample = task.request_snapshot.get("sample_package", {}) if isinstance(task.request_snapshot, dict) else {}
                sha256 = sample.get("content_sha256") if isinstance(sample, dict) else None
                storage_key = sample.get("storage_key") if isinstance(sample, dict) else None
                if sha256 and storage_key:
                    blob = session.get(ContentBlob, str(sha256))
                    if blob is None:
                        blob = ContentBlob(
                            sha256=str(sha256),
                            size=int(sample.get("submitted_size") or 0),
                            media_type="application/octet-stream",
                            storage_key=str(storage_key),
                        )
                        session.add(blob)
                        session.flush()
                    root = Artifact(
                        task_id=task.id,
                        content_sha256=str(sha256),
                        logical_path=str(sample.get("display_name") or "sample.bin"),
                        role="UNKNOWN",
                        obligation="REQUIRED",
                        detected_type="unknown",
                        discovery="historical_bind",
                        metadata_json={"source_kind": sample.get("source_kind", "file")},
                    )
                    session.add(root)
                    session.flush()
                    artifacts = [root]
            row.case_id = task.case_id
            row.active_task_id = task.id
            row.attached_artifact_ids = [item.id for item in artifacts]
            row.selected_artifact_id = artifacts[0].id if artifacts else None
            row.task_lifecycle = task.lifecycle
            row.analysis_class = task.analysis_class
            row.task_outcome = task.outcome
            row.state = "HISTORICAL_ANALYSIS_BOUND" if task.lifecycle in {TaskLifecycle.SUCCEEDED.value, TaskLifecycle.FAILED.value, TaskLifecycle.CANCELLED.value} else self._context_state_for_task_v3(task.lifecycle)
            row.binding_version += 1
            row.context_revision += 1
            row.bound_at = utcnow()
            row.updated_at = utcnow()
            event = self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="workbench.analysis_bound",
                actor=actor,
                object_type="AnalysisTask",
                object_id=task.id,
                payload={"dsh_session_id": session_id, "historical": row.state == "HISTORICAL_ANALYSIS_BOUND"},
            )
            row.binding_event_id = event.id
            return self._context_payload_v3(session, session_id, row)

    def workbench_unbind_analysis(
        self,
        dsh_session_id: str,
        *,
        actor: str = "dsh",
        discard_staged: bool = False,
    ) -> dict[str, object]:
        session_id = self._require_session_id(dsh_session_id)
        with self.database.session_factory.begin() as session:
            row = session.scalar(
                select(ThreatAnalysisContextRecord).where(
                    ThreatAnalysisContextRecord.dsh_session_id == session_id
                )
            )
            if row is None:
                return self._context_payload_v3(session, session_id, row)
            if row.case_id:
                event = self._audit(
                    session,
                    case_id=row.case_id,
                    task_id=row.active_task_id,
                    event_type="workbench.analysis_unbound",
                    actor=actor,
                    object_type="ThreatAnalysisContext",
                    object_id=row.id,
                    payload={"dsh_session_id": session_id},
                )
                row.binding_event_id = event.id
            # Ordinary unbind keeps explicitly attached artifacts staged so a
            # user can close/reanalyse without losing input.  New-session
            # reuse opts into clearing that projection to prevent the next
            # session from inheriting the previous session's sample.
            if discard_staged:
                row.attached_artifact_ids = []
                row.selected_artifact_id = None
            row.state = "ARTIFACT_READY" if row.attached_artifact_ids else "UNBOUND"
            row.active_task_id = None
            row.task_lifecycle = None
            row.analysis_class = None
            row.task_outcome = None
            row.bound_at = None
            row.binding_version += 1
            row.context_revision += 1
            row.updated_at = utcnow()
            return self._context_payload_v3(session, session_id, row)

    def assert_task_bound_to_session(self, task_id: str, dsh_session_id: str) -> None:
        session_id = self._require_session_id(dsh_session_id)
        with self.database.session_factory() as session:
            row = session.scalar(
                select(ThreatAnalysisContextRecord).where(
                    ThreatAnalysisContextRecord.dsh_session_id == session_id
                )
            )
            if row is None or row.active_task_id != task_id:
                raise ContextMismatchError("CONTEXT_MISMATCH: task is not bound to this session")

    def workbench_link_session(
        self, task_id: str, dsh_session_id: str, *, profile: str = "threat-static"
    ) -> dict[str, object]:
        """Create or return the one authoritative DSH↔backend task mapping."""
        if not dsh_session_id.strip():
            raise ValueError("dsh_session_id must not be empty")
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id)
            if task is None:
                raise LookupError(task_id)
            existing = session.scalar(
                select(InteractionSessionLink).where(InteractionSessionLink.task_id == task_id)
            )
            by_dsh = session.scalar(
                select(InteractionSessionLink).where(
                    InteractionSessionLink.dsh_session_id == dsh_session_id
                )
            )
            if existing and existing.dsh_session_id != dsh_session_id:
                raise ValueError("task already has a primary DSH session")
            if by_dsh and by_dsh.task_id != task_id:
                previous_task = session.get(AnalysisTask, by_dsh.task_id)
                if previous_task is None or previous_task.lifecycle not in {
                    TaskLifecycle.SUCCEEDED.value,
                    TaskLifecycle.FAILED.value,
                    TaskLifecycle.CANCELLED.value,
                }:
                    raise ValueError("DSH session is already linked to another active task")
                # A session may explicitly start a new analysis after an old
                # terminal task. Reuse the legacy compatibility row while the
                # ThreatAnalysisContext projection remains the source of truth.
                by_dsh.task_id = task.id
                by_dsh.case_id = task.case_id
                by_dsh.status = "ACTIVE"
                by_dsh.trajectory_status = "LIVE"
                by_dsh.updated_at = utcnow()
            row = existing or by_dsh
            if row is None:
                row = InteractionSessionLink(
                    case_id=task.case_id,
                    task_id=task.id,
                    dsh_session_id=dsh_session_id,
                    profile=profile,
                )
                session.add(row)
                # The audit event requires the generated link identifier. Flush
                # the link before appending the immutable audit record so the
                # workbench session mapping is always traceable.
                session.flush()
                self._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type="workbench.session_linked",
                    actor="dsh",
                    object_type="InteractionSessionLink",
                    object_id=row.id,
                    payload={"dsh_session_id": dsh_session_id, "profile": profile},
                )
            elif row.profile != profile:
                raise ValueError("existing DSH session link uses a different profile")
            # Keep the new server-authoritative context projection in sync for
            # legacy callers that still link an already-created task.
            context = session.scalar(
                select(ThreatAnalysisContextRecord).where(
                    ThreatAnalysisContextRecord.dsh_session_id == dsh_session_id
                )
            )
            if context is None:
                context = ThreatAnalysisContextRecord(dsh_session_id=dsh_session_id)
                session.add(context)
                session.flush()
            task_artifacts = list(
                session.scalars(select(Artifact).where(Artifact.task_id == task.id))
            )
            context.case_id = task.case_id
            context.active_task_id = task.id
            context.attached_artifact_ids = [item.id for item in task_artifacts]
            context.selected_artifact_id = task_artifacts[0].id if task_artifacts else None
            context.task_lifecycle = task.lifecycle
            context.analysis_class = task.analysis_class
            context.task_outcome = task.outcome
            context.state = self._context_state_for_task(task, [item.id for item in task_artifacts])
            context.binding_version += 1
            context.bound_at = context.bound_at or utcnow()
            context.updated_at = utcnow()
            return {
                "id": row.id,
                "case_id": row.case_id,
                "task_id": row.task_id,
                "dsh_session_id": row.dsh_session_id,
                "profile": row.profile,
                "status": row.status,
                "trajectory_status": row.trajectory_status,
                "last_backend_event_seq": row.last_backend_event_seq,
            }

    def workbench_session_link(self, task_id: str) -> dict[str, object] | None:
        with self.database.session_factory() as session:
            if session.get(AnalysisTask, task_id) is None:
                raise LookupError(task_id)
            row = session.scalar(
                select(InteractionSessionLink).where(InteractionSessionLink.task_id == task_id)
            )
            if row is None:
                return None
            return {
                "id": row.id,
                "case_id": row.case_id,
                "task_id": row.task_id,
                "dsh_session_id": row.dsh_session_id,
                "profile": row.profile,
                "status": row.status,
                "trajectory_status": row.trajectory_status,
                "last_backend_event_seq": row.last_backend_event_seq,
            }

    def workbench_task_for_session(self, dsh_session_id: str) -> dict[str, object] | None:
        """Resolve the authoritative task bound to one DSH session.

        The DSH agent runtime owns the session id; it must not need to guess a
        backend task id in every tool call.  Returning only the existing link
        keeps this lookup task-scoped and prevents session enumeration from
        becoming a task discovery API.
        """
        if not dsh_session_id.strip():
            raise ValueError("dsh_session_id must not be empty")
        with self.database.session_factory() as session:
            context = session.scalar(
                select(ThreatAnalysisContextRecord).where(
                    ThreatAnalysisContextRecord.dsh_session_id == dsh_session_id.strip()
                )
            )
            if context is not None and context.active_task_id:
                task = session.get(AnalysisTask, context.active_task_id)
                if task is not None:
                    return {
                        "id": context.id,
                        "case_id": task.case_id,
                        "task_id": task.id,
                        "dsh_session_id": context.dsh_session_id,
                        "profile": "threat-static",
                        "status": "ACTIVE",
                        "trajectory_status": context.state,
                        "last_backend_event_seq": 0,
                    }
            return None

    def workbench_case(self, case_id: str) -> dict[str, object]:
        with self.database.session_factory() as session:
            case = session.get(CaseRecord, case_id)
            if case is None:
                raise LookupError(case_id)
            tasks = list(
                session.scalars(
                    select(AnalysisTask)
                    .where(AnalysisTask.case_id == case_id)
                    .order_by(AnalysisTask.created_at.desc())
                )
            )
            return {
                "schema_version": 1,
                "id": case.id,
                "title": case.title,
                "status": case.status,
                "created_at": case.created_at.isoformat(),
                "tasks": [
                    {
                        "id": task.id,
                        "lifecycle": task.lifecycle,
                        "outcome": task.outcome,
                        "created_at": task.created_at.isoformat(),
                        "finished_at": task.finished_at.isoformat() if task.finished_at else None,
                    }
                    for task in tasks
                ],
            }

    def workbench_artifact(self, artifact_id: str) -> dict[str, object]:
        with self.database.session_factory() as session:
            artifact = session.get(Artifact, artifact_id)
            if artifact is None:
                raise LookupError(artifact_id)
            task = session.get(AnalysisTask, artifact.task_id)
            if task is None:
                raise LookupError(artifact_id)
            # Return a bounded evidence index; full values remain available via
            # the dedicated evidence query/detail endpoints.
            evidence = list(
                session.scalars(
                    select(Evidence)
                    .where(Evidence.artifact_id == artifact_id)
                    .order_by(Evidence.created_at, Evidence.id)
                    .limit(200)
                )
            )
            return {
                "schema_version": 1,
                "id": artifact.id,
                "task_id": task.id,
                "logical_path": artifact.logical_path,
                "sha256": artifact.content_sha256,
                "detected_type": artifact.detected_type,
                "role": artifact.role,
                "obligation": artifact.obligation,
                "parent_artifact_id": artifact.parent_artifact_id,
                "metadata": artifact.metadata_json,
                "disposed": artifact.disposed_at is not None,
                "evidence": [
                    {
                        "id": item.id,
                        "module": item.module,
                        "kind": item.kind,
                        "nature": item.nature,
                        "anchor": item.anchor,
                    }
                    for item in evidence
                ],
                "evidence_truncated": len(evidence) >= 200,
            }

    @staticmethod
    def _workbench_payload_summary(payload: object) -> dict[str, object]:
        """Keep DSH events small and prevent raw evidence from entering Session."""
        if not isinstance(payload, dict):
            return {}
        allowed = {
            "action_type", "status", "state", "hypothesis_status", "gate_status",
            "evidence_count", "evidence_ids", "action_id", "thread_id", "hypothesis_id",
            "mechanism_id", "claim_id", "relation_id", "report_revision_id", "reason",
            "missing", "contradictions", "tool", "model", "provider", "profile",
        }
        result: dict[str, object] = {}
        for key in allowed:
            value = payload.get(key)
            if value is None:
                continue
            if key == "evidence_ids" and isinstance(value, list):
                result[key] = [str(item) for item in value[:32]]
            elif isinstance(value, (str, int, float, bool, list, dict)):
                result[key] = value
        return result

    def workbench_events(self, task_id: str, *, after_seq: int = 0, limit: int = 500) -> dict[str, object]:
        if after_seq < 0:
            raise ValueError("after_seq must be non-negative")
        limit = max(1, min(limit, 1000))
        with self.database.session_factory() as session:
            task = session.get(AnalysisTask, task_id)
            if task is None:
                raise LookupError(task_id)
            rows = list(
                session.scalars(
                    select(AuditEvent)
                    .where(AuditEvent.task_id == task_id, AuditEvent.chain_sequence > after_seq)
                    .order_by(AuditEvent.chain_sequence)
                    .limit(limit)
                )
            )
            events = [
                {
                    "seq": event.chain_sequence,
                    "task_id": task_id,
                    "timestamp": event.created_at.isoformat(),
                    "type": event.event_type,
                    "entity_id": event.object_id,
                    "payload_summary": self._workbench_payload_summary(event.payload),
                    "trace_id": event.trace_id,
                }
                for event in rows
            ]
            next_seq = events[-1]["seq"] if events else after_seq
            return {
                "schema_version": 1,
                "task_id": task_id,
                "events": events,
                "next_seq": next_seq,
                "has_more": len(rows) == limit,
            }

    def workbench_capabilities(self) -> dict[str, object]:
        actions = []
        catalog = ActionCatalog.default()
        for name in catalog.names():
            actions.append(
                {
                    "name": name,
                    "description": f"Bounded read-only static investigation action: {name}",
                    "input_schema": {"type": "object", "additionalProperties": True},
                    "output_schema": {"type": "object", "additionalProperties": True},
                    "security_class": "READ_ONLY_STATIC",
                    "estimated_cost": catalog.require(name).cost_units,
                }
            )
        model_callable_tools = [
            "threat_get_capabilities",
            "threat_get_session_analysis_context",
            "threat_list_session_artifacts",
            "threat_list_session_workspace_artifacts",
            "threat_import_workspace_artifact",
            "threat_start_static_analysis",
            "threat_get_analysis_status",
            "threat_wait_for_analysis_update",
            "threat_propose_static_action",
            "threat_get_action_result",
            "threat_query_current_analysis_evidence",
            "threat_get_thread_summary",
            "threat_get_mechanism",
            "threat_get_report_summary",
            "threat_bind_existing_analysis",
            "threat_unbind_analysis",
        ]
        return {
            "api_version": 1,
            # ``actions`` is retained for API v1 clients.  New model callers
            # must use the single policy-gated proposal tool below.
            "actions": actions,
            "backend_static_action_catalog": actions,
            "model_callable_tools": [
                {"name": name, "security_class": "SESSION_SCOPED_STATIC"}
                for name in model_callable_tools
            ],
            "action_submission_tool": "threat_propose_static_action",
            "unavailable_capabilities": ["sample_execution", "network_access", "arbitrary_shell"],
            "workspace": {
                "supported": bool(str(getattr(self.settings, "workbench_workspace_root", "") or "").strip()),
                "root_token": "configured-read-only-root" if str(getattr(self.settings, "workbench_workspace_root", "") or "").strip() else None,
                "path_mode": "workspace_relative",
            },
            "profiles": ["threat-static"],
            "tool_contract_version": self.THREAT_TOOL_CONTRACT_VERSION,
            "session_context_protocol": self.THREAT_CONTEXT_PROTOCOL,
            "capability_profile": "threat-static",
            "static_only": True,
            "sample_execution": False,
            "network_access": False,
        }

    def workbench_query_current_evidence(
        self,
        dsh_session_id: str,
        *,
        kind: str | None = None,
        module: str | None = None,
        artifact_id: str | None = None,
        limit: int = 100,
    ) -> dict[str, object]:
        context = self.workbench_analysis_context_v3(dsh_session_id)
        task_id = context.get("active_task_id")
        if not task_id:
            return {
                "schema_version": 1,
                "session_id": dsh_session_id,
                "state": context.get("state", "UNBOUND"),
                "code": "NO_ACTIVE_ANALYSIS",
                "items": [],
                "limit": max(1, min(int(limit), 500)),
            }
        result = self.workbench_query_evidence(
            task_id=str(task_id), kind=kind, module=module, artifact_id=artifact_id, limit=limit
        )
        return {**result, "session_id": dsh_session_id, "state": context.get("state")}

    def workbench_query_evidence(
        self,
        *,
        task_id: str,
        kind: str | None = None,
        module: str | None = None,
        artifact_id: str | None = None,
        limit: int = 100,
    ) -> dict[str, object]:
        limit = max(1, min(limit, 500))
        with self.database.session_factory() as session:
            if session.get(AnalysisTask, task_id) is None:
                raise LookupError(task_id)
            query = select(Evidence).where(Evidence.task_id == task_id)
            if kind:
                query = query.where(Evidence.kind == kind)
            if module:
                query = query.where(Evidence.module == module)
            if artifact_id:
                query = query.where(Evidence.artifact_id == artifact_id)
            rows = list(session.scalars(query.order_by(Evidence.created_at, Evidence.id).limit(limit)))
            return {
                "task_id": task_id,
                "items": [
                    {
                        "id": row.id,
                        "artifact_id": row.artifact_id,
                        "module": row.module,
                        "kind": row.kind,
                        "nature": row.nature,
                        "value": row.value,
                        "anchor": row.anchor,
                    }
                    for row in rows
                ],
                "limit": limit,
            }

    def workbench_domain_view(self, task_id: str) -> dict[str, object]:
        """Stable, bounded projection for DSH views.

        This endpoint is polled by the workbench tabs.  It must not call
        ``task_view`` because that projection intentionally materializes every
        Evidence row for export and can contain tens of thousands of rows.
        Raw evidence remains available through the paginated query endpoint.
        """
        with self.database.session_factory() as session:
            task = session.get(AnalysisTask, task_id)
            if task is None:
                raise LookupError(task_id)
            failure = session.scalar(
                select(AnalysisFailureRecord).where(AnalysisFailureRecord.task_id == task.id)
            )
            case = session.get(CaseRecord, task.case_id)
            artifacts = list(
                session.scalars(
                    select(Artifact)
                    .where(Artifact.task_id == task_id)
                    .order_by(Artifact.created_at, Artifact.id)
                )
            )
            threads = list(
                session.scalars(
                    select(InvestigationThreadRecord)
                    .where(InvestigationThreadRecord.task_id == task_id)
                    .order_by(InvestigationThreadRecord.created_at, InvestigationThreadRecord.id)
                )
            )
            hypotheses = list(
                session.scalars(
                    select(InvestigationHypothesisRecord)
                    .where(InvestigationHypothesisRecord.task_id == task_id)
                    .order_by(InvestigationHypothesisRecord.created_at, InvestigationHypothesisRecord.id)
                )
            )
            actions = list(
                session.scalars(
                    select(InvestigationActionRecord)
                    .where(InvestigationActionRecord.task_id == task_id)
                    .order_by(InvestigationActionRecord.created_at, InvestigationActionRecord.id)
                )
            )
            claims_rows = list(
                session.scalars(
                    select(Claim).where(Claim.task_id == task_id).order_by(Claim.created_at, Claim.id)
                )
            )
            claim_evidence = list(
                session.scalars(
                    select(ClaimEvidence)
                    .join(Claim, Claim.id == ClaimEvidence.claim_id)
                    .where(Claim.task_id == task_id)
                )
            )
            evidence_by_claim: dict[str, list[str]] = {}
            for link in claim_evidence:
                if link.stance == "SUPPORTS":
                    evidence_by_claim.setdefault(link.claim_id, []).append(link.evidence_id)
            claims = [
                {
                    "id": item.id,
                    "module": item.module,
                    "claim_type": item.claim_type,
                    "subject": item.subject,
                    "action": item.action,
                    "object": item.object,
                    "mechanism": item.mechanism,
                    "condition": item.condition,
                    "nature": item.nature,
                    "statement": item.statement,
                    "status": item.status,
                    "confidence": item.confidence,
                    "attack_mapping": item.attack_mapping,
                    "model_call_id": item.model_call_id,
                    "evidence_ids": evidence_by_claim.get(item.id, []),
                }
                for item in claims_rows
            ]
            relations_rows = list(
                session.scalars(
                    select(Relation).where(Relation.task_id == task_id).order_by(Relation.created_at, Relation.id)
                )
            )
            relations = [
                {
                    "id": item.id,
                    "source_artifact_id": item.source_artifact_id,
                    "target_artifact_id": item.target_artifact_id,
                    "relation_type": item.relation_type,
                    "evidence_id": item.evidence_id,
                    "claim_id": item.claim_id,
                    "status": item.status,
                }
                for item in relations_rows
            ]
            revisions = list(
                session.scalars(
                    select(ReportRevision)
                    .where(ReportRevision.task_id == task_id)
                    .order_by(ReportRevision.created_at.desc(), ReportRevision.id.desc())
                )
            )
            artifact_payload = [
                {
                    "id": item.id,
                    "logical_path": item.logical_path,
                    "sha256": item.content_sha256,
                    "detected_type": item.detected_type,
                    "role": item.role,
                    "obligation": item.obligation,
                    "parent_artifact_id": item.parent_artifact_id,
                    "disposed": item.disposed_at is not None,
                }
                for item in artifacts
            ]
            thread_payload = [
                {
                    "id": item.id,
                    "artifact_id": item.artifact_id,
                    "state": item.state,
                    "question": item.question,
                    "seed_kind": item.seed_kind,
                    "evidence_ids": item.evidence_ids,
                    "hypothesis_ids": item.hypothesis_ids,
                    "action_ids": item.action_ids,
                    "transition_count": item.transition_count,
                }
                for item in threads
            ]
            hypothesis_payload = [
                {
                    "id": item.id,
                    "thread_id": item.thread_id,
                    "statement": item.statement,
                    "dimension": item.dimension,
                    "status": item.status,
                    "confidence": item.confidence,
                    "evidence_ids": item.evidence_ids,
                    "required_evidence": item.required_evidence,
                }
                for item in hypotheses
            ]
            action_payload = [self._action_payload(item) for item in actions]
            task_payload = {
                "id": task.id,
                "case_id": task.case_id,
                "case_title": case.title if case else "",
                "trace_id": task.trace_id,
                "lifecycle": task.lifecycle,
                "outcome": task.outcome,
                "target_granularity": {"breadth": task.target_breadth, "depth": task.target_depth},
                "actual_granularity": task.actual_granularity,
                "limitations": task.limitations,
                "latest_report_revision_id": revisions[0].id if revisions else None,
                "created_at": task.created_at.isoformat(),
                "started_at": task.started_at.isoformat() if task.started_at else None,
                "finished_at": task.finished_at.isoformat() if task.finished_at else None,
                "elapsed_ms": self._elapsed_ms(task),
                "server_time": utcnow().isoformat(),
                "failure": self._failure_payload(failure),
            }
            strategy = task.strategy_snapshot or {}
            strategy_investigation = (
                strategy.get("investigation", {})
                if isinstance(strategy, dict)
                else {}
            )
            snapshot_mechanisms = [
                dict(item)
                for item in (
                    strategy_investigation.get("mechanisms", [])
                    if isinstance(strategy_investigation, dict)
                    else []
                )
                if isinstance(item, dict)
            ]
        result = {
            "schema_version": 1,
            "task": task_payload,
            "artifacts": artifact_payload,
            "threads": thread_payload,
            "hypotheses": hypothesis_payload,
            "actions": action_payload,
            # Claims are the normal domain source, but specialist investigation
            # results are also persisted in the task snapshot.  Include both
            # projections so a verified mechanism is not hidden merely because
            # its Claim is materialized in a later transaction or has no
            # human-facing mechanism text yet.
            "mechanisms": [],
            "claims": claims,
            "relations": relations,
            "sample_timeline": [],
            "report": {
                "revision_id": revisions[0].id if revisions else None,
                "available": bool(revisions),
            },
        }
        mechanism_rows: list[dict[str, object]] = []
        by_mechanism_key: dict[str, dict[str, object]] = {}
        for candidate in snapshot_mechanisms:
            if not isinstance(candidate, dict):
                continue
            key = str(candidate.get("mechanism_id") or candidate.get("id") or "")
            if not key:
                continue
            current = by_mechanism_key.get(key)
            if current is None:
                current = dict(candidate)
                by_mechanism_key[key] = current
                mechanism_rows.append(current)
                continue
            for field, value in candidate.items():
                if value not in (None, "", [], {}):
                    current[field] = value
        for candidate in claims:
            if not isinstance(candidate, dict) or not candidate.get("mechanism"):
                continue
            key = str(
                candidate.get("mechanism_id")
                or candidate.get("id")
                or candidate.get("claim_id")
            )
            current = by_mechanism_key.get(key)
            if current is None:
                current = dict(candidate)
                by_mechanism_key[key] = current
                mechanism_rows.append(current)
                continue
            # Merge non-empty fields from the second projection without
            # downgrading a verified status or replacing rich fields with
            # empty/placeholder values.
            for field, value in candidate.items():
                if value in (None, "", [], {}):
                    continue
                if field == "status" and str(current.get(field, "")).upper() in {
                    "VERIFIED", "SUPPORTED", "CONFIRMED"
                }:
                    continue
                if field in {"evidence_ids", "claim_ids"}:
                    current[field] = list(dict.fromkeys([
                        *(
                            item for item in current.get(field, [])
                            if item
                        ),
                        *(item for item in value if item),
                    ]))
                else:
                    current[field] = value
        result["mechanisms"] = mechanism_rows[:128]
        # ``task_view`` intentionally contains the strategy/runtime records
        # needed for the audit trace, while the compact Workbench task
        # projection omits them.  Build the timeline once here so both the
        # aggregate view and the dedicated collection endpoint expose the same
        # bounded, non-sensitive sequence.
        investigation_state = strategy.get("investigation", {}) if isinstance(strategy, dict) else {}
        timeline: list[dict[str, object]] = []
        if isinstance(investigation_state, dict):
            for item in investigation_state.get("seed_rankings", []):
                if isinstance(item, dict):
                    timeline.append({
                        "phase": "DISCOVERED->PRIORITIZED",
                        "artifact_id": item.get("artifact_id"),
                        "priority": item.get("priority"),
                        "question": item.get("question"),
                        "rationale": item.get("rationale"),
                    })
            runtime = investigation_state.get("runtime", {})
            if isinstance(runtime, dict):
                for item in runtime.get("events", []):
                    if isinstance(item, dict):
                        timeline.append({
                            "phase": str(item.get("phase", "investigation")),
                            "state": item.get("state"),
                            "action_id": item.get("action_id"),
                            "evidence_ids": list(item.get("evidence_ids", [])),
                            "message": item.get("message"),
                        })
        for claim in claims:
            if isinstance(claim, dict) and claim.get("mechanism"):
                timeline.append({
                    "phase": "MECHANISM_READY->CLAIM_READY",
                    "claim_id": claim.get("id"),
                    "module": claim.get("module"),
                    "action": claim.get("action"),
                    "status": claim.get("status"),
                    "confidence": claim.get("confidence"),
                    "evidence_ids": list(claim.get("evidence_ids", [])),
                })
        for relation in relations:
            if isinstance(relation, dict):
                timeline.append({
                    "phase": "CLAIM_READY->RELATION",
                    "relation_id": relation.get("id"),
                    "relation": relation.get("relation_type"),
                    "status": relation.get("status"),
                    "evidence_id": relation.get("evidence_id"),
                    "claim_id": relation.get("claim_id"),
                })
        result["sample_timeline"] = timeline[:256]
        return result

    def workbench_submit_action(self, task_id: str, payload: dict[str, object]) -> dict[str, object]:
        """Accept a human/DSH action only through the closed static catalog.

        The action is persisted as a proposal and executed by the existing
        evidence-driven investigation loop on the next task cycle.  No DSH
        caller receives a direct worker or subprocess handle.
        """
        try:
            action_type = ActionType(str(payload.get("action_type", "")))
        except ValueError as exc:
            raise ValueError("action_type is not in the static Action Catalog") from exc
        target_artifact_id = str(payload.get("target_artifact_id", ""))
        selector = payload.get("target_selector")
        if not target_artifact_id or not isinstance(selector, dict) or not selector:
            raise ValueError("target_artifact_id and target_selector are required")
        expected = payload.get("expected_evidence_kinds")
        if not isinstance(expected, list) or not expected:
            raise ValueError("expected_evidence_kinds are required")
        action_id: str | None = None
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id)
            if task is None:
                raise LookupError(task_id)
            artifact = session.get(Artifact, target_artifact_id)
            if artifact is None or artifact.task_id != task.id:
                raise ValueError("target artifact does not belong to task")
            definition = ActionCatalog.default().require(action_type)
            if definition.sample_execution or definition.network_access:
                raise ValueError("unsafe action is not available in threat-static")
            if set(selector) - set(definition.selector_keys):
                raise ValueError("target selector contains unsupported keys")
            action_id = f"{task.id}:dsh:{hashlib.sha256(self._canonical_json(payload).encode()).hexdigest()[:24]}"
            existing = session.get(InvestigationActionRecord, action_id)
            if existing is not None:
                return {"id": existing.id, "status": existing.status, "deduplicated": True}
            threads = list(session.scalars(select(InvestigationThreadRecord).where(InvestigationThreadRecord.task_id == task.id, InvestigationThreadRecord.artifact_id == artifact.id)))
            if not threads:
                # A Workbench action may arrive before the asynchronous
                # analysis loop has initialized its investigation records.
                # Create the same deterministic thread/hypothesis pair used
                # by the loop so the proposal can be executed immediately.
                thread_id = f"thread-{hashlib.sha256(f'{task.id}:{artifact.id}'.encode()).hexdigest()[:20]}"
                hypothesis_id = f"hypothesis-{hashlib.sha256(f'{thread_id}:mechanism'.encode()).hexdigest()[:20]}"
                thread = InvestigationThreadRecord(
                    id=thread_id,
                    task_id=task.id,
                    artifact_id=artifact.id,
                    state="DISCOVERED",
                    question="Which evidence explains the artifact's highest-risk static mechanism?",
                    seed_kind="workbench_action",
                    hypothesis_ids=[hypothesis_id],
                )
                session.add(thread)
                session.flush()
                session.add(
                    InvestigationHypothesisRecord(
                        id=hypothesis_id,
                        task_id=task.id,
                        thread_id=thread.id,
                        statement="The artifact may contain an ordered static mechanism.",
                        dimension="mechanism_discovery",
                        status="OPEN",
                        confidence="LOW",
                        required_evidence=list(payload.get("expected_evidence_kinds", []))[:32],
                    )
                )
                session.flush()
                threads = [thread]
            thread = threads[0]
            hypothesis_id = str(payload.get("hypothesis_id") or (thread.hypothesis_ids or [""])[0])
            hypothesis = session.get(InvestigationHypothesisRecord, hypothesis_id)
            if hypothesis is None or hypothesis.thread_id != thread.id:
                raise ValueError("hypothesis does not belong to artifact investigation thread")
            row = InvestigationActionRecord(
                id=action_id,
                task_id=task.id,
                thread_id=thread.id,
                hypothesis_id=hypothesis.id,
                artifact_id=artifact.id,
                action_type=action_type.value,
                reason=str(payload.get("reason", "DSH analyst proposal"))[:2000],
                parameters=dict(selector),
                target_selector=dict(selector),
                expected_evidence_kinds=[str(item) for item in expected[:32]],
                success_condition=str(payload.get("success_condition", "new_targeted_evidence"))[:160],
                failure_interpretation=str(payload.get("failure_interpretation", "UNKNOWN")),
                cost_units=definition.cost_units,
                priority=20,
                status="QUEUED",
            )
            session.add(row)
            thread.action_ids = list(dict.fromkeys([*(thread.action_ids or []), row.id]))
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="workbench.action_proposed",
                actor="dsh",
                object_type="InvestigationAction",
                object_id=row.id,
                payload={"action_type": row.action_type, "target_artifact_id": row.artifact_id},
            )
            result = {"id": row.id, "task_id": task.id, "thread_id": row.thread_id, "status": row.status, "action_type": row.action_type}

        # The database row is committed before the executor is entered.  This
        # keeps the public API transaction short and makes the exact same
        # policy-checked static executor serve DSH, human, and model proposals.
        # No sample bytes are executed and no worker handle is exposed here.
        if action_id:
            try:
                self._run_investigation_loop(task_id, model_actions_only=True)
            except Exception as exc:
                # Execution failures are persisted by the loop as FAILED
                # actions; return the durable state rather than leaking an
                # internal exception through the DSH contract.
                result["execution_error"] = type(exc).__name__
            # A targeted action is a first-class investigation turn.  Once it
            # has produced durable Evidence, refresh the immutable analysis
            # snapshot and create a child ReportRevision so the Workbench and
            # exported report see the same semantic result.  This deliberately
            # happens after the executor transaction has committed.
            try:
                refreshed = self._refresh_report_after_investigation(task_id)
                if refreshed:
                    result.update(refreshed)
            except Exception as exc:
                # Report generation must never hide the durable action result;
                # retain an auditable diagnostic for the client instead.
                result["report_refresh_error"] = type(exc).__name__
            return self.workbench_action(action_id) | {"accepted": True, **result}
        return result

    def _refresh_report_after_investigation(
        self,
        task_id: str,
        *,
        author: str = "investigation-agent",
    ) -> dict[str, object]:
        """Materialize post-action Evidence into a new immutable report.

        Workbench actions are intentionally append-only.  Reusing the old
        snapshot would make newly recovered arguments, call paths, or decode
        results visible in chat but absent from the report export.  This helper
        creates a new snapshot and revision while retaining the previous
        revision as ``parent_revision_id``.
        """
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if task is None:
                raise LookupError(task_id)
            self._materialize_mechanism_snapshot(session, task)
            latest = session.scalar(
                select(ReportRevision)
                .where(ReportRevision.task_id == task.id)
                .order_by(ReportRevision.created_at.desc(), ReportRevision.id.desc())
            )
            modules = list(latest.selected_modules) if latest and latest.selected_modules else list(task.selected_modules or REPORT_MODULES)
            snapshot = self._freeze_snapshot(session, task)
            revision = self._create_report_revision(
                session,
                task,
                snapshot,
                normalize_modules(modules),
                parent_revision_id=latest.id if latest else None,
                author=author,
            )
            return {
                "report_revision_id": revision.id,
                "snapshot_id": snapshot.id,
                "report_refreshed": True,
            }

    def workbench_submit_session_action(
        self,
        dsh_session_id: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        """Submit a bounded static action using only the session's active task."""
        context = self.workbench_analysis_context_v3(dsh_session_id)
        task_id = context.get("active_task_id")
        if not task_id:
            raise ValueError("NO_ACTIVE_ANALYSIS")
        body = dict(payload)
        body.pop("task_id", None)
        result = self.workbench_submit_action(str(task_id), body)
        return {**result, "session_id": dsh_session_id, "context_revision": context.get("context_revision")}

    @staticmethod
    def _action_payload(row: InvestigationActionRecord) -> dict[str, object]:
        return {
            "id": row.id,
            "task_id": row.task_id,
            "thread_id": row.thread_id,
            "hypothesis_id": row.hypothesis_id,
            "artifact_id": row.artifact_id,
            "action_type": row.action_type,
            "reason": row.reason,
            "parameters": row.parameters,
            "target_selector": row.target_selector,
            "expected_evidence_kinds": row.expected_evidence_kinds,
            "success_condition": row.success_condition,
            "failure_interpretation": row.failure_interpretation,
            "cost_units": row.cost_units,
            "priority": row.priority,
            "status": row.status,
            "attempts": row.attempts,
            "depends_on": row.depends_on,
            "result_evidence_ids": row.result_evidence_ids,
            "error": row.error,
            "created_at": row.created_at.isoformat(),
            "finished_at": row.finished_at.isoformat() if row.finished_at else None,
        }

    def workbench_action(self, action_id: str) -> dict[str, object]:
        """Return one task-owned action and its bounded execution result."""
        with self.database.session_factory() as session:
            row = session.get(InvestigationActionRecord, action_id)
            if row is None:
                raise LookupError(action_id)
            task = session.get(AnalysisTask, row.task_id)
            if task is None:
                raise LookupError(action_id)
            payload = self._action_payload(row)
            payload["schema_version"] = 1
            latest_revision = session.scalar(
                select(ReportRevision)
                .where(ReportRevision.task_id == task.id)
                .order_by(ReportRevision.created_at.desc(), ReportRevision.id.desc())
            )
            payload["report_revision_id"] = latest_revision.id if latest_revision else None
            evidence_rows = list(
                session.scalars(
                    select(Evidence).where(Evidence.id.in_(row.result_evidence_ids or []))
                )
            ) if row.result_evidence_ids else []
            payload["evidence"] = [
                {
                    "id": evidence.id,
                    "kind": evidence.kind,
                    "nature": evidence.nature,
                    "value": evidence.value,
                    "anchor": evidence.anchor,
                }
                for evidence in evidence_rows
            ]
            payload["semantic_result"] = self._semantic_action_result(
                row.action_type, evidence_rows
            )
            return payload

    @staticmethod
    def _semantic_action_result(
        action_type: str,
        evidence_rows: list[Evidence],
    ) -> dict[str, object]:
        """Return a compact, action-specific result for analyst clients.

        Evidence IDs remain the provenance authority.  This projection gives
        DSH a useful answer without requiring it to dereference opaque ledger
        rows or infer semantics from raw instruction dumps.
        """
        values = [item.value for item in evidence_rows if isinstance(item.value, dict)]
        action = str(action_type).upper()
        if action in {ActionType.GET_CALLERS.value, ActionType.GET_CALLEES.value, ActionType.GET_XREFS_TO.value, ActionType.GET_XREFS_FROM.value}:
            edges: list[dict[str, object]] = []
            for value in values:
                edge = {
                    key: value[key]
                    for key in ("caller", "callee", "source", "referenced_target", "api", "callsite", "from", "to", "edge", "direction")
                    if value.get(key) is not None
                }
                if edge:
                    edges.append(edge)
            return {"kind": "call_graph_edges", "edges": edges[:128], "count": len(edges)}
        if action == ActionType.TRACE_API_ARGUMENT.value:
            return {"kind": "api_argument_trace", "traces": values[:64], "count": len(values)}
        if action == ActionType.DECODE_CANDIDATE.value:
            return {"kind": "decode_results", "results": values[:32], "count": len(values)}
        if action == ActionType.GET_PCODE_SLICE.value:
            slices = []
            for value in values:
                slices.append({
                    "source": value.get("source") or value.get("inputs") or value.get("function"),
                    "sinks": value.get("sinks") or value.get("outputs") or value.get("consumers"),
                    "critical_operations": value.get("critical_operations") or value.get("operations") or value.get("steps"),
                    "conditions": value.get("conditions") or value.get("path_conditions"),
                    "unknowns": value.get("unknowns") or value.get("limitations"),
                    "evidence_id": next((item.id for item in evidence_rows if item.value is value), None),
                })
            return {"kind": "pcode_slice", "slices": slices[:32], "count": len(slices)}
        return {
            "kind": "evidence_projection",
            "observations": [
                {"evidence_id": item.id, "kind": item.kind, "value": item.value, "anchor": item.anchor}
                for item in evidence_rows[:64]
            ],
            "count": len(evidence_rows),
        }

    def workbench_action_for_task(self, task_id: str, action_id: str) -> dict[str, object]:
        """Task-scoped Action detail used by nested Workbench routes."""
        with self.database.session_factory() as session:
            if session.get(AnalysisTask, task_id) is None:
                raise LookupError(task_id)
            row = session.get(InvestigationActionRecord, action_id)
            if row is None or row.task_id != task_id:
                raise LookupError(action_id)
        return self.workbench_action(action_id)

    def workbench_thread(self, thread_id: str) -> dict[str, object]:
        with self.database.session_factory() as session:
            row = session.get(InvestigationThreadRecord, thread_id)
            if row is None:
                raise LookupError(thread_id)
            task = session.get(AnalysisTask, row.task_id)
            if task is None:
                raise LookupError(thread_id)
            hypothesis_rows = list(session.scalars(select(InvestigationHypothesisRecord).where(InvestigationHypothesisRecord.thread_id == row.id)))
            action_rows = list(session.scalars(select(InvestigationActionRecord).where(InvestigationActionRecord.thread_id == row.id).order_by(InvestigationActionRecord.created_at)))
            return {
                "schema_version": 1,
                "id": row.id,
                "task_id": row.task_id,
                "artifact_id": row.artifact_id,
                "state": row.state,
                "question": row.question,
                "seed_kind": row.seed_kind,
                "evidence_ids": row.evidence_ids,
                "transition_count": row.transition_count,
                "hypotheses": [
                    {"id": item.id, "statement": item.statement, "dimension": item.dimension, "status": item.status, "confidence": item.confidence, "evidence_ids": item.evidence_ids, "required_evidence": item.required_evidence}
                    for item in hypothesis_rows
                ],
                "actions": [self._action_payload(item) for item in action_rows],
            }

    def workbench_collection(self, task_id: str, name: str) -> dict[str, object]:
        """Return a bounded stable projection for one domain result collection."""
        view = self.workbench_domain_view(task_id)
        if name not in {"mechanisms", "claims", "relations", "sample_timeline"}:
            raise ValueError(f"unsupported workbench collection: {name}")
        items = list(view.get(name, []))
        payload = {"schema_version": 1, "task_id": task_id, "items": items}
        # Named aliases make the projection ergonomic for clients while
        # retaining the common ``items`` envelope used by all collections.
        payload[name] = items
        return payload

    def workbench_model_complete(self, payload: dict[str, object]) -> dict[str, object]:
        """Invoke the configured model gateway on behalf of a DSH session.

        DSH supplies correlation metadata and messages, but cannot select an
        arbitrary response schema or provider. The existing gateway remains
        the only network/model execution path and its attempts are persisted
        through the normal audit model.
        """
        session_id = self._require_session_id(str(payload.get("session_id", "")))
        requested_task_id = str(payload.get("task_id", "")).strip()
        case_id = str(payload.get("case_id", ""))
        with self.database.session_factory() as session:
            context = session.scalar(
                select(ThreatAnalysisContextRecord).where(
                    ThreatAnalysisContextRecord.dsh_session_id == session_id
                )
            )
            bound_task_id = str(context.active_task_id) if context and context.active_task_id else ""
            if requested_task_id and requested_task_id != bound_task_id:
                raise ContextMismatchError(
                    "CONTEXT_MISMATCH: task is not bound to this session"
                )
            task_id = requested_task_id or bound_task_id
            if not task_id:
                raise ValueError("NO_ACTIVE_ANALYSIS: start an analysis before invoking the model")
            task = session.get(AnalysisTask, task_id)
            if task is None or task.case_id != case_id:
                raise LookupError(task_id)
        raw_messages = payload.get("messages")
        if not isinstance(raw_messages, list) or not raw_messages:
            raise ValueError("messages are required")
        messages: list[dict[str, str]] = []
        for item in raw_messages[:32]:
            if not isinstance(item, dict) or item.get("role") not in {"system", "user", "assistant"}:
                raise ValueError("messages contain an invalid role")
            content = str(item.get("content", ""))
            if not content or len(content.encode("utf-8")) > self.settings.model_context_max_bytes:
                raise ValueError("message content exceeds the model context limit")
            messages.append({"role": str(item["role"]), "content": content})
        operation = str(payload.get("operation", ""))
        schema = {
            "planning": DynamicPlanEnvelope,
            "claims": AtomicClaimEnvelope,
        }.get(operation)
        if schema is None:
            raise ValueError("operation must be planning or claims")
        prompt = SimpleNamespace(
            id=str(payload.get("prompt_id", "dsh"))[:120],
            version=str(payload.get("prompt_version", "1"))[:80],
            sha256=str(payload.get("prompt_sha256", "")),
        )
        if len(prompt.sha256) != 64 or any(char not in "0123456789abcdefABCDEF" for char in prompt.sha256):
            raise ValueError("prompt_sha256 must be a SHA-256 hex digest")
        request = ModelRequest(
            task_id=task_id,
            case_id=case_id,
            trace_id=str(task.trace_id),
            module=str(payload.get("module", operation))[:64],
            prompt_id=prompt.id,
            prompt_version=prompt.version,
            prompt_sha256=prompt.sha256,
            messages=tuple(messages),
            response_schema=schema,
            timeout_s=float(payload.get("timeout_s", self.settings.model_timeout_s)),
            max_tokens=int(payload.get("max_tokens", self.settings.model_max_tokens)),
            temperature=payload.get("temperature"),
            top_p=payload.get("top_p"),
            stream=payload.get("stream"),
            structured_output=payload.get("structured_output"),
            disable_reasoning=payload.get("disable_reasoning"),
        )
        request_stored = self._store_model_payload(
            json.dumps({"operation": operation, "messages": messages}, ensure_ascii=True, separators=(",", ":")).encode()
        )
        runtime_result = AgentRuntime(
            self.model_gateway,
            max_context_bytes=self.settings.model_context_max_bytes,
            cancellation_requested=lambda: self._is_task_cancelled(task_id),
        ).run(request)
        response_stored = self._store_model_payload(runtime_result.response.raw_response) if runtime_result.response else None
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if task is None:
                raise LookupError(task_id)
            calls = self._persist_model_attempts(
                session,
                task,
                prompt,
                runtime_result.attempts,
                request_stored,
                [],
                request=request,
                response_stored=response_stored,
                successful_call_id=runtime_result.response.model_call_id if runtime_result.response else None,
                agent_run_id=runtime_result.run_id,
                module=request.module,
                turn_id=str(payload.get("turn_id", ""))[:200] or None,
                phase=operation,
                timeout_s=request.timeout_s,
                max_tokens=request.max_tokens,
            )
        if runtime_result.response is None:
            return {
                "status": runtime_result.status,
                "run_id": runtime_result.run_id,
                "model_call_id": calls[-1].id if calls else None,
                "attempts": [item.__dict__ for item in runtime_result.attempts],
            }
        response = runtime_result.response
        return {
            "status": "SUCCEEDED",
            "session_id": session_id,
            "task_id": task_id,
            "run_id": runtime_result.run_id,
            "model_call_id": response.model_call_id,
            "provider": response.provider,
            "model": response.model,
            "content": response.parsed.model_dump_json(),
            "parsed": response.parsed.model_dump(mode="json"),
            "usage": {"input_tokens": response.input_tokens, "output_tokens": response.output_tokens},
            "fallback_reason": response.fallback_reason,
            "attempts": [
                {
                    "provider": item.provider,
                    "model": item.model,
                    "status": item.status,
                    "error_type": item.error_type,
                    "http_status": item.http_status,
                    "endpoint_path": item.endpoint_path,
                    "error_detail": item.error_detail,
                    "latency_ms": item.latency_ms,
                }
                for item in response.attempts
            ],
        }

    def cancel_task(
        self,
        task_id: str,
        *,
        actor: str = "demo-analyst",
    ) -> dict[str, object]:
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if task is None:
                raise LookupError(task_id)
            if task.lifecycle == TaskLifecycle.CANCELLED.value:
                return self.task_view(task_id)
            if task.lifecycle in {
                TaskLifecycle.SUCCEEDED.value,
                TaskLifecycle.FAILED.value,
            }:
                raise ValueError(f"Task {task_id} is already terminal: {task.lifecycle}")
            active_runs = list(
                session.scalars(
                    select(ToolRun).where(
                        ToolRun.task_id == task_id,
                        ToolRun.status.in_(
                            [ToolRunStatus.QUEUED.value, ToolRunStatus.RUNNING.value]
                        ),
                    )
                )
            )
            active_run_ids = [run.id for run in active_runs]
            workflow_ids = sorted(
                {
                    str(run.environment["workflow_id"])
                    for run in active_runs
                    if run.environment.get("workflow_id")
                }
            )
            task.lifecycle = transition_task(task.lifecycle, TaskLifecycle.CANCELLED).value
            task.outcome = None
            task.finished_at = utcnow()
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="analysis_task.cancel_requested",
                actor=actor,
                object_type="AnalysisTask",
                object_id=task.id,
                payload={"workflow_ids": workflow_ids},
            )

        cancellation_errors: list[dict[str, str]] = []
        executor = TemporalToolExecutor(self.settings.temporal_address)
        for workflow_id in workflow_ids:
            try:
                asyncio.run(executor.cancel_workflow(workflow_id))
            except Exception as exc:
                cancellation_errors.append(
                    {"workflow_id": workflow_id, "error_type": type(exc).__name__}
                )

        delete_staged_output = getattr(
            self.content_store,
            "delete_tool_run_output",
            None,
        )
        if callable(delete_staged_output):
            for tool_run_id in active_run_ids:
                try:
                    delete_staged_output(
                        tool_run_id,
                        f"tool-runs/{tool_run_id}/output.json",
                    )
                except Exception as exc:
                    cancellation_errors.append(
                        {
                            "workflow_id": f"staging:{tool_run_id}",
                            "error_type": type(exc).__name__,
                        }
                    )

        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if task is None:
                raise LookupError(task_id)
            unfinished = list(
                session.scalars(
                    select(ToolRun).where(
                        ToolRun.task_id == task_id,
                        ToolRun.status.in_(
                            [ToolRunStatus.QUEUED.value, ToolRunStatus.RUNNING.value]
                        ),
                    )
                )
            )
            for tool_run in unfinished:
                tool_run.status = ToolRunStatus.CANCELLED.value
                tool_run.error = tool_run.error or "TASK_CANCELLED"
                tool_run.finished_at = utcnow()
                tool_run.output_sha256 = None
                tool_run.output_storage_key = None
                tool_run.output = {}
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="analysis_task.cancelled",
                actor=actor,
                object_type="AnalysisTask",
                object_id=task.id,
                payload={
                    "workflow_ids": workflow_ids,
                    "cancellation_errors": cancellation_errors,
                },
            )
            self._seal_task_audit_chain(session, task, "analysis_task.cancelled")
        return self.task_view(task_id)

    def task_status(self, task_id: str) -> dict[str, object]:
        """Return a lightweight, polling-safe task projection.

        ``task_view`` intentionally includes every Evidence and Claim row for
        the workbench.  Polling that projection during a large Ghidra run can
        repeatedly serialize megabytes and starve the worker's finalization
        transaction, so clients that only need lifecycle progress must use
        this bounded endpoint.
        """
        with self.database.session_factory() as session:
            task = session.get(AnalysisTask, task_id)
            if task is None:
                raise LookupError(task_id)
            case = session.get(CaseRecord, task.case_id)
            failure = session.scalar(
                select(AnalysisFailureRecord).where(AnalysisFailureRecord.task_id == task.id)
            )
            return {
                "id": task.id,
                "case_id": task.case_id,
                "trace_id": task.trace_id,
                "case_title": case.title if case else "",
                "lifecycle": task.lifecycle,
                "outcome": task.outcome,
                "analysis_class": task.analysis_class,
                "analysis_coverage": task.coverage or {},
                "artifact_count": session.query(Artifact).filter(Artifact.task_id == task_id).count(),
                "evidence_count": session.query(Evidence).filter(Evidence.task_id == task_id).count(),
                "claim_count": session.query(Claim).filter(Claim.task_id == task_id).count(),
                "tool_run_count": session.query(ToolRun).filter(ToolRun.task_id == task_id).count(),
                "model_call_count": session.query(ModelCall).filter(ModelCall.task_id == task_id).count(),
                "report_available": session.query(ReportRevision).filter(ReportRevision.task_id == task_id).count() > 0,
                "created_at": self._audit_timestamp(task.created_at),
                "started_at": self._audit_timestamp(task.started_at) if task.started_at else None,
                "finished_at": self._audit_timestamp(task.finished_at) if task.finished_at else None,
                "elapsed_ms": self._elapsed_ms(task),
                "failure": self._failure_payload(failure),
            }

    def task_view(self, task_id: str) -> dict[str, object]:
        with self.database.session_factory() as session:
            task = session.get(AnalysisTask, task_id)
            if task is None:
                raise LookupError(task_id)
            case = session.get(CaseRecord, task.case_id)
            failure = session.scalar(
                select(AnalysisFailureRecord).where(AnalysisFailureRecord.task_id == task.id)
            )
            inputs = self._report_inputs(session, task_id)
            claim_evidence_map: dict[str, list[str]] = {}
            for link in inputs["claim_evidence"]:
                if link.stance == "SUPPORTS":
                    claim_evidence_map.setdefault(link.claim_id, []).append(link.evidence_id)
            disposed_artifact_ids = {
                artifact.id for artifact in inputs["artifacts"] if artifact.disposed_at is not None
            }
            revisions = list(
                session.scalars(
                    select(ReportRevision)
                    .where(ReportRevision.task_id == task_id)
                    .order_by(ReportRevision.created_at.desc())
                )
            )
            delivery_rows = list(
                session.scalars(
                    select(EvidenceDeliveryTrace)
                    .where(EvidenceDeliveryTrace.task_id == task_id)
                    .order_by(EvidenceDeliveryTrace.created_at, EvidenceDeliveryTrace.id)
                )
            )
            blind_rows = list(
                session.scalars(
                    select(BlindRun)
                    .where(BlindRun.task_id == task_id)
                    .order_by(BlindRun.created_at, BlindRun.id)
                )
            )
            delivery_counts: dict[str, int] = {}
            for item in delivery_rows:
                delivery_counts[item.stage] = delivery_counts.get(item.stage, 0) + 1
            return {
                "id": task.id,
                "case_id": task.case_id,
                "trace_id": task.trace_id,
                "case_title": case.title if case else "",
                "lifecycle": task.lifecycle,
                "outcome": task.outcome,
                "analysis_class": task.analysis_class,
                "failure": self._failure_payload(failure),
                "analysis_coverage": task.coverage or {},
                "target_granularity": {
                    "breadth": task.target_breadth,
                    "depth": task.target_depth,
                },
                "actual_granularity": task.actual_granularity,
                "selected_report_modules": task.selected_modules,
                "limitations": task.limitations,
                "request_snapshot": task.request_snapshot,
                "strategy_snapshot": task.strategy_snapshot,
                "blind_runs": [
                    {
                        "id": item.id,
                        "status": item.status,
                        "snapshot": item.snapshot,
                        "snapshot_sha256": item.snapshot_sha256,
                        "created_at": item.created_at.isoformat(),
                    }
                    for item in blind_rows
                ],
                "artifacts": [
                    {
                        "id": item.id,
                        "logical_path": item.logical_path,
                        "sha256": item.content_sha256,
                        "detected_type": item.detected_type,
                        "role": item.role,
                        "obligation": item.obligation,
                        "parent_artifact_id": item.parent_artifact_id,
                        "disposed": item.disposed_at is not None,
                    }
                    for item in inputs["artifacts"]
                ],
                "tool_runs": [
                    {
                        "id": item.id,
                        "artifact_id": item.artifact_id,
                        "tool": item.tool_name,
                        "version": item.tool_version,
                        "status": item.status,
                        "error": item.error,
                        "parameters": {
                            key: item.parameters[key]
                            for key in ("scheduler", "planned_tools", "analysis_modules")
                            if key in (item.parameters or {})
                        },
                        "output_reference": (
                            {
                                "sha256": item.output_sha256,
                                "storage_key": item.output_storage_key,
                            }
                            if item.output_sha256 and item.output_storage_key
                            else None
                        ),
                        "execution": {
                            key: item.environment[key]
                            for key in (
                                "case_id",
                                "trace_id",
                                "tool_run_id",
                                "executor",
                                "execution_mode",
                                "workflow_id",
                                "task_queue",
                                "environment_version",
                            )
                            if key in item.environment
                        },
                        "started_at": (
                            self._audit_timestamp(item.started_at) if item.started_at else None
                        ),
                        "finished_at": (
                            self._audit_timestamp(item.finished_at) if item.finished_at else None
                        ),
                    }
                    for item in inputs["tool_runs"]
                ],
                "model_calls": [
                    {
                        "id": item.id,
                        "module": item.module,
                        "turn_id": item.turn_id,
                        "phase": item.phase,
                        "provider": item.provider,
                        "model": item.model,
                        "attempt": item.attempt,
                        "status": item.status,
                        "prompt_id": item.prompt_id,
                        "prompt_version": item.prompt_version,
                        "prompt_sha256": item.prompt_sha256,
                        "request_sha256": item.request_sha256,
                        "response_sha256": item.response_sha256,
                        "payload_schema_version": item.payload_schema_version,
                        "encryption_key_id": item.encryption_key_id,
                        "security_classification": item.security_classification,
                        "access_policy": item.access_policy,
                        "input_tokens": item.input_tokens,
                        "output_tokens": item.output_tokens,
                        "latency_ms": item.latency_ms,
                        "error_type": item.error_type,
                        "http_status": item.parameters.get("http_status"),
                         "endpoint_path": item.parameters.get("endpoint_path"),
                         "error_detail": item.parameters.get("error_detail"),
                         "agent_run_id": item.parameters.get("agent_run_id"),
                         "context_evidence_count": item.parameters.get("context_evidence_count"),
                         "context_bytes": item.parameters.get("context_bytes"),
                     }
                    for item in inputs["model_calls"]
                ],
                "analysis_turns": [
                    {
                        "id": item.id,
                        "thread_id": item.thread_id,
                        "turn_id": item.turn_id,
                        "phase": item.phase,
                        "hypothesis_before": item.hypothesis_before,
                        "retrieval_request": item.retrieval_request,
                        "candidate_evidence_ids": item.candidate_evidence_ids,
                        "selected_evidence_ids": item.selected_evidence_ids,
                        "delivered_evidence_ids": item.delivered_evidence_ids,
                        "context_manifest": [
                            {
                                key: value
                                for key, value in manifest.items()
                                if key
                                in {
                                    "evidence_id",
                                    "artifact_id",
                                    "kind",
                                    "nature",
                                    "context_role",
                                    "selection_score",
                                    "selection_rationale",
                                    "quota_group",
                                    "trust_zone",
                                }
                            }
                            for manifest in item.context_manifest
                            if isinstance(manifest, dict)
                        ],
                        "model_call_id": item.model_call_id,
                        "raw_response": (
                            {
                                "sha256": item.raw_response_sha256,
                                "storage_key": item.raw_response_storage_key,
                            }
                            if item.raw_response_sha256 and item.raw_response_storage_key
                            else None
                        ),
                        "action_proposals": item.action_proposals,
                        "policy_decisions": item.policy_decisions,
                        "tool_run_ids": item.tool_run_ids,
                        "new_evidence_ids": item.new_evidence_ids,
                        "verifier_result": item.verifier_result,
                        "hypothesis_after": item.hypothesis_after,
                        "mechanism_state": item.mechanism_state,
                        "stop_reason": item.stop_reason,
                        "created_at": item.created_at.isoformat(),
                    }
                    for item in inputs["analysis_turns"]
                ],
                "analysis_turn_results": [
                    {
                        "id": item.id,
                        "parent_turn_id": item.parent_turn_id,
                        "thread_id": item.thread_id,
                        "turn_id": item.turn_id,
                        "phase": item.phase,
                        "completed_actions": item.completed_actions,
                        "tool_run_ids": item.tool_run_ids,
                        "new_evidence_ids": item.new_evidence_ids,
                        "verifier_result": item.verifier_result,
                        "hypothesis_after": item.hypothesis_after,
                        "mechanism_state": item.mechanism_state,
                        "stop_reason": item.stop_reason,
                        "created_at": item.created_at.isoformat(),
                    }
                    for item in inputs["analysis_turn_results"]
                ],
                "claims": [
                    {
                        "id": item.id,
                        "module": item.module,
                        "claim_type": item.claim_type,
                        "subject": item.subject,
                        "action": item.action,
                        "object": item.object,
                        "mechanism": item.mechanism,
                        "condition": item.condition,
                        "nature": item.nature,
                        "statement": item.statement,
                        "status": item.status,
                        "confidence": item.confidence,
                        "attack_mapping": item.attack_mapping,
                        "model_call_id": item.model_call_id,
                        "evidence_ids": claim_evidence_map.get(item.id, []),
                    }
                    for item in inputs["claims"]
                ],
                "claim_evidence": [
                    {
                        "claim_id": item.claim_id,
                        "evidence_id": item.evidence_id,
                        "stance": item.stance,
                    }
                    for item in inputs["claim_evidence"]
                ],
                "relations": [
                    {
                        "id": item.id,
                        "source_artifact_id": item.source_artifact_id,
                        "target_artifact_id": item.target_artifact_id,
                        "relation_type": item.relation_type,
                        "evidence_id": item.evidence_id,
                        "claim_id": item.claim_id,
                        "status": item.status,
                    }
                    for item in inputs["relations"]
                ],
                "evidence": [
                    {
                        "id": item.id,
                        "artifact_id": item.artifact_id,
                        "module": item.module,
                        "kind": item.kind,
                        "nature": item.nature,
                        "value": (
                            {"redacted": True, "reason": "artifact_disposed"}
                            if item.artifact_id in disposed_artifact_ids
                            else item.value
                        ),
                        "anchor": item.anchor,
                    }
                    for item in inputs["evidence"]
                ],
                "gates": [
                    {
                        "id": item.id,
                        "type": item.gate_type,
                        "status": item.status,
                        "reason": item.reason,
                        "context": item.context,
                    }
                    for item in inputs["gates"]
                ],
                "evidence_delivery": {
                    "counts": delivery_counts,
                    "records": [
                        {
                            "turn_id": item.turn_id,
                            "thread_id": item.thread_id,
                            "model_call_id": item.model_call_id,
                            "subject_key": item.subject_key,
                            "evidence_id": item.evidence_id,
                            "stage": item.stage,
                            "context_role": item.context_role,
                            "selection_score": item.selection_score,
                            "exclusion_reason": item.exclusion_reason,
                            "details": item.details,
                        }
                        for item in delivery_rows
                    ],
                },
                "investigation": {
                    "threads": [
                        {
                            "id": item.id,
                            "artifact_id": item.artifact_id,
                            "state": item.state,
                            "question": item.question,
                            "seed_kind": item.seed_kind,
                            "evidence_ids": item.evidence_ids,
                            "hypothesis_ids": item.hypothesis_ids,
                            "action_ids": item.action_ids,
                            "transition_count": item.transition_count,
                        }
                        for item in inputs["investigation_threads"]
                    ],
                    "hypotheses": [
                        {
                            "id": item.id,
                            "thread_id": item.thread_id,
                            "statement": item.statement,
                            "dimension": item.dimension,
                            "status": item.status,
                            "confidence": item.confidence,
                            "evidence_ids": item.evidence_ids,
                            "required_evidence": item.required_evidence,
                        }
                        for item in inputs["investigation_hypotheses"]
                    ],
                    "actions": [
                        {
                            "id": item.id,
                            "thread_id": item.thread_id,
                            "hypothesis_id": item.hypothesis_id,
                            "artifact_id": item.artifact_id,
                            "action_type": item.action_type,
                            "parameters": item.parameters,
                            "target_selector": item.target_selector,
                            "expected_evidence_kinds": item.expected_evidence_kinds,
                            "success_condition": item.success_condition,
                            "failure_interpretation": item.failure_interpretation,
                            "cost_units": item.cost_units,
                            "status": item.status,
                            "priority": item.priority,
                            "attempts": item.attempts,
                            "depends_on": item.depends_on,
                            "result_evidence_ids": item.result_evidence_ids,
                            "error": item.error,
                        }
                        for item in inputs["investigation_actions"]
                    ],
                },
                "mechanism_effectiveness_traces": [
                    {
                        "id": item.id,
                        "trace_version": item.trace_version,
                        "mechanism_id": item.mechanism_id,
                        "mechanism_type": item.mechanism_type,
                        "artifact_id": item.artifact_id,
                        "seed": item.seed,
                        "question": item.question,
                        "competing_hypotheses": item.competing_hypotheses,
                        "action_proposals": item.action_proposals,
                        "tool_runs": item.tool_run_ids,
                        "new_evidence_ids": item.new_evidence_ids,
                        "evidence_delta": item.evidence_delta,
                        "hypothesis_delta": item.hypothesis_delta,
                        "mechanism_delta": item.mechanism_delta,
                        "verifier_result": item.verifier_result,
                        "claim_gate": item.claim_gate,
                        "report_projection": item.report_projection,
                        "model_action_productivity": item.model_action_productivity,
                        "trace_sha256": item.trace_sha256,
                        "created_at": item.created_at.isoformat(),
                    }
                    for item in inputs["mechanism_effectiveness_traces"]
                ],
                "latest_report_revision_id": revisions[0].id if revisions else None,
                "created_at": task.created_at.isoformat(),
                "finished_at": task.finished_at.isoformat() if task.finished_at else None,
            }

    def _persist_evidence_delivery_ledger(
        self,
        session: Session,
        *,
        task: AnalysisTask,
        artifact_id: str | None,
        ledger: EvidenceDeliveryLedger,
        model_call_id: str | None,
    ) -> None:
        """Append unseen funnel events; Evidence itself remains immutable.

        This method is idempotent for a turn.  It permits a caller to persist
        delivery before a failed response and append later model-reference or
        verifier-acceptance events without updating the original trace rows.
        """
        subject_keys = tuple(dict.fromkeys(event.evidence_id for event in ledger.events))
        existing = set(
            session.execute(
                select(EvidenceDeliveryTrace.subject_key, EvidenceDeliveryTrace.stage).where(
                    EvidenceDeliveryTrace.task_id == task.id,
                    EvidenceDeliveryTrace.turn_id == ledger.turn_id,
                    EvidenceDeliveryTrace.subject_key.in_(subject_keys),
                )
            ).all()
        ) if subject_keys else set()
        existing_evidence_ids = set(
            session.scalars(
                select(Evidence.id).where(Evidence.task_id == task.id, Evidence.id.in_(subject_keys))
            ).all()
        ) if subject_keys else set()
        evidence_artifacts = {
            str(evidence_id): str(evidence_artifact_id)
            for evidence_id, evidence_artifact_id in session.execute(
                select(Evidence.id, Evidence.artifact_id).where(
                    Evidence.task_id == task.id,
                    Evidence.id.in_(subject_keys),
                )
            ).all()
        } if subject_keys else {}
        added = 0
        for event in ledger.events:
            key = (event.evidence_id, event.stage.value)
            if key in existing:
                continue
            details = dict(event.details)
            role = details.pop("context_role", None)
            score = details.pop("selection_score", None)
            exclusion = details.pop("exclusion_reason", None)
            session.add(
                EvidenceDeliveryTrace(
                    task_id=task.id,
                    artifact_id=artifact_id or evidence_artifacts.get(event.evidence_id),
                    thread_id=event.thread_id or None,
                    model_call_id=model_call_id,
                    turn_id=event.turn_id,
                    subject_key=event.evidence_id,
                    evidence_id=(event.evidence_id if event.evidence_id in existing_evidence_ids else None),
                    stage=event.stage.value,
                    context_role=str(role) if role else None,
                    selection_score=float(score) if score is not None else None,
                    exclusion_reason=str(exclusion) if exclusion else None,
                    details=details,
                )
            )
            added += 1
        if added:
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="evidence.delivery_traced",
                actor="evidence-retriever",
                object_type="EvidenceDeliveryTrace",
                object_id=ledger.turn_id[:80],
                payload={
                    "turn_id": ledger.turn_id,
                    "thread_id": ledger.thread_id,
                    "record_count": added,
                    "model_call_id": model_call_id,
                },
            )

    def record_evidence_delivery_trace(
        self,
        *,
        task_id: str,
        artifact_id: str | None,
        ledger: EvidenceDeliveryLedger,
        model_call_id: str | None = None,
    ) -> None:
        """Public append-only delivery trace operation for integration clients."""
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id)
            if task is None:
                raise LookupError(task_id)
            self._persist_evidence_delivery_ledger(
                session,
                task=task,
                artifact_id=artifact_id,
                ledger=ledger,
                model_call_id=model_call_id,
            )

    def get_evidence(self, evidence_id: str) -> dict[str, object]:
        with self.database.session_factory() as session:
            item = session.get(Evidence, evidence_id)
            if item is None:
                raise LookupError(evidence_id)
            artifact = session.get(Artifact, item.artifact_id)
            tool_run = session.get(ToolRun, item.tool_run_id)
            if artifact is not None and artifact.disposed_at is not None:
                raise LookupError(f"Evidence {evidence_id} has been disposed")
            return {
                "id": item.id,
                "task_id": item.task_id,
                "module": item.module,
                "kind": item.kind,
                "nature": item.nature,
                "value": item.value,
                "anchor": item.anchor,
                "artifact": {
                    "id": artifact.id,
                    "logical_path": artifact.logical_path,
                    "sha256": artifact.content_sha256,
                }
                if artifact
                else None,
                "tool_run": {
                    "id": tool_run.id,
                    "tool": tool_run.tool_name,
                    "version": tool_run.tool_version,
                    "status": tool_run.status,
                }
                if tool_run
                else None,
            }

    def list_audit_events(self, task_id: str) -> list[dict[str, object]]:
        with self.database.session_factory() as session:
            if session.get(AnalysisTask, task_id) is None:
                raise LookupError(task_id)
            events = session.scalars(
                select(AuditEvent)
                .where(AuditEvent.task_id == task_id)
                .order_by(AuditEvent.chain_sequence)
            )
            return [
                {
                    "id": event.id,
                    "event_type": event.event_type,
                    "actor": event.actor,
                    "object_type": event.object_type,
                    "object_id": event.object_id,
                    "trace_id": event.trace_id,
                    "payload": event.payload,
                    "chain_version": event.chain_version,
                    "chain_sequence": event.chain_sequence,
                    "previous_hash": event.previous_hash,
                    "event_hash": event.event_hash,
                    "created_at": event.created_at.isoformat(),
                }
                for event in events
            ]

    def analysis_trace(self, task_id: str) -> dict[str, object]:
        """Expose a redacted, evidence-linked explanation of the run.

        This is intentionally derived from immutable audit/domain records. It
        is a system trace, not a reconstruction of private model reasoning.
        """
        with self.database.session_factory() as session:
            task = session.get(AnalysisTask, task_id)
            if task is None:
                raise LookupError(task_id)
            inputs = self._report_inputs(session, task_id)
            events = list(
                session.scalars(
                    select(AuditEvent)
                    .where(AuditEvent.task_id == task_id)
                    .order_by(AuditEvent.chain_sequence)
                )
            )

            event_rows = [
                {
                    "event_type": event.event_type,
                    "actor": event.actor,
                    "object_type": event.object_type,
                    "object_id": event.object_id,
                    "payload": event.payload,
                    "chain_sequence": event.chain_sequence,
                    "created_at": event.created_at.isoformat(),
                }
                for event in events
            ]
            claim_rows = [
                {
                    "id": item.id,
                    "module": item.module,
                    "status": item.status,
                    "confidence": item.confidence,
                    "model_call_id": item.model_call_id,
                }
                for item in inputs["claims"]
            ]
            evidence_rows = [
                {"id": item.id, "tool_run_id": item.tool_run_id}
                for item in inputs["evidence"]
            ]
            claim_evidence_rows = [
                {"claim_id": item.claim_id, "evidence_id": item.evidence_id}
                for item in inputs["claim_evidence"]
            ]
            tool_rows = [
                {
                    "id": item.id,
                    "artifact_id": item.artifact_id,
                    "tool": item.tool_name,
                    "status": item.status,
                    "scheduler": (item.parameters or {}).get("scheduler"),
                    "planned_tools": (item.parameters or {}).get("planned_tools", []),
                }
                for item in inputs["tool_runs"]
            ]
            model_rows = [
                {
                    "id": item.id,
                    "turn_id": item.turn_id,
                    "phase": item.phase,
                    "provider": item.provider,
                    "model": item.model,
                    "attempt": item.attempt,
                    "prompt_sha256": item.prompt_sha256,
                    "request_sha256": item.request_sha256,
                    "response_sha256": item.response_sha256,
                    "status": item.status,
                    "error_type": item.error_type,
                    "latency_ms": item.latency_ms,
                    "parameters": item.parameters or {},
                    "agent_run_id": item.parameters.get("agent_run_id"),
                    "context_evidence_count": item.parameters.get("context_evidence_count"),
                    "context_bytes": item.parameters.get("context_bytes"),
                }
                for item in inputs["model_calls"]
            ]
            delivery_rows = list(
                session.scalars(
                    select(EvidenceDeliveryTrace)
                    .where(EvidenceDeliveryTrace.task_id == task_id)
                    .order_by(EvidenceDeliveryTrace.created_at, EvidenceDeliveryTrace.id)
                )
            )
            delivery_payload = [
                {
                    "turn_id": item.turn_id,
                    "thread_id": item.thread_id,
                    "model_call_id": item.model_call_id,
                    "subject_key": item.subject_key,
                    "evidence_id": item.evidence_id,
                    "stage": item.stage,
                    "context_role": item.context_role,
                    "selection_score": item.selection_score,
                    "exclusion_reason": item.exclusion_reason,
                    "details": item.details,
                }
                for item in delivery_rows
            ]
            artifact_rows = [{"id": item.id} for item in inputs["artifacts"]]
            persisted_trace_rows = [
                {
                    "id": item.id,
                    "trace_version": item.trace_version,
                    "mechanism_id": item.mechanism_id,
                    "mechanism_type": item.mechanism_type,
                    "artifact_id": item.artifact_id,
                    "seed": item.seed,
                    "question": item.question,
                    "competing_hypotheses": item.competing_hypotheses,
                    "action_proposals": item.action_proposals,
                    "tool_runs": item.tool_run_ids,
                    "new_evidence_ids": item.new_evidence_ids,
                    "evidence_delta": item.evidence_delta,
                    "hypothesis_delta": item.hypothesis_delta,
                    "mechanism_delta": item.mechanism_delta,
                    "verifier_result": item.verifier_result,
                    "claim_gate": item.claim_gate,
                    "report_projection": item.report_projection,
                    "model_action_productivity": item.model_action_productivity,
                    "trace_sha256": item.trace_sha256,
                    "created_at": item.created_at.isoformat(),
                }
                for item in inputs["mechanism_effectiveness_traces"]
            ]
            task_snapshot = {
                "id": task.id,
                "trace_id": task.trace_id,
                "lifecycle": task.lifecycle,
                "outcome": task.outcome,
                "limitations": list(task.limitations or []),
                "strategy_snapshot": dict(task.strategy_snapshot or {}),
            }

        integrity = self.audit_integrity(task_id)
        return build_analysis_trace(
            task_id=task_snapshot["id"],
            trace_id=task_snapshot["trace_id"],
            lifecycle=task_snapshot["lifecycle"],
            outcome=task_snapshot["outcome"],
            limitations=task_snapshot["limitations"],
            events=event_rows,
            claims=claim_rows,
            claim_evidence=claim_evidence_rows,
            evidence=evidence_rows,
            tool_runs=tool_rows,
            model_calls=model_rows,
            analysis_turns=[
                {
                    "id": item.id,
                    "thread_id": item.thread_id,
                    "turn_id": item.turn_id,
                    "phase": item.phase,
                    "hypothesis_before": item.hypothesis_before,
                    "retrieval_request": item.retrieval_request,
                    "candidate_evidence_ids": item.candidate_evidence_ids,
                    "selected_evidence_ids": item.selected_evidence_ids,
                    "delivered_evidence_ids": item.delivered_evidence_ids,
                    "model_call_id": item.model_call_id,
                    "action_proposals": item.action_proposals,
                    "policy_decisions": item.policy_decisions,
                    "tool_run_ids": item.tool_run_ids,
                    "new_evidence_ids": item.new_evidence_ids,
                    "verifier_result": item.verifier_result,
                    "hypothesis_after": item.hypothesis_after,
                    "mechanism_state": item.mechanism_state,
                    "stop_reason": item.stop_reason,
                    "created_at": item.created_at.isoformat(),
                }
                for item in inputs["analysis_turns"]
            ],
            analysis_turn_results=[
                {
                    "id": item.id,
                    "parent_turn_id": item.parent_turn_id,
                    "thread_id": item.thread_id,
                    "turn_id": item.turn_id,
                    "phase": item.phase,
                    "completed_actions": item.completed_actions,
                    "tool_run_ids": item.tool_run_ids,
                    "new_evidence_ids": item.new_evidence_ids,
                    "verifier_result": item.verifier_result,
                    "hypothesis_after": item.hypothesis_after,
                    "mechanism_state": item.mechanism_state,
                    "stop_reason": item.stop_reason,
                    "created_at": item.created_at.isoformat(),
                }
                for item in inputs["analysis_turn_results"]
            ],
            evidence_delivery=delivery_payload,
            artifacts=artifact_rows,
            persisted_mechanism_effectiveness_traces=persisted_trace_rows,
            integrity={
                "valid": integrity.get("valid"),
                "event_count": integrity.get("event_count"),
                "chain_tip": integrity.get("chain_tip"),
                "seal_count": len(integrity.get("seals", [])),
                "errors": integrity.get("errors", []),
            },
            strategy_snapshot=task_snapshot["strategy_snapshot"],
        )

    def audit_integrity(self, task_id: str) -> dict[str, object]:
        with self.database.session_factory() as session:
            task = session.get(AnalysisTask, task_id)
            if task is None:
                raise LookupError(task_id)
            scope_key = f"task:{task.id}"
            events = list(
                session.scalars(
                    select(AuditEvent)
                    .where(AuditEvent.task_id == task.id)
                    .order_by(AuditEvent.chain_sequence)
                )
            )
            errors: list[str] = []
            previous_hash = "0" * 64
            for expected_sequence, event in enumerate(events, start=1):
                if event.chain_version != "1":
                    errors.append(f"unsupported chain version on event {event.id}")
                if event.chain_sequence != expected_sequence:
                    errors.append(f"unexpected chain sequence on event {event.id}")
                if event.previous_hash != previous_hash:
                    errors.append(f"previous hash mismatch on event {event.id}")
                if event.trace_id != task.trace_id:
                    errors.append(f"trace mismatch on event {event.id}")
                calculated_hash = self._audit_event_hash(
                    event_id=event.id,
                    case_id=event.case_id,
                    task_id=event.task_id,
                    event_type=event.event_type,
                    actor=event.actor,
                    object_type=event.object_type,
                    object_id=event.object_id,
                    trace_id=event.trace_id,
                    payload=event.payload,
                    chain_version=event.chain_version,
                    chain_sequence=event.chain_sequence,
                    previous_hash=event.previous_hash,
                    created_at=event.created_at,
                )
                if not hmac.compare_digest(calculated_hash, event.event_hash):
                    errors.append(f"event hash mismatch on event {event.id}")
                previous_hash = event.event_hash
            seals = list(
                session.scalars(
                    select(AuditSeal)
                    .where(AuditSeal.scope_key == scope_key)
                    .order_by(AuditSeal.sequence)
                )
            )
            event_hashes = {event.chain_sequence: event.event_hash for event in events}
            for seal in seals:
                expected_hash = event_hashes.get(seal.sequence)
                if seal.sequence >= 0 and expected_hash != seal.terminal_event_hash:
                    errors.append(f"seal event mismatch at sequence {seal.sequence}")
                if seal.sequence >= 0:
                    terminal_hashes = [
                        event.event_hash
                        for event in events
                        if event.chain_sequence <= seal.sequence
                    ]
                    if self._merkle_root(terminal_hashes) != seal.merkle_root:
                        errors.append(f"seal Merkle mismatch at sequence {seal.sequence}")
                if seal.seal_window:
                    if not seal.payload_sha256 or not seal.payload_storage_key:
                        errors.append(f"daily seal payload is missing for {seal.seal_window}")
                    else:
                        try:
                            payload_bytes = self.content_store.read(seal.payload_storage_key)
                            if hashlib.sha256(payload_bytes).hexdigest() != seal.payload_sha256:
                                errors.append(
                                    f"daily seal payload hash mismatch for {seal.seal_window}"
                                )
                            payload = json.loads(payload_bytes)
                            terminal_sequence = int(payload["terminal_event_sequence"])
                            if payload.get("scope_key") != scope_key:
                                errors.append(f"daily seal scope mismatch for {seal.seal_window}")
                            if payload.get("utc_day") != seal.seal_window:
                                errors.append(f"daily seal window mismatch for {seal.seal_window}")
                            if event_hashes.get(terminal_sequence) != seal.terminal_event_hash:
                                errors.append(f"daily seal event mismatch for {seal.seal_window}")
                            if payload.get("merkle_root") != seal.merkle_root:
                                errors.append(f"daily seal Merkle mismatch for {seal.seal_window}")
                        except (
                            FileNotFoundError,
                            KeyError,
                            TypeError,
                            ValueError,
                            json.JSONDecodeError,
                        ):
                            errors.append(f"daily seal payload is invalid for {seal.seal_window}")
                key_id, signature = self._audit_signature(
                    seal.scope_key,
                    seal.sequence,
                    seal.terminal_event_hash,
                    seal.merkle_root,
                )
                if seal.key_id != key_id or not hmac.compare_digest(seal.signature, signature):
                    errors.append(f"seal signature mismatch at sequence {seal.sequence}")
            return {
                "task_id": task.id,
                "trace_id": task.trace_id,
                "scope_key": scope_key,
                "valid": not errors,
                "event_count": len(events),
                "chain_tip": previous_hash,
                "seals": [
                    {
                        "sequence": seal.sequence,
                        "terminal_event_type": seal.terminal_event_type,
                        "terminal_event_hash": seal.terminal_event_hash,
                        "merkle_root": seal.merkle_root,
                        "algorithm": seal.algorithm,
                        "key_id": seal.key_id,
                        "sealed_at": seal.sealed_at.isoformat(),
                    }
                    for seal in seals
                ],
                "errors": errors,
            }

    def get_report_revision(self, revision_id: str) -> dict[str, object]:
        with self.database.session_factory() as session:
            revision = session.get(ReportRevision, revision_id)
            if revision is None:
                raise LookupError(revision_id)
            disposed = session.scalar(
                select(Artifact.id).where(
                    Artifact.task_id == revision.task_id, Artifact.disposed_at.is_not(None)
                )
            )
            document = revision.document
            markdown = revision.markdown
            if disposed:
                document = {"content_access": "REDACTED", "snapshot_id": revision.snapshot_id}
                markdown = "[REDACTED: evidence content has been disposed; audit metadata retained]"
            return {
                "id": revision.id,
                "task_id": revision.task_id,
                "snapshot_id": revision.snapshot_id,
                "parent_revision_id": revision.parent_revision_id,
                "status": revision.status,
                "author": revision.author,
                "selected_modules": revision.selected_modules,
                "document": document,
                "markdown": markdown,
                "edit_kind": revision.edit_kind,
                "created_at": revision.created_at.isoformat(),
            }

    def recompose_report(
        self,
        task_id: str,
        selected_modules: list[str],
        actor: str = "demo-analyst",
    ) -> dict[str, object]:
        modules = normalize_modules(selected_modules)
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id)
            if task is None or task.lifecycle != "SUCCEEDED":
                raise LookupError(f"Completed task {task_id} does not exist")
            case = session.get(CaseRecord, task.case_id)
            snapshot = session.scalar(
                select(AnalysisSnapshot)
                .where(AnalysisSnapshot.task_id == task_id)
                .order_by(AnalysisSnapshot.created_at.desc())
            )
            parent = session.scalar(
                select(ReportRevision)
                .where(ReportRevision.task_id == task_id)
                .order_by(ReportRevision.created_at.desc())
            )
            if case is None or snapshot is None:
                raise LookupError(task_id)
            revision = self._create_report_revision(
                session,
                task,
                snapshot,
                modules,
                parent_revision_id=parent.id if parent else None,
                author=actor,
            )
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="report.recomposed",
                actor=actor,
                object_type="ReportRevision",
                object_id=revision.id,
                payload={"selected_modules": modules, "snapshot_id": snapshot.id},
            )
            revision_id = revision.id
        return self.get_report_revision(revision_id)

    def edit_report(
        self,
        revision_id: str,
        markdown: str,
        actor: str = "demo-analyst",
    ) -> dict[str, object]:
        if not markdown.strip():
            raise ValueError("Edited report cannot be empty")
        with self.database.session_factory.begin() as session:
            parent = session.get(ReportRevision, revision_id)
            if parent is None:
                raise LookupError(revision_id)
            task = session.get(AnalysisTask, parent.task_id)
            if task is None:
                raise LookupError(parent.task_id)
            document = dict(parent.document)
            document["manual_edit"] = {
                "base_revision_id": parent.id,
                "author": actor,
                "claim_or_evidence_created": False,
            }
            revision = ReportRevision(
                task_id=parent.task_id,
                snapshot_id=parent.snapshot_id,
                parent_revision_id=parent.id,
                status="DRAFT",
                author=actor,
                selected_modules=parent.selected_modules,
                document=document,
                markdown=markdown,
                edit_kind="MANUAL_EDIT",
            )
            session.add(revision)
            session.flush()
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="report.manually_edited",
                actor=actor,
                object_type="ReportRevision",
                object_id=revision.id,
                payload={
                    "base_revision_id": parent.id,
                    "requires_external_publish_gate": True,
                },
            )
            new_revision_id = revision.id
        return self.get_report_revision(new_revision_id)

    def approve_report(self, revision_id: str, *, actor: str, note: str = "") -> dict[str, object]:
        """Gate 5 approval; facts remain frozen in the referenced snapshot."""
        with self.database.session_factory.begin() as session:
            revision = session.get(ReportRevision, revision_id)
            if revision is None:
                raise LookupError(revision_id)
            if revision.status != "DRAFT":
                raise ValueError(f"report revision is already {revision.status}")
            task = session.get(AnalysisTask, revision.task_id)
            if task is None or task.lifecycle != TaskLifecycle.SUCCEEDED.value:
                raise ValueError("only a succeeded Task can be approved")
            seals = session.scalars(select(AuditSeal).where(AuditSeal.task_id == task.id)).all()
            if not seals:
                raise ValueError("report approval requires an audit seal")
            revision.status = "APPROVED"
            gate = GateRecord(
                task_id=task.id,
                gate_type="REPORT_APPROVAL",
                status="APPROVED",
                reason="Gate 5 report approval",
                context={"revision_id": revision.id, "snapshot_id": revision.snapshot_id},
                decided_by=actor,
                decision_note=note,
                decided_at=utcnow(),
            )
            session.add(gate)
            session.flush()
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="report.approved",
                actor=actor,
                object_type="ReportRevision",
                object_id=revision.id,
                payload={"snapshot_id": revision.snapshot_id, "gate_id": gate.id},
            )
        return self.get_report_revision(revision_id)

    def publish_report(self, revision_id: str, *, actor: str) -> dict[str, object]:
        with self.database.session_factory.begin() as session:
            revision = session.get(ReportRevision, revision_id)
            if revision is None:
                raise LookupError(revision_id)
            if revision.status != "APPROVED":
                raise ValueError("only an APPROVED report can be published")
            task = session.get(AnalysisTask, revision.task_id)
            if task is None:
                raise LookupError(revision.task_id)
            integrity = self.audit_integrity(task.id)
            if not integrity.get("valid") or not integrity.get("seals"):
                raise ValueError("publishing requires a valid sealed audit chain")
            revision.status = "PUBLISHED"
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="report.published",
                actor=actor,
                object_type="ReportRevision",
                object_id=revision.id,
                payload={"snapshot_id": revision.snapshot_id},
            )
        return self.get_report_revision(revision_id)

    def analysis_package(self, task_id: str) -> dict[str, object]:
        with self.database.session_factory() as session:
            task = session.get(AnalysisTask, task_id)
            if task is None or task.lifecycle != "SUCCEEDED":
                raise LookupError(task_id)
            snapshot = session.scalar(
                select(AnalysisSnapshot)
                .where(AnalysisSnapshot.task_id == task_id)
                .order_by(AnalysisSnapshot.created_at.desc())
            )
            if snapshot is None:
                raise LookupError(task_id)
            package = build_report_document(
                selected_modules=list(REPORT_MODULES),
                **self._snapshot_report_context(snapshot),
            )
            package["analysis_snapshot"] = {
                "id": snapshot.id,
                "schema_version": snapshot.object_versions.get("schema_version"),
                "payload": snapshot.object_versions,
            }
            disposed = session.scalar(
                select(Artifact.id).where(
                    Artifact.task_id == task_id, Artifact.disposed_at.is_not(None)
                )
            )
            package["content_access"] = (
                {"status": "REDACTED", "reason": "artifact_disposed"}
                if disposed
                else {"status": "AVAILABLE"}
            )
            return package

    def replay_analysis_package(
        self,
        package: dict[str, object],
        *,
        selected_modules: list[str] | None = None,
    ) -> dict[str, object]:
        snapshot_wrapper = package.get("analysis_snapshot")
        if not isinstance(snapshot_wrapper, dict):
            raise ValueError("analysis package has no immutable snapshot")
        payload = snapshot_wrapper.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("analysis package snapshot payload is invalid")
        snapshot_id = str(snapshot_wrapper.get("id", "imported-analysis-package"))
        snapshot = AnalysisSnapshot(id=snapshot_id, task_id=str(payload.get("task", {}).get("id", "")), object_versions=payload)
        context = self._snapshot_report_context(snapshot)
        modules = normalize_modules(selected_modules)
        return build_report_document(selected_modules=modules, **context)
