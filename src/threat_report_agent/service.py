from __future__ import annotations

from dataclasses import dataclass, replace
import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable, Mapping
import base64
import binascii
import hashlib
import hmac
import json
import os
import zipfile
import io
import time
import threading
import re
from urllib.parse import urlparse

from sqlalchemy import case, func, insert, select
from sqlalchemy.orm import Session, object_session

from threat_report_agent.model.agents import (
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
from threat_report_agent.facts.dataflow import (
    addresses_alias,
    catalog_fields_from_decode_verification,
    catalog_output_consumer_relation,
    catalog_relation_from_api_fields,
    catalog_relation_from_parent_attribute,
    catalog_relation_from_resolved_api,
    catalog_parent_handle_identity,
    catalog_resolved_pointer_identity,
    is_object_level_decode_consumer,
    output_buffer_identity,
    parse_operand_address,
    with_artifact_identity,
)
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
from threat_report_agent.static.evidence_recovery import (
    BoundedEvidenceRepository,
    ContextPacket,
    EvidenceDeliveryLedger,
    EvidenceStage,
    QuestionCentricRetriever,
    RetrievalRequest,
)
from threat_report_agent.static.evidence_index import evidence_search_keys
from threat_report_agent.policy import PolicyRegistry
from threat_report_agent.model.prompts import PromptRegistry
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
    EvidenceSearchKey,
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
    DeepMiningPlanner as DeepMiningPlanner,
    GateDecision as GateDecision,
    InvestigationEvent,
    InvestigationLoopDriver as InvestigationLoopDriver,
    InvestigationResult,
    InvestigationThreadState,
    MechanismPlaybookRegistry,
    Verifier,
    verify_mechanism as verify_mechanism,
    derive_static_mechanism_links,
    investigation_frontier_fingerprint,
    investigation_next_method as investigation_next_method,
    completed_investigation_methods as completed_investigation_methods,
    how_timebox_disposition as how_timebox_disposition,
    apply_emulation_reverification,
    recovery_actions_for_gap,
    normalize_target_selector,
    CATALOG_SELECTOR_KEYS,
)
from threat_report_agent.facts.thread_start import recovered_thread_start_address
from threat_report_agent.investigation.investigation_protocol import (
    fill_protocol,
    tool_authoring_required_ticket as tool_authoring_required_ticket,
)
from threat_report_agent.investigation.persist_how import PersistHow
from threat_report_agent.task.analysis_task_orchestration import (
    PERSIST_KEEP_ACTION_TYPES,
    PERSIST_SKIP_TRACE_ERROR,
    continue_investigation_after_action,
    keep_recovery_after_persist_skip,
    run_analysis_task_investigation,
    run_emulation_informed_investigation,
    run_saturated_investigation,
    supersede_queued_trace_after_persist_skip,
)
# P3.3 layer item 1: the loop-path / persist-HOW SKIP policy now lives in the investigation package, and this module
# imported it from its NEW home rather than from the task module's re-export (plan 7.1 step 5). P3.3f-2 MOVED THE CALLER
# this comment was written for - the loop now lives in `investigation/derivation.py` and imports these itself - so what
# remains here is the `X as X` re-export surface that keeps `service.<name>` reachable until P4 deletes the shims. The
# earlier wording ("This production caller") is corrected rather than left to age into a lie.
from threat_report_agent.investigation.loop_path import (
    LOOP_PATH_BUDGET_DEFER as LOOP_PATH_BUDGET_DEFER,
    LOOP_PATH_PERSIST_BOUNDARY as LOOP_PATH_PERSIST_BOUNDARY,
    LOOP_PATH_PERSIST_READY as LOOP_PATH_PERSIST_READY,
    next_investigation_loop_path as next_investigation_loop_path,
    resolve_persist_how_skip as resolve_persist_how_skip,
)
from threat_report_agent.investigation.investigation_ledger import (
    LEDGER_OPEN as LEDGER_OPEN,
    LEDGER_UNKNOWN as LEDGER_UNKNOWN,
    begin_item as begin_item,
    close_item as close_item,
    defer_item as defer_item,
    register_work_item as register_work_item,
    should_skip_work_item as should_skip_work_item,
    terminate_item as terminate_item,
)
from threat_report_agent.report.analyst_report import (
    AnalystReportPlanEnvelope,
    compact_analyst_context,
    official_revision_semantic_gains,
    render_official_markdown,
    slot_evidence_corpora,
    verify_model_slot_proposals,
)
from threat_report_agent.model.model_gateway import (
    AtomicClaimDraft,
    AtomicClaimEnvelope,
    DynamicPlanEnvelope,
    ModelGateway,
    ModelRequest,
    provider_contract,
)
from threat_report_agent.contracts import DynamicPlanAction
from threat_report_agent.investigation.mechanism_completeness import (
    mechanism_completeness_score,
    mechanism_is_critical_ready as mechanism_is_critical_ready,
)
from threat_report_agent.investigation.mechanism_ready import inspect_mechanism_ready as inspect_mechanism_ready
from threat_report_agent.deep_analysis_quality import no_new_evidence_autopsy
from threat_report_agent.static.pma_static_plan import static_analysis_plan_snapshot
from threat_report_agent.report.reporting import (
    REPORT_MODULES,
    STATIC_ANALYSIS_PLAN_SNAPSHOT_KEY,
    _address_lookup_keys,
    build_report_document,
    build_mechanism_projections,
    build_static_link_mechanism_projections,
    normalize_modules,
)
from threat_report_agent.secret_store import SecretCipher
from threat_report_agent.simulation_adapters import (
    default_simulation_runner,
    qiling_unavailable_observation,
    static_phase_simulation_evidence,
)
from threat_report_agent.emulation.policy import (
    SimulationExecutionPolicy,
    may_execute_in_process,
    worker_defers_simulation,
    evidence_nature_for_simulation_status,
    request_for_granted_window,
    simulation_policy_from_settings,
)
from threat_report_agent.emulation.emulation_plan import (
    _as_int_address,
    controlled_emulation_windows,
    unicorn_granted_windows_for_worker,
)
from threat_report_agent.emulation.controlled_emulation import (
    PLACEHOLDER_STATUSES,
    emulation_entry_key,
    has_real_simulation_result,
    has_uncovered_emulation_entry,
    matching_simulation_results,
    post_static_emulation_needed,
    simulation_covers_request,
)
from threat_report_agent.static.static_simulation import StaticAbstractExecutor
from threat_report_agent.static.static_analysis import (
    StaticFact,
    MAX_INSTRUCTION_WINDOW_ITEMS,
    analyze_xor_decode_window,
    analyze_bytes,
    build_cross_function_chains,
    build_instruction_window_payload,
    correlate_data_references,
    data_reference_truncation,
    derive_mechanism_facts,
    derive_function_mechanism_facts,
    extract_embedded_bytes,
    function_fuzzy_fingerprint,
    identify_format,
    build_investigation_seed_map,
    recovered_payload_from_verification,
    resolve_data_strings_chunked,
    classify_pe_semantics,
    build_pcode_slice,
    build_function_semantic_summary,
    import_api_thunks,
    build_command_string_index,
    recover_dynamic_api_resolutions,
    recover_parent_process_attribute,
    recover_process_creation_arguments,
    track_indirect_function_pointers,
    trace_static_api_arguments,
    unique_thread_function_starts,
    unique_thread_start_routine_vas,
    unique_thread_start_routine_vas_from_pe,
    verify_xor_decode_candidate,
    recover_static_xor_configs,
    decoded_config_string_table,
)
from threat_report_agent.investigation.semantic_predicates import (
    classify_api_symbol,
    is_anti_analysis_signal,
    is_dynamic_loader_call,
    is_execution_call,
    is_injection_call,
    is_network_transport_call,
    normalize_api_symbol,
)
from threat_report_agent.static.function_similarity import (
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
# P3.5-0/D-2: the HOST supplies the tool-execution PORT to the modules it delegates to. The import is only the
# Protocol (a pure type); the adapter is still constructed here, because transport belongs to the composition root.
from threat_report_agent.ports import ToolExecutionPort
from threat_report_agent.tools.tool_execution import (
    ToolRunRequest,
    ToolRunResult,
    TemporalToolExecutor,
    intake_entries_from_payload,
    static_result_from_payload,
)
from threat_report_agent.validation import validate_claim_evidence
from threat_report_agent.model.agent_runtime import AgentRuntime
from threat_report_agent.analysis_trace import (
    build_analysis_trace,
    build_mechanism_effectiveness_traces,
)
from threat_report_agent.runtime_contracts import classify_failure, retry_decision
from threat_report_agent.task.status import (
    AnalysisOutcome,
    TaskLifecycle,
    ToolRunStatus,
    transition_task,
)
from threat_report_agent.product_certification import (
    aggregate_result_class,
    analysis_coverage,
    classify_artifact_result,
    mechanism_coverage_metrics,
    semantic_flow_metrics,
)
# Imported under a private alias because ONE of the delegations below takes a parameter literally named
# `limitations` (the list of limitation strings), which would shadow the module and raise AttributeError.
# MEASURED: that is exactly what the first version of this extraction did, and 7 investigation tests caught it.
from threat_report_agent.task import limitations as _limitations
from threat_report_agent.investigation.seed_support import (
    _ARTIFACT_WIDE_SCHEDULER_DIMENSIONS as _ARTIFACT_WIDE_SCHEDULER_DIMENSIONS,
    _HOW_SEED_CATEGORIES as _HOW_SEED_CATEGORIES,
    _HOW_SLOT_RANK as _HOW_SLOT_RANK,
    _PER_SLOT_TRACE_CAP as _PER_SLOT_TRACE_CAP,
    _PLACEHOLDER_EMU_BUDGET_STATUSES as _PLACEHOLDER_EMU_BUDGET_STATUSES,
    _PROVENANCE_STRIP_KEYS as _PROVENANCE_STRIP_KEYS,
    _SEED_CATEGORY_PLAYBOOKS as _SEED_CATEGORY_PLAYBOOKS,
    _evidence_anchor_keys as _evidence_anchor_keys,
    _evidence_api_symbols as _evidence_api_symbols,
    _provenance_free_digest as _provenance_free_digest,
    scoped_investigation_action_key,
    _seed_context_rows as _seed_context_rows,
    _seed_playbook as _seed_playbook,
    _strip_provenance as _strip_provenance,
    admit_investigation_seed_clusters as admit_investigation_seed_clusters,
    coalesce_investigation_seed_clusters as coalesce_investigation_seed_clusters,
    how_seed_slot_rank as how_seed_slot_rank,
    investigation_budget_charged_action_count as investigation_budget_charged_action_count,
    investigation_seed_step_budget as investigation_seed_step_budget,
)
# THE THREE `X as X` LINES ARE A DELIBERATE RE-EXPORT SURFACE, NOT DEAD IMPORTS, and a Standards-axis review of the
# giant's move is why they are here: the move made them unreadable INSIDE this file (their only reader was the giant),
# the mechanical import cleanup therefore deleted them, and that broke `from threat_report_agent.service import
# plausible_traced_creation_flags` - which the design's section 8 promised would keep working and hands to P4.3 to
# remove, once every reader has been migrated. `X as X` is this repo's recorded spelling for an intentional re-export:
# ruff does not raise F401 for it, unlike a plain import.
from threat_report_agent.investigation.derivation import (
    SimulationWindowOutcome as SimulationWindowOutcome,
    _bind_recovered_xor_verification as _bind_recovered_xor_verification,
    _decode_output_buffer as _decode_output_buffer,
    # P3.3f-2 moved this module-level function with the loop. The design AUTHORISED it to travel (the loop was its only
    # reader), but a Standards-axis review measured that `service._investigation_scheduled_keys` had consequently stopped
    # resolving at all - §7.1 step 4 keeps the old path reachable until P4 deletes the shims, exactly as its twelve
    # siblings are kept.
    _investigation_scheduled_keys as _investigation_scheduled_keys,
    plausible_traced_creation_flags as plausible_traced_creation_flags,
)
from threat_report_agent.investigation import derivation as _derivation
from threat_report_agent.investigation import derivation_support as _derivation_support
from threat_report_agent.investigation.coordinator import (
    deferred_keeps_planner_open,
    frontier_status_is_open,
)
from threat_report_agent.investigation import coordinator as _coordinator
from threat_report_agent.task import task_runner as _task_runner


from threat_report_agent.task.task_runner import SubmissionResult
from threat_report_agent.report import revision_writer as _revision_writer
from threat_report_agent.report.revision_writer import ReportComposeGateRejected as ReportComposeGateRejected
from threat_report_agent import workbench_query as _workbench_query


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


def _qiling_worker_deferred_observation() -> dict[str, object]:
    """Describe a worker-owned Qiling decision without probing the API host."""
    return {
        "status": "DEFERRED_TO_WORKER",
        "simulator": "qiling",
        "stop_reason": "DEFERRED_TO_WORKER",
        "deferred": "isolated_emu_worker",
        "limitations": [
            "Qiling rootfs and OS/architecture compatibility are evaluated by the isolated emu-worker"
        ],
        "anchor": {"type": "qiling_policy", "simulator": "qiling"},
    }


@dataclass(frozen=True)
class RetrievedModelContext:
    """Bounded evidence selected for one model turn and its audit ledger."""

    manifest: tuple[dict[str, object], ...]
    ledger: EvidenceDeliveryLedger
    packets: tuple[ContextPacket, ...]


class ContextMismatchError(ValueError):
    """A task or artifact is not owned by the current DSH analysis context."""

    code = "CONTEXT_MISMATCH"


class AnalysisRunOrphaned(Exception):
    """The API process was restarted while this run was in flight.

    Analysis executes as FastAPI ``BackgroundTasks`` inside the API process, so a
    restart silently ends the run: nothing fails it, nothing retries it, and it
    sits in ``RUNNING`` forever.   Measured on this deployment, five tasks were
    stranded that way - ``0a690901`` (38434 evidence rows, 46 claims, 0 report
    revisions) had produced no new evidence for over two hours while the container
    was idle at 4.7% CPU, and older ones had been "running" for 10 to 20 hours.

    The class exposes ``code = "ANALYSIS_RUN_ORPHANED"``, which
    `classify_failure` matches explicitly to the retryable ``WORKER_FAILURE`` code:
    an interrupted run that never reached a conclusion is exactly the case that
    should be allowed one retry.
    """

    code = "ANALYSIS_RUN_ORPHANED"


# Alias kept for the contract test that pins this behaviour.
_PROVENANCE_FREE_DIGEST = _provenance_free_digest


# `ReportComposeGateRejected` USED TO BE DEFINED HERE. It moved to `threat_report_agent.report.revision_writer`
# (P3.4-2) and is re-exported in this file's import block above with `X as X`, so the object identity the
# workbench route's 422 handler and the plugin's GATE_REJECTED branch rely on is preserved.


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

# A decoded or embedded object is still analyzed, but a non-code payload
# (for example a short configuration blob) must not be treated as a failed
# deep-disassembly obligation. Recognized executable/script/document
# children remain REQUIRED; opaque binary children stay in the queue with a
# SUPPORTING obligation and are reported as a static-boundary data object.
_REQUIRED_CHILD_TYPES = frozenset({"pe", "script", "pdf", "ooxml", "ole", "zip", "7z"})


# Persist CANDIDATE HOW is a claim, not an OPEN TRACE ticket. Kunglao
# DISPATCH_VERIFIER / completion notes-due: leftover remainder is isolated
# emu, not another planner round asking the operator to 再深入.
# Recorded UNKNOWN/PARTIAL/UNSUPPORTED is report content (honest static
# boundary), not a mining ticket TRACE cannot invent (WinHTTP / 0x09080008).


_ANALYSIS_INTENT_MARKERS = (
    "分析这个样本",
    "分析此样本",
    "分析样本",
    "analyze this sample",
    "analyse this sample",
    "start static analysis",
    "开始分析",
)
_IN_FLIGHT_TASK_LIFECYCLES = frozenset(
    {
        TaskLifecycle.PENDING.value,
        TaskLifecycle.WAITING_GATE.value,
        TaskLifecycle.RUNNING.value,
    }
)


def analysis_intent_question(question: object) -> bool:
    """True when the user asked to start one bounded static analysis pass."""
    blob = " ".join(str(question or "").split()).casefold()
    if not blob:
        return False
    return any(marker.casefold() in blob for marker in _ANALYSIS_INTENT_MARKERS)


def _child_obligation(detected_type: str) -> str:
    return "REQUIRED" if str(detected_type).casefold() in _REQUIRED_CHILD_TYPES else "SUPPORTING"


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
    """The compatibility FACADE: dependency assembly plus the stable operations callers may rely on.

    PUBLIC CONTRACT (plan section 8, step P3.1). This class is the boundary between the HTTP adapter (`main.py`) and
    everything behind it, and it has exactly two responsibilities:

      1. **dependency assembly** - settings, `Database` and the content store are injected here and nowhere else;
      2. **stable operations**, of which there are four groups:
         * START an Analysis Task - `create_case`, `analyze_submission`, `analyze_directory`;
         * READ status - `task_view`;
         * READ a Report Revision - `get_report_revision` (the id comes from
           `task_view(...)["authoritative_report_revision_id"]);
         * an AUTHORISED workbench query - `get_evidence`, `workbench_submit_action`.

    `tests/test_service_facade_contract.py` exercises those four groups end-to-end through public members only, and
    checks that BOTH halves of the boundary hold: the contract test itself reaches no private member, and `main.py`
    reaches none either.

    WHAT THIS DOCSTRING IS FOR during Phase 3: the class is being split by RESPONSIBILITY AND SEAM, not by line count,
    and each sub-step (P3.2 `TaskRunner`, P3.3 `InvestigationCoordinator`, P3.4 `ReportRevisionWriter`, P3.5
    `EmulationCoordinator`, P3.6 `WorkbenchQueryReader`) must end with this facade **still constructible by the
    existing HTTP path** and still serving the four groups above. MEASURED when this contract was written: 352
    methods, 76 public and 276 private, in a 29,640-line module; the 276 private methods are expected to keep working
    by delegation for now (plan P3.1's failure clause forbids deleting them first).
    """

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
    _MODEL_EVIDENCE_LIMIT = 12
    _MODEL_EVIDENCE_VALUE_LIMIT = 640
    # One post-baseline planning turn is sufficient to let the model select
    # targeted static follow-ups.  Replanning after every parser stage added
    # latency but no additional semantic frontier, and allowed a streaming
    # provider to delay terminal report generation for many minutes.
    # Allow a short evidence-driven planning horizon.  The first turn runs
    # after the mandatory parser baseline, then up to two bounded follow-ups
    # can request targeted static actions.  This preserves observable
    # multi-turn Agent behavior without permitting an unbounded provider loop.
    _MAX_MODEL_REPLAN_TURNS = 3
    _MAX_CONSECUTIVE_REPLAN_NO_GAIN = 2
    # Analysis runs over the whole recovered function set.  Ranking the
    # functions and then keeping only a small page is information loss: on a
    # 551KB Rust PE Ghidra recovered 703 functions and the previous 96-function
    # page silently dropped every mechanism that lived in the unranked tail
    # (scheduled-task persistence, Windows Defender tampering, and
    # DeleteFileW -> SetFileInformationByHandle delete-on-reboot), even though
    # the strings behind them were already in Evidence.
    # This constant is therefore a degenerate-input guard, not an analysis
    # quota: 65_536 is ~19x the largest corpus observed on the live system
    # (3455 functions, statically linked C++) and clears the low tens of
    # thousands that Ghidra recovers from heavily monomorphised Rust/C++
    # binaries, while still bounding post-processing if a crafted image makes
    # the exporter emit a function per byte.  The complete exporter JSON stays
    # in object storage regardless.
    _MAX_GHIDRA_FUNCTIONS = 65_536
    # Detailed call/Xref/CFG rows dominate PostgreSQL index and audit work on
    # PE files with large autogenerated function corpora.  Keep a compact,
    # deterministic per-function window; the complete Ghidra JSON remains in
    # object storage for later targeted retrieval.
    _MAX_GHIDRA_CALL_EVIDENCE_PER_FUNCTION = 24
    _MAX_GHIDRA_XREF_EVIDENCE_PER_FUNCTION = 12
    _MAX_GHIDRA_CFG_EVIDENCE_PER_FUNCTION = 12
    # The stored instruction window IS the analysed function body: the
    # abstract executor, CFG slice and decompile projections all read this same
    # payload.  A 256-instruction preview therefore deleted the function's own
    # mechanism from Evidence -- for the 551KB Rust PE
    # 6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145 the
    # window held 418 of FUN_140004605's 4481 instructions and omitted every
    # LEA in its Windows Defender registry block.  Keep the complete recovered
    # body.  The value lives in static_analysis next to the window builder so
    # the guard and the payload contract cannot drift apart; it is a
    # degenerate-input guard, not a quota, and the payload always records
    # instructions_total / instructions_selected / instructions_omitted.
    _MAX_GHIDRA_INSTRUCTIONS_PER_FUNCTION = MAX_INSTRUCTION_WINDOW_ITEMS
    # Planner history carries evidence identifiers for audit correlation, but
    # must not replay thousands of IDs into every subsequent model request.
    _MAX_COMPLETED_ACTION_EVIDENCE_IDS = 128
    # Mechanism materialization and the analyst report are projections.  Keep
    # their working set bounded even when the immutable Evidence ledger has
    # hundreds of thousands of parser rows.
    _MECHANISM_PROJECTION_EVIDENCE_LIMIT = 4096
    _MECHANISM_PROJECTION_LINK_LIMIT = 256
    # PMA plan snapshot needs PE/import/string/call facts, not the Ghidra dump.
    _PMA_PLAN_FACT_KINDS = (
        "file_identity",
        "hash",
        "file_hash",
        "pe_structure",
        "pe_section",
        "section",
        "import_symbol",
        "export_symbol",
        "string",
        "string_semantics",
        "function_call",
        "api_argument_trace",
        "encoded_blob",
        "crypto_indicator",
        "high_entropy_section",
        "mechanism_decode_window",
        "crypto_pattern",
        "tls_callback",
        "tls_metadata",
        "unpacked_payload",
        "reconstructed_iat",
        "decoded_artifact",
        "mechanism_chain",
        "process_creation_flags",
    )
    _PMA_PLAN_FACT_LIMIT = 512
    # Investigation actions query the immutable ledger repeatedly. Keep one
    # artifact-local, priority-ordered working set in memory instead of
    # hydrating the same tens of thousands of ORM rows for every action.
    _INVESTIGATION_EXECUTION_EVIDENCE_LIMIT = 20_000
    # Resume-shaped Ghidra persist writes decode_result/value_flow early, then
    # investigation appends hundreds of ordinary data_reference rows. A single
    # newest-256 mix of those kinds dropped every decoded_config_xref. Load
    # each kind with its own cap so persist-time consumer links remain visible.
    _CONFIG_CONSUMER_SEED_KIND_LIMITS = {
        "decode_result": 256,
        "value_flow": 256,
        "data_reference": 512,
        "api_argument_trace": 256,
        "resolved_api": 256,
        "process_creation_flags": 32,
    }
    # Persist-time CreateProcess / PPID / resolved-API catalog rows sit in the
    # middle of Ghidra output. Newest-256 is investigation flood; oldest-128
    # is prologue traces. Scan enough persist-time rows that a 96-function
    # budget can still surface command/flags and parent-attribute facts.
    _CATALOG_HOW_SEED_SCAN_LIMIT = 2048
    _METHODOLOGY_EVIDENCE_LIMIT = 8_192
    _MODEL_EVIDENCE_PRIORITY = {
        "pe_structure": 100,
        "function": 98,
        # Deep investigation emits these rows after the initial parser pass.
        # Keep them ahead of dense string/metadata corpora so a bounded SQL
        # working set preserves the semantic context needed by later actions.
        "function_context": 97,
        "function_call": 96,
        "function_instruction_window": 95,
        "function_interface": 94,
        "function_semantic_summary": 94,
        "api_argument_trace": 94,
        "abstract_execution_trace": 94,
        "simulation_result": 99,
        "decompile_slice": 93,
        "pcode_slice": 93,
        "function_mechanism": 92,
        "function_data_correlation": 92,
        "value_flow": 91,
        "resolved_api": 91,
        "loader_indicator": 90,
        "execution_indicator": 90,
        "anti_analysis_indicator": 90,
        "c2_indicator": 90,
        "cfg_block": 86,
        "xref": 84,
        "data_reference": 83,
        "decode_result": 88,
        "constant": 82,
        "import_symbol": 82,
        "export_symbol": 82,
        "decoded_artifact": 78,
        "file_identity": 74,
        "archive_member": 72,
        "resource_inventory": 70,
        "pe_resource": 70,
        "pe_resource_directory": 70,
        "embedded_artifact": 70,
        "embedded_object": 70,
        "encoded_blob": 64,
        "string_reference": 40,
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
        # ``MODEL_CALLS_ENABLED`` is a deployment-level kill switch.  A
        # persisted UI configuration may enable model routing, but it must
        # never be able to raise this process' effective permission after a
        # restart (or after an API hot reload).
        self._model_calls_env_enabled = bool(settings.model_calls_enabled)
        model_route = "deterministic-static-rules"
        self.triage_agent = TriageAgent(self.prompts, model_route)
        self.static_agent = StaticAnalysisAgent(self.prompts, model_route)
        self.similarity_index = FunctionSimilarityIndex.load_builtin()
        self.methodology_library = FactLibrary.load_builtin()
        self.model_gateway = ModelGateway(
            settings.primary_model,
            settings.fallback_model,
            enabled=settings.model_calls_enabled,
        )
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
        # Kunglao wait-signal analogue: the wait tool owns the cursor so a
        # model that retries with after_seq=0 cannot dump the same prefix.
        self._wait_cursors: dict[str, tuple[str, int]] = {}
        # Bounded analysis concurrency.  Static analysis is CPU-bound and runs inside the
        # API process, and nothing limited how many runs executed at once: measured
        # 2026-09-18, three concurrent tasks (two of them this session's own Resume runs)
        # each held ~100% of a CPU and NONE reached a revision, so the workbench appeared
        # to answer every submission with the last sample that had ever finished.  A
        # second run now waits for a slot instead of competing for the same core.
        self._analysis_slots = threading.BoundedSemaphore(
            max(1, int(getattr(self.settings, "max_concurrent_analyses", 1) or 1))
        )

    def reconcile_orphaned_analysis_runs(self) -> list[str]:
        """Fail runs the API process was restarted out from under.

        Analysis is executed by FastAPI ``BackgroundTasks`` inside the API
        process, so there is no durable queue and no other owner of an in-flight
        run.  When the container restarts - which happens on every image rebuild -
        the run simply stops existing while its row stays ``RUNNING``.  Nothing
        failed it, nothing retried it, and the workbench waited forever.

        Measured on this deployment before the fix: five tasks stranded, including
        ``0a690901`` with 38434 Evidence rows / 46 Claims / 0 report revisions and
        no new evidence for over two hours, and two more "running" for 10-20 hours.
        A user submitting a sample therefore saw a session that never completed,
        which is precisely the "any sample must run to completion" requirement.

        This runs once at startup, when the caller is by definition the only
        process and therefore owns no in-flight work, so every ``RUNNING`` row is
        orphaned.  Tasks are failed through the normal failure contract (retryable
        ``WORKER_FAILURE``), so the existing retry machinery decides whether a
        retry is allowed rather than this method re-running anything itself.

        Returns the ids it reconciled, for logging and tests.
        """
        reconciled: list[str] = []
        # FINALIZING is included deliberately: it is set before the snapshot is
        # frozen and the report revision is written, so a restart there also
        # leaves a task that will never produce a report.
        stuck_states = (TaskLifecycle.RUNNING.value, TaskLifecycle.FINALIZING.value)
        with self.database.session_factory.begin() as session:
            stuck = list(
                session.scalars(
                    select(AnalysisTask).where(AnalysisTask.lifecycle.in_(stuck_states))
                )
            )
            for task in stuck:
                previous_lifecycle = str(task.lifecycle)
                try:
                    task.lifecycle = transition_task(
                        task.lifecycle, TaskLifecycle.FAILED
                    ).value
                except ValueError:
                    # Lifecycle contract refuses the transition; leave the row
                    # exactly as it was rather than forcing an invalid state.
                    continue
                task.analysis_class = "FAILED_ANALYSIS"
                task.outcome = None
                task.finished_at = utcnow()
                exc = AnalysisRunOrphaned(
                    "API process restarted while this analysis run was in flight"
                )
                failure_event = self._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type="analysis_task.orphaned",
                    actor="system",
                    object_type="AnalysisTask",
                    object_id=task.id,
                    payload={
                        "error_type": type(exc).__name__,
                        "previous_lifecycle": previous_lifecycle,
                        "started_at": task.started_at.isoformat() if task.started_at else None,
                        "reason": "no in-flight run survives an API process restart",
                    },
                )
                self._record_analysis_failure(
                    session,
                    task,
                    exc,
                    stage="PROCESS_RESTART",
                    event_id=failure_event.id,
                )
                self._seal_task_audit_chain(session, task, "analysis_task.orphaned")
                reconciled.append(str(task.id))
        return reconciled

    @staticmethod
    def _record_analysis_failure(session: Session, task: AnalysisTask, exc: BaseException, *, stage: str = 'ANALYSIS', event_id: str | None = None) -> dict[str, object]:
        return _limitations.record_analysis_failure(session, task, exc, stage=stage, event_id=event_id)

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
            return self._run_analysis(case_id, task_id, entries, modules, actor, intake_executions)
        except Exception as exc:
            if not self._is_evidence_index_corruption(exc):
                raise
            result = self.database.repair_evidence_search_keys()
            self._record_derived_index_repair(task_id, result=result, original_error=exc)
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
            return self._run_analysis(case_id, task_id, entries, modules, actor, intake_executions)

    @staticmethod
    def _failure_payload(row) -> dict[str, object] | None:
        return _limitations.failure_payload(row)

    def _planner_user_action(
        self,
        *,
        configured: bool,
        provider: str,
        model: str,
        http_status: object,
        last_status: str | None,
    ) -> str:
        return _coordinator._planner_user_action(
            configured=configured,
            provider=provider,
            model=model,
            http_status=http_status,
            last_status=last_status,
        )

    def _model_status_payload(
        self,
        failure: AnalysisFailureRecord | None,
        model_calls: list[ModelCall] | tuple[ModelCall, ...] | None = None,
    ) -> dict[str, object]:
        """Project model/transport health separately from STATIC_BOUNDARY."""
        latest = next(iter(model_calls or ()), None)
        parameters = latest.parameters if latest is not None and isinstance(latest.parameters, dict) else {}
        http_status = parameters.get("http_status")
        failure_code = str(failure.failure_code) if failure is not None else None
        last_status = str(latest.status) if latest is not None else None
        error_type = str(latest.error_type or "") if latest is not None else None
        empty_reply = last_status == "EMPTY" or (error_type or "").casefold() in {
            "empty",
            "empty_reply",
            "empty_response",
        }
        transport_codes = {"MODEL_FAILURE", "TIMEOUT_FAILURE", "WORKER_FAILURE"}
        failed_call = last_status in {"FAILED", "TIMEOUT", "EMPTY", "ERROR"}
        http_transport = http_status in {401, 402, 403, 408, 429, 500, 502, 503, 504}
        is_model_or_transport = bool(
            (failure_code in transport_codes)
            or failed_call
            or http_transport
            or empty_reply
            or (error_type or "").casefold() in {"timeout", "empty_reply", "http_error", "provider_error"}
        )
        kind = "MODEL_OR_TRANSPORT" if is_model_or_transport else ("NONE" if failure is None else "TASK_FAILURE")
        primary = self.settings.primary_model
        provider = str((latest.provider if latest is not None else "") or primary.provider or "")
        model = str((latest.model if latest is not None else "") or primary.model or "")
        configured = bool(getattr(primary, "configured", False))
        return {
            "kind": kind,
            "last_status": last_status,
            "error_type": error_type or None,
            "http_status": http_status,
            "provider": provider or None,
            "model": model or None,
            "prompt_id": latest.prompt_id if latest is not None else None,
            "prompt_version": latest.prompt_version if latest is not None else None,
            "prompt_sha256": latest.prompt_sha256 if latest is not None else None,
            "failure_code": failure_code,
            "distinct_from_static_boundary": bool(
                is_model_or_transport or (failure_code and failure_code != "STATIC_BOUNDARY")
            ),
            "distinct_from_dsh_chat": False,
            "user_action": self._planner_user_action(
                configured=configured,
                provider=provider,
                model=model,
                http_status=http_status,
                last_status=last_status,
            ),
        }

    def _analysis_planner_payload(
        self,
        failure: AnalysisFailureRecord | None = None,
        model_calls: list[ModelCall] | tuple[ModelCall, ...] | None = None,
    ) -> dict[str, object]:
        """Investigation uses the DSH conversation model, not a second planner."""
        status = self._model_status_payload(failure, model_calls)
        return {
            "role": "dsh-conversation",
            "source": "settings.models",
            "distinct_from_dsh_chat": False,
            "dsh_chat_note": "调查与对话共用左下角设置 →「模型」。",
            "enabled": True,
            "last_status": status.get("last_status"),
            "http_status": status.get("http_status"),
            "prompt_id": status.get("prompt_id"),
            "kind": status.get("kind"),
            "user_action": status.get("user_action"),
        }

    def workbench_analysis_planner_model_view(self) -> dict[str, object]:
        return self._analysis_planner_payload()

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

    @property
    def tool_executor(self) -> ToolExecutionPort:
        """The tool-execution PORT this service hands to the modules it delegates to (P3.5-0/D-2).

        WHO READS IT: `task/task_runner.py`'s cancellation cluster, through its host pin (`TASK_HOST_MEMBERS`), as
        `host.tool_executor.cancel(workflow_id)`. That module must not import `tools/tool_execution.py` - it is the
        transport adapter, and a P3.5 emulation coordinator inheriting that import would inherit Temporal - so the
        seam is handed over here instead.

        WHY A PROPERTY AND NOT AN ATTRIBUTE SET IN `__init__`: the pre-D-2 code read `host.settings.temporal_address`
        at CALL time and built the adapter per cancellation call, and `reload_model_configuration` REPLACES
        `self.settings` (`service.py:1112`). An attribute captured in `__init__` would therefore keep cancelling
        against the address that was configured at start-up. The adapter holds nothing but the address, so building
        it per access costs nothing and preserves the measured behaviour exactly.

        It is deliberately built from the module global `TemporalToolExecutor`, so a test that replaces
        `service.TemporalToolExecutor` still replaces what this returns (`tests/test_speakeasy_reachability.py:146`
        relies on that for the execute path). This service's OWN four execute sites keep constructing the adapter
        directly: the host is where transport is allowed, and D-2 changed only the DELEGATED consumer.
        """
        return TemporalToolExecutor(self.settings.temporal_address)

    def reload_model_configuration(self) -> None:
        """Load the persisted model routes and atomically replace the gateway."""
        with self.database.session_factory() as session:
            row = session.get(ModelConfiguration, "active")
            if row is None:
                return
            if not self._model_config_key:
                raise RuntimeError("MODEL_CONFIG_SECRET_KEY or GATE_SECRET_KEY is required")
            key = self._model_config_key
            effective_enabled = bool(row.enabled) and self._model_calls_env_enabled
            # Keep provider metadata/credential state available for health and
            # configuration views even when the deployment kill switch is off.
            # The effective service flag below, plus the public model endpoint
            # guard, is the permission boundary that prevents network calls.
            primary = self._provider_from_config_row(row, "primary", key)
            fallback = self._provider_from_config_row(row, "fallback", key)
            self.settings = replace(
                self.settings,
                primary_model=primary,
                fallback_model=fallback,
                model_calls_enabled=effective_enabled,
                model_context_max_bytes=row.context_max_bytes,
                model_timeout_s=float(row.timeout_s),
                model_max_tokens=int(row.max_tokens),
            )
            self.model_gateway = ModelGateway(
                primary,
                fallback,
                enabled=effective_enabled,
            )
            self.model_config_revision = row.revision

    @staticmethod
    def _provider_from_config_row(
        row: ModelConfiguration,
        slot: str,
        key: str,
        *,
        globally_enabled: bool = True,
    ) -> Any:
        prefix = f"{slot}_"
        ciphertext = getattr(row, f"{prefix}api_key_ciphertext")
        api_key = SecretCipher(key).decrypt(ciphertext) if ciphertext else ""
        return ModelProviderSettings(
            provider=getattr(row, f"{prefix}provider"),
            base_url=getattr(row, f"{prefix}base_url"),
            model=getattr(row, f"{prefix}model"),
            api_key=api_key,
            api_style=getattr(row, f"{prefix}api_style"),
            enabled=(
                bool(getattr(row, f"{prefix}enabled"))
                and bool(row.enabled)
                and globally_enabled
            ),
            stream=bool(getattr(row, f"{prefix}stream", True)),
            supports_json_mode=bool(getattr(row, f"{prefix}supports_json_mode", True)),
            temperature=float(getattr(row, f"{prefix}temperature", 0.0)),
            top_p=float(getattr(row, f"{prefix}top_p", 1.0)),
            disable_reasoning=bool(getattr(row, f"{prefix}disable_reasoning", True)),
        )

    def _config_route_view(self, row: ModelConfiguration, slot: str) -> dict[str, object]:
        return _workbench_query._config_route_view(self, row, slot)

    def model_configuration_view(self) -> dict[str, object]:
        return _workbench_query.model_configuration_view(self)

    def update_model_configuration(
        self, payload: dict[str, object], *, actor: str
    ) -> dict[str, object]:
        key = self._model_config_key
        if not key:
            raise ValueError("Configure MODEL_CONFIG_SECRET_KEY before saving model credentials")
        context_max_bytes = int(
            payload.get("context_max_bytes", self.settings.model_context_max_bytes)
        )
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
                    raise ValueError(
                        f"{slot} provider, base_url and model are required when enabled"
                    )
                if base_url:
                    parsed_url = urlparse(base_url)
                    local_http = parsed_url.scheme == "http" and parsed_url.hostname in {
                        "localhost",
                        "127.0.0.1",
                    }
                    if parsed_url.scheme != "https" and not local_http:
                        raise ValueError(
                            f"{slot} base_url must use HTTPS (localhost is allowed for development)"
                        )
                    if (
                        parsed_url.username
                        or parsed_url.password
                        or parsed_url.query
                        or parsed_url.fragment
                    ):
                        raise ValueError(
                            f"{slot} base_url must not contain credentials, query parameters, or fragments"
                        )
                if api_style not in {
                    "openai",
                    "openai-compatible",
                    "chat-completions",
                    "anthropic",
                    "messages",
                }:
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
                setattr(
                    row, f"{prefix}disable_reasoning", bool(route.get("disable_reasoning", True))
                )
                secret = route.get("api_key")
                if bool(route.get("clear_api_key", False)):
                    setattr(row, f"{prefix}api_key_ciphertext", None)
                    key_changed_slots.append(slot)
                elif secret is not None and str(secret):
                    plaintext = (
                        secret.get_secret_value()
                        if hasattr(secret, "get_secret_value")
                        else str(secret)
                    )
                    setattr(
                        row, f"{prefix}api_key_ciphertext", SecretCipher(key).encrypt(plaintext)
                    )
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
        return _task_runner.archive_case(self, case_id, actor=actor)

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
        return _task_runner.prepare_blind_run(self, task_id, scorecard_version=scorecard_version, actor=actor)

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
                        json.dumps(
                            item.value, ensure_ascii=True, sort_keys=True, default=str
                        ).encode("utf-8")
                    ).hexdigest(),
                    "anchor_sha256": hashlib.sha256(
                        json.dumps(
                            item.anchor, ensure_ascii=True, sort_keys=True, default=str
                        ).encode("utf-8")
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
            serialized = json.dumps(
                snapshot, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            )
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
        return _task_runner.create_submission_task(
            self,
            case_id=case_id,
            filename=filename,
            submitted_size=submitted_size,
            content=content,
            source_kind=source_kind,
            background_context=background_context,
            background_context_input=background_context_input,
            selected_modules=selected_modules,
            idempotency_key=idempotency_key,
            trace_id=trace_id,
            actor=actor,
        )

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
            # Serialise the CPU-bound analysis.  `acquire` blocks the calling worker
            # thread; the workbench poller keeps answering, and the queued run starts as
            # soon as the running one finishes instead of halving its CPU.
            with self._analysis_slots:
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
            # A direct API submission has no DSH conversation and therefore
            # needs the bounded backend planner.  Workbench-created tasks set
            # ``planning_owner=dsh`` and are planned by that single user-facing
            # conversation; the global deployment default must not disable
            # direct API planning or make the two paths indistinguishable.
            planning_owner = str(
                (task.strategy_snapshot or {}).get("planning_owner") or "backend"
            ).lower()
            blind_enabled = bool(
                blind_configuration.get("enabled") and blind_configuration.get("reference_isolated")
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
                "planning_owner": planning_owner,
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
                        "DISCOVERED",
                        "PRIORITIZED",
                        "CONTEXT_READY",
                        "HYPOTHESIZING",
                        "INVESTIGATING",
                        "VERIFYING",
                        "MECHANISM_READY",
                        "CLAIM_READY",
                        "UNKNOWN",
                        "BLOCKED",
                        "REJECTED",
                        "CONTRADICTED",
                        "CLOSED",
                    ],
                    "threads": [
                        item.model_dump(mode="json") for item in plan.investigation_threads
                    ],
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
                str(item.get("artifact_id")) for item in existing_threads if isinstance(item, dict)
            }
            for seed in ranked_seeds:
                if seed.artifact_id in existing_ids:
                    continue
                thread_id = (
                    "thread-"
                    + hashlib.sha256(f"{task.id}:{seed.artifact_id}".encode("utf-8")).hexdigest()[
                        :20
                    ]
                )
                hypothesis_id = (
                    "hypothesis-"
                    + hashlib.sha256(f"{thread_id}:mechanism".encode("utf-8")).hexdigest()[:20]
                )
                mechanism_id = (
                    "mechanism-"
                    + hashlib.sha256(f"{thread_id}:static".encode("utf-8")).hexdigest()[:20]
                )
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
                        "limitations": [
                            "No runtime execution or network access is permitted in this phase."
                        ],
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
                            "seed_kind": QuestionCompiler()
                            .compile(
                                "",
                                artifact_id=seed.artifact_id,
                                detected_type=next(
                                    (
                                        str(item.detected_type)
                                        for item in artifacts
                                        if item.id == seed.artifact_id
                                    ),
                                    "unknown",
                                ),
                            )[0]
                            .thread_type,
                            "question": QuestionCompiler()
                            .compile(
                                "",
                                artifact_id=seed.artifact_id,
                                detected_type=next(
                                    (
                                        str(item.detected_type)
                                        for item in artifacts
                                        if item.id == seed.artifact_id
                                    ),
                                    "unknown",
                                ),
                            )[0]
                            .question,
                            "rationale": seed.rationale,
                            "expected_tools": list(seed.expected_tools),
                            "required_evidence_kinds": list(
                                QuestionCompiler()
                                .compile(
                                    "",
                                    artifact_id=seed.artifact_id,
                                    detected_type=next(
                                        (
                                            str(item.detected_type)
                                            for item in artifacts
                                            if item.id == seed.artifact_id
                                        ),
                                        "unknown",
                                    ),
                                )[0]
                                .required_evidence_kinds
                            ),
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
            # The first planner turn must see persisted static observations.
            # Planning against the pre-parser context produces selectors that
            # cannot be anchored to Evidence and turns the model route into a
            # write-only hint.  Start with the mandatory deterministic tools;
            # the bounded replan below runs after the first tool transaction
            # commits its observations.
            model_actions, planning_limitations = [], []
        limitations: list[str] = list(planning_limitations)
        execution_queue = self._build_execution_queue(
            deterministic_actions, model_actions, artifacts
        )
        planned_tools_by_artifact: dict[str, tuple[str, ...]] = {}
        for action in execution_queue:
            if action.source == "model_plan":
                planned_tools_by_artifact.setdefault(action.artifact_id, tuple())
                planned_tools_by_artifact[action.artifact_id] = tuple(
                    dict.fromkeys(
                        (*planned_tools_by_artifact[action.artifact_id], action.tool_name)
                    )
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
        # Every route starts with zero model turns.  The first planner call is
        # intentionally made only after a semantic static baseline commits
        # Evidence, so model actions are anchored to persisted observations.
        model_replan_turns = 0
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
            # Keep the orchestration session read-only around the action.
            # Static parser execution may block on a Temporal Worker for
            # minutes, so any transaction opened by the bookkeeping queries
            # is explicitly rolled back before entering the external call.
            with self.database.session_factory() as session:
                task = session.get(AnalysisTask, task_id)
                artifact = session.get(Artifact, artifact_id)
                if task is None or artifact is None:
                    raise LookupError(artifact_id)
                if task.lifecycle == TaskLifecycle.CANCELLED.value:
                    return SubmissionResult(case_id, task_id, task.lifecycle, None, None)
                planned_names = planned_tools_by_artifact.get(artifact_id, ())
                evidence_before = (
                    session.query(Evidence)
                    .filter(
                        Evidence.task_id == task_id,
                        Evidence.artifact_id == artifact_id,
                    )
                    .count()
                )
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
                session.rollback()
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
                elif scheduled.tool_name == "controlled-emulator":
                    limitations.extend(
                        self._run_controlled_emulator(
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
                            release_transaction_before_wait=True,
                        )
                    )
                session.commit()
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
                            session.query(Evidence)
                            .filter(
                                Evidence.task_id == task_id,
                                Evidence.artifact_id == artifact_id,
                            )
                            .count()
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
                        limitations.append(
                            f"Child artifact content unavailable: {child.logical_path}."
                        )
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
            # Replan only after a meaningful persisted frontier delta.  A
            # completed tool invocation, a model call, or a no-result is not
            # itself a reason to ask the model again: that previously created
            # repetitive plans against identical evidence.  Static failures
            # are recorded by their normal autopsy path; a later planner can
            # see them only after some new static observation changes the
            # decision surface.
            semantic_baseline_ready = new_evidence_count > 0 and scheduled.tool_name in {
                "ghidra-headless",
                "script-parser",
                "document-carrier-parser",
                "builtin-static-analyzer",
            }
            # A model-selected specialist may advance the plan, but only when
            # it actually produced a new observation.  This makes an explicit
            # evidence delta, rather than a scheduler event, the replan gate.
            model_observation_ready = new_evidence_count > 0 and scheduled.source == "model_plan"
            if (
                self.settings.model_calls_enabled
                and self.settings.environment.lower() != "test"
                and planning_owner != "dsh"
                and (semantic_baseline_ready or model_observation_ready)
                and model_replan_turns < self._MAX_MODEL_REPLAN_TURNS
                and consecutive_replan_no_gain < self._MAX_CONSECUTIVE_REPLAN_NO_GAIN
            ):
                model_replan_turns += 1
                remaining_ids = list(dict.fromkeys(item[0].artifact_id for item in pending)) or [
                    artifact_id
                ]
                with self.database.session_factory() as session:
                    remaining_artifacts = list(
                        session.scalars(select(Artifact).where(Artifact.id.in_(remaining_ids)))
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
                    pending_by_key = {
                        (item[0].artifact_id, item[0].tool_name): item for item in pending
                    }
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
            stop_reason=(
                "STATIC_QUEUE_DRAINED" if not pending else "STATIC_QUEUE_BUDGET_EXHAUSTED"
            ),
        )
        with self.database.session_factory() as session:
            all_artifacts = list(
                session.scalars(select(Artifact).where(Artifact.task_id == task_id))
            )

        # Methodology profiles are a first-class static result even when the
        # optional planning model is unavailable.  The operation is idempotent
        # per Artifact and therefore safe after a model-selected specialist turn.
        for artifact in all_artifacts:
            limitations.extend(
                self._run_methodology_action(
                    task_id, artifact.id, "signal-extractor", scheduler="deterministic_methodology"
                )
            )

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
                    kinds = tuple(
                        sorted(
                            {
                                str(item)
                                for item in session.scalars(
                                    select(Evidence.kind).where(
                                        Evidence.task_id == task_id,
                                        Evidence.artifact_id == artifact.id,
                                    )
                                ).all()
                            }
                        )
                    )
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
                self._persist_pma_static_analysis_plan(session, task)
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
        if self.settings.model_calls_enabled and planning_owner != "dsh":
            limitations.extend(self._run_investigation_loop(task_id, model_actions_only=True))

        # Turn parser observations into a bounded, evidence-driven investigation
        # loop.  Keep dispatching while later high-value seeds remain deferred
        # so a first user request does not idle with unused later passes.
        limitations.extend(run_analysis_task_investigation(self, task_id))

        if self.settings.model_calls_enabled and planning_owner != "dsh":
            # The deterministic continuation can discover new mechanism gaps
            # after the last in-queue planner turn.  Give those gaps a small,
            # explicit planning horizon before synthesis so a first request
            # does not end with a shallow static listing and require the user
            # to say "continue".  The helper persists a stop reason and keeps
            # the provider/action budget bounded.
            limitations.extend(self._run_gap_driven_model_rounds(task_id))
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
                set(limitations)
                | set(self._completion_limitations(session, task.id, all_artifacts))
                # Operational failures carry their own reason; without this a cancelled or timed-out tool run
                # was indistinguishable from a run that simply produced less. Measured 0/551 revisions named
                # `CANCELLED` or `TIMED_OUT` while the database held 7 timed-out and 2 cancelled tool runs.
                # These now reach the reader through `_merge_operational_limitations` -> the document key ->
                # `render_official_markdown`.
                | set(self._failed_tool_run_limitations(session, task.id))
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
                    item
                    for item in task.limitations
                    if any(
                        marker in str(item).casefold()
                        for marker in (
                            "missing custom dll",
                            "required artifact",
                            "packed",
                            "packer",
                            "virtualized",
                            "self-modif",
                            "runtime-only",
                            "runtime only",
                            "decompiler",
                            "decompilation failed",
                            "unresolved indirect",
                            "truncated",
                            "damaged",
                            "static boundary",
                            "code recovery",
                            "cannot parse",
                            "parsing incomplete",
                        )
                    )
                ]
                artifact_classes.append(
                    classify_artifact_result(
                        analyzed_artifact.detected_type,
                        tool_runs=[
                            {"status": run.status, "tool_name": run.tool_name} for run in runs
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
            investigation_state = dict((task.strategy_snapshot or {}).get("investigation", {}))
            mechanism_rows = [
                item for item in investigation_state.get("mechanisms", []) if isinstance(item, dict)
            ]
            closed_statuses = {"VERIFIED", "SUPPORTED", "CONFIRMED"}
            closed_rows = [
                item
                for item in mechanism_rows
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
                "MECHANISM_READY",
                "CLAIM_READY",
                "UNKNOWN",
                "BLOCKED",
                "REJECTED",
                "CONTRADICTED",
                "CLOSED",
            }
            semantic_limitations: list[str] = []
            if mechanism_rows:
                closure_rate = len(closed_rows) / max(1, len(mechanism_rows))
                candidate_ratio = (len(mechanism_rows) - len(closed_rows)) / max(
                    1, len(mechanism_rows)
                )
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
            verified_rate = float(
                coverage_payload.get("dimensions", {}).get("verified_mechanism_coverage", 0.0)
                or 0.0
            )
            relation_rate = float(
                coverage_payload.get("dimensions", {}).get("relation_flow_coverage", 0.0) or 0.0
            )
            if task.analysis_class == "FULL_STATIC_ANALYSIS" and (
                (verified_rate <= 0.0 and relation_rate <= 0.0) or bool(semantic_limitations)
            ):
                task.analysis_class = "BOUNDED_STATIC_ANALYSIS"
                # Keep the legacy lifecycle ``outcome`` independent from the
                # product result class. The semantic gap is already visible
                # in coverage dimensions and should not turn a successfully
                # completed parser task into a failed/partial lifecycle.
            task.lifecycle = transition_task(task.lifecycle, TaskLifecycle.FINALIZING).value
            session.flush()
            # C10: emitting a report is not COMPLETE. Bounded or failed
            # analysis stays PARTIAL even when the parser finished.
            task.outcome = (
                AnalysisOutcome.PARTIAL.value
                if (
                    legacy_limitations
                    or task.analysis_class
                    in {"FAILED_ANALYSIS", "BOUNDED_STATIC_ANALYSIS"}
                )
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

    @staticmethod
    def _locator_key(raw: object) -> str:
        return _derivation_support._locator_key(raw)

    @classmethod
    def _overlay_pe_parser_thread_start(
        cls,
        trace: Mapping[str, object],
        pe_summary: Mapping[str, object] | None,
    ) -> dict[str, object]:
        return _derivation_support._overlay_pe_parser_thread_start(trace, pe_summary)


    @classmethod
    def _instruction_access_kind(cls, text: object) -> str | None:
        return _derivation._instruction_access_kind(text)

    @classmethod
    def _reference_access_kind(
        cls, ref_type: object, instruction_text: object = ""
    ) -> str | None:
        return _derivation._reference_access_kind(ref_type, instruction_text)

    @classmethod
    def _ghidra_data_reference_rows(
        cls,
        references: object,
        instructions: object = None,
    ) -> list[dict[str, object]]:
        """Keep unnamed DATA/WRITE refs; classify DATA stores from instruction text."""
        rows = references if isinstance(references, list) else []
        instruction_text: dict[str, str] = {}
        for item in instructions if isinstance(instructions, list) else ():
            if not isinstance(item, dict):
                continue
            address = cls._locator_key(item.get("address") or item.get("from"))
            if not address:
                continue
            instruction_text[address] = str(item.get("text") or item.get("mnemonic") or "")
        found: list[dict[str, object]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            type_text = str(row.get("type") or row.get("reference_type") or "")
            if "call" in type_text.casefold():
                continue
            name = str(row.get("target_name") or row.get("name") or "").strip()
            address = row.get("to") or row.get("address") or row.get("target")
            if not name and not address:
                continue
            site = cls._locator_key(row.get("from"))
            access = cls._reference_access_kind(
                type_text, instruction_text.get(site, "")
            )
            persisted_type = type_text
            if access == "write" and "WRITE" not in type_text.upper():
                persisted_type = "WRITE"
            elif access == "read" and "READ" not in type_text.upper():
                persisted_type = "READ"
            elif access is None:
                # Unnamed DATA refs still identify the object VA. Dropping them
                # hid Resume-shaped XOR buffers that Ghidra never labelled.
                if not name and address in (None, ""):
                    continue
            found.append(
                {
                    "from": row.get("from"),
                    "to": address,
                    "type": persisted_type,
                    "target_name": name,
                }
            )
        return found

    @classmethod
    def _global_accesses_from_rows(
        cls,
        rows: Iterable[object],
    ) -> tuple[dict[str, object], ...]:
        return _derivation._global_accesses_from_rows(rows)

    def derive_investigation_observations(self, source_rows: list[Evidence], action: ActionSpec, *, artifact_content: bytes | None = None, pe_summary: dict[str, object] | None = None) -> list[dict[str, object]]:
        """Public behaviour entry point for `_derive_investigation_observations` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private method stays the implementation, and the facade delegates to it so a test that still
        replaces the private attribute keeps working.
        """
        return self._derive_investigation_observations(source_rows, action, artifact_content=artifact_content, pe_summary=pe_summary)


    def _derive_investigation_observations(
        self,
        source_rows: list[Evidence],
        action: ActionSpec,
        *,
        artifact_content: bytes | None = None,
        pe_summary: dict[str, object] | None = None,
    ) -> list[dict[str, object]]:
        return _derivation._derive_investigation_observations(
            self,
            source_rows,
            action,
            artifact_content=artifact_content,
            pe_summary=pe_summary,
        )

    @classmethod
    def _select_investigation_execution_rows(
        cls,
        rows: list[Evidence],
        *,
        limit: int | None = None,
    ) -> list[Evidence]:
        """Build a bounded, high-signal execution corpus for one artifact.

        The immutable ledger remains complete. This projection is only the
        working set used by repeated read-only investigation actions; cited
        rows can be appended by the caller when they fall outside the cap.
        """
        cap = int(limit or cls._INVESTIGATION_EXECUTION_EVIDENCE_LIMIT)
        if cap < 1:
            return []
        if len(rows) <= cap:
            return list(rows)

        def rank(item: Evidence) -> tuple[int, str, str]:
            return (
                -cls._MODEL_EVIDENCE_PRIORITY.get(item.kind, 20),
                item.created_at.isoformat() if getattr(item, "created_at", None) else "",
                str(item.id),
            )

        return sorted(rows, key=rank)[:cap]

    @classmethod
    def _is_config_consumer_seed_row(cls, row: object) -> bool:
        """Keep recovered XOR consumer links out of the 768 export-symbol window."""
        kind = str(getattr(row, "kind", "") or "")
        value = getattr(row, "value", None)
        value = value if isinstance(value, dict) else {}
        anchor = getattr(row, "anchor", None)
        anchor = anchor if isinstance(anchor, dict) else {}
        if kind == "decode_result":
            return str(value.get("consumer_status") or "") == "LINKED_STATIC"
        if kind == "value_flow":
            return str(value.get("relation") or "") == "output_to_consumer"
        if kind == "data_reference":
            return str(anchor.get("type") or "") in {
                "decoded_config_xref",
                "decoded_config_consumer",
            } or str(value.get("link_kind") or "") == "decoded_va_reference"
        return False

    @classmethod
    def _is_process_creation_seed_row(cls, *args, **kwargs):
        return PersistHow._is_process_creation_seed_row(*args, **kwargs)

    _HTTP_TRANSPORT_API_RE = PersistHow._HTTP_TRANSPORT_API_RE
    _HTTP_ENDPOINT_RE = PersistHow._HTTP_ENDPOINT_RE

    @classmethod
    def _decode_plaintext_texts(cls, *args, **kwargs):
        return PersistHow._decode_plaintext_texts(*args, **kwargs)

    @classmethod
    def _is_rejected_http_plaintext(cls, *args, **kwargs):
        return PersistHow._is_rejected_http_plaintext(*args, **kwargs)

    @classmethod
    def _http_transport_api_names(cls, *args, **kwargs):
        return PersistHow._http_transport_api_names(*args, **kwargs)

    @classmethod
    def _http_endpoints(cls, *args, **kwargs):
        return PersistHow._http_endpoints(*args, **kwargs)

    @classmethod
    def is_http_transport_seed_row(cls, *args, **kwargs):
        """Public behaviour entry point for `_is_http_transport_seed_row` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private classmethod stays the implementation and the facade delegates to it.
        """
        return cls._is_http_transport_seed_row(*args, **kwargs)


    @classmethod
    def _is_http_transport_seed_row(cls, *args, **kwargs):
        return PersistHow._is_http_transport_seed_row(*args, **kwargs)

    @classmethod
    def _select_http_transport_seed_rows(
        cls,
        rows: Iterable[object],
        *,
        limit: int = 128,
    ) -> list[object]:
        return _derivation._select_http_transport_seed_rows(cls, rows, limit=limit)

    @classmethod
    def _select_process_creation_seed_rows(
        cls,
        rows: Iterable[object],
        *,
        limit: int = 128,
    ) -> list[object]:
        return _derivation._select_process_creation_seed_rows(cls, rows, limit=limit)

    @classmethod
    def _unique_thread_start_keys(cls, rows: Iterable[object]) -> set[str]:
        keys: set[str] = set()
        for row in rows:
            if str(getattr(row, "kind", "") or "") != "api_argument_trace":
                continue
            value = getattr(row, "value", None)
            value = value if isinstance(value, dict) else {}
            start = recovered_thread_start_address(value)
            if start:
                keys.update(_address_lookup_keys(start))
        return keys

    @classmethod
    def _is_unique_thread_seed_row(cls, row: object, start_keys: set[str]) -> bool:
        """Keep recovered CreateThread start + start-routine body, not sibling HOW."""
        kind = str(getattr(row, "kind", "") or "")
        value = getattr(row, "value", None)
        value = value if isinstance(value, dict) else {}
        if kind == "api_argument_trace":
            return bool(recovered_thread_start_address(value))
        if kind not in {
            "function_context",
            "function",
            "function_semantic_summary",
            "decompile_slice",
            "cfg_block",
            "function_instruction_window",
        }:
            return False
        if not start_keys:
            return False
        anchor = getattr(row, "anchor", None)
        anchor = anchor if isinstance(anchor, dict) else {}
        entry = str(
            value.get("name")
            or value.get("entry")
            or value.get("function_entry")
            or value.get("function")
            or anchor.get("function_entry")
            or ""
        )
        return bool(start_keys & set(_address_lookup_keys(entry)))

    @classmethod
    def _select_unique_thread_seed_rows(
        cls,
        rows: Iterable[object],
        *,
        limit: int = 128,
    ) -> list[object]:
        return _derivation._select_unique_thread_seed_rows(cls, rows, limit=limit)

    _PPID_ENUM_API_MARKERS = PersistHow._PPID_ENUM_API_MARKERS

    @classmethod
    def _ppid_row_kind_value(cls, *args, **kwargs):
        return PersistHow._ppid_row_kind_value(*args, **kwargs)

    @classmethod
    def _is_process_enumeration_row(cls, *args, **kwargs):
        return PersistHow._is_process_enumeration_row(*args, **kwargs)

    @classmethod
    def _is_explorer_parent_string_row(cls, *args, **kwargs):
        return PersistHow._is_explorer_parent_string_row(*args, **kwargs)

    @classmethod
    def _select_ppid_parent_identity_rows(
        cls,
        rows: Iterable[object],
        *,
        limit: int = 32,
    ) -> list[object]:
        return _derivation._select_ppid_parent_identity_rows(cls, rows, limit=limit)

    @classmethod
    def _is_parent_attribute_seed_row(cls, *args, **kwargs):
        return PersistHow._is_parent_attribute_seed_row(*args, **kwargs)

    @classmethod
    def _parent_process_attribute_token(cls, *args, **kwargs):
        return PersistHow._parent_process_attribute_token(*args, **kwargs)

    @classmethod
    def _ppid_parent_image(cls, *args, **kwargs):
        return PersistHow._ppid_parent_image(*args, **kwargs)

    @classmethod
    def _select_parent_attribute_seed_rows(
        cls,
        rows: Iterable[object],
        *,
        limit: int = 128,
    ) -> list[object]:
        return _derivation._select_parent_attribute_seed_rows(cls, rows, limit=limit)

    @classmethod
    def _is_dynamic_api_seed_row(cls, row: object) -> bool:
        kind = str(getattr(row, "kind", "") or "")
        value = getattr(row, "value", None)
        value = value if isinstance(value, dict) else {}
        if kind == "resolved_api":
            return bool(value.get("api_name") or value.get("api_identity"))
        if kind == "value_flow":
            return str(value.get("relation") or "") == "resolved_pointer_to_call"
        return False

    @classmethod
    def _select_dynamic_api_seed_rows(
        cls,
        rows: Iterable[object],
        *,
        limit: int = 128,
    ) -> list[object]:
        return _derivation._select_dynamic_api_seed_rows(cls, rows, limit=limit)

    @classmethod
    def select_config_consumer_seed_rows(cls, rows: Iterable[object], *, limit: int = 128) -> list[object]:
        """Public behaviour entry point for `_select_config_consumer_seed_rows` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private classmethod stays the implementation and the facade delegates to it.
        """
        return cls._select_config_consumer_seed_rows(rows, limit=limit)


    @classmethod
    def _select_config_consumer_seed_rows(
        cls,
        rows: Iterable[object],
        *,
        limit: int = 128,
    ) -> list[object]:
        return _derivation._select_config_consumer_seed_rows(cls, rows, limit=limit)

    @classmethod
    def _newest_config_consumer_candidates(
        cls,
        rows: Iterable[object],
        *,
        limits: Mapping[str, int] | None = None,
    ) -> list[object]:
        """Keep newest rows per kind so later xrefs cannot hide persist-time links."""
        caps = dict(cls._CONFIG_CONSUMER_SEED_KIND_LIMITS)
        if limits:
            caps.update({str(kind): int(cap) for kind, cap in limits.items()})
        grouped: dict[str, list[object]] = {kind: [] for kind in caps}

        def sort_key(row: object) -> tuple[object, str]:
            created = getattr(row, "created_at", None)
            return (created or 0, str(getattr(row, "id", "") or ""))

        for row in sorted(rows, key=sort_key, reverse=True):
            kind = str(getattr(row, "kind", "") or "")
            bucket = grouped.get(kind)
            if bucket is None or len(bucket) >= caps[kind]:
                continue
            bucket.append(row)
        found: list[object] = []
        for kind in caps:
            found.extend(grouped[kind])
        return found

    @classmethod
    def pin_config_consumer_seed_rows(cls, seed_rows: Iterable[object], pinned_rows: Iterable[object]) -> list[object]:
        """Public behaviour entry point for `_pin_config_consumer_seed_rows` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private classmethod stays the implementation and the facade delegates to it.
        """
        return cls._pin_config_consumer_seed_rows(seed_rows, pinned_rows)


    @classmethod
    def _pin_config_consumer_seed_rows(
        cls,
        seed_rows: Iterable[object],
        pinned_rows: Iterable[object],
    ) -> list[object]:
        return _derivation._pin_config_consumer_seed_rows(seed_rows, pinned_rows)

    @classmethod
    def gate_for_seed_playbook(cls, *args, **kwargs):
        """Public behaviour entry point for `_gate_for_seed_playbook` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private classmethod stays the implementation and the facade delegates to it, so a test that replaces
        the private attribute on the class keeps working.
        """
        return cls._gate_for_seed_playbook(*args, **kwargs)


    @classmethod
    def _gate_for_seed_playbook(cls, *args, **kwargs):
        return PersistHow._gate_for_seed_playbook(*args, **kwargs)

    @classmethod
    def _apply_seed_playbook_gate(cls, result: object, playbook: object):
        return _derivation._apply_seed_playbook_gate(cls, result, playbook)

    @classmethod
    def persist_time_seed_result(cls, *, playbook: object, evidence: Iterable[object], thread_id: str, artifact_id: str) -> InvestigationResult | None:
        """Public behaviour entry point for `_persist_time_seed_result` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private classmethod stays the implementation and the facade delegates to it, so a test that replaces
        the private attribute on the class keeps working.
        """
        return cls._persist_time_seed_result(playbook=playbook, evidence=evidence, thread_id=thread_id, artifact_id=artifact_id)


    @classmethod
    def _persist_time_seed_result(
        cls,
        *,
        playbook: object,
        evidence: Iterable[object],
        thread_id: str,
        artifact_id: str,
    ) -> InvestigationResult | None:
        return _derivation._persist_time_seed_result(
            cls,
            playbook=playbook,
            evidence=evidence,
            thread_id=thread_id,
            artifact_id=artifact_id,
        )

    @classmethod
    def _persist_time_static_boundary(
        cls,
        *,
        playbook: object,
        evidence: Iterable[object],
        thread_id: str,
        artifact_id: str,
    ) -> InvestigationResult | None:
        """Skip TRACE when persist already recovered catalog HOW facts.

        Kunglao cost-is-noise: PPID catalog can close on recovered
        parent_handle_to_attribute while ClaimGate still needs 0x09080008.
        TRACE of the same function cannot invent that immediate. Spending the
        leftover 64-action cap there starves process-execution persist skip.
        """
        rows = [
            dict(row) if isinstance(row, Mapping) else row
            for row in evidence
            if isinstance(row, Mapping)
        ]
        seed_gate = cls._gate_for_seed_playbook(playbook, rows)
        if seed_gate is None or seed_gate.accepted:
            return None
        playbook_id = str(getattr(playbook, "id", "") or "").strip()
        entry = MechanismPlaybookRegistry().behavior_entry(playbook_id)
        contract = getattr(entry, "contract", None)
        evaluate = getattr(contract, "evaluate", None)
        catalog_ready = False
        if callable(evaluate):
            catalog_eval = evaluate(rows)
            catalog_ready = bool(getattr(catalog_eval, "accepted", False))
        # Skip TRACE after persist already recovered catalog HOW facts, or
        # when leftover mining cannot invent missing tokens (WinHttp without
        # a transport API, entrypoint without a catalogue contract). Incomplete
        # HOW with a recoverable function/API lead still runs TRACE/decompile.
        if callable(evaluate) and not catalog_ready:
            recovery = recovery_actions_for_gap(
                str(getattr(playbook, "mechanism_type", "") or playbook_id),
                getattr(seed_gate, "missing", ()) or (),
                evidence=rows,
            )
            if recovery:
                return None
            if playbook_id not in cls._HOW_PLAYBOOK_IDS:
                return None
        evidence_ids = tuple(
            str(item.get("id") or "")
            for item in rows
            if isinstance(item, Mapping) and str(item.get("id") or "").strip()
        )
        missing = ", ".join(str(item) for item in seed_gate.missing[:6]) or seed_gate.reason
        return InvestigationResult(
            thread_id=thread_id,
            artifact_id=artifact_id,
            thread_state=InvestigationThreadState.UNKNOWN,
            hypothesis_status="UNKNOWN",
            evidence=tuple(rows),
            events=(
                InvestigationEvent(
                    phase="persist_time_static_boundary",
                    action_id=None,
                    state=InvestigationThreadState.UNKNOWN.value,
                    evidence_ids=evidence_ids[:32],
                    message=(
                        "Persist-time catalog facts already recovered this "
                        "seed; TRACE was not charged because ClaimGate still "
                        f"missing {missing}."
                    ),
                ),
            ),
            actions=(),
            gate=seed_gate,
            coverage={
                "complete": True,
                "evidence_complete": True,
                "claim_eligible": False,
                "target_count": 0,
                "targets": (),
                "protocol": fill_protocol(rows),
            },
        )

    @classmethod
    def _supporting_seed_static_boundary(
        cls,
        *,
        evidence: Iterable[object],
        thread_id: str,
        artifact_id: str,
        category: str,
    ) -> InvestigationResult:
        return _derivation._supporting_seed_static_boundary(
            evidence=evidence,
            thread_id=thread_id,
            artifact_id=artifact_id,
            category=category,
        )

    @classmethod
    def _creation_flags_text(cls, *args, **kwargs):
        return PersistHow._creation_flags_text(*args, **kwargs)

    @classmethod
    def _process_command_text(cls, *args, **kwargs):
        return PersistHow._process_command_text(*args, **kwargs)

    @classmethod
    def _preferred_process_command(cls, *args, **kwargs):
        return PersistHow._preferred_process_command(*args, **kwargs)

    @classmethod
    def _preferred_process_flags(cls, *args, **kwargs):
        return PersistHow._preferred_process_flags(*args, **kwargs)

    @classmethod
    def _recovered_process_how_fields(cls, *args, **kwargs):
        return PersistHow._recovered_process_how_fields(*args, **kwargs)

    @classmethod
    def _recovered_dynamic_api_how_fields(cls, *args, **kwargs):
        return PersistHow._recovered_dynamic_api_how_fields(*args, **kwargs)

    @classmethod
    def _recovered_decode_how_fields(cls, *args, **kwargs):
        return PersistHow._recovered_decode_how_fields(*args, **kwargs)

    @classmethod
    def recovered_http_how_fields(cls, *args, **kwargs):
        """Public behaviour entry point for `_recovered_http_how_fields` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private classmethod stays the implementation and the facade delegates to it.
        """
        return cls._recovered_http_how_fields(*args, **kwargs)


    @classmethod
    def _recovered_http_how_fields(cls, *args, **kwargs):
        return PersistHow._recovered_http_how_fields(*args, **kwargs)

    @classmethod
    def _recovered_ppid_how_fields(cls, *args, **kwargs):
        return PersistHow._recovered_ppid_how_fields(*args, **kwargs)

    @classmethod
    def _investigated_mechanism_claim_fields(cls, *args, **kwargs):
        return _derivation._investigated_mechanism_claim_fields(*args, **kwargs)

    @classmethod
    def _how_recovery_evidence(cls, *args, **kwargs):
        return PersistHow._how_recovery_evidence(*args, **kwargs)

    @classmethod
    def _catalog_candidate_mechanism_fields(cls, *args, **kwargs):
        return _derivation._catalog_candidate_mechanism_fields(*args, **kwargs)

    _PERSIST_HOW_PLAYBOOKS = PersistHow._PERSIST_HOW_PLAYBOOKS
    _PERSIST_HOW_CLAIM_MODULES = PersistHow._PERSIST_HOW_CLAIM_MODULES
    _NAMED_API_CLAIM_SKIP = PersistHow._NAMED_API_CLAIM_SKIP
    _HOW_PLAYBOOK_IDS = PersistHow._HOW_PLAYBOOK_IDS

    @classmethod
    def _investigation_row_mapping(cls, *args, **kwargs):
        return PersistHow._investigation_row_mapping(*args, **kwargs)

    @classmethod
    def _persist_how_rows_for_playbook(cls, *args, **kwargs):
        return PersistHow._persist_how_rows_for_playbook(*args, **kwargs)

    @classmethod
    def _persist_partial_how_ready(cls, *args, **kwargs):
        return PersistHow._persist_partial_how_ready(*args, **kwargs)

    @classmethod
    def persist_how_claim_specs(cls, *args, **kwargs):
        """Public behaviour entry point for `_persist_how_claim_specs` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private classmethod stays the implementation and the facade delegates to it, so a test that replaces
        the private attribute on the class keeps working.
        """
        return cls._persist_how_claim_specs(*args, **kwargs)


    @classmethod
    def _persist_how_claim_specs(cls, *args, **kwargs):
        return PersistHow._persist_how_claim_specs(*args, **kwargs)

    @classmethod
    def _persist_unique_thread_claim_specs(cls, *args, **kwargs):
        return PersistHow._persist_unique_thread_claim_specs(*args, **kwargs)

    @classmethod
    def _persist_time_unique_thread_result(
        cls,
        *,
        evidence: Iterable[object],
        thread_id: str,
        artifact_id: str,
    ) -> InvestigationResult | None:
        return _derivation._persist_time_unique_thread_result(
            cls,
            evidence=evidence,
            thread_id=thread_id,
            artifact_id=artifact_id,
        )

    @classmethod
    def _persist_how_row_groups(cls, *args, **kwargs):
        return PersistHow._persist_how_row_groups(*args, **kwargs)

    @classmethod
    def _stage_persist_how_claims(cls, *args, **kwargs):
        return PersistHow._stage_persist_how_claims(*args, **kwargs)

    _GENERIC_GHIDRA_BEHAVIOR_KIND = "ghidra_function_behavior"
    _GENERIC_CLAIM_KINDS = frozenset(
        {
            "ghidra_function_behavior",
            "ghidra_mechanism_chain",
        }
    )
    _GENERIC_BEHAVIOR_SUPERSEDED_BY = {
        "may_execute": "may_create_process",
        "may_decode_or_decrypt": "may_decode_configuration",
        "references_network_endpoint": "may_download_over_http",
        "may_connect_to_network": "may_download_over_http",
    }

    @classmethod
    def _collapse_generic_ghidra_behavior_claims(
        cls,
        pending_claims: list[tuple[object, object, object, object]],
    ) -> None:
        """Kunglao cost-is-noise: persist HOW is the claim; per-function keywords are leftover."""
        persist_actions = {
            str(getattr(item[0], "action", "") or "")
            for item in pending_claims
            if isinstance(item[3], Mapping)
            and str(item[3].get("claim_kind") or "") == "persist_time_investigated_mechanism"
        }
        kept: list[tuple[object, object, object, object]] = []
        seen_generic: set[tuple[str, str]] = set()
        for item in pending_claims:
            claim, _evidence_ids, _infer, payload = item
            kind = str(payload.get("claim_kind") or "") if isinstance(payload, Mapping) else ""
            action = str(getattr(claim, "action", "") or "")
            obj = str(getattr(claim, "object", "") or "")
            if kind in cls._GENERIC_CLAIM_KINDS:
                superseded = cls._GENERIC_BEHAVIOR_SUPERSEDED_BY.get(action)
                if superseded and superseded in persist_actions:
                    continue
                key = (action, obj)
                if key in seen_generic:
                    continue
                seen_generic.add(key)
            kept.append(item)
        pending_claims[:] = kept

    @classmethod
    def _select_cross_function_chain_claims(
        cls,
        chains: Iterable[object],
        *,
        limit: int = 8,
    ) -> list[Mapping[str, object]]:
        """Kunglao cost-is-noise: one claim per category path, not 128 near-duplicates."""
        selected: list[Mapping[str, object]] = []
        seen: set[tuple[str, ...]] = set()
        for chain in chains:
            if not isinstance(chain, Mapping):
                continue
            categories = tuple(
                str(item)
                for item in (chain.get("categories") or ())
                if str(item).strip()
            )
            if not categories or categories in seen:
                continue
            seen.add(categories)
            selected.append(chain)
            if len(selected) >= limit:
                break
        return selected

    @classmethod
    def stamp_persist_how_snapshot(cls, *args, **kwargs):
        """Public behaviour entry point for `_stamp_persist_how_snapshot` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private classmethod stays the implementation and the facade delegates to it, so a test that replaces
        the private attribute on the class keeps working.
        """
        return cls._stamp_persist_how_snapshot(*args, **kwargs)


    @classmethod
    def _stamp_persist_how_snapshot(cls, *args, **kwargs):
        return _derivation._stamp_persist_how_snapshot(*args, **kwargs)

    @classmethod
    def _persist_how_function_entries(
        cls,
        evidence: Iterable[object],
    ) -> tuple[str, ...]:
        """Recovered HOW function entries only. Seed flood / IAT thunks are not tickets."""
        rows = [
            mapped
            for mapped in (cls._investigation_row_mapping(item) for item in evidence)
            if mapped is not None
        ]
        seen: set[str] = set()
        entries: list[str] = []
        for playbook_id in cls._PERSIST_HOW_PLAYBOOKS:
            for row in cls._persist_how_rows_for_playbook(playbook_id, rows):
                kind = str(row.get("kind") or "")
                value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
                if playbook_id == "process-execution" and kind == "function_call":
                    if not (
                        value.get("command")
                        or value.get("command_line")
                        or value.get("creation_flags")
                        or value.get("flags")
                    ):
                        continue
                if playbook_id == "dynamic-api-resolution" and kind == "resolved_api":
                    has_module = bool(value.get("module_input") or value.get("module"))
                    has_named_consumer = bool(
                        (value.get("api_name") or value.get("api_identity"))
                        and (value.get("consumer") or value.get("consumer_callsite"))
                    )
                    if not has_module and not has_named_consumer:
                        continue
                anchor = row.get("anchor") if isinstance(row.get("anchor"), Mapping) else {}
                parsed = None
                for source in (value, anchor):
                    if not isinstance(source, Mapping):
                        continue
                    for key in ("function_entry", "entry", "function"):
                        parsed = _as_int_address(source.get(key))
                        if parsed is not None:
                            break
                    if parsed is not None:
                        break
                if parsed is None:
                    continue
                entry = hex(parsed)
                if entry in seen:
                    continue
                seen.add(entry)
                entries.append(entry)
        for row in rows:
            if str(row.get("kind") or "") != "api_argument_trace":
                continue
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            start = recovered_thread_start_address(value)
            if not start or start in seen:
                continue
            seen.add(start)
            entries.append(start)
            if len(entries) >= 8:
                break
        return tuple(entries)

    @classmethod
    def persist_ready_emulation_actions(cls, *, evidence: Iterable[object], thread_id: str, hypothesis_id: str, artifact_id: str, scheduled_keys: Iterable[str] = ()) -> tuple[ActionSpec, ...]:
        """Public behaviour entry point for `_persist_ready_emulation_actions` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private classmethod stays the implementation and the facade delegates to it.
        """
        return cls._persist_ready_emulation_actions(evidence=evidence, thread_id=thread_id, hypothesis_id=hypothesis_id, artifact_id=artifact_id, scheduled_keys=scheduled_keys)


    @classmethod
    def _persist_ready_emulation_actions(
        cls,
        *,
        evidence: Iterable[object],
        thread_id: str,
        hypothesis_id: str,
        artifact_id: str,
        scheduled_keys: Iterable[str] = (),
    ) -> tuple[ActionSpec, ...]:
        """Kunglao leftover remainder: persist-closed HOW still needs isolated emu.

        TRACE is not charged. CONTROLLED_EMULATE tickets do not consume the
        64-action cap. Skipping the driver after persist CLAIM_READY left
        CreateProcess/GetProcAddress windows unemulated. Seed-flood
        function_entry values must not steal those four tickets.
        """
        scheduled = {str(item) for item in scheduled_keys if str(item).strip()}
        actions: list[ActionSpec] = []
        for entry in cls._persist_how_function_entries(evidence):
            selector = {"function_entry": entry, "target": entry}
            key = scoped_investigation_action_key(
                ActionType.CONTROLLED_EMULATE.value,
                selector,
                {},
            )
            if key in scheduled:
                continue
            actions.append(
                ActionSpec(
                    id=f"{thread_id}:emu:{hashlib.sha256(entry.encode('utf-8')).hexdigest()[:16]}",
                    action_type=ActionType.CONTROLLED_EMULATE,
                    thread_id=thread_id,
                    hypothesis_id=hypothesis_id,
                    artifact_id=artifact_id,
                    priority=5,
                    reason=(
                        "Kunglao leftover remainder: persist-closed HOW still "
                        "needs isolated Unicorn corroboration."
                    ),
                    parameters=selector,
                    target_selector=selector,
                    expected_evidence_kinds=("simulation_result",),
                )
            )
            if len(actions) >= 4:
                break
        return tuple(actions)

    _PERSIST_SKIP_TRACE_ERROR = PERSIST_SKIP_TRACE_ERROR
    _PERSIST_KEEP_ACTION_TYPES = PERSIST_KEEP_ACTION_TYPES

    @classmethod
    def action_is_model_or_human(cls, item: object) -> bool:
        """Public behaviour entry point for `_action_is_model_or_human` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private classmethod stays the implementation and the facade delegates to it.
        """
        return cls._action_is_model_or_human(item)


    @classmethod
    def _action_is_model_or_human(cls, item: object) -> bool:
        return _coordinator._action_is_model_or_human(item)

    @classmethod
    def _keep_emulation_after_persist_skip(
        cls,
        actions: Iterable[object],
    ) -> tuple[ActionSpec, ...]:
        """Keep required recovery tools after persist CANDIDATE; drop leftover TRACE."""
        return keep_recovery_after_persist_skip(actions)

    @classmethod
    def _supersede_queued_trace_after_persist_skip(
        cls,
        queued_rows: Iterable[object],
        *,
        thread_id: str,
    ) -> None:
        """Do not leave leftover DSH TRACE tickets QUEUED after persist HOW skip."""
        supersede_queued_trace_after_persist_skip(queued_rows, thread_id=thread_id)

    @classmethod
    def _load_investigation_execution_rows(
        cls,
        session: Session,
        *,
        task_id: str,
        artifact_id: str,
        action_kinds: set[str] | frozenset[str],
        limit: int | None = None,
    ) -> list[Evidence]:
        """Load the bounded investigation corpus in signal order.

        This is deliberately kept next to the in-memory projection helper so
        both layers share one ordering contract.  The ``LIMIT`` must be
        applied *after* the priority ``CASE`` ordering; otherwise a dense
        string corpus created early in a task can hide the later function,
        call-graph, CFG, and mechanism rows that the investigator needs.
        """
        cap = int(limit or cls._INVESTIGATION_EXECUTION_EVIDENCE_LIMIT)
        if cap < 1:
            return []
        allowed_kinds = set(action_kinds)
        if not allowed_kinds:
            return []
        priority_order = case(
            *(
                (Evidence.kind == kind, priority)
                for kind, priority in cls._MODEL_EVIDENCE_PRIORITY.items()
                if kind in allowed_kinds
            ),
            else_=20,
        )
        return list(
            session.scalars(
                select(Evidence)
                .where(
                    Evidence.task_id == task_id,
                    Evidence.artifact_id == artifact_id,
                    Evidence.kind.in_(allowed_kinds),
                    Evidence.nature != "BACKGROUND_REPORTED",
                )
                .order_by(
                    priority_order.desc(),
                    Evidence.created_at,
                    Evidence.id,
                )
                .limit(cap)
            )
        )

    @staticmethod
    def _specialized_verifier_context(
        current_rows: list[Mapping[str, object]],
        scope_rows: list[Any],
        *,
        mechanism_type: str,
        prior_mechanism: Mapping[str, object] | None = None,
    ) -> list[dict[str, object]]:
        return _derivation._specialized_verifier_context(
            current_rows,
            scope_rows,
            mechanism_type=mechanism_type,
            prior_mechanism=prior_mechanism,
        )

    @staticmethod
    def _preserve_verified_mechanism(
        current: Mapping[str, object], candidate: Mapping[str, object]
    ) -> dict[str, object]:
        return _derivation._preserve_verified_mechanism(current, candidate)

    def _deferred_budget_thread_ids(self, task_id: str) -> tuple[str, ...]:
        return _task_runner._deferred_budget_thread_ids(self, task_id)

    def _unattempted_seed_thread_ids(self, task_id: str) -> tuple[str, ...]:
        return _coordinator._unattempted_seed_thread_ids(self, task_id)

    def _pma_plan_facts_from_session(
        self, session: Session, task_id: str
    ) -> list[dict[str, object]]:
        """Bounded PE/import/string/call rows for the live PMA plan snapshot."""
        rows = list(
            session.scalars(
                select(Evidence)
                .where(
                    Evidence.task_id == task_id,
                    Evidence.kind.in_(self._PMA_PLAN_FACT_KINDS),
                )
                .order_by(Evidence.created_at, Evidence.id)
                .limit(self._PMA_PLAN_FACT_LIMIT)
            )
        )
        facts: list[dict[str, object]] = []
        for row in rows:
            facts.append(
                {
                    "id": row.id,
                    "kind": row.kind,
                    "nature": row.nature,
                    "value": row.value if isinstance(row.value, Mapping) else {},
                    "anchor": row.anchor if isinstance(row.anchor, Mapping) else {},
                }
            )
        return facts

    def _persist_pma_static_analysis_plan(
        self, session: Session, task: AnalysisTask
    ) -> dict[str, object]:
        """Write investigation.static_analysis_plan for reporting/DSH.

        PMA planning is PE-shaped. Hash/string-only scripts keep the previous
        snapshot so a COMPLETED fingerprint rung cannot advertise report-ready.
        """
        facts = self._pma_plan_facts_from_session(session, task.id)
        kinds = {str(item.get("kind") or "").casefold() for item in facts}
        if not kinds.intersection(
            {
                "pe_structure",
                "pe_section",
                "import_symbol",
                "unpacked_payload",
                "reconstructed_iat",
            }
        ):
            return {}
        plan = static_analysis_plan_snapshot(facts)
        snapshot = dict(task.strategy_snapshot or {})
        investigation = dict(snapshot.get("investigation") or {})
        investigation[STATIC_ANALYSIS_PLAN_SNAPSHOT_KEY] = plan
        task.strategy_snapshot = {**snapshot, "investigation": investigation}
        return plan

    def _work_ledger(self, task_id: str) -> list[dict[str, object]]:
        return _coordinator._work_ledger(self, task_id)

    def _park_open_ledger(self, task_id: str) -> None:
        return _coordinator._park_open_ledger(self, task_id)

    def _finalize_tail_ledger(self, task_id: str) -> None:
        return _coordinator._finalize_tail_ledger(self, task_id)

    def _run_saturated_investigation(self, task_id: str) -> list[str]:
        """Keep investigating until the work ledger has no OPEN or DEFERRED items."""
        return run_saturated_investigation(self, task_id)

    def _real_simulation_result_count(self, task_id: str) -> int:
        with self.database.session_factory() as session:
            rows = session.scalars(
                select(Evidence).where(
                    Evidence.task_id == task_id,
                    Evidence.kind == "simulation_result",
                )
            )
            return sum(
                1
                for row in rows
                if isinstance(getattr(row, "value", None), dict)
                and str(row.value.get("status") or "").upper()
                not in PLACEHOLDER_STATUSES
            )

    def _run_emulation_informed_investigation(
        self,
        task_id: str,
        *,
        saturated: bool = True,
    ) -> list[str]:
        """Dispatch isolated emu, then continue investigation on the new facts."""
        return run_emulation_informed_investigation(self, task_id, saturated=saturated)

    def _reverify_how_after_emulation(self, task_id: str) -> None:
        """Feed real worker simulation_result rows back into specialist verifiers."""
        from sqlalchemy.exc import SQLAlchemyError

        try:
            with self.database.session_factory.begin() as session:
                task = session.get(AnalysisTask, task_id, with_for_update=True)
                if task is None:
                    return
                current = dict(task.strategy_snapshot or {})
                investigation = dict(current.get("investigation") or {})
                mechanisms = list(investigation.get("mechanisms") or [])
                if not mechanisms:
                    return
                evidence_rows = [
                    {
                        "id": row.id,
                        "kind": row.kind,
                        "nature": row.nature,
                        "value": row.value or {},
                        "anchor": row.anchor or {},
                    }
                    for row in session.scalars(
                        select(Evidence).where(Evidence.task_id == task_id)
                    )
                ]
                investigation["mechanisms"] = apply_emulation_reverification(
                    mechanisms, evidence_rows
                )
                current["investigation"] = investigation
                task.strategy_snapshot = current
        except SQLAlchemyError:
            return

    def run_investigation_loop(self, task_id: str, *, model_actions_only: bool = False, ledger_phase: str = 'coverage') -> list[str]:
        """Public behaviour entry point for `_run_investigation_loop` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name, so a test asserted against an
        implementation detail rather than against a behaviour the service offers. Callers outside the class use this
        name; the private method stays the implementation, and its ONE deliberate remaining caller is production code
        that a test replaces by attribute (`tests/test_analysis_task_orchestration.py`), which is why the private name
        is not removed here.
        """
        return self._run_investigation_loop(task_id, model_actions_only=model_actions_only, ledger_phase=ledger_phase)


    def _run_investigation_loop(
        self,
        task_id: str,
        *,
        model_actions_only: bool = False,
        ledger_phase: str = "coverage",
    ) -> list[str]:
        return _derivation._run_investigation_loop(
            self,
            task_id,
            model_actions_only=model_actions_only,
            ledger_phase=ledger_phase,
        )

    @staticmethod
    def _link_claim_evidence(
        session: Session,
        *,
        claim_id: str,
        evidence_id: str,
        stance: str = "SUPPORTS",
    ) -> None:
        """Attach Evidence to a Claim without aborting on a duplicate pair."""
        claim_id = str(claim_id or "").strip()
        evidence_id = str(evidence_id or "").strip()
        if not claim_id or not evidence_id:
            return
        pending_items = getattr(session, "new", ())
        try:
            pending_iter = tuple(pending_items or ())
        except TypeError:
            # Lightweight test/dry-run sessions may expose ``new`` as a
            # non-iterable mock.  Treat that as an empty pending collection;
            # real SQLAlchemy sessions provide an iterable IdentitySet.
            pending_iter = ()
        pending = {
            (str(item.claim_id), str(item.evidence_id))
            for item in pending_iter
            if isinstance(item, ClaimEvidence)
        }
        if (claim_id, evidence_id) in pending:
            return
        if session.get(ClaimEvidence, (claim_id, evidence_id)) is not None:
            return
        session.add(
            ClaimEvidence(claim_id=claim_id, evidence_id=evidence_id, stance=stance)
        )

    @staticmethod
    def _deterministic_action_plan(artifacts: list[Artifact]) -> list[str]:
        return _coordinator._deterministic_action_plan(artifacts)

    @staticmethod
    def _expected_evidence_for_tool(tool_name: str) -> tuple[str, ...]:
        return {
            "pe-parser": ("pe_structure", "import_symbol", "string", "resource_inventory"),
            "script-parser": ("script_import", "script_call", "script_line"),
            "document-carrier-parser": ("document_metadata", "embedded_object", "document_url"),
            "builtin-static-analyzer": ("file_identity", "string", "indicator"),
            "ghidra-headless": ("function", "xref", "cfg_block", "function_mechanism"),
            "controlled-emulator": ("simulation_result",),
        }.get(tool_name, ("specialist_observation",))

    @staticmethod
    def _analysis_focus_for_tool(tool_name: str) -> tuple[str, ...]:
        return {
            "pe-parser": ("identity", "imports", "sections", "resources"),
            "ghidra-headless": ("call_graph", "rva", "cfg", "mechanism_chain"),
            "controlled-emulator": ("granted_window", "start_routine", "simulation_result"),
            "script-parser": ("line_evidence", "imports", "calls"),
            "document-carrier-parser": ("carrier", "embedded_objects", "urls"),
            "python-zipfile-safe-reader": ("recursive_inventory", "password_gate"),
        }.get(tool_name, ("static_observation",))

    def _baseline_tools_for_artifact(self, artifact: Artifact) -> tuple[str, ...]:
        """Return the static coverage actions that cannot be skipped by a model.

        MEASURED gap this closes: `_build_execution_queue` seeds its queue with these tools and with
        `model_actions=[]` (the first planner turn deliberately runs AFTER the baseline commits), so a
        tool absent here can only be scheduled by a later model replan. Across 474 tasks in the database
        that left three declared tools with ZERO runs ever - `crypto-pattern-scanner`,
        `build-metadata-scanner`, `knowledge-fact-matcher` - and the other PE specialists barely
        present. Their findings could therefore never appear in a report.

        The PE specialists are deterministic and read-only (`_run_methodology_action`), so putting them
        in the baseline removes the model from the critical path for coverage. They are ordered AFTER
        parser/Ghidra/emulator so a queue budget cut still drops the cheapest-to-lose work first.
        """
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
            tools = [parser, "ghidra-headless"]
            if simulation_policy_from_settings(self.settings).enabled:
                tools.append("controlled-emulator")
            tools.extend(self._baseline_specialist_tools(artifact, already=set(tools)))
            return tuple(tools)
        return (parser,)

    @staticmethod
    def baseline_specialist_tools(artifact: Artifact, *, already: set[str]) -> tuple[str, ...]:
        """Public behaviour entry point for `_baseline_specialist_tools` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private staticmethod stays the implementation and the facade delegates to it.
        """
        return AnalysisService._baseline_specialist_tools(artifact, already=already)


    @staticmethod
    def _baseline_specialist_tools(
        artifact: Artifact, *, already: set[str]
    ) -> tuple[str, ...]:
        """PE-appropriate specialist tools, in a stable order, minus anything already queued."""
        # `signal-extractor` is NOT included: it already runs unconditionally at the end of the
        # deterministic route (`_run_methodology_action(..., "signal-extractor",
        # scheduler="deterministic_methodology")`), so adding it here would execute it twice.
        preferred = (
            "knowledge-fact-matcher",
            "rva-xref-query",
            "crypto-pattern-scanner",
            "c2-protocol-scanner",
            "build-metadata-scanner",
            "codename-scanner",
        )
        compatible = AnalysisService._compatible_static_tools(artifact)
        return tuple(name for name in preferred if name in compatible and name not in already)

    @staticmethod
    def _compatible_static_tools(artifact: Artifact) -> set[str]:
        tools = set(AnalysisService._parser_tools_for_artifact(artifact))
        tools.add("signal-extractor")
        tools.add("knowledge-fact-matcher")
        if artifact.detected_type == "pe":
            tools.update(
                {
                    "rva-xref-query",
                    "crypto-pattern-scanner",
                    "build-metadata-scanner",
                    "codename-scanner",
                    "controlled-emulator",
                }
            )
        if artifact.detected_type in {"pe", "script", "pdf", "ooxml", "ole"}:
            tools.add("c2-protocol-scanner")
        return tools

    @staticmethod
    def _parser_tools_for_artifact(artifact: Artifact) -> tuple[str, ...]:
        parser_by_type = {
            "pe": "pe-parser",
            "script": "script-parser",
            "pdf": "document-carrier-parser",
            "ooxml": "document-carrier-parser",
            "ole": "document-carrier-parser",
        }
        parser = parser_by_type.get(artifact.detected_type, "builtin-static-analyzer")
        if artifact.detected_type == "pe":
            return parser, "ghidra-headless"
        return (parser,)

    @staticmethod
    def _is_reference_isolated_blind(task: AnalysisTask) -> bool:
        blind_run = dict((task.strategy_snapshot or {}).get("blind_run", {}))
        return bool(blind_run.get("enabled") and blind_run.get("reference_isolated"))

    @staticmethod
    def _normalise_dependency(raw: str, action: ScheduledStaticAction) -> str:
        """Accept compact planner dependency forms without trusting free text."""
        known_tools = {
            "pe-parser",
            "script-parser",
            "document-carrier-parser",
            "builtin-static-analyzer",
            "ghidra-headless",
            "controlled-emulator",
            *SPECIALIST_STATIC_TOOLS,
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
        artifact_rank = {
            artifact_id: index for index, artifact_id in enumerate(deterministic_actions)
        }
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
                    depends_on = (
                        (f"{artifact_id}:ghidra-headless",)
                        if tool_name == "controlled-emulator"
                        else ()
                    )
                    candidates.append(
                        ScheduledStaticAction(
                            artifact_id=artifact_id,
                            tool_name=tool_name,
                            priority=10000 + index * 10 + tool_offset,
                            reason="mandatory static coverage",
                            depends_on=depends_on,
                            planner_turn_id=None,
                        )
                    )
                    continue
                dependencies = tuple(
                    dependency
                    for dependency in (
                        self._normalise_dependency(
                            value,
                            ScheduledStaticAction(
                                artifact_id=artifact_id,
                                tool_name=tool_name,
                                priority=proposal.priority,
                                reason=proposal.reason,
                            ),
                        )
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
            ready.sort(
                key=lambda item: (
                    item.priority,
                    artifact_rank.get(item.artifact_id, 10**6),
                    item.key,
                )
            )
            selected = ready[0]
            ordered.append(selected)
            remaining.remove(selected.key)
        return ordered

    @staticmethod
    def _static_decode_recovery_from_evidence(rows: Iterable[object]) -> str:
        return _derivation._static_decode_recovery_from_evidence(rows)

    @staticmethod
    def _static_decode_recovery_from_limitations(limitations) -> str:
        return _limitations.static_decode_recovery_from_limitations(limitations)

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
            if self._is_reference_isolated_blind(task) and tool_name == "knowledge-fact-matcher":
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
                return ["Reference-isolated blind run blocks knowledge-fact-matcher."]
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
            # Profile extraction is a derived summary, not the evidence
            # ledger. Keep the authoritative row count separate from the
            # bounded working set so idempotency and audit remain truthful.
            observed_evidence_count = (
                session.query(Evidence)
                .filter(
                    Evidence.task_id == task_id,
                    Evidence.artifact_id == artifact_id,
                    Evidence.kind.notin_(("analysis_profile", "fact_match")),
                )
                .count()
            )
            observations = list(
                session.scalars(
                    select(Evidence)
                    .where(
                        Evidence.task_id == task_id,
                        Evidence.artifact_id == artifact_id,
                        Evidence.kind.notin_(("analysis_profile", "fact_match")),
                    )
                    .order_by(Evidence.created_at, Evidence.id)
                    .limit(self._METHODOLOGY_EVIDENCE_LIMIT)
                )
            )
            existing = list(
                session.scalars(
                    select(Evidence)
                    .where(
                        Evidence.task_id == task_id,
                        Evidence.artifact_id == artifact_id,
                        Evidence.kind == "analysis_profile",
                        # Scope to THIS tool: otherwise a sibling specialist's profile satisfies the
                        # guard and this tool silently produces nothing. See the note below.
                        Evidence.value["tool_name"].as_string() == tool_name,
                    )
                    .order_by(Evidence.created_at.desc(), Evidence.id.desc())
                    .limit(1)
                )
            )
            if existing:
                # Idempotency must be keyed per (artifact, tool), not per artifact.
                #
                # MEASURED defect this fixes: the guard used to be per-artifact - it took the newest
                # `analysis_profile` row for the artifact and skipped whenever its
                # `observed_evidence_count` was >= the current one. Because every specialist in
                # SPECIALIST_STATIC_TOOLS runs `_run_methodology_action` against the SAME artifact within
                # the same second, the first one to run (priority order puts `knowledge-fact-matcher`
                # first) wrote the profile with an identical evidence count, and all the following tools
                # hit `prior_count >= observed_evidence_count` and returned here - BEFORE creating their
                # own ToolRun. Result across the whole database: those tools had essentially zero runs
                # ever (`crypto-pattern-scanner` and `build-metadata-scanner` had none at all), so their
                # findings could never reach a report.
                #
                # The guard still suppresses true re-work: a tool is skipped only when ITS OWN previous
                # profile already covered at least as much evidence. `tool_name` is recorded on the
                # profile below for exactly this check, and rows written before that field existed fall
                # back to the old per-artifact behaviour so legacy tasks stay idempotent.
                prior_tool = str(existing[0].value.get("tool_name") or "")
                if prior_tool == tool_name:
                    prior_count = int(existing[0].value.get("observed_evidence_count", 0))
                    if prior_count >= observed_evidence_count:
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
                    environment={
                        "deterministic": True,
                        "sample_execution": False,
                        "network_access": False,
                    },
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
                nature="STATIC_DERIVED",
                value={
                    **profile.as_dict(),
                    "observed_evidence_count": observed_evidence_count,
                    "profile_evidence_count": len(observations),
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
                    nature="STATIC_DERIVED",
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
                    action="matches_knowledge_fact"
                    if match.status in {"HIT", "PARTIAL"}
                    else "excludes_knowledge_fact",
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
                    self._link_claim_evidence(
                        session, claim_id=claim.id, evidence_id=evidence_id
                    )
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
        return _coordinator._merge_planned_actions(deterministic_actions, model_actions, artifacts)

    @staticmethod
    def _model_action_plan(action: DynamicPlanAction | Mapping[str, object]) -> dict[str, object]:
        return _coordinator._model_action_plan(action)

    # Kunglao-inspired convergence controls.  These helpers deliberately
    # remain service-owned metadata: the Action Catalog and target selector
    # continue to be the only execution authority.
    _CONVERGENCE_ALTERNATES: dict[ActionType, tuple[ActionType, ...]] = {
        ActionType.TRACE_API_ARGUMENT: (
            ActionType.GET_PCODE_SLICE,
            ActionType.GET_DATA_REFERENCES,
            ActionType.GET_DECOMPILE,
        ),
        ActionType.GET_PCODE_SLICE: (
            ActionType.GET_DECOMPILE,
            ActionType.GET_CFG_SLICE,
            ActionType.GET_DATA_REFERENCES,
        ),
        ActionType.GET_DATA_REFERENCES: (
            ActionType.GET_XREFS_TO,
            ActionType.GET_PCODE_SLICE,
            ActionType.GET_DECOMPILE,
        ),
        ActionType.GET_XREFS_TO: (
            ActionType.GET_XREFS_FROM,
            ActionType.GET_DECOMPILE,
            ActionType.CONTROLLED_EMULATE,
        ),
        ActionType.GET_XREFS_FROM: (
            ActionType.GET_DECOMPILE,
            ActionType.CONTROLLED_EMULATE,
            ActionType.GET_CFG_SLICE,
        ),
        ActionType.GET_CALLERS: (
            ActionType.GET_DECOMPILE,
            ActionType.CONTROLLED_EMULATE,
            ActionType.GET_CFG_SLICE,
        ),
        ActionType.GET_CALLEES: (
            ActionType.GET_DECOMPILE,
            ActionType.CONTROLLED_EMULATE,
            ActionType.GET_PCODE_SLICE,
        ),
        ActionType.GET_STRINGS_REFERENCED: (
            ActionType.GET_XREFS_TO,
            ActionType.GET_DATA_REFERENCES,
            ActionType.GET_DECOMPILE,
        ),
        ActionType.GET_DECOMPILE: (
            ActionType.CONTROLLED_EMULATE,
            ActionType.GET_PCODE_SLICE,
            ActionType.GET_CFG_SLICE,
        ),
        ActionType.GET_CFG_SLICE: (
            ActionType.GET_PCODE_SLICE,
            ActionType.GET_DECOMPILE,
            ActionType.GET_XREFS_FROM,
        ),
        ActionType.TRACE_RETURN_VALUE: (
            ActionType.TRACE_GLOBAL_USAGE,
            ActionType.GET_PCODE_SLICE,
            ActionType.GET_DATA_REFERENCES,
        ),
        ActionType.TRACE_GLOBAL_USAGE: (
            ActionType.GET_DATA_REFERENCES,
            ActionType.TRACE_RETURN_VALUE,
            ActionType.GET_PCODE_SLICE,
        ),
        ActionType.DECODE_CANDIDATE: (
            ActionType.READ_BYTES,
            ActionType.GET_DATA_REFERENCES,
            ActionType.CONTROLLED_EMULATE,
        ),
        ActionType.READ_BYTES: (
            ActionType.GET_DATA_REFERENCES,
            ActionType.DECODE_CANDIDATE,
            ActionType.CONTROLLED_EMULATE,
        ),
        ActionType.EVALUATE_CONSTANT: (
            ActionType.GET_PCODE_SLICE,
            ActionType.READ_BYTES,
            ActionType.GET_DECOMPILE,
        ),
        ActionType.COMPARE_FUNCTION: (
            ActionType.GET_DECOMPILE,
            ActionType.GET_PCODE_SLICE,
            ActionType.GET_CFG_SLICE,
        ),
        ActionType.GET_FUNCTION: (
            ActionType.GET_DECOMPILE,
            ActionType.CONTROLLED_EMULATE,
            ActionType.GET_DATA_REFERENCES,
        ),
    }
    _CONVERGENCE_EXPECTED_KINDS: dict[ActionType, tuple[str, ...]] = {
        ActionType.GET_CALLERS: ("function_call", "xref"),
        ActionType.GET_CALLEES: ("function_call", "xref"),
        ActionType.GET_XREFS_TO: ("xref", "function_call", "data_reference"),
        ActionType.GET_XREFS_FROM: ("xref", "function_call", "data_reference"),
        ActionType.GET_STRINGS_REFERENCED: ("string", "string_reference"),
        ActionType.GET_DATA_REFERENCES: ("data_reference", "function_data_correlation"),
        ActionType.GET_DECOMPILE: ("decompile_slice", "abstract_execution_trace"),
        ActionType.GET_PCODE_SLICE: ("pcode_slice", "abstract_execution_trace"),
        ActionType.GET_CFG_SLICE: ("cfg_block", "control_flow"),
        ActionType.TRACE_API_ARGUMENT: ("api_argument_trace", "value_flow"),
        ActionType.TRACE_RETURN_VALUE: ("return_value_trace", "value_flow"),
        ActionType.TRACE_GLOBAL_USAGE: ("global_usage", "value_flow"),
        ActionType.DECODE_CANDIDATE: ("decode_result", "decoded_artifact"),
        ActionType.READ_BYTES: ("byte_window", "bytes"),
        ActionType.EVALUATE_CONSTANT: ("constant", "constant_evaluation"),
        ActionType.COMPARE_FUNCTION: ("function_similarity", "function"),
        ActionType.GET_FUNCTION: ("function", "function_context"),
        ActionType.CONTROLLED_EMULATE: ("simulation_result",),
    }

    @classmethod
    def _convergence_method_id(
        cls,
        action_type: ActionType | str,
        selector: Mapping[str, object] | None = None,
        plan: Mapping[str, object] | None = None,
    ) -> str:
        return _coordinator._convergence_method_id(action_type, selector, plan)

    @classmethod
    def _convergence_frontier_fingerprint(cls, rows: object) -> str:
        return _coordinator._convergence_frontier_fingerprint(rows)

    @classmethod
    def _convergence_completed_fields(
        cls,
        evidence: object,
        coverage: Mapping[str, object] | None = None,
    ) -> list[str]:
        return _coordinator._convergence_completed_fields(evidence, coverage)

    @classmethod
    def _convergence_alternate_type(
        cls,
        action_type: ActionType | str,
        attempted: object = (),
    ) -> ActionType | None:
        return _coordinator._convergence_alternate_type(cls, action_type, attempted)

    @classmethod
    def _convergence_failure_contract(
        cls,
        action: ActionSpec,
        *,
        outcome: str,
        frontier_before: str,
        frontier_after: str,
        existing_method_ids: object = (),
        error_type: str | None = None,
    ) -> dict[str, object]:
        return _coordinator._convergence_failure_contract(
            cls,
            action,
            outcome=outcome,
            frontier_before=frontier_before,
            frontier_after=frontier_after,
            existing_method_ids=existing_method_ids,
            error_type=error_type,
        )

    @classmethod
    def _build_convergence_alternate(
        cls,
        *,
        original: InvestigationActionRecord,
        thread_id: str,
        hypothesis_id: str,
        artifact_id: str,
    ) -> ActionSpec | None:
        return _coordinator._build_convergence_alternate(
            cls,
            original=original,
            thread_id=thread_id,
            hypothesis_id=hypothesis_id,
            artifact_id=artifact_id,
        )

    @classmethod
    def _has_complete_model_action_plan(cls, action: DynamicPlanAction) -> bool:
        return _coordinator._has_complete_model_action_plan(action)

    @classmethod
    def _grounded_planner_action_candidates(
        cls,
        context_manifest: list[dict[str, object]],
        *,
        artifact_ids: set[str],
        limit: int = 6,
    ) -> list[dict[str, object]]:
        return _coordinator._grounded_planner_action_candidates(
            context_manifest,
            artifact_ids=artifact_ids,
            limit=limit,
        )

    @staticmethod
    def _frontier_value_present(value: object) -> bool:
        return _coordinator._frontier_value_present(value)

    @classmethod
    def _mechanism_missing_fields(cls, mechanism: Mapping[str, object]) -> list[str]:
        return _coordinator._mechanism_missing_fields(mechanism)

    @classmethod
    def _build_investigation_frontier(
        cls,
        session: Session,
        *,
        task: AnalysisTask,
        artifacts: list[Artifact],
        completed_actions: list[dict[str, object]],
    ) -> dict[str, object]:
        return _coordinator._build_investigation_frontier(
            session,
            task=task,
            artifacts=artifacts,
            completed_actions=completed_actions,
        )

    def run_model_planning(self, task_id: str, artifacts: list[Artifact], deterministic_actions: list[str], *, phase: str, completed_actions: list[dict[str, object]] | None = None) -> tuple[list[DynamicPlanAction], list[str]]:
        """Public behaviour entry point for `_run_model_planning` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private method stays the implementation, and the facade delegates to it so a test that still
        replaces the private attribute keeps working.
        """
        return self._run_model_planning(task_id, artifacts, deterministic_actions, phase=phase, completed_actions=completed_actions)


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
            investigation_frontier = self._build_investigation_frontier(
                session,
                task=task,
                artifacts=artifacts,
                completed_actions=bounded_completed_actions,
            )
            hypothesis_before = list(investigation_frontier.get("hypotheses", []))
            if not hypothesis_before:
                # A planner may legitimately run before the durable investigator
                # has materialized a thread (for example after a recovered task
                # snapshot). Keep a truthful fallback, but never present it as
                # a completed mechanism or as sample-specific evidence.
                hypothesis_before = [
                    {
                        "id": "model-planning-frontier",
                        "statement": "The current static evidence may support a recoverable mechanism; concrete fields remain to be tested.",
                        "status": "OPEN",
                        "evidence_ids": [],
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
            open_unknowns = list(investigation_frontier.get("open_unknowns", []))
            mechanism_rows = list(investigation_frontier.get("mechanisms", []))
            leading = next(
                (
                    item for item in mechanism_rows
                    if frontier_status_is_open(item.get("status"))
                ),
                None,
            )
            if leading is not None:
                missing = list(leading.get("missing_fields", []))
                question = (
                    f"Close the {leading.get('type') or 'mechanism'} frontier for "
                    f"{leading.get('artifact_path') or leading.get('artifact_id') or 'the artifact'}: "
                    + ("; ".join(missing[:4]) if missing else "verify the next unresolved relation")
                    + ". Which bounded static action most reduces this uncertainty?"
                )
            elif mechanism_rows:
                question = (
                    "Persist-time HOW is already CANDIDATE/CLAIM_READY. Do not ask the "
                    "operator for another TRACE round. Synthesize the official report "
                    "from recovered command/flags, named APIs, and decode facts; keep "
                    "remaining slots UNKNOWN/PARTIAL."
                )
            else:
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
                "hypotheses": hypothesis_before[:64],
                "investigation_frontier": investigation_frontier,
                "retrieval_packets": [packet.as_dict() for packet in retrieved.packets],
                "open_unknowns": list(dict.fromkeys(
                    [*open_unknowns, "runtime execution and network intent are not proven by static evidence"]
                ))[:96],
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
            planner_candidates = self._grounded_planner_action_candidates(
                context_manifest,
                artifact_ids={item.id for item in artifacts},
            )
            # A model turn may select several independent, already-grounded
            # targets.  Asking for a small batch makes model contribution
            # measurable without turning the model into a broad enumerator;
            # every item still has to cite delivered Evidence and pass the
            # closed catalog/policy checks below.
            required_action_count = min(3, len(planner_candidates))
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
                "output_contract": "static-investigation-plan-v2",
                "investigation_frontier": investigation_frontier,
                "allowed_investigation_actions": list(ActionCatalog.default().names()),
                "action_requirement": {
                    "minimum_actions_when_candidates_exist": 1 if planner_candidates else 0,
                    "required_action_count": required_action_count,
                    "candidates": planner_candidates,
                    "rule": (
                        "When candidates are present, select the required number of distinct candidate "
                        "actions when that many independent candidates are supplied; otherwise select all "
                        "available candidates. A limitation is valid only when it identifies why every "
                        "supplied concrete candidate is invalid."
                    ),
                },
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
                # A planner chooses a handful of catalog actions.  Keep its
                # budget bounded so it cannot hold final synthesis hostage,
                # but allow the configured provider enough time to return a
                # structured plan.  A 45-second cap prematurely cancelled
                # observed valid responses from the configured route.
                timeout_s=min(75.0, self.settings.model_timeout_s),
                # A complete plan-first action has evidence, target and
                # failure semantics. Three independent candidates do not fit
                # reliably in the former 768-token cap on OpenAI-compatible
                # models, which caused valid actions to be cut mid-envelope.
                #
                # NO LOCAL CAP. Three call sites used to clamp the completion budget to their own
                # hardcoded number (2_048 here, 4_096 for enrichment, 2_048 for the report overlay) while
                # the configured route allowed 4_096. For a REASONING model that is fatal rather than
                # merely tight: measured on the 白象 run, `deepseek-v4-pro` spent all 2_048 completion
                # tokens on hidden reasoning, returned `finish_reason=length` with an EMPTY content
                # string, and the call surfaced as a schema ValidationError. The configured budget is the
                # one authority; a per-call constant silently overrides the operator's setting.
                max_tokens=self.settings.model_max_tokens,
                # Planning is a control-plane turn. It needs a compact,
                # schema-valid action envelope, not an unbounded reasoning
                # stream that can consume its entire completion budget before
                # emitting a selector. The evidence/action audit trail is the
                # product-visible explanation surface.
                structured_output=True,
                disable_reasoning=True,
                stream=False,
            )
        runtime_result = AgentRuntime(
            self.model_gateway,
            max_context_bytes=self.settings.model_context_max_bytes,
            cancellation_requested=lambda: self._is_task_cancelled(task_id),
        ).run(request)
        planning_runs: list[tuple[str, ModelRequest[Any], Any, Any]] = [
            ("initial", request, request_stored, runtime_result)
        ]
        # Some OpenAI-compatible routes acknowledge JSON mode by returning an
        # empty object.  That is transport success, but not a plan when the
        # context contains a concrete, policy-safe anchor. Re-ask with a
        # deliberately compact task contract rather than replaying the entire
        # evidence context. This mirrors the investigation model: one bounded
        # question, one concrete action candidate, and explicit success/failure
        # criteria. No deterministic fallback is ever credited as a model
        # decision.
        if (
            planner_candidates
            and runtime_result.status == "SUCCEEDED"
            and runtime_result.response is not None
            and not runtime_result.response.parsed.actions
        ):
            repair_payload = {
                "objective": "Select one or more supplied static actions that reduce uncertainty.",
                "output_contract": "static-investigation-plan-v2",
                "artifacts": artifact_manifest,
                "allowed_tools": allowed_tools,
                "allowed_investigation_actions": list(ActionCatalog.default().names()),
                "allowed_evidence_ids": [
                    str(candidate["evidence_id"])
                    for candidate in planner_candidates
                    if candidate.get("evidence_id")
                ],
                "planner_repair": {
                    "reason": "EMPTY_ACTION_PLAN_WITH_GROUNDED_CANDIDATES",
                    "required_action_count": required_action_count,
                    "candidates": planner_candidates,
                    "instruction": (
                        f"Return exactly {required_action_count} complete action(s) by copying distinct "
                        "candidate artifact IDs, Evidence IDs and selectors exactly. An empty JSON object "
                        "or empty actions array is invalid because grounded candidates exist."
                    ),
                },
            }
            repair_messages = tuple(self.prompts.build_messages(prompt, repair_payload))
            repair_content = json.dumps(
                {"messages": repair_messages, "artifact_ids": deterministic_actions},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            repair_stored = self._store_model_payload(repair_content)
            repair_request = replace(request, messages=repair_messages)
            repair_result = AgentRuntime(
                self.model_gateway,
                max_context_bytes=self.settings.model_context_max_bytes,
                cancellation_requested=lambda: self._is_task_cancelled(task_id),
            ).run(repair_request)
            planning_runs.append(("empty_plan_repair", repair_request, repair_stored, repair_result))
            request = repair_request
            request_stored = repair_stored
            runtime_result = repair_result
            # Some proxy routes implement JSON mode but emit an empty object
            # for an otherwise valid streamed completion.  A final, compact
            # compatibility retry lets the model place the same JSON envelope
            # in normal text (the gateway validates it before use). This is a
            # transport adaptation, not permission to accept prose or to run
            # anything outside the closed static Action Catalog.
            if (
                repair_result.status == "SUCCEEDED"
                and repair_result.response is not None
                and not repair_result.response.parsed.actions
            ):
                portable_payload = {
                    **repair_payload,
                    "planner_repair": {
                        **repair_payload["planner_repair"],
                        "reason": "EMPTY_ACTION_PLAN_AFTER_JSON_REPAIR",
                        "instruction": (
                            "Return exactly one JSON object in normal response text containing an actions "
                            f"array with exactly {required_action_count} complete, distinct candidate action(s). "
                            "Copy each action exactly. Do not return an empty object, markdown explanation, "
                            "or an empty actions array."
                        ),
                    },
                    "transport_compatibility": {
                        "response_format": "not_forced",
                        "reason": "provider_returned_empty_json_envelope_twice",
                    },
                }
                portable_messages = tuple(self.prompts.build_messages(prompt, portable_payload))
                portable_content = json.dumps(
                    {"messages": portable_messages, "artifact_ids": deterministic_actions},
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                portable_stored = self._store_model_payload(portable_content)
                portable_request = replace(
                    repair_request,
                    messages=portable_messages,
                    structured_output=False,
                    # Keep the same token budget for the executable plan.
                    # If a route rejects this optional switch, ModelGateway
                    # performs its existing portable retry without it.
                    disable_reasoning=True,
                )
                portable_result = AgentRuntime(
                    self.model_gateway,
                    max_context_bytes=self.settings.model_context_max_bytes,
                    cancellation_requested=lambda: self._is_task_cancelled(task_id),
                ).run(portable_request)
                planning_runs.append(
                    ("portable_empty_plan_repair", portable_request, portable_stored, portable_result)
                )
                request = portable_request
                request_stored = portable_stored
                runtime_result = portable_result
        with self.database.session_factory.begin() as session:
            task = session.get(AnalysisTask, task_id, with_for_update=True)
            if task is None:
                raise LookupError(task_id)
            calls: list[ModelCall] = []
            for run_kind, run_request, run_stored, run_result in planning_runs:
                for event in run_result.events:
                    self._audit(
                        session,
                        case_id=task.case_id,
                        task_id=task.id,
                        event_type=event.name,
                        actor="agent-runtime",
                        object_type="AgentRun",
                        object_id=run_result.run_id,
                        payload={"run_id": run_result.run_id, "planning_run": run_kind, **event.payload},
                    )
                run_calls = self._persist_model_attempts(
                    session,
                    task,
                    prompt,
                    run_result.attempts,
                    run_stored,
                    context_manifest,
                    request=run_request,
                    response_stored=(
                        self._store_model_payload(run_result.response.raw_response)
                        if run_result.response is not None
                        else None
                    ),
                    successful_call_id=(
                        run_result.response.model_call_id
                        if run_result.response is not None
                        else None
                    ),
                    agent_run_id=run_result.run_id,
                    module="planning",
                    turn_id=retrieved.ledger.turn_id,
                    phase=f"{phase}:{run_kind}",
                    timeout_s=run_request.timeout_s,
                    max_tokens=run_request.max_tokens,
                )
                calls.extend(run_calls)
                if run_kind in {"empty_plan_repair", "portable_empty_plan_repair"}:
                    self._audit(
                        session,
                        case_id=task.case_id,
                        task_id=task.id,
                        event_type=(
                            "orchestration.plan_repair_requested"
                            if run_kind == "empty_plan_repair"
                            else "orchestration.plan_portable_repair_requested"
                        ),
                        actor="analysis-planner-agent",
                        object_type="AnalysisTask",
                        object_id=task.id,
                        payload={
                            "reason": (
                                "EMPTY_ACTION_PLAN_WITH_GROUNDED_CANDIDATES"
                                if run_kind == "empty_plan_repair"
                                else "EMPTY_ACTION_PLAN_AFTER_JSON_REPAIR"
                            ),
                            "candidate_count": len(planner_candidates),
                            "previous_model_call_id": calls[-len(run_calls) - 1].id
                            if len(calls) > len(run_calls)
                            else None,
                        },
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
                return [], ["Model planning failed; deterministic scheduler order retained."]
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
            selector_keys = frozenset(CATALOG_SELECTOR_KEYS)
            valid_actions: list[DynamicPlanAction] = []
            rejected = 0
            rejected_actions: list[dict[str, object]] = []
            # Over-long lists the schema TRUNCATED in the provider's answer (see
            # `DynamicPlanAction._truncate_oversized_lists`). Collected here so the notice REACHES A READER:
            # recording it on the parsed object and dropping it there satisfies the rule only at the schema
            # layer, which is precisely the half-done state the field was added to avoid (round 35). Collected
            # from the ENVELOPE, not from the filtered `valid_actions`, so a truncation on an action that is
            # later rejected is still reported.
            truncated_fields: list[str] = []
            for candidate_action in response.parsed.actions:
                for notice in candidate_action.truncated_fields or []:
                    if notice not in truncated_fields:
                        truncated_fields.append(notice)
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
                    rejected_actions.append(
                        {"action": action.model_dump(mode="json"), "reason": "unknown_artifact"}
                    )
                    continue
                if action.action_type:
                    # Dependencies are normalized after durable ActionSpec IDs
                    # are assigned in the investigation loop.  A model may
                    # refer to another action by index, semantic dedupe key or
                    # exact ID; unresolved references are audited and omitted
                    # from queue blocking dependencies rather than silently
                    # deadlocking the investigation.
                    try:
                        ActionType(action.action_type)
                    except ValueError:
                        rejected += 1
                        rejected_actions.append(
                            {
                                "action": action.model_dump(mode="json"),
                                "reason": "action_not_in_catalog",
                            }
                        )
                        continue
                    if not action.evidence_ids:
                        rejected += 1
                        rejected_actions.append(
                            {
                                "action": action.model_dump(mode="json"),
                                "reason": "uncited_investigation_action",
                            }
                        )
                        continue
                    if not set(action.evidence_ids).issubset(allowed_evidence_ids):
                        rejected += 1
                        rejected_actions.append(
                            {
                                "action": action.model_dump(mode="json"),
                                "reason": "undelivered_action_evidence",
                            }
                        )
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
                    raw_selector = normalize_target_selector(
                        dict(action.target_selector),
                        allowed_keys=selector_keys,
                    )
                    if not raw_selector:
                        raw_selector = normalize_target_selector(
                            dict(action.parameters),
                            allowed_keys=selector_keys,
                        )
                    if not raw_selector:
                        rejected += 1
                        rejected_actions.append(
                            {
                                "action": action.model_dump(mode="json"),
                                "reason": "invalid_target_selector",
                            }
                        )
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
                    if (
                        not expected_evidence_kinds
                        or not all(
                            isinstance(item, str) and item.strip()
                            for item in expected_evidence_kinds
                        )
                        or not action.success_condition.strip()
                    ):
                        rejected += 1
                        rejected_actions.append(
                            {
                                "action": action.model_dump(mode="json"),
                                "reason": "incomplete_action_semantics",
                            }
                        )
                        continue
                    if not self._has_complete_model_action_plan(action):
                        rejected += 1
                        rejected_actions.append(
                            {
                                "action": action.model_dump(mode="json"),
                                "reason": "incomplete_plan_first_contract",
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
                        rejected_actions.append(
                            {
                                "action": action.model_dump(mode="json"),
                                "reason": "action_not_in_catalog",
                            }
                        )
                        continue
                    if definition.sample_execution or definition.network_access:
                        rejected += 1
                        rejected_actions.append(
                            {
                                "action": action.model_dump(mode="json"),
                                "reason": "unsafe_action_policy",
                            }
                        )
                        continue
                    try:
                        policy = self.policy.require_tool(action.tool_name)
                    except ValueError:
                        rejected += 1
                        rejected_actions.append(
                            {"action": action.model_dump(mode="json"), "reason": "tool_not_allowed"}
                        )
                        continue
                    if (
                        action.tool_name not in allowed_tools
                        or action.tool_name not in self._compatible_static_tools(target)
                        or policy.sample_execution
                        or policy.network_access
                    ):
                        rejected += 1
                        rejected_actions.append(
                            {
                                "action": action.model_dump(mode="json"),
                                "reason": "unsafe_or_incompatible_tool",
                            }
                        )
                        continue
                else:
                    try:
                        policy = self.policy.require_tool(action.tool_name)
                    except ValueError:
                        rejected += 1
                        rejected_actions.append(
                            {"action": action.model_dump(mode="json"), "reason": "tool_not_allowed"}
                        )
                        continue
                    if action.tool_name not in self._compatible_static_tools(target):
                        rejected += 1
                        rejected_actions.append(
                            {
                                "action": action.model_dump(mode="json"),
                                "reason": "incompatible_artifact",
                            }
                        )
                        continue
                    if action.tool_name not in allowed_tools:
                        rejected += 1
                        rejected_actions.append(
                            {
                                "action": action.model_dump(mode="json"),
                                "reason": "tool_not_in_catalog",
                            }
                        )
                        continue
                    if policy.sample_execution or policy.network_access:
                        rejected += 1
                        rejected_actions.append(
                            {"action": action.model_dump(mode="json"), "reason": "unsafe_policy"}
                        )
                        continue
                for evidence_id in dict.fromkeys(action.evidence_ids):
                    if retrieved.ledger.stage_for(evidence_id) == EvidenceStage.DELIVERED:
                        retrieved.ledger.advance(
                            evidence_id,
                            EvidenceStage.REFERENCED_BY_MODEL,
                            details={
                                "reference_kind": "action_proposal",
                                "action_type": action.action_type,
                            },
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
                item for item in prior_planning.get("action_history", []) if isinstance(item, dict)
            ]
            action_history = prior_action_history + [
                {**item.model_dump(mode="json"), "planning_phase": phase} for item in valid_actions
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
                    "last_transition": "HYPOTHESIZING->INVESTIGATING"
                    if valid_actions
                    else "HYPOTHESIZING->UNKNOWN",
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
            if truncated_fields:
                # The bound is stated in the READER's document, and it says what was dropped rather than
                # merely that something was: a consumer that sees a bounded list must not read it as complete
                # (EC-4), and the provider's excess items are NOT represented anywhere else.
                limitations.append(
                    "Model planner returned lists longer than the accepted bound; the excess items were "
                    "dropped and are not represented: " + ", ".join(truncated_fields) + "."
                )
            if not valid_actions:
                limitations.append(
                    "Model planner returned no executable actions; deterministic scheduler order retained."
                )
            return valid_actions, limitations

    @staticmethod
    def _ledger_ids(ledger: EvidenceDeliveryLedger, stage: EvidenceStage) -> list[str]:
        return _coordinator._ledger_ids(ledger, stage)

    @classmethod
    def _bound_completed_actions(
        cls,
        actions: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        return _coordinator._bound_completed_actions(cls, actions)

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
            dict(item) for item in completed_actions if isinstance(item, Mapping)
        ][-128:]
        # Deterministic baseline actions do not carry a planner token. Attribute
        # those once to the earliest pending turn; model actions are matched by
        # their explicit planner_turn_id below.
        unassigned = [item for item in normalized_actions if not item.get("planner_turn_id")]
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
                scoped_investigation_action_key(
                    str(action.action_type),
                    dict(action.target_selector),
                    self._model_action_plan(action),
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
                scoped_investigation_action_key(
                    str(action.action_type),
                    dict(action.target_selector),
                    self._model_action_plan(action),
                ),
            ): action
            for action in actions
        }
        seen: set[str] = set()
        for record in records:
            record_parameters = dict(record.parameters or {})
            record_plan = record_parameters.get("_analysis_plan", {})
            key = scoped_investigation_action_key(
                record.action_type,
                dict(record.target_selector or {}),
                record_plan if isinstance(record_plan, Mapping) else None,
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
            convergence = (
                dict(parameters.get("_convergence", {}))
                if isinstance(parameters.get("_convergence"), Mapping)
                else {}
            )
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
                    "source_evidence_ids": list(source_action.evidence_ids)
                    if source_action
                    else [],
                    "origin": source_action.origin if source_action else "model",
                    "dedupe_key": key,
                    "artifact_boundary": record.artifact_id,
                    "autopsy_category": autopsy.get("category"),
                    "autopsy": autopsy,
                    "convergence": convergence,
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
        knowledge_sha256 = ""
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
            knowledge_sha256 = mappings[0].knowledge_sha256
            claim.attack_mapping = {
                "status": "candidate",
                "snapshot_version": snapshot.version,
                "snapshot_sha256": snapshot.sha256,
                "knowledge_sha256": mappings[0].knowledge_sha256,
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
                        "knowledge_status": mapping.knowledge_status,
                        "knowledge_sha256": mapping.knowledge_sha256,
                        "url": mapping.url,
                        "tactics": list(mapping.tactics),
                        "detection_strategies": list(mapping.detection_strategies),
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
            tool_version="0.2.0",
            status="SUCCEEDED",
            parameters={
                "snapshot_version": snapshot.version,
                "knowledge_sha256": knowledge_sha256,
            },
            environment={"deterministic": True, "sample_execution": False, "network_access": False},
            output={
                "snapshot_version": snapshot.version,
                "snapshot_sha256": snapshot.sha256,
                "knowledge_sha256": knowledge_sha256,
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
                id=new_id(),
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
        release_transaction_before_wait: bool = False,
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
                (task.strategy_snapshot.get("investigation") or {})
                .get("threads", [{}])[0]
                .get("id")
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
                "scheduler": scheduler
                or ("model_plan" if planned_tool_names else "deterministic_baseline"),
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
                "scheduler": scheduler
                or ("model_plan" if planned_tool_names else "deterministic_baseline"),
                "planned_tools": list(planned_tool_names),
            },
            max_cpu_seconds=policy.max_cpu_seconds,
            max_memory_mb=policy.max_memory_mb,
            task_queue=self.settings.task_queue_for(tool_name),
        )
        try:
            # Temporal execution can take minutes.  The caller of the
            # isolated action path deliberately gives this method a short
            # read/audit session; commit that session before awaiting the
            # Worker so task status and cancellation writes never wait on the
            # parser's transaction.  The legacy in-transaction path keeps
            # the default ``False`` for compatibility with direct tests.
            if release_transaction_before_wait:
                session.commit()
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
        release_transaction_before_wait: bool = False,
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
            release_transaction_before_wait=release_transaction_before_wait,
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
                "scheduler": scheduler
                or ("model_plan" if planned_tool_names else "deterministic_baseline"),
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
                self._record_builtin_code_signal_evidence(session, task, artifact, tool_run, result)
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
            if fact.kind.startswith("mechanism_")
            or fact.kind in {"resource_inventory", "pe_header_anomaly"}
        )
        facts = tuple(result.facts)
        if not mechanism_facts:
            facts += derive_mechanism_facts(facts, subject=artifact.logical_path)
        evidence_rows: list[Evidence] = []
        # Derived facts commonly sit next to their observed source at the
        # same RVA/file offset.  Keep a small inverted index while building
        # the batch so source recovery does not rescan every prior Evidence
        # row for every derived fact (which becomes O(n^2) on string-heavy
        # samples).  Candidate rows are still checked by ``_same_anchor``
        # below to preserve the historical subset-matching semantics.
        anchor_locator_keys = (
            "offset",
            "function_entry",
            "rva",
            "entry",
            "address",
            "from",
            "to",
        )
        observed_by_anchor: dict[tuple[str, str, str], list[str]] = {}
        observed_ids: list[str] = []
        evidence_by_id: dict[str, Evidence] = {}

        def _index_observed(row: Evidence) -> None:
            if row.nature != "STATIC_OBSERVED":
                return
            # Preserve the legacy bounded fallback, which included observed
            # rows even when a parser omitted an anchor type.
            observed_ids.append(row.id)
            if not isinstance(row.anchor, dict):
                return
            anchor_type = row.anchor.get("type")
            if anchor_type is None:
                return
            type_key = str(anchor_type)
            for key in anchor_locator_keys:
                value = row.anchor.get(key)
                if value is not None:
                    observed_by_anchor.setdefault((type_key, key, str(value)), []).append(row.id)

        for fact in facts:
            anchor = {
                **fact.anchor,
                "artifact_id": artifact.id,
                "content_sha256": artifact.content_sha256,
                "logical_path": artifact.logical_path,
            }
            fact_value = fact.value
            fact_is_derived = fact.kind.startswith("mechanism_") or fact.kind in {
                "resource_inventory",
                "pe_header_anomaly",
                "string_semantics",
                "function_data_correlation",
                "cross_function_chain",
                # `decode_result` is COMPUTED, not observed: the fact is the output of applying a decode
                # chain (stride -> unhexlify -> text) to bytes read from the image. ADR-0030 puts
                # deterministic transformations of observations on the DERIVED side, and the Claim Gate
                # enforces provenance for derived rows - which is exactly the guarantee a decode result
                # needs, because "we decoded X" must name what it was decoded FROM.
                #
                # MEASURED before this change: the row carried `nature='STATIC_OBSERVED'` with
                # `verification_status=DECODED_STATIC`, so a computed recovery was indistinguishable from
                # a direct tool reading, and it carried no `derivation` envelope. The envelope below is
                # generated automatically for derived facts and pins the input evidence ids plus
                # input/output digests.
                "decode_result",
            }
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
                        compared = [
                            key
                            for key in anchor_locator_keys
                            if anchor.get(key) is not None and row.anchor.get(key) is not None
                        ]
                        return bool(compared) and all(
                            str(row.anchor.get(key)) == str(anchor.get(key)) for key in compared
                        )

                    indexed_ids: list[str] = []
                    anchor_type = anchor.get("type")
                    if anchor_type is not None:
                        seen_indexed: set[str] = set()
                        for key in anchor_locator_keys:
                            value = anchor.get(key)
                            if value is None:
                                continue
                            for row_id in observed_by_anchor.get(
                                (str(anchor_type), key, str(value)), ()
                            ):
                                if row_id not in seen_indexed:
                                    seen_indexed.add(row_id)
                                    indexed_ids.append(row_id)
                    source_ids = [
                        row_id
                        for row_id in indexed_ids
                        if row_id in evidence_by_id and _same_anchor(evidence_by_id[row_id])
                    ]
                if not source_ids:
                    source_ids = observed_ids[:24]
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
                id=new_id(),
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
                    if fact_is_derived
                    else "STATIC_INFERRED"
                    if fact.kind
                    in {
                        "function_semantic_summary",
                        "decompile_slice",
                        "abstract_execution_trace",
                        "pcode_slice",
                    }
                    else "STATIC_OBSERVED"
                ),
                value=fact_value,
                anchor=anchor,
            )
            session.add(evidence)
            evidence_rows.append(evidence)
            evidence_by_id[evidence.id] = evidence
            _index_observed(evidence)
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
        # Correlate the fresh observed rows before constructing the seed map.
        # This is the deterministic baseline path: mechanism links must not
        # depend on a model planner turn being available.  The correlator is
        # deliberately restricted to STATIC_OBSERVED rows, so a prior derived
        # link can never feed itself or manufacture a new mechanism.
        observed_rows = [
            {
                "id": row.id,
                "kind": row.kind,
                "value": row.value,
                "anchor": row.anchor,
            }
            for row in evidence_rows
            if row.nature == "STATIC_OBSERVED"
        ]
        for link in derive_static_mechanism_links(observed_rows):
            link_id = str(link.get("id") or "")
            link_value = link.get("value")
            if not link_id or not isinstance(link_value, dict):
                continue
            if session.get(Evidence, link_id) is not None:
                continue
            source_ids = [
                str(item)
                for item in link_value.get("source_evidence_ids", ())
                if str(item).strip()
            ][:32]
            if not source_ids:
                continue
            normalized_value = {
                **link_value,
                "source_evidence_ids": source_ids,
                "derivation": {
                    "evaluator": "derive_static_mechanism_links",
                    "input_evidence_ids": source_ids,
                    "input_digest": hashlib.sha256(
                        json.dumps(
                            source_ids,
                            ensure_ascii=True,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest(),
                    "output_digest": hashlib.sha256(
                        json.dumps(
                            link_value,
                            ensure_ascii=True,
                            sort_keys=True,
                            default=str,
                        ).encode("utf-8")
                    ).hexdigest(),
                    "exact": True,
                },
            }
            link_evidence = Evidence(
                id=link_id,
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=tool_run.id,
                module="static_triage",
                kind=str(link.get("kind") or "investigation_mechanism_link"),
                nature="STATIC_DERIVED",
                value=normalized_value,
                anchor={
                    **(
                        dict(link.get("anchor"))
                        if isinstance(link.get("anchor"), dict)
                        else {}
                    ),
                    "artifact_id": artifact.id,
                    "content_sha256": artifact.content_sha256,
                    "logical_path": artifact.logical_path,
                    "source_evidence_ids": source_ids,
                },
            )
            session.add(link_evidence)
            evidence_rows.append(link_evidence)
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="evidence.recorded",
                actor="static-mechanism-correlator",
                object_type="Evidence",
                object_id=link_evidence.id,
                payload={
                    "kind": link_evidence.kind,
                    "nature": link_evidence.nature,
                    "tool_run_id": tool_run.id,
                    "source_evidence_ids": source_ids,
                    "evaluator": "derive_static_mechanism_links",
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
                # The report/prompt view remains bounded, while 64 clusters
                # gives the investigation scheduler enough room to cover all
                # high-signal functions in ordinary multi-function samples.
                max_clusters=64,
            )
            seed_evidence = Evidence(
                id=new_id(),
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=tool_run.id,
                module="static_triage",
                kind="investigation_seed_map",
                # Clustering competing hypotheses is a bounded interpretation,
                # not an exact replay of preserved static bytes (ADR-0030).
                nature="STATIC_INFERRED",
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
                        "exact": False,
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
                item
                for item in investigation.get("seed_queue", [])
                if isinstance(item, dict) and str(item.get("artifact_id")) != str(artifact.id)
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
            queue.sort(
                key=lambda item: (
                    int(item.get("priority", 0)) * -1,
                    str(item.get("cluster_id", "")),
                )
            )
            task.strategy_snapshot = {
                **(task.strategy_snapshot or {}),
                "investigation": {
                    **investigation,
                    "seed_maps": seed_maps,
                    "seed_queue": queue[:64],
                    "seed_map_version": "1.0",
                },
            }
        # Evidence IDs are allocated eagerly, but ClaimEvidence has a real FK
        # to the Evidence table. Materialize the complete parser batch once
        # before any claim/relation query can trigger SQLAlchemy autoflush.
        session.flush()
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
                id=new_id(),
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
                self._link_claim_evidence(
                    session, claim_id=claim.id, evidence_id=evidence_id
                )
            self._infer_component_relations(session, task, artifact, claim)
        if not specifications and evidence_rows and artifact.role != "CONTAINER":
            # A successful static pass with no behavior indicator still gets a
            # visible, evidence-backed profile result. This prevents a task
            # from reporting COMPLETE while exposing only raw fragments.
            profile_evidence = evidence_rows[0]
            claim = Claim(
                id=new_id(),
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
            self._link_claim_evidence(
                session, claim_id=claim.id, evidence_id=profile_evidence.id
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
        architecture = str(signals.get("architecture") or "x86")
        evidence_ids: list[str] = []
        api_names: list[str] = []
        # A 256-call page of the Capstone fallback signal list is the same
        # silent-loss shape as the retired 64-reference cut: whatever lives in
        # the tail of the list never becomes Evidence, so a later join cannot
        # see it.  Keep the recovered set; the degenerate guard is the same one
        # the Ghidra path uses.
        for call in calls[: AnalysisService._MAX_GHIDRA_INSTRUCTIONS_PER_FUNCTION]:
            if not isinstance(call, dict):
                continue
            api = str(call.get("api", ""))
            api_names.append(api)
            evidence = Evidence(
                id=new_id(),
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=tool_run.id,
                module="static_triage",
                kind="code_api_call",
                nature="STATIC_OBSERVED",
                value={
                    "api": api,
                    "rva": call.get("address"),
                    "file_offset": call.get("file_offset"),
                },
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
            evidence_ids.append(evidence.id)
        if not evidence_ids:
            return

        # Feed fallback call-site observations through the same typed
        # correlator used by Ghidra facts.  Without this bridge, x64 Capstone
        # can recover concrete RVAs but the report only receives a generic
        # call-graph Claim and never gets a mechanism link.  Derived rows are
        # still STATIC_DERIVED and retain every source Evidence ID.
        code_rows = [
            {
                "id": evidence.id,
                "kind": evidence.kind,
                "value": evidence.value,
                "anchor": evidence.anchor,
            }
            for evidence in (
                session.scalars(
                    select(Evidence)
                    .where(
                        Evidence.task_id == task.id,
                        Evidence.artifact_id == artifact.id,
                        Evidence.tool_run_id == tool_run.id,
                        Evidence.kind == "code_api_call",
                    )
                    .order_by(Evidence.id)
                )
            )
        ]
        for link in derive_static_mechanism_links(code_rows):
            link_id = str(link.get("id") or "")
            link_value = link.get("value")
            if not link_id or not isinstance(link_value, dict) or session.get(Evidence, link_id):
                continue
            source_ids = list(
                dict.fromkeys(
                    str(item)
                    for item in link_value.get("source_evidence_ids", ())
                    if str(item).strip()
                )
            )[:32]
            if not source_ids:
                continue
            normalized_value = {
                **link_value,
                "source_evidence_ids": source_ids,
                "derivation": {
                    "evaluator": "derive_static_mechanism_links",
                    "input_evidence_ids": source_ids,
                    "input_digest": hashlib.sha256(
                        json.dumps(source_ids, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    ).hexdigest(),
                    "output_digest": hashlib.sha256(
                        json.dumps(link_value, ensure_ascii=True, sort_keys=True, default=str).encode("utf-8")
                    ).hexdigest(),
                    "exact": True,
                },
            }
            link_evidence = Evidence(
                id=link_id,
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=tool_run.id,
                module="static_triage",
                kind=str(link.get("kind") or "investigation_mechanism_link"),
                nature="STATIC_DERIVED",
                value=normalized_value,
                anchor={
                    **(dict(link.get("anchor")) if isinstance(link.get("anchor"), dict) else {}),
                    "artifact_id": artifact.id,
                    "content_sha256": artifact.content_sha256,
                    "logical_path": artifact.logical_path,
                    "source_evidence_ids": source_ids,
                },
            )
            session.add(link_evidence)
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="evidence.recorded",
                actor="static-mechanism-correlator",
                object_type="Evidence",
                object_id=link_evidence.id,
                payload={
                    "kind": link_evidence.kind,
                    "nature": link_evidence.nature,
                    "tool_run_id": tool_run.id,
                    "source_evidence_ids": source_ids,
                    "evaluator": "derive_static_mechanism_links",
                    "fallback_architecture": architecture,
                },
            )
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
            id=new_id(),
            task_id=task.id,
            module="static_triage",
            claim_type="FALLBACK_CODE_CALL_GRAPH",
            subject=artifact.logical_path,
            action="contains_rva_level_call_sites",
            object="imported API call targets",
            mechanism=f"Capstone {architecture} fallback over executable PE sections",
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
        for evidence_id in evidence_ids:
            self._link_claim_evidence(
                session, claim_id=claim.id, evidence_id=evidence_id
            )
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
            (
                int(call["address"])
                for call in calls
                if isinstance(call, dict) and call.get("address") is not None
            ),
            None,
        )
        if first_rva is not None:
            priority_claim = Claim(
                id=new_id(),
                task_id=task.id,
                module="static_triage",
                claim_type="FUNCTION_REVIEW_PRIORITY",
                subject=artifact.logical_path,
                action="prioritizes",
                object=f"x86 fallback code region@RVA 0x{first_rva:x}",
                mechanism="API call-site density and security-relevant targets",
                condition="function boundaries unavailable because Ghidra architecture validation failed",
                statement=(
                    f"Prioritize the {architecture} code region around RVA 0x{first_rva:x} for manual review: "
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
                self._link_claim_evidence(
                    session, claim_id=priority_claim.id, evidence_id=evidence_id
                )
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
            logical_path = (
                f"{parent.logical_path}!/.rsrc/{resource_type}-{resource_name}-{language}.bin"
            )
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
            detected_type = identify_format(payload, logical_path).detected_type
            child = Artifact(
                task_id=task.id,
                content_sha256=stored.sha256,
                parent_artifact_id=parent.id,
                logical_path=logical_path,
                role="EMBEDDED_OBJECT",
                obligation=_child_obligation(detected_type),
                detected_type=detected_type,
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
            detected_type = identify_format(decoded, logical_path).detected_type
            child = Artifact(
                task_id=task.id,
                content_sha256=stored.sha256,
                parent_artifact_id=parent.id,
                logical_path=logical_path,
                role="DECODED_PAYLOAD",
                obligation=_child_obligation(detected_type),
                detected_type=detected_type,
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
            detected_type = identify_format(embedded_content, internal_path).detected_type
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
                    obligation=_child_obligation(detected_type),
                    detected_type=detected_type,
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
                child.obligation = _child_obligation(detected_type)
                child.detected_type = detected_type
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
                    image_base = int(identity.summary["pe"].get("image_base") or 0)
                    ghidra_entries: set[int] = set()
                    for item in run.output.get("functions", []):
                        if not isinstance(item, dict):
                            continue
                        for locator in self._function_entry_integers(item):
                            ghidra_entries.add(locator)
                            if image_base and locator >= image_base:
                                ghidra_entries.add(locator - image_base)
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
                            retry_entries: set[int] = set()
                            for item in retry.output.get("functions", []):
                                if not isinstance(item, dict):
                                    continue
                                for locator in self._function_entry_integers(item):
                                    retry_entries.add(locator)
                                    if image_base and locator >= image_base:
                                        retry_entries.add(locator - image_base)
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
                    "scheduler": scheduler
                    or ("model_plan" if planned_tool_names else "deterministic_baseline"),
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

    @classmethod
    def _parse_static_address(cls, value: object) -> int | None:
        return _derivation_support._parse_static_address(value)

    @classmethod
    def _code_locator_integers(cls, value: object) -> set[int]:
        return _derivation_support._code_locator_integers(value)

    @classmethod
    def _row_own_function_payload(cls, row: object) -> dict[str, object]:
        return _derivation_support._row_own_function_payload(row)

    @classmethod
    def _row_own_function_matches(cls, row: object, target: str) -> bool:
        return _derivation._row_own_function_matches(row, target)

    @classmethod
    def _follow_local_tail_jmp(
        cls,
        function: dict[str, object],
        artifact_rows: list[object],
    ) -> dict[str, object]:
        """If the selected function is only a local jmp thunk, decompile the body."""
        tail_ints: set[int] = set()
        api_calls = False
        for edge in function.get("call_targets") or []:
            if not isinstance(edge, dict):
                continue
            kind = str(edge.get("consumer_kind") or edge.get("type") or "").upper()
            name = str(edge.get("target_name") or edge.get("target_function") or "")
            if kind in {"JUMP", "JMP", "TAIL"}:
                tail_ints |= cls._code_locator_integers(edge.get("to") or edge.get("target") or name)
                continue
            if name and not re.match(r"^(?:FUN_|sub_|thunk_)", name, re.I):
                if re.search(r"[A-Za-z]", name) and cls._parse_static_address(name) is None:
                    api_calls = True
        for instruction in function.get("instructions") or []:
            if not isinstance(instruction, dict):
                continue
            text = str(instruction.get("text") or "").strip()
            if re.match(r"jmp\s+", text, re.I) and "ptr" not in text.casefold():
                token = text.split(None, 1)[-1]
                tail_ints |= cls._code_locator_integers(token)
            elif re.match(r"call\s+", text, re.I):
                api_calls = True
        if api_calls or len(tail_ints) != 1:
            return function
        target_int = next(iter(tail_ints))
        for row in artifact_rows:
            if getattr(row, "kind", None) != "function_context":
                continue
            payload = cls._row_own_function_payload(row)
            own = cls._function_entry_integers(payload) | cls._code_locator_integers(
                payload.get("name")
            )
            if target_int not in own:
                continue
            merged = dict(function)
            tail_calls = payload.get("call_targets") or []
            if isinstance(tail_calls, list):
                combined = [
                    dict(item)
                    for item in list(function.get("call_targets") or []) + list(tail_calls)
                    if isinstance(item, dict)
                ]
                # This branch only runs for a bare local jmp thunk (no API call
                # and exactly one tail target), so the merged lists stay tiny.
                # The cut is a degenerate-input guard, not a quota, and is far
                # above anything a real thunk carries.
                merged["call_targets"] = combined[
                    : cls._MAX_GHIDRA_INSTRUCTIONS_PER_FUNCTION
                ]
                merged["references_from"] = merged["call_targets"]
            tail_instructions = payload.get("instructions") or []
            if isinstance(tail_instructions, list):
                merged["instructions"] = [
                    dict(item)
                    for item in list(function.get("instructions") or []) + list(tail_instructions)
                    if isinstance(item, dict)
                ][: cls._MAX_GHIDRA_INSTRUCTIONS_PER_FUNCTION]
            anchor = getattr(row, "anchor", None)
            tail_entry = payload.get("entry")
            if not tail_entry and isinstance(anchor, dict):
                tail_entry = anchor.get("function_entry")
            merged["name"] = payload.get("name") or function.get("name")
            merged["entry"] = tail_entry or function.get("entry")
            merged["thunk_from"] = function.get("entry")
            return merged
        return function

    @classmethod
    def _function_entry_integers(cls, function: Mapping[str, object] | None) -> set[int]:
        return _derivation_support._function_entry_integers(function)

    @classmethod
    def _function_name_matches_vas(
        cls,
        function: Mapping[str, object] | None,
        addresses: Iterable[int],
    ) -> bool:
        """True when Ghidra named the function FUN_<start-va> without a matching entry field."""
        if not isinstance(function, Mapping):
            return False
        wanted = {item for item in addresses if isinstance(item, int) and item >= 0}
        if not wanted:
            return False
        match = re.search(
            r"(?i)(?:FUN_|sub_|LAB_)([0-9a-f]{6,})$",
            str(function.get("name") or function.get("symbol") or ""),
        )
        if not match:
            return False
        parsed = cls._parse_static_address("0x" + match.group(1))
        return parsed is not None and parsed in wanted

    @classmethod
    def _function_references_addresses(
        cls,
        function: Mapping[str, object] | None,
        addresses: Iterable[int],
        *,
        image_base: int = 0,
    ) -> bool:
        """True when a Ghidra function already names one of the recovered VAs."""
        wanted = tuple(item for item in addresses if isinstance(item, int) and item >= 0)
        if not wanted or not isinstance(function, Mapping):
            return False
        blobs: list[Mapping[str, object]] = []
        for key in ("references_from", "data_references", "references"):
            raw = function.get(key)
            if isinstance(raw, list):
                blobs.extend(item for item in raw if isinstance(item, Mapping))
        for ins in function.get("instructions") or ():
            if isinstance(ins, Mapping):
                blobs.append(ins)
        for blob in blobs:
            locators = (
                blob.get("to"),
                blob.get("address"),
                blob.get("target"),
                blob.get("target_name"),
                blob.get("text"),
                blob.get("mnemonic"),
            )
            for locator in locators:
                parsed = parse_operand_address(locator)
                if parsed is None:
                    parsed = cls._parse_static_address(locator)
                if parsed is None:
                    continue
                if any(addresses_alias(parsed, va, image_base) for va in wanted):
                    return True
        return False

    @classmethod
    def _normalized_pin_addresses(cls, addresses: Iterable[object]) -> tuple[int, ...]:
        wanted: list[int] = []
        for item in addresses:
            if isinstance(item, bool):
                continue
            if isinstance(item, int) and item >= 0:
                wanted.append(item)
                continue
            parsed = cls._parse_static_address(item)
            if parsed is not None:
                wanted.append(parsed)
        return tuple(dict.fromkeys(wanted))

    @classmethod
    def _locator_aliases_addresses(
        cls,
        locator: object,
        addresses: Iterable[int],
        *,
        image_base: int = 0,
    ) -> bool:
        parsed = parse_operand_address(locator)
        if parsed is None:
            parsed = cls._parse_static_address(locator)
        if parsed is None:
            return False
        return any(addresses_alias(parsed, va, image_base) for va in addresses)

    @classmethod
    def _reference_aliases_addresses(
        cls,
        blob: Mapping[str, object] | None,
        addresses: Iterable[int],
        *,
        image_base: int = 0,
    ) -> bool:
        if not isinstance(blob, Mapping) or not tuple(addresses):
            return False
        locators = (
            blob.get("to"),
            blob.get("address"),
            blob.get("target"),
            blob.get("target_name"),
            blob.get("text"),
            blob.get("mnemonic"),
        )
        return any(
            cls._locator_aliases_addresses(item, addresses, image_base=image_base)
            for item in locators
            if item not in (None, "")
        )

    @classmethod
    def _collect_recovered_config_xrefs(
        cls,
        functions: Iterable[object],
        addresses: Iterable[object],
        *,
        image_base: int = 0,
        limit: int = 64,
    ) -> list[dict[str, object]]:
        """Keep decoded-buffer DATA refs even when the owning function is huge."""
        wanted = cls._normalized_pin_addresses(addresses)
        if not wanted:
            return []
        found: list[dict[str, object]] = []
        seen: set[tuple[str, str, str]] = set()
        for function in functions:
            if not isinstance(function, Mapping):
                continue
            entry = str(function.get("entry") or "")
            name = str(function.get("name") or "")
            refs = function.get("references_from")
            rows = refs if isinstance(refs, list) else []
            for row in rows:
                if not isinstance(row, Mapping):
                    continue
                if "call" in str(row.get("type") or "").casefold():
                    continue
                if not cls._reference_aliases_addresses(row, wanted, image_base=image_base):
                    continue
                payload = {
                    "from": row.get("from"),
                    "to": row.get("to") or row.get("address") or row.get("target"),
                    "type": row.get("type"),
                    "target_name": row.get("target_name") or row.get("name") or "",
                    "function": name,
                    "entry": entry,
                    "link_kind": "decoded_va_reference",
                }
                key = (
                    str(payload.get("from") or ""),
                    str(payload.get("to") or ""),
                    str(payload.get("type") or ""),
                )
                if key in seen:
                    continue
                seen.add(key)
                found.append(payload)
                if len(found) >= limit:
                    return found
        return found

    @classmethod
    def _prioritize_config_data_references(
        cls,
        rows: Iterable[object],
        addresses: Iterable[object],
        *,
        image_base: int = 0,
        limit: int = 48,
    ) -> list[dict[str, object]]:
        """Keep recovered XOR VAs in the 48-slot function_context page."""
        wanted = cls._normalized_pin_addresses(addresses)
        pinned: list[dict[str, object]] = []
        rest: list[dict[str, object]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if wanted and cls._reference_aliases_addresses(row, wanted, image_base=image_base):
                pinned.append(row)
            else:
                rest.append(row)
        remaining = max(0, limit - len(pinned))
        return pinned + rest[:remaining]

    @classmethod
    def instruction_indices_referencing_addresses(cls, instructions: object, addresses: Iterable[object], xrefs: Iterable[Mapping[str, object]] = (), *, image_base: int = 0, context: int = 3, lookback: int = 0) -> set[int]:
        """Public behaviour entry point for `_instruction_indices_referencing_addresses` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private classmethod stays the implementation and the facade delegates to it.
        """
        return cls._instruction_indices_referencing_addresses(instructions, addresses, xrefs, image_base=image_base, context=context, lookback=lookback)


    @classmethod
    def _instruction_indices_referencing_addresses(
        cls,
        instructions: object,
        addresses: Iterable[object],
        xrefs: Iterable[Mapping[str, object]] = (),
        *,
        image_base: int = 0,
        context: int = 3,
        lookback: int = 0,
    ) -> set[int]:
        """Force LEA/MOV sites of recovered buffers into the 256-op window."""
        rows = (
            [item for item in instructions if isinstance(item, dict)]
            if isinstance(instructions, list)
            else []
        )
        wanted = cls._normalized_pin_addresses(addresses)
        sites: set[str] = set()
        for xref in xrefs:
            if not isinstance(xref, Mapping):
                continue
            site = cls._locator_key(xref.get("from"))
            if site:
                sites.add(site)
        selected: set[int] = set()
        behind = max(0, int(lookback))
        around = max(0, int(context))
        for index, row in enumerate(rows):
            address = cls._locator_key(row.get("address") or row.get("from"))
            text = str(row.get("text") or row.get("mnemonic") or "")
            hit = bool(address and address in sites)
            if not hit and wanted:
                hit = cls._locator_aliases_addresses(text, wanted, image_base=image_base)
            if not hit:
                continue
            start = max(0, index - max(around, behind))
            end = min(len(rows), index + around + 1)
            selected.update(range(start, end))
        return selected

    @classmethod
    def _recovered_config_consumer_links(
        cls,
        xor_hits: Iterable[object],
        config_xrefs: Iterable[object],
        *,
        artifact_id: str,
        image_base: int = 0,
    ) -> list[dict[str, object]]:
        """Link recovered XOR buffers to Ghidra DATA xrefs without another action."""
        links: list[dict[str, object]] = []
        xref_rows = [item for item in config_xrefs if isinstance(item, Mapping)]
        for hit in xor_hits:
            if not isinstance(hit, Mapping):
                continue
            raw_va = hit.get("virtual_address")
            parsed_va = (
                raw_va
                if isinstance(raw_va, int) and raw_va >= 0
                else cls._parse_static_address(raw_va)
            )
            if parsed_va is None:
                continue
            identified = with_artifact_identity(
                hit.get("output_buffer")
                if isinstance(hit.get("output_buffer"), Mapping)
                else None,
                artifact_id,
            )
            if identified is None:
                identified = with_artifact_identity(
                    output_buffer_identity(
                        address_space="image",
                        address=parsed_va,
                        length=hit.get("length"),
                    ),
                    artifact_id,
                )
            fields = catalog_fields_from_decode_verification(
                hit,
                artifact_id=artifact_id,
                output_buffer=identified,
            )
            identified = (
                fields.get("output_buffer")
                if isinstance(fields.get("output_buffer"), Mapping)
                else identified
            )
            if not isinstance(identified, Mapping) or not fields:
                continue
            matched = [
                dict(item)
                for item in xref_rows
                if cls._locator_aliases_addresses(
                    item.get("to"), (parsed_va,), image_base=image_base
                )
            ]
            if not matched:
                continue
            consumer = matched[0]
            consumer["input_buffer"] = identified
            links.append(
                {
                    "verification": dict(hit),
                    "fields": fields,
                    "consumer": consumer,
                    "output_buffer": identified,
                }
            )
        return links

    @classmethod
    def _pe_entry_integers(cls, pe_summary: Mapping[str, object] | None) -> set[int]:
        return _derivation_support._pe_entry_integers(pe_summary)

    @classmethod
    def select_ghidra_function_rows(cls, functions: object, pe_summary: Mapping[str, object] | None = None, *, limit: int | None = None, pin_data_addresses: Iterable[object] = (), thunks: Mapping[int, str] | None = None) -> list[dict[str, object]]:
        """Public behaviour entry point for `_select_ghidra_function_rows` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private classmethod stays the implementation and the facade delegates to it, so a test that replaces
        the private attribute on the class keeps working.
        """
        return cls._select_ghidra_function_rows(functions, pe_summary, limit=limit, pin_data_addresses=pin_data_addresses, thunks=thunks)


    @classmethod
    def _select_ghidra_function_rows(
        cls,
        functions: object,
        pe_summary: Mapping[str, object] | None = None,
        *,
        limit: int | None = None,
        pin_data_addresses: Iterable[object] = (),
        thunks: Mapping[int, str] | None = None,
    ) -> list[dict[str, object]]:
        """Keep the PE entry and recovered-config xref functions in the budget."""
        budget = limit if limit is not None else cls._MAX_GHIDRA_FUNCTIONS
        all_rows = [item for item in functions if isinstance(item, dict)] if isinstance(functions, list) else []
        locators = cls._pe_entry_integers(pe_summary)
        image_base = cls._parse_static_address((pe_summary or {}).get("image_base")) or 0
        wanted: list[int] = []
        for item in pin_data_addresses:
            if isinstance(item, bool):
                continue
            if isinstance(item, int) and item >= 0:
                wanted.append(item)
                continue
            parsed = cls._parse_static_address(item)
            if parsed is not None:
                wanted.append(parsed)
        wanted_vas = tuple(dict.fromkeys(wanted))
        thread_start_vas = set(unique_thread_start_routine_vas(all_rows, thunks=thunks))
        thread_start_vas.update(unique_thread_start_routine_vas_from_pe(pe_summary))
        pinned: list[dict[str, object]] = []
        thread_pinned: list[dict[str, object]] = []
        data_pinned: list[dict[str, object]] = []
        rest: list[dict[str, object]] = []
        for item in all_rows:
            if locators and cls._function_entry_integers(item) & locators:
                pinned.append(item)
            elif thread_start_vas and (
                cls._function_entry_integers(item) & thread_start_vas
                or cls._function_name_matches_vas(item, thread_start_vas)
            ):
                if len(thread_pinned) < 8:
                    thread_pinned.append(item)
                else:
                    rest.append(item)
            elif wanted_vas and cls._function_references_addresses(
                item, wanted_vas, image_base=image_base
            ):
                if len(data_pinned) < 16:
                    data_pinned.append(item)
                else:
                    rest.append(item)
            else:
                rest.append(item)
        signal_terms = (
            "createprocess",
            "shellexecute",
            "winexec",
            "loadlibrary",
            "getprocaddress",
            "virtualalloc",
            "virtualprotect",
            "writeprocessmemory",
            "createremotethread",
            "createthread",
            "openprocess",
            "updateprocthreadattribute",
            "internet",
            "winhttp",
            "wininet",
            "socket",
            "connect",
            "dns",
            "crypt",
            "decompress",
            "resource",
            "isdebuggerpresent",
            "virtualquery",
            "gettickcount",
        )

        def function_priority(item: dict[str, object], ordinal: int) -> tuple[int, ...]:
            calls = item.get("references_from", [])
            call_rows = calls if isinstance(calls, list) else []
            names = " ".join(
                str(row.get("target_name") or row.get("target_function") or "").lower()
                for row in call_rows
                if isinstance(row, dict)
            )
            signal_count = sum(term in names for term in signal_terms)
            return (
                signal_count,
                len(item.get("xrefs_to_entry", []) or []),
                len(call_rows),
                len(item.get("cfg_blocks", []) or []),
                len(item.get("mnemonics", []) or []),
                -ordinal,
            )

        ranked = sorted(
            enumerate(rest),
            key=lambda pair: function_priority(pair[1], pair[0]),
            reverse=True,
        )
        selected = list(pinned) + list(thread_pinned) + list(data_pinned)
        remaining = max(0, budget - len(selected))
        selected.extend(item for _, item in ranked[:remaining])
        return selected

    @classmethod
    def _is_process_creation_call_row(
        cls,
        row: Mapping[str, object] | None,
        thunks: Mapping[int, str] | None = None,
    ) -> bool:
        """True when a Ghidra call edge is CreateProcess/WinExec or an IAT thunk."""
        if not isinstance(row, Mapping):
            return False
        name = str(row.get("target_name") or row.get("target_function") or row.get("api") or "")
        folded = name.casefold()
        if any(token in folded for token in ("createprocess", "winexec", "shellexecute")):
            return True
        locators = (
            row.get("to"),
            row.get("target"),
            row.get("target_name"),
            row.get("target_function"),
        )
        thunk_vas = tuple(thunks or ())
        for locator in locators:
            parsed = parse_operand_address(locator)
            if parsed is None:
                parsed = cls._parse_static_address(locator)
            if parsed is None:
                continue
            if any(addresses_alias(parsed, va) for va in thunk_vas):
                return True
        return False

    @classmethod
    def _is_ppid_chain_call_row(
        cls,
        row: Mapping[str, object] | None,
        thunks: Mapping[int, str] | None = None,
    ) -> bool:
        """True when a Ghidra call edge is OpenProcess/UpdateProcThreadAttribute or its thunk."""
        if not isinstance(row, Mapping):
            return False
        name = str(row.get("target_name") or row.get("target_function") or row.get("api") or "")
        folded = name.casefold()
        if any(
            token in folded
            for token in (
                "openprocess",
                "updateprocthreadattribute",
                "initializeprocthreadattributelist",
            )
        ):
            return True
        locators = (
            row.get("to"),
            row.get("target"),
            row.get("target_name"),
            row.get("target_function"),
        )
        thunk_vas = tuple(thunks or ())
        for locator in locators:
            parsed = parse_operand_address(locator)
            if parsed is None:
                parsed = cls._parse_static_address(locator)
            if parsed is None:
                continue
            if any(addresses_alias(parsed, va) for va in thunk_vas):
                return True
        return False

    def materialize_recovered_bytes_child(self, session: Session, task: AnalysisTask, parent: Artifact, tool_run: ToolRun, payload: bytes, *, source: str, anchor: dict[str, object]) -> str | None:
        """Public behaviour entry point for `_materialize_recovered_bytes_child` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private method stays the implementation, and the facade delegates to it so a test that still
        replaces the private attribute keeps working.
        """
        return self._materialize_recovered_bytes_child(session, task, parent, tool_run, payload, source=source, anchor=anchor)


    def _materialize_recovered_bytes_child(
        self,
        session: Session,
        task: AnalysisTask,
        parent: Artifact,
        tool_run: ToolRun,
        payload: bytes,
        *,
        source: str,
        anchor: dict[str, object],
    ) -> str | None:
        """Create a child Artifact only from recovered bytes, never from MZ text."""
        if not payload or len(payload) < 16 or payload == b"MZ":
            return None
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
        logical_path = f"{parent.logical_path}!/recovered/{source}-{stored.sha256[:12]}.bin"
        existing = session.scalar(
            select(Artifact.id).where(
                Artifact.task_id == task.id, Artifact.logical_path == logical_path
            )
        )
        if existing:
            existing_id = str(existing)
            evidence_id = None
            for row in session.scalars(
                select(Evidence).where(
                    Evidence.task_id == task.id,
                    Evidence.artifact_id == parent.id,
                    Evidence.kind == "decoded_artifact",
                )
            ):
                value = row.value if isinstance(row.value, dict) else {}
                if str(value.get("child_artifact_id") or "") == existing_id:
                    evidence_id = row.id
                    break
            if evidence_id is not None:
                self._ensure_component_relation(
                    session,
                    task.id,
                    parent.id,
                    existing_id,
                    "EXTRACTED_FROM",
                    evidence_id=evidence_id,
                )
                self._ensure_component_relation(
                    session,
                    task.id,
                    parent.id,
                    existing_id,
                    "DROPS",
                    evidence_id=evidence_id,
                )
            return existing_id
        recovered_count = session.scalar(
            select(func.count())
            .select_from(Artifact)
            .where(
                Artifact.task_id == task.id,
                Artifact.parent_artifact_id == parent.id,
                Artifact.role == "DECODED_PAYLOAD",
            )
        )
        if int(recovered_count or 0) >= 4:
            return None
        detected_type = identify_format(payload, logical_path).detected_type
        child = Artifact(
            task_id=task.id,
            content_sha256=stored.sha256,
            parent_artifact_id=parent.id,
            logical_path=logical_path,
            role="DECODED_PAYLOAD",
            obligation=_child_obligation(detected_type),
            detected_type=detected_type,
            discovery=source,
            metadata_json={"recovered_from": parent.id, "execution": False, "source": source},
        )
        session.add(child)
        session.flush()
        evidence = Evidence(
            task_id=task.id,
            artifact_id=parent.id,
            tool_run_id=tool_run.id,
            module="decryption",
            kind="decoded_artifact",
            nature="STATIC_DERIVED" if source != "controlled_emulation" else "EMULATION_OBSERVED",
            value={
                "child_artifact_id": child.id,
                "sha256": stored.sha256,
                "size": len(payload),
                "source": source,
            },
            anchor={**anchor, "artifact_id": parent.id},
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
        self._analyze_recovered_child_static(session, task, child, tool_run, payload)
        self._record_unpacked_payload_facts(
            session,
            task,
            parent,
            child,
            tool_run,
            source=source,
            anchor=anchor,
        )
        self._record_parent_recovered_child_impact(
            session,
            task,
            parent,
            child,
            tool_run,
            evidence,
            source=source,
            anchor=anchor,
        )
        self._persist_pma_static_analysis_plan(session, task)
        return child.id

    def _ensure_component_relation(
        self,
        session: Session,
        task_id: str,
        source_artifact_id: str,
        target_artifact_id: str,
        relation_type: str,
        *,
        evidence_id: str | None,
    ) -> None:
        existing = session.scalar(
            select(Relation.id).where(
                Relation.task_id == task_id,
                Relation.source_artifact_id == source_artifact_id,
                Relation.target_artifact_id == target_artifact_id,
                Relation.relation_type == relation_type,
            )
        )
        if existing:
            return
        session.add(
            Relation(
                task_id=task_id,
                source_artifact_id=source_artifact_id,
                target_artifact_id=target_artifact_id,
                relation_type=relation_type,
                evidence_id=evidence_id,
                status="OBSERVED",
            )
        )

    def _record_unpacked_payload_facts(
        self,
        session: Session,
        task: AnalysisTask,
        parent: Artifact,
        child: Artifact,
        tool_run: ToolRun,
        *,
        source: str,
        anchor: dict[str, object],
    ) -> None:
        """Lift stub-IAT suppression only after a recovered child has PE/IAT facts."""
        existing = session.scalar(
            select(Evidence.id).where(
                Evidence.task_id == task.id,
                Evidence.artifact_id == parent.id,
                Evidence.kind == "unpacked_payload",
            )
        )
        if existing:
            return
        imports: list[str] = []
        oep = ""
        for row in session.scalars(
            select(Evidence).where(
                Evidence.task_id == task.id,
                Evidence.artifact_id == child.id,
                Evidence.kind.in_(("import_symbol", "pe_structure")),
            )
        ):
            value = row.value if isinstance(row.value, dict) else {}
            if row.kind == "import_symbol":
                name = str(value.get("name") or value.get("api") or value.get("symbol") or "").strip()
                if name and name not in imports:
                    imports.append(name)
                continue
            raw = value.get("entry_rva") or value.get("entry") or value.get("address_of_entry_point")
            if isinstance(raw, int) and raw >= 0:
                oep = hex(raw)
            else:
                text = str(raw or "").strip()
                if text:
                    oep = text if text.lower().startswith("0x") else text
            nested = value.get("imports") or ()
            if isinstance(nested, Mapping):
                nested = (nested,)
            if isinstance(nested, (list, tuple)):
                for module in nested:
                    if not isinstance(module, Mapping):
                        continue
                    functions = module.get("functions") or module.get("names") or ()
                    if not isinstance(functions, (list, tuple, set)):
                        continue
                    for item in functions:
                        name = str(
                            (item.get("name") or item.get("function"))
                            if isinstance(item, Mapping)
                            else item
                        ).strip()
                        if name and name not in imports:
                            imports.append(name)
        session.add(
            Evidence(
                task_id=task.id,
                artifact_id=parent.id,
                tool_run_id=tool_run.id,
                module="decryption",
                kind="unpacked_payload",
                nature="EMULATION_OBSERVED"
                if source == "controlled_emulation"
                else "STATIC_DERIVED",
                value={
                    "child_artifact_id": child.id,
                    "child_detected_type": child.detected_type,
                    "oep": oep,
                    "reconstructed_iat": imports[:64],
                    "source": source,
                },
                anchor={**anchor, "artifact_id": parent.id, "child_artifact_id": child.id},
            )
        )

    def _analyze_recovered_child_static(
        self,
        session: Session,
        task: AnalysisTask,
        child: Artifact,
        tool_run: ToolRun,
        payload: bytes,
    ) -> None:
        """Give a recovered child its own static facts; never execute it."""
        if not payload or len(payload) > 256 * 1024:
            return
        result = analyze_bytes(payload, child.logical_path)
        entry = PackageEntry(
            logical_path=child.logical_path,
            content=payload,
            parent_path=None,
            discovery=child.discovery,
            content_sha256=child.content_sha256,
            detected_type=child.detected_type,
        )
        self._record_static_result(session, task, child, tool_run, result, entry)

    def _record_parent_recovered_child_impact(
        self,
        session: Session,
        task: AnalysisTask,
        parent: Artifact,
        child: Artifact,
        tool_run: ToolRun,
        decoded_evidence: Evidence,
        *,
        source: str,
        anchor: dict[str, object],
    ) -> None:
        """Keep recovered-child static facts visible on the parent behavior graph."""
        for row in session.scalars(
            select(Evidence).where(
                Evidence.task_id == task.id,
                Evidence.artifact_id == parent.id,
                Evidence.kind == "mechanism_chain",
            )
        ):
            value = row.value if isinstance(row.value, dict) else {}
            if value.get("child_artifact_id") == child.id:
                return
        child_rows = list(
            session.scalars(
                select(Evidence).where(
                    Evidence.task_id == task.id, Evidence.artifact_id == child.id
                )
            )
        )
        source_ids = [decoded_evidence.id, *[row.id for row in child_rows[:16]]]
        source_ids = [item for item in source_ids if str(item).strip()][:24]
        if not source_ids:
            return
        fact_kinds = list(dict.fromkeys(row.kind for row in child_rows if row.kind))[:16]
        normalized_value = {
            "chain_type": "recovered_payload",
            "categories": ["multi_stage"],
            "steps": [
                {"name": source, "operation": source, "category": "multi_stage"},
                {
                    "name": child.detected_type or "decoded_payload",
                    "operation": "static_reentry",
                    "category": "multi_stage",
                    "artifact_id": child.id,
                },
            ],
            "child_artifact_id": child.id,
            "child_sha256": child.content_sha256,
            "child_detected_type": child.detected_type,
            "child_fact_kinds": fact_kinds,
            "source_evidence_ids": source_ids,
        }
        input_digest = hashlib.sha256(
            json.dumps(
                source_ids,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        output_digest = hashlib.sha256(
            json.dumps(normalized_value, ensure_ascii=True, sort_keys=True, default=str).encode(
                "utf-8"
            )
        ).hexdigest()
        session.add(
            Evidence(
                task_id=task.id,
                artifact_id=parent.id,
                tool_run_id=tool_run.id,
                module="decryption",
                kind="mechanism_chain",
                nature="STATIC_DERIVED",
                value={
                    **normalized_value,
                    "derivation": {
                        "evaluator": "recovered-child-parent-impact-v1",
                        "input_evidence_ids": source_ids,
                        "input_digest": input_digest,
                        "output_digest": output_digest,
                        "exact": True,
                    },
                },
                anchor={**anchor, "artifact_id": parent.id, "child_artifact_id": child.id},
            )
        )

    def _emit_controlled_emulation(
        self,
        emit: Any,
        artifact: Artifact,
        content: bytes,
        *,
        session: Session | None = None,
        task: AnalysisTask | None = None,
        tool_run: ToolRun | None = None,
        pe_summary: dict[str, object] | None = None,
        functions: list[dict[str, object]] | None = None,
        traces: list[dict[str, object]] | None = None,
    ) -> None:
        """Grant content-store bytes to a policy-authorized emulator.

        The original sample path is never passed.  Default static-only
        policy records an honest DISABLED_BY_POLICY result for unique OS
        threads.  Docker isolation defers execution to the Temporal worker.
        SUCCEEDED and worker FAILED/UNMAPPED results are ``EMULATION_OBSERVED``.
        """
        policy = simulation_policy_from_settings(self.settings)
        thread_starts = unique_thread_function_starts(functions)
        if not policy.enabled:
            if thread_starts:
                emit(
                    "simulation_result",
                    {
                        "status": "DISABLED_BY_POLICY",
                        "simulator": "unicorn",
                        "stop_reason": "DISABLED_BY_POLICY",
                        "limitations": [
                            "unique OS thread start routines are eligible for bounded Unicorn once "
                            "SIMULATION_PROFILE authorizes granted function bytes"
                        ],
                        "thread_count": len(thread_starts),
                    },
                    {
                        "type": "unique_thread_emulation",
                        "function_entry": str(
                            thread_starts[0].get("entry") or thread_starts[0].get("entry_rva") or ""
                        ),
                    },
                    nature="STATIC_INFERRED",
                )
            return
        if worker_defers_simulation(policy):
            # Rootfs and simulator availability are evaluated by the trusted
            # emu-worker.  The API records a deferred boundary, never a
            # host-side ROOTFS_REQUIRED claim based on an inaccessible path.
            deferred = _qiling_worker_deferred_observation()
            emit("simulation_result", deferred, dict(deferred["anchor"]), nature="STATIC_INFERRED")
            return
        if not content:
            return
        runner = default_simulation_runner(
            policy,
            # Was hardcoded `True`, safe only because of the early return above (~line 18377). The value is
            # now computed where it is used, so moving that guard cannot silently make the host run bytes.
            execute_in_process=may_execute_in_process(policy, environment=self.settings.environment),
        )
        windows = controlled_emulation_windows(
            content,
            pe_summary,
            functions,
            traces,
            allow_speakeasy=False,
            max_windows=4,
            snippet_length=min(512, policy.max_input_bytes),
            max_pe_bytes=policy.max_input_bytes,
        )
        if not windows:
            qiling_row = (
                qiling_unavailable_observation(policy)
                if not worker_defers_simulation(policy)
                else None
            )
            if qiling_row is not None:
                emit(
                    "simulation_result",
                    qiling_row,
                    dict(qiling_row.get("anchor") or {"type": "qiling_policy"}),
                    nature=evidence_nature_for_simulation_status(
                        qiling_row.get("status"),
                        stop_reason=qiling_row.get("stop_reason"),
                    ),
                )
            return
        for window in windows[:4]:
            result = runner.run(request_for_granted_window(policy, window))
            anchor = dict(window.get("anchor") or {"type": "controlled_emulation"})
            payload = result.as_dict()
            if result.status == "SUCCEEDED" and result.output_bytes:
                payload["output_hex"] = result.output_bytes.hex()
            emit(
                "simulation_result",
                payload,
                anchor,
                nature=evidence_nature_for_simulation_status(
                    result.status, stop_reason=result.stop_reason
                ),
            )
            recovered = result.output_bytes if result.status == "SUCCEEDED" else b""
            granted = window.get("input_bytes")
            granted_bytes = granted if isinstance(granted, (bytes, bytearray)) else b""
            if (
                recovered
                and recovered != granted_bytes
                and session is not None
                and task is not None
                and tool_run is not None
            ):
                self._materialize_recovered_bytes_child(
                    session,
                    task,
                    artifact,
                    tool_run,
                    recovered,
                    source="controlled_emulation",
                    anchor=anchor,
                )
        qiling_row = (
            qiling_unavailable_observation(policy)
            if not worker_defers_simulation(policy)
            else None
        )
        if qiling_row is not None:
            emit(
                "simulation_result",
                qiling_row,
                dict(qiling_row.get("anchor") or {"type": "qiling_policy"}),
                nature=evidence_nature_for_simulation_status(
                    qiling_row.get("status"),
                    stop_reason=qiling_row.get("stop_reason"),
                ),
            )

    def _collect_emulation_inputs(
        self,
        session: Session,
        task_id: str,
        artifact_id: str,
    ) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        rows = list(
            session.scalars(
                select(Evidence).where(
                    Evidence.task_id == task_id,
                    Evidence.artifact_id == artifact_id,
                    Evidence.kind.in_(
                        (
                            "function",
                            "function_context",
                            "api_argument_trace",
                            "function_call",
                            "resolved_api",
                        )
                    ),
                )
            )
        )
        functions: list[dict[str, object]] = []
        traces: list[dict[str, object]] = []
        for row in rows:
            value = dict(row.value) if isinstance(row.value, dict) else {}
            if row.kind in {"function", "function_context", "function_call"}:
                merged = dict(value)
                anchor = row.anchor if isinstance(row.anchor, dict) else {}
                merged.setdefault("entry", anchor.get("entry") or value.get("entry"))
                merged.setdefault("entry_rva", anchor.get("rva") or value.get("entry_rva"))
                if row.kind == "function_call":
                    api_name = value.get("target_name") or value.get("name")
                    if api_name:
                        merged.setdefault("references_from", [{"target_name": api_name}])
                functions.append(merged)
            elif row.kind in {"api_argument_trace", "resolved_api"}:
                traces.append({"value": value})
        deferred_rows = session.scalars(
            select(Evidence).where(
                Evidence.task_id == task_id,
                Evidence.artifact_id == artifact_id,
                Evidence.kind == "simulation_result",
            )
        )
        seen_entries = {
            self._emulation_entry_key(item)
            for item in functions
            if self._emulation_entry_key(item)
        }
        for row in deferred_rows:
            value = dict(row.value) if isinstance(row.value, dict) else {}
            entry = self._emulation_entry_key(value)
            if not entry or entry in seen_entries:
                continue
            if str(value.get("status") or "").upper() not in PLACEHOLDER_STATUSES:
                continue
            functions.append(
                {
                    "entry": entry,
                    "entry_rva": value.get("entry_rva"),
                    "planned_emulation": True,
                }
            )
            seen_entries.add(entry)
        action_rows = session.scalars(
            select(InvestigationActionRecord).where(
                InvestigationActionRecord.task_id == task_id,
                InvestigationActionRecord.artifact_id == artifact_id,
                InvestigationActionRecord.action_type == ActionType.CONTROLLED_EMULATE.value,
            )
        )
        for row in action_rows:
            selector = row.target_selector if isinstance(row.target_selector, dict) else {}
            entry = self._emulation_entry_key(selector)
            if not entry or entry in seen_entries:
                continue
            functions.append(
                {
                    "entry": selector.get("function_entry")
                    or selector.get("entry")
                    or selector.get("target")
                    or entry,
                    "entry_rva": selector.get("entry_rva") or selector.get("rva"),
                    "planned_emulation": True,
                }
            )
            seen_entries.add(entry)
        return functions, traces

    _EMULATION_PLACEHOLDER_STATUSES = PLACEHOLDER_STATUSES

    @classmethod
    def _emulation_entry_key(cls, value: Mapping[str, object] | str | None) -> str:
        return emulation_entry_key(value)

    @classmethod
    def simulation_covers_request(cls, value: Mapping[str, object], requested_entry: str, *, simulator: str | None = None) -> bool:
        """Public behaviour entry point for `_simulation_covers_request` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private classmethod stays the implementation and the facade delegates to it, so a test that replaces
        the private attribute on the class keeps working.
        """
        return cls._simulation_covers_request(value, requested_entry, simulator=simulator)


    @classmethod
    def _simulation_covers_request(
        cls,
        value: Mapping[str, object],
        requested_entry: str,
        *,
        simulator: str | None = None,
    ) -> bool:
        return simulation_covers_request(
            value, requested_entry, simulator=simulator
        )

    @classmethod
    def matching_simulation_results(cls, rows: Iterable[Any], selector: Mapping[str, object], *, require_success: bool = True) -> tuple[Any, ...]:
        """Public behaviour entry point for `_matching_simulation_results` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private classmethod stays the implementation and the facade delegates to it.
        """
        return cls._matching_simulation_results(rows, selector, require_success=require_success)


    @classmethod
    def _matching_simulation_results(
        cls,
        rows: Iterable[Any],
        selector: Mapping[str, object],
        *,
        require_success: bool = True,
    ) -> tuple[Any, ...]:
        return matching_simulation_results(
            rows, selector, require_success=require_success
        )

    def run_simulation_window(self, policy: SimulationExecutionPolicy, window: Mapping[str, object]) -> SimulationWindowOutcome:
        """Public behaviour entry point for `_run_simulation_window` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private method stays the implementation, and the facade delegates to it so a test that still
        replaces the private attribute keeps working.
        """
        return self._run_simulation_window(policy, window)


    def _run_simulation_window(
        self, policy: SimulationExecutionPolicy, window: Mapping[str, object]
    ) -> SimulationWindowOutcome:
        """Run ONE granted window in the isolated runner the HOST owns (P3.3e's execution seam).

        RELOCATED VERBATIM from `_derive_investigation_observations`, where the runner construction and the
        `runner.run(...)` call sat inline: the moved derivation must not import `simulation_adapters` (plan section 3.2
        admits emulation INTERFACES into `investigation/`, and that module is an implementation), so the two lines that
        touch it live here, behind the port, and the moved body calls this instead.

        MEASURED BEHAVIOUR EQUIVALENCE for building the runner PER WINDOW instead of once per action: every `self.<x>`
        store in `IsolatedSimulationRunner` is in `__init__` (`adapters`, `policy`, `environment`,
        `execute_in_process`), `run` mutates nothing on it and the module holds no mutable global state - so two runners
        built from the same policy are interchangeable. `.scratch/p33e-seam-verify.py` asserts the relocated fragments
        appear here byte-for-byte and that the site they left only calls this member.
        """
        runner = default_simulation_runner(
            policy,
            # One definition for all three sites (`may_execute_in_process`). Previously this site
            # computed the condition while two others hardcoded `True`.
            execute_in_process=may_execute_in_process(
                policy, environment=self.settings.environment
            ),
        )
        return runner.run(request_for_granted_window(policy, window))

    def _qiling_unavailable_observation(
        self, policy: SimulationExecutionPolicy
    ) -> dict[str, object] | None:
        """The Qiling policy probe, kept on the host because it calls into `simulation_adapters`.

        Relocated verbatim from the same seam (one call site, `qiling_unavailable_observation(policy)`). The moved
        derivation needs the row but may not import the module that produces it.
        """
        return qiling_unavailable_observation(policy)

    @classmethod
    def _has_uncovered_emulation_entry(
        cls,
        rows: Iterable[Any],
        simulator: str,
        planned_entries: Iterable[str],
    ) -> bool:
        return has_uncovered_emulation_entry(rows, simulator, planned_entries)

    @classmethod
    def _has_real_simulation_result(cls, rows: Iterable[Any], simulator: str) -> bool:
        return has_real_simulation_result(rows, simulator)

    def run_post_static_emulation(self, task_id: str) -> list[str]:
        """Public behaviour entry point for `_run_post_static_emulation` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name, so a test asserted against an
        implementation detail rather than against a behaviour the service offers. Callers outside the class use this
        name; the private method stays the implementation, and its ONE deliberate remaining caller is production code
        that a test replaces by attribute (`tests/test_analysis_task_orchestration.py`), which is why the private name
        is not removed here.
        """
        return self._run_post_static_emulation(task_id)


    def _run_post_static_emulation(self, task_id: str) -> list[str]:
        """After static recovery, emulate granted start-routine windows in isolation."""
        policy = simulation_policy_from_settings(self.settings)
        if not policy.enabled:
            return []
        limitations: list[str] = []
        allowed = {str(item).casefold() for item in policy.allowed_simulators}
        with self.database.session_factory() as session:
            artifacts = list(
                session.scalars(
                    select(Artifact).where(
                        Artifact.task_id == task_id,
                        Artifact.detected_type.in_(("pe", "elf")),
                    )
                )
            )
            entries: list[tuple[str, PackageEntry]] = []
            for artifact in artifacts:
                existing = list(
                    session.scalars(
                        select(Evidence).where(
                            Evidence.task_id == task_id,
                            Evidence.artifact_id == artifact.id,
                            Evidence.kind == "simulation_result",
                        )
                    )
                )
                planned_entries: list[str] = []
                for row in existing:
                    value = row.value if isinstance(getattr(row, "value", None), dict) else {}
                    entry = self._emulation_entry_key(value)
                    if (
                        entry
                        and str(value.get("status") or "").upper()
                        in PLACEHOLDER_STATUSES
                    ):
                        planned_entries.append(entry)
                action_rows = session.scalars(
                    select(InvestigationActionRecord).where(
                        InvestigationActionRecord.task_id == task_id,
                        InvestigationActionRecord.artifact_id == artifact.id,
                        InvestigationActionRecord.action_type
                        == ActionType.CONTROLLED_EMULATE.value,
                    )
                )
                for row in action_rows:
                    selector = (
                        row.target_selector if isinstance(row.target_selector, dict) else {}
                    )
                    entry = self._emulation_entry_key(selector)
                    if entry:
                        planned_entries.append(entry)
                still_needed = post_static_emulation_needed(
                    allowed_simulators=allowed,
                    artifact_type=str(artifact.detected_type),
                    results=existing,
                    planned_entries=planned_entries,
                )
                if not still_needed:
                    continue
                blob = session.get(ContentBlob, artifact.content_sha256)
                if blob is None or blob.disposed_at is not None:
                    continue
                try:
                    content = self.content_store.read(blob.storage_key)
                except (OSError, ValueError):
                    continue
                entries.append(
                    (
                        artifact.id,
                        PackageEntry(
                            logical_path=artifact.logical_path,
                            content=content,
                            parent_path=None,
                            discovery="post_static_emulation",
                        ),
                    )
                )
        for artifact_id, entry in entries:
            limitations.extend(
                self._run_controlled_emulator(
                    task_id,
                    artifact_id,
                    entry,
                    scheduler="post_static_emulation",
                )
            )
        return limitations

    def run_controlled_emulator(self, task_id: str, artifact_id: str, entry: PackageEntry, *, planned_tool_names: tuple[str, ...] = (), scheduler: str | None = None, allow_speakeasy: bool | None = None) -> list[str]:
        """Public behaviour entry point for `_run_controlled_emulator` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name, so a test asserted against an
        implementation detail rather than against a behaviour the service offers. Callers outside the class use this
        name; the private method stays the implementation, and its ONE deliberate remaining caller is production code
        that a test replaces by attribute (`tests/test_analysis_task_orchestration.py`), which is why the private name
        is not removed here.
        """
        return self._run_controlled_emulator(task_id, artifact_id, entry, planned_tool_names=planned_tool_names, scheduler=scheduler, allow_speakeasy=allow_speakeasy)


    def _run_controlled_emulator(
        self,
        task_id: str,
        artifact_id: str,
        entry: PackageEntry,
        *,
        planned_tool_names: tuple[str, ...] = (),
        scheduler: str | None = None,
        allow_speakeasy: bool | None = None,
    ) -> list[str]:
        policy = simulation_policy_from_settings(self.settings)
        if not policy.enabled:
            return []
        started_at = utcnow()
        tool_run_id = new_id()
        with self.database.session_factory() as session:
            task = session.get(AnalysisTask, task_id)
            artifact = session.get(Artifact, artifact_id)
            if task is None or artifact is None:
                raise LookupError(artifact_id)
            if task.lifecycle == TaskLifecycle.CANCELLED.value:
                return []
            tool_policy = self.policy.require_tool("controlled-emulator")
            functions, traces = self._collect_emulation_inputs(session, task_id, artifact_id)
            case_id = task.case_id
            trace_id = task.trace_id
            blob = session.get(ContentBlob, artifact.content_sha256)
            storage_key = blob.storage_key if blob is not None else ""
            content_sha256 = artifact.content_sha256
            logical_path = artifact.logical_path
        worker_owned = self.settings.tool_execution_mode == "temporal"
        speakeasy = (
            bool(allow_speakeasy)
            if allow_speakeasy is not None
            else "speakeasy" in policy.allowed_simulators
        ) and worker_owned
        sample = entry.content or b""
        if not sample and storage_key:
            try:
                sample = self.content_store.read(storage_key)
            except (OSError, TypeError, ValueError):
                sample = b""
        pe_summary: dict[str, object] = {}
        if sample:
            try:
                pe_raw = analyze_bytes(sample, logical_path).summary.get("pe")
                if isinstance(pe_raw, dict):
                    pe_summary = pe_raw
            except (TypeError, ValueError, KeyError, AttributeError):
                pe_summary = {}
        persist_how_entries = tuple(
            item.get("entry") or item.get("entry_rva") or item.get("target")
            for item in functions
            if isinstance(item, dict) and item.get("planned_emulation")
        )
        granted_windows = unicorn_granted_windows_for_worker(
            controlled_emulation_windows(
                sample,
                pe_summary,
                functions,
                traces,
                # Plan the grant WITH the operator's Speakeasy decision.  Building this plan with
                # `allow_speakeasy=False` was the defect that made the full-PE emulator
                # unreachable: the full-PE window was never in the plan, and the request below
                # then resolved `allow_speakeasy` to False for EVERY run.
                #
                # CORRECTED (plan T1a): this comment used to claim that
                # `unicorn_granted_windows_for_worker` "keeps that window alongside the Unicorn ones, so
                # asking for it does not displace the snippet windows". It does not - that function's own
                # docstring says "Skip Speakeasy full-PE" and it `continue`s on any non-Unicorn window.
                # What actually makes the full-PE window reachable is on the WORKER side: the grant branch
                # now builds the plan itself and places the Speakeasy window ahead of the snippets
                # (`tool_execution._execute_controlled_emulator`). Passing `allow_speakeasy` here is what
                # authorises it, and the grant list deliberately stays Unicorn-only.
                allow_speakeasy=speakeasy,
                allow_qiling=False,
                max_windows=4,
                snippet_length=min(512, policy.max_input_bytes),
                max_pe_bytes=policy.max_input_bytes,
                preferred_entries=persist_how_entries,
            )
            if sample
            else (),
            max_windows=4,
        )
        parameters = {
            "functions": functions[:64],
            "traces": traces[:32],
            # The operator's configured simulator decision, not a consequence of having produced
            # any Unicorn window.  Every real PE yields at least a PE-entry Unicorn window, so the
            # previous `False if granted_windows else speakeasy` was False in every single run -
            # measured on the real Resume bytes, the snippet emulator stops after 3 instructions
            # with UNMAPPED_DATA (no loader, no IAT), while the full-PE emulator reaches the module
            # entry and executes real code before stopping on an unimplemented CRT import.
            "allow_speakeasy": speakeasy,
            "scheduler": scheduler or "deterministic_baseline",
            "planned_tools": list(planned_tool_names),
        }
        if granted_windows:
            parameters["granted_windows"] = list(granted_windows)
        if self.settings.tool_execution_mode == "temporal":
            request = ToolRunRequest(
                case_id=case_id,
                task_id=task_id,
                trace_id=trace_id,
                artifact_id=artifact_id,
                tool_run_id=tool_run_id,
                tool_name="controlled-emulator",
                tool_version="0.1.0",
                content_sha256=content_sha256,
                storage_key=storage_key,
                logical_path=logical_path,
                parameters=parameters,
                max_cpu_seconds=min(tool_policy.max_cpu_seconds, 60),
                max_memory_mb=tool_policy.max_memory_mb,
                task_queue=self.settings.task_queue_for("controlled-emulator"),
                sample_execution=False,
                network_access=False,
            )
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
            results: list[dict[str, object]] = []
            # Why the emulator's output could not be read, when it could not be. MEASURED (adversarial defect
            # audit): the `except` below swallowed the failure and left `results = []`, which is
            # INDISTINGUISHABLE from "the emulator genuinely found no window". The empty list then drove a
            # fabricated row asserting `NO_GRANTED_WINDOW` and blaming the sample's static recovery
            # ("...isolated emulation was still attempted"), while the truth was that the emulation HAD run and
            # its output was unreadable - reachable whenever the content store is unavailable (minio reported
            # `InsufficientWriteQuorum` during this session). Absence was converted into a claim about the
            # sample.
            output_read_error: str | None = None
            if response.output_storage_key:
                try:
                    payload = json.loads(self.content_store.read(response.output_storage_key))
                    if isinstance(payload, dict) and payload.get("kind") == "emulation":
                        raw_results = payload.get("results")
                        if isinstance(raw_results, list):
                            results = [item for item in raw_results if isinstance(item, dict)]
                except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    output_read_error = f"{type(exc).__name__}: {exc}"[:200]
                    results = []
            status = response.status
            error = response.error
            execution_metadata = {
                **dict(response.worker_metadata or {}),
                "executor": "temporal",
                "tool_run_id": tool_run_id,
            }
        elif policy.allow_local_process and self.settings.environment.lower() in {
            "test",
            "demo",
            "development",
        }:
            # Defined on this path too: the fallback-row builder below is SHARED by both branches and reads it.
            # MEASURED: omitting it raised NameError at the shared `output={...}` and turned the 6 baseline
            # failures into 8 (two in test_controlled_emulation.py) - caught by the baseline comparison, not by
            # the tests that exercise this path.
            output_read_error: str | None = None
            runner = default_simulation_runner(
                policy,
                # Was hardcoded `True`, safe only because of the `elif` above (~line 18833) which already
                # requires a non-production environment. Stated here instead of relied upon there.
                execute_in_process=may_execute_in_process(
                    policy, environment=self.settings.environment
                ),
            )
            pe_summary: dict[str, object] = {}
            try:
                pe_raw = analyze_bytes(entry.content, entry.logical_path).summary.get("pe")
                if isinstance(pe_raw, dict):
                    pe_summary = pe_raw
            except (TypeError, ValueError):
                pe_summary = {}
            persist_how_entries = tuple(
                item.get("entry") or item.get("entry_rva") or item.get("target")
                for item in functions
                if isinstance(item, dict) and item.get("planned_emulation")
            )
            windows = controlled_emulation_windows(
                entry.content,
                pe_summary,
                functions,
                traces,
                allow_speakeasy=speakeasy,
                allow_qiling="qiling" in {str(item).casefold() for item in policy.allowed_simulators},
                max_windows=4,
                snippet_length=min(512, policy.max_input_bytes),
                max_pe_bytes=policy.max_input_bytes,
                preferred_entries=persist_how_entries,
            )
            results = []
            status = "SUCCEEDED"
            error = None
            for window in windows[:4]:
                result = runner.run(request_for_granted_window(policy, window))
                payload = result.as_dict()
                payload["anchor"] = dict(window.get("anchor") or {})
                if result.status == "SUCCEEDED" and result.output_bytes:
                    payload["output_hex"] = result.output_bytes.hex()
                    payload["_output_bytes"] = result.output_bytes
                    payload["_granted_bytes"] = window.get("input_bytes")
                results.append(payload)
                if result.status != "SUCCEEDED" and status == "SUCCEEDED":
                    status = result.status
                    error = result.stop_reason
            qiling_row = (
                qiling_unavailable_observation(policy)
                if not worker_defers_simulation(policy)
                else None
            )
            if qiling_row is not None and not any(
                str(item.get("simulator") or "").casefold() == "qiling" for item in results
            ):
                results.append(qiling_row)
            execution_metadata = {
                "tool_run_id": tool_run_id,
                "executor": "in_process",
                "execution_mode": self.settings.tool_execution_mode,
            }
        else:
            results = [
                {
                    "status": "WORKER_REQUIRED",
                    "simulator": "unicorn",
                    "stop_reason": "WORKER_REQUIRED",
                    "limitations": [
                        "docker-isolated emulation must run in the dedicated Temporal worker"
                    ],
                    "anchor": {"type": "unique_thread_emulation"},
                }
            ]
            status = "FAILED"
            error = "WORKER_REQUIRED"
            execution_metadata = {
                "tool_run_id": tool_run_id,
                "executor": "api_process_denied",
            }
        return self._persist_emulation_result(
            task_id=task_id,
            artifact_id=artifact_id,
            tool_run_id=tool_run_id,
            status=status,
            error=error,
            results=results,
            output_read_error=output_read_error,
            parameters=parameters,
            execution_metadata=execution_metadata,
            started_at=started_at,
            scheduler=scheduler,
        )

    def _persist_emulation_result(
        self,
        *,
        task_id: str,
        artifact_id: str,
        tool_run_id: str,
        status: str,
        error: str | None,
        results: list[dict[str, object]],
        output_read_error: str | None = None,
        parameters: dict[str, object],
        execution_metadata: dict[str, object],
        started_at: datetime,
        scheduler: str | None,
    ) -> list[str]:
        limitations: list[str] = []
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
                tool_name="controlled-emulator",
                tool_version="0.1.0",
                status=status if status in {"SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT"} else "FAILED",
                parameters=parameters,
                environment={
                    "sample_execution": False,
                    "network_access": False,
                    "executor": execution_metadata.get("executor"),
                    "isolation_boundary": "granted_bytes_no_host_loader",
                },
                output={
                    "result_count": len(results),
                    "error": error,
                    # Persisted so the DB distinguishes "the emulator produced nothing" from "we could not read
                    # what it produced"; without it both look like `result_count: 0`.
                    "output_read_error": output_read_error,
                },
                started_at=started_at,
                finished_at=utcnow(),
            )
            # The fallback row must say what actually happened. A run whose OUTPUT could not be read did not fail
            # because of the sample's static recovery, and must not be published as though it had: the emulation
            # ran, and the honest record is that its result is unavailable.
            for payload in results or [self._emulation_fallback_payload(output_read_error)]:
                anchor = dict(payload.get("anchor") or {"type": "controlled_emulation"})
                stored = {
                    key: value
                    for key, value in payload.items()
                    if key not in {"_output_bytes", "_granted_bytes"}
                }
                evidence = Evidence(
                    id=new_id(),
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=tool_run.id,
                    module="static_triage",
                    kind="simulation_result",
                    nature=evidence_nature_for_simulation_status(
                        stored.get("status"), stop_reason=stored.get("stop_reason")
                    ),
                    value=stored,
                    anchor={
                        **anchor,
                        "artifact_id": artifact.id,
                        "content_sha256": artifact.content_sha256,
                        "logical_path": artifact.logical_path,
                    },
                )
                session.add(evidence)
                recovered = payload.get("_output_bytes")
                granted = payload.get("_granted_bytes")
                hex_text = str(payload.get("output_hex") or "")
                if not isinstance(recovered, (bytes, bytearray)) and hex_text:
                    try:
                        recovered = bytes.fromhex(hex_text)
                    except ValueError:
                        recovered = b""
                if (
                    isinstance(recovered, (bytes, bytearray))
                    and recovered
                    and recovered != granted
                    and stored.get("status") == "SUCCEEDED"
                ):
                    self._materialize_recovered_bytes_child(
                        session,
                        task,
                        artifact,
                        tool_run,
                        bytes(recovered),
                        source="controlled_emulation",
                        anchor=anchor,
                    )
            session.flush()
            real_simulators = {
                str(payload.get("simulator") or "").casefold()
                for payload in results
                if isinstance(payload, dict)
                and str(payload.get("status") or "").upper()
                not in PLACEHOLDER_STATUSES
            }
            if real_simulators:
                for row in session.scalars(
                    select(Evidence).where(
                        Evidence.task_id == task.id,
                        Evidence.artifact_id == artifact.id,
                        Evidence.kind == "simulation_result",
                    )
                ):
                    value = dict(row.value or {}) if isinstance(row.value, dict) else {}
                    sim = str(value.get("simulator") or "").casefold()
                    if sim not in real_simulators:
                        continue
                    if str(value.get("status") or "").upper() not in {
                        "DEFERRED_TO_WORKER",
                        "WORKER_REQUIRED",
                    }:
                        continue
                    value["status"] = "SUPERSEDED_BY_WORKER"
                    value["superseded"] = True
                    value["stop_reason"] = "SUPERSEDED_BY_WORKER"
                    row.value = value
            if status != "SUCCEEDED":
                limitations.append(
                    error or "controlled-emulator did not succeed"
                )
        return limitations

    @classmethod
    def _ghidra_ranked_symbol_emissions(
        cls,
        output: Mapping[str, object],
    ) -> list[tuple[str, dict[str, object], dict[str, object]]]:
        return PersistHow.ranked_symbol_emissions(output)

    @classmethod
    def _emit_ranked_symbols_then_stage(cls, *args, **kwargs):
        return PersistHow.emit_ranked_symbols_then_stage(*args, **kwargs)

    def record_ghidra_evidence(self, session: Session, task: AnalysisTask, artifact: Artifact, tool_run: ToolRun, output: dict[str, object]) -> None:
        """Public behaviour entry point for `_record_ghidra_evidence` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name, so a test asserted against an
        implementation detail rather than against a behaviour the service offers. Callers outside the class use this
        name; the private method stays the implementation, and its ONE deliberate remaining caller is production code
        that a test replaces by attribute (`tests/test_analysis_task_orchestration.py`), which is why the private name
        is not removed here.
        """
        return self._record_ghidra_evidence(session, task, artifact, tool_run, output)


    def _record_ghidra_evidence(
        self,
        session: Session,
        task: AnalysisTask,
        artifact: Artifact,
        tool_run: ToolRun,
        output: dict[str, object],
    ) -> None:
        # EvidenceSearchKey is a rebuildable projection. Deferring its
        # fan-out during Ghidra post-processing keeps intermediate flushes
        # focused on immutable Evidence and Claims; selectors are materialized
        # once after the complete bounded evidence batch is staged.
        session.info["defer_evidence_search_keys"] = True
        emitted_evidence: list[Evidence] = []
        # Claims are staged until the complete immutable Evidence batch has
        # been flushed.  This preserves FK ordering while avoiding a flush per
        # function, per mechanism, or per call-graph chain.
        pending_claims: list[tuple[Claim, tuple[str, ...], bool, dict[str, object]]] = []
        pending_cross_claims: list[tuple[Claim, str, tuple[str, ...]]] = []

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
            static_phase_simulation_evidence(
                simulation_policy_from_settings(self.settings),
                # Under Docker isolation the emulators run in the isolated worker, where unicorn
                # and speakeasy ARE installed. Probing them in this process reported every one as
                # `installed: false, allowed: false` and the phase as UNAVAILABLE, so the report
                # told the analyst no emulator exists while the worker was running them.
                worker_owned=self.settings.tool_execution_mode == "temporal",
            ),
            {"type": "capability_probe", "phase": self.settings.simulation_profile},
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
                # Evidence and claims use preallocated immutable identifiers.
                # SQLAlchemy orders the dependent ClaimEvidence insert after
                # both parent rows during the unit-of-work flush, so avoid a
                # per-claim flush here.  On real Ghidra runs this path can be
                # reached hundreds of times and each flush would rescan the
                # entire pending Evidence batch.
                claim = Claim(
                    id=new_id(),
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
                pending_claims.append(
                    (
                        claim,
                        tuple(validation.evidence_ids),
                        False,
                        {
                            "module": claim.module,
                            "claim_kind": "ghidra_mechanism_chain",
                            "confidence": claim.confidence,
                            **self.static_agent.metadata,
                        },
                    )
                )

        functions = output.get("functions", [])
        function_candidates: list[FunctionEvidenceCandidate] = []
        if isinstance(functions, list):
            all_function_rows = [item for item in functions if isinstance(item, dict)]
            artifact_content = b""
            artifact_blob = session.get(ContentBlob, artifact.content_sha256)
            if artifact_blob is not None:
                try:
                    artifact_content = self.content_store.read(artifact_blob.storage_key)
                except (OSError, ValueError):
                    artifact_content = b""
            deterministic_pe: dict[str, object] = {}
            if artifact_content:
                try:
                    parsed_pe = analyze_bytes(artifact_content, artifact.logical_path).summary.get("pe")
                    if isinstance(parsed_pe, dict):
                        deterministic_pe = parsed_pe
                except (TypeError, ValueError):
                    deterministic_pe = {}
            xor_hits: tuple[dict[str, object], ...] = ()
            if artifact_content and deterministic_pe:
                xor_hits = tuple(
                    item
                    for item in recover_static_xor_configs(artifact_content, deterministic_pe)
                    if isinstance(item, dict) and item.get("virtual_address") not in (None, "")
                )
            xor_vas = tuple(item.get("virtual_address") for item in xor_hits)
            raw_image_base = deterministic_pe.get("image_base")
            image_base = (
                raw_image_base
                if isinstance(raw_image_base, int) and raw_image_base >= 0
                else (self._parse_static_address(raw_image_base) or 0)
            )
            api_thunks = import_api_thunks(all_function_rows)
            process_thunks = {
                key: value
                for key, value in api_thunks.items()
                if str(value).casefold() in {
                    "createprocessw",
                    "createprocessa",
                    "winexec",
                    "shellexecutew",
                    "shellexecutea",
                }
            }
            config_xrefs = self._collect_recovered_config_xrefs(
                all_function_rows,
                xor_vas,
                image_base=image_base,
            )
            config_links = self._recovered_config_consumer_links(
                xor_hits,
                config_xrefs,
                artifact_id=artifact.id,
                image_base=image_base,
            )
            consumer_by_site = {
                (
                    str(item["consumer"].get("from") or ""),
                    str(item["consumer"].get("to") or ""),
                ): item
                for item in config_links
            }
            emitted_consumers: dict[tuple[str, str], Evidence] = {}
            for xref in config_xrefs:
                site = (str(xref.get("from") or ""), str(xref.get("to") or ""))
                linked = consumer_by_site.get(site)
                payload = dict(xref)
                if linked is not None:
                    payload["input_buffer"] = linked["output_buffer"]
                consumer_row = emit(
                    "data_reference",
                    payload,
                    {
                        "type": "decoded_config_xref",
                        "entry": xref.get("entry"),
                        "function": xref.get("function"),
                    },
                )
                emit(
                    "xref",
                    {**payload, "direction": "to_decoded_buffer"},
                    {
                        "type": "decoded_config_xref",
                        "entry": xref.get("entry"),
                        "function": xref.get("function"),
                    },
                )
                if linked is not None and site not in emitted_consumers:
                    emitted_consumers[site] = consumer_row
            for link in config_links:
                consumer = link["consumer"]
                site = (str(consumer.get("from") or ""), str(consumer.get("to") or ""))
                consumer_row = emitted_consumers.get(site)
                if consumer_row is None:
                    continue
                consumer_api = consumer.get("api") or consumer.get("function")
                object_consumer = is_object_level_decode_consumer(
                    {
                        "api": consumer_api,
                        "link_kind": consumer.get("link_kind") or "decoded_va_reference",
                    }
                )
                decode_row = emit(
                    "decode_result",
                    {
                        **link["fields"],
                        "source_kind": "encoded_blob",
                        "verification": link["verification"],
                        "verification_status": link["verification"].get("status"),
                        "candidate": {
                            "formula": link["verification"].get("formula"),
                            "memory_addresses": [link["verification"].get("virtual_address")],
                            "output_buffer": link["output_buffer"],
                        },
                        "consumer_status": "LINKED_STATIC" if object_consumer else "NOT_IDENTIFIED",
                        "static_only": True,
                    },
                    {
                        "type": "decoded_config_consumer",
                        "virtual_address": link["verification"].get("virtual_address"),
                        "entry": consumer.get("entry"),
                    },
                )
                if not object_consumer:
                    continue
                relation = catalog_output_consumer_relation(
                    producer_id=decode_row.id,
                    consumer_id=consumer_row.id,
                    output_buffer=link["output_buffer"],
                    consumer_api=consumer_api,
                )
                if relation is not None:
                    emit(
                        "value_flow",
                        relation,
                        {
                            "type": "decoded_config_consumer",
                            "entry": consumer.get("entry"),
                        },
                        nature="STATIC_INFERRED",
                    )
            function_rows = self._select_ghidra_function_rows(
                all_function_rows,
                deterministic_pe,
                limit=self._MAX_GHIDRA_FUNCTIONS,
                pin_data_addresses=(*xor_vas, *api_thunks.keys()),
                thunks=api_thunks,
            )
            # Emit the coverage ratio unconditionally, including when nothing
            # was culled.  A merely absent row cannot be told apart from a
            # post-processing step that failed before writing it, so a reader
            # needs the explicit "processed_functions == total_functions"
            # signal to know the whole recovered function set was analysed.
            emit(
                "ghidra_function_budget",
                {
                    "total_functions": len(all_function_rows),
                    "processed_functions": len(function_rows),
                    "selection": "pe_entry_pinned_signal_xref_call_cfg_rank",
                    "pinned_entry_rva": deterministic_pe.get("entry_rva"),
                    "pinned_config_xrefs": len(config_xrefs),
                },
                {"type": "ghidra_postprocess_budget"},
            )
            self._emit_controlled_emulation(
                emit,
                artifact,
                artifact_content,
                session=session,
                task=task,
                tool_run=tool_run,
                pe_summary=deterministic_pe if isinstance(deterministic_pe, dict) else {},
                functions=function_rows,
            )
            # The exporter exposes non-call references, but raw Ghidra output
            # does not include decoded string contents. Resolve *every*
            # recovered reference target in bounded chunks: a flat call only
            # covered the first 256 addresses of the task, which on the 551KB
            # Rust PE 6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145
            # resolved 78 of 9727 and dropped every Windows Defender registry
            # literal, so the correlation join could never name the key that
            # FUN_140004605 writes. Unresolved addresses still remain
            # unresolved -- chunking extends coverage, it does not invent text.
            data_addresses = [
                str(reference.get("to"))
                for function_row in function_rows
                for reference in (
                    function_row.get("references_from", [])
                    if isinstance(function_row.get("references_from", []), list)
                    else []
                )
                if isinstance(reference, dict)
                and "call" not in str(reference.get("type", "")).lower()
                and reference.get("to")
            ]
            strings_by_address: dict[str, str] = resolve_data_strings_chunked(
                artifact_content,
                data_addresses,
                deterministic_pe,
            )
            for item in (
                output.get("strings", []) if isinstance(output.get("strings"), list) else []
            ):
                # The current exporter schema publishes recovered labels under
                # ``symbols``, but ``_record_ghidra_evidence`` has a deliberate
                # contract that it does not reach for that key (see
                # tests/test_pe_entry_function_budget.py).  String content for
                # the correlation join therefore comes from the byte reader
                # above and from the decode table below.
                if isinstance(item, dict) and item.get("address") and item.get("text"):
                    strings_by_address[str(item["address"])] = str(item["text"])
            # Capability: the decoded configuration is a string table too.  A
            # sample that resolves its APIs dynamically keeps the procedure names
            # inside the encoded blob, so they only exist at these image
            # addresses after the decode.  Merging them lets
            # recover_dynamic_api_resolutions name the resolved APIs instead of
            # only the ones already plaintext in the image -- which is what the
            # decode -> consumer Join depends on.  setdefault, so a real static
            # string at the same address wins.
            for address, text in decoded_config_string_table(xor_hits).items():
                strings_by_address.setdefault(address, text)
            # Built ONCE per artifact and threaded through the per-function loop below.
            #
            # `recover_process_creation_arguments` used to index the whole `strings_by_address`
            # mapping on every call, and it is called once per analysed function, so the mapping was
            # re-indexed per function. Armed with `faulthandler`, a 1 MB PE that stalled at 7,332
            # evidence rows with the API at 100% CPU for 325 s named the frame:
            #
            #     static_analysis.py:4296 in _address_variants
            #     static_analysis.py:4303 in recover_process_creation_arguments
            #     service.py:19573 in _record_ghidra_evidence
            #
            # Measured cost of the redundant rebuild: 100,000 strings cost 0.332 s per function, i.e.
            # 233 s across 703 functions; 500,000 strings cost 2.032 s each, i.e. 23.8 minutes. The
            # whole cost sat inside one GIL-holding call, which is why the HTTP event loop died too.
            command_string_index = build_command_string_index(strings_by_address)
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
                    if isinstance(call, dict) and ("call" in str(call.get("type", "")).lower())
                ]
                process_call_targets = [
                    row
                    for row in call_targets
                    if self._is_process_creation_call_row(row, process_thunks)
                ]
                ppid_thunks = {
                    key: value
                    for key, value in api_thunks.items()
                    if str(value).casefold() in {
                        "openprocess",
                        "updateprocthreadattribute",
                        "initializeprocthreadattributelist",
                    }
                }
                ppid_call_targets = [
                    row
                    for row in call_targets
                    if self._is_ppid_chain_call_row(row, ppid_thunks)
                ]
                pinned_call_targets: list[dict[str, object]] = []
                seen_call_ids: set[int] = set()
                for row in (*process_call_targets, *ppid_call_targets):
                    marker = id(row)
                    if marker in seen_call_ids:
                        continue
                    seen_call_ids.add(marker)
                    pinned_call_targets.append(row)
                if pinned_call_targets:
                    pinned_ids = {id(row) for row in pinned_call_targets}
                    call_targets = pinned_call_targets + [
                        row for row in call_targets if id(row) not in pinned_ids
                    ]
                data_targets = self._prioritize_config_data_references(
                    self._ghidra_data_reference_rows(
                        call_rows, function.get("instructions")
                    ),
                    xor_vas,
                    image_base=image_base,
                )
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
                        role
                        for role in classify_pe_semantics(function, deterministic_pe)
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
                abstract_execution = StaticAbstractExecutor(
                    max_steps=self.settings.static_abstract_execution_max_steps
                ).analyze(
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
                # Materialize one compact, analyst-facing semantic projection
                # per selected function.  This joins ordered calls, static
                # argument producers, predicates and consumers while keeping
                # runtime reachability explicitly unknown.
                function_chain_facts = tuple(function_chain_facts) + (
                    StaticFact(
                        "static_triage",
                        "function_semantic_summary",
                        build_function_semantic_summary(function),
                        {
                            "type": "function_semantic_summary",
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
                # Join GetProcAddress's RDX/EDX producer with the exported
                # string table.  These are derived static observations (not
                # direct tool output), so keep their provenance and nature
                # explicit for mechanism verifiers and report consumers.
                dynamic_resolutions = recover_dynamic_api_resolutions(
                    function,
                    strings_by_address,
                    thunks=api_thunks,
                    string_index=command_string_index,
                )
                for resolution in dynamic_resolutions:
                    # ``resolved_api`` is a semantic join of a resolver call,
                    # its argument producer, and the mapped string table. It
                    # is therefore STATIC_DERIVED rather than a direct
                    # Ghidra observation. Keep an explicit, reproducible
                    # derivation envelope so ClaimGate and later audit/replay
                    # can distinguish a recovered API identity from a mere
                    # GetProcAddress import.
                    source_ids = [
                        str(item)
                        for item in (context_evidence.id,)
                        if str(item).strip()
                    ]
                    normalized_resolution = {
                        **dict(resolution),
                        "source_evidence_ids": source_ids,
                        "static_only": True,
                    }
                    catalog_identity = str(resolution.get("api_name") or "").strip()
                    if catalog_identity:
                        normalized_resolution["api_identity"] = catalog_identity
                    if catalog_identity and (
                        normalized_resolution.get("consumer")
                        or normalized_resolution.get("consumer_callsite")
                    ):
                        pointer = catalog_resolved_pointer_identity(
                            artifact_id=artifact.id,
                            callsite=(
                                normalized_resolution.get("resolver_callsite")
                                or normalized_resolution.get("consumer_callsite")
                            ),
                        )
                        if pointer is not None:
                            normalized_resolution["resolved_pointer"] = pointer
                            normalized_resolution["output_buffer"] = pointer
                            normalized_resolution["consumer_pointer"] = pointer
                            normalized_resolution["input_buffer"] = pointer
                    input_digest = hashlib.sha256(
                        json.dumps(
                            {
                                "tool_run_id": tool_run.id,
                                "evaluator": "static-resolved-api-v1",
                                "source_evidence_ids": source_ids,
                            },
                            ensure_ascii=True,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest()
                    output_digest = hashlib.sha256(
                        json.dumps(
                            normalized_resolution,
                            ensure_ascii=True,
                            sort_keys=True,
                            default=str,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest()
                    normalized_resolution["derivation"] = {
                        "evaluator": "static-resolved-api-v1",
                        "input_evidence_ids": source_ids,
                        "input_digest": input_digest,
                        "output_digest": output_digest,
                        "exact": True,
                    }
                    resolution_evidence = emit(
                        "resolved_api",
                        normalized_resolution,
                        {
                            **anchor,
                            "type": "dynamic_api_resolution",
                            "resolver_callsite": resolution.get("resolver_callsite"),
                            "string_address": resolution.get("string_address"),
                            "api": resolution.get("api_name"),
                        },
                        nature="STATIC_DERIVED",
                    )
                    supporting_ids.append(resolution_evidence.id)
                    relation = catalog_relation_from_resolved_api(
                        normalized_resolution,
                        artifact_id=artifact.id,
                        source_evidence_id=resolution_evidence.id,
                        target_evidence_id=resolution_evidence.id,
                    )
                    if relation is not None:
                        emit(
                            "value_flow",
                            relation,
                            {
                                **anchor,
                                "type": "resolved_pointer_to_call",
                                "resolver_callsite": resolution.get("resolver_callsite"),
                                "consumer_callsite": resolution.get("consumer_callsite"),
                                "api": resolution.get("api_name"),
                            },
                            nature="STATIC_DERIVED",
                        )
                process_creations = recover_process_creation_arguments(
                    function,
                    strings_by_address,
                    thunks=process_thunks,
                    string_index=command_string_index,
                )
                parent_attribute = recover_parent_process_attribute(
                    function,
                    strings_by_address,
                    thunks=api_thunks,
                    content=artifact_content,
                    pe_summary=deterministic_pe,
                )
                if parent_attribute:
                    merged_flags = None
                    if process_creations:
                        first = dict(process_creations[0])
                        for key in (
                            "parent_selection",
                            "access_mask",
                            "attribute",
                            "startup_info",
                            "open_process",
                        ):
                            if parent_attribute.get(key) and not first.get(key):
                                first[key] = parent_attribute[key]
                        merged_flags = first.get("creation_flags") or first.get("flags") or parent_attribute.get("creation_flags")
                        if merged_flags and not first.get("startup_info"):
                            try:
                                if int(str(merged_flags), 16) & 0x00080000:
                                    first["startup_info"] = "STARTUPINFOEX"
                            except (TypeError, ValueError):
                                pass
                        process_creations = (first, *process_creations[1:])
                    elif any(
                        parent_attribute.get(key) not in (None, "")
                        for key in ("parent_selection", "attribute", "startup_info")
                    ):
                        process_creations = (dict(parent_attribute),)
                for creation in process_creations:
                    catalog_fields = {
                        key: creation[key]
                        for key in (
                            "command",
                            "command_line",
                            "image",
                            "creation_flags",
                            "flags",
                            "return_branch",
                            "parent_selection",
                            "access_mask",
                            "attribute",
                            "startup_info",
                            "open_process",
                        )
                        if creation.get(key) not in (None, "")
                    }
                    if not catalog_fields:
                        continue
                    site = str(creation.get("callsite") or "").strip()
                    parent_handle = None
                    attribute_handle = None
                    if catalog_fields.get("parent_selection") or catalog_fields.get("attribute") or catalog_fields.get("startup_info"):
                        parent_handle = catalog_parent_handle_identity(
                            artifact_id=artifact.id,
                            handle_id=f"openprocess:{site or context_evidence.id}",
                        )
                        attribute_handle = catalog_parent_handle_identity(
                            artifact_id=artifact.id,
                            handle_id=f"updateprocthreadattribute:{site or context_evidence.id}",
                        )
                        if parent_handle is not None:
                            catalog_fields["parent_handle"] = parent_handle
                        if attribute_handle is not None:
                            catalog_fields["attribute_handle"] = attribute_handle
                    trace = emit(
                        "api_argument_trace",
                        {
                            "api": creation.get("api") or creation.get("create_process") or "CreateProcessW",
                            "callsite": creation.get("callsite"),
                            "function": function.get("name"),
                            "function_entry": entry,
                            "static_only": True,
                            **catalog_fields,
                        },
                        {
                            **anchor,
                            "type": "process_creation_arguments",
                            "callsite": creation.get("callsite"),
                            "api": creation.get("api"),
                        },
                        nature="STATIC_DERIVED",
                    )
                    supporting_ids.append(trace.id)
                    relation = catalog_relation_from_api_fields(
                        creation.get("api") or creation.get("create_process"),
                        catalog_fields,
                        artifact_id=artifact.id,
                        callsite=creation.get("callsite"),
                        source_evidence_id=trace.id,
                        target_evidence_id=context_evidence.id,
                    )
                    if relation is not None:
                        emit(
                            "value_flow",
                            relation,
                            {
                                **anchor,
                                "type": "command_to_process_sink",
                                "callsite": creation.get("callsite"),
                            },
                            nature="STATIC_DERIVED",
                        )
                    parent_relation = catalog_relation_from_parent_attribute(
                        {
                            **catalog_fields,
                            "api": creation.get("api") or "UpdateProcThreadAttribute",
                            "callsite": creation.get("callsite"),
                            "parent_handle": parent_handle,
                            "attribute_handle": attribute_handle,
                        },
                        artifact_id=artifact.id,
                        source_evidence_id=trace.id,
                        target_evidence_id=trace.id,
                        callsite=creation.get("callsite"),
                    )
                    if parent_relation is not None:
                        emit(
                            "value_flow",
                            parent_relation,
                            {
                                **anchor,
                                "type": "parent_handle_to_attribute",
                                "callsite": creation.get("callsite"),
                            },
                            nature="STATIC_DERIVED",
                        )
                decode_window = analyze_xor_decode_window(instruction_rows)
                if decode_window is not None:
                    verified = verify_xor_decode_candidate(
                        decode_window,
                        artifact_content,
                        deterministic_pe,
                    )
                    recovered = recovered_payload_from_verification(verified)
                    if recovered:
                        self._materialize_recovered_bytes_child(
                            session,
                            task,
                            artifact,
                            tool_run,
                            recovered,
                            source="xor_decode",
                            anchor={
                                "type": "function_instruction_window",
                                "function_entry": entry,
                                "rva": entry_rva,
                            },
                        )
                    window_value = {**decode_window, "verification_result": verified}
                    identity = None
                    if isinstance(verified, Mapping):
                        identity = verified.get("output_buffer")
                    if not isinstance(identity, Mapping):
                        identity = output_buffer_identity(
                            address_space="image",
                            address=(
                                (verified or {}).get("virtual_address")
                                if isinstance(verified, Mapping)
                                else None
                            )
                            or (decode_window.get("memory_addresses") or [None])[0],
                            length=(
                                (verified or {}).get("length")
                                if isinstance(verified, Mapping)
                                else None
                            ),
                        )
                    if isinstance(identity, Mapping):
                        window_value["output_buffer"] = identity
                    function_chain_facts = tuple(function_chain_facts) + (
                        StaticFact(
                            "decryption",
                            "mechanism_decode_window",
                            window_value,
                            {
                                "type": "function_instruction_window",
                                "function_entry": entry,
                                "rva": entry_rva,
                            },
                        ),
                    )
                data_correlations = correlate_data_references(function, strings_by_address)
                if data_correlations:
                    correlation_payload: dict[str, object] = {
                        "function": function.get("name"),
                        "references": list(data_correlations),
                    }
                    # A degenerate-input guard may still cut the recovered set.
                    # Record the cut in the payload itself: a reader must never
                    # be able to mistake "we capped it" for "there was nothing
                    # there", which is exactly how the 64-reference cut hid the
                    # Windows Defender registry block.
                    truncation = data_reference_truncation(function, data_correlations)
                    if truncation:
                        correlation_payload["truncation"] = truncation
                        correlation_payload["source_evidence_ids"] = [
                            str(context_evidence.id)
                        ]
                    function_chain_facts = tuple(function_chain_facts) + (
                        StaticFact(
                            "static_triage",
                            "function_data_correlation",
                            correlation_payload,
                            {
                                "type": "function_data_reference",
                                "function_entry": entry,
                                "rva": entry_rva,
                            },
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
                # The window is Evidence about what the function does, not a
                # model prompt: a bounded preview is fine for planning, but a
                # stored window that silently drops most of the body makes the
                # function's own mechanism unstateable.  The previous 256-item
                # preview kept 418 of 4481 instructions for FUN_140004605 and
                # omitted every LEA in the Windows Defender registry block,
                # while the abstract/CFG consumers below read this same payload
                # as the function body.  Keep the whole recovered instruction
                # list; the exporter JSON is ~4.5 MB for 704 functions on this
                # sample, so a complete set is bounded by the artifact itself.
                # Force-pinned sites (recovered decode buffers, API thunks,
                # process-creation and PPID callsites) are always admitted and
                # no longer compete with the preview for the same slots.
                forced_indexes = self._instruction_indices_referencing_addresses(
                    instruction_rows,
                    xor_vas,
                    data_targets,
                    image_base=image_base,
                )
                how_indexes = self._instruction_indices_referencing_addresses(
                    instruction_rows,
                    api_thunks.keys(),
                    [*process_call_targets, *ppid_call_targets],
                    image_base=image_base,
                    context=3,
                    lookback=128,
                )
                forced_indexes |= how_indexes
                if instruction_rows:
                    window_payload = build_instruction_window_payload(
                        name=function.get("name"),
                        entry=entry,
                        entry_rva=entry_rva,
                        instructions=instruction_rows,
                        pinned_indexes=forced_indexes,
                        max_items=self._MAX_GHIDRA_INSTRUCTIONS_PER_FUNCTION,
                    )
                    instruction_evidence = emit(
                        "function_instruction_window",
                        window_payload,
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
                    item
                    for item in argument_targets
                    if any(
                        token in item.casefold()
                        for token in (
                            "winhttp",
                            "wininet",
                            "internet",
                            "createprocess",
                            "shellexecute",
                            "winexec",
                            "virtualalloc",
                            "virtualprotect",
                            "writeprocessmemory",
                            "openprocess",
                            "regsetvalue",
                            "createservice",
                            "loadlibrary",
                            "getprocaddress",
                            "createfile",
                            "writefile",
                            "readfile",
                            "cryptgenkey",
                            "cryptencrypt",
                            "cryptdecrypt",
                            "cryptimportkey",
                            "createthread",
                            "createthreadex",
                        )
                    )
                }
                for argument_api in sorted(argument_targets)[:24]:
                    for trace in trace_static_api_arguments(function, argument_api):
                        payload = {
                            **trace,
                            "function_entry": entry,
                            "rva": entry_rva,
                            "consumer": argument_api,
                            "source_evidence_ids": list(supporting_ids),
                            "static_only": True,
                        }
                        payload = self._overlay_pe_parser_thread_start(
                            payload, deterministic_pe
                        )
                        argument_evidence = emit(
                            "api_argument_trace",
                            payload,
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
                    # Evidence and Claims are flushed as one dependency-ordered
                    # unit at the end of Ghidra post-processing.  All IDs are
                    # preallocated, so there is no need to flush per function.
                    claim = Claim(
                        id=new_id(),
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
                    pending_claims.append(
                        (
                            claim,
                            tuple(validation.evidence_ids),
                            True,
                            {
                                "module": claim.module,
                                "claim_kind": "ghidra_mechanism_chain",
                                "function_entry": entry,
                                **self.static_agent.metadata,
                            },
                        )
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
                for behavior_claim, behavior_evidence_ids in self._record_ghidra_behavior_claims(
                    session,
                    task,
                    artifact,
                    function,
                    tuple(supporting_ids),
                    persist=False,
                ):
                    pending_claims.append(
                        (
                            behavior_claim,
                            behavior_evidence_ids,
                            True,
                            {
                                "module": behavior_claim.module,
                                "claim_kind": "ghidra_function_behavior",
                                "function_entry": entry,
                                **self.static_agent.metadata,
                            },
                        )
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
                source_rows = [
                    evidence_by_id[item] for item in source_ids if item in evidence_by_id
                ]
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
            for chain in self._select_cross_function_chain_claims(cross_function_chains):
                chain_evidence = emit(
                    "cross_function_chain",
                    chain,
                    {
                        "type": "call_graph_path",
                        "function_entries": list(chain.get("functions", [])),
                    },
                )
                claim = Claim(
                    id=new_id(),
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
                relation_types = {
                    "network": "LOADS",
                    "execution": "EXECUTES",
                    "persistence": "LOADS",
                    "dynamic_resolution": "LOADS",
                    "anti_analysis": "DECRYPTS",
                }
                pending_cross_claims.append(
                    (
                        claim,
                        chain_evidence.id,
                        tuple(
                            relation_types[str(category)]
                            for category in dict.fromkeys(chain.get("categories", []))
                            if str(category) in relation_types
                        ),
                    )
                )
        processed_function_entries = {
            str(item.get("entry"))
            for item in function_rows
            if isinstance(item, dict) and item.get("entry") is not None
        }
        persist_extra: list[object] = []
        with session.no_autoflush:
            persist_extra.extend(
                session.query(Evidence)
                .filter(
                    Evidence.task_id == task.id,
                    Evidence.artifact_id == artifact.id,
                    Evidence.kind == "string",
                )
                .all()
            )
        self._emit_ranked_symbols_then_stage(
            output,
            emit=emit,
            extra_evidence=persist_extra,
            emitted_evidence=emitted_evidence,
            artifact_path=str(artifact.logical_path or ""),
            pending_claims=pending_claims,
            task_id=task.id,
            subject=str(artifact.logical_path or ""),
        )
        self._collapse_generic_ghidra_behavior_claims(pending_claims)
        # All Ghidra Evidence has now been emitted.  Flush only that immutable
        # batch before similarity/relation queries can trigger autoflush; this
        # guarantees ClaimEvidence foreign keys without paying one flush per
        # function or per claim.
        # Flush the complete pending unit of work once before inserting
        # ClaimEvidence.  Passing ``objects=...`` looks cheaper, but it can
        # leave an Evidence row referenced by a staged claim unflushed when
        # SQLAlchemy has additional pending objects in the same dependency
        # graph, producing a PostgreSQL FK violation on real PE runs.  A
        # single full flush preserves the batch-performance property while
        # making the provenance boundary explicit and reliable.
        session.flush()
        for claim, evidence_ids, infer_relations, _payload in pending_claims:
            session.add(claim)
            for evidence_id in evidence_ids:
                self._link_claim_evidence(
                    session, claim_id=claim.id, evidence_id=evidence_id
                )
            if infer_relations:
                self._infer_component_relations(session, task, artifact, claim)
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="claim.created",
                actor="static-analysis-agent",
                object_type="Claim",
                object_id=claim.id,
                payload=_payload,
            )
        behavioral_component_relations = {"LOADS", "DECRYPTS", "EXECUTES", "INJECTS"}
        for claim, evidence_id, relation_types in pending_cross_claims:
            session.add(claim)
            self._link_claim_evidence(
                session, claim_id=claim.id, evidence_id=evidence_id
            )
            source_artifact_id = artifact.id
            # This path recovers a call-graph chain on one Artifact. A
            # distinct child/other component is required before a behavioral
            # component relation can exist; same-id INJECTS is an overclaim
            # (APC ≠ remote injection).
            target_artifact_id = artifact.id
            for relation_type in relation_types:
                if (
                    relation_type in behavioral_component_relations
                    and source_artifact_id == target_artifact_id
                ):
                    continue
                session.add(
                    Relation(
                        id=new_id(),
                        task_id=task.id,
                        source_artifact_id=source_artifact_id,
                        target_artifact_id=target_artifact_id,
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
                payload={"claim_kind": "cross_function_mechanism", "evidence_id": evidence_id},
            )
        # Persist all Claim/ClaimEvidence/Relation rows after the Evidence
        # batch is known to exist, before any similarity query can autoflush.
        session.flush()
        self._record_function_similarity(
            session,
            task,
            artifact,
            tool_run,
            processed_function_entries=processed_function_entries,
        )
        # Function evidence is emitted without per-row flushes.  Materialize
        # the batch once before priority claims reference those evidence IDs.
        session.flush()
        for proposal in self.static_agent.prioritize_function_evidence(tuple(function_candidates)):
            validation = validate_claim_evidence(
                proposal.evidence_ids,
                set(proposal.evidence_ids),
                module="static_triage",
                evidence_natures={item: "STATIC_OBSERVED" for item in proposal.evidence_ids},
            )
            if not validation.accepted:
                raise ValueError(validation.reason)
            claim = Claim(
                id=new_id(),
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
            for evidence_id in validation.evidence_ids:
                self._link_claim_evidence(
                    session, claim_id=claim.id, evidence_id=evidence_id
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
        # Flush immutable rows once so their explicit IDs are present before
        # the derived selector rows are inserted. The listener is disabled by
        # the session flag above during all earlier claim/correlation flushes.
        session.flush()
        # The selector index is rebuildable state.  Adding one ORM object per
        # selector made large Ghidra runs spend minutes tracking hundreds of
        # thousands of short-lived instances and could exhaust the worker
        # memory limit.  Keep the exact selector contract but use bounded
        # executemany batches so SQLAlchemy does not retain an object graph.
        search_key_rows: list[dict[str, str]] = []
        for item in emitted_evidence:
            for selector in evidence_search_keys(
                kind=item.kind, value=item.value, anchor=item.anchor
            ):
                search_key_rows.append(
                    {
                        "id": new_id(),
                        "task_id": item.task_id,
                        "artifact_id": item.artifact_id,
                        "evidence_id": item.id,
                        "selector": selector,
                        "kind": item.kind,
                    }
                )
                if len(search_key_rows) >= 4096:
                    session.execute(insert(EvidenceSearchKey), search_key_rows)
                    search_key_rows.clear()
        if search_key_rows:
            session.execute(insert(EvidenceSearchKey), search_key_rows)
        session.info.pop("defer_evidence_search_keys", None)

    def _record_ghidra_behavior_claims(
        self,
        session: Session,
        task: AnalysisTask,
        artifact: Artifact,
        function: dict[str, object],
        evidence_ids: tuple[str, ...],
        *,
        persist: bool = True,
    ) -> list[tuple[Claim, tuple[str, ...]]]:
        """Aggregate function call evidence into conservative atomic Claims."""
        deferred: list[tuple[Claim, tuple[str, ...]]] = []
        calls = function.get("references_from", [])
        if not isinstance(calls, list) or not evidence_ids:
            return deferred
        ordered_names = list(
            dict.fromkeys(
                str(call.get("target_name") or call.get("target_function"))
                for call in calls
                if isinstance(call, dict)
                and (call.get("target_name") or call.get("target_function"))
            )
        )
        names = sorted(ordered_names)
        if not names:
            return deferred
        navigation_label = re.compile(r"^(?:PTR_|LAB_|DAT_|FUN_|thunk_)", re.IGNORECASE)
        semantic_names = [
            name for name in ordered_names if not navigation_label.match(str(name).strip())
        ]
        call_sequence = " -> ".join((semantic_names or ordered_names)[:16])
        normalized_names = {normalize_api_symbol(name) for name in names}

        def has_name(values: tuple[str, ...]) -> bool:
            return any(normalize_api_symbol(value) in normalized_names for value in values)

        def has_prefix(prefixes: tuple[str, ...]) -> bool:
            return any(
                any(normalize_api_symbol(name).startswith(prefix) for prefix in prefixes)
                for name in names
            )

        categories: list[tuple[str, str, str, str, str]] = []
        if has_name(
            ("CryptDecrypt", "CryptEncrypt", "BCryptDecrypt", "BCryptEncrypt", "AES", "RC4", "XOR")
        ):
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
        if any(
            is_dynamic_loader_call(name)
            or is_injection_call(name)
            or classify_api_symbol(name).value in {"MEMORY_ALLOCATION", "MEMORY_PROTECTION"}
            for name in names
            if classify_api_symbol(name) is not None
        ):
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
        instruction_count = (
            len(function.get("instructions", []) or [])
            if isinstance(function.get("instructions"), list)
            else 0
        )
        data_reference_count = sum(
            1
            for call in calls
            if isinstance(call, dict) and "call" not in str(call.get("type", "")).casefold()
        )
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
                evidence_natures={item: "STATIC_OBSERVED" for item in evidence_ids},
            )
            if not validation.accepted:
                raise ValueError(validation.reason)
            attack_mapping: dict[str, object] = {}
            if action == "decompresses_or_decodes":
                attack_mapping = {
                    "status": "candidate",
                    "mappings": [
                        {
                            "technique_id": "T1140",
                            "technique_name": "Deobfuscate/Decode Files or Information",
                            "status": "candidate",
                        }
                    ],
                }
            elif action == "queries_service_state":
                attack_mapping = {
                    "status": "candidate",
                    "mappings": [
                        {
                            "technique_id": "T1007",
                            "technique_name": "System Service Discovery",
                            "status": "candidate",
                        }
                    ],
                }
            elif action == "checks_execution_environment":
                attack_mapping = {
                    "status": "candidate",
                    "mappings": [
                        {
                            "technique_id": "T1497",
                            "technique_name": "Virtualization/Sandbox Evasion",
                            "status": "candidate",
                        }
                    ],
                }
            elif action == "may_execute":
                # CreateProcess/WinExec references describe a process
                # creation capability, not necessarily a command interpreter.
                # Emit T1059 only when the function also carries an explicit
                # interpreter token; otherwise keep the behavior Claim
                # unmapped and let the analyst inspect the anchored evidence.
                interpreter_tokens = (
                    "cmd.exe",
                    "powershell",
                    "wscript",
                    "cscript",
                    "rundll32",
                    "regsvr32",
                )
                if any(token in " ".join(names).casefold() for token in interpreter_tokens):
                    attack_mapping = {
                        "status": "candidate",
                        "mappings": [
                            {
                                "technique_id": "T1059",
                                "technique_name": "Command and Scripting Interpreter",
                                "status": "candidate",
                            }
                        ],
                    }
            claim = Claim(
                id=new_id(),
                task_id=task.id,
                module=module,
                claim_type="BEHAVIOR",
                subject=f"{artifact.logical_path}:{function_name}@{entry}",
                action=action,
                object=obj,
                mechanism=mechanism,
                condition=condition,
                statement=(
                    f"Function {function_name} at {entry} contains the ordered static call path "
                    f"{call_sequence or ', '.join(names[:12])}; this is consistent with {module} behavior. "
                    f"The function has {instruction_count} recovered instructions and {data_reference_count} "
                    "non-call data references. Runtime reachability and side effects remain unobserved."
                ),
                nature="STATIC_INFERRED",
                status="CANDIDATE",
                confidence="MEDIUM",
                attack_mapping=attack_mapping,
            )
            deferred.append((claim, tuple(validation.evidence_ids)))
            if persist:
                session.add(claim)
                for evidence_id in validation.evidence_ids:
                    self._link_claim_evidence(
                        session, claim_id=claim.id, evidence_id=evidence_id
                    )
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
        return deferred

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
        # Claims and Evidence in the Ghidra batch have preallocated IDs.  Do
        # not let this lookup autoflush the entire pending batch for every
        # function; child artifacts are immutable for the task and can be
        # read without flushing staged rows.
        with session.no_autoflush:
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
            if child.id == artifact.id:
                continue
            relation = Relation(
                id=new_id(),
                task_id=task.id,
                source_artifact_id=artifact.id,
                target_artifact_id=child.id,
                relation_type=relation_type,
                claim_id=claim.id,
                status="INFERRED",
            )
            session.add(relation)
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
        return _task_runner._actual_depth(session, task_id, artifacts)

    @staticmethod
    def _completion_limitations(session, task_id, artifacts) -> list[str]:
        return _limitations.completion_limitations(session, task_id, artifacts)

    @staticmethod
    def failed_tool_run_limitations(session, task_id) -> list[str]:
        """Public behaviour entry point for `_failed_tool_run_limitations` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private staticmethod stays the implementation and the facade delegates to it, so a test that replaces
        the private attribute on the class keeps working.
        """
        return AnalysisService._failed_tool_run_limitations(session, task_id)


    @staticmethod
    def _failed_tool_run_limitations(session, task_id) -> list[str]:
        return _limitations.failed_tool_run_limitations(session, task_id)

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
        strategy_snapshot = (
            task.strategy_snapshot
            if task is not None and isinstance(task.strategy_snapshot, dict)
            else {}
        )
        investigation_snapshot = strategy_snapshot.get("investigation", {})
        snapshot_mechanisms = (
            investigation_snapshot.get("mechanisms", [])
            if isinstance(investigation_snapshot, dict)
            else []
        )
        mechanism_metrics = mechanism_coverage_metrics(snapshot_mechanisms)
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
                if any(
                    item.kind
                    in {
                        "function",
                        "function_context",
                        "script_function",
                        "pe_structure",
                        "decompile",
                        "pcode",
                    }
                    for item in evidence
                ):
                    code += 1
            if any(
                item.kind in {"function", "function_context", "function_call"} for item in evidence
            ):
                functions += 1
            if any(item.kind in {"data_reference", "xref", "value_flow"} for item in evidence):
                data_refs += 1
            if any(
                item.kind.startswith("mechanism") or item.kind == "abstract_execution_trace"
                for item in evidence
            ):
                mechanisms += 1
            claims = list(
                session.scalars(
                    select(Claim).where(
                        Claim.task_id == task_id, Claim.subject == artifact.logical_path
                    )
                )
            )
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
            verified_snapshot_for_artifact = any(
                isinstance(item, dict)
                and (
                    str(item.get("artifact_id") or item.get("target_artifact_id") or "")
                    == str(artifact.id)
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
                    str(item.get("artifact_id") or item.get("target_artifact_id") or "")
                    == str(artifact.id)
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
            verified_mechanism_coverage=float(mechanism_metrics["verified_mechanism_coverage"]),
            relation_flow_coverage=relation_flow_rate,
            semantic_flow_nodes=semantic_flow_nodes,
            semantic_flow_edges=semantic_flow_edges,
            behavior_flow_present=(
                semantic_flow_nodes >= 3
                and semantic_flow_edges >= 2
                and participating_flow_mechanisms > 0
            ),
            coverage_applicable=eligible_flow_mechanisms > 0,
            artifact_verified_mechanism_coverage=verified_mechanisms / denominator,
            mechanism_count=int(mechanism_metrics["mechanism_count"]),
            verified_mechanism_count=int(mechanism_metrics["verified_mechanism_count"]),
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
        if (
            normalized in behavioral
            and source_artifact_id == target_artifact_id
        ):
            raise ValueError(
                f"{normalized} cannot use the same Artifact as source and target"
            )
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

    def record_function_similarity(self, session: Session, task: AnalysisTask, artifact: Artifact, source_tool_run: ToolRun, *, processed_function_entries: set[str] | None = None) -> None:
        """Public behaviour entry point for `_record_function_similarity` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name, so a test asserted against an
        implementation detail rather than against a behaviour the service offers. Callers outside the class use this
        name; the private method stays the implementation, and its ONE deliberate remaining caller is production code
        that a test replaces by attribute (`tests/test_analysis_task_orchestration.py`), which is why the private name
        is not removed here.
        """
        return self._record_function_similarity(session, task, artifact, source_tool_run, processed_function_entries=processed_function_entries)


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
            id=new_id(),
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
        # The similarity Evidence rows reference this synthetic ToolRun.  A
        # single parent flush is sufficient; individual match flushes would
        # reintroduce the large-file performance regression.
        session.flush(objects=[similarity_run])
        # ONE ROW PER SOURCE FINGERPRINT, not one per match.  Measured on task `de738f12`:
        # 704 simhash rows produced 7,406 `function_similarity` rows (2,785 kB - the second-largest
        # evidence kind) and ~11,406 chained `evidence.recorded` audit events out of the task's
        # 12,648.  Nothing consumes those rows: claims read 0 and relations cite 0, and
        # `ActionType.COMPARE_FUNCTION` reads `function_simhash`.
        #
        # The matches are a real finding - 88% sit at Hamming distance 0 (identical function bodies)
        # across 334 sources and 262 references - so the fix reduces the PAIRS-per-row, never the
        # information: every match, distance, threshold and reference id is kept in the row's
        # `matches` list.  Row count now tracks the number of sources (334) instead of the number of
        # match pairs (7,406), and the audit cost drops with it.
        matched_sources = 0
        for source in source_rows:
            query = SimilarityQuery(
                source.id,
                str(source.value.get("value", "")),
                scopes,
            )
            matches = [
                {
                    "reference_kind": match.reference_kind,
                    "reference_id": match.reference_id,
                    "distance": match.distance,
                    "threshold": match.threshold,
                    "algorithm": match.algorithm,
                    "feature": match.feature,
                    "reference_metadata": match.reference_metadata,
                    "catalog_sha256": match.catalog_sha256,
                }
                for match in self.similarity_index.search(query, records=records)
            ]
            if not matches:
                continue
            matched_sources += 1
            # The nearest match leads the row so a reader and a rule can use the row directly
            # without walking the list; `matches` keeps the complete set.
            nearest = min(matches, key=lambda item: item["distance"])
            evidence = Evidence(
                id=new_id(),
                task_id=task.id,
                artifact_id=source.artifact_id,
                tool_run_id=similarity_run.id,
                module="static_triage",
                kind="function_similarity",
                nature="STATIC_OBSERVED",
                value={
                    "source_evidence_id": source.id,
                    "reference_kind": nearest["reference_kind"],
                    "reference_id": nearest["reference_id"],
                    "distance": nearest["distance"],
                    "threshold": nearest["threshold"],
                    "algorithm": nearest["algorithm"],
                    "feature": nearest["feature"],
                    "reference_metadata": nearest["reference_metadata"],
                    "catalog_sha256": nearest["catalog_sha256"],
                    "match_count": len(matches),
                    "matches": matches,
                },
                anchor={**source.anchor, "similarity_source": source.id},
            )
            session.add(evidence)
            self._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="evidence.recorded",
                actor="function-similarity-index",
                object_type="Evidence",
                object_id=evidence.id,
                payload={
                    "kind": evidence.kind,
                    "tool_run_id": similarity_run.id,
                    "match_count": len(matches),
                },
            )
        del matched_sources

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
            if not isinstance(action, dict) or action.get("target_artifact_id") not in {
                None,
                artifact_id,
            }:
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
            and (target_artifact_id is None or str(item.get("artifact_id")) == target_artifact_id)
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
        if any(
            anchor.casefold() in {"getprocaddress", "loadlibrarya", "loadlibraryw"}
            for anchor in anchors
        ):
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
            for token in (
                "openprocess",
                "updateprocthreadattribute",
                "parent_process",
                "explorer.exe",
            )
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
            data_xref_depth=1
            if profile in {"dynamic-api-resolution", "xor-config-recovery"}
            else 0,
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
            packet = QuestionCentricRetriever(max_items=per_artifact_limit).build(
                request, serialized
            )
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
        vocabulary = ("input", "transformation", "condition", "output", "consumer", "side effect")
        return (
            evidence_count >= 2
            and mechanism.count("->") >= 2
            and any(token in mechanism.casefold() for token in vocabulary)
        )

    def run_gap_driven_model_rounds(self, task_id: str) -> list[str]:
        """Public behaviour entry point for `_run_gap_driven_model_rounds` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name, so a test asserted against an
        implementation detail rather than against a behaviour the service offers. Callers outside the class use this
        name; the private method stays the implementation, and its ONE deliberate remaining caller is production code
        that a test replaces by attribute (`tests/test_analysis_task_orchestration.py`), which is why the private name
        is not removed here.
        """
        return self._run_gap_driven_model_rounds(task_id)


    def _run_gap_driven_model_rounds(self, task_id: str) -> list[str]:
        """Continue model planning from unresolved semantic frontier gaps.

        The normal scheduler invokes planning when a baseline action produces
        new rows.  A later deterministic investigation pass can itself expose
        a missing consumer, branch, or child relation, though.  This bounded
        post-pass closes that control-plane hole: each turn reads the durable
        frontier, proposes catalog actions, executes only policy-approved
        actions, and stops on a real no-gain result or the configured horizon.
        """
        if (
            not self.settings.model_calls_enabled
            or self.settings.environment.lower() == "test"
        ):
            return []
        limitations: list[str] = []
        # Do not let repeated task resumes create an unbounded model budget.
        with self.database.session_factory() as session:
            task = session.get(AnalysisTask, task_id)
            if task is None:
                return []
            planning = dict((task.strategy_snapshot or {}).get("dynamic_planning", {}))
            prior_rounds = int(planning.get("post_investigation_rounds", 0) or 0)
            if prior_rounds >= 2:
                return []
            artifacts = list(
                session.scalars(
                    select(Artifact)
                    .where(Artifact.task_id == task_id, Artifact.role != "CONTAINER")
                    .order_by(Artifact.created_at, Artifact.id)
                )
            )
            frontier = self._build_investigation_frontier(
                session,
                task=task,
                artifacts=artifacts,
                completed_actions=[],
            )
            open_unknowns = list(frontier.get("open_unknowns", []))
            deferred = list(frontier.get("deferred_frontier", []))
            mechanisms = list(frontier.get("mechanisms", []))
            unresolved = [
                row for row in mechanisms
                if frontier_status_is_open(row.get("status"))
            ]
            recoverable = [
                row
                for row in mechanisms
                if isinstance(row, Mapping)
                and recovery_actions_for_gap(
                    str(row.get("mechanism_type") or ""),
                    (row.get("verifier") or {}).get("missing")
                    if isinstance(row.get("verifier"), Mapping)
                    else row.get("missing") or (),
                )
            ]
            planner_deferred = [
                row for row in deferred if deferred_keeps_planner_open(row)
            ]
            ledger_waiting = [
                row
                for row in (task.strategy_snapshot or {}).get("investigation", {}).get("work_ledger", [])
                if isinstance(row, Mapping)
                and str(row.get("status") or "").upper() == "DEFERRED"
                and str(row.get("next_method") or "").upper() in {
                    ActionType.CONTROLLED_EMULATE.value,
                    ActionType.TRACE_API_ARGUMENT.value,
                    ActionType.GET_DECOMPILE.value,
                    ActionType.READ_BYTES.value,
                }
            ]
            if (
                not open_unknowns
                and not planner_deferred
                and not unresolved
                and not recoverable
                and not ledger_waiting
            ):
                return []
            completed_history = list(planning.get("completed_actions", []))
            all_artifact_ids = [str(item.id) for item in artifacts]

        for offset in range(2 - prior_rounds):
            phase = f"post_investigation_gap_{prior_rounds + offset + 1}"
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
            if not artifacts:
                break
            actions, round_limitations = self._run_model_planning(
                task_id,
                artifacts,
                all_artifact_ids,
                phase=phase,
                completed_actions=self._bound_completed_actions(completed_history),
            )
            limitations.extend(round_limitations)
            if not actions:
                limitations.append(
                    f"Gap-driven planning stopped at {phase}: no executable action was returned for the persisted frontier."
                )
                break
            before = self._task_evidence_count(task_id)
            limitations.extend(self._run_investigation_loop(task_id, model_actions_only=True))
            results = self._collect_model_action_results(task_id, actions)
            completed_history.extend(results)
            self._finalize_pending_analysis_turn_results(
                task_id,
                self._bound_completed_actions(completed_history),
                stop_reason=("GAP_ACTIONS_EXECUTED" if results else "GAP_ACTIONS_NOT_RECORDED"),
            )
            after = self._task_evidence_count(task_id)
            with self.database.session_factory.begin() as session:
                task = session.get(AnalysisTask, task_id, with_for_update=True)
                if task is None:
                    raise LookupError(task_id)
                current = dict(task.strategy_snapshot or {})
                current_planning = dict(current.get("dynamic_planning", {}))
                current_history = list(current_planning.get("completed_actions", []))
                current_history.extend(results)
                current_planning.update(
                    {
                        "post_investigation_rounds": prior_rounds + offset + 1,
                        "completed_actions": self._bound_completed_actions(current_history)[-128:],
                        "last_gap_phase": phase,
                        "last_gap_evidence_delta": max(0, after - before),
                        "last_gap_stop_reason": (
                            "NEW_EVIDENCE" if after > before else "NO_NEW_EVIDENCE"
                        ),
                    }
                )
                task.strategy_snapshot = {**current, "dynamic_planning": current_planning}
            if after <= before:
                limitations.append(
                    f"Gap-driven planning stopped at {phase}: accepted actions produced no new Evidence; remaining unknowns are retained."
                )
                break
            # A productive action may reveal a fresh frontier. The next loop
            # re-enters _run_model_planning, which rebuilds it from the DB.
        return limitations

    def _task_evidence_count(self, task_id: str) -> int:
        """Return a cheap, transaction-safe evidence count for a gap round."""
        with self.database.session_factory() as session:
            return int(
                session.scalar(
                    select(func.count(Evidence.id)).where(Evidence.task_id == task_id)
                )
                or 0
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
                    (task.strategy_snapshot or {})
                    .get("dynamic_planning", {})
                    .get("completed_actions", [])
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
                    "target",
                    "inputs",
                    "transformation_or_control",
                    "conditions",
                    "outputs",
                    "consumers",
                    "side_effects",
                    "evidence_ids",
                ],
                "must_emit_evidence_backed_claim": any(
                    str(item.get("kind", "")).startswith("mechanism")
                    or item.get("kind")
                    in {"abstract_execution_trace", "function_call", "function_context"}
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
                # Keep enrichment bounded independently from the user-facing
                # provider timeout.  The deterministic report remains the
                # authoritative fallback when the remote model is slow.
                timeout_s=min(90.0, self.settings.model_timeout_s),
                # Keep enough completion budget for a bounded evidence-backed
                # envelope. Qwen reasoning can consume the old 1536-token cap
                # before emitting the closing JSON brace.
                #
                # The budget is the CONFIGURED one, not a local constant: see the note at the planner
                # call site. This site used 4_096 while the report overlay used 2_048, so the same
                # reasoning model succeeded for enrichment and failed for the report.
                max_tokens=self.settings.model_max_tokens,
                # Chat Settings may enable SSE for the DSH composer. Analysis
                # enrichment needs one complete JSON envelope from the same
                # saved route, not a reasoning stream that fails as ValueError.
                stream=False,
                structured_output=True,
                disable_reasoning=True,
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
                return [
                    "Agent context exceeded the configured budget; deterministic Claims were retained."
                ]
            failures = ", ".join(
                f"{attempt.provider}/{attempt.model}:{attempt.error_type or attempt.status}"
                for attempt in runtime_result.attempts
            )
            schema_mismatch = any(
                attempt.error_type == "ValidationError" for attempt in runtime_result.attempts
            )
            prefix = (
                "Model enrichment JSON did not match the atomic-claim envelope; deterministic Claims were retained."
                if schema_mismatch
                else "Model analysis providers failed; deterministic Claims were retained."
            )
            return [prefix + (f" Attempts: {failures}." if failures else "")]

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
                    and self._model_candidate_shape_is_valid(draft, len(validation.evidence_ids))
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
                    self._link_claim_evidence(
                        session, claim_id=claim.id, evidence_id=evidence_id
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
            artifact_id: [
                item
                for item in sorted(groups[artifact_id], key=rank)
                if item.id not in selected_ids
            ]
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
        limit = max(128, int(limit or cls._MODEL_EVIDENCE_VALUE_LIMIT))
        priority = (
            "api", "api_name", "target_name", "target_function", "name",
            "entry", "entry_rva", "function_entry", "rva", "address",
            "from", "to", "callsite", "relationship", "source_evidence_ids",
            "consumer", "module", "endpoint", "url", "text", "instructions",
            "call_targets", "references_from", "arguments",
        )

        def compact(item: object, depth: int = 0) -> object:
            if isinstance(item, str):
                text_limit = 240 if depth < 2 else 120
                return item if len(item) <= text_limit else item[: text_limit - 3] + "..."
            if isinstance(item, Mapping):
                ordered = sorted(
                    item.items(),
                    key=lambda pair: (
                        priority.index(str(pair[0])) if str(pair[0]) in priority else len(priority),
                        str(pair[0]),
                    ),
                )[:16]
                return {str(key): compact(child, depth + 1) for key, child in ordered}
            if isinstance(item, (list, tuple, set)):
                values = list(item)
                output = [compact(child, depth + 1) for child in values[:12]]
                if len(values) > 12:
                    output.append(f"... ({len(values) - 12} more items)")
                return output
            return item

        result = compact(value)
        serialized = json.dumps(result, ensure_ascii=False, default=str, separators=(",", ":"))
        if len(serialized.encode("utf-8")) <= limit:
            return result
        # The final cap is on the serialized representation, not merely each
        # nested field. This prevents a dense Ghidra instruction window from
        # turning a nominal 12-item context into a 100 KB planner request.
        preview_budget = max(48, min(240, limit // 3))
        return {
            "truncated": True,
            "preview": serialized.encode("utf-8")[:preview_budget].decode("utf-8", errors="ignore"),
        }

    @classmethod
    def _model_evidence_manifest(cls, item: Evidence) -> dict[str, object]:
        return {
            "evidence_id": item.id,
            "artifact_id": item.artifact_id,
            "kind": item.kind,
            "nature": item.nature,
            "value": cls._compact_model_value(item.value),
            "anchor": cls._compact_model_value(item.anchor, limit=384),
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
                request.top_p if request is not None and request.top_p is not None else route.top_p
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
                    "origin": "model",
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

    def _is_task_cancelled(self, task_id: str, *, observing: Session | None = None) -> bool:
        return _limitations.is_task_cancelled(self.database, task_id, observing=observing)

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
                keys = {key for key in (call.request_storage_key, call.response_storage_key) if key}
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

    def freeze_snapshot(self, session: Session, task: AnalysisTask) -> AnalysisSnapshot:
        """Public behaviour entry point for `_freeze_snapshot` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private method stays the implementation, and the facade delegates to it so a test that still
        replaces the private attribute keeps working.
        """
        return self._freeze_snapshot(session, task)


    def _freeze_snapshot(self, session: Session, task: AnalysisTask) -> AnalysisSnapshot:
        case = session.get(CaseRecord, task.case_id)
        if case is None:
            raise LookupError(task.case_id)
        # The immutable snapshot deliberately captures the complete ledger;
        # report projections are bounded later without weakening replay.
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
        payload["content_sha256"] = self._canonical_sha256(payload)

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
        # Effectiveness traces consume only planner turns/results. Loading
        # the complete Evidence/Claim ledger here duplicated finalization
        # work and made large tasks pay an avoidable second serialization.
        inputs = {
            "analysis_turns": list(
                session.scalars(
                    select(AnalysisTurnRecord)
                    .where(AnalysisTurnRecord.task_id == task.id)
                    .order_by(AnalysisTurnRecord.created_at, AnalysisTurnRecord.id)
                )
            ),
            "analysis_turn_results": list(
                session.scalars(
                    select(AnalysisTurnResultRecord)
                    .where(AnalysisTurnResultRecord.task_id == task.id)
                    .order_by(AnalysisTurnResultRecord.created_at, AnalysisTurnResultRecord.id)
                )
            ),
        }
        events = list(
            session.scalars(
                select(AuditEvent)
                # The trace builder only consumes report revision IDs from
                # audit events.  Keep the immutable audit ledger complete in
                # the database, but avoid loading every parser/action event
                # into this finalization projection for long tasks.
                .where(
                    AuditEvent.task_id == task.id,
                    AuditEvent.event_type.in_({"report.generated", "report.recomposed"}),
                )
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
        seen_digests: set[str] = set()
        for trace in traces:
            payload = {
                key: value for key, value in trace.items() if key not in {"id", "trace_sha256"}
            }
            # Scope the content digest to this task. The column is globally
            # unique, so a second analysis of the same sample must not reuse
            # another task's digest or finalization aborts with IntegrityError.
            digest = hashlib.sha256(
                self._canonical_json({"task_id": task.id, **payload}).encode("utf-8")
            ).hexdigest()
            if digest in seen_digests:
                continue
            if (
                session.scalar(
                    select(MechanismEffectivenessTraceRecord).where(
                        MechanismEffectivenessTraceRecord.trace_sha256 == digest
                    )
                )
                is not None
            ):
                continue
            seen_digests.add(digest)
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
                    question=(
                        str(trace["question"]) if trace.get("question") is not None else None
                    ),
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
        claim_ids = [item.id for item in claims]
        claim_evidence_rows = (
            list(
                session.scalars(select(ClaimEvidence).where(ClaimEvidence.claim_id.in_(claim_ids)))
            )
            if claim_ids
            else []
        )
        for link in claim_evidence_rows:
            if link.stance == "SUPPORTS":
                links.setdefault(link.claim_id, []).append(link.evidence_id)
        # Only Claim-linked evidence and specialist mechanism links can affect
        # this projection.  The full ledger remains untouched in the database
        # and is captured by _freeze_snapshot; avoiding a task-wide Evidence
        # load here is what keeps large Ghidra runs from stalling finalization.
        linked_ids = {
            str(item.evidence_id) for item in claim_evidence_rows if item.stance == "SUPPORTS"
        }
        static_links = list(
            session.scalars(
                select(Evidence)
                .where(
                    Evidence.task_id == task.id,
                    Evidence.kind.in_(
                        {
                            "mechanism_dynamic_api_link",
                            "mechanism_http_transport_link",
                            "mechanism_shell_output_link",
                            "mechanism_etw_patch_link",
                        }
                    ),
                )
                .order_by(Evidence.created_at, Evidence.id)
                .limit(self._MECHANISM_PROJECTION_LINK_LIMIT)
            )
        )
        linked_ids.update(item.id for item in static_links)
        linked_ids.update(
            str(source_id)
            for item in static_links
            if isinstance(item.value, Mapping)
            for source_id in (item.value.get("source_evidence_ids") or ())[:32]
            if str(source_id).strip()
        )
        evidence_by_id = {
            item.id: item
            for item in session.scalars(
                select(Evidence).where(
                    Evidence.task_id == task.id,
                    Evidence.id.in_(list(linked_ids)[: self._MECHANISM_PROJECTION_EVIDENCE_LIMIT]),
                )
            )
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
        by_claim: dict[str, dict[str, object]] = {}
        for item in existing:
            raw_claim_ids = [item.get("claim_id"), *(item.get("claim_ids") or ())]
            for raw_claim_id in raw_claim_ids:
                if raw_claim_id:
                    by_claim.setdefault(str(raw_claim_id), item)
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
                        row.get("mechanism_type") or row.get("type") or row.get("dimension") or ""
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
                    current["provenance"] = projection.get(
                        "provenance", current.get("provenance", {})
                    )
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
                clone_claim_ids = ([str(row["claim_id"])] if row.get("claim_id") else []) + [
                    str(item) for item in (row.get("claim_ids") or ()) if item
                ]
                clone["claim_ids"] = list(dict.fromkeys(clone_claim_ids))
                by_semantic_key[semantic_key] = clone
                deduped.append(clone)
                continue
            claim_id = row.get("claim_id")
            if claim_id and str(claim_id) not in current.setdefault("claim_ids", []):
                current["claim_ids"].append(str(claim_id))
            for claim_id in row.get("claim_ids") or ():
                if claim_id and str(claim_id) not in current.setdefault("claim_ids", []):
                    current["claim_ids"].append(str(claim_id))
            evidence_ids = list(
                dict.fromkeys(
                    [str(item) for item in current.get("evidence_ids", []) if item]
                    + [str(item) for item in row.get("evidence_ids", []) if item]
                )
            )
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
        self._persist_pma_static_analysis_plan(session, task)
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
        from threat_report_agent.investigation.mechanism_completeness import has_semantic_value

        current_status = str(current.get("status", "")).upper()
        for key in (
            "target",
            "inputs",
            "transformation_or_control",
            "conditions",
            "outputs",
            "consumers",
            "side_effects",
            "evidence_ids",
            "alternative_hypotheses",
            "unknowns",
            "limitations",
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
        # The snapshot is immutable.  Report projection enriches nested
        # investigation rows with protocol metadata and may bound Evidence; the
        # sealed JSON must never be mutated or its content digest invalidated.
        #
        # That guarantee used to cost a ``copy.deepcopy`` of the WHOLE payload plus
        # a materialised canonical JSON string of it on every report build.  Both
        # are needless at this size: a live snapshot carries ~100 MB of Evidence
        # (``analysis_snapshots`` totals 16 GB; the largest payloads are ~600 MB),
        # while the report consumes a bounded projection of it.  Measured on a real
        # 116 MB snapshot: 3.9 s of deep copy + 1.0 s of whole-payload
        # serialisation (a further 110 MB string plus 110 MB of encoded bytes),
        # 186 MB of resident copy, and 178 MB off the measured peak RSS.
        #
        # The invariant is preserved structurally instead of by copying:
        #   * the digest is streamed into ``hashlib`` in bounded chunks so the
        #     canonical bytes are never materialised (same algorithm, same digest);
        #   * ``payload`` is a shallow top-level copy and every row this projection
        #     rewrites is copied first (copy-on-write), so no object reachable from
        #     ``snapshot.object_versions`` is mutated;
        #   * ``tests/test_report_synthesis_performance.py`` locks that down by
        #     re-verifying the sealed digest after a full report build and asserting
        #     the ORM attribute is never marked dirty.
        return _revision_writer._snapshot_report_context(self, snapshot)

    @classmethod
    def select_report_evidence_rows(cls, rows: list[object], *, referenced_ids: set[str], limit: int) -> list[object]:
        """Public behaviour entry point for `_select_report_evidence_rows` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private classmethod stays the implementation and the facade delegates to it, so a test that replaces
        the private attribute on the class keeps working.
        """
        return cls._select_report_evidence_rows(rows, referenced_ids=referenced_ids, limit=limit)


    @classmethod
    def _select_report_evidence_rows(
        cls,
        rows: list[object],
        *,
        referenced_ids: set[str],
        limit: int,
    ) -> list[object]:
        """Select a bounded report view without deleting ledger evidence."""
        return _revision_writer._select_report_evidence_rows(rows, referenced_ids=referenced_ids, limit=limit)

    @classmethod
    def _migrate_snapshot_payload(
        cls, snapshot_id: str, payload: dict[str, object]
    ) -> dict[str, object]:
        """Read-only migration registry for immutable Analysis Snapshot payloads."""
        return _revision_writer._migrate_snapshot_payload(cls, snapshot_id, payload)

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

    @staticmethod
    def _postgres_safe_text(value: str) -> str:
        """PostgreSQL TEXT/VARCHAR cannot store NUL bytes from recovered PE strings."""
        return str(value).replace("\x00", "")

    @classmethod
    def _postgres_safe_value(cls, value: object) -> object:
        if isinstance(value, str):
            return cls._postgres_safe_text(value)
        if isinstance(value, Mapping):
            return {str(key): cls._postgres_safe_value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [cls._postgres_safe_value(item) for item in value]
        if isinstance(value, tuple):
            return [cls._postgres_safe_value(item) for item in value]
        return value

    def _persist_analyst_overlay_attempt(
        self,
        task: AnalysisTask,
        prompt: Any,
        request: ModelRequest[Any],
        result: Any,
    ) -> None:
        """Record the report overlay's model attempt in `model_calls`.

        Reuses `_persist_model_attempts`, the same projection the planner and the enrichment turns use, so
        the overlay is auditable on exactly the same terms: provider, model, prompt hash, latency, token
        counts, error type, gateway error detail, and the encrypted request payload.

        BORROWS THE CALLER'S SESSION, and that is the whole point. The first version opened its own
        `session_factory.begin()` block, which on a single-connection engine (sqlite `StaticPool`) cannot be
        satisfied while the caller's transaction already holds the connection: the run deadlocked with the
        analysis thread parked in `psycopg connection.wait` and the API process at 0.23% CPU, with evidence
        frozen at 3,956 rows (thread dump via `THREAT_STACK_DUMP=1`, `docker kill -s USR1`). This is the same
        defect class as the cancellation probe fixed earlier, reintroduced by me - a nested session is not a
        separate transaction when there is one connection.

        Writing into the caller's transaction is correct here: the caller is `_create_report_revision`, which
        is already writing the revision itself, so the telemetry shares its fate rather than racing it.
        """
        attempts = tuple(getattr(result, "attempts", ()) or ())
        if not attempts:
            return
        session = object_session(task)
        if session is None:
            return
        try:
            request_content = json.dumps(
                {"messages": request.messages, "module": "analyst_report"},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            request_stored = self._store_model_payload(request_content)
            self._persist_model_attempts(
                session,
                task,
                prompt,
                attempts,
                request_stored,
                [],
                request=request,
                agent_run_id=getattr(result, "run_id", None),
                module="analyst_report",
                phase="analyst_report_overlay",
                timeout_s=float(request.timeout_s),
                max_tokens=int(request.max_tokens),
            )
        except Exception:
            # Telemetry is best-effort. The document key written by the caller is the durable record.
            pass

    def _audit_analyst_overlay_unavailable(
        self,
        task: AnalysisTask,
        reason: str,
        attempts: list[dict[str, object]],
    ) -> None:
        """Record that the report overlay produced nothing, in its own committed transaction.

        NOT CALLED from inside `_overlay_analyst_report_plan`, deliberately. That function runs within the
        caller's `_create_report_revision` transaction, and opening a second session there deadlocks on a
        single-connection engine - the defect that stalled a real run with the analysis thread parked in
        `psycopg connection.wait`. This helper exists so the write can be made from a call site that is NOT
        holding a transaction, and it is currently unused: the durable record of an unavailable overlay is
        `document["analyst_report_unavailable"]`, which the caller persists with the revision itself.
        """
        try:
            with self.database.session_factory.begin() as audit_session:
                self._audit(
                    audit_session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type="report.analyst_overlay_unavailable",
                    actor="system",
                    object_type="AnalysisTask",
                    object_id=task.id,
                    payload={"reason": reason, "attempts": attempts},
                )
        except Exception:
            # The audit write must never be the reason a report fails to publish.
            pass

    @staticmethod
    def _emulation_fallback_payload(output_read_error: str | None) -> dict[str, object]:
        """The row recorded when the emulator returned no usable results - with the REAL cause.

        MEASURED defect this replaces (adversarial defect audit): whatever emptied `results` - including an
        unreadable content-store object - produced the same row asserting `NO_GRANTED_WINDOW` and blaming the
        sample's static recovery ("static recovery did not yield a bounded start-routine window; isolated
        emulation was still attempted"). When the read failed that sentence is FALSE: the emulation ran and its
        output was unreadable, which is a statement about the pipeline, not about the sample. Reachable whenever
        the content store is down (minio reported `InsufficientWriteQuorum` during this session).

        Kept as a pure function of the one input that distinguishes the two cases, so the distinction is
        testable at all - the inline version could only be exercised by driving the whole worker path.
        """
        if output_read_error:
            return {
                "status": "EMULATION_OUTPUT_UNREADABLE",
                "simulator": "unicorn",
                "stop_reason": "EMULATION_OUTPUT_UNREADABLE",
                "limitations": [
                    f"isolated emulation output could not be read ({output_read_error}); the emulation ran but "
                    "its result is unavailable, so this is not evidence about the sample"
                ],
                "anchor": {"type": "controlled_emulation"},
            }
        return {
            "status": "NO_GRANTED_WINDOW",
            "simulator": "unicorn",
            "stop_reason": "NO_GRANTED_WINDOW",
            "limitations": [
                "static recovery did not yield a bounded start-routine window; isolated emulation was still "
                "attempted"
            ],
            "anchor": {"type": "controlled_emulation"},
        }

    @staticmethod
    def _merge_operational_limitations(document, task) -> None:
        return _limitations.merge_operational_limitations(document, task)

    def _overlay_analyst_report_plan(
        self,
        task: AnalysisTask,
        document: dict[str, object],
    ) -> dict[str, object]:
        """Optional LLM chapter overlay at synthesis; never blocks the report.

        DSH-owned investigation planning skips claim enrichment, but the GET
        report is still the analyst-facing artifact.  When the workbench model
        is enabled, use it to retitle or add evidence-grounded chapters.  The
        deterministic catalog planner remains the fallback and the authority
        for dropping ungrounded extras.
        """
        if not self.settings.model_calls_enabled:
            return document
        if str(self.settings.environment or "").lower() == "test":
            return document
        try:
            prompt = self.prompts.require("analyst-report-agent", "1.0.0")
            payload = compact_analyst_context(document)
            messages = tuple(self.prompts.build_messages(prompt, payload))
            request = ModelRequest(
                task_id=task.id,
                case_id=task.case_id,
                trace_id=str(task.trace_id),
                module="analyst_report",
                prompt_id=prompt.id,
                prompt_version=prompt.version,
                prompt_sha256=prompt.sha256,
                messages=messages,
                response_schema=AnalystReportPlanEnvelope,
                # The report overlay is the LAST model turn of a run and the one the analyst actually
                # reads, so it gets the full configured budget. The former 60 s timeout was measured
                # against a non-reasoning model; a reasoning route needs ~22 s of hidden reasoning before
                # it emits anything, which left no margin.
                # PAIRED WITH `max_tokens` BELOW - they are ONE decision, not two.
                #
                # MEASURED: raising the completion budget alone (4096 -> 16384) against this same 180 s
                # deadline failed BOTH attempts with `ReadTimeout` (task `acbb3fd6`) and produced no plan at
                # all, where 4096 had at least returned a plan with `slots` truncated. A larger answer needs a
                # proportionally larger deadline, or the change makes the outcome worse.
                timeout_s=max(float(self.settings.model_timeout_s), 600.0),
                # MEASURED ROOT CAUSE of "the model never wrote the report". This was
                # `min(2048, model_max_tokens)` while the configured route allowed 4096. On the 白象 run
                # `deepseek-v4-pro` consumed all 2048 completion tokens as `reasoning_tokens`, returned
                # `finish_reason=length` with an EMPTY content string, and the failure surfaced only as a
                # schema ValidationError that the handler below discarded - so the published body looked
                # like a deliberate deterministic render while the model call had in fact failed every
                # time. At 4096 the same request returns `finish_reason=stop` and 8 chapters; at 16384 it
                # returns in 22 s. Never clamp a completion budget to a local constant: for a reasoning
                # model the reasoning stream and the answer share the budget.
                #
                # RAISED AGAIN, for the SAME reason, with a second measurement: task `f8b163eb` recorded
                # `input_tokens=7378, output_tokens=4096` - the completion sat EXACTLY on the configured
                # ceiling. The envelope asks for `chapters` first and `slots`/`limitations` after, so the
                # model ran out of budget before it reached `slots`: the plan came back with chapters and
                # `analyst_slot_proposals` was never written. Runs before that were worse still - reasoning
                # prose filled the budget and nothing parsed at all (13,081 characters, no JSON).
                #
                # The prompt grew when the recovered script started travelling with it, so the old ceiling is
                # no longer enough for the answer PLUS the reasoning that shares it.
                #
                # ATTEMPTED AND REVERTED, with the measurement: raising this to
                # `max(configured, 16384)` made things WORSE, not better. Task `acbb3fd6` then failed BOTH
                # attempts with `ReadTimeout` at the configured `timeout_s=180` and produced no plan at all,
                # where 4096 had at least returned a plan (chapters present, `slots` truncated away). The
                # historical "at 16384 it returns in 22 s" was measured on a SMALLER prompt, before the script
                # travelled with the request.
                #
                # So the budget and the timeout are ONE decision, not two: a larger completion budget needs a
                # proportionally larger deadline, and this call site sets both. Raising only the budget
                # converts "truncated answer" into "no answer", which is strictly worse.
                # 8192 rather than 16384: 4096 truncated the envelope before `slots`, but 16384 did not
                # finish inside any deadline this route was given. This is the midpoint that the two
                # measurements bracket, and it is a FLOOR - a route configured for more keeps its own value.
                max_tokens=max(int(self.settings.model_max_tokens), 8192),
                stream=False,
                structured_output=True,
                disable_reasoning=True,
            )
            runtime = AgentRuntime(
                self.model_gateway,
                max_context_bytes=self.settings.model_context_max_bytes,
                cancellation_requested=lambda: self._is_task_cancelled(
                    task.id,
                    # The caller of this overlay is mid-transaction: it has already flushed the report's
                    # snapshot row, which the revision that follows references by foreign key.  Answer the
                    # cancellation probe inside that same transaction so the probe cannot roll it back.
                    observing=object_session(task),
                ),
            )
            result = runtime.run(request)
            # PERSIST THE ATTEMPT, whichever way it went.
            #
            # This overlay called the model but never recorded a `ModelCall`, so the `analyst_report`
            # module had ZERO rows in `model_calls` for EVERY task - measured across the whole database,
            # not just the 白象 run. That is why the 2048-token defect stayed invisible for so long: the
            # only surface that could have reported "the report model was called and returned nothing" was
            # never written. A model turn an operator cannot see is a model turn that can fail forever.
            self._persist_analyst_overlay_attempt(task, prompt, request, result)
            if result.status != "SUCCEEDED" or result.response is None:
                # Record WHY the overlay produced nothing. Returning silently is what made this defect
                # invisible: the body published a complete deterministic report, so a failed model turn
                # was indistinguishable from a deliberate deterministic render, and a run whose
                # `analyst_report` module had ZERO successful calls looked normal. The analyst still gets
                # the deterministic body - the overlay has always been optional - but the reason is now
                # in the document and in the audit trail.
                reason = str(result.error or "MODEL_RESPONSE_MISSING")
                attempts = [
                    {
                        "provider": attempt.provider,
                        "model": attempt.model,
                        "status": attempt.status,
                        "error_type": attempt.error_type,
                        # WHY THE DETAIL IS KEPT, bounded.
                        #
                        # MEASURED: two consecutive runs failed here with `JSONDecodeError` and `ValueError`
                        # and the document recorded only the TYPE. `model_calls` has no `error_detail`
                        # column either, and `response_storage_key` was NULL for both attempts, so the raw
                        # response existed NOWHERE afterwards - the only way to learn what actually came
                        # back was to reproduce the call by hand.
                        #
                        # For a JSON failure the message carries the position and a snippet
                        # ("Expecting value: line 1 column 1" vs "Unterminated string starting at ..."),
                        # which is exactly what distinguishes "the model wrapped its JSON in prose" from
                        # "the answer was cut off at max_tokens". Those two need different fixes, and
                        # without this field the next run cannot tell them apart either.
                        "error_detail": str(getattr(attempt, "error_detail", "") or "")[:600],
                        "http_status": getattr(attempt, "http_status", None),
                        # Token counts are the discriminator between the two candidate causes of a JSON
                        # failure: `output_tokens` at the ceiling means the answer was CUT OFF (fix: shrink
                        # what we ask for), while a low count with a parse error means the model wrapped or
                        # prefixed its JSON (fix: the parser). `model_calls` recorded NULL for both on the
                        # failing runs, so these are captured here instead.
                        "input_tokens": getattr(attempt, "input_tokens", None),
                        "output_tokens": getattr(attempt, "output_tokens", None),
                    }
                    for attempt in (result.attempts or ())
                ]
                if isinstance(document, dict):
                    document["analyst_report_unavailable"] = {
                        "reason": reason,
                        "attempts": attempts,
                        "boundary": (
                            "本章节计划未能由模型生成；正文为确定性渲染结果，未包含模型选题。"
                        ),
                    }
                # The durable record of an unavailable overlay is the document key below. An audit event
                # would need its own transaction, and this call site is inside the caller's
                # `_create_report_revision` transaction, so writing one here deadlocks on a single-connection
                # engine (measured: the run stalled with the analysis thread in `psycopg connection.wait`).
                return document
            parsed = result.response.parsed
            document["analyst_model_plan"] = [
                {
                    "catalog_id": str(item.catalog_id or ""),
                    "title": str(item.title or ""),
                    "evidence_anchors": [
                        str(anchor) for anchor in item.evidence_anchors if str(anchor).strip()
                    ],
                    "notes": str(item.notes or "")[:400],
                }
                for item in parsed.chapters[:12]
            ]
            if parsed.limitations:
                document["analyst_report_limitations"] = [
                    str(item)[:400] for item in parsed.limitations[:16]
                ]
            # OPERATIONAL limitations must reach the reader too; see `_merge_operational_limitations`, which
            # owns the reasoning and is unit-tested directly because this function's upstream branches cannot be
            # driven in isolation.
            self._merge_operational_limitations(document, task)
            if parsed.slots:
                # MODEL SLOT PROPOSALS ARE VERIFIED AT PERSISTENCE TIME, NOT AT RENDER TIME.
                #
                # Why the distinction is load-bearing: replacing `UNKNOWN(slot)` inside `_slot_display`
                # would be render-time promotion - turning a candidate into an in-body fact at the last
                # moment, forbidden by the behavior plan (§5:157) and already done once by
                # `creation_flags_from_callsite`. Verifying HERE means the decision is recorded, the appendix
                # can audit both the accepted and the rejected ones, and the renderer only ever reads a
                # decision that was already made.
                #
                # WHAT ACTUALLY RUNS HERE, stated without flattery: the ONLY check is
                # `verify_model_slot_proposals` - corpus membership plus a literal substring test. It does NOT
                # check that the substring means what the proposal says it means.
                #
                # An earlier version of this comment said "the Claim Gate sees the proposal". THAT WAS
                # FALSE. The real gate (`investigation.py`, `class ClaimGate`) rejects evidence whose nature
                # is outside its scope, so wiring it here would require MANUFACTURING an Evidence row for a
                # bare substring - i.e. inventing evidence to satisfy a gate. That is why the honest move is
                # the opposite one: keep the substring test as the only check, and say so. A comment that
                # claims a gate which does not run is worse than no comment, because it is what a future
                # reader will trust instead of re-checking.
                #
                # No cap on how many survive: the count emerges from how many carry a real substring.
                supported, rejected = verify_model_slot_proposals(
                    [item.model_dump() for item in parsed.slots],
                    slot_evidence_corpora(document),
                )
                document["analyst_slot_proposals"] = {
                    "supported": supported,
                    "rejected": rejected,
                    "boundary": (
                        "槽位提案由模型提出、经字面子串校验后于**持久化期**写入；"
                        # NOT "状态为 CANDIDATE": CANDIDATE is a CLAIM status (CONTEXT.md) and a slot
                        # proposal is not a claim - it carries no evidence_id. Calling it one would be
                        # cross-layer promotion by field name (behavior plan §12.5 item 1). What was
                        # actually checked is the support kind, and that is what this says.
                        "通过者的支撑方式为 `substring_matched`（字面匹配，未核对含义），不是已验证事实；"
                        "校验只证明该子串存在于所指语料，不证明其含义。"
                    ),
                }
        except Exception as exc:
            # Same reasoning as above, for the raised path: an exception here used to vanish entirely.
            if isinstance(document, dict):
                document["analyst_report_unavailable"] = {
                    "reason": f"{type(exc).__name__}: {str(exc)[:300]}",
                    "attempts": [],
                    "boundary": (
                        "本章节计划未能由模型生成；正文为确定性渲染结果，未包含模型选题。"
                    ),
                }
            return document
        return document

    @staticmethod
    def _apply_honest_analysis_outcome(task: AnalysisTask, document: dict[str, object]) -> None:
        """C10: a minted report is not COMPLETE when the critic or depth is bounded."""
        quality = document.get("analysis_quality")
        if not isinstance(quality, dict):
            quality = {}
        critic = quality.get("critic") if isinstance(quality.get("critic"), dict) else {}
        critic_status = str(critic.get("status") or "").upper()
        readiness = str(quality.get("readiness") or "").upper()
        s4_rows = quality.get("s4_orchestration")
        blocked_s4 = False
        if isinstance(s4_rows, list):
            blocked_s4 = any(
                isinstance(row, dict) and str(row.get("status") or "").upper() == "BLOCKED"
                for row in s4_rows
            )
        outcome = str(document.get("analysis_outcome") or getattr(task, "outcome", "") or "").upper()
        analysis_class = str(
            getattr(task, "analysis_class", None) or document.get("analysis_class") or ""
        )
        bounded = (
            critic_status == "BLOCKED"
            or blocked_s4
            or (readiness != "" and readiness != "READY_FOR_REPORT")
            or analysis_class in {"BOUNDED_STATIC_ANALYSIS", "FAILED_ANALYSIS"}
        )
        if bounded and outcome == "COMPLETE":
            document["analysis_outcome"] = AnalysisOutcome.PARTIAL.value
            task.outcome = AnalysisOutcome.PARTIAL.value

    @staticmethod
    def _t6_trace_gains(
        parent_document: Mapping[str, object] | None,
        document: Mapping[str, object] | None,
    ) -> list[str]:
        """T6: new relations are gains. Extra ToolRuns or evidence rows are not."""
        if not isinstance(parent_document, Mapping) or not isinstance(document, Mapping):
            return []
        parent_trace = parent_document.get("trace")
        current_trace = document.get("trace")
        if not isinstance(parent_trace, Mapping) or not isinstance(current_trace, Mapping):
            return []
        gains: list[str] = []
        for key, token in (
            ("relation_ids", "relation"),
            ("behavior_relation_ids", "behavior_relation"),
        ):
            before = {str(item) for item in (parent_trace.get(key) or []) if item}
            after = {str(item) for item in (current_trace.get(key) or []) if item}
            if after - before:
                gains.append(f"new_{token}")
        return gains

    @staticmethod
    def _t6_revision_diff_payload(
        parent_markdown: str | None,
        markdown: str,
        parent_document: Mapping[str, object] | None = None,
        document: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        """T6: new HOW/relation/bytes vs parent. Word or action count is never a gain."""
        if not parent_markdown:
            return {
                "parent_present": False,
                "gains": [],
                "substantive": False,
                "word_count_delta_is_not_gain": True,
                "action_count_delta_is_not_gain": True,
            }
        gains = list(official_revision_semantic_gains(parent_markdown, markdown))
        gains.extend(AnalysisService._t6_trace_gains(parent_document, document))
        return {
            "parent_present": True,
            "gains": gains[:32],
            "substantive": bool(gains),
            "word_count_delta_is_not_gain": True,
            "action_count_delta_is_not_gain": True,
        }

    def create_report_revision(self, session: Session, task: AnalysisTask, snapshot: AnalysisSnapshot, modules: list[str], *, parent_revision_id: str | None = None, author: str = 'system') -> ReportRevision:
        """Public behaviour entry point for `_create_report_revision` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private method stays the implementation, and the facade delegates to it so a test that still
        replaces the private attribute keeps working.
        """
        return self._create_report_revision(session, task, snapshot, modules, parent_revision_id=parent_revision_id, author=author)


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
        return _revision_writer._create_report_revision(
            self,
            session,
            task,
            snapshot,
            modules,
            parent_revision_id=parent_revision_id,
            author=author,
        )

    @staticmethod
    def canonical_json(value: object) -> str:
        """Public behaviour entry point for `_canonical_json` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private staticmethod stays the implementation and the facade delegates to it.
        """
        return AnalysisService._canonical_json(value)


    @staticmethod
    def _canonical_json(value: object) -> str:
        return json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str
        )

    #: Canonical-JSON leaves larger than this are hashed in bounded slices so a
    #: several-hundred-megabyte snapshot never needs a second full-size copy.
    _CANONICAL_CHUNK_BYTES = 8 * 1024 * 1024

    @classmethod
    def _canonical_encode(cls, value: object) -> bytes:
        return json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")

    @staticmethod
    def _canonical_slices(encoded: bytes, budget: int) -> Iterable[bytes]:
        if len(encoded) <= budget:
            yield encoded
            return
        for start in range(0, len(encoded), budget):
            yield encoded[start : start + budget]

    @classmethod
    def canonical_json_chunks(cls, value: object, *, exclude_keys: Iterable[str] = (), chunk_bytes: int | None = None) -> Iterable[bytes]:
        """Public behaviour entry point for `_canonical_json_chunks` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private classmethod stays the implementation and the facade delegates to it.
        """
        return cls._canonical_json_chunks(value, exclude_keys=exclude_keys, chunk_bytes=chunk_bytes)


    @classmethod
    def _canonical_json_chunks(
        cls,
        value: object,
        *,
        exclude_keys: Iterable[str] = (),
        chunk_bytes: int | None = None,
    ) -> Iterable[bytes]:
        """Yield the canonical JSON encoding of ``value`` in bounded chunks.

        Byte-identical to ``_canonical_json(value).encode("utf-8")`` - that is the
        digest 16 GB of already-sealed snapshots were written with - but the whole
        document is never held as one string plus one bytes copy.

        ``json``'s C encoder still does all leaf encoding: a pure-Python chunked
        encoder measured 11.8 s against 0.93 s of ``json.dumps`` on a real 116 MB
        payload, which is a far worse trade than the peak memory it saves.  Only
        the top-level mapping and list-shaped sections (Evidence and friends) are
        assembled here, so a 600 MB Evidence ledger is emitted row by row.
        ``exclude_keys`` drops the named top-level keys, mirroring the
        ``payload.pop("content_sha256", None)`` that used to precede hashing.
        """
        budget = int(chunk_bytes or cls._CANONICAL_CHUNK_BYTES)
        if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
            excluded = set(exclude_keys)
            yield b"{"
            first = True
            for key in sorted(value):
                if key in excluded:
                    continue
                if not first:
                    yield b","
                first = False
                yield json.dumps(key, ensure_ascii=True).encode("utf-8")
                yield b":"
                yield from cls._canonical_section_chunks(value[key], budget)
            yield b"}"
            return
        yield from cls._canonical_section_chunks(value, budget)

    @classmethod
    def _canonical_section_chunks(cls, value: object, budget: int) -> Iterable[bytes]:
        """Encode one payload section, row by row when it is a list of rows."""
        if isinstance(value, (list, tuple)):
            yield b"["
            for index, item in enumerate(value):
                if index:
                    yield b","
                yield from cls._canonical_slices(cls._canonical_encode(item), budget)
            yield b"]"
            return
        yield from cls._canonical_slices(cls._canonical_encode(value), budget)

    @classmethod
    def canonical_sha256(cls, value: object, *, exclude_keys: Iterable[str] = ()) -> str:
        """Public behaviour entry point for `_canonical_sha256` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private classmethod stays the implementation and the facade delegates to it.
        """
        return cls._canonical_sha256(value, exclude_keys=exclude_keys)


    @classmethod
    def _canonical_sha256(cls, value: object, *, exclude_keys: Iterable[str] = ()) -> str:
        """sha256 of the canonical JSON bytes, computed without materialising them."""
        return _revision_writer._canonical_sha256(cls, value, exclude_keys=exclude_keys)

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

    def audit(self, session: Session, *, case_id: str | None, event_type: str, actor: str, object_type: str, object_id: str, payload: dict[str, object], task_id: str | None = None) -> AuditEvent:
        """Public behaviour entry point for `_audit` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private method stays the implementation, and the facade delegates to it so a test that still
        replaces the private attribute keeps working.
        """
        return self._audit(session, case_id=case_id, event_type=event_type, actor=actor, object_type=object_type, object_id=object_id, payload=payload, task_id=task_id)


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

        # A large static run emits one audit event per immutable row. Reusing
        # the row already locked in this transaction avoids an extra
        # SELECT ... FOR UPDATE for every Evidence/Claim while preserving the
        # same monotonic sequence and hash chain semantics.
        audit_heads = session.info.setdefault("_threat_audit_heads", {})
        head = audit_heads.get(scope_key)
        if head is None:
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
        audit_heads[scope_key] = head
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
                            [
                                item.event_hash
                                for item in sorted(
                                    scoped_events, key=lambda row: row.chain_sequence
                                )
                            ]
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
                    [
                        item.event_hash
                        for item in sorted(scoped_events, key=lambda row: row.chain_sequence)
                    ]
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
            and task.lifecycle
            in {
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
                    select(Artifact).where(Artifact.id.in_(attached_ids))
                    if attached_ids
                    else select(Artifact).where(False)
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
            "context_revision": context.context_revision
            if hasattr(context, "context_revision")
            else 1,
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
        return _task_runner.bind_historical_analysis(self, dsh_session_id, task_id, actor=actor)

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
                "analysis_planner": self._analysis_planner_payload(),
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
            artifact_rows = session.scalars(select(Artifact).where(Artifact.id.in_(artifact_ids)))
            by_id = {item.id: item for item in artifact_rows}
            artifacts = [
                self._context_artifact_payload(by_id[item])
                for item in artifact_ids
                if item in by_id
            ]
        model_calls: list[ModelCall] = []
        if task is not None:
            model_calls = list(
                session.scalars(
                    select(ModelCall)
                    .where(ModelCall.task_id == task.id)
                    .order_by(ModelCall.created_at.desc(), ModelCall.id.desc())
                    .limit(8)
                )
            )
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
            "analysis_planner": self._analysis_planner_payload(failure, model_calls),
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
                    next_state = self._context_state_for_task_v3(task.lifecycle)
                    next_lifecycle = task.lifecycle
                    next_analysis_class = task.analysis_class
                    next_outcome = task.outcome
                    # Context reads are on the hot path of the bounded wait
                    # endpoint.  Do not turn an unchanged read into a write
                    # transaction merely by refreshing ``updated_at``; this
                    # needlessly contends with append-heavy evidence writes.
                    if (
                        row.state != next_state
                        or row.task_lifecycle != next_lifecycle
                        or row.analysis_class != next_analysis_class
                        or row.task_outcome != next_outcome
                    ):
                        row.state = next_state
                        row.task_lifecycle = next_lifecycle
                        row.analysis_class = next_analysis_class
                        row.task_outcome = next_outcome
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
            case = session.get(CaseRecord, case_id) if case_id else None
            if case is None:
                # DSH models often invent placeholder IDs such as "default".
                # A missing case must not block the 3080 attach/import path.
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
                triage = self.triage_agent.triage(
                    clean_name,
                    identity.detected_type,
                    is_container=zipfile.is_zipfile(io.BytesIO(content)),
                )
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
                    payload={
                        "dsh_session_id": session_id,
                        "logical_path": clean_name,
                        "sha256": stored.sha256,
                    },
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
                    raise ContextMismatchError(
                        "CONTEXT_MISMATCH: artifact is not attached to session"
                    )
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
                    preset_id=(
                        "first-phase-full-static"
                        if source_kind == "zip"
                        else "single-sample-static-deep"
                    ),
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
                strategy_snapshot={"planning_owner": "dsh"},
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
                payload={
                    "dsh_session_id": session_id,
                    "artifact_id": artifact.id,
                    "static_only": True,
                },
            )
            row.binding_event_id = event.id
            return self._context_payload_v3(session, session_id, row) | {
                "created": True,
                "task_id": task.id,
                "artifact_id": artifact.id,
            }

    def workbench_dispatch_analysis_intent(
        self,
        dsh_session_id: str,
        *,
        question: str,
        actor: str = "dsh",
    ) -> dict[str, object]:
        """Kunglao DISPATCH: start analysis from the user question, not a model tool.

        Upload still does not start a task. A first-turn analyze request with
        one attached artifact or exactly one workspace candidate starts the
        bounded static queue before the chat model answers. In-flight and
        already-bound sessions are left alone when they already hold that
        same sample, so wait loops cannot spawn a second task. A leftover
        binding of a *different* file must not block the single workspace
        candidate: 3080 「分析这个样本」 would otherwise wait on a reused
        session's earlier task instead of importing the candidate the user
        actually attached. No sample name is special-cased here.
        Zero or multiple workspace candidates stay UNBOUND.
        """
        session_id = self._require_session_id(dsh_session_id)
        if not analysis_intent_question(question):
            return self.workbench_analysis_context_v3(session_id) | {
                "dispatched": False,
                "created": False,
                "reason": "NOT_ANALYSIS_INTENT",
            }
        context = self.workbench_analysis_context_v3(session_id)
        candidates = self._workspace_intent_candidates(session_id)
        single = candidates[0] if len(candidates) == 1 else None
        if single and not self._bound_artifacts_match_workspace_candidate(context, single):
            if context.get("active_task_id") or context.get("attached_artifact_ids"):
                self.workbench_unbind_analysis(
                    session_id, actor=actor, discard_staged=True
                )
                context = self.workbench_analysis_context_v3(session_id)
        lifecycle = str(context.get("task_lifecycle") or "")
        if context.get("active_task_id") and lifecycle in _IN_FLIGHT_TASK_LIFECYCLES:
            return context | {
                "dispatched": False,
                "created": False,
                "reason": "ALREADY_RUNNING",
            }
        if context.get("active_task_id"):
            return context | {
                "dispatched": False,
                "created": False,
                "reason": "ALREADY_BOUND",
            }
        imported_relative_path = ""
        if not context.get("attached_artifact_ids"):
            try:
                listing = self.workbench_list_workspace_artifacts(
                    session_id, relative_dir=".", limit=64
                )
            except LookupError:
                listing = {"items": []}
            candidates = [
                item
                for item in listing.get("items") or ()
                if isinstance(item, Mapping) and item.get("candidate")
            ]
            if len(candidates) != 1:
                return context | {
                    "dispatched": False,
                    "created": False,
                    "reason": "SAMPLE_SELECTION_REQUIRED",
                    "workspace_candidate_count": len(candidates),
                }
            imported = self.workbench_import_workspace_artifact(
                session_id,
                relative_path=str(candidates[0].get("relative_path") or ""),
                actor=actor,
            )
            imported_relative_path = str(imported.get("source_relative_path") or "")
        started = self.workbench_start_static_analysis(session_id, actor=actor)
        return started | {
            "dispatched": bool(started.get("created")),
            "reason": "DISPATCHED" if started.get("created") else "ALREADY_BOUND",
            "imported_relative_path": imported_relative_path,
        }

    def _workspace_intent_candidates(self, session_id: str) -> list[Mapping[str, object]]:
        try:
            listing = self.workbench_list_workspace_artifacts(
                session_id, relative_dir=".", limit=64
            )
        except (LookupError, ValueError):
            return []
        return [
            item
            for item in listing.get("items") or ()
            if isinstance(item, Mapping) and item.get("candidate")
        ]

    @staticmethod
    def _bound_artifacts_match_workspace_candidate(
        context: Mapping[str, object],
        candidate: Mapping[str, object],
    ) -> bool:
        wanted = {
            str(candidate.get("name") or "").casefold(),
            str(candidate.get("relative_path") or "").casefold(),
            str(candidate.get("relative_path") or "").rsplit("/", 1)[-1].casefold(),
        }
        wanted.discard("")
        for item in context.get("attached_artifacts") or ():
            if not isinstance(item, Mapping):
                continue
            path = str(item.get("logical_path") or "").replace("\\", "/").casefold()
            if path in wanted or path.rsplit("/", 1)[-1] in wanted:
                return True
        return False

    def analysis_progress(self, task_id: str, *, after_seq: int = 0) -> dict[str, object]:
        """Public behaviour entry point for `_analysis_progress` (P3.7).

        WHY IT EXISTS: the test surface reached this behaviour by its PRIVATE name. Callers outside the class use
        this name; the private method stays the implementation, and the facade delegates to it so a test that still
        replaces the private attribute keeps working.
        """
        return self._analysis_progress(task_id, after_seq=after_seq)


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
            threads_total = (
                session.query(InvestigationThreadRecord)
                .filter(InvestigationThreadRecord.task_id == task_id)
                .count()
            )
            threads_active = (
                session.query(InvestigationThreadRecord)
                .filter(
                    InvestigationThreadRecord.task_id == task_id,
                    InvestigationThreadRecord.state.in_(("INVESTIGATING", "VERIFYING")),
                )
                .count()
            )
            mechanisms_verified = (
                session.query(Claim)
                .filter(Claim.task_id == task_id, Claim.status.in_(("VERIFIED", "SUPPORTED")))
                .count()
            )
            mechanisms_candidate = (
                session.query(Claim)
                .filter(Claim.task_id == task_id, Claim.status == "CANDIDATE")
                .count()
            )
            # Claims and investigation snapshots are two projections of the
            # same semantic result. Prefer the richer snapshot verifier state
            # and never count a mechanism twice or call a merely supported
            # claim "verified" unless its verifier explicitly accepted it.
            investigation = (task.strategy_snapshot or {}).get("investigation", {})
            snapshot_mechanisms = (
                investigation.get("mechanisms", []) if isinstance(investigation, dict) else []
            )
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
                    1
                    for item in snapshot_mechanisms
                    if isinstance(item, dict) and str(item.get("status", "")).upper() == "CANDIDATE"
                ),
            )
            new_evidence_since_last = (
                session.query(AuditEvent)
                .filter(
                    AuditEvent.task_id == task_id,
                    AuditEvent.object_type == "Evidence",
                    AuditEvent.chain_sequence > after_seq,
                )
                .count()
            )
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

    _ANALYSIS_WAIT_MAX_SECONDS = 180
    _WAIT_TERMINAL_STATES = frozenset({"ANALYSIS_READY", "ANALYSIS_FAILED", "ANALYSIS_CANCELLED"})
    _WAIT_ACTIVE_STATES = frozenset({"ANALYSIS_QUEUED", "ANALYSIS_RUNNING"})
    _WAIT_NOISE_EVENT_TYPES = frozenset({
        "evidence.recorded",
        "orchestration.action_dequeued",
        "orchestration.action_enqueued",
    })
    _WAIT_CONTEXT_KEYS = (
        "session_id",
        "state",
        "status",
        "code",
        "active_task_id",
        "task_lifecycle",
        "task_outcome",
        "elapsed_ms",
        "context_revision",
        "failure",
    )

    @classmethod
    def _compact_wait_context(cls, context: Mapping[str, object] | None) -> dict[str, object]:
        source = context or {}
        return {
            key: source.get(key)
            for key in cls._WAIT_CONTEXT_KEYS
            if source.get(key) is not None
        }

    @classmethod
    def _wait_event_counts(cls, events: list[object]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for event in events:
            name = str(getattr(event, "event_type", "") or "unknown")
            counts[name] = counts.get(name, 0) + 1
        return counts

    def _wait_tool_payload(
        self,
        *,
        session_id: str,
        context: Mapping[str, object] | None,
        after_seq: int,
        next_seq: int,
        timed_out: bool,
        event_counts: Mapping[str, int],
        last_meaningful: Mapping[str, object] | None,
        task_id: object,
    ) -> dict[str, object]:
        progress = (
            self._analysis_progress(str(task_id), after_seq=after_seq)
            if task_id
            else {
                "state": (context or {}).get("state"),
                "progress_revision": (context or {}).get("context_revision", 0),
                "changed": False,
                "server_time": utcnow().isoformat(),
            }
        )
        payload = {
            "schema_version": 1,
            "session_id": session_id,
            "changed": int(next_seq) > int(after_seq),
            "context": self._compact_wait_context(context),
            "events": [],
            "event_counts": dict(event_counts),
            "last_meaningful_event": last_meaningful,
            "next_seq": int(next_seq),
            "progress": progress,
            **self._wait_continuation(context, timed_out=timed_out, next_seq=next_seq),
        }
        if payload.get("convergence") == "CONVERGED" and task_id:
            dumped = self._leftover_official_report_dump(str(task_id))
            if dumped:
                payload.update(dumped)
                self._apply_incomplete_leftover_wait_instruction(payload)
        self._remember_wait_cursor(session_id, context, int(next_seq))
        return payload

    def _leftover_official_report_dump(self, task_id: str) -> dict[str, object]:
        """Kunglao leftover dump: CONVERGED remainder is the official revision."""
        try:
            view = self.workbench_domain_view(task_id)
            report = view.get("report") if isinstance(view, Mapping) else {}
            if not isinstance(report, Mapping):
                report = {}
            revision_id = str(report.get("revision_id") or "").strip()
            if not revision_id:
                return {}
            revision = self.get_report_revision(revision_id)
            markdown = str(revision.get("markdown") or "")
            if not markdown.strip():
                return {}
            document = revision.get("document") if isinstance(revision, Mapping) else {}
            quality = document.get("analysis_quality") if isinstance(document, Mapping) else {}
            readiness = (
                quality.get("one_round_readiness") if isinstance(quality, Mapping) else {}
            )
            if not isinstance(readiness, Mapping):
                readiness = {}
            complete = bool(readiness.get("complete", True)) and not readiness.get("violations")
            return {
                "task_id": task_id,
                "report_available": True,
                "report_revision_id": revision_id,
                "authoritative_revision_id": revision_id,
                "content": markdown,
                "one_round_complete": complete,
                "one_round_readiness": dict(readiness),
            }
        except (LookupError, TypeError, ValueError, AttributeError):
            return {}

    @classmethod
    def _apply_incomplete_leftover_wait_instruction(
        cls,
        payload: dict[str, object],
    ) -> None:
        """Incomplete leftover dump is copyable PARTIAL, not a finished one-round answer."""
        if payload.get("one_round_complete") is not False:
            return
        payload["convergence"] = "CONVERGED"
        payload["instruction"] = (
            "PARTIAL leftover dump is in content. Copy How / Unique OS "
            "/ Unknowns, quote authoritative_revision_id. "
            "one_round_complete is false; this is not the finished "
            "one-round answer. Do not ask 再深入."
        )

    def _floor_wait_cursor(
        self,
        session_id: str,
        context: Mapping[str, object] | None,
        after_seq: int,
    ) -> int:
        """Refuse to rewind wait; kunglao wait-signal owns the cursor."""
        task_id = str((context or {}).get("active_task_id") or "")
        cursors = getattr(self, "_wait_cursors", None)
        if not isinstance(cursors, dict) or not task_id:
            return after_seq
        stored_task, stored_seq = cursors.get(session_id, ("", 0))
        if stored_task == task_id and int(stored_seq) > after_seq:
            return int(stored_seq)
        return after_seq

    def _remember_wait_cursor(
        self,
        session_id: str,
        context: Mapping[str, object] | None,
        next_seq: int,
    ) -> None:
        task_id = str((context or {}).get("active_task_id") or "")
        if not task_id:
            return
        cursors = getattr(self, "_wait_cursors", None)
        if not isinstance(cursors, dict):
            self._wait_cursors = {}
            cursors = self._wait_cursors
        stored_task, stored_seq = cursors.get(session_id, ("", 0))
        if stored_task != task_id or int(next_seq) > int(stored_seq):
            cursors[session_id] = (task_id, int(next_seq))

    @classmethod
    def _wait_continuation(
        cls,
        context: Mapping[str, object] | None,
        *,
        timed_out: bool,
        next_seq: int,
    ) -> dict[str, object]:
        """Tell the conversation whether another wait is required.

        A 30s idle timeout is not a terminal analysis result. Resume/ComHost
        first-round work outlasts one wait; the tool result must say so.
        """
        state = str((context or {}).get("state") or "")
        must_continue = state in cls._WAIT_ACTIVE_STATES
        if must_continue:
            convergence = "SATURATED"
            instruction = (
                f"SATURATED: task is still {state}. Immediately call "
                "threat_wait_for_analysis_update with "
                f"after_event_seq={int(next_seq)}. Do not narrate progress, "
                "do not list event counts, and do not write a factual report "
                "until the task is terminal."
            )
        elif state in cls._WAIT_TERMINAL_STATES:
            failed = state in {"ANALYSIS_FAILED", "ANALYSIS_CANCELLED"}
            convergence = "BLOCKED" if failed else "CONVERGED"
            instruction = (
                "BLOCKED: task is terminal. Call threat_get_report_summary "
                "and cite authoritative_revision_id from that tool result. "
                "Do not summarize from wait heartbeats."
                if failed
                else (
                    "CONVERGED leftover dump is in content. Copy How / Unique OS "
                    "/ Unknowns, quote authoritative_revision_id, and do not ask "
                    "再深入. Honor one_round_complete from this payload. Call "
                    "threat_get_report_summary only if content is missing."
                )
            )
        else:
            convergence = "IDLE"
            instruction = ""
        return {
            "wait_status": "timed_out" if timed_out else "updated",
            "must_continue_waiting": must_continue,
            "next_after_event_seq": int(next_seq),
            "convergence": convergence,
            "instruction": instruction,
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
        context = self.workbench_analysis_context_v3(session_id)
        after_seq = self._floor_wait_cursor(session_id, context, after_seq)
        timeout_seconds = max(0, min(int(timeout_seconds), self._ANALYSIS_WAIT_MAX_SECONDS))
        deadline = time.monotonic() + timeout_seconds
        # Keep the public wait endpoint event-driven without making every
        # connected browser hit the session/context and audit tables four
        # times per second for the entire timeout.  The short first delay
        # keeps interactive updates responsive; the bounded backoff controls
        # idle CPU/DB load and remains friendly to SQLite development mode.
        poll_delay = 0.05
        max_poll_delay = 1.0
        # The event query is already scoped to the bound task and is cheap to
        # repeat.  Refreshing the full session projection on every backoff,
        # however, performs an extra transaction (and used to rewrite the
        # projection even when nothing changed).  Keep the binding probe
        # authoritative within a short bounded window while avoiding one
        # context read per event query.
        next_context_refresh = time.monotonic() + max_poll_delay
        caller_after_seq = after_seq
        cursor = after_seq
        event_counts: dict[str, int] = {}
        last_meaningful: dict[str, object] | None = None
        while True:
            now = time.monotonic()
            if now >= next_context_refresh:
                context = self.workbench_analysis_context_v3(session_id)
                next_context_refresh = now + max_poll_delay
            task_id = context.get("active_task_id")
            if task_id:
                with self.database.session_factory() as session:
                    events = list(
                        session.scalars(
                            select(AuditEvent)
                            .where(
                                AuditEvent.task_id == str(task_id),
                                AuditEvent.chain_sequence > cursor,
                            )
                            .order_by(AuditEvent.chain_sequence)
                            .limit(64)
                        )
                    )
                if events:
                    last_seq = int(events[-1].chain_sequence)
                    if last_seq > cursor:
                        for name, count in self._wait_event_counts(events).items():
                            event_counts[name] = event_counts.get(name, 0) + count
                        meaningful = [
                            event
                            for event in events
                            if str(event.event_type or "") not in self._WAIT_NOISE_EVENT_TYPES
                        ]
                        terminal = str(context.get("state") or "") in self._WAIT_TERMINAL_STATES
                        if meaningful or terminal:
                            context = self.workbench_analysis_context_v3(session_id)
                            if meaningful:
                                last = meaningful[-1]
                                last_meaningful = {
                                    "seq": int(last.chain_sequence),
                                    "type": str(last.event_type or ""),
                                }
                            return self._wait_tool_payload(
                                session_id=session_id,
                                context=context,
                                after_seq=caller_after_seq,
                                next_seq=last_seq,
                                timed_out=False,
                                event_counts=event_counts,
                                last_meaningful=last_meaningful,
                                task_id=task_id,
                            )
                        cursor = last_seq
                        continue
            if time.monotonic() >= deadline:
                return self._wait_tool_payload(
                    session_id=session_id,
                    context=context,
                    after_seq=caller_after_seq,
                    next_seq=cursor,
                    timed_out=True,
                    event_counts=event_counts,
                    last_meaningful=last_meaningful,
                    task_id=task_id,
                )
            remaining = max(0.0, deadline - time.monotonic())
            time.sleep(min(poll_delay, remaining))
            poll_delay = min(max_poll_delay, poll_delay * 2.0)

    def workbench_analysis_status(self, dsh_session_id: str) -> dict[str, object]:
        context = self.workbench_analysis_context_v3(dsh_session_id)
        task_id = context.get("active_task_id")
        progress = (
            self._analysis_progress(str(task_id))
            if task_id
            else {
                "state": context.get("state"),
                "progress_revision": context.get("context_revision", 0),
                "changed": False,
                "last_event_seq": 0,
                "server_time": utcnow().isoformat(),
            }
        )
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
            rows.append(
                {
                    "relative_path": relative,
                    "name": path.name,
                    "size": path.stat().st_size,
                    "detected_type": identity.detected_type,
                    "mime_type": identity.mime_type,
                    "candidate": identity.detected_type != "unknown",
                }
            )
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
        return _task_runner.workbench_bind_existing_analysis(self, dsh_session_id, task_id, actor=actor)

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

    def workbench_submit_analyst_draft(
        self,
        dsh_session_id: str,
        markdown: str,
        *,
        actor: str = "dsh-agent",
    ) -> dict[str, object]:
        """Session-scoped entry point for an agent-authored report narrative.

        The DSH client refuses any path outside ``/api/v1/workbench/``, so the
        agent cannot reach the analyst-facing ``/api/v1/reports/{id}/analyst-draft``
        route directly.  This resolves the session's authoritative task and its
        newest revision, then defers to :meth:`submit_analyst_draft`, which is
        where 报告合成门 (ADR-0036) is enforced.
        """
        return _revision_writer.workbench_submit_analyst_draft(self, dsh_session_id, markdown, actor=actor)

    def workbench_write_report_file(
        self,
        dsh_session_id: str,
        *,
        filename: str,
        markdown: str,
        actor: str = "dsh-agent",
    ) -> dict[str, object]:
        """Write an agent-authored report file into the deployment's report root.

        The analyst deliverable is a document, and an agent produces documents by
        writing files -- not by pasting them into a chat reply. DSH's own file
        tools are disabled by the host bundle and could not be re-enabled from a
        preset, so the product provides the one write it actually needs, bounded
        to a single directory.

        Bounded on purpose: a flat basename ending in ``.md`` under
        ``REPORT_OUTPUT_ROOT``. No traversal, no absolute path, no subdirectory,
        no overwriting outside that root. The sample workspace stays read-only.

        The same text is then published as the official report revision through
        :meth:`workbench_submit_analyst_draft`, because writing only the file let
        the two artifacts drift: for task ``2fcc0fdc-ae32-4efd-83e6-a6c9fbc734db``
        the file held a 29,584-byte execution timeline while the newest
        ``report_revisions`` row held a 6,254-character digest, so a consumer of
        the official route never saw the analysis.

        The write stays authoritative and the gate cannot defeat it: 报告合成门
        (ADR-0036) governs what may become the official body, not whether the
        agent keeps its own work product, so a rejected draft is reported in the
        payload (``published``/``gate_violations``) and the path and size are
        still returned. No ungated text can reach a revision either way --
        :meth:`submit_analyst_draft` raises before it inserts one.
        """
        raw_name = str(filename or "").strip()
        if not raw_name:
            raise ValueError("filename is required")
        if raw_name != os.path.basename(raw_name) or "/" in raw_name or "\\" in raw_name:
            raise ValueError("filename must be a plain file name, not a path")
        if raw_name.startswith("."):
            raise ValueError("filename must not start with a dot")
        if not raw_name.casefold().endswith((".md", ".markdown")):
            raise ValueError("report file must be markdown (.md)")
        text = str(markdown or "")
        if not text.strip():
            raise ValueError("report markdown must not be empty")
        link = self.workbench_task_for_session(dsh_session_id)
        if not link:
            raise ValueError("no authoritative task is bound to this session")
        root = Path(os.getenv("REPORT_OUTPUT_ROOT", "/reports"))
        try:
            root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ValueError(f"report root is not writable: {exc}") from exc
        target = root / raw_name
        try:
            target.write_text(text, encoding="utf-8", newline="\n")
        except OSError as exc:
            raise ValueError(f"report file could not be written: {exc}") from exc
        payload: dict[str, object] = {
            "schema_version": 1,
            "task_id": str(link.get("task_id") or ""),
            "path": str(target),
            "filename": raw_name,
            "bytes": len(text.encode("utf-8")),
            "written": True,
        }
        # Publish the same text as the official body. The file is authoritative
        # and already on disk, so every domain-level refusal is reported in the
        # payload instead of raised: a caller that got an exception would not
        # learn the path and size of the file it just wrote. Unexpected errors
        # (database outage, programming faults) still propagate loudly.
        try:
            revision = self.workbench_submit_analyst_draft(
                dsh_session_id, text, actor=actor
            )
        except ReportComposeGateRejected as exc:
            # The file keeps the raw draft; the official body never does. The
            # gate runs before the revision insert, so nothing published here.
            payload["published"] = False
            payload["revision_id"] = None
            payload["gate_violations"] = list(exc.violations)
        except (ValueError, LookupError) as exc:
            # The session is bound (the write resolved it) but has no revision
            # to chain from, or the bound row disappeared mid-call.
            payload["published"] = False
            payload["revision_id"] = None
            payload["publish_error"] = str(exc)
        else:
            payload["published"] = True
            payload["revision_id"] = str(revision.get("id") or "") or None
        return payload

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
            "action_type",
            "status",
            "state",
            "hypothesis_status",
            "gate_status",
            "evidence_count",
            "evidence_ids",
            "action_id",
            "thread_id",
            "hypothesis_id",
            "mechanism_id",
            "claim_id",
            "relation_id",
            "report_revision_id",
            "reason",
            "missing",
            "contradictions",
            "tool",
            "model",
            "provider",
            "profile",
            "origin",
            "planner_turn_id",
            "model_call_id",
            "model_run_id",
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

    def workbench_events(
        self, task_id: str, *, after_seq: int = 0, limit: int = 500
    ) -> dict[str, object]:
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

    def workbench_capabilities(
        self, catalog: ActionCatalog | None = None
    ) -> dict[str, object]:
        # P3.6-2 DECISION (docs/p36-capability-slice-design-20260922.md section 6.3, option (c)): the catalog is
        # CONSTRUCTED HERE and passed in, not imported by `workbench_query`. Importing `ActionCatalog` from
        # `threat_report_agent.investigation` inside that module would add a `workbench_query -> investigation` edge
        # that `check-import-graph.py --strict` cannot police: the gate's registration check is per-NODE and its
        # deny-list names no pair with `workbench_query` as the source, so the edge would pass every gate green
        # (`docs/import-policy.json` `_recorded_allowed_edges_note` states that blind spot). This module already owns
        # the import (`from threat_report_agent.investigation import ActionCatalog`), so handing the instance over
        # adds ZERO new edges and keeps `workbench_query` free of any `investigation` import.
        #
        # WHY THE PARAMETER EXISTS EVEN THOUGH THE SINGLE PRODUCTION CALLER PASSES NOTHING (`main.py:789` calls this
        # with no arguments, and still does): `test_every_delegation_forwards_every_parameter` DERIVES the delegation's
        # expected parameter list from the MOVED BODY's signature and calls this method with one sentinel per
        # non-`host` parameter, so a delegation that dropped `catalog` fails that test with
        # "takes 1 positional argument but 2 were given" - which is exactly what the first version of this delegation
        # did. The default keeps every existing caller working unchanged, which is why `main.py` is untouched.
        #
        # NO DOCSTRING ON PURPOSE, and the reason is measured: `test_delegations_keep_the_implementations_docstring`
        # compares this method's `__doc__` with the moved body's for EXACT string equality, and the moved body is
        # indented 4 spaces while this one would be 8 (the test does NOT `cleandoc`). A module-level `__doc__ = ...`
        # binding on the other side was rejected because it needs `workbench_query` to import `service`, the one edge
        # that module must never have. The decision therefore lives in this comment and in
        # `test_the_capability_delegation_supplies_the_catalog`, which asserts the SHAPE instead of the prose.
        return _workbench_query.workbench_capabilities(self, catalog or ActionCatalog.default())

    def workbench_query_current_evidence(
        self,
        dsh_session_id: str,
        *,
        kind: str | None = None,
        module: str | None = None,
        artifact_id: str | None = None,
        limit: int = 100,
        filter_text: str | None = None,
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
            task_id=str(task_id),
            kind=kind,
            module=module,
            artifact_id=artifact_id,
            limit=limit,
            filter_text=filter_text,
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
        filter_text: str | None = None,
    ) -> dict[str, object]:
        """Query stored evidence, optionally addressable by function or address.

        ``filter_text`` matches the row's ``anchor`` or ``value`` text.  Without
        it the caller can only page a flat list of a kind -- 1283 ``function_call``
        rows with no way to ask "show me function X".  That flatness is what made
        deep investigation impossible for the agent: it could read summaries but
        never drill into a specific function or address.
        """
        return _workbench_query.workbench_query_evidence(
            self,
            task_id=task_id,
            kind=kind,
            module=module,
            artifact_id=artifact_id,
            limit=limit,
            filter_text=filter_text,
        )

    _UNIQUE_THREAD_VIEW_KINDS = (
        "api_argument_trace",
        "function_call",
        "function_context",
        "function_semantic_summary",
        "decompile_slice",
        "simulation_result",
        "tls_callback",
        "thread_callback",
        "import_symbol",
    )

    def _unique_execution_threads_for_view(
        self, session: Session, task_id: str
    ) -> list[dict[str, object]]:
        """Bounded OS-thread rows for DSH task_gaps; not a full evidence dump."""
        return _workbench_query._unique_execution_threads_for_view(self, session, task_id)

    def workbench_domain_view(self, task_id: str) -> dict[str, object]:
        """Stable, bounded projection for DSH views.

        This endpoint is polled by the workbench tabs.  It must not call
        ``task_view`` because that projection intentionally materializes every
        Evidence row for export and can contain tens of thousands of rows.
        Raw evidence remains available through the paginated query endpoint.
        """
        return _workbench_query.workbench_domain_view(self, task_id)

    @staticmethod
    def _workbench_action_provenance(
        payload: Mapping[str, object],
    ) -> tuple[str, str | None, dict[str, object]]:
        """Normalize caller-supplied model provenance for a Workbench action.

        Provenance is deliberately stored beside (rather than inside) the
        selector passed to the Action Catalog.  This keeps authorization
        deterministic while preserving the model call that caused a DSH
        action.  Missing planner metadata is treated as a deterministic
        fallback so it cannot earn model-effectiveness credit by accident.
        """
        requested_origin = str(payload.get("origin") or "").strip().casefold()
        planner_value = payload.get("planner_turn_id")
        planner_turn_id = (
            str(planner_value).strip()[:200]
            if isinstance(planner_value, (str, int)) and str(planner_value).strip()
            else None
        )
        origin = (
            requested_origin
            if requested_origin in {"model", "human", "deterministic_fallback"}
            else ""
        )
        if origin == "model" and not planner_turn_id:
            # A model action must be correlated to a planner turn before it is
            # counted as model-controlled.  Keep the action usable, but label
            # it as a fallback when the caller omitted that correlation.
            origin = "deterministic_fallback"
        if not origin:
            origin = "model" if planner_turn_id else "deterministic_fallback"

        raw = payload.get("model_provenance")
        provenance: dict[str, object] = {}
        if isinstance(raw, Mapping):
            # Keep only bounded scalar metadata.  Raw prompts/responses must
            # continue to use the encrypted model payload store.
            for key, value in raw.items():
                name = str(key).strip()[:80]
                if not name or len(provenance) >= 32:
                    continue
                if isinstance(value, (str, int, float, bool)):
                    provenance[name] = str(value)[:512] if isinstance(value, str) else value
        explicit_fields = (
            ("model_call_id", "model_call_id"),
            ("model_run_id", "model_run_id"),
            ("model_provider", "provider"),
            ("model_name", "model"),
            ("provider", "provider"),
            ("model", "model"),
            ("prompt_sha256", "prompt_sha256"),
            ("profile_digest", "profile_digest"),
            ("policy_digest", "policy_digest"),
            ("action_validation_digest", "action_validation_digest"),
        )
        for payload_key, provenance_key in explicit_fields:
            value = payload.get(payload_key)
            if isinstance(value, (str, int)) and str(value).strip():
                provenance[provenance_key] = str(value).strip()[:256]
        validation = payload.get("action_validation")
        if isinstance(validation, Mapping):
            provenance["action_validation"] = {
                str(key).strip()[:80]: (str(value)[:512] if isinstance(value, str) else value)
                for key, value in list(validation.items())[:32]
                if str(key).strip() and isinstance(value, (str, int, float, bool))
            }
        provenance["origin"] = origin
        if planner_turn_id:
            provenance["planner_turn_id"] = planner_turn_id
        provenance["source"] = "workbench_action_request"
        if requested_origin and requested_origin != origin:
            provenance["requested_origin"] = requested_origin
        return origin, planner_turn_id, provenance

    def workbench_submit_action(
        self, task_id: str, payload: dict[str, object]
    ) -> dict[str, object]:
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
        selector = normalize_target_selector(
            payload.get("target_selector") if isinstance(payload.get("target_selector"), dict) else {}
        )
        if not target_artifact_id or not selector:
            raise ValueError("target_artifact_id and target_selector are required")
        expected = payload.get("expected_evidence_kinds")
        if not isinstance(expected, list) or not expected:
            raise ValueError("expected_evidence_kinds are required")
        origin, planner_turn_id, model_provenance = self._workbench_action_provenance(payload)
        raw_source_evidence_ids = payload.get("evidence_ids", [])
        if not isinstance(raw_source_evidence_ids, (list, tuple, set)):
            raw_source_evidence_ids = []
        source_evidence_ids = tuple(
            str(item).strip()
            for item in raw_source_evidence_ids
            if isinstance(item, (str, int)) and str(item).strip()
        )[:32]
        raw_plan = {
            "question": str(payload.get("question", "")).strip()[:1200],
            "hypothesis": str(payload.get("hypothesis", "")).strip()[:1200],
            "alternatives": [
                str(item).strip()[:320]
                for item in payload.get("alternatives", [])
                if isinstance(item, (str, int)) and str(item).strip()
            ][:8]
            if isinstance(payload.get("alternatives"), list)
            else [],
            "missing_evidence": [
                str(item).strip()[:320]
                for item in payload.get("missing_evidence", [])
                if isinstance(item, (str, int)) and str(item).strip()
            ][:16]
            if isinstance(payload.get("missing_evidence"), list)
            else [],
            "failure_meaning": str(payload.get("failure_meaning", "")).strip()[:1200],
        }
        if origin == "model" and (
            not source_evidence_ids
            or not raw_plan["question"]
            or not raw_plan["hypothesis"]
            or not raw_plan["alternatives"]
            or not raw_plan["missing_evidence"]
            or not raw_plan["failure_meaning"]
        ):
            raise ValueError("model workbench action requires evidence citations and a plan-first contract")
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
            selector = normalize_target_selector(selector, allowed_keys=definition.selector_keys)
            if not selector:
                raise ValueError("target selector contains unsupported keys")
            if source_evidence_ids:
                cited = set(
                    session.scalars(
                        select(Evidence.id).where(
                            Evidence.task_id == task.id,
                            Evidence.artifact_id == artifact.id,
                            Evidence.id.in_(source_evidence_ids),
                        )
                    ).all()
                )
                if cited != set(source_evidence_ids):
                    raise ValueError("workbench action cites evidence outside its artifact scope")
            # Provenance changes must not create a second execution of the
            # same semantic action.  Identity is based only on catalog inputs.
            action_identity = {
                "action_type": action_type.value,
                "target_artifact_id": target_artifact_id,
                "hypothesis_id": str(payload.get("hypothesis_id") or ""),
                "target_selector": dict(selector),
                "expected_evidence_kinds": [str(item) for item in expected[:32]],
                "success_condition": str(payload.get("success_condition", "new_targeted_evidence"))[
                    :160
                ],
            }
            action_id = f"{task.id}:dsh:{hashlib.sha256(self._canonical_json(action_identity).encode()).hexdigest()[:24]}"
            existing = session.get(InvestigationActionRecord, action_id)
            if existing is not None:
                existing_payload = self._action_payload(existing)
                return {
                    "id": existing.id,
                    "task_id": existing.task_id,
                    "thread_id": existing.thread_id,
                    "status": existing.status,
                    "action_type": existing.action_type,
                    "origin": existing_payload["origin"],
                    "planner_turn_id": existing_payload["planner_turn_id"],
                    "model_provenance": existing_payload["model_provenance"],
                    "deduplicated": True,
                }
            threads = list(
                session.scalars(
                    select(InvestigationThreadRecord).where(
                        InvestigationThreadRecord.task_id == task.id,
                        InvestigationThreadRecord.artifact_id == artifact.id,
                    )
                )
            )
            if not threads:
                # A Workbench action may arrive before the asynchronous
                # analysis loop has initialized its investigation records.
                # Create the same deterministic thread/hypothesis pair used
                # by the loop so the proposal can be executed immediately.
                thread_id = (
                    f"thread-{hashlib.sha256(f'{task.id}:{artifact.id}'.encode()).hexdigest()[:20]}"
                )
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
            action_parameters: dict[str, object] = {
                **dict(selector),
                "origin": origin,
                "_model_provenance": model_provenance,
                "_analysis_plan": {
                    **raw_plan,
                    "reason": str(payload.get("reason", "DSH analyst proposal"))[:2000],
                    "planner_protocol": (
                        "plan-first-static-v1" if origin == "model" else "analyst-query-static-v1"
                    ),
                    # DSH/manual queries can enrich the evidence frontier but
                    # are intentionally executed in model-actions-only mode;
                    # they cannot directly promote a Claim.
                    "claim_promotion": "eligible" if origin == "model" else "disabled",
                },
            }
            if planner_turn_id:
                action_parameters["_planner_turn_id"] = planner_turn_id
            if source_evidence_ids:
                action_parameters["_source_evidence_ids"] = list(source_evidence_ids)
            row = InvestigationActionRecord(
                id=action_id,
                task_id=task.id,
                thread_id=thread.id,
                hypothesis_id=hypothesis.id,
                artifact_id=artifact.id,
                action_type=action_type.value,
                reason=str(payload.get("reason", "DSH analyst proposal"))[:2000],
                parameters=action_parameters,
                target_selector=dict(selector),
                expected_evidence_kinds=[str(item) for item in expected[:32]],
                success_condition=str(payload.get("success_condition", "new_targeted_evidence"))[
                    :160
                ],
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
                payload={
                    "action_type": row.action_type,
                    "target_artifact_id": row.artifact_id,
                    "origin": origin,
                    "planner_turn_id": planner_turn_id,
                    "model_call_id": model_provenance.get("model_call_id"),
                    "model_run_id": model_provenance.get("model_run_id"),
                    "provider": model_provenance.get("provider"),
                    "model": model_provenance.get("model"),
                },
            )
            result = {
                "id": row.id,
                "task_id": task.id,
                "thread_id": row.thread_id,
                "status": row.status,
                "action_type": row.action_type,
            }

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
            try:
                continue_investigation_after_action(self, task_id)
            except Exception as exc:
                result["emulation_dispatch_error"] = type(exc).__name__
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
            modules = (
                list(latest.selected_modules)
                if latest and latest.selected_modules
                else list(task.selected_modules or REPORT_MODULES)
            )
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
        return {
            **result,
            "session_id": dsh_session_id,
            "context_revision": context.get("context_revision"),
        }

    @staticmethod
    def _action_payload(row: InvestigationActionRecord) -> dict[str, object]:
        return _coordinator._action_payload(row)

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
            evidence_rows = (
                list(
                    session.scalars(
                        select(Evidence).where(Evidence.id.in_(row.result_evidence_ids or []))
                    )
                )
                if row.result_evidence_ids
                else []
            )
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
        if action in {
            ActionType.GET_CALLERS.value,
            ActionType.GET_CALLEES.value,
            ActionType.GET_XREFS_TO.value,
            ActionType.GET_XREFS_FROM.value,
        }:
            edges: list[dict[str, object]] = []
            for value in values:
                edge = {
                    key: value[key]
                    for key in (
                        "caller",
                        "callee",
                        "source",
                        "referenced_target",
                        "api",
                        "callsite",
                        "from",
                        "to",
                        "edge",
                        "direction",
                    )
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
                slices.append(
                    {
                        "source": value.get("source")
                        or value.get("inputs")
                        or value.get("function"),
                        "sinks": value.get("sinks")
                        or value.get("outputs")
                        or value.get("consumers"),
                        "critical_operations": value.get("critical_operations")
                        or value.get("operations")
                        or value.get("steps"),
                        "conditions": value.get("conditions") or value.get("path_conditions"),
                        "unknowns": value.get("unknowns") or value.get("limitations"),
                        "evidence_id": next(
                            (item.id for item in evidence_rows if item.value is value), None
                        ),
                    }
                )
            return {"kind": "pcode_slice", "slices": slices[:32], "count": len(slices)}
        if action == ActionType.GET_DECOMPILE.value:
            summaries = []
            for item in evidence_rows:
                if item.kind != "function_semantic_summary" or not isinstance(item.value, dict):
                    continue
                value = item.value
                summaries.append(
                    {
                        "evidence_id": item.id,
                        "function": value.get("function"),
                        "call_sequence": value.get("call_sequence", []),
                        "inputs": value.get("inputs", []),
                        "conditions": value.get("conditions", []),
                        "consumers": value.get("consumers", []),
                        "static_only": value.get("static_only", True),
                        "boundary": value.get("boundary", "static evidence only"),
                        "source_evidence_ids": value.get("source_evidence_ids", []),
                    }
                )
            if summaries:
                return {
                    "kind": "function_semantic_summary",
                    "summaries": summaries[:32],
                    "count": len(summaries),
                }
        return {
            "kind": "evidence_projection",
            "observations": [
                {
                    "evidence_id": item.id,
                    "kind": item.kind,
                    "value": item.value,
                    "anchor": item.anchor,
                }
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
        return _workbench_query.workbench_thread(self, thread_id)

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
            bound_task_id = (
                str(context.active_task_id) if context and context.active_task_id else ""
            )
            if requested_task_id and requested_task_id != bound_task_id:
                raise ContextMismatchError("CONTEXT_MISMATCH: task is not bound to this session")
            task_id = requested_task_id or bound_task_id
            if not task_id:
                raise ValueError("NO_ACTIVE_ANALYSIS: start an analysis before invoking the model")
            task = session.get(AnalysisTask, task_id)
            if task is None or task.case_id != case_id:
                raise LookupError(task_id)
        # The deployment-level kill switch is checked after session/task
        # authorization (so callers still receive the useful context error),
        # but before payload storage or AgentRuntime construction.  This keeps
        # the DSH model endpoint fail-closed and guarantees no HTTP attempt or
        # ModelCall row is created while model routing is disabled.
        if not self.settings.model_calls_enabled:
            raise ValueError(
                "MODEL_CALLS_DISABLED: model calls are disabled by deployment policy"
            )
        raw_messages = payload.get("messages")
        if not isinstance(raw_messages, list) or not raw_messages:
            raise ValueError("messages are required")
        messages: list[dict[str, str]] = []
        for item in raw_messages[:32]:
            if not isinstance(item, dict) or item.get("role") not in {
                "system",
                "user",
                "assistant",
            }:
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
        if len(prompt.sha256) != 64 or any(
            char not in "0123456789abcdefABCDEF" for char in prompt.sha256
        ):
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
            json.dumps(
                {"operation": operation, "messages": messages},
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode()
        )
        runtime_result = AgentRuntime(
            self.model_gateway,
            max_context_bytes=self.settings.model_context_max_bytes,
            cancellation_requested=lambda: self._is_task_cancelled(task_id),
        ).run(request)
        response_stored = (
            self._store_model_payload(runtime_result.response.raw_response)
            if runtime_result.response
            else None
        )
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
                successful_call_id=runtime_result.response.model_call_id
                if runtime_result.response
                else None,
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
            "usage": {
                "input_tokens": response.input_tokens,
                "output_tokens": response.output_tokens,
            },
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
        return _task_runner.cancel_task(self, task_id, actor=actor)

    def cancel_tool_run(
        self,
        task_id: str,
        tool_run_id: str,
        *,
        actor: str = "demo-analyst",
    ) -> dict[str, object]:
        return _task_runner.cancel_tool_run(self, task_id, tool_run_id, actor=actor)

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
                "artifact_count": session.query(Artifact)
                .filter(Artifact.task_id == task_id)
                .count(),
                "evidence_count": session.query(Evidence)
                .filter(Evidence.task_id == task_id)
                .count(),
                "claim_count": session.query(Claim).filter(Claim.task_id == task_id).count(),
                "tool_run_count": session.query(ToolRun).filter(ToolRun.task_id == task_id).count(),
                "model_call_count": session.query(ModelCall)
                .filter(ModelCall.task_id == task_id)
                .count(),
                "report_available": session.query(ReportRevision)
                .filter(ReportRevision.task_id == task_id)
                .count()
                > 0,
                "created_at": self._audit_timestamp(task.created_at),
                "started_at": self._audit_timestamp(task.started_at) if task.started_at else None,
                "finished_at": self._audit_timestamp(task.finished_at)
                if task.finished_at
                else None,
                "elapsed_ms": self._elapsed_ms(task),
                "failure": self._failure_payload(failure),
            }

    def task_view(self, task_id: str) -> dict[str, object]:
        return _workbench_query.task_view(self, task_id)

    def _persist_evidence_delivery_ledger(
        self,
        session: Session,
        *,
        task: AnalysisTask,
        artifact_id: str | None,
        ledger: EvidenceDeliveryLedger,
        model_call_id: str | None,
    ) -> None:
        return _coordinator._persist_evidence_delivery_ledger(
            self,
            session,
            task=task,
            artifact_id=artifact_id,
            ledger=ledger,
            model_call_id=model_call_id,
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
                {"id": item.id, "tool_run_id": item.tool_run_id} for item in inputs["evidence"]
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
        return _revision_writer.get_report_revision(self, revision_id)

    def recompose_report(
        self,
        task_id: str,
        selected_modules: list[str],
        actor: str = "demo-analyst",
    ) -> dict[str, object]:
        return _revision_writer.recompose_report(self, task_id, selected_modules, actor)

    def edit_report(
        self,
        revision_id: str,
        markdown: str,
        actor: str = "demo-analyst",
    ) -> dict[str, object]:
        return _revision_writer.edit_report(self, revision_id, markdown, actor)

    def submit_analyst_draft(
        self,
        revision_id: str,
        markdown: str,
        *,
        actor: str = "dsh-agent",
    ) -> dict[str, object]:
        """Admit an agent-authored analyst narrative through the compose gate.

        ADR-0036 / plan §8.3: a fluent draft may reorganise, explain and shorten
        the deterministic fragments, but it may not introduce a fact they do not
        contain.  ``compose_gate_violations`` rejects a novel endpoint, IPv4,
        process image or creation-flags value, and rejects restating a
        CANDIDATE/UNKNOWN as established.

        This is deliberately a *separate* entry point from ``edit_report``: a
        human manual edit is a superseding act by an accountable analyst, while
        an agent draft is a proposal that must clear the gate before it becomes
        the official body.  ``approve_report``/``publish_report`` do not run the
        gate, so gating has to happen here.

        A rejected draft raises ``ReportComposeGateRejected`` (a ``ValueError``)
        carrying the violations instead of silently falling back, so the agent
        can see what it fabricated and revise rather than believing it published.
        The structured list is on the exception because
        :meth:`workbench_write_report_file` keeps its file write authoritative
        and reports the rejection as data.
        """
        return _revision_writer.submit_analyst_draft(self, revision_id, markdown, actor=actor)

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
        return _revision_writer.publish_report(self, revision_id, actor=actor)

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
        snapshot = AnalysisSnapshot(
            id=snapshot_id,
            task_id=str(payload.get("task", {}).get("id", "")),
            object_versions=payload,
        )
        context = self._snapshot_report_context(snapshot)
        modules = normalize_modules(selected_modules)
        return build_report_document(selected_modules=modules, **context)
