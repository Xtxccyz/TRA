from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy import select

from threat_report_agent.evidence_recovery import (
    BoundedEvidenceRepository,
    ContextRole,
    EvidenceDeliveryLedger,
    EvidenceStage,
    QuestionCentricRetriever,
    RetrievalRequest,
)
from threat_report_agent.investigation import ActionSpec, ActionType, InvestigationQueue
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import (
    AnalysisTask,
    AuditEvent,
    Artifact,
    ContentBlob,
    Evidence,
    EvidenceDeliveryTrace,
    ToolRun,
)
from threat_report_agent.service import AnalysisService
from threat_report_agent.status import EvidenceNature


def _evidence(
    evidence_id: str,
    kind: str,
    value: dict[str, object],
    *,
    anchor: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "evidence_id": evidence_id,
        "artifact_id": "artifact-1",
        "kind": kind,
        "nature": "STATIC_OBSERVED",
        "value": value,
        "anchor": anchor or {},
    }


def test_dynamic_resolver_context_prioritizes_targeted_mechanism_evidence() -> None:
    request = RetrievalRequest(
        thread_id="dyn-1",
        artifact_id="artifact-1",
        hypothesis_type="dynamic_api_resolution",
        target_anchors=("GetProcAddress", "LoadLibraryA"),
        required_evidence_kinds=(
            "import_symbol",
            "xref",
            "function_context",
            "data_reference",
        ),
        caller_depth=2,
        callee_depth=1,
        data_xref_depth=1,
    )
    evidence = [
        _evidence("import-gpa", "import_symbol", {"name": "GetProcAddress"}),
        _evidence(
            "xref-gpa",
            "xref",
            {"target_name": "GetProcAddress", "caller": "resolver"},
            anchor={"function_entry": "0x140001000"},
        ),
        _evidence(
            "resolver-context",
            "function_context",
            {"name": "resolver", "call_targets": ["GetProcAddress"]},
            anchor={"function_entry": "0x140001000"},
        ),
        _evidence(
            "resolver-data",
            "data_reference",
            {"function": "resolver", "text": "winhttp.dll"},
            anchor={"function_entry": "0x140001000"},
        ),
    ]
    evidence.extend(
        _evidence(f"generic-{index}", "function", {"name": f"FUN_{index}"})
        for index in range(64)
    )

    packet = QuestionCentricRetriever(max_items=8).build(request, evidence)

    assert {item.evidence_id for item in packet.core} >= {
        "import-gpa",
        "xref-gpa",
        "resolver-context",
        "resolver-data",
    }
    assert all(item.role != ContextRole.CORE_SUPPORT for item in packet.items if item.kind == "function")
    assert packet.exclusion_reasons["generic-63"] == "type_budget_exhausted"


def test_delivery_funnel_distinguishes_model_reference_from_accepted_support() -> None:
    ledger = EvidenceDeliveryLedger(turn_id="turn-1", thread_id="dyn-1")
    for stage in (
        EvidenceStage.PRODUCED,
        EvidenceStage.NORMALIZED,
        EvidenceStage.PERSISTED,
        EvidenceStage.ELIGIBLE,
        EvidenceStage.CANDIDATE,
        EvidenceStage.SELECTED,
        EvidenceStage.DELIVERED,
        EvidenceStage.REFERENCED_BY_MODEL,
    ):
        ledger.advance("evidence-1", stage)
    ledger.advance("evidence-2", EvidenceStage.PRODUCED)
    ledger.advance("evidence-2", EvidenceStage.NORMALIZED)
    ledger.advance("evidence-2", EvidenceStage.PERSISTED)

    assert ledger.counts[EvidenceStage.REFERENCED_BY_MODEL] == 1
    assert ledger.counts[EvidenceStage.ACCEPTED_AS_SUPPORT] == 0
    ledger.advance("evidence-1", EvidenceStage.ACCEPTED_AS_SUPPORT)
    assert ledger.counts[EvidenceStage.ACCEPTED_AS_SUPPORT] == 1


def test_action_queue_deduplicates_exact_experiment_not_action_type() -> None:
    queue = InvestigationQueue(max_steps=4)
    base = {
        "thread_id": "dyn-1",
        "hypothesis_id": "hyp-1",
        "artifact_id": "artifact-1",
        "action_type": ActionType.GET_XREFS_TO,
    }
    get_proc = ActionSpec(
        id="xrefs-gpa",
        parameters={"target": "GetProcAddress"},
        **base,
    )
    load_library = ActionSpec(
        id="xrefs-loadlibrary",
        parameters={"target": "LoadLibraryA"},
        **base,
    )
    duplicate_get_proc = ActionSpec(
        id="xrefs-gpa-duplicate",
        parameters={"target": "GetProcAddress"},
        **base,
    )

    assert queue.enqueue(get_proc) is True
    assert queue.enqueue(load_library) is True
    assert queue.enqueue(duplicate_get_proc) is False


def test_delivery_trace_is_persisted_and_exposed_in_task_view(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("delivery trace")
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        session.add(
            ContentBlob(
                sha256="a" * 64,
                size=1,
                media_type="application/octet-stream",
                storage_key="sha256/test",
            )
        )
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256="a" * 64,
            logical_path="sample.exe",
            detected_type="pe",
        )
        session.add(artifact)
        session.flush()
        task_id = task.id
        artifact_id = artifact.id

    ledger = EvidenceDeliveryLedger(turn_id="turn-1", thread_id="thread-1")
    ledger.advance("raw:1", EvidenceStage.PRODUCED)
    ledger.advance("raw:1", EvidenceStage.NORMALIZED)
    ledger.advance("raw:1", EvidenceStage.PERSISTED)

    service.record_evidence_delivery_trace(
        task_id=task_id,
        artifact_id=artifact_id,
        ledger=ledger,
    )

    with database.session_factory() as session:
        rows = list(session.query(EvidenceDeliveryTrace).filter(EvidenceDeliveryTrace.task_id == task_id))
    assert [row.stage for row in rows] == [
        "PRODUCED",
        "NORMALIZED",
        "PERSISTED",
    ]
    assert service.task_view(task_id)["evidence_delivery"]["counts"]["PERSISTED"] == 1
    assert EvidenceNature.STATIC_DERIVED.value == "STATIC_DERIVED"


def test_bounded_database_retrieval_finds_late_target_evidence_before_generic_rows(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("targeted retrieval")
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.add(
            ContentBlob(
                sha256="b" * 64,
                size=1,
                media_type="application/octet-stream",
                storage_key="sha256/targeted",
            )
        )
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256="b" * 64,
            logical_path="resolver.exe",
            detected_type="pe",
        )
        session.add(artifact)
        session.flush()
        tool_run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="ghidra-headless",
            tool_version="test",
            status="SUCCEEDED",
        )
        session.add(tool_run)
        session.flush()
        for index in range(96):
            session.add(
                Evidence(
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=tool_run.id,
                    module="static",
                    kind="function",
                    nature="STATIC_OBSERVED",
                    value={"name": f"FUN_{index:04x}"},
                    anchor={"function_entry": hex(0x140001000 + index * 16)},
                )
            )
        session.add_all(
            [
                Evidence(
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=tool_run.id,
                    module="static",
                    kind="xref",
                    nature="STATIC_OBSERVED",
                    value={"target_name": "GetProcAddress", "caller": "resolve_api"},
                    anchor={"function_entry": "0x140005000"},
                ),
                Evidence(
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=tool_run.id,
                    module="static",
                    kind="function_context",
                    nature="STATIC_OBSERVED",
                    value={"name": "resolve_api", "call_targets": ["GetProcAddress"]},
                    anchor={"function_entry": "0x140005000"},
                ),
            ]
        )
        session.flush()
        # The index rows are created after the Evidence flush.  A second flush
        # makes the test exercise the same persisted lookup path as production.
        session.flush()
        request = RetrievalRequest(
            thread_id="resolver-thread",
            artifact_id=artifact.id,
            hypothesis_type="dynamic_api_resolution",
            target_anchors=("GetProcAddress",),
            required_evidence_kinds=("xref", "function_context"),
            caller_depth=1,
            candidate_limit=12,
        )
        batch = BoundedEvidenceRepository().retrieve(session, task_id=task.id, request=request)

    assert batch.query_count <= 6
    assert batch.candidate_count <= 12
    assert {row.kind for row in batch.rows} >= {"xref", "function_context"}
    assert all(row.artifact_id == request.artifact_id for row in batch.rows)


def test_bounded_database_retrieval_expands_typed_caller_and_data_edges(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("typed graph expansion")
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.add(
            ContentBlob(
                sha256="f" * 64,
                size=1,
                media_type="application/octet-stream",
                storage_key="sha256/graph",
            )
        )
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256="f" * 64,
            logical_path="graph.exe",
            detected_type="pe",
        )
        session.add(artifact)
        session.flush()
        tool_run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="ghidra-headless",
            tool_version="test",
            status="SUCCEEDED",
        )
        session.add(tool_run)
        session.flush()
        session.add_all(
            [
                Evidence(
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=tool_run.id,
                    module="static",
                    kind="function_context",
                    nature="STATIC_OBSERVED",
                    value={
                        "name": "resolve_api",
                        "entry": "0x140001000",
                        "call_targets": [{"target_name": "GetProcAddress"}],
                        "data_references": [{"to": "0x140009000", "target_name": "encoded_config"}],
                    },
                    anchor={"function_entry": "0x140001000"},
                ),
                Evidence(
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=tool_run.id,
                    module="static",
                    kind="function_instruction_window",
                    nature="STATIC_OBSERVED",
                    value={"name": "resolve_api", "entry": "0x140001000", "instructions": [{"text": "call GetProcAddress"}]},
                    anchor={"function_entry": "0x140001000"},
                ),
                Evidence(
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=tool_run.id,
                    module="static",
                    kind="data_reference",
                    nature="STATIC_OBSERVED",
                    value={"address": "0x140009000", "text": "ciphertext"},
                    anchor={"address": "0x140009000"},
                ),
            ]
        )
        session.flush()
        request = RetrievalRequest(
            thread_id="resolver-thread",
            hypothesis_id="hyp-resolver",
            artifact_id=artifact.id,
            hypothesis_type="dynamic_api_resolution",
            target_anchors=("GetProcAddress",),
            required_evidence_kinds=("function_context",),
            caller_depth=1,
            data_xref_depth=1,
            candidate_limit=16,
        )
        batch = BoundedEvidenceRepository().retrieve(session, task_id=task.id, request=request)

    assert {row.kind for row in batch.rows} >= {
        "function_context",
        "function_instruction_window",
        "data_reference",
    }
    assert {item["direction"] for item in batch.graph_expansions} >= {"caller", "data"}
    assert batch.query_count <= 10


def test_targeted_static_action_returns_only_the_requested_anchor(test_settings) -> None:
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    source_rows = [
        SimpleNamespace(
            id="gpa-context",
            kind="function_context",
            value={"name": "resolver", "call_targets": ["GetProcAddress"]},
            anchor={"function_entry": "0x140005000"},
        ),
        SimpleNamespace(
            id="loadlibrary-context",
            kind="function_context",
            value={"name": "loader", "call_targets": ["LoadLibraryA"]},
            anchor={"function_entry": "0x140006000"},
        ),
    ]
    action = ActionSpec(
        id="xrefs-gpa",
        action_type=ActionType.GET_XREFS_TO,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        parameters={"target": "GetProcAddress"},
    )

    observations = service._derive_investigation_observations(source_rows, action)

    assert observations
    assert all("getprocaddress" in str(item["value"]).lower() for item in observations)
    assert all(
        item["anchor"]["target_selector"] == "GetProcAddress" for item in observations
    )


def test_targeted_static_actions_preserve_graph_direction_and_verified_decode_result(test_settings) -> None:
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    source_rows = [
        SimpleNamespace(
            id="resolver",
            kind="function_context",
            value={
                "name": "resolve_api",
                "entry": "0x140001000",
                "call_targets": [{"target_name": "GetProcAddress"}],
            },
            anchor={"function_entry": "0x140001000"},
        ),
        SimpleNamespace(
            id="bootstrap",
            kind="function_context",
            value={
                "name": "bootstrap",
                "entry": "0x140002000",
                "call_targets": [{"target_name": "resolve_api"}],
            },
            anchor={"function_entry": "0x140002000"},
        ),
        SimpleNamespace(
            id="decode",
            kind="mechanism_decode_window",
            value={
                "key_candidates": [0x41],
                "verification_result": {
                    "status": "VERIFIED_STATIC_DATA",
                    "decoded_preview": "https://example.invalid/path",
                },
            },
            anchor={"function_entry": "0x140003000"},
        ),
    ]

    def action(action_type: ActionType, target: str) -> ActionSpec:
        return ActionSpec(
            id=f"{action_type.value}:{target}",
            action_type=action_type,
            thread_id="thread-1",
            hypothesis_id="hypothesis-1",
            artifact_id="artifact-1",
            parameters={"target": target},
            expected_evidence_kinds=("function_call",),
            success_condition="targeted static edge recovered",
        )

    callers = service._derive_investigation_observations(
        source_rows, action(ActionType.GET_CALLERS, "resolve_api")
    )
    callees = service._derive_investigation_observations(
        source_rows, action(ActionType.GET_CALLEES, "resolve_api")
    )
    decoded = service._derive_investigation_observations(
        source_rows, action(ActionType.DECODE_CANDIDATE, "xor")
    )

    assert callers and callers[0]["value"]["direction"] == "caller"
    assert callers[0]["value"]["caller"] == "bootstrap"
    assert callees and callees[0]["value"]["direction"] == "callee"
    assert callees[0]["value"]["callee"] == "GetProcAddress"
    assert decoded and decoded[0]["kind"] == "decode_result"
    assert decoded[0]["value"]["verification"]["status"] == "VERIFIED_STATIC_DATA"


def test_pcode_action_emits_semantic_source_sink_slice(test_settings) -> None:
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    source_rows = [
        SimpleNamespace(
            id="ctx-pcode",
            kind="function_context",
            value={
                "name": "decode_and_load",
                "entry": "0x140001000",
                "call_targets": [{"target_name": "LoadLibraryW", "from": "0x140001020"}],
            },
            anchor={"function_entry": "0x140001000"},
        ),
        SimpleNamespace(
            id="ins-pcode",
            kind="function_instruction_window",
            value={
                "instructions": [
                    {"address": "0x140001000", "text": "MOV RCX, [RDX]"},
                    {"address": "0x140001010", "text": "XOR EAX, EAX"},
                    {"address": "0x140001020", "text": "CALL LoadLibraryW"},
                ]
            },
            anchor={"function_entry": "0x140001000"},
        ),
    ]
    action = ActionSpec(
        id="pcode-semantic",
        action_type=ActionType.GET_PCODE_SLICE,
        thread_id="thread-pcode",
        hypothesis_id="hypothesis-pcode",
        artifact_id="artifact-pcode",
        parameters={"target": "decode_and_load"},
        expected_evidence_kinds=("pcode_slice",),
    )
    observations = service._derive_investigation_observations(source_rows, action)
    slices = [item for item in observations if item["kind"] == "pcode_slice"]
    assert slices
    value = slices[0]["value"]
    assert value["source"]["function"] == "decode_and_load"
    assert value["critical_operations"]
    assert value["sinks"][0]["api"] == "LoadLibraryW"


def test_decode_result_links_same_function_static_consumer(test_settings) -> None:
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    plaintext = b"https://example.invalid/gate"
    ciphertext = bytes(value ^ 0x41 for value in plaintext)
    source_rows = [
        SimpleNamespace(
            id="decode-with-consumer",
            kind="mechanism_decode_window",
            value={
                "memory_addresses": [0],
                "key_candidates": [0x41],
                "verification_result": {"status": "VERIFIED_STATIC_DATA"},
            },
            anchor={"function_entry": "0x140003000"},
        ),
        SimpleNamespace(
            id="decode-consumer",
            kind="function_call",
            value={"api": "LoadLibraryW", "from": "0x140003020"},
            anchor={"function_entry": "0x140003000"},
        ),
    ]
    action = ActionSpec(
        id="decode-with-consumer-action",
        action_type=ActionType.DECODE_CANDIDATE,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        parameters={"target": "xor"},
        expected_evidence_kinds=("decode_result",),
    )
    observations = service._derive_investigation_observations(
        source_rows,
        action,
        artifact_content=ciphertext,
    )
    assert observations and observations[0]["kind"] == "decode_result"
    value = observations[0]["value"]
    assert value["verification_status"] == "VERIFIED_STATIC_DATA"
    assert value["consumer_status"] == "LINKED_STATIC"
    assert value["consumer_candidates"][0]["api"] == "LoadLibraryW"
    assert "decode-consumer" in value["consumer_evidence_ids"]
    assert "decode-consumer" in value["derivation"]["input_evidence_ids"]


def test_global_string_action_returns_artifact_local_string_observations(test_settings) -> None:
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    source_rows = [
        SimpleNamespace(
            id="string-1",
            kind="string",
            value={"text": "https://example.invalid/command"},
            anchor={"offset": 128},
        ),
        SimpleNamespace(
            id="string-2",
            kind="string",
            value={"text": "C:\\ProgramData\\stage.dat"},
            anchor={"offset": 256},
        ),
    ]
    action = ActionSpec(
        id="strings-global",
        action_type=ActionType.GET_STRINGS_REFERENCED,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        parameters={"target": "global"},
        expected_evidence_kinds=("string",),
    )

    observations = service._derive_investigation_observations(source_rows, action)

    assert len(observations) == 2
    assert {item["kind"] for item in observations} == {"string_reference"}
    assert all(item["anchor"]["target_selector"] == "global" for item in observations)
    assert all(item["value"]["source_evidence_ids"] for item in observations)


def test_cited_xref_expands_to_matching_function_context_for_decompile(test_settings) -> None:
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    source_rows = [
        SimpleNamespace(
            id="xref-1",
            artifact_id="artifact-1",
            kind="xref",
            value={"from": "1400ec620", "to": "1400ad4d0", "type": "UNCONDITIONAL_CALL"},
            anchor={"function_entry": "1400ad4d0"},
        ),
        SimpleNamespace(
            id="context-1",
            artifact_id="artifact-1",
            kind="function_context",
            value={"name": "FUN_1400ad4d0", "entry": "1400ad4d0", "call_targets": [{"target_name": "CreateFileA"}]},
            anchor={"function_entry": "1400ad4d0"},
        ),
        SimpleNamespace(
            id="instructions-1",
            artifact_id="artifact-1",
            kind="function_instruction_window",
            value={"entry": "1400ad4d0", "instructions": [{"text": "CALL CreateFileA"}]},
            anchor={"function_entry": "1400ad4d0"},
        ),
        SimpleNamespace(
            id="other-context",
            artifact_id="artifact-1",
            kind="function_context",
            value={"name": "FUN_1400beef0", "entry": "1400beef0", "call_targets": [{"target_name": "DeleteFileA"}]},
            anchor={"function_entry": "1400beef0"},
        ),
    ]
    action = ActionSpec(
        id="decompile-xref",
        action_type=ActionType.GET_DECOMPILE,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        parameters={"target": "1400ad4d0"},
        expected_evidence_kinds=("function_context", "function_call"),
        source_evidence_ids=("xref-1",),
    )

    observations = service._derive_investigation_observations(source_rows, action)

    trace = next(item for item in observations if item["kind"] == "abstract_execution_trace")
    assert set(trace["value"]["source_evidence_ids"]) >= {"context-1", "instructions-1"}
    assert "other-context" not in trace["value"]["source_evidence_ids"]


def test_no_result_investigation_action_is_not_persisted_as_success(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("no-result action")
    with database.session_factory.begin() as session:
        session.add(ContentBlob(sha256="1" * 64, size=1, media_type="application/octet-stream", storage_key="sha256/no-result"))
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        artifact = Artifact(task_id=task.id, content_sha256="1" * 64, logical_path="sample.exe", detected_type="pe")
        session.add(artifact)
        session.flush()
        run = ToolRun(task_id=task.id, artifact_id=artifact.id, tool_name="ghidra-headless", tool_version="test", status="SUCCEEDED")
        session.add(run)
        session.flush()
        session.add(Evidence(task_id=task.id, artifact_id=artifact.id, tool_run_id=run.id, module="static", kind="function_context", nature="STATIC_OBSERVED", value={"name": "entry", "entry": "0x1000"}, anchor={"function_entry": "0x1000"}))
        task_id = task.id
        artifact_id = artifact.id

    with database.session_factory.begin() as session:
        task = session.get(AnalysisTask, task_id)
        task.strategy_snapshot = {
            "dynamic_planning": {
                "action_history": [{
                    "action_type": "GET_STRINGS_REFERENCED",
                    "target_artifact_id": artifact_id,
                    "target_selector": {"target": "global"},
                    "parameters": {"target": "global"},
                    "expected_evidence_kinds": ["string"],
                    "success_condition": "new_targeted_evidence",
                    "failure_interpretation": "UNKNOWN",
                    "evidence_ids": [],
                }]
            }
        }

    service._run_investigation_loop(task_id, model_actions_only=True)
    view = service.task_view(task_id)
    action = next(
        item
        for item in view["investigation"]["actions"]
        if item["action_type"] == "GET_STRINGS_REFERENCED"
        and item.get("target_selector", {}).get("target") == "global"
    )
    assert action["status"] == "FAILED"
    assert action["error"] == "NO_NEW_EVIDENCE"
    assert action["result_evidence_ids"] == []
    assert action["parameters"]["_autopsy"]["category"] == "LOW_INFORMATION_ACTION"
    assert action["parameters"]["_autopsy"]["target_selector"] == {"target": "global"}


def test_blind_run_freezes_reference_isolated_baseline_snapshot(test_settings) -> None:
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    service.database.create_schema()
    case = service.create_case("blind v2")

    result = service.analyze_blind_submission(
        case_id=case.id,
        filename="blind.py",
        content=b"OpenProcess UpdateProcThreadAttribute",
        scorecard_version="blind-test-v2",
    )

    blind_runs = service.task_view(result.task_id)["blind_runs"]
    assert len(blind_runs) == 1
    snapshot = blind_runs[0]["snapshot"]
    assert blind_runs[0]["status"] == "COMPLETED"
    assert snapshot["reference_isolated"] is True
    assert snapshot["scorecard_version"] == "blind-test-v2"
    assert snapshot["initial_evidence"]
    assert all("value_sha256" in item and "value" not in item for item in snapshot["initial_evidence"])


def test_reference_isolated_blind_run_never_emits_external_fact_matches(test_settings) -> None:
    """Blind v2 may derive sample signals, but cannot consult packaged threat facts."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    service.database.create_schema()
    case = service.create_case("blind fact isolation")

    result = service.analyze_blind_submission(
        case_id=case.id,
        filename="blind.py",
        content=b'payload = "lsass.exe"\n',
        scorecard_version="blind-fact-isolation-v1",
    )

    task = service.task_view(result.task_id)
    profiles = [item for item in task["evidence"] if item["kind"] == "analysis_profile"]
    assert profiles
    assert not [item for item in task["evidence"] if item["kind"] == "fact_match"]
    assert not [item for item in task["tool_runs"] if item["tool"] == "knowledge-fact-matcher"]
    # Both the ordinary and blind runtime snapshots are intentionally empty;
    # the distinction is the trust-zone/source label, not a sample-specific
    # hash that could become an analysis input.
    assert profiles[0]["anchor"]["knowledge_sha256"] == service.methodology_library.sha256
    snapshot = task["blind_runs"][0]["snapshot"]
    assert snapshot["knowledge"]["fact_library_source"] == "reference-isolated-empty"
    assert snapshot["knowledge"]["fact_library_sha256"] == profiles[0]["anchor"]["knowledge_sha256"]


def test_blind_preparation_rejects_background_context(test_settings) -> None:
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    service.database.create_schema()
    case = service.create_case("blind background isolation")
    queued, _ = service.create_submission_task(
        case_id=case.id,
        filename="sample.py",
        submitted_size=12,
        content=b"print('ok')\n",
        background_context="reference-only conclusion must not enter blind analysis",
    )

    with pytest.raises(ValueError, match="cannot contain background context"):
        service.prepare_blind_run(queued.task_id)


def test_blind_retrieval_excludes_forged_background_evidence(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("blind retrieval isolation")
    with database.session_factory.begin() as session:
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="RUNNING",
            request_snapshot={
                "background_context": {"content": "forged reference context"}
            },
            strategy_snapshot={"blind_run": {"enabled": True, "reference_isolated": True}},
        )
        session.add(task)
        session.flush()
        session.add(ContentBlob(
            sha256="d" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/blind-background",
        ))
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256="d" * 64,
            logical_path="blind.exe",
            detected_type="pe",
            role="EXECUTABLE",
            obligation="REQUIRED",
        )
        session.add(artifact)
        session.flush()
        background_run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="background-context-ingest",
            tool_version="test",
            status="SUCCEEDED",
            parameters={},
            environment={"sample_execution": False, "network_access": False},
        )
        session.add(background_run)
        session.flush()
        background = Evidence(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_run_id=background_run.id,
            module="input_manifest",
            kind="background_context",
            nature="BACKGROUND_REPORTED",
            value={"content": "reference-only conclusion"},
            anchor={"type": "background_context"},
        )
        session.add(background)
        session.flush()
        background_count_before = len(list(session.scalars(
            select(Evidence).where(
                Evidence.task_id == task.id,
                Evidence.kind == "background_context",
            )
        )))
        # The sink must enforce isolation even when a forged task snapshot
        # bypasses prepare_blind_run(). No additional ToolRun/Evidence may be
        # persisted; only an auditable policy decision is allowed.
        service._record_background_evidence(session, task, artifact)
        assert len(list(session.scalars(
            select(ToolRun).where(ToolRun.task_id == task.id)
        ))) == 1
        assert len(list(session.scalars(
            select(Evidence).where(
                Evidence.task_id == task.id,
                Evidence.kind == "background_context",
            )
        ))) == background_count_before
        blocked_events = list(session.scalars(
            select(AuditEvent).where(
                AuditEvent.task_id == task.id,
                AuditEvent.event_type == "policy.background_context_blocked",
            )
        ))
        assert blocked_events
        retrieved = service._retrieve_model_context(
            session,
            task=task,
            artifacts=[artifact],
            module="planning",
            phase="blind-regression",
            completed_actions=[],
        )

    assert background.id not in {item["evidence_id"] for item in retrieved.manifest}
    assert retrieved.ledger.stage_for(background.id) == EvidenceStage.CANDIDATE
    blocked = [event for event in retrieved.ledger.events if event.evidence_id == background.id]
    assert blocked[-1].details["exclusion_reason"] == "reference_isolation_policy"


def test_blind_function_similarity_never_queries_known_library(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("blind similarity isolation")
    with database.session_factory.begin() as session:
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="RUNNING",
            strategy_snapshot={"blind_run": {"enabled": True, "reference_isolated": True}},
        )
        session.add(task)
        session.flush()
        session.add(ContentBlob(
            sha256="e" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/blind-similarity",
        ))
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256="e" * 64,
            logical_path="blind.exe",
            detected_type="pe",
            role="EXECUTABLE",
            obligation="REQUIRED",
        )
        session.add(artifact)
        session.flush()
        source_run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="ghidra-headless",
            tool_version="test",
            status="SUCCEEDED",
            parameters={},
            environment={"sample_execution": False, "network_access": False},
        )
        session.add(source_run)
        session.flush()
        session.add(Evidence(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_run_id=source_run.id,
            module="static_triage",
            kind="function_simhash",
            nature="STATIC_OBSERVED",
            value={
                "value": "44e0cbb281dca986",
                "algorithm": "simhash-v1",
                "feature": "mnemonic-ngrams-v1",
                "hash": "sha256",
            },
            anchor={"entry": "0x401000"},
        ))
        session.flush()
        service._record_function_similarity(session, task, artifact, source_run)
        session.flush()
        similarity_scopes = next(
            run.parameters["scopes"]
            for run in session.query(ToolRun)
            if run.tool_name == "function-similarity-index"
        )
        task_id = task.id

    task_view = service.task_view(task_id)
    assert similarity_scopes == ["CURRENT_TASK"]
    assert not [item for item in task_view["evidence"] if item["kind"] == "function_similarity"]
