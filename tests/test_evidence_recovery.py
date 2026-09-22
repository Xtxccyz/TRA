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
from threat_report_agent.static_analysis import recover_static_xor_configs
from threat_report_agent.task.status import EvidenceNature


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


def test_derived_function_call_preserves_entry_anchor_from_parser_context(test_settings) -> None:
    """Parser ``entry`` anchors remain usable for later function-local actions."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    source_rows = [
        SimpleNamespace(
            id="ctx-entry-only",
            kind="function_context",
            value={
                "name": "spawn_worker",
                "entry": "0x140001000",
                "call_targets": [{"target_name": "CreateProcessW", "from": "0x140001020"}],
            },
            # This is the shape emitted by the Ghidra persistence path.
            anchor={"type": "function_context", "entry": "0x140001000", "rva": 4096},
        )
    ]
    action = ActionSpec(
        id="callees-entry-only",
        action_type=ActionType.GET_CALLEES,
        thread_id="thread-entry-only",
        hypothesis_id="hypothesis-entry-only",
        artifact_id="artifact-entry-only",
        parameters={"target": "spawn_worker"},
        target_selector={"target": "spawn_worker"},
        expected_evidence_kinds=("function_call",),
    )

    observations = service._derive_investigation_observations(source_rows, action)

    derived = next(item for item in observations if item["kind"] == "function_call")
    assert derived["anchor"]["function_entry"] == "0x140001000"
    assert derived["anchor"]["rva"] == "4096"


@pytest.mark.parametrize("consumer_kind,consumer_anchor", [
    ("function_call", {"function_entry": "0x140003000"}),
    ("function_call", {"function_entry": "0x140008000"}),
    ("import_symbol", {}),
])
def test_decode_result_does_not_link_api_cooccurrence(
    test_settings, consumer_kind, consumer_anchor
) -> None:
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
            kind=consumer_kind,
            value={"api": "LoadLibraryW", "from": "0x140003020"},
            anchor=consumer_anchor,
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
    assert value["consumer_status"] == "NOT_IDENTIFIED"
    assert value["consumer_evidence_ids"] == []
    assert "decode-consumer" not in value["derivation"]["input_evidence_ids"]


def test_decode_result_links_only_a_traced_decoded_output_buffer(test_settings) -> None:
    """B01: API co-location becomes a consumer only after exact value flow."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    output_buffer = {
        "artifact_id": "artifact-1",
        "address_space": "artifact-1",
        "address": 0x5000,
        "length": 24,
    }
    source_rows = [
        SimpleNamespace(
            id="decode-producer",
            kind="mechanism_decode_window",
            value={
                "memory_addresses": [0],
                "key_candidates": [0x41],
                "output_buffer": output_buffer,
                "verification_result": {
                    "status": "VERIFIED_STATIC_DATA",
                    "decoded_text": "https://example.invalid/gate",
                },
            },
            anchor={"function_entry": "0x140003000"},
        ),
        # This is the decisive relation: a resolved argument trace cites the
        # decoder producer and the exact same output-buffer identity.
        SimpleNamespace(
            id="loadlibrary-argument",
            kind="api_argument_trace",
            value={
                "api": "LoadLibraryW",
                "callsite": "0x140003020",
                "argument_index": 0,
                "resolved": True,
                "producer_evidence_id": "decode-producer",
                "source_role": "decoded_output",
                "source_buffer": dict(output_buffer),
            },
            anchor={"function_entry": "0x140003000", "callsite": "0x140003020"},
        ),
    ]
    action = ActionSpec(
        id="decode-output-flow",
        action_type=ActionType.DECODE_CANDIDATE,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        parameters={"target": "xor"},
        target_selector={"target": "xor"},
        expected_evidence_kinds=("decode_result",),
    )

    observations = service._derive_investigation_observations(source_rows, action)

    result = next(item for item in observations if item["kind"] == "decode_result")
    assert result["value"]["consumer_status"] == "LINKED_STATIC"
    assert result["value"]["consumer_evidence_ids"] == ["loadlibrary-argument"]
    assert result["value"]["consumer_candidates"][0]["api"] == "LoadLibraryW"


def test_decode_result_rejects_trace_for_a_different_buffer(test_settings) -> None:
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    producer_buffer = {
        "artifact_id": "artifact-1",
        "address_space": "artifact-1",
        "address": 0x5000,
        "length": 24,
    }
    source_rows = [
        SimpleNamespace(
            id="decode-producer",
            kind="mechanism_decode_window",
            value={
                "output_buffer": producer_buffer,
                "verification_result": {"status": "VERIFIED_STATIC_DATA"},
            },
            anchor={"function_entry": "0x140003000"},
        ),
        SimpleNamespace(
            id="wrong-buffer-argument",
            kind="api_argument_trace",
            value={
                "api": "LoadLibraryW",
                "callsite": "0x140003020",
                "argument_index": 0,
                "resolved": True,
                "producer_evidence_id": "decode-producer",
                "source_role": "decoded_output",
                "source_buffer": {**producer_buffer, "address": 0x6000},
            },
            anchor={"function_entry": "0x140003000", "callsite": "0x140003020"},
        ),
    ]
    action = ActionSpec(
        id="decode-wrong-output-flow",
        action_type=ActionType.DECODE_CANDIDATE,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        parameters={"target": "xor"},
        target_selector={"target": "xor"},
        expected_evidence_kinds=("decode_result",),
    )

    observations = service._derive_investigation_observations(source_rows, action)

    result = next(item for item in observations if item["kind"] == "decode_result")
    assert result["value"]["consumer_status"] == "NOT_IDENTIFIED"
    assert result["value"]["consumer_evidence_ids"] == []


def test_decode_candidate_does_not_give_the_first_xor_config_to_a_second_buffer(
    test_settings,
) -> None:
    """T1: two recovered XOR buffers; only the traced buffer is the LoadLibrary consumer."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    table = bytes(range(0x10, 0x20))
    first = b"http://203.0.113.9/payload.exe"
    second = b"http://198.51.100.7/unused.dll"

    def encode(plain: bytes) -> bytes:
        return bytes(
            byte ^ table[index % 16] ^ ((3 + index * 7) & 0xFF)
            for index, byte in enumerate(plain)
        )

    payload = table + encode(first) + (b"\x00" * 48) + table + encode(second)
    pe = {
        "image_base": 0x140000000,
        "sections": [
            {
                "name": ".rdata",
                "virtual_address": 0x4C000,
                "virtual_size": len(payload),
                "raw_size": len(payload),
                "raw_offset": 0,
            }
        ],
    }
    hits = recover_static_xor_configs(payload, pe)
    assert len(hits) >= 2
    addr_a = hits[0]["output_buffer"]["address"]
    addr_b = hits[1]["output_buffer"]["address"]
    assert addr_a != addr_b
    source_rows = [
        SimpleNamespace(
            id="decode-a",
            artifact_id="artifact-1",
            kind="encoded_blob",
            value={"verification_result": {"status": "UNVERIFIED_STATIC_CANDIDATE"}},
            anchor={"function_entry": "0x140003000"},
        ),
        SimpleNamespace(
            id="decode-b",
            artifact_id="artifact-1",
            kind="encoded_blob",
            value={"verification_result": {"status": "UNVERIFIED_STATIC_CANDIDATE"}},
            anchor={"function_entry": "0x140008000"},
        ),
        SimpleNamespace(
            id="loadlibrary-argument",
            artifact_id="artifact-1",
            kind="api_argument_trace",
            value={
                "api": "LoadLibraryW",
                "callsite": "0x140003020",
                "arguments": [
                    {"index": 0, "value": hex(int(addr_a)), "resolved": True},
                ],
            },
            anchor={"function_entry": "0x140003000", "callsite": "0x140003020"},
        ),
    ]
    action = ActionSpec(
        id="decode-two-buffers",
        action_type=ActionType.DECODE_CANDIDATE,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        parameters={"target": "xor"},
        target_selector={"target": "xor"},
        expected_evidence_kinds=("decode_result",),
    )
    observations = service._derive_investigation_observations(
        source_rows,
        action,
        artifact_content=payload,
        pe_summary=pe,
    )
    results = [item for item in observations if item["kind"] == "decode_result"]
    statused = [item for item in results if "consumer_status" in item["value"]]
    assert len(statused) == 2
    linked = [item for item in statused if item["value"].get("consumer_status") == "LINKED_STATIC"]
    unidentified = [
        item for item in statused if item["value"].get("consumer_status") == "NOT_IDENTIFIED"
    ]
    assert len(linked) == 1
    assert linked[0]["value"]["consumer_candidates"][0]["api"] == "LoadLibraryW"
    assert len(unidentified) == 1
    texts = " ".join(str(item["value"]) for item in results)
    assert "unused.dll" in texts or "payload.exe" in texts


def test_trace_api_argument_stamps_decoded_output_when_operand_is_output_buffer(test_settings) -> None:
    """B01 live path: TRACE_API_ARGUMENT emits the exact-buffer consumer row."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    output_buffer = {
        "address_space": "image",
        "address": 0x140005000,
        "length": 24,
    }
    rows = [
        SimpleNamespace(
            id="decode-producer",
            artifact_id="artifact-1",
            kind="encoded_blob",
            value={
                "output_buffer": output_buffer,
                "memory_addresses": [0x140005000],
                "verification_result": {
                    "status": "VERIFIED_STATIC_DATA",
                    "virtual_address": 0x140005000,
                    "length": 24,
                },
            },
            anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="ctx-1",
            artifact_id="artifact-1",
            kind="function_context",
            value={
                "name": "FUN_decode",
                "entry": "0x401000",
                "call_targets": [{"target_name": "LoadLibraryW", "from": "0x401020"}],
            },
            anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="ins-1",
            artifact_id="artifact-1",
            kind="function_instruction_window",
            value={
                "instructions": [
                    {"address": "0x401010", "text": "LEA RCX, [0x140005000]"},
                    {"address": "0x401020", "text": "CALL LoadLibraryW"},
                ]
            },
            anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="call-1",
            artifact_id="artifact-1",
            kind="function_call",
            value={"api": "LoadLibraryW", "from": "0x401020"},
            anchor={"function_entry": "0x401000", "callsite": "0x401020"},
        ),
    ]
    action = ActionSpec(
        id="trace-decoded-output",
        action_type=ActionType.TRACE_API_ARGUMENT,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        target_selector={"target": "LoadLibraryW"},
        expected_evidence_kinds=("api_argument_trace",),
        source_evidence_ids=("decode-producer", "ctx-1", "ins-1", "call-1"),
    )
    observations = service._derive_investigation_observations(rows, action)
    linked = [
        item["value"]
        for item in observations
        if item["kind"] == "api_argument_trace"
        and item["value"].get("source_role") == "decoded_output"
    ]
    assert len(linked) == 1
    assert linked[0]["producer_evidence_id"] == "decode-producer"
    assert linked[0]["source_buffer"] == {**output_buffer, "artifact_id": "artifact-1"}
    assert linked[0]["argument_index"] == 0
    assert linked[0]["resolved"] is True
    assert any(
        item["kind"] == "value_flow"
        and item["value"].get("relation") == "output_to_consumer"
        for item in observations
    )
    assert next(
        item["nature"]
        for item in observations
        if item["kind"] == "api_argument_trace" and item["value"].get("source_role") == "decoded_output"
    ) == "STATIC_INFERRED"


def test_trace_createprocess_command_buffer_emits_decode_process_join(test_settings) -> None:
    """C3: TRACE must Join decoder output to CreateProcess when lpCommandLine is that buffer."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    output_buffer = {
        "address_space": "image",
        "address": 0x140005000,
        "length": 24,
    }
    rows = [
        SimpleNamespace(
            id="decode-producer",
            artifact_id="artifact-1",
            kind="encoded_blob",
            value={
                "output_buffer": output_buffer,
                "memory_addresses": [0x140005000],
                "verification_result": {
                    "status": "VERIFIED_STATIC_DATA",
                    "virtual_address": 0x140005000,
                    "length": 24,
                    "decoded_text": "FoxitPDFReader.exe",
                },
            },
            anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="ctx-1",
            artifact_id="artifact-1",
            kind="function_context",
            value={
                "name": "FUN_launch",
                "entry": "0x401000",
                "call_targets": [{"target_name": "CreateProcessW", "from": "0x401020"}],
            },
            anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="ins-1",
            artifact_id="artifact-1",
            kind="function_instruction_window",
            value={
                "instructions": [
                    {"address": "0x401010", "text": "LEA RDX, [0x140005000]"},
                    {"address": "0x401020", "text": "CALL CreateProcessW"},
                ]
            },
            anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="call-1",
            artifact_id="artifact-1",
            kind="function_call",
            value={"api": "CreateProcessW", "from": "0x401020"},
            anchor={"function_entry": "0x401000", "callsite": "0x401020"},
        ),
    ]
    action = ActionSpec(
        id="trace-createprocess-join",
        action_type=ActionType.TRACE_API_ARGUMENT,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        target_selector={"target": "CreateProcessW"},
        expected_evidence_kinds=("api_argument_trace",),
        source_evidence_ids=("decode-producer", "ctx-1", "ins-1", "call-1"),
    )
    observations = service._derive_investigation_observations(rows, action)
    joined = [
        item["value"]
        for item in observations
        if item["kind"] == "value_flow"
        and item["value"].get("relation") == "decode_output_to_process_command"
    ]
    assert joined, "same-buffer CreateProcess command must mint decode_output_to_process_command"
    assert joined[0]["output_buffer"]["address"] == 0x140005000
    assert joined[0]["command_buffer"]["address"] == 0x140005000
    assert joined[0]["source_evidence_id"] == "decode-producer"
    assert joined[0]["target_evidence_id"] in {"call-1", "ctx-1"}


def test_trace_virtualalloc_emits_decode_output_consumer(test_settings) -> None:
    """C3: TRACE joins CryptoAPI/decode output to VirtualAlloc on the same buffer."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    output_buffer = {
        "address_space": "image",
        "address": 0x14005A000,
        "length": 0x1000,
    }
    rows = [
        SimpleNamespace(
            id="decode-producer",
            artifact_id="artifact-1",
            kind="encoded_blob",
            value={
                "output_buffer": output_buffer,
                "memory_addresses": [0x14005A000],
                "verification_result": {
                    "status": "VERIFIED_STATIC_DATA",
                    "virtual_address": 0x14005A000,
                    "length": 0x1000,
                },
            },
            anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="ctx-1",
            artifact_id="artifact-1",
            kind="function_context",
            value={
                "name": "FUN_crypt",
                "entry": "0x401000",
                "call_targets": [{"target_name": "VirtualAlloc", "from": "0x401020"}],
            },
            anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="ins-1",
            artifact_id="artifact-1",
            kind="function_instruction_window",
            value={
                "instructions": [
                    {"address": "0x401010", "text": "LEA RCX, [0x14005A000]"},
                    {"address": "0x401020", "text": "CALL VirtualAlloc"},
                ]
            },
            anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="call-1",
            artifact_id="artifact-1",
            kind="function_call",
            value={"api": "VirtualAlloc", "from": "0x401020"},
            anchor={"function_entry": "0x401000", "callsite": "0x401020"},
        ),
    ]
    action = ActionSpec(
        id="trace-virtualalloc-join",
        action_type=ActionType.TRACE_API_ARGUMENT,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        target_selector={"target": "VirtualAlloc"},
        expected_evidence_kinds=("api_argument_trace",),
        source_evidence_ids=("decode-producer", "ctx-1", "ins-1", "call-1"),
    )
    observations = service._derive_investigation_observations(rows, action)
    joined = [
        item["value"]
        for item in observations
        if item["kind"] == "value_flow"
        and item["value"].get("relation") == "output_to_consumer"
    ]
    assert joined, "same-buffer VirtualAlloc must mint output_to_consumer"
    assert joined[0]["output_buffer"]["address"] == 0x14005A000
    assert joined[0].get("api") == "VirtualAlloc" or joined[0].get("consumer") == "VirtualAlloc"
    assert "executed" not in str(joined[0]).casefold()


def test_trace_api_argument_does_not_treat_ciphertext_va_as_decoded_output(test_settings) -> None:
    """B01: an encoded-blob VA without output_buffer is not a consumer link."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    rows = [
        SimpleNamespace(
            id="cipher-only",
            artifact_id="artifact-1",
            kind="encoded_blob",
            value={"memory_addresses": [0x140005000], "length": 24},
            anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="ctx-1",
            artifact_id="artifact-1",
            kind="function_context",
            value={
                "name": "FUN_decode",
                "entry": "0x401000",
                "call_targets": [{"target_name": "LoadLibraryW", "from": "0x401020"}],
            },
            anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="ins-1",
            artifact_id="artifact-1",
            kind="function_instruction_window",
            value={
                "instructions": [
                    {"address": "0x401010", "text": "LEA RCX, [0x140005000]"},
                    {"address": "0x401020", "text": "CALL LoadLibraryW"},
                ]
            },
            anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="call-1",
            artifact_id="artifact-1",
            kind="function_call",
            value={"api": "LoadLibraryW", "from": "0x401020"},
            anchor={"function_entry": "0x401000", "callsite": "0x401020"},
        ),
    ]
    action = ActionSpec(
        id="trace-cipher-only",
        action_type=ActionType.TRACE_API_ARGUMENT,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        target_selector={"target": "LoadLibraryW"},
        expected_evidence_kinds=("api_argument_trace",),
        source_evidence_ids=("cipher-only", "ctx-1", "ins-1", "call-1"),
    )
    observations = service._derive_investigation_observations(rows, action)
    assert not any(
        item["kind"] == "api_argument_trace" and item["value"].get("source_role") == "decoded_output"
        for item in observations
    )


def test_decode_result_links_nested_argument_window_to_output_buffer(test_settings) -> None:
    """DECODE_CANDIDATE may run after TRACE and still recover exact-buffer identity."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    output_buffer = {
        "address_space": "image",
        "address": 0x140005000,
        "length": 24,
    }
    source_rows = [
        SimpleNamespace(
            id="decode-producer",
            kind="encoded_blob",
            value={
                "output_buffer": output_buffer,
                "verification_result": {
                    "status": "VERIFIED_STATIC_DATA",
                    "decoded_text": "https://example.invalid/gate",
                    "virtual_address": 0x140005000,
                    "length": 24,
                },
            },
            anchor={"function_entry": "0x140003000"},
        ),
        SimpleNamespace(
            id="nested-trace",
            kind="api_argument_trace",
            value={
                "api": "LoadLibraryW",
                "callsite": "0x140003020",
                "arguments": [
                    {"index": 0, "register": "RCX", "value": "0x140005000", "resolved": True},
                ],
                "resolved": False,
            },
            anchor={"function_entry": "0x140003000", "callsite": "0x140003020"},
        ),
    ]
    action = ActionSpec(
        id="decode-nested-window",
        action_type=ActionType.DECODE_CANDIDATE,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        parameters={"target": "xor"},
        target_selector={"target": "xor"},
        expected_evidence_kinds=("decode_result",),
    )
    observations = service._derive_investigation_observations(source_rows, action)
    result = next(item for item in observations if item["kind"] == "decode_result")
    assert result["value"]["consumer_status"] == "LINKED_STATIC"
    assert result["value"]["consumer_candidates"][0]["api"] == "LoadLibraryW"


def test_decode_candidate_emits_process_join_when_command_buffer_matches(test_settings) -> None:
    """C3: DECODE_CANDIDATE mints decode_output_to_process_command for lpCommandLine."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    output_buffer = {
        "address_space": "image",
        "address": 0x140005000,
        "length": 24,
    }
    source_rows = [
        SimpleNamespace(
            id="decode-producer",
            kind="encoded_blob",
            value={
                "output_buffer": output_buffer,
                "verification_result": {
                    "status": "VERIFIED_STATIC_DATA",
                    "decoded_text": "FoxitPDFReader.exe",
                    "virtual_address": 0x140005000,
                    "length": 24,
                },
            },
            anchor={"function_entry": "0x140003000"},
        ),
        SimpleNamespace(
            id="nested-trace",
            kind="api_argument_trace",
            value={
                "api": "CreateProcessW",
                "callsite": "0x140003020",
                "arguments": [
                    {"index": 1, "name": "lpCommandLine", "value": "0x140005000", "resolved": True},
                ],
                "resolved": False,
            },
            anchor={"function_entry": "0x140003000", "callsite": "0x140003020"},
        ),
    ]
    action = ActionSpec(
        id="decode-process-join",
        action_type=ActionType.DECODE_CANDIDATE,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        parameters={"target": "xor"},
        target_selector={"target": "xor"},
        expected_evidence_kinds=("decode_result",),
    )
    observations = service._derive_investigation_observations(source_rows, action)
    joined = [
        item["value"]
        for item in observations
        if item["kind"] == "value_flow"
        and item["value"].get("relation") == "decode_output_to_process_command"
    ]
    assert joined
    assert joined[0]["output_buffer"]["address"] == 0x140005000
    assert joined[0]["command_buffer"]["address"] == 0x140005000


def test_decode_candidate_links_output_pointer_loaded_into_a_call(test_settings) -> None:
    """Resume-style decode windows never emit api_argument_trace; the CALL still consumes the VA."""
    from threat_report_agent.investigation.behavior_catalog import BehaviorCatalog

    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    output_buffer = {
        "address_space": "image",
        "address": 0x140005000,
        "length": 24,
        "artifact_id": "artifact-1",
    }
    source_rows = [
        SimpleNamespace(
            id="decode-producer",
            artifact_id="artifact-1",
            kind="encoded_blob",
            value={
                "output_buffer": output_buffer,
                "verification_result": {
                    "status": "VERIFIED_STATIC_DATA",
                    "formula": "key_table_modulo_xor_counter",
                    "key_table": [1, 2, 3],
                    "plaintext_hex": "687474703a2f2f6578616d706c652e696e76616c6964",
                    "ciphertext_hex": "00" * 22,
                    "output_hash": "a" * 64,
                    "output_buffer": output_buffer,
                    "decoded_text": "http://example.invalid",
                    "virtual_address": 0x140005000,
                    "length": 24,
                },
            },
            anchor={"function_entry": "0x140003000"},
        ),
        SimpleNamespace(
            id="ins-1",
            artifact_id="artifact-1",
            kind="function_instruction_window",
            value={
                "entry": "0x140003000",
                "instructions": [
                    {"address": "0x140003010", "text": "LEA RCX, [0x140005000]"},
                    {"address": "0x140003017", "text": "CALL WinHttpConnect"},
                ],
            },
            anchor={"function_entry": "0x140003000"},
        ),
    ]
    action = ActionSpec(
        id="decode-pointer-consumer",
        action_type=ActionType.DECODE_CANDIDATE,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        parameters={"target": "xor"},
        target_selector={"target": "xor"},
        expected_evidence_kinds=("decode_result",),
    )
    observations = service._derive_investigation_observations(source_rows, action)
    result = next(
        item
        for item in observations
        if item["kind"] == "decode_result" and item["value"].get("consumer_status")
    )
    assert result["value"]["consumer_status"] == "LINKED_STATIC"
    assert result["value"]["consumer_candidates"][0]["api"] == "WinHttpConnect"
    assert any(
        item["kind"] == "value_flow" and item["value"].get("relation") == "output_to_consumer"
        for item in observations
    )
    catalog_rows = [
        {
            "id": row.id,
            "kind": row.kind,
            "nature": "STATIC_OBSERVED",
            "value": row.value if isinstance(row.value, dict) else {},
        }
        for row in source_rows
    ]
    catalog_rows.extend(
        {
            "id": f"obs-{index}",
            "kind": item["kind"],
            "nature": item.get("nature") or "STATIC_DERIVED",
            "value": item["value"],
        }
        for index, item in enumerate(observations)
    )
    evaluation = BehaviorCatalog().evaluate("config-and-crypto", catalog_rows)
    assert "output_to_consumer" not in evaluation.missing
    assert "algorithm" not in evaluation.missing


def test_decode_candidate_links_rdata_xref_without_argument_register(test_settings) -> None:
    """A same-VA data xref is a locator, not an object-level decode consumer."""
    from threat_report_agent.investigation.behavior_catalog import BehaviorCatalog

    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    output_buffer = {
        "address_space": "image",
        "address": 0x14004C8E1,
        "length": 31,
        "artifact_id": "artifact-1",
    }
    source_rows = [
        SimpleNamespace(
            id="decode-producer",
            artifact_id="artifact-1",
            kind="encoded_blob",
            value={
                "output_buffer": output_buffer,
                "verification_result": {
                    "status": "VERIFIED_STATIC_DATA",
                    "formula": "key_table_modulo_xor_counter",
                    "key_table": [182, 144, 1, 106],
                    "counter_initial": 3,
                    "counter_step": 7,
                    "plaintext_hex": "687474703a2f2f6578616d706c652e696e76616c6964",
                    "ciphertext_hex": "00" * 22,
                    "output_hash": "b" * 64,
                    "output_buffer": output_buffer,
                    "decoded_text": "http://example.invalid",
                    "virtual_address": 0x14004C8E1,
                    "length": 31,
                },
            },
            anchor={"rva": "0x4c8e1"},
        ),
        SimpleNamespace(
            id="xref-1",
            artifact_id="artifact-1",
            kind="data_reference",
            value={
                "from": "0x140003010",
                "to": "0x14004c8e1",
                "target_name": "DAT_14004c8e1",
            },
            anchor={"function_entry": "0x140003000", "callsite": "0x140003010"},
        ),
        SimpleNamespace(
            id="ins-unrelated",
            artifact_id="artifact-1",
            kind="function_instruction_window",
            value={
                "entry": "0x140003000",
                "instructions": [
                    {"address": "0x140003000", "text": "MOV RAX, RAX"},
                    {"address": "0x140003003", "text": "RET"},
                ],
            },
            anchor={"function_entry": "0x140003000"},
        ),
    ]
    action = ActionSpec(
        id="decode-xref-consumer",
        action_type=ActionType.DECODE_CANDIDATE,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        parameters={"target": "xor"},
        target_selector={"target": "xor"},
        expected_evidence_kinds=("decode_result",),
    )
    observations = service._derive_investigation_observations(source_rows, action)
    result = next(
        item
        for item in observations
        if item["kind"] == "decode_result" and item["value"].get("consumer_status")
    )
    assert result["value"]["consumer_status"] == "NOT_IDENTIFIED"
    assert result["value"]["consumer_candidates"][0]["evidence_id"] == "xref-1"
    assert not any(
        item["kind"] == "value_flow" and item["value"].get("relation") == "output_to_consumer"
        for item in observations
    )
    catalog_rows = [
        {
            "id": row.id,
            "kind": row.kind,
            "nature": "STATIC_OBSERVED",
            "value": row.value if isinstance(row.value, dict) else {},
        }
        for row in source_rows
    ]
    catalog_rows.extend(
        {
            "id": f"obs-{index}",
            "kind": item["kind"],
            "nature": item.get("nature") or "STATIC_DERIVED",
            "value": item["value"],
        }
        for index, item in enumerate(observations)
    )
    evaluation = BehaviorCatalog().evaluate("config-and-crypto", catalog_rows)
    assert "output_to_consumer" in evaluation.missing


def test_trace_api_argument_skips_ghidra_string_labels(test_settings) -> None:
    """Ghidra s_/DAT_ labels are data names, not recovered WinHTTP APIs."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    rows = [
        SimpleNamespace(
            id="ins-1",
            artifact_id="artifact-1",
            kind="function_instruction_window",
            value={
                "instructions": [
                    {
                        "address": "0x140003010",
                        "text": "CALL s_winhttp_export_not_found_14004c66f",
                    }
                ]
            },
            anchor={"function_entry": "0x140003000"},
        ),
        SimpleNamespace(
            id="call-1",
            artifact_id="artifact-1",
            kind="function_call",
            value={
                "api": "s_winhttp_export_not_found_14004c66f",
                "from": "0x140003010",
            },
            anchor={"function_entry": "0x140003000", "callsite": "0x140003010"},
        ),
    ]
    action = ActionSpec(
        id="trace-label",
        action_type=ActionType.TRACE_API_ARGUMENT,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        target_selector={"target": "s_winhttp_export_not_found_14004c66f"},
        expected_evidence_kinds=("api_argument_trace",),
        source_evidence_ids=("ins-1", "call-1"),
    )
    observations = service._derive_investigation_observations(rows, action)
    traces = [
        item
        for item in observations
        if item["kind"] == "api_argument_trace"
        and "s_winhttp" in str(item["value"].get("api") or "").casefold()
    ]
    assert traces == []


def test_return_value_action_recovers_caller_argument_flow(test_settings) -> None:
    service = AnalysisService(
        test_settings, Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    rows = [
        SimpleNamespace(
            id="producer-context", kind="function_context",
            value={"name": "decode_config", "entry": "0x2000",
                   "call_targets": [{"target_name": "helper", "from": "0x2005"}]},
            anchor={"function_entry": "0x2000"},
        ),
        SimpleNamespace(
            id="caller-context", kind="function_context",
            value={"name": "load_config", "entry": "0x1000", "architecture": "x86_64",
                   "call_targets": [{"target_name": "decode_config", "from": "0x1000"},
                                    {"target_name": "LoadLibraryW", "from": "0x1010"}]},
            anchor={"function_entry": "0x1000"},
        ),
        SimpleNamespace(
            id="caller-instructions", kind="function_instruction_window",
            value={"instructions": [
                {"address": "0x1000", "text": "CALL decode_config"},
                {"address": "0x1005", "text": "MOV RCX, RAX"},
                {"address": "0x1010", "text": "CALL LoadLibraryW"},
            ]}, anchor={"function_entry": "0x1000"},
        ),
    ]
    action = ActionSpec(
        id="trace-return", action_type=ActionType.TRACE_RETURN_VALUE,
        thread_id="thread-1", hypothesis_id="hypothesis-1", artifact_id="artifact-1",
        parameters={"target": "decode_config"}, expected_evidence_kinds=("value_flow",),
        source_evidence_ids=("producer-context",),
    )
    observations = service._derive_investigation_observations(rows, action)
    flow = next(row["value"] for row in observations if row["kind"] == "value_flow")
    assert flow["consumers"] == ["LoadLibraryW"]
    assert flow["links"][0]["producer_callsite"] == "0x1000"
    assert flow["links"][0]["argument_index"] == 0
    assert "caller-instructions" in flow["derivation"]["input_evidence_ids"]


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
