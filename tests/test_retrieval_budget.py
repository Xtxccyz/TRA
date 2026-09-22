from __future__ import annotations

import pytest

from threat_report_agent.database import Database
from threat_report_agent.evidence_recovery import BoundedEvidenceRepository, QuestionCentricRetriever, RetrievalRequest
from threat_report_agent.models import AnalysisTask, Artifact, CaseRecord, ContentBlob, Evidence, ToolRun


@pytest.fixture
def evidence_corpus(test_settings):
    database = Database(test_settings.database_url)
    database.create_schema()
    with database.session_factory.begin() as session:
        case = CaseRecord(title="bounded retrieval")
        session.add(case)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.add(ContentBlob(sha256="e" * 64, size=1, media_type="application/octet-stream", storage_key="test"))
        session.flush()
        artifact = Artifact(task_id=task.id, content_sha256="e" * 64, logical_path="test.exe", detected_type="pe")
        session.add(artifact)
        session.flush()
        run = ToolRun(task_id=task.id, artifact_id=artifact.id, tool_name="ghidra-headless", tool_version="test", status="SUCCEEDED")
        session.add(run)
        session.flush()

        def add(identifier, kind, value, anchor=None, *, artifact_id=None):
            row = Evidence(id=identifier, task_id=task.id, artifact_id=artifact_id or artifact.id,
                           tool_run_id=run.id, module="static", kind=kind,
                           nature="STATIC_OBSERVED", value=value, anchor=anchor or {})
            session.add(row)
            return row

        yield session, task, artifact, add


def test_graph_evidence_precedes_unrelated_kind_backfill(evidence_corpus):
    session, task, artifact, add = evidence_corpus
    for index in range(12):
        add(f"a-{index:02}", "function_context", {"name": f"unrelated_{index}"})
    add("y-context", "function_context", {
        "name": "resolver", "entry": "0x401000",
        "call_targets": [{"target_name": "GetProcAddress"}],
        "data_references": [{"address": "0x409000"}],
    }, {"function_entry": "0x401000"})
    add("z-window", "function_instruction_window", {"instructions": [{"text": "MOV EAX, 7"}]}, {"function_entry": "0x401000"})
    add("z-data", "data_reference", {"address": "0x409000", "text": "encoded bytes"})
    session.flush()
    request = RetrievalRequest(thread_id="t", artifact_id=artifact.id, hypothesis_type="resolver",
                               target_anchors=("GetProcAddress",), required_evidence_kinds=("function_context",),
                               caller_depth=1, data_xref_depth=1, candidate_limit=4)
    batch = BoundedEvidenceRepository().retrieve(session, task_id=task.id, request=request)
    assert {"y-context", "z-window", "z-data"} <= {row.id for row in batch.rows}
    assert batch.candidate_count <= request.candidate_limit
    assert batch.query_count <= 10


def test_selector_aliases_do_not_spend_multiple_candidate_slots(evidence_corpus):
    session, task, artifact, add = evidence_corpus
    add("a-both", "function_context", {"call_targets": ["GetProcAddress", "LoadLibraryW"]})
    add("z-consumer", "function_call", {"api": "GetProcAddress"})
    session.flush()
    request = RetrievalRequest(thread_id="t", artifact_id=artifact.id, hypothesis_type="resolver",
                               target_anchors=("GetProcAddress", "LoadLibraryW"),
                               required_evidence_kinds=(), candidate_limit=2)
    batch = BoundedEvidenceRepository().retrieve(session, task_id=task.id, request=request)
    assert {row.id for row in batch.rows} == {"a-both", "z-consumer"}


def test_long_instruction_window_remains_retrievable_by_function_anchor(evidence_corpus):
    session, task, artifact, add = evidence_corpus
    add("large-window", "function_instruction_window", {
        "instructions": [{"text": f"ADD EAX, constant_{index:03}"} for index in range(64)],
    }, {"function_entry": "fff12345", "rva": 123456})
    session.flush()
    for target in ("fff12345", 123456):
        request = RetrievalRequest(thread_id="t", artifact_id=artifact.id, hypothesis_type="argument",
                                   target_anchors=(str(target),), required_evidence_kinds=(), candidate_limit=1)
        batch = BoundedEvidenceRepository().retrieve(session, task_id=task.id, request=request)
        assert [row.id for row in batch.rows] == ["large-window"]


@pytest.mark.parametrize("kind", ["pcode_slice", "value_flow", "resolved_api", "mechanism_decode_window", "abstract_execution_trace"])
def test_deep_action_results_are_retrievable_without_global_kind_scan(evidence_corpus, kind):
    session, task, artifact, add = evidence_corpus
    add("deep-result", kind, {"function_entry": "0x405000", "source_evidence_ids": ["source"]},
        {"function_entry": "0x405000"})
    session.flush()
    request = RetrievalRequest(thread_id="t", artifact_id=artifact.id, hypothesis_type="deep-followup",
                               target_anchors=("0x405000",), required_evidence_kinds=(), candidate_limit=4)
    batch = BoundedEvidenceRepository().retrieve(session, task_id=task.id, request=request)
    assert [row.id for row in batch.rows] == ["deep-result"]


@pytest.mark.parametrize("max_items", [1, 2])
def test_profile_minimums_respect_hard_context_limit(max_items):
    request = RetrievalRequest(thread_id="t", artifact_id="a", hypothesis_type="resolver",
                               target_anchors=("GetProcAddress",), required_evidence_kinds=("xref", "function_context", "data_reference"),
                               playbook_id="dynamic-api-resolution")
    packet = QuestionCentricRetriever(max_items=max_items).build(request, [
        {"id": kind, "artifact_id": "a", "kind": kind, "value": {"api": "GetProcAddress"}, "anchor": {}}
        for kind in request.required_evidence_kinds
    ])
    assert len(packet.items) == max_items
    assert len(packet.exclusion_reasons) == 3 - max_items


def test_hex_function_address_does_not_match_a_suffix_token(evidence_corpus):
    session, task, artifact, add = evidence_corpus
    add("a-unrelated", "string", {"text": "c520"})
    add("z-target", "pcode_slice", {}, {"function_entry": "14000c520"})
    session.flush()
    request = RetrievalRequest(thread_id="t", artifact_id=artifact.id, hypothesis_type="followup",
                               target_anchors=("14000c520",), required_evidence_kinds=(), candidate_limit=1)
    batch = BoundedEvidenceRepository().retrieve(session, task_id=task.id, request=request)
    assert [row.id for row in batch.rows] == ["z-target"]


def test_targeted_deep_result_survives_many_same_function_call_rows(evidence_corpus):
    session, task, artifact, add = evidence_corpus
    for index in range(20):
        add(f"a-call-{index:02}", "function_call", {"api": "CloseHandle"}, {"function_entry": "0x403000"})
    add("z-context", "function_context", {"entry": "0x403000"})
    add("z-deep", "abstract_execution_trace", {}, {"function_entry": "0x403000"})
    session.flush()
    request = RetrievalRequest(thread_id="t", artifact_id=artifact.id, hypothesis_type="followup",
                               target_anchors=("0x403000",), required_evidence_kinds=(), candidate_limit=2)
    batch = BoundedEvidenceRepository().retrieve(session, task_id=task.id, request=request)
    assert {row.id for row in batch.rows} == {"z-context", "z-deep"}
