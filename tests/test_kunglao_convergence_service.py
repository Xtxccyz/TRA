from datetime import UTC, datetime

from sqlalchemy import select

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import (
    AnalysisTask,
    Artifact,
    ContentBlob,
    Evidence,
    InvestigationActionRecord,
    InvestigationHypothesisRecord,
    InvestigationThreadRecord,
    ToolRun,
)
from threat_report_agent.service import AnalysisService


def _seed_service(test_settings, name: str = "convergence"):
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    case = service.create_case(name)
    blob = store.put(b"MZ" + b"\0" * 64)
    with database.session_factory.begin() as session:
        session.add(ContentBlob(
            sha256=blob.sha256,
            size=blob.size,
            media_type="application/octet-stream",
            storage_key=blob.storage_key,
        ))
        session.flush()
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="RUNNING",
            strategy_snapshot={"investigation": {"threads": []}},
        )
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="convergence.exe",
            detected_type="pe",
            role="EXECUTABLE",
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
        session.add(Evidence(
            id="convergence-anchor",
            task_id=task.id,
            artifact_id=artifact.id,
            tool_run_id=tool_run.id,
            module="static",
            kind="function_context",
            nature="STATIC_OBSERVED",
            value={
                "name": "resolver",
                "entry": "0x1000",
                "call_targets": [{"target_name": "LoadLibraryA", "from": "0x1010"}],
            },
            anchor={"function_entry": "0x1000"},
        ))
        session.flush()
        thread = InvestigationThreadRecord(
            id="convergence-thread",
            task_id=task.id,
            artifact_id=artifact.id,
            question="Which method exposes the resolver consumer?",
            hypothesis_ids=["convergence-hypothesis"],
        )
        session.add(thread)
        session.flush()
        session.add(InvestigationHypothesisRecord(
            id="convergence-hypothesis",
            task_id=task.id,
            thread_id=thread.id,
            statement="The resolver may feed a loader path.",
            dimension="loader",
        ))
        session.flush()
        task.strategy_snapshot = {
            "investigation": {
                "threads": [{
                    "id": thread.id,
                    "artifact_id": artifact.id,
                    "question": thread.question,
                    "hypothesis_ids": ["convergence-hypothesis"],
                }],
                "seed_maps": {artifact.id: {"clusters": []}},
            },
            "dynamic_planning": {"action_history": []},
        }
        return database, service, task.id, artifact.id


def _failed_action_payload(action_type: str, *, requires_alternate: bool, next_type: str | None):
    return {
        "_source_evidence_ids": ["convergence-anchor"],
        "_analysis_plan": {
            "question": "Which method exposes the resolver consumer?",
            "hypothesis": "The resolver may feed a loader path.",
            "alternatives": ["unused wrapper"],
            "missing_evidence": ["consumer relationship"],
            "failure_meaning": "No result is not refutation.",
        },
        "_convergence": {
            "attempt_id": "prior-action",
            "method_id": f"{action_type}:prior",
            "method_assumption": "The selected method should expose a targeted consumer.",
            "assumption_validity": "not_justified",
            "next_method": next_type or "STATIC_BOUNDARY",
            "next_method_action_type": next_type,
            "frontier_fingerprint_before": "f" * 64,
            "frontier_fingerprint_after": "f" * 64,
            "outcome": "NO_NEW_EVIDENCE",
            "attempted_method_ids": [f"{action_type}:prior"],
            "requires_alternate": requires_alternate,
        },
    }


def test_service_materializes_one_different_method_after_no_gain(test_settings):
    database, service, task_id, artifact_id = _seed_service(test_settings, "alternate")
    with database.session_factory.begin() as session:
        session.add(InvestigationActionRecord(
            id="prior-action",
            task_id=task_id,
            thread_id="convergence-thread",
            hypothesis_id="convergence-hypothesis",
            artifact_id=artifact_id,
            action_type="GET_XREFS_TO",
            target_selector={"target": "MissingConsumer"},
            expected_evidence_kinds=["xref"],
            status="FAILED",
            error="NO_NEW_EVIDENCE",
            parameters=_failed_action_payload(
                "GET_XREFS_TO", requires_alternate=True, next_type="GET_XREFS_FROM"
            ),
            finished_at=datetime.now(UTC),
        ))

    service.run_investigation_loop(task_id, model_actions_only=True)
    with database.session_factory() as session:
        rows = list(session.scalars(select(InvestigationActionRecord).where(
            InvestigationActionRecord.task_id == task_id
        )))
    alternate_rows = [row for row in rows if row.action_type == "GET_XREFS_FROM"]
    assert len(alternate_rows) == 1
    assert alternate_rows[0].parameters["_convergence"]["alternate_of"] == "GET_XREFS_TO:prior"


def test_service_does_not_static_boundary_after_two_distinct_no_gain_methods(test_settings):
    database, service, task_id, artifact_id = _seed_service(test_settings, "stalled")
    with database.session_factory.begin() as session:
        session.add(InvestigationActionRecord(
            id="prior-action",
            task_id=task_id,
            thread_id="convergence-thread",
            hypothesis_id="convergence-hypothesis",
            artifact_id=artifact_id,
            action_type="GET_XREFS_TO",
            target_selector={"target": "MissingConsumer"},
            expected_evidence_kinds=["xref"],
            status="QUEUED",
            parameters={
                "_source_evidence_ids": ["convergence-anchor"],
                "_analysis_plan": {
                    "action_scope": "loader",
                    "next_method": "GET_XREFS_FROM",
                    "next_method_action_type": "GET_XREFS_FROM",
                },
            },
        ))

    # First pass records the failure contract for the original method.
    service.run_investigation_loop(task_id, model_actions_only=True)
    with database.session_factory() as session:
        original = session.get(InvestigationActionRecord, "prior-action")
    assert original is not None
    assert original.status == "FAILED"
    assert original.error == "NO_NEW_EVIDENCE"
    contract = (original.parameters or {}).get("_convergence") or {}
    assert contract.get("requires_alternate") is True
    assert contract.get("next_method_action_type") == "GET_XREFS_FROM"
    assert contract.get("gain_class") == "NO_NEW_EVIDENCE"
    assert contract.get("assumption_validity") == "not_justified"
    # The next bounded pass executes the stamped different method. Two dry
    # static methods must keep a concrete next method (decompile then isolated
    # emulation). STATIC_BOUNDARY is only honest after CONTROLLED_EMULATE.
    service.run_investigation_loop(task_id, model_actions_only=True)
    view = service.task_view(task_id)
    convergence = view["strategy_snapshot"]["investigation"]["convergence"]
    record = convergence["convergence-thread"]
    assert record["status"] == "PROGRESSING"
    assert record["intervention"] in {"GET_DECOMPILE", "CONTROLLED_EMULATE"}
    assert len(record["no_gain_method_ids"]) == 2
    assert not any("STATIC_BOUNDARY" in str(item) for item in view.get("limitations", []))
