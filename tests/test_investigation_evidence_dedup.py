from __future__ import annotations

from sqlalchemy import select

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import (
    AnalysisTask,
    Artifact,
    CaseRecord,
    ContentBlob,
    Evidence,
    InvestigationActionRecord,
    InvestigationHypothesisRecord,
    InvestigationThreadRecord,
    ToolRun,
)
from threat_report_agent.service import AnalysisService


def test_identical_static_observations_are_reused_across_action_scopes(test_settings) -> None:
    """A repeated static query must not append an equivalent Evidence row.

    Independent mechanism threads may intentionally use different action
    scopes, so queue de-duplication alone cannot prevent this duplication.
    The immutable observation should be persisted once and referenced by both
    actions; provenance for each action remains in its own action/audit row.
    """
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()

    with database.session_factory.begin() as session:
        case = CaseRecord(id="case-evidence-reuse", title="Evidence reuse")
        session.add(case)
        blob = store.put(b"MZ" + b"\0" * 64)
        session.add(
            ContentBlob(
                sha256=blob.sha256,
                size=blob.size,
                media_type="application/octet-stream",
                storage_key=blob.storage_key,
            )
        )
        session.flush()
        task = AnalysisTask(id="task-evidence-reuse", case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            id="artifact-evidence-reuse",
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="reuse.exe",
            detected_type="pe",
            role="EXECUTABLE",
        )
        session.add(artifact)
        session.flush()
        tool_run = ToolRun(
            id="run-evidence-reuse",
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="ghidra",
            tool_version="test",
            status="SUCCEEDED",
        )
        session.add(tool_run)
        session.flush()
        session.add(
            Evidence(
                id="context-evidence-reuse",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=tool_run.id,
                module="static",
                kind="function_context",
                nature="STATIC_OBSERVED",
                value={
                    "name": "resolver",
                    "entry": "0x1000",
                    "call_targets": [{"target_name": "GetProcAddress", "from": "0x1010"}],
                },
                anchor={"function_entry": "0x1000"},
            )
        )
        session.flush()
        session.add(
            InvestigationThreadRecord(
                id="thread-evidence-reuse",
                task_id=task.id,
                artifact_id=artifact.id,
                question="Which static call path is present?",
            )
        )
        session.flush()
        session.add(
            InvestigationHypothesisRecord(
                id="hypothesis-evidence-reuse",
                task_id=task.id,
                thread_id="thread-evidence-reuse",
                statement="The resolver has a statically recoverable callee.",
                dimension="dynamic_api_resolution",
            )
        )
        session.flush()
        for index, scope in enumerate(("resolver-path", "consumer-path")):
            session.add(
                InvestigationActionRecord(
                    id=f"action-evidence-reuse-{index}",
                    task_id=task.id,
                    thread_id="thread-evidence-reuse",
                    hypothesis_id="hypothesis-evidence-reuse",
                    artifact_id=artifact.id,
                    action_type="GET_CALLEES",
                    reason="repeat the same bounded static query",
                    parameters={
                        "_analysis_plan": {"action_scope": scope},
                        "_source_evidence_ids": ["context-evidence-reuse"],
                        "_planner_turn_id": f"turn-evidence-reuse-{index}",
                    },
                    target_selector={"target": "0x1000"},
                    expected_evidence_kinds=["function_call"],
                    success_condition="new_targeted_evidence",
                    failure_interpretation="UNKNOWN",
                    cost_units=1,
                    priority=1,
                    status="QUEUED",
                )
            )
        task_id = task.id

    service.run_investigation_loop(task_id, model_actions_only=True)

    with database.session_factory() as session:
        rows = list(
            session.scalars(
                select(Evidence).where(
                    Evidence.task_id == task_id,
                    Evidence.module == "investigation",
                    Evidence.kind == "function_call",
                )
            )
        )
        actions = list(
            session.scalars(
                select(InvestigationActionRecord).where(
                    InvestigationActionRecord.task_id == task_id,
                    InvestigationActionRecord.action_type == "GET_CALLEES",
                )
            )
        )

    assert len(rows) == 1
    assert len(actions) == 2
    assert all(action.status == "SUCCEEDED" for action in actions)
    assert {item for action in actions for item in action.result_evidence_ids} == {rows[0].id}
