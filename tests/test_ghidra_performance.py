from types import SimpleNamespace
from unittest.mock import Mock

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import AnalysisTask, Artifact, ContentBlob, Evidence, ToolRun
from threat_report_agent.service import AnalysisService


def test_behavior_claim_validation_is_bounded(test_settings) -> None:
    service = AnalysisService(
        test_settings, Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    session = Mock()
    service._infer_component_relations = Mock()
    service._audit = Mock()
    service._record_ghidra_behavior_claims(
        session,
        SimpleNamespace(id='task', case_id='case'),
        SimpleNamespace(logical_path='sample.exe'),
        {'name': 'entry', 'entry': '0x1000',
         'references_from': [{'target_name': 'CreateProcessW'}]},
        ('evidence-1',),
    )
    session.scalars.assert_not_called()


def test_ghidra_similarity_filter_uses_processed_function_budget(test_settings) -> None:
    """Unselected exporter functions must not enter the similarity index."""
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    case = service.create_case("bounded ghidra similarity")
    stored = store.put(b"static fixture")
    with database.session_factory.begin() as session:
        session.add(ContentBlob(
            sha256=stored.sha256,
            size=stored.size,
            media_type="application/octet-stream",
            storage_key=stored.storage_key,
        ))
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=stored.sha256,
            logical_path="fixture.exe",
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
            environment={"sample_execution": False},
        )
        session.add(source_run)
        session.flush()
        source_evidence_ids = {}
        for entry, value in (("0x401000", "44e0cbb281dca986"), ("0x402000", "44e0cbb281dca986")):
            evidence = Evidence(
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=source_run.id,
                module="static_triage",
                kind="function_simhash",
                nature="STATIC_OBSERVED",
                value={
                    "value": value,
                        "algorithm": "charikar-simhash-64",
                        "feature": "mnemonic-4gram",
                        "hash": "md5-prefix-64-le",
                },
                anchor={"entry": entry},
            )
            session.add(evidence)
            session.flush()
            source_evidence_ids[entry] = evidence.id
        session.flush()
        service._record_function_similarity(
            session,
            task,
            artifact,
            source_run,
            processed_function_entries={"0x401000"},
        )
        similarity_rows = list(session.query(Evidence).filter(
            Evidence.task_id == task.id,
            Evidence.kind == "function_similarity",
        ))
    assert similarity_rows
    assert {
        row.value["source_evidence_id"] for row in similarity_rows
    } == {source_evidence_ids["0x401000"]}


def test_planner_history_bounds_large_evidence_id_lists() -> None:
    actions = [{
        "action_key": "artifact:pe-parser",
        "new_evidence_count": 5000,
        "new_evidence_ids": [f"evidence-{index}" for index in range(5000)],
    }]
    bounded = AnalysisService._bound_completed_actions(actions)
    assert len(bounded) == 1
    assert len(bounded[0]["new_evidence_ids"]) == AnalysisService._MAX_COMPLETED_ACTION_EVIDENCE_IDS
    assert bounded[0]["new_evidence_count"] == 5000
    assert bounded[0]["new_evidence_ids_truncated"] == 5000 - AnalysisService._MAX_COMPLETED_ACTION_EVIDENCE_IDS
