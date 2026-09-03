from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import AnalysisTask, ToolRun
from threat_report_agent.service import AnalysisService


def _service(test_settings) -> tuple[AnalysisService, Database]:
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    return service, database


def test_progress_reports_event_and_evidence_delta(test_settings) -> None:
    service, database = _service(test_settings)
    case = service.create_case("progress delta")
    with database.session_factory.begin() as session:
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="RUNNING",
            created_at=datetime.now(UTC) - timedelta(seconds=5),
            started_at=datetime.now(UTC) - timedelta(seconds=4),
        )
        session.add(task)
        session.flush()
        run = ToolRun(task_id=task.id, artifact_id=None, tool_name="test", tool_version="1", status="SUCCEEDED")
        session.add(run)
        session.flush()
        service._audit(session, case_id=case.id, task_id=task.id, event_type="evidence.created", actor="test", object_type="Evidence", object_id="e1", payload={})
        # The progress contract uses the append-only Evidence audit event as
        # its authoritative delta signal.  No Evidence row is needed here;
        # keeping the fixture at that public seam also avoids introducing a
        # deliberately invalid foreign-key row.
        task_id = task.id
    progress = service._analysis_progress(task_id, after_seq=0)
    assert progress["progress_revision"] >= 1
    assert progress["new_evidence_since_last"] == 1
    assert progress["changed"] is True
    current = service._analysis_progress(task_id, after_seq=int(progress["progress_revision"]))
    assert current["new_evidence_since_last"] == 0
    assert current["changed"] is False
    assert current["server_time"]


def test_failure_contract_does_not_point_retry_lineage_to_itself(test_settings) -> None:
    service, database = _service(test_settings)
    case = service.create_case("failure lineage")
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        payload = service._record_analysis_failure(session, task, RuntimeError("deterministic parser error"))
        assert payload["retry_of_task_id"] is None
        assert payload["attempt_number"] == 1
        assert payload["retry_suppressed"] is False


def test_failure_contract_links_previous_attempt_and_suppresses_duplicate(test_settings) -> None:
    service, database = _service(test_settings)
    case = service.create_case("failure retry lineage")
    with database.session_factory.begin() as session:
        first = AnalysisTask(case_id=case.id, lifecycle="FAILED")
        session.add(first)
        session.flush()
        first_payload = service._record_analysis_failure(
            session, first, RuntimeError("deterministic parser error")
        )
        assert first_payload["attempt_number"] == 1
        second = AnalysisTask(case_id=case.id, lifecycle="FAILED")
        session.add(second)
        session.flush()
        second_payload = service._record_analysis_failure(
            session, second, RuntimeError("deterministic parser error")
        )
        assert second_payload["retry_of_task_id"] == first.id
        assert second_payload["attempt_number"] == 2
        assert second_payload["retry_suppressed"] is True
        assert second_payload["retry"]["retry"] is False


def test_database_exposes_derived_index_repair_operation(test_settings) -> None:
    service, database = _service(test_settings)
    assert service is not None
    result = database.repair_evidence_search_keys()
    assert result["status"] in {"SKIPPED", "REPAIRED"}
    assert result["table"] == "evidence_search_keys"


def test_dsh_query_tool_schema_is_session_bound() -> None:
    source = Path("threat-dsh-workbench/packages/threat-tool-provider/src/index.ts").read_text(encoding="utf-8")
    marker = "name: 'threat_query_current_analysis_evidence'"
    section = source[source.index(marker) : source.index("name: 'threat_get_capabilities'")]
    assert "task_id" not in section
    assert "currentEvidence" in section
