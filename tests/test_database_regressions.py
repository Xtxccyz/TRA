from __future__ import annotations

import json
import os
import threading
import time

import pytest
from sqlalchemy import event, select, text
from sqlalchemy.exc import IntegrityError

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.evidence_recovery import BoundedEvidenceRepository, EvidenceDeliveryLedger, EvidenceStage, RetrievalRequest
from threat_report_agent.models import (
    AnalysisFailureRecord,
    AnalysisTask,
    Artifact,
    CaseRecord,
    ContentBlob,
    Evidence,
    EvidenceDeliveryTrace,
    EvidenceSearchKey,
    ToolRun,
    AnalysisTurnRecord,
    AnalysisTurnResultRecord,
    Relation,
)
from threat_report_agent.reporting import REPORT_MODULES
from threat_report_agent.service import AnalysisService


def test_sqlite_file_database_uses_wal_and_busy_timeout_for_background_analysis(tmp_path) -> None:
    """Concurrent status reads must not fail while a local analysis writes."""
    database = Database(f"sqlite:///{tmp_path / 'concurrency.db'}")
    database.create_schema()

    with database.engine.connect() as connection:
        journal_mode = connection.execute(text("PRAGMA journal_mode")).scalar_one()
        busy_timeout = connection.execute(text("PRAGMA busy_timeout")).scalar_one()

    assert str(journal_mode).lower() == "wal"
    assert int(busy_timeout) >= 30_000


@pytest.mark.integration
def test_postgres_task_snapshot_writers_serialize_without_deadlock() -> None:
    """Concurrent control-plane writers must serialize on the task row.

    The production deadlock was observed only with PostgreSQL.  Keep this
    regression opt-in so the normal SQLite suite stays fast, while CI or a
    running Compose stack can execute the same public database behavior.
    """
    database_url = os.environ.get("THREAT_POSTGRES_TEST_URL")
    if not database_url:
        pytest.skip("set THREAT_POSTGRES_TEST_URL to run the PostgreSQL regression")
    database = Database(database_url)
    database.create_schema()
    with database.session_factory.begin() as session:
        case = CaseRecord(title="postgres task lock")
        session.add(case)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        task_id = task.id

    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def writer(value: str) -> None:
        try:
            barrier.wait(timeout=5)
            with database.session_factory.begin() as session:
                row = session.get(AnalysisTask, task_id, with_for_update=True)
                assert row is not None
                snapshot = dict(row.strategy_snapshot or {})
                snapshot["writer"] = value
                row.strategy_snapshot = snapshot
                time.sleep(0.05)
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(str(index),)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert all(not thread.is_alive() for thread in threads)
    assert errors == []


@pytest.mark.integration
def test_postgres_schema_recheck_does_not_repeat_nullable_column_ddl() -> None:
    """A warm startup must not take table DDL locks during an analysis run.

    Worker and API processes all call ``create_schema``.  Once the nullable
    migration has completed, a later process must only inspect the schema;
    repeating ``ALTER TABLE ... DROP NOT NULL`` can deadlock with evidence
    queries that already hold a row/table lock.
    """
    database_url = os.environ.get("THREAT_POSTGRES_TEST_URL")
    if not database_url:
        pytest.skip("set THREAT_POSTGRES_TEST_URL to run the PostgreSQL regression")
    database = Database(database_url)
    database.create_schema()
    statements: list[str] = []

    def capture(_conn, _cursor, statement, _parameters, _context, _executemany) -> None:
        normalized = " ".join(str(statement).split()).upper()
        if normalized.startswith("ALTER TABLE") and "DROP NOT NULL" in normalized:
            statements.append(normalized)

    event.listen(database.engine, "before_cursor_execute", capture)
    try:
        database.create_schema()
    finally:
        event.remove(database.engine, "before_cursor_execute", capture)

    assert statements == []



def test_delivery_trace_is_append_only_for_update_and_delete(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case('delivery trace immutability')
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle='RUNNING')
        session.add(task)
        session.flush()
        trace = EvidenceDeliveryTrace(task_id=task.id, turn_id='turn-immutable', subject_key='evidence-immutable', stage='PRODUCED', details={})
        session.add(trace)
        session.flush()
        trace_id = trace.id
    with pytest.raises(IntegrityError):
        with database.session_factory.begin() as session:
            session.execute(EvidenceDeliveryTrace.__table__.update().where(EvidenceDeliveryTrace.id == trace_id).values(stage='PERSISTED'))
    with pytest.raises(IntegrityError):
        with database.session_factory.begin() as session:
            session.execute(EvidenceDeliveryTrace.__table__.delete().where(EvidenceDeliveryTrace.id == trace_id))

def test_old_evidence_rows_are_backfilled_into_selector_index(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case('selector migration')
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle='RUNNING')
        session.add(task)
        session.flush()
        session.add(ContentBlob(sha256='9' * 64, size=1, media_type='application/octet-stream', storage_key='sha256/old-evidence'))
        session.flush()
        artifact = Artifact(task_id=task.id, content_sha256='9' * 64, logical_path='old.exe', detected_type='pe')
        session.add(artifact)
        session.flush()
        run = ToolRun(task_id=task.id, artifact_id=artifact.id, tool_name='ghidra-headless', tool_version='test', status='SUCCEEDED')
        session.add(run)
        session.flush()
        # Non-indexable rows must not permanently occupy the migration page.
        session.add_all(
            Evidence(id=f'a-legacy-{index:04}', task_id=task.id, artifact_id=artifact.id,
                     tool_run_id=run.id, module='static', kind='file_identity',
                     nature='STATIC_OBSERVED', value={}, anchor={})
            for index in range(260)
        )
        evidence = Evidence(id='z-legacy-target', task_id=task.id, artifact_id=artifact.id, tool_run_id=run.id, module='static', kind='xref', nature='STATIC_OBSERVED', value={'target_name': 'GetProcAddress'}, anchor={'function_entry': '0x140001000'})
        session.add(evidence)
        session.flush()
        session.query(EvidenceSearchKey).delete()
        evidence_id = evidence.id
        task_id = task.id
        artifact_id = artifact.id

    database.create_schema()
    with database.session_factory() as session:
        request = RetrievalRequest(thread_id='migration-thread', artifact_id=artifact_id, hypothesis_type='dynamic_api_resolution', target_anchors=('GetProcAddress',), required_evidence_kinds=(), candidate_limit=4)
        batch = BoundedEvidenceRepository().retrieve(session, task_id=task_id, request=request)

    assert evidence_id in {row.id for row in batch.rows}


@pytest.mark.parametrize("flush_batch_size", [32, 8])
def test_evidence_selector_index_is_inserted_as_one_executemany_batch(
    test_settings, flush_batch_size: int
) -> None:
    """Each flush indexes its written Evidence in one bulk insert."""
    database = Database(test_settings.database_url)
    database.create_schema()
    statements: list[tuple[str, bool, int]] = []

    def capture(_conn, _cursor, statement, parameters, _context, executemany) -> None:
        normalized = " ".join(str(statement).split()).lower()
        if "insert into evidence_search_keys" in normalized:
            count = len(parameters) if executemany and hasattr(parameters, "__len__") else 1
            statements.append((normalized, bool(executemany), count))

    event.listen(database.engine, "before_cursor_execute", capture)
    try:
        with database.session_factory.begin() as session:
            case = CaseRecord(title="selector batch")
            session.add(case)
            session.flush()
            task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
            session.add(task)
            session.flush()
            blob = ContentBlob(
                sha256="b" * 64,
                size=1,
                media_type="application/octet-stream",
                storage_key="sha256/selector-batch",
            )
            session.add(blob)
            session.flush()
            artifact = Artifact(
                task_id=task.id,
                content_sha256=blob.sha256,
                logical_path="selector-batch.exe",
                detected_type="pe",
            )
            session.add(artifact)
            session.flush()
            run = ToolRun(
                task_id=task.id,
                artifact_id=artifact.id,
                tool_name="test",
                tool_version="1",
                status="SUCCEEDED",
            )
            session.add(run)
            session.flush()
            evidence_rows = [
                Evidence(
                    id=f"selector-evidence-{index}",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_context",
                    nature="STATIC_OBSERVED",
                    value={
                        "name": f"Function{index}",
                        "target_name": "GetProcAddress",
                    },
                    anchor={"function_entry": hex(0x401000 + index * 16)},
                )
                for index in range(32)
            ]
            session.add_all(evidence_rows)
            for offset in range(0, len(evidence_rows), flush_batch_size):
                session.flush(objects=evidence_rows[offset : offset + flush_batch_size])
                with session.no_autoflush:
                    indexed_ids = set(session.scalars(select(EvidenceSearchKey.evidence_id)))
                assert indexed_ids == {
                    row.id for row in evidence_rows[: offset + flush_batch_size]
                }
                assert len(session.new) == len(evidence_rows) - offset - flush_batch_size
    finally:
        event.remove(database.engine, "before_cursor_execute", capture)

    assert len(statements) == 32 // flush_batch_size
    assert all(
        executemany and row_count > flush_batch_size for _, executemany, row_count in statements
    )


def _legacy_failed_task(service: AnalysisService, database: Database, case_id: str, *, message: str) -> str:
    """Persist the shape emitted by pre-failure-contract runtimes."""
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case_id, lifecycle="FAILED")
        session.add(task)
        session.flush()
        service._audit(
            session,
            case_id=case_id,
            task_id=task.id,
            event_type="orchestration.static.completed",
            actor="legacy-worker",
            object_type="AnalysisTask",
            object_id=task.id,
            payload={"status": "SUCCEEDED"},
        )
        service._audit(
            session,
            case_id=case_id,
            task_id=task.id,
            event_type="analysis_task.failed",
            actor="legacy-worker",
            object_type="AnalysisTask",
            object_id=task.id,
            payload={"error_type": "DataCorrupted", "message": message},
        )
        return task.id


def test_audit_head_is_reused_within_transaction_and_chain_remains_valid(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("audit head reuse")
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        first = service._audit(
            session, case_id=case.id, task_id=task.id, event_type="test.first",
            actor="test", object_type="Evidence", object_id="e1", payload={},
        )
        second = service._audit(
            session, case_id=case.id, task_id=task.id, event_type="test.second",
            actor="test", object_type="Evidence", object_id="e2", payload={},
        )
        assert second.chain_sequence == first.chain_sequence + 1
        assert second.previous_hash == first.event_hash
        assert session.info["_threat_audit_heads"][f"task:{task.id}"].sequence == 2
        task_id = task.id
    assert service.audit_integrity(task_id)["valid"] is True


def test_backfill_legacy_failed_task_creates_retryable_db_failure_contract(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("legacy failure backfill")
    task_id = _legacy_failed_task(
        service,
        database,
        case.id,
        message="psycopg.errors.DataCorrupted: compressed lz4 data is corrupt in evidence_search_keys",
    )

    database._backfill_analysis_failures()
    with database.session_factory() as session:
        failure = session.query(AnalysisFailureRecord).filter_by(task_id=task_id).one()

    assert failure.failure_code == "DB_FAILURE"
    assert failure.retryable is True
    assert failure.attempt_number == 1
    assert failure.retry_of_task_id is None
    assert failure.retry_suppressed is False
    assert failure.last_successful_stage == "orchestration.static.completed"
    assert failure.last_successful_stage != "analysis_task.failed"


def test_backfill_links_identical_legacy_failures_without_self_reference(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("legacy retry lineage")
    first_id = _legacy_failed_task(service, database, case.id, message="evidence_search_keys lz4 corrupt")
    database._backfill_analysis_failures()
    second_id = _legacy_failed_task(service, database, case.id, message="evidence_search_keys lz4 corrupt")
    database._backfill_analysis_failures()

    with database.session_factory() as session:
        first = session.query(AnalysisFailureRecord).filter_by(task_id=first_id).one()
        second = session.query(AnalysisFailureRecord).filter_by(task_id=second_id).one()

    assert second.attempt_number == 2
    assert second.retry_of_task_id == first_id
    assert second.retry_of_task_id != second.task_id
    assert second.retry_suppressed is True
    assert first.retry_of_task_id is None


def test_backfill_repairs_legacy_self_lineage_and_terminal_stage(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("repair stale failure projection")
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="FAILED")
        session.add(task)
        session.flush()
        session.add(
            AnalysisFailureRecord(
                task_id=task.id,
                failure_code="DB_FAILURE",
                failure_stage="analysis_task.failed",
                failed_component="legacy",
                failed_activity="legacy",
                failure_fingerprint="a" * 64,
                last_successful_stage="analysis_task.failed",
                retry_of_task_id=task.id,
            )
        )
        task_id = task.id

    database._backfill_analysis_failures()
    with database.session_factory() as session:
        failure = session.query(AnalysisFailureRecord).filter_by(task_id=task_id).one()

    assert failure.retry_of_task_id is None
    assert failure.last_successful_stage == "UNKNOWN"


def test_delivery_trace_infers_artifact_from_evidence(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case('delivery trace artifact inference')
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle='RUNNING')
        session.add(task)
        session.flush()
        session.add(ContentBlob(sha256='8' * 64, size=1, media_type='application/octet-stream', storage_key='sha256/delivery'))
        session.flush()
        artifact = Artifact(task_id=task.id, content_sha256='8' * 64, logical_path='delivery.exe', detected_type='pe')
        session.add(artifact)
        session.flush()
        run = ToolRun(task_id=task.id, artifact_id=artifact.id, tool_name='test', tool_version='1', status='SUCCEEDED')
        session.add(run)
        session.flush()
        evidence = Evidence(task_id=task.id, artifact_id=artifact.id, tool_run_id=run.id, module='static', kind='string', nature='STATIC_OBSERVED', value={'text': 'seed'}, anchor={})
        session.add(evidence)
        session.flush()
        task_id, evidence_id, artifact_id = task.id, evidence.id, artifact.id
    ledger = EvidenceDeliveryLedger(turn_id='turn-artifact-inference', thread_id='thread-artifact-inference')
    ledger.advance(evidence_id, EvidenceStage.PRODUCED)
    ledger.advance(evidence_id, EvidenceStage.NORMALIZED)
    service.record_evidence_delivery_trace(task_id=task_id, artifact_id=None, ledger=ledger)
    with database.session_factory() as session:
        trace = session.query(EvidenceDeliveryTrace).filter_by(task_id=task_id, evidence_id=evidence_id, stage='NORMALIZED').one()
        assert trace.artifact_id == artifact_id


def test_analysis_turn_and_post_action_result_are_immutable_and_linked(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("turn result immutability")
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        turn = AnalysisTurnRecord(
            task_id=task.id,
            thread_id="thread-1",
            turn_id="turn-1",
            phase="initial",
            hypothesis_before=[],
            retrieval_request={},
            candidate_evidence_ids=[],
            selected_evidence_ids=[],
            delivered_evidence_ids=[],
            context_manifest=[],
            action_proposals=[],
            policy_decisions=[],
            tool_run_ids=[],
            new_evidence_ids=[],
            verifier_result={"status": "PENDING_POST_ACTION_VERIFICATION"},
            hypothesis_after=[],
            mechanism_state="INVESTIGATING",
            stop_reason="MODEL_PLAN_APPLIED",
        )
        session.add(turn)
        session.flush()
        result = AnalysisTurnResultRecord(
            task_id=task.id,
            parent_turn_id=turn.id,
            thread_id=turn.thread_id,
            turn_id=turn.turn_id,
            phase=turn.phase,
            completed_actions=[{"action_key": "a1", "new_evidence_ids": ["e1"], "tool_run_ids": ["t1"]}],
            tool_run_ids=["t1"],
            new_evidence_ids=["e1"],
            verifier_result={"status": "COMPLETED_STATIC_ACTIONS"},
            hypothesis_after=[],
            mechanism_state="EVIDENCE_UPDATED",
            stop_reason="STATIC_QUEUE_DRAINED",
        )
        session.add(result)
        session.flush()
        turn_id, result_id = turn.id, result.id
    with pytest.raises(IntegrityError):
        with database.session_factory.begin() as session:
            session.execute(AnalysisTurnRecord.__table__.update().where(AnalysisTurnRecord.id == turn_id).values(stop_reason="tampered"))
    with pytest.raises(IntegrityError):
        with database.session_factory.begin() as session:
            session.execute(AnalysisTurnResultRecord.__table__.delete().where(AnalysisTurnResultRecord.id == result_id))


def test_analysis_turn_results_only_include_actions_from_their_planner_turn(test_settings) -> None:
    """Cumulative task history must not leak into an earlier Turn result."""
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("turn result attribution")
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        for turn_id in ("turn-a", "turn-b"):
            session.add(
                AnalysisTurnRecord(
                    task_id=task.id,
                    thread_id="thread-1",
                    turn_id=turn_id,
                    phase=turn_id,
                    hypothesis_before=[],
                    retrieval_request={},
                    candidate_evidence_ids=[],
                    selected_evidence_ids=[],
                    delivered_evidence_ids=[],
                    context_manifest=[],
                    action_proposals=[],
                    policy_decisions=[],
                    tool_run_ids=[],
                    new_evidence_ids=[],
                    verifier_result={"status": "PENDING_POST_ACTION_VERIFICATION"},
                    hypothesis_after=[],
                    mechanism_state="INVESTIGATING",
                    stop_reason="MODEL_PLAN_APPLIED",
                )
            )
        session.flush()
        created = service._persist_analysis_turn_results(
            session,
            task=task,
            completed_actions=[
                {"action_key": "a", "planner_turn_id": "turn-a", "new_evidence_ids": ["e-a"], "tool_run_ids": ["t-a"]},
                {"action_key": "b", "planner_turn_id": "turn-b", "new_evidence_ids": ["e-b"], "tool_run_ids": ["t-b"]},
            ],
            stop_reason="MODEL_ACTIONS_EXECUTED",
        )
        assert created == 2
        orm_rows = {
            row.turn_id: row
            for row in session.query(AnalysisTurnResultRecord).all()
        }
        assert orm_rows["turn-a"].completed_actions == [
            {"action_key": "a", "planner_turn_id": "turn-a", "new_evidence_ids": ["e-a"], "tool_run_ids": ["t-a"]}
        ]
        assert orm_rows["turn-b"].completed_actions == [
            {"action_key": "b", "planner_turn_id": "turn-b", "new_evidence_ids": ["e-b"], "tool_run_ids": ["t-b"]}
        ]


def test_relation_support_guard_also_blocks_unsupported_updates(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("relation update guard")
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        session.add(ContentBlob(sha256="b" * 64, size=1, media_type="application/octet-stream", storage_key="sha256/relation"))
        session.flush()
        artifact = Artifact(task_id=task.id, content_sha256="b" * 64, logical_path="relation.exe", detected_type="pe")
        session.add(artifact)
        session.flush()
        run = ToolRun(task_id=task.id, artifact_id=artifact.id, tool_name="test", tool_version="1", status="SUCCEEDED")
        session.add(run)
        session.flush()
        evidence = Evidence(task_id=task.id, artifact_id=artifact.id, tool_run_id=run.id, module="static", kind="string", nature="STATIC_OBSERVED", value={"text": "child"}, anchor={})
        session.add(evidence)
        session.flush()
        relation = Relation(task_id=task.id, source_artifact_id=artifact.id, target_artifact_id=artifact.id, relation_type="CONTAINS", evidence_id=evidence.id, status="OBSERVED")
        session.add(relation)
        session.flush()
        relation_id = relation.id
    with pytest.raises(IntegrityError):
        with database.session_factory.begin() as session:
            session.execute(Relation.__table__.update().where(Relation.id == relation_id).values(evidence_id=None))


def test_report_revision_strips_nul_bytes_before_persist(test_settings) -> None:
    """Recovered PE strings may contain NUL; PostgreSQL TEXT cannot store them."""
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    database.create_schema()
    case = service.create_case("nul in recovered strings")
    with database.session_factory.begin() as session:
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="SUCCEEDED",
            outcome="PARTIAL",
            analysis_class="BOUNDED_STATIC_ANALYSIS",
            limitations=["recovered UTF-16 buffer hello\x00world"],
        )
        session.add(task)
        session.flush()
        session.add(
            ContentBlob(
                sha256="9" * 64,
                size=1,
                media_type="application/octet-stream",
                storage_key="sha256/nul-report",
            )
        )
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256="9" * 64,
            logical_path="notepad.exe",
            detected_type="pe",
        )
        session.add(artifact)
        session.flush()
        run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="static",
            tool_version="1",
            status="SUCCEEDED",
        )
        session.add(run)
        session.flush()
        session.add(
            Evidence(
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="string",
                nature="STATIC_OBSERVED",
                value={"text": "hello\x00world"},
                anchor={},
            )
        )
        session.flush()
        snapshot = service._freeze_snapshot(session, task)
        revision = service._create_report_revision(
            session, task, snapshot, list(REPORT_MODULES)
        )
        assert "\x00" not in revision.markdown
        payload = json.dumps(revision.document)
        assert "\x00" not in payload
        assert "hello" in payload
        assert "world" in payload
