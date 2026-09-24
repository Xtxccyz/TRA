from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
import json

import pytest

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from sqlalchemy import inspect, select

from threat_report_agent.models import (
    AnalysisTask,
    CaseRecord,
    ThreatAnalysisContextRecord,
    ToolRun,
)
from threat_report_agent.service import AnalysisService
from threat_report_agent.task.turn_lifecycle import LongTurnLifecycle


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
        service.audit(session, case_id=case.id, task_id=task.id, event_type="evidence.created", actor="test", object_type="Evidence", object_id="e1", payload={})
        # The progress contract uses the append-only Evidence audit event as
        # its authoritative delta signal.  No Evidence row is needed here;
        # keeping the fixture at that public seam also avoids introducing a
        # deliberately invalid foreign-key row.
        task_id = task.id
    progress = service.analysis_progress(task_id, after_seq=0)
    assert progress["progress_revision"] >= 1
    assert progress["new_evidence_since_last"] == 1
    assert progress["changed"] is True
    current = service.analysis_progress(task_id, after_seq=int(progress["progress_revision"]))
    assert current["new_evidence_since_last"] == 0
    assert current["changed"] is False
    assert current["server_time"]


def test_elapsed_time_is_server_authoritative_and_stable_after_completion(test_settings) -> None:
    service, database = _service(test_settings)
    case = service.create_case("elapsed truth")
    created = datetime(2026, 1, 1, tzinfo=UTC)
    started = created + timedelta(seconds=2)
    finished = started + timedelta(seconds=7, milliseconds=250)
    with database.session_factory.begin() as session:
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="SUCCEEDED",
            created_at=created,
            started_at=started,
            finished_at=finished,
        )
        session.add(task)
        session.flush()
        task_id = task.id
    progress = service.analysis_progress(task_id, after_seq=0)
    assert progress["created_at"].startswith("2026-01-01T00:00:00")
    assert progress["started_at"].startswith("2026-01-01T00:00:02")
    assert progress["finished_at"].startswith("2026-01-01T00:00:09")
    assert progress["elapsed_ms"] == 7250
    status = service.task_status(task_id)
    assert status["elapsed_ms"] == 7250
    assert status["elapsed_ms"] == service.task_status(task_id)["elapsed_ms"]


def test_workbench_wait_uses_bounded_exponential_backoff_when_idle(monkeypatch) -> None:
    """Idle browser sessions must not poll the database at a fixed 250ms rate."""
    service = AnalysisService.__new__(AnalysisService)
    service._require_session_id = lambda value: value
    context_calls = 0

    def context(_session_id):
        nonlocal context_calls
        context_calls += 1
        return {
            "session_id": "session-id",
            "state": "IDLE",
            "context_revision": 1,
            "active_task_id": None,
        }

    service.workbench_analysis_context_v3 = context

    class FakeClock:
        def __init__(self) -> None:
            self.now = 0.0
            self.delays: list[float] = []

        def monotonic(self) -> float:
            return self.now

        def sleep(self, delay: float) -> None:
            self.delays.append(delay)
            self.now += delay

    clock = FakeClock()
    monkeypatch.setattr("threat_report_agent.service.time", clock)
    result = service.workbench_wait_for_analysis_update(
        "session-id", after_seq=0, timeout_seconds=3
    )

    assert result["changed"] is False
    assert result["must_continue_waiting"] is False
    assert result["wait_status"] == "timed_out"
    assert clock.delays
    assert clock.delays[:4] == [0.05, 0.1, 0.2, 0.4]
    assert max(clock.delays) <= 1.0
    # The bounded backoff completes a 3s idle wait in a small fixed number of
    # checks instead of the twelve checks produced by a 250ms spin loop.
    assert len(clock.delays) <= 8
    assert context_calls <= 5


def test_workbench_wait_timeout_while_running_requires_another_wait(monkeypatch) -> None:
    """A wait timeout during RUNNING is not a report; the client must wait again."""
    service = AnalysisService.__new__(AnalysisService)
    service._require_session_id = lambda value: value
    service.workbench_analysis_context_v3 = lambda _session_id: {
        "session_id": "session-id",
        "state": "ANALYSIS_RUNNING",
        "context_revision": 1,
        "active_task_id": "task-running",
    }
    service._analysis_progress = lambda task_id, after_seq=0: {"state": "ANALYSIS_RUNNING"}

    class EmptySession:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def scalars(self, _stmt):
            return []

    service.database = SimpleNamespace(session_factory=lambda: EmptySession())

    class FakeClock:
        def __init__(self) -> None:
            self.now = 0.0

        def monotonic(self) -> float:
            return self.now

        def sleep(self, delay: float) -> None:
            self.now += delay

    monkeypatch.setattr("threat_report_agent.service.time", FakeClock())
    result = service.workbench_wait_for_analysis_update(
        "session-id", after_seq=7, timeout_seconds=2
    )
    assert result["changed"] is False
    assert result["wait_status"] == "timed_out"
    assert result["must_continue_waiting"] is True
    assert result["next_after_event_seq"] == 7
    assert "after_event_seq=7" in str(result["instruction"])
    assert result["convergence"] == "SATURATED"
    assert "factual" in str(result["instruction"]).casefold()


def test_workbench_wait_coalesces_evidence_recorded_instead_of_dumping_rows(monkeypatch) -> None:
    """evidence.recorded must not wake the conversation 64 events at a time."""
    service = AnalysisService.__new__(AnalysisService)
    service._require_session_id = lambda value: value
    service.workbench_analysis_context_v3 = lambda _session_id: {
        "session_id": "session-id",
        "state": "ANALYSIS_RUNNING",
        "code": None,
        "active_task_id": "task-running",
        "task_lifecycle": "RUNNING",
        "investigation_frontier": {"open_questions": ["x" * 4000]},
    }
    service._analysis_progress = lambda task_id, after_seq=0: {
        "state": "ANALYSIS_RUNNING",
        "last_event_seq": 64,
        "new_evidence_since_last": 64,
        "stage": "evidence.recorded",
    }

    class NoiseSession:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def scalars(self, _stmt):
            if getattr(self, "served", False):
                return []
            self.served = True
            return [
                SimpleNamespace(id=f"ev-{index}", chain_sequence=index, event_type="evidence.recorded", payload={"evidence_ids": [f"e-{index}"]})
                for index in range(1, 65)
            ]

    service.database = SimpleNamespace(session_factory=lambda: NoiseSession())

    class FakeClock:
        def __init__(self) -> None:
            self.now = 0.0
            self.sleeps = 0

        def monotonic(self) -> float:
            return self.now

        def sleep(self, delay: float) -> None:
            self.sleeps += 1
            self.now += delay

    clock = FakeClock()
    monkeypatch.setattr("threat_report_agent.service.time", clock)
    result = service.workbench_wait_for_analysis_update(
        "session-id", after_seq=0, timeout_seconds=2
    )
    assert clock.sleeps > 0
    assert result["wait_status"] == "timed_out"
    assert result["must_continue_waiting"] is True
    assert result["next_after_event_seq"] == 64
    assert result["events"] == []
    assert "investigation_frontier" not in result["context"]
    assert result["event_counts"]["evidence.recorded"] == 64
    dumped = json.dumps(result)
    assert "e-1" not in dumped
    assert len(dumped) < 4000


def test_workbench_wait_coalesces_queue_noise_instead_of_dumping_rows(monkeypatch) -> None:
    """Queue dequeue rows must not wake the conversation 64 events at a time."""
    service = AnalysisService.__new__(AnalysisService)
    service._require_session_id = lambda value: value
    service.workbench_analysis_context_v3 = lambda _session_id: {
        "session_id": "session-id",
        "state": "ANALYSIS_RUNNING",
        "active_task_id": "task-running",
        "task_lifecycle": "RUNNING",
    }
    service._analysis_progress = lambda task_id, after_seq=0: {
        "state": "ANALYSIS_RUNNING",
        "last_event_seq": 64,
        "stage": "orchestration.action_dequeued",
    }

    class NoiseSession:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def scalars(self, _stmt):
            if getattr(self, "served", False):
                return []
            self.served = True
            return [
                SimpleNamespace(
                    id=f"ev-{index}",
                    chain_sequence=index,
                    event_type="orchestration.action_dequeued",
                    payload={"action_id": f"a-{index}"},
                )
                for index in range(1, 65)
            ]

    service.database = SimpleNamespace(session_factory=lambda: NoiseSession())

    class FakeClock:
        def __init__(self) -> None:
            self.now = 0.0
            self.sleeps = 0

        def monotonic(self) -> float:
            return self.now

        def sleep(self, delay: float) -> None:
            self.sleeps += 1
            self.now += delay

    clock = FakeClock()
    monkeypatch.setattr("threat_report_agent.service.time", clock)
    result = service.workbench_wait_for_analysis_update(
        "session-id", after_seq=0, timeout_seconds=2
    )
    assert clock.sleeps > 0
    assert result["wait_status"] == "timed_out"
    assert result["must_continue_waiting"] is True
    assert result["next_after_event_seq"] == 64
    assert result["events"] == []
    assert result["event_counts"]["orchestration.action_dequeued"] == 64
    assert result["convergence"] == "SATURATED"
    assert "a-1" not in json.dumps(result)


def test_workbench_wait_does_not_rewind_to_seq_zero(monkeypatch) -> None:
    """Kunglao wait-signal: after_seq=0 cannot dump a prefix already consumed."""
    service = AnalysisService.__new__(AnalysisService)
    service._require_session_id = lambda value: value
    service._wait_cursors = {}
    service.workbench_analysis_context_v3 = lambda _session_id: {
        "session_id": "session-id",
        "state": "ANALYSIS_RUNNING",
        "active_task_id": "task-running",
        "task_lifecycle": "RUNNING",
    }
    service._analysis_progress = lambda task_id, after_seq=0: {
        "state": "ANALYSIS_RUNNING",
        "last_event_seq": 64,
        "stage": "investigation.questions_recompiled",
    }

    class CursorSession:
        queries = 0

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def scalars(self, _stmt):
            CursorSession.queries += 1
            if service._wait_cursors:
                return [
                    SimpleNamespace(
                        id="ev-claim",
                        chain_sequence=1,
                        event_type="claim.created",
                        payload={"claim_id": "c-1"},
                    )
                ]
            return [
                SimpleNamespace(
                    id=f"ev-{index}",
                    chain_sequence=index,
                    event_type="evidence.recorded",
                    payload={"evidence_ids": [f"e-{index}"]},
                )
                for index in range(1, 65)
            ]

    service.database = SimpleNamespace(session_factory=lambda: CursorSession())

    class FakeClock:
        def __init__(self) -> None:
            self.now = 0.0
            self.sleeps = 0

        def monotonic(self) -> float:
            return self.now

        def sleep(self, delay: float) -> None:
            self.sleeps += 1
            self.now += delay

    clock = FakeClock()
    monkeypatch.setattr("threat_report_agent.service.time", clock)
    first = service.workbench_wait_for_analysis_update(
        "session-id", after_seq=0, timeout_seconds=2
    )
    assert first["next_after_event_seq"] == 64
    assert first["convergence"] == "SATURATED"
    clock.now = 0.0
    clock.sleeps = 0
    second = service.workbench_wait_for_analysis_update(
        "session-id", after_seq=0, timeout_seconds=2
    )
    assert second["wait_status"] == "timed_out"
    assert second["must_continue_waiting"] is True
    assert second["last_meaningful_event"] is None
    assert "c-1" not in json.dumps(second)


def test_context_read_does_not_rewrite_unchanged_projection(test_settings) -> None:
    """A status read must remain read-only when the task lifecycle is stable."""
    service, database = _service(test_settings)
    projection_time = datetime(2026, 1, 1, tzinfo=UTC)
    with database.session_factory.begin() as session:
        case = CaseRecord(title="context read")
        session.add(case)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        session.add(
            ThreatAnalysisContextRecord(
                dsh_session_id="context-read-session",
                case_id=case.id,
                active_task_id=task.id,
                state="ANALYSIS_RUNNING",
                task_lifecycle="RUNNING",
                updated_at=projection_time,
            )
        )

    service.workbench_analysis_context_v3("context-read-session")
    with database.session_factory() as session:
        row = session.scalar(
            select(ThreatAnalysisContextRecord).where(
                ThreatAnalysisContextRecord.dsh_session_id == "context-read-session"
            )
        )
        assert row is not None
        assert row.updated_at.replace(tzinfo=UTC) == projection_time


def test_audit_event_wait_query_has_task_sequence_index(test_settings) -> None:
    """The bounded wait query can use its task and cursor predicates directly."""
    _service_instance, database = _service(test_settings)
    index_names = {item["name"] for item in inspect(database.engine).get_indexes("audit_events")}
    assert "ix_audit_events_task_sequence" in index_names


def test_long_turn_returns_async_and_rejects_non_terminal_branch() -> None:
    lifecycle = LongTurnLifecycle()
    started = lifecycle.start_analysis("turn-1")
    assert started.state == "ANALYSIS_RUNNING"
    assert lifecycle.return_async().state == "AWAITING_EVENT"
    with pytest.raises(RuntimeError, match="BRANCH_REQUIRES_TERMINAL_TURN"):
        lifecycle.branch("turn-branch")
    assert lifecycle.accept_event(3, terminal=True).state == "SYNTHESIZING"
    lifecycle.begin_synthesis()
    assert lifecycle.complete().state == "COMPLETED"
    branch = lifecycle.branch("turn-branch")
    assert branch.state == "IDLE"
    assert branch.parent_turn_id == "turn-1"


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


def test_wait_continuation_converged_is_leftover_dump_not_second_round() -> None:
    row = AnalysisService.wait_continuation(
        {"state": "ANALYSIS_READY"},
        timed_out=False,
        next_seq=9,
    )
    assert row["convergence"] == "CONVERGED"
    assert row["must_continue_waiting"] is False
    assert "再深入" in str(row["instruction"])
    assert "content" in str(row["instruction"]).casefold()
    assert "one_round_complete" in str(row["instruction"])


def test_incomplete_leftover_dump_wait_instruction_is_partial_not_one_round() -> None:
    payload = {
        "convergence": "CONVERGED",
        "instruction": (
            "CONVERGED leftover dump is in content. Copy How / Unique OS "
            "/ Unknowns, quote authoritative_revision_id, and do not ask "
            "再深入. Honor one_round_complete from this payload."
        ),
        "content": "# Official GET report\n\n## How\nCreateProcessW\n",
        "one_round_complete": False,
        "authoritative_revision_id": "revision-wait",
    }
    AnalysisService._apply_incomplete_leftover_wait_instruction(payload)
    assert payload["convergence"] == "CONVERGED"
    assert payload["one_round_complete"] is False
    instruction = str(payload["instruction"])
    assert instruction.startswith("PARTIAL")
    assert "one_round_complete" in instruction
    assert "finished one-round" in instruction
    assert "再深入" in instruction
    assert "CONVERGED leftover dump is in content" not in instruction


def test_wait_tool_payload_incomplete_leftover_dump_is_partial_not_one_round() -> None:
    service = AnalysisService.__new__(AnalysisService)
    how = "CreateProcessW command=cmd.exe /c FoxitPDFReader.exe creation_flags=0x000f4240"
    service._analysis_progress = lambda *_args, **_kwargs: {"state": "ANALYSIS_READY"}
    service._compact_wait_context = lambda context: {
        "state": context.get("state"),
        "active_task_id": context.get("active_task_id"),
    }
    service._remember_wait_cursor = lambda *_args, **_kwargs: None
    service._leftover_official_report_dump = lambda task_id: {
        "task_id": task_id,
        "report_available": True,
        "report_revision_id": "revision-wait",
        "authoritative_revision_id": "revision-wait",
        "content": f"# Official GET report\n\n## How\n{how}\n",
        "one_round_complete": False,
        "one_round_readiness": {"complete": False, "violations": ["flooded"]},
    }
    payload = service._wait_tool_payload(
        session_id="session-wait",
        context={"state": "ANALYSIS_READY", "active_task_id": "task-1"},
        after_seq=0,
        next_seq=8,
        timed_out=False,
        event_counts={},
        last_meaningful=None,
        task_id="task-1",
    )
    assert payload["convergence"] == "CONVERGED"
    assert payload["one_round_complete"] is False
    instruction = str(payload["instruction"])
    assert instruction.startswith("PARTIAL")
    assert "one_round_complete" in instruction
    assert "finished one-round" in instruction
    assert "CONVERGED leftover dump is in content" not in instruction
    assert how in str(payload["content"])
    assert payload["must_continue_waiting"] is False


def test_wait_tool_payload_converged_leftover_dumps_official_markdown() -> None:
    service = AnalysisService.__new__(AnalysisService)
    how = "CreateProcessW command=cmd.exe /c FoxitPDFReader.exe creation_flags=0x000f4240"
    service._analysis_progress = lambda *_args, **_kwargs: {"state": "ANALYSIS_READY"}
    service._compact_wait_context = lambda context: {
        "state": context.get("state"),
        "active_task_id": context.get("active_task_id"),
    }
    service._remember_wait_cursor = lambda *_args, **_kwargs: None
    service._leftover_official_report_dump = lambda task_id: {
        "task_id": task_id,
        "report_available": True,
        "report_revision_id": "revision-wait",
        "authoritative_revision_id": "revision-wait",
        "content": f"# Official GET report\n\n## How\n{how}\n",
    }
    payload = service._wait_tool_payload(
        session_id="session-wait",
        context={"state": "ANALYSIS_READY", "active_task_id": "task-1"},
        after_seq=0,
        next_seq=8,
        timed_out=False,
        event_counts={},
        last_meaningful=None,
        task_id="task-1",
    )
    assert payload["convergence"] == "CONVERGED"
    assert payload["authoritative_revision_id"] == "revision-wait"
    assert how in str(payload["content"])
    assert payload["must_continue_waiting"] is False
