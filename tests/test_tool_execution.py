from __future__ import annotations

import asyncio
import base64
from datetime import UTC, datetime, timedelta
import hashlib
import io
import json
from dataclasses import replace
import threading
import time
from typing import get_type_hints
import zipfile

import pytest
from temporalio.converter import DataConverter
from temporalio.exceptions import (
    ActivityError,
    CancelledError as TemporalCancelledError,
    RetryState,
)

from threat_report_agent.content_store import LocalContentStore, ToolRunStorageGrant
from threat_report_agent.database import Database
from threat_report_agent.ghidra_adapter import GhidraRun
from threat_report_agent.models import AnalysisTask, ToolRun
from threat_report_agent.service import AnalysisService
from threat_report_agent.config import Settings
from threat_report_agent.tool_execution import (
    StaticToolActivities,
    StaticToolRunWorkflow,
    ModelPayloadCleanupWorkflow,
    DailyAuditSealWorkflow,
    ToolRunRequest,
    ToolRunResult,
    ToolRunStorageAccess,
    TemporalToolExecutor,
    ensure_model_payload_cleanup_schedule,
    intake_entries_from_payload,
    static_result_from_payload,
)


def test_daily_audit_workflow_defaults_to_previous_utc_day(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeWorkflow:
        @staticmethod
        def now() -> datetime:
            return datetime(2026, 8, 27, 3, 17, tzinfo=UTC)

        @staticmethod
        async def execute_activity(name, payload, **kwargs):
            captured.update({"name": name, "payload": payload})
            return payload

    import threat_report_agent.tool_execution as tool_execution

    monkeypatch.setattr(tool_execution, "workflow", FakeWorkflow)
    result = asyncio.run(DailyAuditSealWorkflow().run({"actor": "test"}))
    assert result["utc_day"] == "2026-08-26"
    assert captured["name"] == "seal_daily_audit"


def test_model_payload_cleanup_workflow_has_durable_activity_contract() -> None:
    assert callable(ModelPayloadCleanupWorkflow.run)
    assert "ModelPayloadCleanupWorkflow" in ModelPayloadCleanupWorkflow.run.__qualname__


def test_model_payload_cleanup_schedule_is_idempotent() -> None:
    class FakeScheduleHandle:
        pass

    class FakeClient:
        def __init__(self) -> None:
            self.calls = []
            self.existing = False

        async def create_schedule(self, schedule_id, schedule):
            self.calls.append((schedule_id, schedule))
            if self.existing:
                from temporalio.client import ScheduleAlreadyRunningError

                raise ScheduleAlreadyRunningError()
            self.existing = True
            return FakeScheduleHandle()

    async def run() -> None:
        client = FakeClient()
        assert await ensure_model_payload_cleanup_schedule(client, task_queue="static-control") is True
        assert await ensure_model_payload_cleanup_schedule(client, task_queue="static-control") is False
        schedule = client.calls[0][1]
        assert schedule.spec.time_zone_name == "UTC"
        calendar = schedule.spec.calendars[0]
        assert calendar.hour[0].start == 3
        assert calendar.minute[0].start == 17
        assert schedule.policy.overlap.name == "SKIP"

    asyncio.run(run())


def make_request(storage_key: str, digest: str, *, tool_run_id: str = "run-1") -> ToolRunRequest:
    return ToolRunRequest(
        case_id="case-1",
        task_id="task-1",
        trace_id="trace-1",
        artifact_id="artifact-1",
        tool_run_id=tool_run_id,
        tool_name="script-parser",
        tool_version="0.1.0",
        content_sha256=digest,
        storage_key=storage_key,
        logical_path="stage.py",
        max_cpu_seconds=60,
        max_memory_mb=512,
        task_queue="static-ghidra",
    )


def test_temporal_payload_contract_round_trips_workflow_and_activity_hints() -> None:
    request = make_request("sha256/aa/aa/" + "a" * 64, "a" * 64)
    converter = DataConverter.default
    payloads = asyncio.run(converter.encode([request.model_dump(mode="json")]))
    hints = (
        get_type_hints(StaticToolRunWorkflow.run)["request"],
        get_type_hints(StaticToolActivities.execute_static_tool)["request_data"],
    )

    for hint in hints:
        decoded = asyncio.run(converter.decode(payloads, [hint]))
        assert ToolRunRequest.model_validate(decoded[0]) == request


def test_tool_run_idempotency_excludes_attempt_specific_run_id(tmp_path) -> None:
    digest = "a" * 64
    first = make_request(f"sha256/aa/aa/{digest}", digest, tool_run_id="run-1")
    second = make_request(f"sha256/aa/aa/{digest}", digest, tool_run_id="run-2")

    assert first.idempotency_key == second.idempotency_key
    assert first.workflow_id == second.workflow_id
    assert "run-1" not in first.workflow_id


def test_tool_run_idempotency_includes_execution_environment_version() -> None:
    digest = "a" * 64
    first = make_request(f"sha256/aa/aa/{digest}", digest)
    upgraded = first.model_copy(update={"environment_version": "static-worker-v2"})

    assert first.idempotency_key != upgraded.idempotency_key


def test_control_preparation_adds_scoped_storage_without_changing_idempotency(
    test_settings: Settings,
) -> None:
    content = b"print('scoped')"
    digest = hashlib.sha256(content).hexdigest()
    request = make_request(f"sha256/{digest[:2]}/{digest[2:4]}/{digest}", digest)

    class ControlStore:
        def read(self, storage_key: str) -> bytes:
            assert storage_key == request.storage_key
            return content

        def issue_tool_run_access(
            self, input_storage_key: str, tool_run_id: str, *, expires_in: int
        ) -> ToolRunStorageGrant:
            assert input_storage_key == request.storage_key
            assert tool_run_id == request.tool_run_id
            assert expires_in >= request.max_cpu_seconds
            return ToolRunStorageGrant(
                input_storage_key=input_storage_key,
                input_url="http://minio/scoped-input",
                output_storage_key=f"tool-runs/{tool_run_id}/output.json",
                output_url="http://minio/scoped-output",
            )

    prepared = asyncio.run(
        StaticToolActivities(test_settings, ControlStore()).prepare_static_tool(
            request.model_dump(mode="json")
        )
    )
    scoped = ToolRunRequest.model_validate(prepared["request"])

    assert prepared["status"] == "READY"
    assert scoped.storage_access is not None
    assert scoped.storage_access.input_storage_key == request.storage_key
    assert scoped.storage_access.output_storage_key == "tool-runs/run-1/output.json"
    assert scoped.idempotency_key == request.idempotency_key


def test_worker_activities_persist_durable_tool_run_status_slices(
    test_settings: Settings,
) -> None:
    store = LocalContentStore(test_settings.content_store_path)
    source = store.put(b"print('durable')")
    database = Database(test_settings.database_url)
    database.create_schema()
    service = AnalysisService(test_settings, database, store)
    case = service.create_case("Durable ToolRun")
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        task_id = task.id
        trace_id = task.trace_id
    request = make_request(source.storage_key, source.sha256).model_copy(
        update={
            "case_id": case.id,
            "task_id": task_id,
            "trace_id": trace_id,
            "artifact_id": None,
        }
    )
    activities = StaticToolActivities(test_settings, store, database)

    asyncio.run(activities.register_static_tool_run(request.model_dump(mode="json")))

    queued = service.task_view(task_id)["tool_runs"][0]
    assert queued["status"] == "QUEUED"
    assert queued["started_at"] is None

    prepared = asyncio.run(activities.prepare_static_tool(request.model_dump(mode="json")))

    running = service.task_view(task_id)["tool_runs"][0]
    assert prepared["status"] == "READY"
    assert running["status"] == "RUNNING"
    assert running["started_at"] is not None

    terminal = ToolRunResult(
        status="SUCCEEDED",
        output_sha256="a" * 64,
        output_storage_key="sha256/aa/aa/" + "a" * 64,
    )
    asyncio.run(
        activities.finalize_static_tool_run(
            {
                "request": request.model_dump(mode="json"),
                "result": terminal.model_dump(mode="json"),
            }
        )
    )

    succeeded = service.task_view(task_id)["tool_runs"][0]
    assert succeeded["status"] == "SUCCEEDED"
    assert succeeded["finished_at"] is not None


def test_output_validation_rejects_a_mismatched_content_reference(
    test_settings: Settings,
) -> None:
    store = LocalContentStore(test_settings.content_store_path)
    source = store.put(b"print('validated')")
    output = store.put(b'{"kind":"static","detected_type":"script","summary":{},"facts":[]}')
    request = make_request(source.storage_key, source.sha256)
    activities = StaticToolActivities(test_settings, store)
    claimed = ToolRunResult(
        status="SUCCEEDED",
        output_sha256="0" * 64,
        output_storage_key=output.storage_key,
    )

    validated = asyncio.run(
        activities.validate_static_tool_output(
            {
                "request": request.model_dump(mode="json"),
                "result": claimed.model_dump(mode="json"),
            }
        )
    )

    assert validated["status"] == "FAILED"
    assert validated["error"] == "OUTPUT_HASH_MISMATCH"


def test_control_validation_materializes_scoped_intake_entries(
    test_settings: Settings,
) -> None:
    delegate = LocalContentStore(test_settings.content_store_path)
    entry_content = b"VirtualAlloc"
    entry_sha256 = hashlib.sha256(entry_content).hexdigest()
    staged = json.dumps(
        {
            "kind": "intake",
            "status": "SUCCEEDED",
            "entries": [
                {
                    "logical_path": "bundle/payload.bin",
                    "parent_path": "bundle",
                    "discovery": "archive",
                    "is_container": False,
                    "content_sha256": entry_sha256,
                    "size": len(entry_content),
                    "detected_type": "unknown",
                    "mime_type": "application/octet-stream",
                    "type_source": "fallback",
                    "content_base64": base64.b64encode(entry_content).decode("ascii"),
                }
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    deleted: list[str] = []

    class ControlStore:
        def read_tool_run_output(self, tool_run_id: str, storage_key: str) -> bytes:
            assert tool_run_id == "run-1"
            assert storage_key == "tool-runs/run-1/output.json"
            return staged

        def put(self, content: bytes):
            return delegate.put(content)

        def delete_tool_run_output(self, tool_run_id: str, storage_key: str) -> None:
            assert tool_run_id == "run-1"
            deleted.append(storage_key)

    source = delegate.put(b"archive")
    request = make_request(source.storage_key, source.sha256).model_copy(
        update={
            "tool_name": "python-zipfile-safe-reader",
            "storage_access": ToolRunStorageAccess(
                input_storage_key=source.storage_key,
                input_url="http://minio/scoped-input",
                output_storage_key="tool-runs/run-1/output.json",
                output_url="http://minio/scoped-output",
            ),
        }
    )
    result = ToolRunResult(
        status="SUCCEEDED",
        output_sha256=hashlib.sha256(staged).hexdigest(),
        output_storage_key="tool-runs/run-1/output.json",
    )

    validated = asyncio.run(
        StaticToolActivities(test_settings, ControlStore()).validate_static_tool_output(
            {
                "request": request.model_dump(mode="json"),
                "result": result.model_dump(mode="json"),
            }
        )
    )
    payload = json.loads(delegate.read(validated["output_storage_key"]))

    assert validated["status"] == "SUCCEEDED"
    assert payload["entries"][0]["storage_key"].endswith(entry_sha256)
    assert "content_base64" not in payload["entries"][0]
    assert delegate.read(payload["entries"][0]["storage_key"]) == entry_content
    assert deleted == ["tool-runs/run-1/output.json"]


def test_workflow_runs_durable_tool_slices_in_order(monkeypatch) -> None:
    request = make_request("sha256/aa/aa/" + "a" * 64, "a" * 64)
    calls: list[str] = []

    async def fake_execute_activity(name: str, argument: dict, **_: object) -> dict:
        calls.append(name)
        if name == "prepare_static_tool":
            return ToolRunResult(status="READY").model_dump(mode="json")
        if name == "execute_static_tool":
            return ToolRunResult(
                status="SUCCEEDED",
                output_sha256="b" * 64,
                output_storage_key="sha256/bb/bb/" + "b" * 64,
            ).model_dump(mode="json")
        if name in {"validate_static_tool_output", "finalize_static_tool_run"}:
            return dict(argument["result"])
        return request.model_dump(mode="json")

    monkeypatch.setattr(
        "threat_report_agent.tool_execution.workflow.execute_activity",
        fake_execute_activity,
    )

    result = asyncio.run(StaticToolRunWorkflow().run(request.model_dump(mode="json")))

    assert result["status"] == "SUCCEEDED"
    assert calls == [
        "register_static_tool_run",
        "prepare_static_tool",
        "execute_static_tool",
        "validate_static_tool_output",
        "finalize_static_tool_run",
    ]


def test_workflow_execution_timeout_allows_worker_cleanup(monkeypatch) -> None:
    request = make_request("sha256/aa/aa/" + "a" * 64, "a" * 64)
    execution_timeout: timedelta | None = None

    async def fake_execute_activity(name: str, argument: dict, **options: object) -> dict:
        nonlocal execution_timeout
        if name == "prepare_static_tool":
            return ToolRunResult(status="READY").model_dump(mode="json")
        if name == "execute_static_tool":
            execution_timeout = options.get("start_to_close_timeout")
            return ToolRunResult(status="FAILED", error="EXPECTED").model_dump(mode="json")
        if name in {"validate_static_tool_output", "finalize_static_tool_run"}:
            return dict(argument["result"])
        return request.model_dump(mode="json")

    monkeypatch.setattr(
        "threat_report_agent.tool_execution.workflow.execute_activity",
        fake_execute_activity,
    )

    asyncio.run(StaticToolRunWorkflow().run(request.model_dump(mode="json")))

    assert execution_timeout is not None
    assert execution_timeout > timedelta(seconds=request.max_cpu_seconds)


def test_workflow_dispatches_control_and_scoped_execution_to_separate_queues(
    monkeypatch,
) -> None:
    request = make_request("sha256/aa/aa/" + "a" * 64, "a" * 64)
    grant = ToolRunStorageAccess(
        input_storage_key=request.storage_key,
        input_url="http://minio/scoped-input",
        output_storage_key="tool-runs/run-1/output.json",
        output_url="http://minio/scoped-output",
    )
    calls: list[tuple[str, str | None, bool]] = []

    async def fake_execute_activity(name: str, argument: dict, **options: object) -> dict:
        access = argument.get("storage_access") if isinstance(argument, dict) else None
        calls.append((name, options.get("task_queue"), access is not None))
        if name == "prepare_static_tool":
            return {
                **ToolRunResult(status="READY").model_dump(mode="json"),
                "request": request.model_copy(update={"storage_access": grant}).model_dump(
                    mode="json"
                ),
            }
        if name == "execute_static_tool":
            return ToolRunResult(
                status="SUCCEEDED",
                output_sha256="b" * 64,
                output_storage_key=grant.output_storage_key,
            ).model_dump(mode="json")
        if name in {"validate_static_tool_output", "finalize_static_tool_run"}:
            return dict(argument["result"])
        return request.model_dump(mode="json")

    monkeypatch.setattr(
        "threat_report_agent.tool_execution.workflow.execute_activity",
        fake_execute_activity,
    )

    asyncio.run(StaticToolRunWorkflow().run(request.model_dump(mode="json")))

    assert calls == [
        ("register_static_tool_run", "static-control", False),
        ("prepare_static_tool", "static-control", False),
        ("execute_static_tool", "static-ghidra", True),
        ("validate_static_tool_output", "static-control", False),
        ("finalize_static_tool_run", "static-control", False),
    ]


def test_workflow_finalizes_a_tool_run_when_execution_exhausts_retries(
    monkeypatch,
) -> None:
    request = make_request("sha256/aa/aa/" + "a" * 64, "a" * 64)
    finalized: list[dict] = []

    async def fake_execute_activity(name: str, argument: dict, **_: object) -> dict:
        if name == "prepare_static_tool":
            return ToolRunResult(status="READY").model_dump(mode="json")
        if name == "execute_static_tool":
            raise RuntimeError("activity retries exhausted")
        if name == "finalize_static_tool_run":
            finalized.append(argument)
            return dict(argument["result"])
        return request.model_dump(mode="json")

    monkeypatch.setattr(
        "threat_report_agent.tool_execution.workflow.execute_activity",
        fake_execute_activity,
    )

    result = asyncio.run(StaticToolRunWorkflow().run(request.model_dump(mode="json")))

    assert result["status"] == "FAILED"
    assert result["error"] == "TEMPORAL_ACTIVITY_FAILED:RuntimeError"
    assert len(finalized) == 1


def test_workflow_propagates_cancelled_activity_cause(monkeypatch) -> None:
    request = make_request("sha256/aa/aa/" + "a" * 64, "a" * 64)
    finalized = False

    async def fake_execute_activity(name: str, _: dict, **__: object) -> dict:
        nonlocal finalized
        if name == "prepare_static_tool":
            return ToolRunResult(status="READY").model_dump(mode="json")
        if name == "execute_static_tool":
            error = ActivityError(
                "activity cancelled",
                scheduled_event_id=1,
                started_event_id=2,
                identity="test-worker",
                activity_type="execute_static_tool",
                activity_id="3",
                retry_state=RetryState.CANCEL_REQUESTED,
            )
            error.__cause__ = TemporalCancelledError()
            raise error
        if name == "finalize_static_tool_run":
            finalized = True
        return request.model_dump(mode="json")

    monkeypatch.setattr(
        "threat_report_agent.tool_execution.workflow.execute_activity",
        fake_execute_activity,
    )

    with pytest.raises(TemporalCancelledError):
        asyncio.run(StaticToolRunWorkflow().run(request.model_dump(mode="json")))

    assert finalized is False


def test_activity_cancellation_stops_ghidra_and_persists_cancelled(
    test_settings: Settings,
    monkeypatch,
) -> None:
    store = LocalContentStore(test_settings.content_store_path)
    source = store.put(b"MZ")
    database = Database(test_settings.database_url)
    database.create_schema()
    service = AnalysisService(test_settings, database, store)
    case = service.create_case("Cancelled ToolRun")
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        task_id = task.id
        trace_id = task.trace_id
    request = make_request(source.storage_key, source.sha256).model_copy(
        update={
            "case_id": case.id,
            "task_id": task_id,
            "trace_id": trace_id,
            "artifact_id": None,
            "tool_name": "ghidra-headless",
            "tool_version": "12.1.2",
        }
    )
    request = request.model_copy(
        update={
            "storage_access": ToolRunStorageAccess(
                input_storage_key=source.storage_key,
                input_url="http://minio/scoped-input",
                output_storage_key=f"tool-runs/{request.tool_run_id}/output.json",
                output_url="http://minio/scoped-output",
            )
        }
    )
    uploads: list[bytes] = []
    stopped = threading.Event()
    started = threading.Event()

    class RecordingScopedStore:
        def __init__(self, _: ToolRunStorageGrant) -> None:
            pass

        def read(self, storage_key: str) -> bytes:
            assert storage_key == source.storage_key
            return b"MZ"

        def put(self, content: bytes):
            uploads.append(content)

            class Stored:
                sha256 = hashlib.sha256(content).hexdigest()
                storage_key = f"tool-runs/{request.tool_run_id}/output.json"
                size = len(content)

            return Stored()

    class CancellableRunner:
        def __init__(self, *_: object) -> None:
            pass

        def analyze(self, content, logical_path, timeout_seconds, cancellation_requested):
            started.set()
            while not cancellation_requested():
                time.sleep(0.001)
            stopped.set()
            return GhidraRun("CANCELLED", {}, "", "", "GHIDRA_CANCELLED")

    monkeypatch.setattr(
        "threat_report_agent.tool_execution.ScopedToolRunContentStore",
        RecordingScopedStore,
    )
    monkeypatch.setattr(
        "threat_report_agent.tool_execution.GhidraHeadlessRunner",
        CancellableRunner,
    )
    monkeypatch.setattr(
        "threat_report_agent.tool_execution.activity.heartbeat",
        lambda *_: None,
    )
    activities = StaticToolActivities(test_settings, store, database)
    asyncio.run(activities.register_static_tool_run(request.model_dump(mode="json")))
    asyncio.run(activities.prepare_static_tool(request.model_dump(mode="json")))

    async def cancel_running_activity() -> None:
        running = asyncio.create_task(
            activities.execute_static_tool(request.model_dump(mode="json"))
        )
        while not started.is_set():
            await asyncio.sleep(0.001)
        running.cancel()
        with pytest.raises(asyncio.CancelledError):
            await running

    asyncio.run(cancel_running_activity())

    persisted = service.task_view(task_id)["tool_runs"][0]
    assert stopped.is_set()
    assert uploads == []
    assert persisted["status"] == "CANCELLED"
    assert persisted["error"] == "GHIDRA_CANCELLED"
    assert persisted["finished_at"] is not None


def test_service_attaches_worker_persisted_tool_runs_without_duplicates(
    test_settings: Settings,
    monkeypatch,
) -> None:
    settings = replace(test_settings, tool_execution_mode="temporal")
    store = LocalContentStore(settings.content_store_path)
    database = Database(settings.database_url)
    database.create_schema()
    service = AnalysisService(settings, database, store)
    activities = StaticToolActivities(settings, store, database)

    async def execute_slices(_: TemporalToolExecutor, request: ToolRunRequest) -> ToolRunResult:
        request_data = request.model_dump(mode="json")
        await activities.register_static_tool_run(request_data)
        prepared = await activities.prepare_static_tool(request_data)
        assert prepared["status"] == "READY"
        executed = activities._execute(request)
        validated = await activities.validate_static_tool_output(
            {"request": request_data, "result": executed}
        )
        finalized = await activities.finalize_static_tool_run(
            {"request": request_data, "result": validated}
        )
        return ToolRunResult.model_validate(finalized)

    monkeypatch.setattr(TemporalToolExecutor, "execute", execute_slices)
    case = service.create_case("Worker persisted ToolRuns")

    result = service.analyze_submission(
        case_id=case.id,
        filename="stage.py",
        content=b"print('persisted')",
    )

    task = service.task_view(result.task_id)
    assert result.lifecycle == "SUCCEEDED"
    assert len(task["tool_runs"]) == 3
    assert any(
        item["tool"] == "signal-extractor" and item["version"] == "methodology-v1"
        for item in task["tool_runs"]
    )
    assert all(item["artifact_id"] is not None for item in task["tool_runs"])
    assert all(item["status"] == "SUCCEEDED" for item in task["tool_runs"])

    # Re-running the deterministic methodology action must be a no-op.  Its
    # derived Profile/FactMatch rows are not observations for the next run.
    artifact_id = task["artifacts"][0]["id"]
    before = {
        "tool_runs": len(task["tool_runs"]),
        "profiles": sum(item["kind"] == "analysis_profile" for item in task["evidence"]),
        "matches": sum(item["kind"] == "fact_match" for item in task["evidence"]),
        "claims": len(task["claims"]),
    }
    service._run_methodology_action(
        result.task_id,
        artifact_id,
        "signal-extractor",
        scheduler="idempotency-regression",
    )
    after = service.task_view(result.task_id)
    assert len(after["tool_runs"]) == before["tool_runs"]
    assert sum(item["kind"] == "analysis_profile" for item in after["evidence"]) == before["profiles"] == 1
    assert sum(item["kind"] == "fact_match" for item in after["evidence"]) == before["matches"]
    assert len(after["claims"]) == before["claims"]


def test_cancel_task_propagates_to_temporal_and_persists_terminal_states(
    test_settings: Settings,
    monkeypatch,
) -> None:
    database = Database(test_settings.database_url)
    database.create_schema()
    service = AnalysisService(
        test_settings,
        database,
        LocalContentStore(test_settings.content_store_path),
    )
    case = service.create_case("Cancellation API")
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        session.add(
            ToolRun(
                task_id=task.id,
                artifact_id=None,
                tool_name="ghidra-headless",
                tool_version="12.1.2",
                status="RUNNING",
                parameters={},
                environment={"workflow_id": "toolrun-cancellable"},
            )
        )
        task_id = task.id
    cancelled: list[str] = []

    async def fake_cancel(_: TemporalToolExecutor, workflow_id: str) -> None:
        cancelled.append(workflow_id)

    monkeypatch.setattr(TemporalToolExecutor, "cancel_workflow", fake_cancel)

    result = service.cancel_task(task_id, actor="test-analyst")

    assert cancelled == ["toolrun-cancellable"]
    assert result["lifecycle"] == "CANCELLED"
    assert result["outcome"] is None
    assert result["tool_runs"][0]["status"] == "CANCELLED"
    assert {event["event_type"] for event in service.list_audit_events(task_id)} >= {
        "analysis_task.cancel_requested",
        "analysis_task.cancelled",
    }


def test_cancel_task_removes_staged_output_after_workflow_closes(
    test_settings: Settings,
    monkeypatch,
) -> None:
    class StagingStore:
        def __init__(self) -> None:
            self.items: set[str] = set()

        def delete_tool_run_output(self, tool_run_id: str, storage_key: str) -> None:
            assert storage_key == f"tool-runs/{tool_run_id}/output.json"
            self.items.discard(storage_key)

    database = Database(test_settings.database_url)
    database.create_schema()
    store = StagingStore()
    service = AnalysisService(test_settings, database, store)
    case = service.create_case("Cancellation staging cleanup")
    tool_run_id = "run-with-delayed-output"
    workflow_id = "toolrun-with-delayed-output"
    staging_key = f"tool-runs/{tool_run_id}/output.json"
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        session.add(
            ToolRun(
                id=tool_run_id,
                task_id=task.id,
                artifact_id=None,
                tool_name="ghidra-headless",
                tool_version="12.1.2",
                status="RUNNING",
                parameters={},
                output_sha256="a" * 64,
                output_storage_key=staging_key,
                environment={"workflow_id": workflow_id},
            )
        )
        task_id = task.id

    async def fake_cancel(_: TemporalToolExecutor, cancelled_workflow_id: str) -> None:
        assert cancelled_workflow_id == workflow_id
        store.items.add(staging_key)

    monkeypatch.setattr(TemporalToolExecutor, "cancel_workflow", fake_cancel)

    result = service.cancel_task(task_id, actor="test-analyst")

    assert result["lifecycle"] == "CANCELLED"
    assert result["tool_runs"][0]["output_reference"] is None
    assert store.items == set()


def test_cancelled_tool_run_rejects_a_late_timeout_finalizer(
    test_settings: Settings,
    monkeypatch,
) -> None:
    database = Database(test_settings.database_url)
    database.create_schema()
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    case = service.create_case("Late finalizer cancellation guard")
    tool_run_id = "run-late-finalizer"
    workflow_id = "toolrun-late-finalizer"
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        task_id = task.id
        trace_id = task.trace_id
        session.add(
            ToolRun(
                id=tool_run_id,
                task_id=task_id,
                artifact_id=None,
                tool_name="ghidra-headless",
                tool_version="12.1.2",
                status="RUNNING",
                parameters={},
                environment={"workflow_id": workflow_id},
            )
        )

    async def fake_cancel(_: TemporalToolExecutor, workflow_id_to_cancel: str) -> None:
        assert workflow_id_to_cancel == workflow_id
        return None

    monkeypatch.setattr(TemporalToolExecutor, "cancel_workflow", fake_cancel)
    service.cancel_task(task_id, actor="test-analyst")
    request = make_request(
        "sha256/aa/aa/" + "a" * 64,
        "a" * 64,
        tool_run_id=tool_run_id,
    ).model_copy(
        update={
            "case_id": case.id,
            "task_id": task_id,
            "trace_id": trace_id,
            "tool_name": "ghidra-headless",
        }
    )
    late_result = ToolRunResult(
        status="TIMED_OUT",
        output_sha256="b" * 64,
        output_storage_key=f"tool-runs/{tool_run_id}/output.json",
        error="TEMPORAL_ACTIVITY_TIMED_OUT",
    )

    asyncio.run(
        StaticToolActivities(test_settings, store, database).finalize_static_tool_run(
            {
                "request": request.model_dump(mode="json"),
                "result": late_result.model_dump(mode="json"),
            }
        )
    )

    persisted = service.task_view(task_id)["tool_runs"][0]
    assert persisted["status"] == "CANCELLED"
    assert persisted["output_reference"] is None


def test_cancel_task_is_not_blocked_by_a_running_ghidra_workflow(
    test_settings: Settings,
    tmp_path,
    monkeypatch,
) -> None:
    settings = replace(
        test_settings,
        database_url=f"sqlite:///{tmp_path / 'cancellation.db'}?timeout=0.2",
        content_store_path=str(tmp_path / "content"),
        tool_execution_mode="temporal",
    )
    database = Database(settings.database_url)
    database.create_schema()
    store = LocalContentStore(settings.content_store_path)
    service = AnalysisService(settings, database, store)
    activity = StaticToolActivities(settings, store)
    case = service.create_case("Cancellation during Ghidra")
    queued, _ = service.create_submission_task(
        case_id=case.id,
        filename="truncated.exe",
        submitted_size=2,
    )
    with database.session_factory.begin() as session:
        session.add(
            ToolRun(
                task_id=queued.task_id,
                artifact_id=None,
                tool_name="ghidra-headless",
                tool_version="12.1.2",
                status="RUNNING",
                parameters={},
                environment={"workflow_id": "toolrun-cancellable"},
            )
        )

    ghidra_started = threading.Event()
    release_ghidra = threading.Event()
    cancelled: list[str] = []

    async def fake_execute(_: TemporalToolExecutor, request: ToolRunRequest) -> ToolRunResult:
        if request.tool_name != "ghidra-headless":
            return ToolRunResult.model_validate(activity._execute(request))
        ghidra_started.set()
        while not release_ghidra.is_set():
            await asyncio.sleep(0.01)
        return ToolRunResult(
            status="CANCELLED",
            error="TOOL_ACTIVITY_CANCELLED",
            worker_metadata={
                "workflow_id": request.workflow_id,
                "task_queue": request.task_queue,
            },
        )

    async def fake_cancel(_: TemporalToolExecutor, workflow_id: str) -> None:
        cancelled.append(workflow_id)
        release_ghidra.set()

    monkeypatch.setattr(TemporalToolExecutor, "execute", fake_execute)
    monkeypatch.setattr(TemporalToolExecutor, "cancel_workflow", fake_cancel)
    analysis_errors: list[BaseException] = []

    def execute_analysis() -> None:
        try:
            service.execute_submission_task(
                task_id=queued.task_id,
                filename="truncated.exe",
                content=b"MZ",
            )
        except BaseException as exc:
            analysis_errors.append(exc)

    analysis = threading.Thread(target=execute_analysis, daemon=True)
    analysis.start()
    assert ghidra_started.wait(timeout=3)
    try:
        result = service.cancel_task(queued.task_id, actor="test-analyst")
    finally:
        release_ghidra.set()
        analysis.join(timeout=3)

    assert not analysis.is_alive()
    assert analysis_errors == []
    assert cancelled == ["toolrun-cancellable"]
    assert result["lifecycle"] == "CANCELLED"
    assert service.audit_integrity(queued.task_id)["valid"] is True


def test_intake_exception_transitions_task_to_failed_and_seals_audit(
    test_settings: Settings,
    tmp_path,
    monkeypatch,
) -> None:
    settings = replace(
        test_settings,
        database_url=f"sqlite:///{tmp_path / 'intake-failure.db'}",
        content_store_path=str(tmp_path / "content"),
        tool_execution_mode="temporal",
    )
    database = Database(settings.database_url)
    database.create_schema()
    store = LocalContentStore(settings.content_store_path)
    service = AnalysisService(settings, database, store)
    case = service.create_case("Intake failure terminal state")
    queued, _ = service.create_submission_task(
        case_id=case.id,
        filename="bundle.zip",
        submitted_size=4,
        content=b"PK\x03\x04",
        source_kind="zip",
    )

    async def fail_intake(_: TemporalToolExecutor, __: ToolRunRequest) -> ToolRunResult:
        raise RuntimeError("presigned output rejected")

    monkeypatch.setattr(TemporalToolExecutor, "execute", fail_intake)

    with pytest.raises(RuntimeError, match="presigned output rejected"):
        service.execute_submission_task(task_id=queued.task_id)

    task = service.task_view(queued.task_id)
    events = service.list_audit_events(queued.task_id)
    integrity = service.audit_integrity(queued.task_id)
    assert task["lifecycle"] == "FAILED"
    assert task["finished_at"] is not None
    assert events[-1]["event_type"] == "analysis_task.failed"
    assert integrity["valid"] is True
    assert integrity["seals"][-1]["terminal_event_type"] == "analysis_task.failed"


def test_worker_reads_referenced_content_and_persists_static_output(
    test_settings: Settings,
) -> None:
    store = LocalContentStore(test_settings.content_store_path)
    source = store.put(
        b"import socket\n\ndef stage():\n    return socket.create_connection(('x', 1))\n"
    )
    activity = StaticToolActivities(test_settings, store)

    result = activity._execute(make_request(source.storage_key, source.sha256))

    assert result["status"] == "SUCCEEDED"
    output = json.loads(store.read(str(result["output_storage_key"])))
    assert "claims" not in output
    static = static_result_from_payload(output)
    assert static.detected_type == "script"
    assert any(fact.kind == "script_import" for fact in static.facts)
    assert result["worker_metadata"]["input_sha256"] == source.sha256


def test_worker_rejects_content_reference_with_a_wrong_hash(test_settings: Settings) -> None:
    store = LocalContentStore(test_settings.content_store_path)
    source = store.put(b"print('safe')")
    activity = StaticToolActivities(test_settings, store)
    request = make_request(source.storage_key, "0" * 64)

    result = activity._execute(request)

    assert result["status"] == "FAILED"
    assert result["error"] == "CONTENT_HASH_MISMATCH"


def test_temporal_mode_delegates_static_tools_by_content_reference(
    test_settings: Settings, monkeypatch
) -> None:
    settings = replace(test_settings, tool_execution_mode="temporal")
    store = LocalContentStore(settings.content_store_path)
    database = Database(settings.database_url)
    database.create_schema()
    service = AnalysisService(settings, database, store)
    activity = StaticToolActivities(settings, store)
    submitted: list[ToolRunRequest] = []

    async def fake_execute(_: TemporalToolExecutor, request: ToolRunRequest) -> ToolRunResult:
        submitted.append(request)
        return ToolRunResult.model_validate(activity._execute(request))

    monkeypatch.setattr(TemporalToolExecutor, "execute", fake_execute)
    case = service.create_case("Temporal static test")

    result = service.analyze_submission(
        case_id=case.id,
        filename="stage.py",
        content=b"import socket\nprint(socket.gethostname())\n",
    )

    assert result.lifecycle == "SUCCEEDED"
    intake_request = next(
        request for request in submitted if request.tool_name == "python-zipfile-safe-reader"
    )
    parser_request = next(request for request in submitted if request.tool_name == "script-parser")
    assert intake_request.task_queue == "static-intake"
    assert intake_request.artifact_id is None
    assert parser_request.task_queue == "static-script"
    assert {intake_request.case_id, parser_request.case_id} == {case.id}
    assert intake_request.trace_id == parser_request.trace_id
    assert len(intake_request.trace_id) == 36
    assert parser_request.content_sha256
    assert not hasattr(parser_request, "content")
    task = service.task_view(result.task_id)
    intake_run = next(
        item for item in task["tool_runs"] if item["tool"] == "python-zipfile-safe-reader"
    )
    parser_run = next(item for item in task["tool_runs"] if item["tool"] == "script-parser")
    assert intake_run["id"] == intake_request.tool_run_id
    assert parser_run["id"] == parser_request.tool_run_id
    for persisted, request in (
        (intake_run, intake_request),
        (parser_run, parser_request),
    ):
        assert persisted["started_at"] <= persisted["finished_at"]
        assert persisted["execution"]["case_id"] == case.id
        assert persisted["execution"]["trace_id"] == request.trace_id
        assert persisted["execution"]["tool_run_id"] == persisted["id"]
        assert persisted["execution"]["environment_version"] == request.environment_version
    assert parser_run["execution"]["executor"] == "temporal"
    assert parser_run["execution"]["workflow_id"].startswith("toolrun-")
    assert parser_run["output_reference"]["sha256"]


def test_temporal_mode_delegates_ghidra_without_local_runner(
    test_settings: Settings, monkeypatch
) -> None:
    settings = replace(test_settings, tool_execution_mode="temporal")
    store = LocalContentStore(settings.content_store_path)
    database = Database(settings.database_url)
    database.create_schema()
    service = AnalysisService(settings, database, store)
    activity = StaticToolActivities(settings, store)
    submitted: list[ToolRunRequest] = []

    async def fake_execute(_: TemporalToolExecutor, request: ToolRunRequest) -> ToolRunResult:
        submitted.append(request)
        if request.tool_name == "ghidra-headless":
            output = store.put(
                json.dumps(
                    {
                        "kind": "ghidra",
                        "status": "FAILED",
                        "output": {},
                        "error": "GHIDRA_WORKER_UNAVAILABLE",
                    }
                ).encode("utf-8")
            )
            return ToolRunResult(
                status="FAILED",
                output_sha256=output.sha256,
                output_storage_key=output.storage_key,
                error="GHIDRA_WORKER_UNAVAILABLE",
                started_at=datetime(2026, 1, 1, tzinfo=UTC),
                finished_at=datetime(2026, 1, 1, 0, 0, 5, tzinfo=UTC),
                worker_metadata={
                    "executor": "temporal",
                    "workflow_id": request.workflow_id,
                    "task_queue": request.task_queue,
                },
            )
        return ToolRunResult.model_validate(activity._execute(request))

    monkeypatch.setattr(TemporalToolExecutor, "execute", fake_execute)
    case = service.create_case("Temporal Ghidra test")

    result = service.analyze_submission(case_id=case.id, filename="truncated.exe", content=b"MZ")

    assert result.outcome == "PARTIAL"
    ghidra_request = next(
        request for request in submitted if request.tool_name == "ghidra-headless"
    )
    task = service.task_view(result.task_id)
    ghidra_run = next(item for item in task["tool_runs"] if item["tool"] == "ghidra-headless")
    assert ghidra_run["id"] == ghidra_request.tool_run_id
    assert ghidra_run["started_at"] == "2026-01-01T00:00:00+00:00"
    assert ghidra_run["finished_at"] == "2026-01-01T00:00:05+00:00"
    assert ghidra_run["execution"]["executor"] == "temporal"
    assert ghidra_run["execution"]["case_id"] == case.id
    assert ghidra_run["execution"]["trace_id"] == ghidra_request.trace_id
    assert ghidra_run["execution"]["tool_run_id"] == ghidra_run["id"]
    assert ghidra_run["execution"]["environment_version"] == ghidra_request.environment_version


def test_temporal_ghidra_output_records_nested_function_evidence(
    test_settings: Settings, monkeypatch
) -> None:
    settings = replace(test_settings, tool_execution_mode="temporal")
    store = LocalContentStore(settings.content_store_path)
    database = Database(settings.database_url)
    database.create_schema()
    service = AnalysisService(settings, database, store)
    activity = StaticToolActivities(settings, store)

    async def fake_execute(_: TemporalToolExecutor, request: ToolRunRequest) -> ToolRunResult:
        if request.tool_name != "ghidra-headless":
            return ToolRunResult.model_validate(activity._execute(request))
        output = store.put(
            json.dumps(
                {
                    "kind": "ghidra",
                    "status": "SUCCEEDED",
                    "output": {
                        "functions": [
                            {
                                "name": "entry",
                                "entry": "140001000",
                                "entry_rva": 4096,
                                "signature": "void entry(void)",
                                "mnemonics": ["PUSH", "MOV", "RET"],
                                "instructions": [
                                    {
                                        "address": "140001001",
                                        "mnemonic": "MOV",
                                        "text": "MOV RBX, qword ptr [PTR_GetProcAddress]",
                                    },
                                    {
                                        "address": "140001002",
                                        "mnemonic": "CALL",
                                        "text": "CALL RBX",
                                    },
                                    {
                                        "address": "140001003",
                                        "mnemonic": "MOV",
                                        "text": "MOV qword ptr [0x1400d0320], RAX",
                                    },
                                    {
                                        "address": "140001004",
                                        "mnemonic": "JMP",
                                        "text": "JMP RAX",
                                    },
                                ],
                                "references_from": [
                                    {
                                        "from": "140001001",
                                        "to": "0x140102588",
                                        "type": "DATA",
                                        "target_name": "PTR_GetProcAddress",
                                    },
                                    {
                                        "from": "140001005",
                                        "to": "KERNEL32!LoadLibraryW",
                                        "type": "CALL",
                                        "target_name": "LoadLibraryW",
                                    },
                                    {
                                        "from": "140001006",
                                        "to": "KERNEL32!GetProcAddress",
                                        "type": "CALL",
                                        "target_name": "GetProcAddress",
                                    },
                                    {
                                        "from": "140001007",
                                        "to": "KERNEL32!VirtualAlloc",
                                        "type": "CALL",
                                        "target_name": "VirtualAlloc",
                                    },
                                    {
                                        "from": "140001008",
                                        "to": "KERNEL32!VirtualProtect",
                                        "type": "CALL",
                                        "target_name": "VirtualProtect",
                                    },
                                    {
                                        "from": "14000100c",
                                        "to": "KERNEL32!CreateProcessW",
                                        "type": "CALL",
                                        "target_name": "CreateProcessW",
                                    },
                                    {
                                        "from": "140001010",
                                        "to": "KERNEL32!CreatePipe",
                                        "type": "CALL",
                                        "target_name": "CreatePipe",
                                    },
                                    {
                                        "from": "140001014",
                                        "to": "KERNEL32!ReadFile",
                                        "type": "CALL",
                                        "target_name": "ReadFile",
                                    },
                                ],
                                "xrefs_to_entry": [
                                    {
                                        "from": "140002000",
                                        "to": "140001000",
                                        "type": "UNCONDITIONAL_CALL",
                                    }
                                ],
                                "cfg_blocks": [
                                    {
                                        "start": "140001000",
                                        "end": "140001008",
                                        "destinations": [],
                                    }
                                ],
                            }
                        ],
                        "symbols": [],
                    },
                    "error": None,
                }
            ).encode("utf-8")
        )
        return ToolRunResult(
            status="SUCCEEDED",
            output_sha256=output.sha256,
            output_storage_key=output.storage_key,
            worker_metadata={
                "executor": "temporal",
                "workflow_id": request.workflow_id,
                "task_queue": request.task_queue,
            },
        )

    monkeypatch.setattr(TemporalToolExecutor, "execute", fake_execute)
    case = service.create_case("Temporal Ghidra evidence test")

    result = service.analyze_submission(case_id=case.id, filename="truncated.exe", content=b"MZ")
    task = service.task_view(result.task_id)
    evidence_kinds = {item["kind"] for item in task["evidence"]}
    ghidra_run = next(item for item in task["tool_runs"] if item["tool"] == "ghidra-headless")

    assert ghidra_run["status"] == "SUCCEEDED"
    assert len(ghidra_run["output_reference"]["sha256"]) == 64
    assert ghidra_run["output_reference"]["storage_key"]
    assert {"function", "function_simhash", "xref", "cfg_block", "abstract_execution_trace"} <= evidence_kinds
    assert {"function_interface"} <= evidence_kinds
    assert {
        "mechanism_dynamic_api_link",
        "mechanism_shell_output_link",
    } <= evidence_kinds
    linked_evidence = [
        item
        for item in task["evidence"]
        if item["kind"] in {"mechanism_dynamic_api_link", "mechanism_shell_output_link"}
    ]
    assert linked_evidence
    assert all(item["nature"] == "STATIC_DERIVED" for item in linked_evidence)
    assert all(item["value"].get("source_evidence_ids") for item in linked_evidence)
    assert all(item["value"].get("derivation", {}).get("evaluator") == "derive_static_mechanism_links" for item in linked_evidence)
    assert task["actual_granularity"]["depth"] == "D3"
    simhash_evidence = next(item for item in task["evidence"] if item["kind"] == "function_simhash")
    assert simhash_evidence["value"] == {
        "algorithm": "charikar-simhash-64",
        "feature": "mnemonic-4gram",
        "hash": "md5-prefix-64-le",
        "value": "476551a24aa9862b",
    }
    assert any(
        "High-value static review candidate" in claim["statement"] for claim in task["claims"]
    )
    assert all(
        claim["confidence"] in ("LOW", "MEDIUM", "HIGH")
        for claim in task["claims"]
        if "High-value static review candidate" in claim["statement"]
    )


def test_temporal_ghidra_output_rejects_invalid_function_schema(
    test_settings: Settings, monkeypatch
) -> None:
    settings = replace(test_settings, tool_execution_mode="temporal")
    store = LocalContentStore(settings.content_store_path)
    database = Database(settings.database_url)
    database.create_schema()
    service = AnalysisService(settings, database, store)
    activity = StaticToolActivities(settings, store)

    async def fake_execute(_: TemporalToolExecutor, request: ToolRunRequest) -> ToolRunResult:
        if request.tool_name != "ghidra-headless":
            return ToolRunResult.model_validate(activity._execute(request))
        output = store.put(
            json.dumps(
                {
                    "kind": "ghidra",
                    "status": "SUCCEEDED",
                    "output": {
                        "functions": [{"name": "entry", "mnemonics": "not-a-list"}],
                        "symbols": [],
                    },
                    "error": None,
                }
            ).encode("utf-8")
        )
        return ToolRunResult(
            status="SUCCEEDED",
            output_sha256=output.sha256,
            output_storage_key=output.storage_key,
            started_at=datetime(2026, 1, 3, tzinfo=UTC),
            finished_at=datetime(2026, 1, 3, 0, 0, 8, tzinfo=UTC),
            worker_metadata={"executor": "temporal"},
        )

    monkeypatch.setattr(TemporalToolExecutor, "execute", fake_execute)
    case = service.create_case("Invalid Ghidra function output")

    result = service.analyze_submission(case_id=case.id, filename="truncated.exe", content=b"MZ")

    assert result.outcome == "PARTIAL"
    task = service.task_view(result.task_id)
    ghidra_run = next(item for item in task["tool_runs"] if item["tool"] == "ghidra-headless")
    assert ghidra_run["status"] == "FAILED"
    assert ghidra_run["error"] == "INVALID_GHIDRA_OUTPUT:GHIDRA_OUTPUT_INVALID_SCHEMA"
    assert ghidra_run["started_at"] == "2026-01-03T00:00:00+00:00"
    assert ghidra_run["finished_at"] == "2026-01-03T00:00:08+00:00"


def test_intake_worker_persists_only_member_references(test_settings: Settings) -> None:
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("nested/stage.py", b"import socket\n")
    store = LocalContentStore(test_settings.content_store_path)
    source = store.put(archive_bytes.getvalue())
    activity = StaticToolActivities(test_settings, store)
    request = ToolRunRequest(
        case_id="case-1",
        task_id="task-1",
        trace_id="trace-1",
        artifact_id="task-1",
        tool_run_id="intake-1",
        tool_name="python-zipfile-safe-reader",
        tool_version="3.12",
        content_sha256=source.sha256,
        storage_key=source.storage_key,
        logical_path="bundle.zip",
        parameters={"max_files": 10, "max_bytes": 1024 * 1024, "max_depth": 2},
        max_cpu_seconds=60,
        max_memory_mb=512,
        task_queue="static-intake",
    )

    result = activity._execute(request)
    payload = json.loads(store.read(str(result["output_storage_key"])))
    entries = intake_entries_from_payload(payload)

    assert result["status"] == "SUCCEEDED"
    assert [entry.logical_path for entry in entries] == [
        "bundle.zip",
        "bundle.zip!/nested/stage.py",
    ]
    assert all(entry.content == b"" for entry in entries)
    assert all(entry.content_sha256 and entry.storage_key for entry in entries)


def test_worker_rejects_tool_assigned_to_a_different_queue(
    test_settings: Settings,
) -> None:
    settings = replace(test_settings, tool_allowed_tools=("pe-parser",))
    store = LocalContentStore(settings.content_store_path)
    source = store.put(b"print('x')")
    activity = StaticToolActivities(settings, store)
    request = make_request(source.storage_key, source.sha256)

    result = asyncio.run(activity.execute_static_tool(request.model_dump(mode="json")))

    assert result["status"] == "FAILED"
    assert result["error"] == "TOOL_NOT_ALLOWED_ON_WORKER"


def test_temporal_parser_exception_records_failed_tool_run(
    test_settings: Settings,
    monkeypatch,
) -> None:
    settings = replace(test_settings, tool_execution_mode="temporal")
    store = LocalContentStore(settings.content_store_path)
    database = Database(settings.database_url)
    database.create_schema()
    service = AnalysisService(settings, database, store)
    activity = StaticToolActivities(settings, store)

    async def fake_execute(_: TemporalToolExecutor, request: ToolRunRequest) -> ToolRunResult:
        if request.tool_name == "python-zipfile-safe-reader":
            return ToolRunResult.model_validate(activity._execute(request))
        raise RuntimeError("worker unavailable")

    monkeypatch.setattr(TemporalToolExecutor, "execute", fake_execute)
    case = service.create_case("Temporal parser failure")

    result = service.analyze_submission(
        case_id=case.id,
        filename="stage.py",
        content=b"print('x')",
    )
    task = service.task_view(result.task_id)
    parser_run = next(item for item in task["tool_runs"] if item["tool"] == "script-parser")

    assert result.lifecycle == "SUCCEEDED"
    assert result.outcome == "PARTIAL"
    assert parser_run["status"] == "FAILED"
    assert parser_run["error"] == "TEMPORAL_WORKFLOW_FAILED:RuntimeError"
    assert any("script-parser failed" in limitation for limitation in task["limitations"])


def test_temporal_invalid_parser_output_preserves_worker_timing(
    test_settings: Settings,
    monkeypatch,
) -> None:
    settings = replace(test_settings, tool_execution_mode="temporal")
    store = LocalContentStore(settings.content_store_path)
    database = Database(settings.database_url)
    database.create_schema()
    service = AnalysisService(settings, database, store)
    activity = StaticToolActivities(settings, store)

    async def fake_execute(_: TemporalToolExecutor, request: ToolRunRequest) -> ToolRunResult:
        if request.tool_name == "python-zipfile-safe-reader":
            return ToolRunResult.model_validate(activity._execute(request))
        output = store.put(b'{"kind":"unexpected"}')
        return ToolRunResult(
            status="SUCCEEDED",
            output_sha256=output.sha256,
            output_storage_key=output.storage_key,
            started_at=datetime(2026, 1, 2, tzinfo=UTC),
            finished_at=datetime(2026, 1, 2, 0, 0, 7, tzinfo=UTC),
            worker_metadata={"executor": "temporal"},
        )

    monkeypatch.setattr(TemporalToolExecutor, "execute", fake_execute)
    case = service.create_case("Invalid parser output")

    result = service.analyze_submission(
        case_id=case.id,
        filename="stage.py",
        content=b"print('x')",
    )
    task = service.task_view(result.task_id)
    parser_run = next(item for item in task["tool_runs"] if item["tool"] == "script-parser")

    assert result.outcome == "PARTIAL"
    assert parser_run["status"] == "FAILED"
    assert parser_run["error"] == "INVALID_STATIC_TOOL_OUTPUT:ValueError"
    assert parser_run["started_at"] == "2026-01-02T00:00:00+00:00"
    assert parser_run["finished_at"] == "2026-01-02T00:00:07+00:00"
