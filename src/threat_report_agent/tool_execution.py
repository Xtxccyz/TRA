from __future__ import annotations

import asyncio
import base64
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
import hashlib
import json
import threading
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from temporalio import activity, workflow
from temporalio.client import (
    Client,
    Schedule,
    ScheduleActionStartWorkflow,
    ScheduleCalendarSpec,
    ScheduleOverlapPolicy,
    SchedulePolicy,
    ScheduleRange,
    ScheduleSpec,
    ScheduleAlreadyRunningError,
)
from temporalio.exceptions import CancelledError as TemporalCancelledError
from temporalio.exceptions import TimeoutError as TemporalTimeoutError
from temporalio.exceptions import WorkflowAlreadyStartedError
from temporalio.common import RetryPolicy
from temporalio.worker import Worker

with workflow.unsafe.imports_passed_through():
    from threat_report_agent.config import Settings
    from threat_report_agent.content_store import (
        ContentStore,
        LocalContentStore,
        S3ContentStore,
        ScopedToolRunContentStore,
        ToolRunStorageGrant,
    )
    from threat_report_agent.database import Database
    from threat_report_agent.ghidra_adapter import GhidraHeadlessRunner
    from threat_report_agent.intake import IntakeGateRequired, PackageEntry, expand_submission
    from threat_report_agent.models import AnalysisTask, TaskSecret, ToolRun, utcnow
    from threat_report_agent.secret_store import SecretCipher
    from threat_report_agent.static.static_analysis import (
        StaticFact,
        StaticResult,
        analyze_bytes,
        identify_format,
    )
    from threat_report_agent.controlled_emulation import is_placeholder_status
    from threat_report_agent.emulation_plan import (
        _as_int_address,
        controlled_emulation_windows,
    )
    from threat_report_agent.simulation_adapters import (
        IsolatedSimulationRunner,
        default_simulation_runner,
        qiling_unavailable_observation,
        request_for_granted_window,
        simulation_policy_from_settings,
    )


STATIC_TOOL_ALLOWLIST = frozenset(
    {
        "python-zipfile-safe-reader",
        "builtin-static-analyzer",
        "pe-parser",
        "script-parser",
        "document-carrier-parser",
        "ghidra-headless",
        "controlled-emulator",
    }
)


class ToolRunStorageAccess(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    input_storage_key: str = Field(min_length=1, max_length=512)
    input_url: str = Field(min_length=1)
    output_storage_key: str = Field(min_length=1, max_length=512)
    output_url: str = Field(min_length=1)

    @classmethod
    def from_grant(cls, grant: ToolRunStorageGrant) -> "ToolRunStorageAccess":
        return cls(
            input_storage_key=grant.input_storage_key,
            input_url=grant.input_url,
            output_storage_key=grant.output_storage_key,
            output_url=grant.output_url,
        )


class ToolRunRequest(BaseModel):
    """Serializable Worker input. It deliberately contains no sample bytes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str = Field(min_length=1, max_length=36)
    task_id: str = Field(min_length=1, max_length=36)
    trace_id: str = Field(min_length=1, max_length=36)
    artifact_id: str | None = Field(default=None, min_length=1, max_length=36)
    tool_run_id: str = Field(min_length=1, max_length=36)
    tool_name: str = Field(min_length=1, max_length=120)
    tool_version: str = Field(min_length=1, max_length=80)
    content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    storage_key: str = Field(min_length=1, max_length=512)
    logical_path: str = Field(min_length=1, max_length=1024)
    parameters: dict[str, object] = Field(default_factory=dict)
    max_cpu_seconds: int = Field(ge=1, le=3600)
    max_memory_mb: int = Field(ge=64, le=32768)
    control_task_queue: str = Field(default="static-control", min_length=1, max_length=120)
    task_queue: str = Field(default="static-parser", min_length=1, max_length=120)
    environment_version: str = Field(default="static-worker-v1", min_length=1, max_length=160)
    sample_execution: bool = False
    network_access: bool = False
    storage_access: ToolRunStorageAccess | None = None

    @property
    def idempotency_key(self) -> str:
        material = {
            "task_id": self.task_id,
            "artifact_id": self.artifact_id,
            "content_sha256": self.content_sha256,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "parameters": self.parameters,
            "max_cpu_seconds": self.max_cpu_seconds,
            "max_memory_mb": self.max_memory_mb,
            "task_queue": self.task_queue,
            "environment_version": self.environment_version,
        }
        encoded = json.dumps(material, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @property
    def workflow_id(self) -> str:
        return f"toolrun-{self.idempotency_key}"


class ToolRunResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    status: str
    output_sha256: str | None = None
    output_storage_key: str | None = None
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    worker_metadata: dict[str, object] = Field(default_factory=dict)


@workflow.defn
class StaticToolRunWorkflow:
    @workflow.run
    async def run(self, request: dict[str, Any]) -> dict[str, Any]:
        validated = ToolRunRequest.model_validate(request)
        request_data = validated.model_dump(mode="json")
        control_timeout = timedelta(seconds=30)
        control_retry = RetryPolicy(maximum_attempts=3)
        await workflow.execute_activity(
            "register_static_tool_run",
            request_data,
            start_to_close_timeout=control_timeout,
            retry_policy=control_retry,
            task_queue=validated.control_task_queue,
        )
        prepared = await workflow.execute_activity(
            "prepare_static_tool",
            request_data,
            start_to_close_timeout=control_timeout,
            retry_policy=control_retry,
            task_queue=validated.control_task_queue,
        )
        execution_request = prepared.pop("request", request_data)
        if prepared["status"] == "READY":
            try:
                result = await workflow.execute_activity(
                    "execute_static_tool",
                    execution_request,
                    schedule_to_start_timeout=timedelta(seconds=30),
                    start_to_close_timeout=timedelta(seconds=validated.max_cpu_seconds + 30),
                    heartbeat_timeout=timedelta(seconds=min(30, validated.max_cpu_seconds)),
                    retry_policy=RetryPolicy(maximum_attempts=3),
                    cancellation_type=(
                        workflow.ActivityCancellationType.WAIT_CANCELLATION_COMPLETED
                    ),
                    task_queue=validated.task_queue,
                )
                if result.get("started_at") is None:
                    result["started_at"] = prepared.get("started_at")
                result = await workflow.execute_activity(
                    "validate_static_tool_output",
                    {"request": execution_request, "result": result},
                    start_to_close_timeout=control_timeout,
                    retry_policy=control_retry,
                    task_queue=validated.control_task_queue,
                )
            except TemporalCancelledError:
                raise
            except Exception as exc:
                cause = getattr(exc, "cause", None)
                if isinstance(cause, TemporalCancelledError):
                    raise cause
                timed_out = isinstance(exc, TemporalTimeoutError) or isinstance(
                    cause, TemporalTimeoutError
                )
                result = ToolRunResult(
                    status="TIMED_OUT" if timed_out else "FAILED",
                    error=(
                        "TEMPORAL_ACTIVITY_TIMED_OUT"
                        if timed_out
                        else f"TEMPORAL_ACTIVITY_FAILED:{type(exc).__name__}"
                    ),
                    started_at=prepared.get("started_at"),
                ).model_dump(mode="json")
        else:
            result = prepared
        return await workflow.execute_activity(
            "finalize_static_tool_run",
            {"request": request_data, "result": result},
            start_to_close_timeout=control_timeout,
            retry_policy=control_retry,
            task_queue=validated.control_task_queue,
        )


@workflow.defn
class ModelPayloadCleanupWorkflow:
    """Durable daily trigger for encrypted model-payload retention cleanup."""

    @workflow.run
    async def run(self, request: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = request or {}
        return await workflow.execute_activity(
            "expire_model_payloads",
            payload,
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=RetryPolicy(maximum_attempts=3),
            task_queue=str(payload.get("control_task_queue", "static-control")),
        )


@workflow.defn
class DailyAuditSealWorkflow:
    """Durable UTC-day audit sealing trigger for the control Worker."""

    @workflow.run
    async def run(self, request: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = dict(request or {})
        if not payload.get("utc_day"):
            # The schedule runs shortly after a UTC-day boundary. Seal the
            # completed prior day; never mark the in-progress current day as
            # a complete audit window.
            payload["utc_day"] = (workflow.now().date() - timedelta(days=1)).isoformat()
        return await workflow.execute_activity(
            "seal_daily_audit",
            payload,
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=RetryPolicy(maximum_attempts=3),
            task_queue=str(payload.get("control_task_queue", "static-control")),
        )


def emulation_overall_from_results(
    results: Iterable[Mapping[str, object]],
    *,
    current_overall: str = "FAILED",
    current_error: str | None = None,
) -> tuple[str, str | None]:
    """Kunglao leftover remainder: Unicorn HOW is not Speakeasy poison.

    A Speakeasy/Qiling EXECUTION_ERROR used to set the worker overall FAILED
    even when a granted Unicorn window SUCCEEDED. One-round reports then
    listed controlled-emulator FAILED and Unique OS threads as NOT_ATTEMPTED.
    """
    rows = [item for item in results if isinstance(item, Mapping)]
    if not rows:
        return current_overall or "FAILED", current_error
    # A row for a window that NEVER RAN says nothing about the run's outcome, so it must not participate in
    # the aggregation. MEASURED why this filter exists (T1a audit finding F2): the `all(...)` test below
    # requires every status to be UNSUPPORTED/UNAVAILABLE, so one NOT_EXECUTED row falsified it and a run
    # whose executed windows were all UNSUPPORTED fell through to `current_overall == "SUCCEEDED"` and
    # reported FAILED instead. `is_placeholder_status` is the shared definition, so this cannot drift from
    # the predicate that decides whether a real simulation landed.
    rows = [item for item in rows if not is_placeholder_status(item.get("status"))]
    if not rows:
        return current_overall or "FAILED", current_error
    statuses = [str(item.get("status") or "").upper() for item in rows]
    if "CANCELLED" in statuses:
        return "CANCELLED", current_error or "TOOL_ACTIVITY_CANCELLED"

    def _sim(item: Mapping[str, object]) -> str:
        return str(item.get("simulator") or "").casefold()

    def _st(item: Mapping[str, object]) -> str:
        return str(item.get("status") or "").upper()

    unicorn_ok = any(
        _sim(item) == "unicorn" and _st(item) in {"SUCCEEDED", "PARTIAL"} for item in rows
    )
    any_ok = any(_st(item) in {"SUCCEEDED", "PARTIAL"} for item in rows)
    if unicorn_ok or any_ok:
        if any(_st(item) == "SUCCEEDED" for item in rows):
            return "SUCCEEDED", None
        return "PARTIAL", current_error
    if statuses and all(item in {"UNSUPPORTED", "UNAVAILABLE"} for item in statuses):
        return "UNSUPPORTED", current_error
    if current_overall == "SUCCEEDED":
        return "FAILED", current_error
    return current_overall or "FAILED", current_error


class StaticToolActivities:
    """Worker-side static analysis. This class never executes the submitted sample."""

    def __init__(
        self,
        settings: Settings,
        content_store: ContentStore | None,
        database: Database | None = None,
    ) -> None:
        self.settings = settings
        self.content_store = content_store
        self.database = database

    @activity.defn(name="register_static_tool_run")
    async def register_static_tool_run(self, request_data: dict[str, Any]) -> dict[str, Any]:
        request = ToolRunRequest.model_validate(request_data)
        if self.database is not None:
            with self.database.session_factory.begin() as session:
                tool_run = session.get(ToolRun, request.tool_run_id)
                if tool_run is None:
                    session.add(
                        ToolRun(
                            id=request.tool_run_id,
                            task_id=request.task_id,
                            artifact_id=None,
                            tool_name=request.tool_name,
                            tool_version=request.tool_version,
                            status="QUEUED",
                            parameters=request.parameters,
                            environment=self._worker_metadata(request),
                            output={},
                            started_at=None,
                            finished_at=None,
                        )
                    )
        return request.model_dump(mode="json")

    @activity.defn(name="expire_model_payloads")
    async def expire_model_payloads(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run retention cleanup through the authoritative service transaction."""
        if self.database is None or self.content_store is None:
            raise RuntimeError("retention cleanup requires the control Worker")
        from threat_report_agent.service import AnalysisService

        request = payload or {}
        actor = str(request.get("actor", "retention-worker"))
        service = AnalysisService(self.settings, self.database, self.content_store)
        disposed = service.expire_model_payloads(actor=actor)
        return {"disposed": disposed, "actor": actor}

    @activity.defn(name="seal_daily_audit")
    async def seal_daily_audit(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Seal the requested UTC day using the control-plane database/store."""
        if self.database is None or self.content_store is None:
            raise RuntimeError("daily audit sealing requires the control Worker")
        from threat_report_agent.service import AnalysisService

        request = payload or {}
        raw_day = request.get("utc_day")
        if raw_day:
            utc_day = datetime.fromisoformat(str(raw_day)).date()
        else:
            utc_day = datetime.now(UTC).date() - timedelta(days=1)
        actor = str(request.get("actor", "audit-sealer"))
        service = AnalysisService(self.settings, self.database, self.content_store)
        created = service.run_daily_audit_sealer(utc_day=utc_day, actor=actor)
        return {"utc_day": utc_day.isoformat(), "created": created, "actor": actor}

    @activity.defn(name="prepare_static_tool")
    async def prepare_static_tool(self, request_data: dict[str, Any]) -> dict[str, Any]:
        request = ToolRunRequest.model_validate(request_data)
        started_at = utcnow()
        self._update_tool_run(request, status="RUNNING", started_at=started_at)
        error = self._request_error(request)
        scoped_request = request
        if error is None:
            if self.content_store is None:
                raise RuntimeError("control activity requires a privileged content store")
            content = self.content_store.read(request.storage_key)
            if hashlib.sha256(content).hexdigest() != request.content_sha256:
                error = "CONTENT_HASH_MISMATCH"
            elif hasattr(self.content_store, "issue_tool_run_access"):
                grant = self.content_store.issue_tool_run_access(
                    request.storage_key,
                    request.tool_run_id,
                    expires_in=max(3600, request.max_cpu_seconds * 4),
                )
                scoped_request = request.model_copy(
                    update={"storage_access": ToolRunStorageAccess.from_grant(grant)}
                )
        prepared = ToolRunResult(
            status="READY" if error is None else "FAILED",
            error=error,
            started_at=started_at,
            worker_metadata=self._worker_metadata(request),
        ).model_dump(mode="json")
        prepared["request"] = scoped_request.model_dump(mode="json")
        return prepared

    @activity.defn(name="finalize_static_tool_run")
    async def finalize_static_tool_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        request = ToolRunRequest.model_validate(payload["request"])
        result = ToolRunResult.model_validate(payload["result"])
        result = result.model_copy(
            update={
                "finished_at": result.finished_at or utcnow(),
                "worker_metadata": {
                    **self._worker_metadata(request),
                    **result.worker_metadata,
                },
            }
        )
        self._update_tool_run(
            request,
            status=result.status,
            started_at=result.started_at,
            finished_at=result.finished_at,
            output_sha256=result.output_sha256,
            output_storage_key=result.output_storage_key,
            error=result.error,
            environment=result.worker_metadata,
        )
        return result.model_dump(mode="json")

    @activity.defn(name="validate_static_tool_output")
    async def validate_static_tool_output(self, payload: dict[str, Any]) -> dict[str, Any]:
        request = ToolRunRequest.model_validate(payload["request"])
        result = ToolRunResult.model_validate(payload["result"])
        if result.output_storage_key is None:
            if result.status == "FAILED":
                return result.model_dump(mode="json")
            return self._invalid_output(result, "OUTPUT_REFERENCE_MISSING")
        if self.content_store is None:
            return self._invalid_output(result, "CONTROL_CONTENT_STORE_UNAVAILABLE")
        try:
            if request.storage_access is not None:
                if result.output_storage_key != request.storage_access.output_storage_key:
                    return self._invalid_output(result, "OUTPUT_REFERENCE_OUTSIDE_GRANT")
                if not hasattr(self.content_store, "read_tool_run_output"):
                    return self._invalid_output(result, "STAGED_OUTPUT_READER_UNAVAILABLE")
                output = self.content_store.read_tool_run_output(
                    request.tool_run_id,
                    result.output_storage_key,
                )
            else:
                output = self.content_store.read(result.output_storage_key)
        except (FileNotFoundError, KeyError, ValueError):
            return self._invalid_output(result, "OUTPUT_REFERENCE_UNREADABLE")
        if (
            result.output_sha256 is None
            or hashlib.sha256(output).hexdigest() != result.output_sha256
        ):
            return self._invalid_output(result, "OUTPUT_HASH_MISMATCH")
        try:
            decoded = json.loads(output)
        except (TypeError, ValueError):
            return self._invalid_output(result, "OUTPUT_JSON_INVALID")
        expected_kind = (
            "intake"
            if request.tool_name == "python-zipfile-safe-reader"
            else "ghidra"
            if request.tool_name == "ghidra-headless"
            else "emulation"
            if request.tool_name == "controlled-emulator"
            else "static"
        )
        if not isinstance(decoded, dict) or decoded.get("kind") != expected_kind:
            return self._invalid_output(result, "OUTPUT_KIND_MISMATCH")
        try:
            if request.tool_name == "python-zipfile-safe-reader":
                decoded = self._materialize_intake_entries(decoded)
            canonical = json.dumps(
                decoded,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            stored = self.content_store.put(canonical)
            if request.storage_access is not None and hasattr(
                self.content_store, "delete_tool_run_output"
            ):
                self.content_store.delete_tool_run_output(
                    request.tool_run_id,
                    result.output_storage_key,
                )
        except (KeyError, TypeError, ValueError):
            return self._invalid_output(result, "OUTPUT_MATERIALIZATION_FAILED")
        return result.model_copy(
            update={
                "output_sha256": stored.sha256,
                "output_storage_key": stored.storage_key,
            }
        ).model_dump(mode="json")

    def _materialize_intake_entries(
        self,
        payload: dict[str, object],
    ) -> dict[str, object]:
        entries = payload.get("entries")
        if not isinstance(entries, list):
            raise ValueError("intake output entries are invalid")
        materialized: list[dict[str, object]] = []
        for raw_entry in entries:
            if not isinstance(raw_entry, dict):
                raise ValueError("intake output entry is invalid")
            entry = dict(raw_entry)
            encoded_content = entry.pop("content_base64", None)
            if encoded_content is not None:
                if not isinstance(encoded_content, str) or self.content_store is None:
                    raise ValueError("intake output content is invalid")
                content = base64.b64decode(encoded_content, validate=True)
                expected_sha256 = str(entry.get("content_sha256", ""))
                if hashlib.sha256(content).hexdigest() != expected_sha256 or len(content) != int(
                    entry.get("size", -1)
                ):
                    raise ValueError("intake entry content failed integrity validation")
                stored = self.content_store.put(content)
                entry["content_sha256"] = stored.sha256
                entry["storage_key"] = stored.storage_key
                entry["size"] = stored.size
            if not isinstance(entry.get("storage_key"), str):
                raise ValueError("intake entry has no stable storage reference")
            materialized.append(entry)
        return {**payload, "entries": materialized}

    @staticmethod
    def _invalid_output(result: ToolRunResult, error: str) -> dict[str, Any]:
        return result.model_copy(update={"status": "FAILED", "error": error}).model_dump(
            mode="json"
        )

    def _request_error(self, request: ToolRunRequest) -> str | None:
        if request.sample_execution or request.network_access:
            return "UNSAFE_TOOL_REQUEST"
        if request.tool_name not in STATIC_TOOL_ALLOWLIST:
            return "TOOL_NOT_WHITELISTED"
        if (
            self.settings.tool_allowed_tools
            and request.tool_name not in self.settings.tool_allowed_tools
        ):
            return "TOOL_NOT_ALLOWED_ON_WORKER"
        return None

    @staticmethod
    def _worker_metadata(request: ToolRunRequest) -> dict[str, object]:
        return {
            "executor": "temporal",
            "case_id": request.case_id,
            "trace_id": request.trace_id,
            "tool_run_id": request.tool_run_id,
            "workflow_id": request.workflow_id,
            "task_queue": request.task_queue,
            "environment_version": request.environment_version,
            "input_sha256": request.content_sha256,
        }

    def _update_tool_run(
        self,
        request: ToolRunRequest,
        *,
        status: str,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
        output_sha256: str | None = None,
        output_storage_key: str | None = None,
        error: str | None = None,
        environment: dict[str, object] | None = None,
    ) -> None:
        if self.database is None:
            return
        with self.database.session_factory.begin() as session:
            tool_run = session.get(ToolRun, request.tool_run_id)
            if tool_run is None:
                return
            if tool_run.status in {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED"}:
                return
            task = session.get(AnalysisTask, tool_run.task_id)
            if task is not None and task.lifecycle == "CANCELLED":
                if status != "CANCELLED":
                    return
                output_sha256 = None
                output_storage_key = None
            tool_run.status = status
            if started_at is not None:
                tool_run.started_at = started_at
            if finished_at is not None:
                tool_run.finished_at = finished_at
            tool_run.output_sha256 = output_sha256
            tool_run.output_storage_key = output_storage_key
            tool_run.error = error
            if environment is not None:
                tool_run.environment = environment

    @activity.defn(name="execute_static_tool")
    async def execute_static_tool(self, request_data: dict[str, Any]) -> dict[str, Any]:
        request = ToolRunRequest.model_validate(request_data)
        request_error = self._request_error(request)
        if request_error is not None:
            return ToolRunResult(
                status="FAILED",
                error=request_error,
                worker_metadata={"task_queue": request.task_queue},
            ).model_dump()

        done = asyncio.Event()
        heartbeat = asyncio.create_task(self._heartbeat_until_done(done))
        cancellation_requested = threading.Event()
        execution = asyncio.create_task(
            asyncio.to_thread(self._execute, request, cancellation_requested.is_set)
        )
        try:
            return await asyncio.shield(execution)
        except asyncio.CancelledError:
            cancellation_requested.set()
            completed = ToolRunResult.model_validate(await asyncio.shield(execution))
            cancelled = completed.model_copy(
                update={
                    "status": "CANCELLED",
                    "error": completed.error or "TOOL_ACTIVITY_CANCELLED",
                    "finished_at": completed.finished_at or utcnow(),
                }
            )
            self._update_tool_run(
                request,
                status=cancelled.status,
                started_at=cancelled.started_at,
                finished_at=cancelled.finished_at,
                output_sha256=cancelled.output_sha256,
                output_storage_key=cancelled.output_storage_key,
                error=cancelled.error,
                environment={
                    **self._worker_metadata(request),
                    **cancelled.worker_metadata,
                },
            )
            raise
        finally:
            done.set()
            # The heartbeat loop is auxiliary work.  Cancel it explicitly so
            # activity cancellation never waits for its polling interval.
            heartbeat.cancel()
            try:
                await heartbeat
            except asyncio.CancelledError:
                pass

    @staticmethod
    async def _heartbeat_until_done(done: asyncio.Event) -> None:
        while not done.is_set():
            activity.heartbeat({"phase": "running"})
            try:
                await asyncio.wait_for(done.wait(), timeout=10)
            except TimeoutError:
                pass

    def _execute(
        self,
        request: ToolRunRequest,
        cancellation_requested: Callable[[], bool] | None = None,
    ) -> dict[str, object]:
        content_store = self._execution_content_store(request)
        content = content_store.read(request.storage_key)
        if hashlib.sha256(content).hexdigest() != request.content_sha256:
            return ToolRunResult(status="FAILED", error="CONTENT_HASH_MISMATCH").model_dump()
        if request.tool_name == "python-zipfile-safe-reader":
            return self._execute_intake(request, content, content_store)
        analysis_metadata: dict[str, object] = {}
        if request.tool_name == "ghidra-headless":
            runner = GhidraHeadlessRunner(self.settings.ghidra_home, self.settings.java_home)
            processor: str | None = None
            try:
                identity = analyze_bytes(content, request.logical_path)
                if (
                    str(identity.summary.get("pe", {}).get("machine", "")).lower() == "0x0000"
                    and str(identity.summary.get("pe", {}).get("format", "")) == "PE32"
                ):
                    processor = "x86:LE:32:default"
            except (AttributeError, TypeError, ValueError, KeyError):
                pass
            analyze_kwargs: dict[str, object] = {
                "cancellation_requested": cancellation_requested,
            }
            if processor:
                analyze_kwargs["processor"] = processor
            run = runner.analyze(
                content,
                request.logical_path,
                request.max_cpu_seconds,
                **analyze_kwargs,
            )
            analysis_metadata = (
                {
                    "processor_override": processor,
                    "input_transform": "PE_MACHINE_ZERO_NORMALIZED_TO_I386",
                }
                if processor
                else {}
            )
            if run.status == "CANCELLED":
                return ToolRunResult(
                    status=run.status,
                    error=run.error,
                    worker_metadata={**self._worker_metadata(request), **analysis_metadata},
                ).model_dump(mode="json")
            payload: dict[str, object] = {
                "kind": "ghidra",
                "status": run.status,
                "output": run.output,
                "error": run.error,
            }
            status = run.status
            error = run.error
        elif request.tool_name == "controlled-emulator":
            payload, status, error = self._execute_controlled_emulator(
                request, content, cancellation_requested
            )
            if status == "CANCELLED":
                return ToolRunResult(
                    status=status,
                    error=error,
                    worker_metadata=self._worker_metadata(request),
                ).model_dump(mode="json")
        else:
            result = analyze_bytes(content, request.logical_path)
            payload = self._static_result_payload(result)
            status = "SUCCEEDED"
            error = None
        return self._store_result(
            request, payload, status, error, content_store, worker_metadata=analysis_metadata
        )

    def _execute_controlled_emulator(
        self,
        request: ToolRunRequest,
        content: bytes,
        cancellation_requested: Callable[[], bool] | None = None,
    ) -> tuple[dict[str, object], str, str | None]:
        """Emulate granted content-store bytes inside this worker process.

        The original sample path is never opened. Explicit ``granted_windows``
        treat the stored object as the bounded snippet; otherwise windows are
        sliced from the PE using planner parameters.
        """
        if cancellation_requested is not None and cancellation_requested():
            return (
                {
                    "kind": "emulation",
                    "status": "CANCELLED",
                    "results": [],
                    "error": "TOOL_ACTIVITY_CANCELLED",
                },
                "CANCELLED",
                "TOOL_ACTIVITY_CANCELLED",
            )
        policy = simulation_policy_from_settings(self.settings)
        runner = IsolatedSimulationRunner(
            default_simulation_runner(policy, execute_in_process=True).adapters,
            policy=policy,
            execute_in_process=True,
        )
        windows: list[dict[str, object]] = []
        explicit = request.parameters.get("granted_windows")

        # The full-PE plan is built for BOTH branches, not only for the empty-grant one.
        #
        # MEASURED why (plan T1a): when `granted_windows` is non-empty the worker used to skip
        # `controlled_emulation_windows` entirely, so the Speakeasy window the API had ALREADY planned was
        # never built - and Speakeasy is the only adapter here with Windows API semantics. Measured on the real
        # Resume run: 20 Unicorn runs, 9 of them "SUCCEEDED", every single one with ZERO api observations,
        # while Speakeasy was never dispatched once. 白象 escaped only because its bootstrap-trampoline entry
        # makes the Unicorn window unserializable (`input_bytes=b""`), leaving the grant list empty.
        #
        # `content` is the stored artifact in BOTH branches (it comes from
        # `content_store.read(request.storage_key)` above), so the plan costs nothing extra to build and
        # nothing has to be inlined into the request - which matters because Temporal rejects payloads over
        # 2 MiB (measured) while a 4 MiB sample inlined as hex is ~8 MiB.
        pe_summary: dict[str, object] = {}
        try:
            identity = analyze_bytes(content, request.logical_path)
            pe_raw = identity.summary.get("pe")
            if isinstance(pe_raw, dict):
                pe_summary = pe_raw
        except (AttributeError, TypeError, ValueError, KeyError):
            pe_summary = {}
        functions = request.parameters.get("functions")
        traces = request.parameters.get("traces")
        allow_speakeasy = bool(request.parameters.get("allow_speakeasy", False)) and (
            "speakeasy" in policy.allowed_simulators
        )
        allow_qiling = "qiling" in {str(item).casefold() for item in policy.allowed_simulators}
        planned_windows = [
            dict(item)
            for item in controlled_emulation_windows(
                content,
                pe_summary,
                functions if isinstance(functions, list) else (),
                traces if isinstance(traces, list) else (),
                allow_speakeasy=allow_speakeasy,
                allow_qiling=allow_qiling,
                max_windows=8,
                snippet_length=min(512, policy.max_input_bytes),
                max_pe_bytes=policy.max_input_bytes,
            )
        ]

        # T1's incremental Speakeasy window, kept OUT of the execution budget below.
        #
        # R5 requires T1 to be incremental dispatch ("只做增量派发，不改既有窗口"). MEASURED violation this
        # removes: the window is PREPENDED to `windows`, and the budget then sliced `windows[:4]`, so on every
        # grant-carrying run the Speakeasy window consumed one of the four slots and grants executed 3 instead
        # of 4. The literal 4 was unchanged, which is exactly why it was easy to miss - the REACH changed, not
        # the number. The caller's grants are not T1's to spend.
        incremental_windows: list[dict[str, object]] = []
        if isinstance(explicit, list) and explicit:
            # ALL grants, not `explicit[:4]`. MEASURED defect this removes (T1a audit finding F4c, found by the
            # test written for the truncation report): slicing here dropped grants 5+ BEFORE they entered
            # `windows`, so the truncation report below could not see them and they vanished without trace.
            # The execution budget below still caps what RUNS; the difference is that what does not run is now
            # recorded.
            for item in explicit:
                if not isinstance(item, dict):
                    continue
                hex_text = str(item.get("input_hex") or "").replace(" ", "")
                granted = content
                if hex_text:
                    try:
                        granted = bytes.fromhex(hex_text)
                    except ValueError:
                        continue
                entry = item.get("entry_address", item.get("function_entry", 0x1000000))
                entry_address = _as_int_address(entry)
                if entry_address is None:
                    entry_address = 0x1000000
                windows.append(
                    {
                        "simulator": str(item.get("simulator") or "unicorn"),
                        "input_bytes": granted,
                        "entry_address": entry_address,
                        "architecture": str(item.get("architecture") or "x86_64"),
                        "anchor": {
                            "type": "unique_thread_emulation",
                            "simulator": str(item.get("simulator") or "unicorn"),
                            "role": str(item.get("role") or "granted_window"),
                            "function_entry": str(item.get("function_entry") or ""),
                        },
                    }
                )
            # The full-PE window - and ONLY that one - goes FIRST so the execution budget below cannot drop
            # it. A Unicorn snippet the budget then excludes is recorded, not silently lost (see the
            # truncation report after this block).
            #
            # Deliberately narrow: an earlier version appended every non-Unicorn planned window, which also
            # injected the planner's QILING decision row into grant-carrying runs and changed that row's
            # meaning for them (measured: `test_worker_records_qiling_unsupported_without_rootfs` failed with
            # `UNSUPPORTED` becoming `NOT_APPLICABLE`). T1a's purpose is to make the full-PE emulator
            # reachable, not to reshape the plan's other decisions, so the filter names what it wants.
            incremental_windows = [
                window
                for window in planned_windows
                if str(window.get("simulator") or "").casefold() == "speakeasy"
            ]
            windows = incremental_windows + windows
        else:
            windows.extend(planned_windows)
        results: list[dict[str, object]] = []
        overall = "SUCCEEDED" if windows else "FAILED"
        error: str | None = None if windows else "NO_GRANTED_WINDOW"
        if "unicorn" in policy.allowed_simulators and not any(
            str(item.get("simulator") or "").casefold() == "unicorn" for item in windows
        ):
            results.append(
                {
                    "status": "FAILED",
                    "simulator": "unicorn",
                    "stop_reason": "NO_GRANTED_WINDOW",
                    "limitations": [
                        "no bounded start-routine or PE-entry window was recovered"
                    ],
                    "anchor": {
                        "type": "unique_thread_emulation",
                        "simulator": "unicorn",
                        "role": "pe_entry",
                    },
                }
            )
            overall = "FAILED"
            error = "NO_GRANTED_WINDOW"
        # The per-run execution budget. Named so the truncation report below and the slice that enforces it
        # share ONE source - a statement derived from the same value as the behaviour cannot drift from it
        # (G2/G3). The VALUE is unchanged: this is the literal that was already there.
        execution_budget = 4

        # The budget governs the PRE-EXISTING windows only. T1's incremental windows sit ahead of them in
        # `windows` and are NOT charged against it, so a grant-carrying run executes the same four grants it
        # did before T1 plus the full-PE window, instead of three grants and the full-PE window.
        incremental_count = len(incremental_windows)
        budgeted_windows = windows[incremental_count:]

        # Windows the budget excludes are recorded AFTER the ones that ran.
        #
        # Order matters to consumers: several read `results[0]` as "the first simulator outcome", so putting a
        # never-executed placeholder first would misreport which simulator ran first. Collected here and
        # appended once the execution loop below has finished.
        excluded_windows = budgeted_windows[execution_budget:]

        for window in windows[:incremental_count] + budgeted_windows[:execution_budget]:
            if str(window.get("skip_reason") or "").strip():
                # The plan already decided this window cannot succeed (for example a Linux-only adapter
                # against a Windows PE). Record the decision as evidence and do NOT spend a worker turn -
                # measured before this guard: 418 `os_mismatch` rows, none with an observation.
                results.append(
                    {
                        "status": "NOT_APPLICABLE",
                        "simulator": str(window.get("simulator") or ""),
                        "stop_reason": str(window.get("skip_reason")),
                        "limitations": [
                            str((window.get("anchor") or {}).get("reason") or "")
                            or "the granted bytes are outside this adapter's applicability"
                        ],
                        "anchor": dict(window.get("anchor") or {}),
                    }
                )
                continue
            if cancellation_requested is not None and cancellation_requested():
                return (
                    {
                        "kind": "emulation",
                        "status": "CANCELLED",
                        "results": results,
                        "error": "TOOL_ACTIVITY_CANCELLED",
                    },
                    "CANCELLED",
                    "TOOL_ACTIVITY_CANCELLED",
                )
            result = runner.run(
                request_for_granted_window(policy, window),
                cancellation_requested=cancellation_requested,
            )
            payload = result.as_dict()
            payload["anchor"] = dict(window.get("anchor") or {})
            if result.status == "SUCCEEDED" and result.output_bytes:
                payload["output_hex"] = result.output_bytes.hex()
            results.append(payload)
            if result.status == "CANCELLED":
                return (
                    {
                        "kind": "emulation",
                        "status": "CANCELLED",
                        "results": results,
                        "error": result.stop_reason or "TOOL_ACTIVITY_CANCELLED",
                    },
                    "CANCELLED",
                    result.stop_reason or "TOOL_ACTIVITY_CANCELLED",
                )
            if result.status not in {"SUCCEEDED", "UNSUPPORTED", "UNAVAILABLE", "PARTIAL"}:
                overall = result.status
                error = result.stop_reason
        have_qiling = any(
            str(item.get("simulator") or "").casefold() == "qiling" for item in results
        )
        if not have_qiling and "qiling" in {str(item).casefold() for item in policy.allowed_simulators}:
            if cancellation_requested is not None and cancellation_requested():
                return (
                    {
                        "kind": "emulation",
                        "status": "CANCELLED",
                        "results": results,
                        "error": "TOOL_ACTIVITY_CANCELLED",
                    },
                    "CANCELLED",
                    "TOOL_ACTIVITY_CANCELLED",
                )
            results.append(
                default_simulation_runner(policy, execute_in_process=True)
                .run(
                    request_for_granted_window(
                        policy,
                        {
                            "simulator": "qiling",
                            "input_bytes": content,
                            "entry_address": 0x400000,
                            "architecture": "x86_64",
                            "anchor": {"type": "qiling_linux_usermode", "simulator": "qiling"},
                        },
                    ),
                    cancellation_requested=cancellation_requested,
                )
                .as_dict()
            )
            results[-1]["anchor"] = {
                "type": "qiling_linux_usermode",
                "simulator": "qiling",
                "role": "linux_elf" if content.startswith(b"\x7fELF") else "os_mismatch",
            }
        # Record what the budget excluded instead of dropping it in silence.
        #
        # The same rule the report side applies to a capped list: a truncated set must say it is truncated.
        # It matters here because the full-PE window is placed ahead of the granted snippets, so with a full
        # grant list the last snippet is the one that loses its slot - and a reader shown only four results
        # could not tell that a fifth window existed at all.
        for window in excluded_windows:
            results.append(
                {
                    "status": "NOT_EXECUTED",
                    "simulator": str(window.get("simulator") or ""),
                    "stop_reason": "WINDOW_BUDGET_EXHAUSTED",
                    "limitations": [
                        f"the worker runs at most {execution_budget} planned/granted windows per run "
                        "(the incremental full-PE window is not charged against that budget); this window "
                        "was planned but not executed"
                    ],
                    "anchor": dict(window.get("anchor") or {}),
                }
            )
        qiling_row = qiling_unavailable_observation(policy)
        if qiling_row is not None and not any(
            str(item.get("simulator") or "").casefold() == "qiling" for item in results
        ):
            results.append(qiling_row)
        overall, error = emulation_overall_from_results(
            results,
            current_overall=overall,
            current_error=error,
        )
        return (
            {
                "kind": "emulation",
                "status": overall,
                "results": results,
                "error": error,
            },
            overall if overall in {"SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT"} else "FAILED",
            error,
        )

    def _execution_content_store(self, request: ToolRunRequest) -> ContentStore:
        if request.storage_access is not None:
            return ScopedToolRunContentStore(
                ToolRunStorageGrant(
                    input_storage_key=request.storage_access.input_storage_key,
                    input_url=request.storage_access.input_url,
                    output_storage_key=request.storage_access.output_storage_key,
                    output_url=request.storage_access.output_url,
                )
            )
        if self.content_store is None:
            raise RuntimeError("tool execution requires scoped object access")
        return self.content_store

    def _execute_intake(
        self,
        request: ToolRunRequest,
        content: bytes,
        content_store: ContentStore,
    ) -> dict[str, object]:
        secret_id = request.parameters.get("archive_secret_id")
        archive_password = self._read_archive_password(request, secret_id)
        try:
            entries = expand_submission(
                request.logical_path,
                content,
                max_files=int(request.parameters.get("max_files", self.settings.max_sample_files)),
                max_bytes=int(request.parameters.get("max_bytes", self.settings.max_sample_bytes)),
                max_depth=int(request.parameters.get("max_depth", self.settings.max_archive_depth)),
                archive_password=archive_password,
            )
        except IntakeGateRequired as exc:
            payload: dict[str, object] = {
                "kind": "intake",
                "status": "GATE_REQUIRED",
                "reason": exc.reason,
                "context": exc.context,
                "entries": [],
            }
            return self._store_result(
                request,
                payload,
                "FAILED",
                exc.reason,
                content_store,
            )
        if isinstance(secret_id, str):
            self._mark_secret_consumed(secret_id)

        manifest: list[dict[str, object]] = []
        root_path = entries[0].logical_path
        requested_path = request.parameters.get("root_logical_path")
        if not isinstance(requested_path, str) or not requested_path:
            requested_path = root_path
        for entry in entries:
            identity = identify_format(entry.content, entry.logical_path)
            logical_path = requested_path + entry.logical_path[len(root_path) :]
            parent_path = entry.parent_path
            if parent_path is not None:
                parent_path = requested_path + parent_path[len(root_path) :]
            manifest_entry: dict[str, object] = {
                "logical_path": logical_path,
                "parent_path": parent_path,
                "discovery": entry.discovery,
                "is_container": entry.is_container,
                "content_sha256": hashlib.sha256(entry.content).hexdigest(),
                "size": entry.size,
                "detected_type": identity.detected_type,
                "mime_type": identity.mime_type,
                "type_source": identity.source,
            }
            if request.storage_access is None:
                stored_entry = content_store.put(entry.content)
                manifest_entry["content_sha256"] = stored_entry.sha256
                manifest_entry["storage_key"] = stored_entry.storage_key
                manifest_entry["size"] = stored_entry.size
            else:
                manifest_entry["content_base64"] = base64.b64encode(entry.content).decode("ascii")
            manifest.append(manifest_entry)
        payload = {
            "kind": "intake",
            "status": "SUCCEEDED",
            "entries": manifest,
        }
        return self._store_result(
            request,
            payload,
            "SUCCEEDED",
            None,
            content_store,
        )

    def _read_archive_password(
        self,
        request: ToolRunRequest,
        secret_id: object,
    ) -> str | None:
        if not isinstance(secret_id, str):
            return None
        if self.database is None:
            raise ValueError("Archive secret requires the Worker database")
        with self.database.session_factory() as session:
            secret = session.get(TaskSecret, secret_id)
            if (
                secret is None
                or secret.task_id != request.task_id
                or secret.secret_type != "ARCHIVE_PASSWORD"
            ):
                raise ValueError("Archive secret reference is invalid")
            return SecretCipher(self.settings.gate_secret_key).decrypt(secret.ciphertext)

    def _mark_secret_consumed(self, secret_id: str) -> None:
        if self.database is None:
            return
        with self.database.session_factory.begin() as session:
            secret = session.get(TaskSecret, secret_id)
            if secret is not None:
                secret.consumed_at = utcnow()

    def _store_result(
        self,
        request: ToolRunRequest,
        payload: dict[str, object],
        status: str,
        error: str | None,
        content_store: ContentStore,
        worker_metadata: dict[str, object] | None = None,
    ) -> dict[str, object]:
        stored = content_store.put(
            json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        )
        return ToolRunResult(
            status=status,
            output_sha256=stored.sha256,
            output_storage_key=stored.storage_key,
            error=error,
            worker_metadata={
                "executor": "temporal",
                "case_id": request.case_id,
                "trace_id": request.trace_id,
                "tool_run_id": request.tool_run_id,
                "workflow_id": request.workflow_id,
                "task_queue": request.task_queue,
                "environment_version": request.environment_version,
                "input_sha256": request.content_sha256,
                "output_size": stored.size,
                **(worker_metadata or {}),
            },
        ).model_dump(mode="json")

    @staticmethod
    def _static_result_payload(result: StaticResult) -> dict[str, object]:
        return {
            "kind": "static",
            "detected_type": result.detected_type,
            "summary": result.summary,
            "facts": [asdict(item) for item in result.facts],
            "limitations": list(result.limitations),
        }


def static_result_from_payload(payload: dict[str, object]) -> StaticResult:
    if payload.get("kind") != "static":
        raise ValueError("Temporal output is not a static analysis result")
    facts = tuple(StaticFact(**item) for item in payload.get("facts", []) if isinstance(item, dict))
    return StaticResult(
        detected_type=str(payload["detected_type"]),
        summary=dict(payload["summary"]),
        facts=facts,
        limitations=tuple(str(item) for item in payload.get("limitations", [])),
    )


def intake_entries_from_payload(payload: dict[str, object]) -> list[PackageEntry]:
    if payload.get("kind") != "intake":
        raise ValueError("Temporal output is not an intake result")
    if payload.get("status") == "GATE_REQUIRED":
        context = payload.get("context")
        raise IntakeGateRequired(
            str(payload.get("reason", "Input requires review")),
            dict(context) if isinstance(context, dict) else {},
        )
    if payload.get("status") != "SUCCEEDED":
        raise ValueError("Temporal intake did not succeed")
    entries: list[PackageEntry] = []
    for item in payload.get("entries", []):
        if not isinstance(item, dict):
            continue
        entries.append(
            PackageEntry(
                logical_path=str(item["logical_path"]),
                content=b"",
                parent_path=(
                    str(item["parent_path"]) if item.get("parent_path") is not None else None
                ),
                discovery=str(item["discovery"]),
                is_container=bool(item.get("is_container")),
                content_sha256=str(item["content_sha256"]),
                storage_key=str(item["storage_key"]),
                stored_size=int(item["size"]),
                detected_type=str(item["detected_type"]),
                mime_type=str(item["mime_type"]),
                type_source=str(item["type_source"]),
            )
        )
    if not entries:
        raise ValueError("Temporal intake returned no entries")
    return entries


def client_result_timeout_seconds(max_cpu_seconds: int) -> float:
    """Wait for the workflow at least as long as the tool CPU budget.

    A flat 90s client wait cancelled Ghidra on Resume (policy 900s) after the
    activity had already started. Keep a 90s floor so a worker that never
    starts still fails fast via schedule_to_start plus this bound.
    """
    return float(max(90, int(max_cpu_seconds) + 45))


class TemporalToolExecutor:
    """Client adapter for durable ToolRun workflows and cancellation propagation."""

    def __init__(self, temporal_address: str) -> None:
        self.temporal_address = temporal_address

    async def execute(self, request: ToolRunRequest) -> ToolRunResult:
        client = await Client.connect(self.temporal_address)
        try:
            handle = await client.start_workflow(
                StaticToolRunWorkflow.run,
                request.model_dump(mode="json"),
                id=request.workflow_id,
                task_queue=request.control_task_queue,
            )
        except WorkflowAlreadyStartedError:
            handle = client.get_workflow_handle(request.workflow_id)
        try:
            raw = await asyncio.wait_for(
                handle.result(),
                timeout=client_result_timeout_seconds(request.max_cpu_seconds),
            )
        except TimeoutError:
            try:
                await handle.cancel()
            except Exception:
                pass
            return ToolRunResult(
                status="FAILED",
                error="TEMPORAL_WORKFLOW_TIMEOUT",
                worker_metadata={
                    "workflow_id": request.workflow_id,
                    "task_queue": request.task_queue,
                    "control_task_queue": request.control_task_queue,
                },
            )
        return ToolRunResult.model_validate(raw)

    async def cancel(self, request: ToolRunRequest) -> None:
        await self.cancel_workflow(request.workflow_id)

    async def cancel_workflow(self, workflow_id: str) -> None:
        client = await Client.connect(self.temporal_address)
        handle = client.get_workflow_handle(workflow_id)
        await handle.cancel()
        try:
            await handle.result()
        except TemporalCancelledError:
            pass


async def run_static_worker(settings: Settings, *, role: str = "tool") -> None:
    database = Database(settings.database_url)
    database.create_schema()
    client = await Client.connect(settings.temporal_address)
    if role == "control":
        content_store: ContentStore
        if settings.content_store_backend == "s3":
            content_store = S3ContentStore(
                settings.object_store_endpoint,
                settings.object_store_bucket,
                settings.object_store_access_key,
                settings.object_store_secret_key,
                audit_bucket=settings.audit_seal_bucket or None,
                audit_object_lock_mode=settings.audit_object_lock_mode,
                audit_object_lock_days=settings.audit_object_lock_days,
            )
        else:
            content_store = LocalContentStore(settings.content_store_path)
        activities = StaticToolActivities(settings, content_store, database)
        await ensure_model_payload_cleanup_schedule(
            client,
            task_queue=settings.control_task_queue,
            schedule_id="threat-report-agent-model-payload-cleanup",
        )
        await ensure_daily_audit_seal_schedule(
            client,
            task_queue=settings.control_task_queue,
            schedule_id="threat-report-agent-daily-audit-seal",
        )
        worker = Worker(
            client,
            task_queue=settings.control_task_queue,
            workflows=[StaticToolRunWorkflow, ModelPayloadCleanupWorkflow, DailyAuditSealWorkflow],
            activities=[
                activities.register_static_tool_run,
                activities.prepare_static_tool,
                activities.validate_static_tool_output,
                activities.finalize_static_tool_run,
                activities.expire_model_payloads,
                activities.seal_daily_audit,
            ],
        )
    elif role == "tool":
        activities = StaticToolActivities(settings, None, database)
        worker = Worker(
            client,
            task_queue=settings.tool_task_queue,
            workflows=[],
            activities=[activities.execute_static_tool],
        )
    else:
        raise ValueError(f"Unknown Worker role: {role}")
    await worker.run()


async def ensure_model_payload_cleanup_schedule(
    client: Client,
    *,
    task_queue: str = "static-control",
    schedule_id: str = "threat-report-agent-model-payload-cleanup",
) -> bool:
    """Create the daily retention schedule once; return whether it was created."""
    action = ScheduleActionStartWorkflow(
        ModelPayloadCleanupWorkflow.run,
        {"control_task_queue": task_queue, "actor": "retention-worker"},
        id=f"{schedule_id}-workflow",
        task_queue=task_queue,
        execution_timeout=timedelta(minutes=15),
        static_summary="Expire encrypted model payloads after configured retention period",
    )
    schedule = Schedule(
        action=action,
        spec=ScheduleSpec(
            calendars=[
                ScheduleCalendarSpec(
                    hour=[ScheduleRange(start=3, end=3)],
                    minute=[ScheduleRange(start=17, end=17)],
                )
            ],
            time_zone_name="UTC",
        ),
        policy=SchedulePolicy(
            overlap=ScheduleOverlapPolicy.SKIP,
            catchup_window=timedelta(hours=2),
            pause_on_failure=False,
        ),
    )
    try:
        await client.create_schedule(schedule_id, schedule)
        return True
    except ScheduleAlreadyRunningError:
        return False


async def ensure_daily_audit_seal_schedule(
    client: Client,
    *,
    task_queue: str = "static-control",
    schedule_id: str = "threat-report-agent-daily-audit-seal",
) -> bool:
    """Create the UTC daily audit-seal schedule once."""
    action = ScheduleActionStartWorkflow(
        DailyAuditSealWorkflow.run,
        {"control_task_queue": task_queue, "actor": "audit-sealer"},
        id=f"{schedule_id}-workflow",
        task_queue=task_queue,
        execution_timeout=timedelta(minutes=15),
        static_summary="Seal each UTC day's audit event stream",
    )
    schedule = Schedule(
        action=action,
        spec=ScheduleSpec(
            calendars=[
                ScheduleCalendarSpec(
                    hour=[ScheduleRange(start=3, end=3)],
                    minute=[ScheduleRange(start=23, end=23)],
                )
            ],
            time_zone_name="UTC",
        ),
        policy=SchedulePolicy(
            overlap=ScheduleOverlapPolicy.SKIP,
            catchup_window=timedelta(hours=2),
            pause_on_failure=False,
        ),
    )
    try:
        await client.create_schedule(schedule_id, schedule)
        return True
    except ScheduleAlreadyRunningError:
        return False
