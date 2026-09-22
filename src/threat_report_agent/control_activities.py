"""Control-plane Temporal activities, workflows, schedules and the worker composition root.

EXTRACTED FROM `tool_execution.py` BY PLAN STEP P2-T.0 - the tool layer must not reach the service layer.

MEASURED (`.scratch/p2t0-inventory.py`): `StaticToolActivities.expire_model_payloads` and `.seal_daily_audit` each
imported `AnalysisService` INSIDE the function body. That function-level import is the reverse leg of the
allowlisted `service <-> tool_execution` cycle, and plan 7.5 requires the cycle to be unwound before the tool layer
moves into `tools/` rather than carried into it.

WHY A SEPARATION AND NOT A PORT: the composition root that could inject a port (`run_static_worker`) lived in the
same module, so injecting `AnalysisService` from there would still leave `tools -> service`. These activities,
their workflows and their schedules are CONTROL PLANE - retention cleanup and audit sealing, not tool execution -
so they belong beside the service they drive.

WHAT DID NOT CHANGE: the activity NAMES (`expire_model_payloads`, `seal_daily_audit`), the task queue each role
registers, the schedules (03:17 and 03:23 UTC, SKIP overlap, 2h catchup) and the two function-level service
imports, which were moved verbatim. `tests/test_control_plane_contract.py` pins the name sets per role.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

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
from temporalio.common import RetryPolicy
from temporalio.worker import Worker

with workflow.unsafe.imports_passed_through():
    from threat_report_agent.config import Settings
    from threat_report_agent.content_store import ContentStore, LocalContentStore, S3ContentStore
    from threat_report_agent.database import Database
    from threat_report_agent.tool_execution import StaticToolActivities, StaticToolRunWorkflow


class RetentionActivities:
    """Retention and audit-seal activities. Control plane: this class never executes the submitted sample."""

    def __init__(
        self,
        settings: Settings,
        content_store: ContentStore | None,
        database: Database | None = None,
    ) -> None:
        self.settings = settings
        self.content_store = content_store
        self.database = database

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
        retention = RetentionActivities(settings, content_store, database)
        worker = Worker(
            client,
            task_queue=settings.control_task_queue,
            workflows=[StaticToolRunWorkflow, ModelPayloadCleanupWorkflow, DailyAuditSealWorkflow],
            activities=[
                activities.register_static_tool_run,
                activities.prepare_static_tool,
                activities.validate_static_tool_output,
                activities.finalize_static_tool_run,
                retention.expire_model_payloads,
                retention.seal_daily_audit,
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
