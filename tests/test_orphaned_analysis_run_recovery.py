"""A restarted API process must not leave a run stuck in RUNNING forever.

Regression this pins.  Static analysis is executed by FastAPI ``BackgroundTasks``
inside the API process (``start_workbench_analysis`` adds
``execute_submission_task`` to ``background_tasks``), so there is no durable queue
and no second owner of an in-flight run.  When the container restarts - which
happens on every image rebuild - the run stops existing while its database row
stays ``RUNNING``.  Nothing fails it, nothing retries it.

Measured on the live deployment before the fix, five tasks were stranded:

    id       lifecycle  evidence  claims  revisions  newest evidence
    0a690901 RUNNING    38434     46      0          2 h 15 min stale
    50702565 RUNNING    12589     42      0          15 h stale
    8a353bd9 RUNNING    4256      6       0          15 h stale
    a77a9a14 RUNNING    15708     39      0          20 h stale
    b309d8f5 RUNNING    6296      5       0          12 h stale

while the API container sat at 4.7% CPU with no workers active - i.e. no run was
executing at all.  A user who submitted a sample saw a session that never
completed, which breaks the "any sample runs to completion" requirement.

`FINALIZING` is reconciled too: it is entered before the snapshot is frozen and
the report revision is written, so a restart there also yields no report.
"""

from __future__ import annotations

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.models import AnalysisTask
from threat_report_agent.service import AnalysisRunOrphaned
from threat_report_agent.status import AnalysisOutcome, TaskLifecycle, transition_task


def _service(test_settings):  # noqa: ANN001, ANN202
    from threat_report_agent.database import Database
    from threat_report_agent.service import AnalysisService

    database = Database(test_settings.database_url)
    database.create_schema()
    store = LocalContentStore(test_settings.content_store_path)
    return database, AnalysisService(test_settings, database, store)


def _stranded_task(database, case_id: str, submission_key: str, lifecycle: str):  # noqa: ANN001, ANN202
    """Create a Case + AnalysisTask in the given lifecycle, as the real path does."""
    from threat_report_agent.models import CaseRecord

    with database.session_factory.begin() as session:
        session.add(CaseRecord(id=case_id, title=case_id))
        session.flush()
        task = AnalysisTask(
            case_id=case_id,
            trace_id=f"trace-{submission_key}",
            submission_key=submission_key,
            lifecycle=lifecycle,
            outcome=None,
            target_breadth="B1",
            target_depth="D2",
            request_snapshot={},
            strategy_snapshot={},
            selected_modules=[],
            actual_granularity=None,
            limitations=[],
        )
        session.add(task)
        session.flush()
        return task.id


def test_orphan_exception_is_classified_retryable() -> None:
    """An interrupted run must be eligible for the retry machinery.

    `classify_failure` matches the exception's ``code`` explicitly.  The first
    attempt relied on ``"worker" in type(exc).__name__.casefold()``, which is
    False for ``AnalysisRunOrphaned``, so the failure became the NON-retryable
    ``STATIC_WORKFLOW_ACTIVITY_FAILED`` and the sample would never have been
    analysed again - the exact opposite of the intent.
    """
    from threat_report_agent.runtime_contracts import classify_failure

    contract = classify_failure(
        AnalysisRunOrphaned("restart"), stage="PROCESS_RESTART"
    )
    assert contract["failure_code"] == "WORKER_FAILURE"
    assert contract["retryable"] is True
    assert contract["analysis_class"] == "FAILED_ANALYSIS"


def test_running_can_transition_to_failed() -> None:
    assert (
        transition_task(TaskLifecycle.RUNNING, TaskLifecycle.FAILED)
        is TaskLifecycle.FAILED
    )


def test_finalizing_can_transition_to_failed() -> None:
    """Ran during report synthesis counts as orphaned too."""
    assert (
        transition_task(TaskLifecycle.FINALIZING, TaskLifecycle.FAILED)
        is TaskLifecycle.FAILED
    )


def test_reconcile_marks_stranded_runs_failed(test_settings) -> None:  # noqa: ANN001
    """The real method must fail a stranded row and record a failure contract."""
    from sqlalchemy import select

    from threat_report_agent.models import AnalysisFailureRecord

    database, service = _service(test_settings)
    task_id = _stranded_task(
        database, "case-orphan", "submission-orphan", TaskLifecycle.RUNNING.value
    )

    reconciled = service.reconcile_orphaned_analysis_runs()
    assert task_id in reconciled, "the stranded RUNNING task must be reconciled"

    with database.session_factory.begin() as session:
        task = session.get(AnalysisTask, task_id)
        assert task is not None
        assert task.lifecycle == TaskLifecycle.FAILED.value
        assert task.analysis_class == "FAILED_ANALYSIS"
        assert task.outcome is None
        assert task.finished_at is not None
        failure = session.scalar(
            select(AnalysisFailureRecord).where(
                AnalysisFailureRecord.task_id == task_id
            )
        )
        assert failure is not None, "a failure contract must be recorded for the UI"
        assert failure.failure_code == "WORKER_FAILURE"
        assert failure.retryable is True
        assert failure.failure_stage == "PROCESS_RESTART"


def test_reconcile_is_idempotent(test_settings) -> None:  # noqa: ANN001
    """A second startup must not re-fail an already-failed run."""
    database, service = _service(test_settings)
    task_id = _stranded_task(
        database, "case-orphan-2", "submission-orphan-2", TaskLifecycle.RUNNING.value
    )

    first = service.reconcile_orphaned_analysis_runs()
    second = service.reconcile_orphaned_analysis_runs()
    assert task_id in first
    assert task_id not in second, "reconciliation must not repeat for a FAILED row"


def test_reconcile_covers_finalizing_runs(test_settings) -> None:  # noqa: ANN001
    """A restart during report synthesis also strands a run with no report.

    `FINALIZING` is set before the snapshot is frozen and the report revision is
    written, so a crash there leaves a task that can never publish.  Reconciling
    only `RUNNING` would miss exactly the runs closest to completion.
    """
    database, service = _service(test_settings)
    task_id = _stranded_task(
        database, "case-final", "submission-final", TaskLifecycle.FINALIZING.value
    )

    reconciled = service.reconcile_orphaned_analysis_runs()
    assert task_id in reconciled
    with database.session_factory.begin() as session:
        task = session.get(AnalysisTask, task_id)
        assert task.lifecycle == TaskLifecycle.FAILED.value


def test_reconcile_leaves_succeeded_tasks_alone(test_settings) -> None:  # noqa: ANN001
    database, service = _service(test_settings)
    task_id = _stranded_task(
        database, "case-done", "submission-done", TaskLifecycle.SUCCEEDED.value
    )

    reconciled = service.reconcile_orphaned_analysis_runs()
    assert task_id not in reconciled
    with database.session_factory.begin() as session:
        task = session.get(AnalysisTask, task_id)
        assert task.lifecycle == TaskLifecycle.SUCCEEDED.value
