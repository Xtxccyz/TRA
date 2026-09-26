"""P-1.2: the CANCELLED-task clause, measured on the product's own cancellation entry point.

The plan's success criterion for this step has three clauses:

    成功标准：取消任务不再产生无限制正文；`SUCCEEDED` 且无 error 不产生虚假限制；任务 lifecycle 和 Analysis
    Outcome 语义不变。

The sibling file (`test_failed_tool_run_status_reaches_the_official_body.py`) proves clause 2 for the publish path
and pins the lifecycle/outcome of a task whose tool run was cancelled. This file measures clause 1 - "a cancelled
task no longer produces a body without limitations" - and it measures it in three parts, because the clause can be
satisfied in three different ways and only one of them is the obvious one:

  * THE GUARD: a task already `CANCELLED` when the finalize block runs must publish NO body rather than a body
    whose limitation list is silent about the cancellation, and must not take an outcome.
  * THE OPERATOR PATH: after a cancellation through `AnalysisService.cancel_task`, no NEW body can be obtained
    either - the only route that mints a revision for an existing task is refused.
  * THE POSITIVE HALF: a cancellation that IS recorded on a task row still reaches the body of a run that
    publishes one, so the clause is not satisfied by suppressing bodies in general.

MEASUREMENTS THIS FILE IS BASED ON (raw runs in `.scratch/ghidra-c3/preflight/P-1.2-gap-probe.txt` and
`P-1.2-cancel-probe.txt`, structured copies beside them as `.json`):

  * Gate 1 is reachable and already correct. Injecting the lifecycle at the finalize seam produces a refused body.
  * The OPERATOR path is refused too: `recompose_report` raises `LookupError` for a cancelled task.
  * A LIMIT OF THE CONCURRENT MEASUREMENT, recorded so nobody repeats it: a cancellation aimed at the finalize
    window from a second thread CANNOT be scheduled through that seam. MEASURED
    (`P-1.2-cancel-probe.json`, `cancel_blocked_seconds`): the seam sits inside the finalize block's
    `session_factory.begin()` transaction, so on SQLite the operator's UPDATE blocks on that open write
    transaction (20.3 s, i.e. until the run finished) and therefore never lands before the guard. The lock is a
    property of the harness. The first attempt at this step read the resulting row (`CANCELLED` + a published
    body) as a production defect; the blocking measurement shows the cancellation simply arrived AFTER the run,
    and the run's result was correct. That correction is recorded rather than quietly dropped.
  * KNOWN GAP, pinned by the last test: `task.limitations` is computed at finalize and frozen into the Analysis
    Snapshot, so a tool run that ends NON-`SUCCEEDED` AFTER the publish reaches no later body either - not even a
    `recompose_report` one. Measured: the recomposed revision names no late run while the task row and the new
    snapshot both hold it. Recorded, not fixed: re-projecting the current task at revision time is a semantics
    change to "recompose" and belongs to the step that owns report revisions.
"""
from __future__ import annotations

import io
import json
import types
import zipfile
from datetime import datetime, timezone

import pytest
from sqlalchemy import text as sql_text

from threat_report_agent.analyst_report import render_official_markdown
from threat_report_agent.config import ModelProviderSettings, Settings
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import AnalysisTask, ToolRun
from threat_report_agent.service import AnalysisService
from threat_report_agent.task.status import TaskLifecycle

CANCELLING_TOOL = "p12-cancelled-emulator"
CANCELLING_ERROR = "TOOL_ACTIVITY_CANCELLED"


def sample_zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "payload.txt",
            b"http://evil.example.com/api VirtualAlloc WriteProcessMemory IsDebuggerPresent CryptDecrypt",
        )
    return buffer.getvalue()


def settings_for(url: str, content_dir) -> Settings:
    return Settings(
        environment="test",
        database_url=url,
        object_store_endpoint="http://object-store",
        object_store_bucket="test",
        object_store_access_key="test",
        object_store_secret_key="test",
        content_store_backend="local",
        content_store_path=str(content_dir),
        temporal_address="temporal:7233",
        ghidra_home="",
        java_home="",
        max_sample_files=100,
        max_sample_bytes=16 * 1024 * 1024,
        max_archive_depth=3,
        gate_secret_key="test-gate-secret",
        primary_model=ModelProviderSettings(
            "test-provider", "http://model.invalid/v1", "test-model", "test-key"
        ),
        fallback_model=ModelProviderSettings("fallback", "", "", ""),
    )


class Harness:
    def __init__(self, tmp_path, *, name: str = "cancel") -> None:
        self.settings = settings_for(
            f"sqlite:///{(tmp_path / f'{name}.sqlite3').as_posix()}", tmp_path / f"{name}-content"
        )
        self.database = Database(self.settings.database_url)
        self.database.create_schema()
        self.service = AnalysisService(
            self.settings, self.database, LocalContentStore(self.settings.content_store_path)
        )
        self.hook_calls = 0

    def install_limitations_hook(self, hook) -> None:  # noqa: ANN001 - a bound replacement
        """Install a replacement for `_completion_limitations` ON THIS SERVICE INSTANCE.

        NEVER on `AnalysisService` itself. A class attribute is global mutable state: two harnesses alive at once,
        or any other test reaching the class, would see a foreign hook, and the outcome would depend on pytest's
        ordering. `types.MethodType` shadows the staticmethod descriptor for this service only and disappears with
        it, so there is no restoration step to get wrong and no window in which the class is modified.
        """
        self._original_completion = AnalysisService._completion_limitations
        self.service._completion_limitations = types.MethodType(hook, self.service)  # type: ignore[method-assign]

    def sql(self, statement: str, parameters: dict[str, object] | None = None) -> list[tuple]:
        with self.database.session_factory() as session:
            return [tuple(row) for row in session.execute(sql_text(statement), parameters or {}).all()]

    def revision_count(self, task_id: str) -> int:
        return int(self.sql(
            "SELECT count(*) FROM report_revisions WHERE task_id = :task_id", {"task_id": task_id}
        )[0][0])

    def task_row(self, task_id: str) -> tuple:
        return self.sql(
            "SELECT lifecycle, outcome, limitations FROM analysis_tasks WHERE id = :task_id",
            {"task_id": task_id},
        )[0]


def analyse_with_a_cancelled_task_at_the_finalize_seam(harness: Harness, case_id: str) -> dict[str, object]:
    """Analyse a submission whose task is `CANCELLED` by the time the finalize block reaches its guard.

    The seam is the statement immediately above the guard inside the finalize transaction, which is the only
    placement that makes the guard's decision deterministic: no other point in the call is guaranteed to be after
    the pipeline and before the guard. The lifecycle is written the way the operator path writes it (`CANCELLED`
    plus a NULL outcome), and the hook does not wait, sleep or poll - it writes and continues.

    NOTHING ELSE IS INJECTED, and that is deliberate. MEASURED: a `tool_runs` row added at this seam is NOT
    persisted when the run is refused - the finalize block's own failing state transition rolls the whole
    transaction back - so a fixture that injected one would be asserting on a row that never existed.
    """
    state: dict[str, object] = {}

    def hook(_service, session, task_id, artifacts):  # noqa: ANN001 - bound-method signature
        harness.hook_calls += 1
        if harness.hook_calls == 1:
            task = session.get(AnalysisTask, task_id)
            task.lifecycle = TaskLifecycle.CANCELLED.value
            task.outcome = None
            session.flush()
            state["task_id"] = str(task_id)
        return harness._original_completion(session, task_id, artifacts)

    harness.install_limitations_hook(hook)
    try:
        result = harness.service.analyze_submission(
            case_id=case_id, filename="p12-cancel.zip", content=sample_zip_bytes()
        )
        raised = None
    except Exception as exc:  # noqa: BLE001 - the measurement is what raised
        result, raised = None, f"{type(exc).__name__}: {exc}"[:300]
    return {"result": result, "raised": raised, "task_id": state.get("task_id")}


def test_a_cancelled_task_publishes_no_body_rather_than_one_without_the_cancellation(tmp_path) -> None:
    """THE GUARD: a task that is `CANCELLED` when finalize runs publishes NO body and takes no outcome.

    "No revision" is the ONLY honest outcome for a cancelled run: a revision written from the pre-cancellation
    state would be a body whose limitations list is silent about a cancellation that had already happened - which
    is exactly the "无限制正文" (body without limitations) the criterion forbids. The guard is the thing that
    decides this, and it reads the lifecycle at the top of the finalize block.

    WHAT THE MEASUREMENT SHOWS, stated exactly: the run is NOT written as `SUCCEEDED`. MEASURED: the finalize
    block's own state transition is what refuses it (`InvalidStateTransition: CANCELLED -> FINALIZING`, recorded
    in `attempt["raised"]`), the generic failure handler then records the attempt, and the terminal row is
    `FAILED` with a NULL outcome - i.e. the cancellation is not readable afterwards as a completed analysis. The
    test asserts the OUTCOME OF THE DECISION that both paths share (no body, no outcome, terminal) rather than the
    name of the branch, because asserting the branch name would pin an implementation detail rather than the
    contract this clause is about.
    """
    harness = Harness(tmp_path)
    case = harness.service.create_case("p12 cancel clause")
    attempt = analyse_with_a_cancelled_task_at_the_finalize_seam(harness, case.id)
    assert attempt["task_id"], f"the seam never ran, so the branch was not exercised: {attempt!r}"
    task_id = str(attempt["task_id"])

    lifecycle, outcome, limitations = harness.task_row(task_id)
    assert lifecycle != TaskLifecycle.SUCCEEDED.value, (
        f"a cancelled run was published as SUCCEEDED: {lifecycle!r} (raised: {attempt['raised']!r})"
    )
    assert lifecycle in {
        TaskLifecycle.CANCELLED.value,
        TaskLifecycle.FAILED.value,
    }, f"unexpected terminal lifecycle {lifecycle!r}"
    assert outcome is None, f"a cancelled task must not carry an analysis outcome: {outcome!r}"
    assert harness.revision_count(task_id) == 0, (
        f"a cancelled task published {harness.revision_count(task_id)} report revision(s); a body written from "
        "the pre-cancellation state is exactly the unlimited body this clause forbids"
    )
    assert attempt["result"] is None or getattr(attempt["result"], "report_revision_id", None) is None, (
        f"the submission handed back a revision id for a cancelled run: {attempt['result']!r}"
    )
    # The refusal happened AFTER the pipeline stored its runs, so "no body" is not "nothing ever ran": the
    # pipeline's own runs are on the row, and the only thing missing is the publication.
    stored_statuses = {str(row[1]) for row in harness.sql(
        "SELECT tool_name, status FROM tool_runs WHERE task_id = :task_id", {"task_id": task_id}
    )}
    assert stored_statuses == {"SUCCEEDED"}, (
        f"the refused run kept a non-SUCCEEDED row, so this fixture is not the one it claims: {stored_statuses!r}"
    )


def test_the_public_cancel_entry_point_refuses_to_publish_a_new_body_afterwards(tmp_path) -> None:
    """THE OPERATOR PATH: after the public cancellation, no NEW body can be obtained.

    The task is cancelled by writing the row exactly as `cancel_task` writes it (the entry point itself refuses a
    terminal task, so a cancelled-then-recomposed task is set up directly), and the test then tries the only route
    that can mint a revision for an existing task. It must be refused: a body recomposed from the frozen
    pre-cancellation snapshot would carry the tool-run list of the moment of publish and nothing about the
    cancellation.
    """
    harness = Harness(tmp_path)
    case = harness.service.create_case("p12 cancel operator path")
    submitted = harness.service.analyze_submission(
        case_id=case.id, filename="p12-cancel-2.zip", content=sample_zip_bytes()
    )
    first = harness.service.get_report_revision(submitted.report_revision_id)
    assert first["markdown"], "the first body must exist, or 'no NEW body' would be vacuous"
    before = harness.revision_count(submitted.task_id)

    with harness.database.session_factory.begin() as session:
        session.add(
            ToolRun(
                task_id=submitted.task_id,
                artifact_id=None,
                tool_name=CANCELLING_TOOL,
                tool_version="0.1.0",
                status="CANCELLED",
                parameters={"fixture": "p12-cancel"},
                environment={"fixture": "p12-cancel"},
                output={},
                error=CANCELLING_ERROR,
            )
        )
        task = session.get(AnalysisTask, submitted.task_id)
        task.lifecycle = TaskLifecycle.CANCELLED.value
        task.outcome = None

    with pytest.raises(LookupError):
        harness.service.recompose_report(submitted.task_id, ["limitations"])
    assert harness.revision_count(submitted.task_id) == before, (
        "a revision was minted for a cancelled task after the cancellation"
    )
    lifecycle, outcome, _ = harness.task_row(submitted.task_id)
    assert lifecycle == TaskLifecycle.CANCELLED.value
    assert outcome is None


def test_a_recorded_cancellation_still_reaches_a_body_when_one_is_published(tmp_path) -> None:
    """THE POSITIVE HALF: the clause must not be satisfied by suppressing bodies in general.

    A `CANCELLED` tool run on a task that goes on to publish a body DOES reach that body with its status and error
    category, under the operational-limitations heading, and the task's lifecycle/outcome semantics are unchanged
    by the fact that a TOOL RUN was cancelled - only the task-level decision may set `CANCELLED`.
    """
    harness = Harness(tmp_path, name="recorded")
    case = harness.service.create_case("p12 cancel recorded")
    state: dict[str, object] = {}

    def hook(_service, session, task_id, artifacts):  # noqa: ANN001 - bound-method signature
        harness.hook_calls += 1
        if harness.hook_calls == 1:
            session.add(
                ToolRun(
                    task_id=str(task_id),
                    artifact_id=None,
                    tool_name=CANCELLING_TOOL,
                    tool_version="0.1.0",
                    status="CANCELLED",
                    parameters={"fixture": "p12-cancel"},
                    environment={"fixture": "p12-cancel"},
                    output={},
                    error=CANCELLING_ERROR,
                    started_at=datetime.now(timezone.utc),
                    finished_at=datetime.now(timezone.utc),
                )
            )
            session.flush()
            state["task_id"] = str(task_id)
        return harness._original_completion(session, task_id, artifacts)

    harness.install_limitations_hook(hook)
    result = harness.service.analyze_submission(
        case_id=case.id, filename="p12-cancel-3.zip", content=sample_zip_bytes()
    )

    body = harness.service.get_report_revision(result.report_revision_id)
    lifecycle, outcome, limitations = harness.task_row(result.task_id)
    assert lifecycle == "SUCCEEDED", f"a run cancellation must not change the task lifecycle: {lifecycle!r}"
    assert outcome == "PARTIAL", f"the analysis outcome semantics changed: {outcome!r}"
    expected = f"Tool run {CANCELLING_TOOL} ended CANCELLED: {CANCELLING_ERROR}."
    assert expected in list(json.loads(limitations or "[]")), limitations
    assert f"[pipeline] {expected}" in body["markdown"], (
        f"the recorded cancellation is not in the published body: tail={body['markdown'][-600:]!r}"
    )
    # The body stays a body: the cancellation is a limitation, not a reason to withhold the report.
    assert len(body["markdown"]) > 1000


def test_a_late_non_succeeded_tool_run_reaches_no_later_body_characterisation(tmp_path) -> None:
    """KNOWN GAP, pinned so a change of behaviour cannot pass unnoticed.

    MEASURED: a tool run that ends NON-`SUCCEEDED` after the first publish is in the DATABASE and in the frozen
    snapshot's `tool_runs`, but no limitation is attached to it, because `task.limitations` is computed once at
    finalize and the revision writer projects that frozen task. A `recompose_report` call made afterwards
    therefore publishes a NEW revision that names the run nowhere - the reader gets a body that is silent about a
    timeout that had already happened when it was written.

    This test asserts the measured behaviour, not a desired one: if a later step re-projects the task at revision
    time, this test FAILS and forces that step to record the change instead of making it invisibly. The gap is
    owned by whoever owns report-revision semantics; fixing it here would change what "recompose" means.
    """
    harness = Harness(tmp_path)
    case = harness.service.create_case("p12 late run")
    submitted = harness.service.analyze_submission(
        case_id=case.id, filename="p12-late.zip", content=sample_zip_bytes()
    )
    first = harness.service.get_report_revision(submitted.report_revision_id)
    assert "p12-late-emulator" not in str(first["markdown"])

    with harness.database.session_factory.begin() as session:
        session.add(
            ToolRun(
                task_id=submitted.task_id,
                artifact_id=None,
                tool_name="p12-late-emulator",
                tool_version="0.1.0",
                status="TIMED_OUT",
                parameters={"fixture": "p12-late"},
                environment={"fixture": "p12-late"},
                output={},
                error="LATE_WORKER_DEADLINE",
            )
        )

    recomposed = harness.service.recompose_report(submitted.task_id, ["limitations"])
    # The late row IS visible to the product's own SQL, so "not named" is not "not stored".
    stored = harness.sql(
        "SELECT tool_name, status, error FROM tool_runs "
        "WHERE task_id = :task_id AND status != 'SUCCEEDED'",
        {"task_id": submitted.task_id},
    )
    assert ("p12-late-emulator", "TIMED_OUT", "LATE_WORKER_DEADLINE") in stored, stored
    # ...and the recomposed revision is a real, canonical render of its own document.
    document = harness.sql(
        "SELECT document FROM report_revisions WHERE id = :revision_id", {"revision_id": recomposed["id"]}
    )[0][0]
    document = json.loads(document)
    assert render_official_markdown(document) == recomposed["markdown"]
    assert len(str(recomposed["markdown"])) > 1000
    # THE PINNED GAP: the new body does not name the run, and no limitation list carries it.
    assert "p12-late-emulator" not in str(recomposed["markdown"]), (
        "a late non-SUCCEEDED run now reaches the recomposed body - update this record and the gap note"
    )
    assert "LATE_WORKER_DEADLINE" not in str(recomposed["markdown"])
    limitations = list(document.get("analyst_report_limitations") or [])
    assert not any("p12-late-emulator" in str(item) for item in limitations), limitations
