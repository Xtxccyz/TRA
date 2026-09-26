"""P-1.2: a NON-`SUCCEEDED` ToolRun must project into a limitation that reaches the OFFICIAL body.

WHAT THIS FILE PINS, and why the existing suites were not enough:

* `tests/test_failed_tool_runs_reach_the_report.py` drives `AnalysisService.failed_tool_run_limitations` with a
  session STUB. It proves the helper formats a row; it cannot prove that a real `tool_runs` row of a real task
  ever reaches a body, because the stub supplies the rows itself.
* `tests/test_analyst_report_acceptance.py` proves `task.limitations` reach the rendered Markdown, but its live
  fixture is a CLEAN task - every ToolRun it creates is `SUCCEEDED` - so it says nothing about CANCELLED /
  TIMED_OUT / FAILED.

The plan's own criterion for this step is stronger than a substring check: "字符串出现本身不算语义正确，必须证明该
bullet 由同一 ToolRun 状态投影而来" - the bullet must be shown to come from the SAME ToolRun row, with the ToolRun
status IN the SQL that selected it. So the chain proved here is, per status:

    tool_runs(tool_name, status, error)          <- real SQL, revision-bound, product's own schema
      -> analysis_tasks.limitations               <- what finalize computed FROM those rows
      -> analysis_snapshots.object_versions.task  <- frozen at publish time
      -> report_revisions.document[analyst_report_limitations]
      -> report_revisions.markdown                <- the official body a reader gets

Every link is read back from the database or from the revision the product wrote; nothing is hand-typed.

WHY THE ROWS ARE INSERTED AT A SEAM RATHER THAN BEFORE THE RUN: the projection of `tool_runs` into
`task.limitations` happens inside the analyse call, immediately before the report is frozen, so a row inserted
before the run would be overwritten by the pipeline's own bookkeeping only if it collided - and a row inserted
after the run could never have been seen. The seam below wraps `AnalysisService._completion_limitations`, which
the SAME `with self.database.session_factory.begin() as session:` block calls ONE statement line above
`set(self._failed_tool_run_limitations(session, task.id))`, so the rows are committed before the projection runs
and the production code path between the two is untouched.

WHAT THIS FILE DOES NOT CLAIM: nothing here says the projection was previously broken. MEASURED: the producer
(`task/limitations.py::failed_tool_run_limitations`) and its two merge call sites already exist, and every test
below PASSES on the unmodified product - which is why `.scratch/ghidra-c3/preflight/p12-canfail.py` disconnects
each half of the wiring in a real subprocess and requires the matching test to FAIL. A green test whose wiring
can be removed silently would be no evidence at all.
"""
from __future__ import annotations

import ctypes
import hashlib
import io
import json
import os
import re
import sys
import tempfile
import threading
import time
import traceback
import types
import zipfile
from contextlib import contextmanager, redirect_stderr
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import select as sa_select

from threat_report_agent.analyst_report import (
    OPERATIONAL_LIMITATIONS_HEADING,
    compose_official_markdown,
    render_official_markdown,
)
from threat_report_agent.config import ModelProviderSettings, Settings
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.emulation.policy import (
    SimulationRequest,
    evidence_nature_for_simulation_status,
)
from threat_report_agent.models import Artifact, Evidence, ToolRun
from threat_report_agent.service import AnalysisService
from threat_report_agent.simulation_adapters import (
    EMULATOR_STDERR_BOUND_ENV,
    EMULATOR_STDERR_BOUND_SOURCE,
    EMULATOR_STDERR_EVENT,
    EMULATOR_STDERR_NATURE,
    EmulatorDiagnosticBinding,
    _EMULATOR_STDERR_CAPTURE_LOCK,
    _capture_emulator_stderr,
    _emulator_diagnostic_summary,
    _emulator_stderr_text_bound,
    _speakeasy_adapter,
    _speakeasy_start_address,
    bind_emulator_diagnostic_context,
    emulator_diagnostic_binding,
)
from threat_report_agent.static.evidence_index import evidence_search_keys

#: The four statuses this step names, each with the error category the pipeline records for it. `FAILED` carries
#: a NULL error on purpose: the projection must still name the status instead of inventing a reason.
FIXTURE_ROWS: tuple[tuple[str, str, str | None], ...] = (
    ("p12-ghidra-headless", "TIMED_OUT", "TEMPORAL_ACTIVITY_TIMED_OUT"),
    ("p12-controlled-emulator", "CANCELLED", "TOOL_ACTIVITY_CANCELLED"),
    ("p12-parser-worker", "FAILED", None),
    ("p12-attack-mapping-index", "SUCCEEDED", None),
)
CLEAN_TOOL = "p12-attack-mapping-index"

#: The revision-bound SELECT: the ToolRun STATUS is in the WHERE clause, and the revision is joined in, so the
#: same statement that names the runs also names the task/revision/content identity the plan's M3 demands.
REVISION_BOUND_SQL = (
    "SELECT r.id AS revision_id, r.task_id AS task_id, t.tool_name AS tool_name, t.status AS status, "
    "t.error AS error, json_extract(a.request_snapshot, '$.sample_package.content_sha256') AS content_sha256 "
    "FROM report_revisions AS r "
    "JOIN analysis_tasks AS a ON a.id = r.task_id "
    "JOIN tool_runs AS t ON t.task_id = r.task_id "
    "WHERE r.id = :revision_id AND t.status != 'SUCCEEDED' "
    "ORDER BY t.tool_name, t.status"
)


def sample_zip_bytes() -> bytes:
    """The exact bytes submitted as the sample; the artifact's `content_source` is written from this."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "payload.txt",
            b"http://evil.example.com/api VirtualAlloc WriteProcessMemory IsDebuggerPresent CryptDecrypt",
        )
    return buffer.getvalue()


def probe_settings(root: Path, name: str = "p12") -> Settings:
    """Settings for a THROWAWAY SQLITE DATABASE, one per fixture.

    ONE FILE PER FIXTURE IS DELIBERATE: an earlier version let two `Fixture`s share one database file through two
    separate engines, which means two SQLite writers on one file and a `database is locked` outcome that depends
    on scheduling. Nothing in this file needs the two fixtures to share storage - the cross-task assertion is
    about which `task_id` the SQL is bound to, and that is checked against a row count, not against co-location.
    """
    root.mkdir(parents=True, exist_ok=True)
    return Settings(
        environment="test",
        database_url=f"sqlite:///{(root / f'{name}.sqlite3').as_posix()}",
        object_store_endpoint="http://object-store",
        object_store_bucket="test",
        object_store_access_key="test",
        object_store_secret_key="test",
        content_store_backend="local",
        content_store_path=str(root / f"{name}-content"),
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


class Fixture:
    """One analysed task whose report revision was published WITH its ToolRun rows in the database.

    DETERMINISM, because an earlier version of this class was not:
      * the seam is installed on the SERVICE INSTANCE, never on `AnalysisService` itself. A class attribute is
        global mutable state: two fixtures alive at once (and any other test that reaches the class) would see a
        foreign seam, and the failure would depend on the order pytest happened to run things in. An instance
        attribute shadows the staticmethod descriptor for that one service, and dies with it.
      * the hook does not wait, sleep or poll. It stores the rows and continues, so the ordering the projection
        needs is the transaction's own statement order rather than a clock.
      * every fixture gets its own database file (`probe_settings`), so no two engines write one SQLite file.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        rows: tuple[tuple[str, str, str | None], ...] = FIXTURE_ROWS,
    ) -> None:
        self.settings = settings
        self.inserted_rows = rows
        self.database = Database(settings.database_url)
        self.database.create_schema()
        self.service = AnalysisService(
            settings, self.database, LocalContentStore(settings.content_store_path)
        )
        self.sample_bytes = sample_zip_bytes()
        self.sample_sha256 = hashlib.sha256(self.sample_bytes).hexdigest()
        self.projection_hook_calls = 0
        self.inserted = self._analyse_with_fixture_runs()
        self.revision_id = str(self.inserted["revision_id"])
        self.task_id = str(self.inserted["task_id"])

    def _analyse_with_fixture_runs(self) -> dict[str, object]:
        """Analyse the sample, inserting the ToolRun rows at the finalize seam.

        The seam is `AnalysisService._completion_limitations`, which the SAME
        `with self.database.session_factory.begin() as session:` block calls ONE statement line above
        `set(self._failed_tool_run_limitations(session, task.id))`. The rows are therefore in the session before
        the projection's SELECT runs, and everything between the two is the untouched production path.
        """
        service = self.service
        original = AnalysisService._completion_limitations

        def hook(_service, session, task_id, artifacts):  # noqa: ANN001 - bound-method signature
            self.projection_hook_calls += 1
            if self.projection_hook_calls == 1:
                now = datetime.now(timezone.utc)
                for tool_name, status, error in self.inserted_rows:
                    session.add(
                        ToolRun(
                            task_id=str(task_id),
                            artifact_id=None,
                            tool_name=tool_name,
                            tool_version="0.1.0",
                            status=status,
                            parameters={"fixture": "p12"},
                            environment={"fixture": "p12"},
                            output={},
                            error=error,
                            started_at=now,
                            finished_at=now,
                        )
                    )
                session.flush()
            return original(session, task_id, artifacts)

        # INSTANCE-LEVEL: `types.MethodType(hook, service)` shadows the class's staticmethod for THIS service
        # only, and the attribute disappears with the fixture, so no cleanup is needed and no other test can see it.
        service._completion_limitations = types.MethodType(  # type: ignore[method-assign]
            hook, service
        )
        case = service.create_case("p12 tool run statuses")
        result = service.analyze_submission(
            case_id=case.id, filename="p12-bundle.zip", content=self.sample_bytes
        )
        return {"task_id": result.task_id, "revision_id": result.report_revision_id}

    # -- real SQL against the product's own schema -------------------------------------------------------------

    def sql(self, statement: str, parameters: dict[str, object] | None = None) -> list[tuple]:
        """Execute `statement` on a real connection and return its rows."""
        connection = self.database.engine.raw_connection()
        try:
            cursor = connection.cursor()
            cursor.execute(statement, parameters or {})
            return [tuple(row) for row in cursor.fetchall()]
        finally:
            connection.close()

    def revision_bound_rows(self, revision_id: str | None = None) -> list[tuple]:
        """The revision-bound SELECT above, for this revision or for one the caller names."""
        return self.sql(REVISION_BOUND_SQL, {"revision_id": revision_id or self.revision_id})

    def task_limitations(self) -> list[str]:
        rows = self.sql(
            "SELECT limitations FROM analysis_tasks WHERE id = :task_id", {"task_id": self.task_id}
        )
        assert len(rows) == 1, rows
        return list(json.loads(rows[0][0] or "[]"))

    def published_markdown(self) -> str:
        rows = self.sql(
            "SELECT markdown FROM report_revisions WHERE id = :revision_id",
            {"revision_id": self.revision_id},
        )
        assert len(rows) == 1, rows
        return str(rows[0][0])

    def revision_document(self) -> dict[str, object]:
        rows = self.sql(
            "SELECT document FROM report_revisions WHERE id = :revision_id",
            {"revision_id": self.revision_id},
        )
        assert len(rows) == 1, rows
        return dict(json.loads(rows[0][0]))

    def snapshot_task_limitations(self) -> list[str]:
        rows = self.sql(
            "SELECT json_extract(object_versions, '$.task.limitations') FROM analysis_snapshots "
            "WHERE task_id = :task_id ORDER BY created_at DESC LIMIT 1",
            {"task_id": self.task_id},
        )
        assert rows, "no snapshot row for this task"
        return list(json.loads(rows[0][0] or "[]"))


@pytest.fixture(scope="module")
def fixture(tmp_path_factory) -> Fixture:
    """One real end-to-end analysis shared by the assertions below."""
    return Fixture(probe_settings(tmp_path_factory.mktemp("p12")))


# -----------------------------------------------------------------------------------------------------------
# The fixture itself must be non-vacuous: the SELECT is revision-bound and the sample hash is real.
# -----------------------------------------------------------------------------------------------------------
def test_the_revision_bound_sql_selects_every_status_and_the_real_sample_hash(fixture: Fixture) -> None:
    """M3: task/revision/content identity and the run rows come from ONE revision-bound SQL statement."""
    rows = fixture.revision_bound_rows()
    selected = {(str(row[2]), str(row[3]), row[4]) for row in rows}
    expected = {(tool, status, error) for tool, status, error in FIXTURE_ROWS if status != "SUCCEEDED"}
    assert selected == expected, f"the revision-bound SELECT did not return the fixture rows: {rows!r}"
    assert {str(row[0]) for row in rows} == {fixture.revision_id}, "the rows must belong to THIS revision"
    # `content_sha256` is the submitted bytes' own digest, recomputed here rather than trusted from the report.
    assert hashlib.sha256(fixture.sample_bytes).hexdigest() == fixture.sample_sha256
    assert {str(row[5]) for row in rows} == {fixture.sample_sha256}, (
        f"the stored sample hash is not the submitted bytes' digest {fixture.sample_sha256!r}: {rows!r}"
    )


# -----------------------------------------------------------------------------------------------------------
# Per status: the row, the task fact it produced, and the bullet in the OFFICIAL body.
# -----------------------------------------------------------------------------------------------------------
def test_each_non_succeeded_status_projects_its_own_bullet_into_the_official_body(
    fixture: Fixture,
) -> None:
    """PRODUCER -> DOCUMENT -> OFFICIAL MARKDOWN, per ToolRun row, with the status read from SQL."""
    assert fixture.projection_hook_calls == 1, (
        "the finalize seam ran a different number of times than once, so the fixture's insertion point is not "
        f"the one this test documents: {fixture.projection_hook_calls}"
    )
    rows = fixture.revision_bound_rows()
    assert rows, "no non-SUCCEEDED fixture row was selected, so this test would be vacuous"
    document_limitations = fixture.revision_document().get("analyst_report_limitations") or []
    official = fixture.published_markdown()
    for _revision, _task, tool_name, status, error, _content in rows:
        projected = f"Tool run {tool_name} ended {status}: {error or 'no error recorded'}."
        expected = f"[pipeline] {projected}"
        assert expected in document_limitations, (
            f"the run ({tool_name}, {status}, {error!r}) did not reach the revision's document; "
            f"document limitations={document_limitations!r}"
        )
        # The TASK row holds the pipeline's own wording; the `[pipeline]` label is added by the merge, so the
        # bullet is traceable to the row AND distinguishable from a model-stated limitation.
        assert projected in fixture.task_limitations(), (
            "the bullet must be projected from the ToolRun rows into the TASK's own limitations first; "
            f"task limitations={fixture.task_limitations()!r}"
        )
        assert expected in official, (
            f"the official body does not name the {status} run {tool_name}; body tail={official[-900:]!r}"
        )
        assert projected in fixture.snapshot_task_limitations(), (
            "the published revision's snapshot does not carry the limitation, so the body could only have "
            "come from a second projection"
        )


def test_a_wrong_revision_returns_no_row_for_the_same_sql(fixture: Fixture) -> None:
    """M3 NEGATIVE CONTROL: the SAME revision-bound SQL returns nothing for a revision that is not this one."""
    assert fixture.revision_bound_rows(), "the control is vacuous unless the right revision does return rows"
    rows = fixture.revision_bound_rows("00000000-0000-4000-8000-000000000000")
    assert rows == [], f"a wrong revision returned rows, so the SQL does not identify the sample: {rows!r}"


def test_a_succeeded_run_without_an_error_adds_no_limitation(fixture: Fixture) -> None:
    """NEGATIVE: a clean run must not manufacture a limitation (the 'fake limitation' failure mode).

    The `SUCCEEDED` fixture row is in the table (asserted below), so its absence from every limitation list is a
    real exclusion rather than an empty table.
    """
    clean_rows = fixture.sql(
        "SELECT tool_name FROM tool_runs WHERE task_id = :task_id AND tool_name = :tool",
        {"task_id": fixture.task_id, "tool": CLEAN_TOOL},
    )
    assert clean_rows, "the SUCCEEDED fixture row is missing, so its exclusion would be vacuous"
    official = fixture.published_markdown()
    for text in (*fixture.task_limitations(), *(fixture.revision_document().get(
        "analyst_report_limitations"
    ) or [])):
        assert CLEAN_TOOL not in str(text), f"a SUCCEEDED run produced a limitation: {text!r}"
    assert CLEAN_TOOL not in official, (
        f"the official body names the SUCCEEDED run {CLEAN_TOOL} as a limitation"
    )


def test_the_body_is_the_canonical_render_of_the_same_revisions_document(fixture: Fixture) -> None:
    """The bullet is read from the RENDERED Markdown, and the render is reproducible from the same revision."""
    document = fixture.revision_document()
    published = fixture.published_markdown()
    assert render_official_markdown(document) == published, (
        "re-rendering the revision's own document does not reproduce the published body, so the stored "
        "markdown is not this document's render"
    )
    assert compose_official_markdown(document) == published
    for _revision, _task, tool_name, status, _error, _content in fixture.revision_bound_rows():
        assert f"Tool run {tool_name} ended {status}" in published


def test_a_different_error_category_projects_a_different_bullet_for_the_same_status(
    tmp_path_factory,
) -> None:
    """The bullet is a projection of THIS row's `error` column, not a per-status constant.

    A second task is analysed through the SAME seam with the same tool names and the SAME statuses but different
    error categories. If the bullet were a lookup table keyed on the status alone, the two bodies would print
    identical text; if the `task_id` predicate were missing, this task's body would carry the first task's
    categories.
    """
    root = tmp_path_factory.mktemp("p12-second")
    first = Fixture(probe_settings(root / "a", "a"))
    second = Fixture(
        probe_settings(root / "b", "b"),
        rows=(
            ("p12-ghidra-headless", "TIMED_OUT", "WORKER_DEADLINE_EXCEEDED"),
            ("p12-controlled-emulator", "CANCELLED", "OPERATOR_CANCELLED"),
            ("p12-parser-worker", "FAILED", None),
            ("p12-attack-mapping-index", "SUCCEEDED", None),
        ),
    )
    assert second.task_id != first.task_id
    official = second.published_markdown()
    body = first.published_markdown()
    for _revision, _task, tool_name, status, error, _content in second.revision_bound_rows():
        assert f"[pipeline] Tool run {tool_name} ended {status}: {error or 'no error recorded'}." in official, (
            f"the second task's body does not project its own error category {error!r}: {official[-900:]!r}"
        )
    assert "TEMPORAL_ACTIVITY_TIMED_OUT" not in official, "the first task's error category leaked into the second"
    assert "TOOL_ACTIVITY_CANCELLED" not in official
    assert official != body, "two different error categories rendered identically, which a lookup table would"
    assert "WORKER_DEADLINE_EXCEEDED" not in body


# -----------------------------------------------------------------------------------------------------------
# A tool error is a PIPELINE fact: it must not be readable as something the sample did.
# -----------------------------------------------------------------------------------------------------------
#: A `tool_runs.error` column is free text, so this is what a crashed activity can actually contain. Every token
#: here is the kind of thing a reader would take as a finding about the SAMPLE.
FACT_SHAPED_TOOL_ERROR = (
    "C2 http://c2.evil.test/beacon reached; CreateRemoteThread into explorer.exe"
)
CONCLUSION_HEADINGS = ("## 分析结论", "### 分析结论")


def _limitations_block_lines(markdown: str) -> list[str]:
    """The bullet lines of the operational-limitations block, by its own heading."""
    lines = markdown.splitlines()
    try:
        start = next(
            index for index, line in enumerate(lines) if line.strip() == OPERATIONAL_LIMITATIONS_HEADING
        )
    except StopIteration:
        return []
    block: list[str] = []
    for line in lines[start + 1:]:
        if line.startswith("- "):
            block.append(line)
        elif line.strip():
            break
    return block


def test_a_tool_error_is_rendered_as_a_labelled_pipeline_limitation_and_not_as_a_finding(
    tmp_path_factory,
) -> None:
    """The bullet carries the `[pipeline]` label, lives in the limitations block, and is nowhere else.

    `[pipeline] Tool run X ended FAILED: <free text>.` cannot be read as a sentence about the sample: the label
    names the emitter, the sentence names the RUN, and the payload is a tool error category. This test measures
    that structure rather than trusting it, because the error column is untrusted free text.
    """
    probe = Fixture(
        probe_settings(tmp_path_factory.mktemp("p12-fact"), "fact"),
        rows=(("p12-crashed-emulator", "FAILED", FACT_SHAPED_TOOL_ERROR),),
    )
    official = probe.published_markdown()
    bullets = _limitations_block_lines(official)
    expected = f"- [pipeline] Tool run p12-crashed-emulator ended FAILED: {FACT_SHAPED_TOOL_ERROR}."
    assert expected in bullets, (
        f"the tool error is not a labelled bullet of the operational-limitations block; block={bullets!r}"
    )
    # Only ONE line of the whole body carries the untrusted text, and it is the labelled bullet: no chapter, no
    # IOC row and no conclusion carries it, so a reader cannot mistake it for something the sample did.
    carriers = [line for line in official.splitlines() if FACT_SHAPED_TOOL_ERROR in line]
    assert carriers == [expected], f"the tool error leaked outside the labelled bullet: {carriers!r}"
    for line in official.splitlines():
        if any(line.startswith(heading) for heading in CONCLUSION_HEADINGS):
            assert "p12-crashed-emulator" not in line, (
                f"a pipeline failure was written into the analysis conclusion: {line!r}"
            )
    # NEGATIVE for the label itself: the same error WITHOUT the label would be a sample-facing sentence, so the
    # label is what makes the bullet safe and its absence must be detectable.
    assert f"- Tool run p12-crashed-emulator ended FAILED: {FACT_SHAPED_TOOL_ERROR}." not in bullets


# -----------------------------------------------------------------------------------------------------------
# REAL-PIPELINE control: this synthetic sample's every run succeeds, and no body may invent a limitation for it.
# -----------------------------------------------------------------------------------------------------------
def test_the_real_pipeline_clean_run_adds_no_tool_run_limitation(tmp_path_factory) -> None:
    """Measured WITHOUT any injected row, on the same sample bytes.

    A `[pipeline] Tool run ...` bullet in THIS body would be a fabricated limitation, because the SELECT that
    projects those bullets returns nothing for this task - asserted by SQL, not by absence of the string.
    """
    clean = Fixture(probe_settings(tmp_path_factory.mktemp("p12-clean"), "clean"), rows=())
    rows = clean.sql(
        "SELECT tool_name, status FROM tool_runs WHERE task_id = :task_id AND status != 'SUCCEEDED'",
        {"task_id": clean.task_id},
    )
    assert rows == [], f"the control task has non-SUCCEEDED runs, so it is not a clean run: {rows!r}"
    total = clean.sql(
        "SELECT count(*) FROM tool_runs WHERE task_id = :task_id", {"task_id": clean.task_id}
    )[0][0]
    assert total > 0, "the control task produced no tool runs at all, so it proves nothing about a clean run"
    official = clean.published_markdown()
    assert "Tool run" not in official, (
        f"the body names a tool run as a limitation for a clean task: "
        f"{[line for line in official.splitlines() if 'Tool run' in line]!r}"
    )
    assert not [line for line in official.splitlines() if line.startswith("FAILED ")], (
        "pytest's own failure lines would make the assertion above vacuous by matching nothing"
    )
    # The body is still bounded by the pipeline's own semantic limitations, so the block is not simply absent.
    assert "[pipeline]" in official, "the operational-limitations block vanished entirely for the clean task"


def test_a_multi_line_tool_error_cannot_forge_a_second_markdown_block(tmp_path_factory) -> None:
    """The `error` column is free text and may contain newlines; ONE limitation must stay ONE bullet.

    MEASURED RISK this pins: `_operational_limitation_lines` writes `- {item}` per limitation. If a tool error
    kept its line breaks, an error carrying its own heading and a conclusion-shaped sentence would put BOTH into
    the analyst-facing body as separate lines - a pipeline failure written as a finding about the sample. The
    renderer collapses the line structure; this test measures that the collapse holds for a `tool_runs.error`
    value, which is the untrusted input this step adds to the channel.

    WHY THE FORGED TOKENS ARE INVENTED RATHER THAN REAL HEADINGS: the first version of this test asserted
    `"## 分析结论" not in official` and FAILED on correct product output, because that heading is a legitimate
    section of every official body. The assertion was wrong, not the renderer - the same mistake the P-1.1 review
    recorded (`### 结论摘要` matching real text). An injected token must be one the product never prints, so the
    measurement is "did the newline survive" and not "does the report contain its own headings".
    """
    forged = "first line\n## P12-FORGED-HEADING\n\nP12-FORGED-CONCLUSION-SENTENCE"
    probe = Fixture(
        probe_settings(tmp_path_factory.mktemp("p12-forge"), "forge"),
        rows=(("p12-forging-emulator", "FAILED", forged),),
    )
    official = probe.published_markdown()
    collapsed = "first line ## P12-FORGED-HEADING P12-FORGED-CONCLUSION-SENTENCE"
    expected = f"- [pipeline] Tool run p12-forging-emulator ended FAILED: {collapsed}."
    bullets = _limitations_block_lines(official)
    assert expected in bullets, f"the error was not collapsed into one labelled bullet: {bullets!r}"
    # The forged tokens are present in the WORDS (the bullet is verbatim) but never as their own LINE, which is
    # the property that makes a forged heading or conclusion impossible.
    assert not [line for line in official.splitlines() if line.strip() == "## P12-FORGED-HEADING"], (
        "a tool error forged a heading line into the body"
    )
    assert not [
        line for line in official.splitlines()
        if line.strip() == "P12-FORGED-CONCLUSION-SENTENCE"
    ], "a tool error forged a conclusion-shaped line into the body"
    assert sum("P12-FORGED-HEADING" in line for line in official.splitlines()) == 1, (
        "the forged token appears on more than one line, so the line structure was not collapsed"
    )


def test_repeated_identical_runs_collapse_to_one_bullet_and_distinct_ones_survive(
    tmp_path_factory,
) -> None:
    """The collection is a SET of stable identities, not a row count.

    `failed_tool_run_limitations` dedupes deliberately (its docstring: adding a `[:N]` here would be a fresh
    unannounced truncation), so the reader-facing count is the number of DISTINCT `(tool_name, status, error)`
    triples. Pinned here because the M5 set difference in the step artifact uses that same identity key: a test
    that assumed one bullet per ROW would report a spurious `expected_minus_actual` for any task that retried a
    tool, and a projection that dropped the dedupe would publish the same failure twice.
    """
    probe = Fixture(
        probe_settings(tmp_path_factory.mktemp("p12-dedupe"), "dedupe"),
        rows=(
            ("p12-retried-emulator", "TIMED_OUT", "SAME_REASON"),
            ("p12-retried-emulator", "TIMED_OUT", "SAME_REASON"),
            ("p12-other-emulator", "TIMED_OUT", "SAME_REASON"),
        ),
    )
    rows = probe.revision_bound_rows()
    assert len(rows) == 3, f"the retry was not stored, so this test would be vacuous: {rows!r}"
    limitations = probe.task_limitations()
    tool_run_entries = [item for item in limitations if "Tool run" in str(item)]
    assert len(tool_run_entries) == 2, (
        f"two identical rows must collapse to one bullet and the distinct one must survive: {tool_run_entries!r}"
    )
    bullets = _limitations_block_lines(probe.published_markdown())
    tool_run_bullets = [line for line in bullets if "Tool run" in line]
    assert len(tool_run_bullets) == 2, tool_run_bullets
    assert sum("p12-retried-emulator" in line for line in tool_run_bullets) == 1


def test_the_artifact_fixture_records_the_sample_bytes_it_hashes(tmp_path_factory) -> None:
    """The M3 record's `content_source` is the exact submitted bytes, so the validator can re-hash it.

    The file is written from the same function the fixture submits, and its digest is compared against the copy
    the RUNNING fixture actually stored, so the artifact's `content_sha256` cannot drift from the run.
    """
    probe = Fixture(probe_settings(tmp_path_factory.mktemp("p12-source"), "source"))
    source = Path(probe.settings.content_store_path).parent / "p12-m3-sample.zip"
    source.write_bytes(probe.sample_bytes)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == probe.sample_sha256
    stored = probe.sql(
        "SELECT json_extract(request_snapshot, '$.sample_package.content_sha256') "
        "FROM analysis_tasks WHERE id = :task_id",
        {"task_id": probe.task_id},
    )
    assert stored[0][0] == probe.sample_sha256


# ===========================================================================================================
# P-1.4: the emu-worker DIAGNOSTIC CHANNEL - the fd 2 / ctypes traceback around the emulator call
# ===========================================================================================================
# THE DEFECT THIS CHANNEL IS FOR, already recorded in `tests/test_empty_emulator_report_is_not_success.py:1-22`:
# Speakeasy crashes inside its own unmapped-memory handler (the `get_peb_ldr` AttributeError on `None`), `ctypes`
# prints that traceback to the OS-level fd 2 and SWALLOWS it, and the run then returns a report with no entry points.
# The CONSEQUENCE was classified; the TEXT was discarded, so the published limitation read `EMULATOR_NO_REPORT` -
# the symptom - while the cause sat nowhere.
#
# WHAT IS REAL HERE: the production capture (`_capture_emulator_stderr`), the observation builder, the byte bound, the
# whole `_speakeasy_adapter` body on BOTH of its call-site branches, the `SimulationResult` projections, the Evidence
# row, the report document, and the official Markdown. WHAT IS STUBBED: the third-party `speakeasy` package (via
# `sys.modules`), because reaching that failure on the real package needs a real crashed emulation. The traceback
# itself is NOT simulated: it is an exception escaping a real `ctypes` callback, printed by CPython through the same
# `PyErr_Print()` path the real defect used.
#
# THE PLAN'S RULE THAT SHAPES EVERY ASSERTION BELOW: stderr text is an OBSERVATION and must never be published as a
# Claim. So the observation carries `is_claim: False`, the official body may cite only the SUMMARY, and the raw
# traceback must be absent from the body.
#: A real PE header is what `_speakeasy_adapter` requires before it will load a module at all. These bytes are
#: synthetic; nothing is executed on the host and `sample_path` is never opened.
P14_MZ_PAYLOAD = b"MZ" + bytes(range(256))
#: The error text the real defect produced, reproduced by an exception escaping a ctypes callback on the SAME object
#: shape (`None.get_peb_ldr`), so the message this channel parses is the message the audit recorded.
P14_MISSING_ATTRIBUTE = "get_peb_ldr"
P14_RAW_TRACEBACK_MARKER = "Traceback (most recent call last)"
P14_SUMMARY_MARKER = "emulator stderr diagnostic (observation, not a claim)"


def p14_ctypes_callback_fault() -> None:
    """Raise AttributeError on None inside a real ctypes callback: ctypes SWALLOWS it.

    The exception escapes the callback into CPython's `PyErr_WriteUnraisable` path. MEASURED on this interpreter
    (CPython 3.12, and visible in this file's own history): that path calls `sys.unraisablehook`, so it does NOT
    reach fd 2 by itself - the DEFAULT hook writes to `sys.stderr`, and pytest installs a hook of its own. The genuine
    traceback text is therefore taken from the real mechanism by `p14_ctypes_swallowed_traceback` and delivered to the
    descriptor by `p14_write_to_fd2_natively`, which is the write path a native emulator layer really uses.
    """
    def callback(_value: int) -> int:
        handle = None
        return handle.get_peb_ldr  # noqa: B015 - the AttributeError IS the subject of this test

    prototype = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)
    prototype(callback)(1)


def p14_ctypes_swallowed_traceback() -> str:
    """The traceback of an exception that really escaped a `ctypes` callback, formatted by the default hook's own API.

    The hook is installed for the duration of the call and the previous one is restored in a `finally`, so pytest's
    unraisable plugin neither sees this fault nor leaks a hook of ours into another test.
    """
    captured: dict[str, str] = {}

    def hook(unraisable: object) -> None:
        captured["text"] = "".join(
            traceback.format_exception(
                unraisable.exc_type,  # type: ignore[attr-defined]
                unraisable.exc_value,  # type: ignore[attr-defined]
                unraisable.exc_traceback,  # type: ignore[attr-defined]
            )
        )

    previous = sys.unraisablehook
    sys.unraisablehook = hook  # type: ignore[assignment]
    try:
        p14_ctypes_callback_fault()
    finally:
        sys.unraisablehook = previous  # type: ignore[assignment]
    assert captured.get("text"), "the ctypes callback produced no traceback, so the channel would be untested"
    assert P14_MISSING_ATTRIBUTE in captured["text"], captured["text"]
    return captured["text"]


def p14_write_to_fd2_natively(text: str) -> None:
    """Write to whatever this process currently calls descriptor 2, from NATIVE code.

    `msvcrt.get_osfhandle(2)` is resolved AT WRITE TIME, so inside the capture window this handle IS the capture
    buffer's - which is exactly the property the channel depends on, and exactly what reassigning `sys.stderr` in
    Python would NOT move. Falls back to `os.write(2, ...)` where the CRT handle is unavailable; both are
    descriptor-level writes, and neither goes through `sys.stderr`.
    """
    payload = text.encode("utf-8", errors="replace")
    try:
        import msvcrt  # noqa: PLC0415 - Windows-only, imported where it is used

        handle = msvcrt.get_osfhandle(2)
        written = ctypes.c_ulong(0)
        accepted = ctypes.windll.kernel32.WriteFile(  # type: ignore[attr-defined]
            ctypes.c_void_p(handle), payload, len(payload), ctypes.byref(written), None
        )
        if accepted and int(written.value) == len(payload):
            return
    except Exception:  # noqa: BLE001 - the fallback below is the portable descriptor write
        pass
    os.write(2, payload)


def p14_emit_native_stderr_traceback() -> str:
    """What the native emulator layer does: a ctypes-swallowed traceback lands on descriptor 2."""
    text = p14_ctypes_swallowed_traceback()
    p14_write_to_fd2_natively(text)
    return text


class _P14FakeSpeakeasy:
    """The smallest object `_speakeasy_adapter` needs, with the fault placed on the branch under test.

    `load_module` returns an object WITHOUT `base`, so `_speakeasy_start_address` returns None and the adapter takes
    `se.run_module(module)`. In `granted` mode it returns an object WITH a base and an image span, so the adapter
    takes `_speakeasy_run_from_address` and the fault sits on `emu.start()` instead - the branch the plan does not
    name, which a channel that only watched `run_module` would miss.
    """

    def __init__(self, config=None, logger=None, *, mode: str = "crash") -> None:  # noqa: ANN001
        self.config = dict(config or {})
        self.logger = logger
        self.mode = mode
        self.emu = types.SimpleNamespace(add_run=lambda run: None, start=self._emu_start)

    def _emu_start(self) -> None:
        if self.mode == "granted":
            p14_emit_native_stderr_traceback()

    def load_module(self, data=None):  # noqa: ANN001 - mirror of the third-party signature
        if self.mode == "granted":
            return types.SimpleNamespace(base=0x400000, image_size=0x2000, entry_points=[])
        return types.SimpleNamespace()

    def run_module(self, module=None):  # noqa: ANN001 - mirror of the third-party signature
        if self.mode == "crash":
            p14_emit_native_stderr_traceback()
        return None

    def get_report(self):
        """`{}` is what a run that died inside Speakeasy's own handler returns; `_speakeasy_stop([])` is then the
        measured FAILED / EMULATOR_NO_REPORT classification the audit recorded."""
        return {}


class _P14FakeSpeakeasyPackage:
    """`sys.modules["speakeasy"]`, installed for the duration of a `with` block and removed afterwards.

    A CONTEXT MANAGER, NOT A MODULE-LEVEL PATCH: the previous wave's recorded defect was a fixture that patched a
    class attribute and leaked into every other test in the process. This restores the exact previous mapping.
    """

    def __init__(self, mode: str = "crash") -> None:
        self.mode = mode
        self.saved: dict[str, object] = {}

    def __enter__(self) -> "_P14FakeSpeakeasyPackage":
        root = Path(tempfile.mkdtemp(prefix="p14-test-speakeasy-"))
        init = root / "__init__.py"
        init.write_text("# p14 test stub\n", encoding="utf-8")
        module = types.ModuleType("speakeasy")
        module.__file__ = str(init)
        module.Speakeasy = lambda config=None, logger=None: _P14FakeSpeakeasy(  # noqa: E731
            config=config, logger=logger, mode=self.mode
        )
        profiler = types.ModuleType("speakeasy.profiler")

        class Run:
            def __init__(self) -> None:
                self.start_addr = 0
                self.type = ""
                self.args: list[object] = []

        profiler.Run = Run
        module.profiler = profiler
        for name, value in (("speakeasy", module), ("speakeasy.profiler", profiler)):
            self.saved[name] = sys.modules.get(name)
            sys.modules[name] = value
        return self

    def __exit__(self, *_exc: object) -> None:
        for name, value in self.saved.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value  # type: ignore[assignment]


def p14_request(payload: bytes = P14_MZ_PAYLOAD, *, entry_address: int = 0x1000000) -> object:
    """A granted-bytes request, shaped like the one `emulation/policy.request_for_granted_window` builds."""
    return SimulationRequest(
        simulator="speakeasy",
        sample_path="",
        timeout_seconds=8,
        instruction_budget=900_000,
        allow_execution=True,
        worker_isolated=True,
        input_bytes=payload,
        input_sha256=hashlib.sha256(payload).hexdigest(),
        architecture="x86",
        entry_address=entry_address,
        max_output_bytes=65536,
        worker_identity="p14-worker",
        worker_image_digest="sha256:" + "b" * 64,
    )


def p14_binding(task_id: str, attempt: int = 1) -> object:
    return EmulatorDiagnosticBinding(
        task_id=task_id,
        revision_id=f"{task_id}-revision",
        content_sha256=hashlib.sha256(P14_MZ_PAYLOAD).hexdigest(),
        worker_attempt=attempt,
        started_at="2026-09-26T00:00:00+00:00",
        finished_at="2026-09-26T00:00:01+00:00",
        source="pytest fixture",
    )


def p14_observation_for(request: object, **kwargs: object) -> dict:
    """Capture the production observation for one request without the adapter: the primitive under test."""
    with _capture_emulator_stderr() as capture:
        p14_emit_native_stderr_traceback()
    observation = capture.observation(request, **kwargs)  # type: ignore[arg-type]
    assert isinstance(observation, dict), "the fd 2 window produced no observation at all"
    return observation


# -----------------------------------------------------------------------------------------------------------
# The observation itself: structured, bounded, and NOT a claim.
# -----------------------------------------------------------------------------------------------------------
def test_the_fd2_traceback_is_captured_as_a_structured_observation() -> None:
    """PRODUCER: a ctypes-swallowed traceback becomes fields, not a string in a log nobody reads."""
    observation = p14_observation_for(p14_request())
    assert observation["event"] == EMULATOR_STDERR_EVENT
    assert observation["traceback_recognised"] is True, (
        "the channel did not recognise the traceback it exists to catch"
    )
    assert observation["exception_type"] == "AttributeError", observation["exception_type"]
    assert P14_MISSING_ATTRIBUTE in str(observation["exception_message"]), observation["exception_message"]
    frame = observation["traceback_last_frame"]
    assert frame.get("file") and frame.get("line") and frame.get("function"), frame
    assert observation["bytes_captured"] > 0
    assert re.fullmatch(r"[0-9a-f]{64}", str(observation["captured_sha256"])), (
        "the capture has no verifiable digest"
    )
    excerpt = str(observation["text_excerpt"])
    assert P14_MISSING_ATTRIBUTE in excerpt and P14_RAW_TRACEBACK_MARKER in excerpt, (
        "the retained excerpt is not the captured traceback"
    )
    assert len(excerpt.encode("utf-8")) <= observation["bytes_captured"]


def test_the_diagnostic_observation_is_not_a_claim_and_lands_in_no_behaviour_bucket() -> None:
    """EC-2: the emulator's own stderr is not an observed behaviour of the SAMPLE.

    `SimulationResult._observation_buckets` classifies by substring, so a diagnostic whose event or kind happened to
    contain `api`, `memory`, `network` or `unsupported` would be published as an attempted call. This measures that it
    is classified into NOTHING, and that the record itself refuses the claim role.
    """
    request = p14_request()
    with _P14FakeSpeakeasyPackage("crash"):
        result = _speakeasy_adapter(request)
    payload = result.as_dict()
    diagnostic = next(
        item for item in payload["observations"] if str(item.get("event")) == EMULATOR_STDERR_EVENT
    )
    assert diagnostic["is_claim"] is False
    assert diagnostic["claim_id"] is None
    assert diagnostic["nature"] == EMULATOR_STDERR_NATURE
    capture_id = str(diagnostic["capture_id"])
    buckets = {
        name: value
        for name, value in payload.items()
        if isinstance(value, list) and name not in {"observations", "limitations", "assumptions"}
    }
    carriers = [
        name for name, rows in buckets.items()
        if any(isinstance(row, dict) and str(row.get("capture_id") or "") == capture_id for row in rows)
    ]
    assert carriers == [], f"the diagnostic was published as an observed behaviour: {carriers}"
    assert "unsupported_apis" in buckets and buckets["unsupported_apis"] == []


def test_a_normal_run_creates_no_error_observation_or_limitation() -> None:
    """NEGATIVE: a run that writes nothing to fd 2 and raises nothing must create NO error record.

    Two halves, because either could invent one: the silent CAPTURE WINDOW, and the whole real adapter on a clean
    emulator run. A channel that always emitted a record would make "the emulator faulted" unreadable.
    """
    request = p14_request()
    with _capture_emulator_stderr() as silent:
        pass
    assert silent.captured == b"", "the window captured text from a silent block"
    assert silent.observation(request) is None, "a silent window produced an observation"
    with _P14FakeSpeakeasyPackage("clean"):
        clean = _speakeasy_adapter(request)
    assert not [item for item in clean.observations if str(item.get("event")) == EMULATOR_STDERR_EVENT], (
        f"a normal run produced a diagnostic observation: {clean.observations!r}"
    )
    assert not [text for text in clean.limitations if P14_SUMMARY_MARKER in text], clean.limitations


def test_the_official_limitation_cites_the_summary_and_never_the_raw_stderr() -> None:
    """CONSUMER: the limitation names the cause, and the raw simulator text stays out of the published sentence."""
    with _P14FakeSpeakeasyPackage("crash"):
        result = _speakeasy_adapter(p14_request())
    assert (result.status, result.stop_reason) == ("FAILED", "EMULATOR_NO_REPORT")
    cited = [text for text in result.limitations if P14_SUMMARY_MARKER in text]
    assert len(cited) == 1, f"the limitation did not cite the diagnostic summary: {result.limitations!r}"
    assert "AttributeError" in cited[0] and P14_MISSING_ATTRIBUTE in cited[0], cited[0]
    assert P14_RAW_TRACEBACK_MARKER not in cited[0], (
        f"the raw stderr text was published as the limitation: {cited[0]!r}"
    )
    assert f"[{P14_SUMMARY_MARKER}]" not in cited[0]


def test_both_speakeasy_call_sites_are_inside_the_capture() -> None:
    """BOTH branches, not only the one the plan names.

    MEASURED: `_speakeasy_start_address` returns an address when the module exposes a base and the granted entry is
    inside it, and that branch calls `_speakeasy_run_from_address` - never `se.run_module`. A capture wired around
    `run_module` alone would be blind on exactly the runs that reach real code.
    """
    run_module_request = p14_request(entry_address=0x1000000)
    with _P14FakeSpeakeasyPackage("crash"):
        run_module_result = _speakeasy_adapter(run_module_request)
    granted_request = p14_request(entry_address=0x401000)
    module = _P14FakeSpeakeasy(mode="granted").load_module(data=P14_MZ_PAYLOAD)
    start_address = _speakeasy_start_address(granted_request, module)
    assert start_address == 0x401000, (
        f"the fixture did not reach the granted-start branch (start_address={start_address!r}), so the assertion "
        "below would be vacuous"
    )
    with _P14FakeSpeakeasyPackage("granted"):
        granted_result = _speakeasy_adapter(granted_request)
    for name, result in (("run_module", run_module_result), ("granted_start", granted_result)):
        events = [str(item.get("event")) for item in result.observations]
        assert EMULATOR_STDERR_EVENT in events, f"the {name} branch was not captured: {events!r}"
        assert any(P14_SUMMARY_MARKER in text for text in result.limitations), (
            f"the {name} branch did not cite the diagnostic: {result.limitations!r}"
        )


def test_the_bound_has_a_configuration_source_and_names_what_it_removed() -> None:
    """M5: the retained text is BOUNDED, the bound is CONFIGURED, and the lines it removed are enumerated.

    Two sources, both measured: the operator override (`EMULATOR_STDERR_BOUND_ENV`) and the configured per-run output
    budget (`request.max_output_bytes` <- `Settings.simulation_max_output_bytes`) capped by the named ceiling. What is
    asserted about the remainder is the SET DIFFERENCE, not a count: the removed line identities must be listed.
    """
    request = p14_request()
    assert _emulator_stderr_text_bound(request) == 4096, (
        "the default bound is not the configured budget's cap"
    )
    with p14_override_bound("64"):
        assert _emulator_stderr_text_bound(request) == 64, "the operator override was ignored"
        observation = p14_observation_for(request)
    boundary = observation["stderr_text_bound"]
    assert boundary["cap"] == 64 and boundary["cap_source"] == EMULATOR_STDERR_BOUND_SOURCE
    assert boundary["enumerated_count"] == boundary["retrieved_count"] + boundary["unexpanded_count"]
    assert boundary["unexpanded_count"] > 0, "the 64-byte bound removed nothing, so it proves nothing"
    assert boundary["expected_minus_actual"], "the removed lines are not enumerated"
    assert boundary["actual_minus_expected"] == []
    assert observation["text_truncated"] is True
    assert len(observation["text_excerpt"].encode("utf-8")) <= 64


@contextmanager
def p14_override_bound(value: str) -> object:
    """Set the documented operator override and put the environment back exactly as it was."""
    previous = os.environ.get(EMULATOR_STDERR_BOUND_ENV)
    os.environ[EMULATOR_STDERR_BOUND_ENV] = value
    try:
        yield value
    finally:
        if previous is None:
            os.environ.pop(EMULATOR_STDERR_BOUND_ENV, None)
        else:
            os.environ[EMULATOR_STDERR_BOUND_ENV] = previous


# -----------------------------------------------------------------------------------------------------------
# CONCURRENCY: fd 2 is process-global, so attribution must be proved, not assumed.
# -----------------------------------------------------------------------------------------------------------
def test_the_channel_reads_the_descriptor_and_not_sys_stderr() -> None:
    """The reason this is an `os.dup2` redirect and not `contextlib.redirect_stderr`.

    A write made to descriptor 2 lands in the capture even while `sys.stderr` points somewhere else, and the decoy
    receives NOTHING. That is the whole difference: a native/ctypes layer writes to the descriptor, so a channel built
    on `sys.stderr` reassignment would observe nothing at all on the real defect.
    """
    request = p14_request()
    decoy = io.StringIO()
    with redirect_stderr(decoy):
        with _capture_emulator_stderr() as capture:
            p14_emit_native_stderr_traceback()
        observation = capture.observation(request)
    assert isinstance(observation, dict)
    assert P14_MISSING_ATTRIBUTE in str(observation["text_excerpt"]), (
        "the descriptor-level write was not captured"
    )
    assert decoy.getvalue() == "", (
        f"the write went through sys.stderr, so this test does not exercise the descriptor: {decoy.getvalue()!r}"
    )
    assert observation["traceback_last_frame"].get("function") == "callback"


def test_two_threads_in_one_process_never_cross_attribute_their_stderr() -> None:
    """Two runs at once in ONE process: one faults, the other only prints.

    The window is serialized by a module-level lock (fd 2 cannot be split between two threads). Both threads keep their
    window OPEN for the same fixed span and write at the END of it, which is what makes the measurement deterministic
    in both directions: with the lock the two windows are disjoint intervals, and WITHOUT it the second `dup2` steals
    the descriptor from the first, so the first run's bytes never reach its own buffer. Exclusivity is read off the
    window boundaries the capture itself records (`monotonic_started`/`monotonic_finished`, both set inside the lock)
    rather than off a comment.
    """
    fault = "P14-OTHER-RUN-NOISE"
    results: dict[str, object] = {}
    started = threading.Barrier(2)

    def raising_thread() -> None:
        request = p14_request()
        started.wait()
        with _capture_emulator_stderr() as capture:
            time.sleep(0.1)
            p14_emit_native_stderr_traceback()
        results["raiser"] = (request, capture.captured, capture.observation(request), capture)

    def printing_thread() -> None:
        request = p14_request(b"MZ" + bytes(range(128)))
        started.wait()
        with _capture_emulator_stderr() as capture:
            time.sleep(0.1)
            p14_write_to_fd2_natively(f"{fault}\n")
        results["printer"] = (request, capture.captured, capture.observation(request), capture)

    threads = [threading.Thread(target=raising_thread), threading.Thread(target=printing_thread)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert len(results) == 2, f"a thread did not finish: {sorted(results)}"
    raiser_request, raiser_bytes, raiser_observation, raiser_capture = results["raiser"]  # type: ignore[misc]
    printer_request, printer_bytes, printer_observation, printer_capture = results["printer"]  # type: ignore[misc]
    first, second = sorted(
        ((raiser_capture.monotonic_started, raiser_capture.monotonic_finished),
         (printer_capture.monotonic_started, printer_capture.monotonic_finished))
    )
    assert first[1] <= second[0], (
        f"two capture windows overlapped ({first!r} and {second!r}), so fd 2 was shared between runs"
    )
    assert raiser_bytes, "the faulting thread captured nothing"
    assert printer_bytes, (
        "the printing thread captured nothing: its descriptor was taken by the other run"
    )
    # NO CROSS-ATTRIBUTION, in both directions.
    assert fault.encode() not in raiser_bytes, (
        f"the faulting run was handed another run's stderr: {raiser_bytes[:200]!r}"
    )
    assert P14_MISSING_ATTRIBUTE.encode() not in printer_bytes, (
        f"the printing run was handed another run's traceback: {printer_bytes[:200]!r}"
    )
    assert raiser_observation is not None and raiser_observation["is_error_observation"] is True
    assert printer_observation is not None and printer_observation["is_error_observation"] is False, (
        f"benign stderr was recorded as an error observation: {printer_observation!r}"
    )
    # The attribution is readable FROM each record: it carries the identity of the request it captured for.
    assert raiser_observation["binding"]["request_input_sha256"] == raiser_request.input_sha256
    assert printer_observation["binding"]["request_input_sha256"] == printer_request.input_sha256
    assert raiser_request.input_sha256 != printer_request.input_sha256
    assert re.fullmatch(r"[0-9a-f]{32}", str(raiser_observation["capture_id"])), (
        "the record does not identify the window it came from"
    )
    assert raiser_observation["captured_at"]["finished_at"], "the window has no closing timestamp"


def test_two_tasks_in_one_process_each_receive_their_own_diagnostic() -> None:
    """Two contexts, one process: each observation carries ITS OWN task/revision/content identity.

    The binding is a `ContextVar`, so a thread that bound nothing cannot read another thread's row identity - which is
    what makes `task_id`/`revision_id`/`worker_attempt` trustworthy once a worker wrapper binds them. A process-global
    binding would attribute the second task's fault to the first, which is the cross-attribution the plan forbids.
    """
    seen: dict[str, dict] = {}
    started = threading.Barrier(2)

    def worker(name: str, attempt: int, request: object) -> None:
        started.wait()
        with bind_emulator_diagnostic_context(p14_binding(name, attempt)):
            seen[name] = p14_observation_for(request)

    requests = {
        "p14-task-a": p14_request(),
        "p14-task-b": p14_request(b"MZ" + bytes(range(64))),
    }
    threads = [
        threading.Thread(target=worker, args=(name, index + 1, request))
        for index, (name, request) in enumerate(requests.items())
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert set(seen) == set(requests), f"a context produced no observation: {sorted(seen)}"
    for name, request in requests.items():
        binding = seen[name]["binding"]
        assert binding["task_id"] == name, f"{name} received {binding['task_id']!r}"
        assert binding["revision_id"] == f"{name}-revision"
        assert binding["content_sha256"] == hashlib.sha256(P14_MZ_PAYLOAD).hexdigest()
        assert binding["request_input_sha256"] == request.input_sha256
        assert binding["source"] == "pytest fixture"
    assert seen["p14-task-a"]["binding"]["worker_attempt"] == 1
    assert seen["p14-task-b"]["binding"]["worker_attempt"] == 2
    # A thread that binds NOTHING reports an empty identity rather than inheriting the neighbour's.
    assert emulator_diagnostic_binding() is None
    unbound = p14_observation_for(p14_request())
    assert unbound["binding"]["task_id"] == ""
    assert unbound["binding"]["source"].startswith("unbound at the adapter seam")


# -----------------------------------------------------------------------------------------------------------
# The DURABLE copy: one Evidence row, bound by SQL to task / revision / content hash / ToolRun timestamps.
# -----------------------------------------------------------------------------------------------------------
#: The revision-bound SELECT. Every value the plan demands is read HERE, in one statement, from the row that actually
#: carries the observation: `evidence.task_id`, the revision of that task, the artifact content hash from the row's own
#: anchor, and the ToolRun's database `started_at`/`finished_at`. `worker_attempt` comes from the retry record when the
#: task was retried; the ToolRun row id IS the attempt's own identity, which is why both are selected.
P14_BINDING_SQL = (
    "SELECT e.id AS evidence_id, e.task_id AS task_id, r.id AS revision_id, "
    "json_extract(e.anchor, '$.content_sha256') AS content_sha256, "
    "tr.id AS tool_run_id, tr.started_at AS started_at, tr.finished_at AS finished_at, "
    "t.started_at AS task_started_at, t.finished_at AS task_finished_at, "
    "COALESCE(f.attempt_number, 0) AS worker_attempt "
    "FROM evidence AS e "
    "JOIN analysis_tasks AS t ON t.id = e.task_id "
    "JOIN report_revisions AS r ON r.task_id = e.task_id "
    "JOIN tool_runs AS tr ON tr.id = e.tool_run_id "
    "LEFT JOIN analysis_failures AS f ON f.task_id = e.task_id "
    "WHERE e.task_id = :task_id AND e.kind = 'simulation_result' "
    "ORDER BY e.created_at"
)
#: The observation is read back out of the STORED payload by SQL, so the test cannot pass on an in-memory object.
P14_OBSERVATION_SQL = (
    "SELECT json_extract(e.value, '$.observations') FROM evidence AS e "
    "WHERE e.task_id = :task_id AND e.kind = 'simulation_result' "
    "AND json_extract(e.value, '$.stop_reason') = 'EMULATOR_NO_REPORT'"
)


class P14DiagnosticFixture:
    """A real `analyze_submission` run whose revision carries a REAL emulator diagnostic.

    The emulator payload is produced by the production adapter (with the third-party package stubbed) and written as
    an `Evidence` row at the FREEZE seam - the same seam `p13-seam-probe.py` used, and for the same measured reason:
    the frozen snapshot is what the report is projected from, so a row inserted there enters the REAL publish path
    without editing the product. The row's `tool_runs` parent is inserted in the same transaction, so the binding this
    file asserts about is a row of the product's own schema rather than a fixture attribute.
    """

    def __init__(self, settings: Settings, *, seed_diagnostic: bool = True) -> None:
        self.settings = settings
        self.seed_diagnostic = seed_diagnostic
        self.database = Database(settings.database_url)
        self.database.create_schema()
        self.service = AnalysisService(
            settings, self.database, LocalContentStore(settings.content_store_path)
        )
        self.sample_bytes = sample_zip_bytes()
        self.sample_sha256 = hashlib.sha256(self.sample_bytes).hexdigest()
        self.payload: dict = {}
        self.summary = ""
        if seed_diagnostic:
            with _P14FakeSpeakeasyPackage("crash"):
                self.payload = _speakeasy_adapter(p14_request()).as_dict()
            self.summary = _emulator_diagnostic_summary(
                next(
                    item for item in self.payload["observations"]
                    if str(item.get("event")) == EMULATOR_STDERR_EVENT
                )
            )
        self.tool_run_started_at = datetime(2026, 9, 26, 1, 2, 3, tzinfo=timezone.utc)
        self.tool_run_finished_at = datetime(2026, 9, 26, 1, 2, 4, tzinfo=timezone.utc)
        self.seeded = self._analyse_with_diagnostic_evidence()
        self.task_id = str(self.seeded["task_id"])
        self.revision_id = str(self.seeded["revision_id"])
        self.tool_run_id = str(self.seeded.get("tool_run_id") or "")
        self.evidence_id = str(self.seeded.get("evidence_id") or "")

    def _analyse_with_diagnostic_evidence(self) -> dict[str, object]:
        if not self.seed_diagnostic:
            # THE CLEAN VARIANT IS THE SAME PIPELINE, not a different one: no seam, no seeded row, the product's own
            # `analyze_submission` exactly as it runs in production.
            case = self.service.create_case("p14 diagnostic channel (clean)")
            result = self.service.analyze_submission(
                case_id=case.id, filename="p14-clean-bundle.zip", content=self.sample_bytes
            )
            return {"task_id": result.task_id, "revision_id": result.report_revision_id}

        service = self.service
        original_freeze = AnalysisService._freeze_snapshot
        seeded: dict[str, object] = {}
        # Bound as LOCALS: the hook is installed with `types.MethodType`, so its first argument is the SERVICE, and
        # `self.tool_run_started_at` inside it would be an AttributeError on the service (measured - that is how the
        # first version of this fixture failed).
        payload = json.loads(json.dumps(self.payload))
        started_at = self.tool_run_started_at
        finished_at = self.tool_run_finished_at

        def freeze_with_diagnostic(service_self, session, task):  # noqa: ANN001 - production signature
            artifact = session.scalars(
                sa_select(Artifact).where(Artifact.task_id == task.id).order_by(Artifact.created_at)
            ).first()
            if artifact is None:
                raise SystemExit("the fixture needs an artifact on this task before the snapshot is frozen")
            tool_run = ToolRun(
                task_id=task.id,
                artifact_id=artifact.id,
                tool_name="p14-controlled-emulator",
                tool_version="0.1.0",
                status="FAILED",
                parameters={"fixture": "p14"},
                environment={"fixture": "p14"},
                output={"result_count": 1},
                error="EMULATOR_NO_REPORT",
                started_at=started_at,
                finished_at=finished_at,
            )
            session.add(tool_run)
            session.flush()
            evidence = Evidence(
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=tool_run.id,
                module="static_triage",
                kind="simulation_result",
                nature=evidence_nature_for_simulation_status(
                    payload.get("status"), stop_reason=payload.get("stop_reason")
                ),
                value=payload,
                anchor={
                    "type": "controlled_emulation",
                    "artifact_id": artifact.id,
                    "content_sha256": artifact.content_sha256,
                    "logical_path": artifact.logical_path,
                },
            )
            session.add(evidence)
            session.flush()
            seeded.update(
                task_id=str(task.id), tool_run_id=str(tool_run.id), evidence_id=str(evidence.id)
            )
            return original_freeze(service_self, session, task)

        service._freeze_snapshot = types.MethodType(  # type: ignore[method-assign]
            freeze_with_diagnostic, service
        )
        case = service.create_case("p14 diagnostic channel")
        result = service.analyze_submission(
            case_id=case.id, filename="p14-bundle.zip", content=self.sample_bytes
        )
        seeded["revision_id"] = result.report_revision_id
        return seeded

    def sql(self, statement: str, parameters: dict[str, object] | None = None) -> list[tuple]:
        connection = self.database.engine.raw_connection()
        try:
            cursor = connection.cursor()
            cursor.execute(statement, parameters or {})
            return [tuple(row) for row in cursor.fetchall()]
        finally:
            connection.close()

    def binding_rows(self, task_id: str | None = None) -> list[tuple]:
        return self.sql(P14_BINDING_SQL, {"task_id": task_id or self.task_id})

    def stored_observations(self) -> list[dict]:
        rows = self.sql(P14_OBSERVATION_SQL, {"task_id": self.task_id})
        assert rows, "no stored emulation payload carries the diagnostic stop reason"
        return [item for item in json.loads(rows[0][0] or "[]") if isinstance(item, dict)]

    def official_markdown(self) -> str:
        rows = self.sql(
            "SELECT markdown FROM report_revisions WHERE id = :revision_id",
            {"revision_id": self.revision_id},
        )
        assert len(rows) == 1, rows
        return str(rows[0][0])

    def revision_document(self) -> dict:
        rows = self.sql(
            "SELECT document FROM report_revisions WHERE id = :revision_id",
            {"revision_id": self.revision_id},
        )
        assert len(rows) == 1, rows
        return dict(json.loads(rows[0][0]))


@pytest.fixture(scope="module")
def p14_fixture(tmp_path_factory) -> P14DiagnosticFixture:
    return P14DiagnosticFixture(probe_settings(tmp_path_factory.mktemp("p14"), "p14"))


def test_the_error_is_retrievable_by_the_kind_query_the_workbench_uses(
    p14_fixture: P14DiagnosticFixture,
) -> None:
    """A REAL error retrieved through a query: the workbench's kind-driven Evidence retrieval path.

    The evidence index (`static/evidence_index.py`) builds exact selectors for a fixed list of kinds and says of
    itself that "kind-driven retrieval still exposes every other immutable row directly from the Evidence table".
    `simulation_result` is one of those kinds, so this is the query a workbench Evidence view makes, and it must
    return the row AND the diagnostic inside it.
    """
    assert evidence_search_keys(kind="simulation_result", value={}, anchor={}) == (), (
        "simulation_result unexpectedly gained selector keys, so this test would not exercise the kind path"
    )
    rows = p14_fixture.sql(
        "SELECT id, tool_run_id, nature, json_extract(value, '$.stop_reason') FROM evidence "
        "WHERE task_id = :task_id AND kind = 'simulation_result' AND tool_run_id = :tool_run_id",
        {"task_id": p14_fixture.task_id, "tool_run_id": p14_fixture.tool_run_id},
    )
    assert len(rows) == 1, f"the kind query did not retrieve the diagnostic row: {rows!r}"
    evidence_id, tool_run_id, nature, stop_reason = rows[0]
    assert evidence_id == p14_fixture.evidence_id
    assert nature == "EMULATION_OBSERVED", nature
    assert stop_reason == "EMULATOR_NO_REPORT"
    observations = p14_fixture.stored_observations()
    diagnostic = next(
        item for item in observations if str(item.get("event")) == EMULATOR_STDERR_EVENT
    )
    assert diagnostic["exception_type"] == "AttributeError"
    assert P14_MISSING_ATTRIBUTE in str(diagnostic["exception_message"])
    assert _emulator_diagnostic_summary(diagnostic) == p14_fixture.summary


def test_every_diagnostic_is_bound_to_its_task_revision_content_hash_and_tool_run(
    p14_fixture: P14DiagnosticFixture,
) -> None:
    """M3: ONE revision-bound statement reads task / revision / content hash / attempt / DB timestamps."""
    rows = p14_fixture.binding_rows()
    assert rows, "the binding SQL returned nothing, so nothing below it is bound"
    (
        evidence_id, task_id, revision_id, content_sha256, tool_run_id,
        started_at, finished_at, task_started_at, task_finished_at, worker_attempt,
    ) = rows[0]
    assert task_id == p14_fixture.task_id
    assert revision_id == p14_fixture.revision_id
    assert tool_run_id == p14_fixture.tool_run_id
    assert content_sha256 == p14_fixture.sample_sha256, (
        "the row's content hash is not the submitted bytes' digest"
    )
    assert str(started_at).startswith("2026-09-26 01:02:03"), started_at
    assert str(finished_at).startswith("2026-09-26 01:02:04"), finished_at
    assert task_started_at and task_finished_at, "the task's own database window is unset"
    assert int(worker_attempt) >= 0
    assert evidence_id == p14_fixture.evidence_id


def test_a_wrong_task_returns_no_binding_row_for_the_same_sql(
    p14_fixture: P14DiagnosticFixture,
) -> None:
    """M3 NEGATIVE CONTROL: the same statement returns NOTHING for a task that is not this one."""
    assert p14_fixture.binding_rows(), "the control is vacuous unless the right task does return a row"
    assert p14_fixture.binding_rows("00000000-0000-4000-8000-000000000000") == []
    other = p14_fixture.sql(
        "SELECT id FROM analysis_tasks WHERE id != :task_id LIMIT 1", {"task_id": p14_fixture.task_id}
    )
    for row in other:
        assert p14_fixture.binding_rows(str(row[0])) == [], (
            "another task's id returned this task's diagnostic row"
        )


def test_the_official_body_of_the_same_revision_states_the_summary_and_not_the_traceback(
    p14_fixture: P14DiagnosticFixture,
) -> None:
    """M4: producer -> consumer -> the OFFICIAL Markdown RE-RENDERED from the same revision.

    The body is read from `report_revisions.markdown`, and the re-render is compared against it, so the value is not
    read out of a JSON file. The RAW traceback must be absent: stderr is untrusted simulator text and the published
    sentence may only cite the summary.
    """
    stored = p14_fixture.official_markdown()
    rerendered = render_official_markdown(p14_fixture.revision_document())
    assert rerendered == stored, "the stored body is not this document's render"
    assert p14_fixture.summary, "the fixture produced no summary to look for"
    assert p14_fixture.summary in stored, (
        "the official body does not cite the diagnostic summary; "
        f"body tail={stored[-1200:]!r}"
    )
    assert P14_RAW_TRACEBACK_MARKER not in stored, (
        "the raw stderr traceback was published into the official body"
    )
    assert "capture_id" not in stored and "captured_sha256" not in stored, (
        "raw observation fields leaked into the reader-facing body"
    )


def test_the_diagnostic_never_becomes_a_claim_row(p14_fixture: P14DiagnosticFixture) -> None:
    """THE PLAN'S RULE, measured in the database: the diagnostic exists, and NO Claim is built from it.

    A Claim is a database row, and the task's own pipeline does create claims (so "zero claims" would be a false
    statement about the product). What is asserted is the relation the plan forbids: no claim text carries the
    diagnostic, and nothing links this Evidence row to a claim.
    """
    diagnostic_rows = p14_fixture.sql(
        "SELECT id FROM evidence WHERE task_id = :task_id "
        "AND json_extract(value, '$.stop_reason') = 'EMULATOR_NO_REPORT'",
        {"task_id": p14_fixture.task_id},
    )
    assert len(diagnostic_rows) == 1, "the diagnostic row is missing, so the control below is vacuous"
    evidence_id = str(diagnostic_rows[0][0])
    assert evidence_id == p14_fixture.evidence_id
    # NON-VACUITY: this task's pipeline does create claims, so the exclusions below are about the diagnostic.
    total_claims = p14_fixture.sql(
        "SELECT count(*) FROM claims WHERE task_id = :task_id", {"task_id": p14_fixture.task_id}
    )
    assert int(total_claims[0][0]) > 0, "the fixture task has no claims, so the exclusions prove nothing"
    carried = p14_fixture.sql(
        "SELECT id, statement FROM claims WHERE task_id = :task_id AND ("
        "statement LIKE '%get_peb_ldr%' OR statement LIKE '%emulator stderr%' "
        "OR statement LIKE '%Traceback (most recent call last)%' OR statement LIKE '%AttributeError%')",
        {"task_id": p14_fixture.task_id},
    )
    assert carried == [], f"emulator stderr was published as a Claim: {carried!r}"
    links = p14_fixture.sql(
        "SELECT claim_id FROM claim_evidence WHERE evidence_id = :evidence_id", {"evidence_id": evidence_id}
    )
    assert links == [], f"the diagnostic Evidence row was linked to a Claim: {links!r}"


def test_the_conclusion_headings_the_tool_error_test_filters_on_are_the_ones_the_product_prints(
    p14_fixture: P14DiagnosticFixture,
) -> None:
    """ANTI-VACUITY for `CONCLUSION_HEADINGS`, after that constant was silently corrupted once.

    MEASURED (P-1.4): a PowerShell `Get-Content -Raw | Set-Content -Encoding utf8` round trip decoded this file as
    CP936, so `CONCLUSION_HEADINGS` became a run of private-use-area characters. The test that filters the body's lines
    through it then asserted that a string the product can never print is absent - true by construction, and green. A
    literal used as a FILTER is only meaningful if the product really emits it, so this measures that.
    """
    assert CONCLUSION_HEADINGS == ("## 分析结论", "### 分析结论"), (
        f"the heading literal is not the product's own text: {CONCLUSION_HEADINGS!r}"
    )
    body = p14_fixture.official_markdown()
    matched = [line for line in body.splitlines() if any(line.startswith(h) for h in CONCLUSION_HEADINGS)]
    assert matched, (
        "no line of the official body starts with a conclusion heading, so every assertion that filters on "
        f"CONCLUSION_HEADINGS is vacuously true: {CONCLUSION_HEADINGS!r}"
    )


def test_a_diagnostic_free_run_adds_nothing_to_any_of_those_channels(
    tmp_path_factory,
) -> None:
    """NEGATIVE for the end-to-end: the SAME pipeline on a task with NO diagnostic row.

    Without this, "the summary is in the body" would also be satisfied by a channel that always published something,
    and "the binding SQL returns a row" would be satisfied by a query that ignores its predicate. The clean run is the
    product's own `analyze_submission` with no seam installed at all.
    """
    fixture = P14DiagnosticFixture(
        probe_settings(tmp_path_factory.mktemp("p14-clean"), "p14-clean"), seed_diagnostic=False
    )
    assert fixture.binding_rows() == [], "a diagnostic-free run produced a bound diagnostic row"
    assert fixture.sql(
        "SELECT id FROM evidence WHERE task_id = :task_id AND "
        "json_extract(value, '$.stop_reason') = 'EMULATOR_NO_REPORT'",
        {"task_id": fixture.task_id},
    ) == [], "a diagnostic-free run produced an EMULATOR_NO_REPORT evidence row"
    # NON-VACUITY: the run really happened and really published a body with an emulation chapter, so the absence above
    # is a statement about the diagnostic rather than about an empty database.
    total = fixture.sql(
        "SELECT count(*) FROM evidence WHERE task_id = :task_id", {"task_id": fixture.task_id}
    )
    assert int(total[0][0]) > 0, "the clean run produced no evidence at all"
    body = fixture.official_markdown()
    assert body.strip(), "the clean run published no body"
    assert P14_SUMMARY_MARKER not in body and P14_RAW_TRACEBACK_MARKER not in body
    assert "[pipeline]" in body, "the operational-limitations block vanished for the clean task"
