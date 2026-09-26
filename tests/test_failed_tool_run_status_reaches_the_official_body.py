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

import hashlib
import io
import json
import tempfile
import types
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from threat_report_agent.analyst_report import (
    OPERATIONAL_LIMITATIONS_HEADING,
    compose_official_markdown,
    render_official_markdown,
)
from threat_report_agent.config import ModelProviderSettings, Settings
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import ToolRun
from threat_report_agent.service import AnalysisService

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
