"""The agent's report deliverable is a file, and the product provides one write.

DSH's own file tools are disabled by the host bundle, and re-enabling them from
an agent preset or from the profile patch did not work across four attempts (see
``.scratch/first-usable-g5-evidence.md``, rounds 13-20). Rather than keep
fighting the harness, the product exposes the single write it actually needs.

The write is deliberately narrow: a flat ``.md`` basename under
``REPORT_OUTPUT_ROOT``. No traversal, no absolute path, no subdirectory, and the
sample workspace stays read-only.

Writing the file also attempts to publish the same text as the official report
revision through :meth:`AnalysisService.workbench_submit_analyst_draft`, so one
write keeps the file and the official body consistent. Before that, the file was
the *only* artifact: for task ``2fcc0fdc-ae32-4efd-83e6-a6c9fbc734db`` the file
held a 29,584-byte execution timeline while the newest revision held a
6,254-character digest, and a consumer of the official route never saw the
analysis. 报告合成门 (ADR-0036) still governs what may become the official body,
so the file write stays authoritative: a rejected draft is reported as data and
the agent keeps its work product.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from threat_report_agent.config import Settings
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import (
    AnalysisSnapshot,
    AnalysisTask,
    CaseRecord,
    ReportRevision,
    ThreatAnalysisContextRecord,
)
from threat_report_agent.service import AnalysisService

# Neither draft below carries a process image, endpoint or creation-flags value,
# so the only thing under test is whether the gate sees a novel fact. The
# deterministic fragments of the fixture document contain none of them.
GOOD_DRAFT = "# 分析结论\n\n样本未执行；本章只覆盖已恢复的静态事实。\n"
# A fabricated endpoint and IPv4 that the deterministic fragments do not hold.
FABRICATED_DRAFT = (
    "# 分析结论\n\n"
    "备用 C2：endpoint `http://198.51.100.7/backup.bin`，回连地址 198.51.100.7。\n"
)


@dataclass(frozen=True)
class BoundReport:
    """A DSH session bound to a task that already has one report revision."""

    service: AnalysisService
    database: Database
    root: Path
    session_id: str
    task_id: str
    base_revision_id: str
    base_markdown: str

    def revisions(self) -> list[ReportRevision]:
        with self.database.session_factory() as session:
            return list(
                session.scalars(
                    select(ReportRevision)
                    .where(ReportRevision.task_id == self.task_id)
                    .order_by(ReportRevision.created_at.asc())
                )
            )


@pytest.fixture
def bound_report(
    tmp_path: Path,
    test_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> BoundReport:
    """Bootstrap the session->task->revision chain the workbench route resolves.

    The base revision's document is the deterministic fact base the compose gate
    measures a draft against, and ``REPORT_OUTPUT_ROOT`` points at a per-test
    directory so no test writes into the deployment's ``/reports`` mount.
    """
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings,
        database,
        LocalContentStore(test_settings.content_store_path),
    )
    database.create_schema()
    root = tmp_path / "reports"
    monkeypatch.setenv("REPORT_OUTPUT_ROOT", str(root))
    base_markdown = "# 静态分析报告\n\n（确定性拼接稿，不是 agent 草稿）\n"
    with database.session_factory.begin() as session:
        case = CaseRecord(title="report file publish")
        session.add(case)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="SUCCEEDED", outcome="PARTIAL")
        session.add(task)
        session.flush()
        snapshot = AnalysisSnapshot(task_id=task.id, object_versions={})
        session.add(snapshot)
        session.flush()
        base = ReportRevision(
            task_id=task.id,
            snapshot_id=snapshot.id,
            selected_modules=[],
            document={
                "case_id": case.id,
                "task_id": task.id,
                "analysis_outcome": "PARTIAL",
                "analysis_class": "STATIC_ONLY",
                "modules": [],
            },
            markdown=base_markdown,
            author="system",
            # Pinned in the past so "newest revision" never depends on how fast
            # the test host creates the fixture relative to the first publish.
            created_at=datetime.now(UTC) - timedelta(hours=2),
        )
        session.add(base)
        session.flush()
        session.add(
            ThreatAnalysisContextRecord(
                dsh_session_id="report-file-session",
                case_id=case.id,
                active_task_id=task.id,
                state="ANALYSIS_READY",
                task_lifecycle="SUCCEEDED",
            )
        )
        base_id = base.id
        task_id = task.id
    return BoundReport(
        service=service,
        database=database,
        root=root,
        session_id="report-file-session",
        task_id=task_id,
        base_revision_id=base_id,
        base_markdown=base_markdown,
    )


def _service() -> AnalysisService:
    """A service instance is not needed: the guard runs before any session use."""
    return AnalysisService.__new__(AnalysisService)


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "../escape.md",
        "sub/dir/report.md",
        "sub\\dir\\report.md",
        "/etc/passwd.md",
        ".hidden.md",
        "report.txt",
        "report",
    ],
)
def test_unsafe_or_non_markdown_names_are_rejected(bad: str) -> None:
    with pytest.raises(ValueError):
        _service().workbench_write_report_file(
            "session-x", filename=bad, markdown="# report"
        )


def test_empty_markdown_is_rejected() -> None:
    with pytest.raises(ValueError):
        _service().workbench_write_report_file(
            "session-x", filename="report.md", markdown="   "
        )


def test_rejection_happens_before_any_session_lookup() -> None:
    """A bad name must not even reach the database."""
    # ``__new__`` gives an instance with no session factory at all; if the guard
    # did not run first, this would raise AttributeError instead of ValueError.
    with pytest.raises(ValueError):
        _service().workbench_write_report_file(
            "session-x", filename="../x.md", markdown="# report"
        )


def test_route_is_registered_and_carries_the_request_model() -> None:
    from threat_report_agent import main

    routes = {getattr(route, "path", "") for route in main.create_app().routes}
    assert "/api/v1/workbench/sessions/{dsh_session_id}/report/file" in routes
    payload = main.WorkbenchReportFileRequest(filename="r.md", markdown="# r")
    assert payload.filename == "r.md"


def test_report_root_is_a_separate_writable_mount() -> None:
    """The sample workspace is read-only, so the report root is its own volume."""
    from pathlib import Path

    compose = Path("docker-compose.yml").read_text(encoding="utf-8")
    assert "/reports:rw" in compose
    assert "/workspace:ro" in compose


def test_the_write_publishes_the_official_revision(bound_report: BoundReport) -> None:
    """One write keeps the file and the official body from drifting apart."""
    result = bound_report.service.workbench_write_report_file(
        bound_report.session_id,
        filename="sample.分析报告.md",
        markdown=GOOD_DRAFT,
        actor="dsh-agent",
    )

    assert result["written"] is True
    assert result["published"] is True
    revision_id = result["revision_id"]
    assert isinstance(revision_id, str) and revision_id
    assert revision_id != bound_report.base_revision_id
    assert "gate_violations" not in result

    written = Path(str(result["path"])).read_text(encoding="utf-8")
    assert written == GOOD_DRAFT
    revisions = bound_report.revisions()
    assert len(revisions) == 2
    published = revisions[-1]
    assert published.id == revision_id
    # The published body is the file's content: that equality is the point of
    # routing the write through the existing gate path.
    assert published.markdown == written
    assert published.parent_revision_id == bound_report.base_revision_id
    assert published.author == "dsh-agent"
    assert published.edit_kind == "AGENT_GENERATED"
    assert published.document["analyst_report_draft"] == GOOD_DRAFT
    assert published.document["analyst_report_draft_gate"] == "PASSED"


def test_rejected_draft_keeps_the_file_and_publishes_nothing(
    bound_report: BoundReport,
) -> None:
    """The gate governs the official body, never whether the agent keeps its work.

    The file stays byte-identical (it is the analyst's raw work product), no
    revision is created from ungated text, and the outcome travels in the
    payload instead of an exception -- otherwise the caller would lose the path
    and size of a file that was written.
    """
    result = bound_report.service.workbench_write_report_file(
        bound_report.session_id,
        filename="sample.分析报告.md",
        markdown=FABRICATED_DRAFT,
    )

    assert result["written"] is True
    assert result["published"] is False
    assert result["revision_id"] is None
    violations = result["gate_violations"]
    assert isinstance(violations, list) and violations
    assert any("198.51.100.7" in str(item) for item in violations)
    assert all("not in composed fragments" in str(item) for item in violations)

    written = Path(str(result["path"])).read_text(encoding="utf-8")
    assert written == FABRICATED_DRAFT
    revisions = bound_report.revisions()
    assert len(revisions) == 1
    assert revisions[0].id == bound_report.base_revision_id
    assert revisions[0].markdown == bound_report.base_markdown
    assert FABRICATED_DRAFT not in revisions[0].markdown


def test_existing_size_and_path_fields_keep_their_meaning(
    bound_report: BoundReport,
) -> None:
    """``bytes``/``written``/``path``/``filename`` keep their published contract.

    ``bytes`` is the UTF-8 size of the file on disk, not a character count, so a
    CJK report reports the size an operator sees in the filesystem.
    """
    text = "# 分析结论\n\n该样本的处置建议：保持隔离，等待人工复核。\n"
    result = bound_report.service.workbench_write_report_file(
        bound_report.session_id,
        filename="sample.分析报告.md",
        markdown=text,
    )

    assert result["schema_version"] == 1
    assert result["task_id"] == bound_report.task_id
    assert result["filename"] == "sample.分析报告.md"
    assert result["path"] == str(bound_report.root / "sample.分析报告.md")
    assert result["written"] is True
    assert result["bytes"] == len(text.encode("utf-8"))
    on_disk = Path(str(result["path"])).read_bytes()
    assert result["bytes"] == len(on_disk)
    assert on_disk.decode("utf-8") == text


def test_published_body_is_the_file_content_normalised(
    bound_report: BoundReport,
) -> None:
    """The revision body is ``draft.strip() + "\\n"``; the file is verbatim.

    ``submit_analyst_draft`` stores ``compose_official_markdown(document, draft=...)``
    and ``publish_composed_markdown`` returns the stripped candidate plus one
    trailing newline, so a draft with outer blank lines differs from the file by
    exactly that whitespace. Recording it here keeps the equality asserted in
    ``test_the_write_publishes_the_official_revision`` honest.
    """
    text = "\n\n# 分析结论\n\n本章只覆盖已恢复的静态事实。\n\n\n"
    result = bound_report.service.workbench_write_report_file(
        bound_report.session_id,
        filename="sample.分析报告.md",
        markdown=text,
    )

    assert result["bytes"] == len(text.encode("utf-8"))
    written = Path(str(result["path"])).read_text(encoding="utf-8")
    assert written == text
    revisions = bound_report.revisions()
    assert len(revisions) == 2
    assert revisions[-1].markdown == text.strip() + "\n"


def test_repeated_writes_chain_from_the_newest_revision(
    bound_report: BoundReport,
) -> None:
    """Repeated rewrites supersede by chaining, and the newest one wins.

    Item 4: each publish resolves the newest revision as its parent, so N writes
    leave the base plus N revisions and the official body is the last draft. The
    chain is the intended shape (``parent_revision_id`` + ``edit_kind`` keep the
    history immutable, as ``edit_report`` does for manual edits).

    The two publishes are pinned apart in time before the second write because
    the parent query orders by ``created_at`` alone: two revisions stamped in
    the same tick are indistinguishable to
    ``order_by(ReportRevision.created_at.desc()).limit(1)``. That gap is
    reachable -- this host's ``datetime.now(UTC)`` returned 3 distinct values
    for 2000 consecutive calls -- and is recorded here rather than asserted,
    because an unspecified order cannot be tested deterministically.
    """
    first = bound_report.service.workbench_write_report_file(
        bound_report.session_id,
        filename="sample.分析报告.md",
        markdown=GOOD_DRAFT,
    )
    assert first["published"] is True
    # Pin the first publish one hour into the past (the base revision sits two
    # hours back) so the second publish's parent is unambiguous even on a host
    # whose clock is too coarse to separate two publishes by a microsecond.
    with bound_report.database.session_factory.begin() as session:
        pinned = session.get(ReportRevision, str(first["revision_id"]))
        assert pinned is not None
        pinned.created_at = datetime.now(UTC) - timedelta(hours=1)
    second = bound_report.service.workbench_write_report_file(
        bound_report.session_id,
        filename="sample.分析报告.md",
        markdown=GOOD_DRAFT + "\n## 处置建议\n\n保持隔离并人工复核。\n",
    )
    assert second["published"] is True

    revisions = bound_report.revisions()
    assert [item.parent_revision_id for item in revisions] == [
        None,
        bound_report.base_revision_id,
        first["revision_id"],
    ]
    assert revisions[-1].id == second["revision_id"]
    assert revisions[-1].markdown == GOOD_DRAFT + "\n## 处置建议\n\n保持隔离并人工复核。\n"
    assert revisions[-1].parent_revision_id == first["revision_id"]


def test_file_route_returns_a_rejection_as_data_not_an_error(
    tmp_path: Path,
    test_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The DSH plugin renders this payload; a 4xx would hide a written file.

    ``threat_write_report_file`` maps a non-2xx to ``WRITE_REJECTED`` and loses
    the path, so the route must answer 201 with ``published: false`` when the
    gate refuses the draft. The analyst-draft route keeps its own contract: the
    same rejection is a 422 there.
    """
    import io
    import zipfile

    from fastapi.testclient import TestClient

    from threat_report_agent.main import create_app

    monkeypatch.setenv("REPORT_OUTPUT_ROOT", str(tmp_path / "reports"))
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("sample.py", "print('static')")
    with TestClient(create_app(test_settings)) as client:
        case = client.post("/api/v1/cases", json={"title": "report file route"}).json()
        submitted = client.post(
            f"/api/v1/cases/{case['id']}/tasks",
            files={"sample": ("sample.zip", archive.getvalue(), "application/zip")},
        )
        assert submitted.status_code == 202, submitted.text
        task_id = submitted.json()["task_id"]
        bound = client.post(
            f"/api/v1/workbench/tasks/{task_id}/session",
            json={"dsh_session_id": "report-file-route", "profile": "threat-static"},
        )
        assert bound.status_code == 201, bound.text

        rejected = client.post(
            "/api/v1/workbench/sessions/report-file-route/report/file",
            json={"filename": "sample.分析报告.md", "markdown": FABRICATED_DRAFT},
        )
        assert rejected.status_code == 201, rejected.text
        body = rejected.json()
        assert body["written"] is True
        assert body["published"] is False
        assert body["revision_id"] is None
        assert any("198.51.100.7" in str(item) for item in body["gate_violations"])
        assert Path(body["path"]).read_text(encoding="utf-8") == FABRICATED_DRAFT

        draft_route = client.post(
            "/api/v1/workbench/sessions/report-file-route/report/analyst-draft",
            json={"markdown": FABRICATED_DRAFT},
        )
        assert draft_route.status_code == 422, draft_route.text
        assert "not in composed fragments" in draft_route.json()["detail"]
