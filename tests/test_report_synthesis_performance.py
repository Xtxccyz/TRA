"""Report synthesis must not pay for the sealed Evidence ledger it does not read.

``_snapshot_report_context`` used to ``copy.deepcopy`` the whole Analysis Snapshot
payload and then materialise its canonical JSON as one string on every report
build.  Measured on a real 116 MB snapshot (task ``1359f2a6``, 39,837 Evidence
rows, 30 MB of ``abstract_execution_trace``): 3.9 s of deep copy + 1.0 s of
serialisation, ~400 MB of avoidable peak RSS, on every report build.

The digest covers that whole payload and 16 GB of already-sealed snapshots must
keep validating, so these tests lock down both halves of the contract:

* the digest is still exactly ``sha256(canonical_json(payload without
  content_sha256))`` - the streaming encoder must be byte-identical to
  ``json.dumps(..., ensure_ascii=True, sort_keys=True, separators=(",", ":"),
  default=str)``;
* a tampered payload is still rejected;
* the report projection no longer deep-copies the ledger, and it must therefore
  never mutate the sealed JSON or leave the ORM attribute dirty.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from sqlalchemy import inspect as sa_inspect

from threat_report_agent.models import (
    AnalysisSnapshot,
    AnalysisTask,
    Artifact,
    ContentBlob,
    Evidence,
    InvestigationThreadRecord,
    ToolRun,
)
from threat_report_agent.reporting import REPORT_MODULES
from threat_report_agent.service import AnalysisService


def _service(test_settings) -> AnalysisService:
    from threat_report_agent.content_store import LocalContentStore
    from threat_report_agent.database import Database

    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    service.database.create_schema()
    return service


def _sealed_snapshot(service: AnalysisService, *, evidence_value: dict[str, object]):
    """Freeze a real (small) snapshot through the production seal path.

    The payload carries one investigation thread whose protocol metadata lives in
    ``task.strategy_snapshot``, because enriching those rows is the one place the
    report projection rewrites the payload (copy-on-write).
    """
    case = service.create_case("report synthesis performance")
    thread_id = "thread-copy-on-write"
    with service.database.session_factory.begin() as session:
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="SUCCEEDED",
            outcome="PARTIAL",
            analysis_class="BOUNDED_STATIC_ANALYSIS",
            strategy_snapshot={
                "investigation": {
                    "thread_protocols": {
                        thread_id: {
                            "protocol": {"steps": ["seed", "verify"]},
                            "s_ladder": {"S1": "observed"},
                        }
                    }
                }
            },
        )
        session.add(task)
        session.flush()
        session.add(
            ContentBlob(
                sha256="c" * 64,
                size=1,
                media_type="application/octet-stream",
                storage_key="sha256/report-synthesis-perf",
            )
        )
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256="c" * 64,
            logical_path="Resume.pdf.exe",
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
            InvestigationThreadRecord(
                id=thread_id,
                task_id=task.id,
                artifact_id=artifact.id,
                state="COMPLETED",
                question="does the loader gate on the host clock?",
                seed_kind="artifact_triage",
                evidence_ids=[],
                hypothesis_ids=[],
                mechanism_ids=[],
                action_ids=[],
            )
        )
        session.flush()
        session.add(
            Evidence(
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static_triage",
                kind="abstract_execution_trace",
                nature="STATIC_DERIVED",
                value=evidence_value,
                anchor={"function": "FUN_140004605", "entry": "140004605"},
            )
        )
        session.flush()
        snapshot = service._freeze_snapshot(session, task)
        return snapshot.id, task.id


@pytest.mark.parametrize(
    "value",
    [
        {"a": 1, "b": [1, 2, {"c": None}], "d": True},
        {"unicode": "\u4e2d\u6587\U0001f600", "nul": "a\x00b", "lone": "\ud800"},
        {"f": 1.5, "i": -3, "big": 2**70, "t": (1, 2), "s": {"x", "y"}},
        {"content_sha256": "x", "nested": {"content_sha256": "keep me"}},
        [[[]]],
        {},
        [],
        "plain",
        5,
        None,
        True,
        {1: 2, 3: 4},
        {"deep": {"deep": {"deep": {"deep": [1, {"x": "y"}]}}}},
        {"escapes": "\t\n\r\\\"'", "high": "\uffff"},
    ],
)
def test_streaming_canonical_digest_is_byte_identical_to_the_materialised_form(value) -> None:
    expected = hashlib.sha256(AnalysisService._canonical_json(value).encode("utf-8")).hexdigest()

    assert AnalysisService._canonical_sha256(value) == expected
    assert b"".join(AnalysisService._canonical_json_chunks(value)) == (
        AnalysisService._canonical_json(value).encode("utf-8")
    )


def test_streaming_canonical_digest_excludes_content_sha256_at_top_level_only() -> None:
    payload = {"content_sha256": "sealed", "nested": {"content_sha256": "kept"}}
    streamed = b"".join(
        AnalysisService._canonical_json_chunks(payload, exclude_keys=("content_sha256",))
    )

    assert b'"content_sha256":"sealed"' not in streamed
    # The exclusion is the top-level ``content_sha256`` only; a nested key of the
    # same name is payload and must stay in the digest.
    assert b'"nested":{"content_sha256":"kept"}' in streamed
    assert streamed == AnalysisService._canonical_json(
        {"nested": {"content_sha256": "kept"}}
    ).encode("utf-8")


def test_frozen_snapshot_digest_matches_the_materialised_canonical_form(
    test_settings,
) -> None:
    """16 GB of sealed snapshots must keep validating after the streaming rewrite."""
    service = _service(test_settings)
    snapshot_id, _ = _sealed_snapshot(service, evidence_value={"steps": [{"index": 0}], "n": 1})

    with service.database.session_factory.begin() as session:
        snapshot = session.get(AnalysisSnapshot, snapshot_id)
        payload = dict(snapshot.object_versions)
        stored = payload.pop("content_sha256")
        expected = hashlib.sha256(service._canonical_json(payload).encode("utf-8")).hexdigest()

    assert stored == expected


def test_tampered_snapshot_payload_is_still_rejected(test_settings) -> None:
    service = _service(test_settings)
    snapshot_id, _ = _sealed_snapshot(service, evidence_value={"steps": [{"index": 0}], "n": 1})

    with service.database.session_factory.begin() as session:
        snapshot = session.get(AnalysisSnapshot, snapshot_id)
        # Control: the sealed payload validates.
        service._snapshot_report_context(snapshot)
        # Tamper one byte inside the Evidence the digest covers.
        snapshot.object_versions["evidence"][0]["value"]["n"] = 2
        with pytest.raises(ValueError, match="failed integrity validation"):
            service._snapshot_report_context(snapshot)


def test_snapshot_report_context_never_mutates_the_sealed_payload(test_settings) -> None:
    """Copy-on-write must not become 'mutate the ORM JSON in place'."""
    service = _service(test_settings)
    snapshot_id, _ = _sealed_snapshot(
        service,
        evidence_value={
            "steps": [{"index": 11, "path_condition": "RAX cmp 0X493E1 (RAX - 0X493E1)"}],
            "n": 1,
        },
    )

    with service.database.session_factory.begin() as session:
        snapshot = session.get(AnalysisSnapshot, snapshot_id)
        before = json.dumps(snapshot.object_versions, sort_keys=True)
        context = service._snapshot_report_context(snapshot)
        after = json.dumps(snapshot.object_versions, sort_keys=True)
        dirty = sa_inspect(snapshot).attrs.object_versions.history.has_changes()

    assert after == before, "report projection mutated the sealed snapshot payload"
    assert dirty is False, "report projection left the immutable snapshot attribute dirty"
    assert context["evidence"]
    # The copy-on-write path really ran: the projection enriched the thread row.
    enriched = [row for row in context["investigation_threads"] if getattr(row, "protocol", None)]
    assert enriched, "fixture did not exercise the protocol enrichment path"
    assert enriched[0].protocol == {"steps": ["seed", "verify"]}


def test_report_not_mutating_snapshot_keeps_the_ledger_digest_valid(test_settings) -> None:
    """A full report build must leave the sealed digest verifiable afterwards."""
    service = _service(test_settings)
    snapshot_id, task_id = _sealed_snapshot(
        service, evidence_value={"steps": [{"index": 11}], "n": 1}
    )

    with service.database.session_factory.begin() as session:
        task = session.get(AnalysisTask, task_id)
        snapshot = session.get(AnalysisSnapshot, snapshot_id)
        sealed_digest = snapshot.object_versions["content_sha256"]
        revision = service._create_report_revision(session, task, snapshot, list(REPORT_MODULES))
        stored = json.loads(json.dumps(snapshot.object_versions))["content_sha256"]

    assert stored == sealed_digest
    assert json.dumps(revision.document)


def test_report_document_stays_json_serialisable_when_strings_carry_nul(test_settings) -> None:
    """The three ``_postgres_safe_value`` passes must keep their invariant."""
    service = _service(
        test_settings,
    )
    snapshot_id, task_id = _sealed_snapshot(
        service,
        evidence_value={"text": "hello\x00world", "nested": {"inner": "a\x00b"}},
    )

    with service.database.session_factory.begin() as session:
        task = session.get(AnalysisTask, task_id)
        snapshot = session.get(AnalysisSnapshot, snapshot_id)
        revision = service._create_report_revision(session, task, snapshot, list(REPORT_MODULES))

        def walk(value: object) -> list[str]:
            if isinstance(value, str):
                return [value]
            if isinstance(value, dict):
                return [item for key, child in value.items() for item in [*walk(key), *walk(child)]]
            if isinstance(value, (list, tuple)):
                return [item for child in value for item in walk(child)]
            return []

        assert all("\x00" not in text for text in walk(revision.document))
        assert "\x00" not in revision.markdown
        assert json.dumps(revision.document)
