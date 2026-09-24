"""R4: one match must not cost one Evidence row plus one chained audit event.

MEASURED on task `de738f12`:

    input    704 simhash rows, 507 distinct fingerprints
    output   7,406 `function_similarity` rows, 2,785 kB
             -> the SECOND-largest evidence kind by row count
    audit    ~11,406 `evidence.recorded` events for the task's 12,648 total
    consumers claims read 0 of them, relations cite 0 of them

The objective names this O(F^2) cost as pathological and requires it measured away rather than
budgeted away. Two separate costs had to be separated first:

  * comparisons are arithmetic - `search()` walks the record tuple per source row;
  * persistence is I/O **per match** - one Evidence row and one chained audit event each.

The output itself is not noise: 88% of matches are at Hamming distance 0 (identical function bodies)
across 334 sources and 262 references, which is a real finding. So the fix is not to emit less
INFORMATION, it is to stop paying one row and one audit event per match. Matches are grouped per
source fingerprint - the grain the comparison actually has - which keeps every match and every
reference id while making the row count track the number of SOURCES instead of the number of PAIRS.

`ActionType.COMPARE_FUNCTION` reads `function_simhash`, and nothing reads
`function_similarity`, so no consumer contract constrains the shape beyond the existing tests, which
require only that rows exist and carry `source_evidence_id`.

P3.7 CONVERSION: these assertions used to read `inspect.getsource(AnalysisService._record_function_similarity)`
and compare INDENTATION LEVELS of `for match in ...` / `session.add(evidence)` / `self._audit(` lines. That
proved the shape of the text, not the cost the file is about, and it broke whenever the body was reformatted.
The tests below now MEASURE the cost directly: they run the real recording path over a same-task corpus and
count the persisted rows and chained audit events against the number of sources and the number of matches.
"""

from __future__ import annotations

from types import SimpleNamespace

from sqlalchemy import select

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import (
    AnalysisTask,
    Artifact,
    AuditEvent,
    ContentBlob,
    Evidence,
    ToolRun,
)
from threat_report_agent.service import AnalysisService
from threat_report_agent.static.function_simhash import ALGORITHM, FEATURE, FEATURE_HASH

#: Three sources whose fingerprints are IDENTICAL, so every source matches the other two: 6 match PAIRS
#: across 3 SOURCES. The per-match shape paid 6 rows and 6 audit events; the per-source shape pays 3 and 3.
#: The fingerprint is the real contract shape: 16 lowercase hex digits (`fingerprint_mnemonics` emits
#: `f"{simhash(...):016x}"`).
FINGERPRINT = "5a" * 8


def _corpus(test_settings, *, sources: int = 3):
    """Persist `sources` identical same-task `function_simhash` rows and return the ids needed to record."""
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    database.create_schema()
    case = service.create_case("function similarity cost")
    with database.session_factory.begin() as session:
        session.add(
            ContentBlob(
                sha256="a" * 64,
                size=1,
                media_type="application/octet-stream",
                storage_key="sha256/function-similarity-cost",
            )
        )
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256="a" * 64,
            logical_path="similarity.exe",
            detected_type="pe",
            role="EXECUTABLE",
        )
        session.add(artifact)
        session.flush()
        run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="ghidra-headless",
            tool_version="test",
            status="SUCCEEDED",
        )
        session.add(run)
        session.flush()
        for index in range(sources):
            session.add(
                Evidence(
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_simhash",
                    nature="STATIC_OBSERVED",
                    value={
                        "value": FINGERPRINT,
                        "algorithm": ALGORITHM,
                        "feature": FEATURE,
                        "hash": FEATURE_HASH,
                    },
                    anchor={"function_entry": f"0x10{index:02x}"},
                )
            )
        session.flush()
        return service, database, task.id, artifact.id, run.id


def _record(test_settings, *, sources: int = 3):
    service, database, task_id, artifact_id, run_id = _corpus(test_settings, sources=sources)
    with database.session_factory.begin() as session:
        task = session.get(AnalysisTask, task_id)
        artifact = session.get(Artifact, artifact_id)
        service._record_function_similarity(
            session,
            task,
            artifact,
            SimpleNamespace(id=run_id),
        )
    return database, task_id, artifact_id


def _persisted(database, task_id: str):
    with database.session_factory() as session:
        similarity_rows = list(
            session.scalars(
                select(Evidence).where(
                    Evidence.task_id == task_id,
                    Evidence.kind == "function_similarity",
                )
            )
        )
        audit_events = list(
            session.scalars(select(AuditEvent).where(AuditEvent.task_id == task_id))
        )
    return similarity_rows, audit_events


def test_one_evidence_row_is_written_per_source_not_per_match(test_settings) -> None:
    """The measured defect: 7,406 rows for 2,785 kB and ~11,406 audit events.

    MEASURED here, not read from the source: 3 identical sources produce 6 ordered match pairs. The old
    per-match write produced 6 `function_similarity` rows; this asserts there are exactly 3 - one per SOURCE
    fingerprint. A per-match `session.add(evidence)` inside the match loop fails this immediately.
    """
    database, task_id, _artifact_id = _record(test_settings, sources=3)
    similarity_rows, _audit = _persisted(database, task_id)

    assert len(similarity_rows) == 3, (
        "persistence still scales with the number of match PAIRS, not the number of SOURCES: "
        f"{len(similarity_rows)} rows for 3 sources / 6 match pairs"
    )
    # Every row is one source's complete match set, not one pair.
    assert sorted(len(row.value["matches"]) for row in similarity_rows) == [2, 2, 2], (
        "a per-source row must carry that source's whole match list: "
        f"{[len(row.value['matches']) for row in similarity_rows]}"
    )


def test_the_audit_event_is_not_emitted_per_match(test_settings) -> None:
    """One chained audit event per match is the other half of the cost.

    `_audit` extends a hash chain under a row lock, so the per-match shape made 7,406 matches mean 7,406 chain
    steps. MEASURED here: 3 sources / 6 match pairs must produce 3 `evidence.recorded` chain steps, not 6.
    """
    database, task_id, _artifact_id = _record(test_settings, sources=3)
    _rows, audit_events = _persisted(database, task_id)

    recorded = [event for event in audit_events if event.event_type == "evidence.recorded"]
    assert len(recorded) == 3, (
        "the audit chain grows with the number of match PAIRS rather than the number of SOURCES: "
        f"{len(recorded)} `evidence.recorded` events for 3 sources / 6 match pairs"
    )
    tool_runs = [event for event in audit_events if event.event_type == "tool_run.completed"]
    assert len(tool_runs) == 1, (
        "the synthetic similarity ToolRun must be audited exactly once, not once per source: "
        f"{len(tool_runs)}"
    )


def test_matches_are_still_recorded_for_every_reference(test_settings) -> None:
    """Aggregation must keep the finding: every match and reference id survives.

    A fix that dropped matches to save rows would be trading the objective's depth for cost, which it
    explicitly forbids. MEASURED: each written row carries the full match list, and every OTHER source id is
    still present as a reference in the matching source's row.
    """
    database, task_id, artifact_id = _record(test_settings, sources=3)
    similarity_rows, _audit = _persisted(database, task_id)

    source_ids = {row.value["source_evidence_id"] for row in similarity_rows}
    assert len(source_ids) == 3, "a source fingerprint lost its row entirely"
    for row in similarity_rows:
        matches = row.value["matches"]
        assert matches, "an aggregated row carries no matches, so the finding was discarded"
        assert "source_evidence_id" in row.value, (
            "the per-source row no longer carries `source_evidence_id`"
        )
        references = {str(item["reference_id"]) for item in matches}
        assert references == source_ids - {row.value["source_evidence_id"]}, (
            "the per-source row no longer keeps every other source as a reference: "
            f"{sorted(references)}"
        )
        assert all(item["distance"] == 0 for item in matches), (
            "identical fingerprints must match at Hamming distance 0: "
            f"{[item['distance'] for item in matches]}"
        )
        assert row.value["match_count"] == len(matches)
        assert row.artifact_id == artifact_id
