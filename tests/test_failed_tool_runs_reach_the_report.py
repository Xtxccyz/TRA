"""A failed tool run must reach the report WITH its own reason.

MEASURED defect this pins (adversarial audit, item 2): published bodies contain `CANCELLED`/`TIMED_OUT` in
**0 of 551** revisions while the database holds 7 timed-out tool runs, 2 cancelled tool runs, 49 cancelled
tasks and 217 FAILED emulator runs. `_completion_limitations` only notices a MISSING success, only for
REQUIRED artifacts, and emits one generic sentence - so the REASON was discarded and a reader could not tell a
cancellation from a timeout from a crashed activity. A run cancelled and retried three times (measured in
ghidra-worker's log) read exactly like a run that simply produced less.

The helper is driven directly with a session stub exposing only `execute(...).all()`, because a test that needs
the whole finalize path is a test that will not be written.

FAILS BEFORE THE FIX: no helper existed and `task.limitations` never carried a tool-run status or error.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent.service import AnalysisService  # noqa: E402


class _Result:
    def __init__(self, rows: list[tuple[object, object, object]]) -> None:
        self._rows = rows

    def all(self) -> list[tuple[object, object, object]]:
        return self._rows


class _Session:
    """Only what the helper uses. The real query is exercised by the DB-backed suite."""

    def __init__(self, rows: list[tuple[object, object, object]]) -> None:
        self._rows = rows
        self.statements: list[object] = []

    def execute(self, statement: object) -> _Result:
        self.statements.append(statement)
        return _Result(self._rows)


def test_a_cancelled_run_names_its_status_and_error() -> None:
    session = _Session([("controlled-emulator", "CANCELLED", "TOOL_ACTIVITY_CANCELLED")])
    limitations = AnalysisService._failed_tool_run_limitations(session, "task-1")  # type: ignore[arg-type]
    assert len(limitations) == 1, f"expected one entry, got {limitations}"
    assert "CANCELLED" in limitations[0], f"the STATUS must be visible: {limitations[0]}"
    assert "TOOL_ACTIVITY_CANCELLED" in limitations[0], f"the REASON must be visible: {limitations[0]}"
    assert "controlled-emulator" in limitations[0], f"the tool must be named: {limitations[0]}"


def test_a_timeout_is_distinguishable_from_a_cancellation() -> None:
    session = _Session(
        [
            ("ghidra-headless", "TIMED_OUT", "TEMPORAL_ACTIVITY_TIMED_OUT"),
            ("controlled-emulator", "CANCELLED", "TOOL_ACTIVITY_CANCELLED"),
        ]
    )
    limitations = AnalysisService._failed_tool_run_limitations(session, "task-1")  # type: ignore[arg-type]
    joined = "\n".join(limitations)
    assert "TIMED_OUT" in joined and "CANCELLED" in joined, (
        f"the two failure modes must remain distinguishable: {limitations}"
    )


def test_a_run_without_a_recorded_error_says_so_without_claiming_there_was_none() -> None:
    session = _Session([("parser", "FAILED", None)])
    limitations = AnalysisService._failed_tool_run_limitations(session, "task-1")  # type: ignore[arg-type]
    assert len(limitations) == 1
    assert "no error recorded" in limitations[0], (
        "the entry must state what we HAVE; 'no error recorded' is not the claim that no error occurred"
    )


def test_repeats_collapse_and_nothing_is_truncated() -> None:
    """The helper adds no cap: repeated identical failures must dedupe, not be cut.

    A `[:N]` here would be a fresh unannounced truncation of the kind this report forbids, so the criterion is
    that MANY distinct failures all survive.
    """
    rows = [("emu", "FAILED", "SAME") for _ in range(5)]
    rows += [(f"tool-{index}", "FAILED", f"E{index}") for index in range(20)]
    session = _Session(rows)
    limitations = AnalysisService._failed_tool_run_limitations(session, "task-1")  # type: ignore[arg-type]
    assert len(limitations) == 21, (
        f"5 identical rows must collapse to 1 and the 20 distinct ones must ALL survive, got {len(limitations)}"
    )


def test_a_clean_task_contributes_nothing() -> None:
    """NEGATIVE CONTROL: no failures must not manufacture a limitation."""
    session = _Session([])
    assert AnalysisService._failed_tool_run_limitations(session, "task-1") == []  # type: ignore[arg-type]
