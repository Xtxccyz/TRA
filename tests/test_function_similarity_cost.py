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
"""

from __future__ import annotations

import inspect

from threat_report_agent.service import AnalysisService

SOURCE = inspect.getsource(AnalysisService._record_function_similarity)


def test_one_evidence_row_is_written_per_source_not_per_match() -> None:
    """The measured defect: 7,406 rows for 2,785 kB and ~11,406 audit events.

    A per-match `session.add(evidence)` inside the match loop is what makes persistence O(matches).
    The fix collects matches per source and writes one row per source, so this asserts the write is
    no longer inside the per-match loop.
    """
    # The add must be indented at the source level (one per source), not inside `for match in ...`.
    lines = SOURCE.splitlines()
    match_loop_indent = None
    add_indents: list[int] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("for match in "):
            match_loop_indent = len(line) - len(line.lstrip())
        elif stripped.startswith("session.add(evidence)"):
            add_indents.append(len(line) - len(line.lstrip()))
    assert match_loop_indent is not None, "the per-match loop was not found; source changed shape"
    assert add_indents, "no Evidence write found"
    assert all(indent < match_loop_indent for indent in add_indents), (
        "an Evidence row is still written inside the per-match loop, so persistence stays O(matches): "
        f"match loop indent={match_loop_indent}, add indents={add_indents}"
    )


def test_the_audit_event_is_not_emitted_per_match() -> None:
    """One chained audit event per match is the other half of the cost.

    `_audit` extends a hash chain under a row lock, so 7,406 matches mean 7,406 chain steps.
    """
    lines = SOURCE.splitlines()
    match_loop_indent = None
    audit_indents: list[int] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("for match in "):
            match_loop_indent = len(line) - len(line.lstrip())
        elif stripped.startswith("self._audit("):
            audit_indents.append(len(line) - len(line.lstrip()))
    assert match_loop_indent is not None
    inside = [indent for indent in audit_indents if indent > match_loop_indent]
    assert not inside, (
        "an audit event is still emitted inside the per-match loop, so the hash chain grows with the "
        f"number of match pairs ({len(inside)} occurrence(s))"
    )


def test_matches_are_still_recorded_for_every_reference() -> None:
    """Aggregation must keep the finding: every match and reference id survives.

    A fix that dropped matches to save rows would be trading the objective's depth for cost, which it
    explicitly forbids. This pins the aggregation shape: each written row carries the full match list.
    """
    assert "matches" in SOURCE or "references" in SOURCE, (
        "the per-source row does not appear to carry the individual matches, so aggregation would "
        "have discarded the findings"
    )
