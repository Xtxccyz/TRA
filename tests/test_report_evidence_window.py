"""The bounded report window must keep operationally significant strings.

Regression this pins.  `_snapshot_report_context` bounds Evidence to
`_REPORT_PROJECTION_EVIDENCE_LIMIT` (4,096) rows before the report builder ever
sees it.  `_select_report_evidence_rows` ranks by Evidence `kind`, and every raw
string shares one kind, so the tiebreak is `row_id` - a UUID.  Selection among
strings was therefore arbitrary.

Measured on task `1359f2a6` (39,837 Evidence rows, limit 4,096) with the real
window applied:

* the composed body scored 13/24, and ALL FOUR string-only benchmark facts went
  missing again - `:Zone.Identifier`, the `schtasks` blob, `.tmp`, and the three
  Defender registry keys;
* every one of their Evidence IDs was absent from the windowed document's
  `trace.evidence_ids`, while all four were present when the builder was given
  the full ledger.

So the window, not the projection, was the binding constraint on the shipped
path.  These tests assert the ordering rule directly, on ids chosen so that a
UUID-ordered selection provably drops the facts.
"""

from __future__ import annotations

from types import SimpleNamespace

from threat_report_agent.service import AnalysisService


def _string_row(evidence_id: str, text: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=evidence_id,
        kind="string",
        module="static_triage",
        value={"encoding": "ascii", "text": text},
    )


def _noise_row(evidence_id: str) -> SimpleNamespace:
    # Real disassembly-derived string noise from this sample's string layer.
    return _string_row(evidence_id, f"L$@{evidence_id[:6].upper()}H")


# UUIDs picked so that a `row_id`-ordered selection takes the noise first.
NOISE_IDS = [f"00000000-0000-4000-8000-{index:012d}" for index in range(40)]
FACT_IDS = {
    "zone": "ffffffff-0000-4000-8000-000000000001",
    "schtasks": "ffffffff-0000-4000-8000-000000000002",
    "tmp": "ffffffff-0000-4000-8000-000000000003",
    "spynet": "ffffffff-0000-4000-8000-000000000004",
}

FACTS = {
    "zone": ":Zone.Identifier",
    "schtasks": "schtasks/create/tn/tr/sconce/st00:00/fschtasks create failed/run/delete",
    "tmp": ".tmp",
    "spynet": "SOFTWARE\\Microsoft\\Windows Defender\\SpyNet",
}


def _rows() -> list[SimpleNamespace]:
    return [_noise_row(item) for item in NOISE_IDS] + [
        _string_row(FACT_IDS[name], text) for name, text in FACTS.items()
    ]


def test_window_keeps_operationally_significant_strings() -> None:
    """A tight budget must still admit the strings an analyst needs.

    The budget here is deliberately smaller than the row count, and every fact id
    sorts AFTER every noise id, so this fails on the old `row_id` tiebreak.
    """
    selected = AnalysisService._select_report_evidence_rows(
        _rows(),
        referenced_ids=set(),
        limit=8,
    )
    selected_ids = {str(getattr(row, "id", "")) for row in selected}
    missing = {
        name: evidence_id
        for name, evidence_id in FACT_IDS.items()
        if evidence_id not in selected_ids
    }
    assert not missing, f"significant strings lost to the bounded window: {missing}"


def test_window_still_respects_the_limit() -> None:
    """Prioritising facts must not break the bound itself."""
    selected = AnalysisService._select_report_evidence_rows(
        _rows(),
        referenced_ids=set(),
        limit=8,
    )
    assert len(selected) <= 8


def test_window_keeps_cited_evidence_ahead_of_strings() -> None:
    """Claim/relation citations keep their reserved budget.

    Evidence that a Claim cites is load-bearing for the report's reasoning, so
    string prioritisation must not evict it.
    """
    cited = "00000000-0000-4000-8000-000000009999"
    rows = [_noise_row(item) for item in NOISE_IDS] + [_string_row(cited, "cited value")]
    rows += [_string_row(FACT_IDS[name], text) for name, text in FACTS.items()]
    selected = AnalysisService._select_report_evidence_rows(
        rows,
        referenced_ids={cited},
        limit=8,
    )
    selected_ids = {str(getattr(row, "id", "")) for row in selected}
    assert cited in selected_ids


def test_window_ranks_significant_strings_above_bulk_non_string_rows() -> None:
    """The rank must beat the kind-priority tier, not merely the other strings.

    First attempt at this fix used a two-valued key that returned 0 for
    "significant string" and 1 for "other string" - but 0 was ALREADY the default
    for every non-string row, so the next key in the tuple
    (``-kind_priority``) still sorted thousands of ``function_call`` rows ahead of
    the handful of significant strings, and the real 39,837-row window still
    dropped every fact.  The unit test that missed it used string rows only.

    Here the budget is 6 and there are 500 high-kind-priority non-string rows, so
    a rank that is not the first tier provably loses.
    """
    bulk = [
        SimpleNamespace(
            id=f"aaaaaaaa-0000-4000-8000-{index:012d}",
            kind="function_call",  # kind priority 108, far above `string` at 10
            module="static_triage",
            value={"name": f"FUN_{index}"},
        )
        for index in range(500)
    ]
    rows = bulk + [
        _string_row(FACT_IDS[name], text) for name, text in FACTS.items()
    ]
    selected = AnalysisService._select_report_evidence_rows(
        rows,
        referenced_ids=set(),
        limit=6,
    )
    selected_ids = {str(getattr(row, "id", "")) for row in selected}
    assert set(FACT_IDS.values()) <= selected_ids, (
        "significant strings lost behind higher-kind-priority bulk rows"
    )


def test_window_is_deterministic() -> None:
    """The same ledger must always yield the same report view."""
    first = AnalysisService._select_report_evidence_rows(_rows(), referenced_ids=set(), limit=8)
    second = AnalysisService._select_report_evidence_rows(_rows(), referenced_ids=set(), limit=8)
    assert [str(getattr(row, "id", "")) for row in first] == [
        str(getattr(row, "id", "")) for row in second
    ]
