"""One source decides which slots are unresolved.

MEASURED defect this pins: the per-topic slot table reads `document["analyst_slot_proposals"]`, while
`_collect_official_unknowns` saw only `rows`. The two could disagree - the body listing a slot as UNKNOWN on
one line and showing it filled on another - which is the "two uncoordinated UNKNOWN sources" the plan warned
about. The fix passes the SAME document record the renderer reads, so a slot the model filled cannot also be
reported as missing.
"""
from __future__ import annotations

from threat_report_agent.analyst_report import AnalystTopic, _collect_official_unknowns

TOPIC = AnalystTopic(
    catalog_id="process-creation",
    title="进程创建",
    status="observed",
    reason="finding present",
    anchors=("process-creation",),
)

ROW = {
    "catalog_id": "process-creation",
    "type": "behavior_finding",
    "how": "CreateProcess 调用点已恢复；creation_flags 未恢复。",
    "unknowns": ["UNKNOWN(creation_flags)", "UNKNOWN(loop)"],
}


def _document(slots: list[str]) -> dict:
    return {
        "analyst_slot_proposals": {
            "supported": [
                {
                    "slot": name,
                    "value": f"{name} 已由恢复文本支撑",
                    "evidence_substring": "Loop Until",
                    "evidence_source": "recovered_script",
                    # The token the product actually emits (`analyst_report.py` `verify_model_slot_proposals`).
                    # It said `substring_verified` here - a name that no longer exists anywhere in `src/`,
                    # left over from the rename that stopped the body printing a verification claim for a
                    # literal match. `_collect_official_unknowns` reads only `slot`, so the stale spelling
                    # changed nothing TODAY; the guard below is what stops it drifting again unnoticed.
                    "support": "substring_matched",
                }
                for name in slots
            ],
            "rejected": [],
        }
    }


def test_a_filled_slot_is_no_longer_reported_as_unknown() -> None:
    with_document = _collect_official_unknowns([ROW], [TOPIC], _document(["loop"]))
    assert not any("loop" in item.casefold() for item in with_document), (
        f"a slot the model filled is still listed as unresolved: {with_document}"
    )
    assert any("creation_flags" in item for item in with_document), (
        "an unrelated unknown was dropped as collateral"
    )


def test_without_a_document_the_unknowns_are_unchanged() -> None:
    """The old call shape must keep working - this is a narrowing, not a redefinition."""
    baseline = _collect_official_unknowns([ROW], [TOPIC])
    assert any("creation_flags" in item for item in baseline)
    assert any("loop" in item.casefold() for item in baseline)


def test_an_empty_proposal_record_changes_nothing() -> None:
    empty = {"analyst_slot_proposals": {"supported": [], "rejected": []}}
    assert _collect_official_unknowns([ROW], [TOPIC], empty) == _collect_official_unknowns([ROW], [TOPIC])


def test_a_malformed_record_does_not_break_the_unknowns() -> None:
    for record in ("not a mapping", {"supported": "not a list"}, {"supported": [None, 3]}, None):
        document = {"analyst_slot_proposals": record} if record is not None else {}
        result = _collect_official_unknowns([ROW], [TOPIC], document)
        assert any("creation_flags" in item for item in result), (
            f"a malformed proposals record silently swallowed the unknowns: {record!r}"
        )


def test_the_fixtures_support_token_is_one_the_product_emits() -> None:
    """Guard against this file pinning a spelling `src/` does not produce.

    MEASURED: the fixture said `substring_verified` for as long as it took to notice, because the code under
    test reads only `slot`. A fixture that names a token the product never emits cannot fail, so it documents
    nothing - and it would silently mislead the next reader who keys on `support`.
    """
    from threat_report_agent.analyst_report import _SUPPORT_DISPLAY

    token = _document(["loop"])["analyst_slot_proposals"]["supported"][0]["support"]
    assert token in _SUPPORT_DISPLAY, (
        f"the fixture claims support={token!r}, which is not a machine identifier the product recognises "
        f"({sorted(_SUPPORT_DISPLAY)})"
    )
