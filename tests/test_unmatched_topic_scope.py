"""An unmatched topic must never borrow another topic's evidence.

MEASURED defect this pins: `_observed_signals_for_topic` first fell back to the whole document when a
topic matched no rows (`_matched_rows(topic, rows) or rows`). On the real 白象 run every one of the five
unmatched topics had `_matched_rows == 0`, so the clause reported evidence kinds scraped from all 311
document rows. That attributes other topics' facts to this one - a wrong join, EC-3 in the
analysis-verification taxonomy, and precisely the defect class this work exists to remove.

The honest answer for a topic with no matched rows is "no evidence observed for this topic".
"""
from __future__ import annotations

from threat_report_agent.analyst_report import (
    AnalystTopic,
    _observed_signals_for_topic,
    unmatched_category_statement,
)


def _topic(catalog_id: str, title: str = "网络通信") -> AnalystTopic:
    return AnalystTopic(catalog_id=catalog_id, title=title, status="unrecovered", reason="r")


def test_no_signals_when_topic_matches_nothing() -> None:
    """A document full of unrelated rows must not leak into an unmatched topic."""
    unrelated = [
        {
            "type": "behavior_finding",
            "catalog_id": "process-creation",
            "what": "WinHttpSendRequest CreateProcess persisted",
            "how": "registry Run key",
        },
        {
            "type": "assessment",
            "catalog_id": "config-and-crypto",
            "what": "WinINet HTTP endpoint",
        },
    ]
    assert _observed_signals_for_topic(_topic("network-transport"), unrelated) == []


def test_statement_says_no_clue_rather_than_borrowing() -> None:
    unrelated = [{"type": "behavior_finding", "catalog_id": "x", "what": "WinHttpSendRequest"}]
    signals = _observed_signals_for_topic(_topic("network-transport"), unrelated)
    text = unmatched_category_statement(_topic("network-transport"), signals)

    assert "本次未见该类目的线索" in text
    assert "已见证据类别" not in text


def test_topic_own_rows_are_named() -> None:
    """When the topic DOES own a matching row, its kind is named."""
    owned = [
        {
            "type": "behavior_finding",
            "catalog_id": "network-transport",
            "what": "WinHttpSendRequest to a recovered endpoint",
        }
    ]
    signals = _observed_signals_for_topic(_topic("network-transport"), owned)
    text = unmatched_category_statement(_topic("network-transport"), signals)

    assert signals == ["behavior_finding"]
    assert "本类目登记的卡点" in text and "behavior_finding" in text


def test_a_row_that_merely_has_a_reason_is_not_a_blocker() -> None:
    """Only the topic's own evidence may supply the statement; an unrelated row must not.

    A `reason`-bearing row from ANOTHER topic must never be reported as this topic's evidence - that is
    the wrong-join (EC-3) failure this module already had once. See the revert note in
    `iter_document_rows` for why publishing `unclosed_high_value` prose was tried and withdrawn.
    """
    rows = [
        {
            "type": "behavior_finding",
            "catalog_id": "process-creation",
            "reason": "some unrelated explanatory note about WinHTTP",
            "what": "WinHttpSendRequest",
        }
    ]
    signals = _observed_signals_for_topic(_topic("network-transport"), rows)

    assert signals == [], "another topic's row must not be adopted as this topic's evidence"


def test_attribution_keeps_its_own_boundary() -> None:
    text = unmatched_category_statement(_topic("attribution", "attribution"), [])
    assert "不代表该样本没有归属" in text