"""The body must answer "who is this" even when the answer is "not established here".

MEASURED GAP. The published body for the 白象 sample `64da3378` (task `0da01730`) contained zero
occurrences of 归因 / attribution / UNKNOWN(attribution). The product HAS an attribution path
(`methodology.fact_matched`, an `attribution` module, and a sanitiser that rewrites unverified APT names to
`UNKNOWN(attribution)`), but the topic was simply omitted when nothing matched, so a reader could not tell
"searched, no validated binding" from "the question was never asked".

Attribution differs from the capability chapters in one way that matters for wording: an unestablished
attribution does NOT mean the sample has no author, so the capability chapters' closing sentence
("不代表样本不具备该能力") would answer a different question. The attribution chapter gets its own.
"""
from __future__ import annotations

from threat_report_agent.analyst_report import (
    _MANDATORY_WINDOWS_CHAPTER_IDS,
    AnalystTopic,
    render_official_markdown,
    unmatched_category_statement,
)


def _document(rows: list[dict] | None = None) -> dict:
    return {
        "report_version": "3.0",
        "case_id": "case-attr",
        "task_id": "task-attr",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 0, "verified_mechanism_count": 0},
        "analyst_topics": [],
        "modules": [
            {
                "id": "static_triage",
                "title": "Static Triage",
                "summary": "",
                "rows": rows
                or [
                    {
                        "type": "pe_basics",
                        "format": "PE32",
                        "machine": "0x014c",
                        "entry_rva": 9348,
                        "subsystem": 2,
                        "section_names": [".text", ".data", ".rsrc"],
                    }
                ],
            }
        ],
        "trace": {},
    }


def test_the_mandatory_set_includes_attribution() -> None:
    assert "attribution" in _MANDATORY_WINDOWS_CHAPTER_IDS


def test_the_published_body_states_that_attribution_is_not_established() -> None:
    body = render_official_markdown(_document())
    assert "归因" in body, (
        "the body never mentions attribution, so a reader cannot tell whether the question was asked"
    )
    assert "UNKNOWN(actor_identity + validated_fact_match)" in body, (
        "the attribution chapter does not name the slot that is missing"
    )
    assert "不代表该样本没有归属" in body, (
        "the attribution chapter reuses the capability chapters' boundary sentence, which answers a "
        "different question: an unestablished attribution does not mean the sample has no author"
    )


def test_the_attribution_chapter_does_not_claim_absence_of_an_actor() -> None:
    """EC-1: "we did not find an actor" must never be published as "there is no actor"."""
    body = render_official_markdown(_document())
    index = body.find("归因")
    chapter = body[max(0, index - 400) : index + 900]
    for forbidden in ("无归属", "不属于任何", "未受任何组织", "不存在攻击者"):
        assert forbidden not in chapter, f"the attribution chapter asserts {forbidden!r}"


def test_a_capability_chapter_keeps_its_own_boundary_sentence() -> None:
    """The attribution wording must not leak into the capability chapters."""
    topic = AnalystTopic(
        catalog_id="network-transport",
        title="网络通信",
        status="unrecovered",
        reason="mandatory",
        anchors=(),
        source="catalog",
    )
    statement = unmatched_category_statement(topic)
    assert "不代表样本不具备该能力" in statement
    assert "不代表该样本没有归属" not in statement
