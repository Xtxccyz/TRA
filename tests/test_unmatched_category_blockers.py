"""An unmatched category must name its concrete blocker, not a fixed 套话.

The objective is explicit: 「查不到写 UNKNOWN(槽位)+具体卡点，禁止「未提供对象级使用链」这类套话
收尾（acceptance 脚本会统计套话次数）」and A 项 requires 套话计数为 0.

Measured on the accepted revision `535340c3` (24/24 criteria): the checker reports
`boilerplate x2`, and both hits are this one template emitted for two unmatched chapters:

    已核对：进程注入与隐蔽启动。静态导入/字符串/调用序列与受控模拟均未提供对象级使用链。
    不是「样本没有恶意能力」的证明。
    已核对：持久化。静态导入/字符串/调用序列与受控模拟均未提供对象级使用链。
    不是「样本没有恶意能力」的证明。

`analyst_report.py:3600` is the source. 24/24 with 套话 present is NOT the objective's A 项, so the
template has to become topic-specific: name what was looked for and the concrete slot that blocked
it - which for this sample is known, e.g. the registry writes whose `lpValueName` is still
`qword ptr [RSP + 0x940]`.

These tests assert on the PUBLISHED body via `render_official_markdown`, because the objective
grades the body and the checker counts phrases in it.
"""

from __future__ import annotations

from threat_report_agent.analyst_report import render_official_markdown
from threat_report_agent.report.reporting import REPORT_V3_REQUIRED_SECTIONS

# The two phrases the acceptance checker counts.
BOILERPLATE_PHRASES = (
    "静态导入/字符串/调用序列与受控模拟均未提供对象级使用链",
    "不是「样本没有恶意能力」的证明",
)


def _document(*, catalog_ids: tuple[str, ...]) -> dict[str, object]:
    """A document whose analyst plan contains the requested unmatched categories."""
    rows = [
        {
            "type": "pe_basics",
            "format": "PE32+",
            "machine": "0x8664",
            "path": "sample.exe",
        },
        {
            "type": "analyst_plan",
            "items": [
                {"catalog_id": catalog_id, "title": catalog_id, "status": "unmatched"}
                for catalog_id in catalog_ids
            ],
        },
    ]
    return {
        "report_version": "3.0",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "case_id": "case-boiler",
        "task_id": "task-boiler",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 1, "verified_mechanism_count": 0},
        "modules": [
            {"id": "static_triage", "title": "Static Triage", "summary": "", "rows": rows}
        ],
        "trace": {},
    }


def test_an_unmatched_chapter_carries_no_fixed_boilerplate() -> None:
    """The exact phrases the checker counts must be gone from the body."""
    body = render_official_markdown(_document(catalog_ids=("process-injection", "persistence")))
    for phrase in BOILERPLATE_PHRASES:
        assert phrase not in body, (
            f"the fixed 套话 is still published ({phrase!r}); the acceptance checker counts it and "
            "A 项 requires zero"
        )


def test_an_unmatched_chapter_names_a_concrete_blocker() -> None:
    """A reader must learn WHAT was checked and WHICH slot is missing."""
    body = render_official_markdown(_document(catalog_ids=("process-injection",)))
    assert "UNKNOWN(" in body, (
        "the objective requires the unresolved slot to be written as UNKNOWN(槽位); the body "
        "carries no UNKNOWN marker for an unmatched category"
    )
    # A concrete blocker must be specific to injection, not a generic sentence.
    assert any(
        token in body
        for token in ("inject", "注入", "target process", "目标进程", "跨进程")
    ), f"the blocker does not name the category's own subject: {body[:600]}"


def test_the_absence_boundary_is_still_stated() -> None:
    """Removing 套话 must not remove the honest boundary that absence is not disproof.

    The old template carried two jobs: a denial of evidence and a statement that the denial is not
    proof of absence. Only the first is 套话; the second is required by G4 §8.2-3, so a fix that
    deleted the whole template would trade one defect for another.
    """
    body = render_official_markdown(_document(catalog_ids=("persistence",)))
    assert any(
        token in body
        for token in ("不代表", "不是排除", "未触发", "not proof", "不能排除")
    ), f"the body no longer states that absence is not disproof: {body[:600]}"
