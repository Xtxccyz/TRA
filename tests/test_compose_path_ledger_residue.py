"""Ledger residue is rejected on BOTH publication paths, and the product's own tokens are not treated as jargon.

Two defects, both measured:

1. `compose_gate_violations` ran only the wording/novelty/upgrade/absence checks. `primary_analyst_violations` -
   which owns the jargon list, Evidence UUIDs, `FUN_` dumps, `FUN_` names, PERSISTED_INVESTIGATION and the
   coverage dictionaries - was applied ONLY on the deterministic render path. But
   `publish_composed_markdown` RETURNS THE MODEL DRAFT, so a draft could carry all of that into the official
   body while the render path rejected the same words. The hole was wider than jargon.

2. `_PRIMARY_JARGON` listed `"unknown(parameter)"`, and the check casefolds. `UNKNOWN(parameter)` is a token
   the PRODUCT emits (`reporting.py` 6 sites, `persist_how.py` 2 sites) meaning "this thread parameter was not
   recovered" - so the gate rejected the product's own honest output. The mapping written for it
   (`"unknown(parameter)" -> "UNKNOWN(parameter)"`) was a provable no-op because the two are casefold-equal,
   and an acceptance test asserting "unknown(parameter) is scrubbed" would have green-lit that corruption.
"""
from __future__ import annotations

import pytest

from threat_report_agent.analyst_report import (
    compose_gate_violations,
    primary_analyst_violations,
)

CLEAN_BODY = "## 分析结论\n\n调用序列已从静态证据恢复。\n"


def test_the_products_own_unknown_parameter_token_is_not_jargon() -> None:
    """`UNKNOWN(parameter)` is what this product writes when a thread parameter was not recovered."""
    for body in (
        "## 分析结论\n\nparameter=UNKNOWN(parameter); 线程参数未恢复。\n",
        "## 分析结论\n\n`UNKNOWN(parameter)` 保持未恢复。\n",
        "## 分析结论\n\nUNKNOWN(parameter)\n",
    ):
        assert primary_analyst_violations(body) == [], (
            f"the product's own token was rejected as ledger jargon: {body!r}"
        )


@pytest.mark.parametrize(
    "body,expected_fragment",
    [
        ("## 分析结论\n\nfield completeness 未达标。\n", "ledger jargon"),
        ("## 分析结论\n\n证据 11111111-2222-3333-4444-555555555555 已记录。\n", "UUID"),
        ("## 分析结论\n\n调用 FUN_0040d2c0 后进入载荷。\n", "FUN_"),
        ("## 分析结论\n\npersisted_investigation 阶段已完成。\n", "PERSISTED_INVESTIGATION"),
        ("## 分析结论\n\npipeline completion 为 100%。\n", "jargon"),
        ("## 分析结论\n\nsemantic analysis coverage 已统计。\n", "jargon"),
    ],
)
def test_each_primary_check_still_fires(body: str, expected_fragment: str) -> None:
    """Removing one bad marker must not remove the detector."""
    violations = primary_analyst_violations(body)
    assert violations, f"the check no longer fires for: {body!r}"
    assert any(expected_fragment in item for item in violations), violations


@pytest.mark.parametrize(
    "draft",
    [
        "报告称 field completeness 很高。",
        "报告引用了 11111111-2222-3333-4444-555555555555。",
        "报告提到 FUN_0040d2c0 的调用。",
        "报告称 persisted_investigation 已完成。",
        "报告称 pipeline completion 为 100%。",
        "报告称 semantic analysis coverage 已统计。",
    ],
)
def test_every_primary_check_also_governs_the_compose_path(draft: str) -> None:
    """The load-bearing half of the fix: the draft path must reject what the render path rejects.

    One case per check, so a future edit that covers only the jargon list fails here.
    """
    assert compose_gate_violations(draft, "片段"), (
        f"the compose path let this through: {draft!r}"
    )


def test_a_clean_draft_passes_the_compose_path() -> None:
    """The new checks must not make the gate unusable."""
    assert compose_gate_violations(CLEAN_BODY, "调用序列已从静态证据恢复。") == []


def test_the_compose_path_labels_the_origin_of_each_finding() -> None:
    """A reader must be able to tell which gate produced a finding."""
    violations = compose_gate_violations("报告称 field completeness 很高。", "片段")
    assert any(item.startswith("compose draft ") for item in violations), violations


def test_a_draft_cannot_carve_out_an_unchecked_region_with_the_appendix_heading() -> None:
    """MEASURED hole in the first version of the A2 fix.

    `primary_analyst_violations` splits its input on `ANALYST_APPENDIX_HEADING` and checks only the part
    BEFORE it. On the render path that heading is machine-appended, so trusting the split is fine. On the
    compose path the text is the MODEL'S DRAFT, so writing the heading moved everything after it out of
    scope: a draft containing a UUID, a `FUN_` name and ledger jargon returned `[]`.

    A draft has no legitimate appendix - this module composes the appendix, not the model - so the heading is
    neutralised before checking and there is nowhere to hide. Kept as a test because the hole was invisible
    to every other test in this file: they all pass a draft WITHOUT the heading.
    """
    from threat_report_agent.analyst_report import ANALYST_APPENDIX_HEADING

    smuggled = (
        "## 分析结论\n\n一切正常。\n\n"
        + ANALYST_APPENDIX_HEADING
        + "\n\nFUN_0040d2c0 11111111-2222-3333-4444-555555555555 field completeness\n"
    )
    violations = compose_gate_violations(smuggled, "片段")
    assert violations, "a draft hid ledger residue behind the appendix heading"
    joined = " ".join(violations)
    for expected in ("jargon", "UUID", "FUN_"):
        assert expected in joined, f"the {expected} check was dodged: {violations}"
