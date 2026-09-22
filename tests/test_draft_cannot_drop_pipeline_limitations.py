"""A draft that drops the pipeline's own limitations must FAIL THE COMPOSE GATE.

MEASURED defect this pins. The published body is the analyst DRAFT whenever it clears the compose gate
(`publish_composed_markdown` returns the candidate; `service.py:24107` passes
`draft=document.get("analyst_report_draft")`). Everything added for the pipeline's own limitations - the
truncation notice, the failed-tool-run reasons, the bounded-list remainder - renders only into the
DETERMINISTIC fragments. So on the common path they reached no reader, and revision `414cb724`'s published body
contains zero occurrences of `限制`/`limitation`.

The fix is deliberately at the GATE rather than a post-processing step: a draft that omits the block is
REJECTED, so the deterministic body is published instead. The omission therefore has to fail something, instead
of depending on the draft having been written correctly.

WHY THESE ASSERT ON `compose_official_markdown`: an earlier version of this session's criteria asserted on
`render_official_markdown`, the INNER function — 157 hits across 26 test files do, while `compose` appears once
in a docstring. A test on the inner layer passes while the published bytes differ. These assert on the publisher.

FAILS BEFORE THE FIX: no gate rule existed, so the draft was published with the block missing.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent.analyst_report import (  # noqa: E402
    OPERATIONAL_LIMITATIONS_HEADING,
    compose_gate_violations,
    compose_official_markdown,
)

BLOCK = f"{OPERATIONAL_LIMITATIONS_HEADING}\n\n- [pipeline] Tool run controlled-emulator ended CANCELLED: TOOL_ACTIVITY_CANCELLED.\n"
FRAGMENTS = f"# 静态分析报告\n\n## 分析结论\n\n正文。\n\n{BLOCK}"
DRAFT_WITHOUT = "# 静态分析报告\n\n## 分析结论\n\n模型润色后的正文。\n"
DRAFT_WITH = DRAFT_WITHOUT + "\n" + BLOCK


def test_a_draft_omitting_the_operational_block_is_a_violation() -> None:
    violations = compose_gate_violations(DRAFT_WITHOUT, FRAGMENTS)
    assert any("operational limitations" in item for item in violations), (
        "a draft may not silently drop the pipeline's own limitations; the reader would lose the only "
        f"statement that the pipeline had a problem. violations={violations}"
    )


def test_a_draft_carrying_the_block_passes_that_rule() -> None:
    """NEGATIVE CONTROL: the rule must not reject a draft that kept the block."""
    violations = compose_gate_violations(DRAFT_WITH, FRAGMENTS)
    assert not any("operational limitations" in item for item in violations), (
        f"a compliant draft was rejected: {violations}"
    )


def test_a_draft_is_not_penalised_when_the_fragments_have_no_block() -> None:
    """NEGATIVE CONTROL: with nothing to carry, the rule must stay silent."""
    violations = compose_gate_violations(DRAFT_WITHOUT, "# 静态分析报告\n\n## 分析结论\n\n正文。\n")
    assert not any("operational limitations" in item for item in violations), (
        f"a draft was rejected for omitting a block that does not exist: {violations}"
    )


def test_the_publisher_falls_back_instead_of_publishing_the_omitting_draft() -> None:
    """THE READER-LEVEL ASSERTION, at the real published layer.

    This is what the earlier criteria lacked: it asks the PUBLISHER what bytes it would serve.
    """
    document = {
        "analyst_report_limitations": [
            "[pipeline] Tool run controlled-emulator ended CANCELLED: TOOL_ACTIVITY_CANCELLED."
        ],
        "analyst_chapters": [],
        "analyst_report_unavailable": {},
        "analysis": {},
    }
    published = compose_official_markdown(document, draft=DRAFT_WITHOUT)

    assert OPERATIONAL_LIMITATIONS_HEADING in published, (
        "the omitting draft was published, so the pipeline's limitation reached no reader; the gate must "
        f"reject it and the deterministic body must be served instead. published={published[:300]!r}"
    )
    assert "模型润色后的正文" not in published, (
        "the draft was still published despite omitting the block"
    )
