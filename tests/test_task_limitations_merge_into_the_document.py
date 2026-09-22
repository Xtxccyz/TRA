"""PRODUCER-side criterion: the task's own limitations are merged into the key the renderer reads.

The consumer side is pinned by `tests/test_pipeline_limitations_reach_the_body.py`, which asserts the notice
appears in `render_official_markdown`'s OUTPUT. This file pins the other half of the pair (M4: producer +
consumer, with an executable test proving the value reaches a rendered document).

The merge lives in `AnalysisService._merge_operational_limitations`, extracted from
`_overlay_analyst_report_plan` precisely so it can be driven directly: that method's upstream branches (model
response parsing, chapter planning) cannot be reached in isolation, and a test that cannot be written is a
claim that cannot be verified. Extraction is the honest response, not skipping the test.

MEASURED defect this pins: the key was populated from `parsed.limitations` only - the MODEL's self-report - so
the pipeline's own operational limitations never entered the document. Published bodies carry
`CANCELLED`/`TIMED_OUT` in 0 of 551 revisions while the database holds 7 timed-out and 2 cancelled tool runs.

FAILS BEFORE THE EXTRACTION/FIX: nothing merged `task.limitations` at all.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent.service import AnalysisService  # noqa: E402

MERGE = AnalysisService._merge_operational_limitations


def test_task_limitations_reach_the_document_key() -> None:
    document: dict[str, object] = {}
    task = SimpleNamespace(limitations=["TOOL_ACTIVITY_CANCELLED", "WINDOW_BUDGET_EXHAUSTED"])

    MERGE(document, task)

    merged = document["analyst_report_limitations"]
    assert isinstance(merged, list)
    assert len(merged) == 2, f"both operational limitations must survive: {merged}"
    assert all(str(item).startswith("[pipeline] ") for item in merged), (
        "every entry must be labelled so a reader can tell a PIPELINE limitation from a MODEL-stated one; "
        f"unlabelled entries make the model's silence indistinguishable from the pipeline's failure: {merged}"
    )
    assert any("TOOL_ACTIVITY_CANCELLED" in str(item) for item in merged)


def test_model_stated_limitations_are_kept() -> None:
    """NEGATIVE CONTROL: the merge must ADD to the model's entries, not replace them."""
    document: dict[str, object] = {"analyst_report_limitations": ["模型自述的一条限制"]}
    MERGE(document, SimpleNamespace(limitations=["TOOL_ACTIVITY_CANCELLED"]))

    merged = [str(item) for item in document["analyst_report_limitations"]]
    assert "模型自述的一条限制" in merged, f"the model's own limitation was dropped: {merged}"
    assert any("TOOL_ACTIVITY_CANCELLED" in item for item in merged)


def test_no_limitations_leaves_the_document_untouched() -> None:
    """NEGATIVE CONTROL: absence must not fabricate an entry, and must not create the key."""
    document: dict[str, object] = {}
    MERGE(document, SimpleNamespace(limitations=[]))
    assert "analyst_report_limitations" not in document, (
        f"an empty list manufactured a key: {document}"
    )
    MERGE(document, SimpleNamespace(limitations=None))
    assert "analyst_report_limitations" not in document


def test_the_same_limitation_is_not_duplicated() -> None:
    document: dict[str, object] = {"analyst_report_limitations": ["[pipeline] TOOL_ACTIVITY_CANCELLED"]}
    MERGE(document, SimpleNamespace(limitations=["[pipeline] TOOL_ACTIVITY_CANCELLED", "TOOL_ACTIVITY_CANCELLED"]))
    merged = [str(item) for item in document["analyst_report_limitations"]]
    assert merged == ["[pipeline] TOOL_ACTIVITY_CANCELLED"], (
        f"a limitation already present was appended again, so a repeated failure inflates the list: {merged}"
    )
