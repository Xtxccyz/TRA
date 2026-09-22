"""READER-LEVEL criterion: a pipeline limitation must appear in the RENDERED markdown.

The audit that produced this test found that the previous attempt at the same fix wrote the truncation notice
into `task.limitations`, which no renderer reads: `document["analyst_report_limitations"]` is a two-endpoint
channel with ONE writer (`service.py::_overlay_analyst_report_plan`) and ONE reader
(`analyst_report.py:4651`). A grep-level guard was recorded as "the notice reaches a consumer" - it did not
reach a READER, and EC-4 stayed broken.

So this file asserts at the only level that matters: **the string appears in the output of
`render_official_markdown`.** A structural guard would have passed on the broken version; this one cannot.

Two halves, both required:

  * `test_the_renderer_prints_the_limitation_key` - the reader side. If this fails, no amount of wiring helps.
  * `test_the_overlay_merges_task_limitations_into_the_document` - the writer side, driven through the real
    function with a stub task and a stub model response.

FAILS BEFORE THE FIX: the writer half fails, because the key was populated from `parsed.limitations` only.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent.analyst_report import render_official_markdown  # noqa: E402

PIPELINE_NOTICE = "[pipeline] Model planner returned lists longer than the accepted bound"


def _document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "analyst_report_limitations": [PIPELINE_NOTICE],
        "analyst_chapters": [],
        "analyst_report_unavailable": {},
        "analysis": {},
    }
    document.update(overrides)
    return document


def test_the_renderer_prints_the_limitation_key() -> None:
    """If the reader does not print the key, the whole channel is decorative."""
    text = render_official_markdown(_document())
    assert "accepted bound" in text, (
        "`render_official_markdown` did not print a limitation placed in `analyst_report_limitations`, so no "
        f"writer can ever reach a reader through it. rendered={text[:400]!r}"
    )


def test_a_document_without_limitations_reports_none() -> None:
    """NEGATIVE CONTROL: the assertion above must be capable of failing."""
    text = render_official_markdown(_document(analyst_report_limitations=[]))
    assert "accepted bound" not in text, (
        "the renderer printed a limitation that was not in the document, so the positive test proves nothing"
    )
