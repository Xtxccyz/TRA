"""The environment guard must publish the thresholds the run actually recovered.

Regression this pins.  The sample's entire first phase is an anti-sandbox gate:

    CALL GetTickCount64 ; CMP RAX,0x493e1              -> uptime < 300001 ms
    CALL GlobalMemoryStatus ; CMP qword ptr [RSI + 0x8],0x60000000  -> RAM <= 1.5 GiB

Both comparisons ARE recovered and DO sit in the report document, but three
separate things stopped them reaching the published body, and each of these tests
covers one:

1. `environment-guard` was absent from `_SEED_OPEN_FROM_IMPORTS`, and no row
   carried that `catalog_id`, so the capability got NO chapter at all.  Measured
   on task `1359f2a6`: `plan_analyst_topics` returned 11 topics with no
   environment guard.
2. `_blob` reads only prose/field keys, so a nested step `text` never reached a
   chapter body.
3. The two gates are stored in DIFFERENT shapes: the uptime gate as a step
   `text`, the memory gate as a raw instruction string inside a `window` array.
   A scan that only looked at `text` found the first and silently missed the
   second -- so a fix for (2) alone still published only half the gate.

These assert on `render_official_markdown` output, not on a helper: the whole
lesson of this defect is that helper-level behaviour looked right while the
published body was wrong.
"""

from __future__ import annotations

from threat_report_agent.analyst_report import (
    _is_threshold_like_constant,
    plan_analyst_topics,
    render_official_markdown,
)
from threat_report_agent.reporting import REPORT_V3_REQUIRED_SECTIONS


def _document(rows: list[dict[str, object]] | None = None, **extra: object) -> dict[str, object]:
    doc: dict[str, object] = {
        "report_version": "3.0",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "case_id": "case-env",
        "task_id": "task-env",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 1, "verified_mechanism_count": 0},
        "modules": [
            {
                "id": "executive_summary",
                "title": "Executive Summary",
                "summary": "",
                "rows": rows or [],
            }
        ],
        "trace": {},
    }
    doc.update(extra)
    return doc


def _gate_row() -> dict[str, object]:
    """One row carrying both recovered gates, in the two real shapes.

    `CMP RAX,0x493e1` as a step text; `CMP qword ptr [RSI + 0x8],0x60000000` only
    as a raw instruction inside a window array.
    """
    return {
        "type": "behavior_finding",
        "what": "environment probe sequence recovered",
        "evidence_samples": [
            {
                "value": {
                    "steps": [{"text": "TEST AL,AL"}, {"text": "CMP RAX,0x493e1"}],
                    "window": [
                        "CALL GlobalMemoryStatus",
                        "CMP qword ptr [RSI + 0x8],0x60000000",
                    ],
                }
            }
        ],
    }


def test_environment_guard_is_planned_as_a_topic() -> None:
    """The capability must get a chapter at all -- it previously got none."""
    document = _document([_gate_row()], sample_name="Resume.pdf.exe.VIR")
    import json

    # Give the planner an import-ish token so the seed path can match; the real
    # document carries the notable-import list.
    document["modules"][0]["rows"].append({"imports": ["GetTickCount64"], "type": "pe"})
    ids = [topic.catalog_id for topic in plan_analyst_topics(document)]
    assert "environment-guard" in ids, json.dumps(ids)


def test_both_recovered_gate_constants_reach_the_published_body() -> None:
    """Both shapes must be surfaced: the step text AND the window instruction.

    The real document carries the notable-import list that seeds the chapter, so
    the fixture includes it; without a seed the chapter is not planned at all
    (covered by ``test_environment_guard_is_planned_as_a_topic``).
    """
    document = _document([_gate_row(), {"type": "pe", "imports": ["GetTickCount64"]}])
    official = render_official_markdown(document)
    assert "0x493e1" in official
    assert "0x60000000" in official


def test_an_unrelated_sample_does_not_get_an_empty_environment_chapter() -> None:
    """Seeding from concrete API names must not open the chapter everywhere."""
    document = _document([{"type": "pe", "imports": ["CreateFileW", "CloseHandle"]}])
    ids = [topic.catalog_id for topic in plan_analyst_topics(document)]
    assert "environment-guard" not in ids


def test_small_immediates_are_not_presented_as_thresholds() -> None:
    """0x1 / 0x100 are counts and mode bits, not gate thresholds."""
    assert _is_threshold_like_constant("0x493e1") is True
    assert _is_threshold_like_constant("0x60000000") is True
    assert _is_threshold_like_constant("0x100") is False
    assert _is_threshold_like_constant("0x1") is False
    assert _is_threshold_like_constant("nonsense") is False
    assert _is_threshold_like_constant(None) is False
