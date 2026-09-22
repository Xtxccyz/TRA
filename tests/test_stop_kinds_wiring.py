"""Wiring D — the report must separate the three ways analysis can stop.

Plan-external requirement (user conversation): analysis limits must distinguish

* a slot that exists in the image and should have been recovered but was not
  (a capability failure),
* a fact that is only observable by running the sample and is therefore allowed
  to stay unknown permanently, and
* a gap where a tool was actually attempted and tool authoring still did not
  resolve it (a concrete, named blocker).

Conflating these lets a report look equally "bounded" whether it failed to read
the file or correctly declined to invent runtime facts.
"""

from __future__ import annotations

from threat_report_agent.analyst_report import (
    STOP_KIND_RECOVERABLE,
    STOP_KIND_RUNTIME,
    STOP_KIND_TOOL_BLOCKED,
    classify_stop_kind,
    render_stop_kinds,
)


def test_image_recoverable_slots_are_capability_failures() -> None:
    for token in (
        "UNKNOWN(creation_flags)",
        "UNKNOWN(consumer)",
        "UNKNOWN(start_routine)",
        "UNKNOWN(join)",
        "UNKNOWN(fallback)",
        "UNKNOWN(loop)",
        "UNKNOWN(parent identity)",
        "UNKNOWN(input)",
        "UNKNOWN(transformation)",
        "UNKNOWN(output)",
        "UNKNOWN(what)",
        "UNKNOWN(target)",
        "UNKNOWN(value)",
        "UNKNOWN(size)",
        "UNKNOWN(threshold)",
        "UNKNOWN(lifetime)",
    ):
        assert classify_stop_kind(token) == STOP_KIND_RECOVERABLE, token


def test_runtime_only_slots_are_allowed_to_stay_unknown() -> None:
    for token in (
        "UNKNOWN(response bytes)",
        "UNKNOWN(response)",
        "UNKNOWN(liveness)",
        "UNKNOWN(runtime parent pid)",
        "UNKNOWN(runtime execution)",
    ):
        assert classify_stop_kind(token) == STOP_KIND_RUNTIME, token


def test_unknown_classification_is_case_and_spacing_insensitive() -> None:
    assert classify_stop_kind("unknown(creation_flags)") == STOP_KIND_RECOVERABLE
    assert (
        classify_stop_kind("UNKNOWN( creation_flags )") == STOP_KIND_RECOVERABLE
    )
    assert classify_stop_kind("UNKNOWN(RESPONSE BYTES)") == STOP_KIND_RUNTIME


def test_unrecognised_token_is_not_silently_called_runtime() -> None:
    """Defaulting to "runtime, therefore allowed" would hide capability gaps."""
    assert classify_stop_kind("UNKNOWN(some_new_slot)") == STOP_KIND_RECOVERABLE


def test_render_lists_all_three_kinds_even_when_two_are_empty() -> None:
    text = render_stop_kinds(["UNKNOWN(creation_flags)", "UNKNOWN(consumer)"], [])
    assert STOP_KIND_RECOVERABLE in text
    assert STOP_KIND_RUNTIME in text
    assert STOP_KIND_TOOL_BLOCKED in text
    assert "UNKNOWN(creation_flags)" in text
    assert "UNKNOWN(consumer)" in text


def _block(text: str, kind: str) -> str:
    """Text of one kind's bullet, including its indented sub-items."""
    lines = text.splitlines()
    start = next(index for index, line in enumerate(lines) if kind in line)
    collected = [lines[start]]
    for line in lines[start + 1 :]:
        if line.startswith("- `"):
            break
        collected.append(line)
    return "\n".join(collected)


def test_render_separates_runtime_slots_from_capability_failures() -> None:
    text = render_stop_kinds(
        ["UNKNOWN(consumer)", "UNKNOWN(response bytes)"],
        [],
    )
    recoverable_block = _block(text, STOP_KIND_RECOVERABLE)
    runtime_block = _block(text, STOP_KIND_RUNTIME)
    assert "UNKNOWN(consumer)" in recoverable_block
    assert "UNKNOWN(response bytes)" not in recoverable_block
    assert "UNKNOWN(response bytes)" in runtime_block
    assert "UNKNOWN(consumer)" not in runtime_block


def test_tool_authoring_blockers_are_reported_from_limitations() -> None:
    limitations = [
        "TOOL_AUTHORING_UNRESOLVED: decode_primitives exhausted 3 candidate keys for thread-abc",
        "Recursive static analysis byte budget exceeded.",
    ]
    text = render_stop_kinds(["UNKNOWN(consumer)"], limitations)
    blocked_block = _block(text, STOP_KIND_TOOL_BLOCKED)
    assert "decode_primitives exhausted 3 candidate keys" in blocked_block
    assert "byte budget" not in blocked_block


def test_render_states_when_a_kind_has_no_entries() -> None:
    """An empty kind must say so rather than vanish."""
    text = render_stop_kinds([], [])
    assert text.count("无") >= 3


def _document_with_open_slots() -> dict[str, object]:
    from threat_report_agent.reporting import REPORT_V3_REQUIRED_SECTIONS

    return {
        "report_version": "3.0",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "case_id": "case-stop-kinds",
        "task_id": "task-stop-kinds",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 4, "verified_mechanism_count": 2},
        "analyst_report_limitations": [
            "TOOL_AUTHORING_UNRESOLVED: decode_primitives exhausted 3 candidate keys",
            "Recursive static analysis byte budget exceeded.",
        ],
        "modules": [
            {
                "id": "static_triage",
                "title": "Static Triage",
                "summary": "",
                "rows": [
                    {
                        "type": "persist_how",
                        "mechanism_type": "DECODE_CONFIG",
                        "status": "UNKNOWN",
                        "target": "loader.exe",
                        "how": "decode_result",
                        "unknowns": ["UNKNOWN(consumer)"],
                    }
                ],
            }
        ],
        "trace": {},
    }


def test_official_markdown_renders_the_three_stop_kinds() -> None:
    """Wiring D must be live in the rendered report, not just callable."""
    from threat_report_agent.analyst_report import render_official_markdown

    official = render_official_markdown(_document_with_open_slots())
    assert STOP_KIND_RECOVERABLE in official
    assert STOP_KIND_RUNTIME in official
    assert STOP_KIND_TOOL_BLOCKED in official
    assert "UNKNOWN(consumer)" in official
    assert "decode_primitives exhausted 3 candidate keys" in official
