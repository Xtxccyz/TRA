"""G6-B in ticket form: record the need for a tool, never claim an attempt.

ADR-0037 allows the agent to author tools, but this product has no execution
surface for authored code and building one would be the new architecture the
working plan forbids.  So the investigation loop records a factual ticket:
"closing this gap needs a tool the product does not have", together with the
action types it really exercised.

The distinction the report must preserve:

* ``TOOL_AUTHORING_REQUIRED``  -- a need, authoring NOT attempted;
* ``TOOL_AUTHORING_UNRESOLVED`` -- an authoring attempt happened and failed.

Collapsing the two would let a skipped gap look like a tried one, which is the
failure mode this whole remediation keeps running into.
"""

from __future__ import annotations

from threat_report_agent.analyst_report import (
    STOP_KIND_RECOVERABLE,
    STOP_KIND_TOOL_BLOCKED,
    render_official_markdown,
    render_stop_kinds,
)
from threat_report_agent.investigation_protocol import (
    TOOL_AUTHORING_REQUIRED_MARKER,
    TOOL_AUTHORING_UNRESOLVED_MARKER,
    tool_authoring_required_entries,
    tool_authoring_required_ticket,
)


def _ticket(**overrides: object) -> str:
    payload: dict[str, object] = {
        "mechanism_type": "DECODE_CONFIG",
        "artifact_path": "Resume.pdf.exe.VIR",
        "missing": ("consumer",),
        "action_types": ("READ_BYTES", "TRACE_API_ARGUMENT", "GET_DECOMPILE"),
    }
    payload.update(overrides)
    return tool_authoring_required_ticket(**payload)  # type: ignore[arg-type]


def test_ticket_states_the_need_and_the_exercised_actions() -> None:
    ticket = _ticket()
    assert ticket.startswith(TOOL_AUTHORING_REQUIRED_MARKER)
    assert "DECODE_CONFIG" in ticket
    assert "Resume.pdf.exe.VIR" in ticket
    assert "consumer" in ticket
    assert "READ_BYTES" in ticket
    assert "TRACE_API_ARGUMENT" in ticket


def test_ticket_never_claims_an_authoring_attempt() -> None:
    ticket = _ticket()
    assert TOOL_AUTHORING_UNRESOLVED_MARKER not in ticket
    assert "tool authoring was not attempted" in ticket


def test_ticket_sorts_and_dedupes_action_types() -> None:
    ticket = _ticket(action_types=("READ_BYTES", "GET_DECOMPILE", "READ_BYTES"))
    assert ticket.count("READ_BYTES") == 1


def test_ticket_survives_empty_inputs() -> None:
    ticket = _ticket(mechanism_type=None, artifact_path=None, missing=(), action_types=())
    assert TOOL_AUTHORING_REQUIRED_MARKER in ticket
    assert "UNKNOWN_MECHANISM" in ticket
    assert "action types exercised: none" in ticket


def test_entries_extraction_is_ordered_and_deduped() -> None:
    first = _ticket(mechanism_type="DECODE_CONFIG")
    second = _ticket(mechanism_type="HTTP_DOWNLOAD")
    entries = tool_authoring_required_entries(
        ["unrelated limitation", first, second, first]
    )
    assert len(entries) == 2
    assert "DECODE_CONFIG" in entries[0]
    assert "HTTP_DOWNLOAD" in entries[1]


def test_entries_extraction_ignores_non_ticket_limitations() -> None:
    entries = tool_authoring_required_entries(
        [
            "Recursive static analysis byte budget exceeded.",
            "Static boundary: no new evidence closed the DECODE_CONFIG mechanism.",
        ]
    )
    assert entries == []


def test_required_tickets_render_under_the_recoverable_kind() -> None:
    text = render_stop_kinds(["UNKNOWN(consumer)"], [_ticket()])
    recoverable_block = text.split(STOP_KIND_TOOL_BLOCKED)[0]
    assert STOP_KIND_RECOVERABLE in recoverable_block
    assert "创作未尝试" in recoverable_block
    assert "DECODE_CONFIG" in recoverable_block
    # The third kind stays reserved for a real attempt.
    blocked_block = text.split(STOP_KIND_TOOL_BLOCKED)[1]
    assert "DECODE_CONFIG" not in blocked_block


def test_attempted_and_unresolved_still_uses_the_third_kind() -> None:
    limitations = [
        f"{TOOL_AUTHORING_UNRESOLVED_MARKER} decode_primitives exhausted 3 candidate keys",
    ]
    text = render_stop_kinds(["UNKNOWN(consumer)"], limitations)
    blocked_block = text.split(STOP_KIND_TOOL_BLOCKED)[1]
    assert "decode_primitives exhausted 3 candidate keys" in blocked_block


def test_official_markdown_surfaces_the_ticket() -> None:
    from threat_report_agent.reporting import REPORT_V3_REQUIRED_SECTIONS

    document: dict[str, object] = {
        "report_version": "3.0",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "case_id": "case-ticket",
        "task_id": "task-ticket",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 4, "verified_mechanism_count": 2},
        "analyst_report_limitations": [_ticket()],
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
    official = render_official_markdown(document)
    assert TOOL_AUTHORING_REQUIRED_MARKER in official
    assert "创作未尝试" in official


def test_official_markdown_surfaces_tickets_carried_only_by_coverage_gaps() -> None:
    """The live path has no model draft, so limitations arrive as coverage gaps."""
    from threat_report_agent.reporting import REPORT_V3_REQUIRED_SECTIONS

    document: dict[str, object] = {
        "report_version": "3.0",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "case_id": "case-gaps",
        "task_id": "task-gaps",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {
            "mechanism_count": 4,
            "verified_mechanism_count": 2,
            "gaps": [
                "Static boundary: no new evidence closed the DECODE_CONFIG mechanism.",
                _ticket(),
            ],
        },
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
    official = render_official_markdown(document)
    assert TOOL_AUTHORING_REQUIRED_MARKER in official
    assert "DECODE_CONFIG" in official
    assert "创作未尝试" in official
