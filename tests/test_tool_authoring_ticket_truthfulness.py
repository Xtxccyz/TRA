"""A tool-authoring ticket must not report a capability as missing when it actually ran.

MEASURED defect this pins. The 白象 run published:

    TOOL_AUTHORING_REQUIRED: DECODE_CONFIG on 64da3378… needs a tool the product does not have;
    missing evidence: key, algorithm, counter, step, consumer, evidence anchor coherence; …

Two claims there are false for that run:

  * "needs a tool the product does not have" - `src/threat_report_agent/literal_table.py` IS that
    tool, and it ran;
  * "missing evidence: algorithm" - the same task's evidence carried a `decode_result` with a
    four-step `decode_chain` (read 20 UTF-16LE chars at a 48-byte stride -> cut at the first NUL ->
    unhexlify the ASCII hex -> decode as latin-1) and 5,881 recovered characters.

A ticket that tells the reader a capability is missing when it executed is worse than no ticket.
"""
from __future__ import annotations

from threat_report_agent.investigation_protocol import (
    TOOL_AUTHORING_REQUIRED_MARKER,
    tool_authoring_required_entries,
    tool_authoring_required_ticket,
)


def _ticket(**kwargs: object) -> str:
    base = {
        "mechanism_type": "DECODE_CONFIG",
        "artifact_path": "64da33787b54a0d179d7f77768b7af1e6ca7ee942a437dc751073879ae6d6c14",
        "missing": ["key", "algorithm", "consumer"],
        "action_types": ["TRACE_API_ARGUMENT"],
    }
    base.update(kwargs)
    return tool_authoring_required_ticket(**base)  # type: ignore[arg-type]


def test_without_recovery_the_missing_tool_wording_is_kept() -> None:
    """No recovery registered -> the original claim is still the truthful one."""
    text = _ticket()
    assert "needs a tool the product does not have" in text
    assert "missing evidence: key, algorithm, consumer" in text


def test_with_recovery_the_ticket_never_claims_a_missing_tool() -> None:
    text = _ticket(static_recovery="encoding=utf16le-asciihex-record-table; recovered_chars=5881")

    assert "needs a tool the product does not have" not in text, (
        "the static decoder ran; claiming the tool is absent is false"
    )
    assert "partly recovered" in text
    assert "utf16le-asciihex-record-table" in text
    assert "5881" in text


def test_with_recovery_the_ticket_still_records_what_is_unclosed() -> None:
    """The gap must survive: recovery is not the same as verification."""
    text = _ticket(static_recovery="encoding=x")

    assert "the verifier still needs" in text
    assert "key, algorithm, consumer" in text
    assert "not claimed as recovered" in text


def test_ticket_keeps_its_marker_and_self_evidence() -> None:
    """Downstream extraction and the 'authoring was not attempted' honesty clause must both hold."""
    text = _ticket(static_recovery="encoding=x")

    assert text.startswith(TOOL_AUTHORING_REQUIRED_MARKER)
    assert "tool authoring was not attempted" in text
    assert "TRACE_API_ARGUMENT" in text
    # The report pulls ticket bodies by marker; a reworded ticket must stay extractable.
    assert tool_authoring_required_entries([text]) == [text[len(TOOL_AUTHORING_REQUIRED_MARKER) :].strip()]


def test_blank_recovery_falls_back_to_original_wording() -> None:
    """A whitespace-only summary must not switch the wording and silently drop the 'missing' claim."""
    text = _ticket(static_recovery="   ")
    assert "needs a tool the product does not have" in text


# --- the recovery detector itself ---------------------------------------------------------------
#
# The detector took three attempts, each caught by a probe rather than by reasoning. These tests pin
# the shape it must read so a fourth regression cannot hide behind the ticket's fixture tests.

from threat_report_agent.service import AnalysisService  # noqa: E402


def _decode_row() -> dict:
    """The real shape: `_specialized_verifier_context.as_mapping` returns
    `{id, artifact_id, kind, nature, value, anchor}`, so the decode fields are INSIDE `value`."""
    return {
        "id": "e1",
        "artifact_id": "a1",
        "kind": "decode_result",
        "nature": "STATIC_OBSERVED",
        "value": {
            "verification_status": "DECODED_STATIC",
            "candidate": {
                "encoding": "utf16le-asciihex-record-table",
                "decode_chain": ["read 20 UTF-16LE chars at a 48-byte stride", "unhexlify"],
            },
            "recovered_text": "x" * 5881,
        },
        "anchor": {},
    }


def test_detector_reads_the_decode_fact_from_value() -> None:
    out = AnalysisService._static_decode_recovery_from_evidence([_decode_row()])

    assert "DECODED_STATIC" in out
    assert "utf16le-asciihex-record-table" in out
    assert "recovered_chars=5881" in out
    assert "48-byte stride" in out


def test_detector_ignores_rows_that_are_not_decodes() -> None:
    """The corpus is full of other rows; anything without a decode status/encoding must not match."""
    rows = [
        {"id": "e0", "kind": "string", "nature": "STATIC_OBSERVED", "value": {"text": "a" * 5881}},
        {"id": "e2", "kind": "decode_result", "nature": "STATIC_OBSERVED", "value": {"candidate": {}}},
        {"id": "e3", "value": "not-a-mapping"},
    ]
    assert AnalysisService._static_decode_recovery_from_evidence(rows) == ""


def test_detector_does_not_read_fields_off_the_row_top_level() -> None:
    """The exact bug that survived one deploy: fields at top level must NOT be treated as the fact.

    A detector that reads `row["verification_status"]` looks correct and returns "" against real data,
    so the ticket keeps its false claim while every fixture test passes.
    """
    flat = {
        "id": "e1",
        "kind": "decode_result",
        "verification_status": "DECODED_STATIC",
        "encoding": "utf16le-asciihex-record-table",
    }
    assert AnalysisService._static_decode_recovery_from_evidence([flat]) == ""
