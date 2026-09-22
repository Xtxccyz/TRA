"""The published body must state what each isolated simulator did or why it could not proceed.

MEASURED gap this pins: the document already carried an `emulation_status` projection, but no chapter
rendered it, so the published body contained ZERO occurrences of the stop reasons. The single most
actionable fact in the run was therefore invisible to the reader:

    limitations: ["Speakeasy stopped before observing any API call:
                   unsupported_api api=MSVBVM60.ordinal_100 pc=0xfeedf0f0 instr=disasm_failed"]

The chapter must also preserve the boundary: a FAILED/NOT_APPLICABLE simulation is a statement about
SIMULATOR COVERAGE, not about the sample's capabilities.
"""
from __future__ import annotations

from threat_report_agent.analyst_report import _emulation_status_section


def _row() -> dict[str, object]:
    return {
        "type": "emulation_status",
        "overall": "FAILED",
        "attempted": True,
        "results": [
            {
                "status": "NOT_APPLICABLE",
                "simulator": "unicorn",
                "stop_reason": "pe_entry_is_bootstrap_trampoline",
                "limitations": ["the entry point only forwards into a runtime bootstrap thunk"],
            },
            {
                "status": "FAILED",
                "simulator": "speakeasy",
                "stop_reason": "EXECUTION_ERROR",
                "limitations": [
                    "Speakeasy stopped before observing any API call: unsupported_api "
                    "api=MSVBVM60.ordinal_100 pc=0xfeedf0f0 instr=disasm_failed"
                ],
            },
            {
                "status": "NOT_APPLICABLE",
                "simulator": "qiling",
                "stop_reason": "qiling_requires_linux_elf",
                "limitations": ["granted bytes are not a Linux ELF"],
            },
        ],
    }


def test_simulator_diagnosis_reaches_the_body() -> None:
    text = "\n".join(_emulation_status_section([_row()]))

    assert "MSVBVM60.ordinal_100" in text, "the blocking symbol is the whole point of the chapter"
    assert "EXECUTION_ERROR" in text
    assert "pe_entry_is_bootstrap_trampoline" in text
    assert "qiling_requires_linux_elf" in text
    assert "FAILED" in text


def test_chapter_states_the_coverage_boundary() -> None:
    """A reader must not read a FAILED simulator as a sample-capability claim."""
    text = "\n".join(_emulation_status_section([_row()]))

    assert "不执行样本" in text
    assert "不构成样本能力结论" in text
    assert "NOT_APPLICABLE" in text and "FAILED" in text


def test_no_section_when_no_emulation_row() -> None:
    assert _emulation_status_section([]) == []
    assert _emulation_status_section([{"type": "pe", "path": "x.exe"}]) == []


def test_overall_status_is_published() -> None:
    text = "\n".join(_emulation_status_section([_row()]))
    assert "总体状态" in text and "`FAILED`" in text


def test_repeated_projection_rows_are_deduped() -> None:
    """The document carries one `emulation_status` row per projection; the same outcome must print once.

    Measured on the real 8 MB document: three identical rows rendered the speakeasy diagnosis 3x, which
    inflates the run and buries the one fact the chapter exists to carry.
    """
    text = "\n".join(_emulation_status_section([_row(), _row(), _row()]))

    assert text.count("MSVBVM60.ordinal_100") == 1
    assert text.count("EXECUTION_ERROR") == 1
    assert text.count("**speakeasy**") == 1
    assert text.count("**unicorn**") == 1
    assert text.count("**qiling**") == 1


def test_distinct_outcomes_are_both_kept() -> None:
    """Dedupe must key on the outcome, not on the simulator: a different stop_reason is new information."""
    second = _row()
    second["results"] = [
        {
            "status": "SUCCEEDED",
            "simulator": "unicorn",
            "stop_reason": "END_ADDRESS",
            "limitations": [],
        }
    ]
    text = "\n".join(_emulation_status_section([_row(), second]))

    assert "pe_entry_is_bootstrap_trampoline" in text
    assert "END_ADDRESS" in text
