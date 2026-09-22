"""The report must be able to NAME the symbol that blocked emulation.

MEASURED on the 白象 sample `64da3378`: Speakeasy ran, hit the entry's runtime thunk, could not resolve
`MSVBVM60.ordinal_100`, jumped to its unmapped sentinel 0xfeedf0f0 and stopped. The product recorded
`stop_reason=EXECUTION_ERROR` with an EMPTY limitations list, so the published report could not tell the
reader whether the emulator was broken or a single runtime ordinal was missing. The structured error it
threw away was the whole diagnosis:

    {'type': 'unsupported_api', 'api_name': 'MSVBVM60.ordinal_100',
     'pc': '0xfeedf0f0', 'instr': 'disasm_failed'}

These tests pin the rendering so the name can never be dropped again.
"""
from __future__ import annotations

from threat_report_agent.simulation_adapters import _simulator_error_detail, _speakeasy_stop


def test_unsupported_api_error_names_the_symbol() -> None:
    """The 白象 case: the blocking ordinal must appear in the rendered detail."""
    entry = [
        {
            "error": {
                "type": "unsupported_api",
                "api_name": "MSVBVM60.ordinal_100",
                "pc": "0xfeedf0f0",
                "instr": "disasm_failed",
            },
            "ret_val": "0x0",
        }
    ]
    detail = _simulator_error_detail(entry[0]["error"])

    assert "MSVBVM60.ordinal_100" in detail
    assert "unsupported_api" in detail
    assert "0xfeedf0f0" in detail


def test_speakeasy_stop_returns_the_detail_when_it_fails() -> None:
    entry = [
        {
            "error": {
                "type": "unsupported_api",
                "api_name": "MSVBVM60.ordinal_100",
                "pc": "0xfeedf0f0",
            },
            "ret_val": "0x0",
        }
    ]
    status, stop_reason, detail = _speakeasy_stop(entry, instruction_budget=1000)

    assert status == "FAILED"
    assert stop_reason == "EXECUTION_ERROR"
    assert "MSVBVM60.ordinal_100" in detail, "the blocking symbol is the diagnosis; keep it"


def test_speakeasy_stop_detail_is_empty_on_success() -> None:
    """A successful stop must not invent a limitation."""
    entry = [{"ret_val": "0x0", "instr_count": 5}]
    status, stop_reason, detail = _speakeasy_stop(entry, instruction_budget=1000)

    assert status == "SUCCEEDED"
    assert stop_reason == "END_ADDRESS"
    assert detail == ""


def test_budget_exhaustion_is_distinguished_from_an_error() -> None:
    entry = [{"ret_val": "0x0", "instr_count": 5000}]
    status, stop_reason, detail = _speakeasy_stop(entry, instruction_budget=1000)

    assert status == "TIMED_OUT"
    assert stop_reason == "INSTRUCTION_BUDGET"
    assert detail == ""


def test_detail_never_collapses_to_a_class_name_only() -> None:
    """A non-mapping error must still carry its text, and an opaque mapping its keys."""
    assert "boom" in _simulator_error_detail(RuntimeError("boom"))
    opaque = _simulator_error_detail({"weird_a": 1, "weird_b": 2})
    assert "weird_a" in opaque and "weird_b" in opaque
