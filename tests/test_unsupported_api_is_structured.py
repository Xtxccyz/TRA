"""The blocking symbol must exist as a STRUCTURED field, not only inside a prose limitation.

MEASURED defect this pins (plan T2): `SimulationResult.unsupported_apis` is filled by a keyword classifier
over `observations`, but Speakeasy's blocking symbol lives in the report's `entry_points[].error`, which the
classifier never sees. So on the real 白象 run the field was `[]` while the limitation said

    Speakeasy observed 256 API call(s) and 1031 modelled VB6 runtime call(s)
    before stopping at unsupported_api api=MSVBVM60.ordinal_648 pc=0xfeedf0cc

A consumer wanting to know WHAT blocked the run had to parse that sentence.
"""
from __future__ import annotations

from threat_report_agent.simulation_adapters import _speakeasy_unsupported_api_names


def test_the_blocking_symbol_is_lifted_from_the_report_error() -> None:
    """The shape Speakeasy actually reports, per the module's own documented example."""
    entry = [
        {
            "error": {
                "type": "unsupported_api",
                "api_name": "MSVBVM60.ordinal_648",
                "instr": "disasm_failed",
            }
        }
    ]
    assert _speakeasy_unsupported_api_names(entry) == ["MSVBVM60.ordinal_648"]


def test_names_are_deduplicated_and_ordered() -> None:
    entry = [
        {"error": {"api_name": "MSVBVM60.ordinal_648"}},
        {"error": {"api_name": "MSVBVM60.ordinal_648"}},
        {"error": {"api_name": "msvcrt.__iob_func"}},
    ]
    assert _speakeasy_unsupported_api_names(entry) == [
        "MSVBVM60.ordinal_648",
        "msvcrt.__iob_func",
    ]


def test_a_run_without_an_error_yields_nothing() -> None:
    """A successful run must not invent a blocker."""
    assert _speakeasy_unsupported_api_names([]) == []
    assert _speakeasy_unsupported_api_names([{"ret_val": 0, "instr_count": 12}]) == []
    assert _speakeasy_unsupported_api_names(["not-a-mapping"]) == []
    assert _speakeasy_unsupported_api_names([{"error": "a string, not a mapping"}]) == []
    assert _speakeasy_unsupported_api_names([{"error": {}}]) == []
