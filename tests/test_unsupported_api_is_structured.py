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


def test_a_never_attempted_call_is_not_published_as_attempted() -> None:
    """MEASURED over-claim (third review, item 2): an unsupported call was ALSO counted as ATTEMPTED.

    `_observation_buckets` matched each row against every bucket's marker substrings independently, and the T2
    observation is `{"event": "unsupported_api", "name": ..., "kind": "unsupported"}` - a label containing BOTH
    "api" and "unsupported". So a call the emulator explicitly could NOT model appeared in `unsupported_apis`
    (correct) and in `attempted_apis` (a claim that it was attempted, which is false).

    The same naive matching could also place such a row in a BEHAVIOURAL bucket whenever its NAME happens to
    contain a marker - e.g. an ordinal named `..._http_...` landing in `network_intents`, which reports
    behaviour for a call that never ran (analysis-verification EC-2, a string read as behaviour).

    FAILS BEFORE THE FIX: `attempted_apis` contained the unsupported names.
    """
    from threat_report_agent.simulation_adapters import SimulationResult

    result = SimulationResult(
        status="FAILED",
        simulator="speakeasy",
        observations=[
            {"event": "unsupported_api", "name": "MSVBVM60.ordinal_648", "kind": "unsupported"},
            # A real, modelled call must still count as attempted - the fix must not empty the bucket.
            {"event": "api_call", "name": "kernel32.CreateFileW", "kind": "resolved_api"},
            # A never-modelled call whose NAME carries a behavioural marker must not fabricate behaviour.
            {"event": "unsupported_api", "name": "MSVBVM60.ordinal_http_send", "kind": "unsupported"},
        ],
    )
    payload = result.as_dict()

    attempted = [row.get("name") for row in payload["attempted_apis"]]
    assert attempted == ["kernel32.CreateFileW"], (
        "a call the emulator could not model was published as ATTEMPTED, or a real call was dropped: "
        f"attempted={attempted}"
    )
    assert [row.get("name") for row in payload["unsupported_apis"]] == [
        "MSVBVM60.ordinal_648",
        "MSVBVM60.ordinal_http_send",
    ], "the blocking dependencies must still be recorded"
    assert payload["network_intents"] == [], (
        "a never-modelled call whose name contains 'http' was published as an observed NETWORK behaviour - "
        "a string read as behaviour"
    )

