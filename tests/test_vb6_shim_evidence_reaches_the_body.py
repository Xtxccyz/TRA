"""The VB6 shim's LIMITS and its ARGUMENT PAIRS must reach the PUBLISHED body, not just a definition.

MEASURED root cause this pins (round 80). `destination_observable` and `argument_pairs` were added to
`Vb6ShimState.as_evidence()` - and **no production module calls that method**: `src/` contains no caller
at all, only host probes call it. So both fields were unreachable from every evidence row and every report,
while the shim itself was running correctly (1,031 modelled calls, 1,028 strings read). The symptom was read
as "the shim never ran", because the check looked for a NAME with no writer instead of the CARRIER that
holds the fact.

The published path has THREE hops, and a field added at one hop but not the others is dropped in silence:

    1. the `vb6_shim` observation event      simulation_adapters.py  (`_speakeasy_adapter`)
    2. the `shim_summary` WHITELIST          reporting.py            (`build_emulation_status_projection`)
    3. the published Chinese body            analyst_report.py       (`_emulation_status_section`)

These tests assert the PATH, not an identifier: the same contract tuple is required at all three hops, so
adding a field at one hop alone fails. `test_the_carrier_reads_the_shims_own_evidence_method` additionally
fails if hop 1 stops deriving from the shim's own publication method, which is what keeps the stated limits
from drifting away from the numbers they bound.
"""
from __future__ import annotations

import inspect

from threat_report_agent import analyst_report, reporting, simulation_adapters

#: The fields whose whole purpose is to stop a reader drawing a stronger conclusion than the record supports.
#: `destination_observable` says the harness cannot see where a string is written; the pair fields say WHICH
#: source record a string came from and how many were kept.
CONTRACT_KEYS = (
    "destination_observable",
    "argument_pairs",
    "argument_pairs_cap",
    "argument_pairs_recorded",
)

#: Text that exists ONLY inside an argument pair. If it ever appears in the body, the decoded payload records
#: were pasted into the report - the exact regression an earlier revision of this section had to be cleaned of.
PAYLOAD_TEXT = "SECRET-ARG-TEXT-DO-NOT-PUBLISH"


def _observation(**overrides: object) -> dict[str, object]:
    event: dict[str, object] = {
        "event": "vb6_shim",
        "registered": 132,
        "modelled_calls": 1031,
        "strings_observed": 1028,
        "distinct_records": 868,
        "decoded_chars": 6140,
        "destination_observable": False,
        "sample_strings_cap": 32,
        "argument_pairs": [
            {"address": "0x40d2c0", "text": PAYLOAD_TEXT},
            {"address": "0x40d2e8", "text": PAYLOAD_TEXT + "-2"},
        ],
        "argument_pairs_cap": 16,
        "argument_pairs_recorded": 614,
    }
    event.update(overrides)
    return event


def _evidence(event: dict[str, object]) -> dict[str, object]:
    return {
        "ev-1": {
            "id": "ev-1",
            "kind": "simulation_result",
            "value": {
                "status": "FAILED",
                "simulator": "controlled-emulator",
                "stop_reason": "EXECUTION_ERROR",
                # The measured pathology: a FAILED stop reason on a run that modelled 1,031 calls.
                "observations": [event],
            },
            "anchor": {},
        }
    }


def _body_for(event: dict[str, object]) -> str:
    projection = reporting.build_emulation_status_projection(_evidence(event))
    assert projection.get("results"), "the projection dropped the simulation_result entirely"
    lines = analyst_report._emulation_status_section([projection])
    assert lines, "the chapter rendered nothing at all"
    return "\n".join(lines)


def _code_only(source: str) -> str:
    """Strip comments from a function's source before asserting on it.

    MEASURED defect this fixes: every hop test below is a source grep, and a grep is satisfied by a COMMENT
    that merely names the key. `.scratch/canfail-three-hop.py` caught this concretely - replacing
    `shim_evidence = shim_state.as_evidence()` with `shim_evidence = {}` still passed, because the explanatory
    comment above it contains the text `as_evidence()`. The probe was valid; the test was not.

    The strip is deliberately simple and slightly over-eager: a full-line comment is dropped, and a trailing
    `#` is cut when it is not preceded by an odd number of double quotes (i.e. it is outside a string, to a
    first approximation). Over-stripping can only make these tests stricter, never more permissive, which is
    the safe direction for a guard.
    """
    kept: list[str] = []
    for line in source.splitlines():
        if line.lstrip().startswith("#"):
            continue
        cut = len(line)
        for index, character in enumerate(line):
            if character == "#" and line[:index].count('"') % 2 == 0:
                cut = index
                break
        kept.append(line[:cut])
    return "\n".join(kept)


# --------------------------------------------------------------------------------------------------
# The path: the same contract must be named at all three hops.
# --------------------------------------------------------------------------------------------------


def test_hop1_the_adapter_publishes_the_contract_keys() -> None:
    source = _code_only(inspect.getsource(simulation_adapters._speakeasy_adapter))
    missing = [key for key in CONTRACT_KEYS if f'"{key}"' not in source]
    assert not missing, (
        f"the vb6_shim observation event does not carry {missing}; the fact cannot enter the record at all"
    )


def test_hop2_the_projection_whitelist_carries_the_contract_keys() -> None:
    source = _code_only(inspect.getsource(reporting.build_emulation_status_projection))
    missing = [key for key in CONTRACT_KEYS if f'"{key}"' not in source]
    assert not missing, (
        f"`shim_summary` is a whitelist and drops {missing}; a field added upstream alone never reaches "
        "the renderer"
    )


def test_hop3_the_body_reads_the_contract_keys() -> None:
    source = _code_only(inspect.getsource(analyst_report._emulation_status_section))
    missing = [key for key in CONTRACT_KEYS if f'"{key}"' not in source]
    assert not missing, f"the published chapter never reads {missing} from `shim`"


def test_the_carrier_reads_the_shims_own_evidence_method() -> None:
    """A definition nobody calls is not evidence.

    The original defect: the fields were correct, tested, and unreachable. Hop 1 must derive them from
    `as_evidence()` so the stated limits cannot drift from the numbers they bound.
    """
    source = _code_only(inspect.getsource(simulation_adapters._speakeasy_adapter))
    assert "shim_state.as_evidence()" in source, (
        "the published carrier no longer CALLS the shim's own evidence method, so its fields are free to "
        "drift from the observation it publishes"
    )


# --------------------------------------------------------------------------------------------------
# Behaviour: what the reader actually gets.
# --------------------------------------------------------------------------------------------------


def test_the_body_publishes_the_shims_inability_to_see_writes() -> None:
    body = _body_for(_observation())
    assert "不能" in body and "写入何处" in body, (
        "the body reports a string count without the boundary that forbids reading it as a copy/write"
    )


def test_a_legacy_row_without_the_flag_still_publishes_the_boundary() -> None:
    """Absence must not restore the stronger reading.

    An evidence row written before this field existed carries nothing. The honest default for "this harness
    cannot see where the sample writes" is to say so; only an explicit claim of observability may suppress it.
    """
    event = _observation()
    event.pop("destination_observable")
    body = _body_for(event)
    assert "写入何处" in body


def test_an_explicit_observability_claim_suppresses_the_boundary() -> None:
    """The check is a fact about the record, not a hardcoded sentence."""
    body = _body_for(_observation(destination_observable=True))
    assert "写入何处" not in body


def test_the_body_publishes_the_source_record_addresses_and_the_caps() -> None:
    body = _body_for(_observation())
    assert "0x40d2c0" in body, "the source record address - which slot the string came from - was dropped"
    assert "0x40d2e8" in body
    # Assert the LABELLED quantities, not bare digits.
    #
    # MEASURED defect in the first version of this test: it asserted `"614" in body`, which the same render
    # satisfies via `decoded_chars=6140`, so the assertion still passed when the recorded count rendered as
    # `None`. `"16" in body` was weaker for the same reason. The quantities are now asserted together with the
    # scope each one names.
    assert "共记录 `614` 对" in body, "the recorded pair count is not published with its scope named"
    assert "保留前 `16` 对" in body, "the pair cap is not published with its scope named"


def test_a_missing_pair_counter_never_renders_a_placeholder() -> None:
    """A counter the record does not carry must not be published as if it were a fact.

    MEASURED: with the keys absent this line rendered 「共记录 `None` 条，上限 `None`」 into the Chinese analyst
    body. Declining to state a number is honest; printing `None` is not.
    """
    event = _observation()
    event.pop("argument_pairs_recorded")
    event.pop("argument_pairs_cap")
    body = _body_for(event)
    assert "None" not in body, "a placeholder was published as a fact"
    assert "未记录" in body, "the line did not say the counters were unrecorded"
    assert "0x40d2c0" in body, "the addresses themselves were dropped along with the counters"


def test_the_decoded_payload_text_is_never_pasted_into_the_body() -> None:
    """These strings ARE the sample's decoded payload records.

    MEASURED: an earlier revision of this section re-introduced exactly the fragment the body had just been
    cleaned of. The addresses carry the correlation information; the text stays in the evidence layer.
    """
    body = _body_for(_observation())
    assert PAYLOAD_TEXT not in body, "the decoded argument text was pasted into the published body"


def test_a_shim_that_registered_nothing_gets_no_boundary_sentence() -> None:
    """The C1 sentence bounds a READ COUNT, so it must not print when no count was published.

    MEASURED defect in the first version of this test: it asserted
    `"VB6 运行时 stub" in body or "controlled-emulator" in body`, and the status line always renders the
    simulator name - so it could not fail, whatever the shim did. The direction that actually matters is the
    opposite one, and it is reachable: the shim installs but `register_vb6_shim` raises, leaving
    `shim_registered` empty and all three counts zero.
    """
    body = _body_for(
        _observation(
            argument_pairs=[],
            argument_pairs_recorded=0,
            strings_observed=0,
            modelled_calls=0,
            registered=0,
        )
    )
    # Positive control: the chapter is present, so an empty body is not what makes the assertions below pass.
    assert "controlled-emulator" in body, "the chapter did not render, so this fixture proves nothing"
    assert "VB6 运行时 stub" not in body, "a count sentence was published for a shim that reported no counts"
    assert "写入何处" not in body, "the boundary refers to a read count that was never published above it"
