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

MIGRATED in P3.7 (this file's four `getsource` sites): the three hop tests used to grep each hop's SOURCE for
the key names, and the carrier test grepped hop 1's source for `shim_state.as_evidence()`. A grep is satisfied
by any mention and says nothing about what a reader receives, so all four sites are now BEHAVIOURAL: hop 1 is
observed by running the REAL `_speakeasy_adapter` against a fake Speakeasy that fires one VB6 call, and hops 2
and 3 by running the real projection and the real renderer over the event hop 1 actually published.
"""
from __future__ import annotations

import struct
import sys
import types

from threat_report_agent import analyst_report, reporting, simulation_adapters
from threat_report_agent.emulation import vb6_runtime_shim
from threat_report_agent.emulation.policy import SimulationRequest

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

#: The one pair the fake run below makes the REAL shim record, and the source-record address it came from.
ARGUMENT_TEXT = "vb6-source-record-text"
ARGUMENT_ADDRESS = 0x402C08


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


# --------------------------------------------------------------------------------------------------
# The path, observed as BEHAVIOUR: hop 1 runs for real, and hops 2-3 carry what hop 1 published.
# --------------------------------------------------------------------------------------------------


class _FakeSpeakeasy:
    """The Speakeasy surface `_speakeasy_adapter` uses, with exactly one VB6 runtime call to model.

    It exists so hop 1 can be read as behaviour: the adapter is RUN, and the `vb6_shim` observation it
    publishes is inspected, instead of grepping the adapter's source for the key names. The call is
    dispatched the way Speakeasy dispatches an unimplemented API (`hook.cb(self, imp_api, None, argv)`),
    so the recorded pair is produced by the production handler, not by a stub of it.
    """

    def __init__(self, config: object = None, logger: object = None) -> None:
        self.config = config
        self.hooks: dict[tuple[str, str], object] = {}
        encoded = ARGUMENT_TEXT.encode("utf-16-le")
        self.memory = {
            ARGUMENT_ADDRESS - 4: struct.pack("<I", len(encoded)),
            ARGUMENT_ADDRESS: encoded,
        }

    def load_module(self, data: object = None) -> types.SimpleNamespace:
        del data
        # No `base`/`image_size`: `_speakeasy_start_address` declines, so `run_module` is the path taken.
        return types.SimpleNamespace()

    def add_api_hook(
        self,
        handler: object,
        module: str = "",
        api_name: str = "",
        argc: int = 0,
        call_conv: object = None,
    ) -> object:
        del argc, call_conv
        self.hooks[(module, api_name)] = handler
        return handler

    def run_module(self, module: object) -> None:
        del module
        handler = self.hooks[("msvbvm60", "__vbastrcopy")]
        handler(self, "__vbastrcopy", None, [])  # type: ignore[operator]

    def get_report(self) -> dict[str, object]:
        return {}

    # --- the emulator surface the shim's handler reads ---------------------------------------------
    def mem_read(self, address: int, size: int) -> bytes:
        for base, payload in self.memory.items():
            if base <= address and address + size <= base + len(payload):
                return payload[address - base : address - base + size]
        raise ValueError(f"unmapped 0x{address:x}")

    def get_register_state(self) -> dict[str, str]:
        return {"edx": hex(ARGUMENT_ADDRESS)}


def _run_adapter_once(monkeypatch) -> tuple[dict[str, object], object]:
    """Run the REAL `_speakeasy_adapter` against the fake Speakeasy.

    Returns the `vb6_shim` observation it published and the shim state that produced it, so a test can
    compare what was published against the shim's own `as_evidence()` publication.
    """
    captured: list[object] = []
    real_install = vb6_runtime_shim.install_vb6_shim

    def install(se: object, **kwargs: object):
        state, handlers = real_install(se, **kwargs)
        captured.append(state)
        return state, handlers

    monkeypatch.setattr(vb6_runtime_shim, "install_vb6_shim", install)
    fake_module = types.ModuleType("speakeasy")
    fake_module.Speakeasy = _FakeSpeakeasy  # type: ignore[attr-defined]
    fake_module.__file__ = ""
    monkeypatch.setitem(sys.modules, "speakeasy", fake_module)

    result = simulation_adapters._speakeasy_adapter(
        SimulationRequest(
            "speakeasy",
            "sample.exe",
            input_bytes=b"MZ" + b"\x00" * 64,
            timeout_seconds=1,
            instruction_budget=1000,
            entry_address=0,
        )
    )
    assert len(captured) == 1, "the adapter never installed the VB6 shim, so nothing below is reachable"
    events = [item for item in result.observations if item.get("event") == "vb6_shim"]
    assert events, f"the adapter published no `vb6_shim` observation: {result.observations}"
    return events[-1], captured[0]


def test_hop1_the_adapter_publishes_the_contract_keys(monkeypatch) -> None:
    """Hop 1, as behaviour: run the adapter and read the event; grep the source for nothing."""
    event, state = _run_adapter_once(monkeypatch)
    shim_evidence = state.as_evidence()  # type: ignore[attr-defined]
    # Positive control: the shim really did record the one pair this fixture dispatches, so the equality
    # below is not an assertion about two empty values.
    assert shim_evidence["argument_pairs_recorded"] == 1, "the fixture did not record the pair it dispatches"
    assert shim_evidence["argument_pairs"], "the fixture recorded no pair, so hop 1 proves nothing"
    missing = [key for key in CONTRACT_KEYS if key not in event]
    assert not missing, (
        f"the vb6_shim observation event does not carry {missing}; the fact cannot enter the record at all"
    )
    assert {key: event[key] for key in CONTRACT_KEYS} == {
        key: shim_evidence[key] for key in CONTRACT_KEYS
    }, "the published event disagrees with the shim's own evidence, so the path is not a pass-through"


def test_hop2_the_projection_whitelist_carries_the_contract_keys() -> None:
    """Hop 2, as behaviour: the projection must hand the renderer the same four values it was given."""
    event = _observation()
    projection = reporting.build_emulation_status_projection(_evidence(event))
    assert projection.get("results"), "the projection dropped the simulation_result entirely"
    shim = projection["results"][0]["shim"]
    missing = [key for key in CONTRACT_KEYS if key not in shim]
    assert not missing, (
        f"`shim_summary` is a whitelist and drops {missing}; a field added upstream alone never reaches "
        "the renderer"
    )
    assert {key: shim[key] for key in CONTRACT_KEYS} == {
        key: event[key] for key in CONTRACT_KEYS
    }, "the `shim_summary` whitelist altered a contract value on its way to the renderer"


def test_hop3_the_body_reads_the_contract_keys() -> None:
    """Hop 3, as behaviour: changing any contract value must change the published body.

    `.scratch/canfail-three-hop.py`'s lesson was that a grep is satisfied by a mention. This direction
    cannot be satisfied by a mention: each key is moved to a different value and the rendered chapter
    has to move with it, which only happens if the renderer actually READS the key.
    """
    baseline = _body_for(_observation())
    varied = {
        "destination_observable": _observation(destination_observable=True),
        "argument_pairs": _observation(
            argument_pairs=[{"address": "0xdeadbeef", "text": PAYLOAD_TEXT}]
        ),
        "argument_pairs_cap": _observation(argument_pairs_cap=7),
        "argument_pairs_recorded": _observation(argument_pairs_recorded=5),
    }
    for key, event in varied.items():
        assert _body_for(event) != baseline, (
            f"changing `{key}` left the published chapter byte-identical: the renderer never reads it, "
            "so the field cannot bound the number it was added to bound"
        )


def test_the_carrier_reads_the_shims_own_evidence_method(monkeypatch) -> None:
    """A definition nobody calls is not evidence.

    The original defect: the fields were correct, tested, and unreachable. Hop 1 must derive them from
    `as_evidence()` so the stated limits cannot drift from the numbers they bound.

    Behavioural discriminator: `as_evidence()` is replaced by a sentinel whose four contract values differ
    from the honest ones the real state would report. If the carrier kept reading the shim's attributes
    directly - or stopped calling the publication method at all - the sentinel could not reach the event.
    """
    sentinel = {
        "destination_observable": True,
        "argument_pairs": [{"address": "0xsentinel", "text": "sentinel"}],
        "argument_pairs_cap": 7,
        "argument_pairs_recorded": 4242,
    }

    def as_evidence(self: object) -> dict[str, object]:  # noqa: ARG001 - sentinel publication
        return dict(sentinel)

    monkeypatch.setattr(vb6_runtime_shim.Vb6ShimState, "as_evidence", as_evidence)
    event, _state = _run_adapter_once(monkeypatch)
    assert {key: event[key] for key in CONTRACT_KEYS} == sentinel, (
        "the published carrier no longer derives its contract fields from the shim's own evidence method, "
        "so its fields are free to drift from the observation it publishes"
    )
    # The dependency is real and not incidental: with the publication method unavailable the carrier falls
    # back to the honest defaults and LOSES the pair the state actually holds. A carrier that read the
    # shim's attributes directly would keep the pair here, so this control is what makes the sentinel above
    # a discriminator rather than a coincidence.
    monkeypatch.setattr(vb6_runtime_shim.Vb6ShimState, "as_evidence", lambda self: {})
    event_without, state = _run_adapter_once(monkeypatch)
    assert state.argument_pairs, "the fixture recorded no pair, so this control proves nothing"  # type: ignore[attr-defined]
    assert event_without["argument_pairs"] == [], "the pair survived without `as_evidence()`, so hop 1 does not use it"
    assert event_without["argument_pairs_recorded"] == 0


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
