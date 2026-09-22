"""The HTTP consumer/request claim must rest on object-level evidence (ADR-0035).

``PersistHow._recovered_http_how_fields`` collected transport API *names* by
regex over decoded plaintext and then picked ``consumer`` from a hardcoded
preference list, and the caller set ``request=recovered`` from the same name
presence.  Plan 5.2/5.3 and ADR-0035 forbid calling that a consumer link: a name
appearing in decoded text says nothing about which call consumes which buffer.

These tests keep the legitimate half (the decoded WinHTTP API sequence and the
decoded endpoint stay reported as recovered *configuration*) while requiring the
consumer and the request claim to be backed by an argument-level binding.
"""

from __future__ import annotations

from threat_report_agent.persist_how import PersistHow

_URL = "http://203.0.113.10/ComHost.exe"


def _decode_row(row_id: str, text: str) -> dict[str, object]:
    return {
        "id": row_id,
        "kind": "decode_result",
        "nature": "STATIC_DERIVED",
        "value": {
            "formula": "single_key_plus_step_xor_const",
            "decoded_preview": text,
            "decoded_strings": [text],
            "status": "VERIFIED_STATIC_DATA",
        },
    }


def _name_only_evidence() -> list[dict[str, object]]:
    return [
        _decode_row("decode-send", "WinHttpSendRequest"),
        _decode_row("decode-open-request", "WinHttpOpenRequest"),
        _decode_row("decode-recv", "WinHttpReceiveResponse"),
        _decode_row("decode-url", _URL),
    ]


def _argument_trace_row(row_id: str, api: str, *, address: int) -> dict[str, object]:
    return {
        "id": row_id,
        "kind": "api_argument_trace",
        "nature": "STATIC_OBSERVED",
        "value": {
            "api": api,
            "callsite": "0x140031f80",
            "function_entry": "0x140031f80",
            "static_only": True,
            "arguments": [
                {"index": 0, "name": "hRequest", "resolved": True, "value": "0x1"},
                {
                    "index": 1,
                    "name": "lpszHeaders",
                    "resolved": True,
                    "value": hex(address),
                },
            ],
        },
    }


def test_decoded_transport_api_names_alone_do_not_name_a_consumer() -> None:
    how = PersistHow._recovered_http_how_fields(_name_only_evidence())
    assert how["consumer"] == ""
    assert how["endpoint"] == _URL


def test_decoded_transport_api_names_are_still_reported_as_configuration() -> None:
    """Do not over-correct: 9.3 wants the decoded WinHTTP sequence and URL."""
    how = PersistHow._recovered_http_how_fields(_name_only_evidence())
    for name in ("WinHttpSendRequest", "WinHttpOpenRequest", "WinHttpReceiveResponse"):
        assert name in how["apis"]
    assert how["endpoint"] == _URL


def test_argument_level_transport_trace_does_name_the_consumer() -> None:
    evidence = [
        *_name_only_evidence(),
        _argument_trace_row(
            "trace-send", "WinHttpSendRequest", address=0x1400560D8
        ),
    ]
    how = PersistHow._recovered_http_how_fields(evidence)
    assert how["consumer"] == "WinHttpSendRequest"


def test_object_level_join_row_also_names_the_consumer() -> None:
    evidence = [
        *_name_only_evidence(),
        {
            "id": "join-1",
            "kind": "decode_result",
            "nature": "STATIC_DERIVED",
            "value": {
                "formula": "key_table_modulo_xor_counter",
                "decoded_preview": "WinHttpOpenRequest",
                "output_buffer": {"address_space": "image", "address": 0x1400560D8, "length": 31},
                "input_buffer": {"address_space": "image", "address": 0x1400560D8, "length": 31},
                "join_status": "JOINED_STATIC",
            },
        },
    ]
    how = PersistHow._recovered_http_how_fields(evidence)
    assert how["consumer"]
    assert how["consumer"].casefold().startswith("winhttp")


def test_preference_list_does_not_upgrade_an_unbound_name() -> None:
    """WinHttpSendRequest sits first in the preference list; that alone is not proof."""
    evidence = [
        _decode_row("decode-send", "WinHttpSendRequest"),
        _decode_row("decode-recv", "WinHttpReceiveResponse"),
        _decode_row("decode-url", _URL),
    ]
    how = PersistHow._recovered_http_how_fields(evidence)
    assert how["consumer"] == ""
    assert how["endpoint"] == _URL


def _http_spec(evidence: list[dict[str, object]]) -> dict[str, object]:
    from threat_report_agent.service import AnalysisService

    specs = AnalysisService._persist_how_claim_specs(
        artifact_path="Resume.pdf.exe.VIR",
        evidence=evidence,
    )
    http_specs = [
        item for item in specs if str(getattr(item[0], "id", "") or "") == "http-download"
    ]
    assert http_specs, "no http-download claim spec was produced"
    return http_specs[0][1]


def test_decoded_names_alone_do_not_claim_request_recovered() -> None:
    mechanism = str(_http_spec(_name_only_evidence())["mechanism"])
    assert "request=recovered" not in mechanism
    assert "request=UNKNOWN(request)" in mechanism
    # The decoded configuration half must survive the correction.
    assert "WinHttpSendRequest" in mechanism
    assert _URL in mechanism


def test_argument_level_binding_claims_request_recovered() -> None:
    evidence = [
        *_name_only_evidence(),
        _argument_trace_row("trace-openreq", "WinHttpOpenRequest", address=0x1400560D8),
    ]
    mechanism = str(_http_spec(evidence)["mechanism"])
    assert "request=recovered" in mechanism
