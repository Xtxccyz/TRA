"""Decoded configuration is part of the string table the resolver joins against.

A sample that resolves APIs dynamically (``LoadLibrary`` + ``GetProcAddress``)
keeps the procedure *names* inside an encoded blob.  Those names therefore only
exist at their image addresses after the static decode.  The dynamic-resolution
join maps a ``GetProcAddress`` argument through ``strings_by_address``; if the
decoded strings are missing from that table, the resolver can only ever name the
APIs that were already plaintext in the image, and the decode -> consumer link
can never close.

``decoded_config_string_table`` is the pure projection that feeds them in.  The
service merges it with ``setdefault`` so a genuinely static string at the same
address always wins.
"""

from __future__ import annotations

from threat_report_agent.static_analysis import (
    decoded_config_string_table,
    recover_dynamic_api_resolutions,
)

_ADDRESS = 0x1400563D6


def _hit(text: str, address: object = _ADDRESS) -> dict[str, object]:
    return {
        "status": "VERIFIED_STATIC_DATA",
        "virtual_address": address,
        "decoded_preview": text,
        "decoded_text": text,
        "output_buffer": {"address_space": "image", "address": address, "length": len(text)},
    }


def test_decoded_hit_becomes_an_address_to_string_entry() -> None:
    table = decoded_config_string_table([_hit("WinHttpOpenRequest")])
    assert "0x1400563d6" in table
    assert "1400563d6" in table
    assert str(_ADDRESS) in table
    for key in ("0x1400563d6", "1400563d6", str(_ADDRESS)):
        assert table[key] == "WinHttpOpenRequest"


def test_preview_wins_over_a_longer_decoded_text() -> None:
    hit = _hit("WinHttpSendRequest")
    hit["decoded_text"] = "WinHttpSendRequest\x00other bytes here"
    table = decoded_config_string_table([hit])
    assert table["0x1400563d6"] == "WinHttpSendRequest"


def test_hits_without_address_or_text_are_skipped() -> None:
    assert decoded_config_string_table([_hit("WinHttpOpen", address=None)]) == {}
    assert decoded_config_string_table([_hit("", address=_ADDRESS)]) == {}
    assert decoded_config_string_table([]) == {}


def test_first_hit_wins_for_the_same_address() -> None:
    table = decoded_config_string_table(
        [_hit("WinHttpOpenRequest"), _hit("WinHttpSendRequest")]
    )
    assert table["0x1400563d6"] == "WinHttpOpenRequest"


def _resolver_function(address: int) -> dict[str, object]:
    """A GetProcAddress call whose RDX producer is an absolute data reference."""
    return {
        "entry": "0x140003000",
        "instructions": [
            {
                "address": "0x140003010",
                "mnemonic": "LEA",
                "text": f"LEA RDX,[{hex(address)}]",
            },
            {
                "address": "0x140003018",
                "mnemonic": "CALL",
                "text": "CALL qword ptr [PTR_GetProcAddress]",
            },
        ],
        "calls": [
            {
                "address": "0x140003018",
                "target": "GetProcAddress",
                "text": "CALL qword ptr [PTR_GetProcAddress]",
            }
        ],
        "references_from": [],
        "references_to": [],
    }


def test_resolver_can_now_name_a_decoded_api() -> None:
    """The join only works because the decoded name is in the string table."""
    function = _resolver_function(_ADDRESS)

    without = recover_dynamic_api_resolutions(function, {})
    assert not any(
        str(row.get("api_name")) == "WinHttpOpenRequest" for row in without
    ), "precondition: the decoded name is not plaintext in the image"

    table = decoded_config_string_table([_hit("WinHttpOpenRequest")])
    with_decoded = recover_dynamic_api_resolutions(function, table)
    assert any(
        str(row.get("api_name")) == "WinHttpOpenRequest" for row in with_decoded
    ), f"decoded API was not resolved; rows={with_decoded}"
