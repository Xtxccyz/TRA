"""Recovered payload must never be published as the explanation of a missing slot.

MEASURED defect this pins. The published body's gap list carried a 400-character slice of the DECODED
SCRIPT, mid-token, as the reason a consumer slot was missing:

    UNKNOWN(consumer: producer writes ace("v ba im fso, fo, Replace( UsrPrf & xtr = xtr
    new_down/"dataz, Repe("|A v a vbNullStri > 4)

Three things are wrong with that. It answers nothing — a payload slice is not a consumer. It leaks a
payload fragment into the primary body. And because `_slot_display` treats any non-empty prose as
`filled`, it SUPPRESSED the honest `UNKNOWN(consumer)` token that should have been printed.

Both directions matter: a detector that fires on everything would delete legitimate slot values.
"""
from __future__ import annotations

import pytest

from threat_report_agent.analyst_report import _is_raw_decoded_fragment, _slot_display

REAL_FRAGMENT = (
    'ace("v ba im fso, fo, Replace( UsrPrf & xtr = xtr new_down/'
    '"dataz, Repe("|A v a vbNullStri > 4)'
)


def test_the_real_published_fragment_is_detected() -> None:
    assert _is_raw_decoded_fragment(REAL_FRAGMENT) is True


@pytest.mark.parametrize(
    "text",
    [
        "consumer(" + "a" * 80,
        "producer writes 写入到 the declared 位置 and then " + "x" * 30,
        "a,b;c:d/e\\f|g(h)i!j?k,l;m:n/o\\p|q(r)s!t?u," * 2,
    ],
)
def test_structural_blob_signatures_are_detected(text: str) -> None:
    assert _is_raw_decoded_fragment(text) is True


@pytest.mark.parametrize(
    "text",
    [
        "the response buffer is consumed by a subsequent CreateProcess call on the same object",
        "consumer=WinHttpSendRequest bound to a recovered endpoint and request parameters",
        "the recovered pointer (0x401000) is dereferenced by the caller after the runtime call",
        'ace("v ba im',
        "",
    ],
)
def test_real_prose_is_never_treated_as_payload(text: str) -> None:
    assert _is_raw_decoded_fragment(text) is False


def test_consumer_slot_collapses_a_payload_slice_to_the_honest_token() -> None:
    """The suppressed-token consequence: a payload slice must NOT mark the slot filled."""
    row = {"catalog_id": "config-and-crypto", "consumer": REAL_FRAGMENT}
    display, filled = _slot_display(row, "consumer", ("consumer", "consumers"), "consumer")

    assert filled is False, "a payload slice must not count as a recovered consumer"
    assert display == "UNKNOWN(consumer)"


def test_consumer_slot_still_reports_a_real_consumer() -> None:
    """The other direction: a genuine consumer value must survive."""
    row = {
        "catalog_id": "config-and-crypto",
        "consumer": "CreateProcessW consumes the decoded command buffer",
    }
    display, filled = _slot_display(row, "consumer", ("consumer", "consumers"), "consumer")

    assert filled is True
    assert "CreateProcessW" in display
