"""`UNKNOWN(...)` tokens must name a slot, and the summary must not count one slot twice.

Why this exists: the published 白象 body carried **32** `UNKNOWN(...)` tokens. Counting them by slot showed
that most of the impression of "the report is full of UNKNOWN" came from repetition and malformation rather
than from 32 distinct gaps:

    consumer      x6   `UNKNOWN(consumer)` AND `UNKNOWN(consumer: not recovered from available static evidence)`
    creation_flags x5
    fallback       x4  `fallback` is an ALIAS of the `failure_fallback` slot, which also appeared separately
    phase not recovered statically x4   <- a SENTENCE where the slot name belongs
    not recovered from available static evidence x2   <- the slot name was lost entirely

The token list below is copied verbatim from that body, so this file fails if the collapse regresses.
"""
from __future__ import annotations

from threat_report_agent.analyst_report import _official_unknown_slot

# Verbatim from the published revision's body, with their measured multiplicities.
MEASURED_TOKENS = [
    "UNKNOWN(creation_flags)",
    "UNKNOWN(consumer)",
    "UNKNOWN(fallback)",
    "UNKNOWN(phase not recovered statically)",
    "UNKNOWN(not recovered from available static evidence)",
    "UNKNOWN(loop: not recovered from available static evidence)",
    "UNKNOWN(consumer: not recovered from available static evidence)",
    "UNKNOWN(failure_fallback: not recovered from available static evidence)",
    "UNKNOWN(start_routine)",
    "UNKNOWN(join)",
    "UNKNOWN(endpoint + request_parameters)",
    "UNKNOWN(parent_identity + attribute_list)",
    "UNKNOWN(target_process + written_buffer)",
    "UNKNOWN(registry_value_name + run_key_path)",
    "UNKNOWN(start_routine + entry_body)",
    "UNKNOWN(actor_identity + validated_fact_match)",
]


def test_two_spellings_of_one_slot_collapse_to_one_key() -> None:
    assert _official_unknown_slot("UNKNOWN(consumer)") == _official_unknown_slot(
        "UNKNOWN(consumer: not recovered from available static evidence)"
    )


def test_an_alias_and_its_canonical_slot_collapse() -> None:
    """`fallback` is listed as an alias of `failure_fallback` in `_OFFICIAL_TEN_QUESTION_SLOTS`."""
    assert _official_unknown_slot("UNKNOWN(fallback)") == _official_unknown_slot(
        "UNKNOWN(failure_fallback: not recovered from available static evidence)"
    )
    assert _official_unknown_slot("UNKNOWN(fallback)") == "failure_fallback"


def test_a_sentence_in_the_slot_position_names_nothing() -> None:
    """These are malformed, not extra gaps: printing them beside real slots implies a slot was named."""
    assert _official_unknown_slot("UNKNOWN(not recovered from available static evidence)") == ""
    assert _official_unknown_slot("UNKNOWN(phase not recovered statically)") == ""


def test_multi_part_joins_keep_their_shape() -> None:
    """A genuine join slot must NOT be folded - it names two slots that failed to connect."""
    assert _official_unknown_slot("UNKNOWN(endpoint + request_parameters)") == "endpoint_+_request_parameters"
    assert _official_unknown_slot("UNKNOWN(start_routine + entry_body)") != ""
    assert _official_unknown_slot("UNKNOWN(actor_identity + validated_fact_match)") != ""


def test_a_payload_fragment_in_the_explanation_collapses_and_is_removed() -> None:
    """The verbatim token the published body carried, with its unbalanced parentheses.

    The decoded script was pasted into the slot explanation, and because the payload itself contains `(`,
    `UNKNOWN(...)` never closes: `re.fullmatch` cannot match it, so it became its own key and did NOT
    collapse with the real `UNKNOWN(consumer)`. A payload fragment was being published as the NAME of a
    missing slot.
    """
    from threat_report_agent.analyst_report import _repair_truncated_unknown_tokens, _sanitise_unknown_token

    payload_token = (
        'UNKNOWN(consumer: producer writes ace("v ba im fso, fo, Replace( UsrPrf & xtr = xtr '
        'new_down/"dataz, Repe("|A v a vbNullStri > 4)'
    )
    repaired = _repair_truncated_unknown_tokens(_sanitise_unknown_token(payload_token))
    assert repaired == "UNKNOWN(consumer)", f"payload survived the repair: {repaired!r}"
    assert _official_unknown_slot(repaired) == _official_unknown_slot("UNKNOWN(consumer)")


def test_the_measured_token_list_collapses_substantially() -> None:
    """The point of the fix, stated as a number so a regression is visible rather than argued about."""
    keys = [_official_unknown_slot(token) for token in MEASURED_TOKENS]
    distinct = {key for key in keys if key}
    malformed = sum(1 for key in keys if not key)

    assert malformed == 2, (
        f"expected 2 DISTINCT malformed tokens in the list ('phase not recovered statically' and the lost "
        f"slot name), got {malformed}. Note the multiplicities above are OCCURRENCE counts from the body "
        f"(4 and 2 = 6 occurrences); this list holds each distinct token once."
    )
    assert len(distinct) < len(MEASURED_TOKENS) - malformed, (
        "the measured list no longer collapses, so the summary will count duplicate slots again"
    )
    # `keys` is the LIST, so both spellings are present: that two entries share one key IS the fix. The
    # de-duplication itself happens in `_collect_official_unknowns`, which keeps one token per key.
    assert keys.count("consumer") == 2, "both consumer spellings must map to the same key"
    assert keys.count("failure_fallback") == 2, "`fallback` and `failure_fallback` must share a key"
    assert keys.count("creation_flags") == 1
    # 14 well-formed tokens collapse to 12 keys: one consumer pair and one fallback pair.
    assert len(distinct) == 12
