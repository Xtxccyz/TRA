"""Playbook matching must return the same playbooks, far faster.

`MechanismPlaybookRegistry.matching` is on the hottest path in the product.  A live
stack of a stalled run:

    _run_investigation_loop -> run_until_converged -> run
      -> _evaluate_gate -> Verifier.evaluate -> MechanismPlaybookRegistry.matching

It evaluated, per playbook, ``any(term in text or term in kinds for term in
trigger_terms)`` against the joined corpus text.  With 115 playbooks and ~5 terms
each that is ~575 full scans of a string that reaches **71 MB** on the real sample,
and the same call happens inside `propose` too.  Measured: one `propose` was
9.9-10.7 s and `Verifier.evaluate` about 0.22 s per MB of accumulated text.

The fix finds the matched terms in ONE regex pass over the text instead of one scan
per term, then selects the playbooks whose terms are in that set.  These tests pin
that it selects exactly the same playbooks, including the cross-boundary case a
naive "match each term against text only" implementation would get wrong.
"""

from __future__ import annotations

from threat_report_agent.investigation import MechanismPlaybookRegistry


def _original_matching(registry, rows):
    """The pre-fix selection, transcribed verbatim, as the oracle."""
    rows = list(rows)
    text = " ".join(str(row.get("value", "")) for row in rows).casefold()
    kinds = {str(row.get("kind", "")).casefold() for row in rows}
    return tuple(
        item
        for item in registry._playbooks
        if any(term in text or term in kinds for term in item.trigger_terms)
    )


def _rows(*values: tuple[str, str]) -> list[dict[str, object]]:
    return [
        {"id": f"ev-{index}", "kind": kind, "value": {"text": value}}
        for index, (kind, value) in enumerate(values)
    ]


CORPORA: list[list[dict[str, object]]] = [
    _rows(("string", "http://69.48.228.74/ComHost.exe")),
    _rows(("api_argument_trace", "CreateProcessW")),
    _rows(("string", "schtasks/create/tn"), ("function", "FUN_140004605")),
    _rows(("process_creation_flags", "0x09080008"), ("string", "explorer.exe")),
    _rows(("function_instruction_window", "cmp rax, 0x493e1")),
    _rows(("string", "SOFTWARE\\Microsoft\\Windows Defender\\SpyNet")),
    _rows(("string", "L$@H"), ("cfg_block", "jmp 0x140001000")),
    _rows(("decode_result", "WinHttpSendRequest"), ("string", "VirtualAlloc")),
    [],
]


def test_matching_selects_the_same_playbooks_as_the_original() -> None:
    registry = MechanismPlaybookRegistry()
    for rows in CORPORA:
        expected = [item.id for item in _original_matching(registry, rows)]
        actual = [item.id for item in registry.matching(rows)]
        assert actual == expected, f"matching diverged for {rows!r}"


def test_matching_is_order_independent_like_the_original() -> None:
    registry = MechanismPlaybookRegistry()
    rows = _rows(("string", "WinHttpOpen"), ("function", "FUNC_1"))
    forward = [item.id for item in registry.matching(rows)]
    backward = [item.id for item in registry.matching(list(reversed(rows)))]
    assert forward == backward


def test_a_kind_is_also_a_trigger_term_so_kinds_must_be_scanned() -> None:
    """The kinds clause is LOAD-BEARING - a text-only scan loses real matches.

    Measured: ``encoded_blob`` is BOTH an evidence kind and a playbook trigger term.
    The original tested ``term in kinds`` against the set of kind strings, so a
    corpus whose decode evidence is recognised purely by that KIND matches
    ``xor-config-recovery`` / ``v3-config-decoder`` through the kinds half alone.

    An optimisation that scans only the joined VALUE text therefore drops those
    playbooks.  This test fails loudly if anyone removes the kinds from the scanned
    text, or if the ``encoded_blob`` relation changes.
    """
    registry = MechanismPlaybookRegistry()
    terms = {term for item in registry._playbooks for term in item.trigger_terms}
    assert "encoded_blob" in terms, "the encoded_blob trigger term disappeared"

    rows = [{"id": "ev-1", "kind": "encoded_blob", "value": {"blob": "qqqq"}}]
    expected = [item.id for item in _original_matching(registry, rows)]
    actual = [item.id for item in registry.matching(rows)]
    assert actual == expected
    assert expected, (
        "a corpus whose only signal is the encoded_blob KIND must still match a "
        "decode playbook; if this is empty the kinds clause is no longer exercised"
    )


def test_trigger_term_and_kind_overlap_is_measured() -> None:
    """Records the one kind/term collision so a future change is noticed."""
    registry = MechanismPlaybookRegistry()
    terms = {term for item in registry._playbooks for term in item.trigger_terms}
    observed_kinds = [
        "string",
        "decode_result",
        "decode_candidate",
        "process_creation_flags",
        "mechanism_decode_window",
        "encoded_blob",
        "function_instruction_window",
        "api_argument_trace",
    ]
    assert sorted(set(observed_kinds) & terms) == ["encoded_blob"]


def test_matching_returns_no_playbooks_for_an_empty_corpus() -> None:
    registry = MechanismPlaybookRegistry()
    assert [item.id for item in registry.matching([])] == [
        item.id for item in _original_matching(registry, [])
    ]


def test_matching_is_stable_across_repeated_calls() -> None:
    registry = MechanismPlaybookRegistry()
    rows = _rows(("string", "schtasks"), ("api_argument_trace", "CreateProcessW"))
    first = [item.id for item in registry.matching(rows)]
    second = [item.id for item in registry.matching(rows)]
    assert first == second
