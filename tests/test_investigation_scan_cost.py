"""The investigation proposer must not re-serialise its corpus once per scan.

Regression cover for the measured between-action stall: one ``propose`` pass
performed ~114 term scans over the same bounded Evidence corpus, and every scan
rebuilt ``repr(Evidence.value)`` plus its case-fold for every row *and*
re-case-folded every term for every row.  On a real 20,000-row PE corpus that
was 19.5 s of a 23.9 s pass; the loop therefore spent its whole action budget
re-deriving identical strings instead of investigating.

These tests assert on **work performed** (call counts and how many distinct row
serialisations happen), never on wall-clock time, and they pin the scan
semantics against a literal re-implementation of the original expression so a
faster-but-different matcher cannot slip through.
"""

from __future__ import annotations

from threat_report_agent.investigation import (
    Investigator,
    MechanismPlaybookRegistry,
    Verifier,
)


class _CountingValue(dict):
    """A mapping that counts how often it is ``repr``-ed by a corpus pass."""

    calls = 0

    def __repr__(self) -> str:  # noqa: D105
        type(self).calls += 1
        return super().__repr__()


def _counting_corpus(
    size: int, *, extra_value: str | None = None
) -> tuple[list[dict[str, object]], int]:
    rows: list[dict[str, object]] = []
    for index in range(size):
        rows.append(
            _row(
                index,
                "function_call" if index % 2 else "function_context",
                _CountingValue({"name": f"sub_{index:x}", "func": f"x{index:x}"}),
            )
        )
    if extra_value is not None:
        # A plain dict, so it never contributes to the counted reprs.
        rows.append(
            _row(size, "function_call", {"api": extra_value, "import": "kernel32"}),
        )
    return rows, size


def _row(index: int, kind: str, value: object, anchor: object | None = None) -> dict[str, object]:
    return {
        "id": f"ev-{index}",
        "artifact_id": "artifact-1",
        "kind": kind,
        "nature": "STATIC_OBSERVED",
        "value": value,
        "anchor": anchor if anchor is not None else {"function_entry": f"0x{index:x}"},
    }


def _corpus(size: int = 400) -> list[dict[str, object]]:
    """A corpus whose every row can be reached by a different term."""
    rows: list[dict[str, object]] = []
    for index in range(size):
        if index % 4 == 0:
            rows.append(_row(index, "function_context", {"name": f"sub_{index:x}", "apis": ["VirtualAlloc", "CreateProcessW"]}))
        elif index % 4 == 1:
            rows.append(_row(index, "function_call", {"callee": "GetProcAddress", "caller": f"sub_{index:x}"}))
        elif index % 4 == 2:
            rows.append(_row(index, "string", {"text": f"C:\\Temp\\payload_{index}.bin", "encoding": "utf-16le"}))
        else:
            rows.append(_row(index, "xref", {"from": f"0x{index:x}", "to": "0x140001000", "type": "data"}))
    return rows


def _original_matching_rows(rows, *terms):
    """The pre-fix scan, transcribed: ``term in f"{kind} {value} {anchor}"``."""
    found = []
    for row in rows:
        haystack = f"{row.get('kind', '')} {row.get('value', '')} {row.get('anchor', '')}".casefold()
        if any(term.casefold() in haystack for term in terms):
            found.append(row)
    return found


def _original_matching(registry, rows):
    """The pre-fix Playbook match, transcribed."""
    text = " ".join(str(row.get("value", "")) for row in rows).casefold()
    kinds = {str(row.get("kind", "")).casefold() for row in rows}
    return tuple(
        item
        for item in registry._playbooks
        if any(term in text or term in kinds for term in item.trigger_terms)
    )


def test_matching_rows_agrees_with_the_original_scan_semantics() -> None:
    """Every term set used by ``propose`` must select exactly the same rows."""
    rows = _corpus()
    investigator = Investigator()
    term_sets = [
        ("openprocess",),
        ("updateprocthreadattribute",),
        ("GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LdrGetProcedureAddress"),
        ("module source", "dll", "path"),
        ("deletefile", "movefileex"),
        # Mixed case must still fold on both sides.
        ("VIRTUALALLOC",),
        ("c:\\temp",),
        # No terms must stay empty, exactly as ``any(())`` did.
        (),
        # A term that spans the join boundary between kind and value.
        ("function_context {",),
    ]
    for terms in term_sets:
        expected = [row["id"] for row in _original_matching_rows(rows, *terms)]
        assert [row["id"] for row in investigator._matching_rows(rows, *terms)] == expected, terms


def test_matching_rows_serialises_each_row_once_per_scan_pass() -> None:
    """The core defect: ~114 scans re-``repr``-ed every row ~114 times.

    ``_row_scan_text`` is still entered once per row per scan, so counting
    entries would measure nothing; what matters is how many of those entries
    actually had to build the string.  A memo miss is real serialisation work.
    """
    rows = _corpus()
    investigator = Investigator()
    serialised: list[int] = []
    original_row_scan_text = investigator._row_scan_text

    def counting_row_scan_text(row):  # noqa: ANN001
        if id(row) not in investigator._row_scan_text_memo:
            serialised.append(id(row))
        return original_row_scan_text(row)

    investigator._row_scan_text = counting_row_scan_text  # type: ignore[method-assign]
    investigator._reset_scan_memo()
    lookups = 0
    try:
        for _ in range(20):
            for terms in (
                ("virtualalloc",),
                ("getprocaddress", "string"),
                ("payload_1", "payload_2"),
            ):
                lookups += len(rows)
                investigator._matching_rows(rows, *terms)
    finally:
        investigator._reset_scan_memo()

    # 20 rounds x 3 scans x 400 rows were offered to the scanner ...
    assert lookups == 24_000
    # ... and the corpus text was built once per row, not once per lookup.
    assert len(serialised) == len(rows)
    assert len(set(serialised)) == len(rows)


def test_propose_reuses_one_corpus_projection_for_playbooks_and_term_checks() -> None:
    """``matching`` and the proposer's own text check must share one projection."""
    rows = _corpus()
    investigator = Investigator()
    calls: list[str] = []
    registry = investigator.playbooks
    original_matching = registry.matching

    def counting_matching(evidence, **kwargs):  # noqa: ANN001
        calls.append("folded" if kwargs.get("folded_text") is not None else "rebuilt")
        return original_matching(evidence, **kwargs)

    registry.matching = counting_matching  # type: ignore[method-assign]
    investigator.propose(evidence=rows, scheduled=set())

    # Exactly one Playbook scan for the pass, and it must be handed the
    # projection the proposer already built rather than rebuilding it.
    assert calls == ["folded"]


def test_propose_clears_its_scan_memo_and_does_not_share_state_between_passes() -> None:
    """A second pass must not see the first pass's corpus."""
    investigator = Investigator()
    first = _corpus(8)
    investigator.propose(evidence=first, scheduled=set())
    assert investigator._row_scan_text_memo == {}
    assert investigator._corpus_projection_memo == {}

    # A row mutated between passes must be re-read, not served from a stale memo.
    second = _corpus(8)
    investigator.propose(evidence=second, scheduled=set())
    expected = _original_matching_rows(second, "virtualalloc")
    assert [row["id"] for row in investigator._matching_rows(second, "virtualalloc")] == [
        row["id"] for row in expected
    ]


def test_propose_selects_the_same_actions_as_the_original_scan() -> None:
    """Same actions, same order, same citations -- proven against the oracle.

    ``propose`` is run once through the real (memoised) scan and once with the
    memo disabled and the original per-scan expression substituted, so the
    comparison is behavioural rather than a golden file that can be
    rubber-stamped.
    """
    rows = _corpus(240)
    scheduled = {"GET_CFG_SLICE|0x140001000"}

    fast_investigator = Investigator()
    fast = fast_investigator.propose(evidence=rows, scheduled=set(scheduled))

    oracle_investigator = Investigator()

    def oracle_matching_rows(inner_rows, *terms, candidates=None):  # noqa: ANN001
        # `propose` now passes an exact `candidates` pre-filter to avoid rescanning
        # the whole corpus once per profile.  The oracle must honour it, otherwise
        # this test compares against a scan of a different row set rather than
        # against the original semantics.  Exactness itself is pinned separately by
        # `tests/test_propose_scan_prefilter.py`, which asserts every profile's
        # matches are a subset of the union's matches.
        source = inner_rows if candidates is None else candidates
        return _original_matching_rows(list(source), *terms)

    oracle_investigator._matching_rows = oracle_matching_rows  # type: ignore[method-assign]
    oracle_registry = MechanismPlaybookRegistry()
    oracle_investigator.playbooks = oracle_registry
    original_matching = MechanismPlaybookRegistry.matching

    def oracle_matching(self, evidence, **kwargs):  # noqa: ANN001
        return _original_matching(self, list(evidence))

    MechanismPlaybookRegistry.matching = oracle_matching
    try:
        slow = oracle_investigator.propose(evidence=rows, scheduled=set(scheduled))
    finally:
        MechanismPlaybookRegistry.matching = original_matching

    def shape(action):  # noqa: ANN001
        return (
            action.action_type.value,
            action.priority,
            action.reason,
            tuple(sorted(action.parameters.items())),
            tuple(action.expected_evidence_kinds),
            action.success_condition,
            tuple(action.source_evidence_ids),
            tuple(sorted(action.plan.items())),
        )

    assert [shape(item) for item in fast] == [shape(item) for item in slow]
    assert fast, "the fixture corpus must actually propose work"


def test_playbook_matching_accepts_a_precomputed_projection_equivalently() -> None:
    """The folded projection must be interchangeable with recomputing it."""
    rows = _corpus(120)
    registry = MechanismPlaybookRegistry()
    text = " ".join(str(row.get("value", "")) for row in rows).casefold()
    kinds = frozenset(str(row.get("kind", "")).casefold() for row in rows)

    assert [item.id for item in registry.matching(rows)] == [
        item.id for item in registry.matching(rows, folded_text=text, folded_kinds=kinds)
    ]
    # And it must be equivalent to the original expression on this corpus.
    assert [item.id for item in registry.matching(rows)] == [
        item.id for item in _original_matching(registry, rows)
    ]


def test_row_scan_text_and_value_text_are_the_original_strings() -> None:
    """The memoised strings must be byte-identical to what callers used to get."""
    rows = _corpus(32)
    investigator = Investigator()
    for row in rows:
        assert investigator._row_scan_text(row) == (
            f"{row.get('kind', '')} {row.get('value', '')} {row.get('anchor', '')}".casefold()
        )
        assert investigator._row_value_text(row) == str(row.get("value", "")).casefold()


def test_row_memo_keys_cannot_alias_a_recycled_row_identity() -> None:
    """Two distinct rows whose ``id()`` could collide must not share a haystack.

    The memo keeps a strong reference to the row it describes, so a released
    row's identity can never be reused for a different payload.
    """
    investigator = Investigator()
    first = _row(0, "string", {"text": "alpha-unique-token"})
    first_text = investigator._row_scan_text(first)
    assert "alpha-unique-token" in first_text
    del first
    for index in range(64):
        other = _row(index, "string", {"text": f"beta-{index}"})
        text = investigator._row_scan_text(other)
        assert "alpha-unique-token" not in text
        assert f"beta-{index}" in text


def test_verifier_matching_still_works_without_a_precomputed_projection() -> None:
    """Other callers keep the self-contained behaviour of ``matching``."""
    registry = MechanismPlaybookRegistry()
    evidence = [
        {
            "id": "ev-1",
            "kind": "function_call",
            "value": {"callee": "GetProcAddress", "caller": "sub_140001000"},
            "anchor": {"function_entry": "0x140001000"},
        }
    ]
    assert [item.id for item in registry.matching(evidence)] == [
        item.id for item in _original_matching(registry, evidence)
    ]


def test_verifier_evaluate_skips_the_corpus_join_when_the_question_names_ppid() -> None:
    """The eager corpus join was a whole extra serialisation pass per gate check.

    With a ppid-named question the ``any(token in text ...)`` side of the ``or``
    already decides the flag, so the join is dead work.  One Playbook scan is
    still required, which is exactly one counted pass.
    """
    rows, counted = _counting_corpus(6, extra_value="UpdateProcThreadAttribute")
    _CountingValue.calls = 0
    decision = Verifier().evaluate(rows, "Which ppid / parent-process chain?", "statement")

    assert _CountingValue.calls == counted, (
        "expected exactly one corpus serialisation; the eager join would need two"
    )
    assert decision.status


def test_verifier_evaluate_still_reads_the_ppid_flag_from_the_corpus_text() -> None:
    """The fallback join must still run when the question does not name ppid."""
    question = "Which endpoint and request consumer?"
    plain, _ = _counting_corpus(6)
    attrs, counted = _counting_corpus(6, extra_value="UpdateProcThreadAttribute")

    _CountingValue.calls = 0
    baseline = Verifier().evaluate(plain, question, "statement")
    baseline_calls = _CountingValue.calls
    _CountingValue.calls = 0
    with_attribute = Verifier().evaluate(attrs, question, "statement")
    attribute_calls = _CountingValue.calls

    # EXACTLY ONE corpus serialisation, not two.  The question never names ppid, so
    # the fallback join runs - and `_corpus_text` then hands that projection to
    # `best_match` instead of letting it rebuild the same 71 MB string.  The earlier
    # assertion pinned `2 * len(plain)` because the join was made twice; that second
    # pass was pure waste and is what this change removes.
    assert baseline_calls == len(plain), (
        f"expected one corpus serialisation, saw {baseline_calls} for {len(plain)} rows"
    )
    assert attribute_calls == counted

    # ... and it must actually be consulted: the extra row carrying
    # ``updateprocthreadattribute`` routes the gate down the PPID path instead
    # of the generic candidate path.
    assert baseline.status == "CANDIDATE"
    assert with_attribute.status != baseline.status


def test_verifier_evaluate_decision_is_unchanged_for_a_ppid_question() -> None:
    """Same corpus, same question, same decision -- the join was only dead work."""
    rows, _ = _counting_corpus(8, extra_value="UpdateProcThreadAttribute")
    question = "What ppid and parent identity does the process chain recover?"
    decision = Verifier().evaluate(rows, question, "statement")

    # Re-run through a fresh verifier: the lazy form must be deterministic and
    # must not depend on any state the first call left behind.
    again = Verifier().evaluate(rows, question, "statement")
    assert (decision.accepted, decision.status, decision.reason) == (
        again.accepted,
        again.status,
        again.reason,
    )
