"""A claim's evidence samples must be CHOSEN, not sliced positionally.

MEASURED DEFECT (task `de738f12`, reproduced by recomposing the real ledger with the code of the
day):

    ledger api_argument_trace rows                     255   (28 for RegSetValueExW)
    of the registry ones, cited by a claim              20
    claims cite up to                                   75   evidence rows (35 of them traces)
    rows reaching the document                          21   (0 for RegSetValueExW)

`_claim_row` published `evidence_ids[:6]`, so whether a REGISTRY WRITE trace survived was a
position lottery against 75 candidates. That join is precisely what the objective's R1 requires
("注册表调用点↔键名/值名参数"), and its input existed and was cited.

Same defect shape as `_summarize_evidence_rows` taking `group[:1]`, which dropped
`:Zone.Identifier` from a 2,926-row string group (see `test_report_string_facts.py`).

These tests exercise `select_claim_evidence_samples` directly. `build_report_document` needs a
fully-populated task/claim object graph, and a fixture that supplies it would be testing the
fixture's completeness rather than the selection - the mistake an earlier version of this file made.
"""

from __future__ import annotations

from types import SimpleNamespace

from threat_report_agent.report.reporting import select_claim_evidence_samples

REGISTRY_CALLSITES = ("140007fa3", "140007fd7", "14000805f")


def _trace(identifier: str, callsite: str, argument: int) -> SimpleNamespace:
    """A real `api_argument_trace` row: one argument per row, callsite + register + value."""
    return SimpleNamespace(
        id=identifier,
        kind="api_argument_trace",
        value={
            "api": "RegSetValueExW",
            "callsite": callsite,
            "argument_index": argument,
            "register": ("RCX", "RDX", "r8", "R9D")[argument],
            "source_kind": "constant" if argument == 3 else "register_or_expression",
            "value": "0x4" if argument == 3 else f"qword ptr [RSP + 0x{900 + argument:x}]",
        },
        anchor={"type": "api_argument_trace"},
    )


def _filler(count: int, kind: str = "string") -> list[SimpleNamespace]:
    return [
        SimpleNamespace(id=f"filler-{index}", kind=kind,
                        value={"text": f"filler-{index}"}, anchor={"type": kind})
        for index in range(count)
    ]


def _by_id(rows: list[SimpleNamespace]) -> dict[str, SimpleNamespace]:
    return {str(row.id): row for row in rows}


def test_a_cited_registry_trace_survives_a_75_row_citation_list() -> None:
    """The measured defect: the traces are LAST in citation order, as they were in the ledger."""
    traces = [
        _trace(f"reg-{index}", REGISTRY_CALLSITES[index % 3], index % 4)
        for index in range(20)
    ]
    filler = _filler(55, kind="string")
    rows = [*filler, *traces]
    # Filler first, so a positional slice can never reach the traces.
    cited = [str(row.id) for row in rows]
    chosen = select_claim_evidence_samples(cited, _by_id(rows))
    assert chosen, "no samples were selected at all"
    kinds = [str(getattr(_by_id(rows)[identifier], "kind")) for identifier in chosen]
    assert "api_argument_trace" in kinds, (
        "a positional slice was taken instead of a ranked choice, so the registry-write join was "
        f"dropped in favour of {kinds}"
    )


def test_the_recovered_write_type_is_among_them() -> None:
    """`dwType = 0x4` is the analyst-relevant slot, and it must be reachable.

    Tested with a tight bound, because that is the honest form of the property: the sampler
    round-robins across API families, so with six slots and six families only ONE argument row per
    family fits. Asserting that the R9D row specifically appears among six would be asserting a
    different policy than the one that prevents a single API from consuming every slot - and the
    first version of this test did exactly that and failed against correct code.
    """
    traces = [
        _trace(f"reg-{index}", REGISTRY_CALLSITES[index % 3], index % 4)
        for index in range(20)
    ]
    rows = [*_filler(55, kind="string"), *traces]
    by_id = _by_id(rows)
    cited = [str(row.id) for row in rows]

    # With a wide bound every argument row is admissible, so the R9D/dwType row must be there.
    wide = select_claim_evidence_samples(cited, by_id, limit=40)
    types = [
        identifier for identifier in wide
        if by_id[identifier].value.get("register") == "R9D"
        and str(by_id[identifier].value.get("value")) == "0x4"
    ]
    assert types, (
        "the recovered dwType (R9D = 0x4) is not selectable at all; a join without its argument is "
        "just an API name next to a string"
    )

    # And with a tight bound the registry family still gets a slot rather than losing to filler.
    tight = select_claim_evidence_samples(cited, by_id, limit=2)
    kinds = {str(by_id[identifier].kind) for identifier in tight}
    assert "api_argument_trace" in kinds, (
        f"a tight bound dropped the conclusion-bearing kind entirely: {kinds}"
    )


def test_selection_stays_bounded_and_deterministic() -> None:
    """The bound is kept, and the same claim must always yield the same rows."""
    from threat_report_agent.report.reporting import _CLAIM_EVIDENCE_SAMPLE_LIMIT

    traces = [
        _trace(f"reg-{index}", REGISTRY_CALLSITES[index % 3], index % 4)
        for index in range(20)
    ]
    rows = [*_filler(55, kind="string"), *traces]
    by_id = _by_id(rows)
    cited = [str(row.id) for row in rows]
    first = select_claim_evidence_samples(cited, by_id)
    # The bound is an upper bound: a fixture with fewer distinct groups than the limit legitimately
    # yields fewer rows, so asserting equality would be asserting the fixture's shape.
    assert 0 < len(first) <= _CLAIM_EVIDENCE_SAMPLE_LIMIT, (
        f"the sample has {len(first)} rows against a bound of {_CLAIM_EVIDENCE_SAMPLE_LIMIT}"
    )
    assert first == select_claim_evidence_samples(cited, by_id), (
        "selection is not deterministic; the same document would render differently twice"
    )
    # Input order must not change how many high-value rows are chosen.
    assert len(select_claim_evidence_samples(list(reversed(cited)), by_id)) == len(first)


def test_a_short_citation_list_is_returned_whole_and_in_order() -> None:
    """Below the bound nothing is reordered: the common case must not churn."""
    rows = _filler(4)
    cited = [str(row.id) for row in rows]
    assert select_claim_evidence_samples(cited, _by_id(rows)) == cited
