"""Model wording must be REPAIRED on the published path, not used to discard the whole report.

MEASURED defect this pins (round 83, 白象 task `8e75f6dc`). The run ended `FAILED_ANALYSIS` /
`REPORT_SYNTHESIS_FAILURE` with `report_available: false` - no report at all - because the model wrote the
single word `connected` and `analyst_report.render_official_markdown` raised on it:

    static-only wording gate rejected report: \\bconnected\\b

5,988 evidence rows and 12 claims were discarded over one word. The English path had always repaired this
wording (`reporting._static_safe_text`, whose docstring states the requirement verbatim - "A single
unqualified runtime verb must not abort an otherwise valid static report"), but the PUBLISHED path only
raised. The repair table now has ONE definition in `product_certification`, used by both paths.

The repair is deliberately conservative and is NOT a way to smuggle runtime claims into a static report: the
gate still runs afterwards and still raises on a residue, so an unrepairable phrase is loudly rejected rather
than published.
"""
from __future__ import annotations

import inspect

import pytest

from threat_report_agent import analyst_report, product_certification, reporting

#: One probe sentence per gate pattern. The gate evaluates the smallest punctuation-delimited clause, so each
#: probe is a plain declarative sentence with no conditional or negative wording.
PROBES: dict[str, str] = {
    r"\bconnected\b": "the socket is connected",
    r"\bdownloaded successfully\b": "the payload downloaded successfully",
    r"\bexecuted\b": "the routine executed",
    r"\bpersisted successfully\b": "the key persisted successfully",
    r"\bserver responded\b": "the server responded",
    r"\bc2 active\b": "C2 active",
    r"\bprocess spawned\b": "a process spawned",
    r"\bregistry modification succeeded\b": "registry modification succeeded",
    r"\bobserved at runtime\b": "the value observed at runtime",
    r"\bdynamic_observed\b": "the flag dynamic_observed",
}


def test_every_gate_pattern_is_repairable() -> None:
    """If the gate gains a pattern the repair table lacks, a report can be lost again.

    This asserts the two lists stay in step, and that each repair really clears the gate rather than merely
    changing the text.
    """
    unprobed = [pattern for pattern in product_certification._FORBIDDEN_RUNTIME_WORDING if pattern not in PROBES]
    assert not unprobed, f"this test needs a probe sentence for {unprobed}"

    for pattern, sentence in PROBES.items():
        assert product_certification.static_wording_violations(sentence), (
            f"the probe {sentence!r} does not trip the gate, so it cannot prove {pattern} is repairable"
        )
        repaired = product_certification.repair_static_runtime_wording(sentence)
        assert not product_certification.static_wording_violations(repaired), (
            f"{pattern} is rejected by the gate but NOT repairable: any report containing it is discarded "
            f"whole. Repaired text was {repaired!r}."
        )


def test_the_published_path_repairs_before_it_gates(monkeypatch: pytest.MonkeyPatch) -> None:
    """The defect was that the published path only raised.

    BEHAVIOURAL (P3.7), not a source-text read: the shared repair function is replaced with a spy that records
    every call and its argument, so the assertion is about what the published path DOES, not about what its
    source says. The sentinel it returns is what the gate must then see - proving the repaired text is the text
    that gates, rather than the repair merely being mentioned in the body.
    """
    calls: list[str] = []
    #: contains none of `_FORBIDDEN_RUNTIME_WORDING`, so the gate must pass on it.
    sentinel = "# 静态分析报告\n\n- 任务结果：**UNKNOWN**\n\n无受限措辞。\n"

    def _repair_spy(text: str) -> str:
        calls.append(text)
        return sentinel

    monkeypatch.setattr(analyst_report, "repair_static_runtime_wording", _repair_spy)

    rendered = analyst_report.render_official_markdown({})

    assert calls, (
        "the published path does not repair model wording before the static-only gate, so one word from the "
        "model can still discard the entire report"
    )
    assert rendered == sentinel, (
        "the published path rendered its own text instead of the repaired text, so the repair is not on the "
        "published path"
    )
    # And the gate is not merely preceded: it still runs, and it raises on what the repair left behind.
    monkeypatch.setattr(analyst_report, "repair_static_runtime_wording", lambda text: "the socket is connected")
    with pytest.raises(ValueError, match="static-only wording gate"):
        analyst_report.render_official_markdown({})


def test_the_repair_table_has_exactly_one_definition() -> None:
    """Two copies is how the paths drifted apart in the first place."""
    assert not hasattr(reporting, "_STATIC_RUNTIME_REWRITES"), (
        "reporting.py carries its own copy of the rewrite table again; the English and published paths can "
        "drift apart"
    )
    assert not hasattr(analyst_report, "_STATIC_RUNTIME_REWRITES"), (
        "analyst_report.py carries its own copy of the rewrite table again"
    )


def test_the_english_path_still_repairs_through_the_shared_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`_static_safe_text` is the English path's entry point and must delegate, not re-implement.

    BEHAVIOURAL (P3.7): the shared table's function is replaced with a spy, so this fails for the SAME reason a
    missing `repair_static_runtime_wording(` call in the source used to fail - the English path no longer routes
    through the one shared table - without reading the implementation's text.
    """
    calls: list[str] = []

    def _repair_spy(text: str) -> str:
        calls.append(text)
        return "repaired by the shared table"

    monkeypatch.setattr(reporting, "repair_static_runtime_wording", _repair_spy)

    assert reporting._static_safe_text("the socket is connected") == "repaired by the shared table"
    assert calls == ["the socket is connected"], (
        "the English path no longer delegates to the shared table"
    )
    # Text the gate already accepts is returned untouched without consulting the table.
    calls.clear()
    assert reporting._static_safe_text("the socket would connect") == "the socket would connect"
    assert calls == []

    # Back to the real table for the remaining assertions.
    monkeypatch.undo()
    repaired = reporting._static_safe_text("the socket is connected")
    assert "connected" not in repaired
    assert not product_certification.static_wording_violations(repaired)
    # HONEST NOTE, pinned deliberately: the mapping is a blind `\bconnected\b -> would connect`, so
    # "is connected" becomes "is would connect" - awkward prose.
    #
    # This is a deliberate trade, not an oversight: the alternative is discarding the entire report over one
    # word, which is what actually happened (task `8e75f6dc`, `report_available: false`). The table is
    # unchanged from the English path's original definition - this fix MOVED it so both paths share it; it did
    # not rewrite the mappings. Pinned here so that improving the grammar is a visible decision with a test to
    # update, rather than a silent drift.
    assert repaired == "the socket is would connect"


def test_conditional_wording_is_left_alone() -> None:
    """The repair must not touch text the gate already accepts, or every read would rewrite the report."""
    already_fine = "the socket would connect; execution was not observed"
    assert not product_certification.static_wording_violations(already_fine)
    assert product_certification.repair_static_runtime_wording(already_fine) == already_fine
