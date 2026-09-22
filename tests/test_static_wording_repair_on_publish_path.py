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


def test_the_published_path_repairs_before_it_gates() -> None:
    """The defect was that the published path only raised."""
    source = inspect.getsource(analyst_report.render_official_markdown)
    assert "repair_static_runtime_wording(" in source, (
        "the published path does not repair model wording before the static-only gate, so one word from the "
        "model can still discard the entire report"
    )
    # And the gate must still be there: repairing is not a substitute for checking.
    assert "static_wording_violations(" in source, "the static-only gate was removed instead of preceded"


def test_the_repair_table_has_exactly_one_definition() -> None:
    """Two copies is how the paths drifted apart in the first place."""
    assert not hasattr(reporting, "_STATIC_RUNTIME_REWRITES"), (
        "reporting.py carries its own copy of the rewrite table again; the English and published paths can "
        "drift apart"
    )
    assert not hasattr(analyst_report, "_STATIC_RUNTIME_REWRITES"), (
        "analyst_report.py carries its own copy of the rewrite table again"
    )


def test_the_english_path_still_repairs_through_the_shared_table() -> None:
    """`_static_safe_text` is the English path's entry point and must delegate, not re-implement."""
    source = inspect.getsource(reporting._static_safe_text)
    assert "repair_static_runtime_wording(" in source, (
        "the English path no longer delegates to the shared table"
    )
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
