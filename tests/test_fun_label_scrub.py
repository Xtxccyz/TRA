"""A residual `FUN_` label must not cost the analyst the whole report - but the scrub must be surgical.

Why this exists: the ledger-residue gate REJECTS THE ENTIRE REPORT. MEASURED on task `83f16229` (白象
`64da3378`):

    failure_code        REPORT_SYNTHESIS_FAILURE
    message             primary report contains FUN_ ledger names
    failure_fingerprint 79b9ccdf... == previous_failure_fingerprint   -> retry suppressed
    published revision  none

while the SAME sample and the SAME code published cleanly on task `72690275`
(`primary_analyst_violations == []`, zero `FUN_` hits). A run-varying leak therefore turned into a missing
report.

The scrub is TOKEN-PRECISE on purpose. An earlier body-wide repair used a greedy pattern that consumed
everything from `UNKNOWN(` to the next backtick or newline, destroyed 11,398 characters, and took every
recovered-fact token (`WScript`, `Svr`, `XMLHTTP`, `ADODB`) to zero occurrences. Every test below exists to
keep this one from becoming that one.
"""
from __future__ import annotations

from threat_report_agent.analyst_report import (
    ANALYST_APPENDIX_HEADING,
    _scrub_fun_names_from_primary,
    primary_analyst_violations,
)

LEAK = (
    "## 分析结论\n\n"
    "调用 FUN_0040d2c0 后进入载荷。恢复文本 `WScript`、`Svr`、`XMLHTTP`、`ADODB` 均在。\n\n"
    + ANALYST_APPENDIX_HEADING
    + "\n\nFUN_0040d2c0@00401000: dump line\n"
)


def test_a_residual_label_stops_tripping_the_gate() -> None:
    assert primary_analyst_violations(LEAK), "the fixture no longer trips the gate it exists for"
    assert primary_analyst_violations(_scrub_fun_names_from_primary(LEAK)) == []


def test_the_scrub_keeps_every_recovered_fact_token() -> None:
    """The measured failure of the previous, greedy attempt."""
    out = _scrub_fun_names_from_primary(LEAK)
    for token in ("WScript", "Svr", "XMLHTTP", "ADODB"):
        assert token in out, f"{token!r} was destroyed by the scrub"


def test_the_appendix_keeps_its_labels() -> None:
    """`FUN_` names are legitimate ledger content; only the analyst-facing primary body excludes them."""
    out = _scrub_fun_names_from_primary(LEAK)
    assert "FUN_0040d2c0@00401000" in out


def test_the_scrub_is_token_sized_not_span_sized() -> None:
    out = _scrub_fun_names_from_primary(LEAK)
    assert len(LEAK) - len(out) < 40, (
        f"the scrub removed {len(LEAK) - len(out)} characters for one 10-character label, which is the "
        f"signature of a span-eating pattern rather than a token removal"
    )


def test_removing_a_label_between_cjk_does_not_join_across_a_newline() -> None:
    """Regression: a `\\s+` collapse swallowed the blank line and produced `## 分析结论调用后进入载荷。`."""
    out = _scrub_fun_names_from_primary(LEAK)
    assert "## 分析结论\n\n" in out
    assert "\n\n" + ANALYST_APPENDIX_HEADING in out, "the blank line before the appendix heading was lost"


def test_clean_input_is_returned_unchanged() -> None:
    clean = "## 分析结论\n\n没有台账残留。\n"
    assert _scrub_fun_names_from_primary(clean) == clean
