"""Recovered TLS callbacks must reach the published body.

MEASURED GAP. Task `50673002` records three `tls_callback` evidence rows:

    {"entry": "0x140016920", "name": "tls_callback", "role": "tls_callback", "rva": "0x16920"}
    {"entry": "0x140047500", "name": "tls_callback", "role": "tls_callback", "rva": "0x47500"}
    {"entry": "0x1400474e0", "name": "tls_callback", "role": "tls_callback", "rva": "0x474e0"}

None of those addresses appears in the published body, whose section titled **线程、TLS 回调与 APC** says:

    静态恢复到同进程 `CreateThread`，入口 `0x140038ae0`。同进程线程不是远程注入；
    APC/TLS 若只有导入而无目标线程证据，保持未证明。

That disclaimer is correct as a boundary, and it is also describing a fact the run HAS: three callback
entries were recovered, with addresses. A TLS callback runs BEFORE the entry point, which is why the named
benchmark's 2.2 CRT初始化阶段 ends by recording its callback - an early-execution location is a first-class
analyst fact, and `investigation.py` already uses these rows as join seeds
(`_tls_callback_starts`), so the pipeline treats them as significant while the reader never sees them.

Root cause, measured: the callbacks are absent from the DOCUMENT entirely (`probe-tls-callbacks` walked the
stored document and found no row carrying `tls_callbacks`), so this is a projection gap, not a rendering
one - no renderer could reach them. The architecture puts facts in deterministic projections, so the
projection comes first and the 正文-level assertion covers both halves.
"""
from __future__ import annotations

from threat_report_agent.analyst_report import render_official_markdown
from threat_report_agent.reporting import build_tls_callback_projection

CALLBACKS = [
    {"entry": "0x140016920", "name": "tls_callback", "role": "tls_callback", "rva": "0x16920"},
    {"entry": "0x140047500", "name": "tls_callback", "role": "tls_callback", "rva": "0x47500"},
    {"entry": "0x1400474e0", "name": "tls_callback", "role": "tls_callback", "rva": "0x474e0"},
]


class _Evidence:
    """Minimal Evidence stand-in: the projection reads `.kind` and `.value`."""

    def __init__(self, kind: str, value: dict, ident: str = "ev-tls") -> None:
        self.kind = kind
        self.value = value
        self.id = ident
        self.module = "static_triage"


def _document(rows: list[dict]) -> dict:
    return {
        "report_version": "3.0",
        "case_id": "case-tls",
        "task_id": "task-tls",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 1, "verified_mechanism_count": 0},
        "analyst_topics": [],
        "tls_callbacks": [row.get("entry") for row in CALLBACKS],
        "modules": [
            {"id": "static_triage", "title": "Static Triage", "summary": "", "rows": rows}
        ],
        "trace": {},
    }


def test_the_projection_reads_recovered_tls_callbacks() -> None:
    evidence = {
        f"ev-{index}": _Evidence("tls_callback", dict(row), ident=f"ev-{index}")
        for index, row in enumerate(CALLBACKS)
    }
    projection = build_tls_callback_projection(evidence)
    assert projection is not None, "no projection was produced for three recovered TLS callbacks"
    assert projection["type"] == "tls_callbacks"
    assert projection["entries"] == ["0x140016920", "0x140047500", "0x1400474e0"], (
        f"the callback entries are wrong or reordered: {projection['entries']}"
    )


def test_the_body_names_every_recovered_callback() -> None:
    """正文级: the addresses must be in the published text, not only in the projection."""
    document = _document([{"type": "tls_callbacks",
                           "entries": ["0x140016920", "0x140047500", "0x1400474e0"]}])
    body = render_official_markdown(document)
    for row in CALLBACKS:
        assert row["entry"] in body, (
            f"TLS callback {row['entry']} was recovered but is not in the published body, so the "
            "reader cannot see an address that runs before the entry point"
        )


def test_the_body_states_that_a_callback_precedes_the_entry_point() -> None:
    """Why the fact matters must be stated, not implied by a bare address list."""
    document = _document([{"type": "tls_callbacks", "entries": ["0x140016920"]}])
    body = render_official_markdown(document)
    section = body[body.find("0x140016920") - 400: body.find("0x140016920") + 400]
    assert "入口点" in section or "入口" in section, (
        "the body lists a TLS callback without saying it runs before the entry point"
    )
    assert "未" in section or "静态" in section, "the callback list carries no static boundary"


def test_no_tls_section_when_no_callback_was_recovered() -> None:
    """A run with no TLS callbacks must not get an empty section claiming otherwise."""
    body = render_official_markdown(_document([]))
    assert "TLS 回调入口" not in body, "a TLS-callback section was emitted with no callbacks recovered"


def test_a_pe_structure_tls_table_is_also_accepted() -> None:
    """The callback table can come from `pe_structure.tls_callbacks`, not only typed rows."""
    evidence = {
        "ev-pe": _Evidence(
            "pe_structure",
            {"entry_rva": 5152, "tls_callbacks": [{"entry": "0x140016920", "rva": "0x16920"}]},
        )
    }
    projection = build_tls_callback_projection(evidence)
    assert projection is not None and projection["entries"] == ["0x140016920"], (
        "a TLS callback carried by the PE structure was not projected"
    )
