"""The body must name the toolchain that compiled the sample, not only list its symbols.

MEASURED GAP. The published body for the 白象 sample `64da3378` (task `0da01730`) listed `MSVBVM60.DLL`,
`VBA6.DLL`, `C:\\NanoVB6\\VB6.OLB` and twenty-one `__vba*` compiler symbols, and never said which language
compiled the file. The named depth benchmark has a 编译语言 field, and the reference document for this
campaign identifies the family BY COMPILER ("Microsoft Visual Basic 5.0 / 6.0"), so "what is this written
in" is a first-order triage question that the body could not answer.

The renderer must ALSO not guess: a sample whose evidence does not settle the toolchain must leave the
field out rather than assert a language, and the line must read as a derivation rather than a recovered
field.
"""
from __future__ import annotations

from threat_report_agent.analyst_report import _document_compile_language, render_official_markdown


def _pe_rows(*values: str) -> list[dict]:
    return [{"type": "pe_basics", "format": "PE32", "machine": "0x014c", "value": value} for value in values]


def test_a_vb6_runtime_names_the_language() -> None:
    rows = [{"type": "pe_basics", "value": "MSVBVM60.DLL"}]
    assert "Visual Basic 6" in _document_compile_language(rows)


def test_vb6_compiler_symbols_alone_also_name_it() -> None:
    """The import table can be stripped; the code generator's own symbols cannot."""
    rows = [{"type": "pe_basics", "value": "__vbaStrCopy"}, {"type": "pe_basics", "value": "EVENT_SINK_Release"}]
    assert "Visual Basic" in _document_compile_language(rows)


def test_an_unsettled_toolchain_is_not_guessed() -> None:
    """Silence beats a confident wrong answer."""
    assert _document_compile_language([{"type": "pe_basics", "value": "kernel32.dll"}]) == ""
    assert _document_compile_language([]) == ""


def test_other_toolchains_are_recognised() -> None:
    assert "Visual C" in _document_compile_language([{"value": "MSVCR120.dll"}])
    assert ".NET" in _document_compile_language([{"value": "mscoree.dll"}])
    assert "GCC" in _document_compile_language([{"value": "libgcc_s_dw2-1.dll"}])


def test_the_marker_is_found_in_TOP_LEVEL_projections_not_only_module_rows() -> None:
    """The real document keeps string facts in a top-level list, and the row walker must reach it.

    This is the shape that defeated the first version of the detector: `iter_document_rows` walked only
    `modules[].rows[]`, so a section built on its output could not see `document["string_facts"]` at all and
    the detector returned "" on a real document that contains `MSVBVM60.DLL`. Unit tests that build module
    rows by hand passed either way, which is why only a real document exposed it.

    The fix was to make the walker include the document's top-level projections, so this asserts the walker
    invariant rather than working around it.
    """
    from threat_report_agent.analyst_report import iter_document_rows

    document = {
        "modules": [{"id": "static_triage", "rows": [{"type": "pe_basics", "format": "PE32"}]}],
        "string_facts": [
            {"type": "string_fact", "value": "MSVBVM60.DLL", "fact_class": "runtime_dependency"},
            {"type": "string_fact", "value": "C:\\NanoVB6\\VB6.OLB", "fact_class": "build_path"},
        ],
    }
    rows = iter_document_rows(document)
    types = {str(row.get("type") or "") for row in rows}
    assert "string_fact" in types, (
        "the row walker does not reach the top-level string facts, so every section built on it is blind "
        "to the document's most analyst-facing projection"
    )
    assert "Visual Basic 6" in _document_compile_language(rows), (
        "the detector does not see the marker that the walker now exposes"
    )


def test_the_published_body_states_the_language_and_its_provenance() -> None:
    document = {
        "report_version": "3.0",
        "case_id": "case-lang",
        "task_id": "task-lang",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 0, "verified_mechanism_count": 0},
        "analyst_topics": [],
        "modules": [
            {
                "id": "static_triage",
                "title": "Static Triage",
                "summary": "",
                "rows": [
                    {
                        "type": "pe_basics",
                        "format": "PE32",
                        "machine": "0x014c",
                        "entry_rva": 9348,
                        "subsystem": 2,
                        "section_names": [".text", ".data", ".rsrc"],
                    },
                    {"type": "string", "value": {"text": "MSVBVM60.DLL"}},
                    {"type": "string", "value": {"text": "C:\\NanoVB6\\VB6.OLB"}},
                ],
            }
        ],
        "trace": {},
    }
    body = render_official_markdown(document)
    assert "编译语言" in body, "the body does not state the compile language"
    assert "Visual Basic 6" in body
    assert "非运行时观察" in body, "the derivation is not marked as a static inference"
