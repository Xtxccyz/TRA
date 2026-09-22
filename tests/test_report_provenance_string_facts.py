"""A toolchain build path, a runtime dependency and a compiler fingerprint are facts.

Measured on a Visual Basic 6 sample the workbench had just analysed (task `6be962d4`), whose
published body was 5,611 characters. The extractor held, and the body did NOT contain:

    C:\\NanoVB6\\VB6.OLB     the build path baked in by the VB6 linker - provenance, and a
                             toolchain fingerprint an analyst uses to recognise the family
    MSVBVM60.DLL            the VB6 runtime the binary needs, i.e. what it will load
    VBA6.DLL                the second half of the same dependency
    ss3advd.exe             a name the sample carries
    __vba / EVENT_SINK      the compiler's fingerprint, present 413 times in evidence

The string-fact classifier recognised MOTW, scheduled tasks, URLs, registry keys, temp paths,
user agents and API names - but none of these classes, so `string_fact_class` returned "" and
the funnel that promotes significant strings into the body dropped them. That is the R2 defect
(projection/render missing) in its generic form: it is not specific to the Resume sample, and
it silently applies to every sample that carries provenance or dependency strings.

Assertions are on the PUBLISHED body, because a fact in the extractor and not in the body is
the failure being fixed.
"""

from __future__ import annotations

from threat_report_agent.analyst_report import render_official_markdown
from threat_report_agent.reporting import (
    REPORT_V3_REQUIRED_SECTIONS,
    build_string_fact_projection,
    string_fact_class,
)

BUILD_PATH = "C:\\NanoVB6\\VB6.OLB"
RUNTIME_DLL = "MSVBVM60.DLL"
SECOND_DLL = "VBA6.DLL"
SAMPLE_NAME = "ss3advd.exe"
COMPILER_MARKER = "__vbaVarMove"


def _string_row(evidence_id: str, text: str) -> dict[str, object]:
    """A string Evidence row in the shape the projection reads.

    `id` is the field `build_string_fact_projection` keys on, and `evidence_id` is the field
    the ledger summary uses - a real row carries both, so a fixture with only one of them
    silently exercised a path production never takes.
    """
    return {
        "id": evidence_id,
        "evidence_id": evidence_id,
        "artifact_id": "artifact-1",
        "tool_run_id": "run-1",
        "module": "static_triage",
        "kind": "string",
        "nature": "STATIC_OBSERVED",
        "value": {"encoding": "ascii", "text": text},
        "anchor": {"type": "string", "rva": 1},
    }


def _document(rows: list[dict[str, object]]) -> dict[str, object]:
    return {
        "report_version": "3.0",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "case_id": "case-vb6",
        "task_id": "task-vb6",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 1, "verified_mechanism_count": 0},
        "string_facts": build_string_fact_projection(rows),
        "modules": [
            {"id": "static_triage", "title": "Static Triage", "summary": "", "rows": rows}
        ],
        "trace": {},
    }


def _facts() -> list[dict[str, object]]:
    return [
        _string_row("ev-build", BUILD_PATH),
        _string_row("ev-rt", RUNTIME_DLL),
        _string_row("ev-rt2", SECOND_DLL),
        _string_row("ev-name", SAMPLE_NAME),
        _string_row("ev-marker", COMPILER_MARKER),
    ]


def test_classifier_recognises_build_path_runtime_and_compiler_marker() -> None:
    """Each class must be identifiable, or nothing downstream can promote it."""
    assert string_fact_class(BUILD_PATH), "a toolchain build path is a fact"
    assert string_fact_class(RUNTIME_DLL), "a runtime DLL dependency is a fact"
    assert string_fact_class(SECOND_DLL), "a runtime DLL dependency is a fact"
    assert string_fact_class(COMPILER_MARKER), "a compiler fingerprint is a fact"


def test_projection_carries_them_with_their_evidence_ids() -> None:
    # A LIST of rows, which is what `build_report_document` passes
    # (`service.py:23193` selects `list(session.scalars(...))`).  An earlier version of this
    # test passed a mapping keyed by id, and iterating a mapping yields its KEYS - so the
    # projection saw strings, skipped every row, and returned [] while looking exercised.
    rows = _facts()
    projection = build_string_fact_projection(rows)
    values = {str(item.get("value")) for item in projection}
    assert BUILD_PATH in values, f"build path missing from the projection: {sorted(values)}"
    assert RUNTIME_DLL in values, f"runtime DLL missing from the projection: {sorted(values)}"
    for item in projection:
        assert item.get("evidence_ids"), (
            "a projected fact without its evidence ids is unusable: a reader cannot go back "
            "to the ledger to verify it"
        )


def test_published_body_carries_the_build_path_and_runtime_dependency() -> None:
    """The graded artefact: a fact in the extractor but not the body is the defect."""
    body = render_official_markdown(_document(_facts()))
    assert RUNTIME_DLL in body, "the binary's runtime dependency never reached the report"
    assert BUILD_PATH in body or "VB6.OLB" in body, (
        "the toolchain build path never reached the report, so the reader cannot identify "
        "how the sample was built"
    )


def test_noise_strings_still_do_not_become_facts() -> None:
    """The classifier must stay selective: these classes are facts, byte noise is not."""
    for noise in ("L$@0H", "junk", "aaaaaaaaaaaaaaaa", "0123456789abcdef"):
        assert not string_fact_class(noise), f"noise classified as a fact: {noise!r}"
