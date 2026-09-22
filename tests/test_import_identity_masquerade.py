"""A sample that carries another product's identity must be reported as doing so.

Measured on task `ce7e310e` (the accepted revision's task). The binary is submitted as
`Resume.pdf.exe.VIR`, and it carries:

    PE resource  type 16 (RT_VERSION)   876 bytes
    PE resource  type 3  (RT_ICON)    9 entries, one at entropy 7.94

plus this `string` Evidence row:

    Adobe Acrobat Reader DC 23.006.20380Copyright 1984-2023 Adobe Inc. ...
    AcroRd32.exeAcroCEF.exeAdobe PDF Library 23.006.20380AdobeARMservice
    C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe
    %LOCALAPPDATA%\\Adobe\\Acrobat\\DC\\CachePDFNetC64.dllPDF-1.7%PDF-1.4endstream

The published body contained none of it: `Adobe` 0 matches, `Acrobat` 0, `PDF-1.7` 0, and the string
facts section listed 13 values of which none was this row. The cause was the classifier, not the
extractor - `build_string_fact_projection` publishes only strings whose class `_STRING_FACT_PATTERNS`
recognises, and no pattern covered a product identity, an imposter executable path, the "Adobe PDF
Library" runtime, or the document-format markers.

That matters because a binary impersonating a PDF reader while being delivered as a `.pdf.exe` is a
headline triage fact, and "版本资源" was absent from the body entirely - the report could not say the
sample presents itself as anything.

These tests assert on the published body, because the objective grades the report, and they also
assert the classifier stays honest: a real Windows system path must not become a "fact".
"""
from __future__ import annotations

from threat_report_agent.analyst_report import render_official_markdown
from threat_report_agent.reporting import (
    build_string_fact_projection,
    string_fact_class,
)

# The real row, as the parser stores it.
IDENTITY_STRING = (
    "Adobe Acrobat Reader DC 23.006.20380Copyright 1984-2023 Adobe Inc. All rights reserved."
    "AcroRd32.exeAcroCEF.exeAdobe PDF Library 23.006.20380AdobeARMserviceAdobe Update Manager"
    "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe"
    "%LOCALAPPDATA%\\Adobe\\Acrobat\\DC\\CachePDFNetC64.dllPDF-1.7%PDF-1.4endstream"
)
IMPOSTER_PATH = "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe"
DOCUMENT_MARKER = "PDF-1.7%PDF-1.4endstream"
PDF_LIBRARY = "PDFNetC64.dll"


def _row(text: str, ident: str = "ev-1") -> dict[str, object]:
    return {
        "id": ident,
        "kind": "string",
        "module": "static_triage",
        "nature": "STATIC_OBSERVED",
        "value": {"encoding": "ascii", "text": text},
    }


def test_identity_strings_are_classified_as_facts() -> None:
    assert string_fact_class(IDENTITY_STRING), "a product-identity string is a triage fact"
    assert string_fact_class(IMPOSTER_PATH), "an imposter executable path is a triage fact"
    assert string_fact_class(DOCUMENT_MARKER), "a document-format marker is a triage fact"
    assert string_fact_class(PDF_LIBRARY), "a bundled document library is a triage fact"


def test_the_body_reports_the_identity_the_sample_claims() -> None:
    """正文-level: the claim has to be in the published text, not only in the projection."""
    document = {
        "report_version": "3.0",
        "case_id": "c",
        "task_id": "t",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "string_facts": build_string_fact_projection([_row(IDENTITY_STRING)]),
        "modules": [],
        "trace": {},
    }
    body = render_official_markdown(document)
    for token in ("Adobe", "Acrobat", "AcroRd32"):
        assert token in body, f"the body never states the sample claims {token!r}"
    assert any(marker in body for marker in ("PDF-1.7", "PDF-1.4")), (
        "the body never states the embedded document-format markers"
    )


def test_a_real_windows_path_is_not_promoted_to_a_fact() -> None:
    """Selectivity: the new classes must not turn the sample's environment into its identity.

    `C:\\Windows\\System32\\kernel32.dll` appears in almost every sample's strings; promoting it
    would put the analyst's own machine in the report as a claim about the sample.
    """
    for benign in (
        "C:\\Windows\\System32\\kernel32.dll",
        "C:\\Windows\\SysWOW64\\advapi32.dll",
        "L$@0H",
        "junk",
    ):
        assert not string_fact_class(benign), f"benign path classified as a fact: {benign!r}"


def test_debug_assertions_are_not_read_as_a_product_identity() -> None:
    """A first draft of `imposter_application` matched the bare word `Edge`.

    Measured: the sample carries Rust `BTreeMap` debug assertions, so the published body grew two
    rows reading 「样本自称的产品身份（冒充迹象）」 above `assertion failed: edge.height ==
    self.node.height - 1`. Publishing an internal data-structure name as a masquerade claim is worse
    than publishing nothing.
    """
    for assertion in (
        "assertion failed: edge.height == self.node.height - 1",
        'assertion failed: edge.height == self.height - 1&"',
        "assertion failed: self.is_char_boundary(new_len)",
    ):
        assert not string_fact_class(assertion), (
            f"a debug assertion was classified as an identity fact: {assertion!r}"
        )
    # and the real multi-token product names still classify
    assert string_fact_class("Adobe Acrobat Reader DC 23.006.20380")
    assert string_fact_class("Microsoft Office Word")


def test_a_resolver_failure_is_not_published_as_an_api_name() -> None:
    """`WinHTTP export not found` is a recovery OUTCOME, and it was listed as a download API.

    Measured on task `ce7e310e`: the published body's string facts carried
    「下载相关 API 名称：`WinHTTP export not found`」, which reads as an API the sample calls. It is the
    product reporting that it could not resolve the symbol.
    """
    from threat_report_agent.reporting import build_string_fact_projection

    projection = build_string_fact_projection([_row("WinHTTP export not found")])
    assert projection, "the resolution failure must still be published - it is a real boundary"
    assert projection[0]["fact_class"] == "resolution_failure", (
        "a resolver failure classified as an API makes the report claim a capability"
    )



def test_the_resource_directory_reaches_the_published_body() -> None:
    """The `RT_VERSION` block and the high-entropy icon were in evidence and in no report.

    Measured on task `ce7e310e`: `pe_structure.resources` holds 11 entries - 9 `RT_ICON` (one at
    entropy 7.94), 1 `RT_GROUP_ICON`, 1 `RT_VERSION` - and the published body named no resource
    whatsoever while its own limitations section listed 资源提取链 as reportable.
    """
    from threat_report_agent.analyst_report import render_official_markdown
    from threat_report_agent.reporting import build_pe_resource_projection

    class _Evidence:
        def __init__(self, kind: str, value: dict) -> None:
            self.kind = kind
            self.value = value

    resources = {
        "rva": 405000,
        "size": 90000,
        "count": 11,
        "rcdata_count": 0,
        "rcdata_total_size": 0,
        "high_entropy_count": 1,
        "entries": [
            {"type": 3, "name": i + 1, "size": 1128 * (i + 1), "entropy": 4.0}
            for i in range(8)
        ]
        + [
            {"type": 3, "name": 9, "size": 11137, "entropy": 7.93893},
            {"type": 14, "name": 1, "size": 132, "entropy": 3.03466},
            {"type": 16, "name": 1, "size": 876, "entropy": 3.37391},
        ],
    }
    projection = build_pe_resource_projection(
        {"ev-pe": _Evidence("pe_structure", {"entry_rva": 5152, "resources": resources})}
    )
    assert projection is not None
    assert projection["resource_count"] == 11
    names = {group["name"]: group for group in projection["entries"]}
    assert names["RT_ICON"]["count"] == 9
    assert names["RT_VERSION"]["count"] == 1
    assert names["RT_ICON"]["max_entropy"] == 7.93893

    document = {
        "report_version": "3.0",
        "case_id": "c",
        "task_id": "t",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "modules": [{"id": "static_triage", "rows": [projection]}],
        "string_facts": build_string_fact_projection([_row(IDENTITY_STRING)]),
        "trace": {},
    }
    body = render_official_markdown(document)
    for token in ("RT_VERSION", "RT_ICON", "RT_GROUP_ICON"):
        assert token in body, f"the body never names the {token} resource"
    assert "7.94" in body, "the high-entropy icon is not flagged, so the payload hint is lost"

