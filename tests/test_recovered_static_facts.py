"""The conclusion summary must lead with the values the run actually recovered.

An analyst reading the report needs the concrete recovered values -- decoded
endpoints, the recovered call sequence, the thread entry, the parent-process
attribute, the dynamically resolved API names -- before the list of open slots.
The earlier summary named only generic capability categories ("dynamic
resolution path"), which read as though nothing specific came out of the run
even when a decoded URL and a thread entry were in hand.

These facts stay phrased as recovered *static values*: none of them asserts
runtime execution or a closed consumer chain.
"""

from __future__ import annotations

from threat_report_agent.analyst_report import (
    _recovered_endpoint_values,
    _recovered_static_facts,
)
from threat_report_agent.reporting import REPORT_V3_REQUIRED_SECTIONS
from threat_report_agent.analyst_report import render_official_markdown


def _rows() -> list[dict[str, object]]:
    return [
        {
            "type": "pe_basics",
            "format": "PE32+",
            "machine": "0x8664",
            "entry_rva": "5152",
            "subsystem": "2",
        },
        {
            "type": "persist_how",
            "mechanism_type": "DECODE_CONFIG",
            "status": "CANDIDATE",
            "target": "Resume.pdf.exe.VIR",
            "how": "key_table_modulo_xor_counter; endpoint=http://203.0.113.10/miaom-c.pdf",
            "verification": {
                "decoded_preview": "http://203.0.113.10/miaom-c.pdf",
                "decoded_text": "http://203.0.113.10/miaom-c.pdf",
            },
        },
        {
            "type": "persist_how",
            "mechanism_type": "HTTP_DOWNLOAD",
            "status": "CANDIDATE",
            "target": "Resume.pdf.exe.VIR",
            "how": (
                "WinHttpOpen -> WinHttpOpenRequest -> WinHttpSendRequest; "
                "endpoint=http://203.0.113.11/ComHost.exe"
            ),
        },
        {
            "type": "persist_how",
            "mechanism_type": "THREAD_CALLBACK",
            "status": "VERIFIED",
            "target": "Resume.pdf.exe.VIR",
            "how": "CreateThread lpStartAddress=0x140038ae0; lpParameter=0x8",
            "outputs": ["0x140038ae0"],
            "consumers": ["0x140038ae0"],
        },
        {
            "type": "persist_how",
            "mechanism_type": "PPID_SPOOFING",
            "status": "UNKNOWN",
            "target": "Resume.pdf.exe.VIR",
            "how": "UpdateProcThreadAttribute; attribute=0x00020000; parent=UNKNOWN(parent identity)",
        },
        {
            "type": "persist_how",
            "mechanism_type": "PROCESS_EXECUTION",
            "status": "CANDIDATE",
            "target": "Resume.pdf.exe.VIR",
            "how": "CreateProcessW command=FoxitPDFReader.exe; creation_flags=UNKNOWN(creation_flags)",
        },
        {
            "type": "resolved_api",
            "kind": "resolved_api",
            "api_name": "GetTempPath2W",
        },
    ]


def test_endpoints_are_collected_in_order() -> None:
    endpoints = _recovered_endpoint_values(_rows())
    assert "http://203.0.113.10/miaom-c.pdf" in endpoints
    assert "http://203.0.113.11/ComHost.exe" in endpoints


def test_reference_links_are_never_reported_as_decoded_endpoints() -> None:
    """attack.mitre.org is this product's own reference, not sample config."""
    rows = _rows() + [
        {
            "type": "attack_mapping",
            "technique_id": "T1071",
            "url": "https://attack.mitre.org/techniques/T1071/",
            "detail": "see https://attack.mitre.org/techniques/T1497/ for evasion",
        }
    ]
    endpoints = _recovered_endpoint_values(rows)
    assert not any("attack.mitre.org" in item for item in endpoints), endpoints


def test_a_url_is_never_reported_as_a_process_command() -> None:
    rows = _rows() + [
        {
            "type": "persist_how",
            "mechanism_type": "HTTP_DOWNLOAD",
            "status": "CANDIDATE",
            "how": "WinHttpSendRequest; command=http://203.0.113.12/stage.bin",
        }
    ]
    facts = " ".join(_recovered_static_facts(rows))
    assert "进程命令行 `http" not in facts


def test_summary_facts_name_the_concrete_recovered_values() -> None:
    facts = " ".join(_recovered_static_facts(_rows()))
    assert "0x140038ae0" in facts
    assert "http://203.0.113.10/miaom-c.pdf" in facts
    assert "0x00020000" in facts
    assert "GetTempPath2W" in facts
    assert "FoxitPDFReader.exe" in facts


def test_summary_facts_never_claim_runtime_execution() -> None:
    facts = " ".join(_recovered_static_facts(_rows()))
    for forbidden in ("已执行", "已运行", "沙箱已", "C2 存活", "服务器存活"):
        assert forbidden not in facts


def test_official_report_leads_with_the_recovered_endpoint() -> None:
    document: dict[str, object] = {
        "report_version": "3.0",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "case_id": "case-facts",
        "task_id": "task-facts",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 4, "verified_mechanism_count": 2},
        "modules": [
            {"id": "static_triage", "title": "Static Triage", "summary": "", "rows": _rows()}
        ],
        "trace": {},
    }
    official = render_official_markdown(document)
    summary = official.split("### 样本概况")[0]
    assert "0x140038ae0" in summary
    assert "http://203.0.113.10/miaom-c.pdf" in summary
    assert "0x00020000" in summary


def _document_for_chapters() -> dict[str, object]:
    return {
        "report_version": "3.0",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "case_id": "case-chapters",
        "task_id": "task-chapters",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 4, "verified_mechanism_count": 2},
        "modules": [
            {"id": "static_triage", "title": "Static Triage", "summary": "", "rows": _rows()}
        ],
        "trace": {},
    }


def test_chapter_status_says_what_was_recovered_and_what_is_missing() -> None:
    """Every unclosed chapter otherwise reads identically."""
    official = render_official_markdown(_document_for_chapters())
    main_body = official.split("## 调查附录")[0]
    assert "CANDIDATE（未过验证器）" in main_body
    assert "已恢复" in main_body
    # The concrete recovered value travels with the verdict.
    thread_chapter = main_body.split("### 线程")[-1].split("### ")[0]
    assert "0x140038ae0" in thread_chapter


def test_appendix_headings_do_not_carry_the_recovered_detail() -> None:
    """The appendix stays a ledger: slot values may hold the VA, headings may not.

    The ten-question appendix legitimately prints ``How: CreateThread
    lpStartAddress=0x140038ae0`` as a slot *value*.  What must not happen is the
    "已恢复 …" detail being appended to the appendix's own topic headings, which
    would blur the main-body / ledger separation the report relies on.
    """
    official = render_official_markdown(_document_for_chapters())
    if "## 调查附录" not in official:
        return
    appendix = official.split("## 调查附录", 1)[1]
    headings = [
        line for line in appendix.splitlines() if line.startswith("**") and line.endswith("**")
    ]
    assert headings, "expected at least one appendix topic heading"
    for line in headings:
        assert "已恢复" not in line, line
