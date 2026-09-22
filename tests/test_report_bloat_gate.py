from threat_report_agent.reporting import (
    REPORT_MAX_MARKDOWN_BYTES,
    apply_report_display_budget,
    document_to_markdown,
    report_bloat_violations,
)


def test_report_bloat_gate_rejects_oversized_and_raw_dump_documents() -> None:
    violations = report_bloat_violations("## 完整 Strings\n" + ("x" * REPORT_MAX_MARKDOWN_BYTES))
    assert any("exceeds" in item for item in violations)
    assert any("raw-dump" in item for item in violations)


def test_report_bloat_gate_accepts_compact_analyst_document() -> None:
    assert report_bloat_violations("# Report\n\nA concise evidence-backed finding.\n") == []


def test_one_round_report_budget_keeps_how_past_96_kib() -> None:
    """Kunglao completeness: a first-round HOW must not be sliced at 96 KiB."""
    assert REPORT_MAX_MARKDOWN_BYTES >= 256 * 1024
    body = "# 静态分析报告\n\n" + ("How: CryptDecrypt(key=CALG_RC4)\n" * 4000)
    assert len(body.encode("utf-8")) > 96 * 1024
    rendered = apply_report_display_budget(body)
    assert "CryptDecrypt(key=CALG_RC4)" in rendered
    assert "96 KiB" not in rendered
    assert len(rendered.encode("utf-8")) <= REPORT_MAX_MARKDOWN_BYTES


def test_unanswered_behavior_leads_stay_compact_instead_of_fake_how() -> None:
    markdown = document_to_markdown(
        {
            "case_id": "case-1",
            "task_id": "task-1",
            "report_version": "3.0",
            "report_sections": ["static_triage"],
            "analysis_outcome": "PARTIAL",
            "analysis_class": "STATIC_ANALYSIS",
            "modules": [
                {
                    "id": "static_triage",
                    "title": "Static Triage",
                    "summary": "semantic evidence",
                    "rows": [
                        {
                            "type": "behavior_finding",
                            "finding_id": "closed-decode",
                            "catalog_id": "config-crypto.decode",
                            "finding_status": "SUPPORTED",
                            "what": "decode resource buffer",
                            "how": "CryptDecrypt(alg=CALG_RC4, input=res#101)",
                            "target": "0x401000",
                            "evidence_ids": ["ev-1"],
                        },
                        {
                            "type": "behavior_finding",
                            "finding_id": "open-thread",
                            "catalog_id": "thread.start_routine",
                            "finding_status": "CANDIDATE",
                            "what": "CreateThread listing",
                            "how": "UNKNOWN(start_routine)",
                            "target": "0x402000",
                            "evidence_ids": ["ev-2"],
                        },
                    ],
                }
            ],
        }
    )
    assert "CryptDecrypt(alg=CALG_RC4, input=res#101)" in markdown
    assert "Deferred unanswered behavior leads" in markdown
    assert "missing=HOW" in markdown
    assert "How: UNKNOWN(start_routine)" not in markdown


def test_report_banner_treats_emulators_as_static_not_sandbox_dynamic() -> None:
    markdown = document_to_markdown(
        {
            "case_id": "case-1",
            "task_id": "task-1",
            "report_version": "3.0",
            "report_sections": ["static_triage"],
            "analysis_outcome": "PARTIAL",
            "analysis_class": "BOUNDED_STATIC_ANALYSIS",
            "modules": [
                {
                    "id": "static_triage",
                    "title": "Static Triage",
                    "summary": "semantic evidence",
                    "rows": [
                        {
                            "type": "emulation_status",
                            "overall": "FAILED",
                            "attempted": True,
                            "results": [
                                {
                                    "simulator": "speakeasy",
                                    "status": "FAILED",
                                    "stop_reason": "EXECUTION_ERROR",
                                }
                            ],
                            "next_step": "continue static recovery",
                        }
                    ],
                }
            ],
        }
    )
    assert "- Sample execution: **false**" in markdown
    assert "- Sandbox/dynamic analysis: **false**" in markdown
    assert "isolated Unicorn/Speakeasy/Qiling" in markdown
    assert "完整沙箱跑样本才是动态分析" in markdown
    assert "not sandbox/dynamic sample execution" in markdown
    assert "take the sample to a sandbox" not in markdown.casefold()

